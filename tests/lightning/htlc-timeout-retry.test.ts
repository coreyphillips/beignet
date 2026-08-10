/**
 * Current peer commitment HTLC claims skipped during a fee spike.
 *
 * Both direct witness-v0 claims used to call builders that throw when the fee
 * exceeds the HTLC value. The exception escaped the commitment resolver and
 * discarded every watch and unrelated claim from the close. A guarded claim
 * must remain tracked and become spendable when a later fee estimate falls.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { buildRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { HtlcDirection } from '../../src/lightning/channel/types';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	ChainAction,
	ChainActionType,
	ITrackedOutput,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { setupNormalChannels } from './helpers/revoked-commitment-fixture';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;
const CONFIRMATION_HEIGHT = 100;
const CLTV_EXPIRY = 120;
const STARVED_SATS = 2_000;
const SPIKE_SAT_PER_VBYTE = 50;
const SPIKE_SAT_PER_KW = SPIKE_SAT_PER_VBYTE * 250;
const CALM_SAT_PER_KW = 250;
const RISING_SAT_PER_KW = 5 * 250;

interface ICurrentHtlcFixture {
	monitor: ChainMonitor;
	commitment: bitcoin.Transaction;
	state: IChannelState;
	openerPrivkeys: Buffer[];
	destinationScript: Buffer;
	paymentHash: Buffer;
	preimage: Buffer;
}

interface ICurrentHtlcOptions {
	anchor?: boolean;
	taproot?: boolean;
	knownPreimage?: boolean;
}

function anchorChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	return flags.toBuffer();
}

function taprootChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT);
	return flags.toBuffer();
}

function currentPeerHtlc(
	direction: HtlcDirection,
	options: ICurrentHtlcOptions = {}
): ICurrentHtlcFixture {
	const { opener, openerPrivkeys } = setupNormalChannels();
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	const amountMsat = BigInt(STARVED_SATS) * 1000n;

	if (direction === HtlcDirection.OFFERED) {
		opener.addHtlc(amountMsat, paymentHash, CLTV_EXPIRY, Buffer.alloc(1366));
	} else {
		opener.handleUpdateAddHtlc({
			channelId: opener.getChannelId()!,
			id: 0n,
			amountMsat,
			paymentHash,
			cltvExpiry: CLTV_EXPIRY,
			onionRoutingPacket: Buffer.alloc(1366)
		});
		// Model the completed commitment round that lets this peer-originated add
		// appear in the peer's current commitment.
		for (const entry of opener.getFullState().htlcs.values()) {
			entry.addLocallyRevoked = true;
		}
	}

	const state = opener.getFullState();
	if (options.taproot) {
		state.channelType = taprootChannelType();
	} else if (options.anchor) {
		state.channelType = anchorChannelType();
	}
	const remotePoint = state.remoteCurrentPerCommitmentPoint!;
	const commitment = buildRemoteCommitment(state, remotePoint).result.tx;
	const destinationScript = bitcoin.payments.p2wpkh({
		pubkey: getPublicKey(openerPrivkeys[0]),
		network
	}).output!;
	const monitor = new ChainMonitor(
		state,
		destinationScript,
		SPIKE_SAT_PER_VBYTE,
		openerPrivkeys[1],
		openerPrivkeys[2],
		network,
		openerPrivkeys[3],
		openerPrivkeys[4]
	);
	if (direction === HtlcDirection.RECEIVED && options.knownPreimage !== false) {
		monitor.addPreimage(paymentHash, preimage);
	}

	return {
		monitor,
		commitment,
		state,
		openerPrivkeys,
		destinationScript,
		paymentHash,
		preimage
	};
}

function broadcasts(actions: ChainAction[]): bitcoin.Transaction[] {
	return actions.flatMap((action) =>
		action.type === ChainActionType.BROADCAST_TX
			? [bitcoin.Transaction.fromBuffer(action.tx)]
			: []
	);
}

function spends(tx: bitcoin.Transaction, output: ITrackedOutput): boolean {
	return tx.ins.some(
		(input) =>
			Buffer.from(input.hash).reverse().toString('hex') === output.txid &&
			input.index === output.outputIndex
	);
}

function htlcOutput(
	monitor: ChainMonitor,
	outputType: OutputType.OFFERED_HTLC | OutputType.RECEIVED_HTLC
): ITrackedOutput {
	const output = monitor
		.getTrackedOutputs()
		.find((candidate) => candidate.outputType === outputType);
	expect(output, `${outputType} output tracked`).to.exist;
	return output!;
}

function skippedFor(
	actions: ChainAction[],
	output: ITrackedOutput
): ChainAction[] {
	return actions.filter(
		(action) =>
			action.type === ChainActionType.SWEEP_UNECONOMIC &&
			action.reason === 'skipped' &&
			action.txid === output.txid &&
			action.outputIndex === output.outputIndex
	);
}

function peerSpend(
	output: ITrackedOutput,
	destinationScript: Buffer,
	preimage?: Buffer
): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(
		Buffer.from(output.txid, 'hex').reverse(),
		output.outputIndex,
		0xfffffffd
	);
	tx.addOutput(destinationScript, Number(output.amount) - 500);
	if (preimage && output.witnessScript) {
		tx.setWitness(0, [Buffer.alloc(72, 1), preimage, output.witnessScript]);
	}
	return tx;
}

describe('Uneconomic current peer HTLC claims', function () {
	it('keeps and retries a witness-v0 offered HTLC timeout claim', function () {
		const fixture = currentPeerHtlc(HtlcDirection.OFFERED);
		let opening: ChainAction[] = [];

		expect(() => {
			opening = fixture.monitor.handleFundingSpent(
				fixture.commitment,
				CONFIRMATION_HEIGHT
			);
		}, 'an uneconomic timeout must not escape the resolver').to.not.throw();

		const offered = htlcOutput(fixture.monitor, OutputType.OFFERED_HTLC);
		expect(offered.amount).to.equal(BigInt(STARVED_SATS));
		expect(offered.status).to.equal(OutputStatus.CONFIRMED);
		expect(offered.sweepTxHex).to.equal(undefined);
		expect(skippedFor(opening, offered)).to.have.length(1);
		expect(
			opening.some(
				(action) =>
					action.type === ChainActionType.WATCH_OUTPUT &&
					action.txid === offered.txid &&
					action.outputIndex === offered.outputIndex
			),
			'the skipped outpoint remains watched'
		).to.equal(true);
		expect(
			opening.some(
				(action) =>
					action.type === ChainActionType.BROADCAST_TX &&
					action.description.includes('to_remote')
			),
			'an unrelated balance claim survives the skipped HTLC'
		).to.equal(true);

		const retry = fixture.monitor.updateFeeRate(CALM_SAT_PER_KW);
		expect(
			broadcasts(retry).some((tx) => spends(tx, offered)),
			'the pre-CLTV timeout stays held'
		).to.equal(false);
		const held = htlcOutput(fixture.monitor, OutputType.OFFERED_HTLC);
		expect(held.status).to.equal(OutputStatus.CONFIRMED);
		expect(held.maturityHeight).to.equal(CLTV_EXPIRY);
		expect(held.sweepTxHex).to.be.a('string');

		const timeout = bitcoin.Transaction.fromHex(held.sweepTxHex!);
		expect(spends(timeout, held)).to.equal(true);
		expect(timeout.locktime).to.equal(CLTV_EXPIRY);
		expect(timeout.ins[0].sequence).to.equal(0xfffffffd);
		expect(timeout.ins[0].witness).to.have.length(3);
		expect(timeout.ins[0].witness[1]).to.have.length(0);
		expect(timeout.outs[0].script.equals(fixture.destinationScript)).to.equal(
			true
		);

		const maturity = broadcasts(fixture.monitor.handleNewBlock(CLTV_EXPIRY));
		const released = maturity.find((tx) => spends(tx, held));
		expect(released, 'the held timeout releases at CLTV').to.exist;
		expect(released!.toHex()).to.equal(timeout.toHex());
	});

	it('keeps and retries a witness-v0 received HTLC with a known preimage', function () {
		const fixture = currentPeerHtlc(HtlcDirection.RECEIVED);
		let opening: ChainAction[] = [];

		expect(() => {
			opening = fixture.monitor.handleFundingSpent(
				fixture.commitment,
				CONFIRMATION_HEIGHT
			);
		}, 'an uneconomic preimage claim must not escape the resolver').to.not.throw();

		const received = htlcOutput(fixture.monitor, OutputType.RECEIVED_HTLC);
		expect(received.status).to.equal(OutputStatus.CONFIRMED);
		expect(received.sweepTxHex).to.equal(undefined);
		expect(skippedFor(opening, received)).to.have.length(1);

		const retry = broadcasts(fixture.monitor.updateFeeRate(CALM_SAT_PER_KW));
		const claim = retry.find((tx) => spends(tx, received));
		expect(claim, 'the fee drop immediately recovers the preimage claim').to
			.exist;
		expect(claim!.locktime).to.equal(0);
		expect(claim!.ins[0].sequence).to.equal(0xfffffffd);
		expect(claim!.ins[0].witness).to.have.length(3);
		expect(claim!.ins[0].witness[1].equals(fixture.preimage!)).to.equal(true);
		expect(claim!.outs[0].script.equals(fixture.destinationScript)).to.equal(
			true
		);
		expect(
			htlcOutput(fixture.monitor, OutputType.RECEIVED_HTLC).status
		).to.equal(OutputStatus.SPEND_BROADCAST);
	});

	it('does not report or retry a received HTLC before its preimage is known', function () {
		const fixture = currentPeerHtlc(HtlcDirection.RECEIVED, {
			knownPreimage: false
		});
		const opening = fixture.monitor.handleFundingSpent(
			fixture.commitment,
			CONFIRMATION_HEIGHT
		);
		const received = htlcOutput(fixture.monitor, OutputType.RECEIVED_HTLC);

		expect(
			skippedFor(opening, received),
			'missing preimage is not a fee decline'
		).to.have.length(0);
		expect(received.sweepTxHex).to.equal(undefined);
		const feeRetry = fixture.monitor.updateFeeRate(CALM_SAT_PER_KW);
		expect(skippedFor(feeRetry, received)).to.have.length(0);
		expect(
			broadcasts(feeRetry).some((tx) => spends(tx, received)),
			'fee changes cannot make a claim possible without its preimage'
		).to.equal(false);
		const blockRetry = fixture.monitor.handleNewBlock(CONFIRMATION_HEIGHT + 1);
		expect(skippedFor(blockRetry, received)).to.have.length(0);
		expect(broadcasts(blockRetry).some((tx) => spends(tx, received))).to.equal(
			false
		);
		expect(received.sweepTxHex).to.equal(undefined);

		const learned = broadcasts(
			fixture.monitor.addPreimage(fixture.paymentHash, fixture.preimage)
		);
		expect(
			learned.some((tx) => spends(tx, received)),
			'the known preimage makes the claim immediately available'
		).to.equal(true);
	});

	it('reports an anchor received HTLC contest only after the parent CSV matures', function () {
		for (const [label, options] of [
			['anchor', { anchor: true }],
			['taproot', { taproot: true }]
		] as const) {
			const fixture = currentPeerHtlc(HtlcDirection.RECEIVED, options);
			const opening = fixture.monitor.handleFundingSpent(fixture.commitment, 0);
			const received = htlcOutput(fixture.monitor, OutputType.RECEIVED_HTLC);
			expect(
				skippedFor(opening, received),
				`${label}: initial decline`
			).to.have.length(1);

			const beforeConfirmation = fixture.monitor.handleNewBlock(CLTV_EXPIRY);
			expect(
				beforeConfirmation.filter(
					(action) =>
						action.type === ChainActionType.SWEEP_UNECONOMIC &&
						action.reason === 'contested' &&
						action.txid === received.txid &&
						action.outputIndex === received.outputIndex
				),
				`${label}: an unconfirmed parent has no relative maturity height`
			).to.have.length(0);

			const confirmation = fixture.monitor.handleFundingSpent(
				fixture.commitment,
				CLTV_EXPIRY
			);
			expect(received.confirmationHeight).to.equal(CLTV_EXPIRY);
			expect(
				confirmation.filter(
					(action) =>
						action.type === ChainActionType.SWEEP_UNECONOMIC &&
						action.reason === 'contested'
				),
				`${label}: sequence 1 is not mature in the parent confirmation block`
			).to.have.length(0);

			const contested = fixture.monitor
				.handleNewBlock(CLTV_EXPIRY + 1)
				.filter(
					(action) =>
						action.type === ChainActionType.SWEEP_UNECONOMIC &&
						action.reason === 'contested' &&
						action.txid === received.txid &&
						action.outputIndex === received.outputIndex
				);
			expect(
				contested,
				`${label}: the real transition is reported`
			).to.have.length(1);
			const report = contested[0];
			expect(report.type).to.equal(ChainActionType.SWEEP_UNECONOMIC);
			if (report.type === ChainActionType.SWEEP_UNECONOMIC) {
				expect(report.contestHeight).to.equal(CLTV_EXPIRY + 1);
			}
			expect(
				fixture.monitor
					.handleNewBlock(CLTV_EXPIRY + 2)
					.filter(
						(action) =>
							action.type === ChainActionType.SWEEP_UNECONOMIC &&
							action.reason === 'contested'
					),
				`${label}: the transition is reported once`
			).to.have.length(0);
		}
	});

	it('retries from a new block and reports the original decline only once', function () {
		const fixture = currentPeerHtlc(HtlcDirection.OFFERED);
		const opening = fixture.monitor.handleFundingSpent(
			fixture.commitment,
			CONFIRMATION_HEIGHT
		);
		const offered = htlcOutput(fixture.monitor, OutputType.OFFERED_HTLC);
		expect(skippedFor(opening, offered)).to.have.length(1);

		const repeatedBlock = fixture.monitor.handleNewBlock(
			CONFIRMATION_HEIGHT + 1
		);
		const repeatedEstimate = fixture.monitor.updateFeeRate(SPIKE_SAT_PER_KW);
		expect(skippedFor(repeatedBlock, offered)).to.have.length(0);
		expect(skippedFor(repeatedEstimate, offered)).to.have.length(0);
		expect(offered.uneconomicSinceHeight).to.equal(CONFIRMATION_HEIGHT);

		// Simulate restart with a calmer fee estimate before another block arrives.
		// The block path, rather than updateFeeRate, must revisit the skipped claim.
		const restored = ChainMonitor.restore(
			fixture.monitor.getFullState(),
			fixture.state,
			fixture.destinationScript,
			1,
			fixture.openerPrivkeys[1],
			fixture.openerPrivkeys[2],
			network,
			fixture.openerPrivkeys[3],
			fixture.openerPrivkeys[4]
		);
		const retried = restored.handleNewBlock(CONFIRMATION_HEIGHT + 2);
		const held = htlcOutput(restored, OutputType.OFFERED_HTLC);
		expect(skippedFor(retried, held)).to.have.length(0);
		expect(
			broadcasts(retried).some((tx) => spends(tx, held)),
			'the timeout remains held before CLTV'
		).to.equal(false);
		expect(held.sweepTxHex).to.be.a('string');
		expect(held.maturityHeight).to.equal(CLTV_EXPIRY);
	});

	it('stops retrying after the peer spends the skipped HTLC', function () {
		const fixture = currentPeerHtlc(HtlcDirection.OFFERED);
		fixture.monitor.handleFundingSpent(fixture.commitment, CONFIRMATION_HEIGHT);
		const offered = htlcOutput(fixture.monitor, OutputType.OFFERED_HTLC);
		const peerClaim = peerSpend(
			offered,
			fixture.destinationScript,
			fixture.preimage
		);

		fixture.monitor.handleOutputSpent(
			offered.txid,
			offered.outputIndex,
			peerClaim,
			CONFIRMATION_HEIGHT + 1
		);
		expect(offered.status).to.equal(OutputStatus.SPEND_CONFIRMED);

		const feeRetry = fixture.monitor.updateFeeRate(CALM_SAT_PER_KW);
		const blockRetry = fixture.monitor.handleNewBlock(CONFIRMATION_HEIGHT + 2);
		expect(
			broadcasts([...feeRetry, ...blockRetry]).some((tx) =>
				spends(tx, offered)
			),
			'a spent outpoint is never claimed again'
		).to.equal(false);
		expect(offered.sweepTxHex).to.equal(undefined);
	});

	it('keeps a held timeout non-final when a peer spend reorgs', function () {
		const fixture = currentPeerHtlc(HtlcDirection.OFFERED);
		fixture.monitor.handleFundingSpent(fixture.commitment, CONFIRMATION_HEIGHT);
		const offered = htlcOutput(fixture.monitor, OutputType.OFFERED_HTLC);
		fixture.monitor.updateFeeRate(CALM_SAT_PER_KW);
		const heldHex = offered.sweepTxHex!;
		expect(offered.maturityHeight).to.equal(CLTV_EXPIRY);

		const peerClaim = peerSpend(
			offered,
			fixture.destinationScript,
			fixture.preimage
		);
		fixture.monitor.handleOutputSpent(
			offered.txid,
			offered.outputIndex,
			peerClaim,
			CONFIRMATION_HEIGHT + 5
		);
		const reorg = fixture.monitor.handleSpendUnconfirmed(
			offered.txid,
			offered.outputIndex
		);

		expect(
			broadcasts(reorg).some((tx) => spends(tx, offered)),
			'an immature timeout is not broadcast during reorg recovery'
		).to.equal(false);
		expect(offered.status).to.equal(OutputStatus.CONFIRMED);
		expect(offered.sweepTxHex).to.equal(heldHex);
		expect(offered.maturityHeight).to.equal(CLTV_EXPIRY);
		expect(
			broadcasts(fixture.monitor.handleNewBlock(CLTV_EXPIRY - 1)).some((tx) =>
				spends(tx, offered)
			)
		).to.equal(false);
		const released = broadcasts(
			fixture.monitor.handleNewBlock(CLTV_EXPIRY)
		).find((tx) => spends(tx, offered));
		expect(released, 'the recovered timeout releases at CLTV').to.exist;
		expect(released!.toHex()).to.equal(heldHex);
	});

	it('rebuilds a held timeout for a new destination', function () {
		const fixture = currentPeerHtlc(HtlcDirection.OFFERED);
		fixture.monitor.handleFundingSpent(fixture.commitment, CONFIRMATION_HEIGHT);
		const offered = htlcOutput(fixture.monitor, OutputType.OFFERED_HTLC);
		fixture.monitor.updateFeeRate(CALM_SAT_PER_KW);
		const oldHex = offered.sweepTxHex!;
		const oldTimeout = bitcoin.Transaction.fromHex(oldHex);
		const newDestination = bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(Buffer.alloc(32, 0x61)),
			network
		}).output!;

		fixture.monitor.setDestinationScript(newDestination);
		const rebuiltHex = offered.sweepTxHex!;
		const rebuilt = bitcoin.Transaction.fromHex(rebuiltHex);
		expect(rebuiltHex).to.not.equal(oldHex);
		expect(
			oldTimeout.outs[0].script.equals(fixture.destinationScript)
		).to.equal(true);
		expect(rebuilt.outs[0].script.equals(newDestination)).to.equal(true);
		expect(spends(rebuilt, offered)).to.equal(true);
		expect(rebuilt.locktime).to.equal(CLTV_EXPIRY);
		expect(rebuilt.ins[0].sequence).to.equal(0xfffffffd);
		expect(rebuilt.ins[0].witness).to.have.length(3);
		expect(offered.maturityHeight).to.equal(CLTV_EXPIRY);

		const released = broadcasts(
			fixture.monitor.handleNewBlock(CLTV_EXPIRY)
		).find((tx) => spends(tx, offered));
		expect(released, 'the redirected timeout releases at CLTV').to.exist;
		expect(released!.toHex()).to.equal(rebuiltHex);
	});

	it('refreshes a held timeout when fees rise before CLTV', function () {
		const fixture = currentPeerHtlc(HtlcDirection.OFFERED);
		fixture.monitor.handleFundingSpent(fixture.commitment, CONFIRMATION_HEIGHT);
		const offered = htlcOutput(fixture.monitor, OutputType.OFFERED_HTLC);
		fixture.monitor.updateFeeRate(CALM_SAT_PER_KW);
		const calmHex = offered.sweepTxHex!;
		const calmTx = bitcoin.Transaction.fromHex(calmHex);
		const calmFee =
			Number(offered.amount) -
			calmTx.outs.reduce((total, output) => total + output.value, 0);

		const refresh = fixture.monitor.updateFeeRate(RISING_SAT_PER_KW);
		expect(
			broadcasts(refresh).some((tx) => spends(tx, offered)),
			'the refreshed timeout remains held before CLTV'
		).to.equal(false);
		const refreshedHex = offered.sweepTxHex!;
		const refreshed = bitcoin.Transaction.fromHex(refreshedHex);
		const refreshedFee =
			Number(offered.amount) -
			refreshed.outs.reduce((total, output) => total + output.value, 0);

		expect(refreshedHex).to.not.equal(calmHex);
		expect(refreshedFee).to.be.greaterThan(calmFee);
		expect(spends(refreshed, offered)).to.equal(true);
		expect(refreshed.locktime).to.equal(CLTV_EXPIRY);
		expect(refreshed.ins[0].sequence).to.equal(0xfffffffd);
		expect(refreshed.ins[0].witness).to.have.length(3);
		expect(offered.status).to.equal(OutputStatus.CONFIRMED);
		expect(offered.maturityHeight).to.equal(CLTV_EXPIRY);

		const released = broadcasts(
			fixture.monitor.handleNewBlock(CLTV_EXPIRY)
		).find((tx) => spends(tx, offered));
		expect(released, 'the refreshed timeout releases at CLTV').to.exist;
		expect(released!.toHex()).to.equal(refreshedHex);
	});

	it('retries an uneconomic taproot offered HTLC timeout claim', function () {
		const fixture = currentPeerHtlc(HtlcDirection.OFFERED, {
			taproot: true
		});
		const opening = fixture.monitor.handleFundingSpent(
			fixture.commitment,
			CONFIRMATION_HEIGHT
		);
		const offered = htlcOutput(fixture.monitor, OutputType.OFFERED_HTLC);

		expect(offered.sweepTxHex).to.equal(undefined);
		expect(skippedFor(opening, offered)).to.have.length(1);
		expect(
			broadcasts(fixture.monitor.updateFeeRate(CALM_SAT_PER_KW)).some((tx) =>
				spends(tx, offered)
			),
			'the taproot timeout remains held before CLTV'
		).to.equal(false);

		const held = htlcOutput(fixture.monitor, OutputType.OFFERED_HTLC);
		expect(held.maturityHeight).to.equal(CLTV_EXPIRY);
		expect(held.sweepTxHex).to.be.a('string');
		const timeout = bitcoin.Transaction.fromHex(held.sweepTxHex!);
		expect(timeout.locktime).to.equal(CLTV_EXPIRY);
		expect(timeout.ins[0].sequence).to.equal(1);
		expect(timeout.ins[0].witness.length).to.be.greaterThan(0);
		expect(timeout.outs[0].script.equals(fixture.destinationScript)).to.equal(
			true
		);

		const released = broadcasts(
			fixture.monitor.handleNewBlock(CLTV_EXPIRY)
		).find((tx) => spends(tx, held));
		expect(released, 'the taproot timeout releases at CLTV').to.exist;
		expect(released!.toHex()).to.equal(timeout.toHex());
	});
});
