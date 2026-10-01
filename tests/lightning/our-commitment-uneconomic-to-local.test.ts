/**
 * Our own force-closed commitment carrying a to_local too small to pay its
 * sweep fee (issue #1015).
 *
 * The witness-v0 to_local sweep used to throw out of resolveOurCommitmentOutputs,
 * and the throw discarded every HTLC-success, HTLC-timeout and watch built for
 * the same commitment. The CSV output of our own second-level HTLC tx had the
 * same throw. A priced-out output must stay tracked and be swept once fees fall.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { buildLocalCommitment } from '../../src/lightning/channel/commitment-builder';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	ChainAction,
	ChainActionType,
	ITrackedOutput,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { setupNormalChannels } from './helpers/revoked-commitment-fixture';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;
const CONFIRMATION_HEIGHT = 100;
const CLTV_EXPIRY = 600;
// Leaves a 774-sat to_local after the opener pays the commitment fee: above
// the dust limit, below the ~1130-sat sweep fee at the watcher's default rate.
const LOCAL_BALANCE_SATS = 1_000n;
const SPIKE_SAT_PER_VBYTE = 10;
const CALM_SAT_PER_KW = 250;

interface IOurCommitmentFixture {
	monitor: ChainMonitor;
	commitment: bitcoin.Transaction;
	state: IChannelState;
	openerPrivkeys: Buffer[];
	destinationScript: Buffer;
}

function ourCommitmentWithReceivedHtlc(
	htlcSats: bigint
): IOurCommitmentFixture {
	const { opener, openerPrivkeys } = setupNormalChannels();
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	opener.handleUpdateAddHtlc({
		channelId: opener.getChannelId()!,
		id: 0n,
		amountMsat: htlcSats * 1000n,
		paymentHash,
		cltvExpiry: CLTV_EXPIRY,
		onionRoutingPacket: Buffer.alloc(1366)
	});

	const state = opener.getFullState();
	state.localBalanceMsat = LOCAL_BALANCE_SATS * 1000n;
	// The monitor does not verify the peer's HTLC signature, only needs one to
	// build the HTLC-success witness.
	state.remoteHtlcSignatures = [Buffer.alloc(64, 0x42)];
	const point = perCommitmentPointFromSecret(
		generateFromSeed(
			state.localPerCommitmentSeed,
			MAX_INDEX - state.localCommitmentNumber
		)
	);
	const commitment = buildLocalCommitment(state, point).result.tx;
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
	monitor.addPreimage(paymentHash, preimage);

	return { monitor, commitment, state, openerPrivkeys, destinationScript };
}

function tracked(
	monitor: ChainMonitor,
	outputType: OutputType
): ITrackedOutput {
	const output = monitor
		.getTrackedOutputs()
		.find((candidate) => candidate.outputType === outputType);
	expect(output, `${outputType} output tracked`).to.exist;
	return output!;
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

function uneconomicFor(
	actions: ChainAction[],
	output: ITrackedOutput,
	reason: 'skipped' | 'contested'
): ChainAction[] {
	return actions.filter(
		(action) =>
			action.type === ChainActionType.SWEEP_UNECONOMIC &&
			action.reason === reason &&
			action.txid === output.txid &&
			action.outputIndex === output.outputIndex
	);
}

function watches(actions: ChainAction[], output: ITrackedOutput): boolean {
	return actions.some(
		(action) =>
			action.type === ChainActionType.WATCH_OUTPUT &&
			action.txid === output.txid &&
			action.outputIndex === output.outputIndex
	);
}

describe('Uneconomic to_local on our own commitment (#1015)', function () {
	it('still builds the HTLC-success and watches every output', function () {
		const fixture = ourCommitmentWithReceivedHtlc(100_000n);
		let opening: ChainAction[] = [];

		expect(() => {
			opening = fixture.monitor.handleFundingSpent(
				fixture.commitment,
				CONFIRMATION_HEIGHT
			);
		}, 'an uneconomic to_local must not escape the resolver').to.not.throw();

		const toLocal = tracked(fixture.monitor, OutputType.TO_LOCAL);
		const received = tracked(fixture.monitor, OutputType.RECEIVED_HTLC);
		expect(toLocal.amount).to.equal(774n);
		expect(received.amount).to.equal(100_000n);

		const success = broadcasts(opening).find((tx) => spends(tx, received));
		expect(success, 'the HTLC-success is broadcast').to.exist;
		expect(received.status).to.equal(OutputStatus.SPEND_BROADCAST);
		for (const output of fixture.monitor.getTrackedOutputs()) {
			expect(watches(opening, output), `${output.outputType} watched`).to.equal(
				true
			);
		}

		expect(toLocal.status).to.equal(OutputStatus.CONFIRMED);
		expect(toLocal.sweepTxHex).to.equal(undefined);
		const skipped = uneconomicFor(opening, toLocal, 'skipped');
		expect(skipped).to.have.length(1);
		const report = skipped[0];
		if (report.type === ChainActionType.SWEEP_UNECONOMIC) {
			expect(
				report.contestHeight,
				'nothing competes for our to_local'
			).to.equal(undefined);
		}
	});

	it('sweeps the declined to_local once fees fall, without a contest report', function () {
		const fixture = ourCommitmentWithReceivedHtlc(100_000n);
		fixture.monitor.handleFundingSpent(fixture.commitment, CONFIRMATION_HEIGHT);
		const toLocal = tracked(fixture.monitor, OutputType.TO_LOCAL);
		const csvMaturity =
			CONFIRMATION_HEIGHT + fixture.state.remoteConfig.toSelfDelay;

		const mature = fixture.monitor.handleNewBlock(csvMaturity);
		expect(uneconomicFor(mature, toLocal, 'contested')).to.have.length(0);
		expect(uneconomicFor(mature, toLocal, 'skipped')).to.have.length(0);
		expect(toLocal.sweepTxHex, 'still priced out').to.equal(undefined);

		const retry = broadcasts(fixture.monitor.updateFeeRate(CALM_SAT_PER_KW));
		const sweep = retry.find((tx) => spends(tx, toLocal));
		expect(sweep, 'the fee drop sweeps the matured to_local').to.exist;
		expect(sweep!.ins[0].sequence).to.equal(
			fixture.state.remoteConfig.toSelfDelay
		);
		expect(sweep!.ins[0].witness).to.have.length(3);
		expect(sweep!.outs[0].script.equals(fixture.destinationScript)).to.equal(
			true
		);
		expect(toLocal.status).to.equal(OutputStatus.SPEND_BROADCAST);
	});

	it('retries the declined to_local from a new block', function () {
		const fixture = ourCommitmentWithReceivedHtlc(100_000n);
		fixture.monitor.handleFundingSpent(fixture.commitment, CONFIRMATION_HEIGHT);

		// Restart with a calmer estimate: the block path, not updateFeeRate, must
		// revisit the declined sweep.
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
		const retried = restored.handleNewBlock(CONFIRMATION_HEIGHT + 1);
		const toLocal = tracked(restored, OutputType.TO_LOCAL);
		expect(
			broadcasts(retried).some((tx) => spends(tx, toLocal)),
			'the sweep is held until its CSV matures'
		).to.equal(false);
		expect(toLocal.sweepTxHex).to.be.a('string');
		expect(toLocal.maturityHeight).to.equal(
			CONFIRMATION_HEIGHT + fixture.state.remoteConfig.toSelfDelay
		);
	});

	it('tracks, watches and later sweeps a priced-out second-level HTLC output', function () {
		// Small enough that its HTLC-success output is below the CSV sweep fee.
		const fixture = ourCommitmentWithReceivedHtlc(1_200n);
		fixture.monitor.handleFundingSpent(fixture.commitment, CONFIRMATION_HEIGHT);
		const received = tracked(fixture.monitor, OutputType.RECEIVED_HTLC);
		expect(received.sweepTxHex, 'HTLC-success built').to.be.a('string');
		const success = bitcoin.Transaction.fromHex(received.sweepTxHex!);
		const successHeight = CONFIRMATION_HEIGHT + 1;

		let spent: ChainAction[] = [];
		expect(() => {
			spent = fixture.monitor.handleOutputSpent(
				received.txid,
				received.outputIndex,
				success,
				successHeight
			);
		}, 'an uneconomic second-level sweep must not escape').to.not.throw();

		const secondLevel = fixture.monitor
			.getTrackedOutputs()
			.find((o) => o.txid === success.getId() && o.outputIndex === 0);
		expect(secondLevel, 'the second-level output is tracked').to.exist;
		expect(secondLevel!.status).to.equal(OutputStatus.CONFIRMED);
		expect(secondLevel!.sweepTxHex).to.equal(undefined);
		expect(watches(spent, secondLevel!), 'and watched').to.equal(true);
		expect(uneconomicFor(spent, secondLevel!, 'skipped')).to.have.length(1);

		fixture.monitor.updateFeeRate(CALM_SAT_PER_KW);
		expect(secondLevel!.sweepTxHex, 'the fee drop builds its sweep').to.be.a(
			'string'
		);
		const sweep = bitcoin.Transaction.fromHex(secondLevel!.sweepTxHex!);
		expect(spends(sweep, secondLevel!)).to.equal(true);
		expect(sweep.outs[0].script.equals(fixture.destinationScript)).to.equal(
			true
		);
		const maturity = successHeight + fixture.state.remoteConfig.toSelfDelay;
		expect(secondLevel!.maturityHeight).to.equal(maturity);
		const released = broadcasts(fixture.monitor.handleNewBlock(maturity)).find(
			(tx) => spends(tx, secondLevel!)
		);
		expect(released, 'the held sweep releases at CSV maturity').to.exist;
	});
});
