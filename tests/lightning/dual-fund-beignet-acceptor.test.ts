/**
 * beignet-to-beignet dual-funded (v2) open, end to end at the ChannelManager
 * level: opener auto-funded from a funding provider, acceptor a PLAIN
 * zero-contribution beignet peer (no lease, no liquidity ads).
 *
 * Two bugs live here, both observed live between two beignet daemons:
 *
 * 1) DEADLOCK: a plain acceptor never registered an interactive-tx
 *    contribution, so _driveDualFunding was a no-op on every one of its turns
 *    and it never sent tx_complete. The opener waited forever; both sides sat
 *    in DUAL_FUNDING_V2 with no funding tx ever negotiated. CLN acceptors
 *    reply on their own, so the CLN interop suite never caught it — only a
 *    beignet-to-beignet open hit it.
 *
 * 2) MAX FUNDING: openChannel(..., fundMax) refused v2 peers outright. It now
 *    commits the funding provider's quoteDualFundingMax amount and funds by
 *    contributing every spendable UTXO, netting change out to exactly zero.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	Channel,
	ISpliceWalletInput
} from '../../src/lightning/channel/channel';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import { decodeAcceptChannel2Message } from '../../src/lightning/message/dual-funding';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	spliceFeeSats,
	dualFundingContributionWeight
} from '../../src/lightning/channel/splice-weight';
import { IFundingProvider } from '../../src/lightning/node/types';

// ─────────────── Helpers ───────────────

interface ISide {
	pubkey: string;
	config: {
		localBasepoints: IChannelBasepoints;
		localPerCommitmentSeed: Buffer;
		localFundingPrivkey: Buffer;
		htlcBasepointSecret: Buffer;
	};
}

/** Key material whose funding pubkey and per-commitment points are REAL, so
 *  the commitment_signed exchange verifies on both sides. */
function makeSide(): ISide {
	const fundingPriv = crypto.randomBytes(32);
	const seed = crypto.randomBytes(32);
	const basepoints: IChannelBasepoints = {
		fundingPubkey: getPublicKey(fundingPriv),
		revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
		paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
		firstPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(seed, MAX_INDEX)
		)
	};
	return {
		pubkey: getPublicKey(crypto.randomBytes(32)).toString('hex'),
		config: {
			localBasepoints: basepoints,
			localPerCommitmentSeed: seed,
			localFundingPrivkey: fundingPriv,
			htlcBasepointSecret: crypto.randomBytes(32)
		}
	};
}

/** A real spendable P2WPKH UTXO with a working witness-signing closure. */
function makeWalletInput(valueSats: number): ISpliceWalletInput {
	const priv = crypto.randomBytes(32);
	const pub = getPublicKey(priv);
	const payment = bitcoin.payments.p2wpkh({ pubkey: pub });
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(payment.output!, valueSats);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output!;
	return {
		prevTx: prevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(valueSats),
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value): Buffer[] => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				scriptCode,
				Number(value),
				bitcoin.Transaction.SIGHASH_ALL
			);
			const der = bitcoin.script.signature.encode(
				Buffer.from(ecc.sign(sighash, priv)),
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [der, pub];
		}
	};
}

function openerParams(
	side: ISide,
	overrides?: Partial<IDualFundingParams>
): IDualFundingParams {
	return {
		fundingSatoshis: 150_000n,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 253,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		locktime: 0,
		localBasepoints: side.config.localBasepoints,
		localPerCommitmentSeed: side.config.localPerCommitmentSeed,
		secondPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(side.config.localPerCommitmentSeed, MAX_INDEX - 1n)
		),
		...overrides
	};
}

/** Wait until pred() holds, yielding to pending promise callbacks (the
 *  funding provider's async selection) between checks. */
async function settle(pred: () => boolean, ms = 2000): Promise<void> {
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		if (pred()) return;
		await new Promise((resolve) => setImmediate(resolve));
	}
}

interface IHarness {
	mgrA: ChannelManager;
	mgrB: ChannelManager;
	errors: string[];
	broadcasts: Buffer[];
	sideA: ISide;
	sideB: ISide;
}

function makeHarness(walletInput: ISpliceWalletInput): IHarness {
	const sideA = makeSide();
	const sideB = makeSide();
	const mgrA = new ChannelManager(sideA.config);
	const mgrB = new ChannelManager(sideB.config);

	const errors: string[] = [];
	mgrA.on('error', (_id: Buffer | null, msg: string) =>
		errors.push(`A: ${msg}`)
	);
	mgrB.on('error', (_id: Buffer | null, msg: string) =>
		errors.push(`B: ${msg}`)
	);

	const broadcasts: Buffer[] = [];
	mgrA.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
	mgrB.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

	// Wire the two managers directly to each other, the transport a real
	// beignet-to-beignet TCP session provides.
	mgrA.on('message:outbound', (_peer: string, type: number, payload: Buffer) =>
		mgrB.handleMessage(sideA.pubkey, type, payload)
	);
	mgrB.on('message:outbound', (_peer: string, type: number, payload: Buffer) =>
		mgrA.handleMessage(sideB.pubkey, type, payload)
	);

	const changeScript = bitcoin.payments.p2wpkh({
		hash: crypto.randomBytes(20)
	}).output!;
	const fundingProvider: IFundingProvider = {
		buildFundingTransaction: async () => {
			throw new Error('v1 funding must not run for a v2 open');
		},
		broadcastTransaction: async () => 'unused',
		selectSpliceInputs: async () => ({
			inputs: [walletInput],
			changeScript
		}),
		selectMaxDualFundingInputs: async () => ({
			inputs: [walletInput],
			changeScript
		})
	};
	mgrA.setFundingProvider(fundingProvider);

	return { mgrA, mgrB, errors, broadcasts, sideA, sideB };
}

function acceptorChannel(h: IHarness): Channel | undefined {
	return h.mgrB.listChannels()[0];
}

const WALLET_UTXO_SATS = 200_000;
const FEERATE_PERKW = 1000;

describe('beignet-to-beignet v2 open (plain acceptor, auto-funded opener)', function () {
	this.timeout(10_000);

	it('a plain zero-contribution acceptor completes the negotiation (no deadlock)', async function () {
		const h = makeHarness(makeWalletInput(WALLET_UTXO_SATS));
		const chA = h.mgrA.createDualFundedChannel(
			h.sideB.pubkey,
			openerParams(h.sideA)
		);

		await settle(
			() => chA.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		expect(h.errors, 'no negotiation errors').to.deep.equal([]);
		// Before the fix the acceptor never sent tx_complete and both sides sat
		// in DUAL_FUNDING_V2 forever.
		expect(chA.getState(), 'opener past negotiation').to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		const chB = acceptorChannel(h);
		expect(chB, 'acceptor has the channel').to.exist;
		expect(chB!.getState(), 'acceptor past negotiation').to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		// The negotiated funding tx exists and pays the committed capacity, with
		// the opener's change output alongside it (fixed-amount open).
		expect(h.broadcasts.length, 'funding tx broadcast').to.be.greaterThan(0);
		const fundingTx = bitcoin.Transaction.fromBuffer(h.broadcasts[0]);
		const values = fundingTx.outs.map((o) => o.value).sort((a, b) => a - b);
		expect(values).to.include(150_000);
		expect(fundingTx.outs.length, 'funding output + change').to.equal(2);
	});

	it('a max open commits the v2 quote and funds with zero change', async function () {
		const h = makeHarness(makeWalletInput(WALLET_UTXO_SATS));
		// The quote the funding provider derives for one input as initiator —
		// the amount LightningNode.openChannel(fundMax) commits.
		const feeSats = spliceFeeSats(
			dualFundingContributionWeight(1, true),
			FEERATE_PERKW
		);
		const maxFunding = BigInt(WALLET_UTXO_SATS) - feeSats;

		const chA = h.mgrA.createDualFundedChannel(
			h.sideB.pubkey,
			openerParams(h.sideA, { fundingSatoshis: maxFunding, fundMax: true })
		);

		await settle(
			() => chA.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		expect(h.errors, 'no negotiation errors').to.deep.equal([]);
		expect(chA.getState()).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
		expect(acceptorChannel(h)!.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		// The whole balance minus the fee went into the funding output and the
		// change netted out to exactly zero: one output, no change.
		expect(h.broadcasts.length, 'funding tx broadcast').to.be.greaterThan(0);
		const fundingTx = bitcoin.Transaction.fromBuffer(h.broadcasts[0]);
		expect(fundingTx.outs.length, 'no change output on a max open').to.equal(1);
		expect(BigInt(fundingTx.outs[0].value)).to.equal(maxFunding);
	});

	it('an underfunded max contribution aborts cleanly instead of stalling', async function () {
		const h = makeHarness(makeWalletInput(WALLET_UTXO_SATS));
		// Committed amount above what the wallet inputs can fund alongside the
		// fee (the balance shrank between quote and funding).
		const chA = h.mgrA.createDualFundedChannel(
			h.sideB.pubkey,
			openerParams(h.sideA, {
				fundingSatoshis: BigInt(WALLET_UTXO_SATS),
				fundMax: true
			})
		);

		await settle(() => h.errors.length > 0);

		expect(
			h.errors.some((e) => /underfunded/i.test(e)),
			`underfunded abort reported (got: ${h.errors.join(' | ')})`
		).to.equal(true);
		expect(chA.getState()).to.not.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});
});

describe('trusted zero-conf v2 open (dual-funded)', function () {
	this.timeout(10_000);

	it('mutual trust: zero_conf channel type negotiates and both sides reach NORMAL unconfirmed', async function () {
		const h = makeHarness(makeWalletInput(WALLET_UTXO_SATS));
		h.mgrA.addTrustedPeer(h.sideB.pubkey);
		h.mgrB.addTrustedPeer(h.sideA.pubkey);

		const chA = h.mgrA.createDualFundedChannel(
			h.sideB.pubkey,
			openerParams(h.sideA),
			{ trusted: true }
		);

		// NORMAL without any funding confirmation on either side: tx_signatures
		// alone brought the channel up (zero-conf fast-track).
		await settle(() => chA.getState() === ChannelState.NORMAL);

		expect(h.errors, 'no negotiation errors').to.deep.equal([]);
		expect(chA.getState()).to.equal(ChannelState.NORMAL);
		const chB = acceptorChannel(h);
		expect(chB, 'acceptor has the channel').to.exist;
		expect(chB!.getState()).to.equal(ChannelState.NORMAL);

		// Both sides negotiated the zero_conf channel type (with its BOLT 9
		// scid_alias dependency) and a 0 depth, and the channel is private:
		// BOLT 2 forbids announcing a type that carries option_scid_alias.
		for (const ch of [chA, chB!]) {
			const st = ch.getFullState();
			expect(st.minimumDepth).to.equal(0);
			expect(st.channelType, 'channel type recorded').to.exist;
			const bits = FeatureFlags.fromBuffer(st.channelType!);
			expect(bits.hasFeature(Feature.ZERO_CONF)).to.equal(true);
			expect(bits.hasFeature(Feature.SCID_ALIAS)).to.equal(true);
			expect(st.announceChannel).to.equal(false);
		}
	});

	it('the accept_channel2 advertises minimum_depth 0 on a zero_conf open', async function () {
		const h = makeHarness(makeWalletInput(WALLET_UTXO_SATS));
		h.mgrA.addTrustedPeer(h.sideB.pubkey);
		h.mgrB.addTrustedPeer(h.sideA.pubkey);

		let acceptDepth: number | null = null;
		h.mgrB.on(
			'message:outbound',
			(_peer: string, type: number, payload: Buffer) => {
				// 65 = accept_channel2
				if (type === 65) {
					acceptDepth = decodeAcceptChannel2Message(payload).minimumDepth;
				}
			}
		);

		const chA = h.mgrA.createDualFundedChannel(
			h.sideB.pubkey,
			openerParams(h.sideA),
			{ trusted: true }
		);
		await settle(() => chA.getState() === ChannelState.NORMAL);

		expect(acceptDepth, 'accept_channel2 observed').to.not.be.null;
		expect(acceptDepth).to.equal(0);
	});

	it('an untrusted acceptor rejects the zero_conf v2 proposal', async function () {
		const h = makeHarness(makeWalletInput(WALLET_UTXO_SATS));
		// Only the opener declares trust.
		h.mgrA.addTrustedPeer(h.sideB.pubkey);

		const chA = h.mgrA.createDualFundedChannel(
			h.sideB.pubkey,
			openerParams(h.sideA),
			{ trusted: true }
		);

		await settle(() => h.errors.length > 0);
		expect(h.errors.some((e) => /trusted peer/.test(e))).to.equal(true);
		expect(chA.getState()).to.not.equal(ChannelState.NORMAL);
	});

	it('a trusted open toward an untrusted-by-us peer throws up front', function () {
		const h = makeHarness(makeWalletInput(WALLET_UTXO_SATS));
		expect(() =>
			h.mgrA.createDualFundedChannel(h.sideB.pubkey, openerParams(h.sideA), {
				trusted: true
			})
		).to.throw('not in the trusted set');
	});

	it('a plain v2 open between trusted peers stays confirmation-gated', async function () {
		// Trust-set membership alone must not fast-track an ordinary open.
		const h = makeHarness(makeWalletInput(WALLET_UTXO_SATS));
		h.mgrA.addTrustedPeer(h.sideB.pubkey);
		h.mgrB.addTrustedPeer(h.sideA.pubkey);

		const chA = h.mgrA.createDualFundedChannel(
			h.sideB.pubkey,
			openerParams(h.sideA)
		);
		await settle(
			() => chA.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		expect(h.errors, 'no negotiation errors').to.deep.equal([]);
		expect(chA.getState()).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
		expect(acceptorChannel(h)!.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});
});
