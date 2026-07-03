/**
 * Fractional-msat HTLC removal: the two sides of a removal round must sign
 * IDENTICAL commitments while a fulfilled/failed HTLC is in flight.
 *
 * The commitment builder adjusts balances for FULFILLED/FAILED HTLCs whose
 * refund/credit has not yet been finalized by revoke_and_ack. Flooring the
 * HTLC amount to whole satoshis SEPARATELY from the (already floored) balance
 * diverges by 1 sat from the finalized computation, which floors the msat SUM
 * (balance + amount): the divergence hits whenever a fractional-msat amount
 * rejoins a balance carrying the matching sub-satoshi residue.
 *
 * Concretely: A offers 999,999 msat (A's balance now ...000,001 msat); B fails
 * it; during the removal round one side computes A's output as
 * floor(balance) + floor(999,999 msat) = X sat while the other (post-cleanup)
 * computes floor(balance + 999,999 msat) = X + 1 sat, and rejects the
 * commitment signature ("Invalid commitment signature") — a failed
 * non-whole-satoshi HTLC desyncs the channel into force-close territory.
 *
 * The fulfill direction has the same defect one layer deeper: the credit
 * lands on the fulfiller's balance, so a SINGLE fractional fulfill is clean
 * (that balance has no residue yet) but the SECOND one desyncs once the first
 * left a residue behind.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

function makeConfig(name: string): IChannelManagerConfig {
	const seed = sha256(Buffer.from(`frac-htlc-${name}`));
	const k = (i: number): Buffer =>
		sha256(Buffer.concat([seed, Buffer.from([i])]));
	const basepoints: IChannelBasepoints = {
		fundingPubkey: getPublicKey(k(0)),
		revocationBasepoint: getPublicKey(k(1)),
		paymentBasepoint: getPublicKey(k(2)),
		delayedPaymentBasepoint: getPublicKey(k(3)),
		htlcBasepoint: getPublicKey(k(4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: basepoints,
		localPerCommitmentSeed: sha256(Buffer.from(`${name}-commit`)),
		localFundingPrivkey: k(0),
		htlcBasepointSecret: k(4),
		nodePrivateKey: sha256(Buffer.from(`${name}-node`)),
		preferAnchors: true
	};
}

const FUNDING_SATOSHIS = 1_000_000n;

interface IPair {
	a: ChannelManager;
	b: ChannelManager;
	channelId: Buffer;
	errors: string[];
	failed: bigint[];
	fulfilled: Buffer[];
	aBalance: () => bigint;
	bBalance: () => bigint;
	bHtlcId: (paymentHash: Buffer) => bigint;
}

/** Two managers, one funded channel A -> B, synchronous loopback. */
function makePair(tag: string): IPair {
	const aConfig = makeConfig(`${tag}-A`);
	const bConfig = makeConfig(`${tag}-B`);
	const aPub = getPublicKey(aConfig.nodePrivateKey!).toString('hex');
	const bPub = getPublicKey(bConfig.nodePrivateKey!).toString('hex');
	const a = new ChannelManager(aConfig);
	const b = new ChannelManager(bConfig);
	const errors: string[] = [];
	a.on('error', (_id, m: string) => errors.push(`A: ${m}`));
	b.on('error', (_id, m: string) => errors.push(`B: ${m}`));
	const failed: bigint[] = [];
	const fulfilled: Buffer[] = [];
	a.on('htlc:failed', (_c, id: bigint) => failed.push(id));
	a.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
		fulfilled.push(preimage)
	);
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === bPub) b.handleMessage(aPub, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === aPub) a.handleMessage(bPub, type, payload);
	});

	const aChannel = a.openChannel(bPub, FUNDING_SATOSHIS);
	a.createFunding(aChannel, crypto.randomBytes(32), 0, crypto.randomBytes(64));
	const channelId = aChannel.getChannelId()!;
	a.handleFundingConfirmed(channelId);
	b.handleFundingConfirmed(channelId);
	const bChannel = b.getChannelsByPeer(aPub)[0];
	expect(aChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(bChannel.getState()).to.equal(ChannelState.NORMAL);

	return {
		a,
		b,
		channelId,
		errors,
		failed,
		fulfilled,
		aBalance: (): bigint => aChannel.getBalances().localMsat,
		bBalance: (): bigint => bChannel.getBalances().localMsat,
		bHtlcId: (paymentHash: Buffer): bigint =>
			[...bChannel.getFullState().htlcs.values()].find((h) =>
				h.paymentHash.equals(paymentHash)
			)!.id
	};
}

const CAPACITY_MSAT = FUNDING_SATOSHIS * 1000n;

describe('fractional-msat HTLC removal (commitment parity)', function () {
	it('failing a fractional-msat HTLC completes the removal round cleanly', function () {
		const t = makePair('fail-frac');
		const hash = sha256(crypto.randomBytes(32));
		t.a.addHtlc(t.channelId, 999_999n, hash, 900, Buffer.alloc(1366));
		t.b.failHtlc(t.channelId, t.bHtlcId(hash), Buffer.from('no route'));
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.failed).to.have.length(1);
		// The refund is exact: A is made whole to the msat.
		expect(t.aBalance()).to.equal(CAPACITY_MSAT);
		expect(t.bBalance()).to.equal(0n);
		// The channel is still usable: a follow-up payment settles.
		const preimage = crypto.randomBytes(32);
		t.a.addHtlc(
			t.channelId,
			2_000_500n,
			sha256(preimage),
			900,
			Buffer.alloc(1366)
		);
		t.b.fulfillHtlc(t.channelId, t.bHtlcId(sha256(preimage)), preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.aBalance()).to.equal(CAPACITY_MSAT - 2_000_500n);
		expect(t.bBalance()).to.equal(2_000_500n);
	});

	it('two sequential fractional-msat fulfills stay in sync (residue on the fulfiller)', function () {
		// The first fractional fulfill leaves a 999-msat residue on B; the
		// second one reunites a fractional amount with that residue — the
		// parts-vs-sum flooring divergence in the fulfill direction.
		const t = makePair('fulfill-frac');
		for (const amount of [1_500_999n, 1_500_999n]) {
			const preimage = crypto.randomBytes(32);
			const hash = sha256(preimage);
			t.a.addHtlc(t.channelId, amount, hash, 900, Buffer.alloc(1366));
			t.b.fulfillHtlc(t.channelId, t.bHtlcId(hash), preimage);
		}
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.fulfilled).to.have.length(2);
		expect(t.bBalance()).to.equal(2n * 1_500_999n);
		expect(t.aBalance()).to.equal(CAPACITY_MSAT - 2n * 1_500_999n);
	});

	it('failing a fractional-msat HTLC after a fractional balance already exists', function () {
		// A's balance already carries a residue (from a settled fractional
		// payment) when the failed HTLC's fractional refund rejoins it.
		const t = makePair('fail-frac-residue');
		const preimage = crypto.randomBytes(32);
		t.a.addHtlc(
			t.channelId,
			1_000_400n,
			sha256(preimage),
			900,
			Buffer.alloc(1366)
		);
		t.b.fulfillHtlc(t.channelId, t.bHtlcId(sha256(preimage)), preimage);
		const hash = sha256(crypto.randomBytes(32));
		t.a.addHtlc(t.channelId, 2_000_700n, hash, 900, Buffer.alloc(1366));
		t.b.failHtlc(t.channelId, t.bHtlcId(hash), Buffer.from('no'));
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.failed).to.have.length(1);
		expect(t.aBalance()).to.equal(CAPACITY_MSAT - 1_000_400n);
		expect(t.bBalance()).to.equal(1_000_400n);
	});

	it('whole-satoshi control: fail and fulfill both clean', function () {
		const t = makePair('whole-sat');
		const hash = sha256(crypto.randomBytes(32));
		t.a.addHtlc(t.channelId, 999_000n, hash, 900, Buffer.alloc(1366));
		t.b.failHtlc(t.channelId, t.bHtlcId(hash), Buffer.from('no'));
		const preimage = crypto.randomBytes(32);
		t.a.addHtlc(
			t.channelId,
			2_000_000n,
			sha256(preimage),
			900,
			Buffer.alloc(1366)
		);
		t.b.fulfillHtlc(t.channelId, t.bHtlcId(sha256(preimage)), preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.aBalance()).to.equal(CAPACITY_MSAT - 2_000_000n);
		expect(t.bBalance()).to.equal(2_000_000n);
	});

	it('single fractional-msat fulfill control: clean', function () {
		const t = makePair('fulfill-single');
		const preimage = crypto.randomBytes(32);
		t.a.addHtlc(
			t.channelId,
			999_999n,
			sha256(preimage),
			900,
			Buffer.alloc(1366)
		);
		t.b.fulfillHtlc(t.channelId, t.bHtlcId(sha256(preimage)), preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.bBalance()).to.equal(999_999n);
	});
});
