/**
 * FFOR M2 gate (spec §15.2) — variant-A settlement + reconciliation with
 * three in-process nodes over real channels:
 *
 *     payer P ── S (settlement peer) ── R (recipient, goes OFFLINE)
 *
 * The payer's payment COMPLETES (preimage received) while R is offline; S's
 * package is durably persisted; R reconnects → replay → reconcile → revoke
 * batch → ff_end → fulfills its vouchers; final balances on BOTH channels are
 * exact (amount − S's fee credited to R, fee retained by S) and the variant-A
 * H_1 binding (P_1 = per_commitment_secret_S[n0]) is observable by the payer.
 *
 * Also: multi-voucher settlement (exercising output-index htlc_sig order),
 * every §8 settlement rejection, duplicate-hash rejection, an S crash between
 * package-persist and upstream-fulfill (idempotent replay), and the escapes
 * bookkeeping (catch-up at n0+2 + n0+1 secret reveal).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MAX_INDEX } from '../../src/lightning/keys/shachain';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	FforEpochState,
	IFforEpochParams
} from '../../src/lightning/ffor/types';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

// ─────────────── Scaffolding ───────────────

function makeSeed(id: string): Buffer {
	return crypto.createHash('sha256').update(`ffor-m2-${id}`).digest();
}

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	htlcSecret: Buffer;
} {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		htlcSecret: keys[4]
	};
}

function makeConfig(name: string): IChannelManagerConfig {
	const seed = makeSeed(name);
	const { basepoints, htlcSecret } = makeBasepoints(seed);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: basepoints,
		localPerCommitmentSeed: makeSeed(name + '-commit'),
		localFundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: htlcSecret,
		nodePrivateKey: makeSeed(name + '-node'),
		preferAnchors: true
	};
}

interface ILink {
	down: () => void;
	up: () => void;
}

/** Loopback with a kill switch (simulates disconnects). */
function connect(
	a: ChannelManager,
	aPub: string,
	b: ChannelManager,
	bPub: string
): ILink {
	let connected = true;
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (connected && peer === bPub) b.handleMessage(aPub, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (connected && peer === aPub) a.handleMessage(bPub, type, payload);
	});
	return {
		down: (): void => {
			connected = false;
		},
		up: (): void => {
			connected = true;
		}
	};
}

const FUNDING_SATOSHIS = 1_000_000n;

function openChannel(
	openerMgr: ChannelManager,
	acceptorMgr: ChannelManager,
	openerPub: string,
	acceptorPub: string
): { openerChannel: Channel; acceptorChannel: Channel; channelId: Buffer } {
	const openerChannel = openerMgr.openChannel(acceptorPub, FUNDING_SATOSHIS);
	openerMgr.createFunding(
		openerChannel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	);
	const channelId = openerChannel.getChannelId()!;
	openerMgr.handleFundingConfirmed(channelId);
	acceptorMgr.handleFundingConfirmed(channelId);
	const acceptorChannel = acceptorMgr
		.getChannelsByPeer(openerPub)
		.find((c) => c.getChannelId()?.equals(channelId))!;
	expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
	return { openerChannel, acceptorChannel, channelId };
}

interface ITriple {
	pManager: ChannelManager;
	sManager: ChannelManager;
	rManager: ChannelManager;
	pPub: string;
	sPub: string;
	rPub: string;
	/** P–S channel (P is the opener/funder). */
	psChannelId: Buffer;
	pChannel: Channel; // P's side
	spChannel: Channel; // S's side of P–S
	/** S–R channel (S is the opener/funder — R's inbound liquidity). */
	srChannelId: Buffer;
	sChannel: Channel; // S's side
	rChannel: Channel; // R's side
	srLink: ILink;
	psLink: ILink;
	pErrors: string[];
	sErrors: string[];
	rErrors: string[];
	pFulfilled: Array<{ htlcId: bigint; preimage: Buffer }>;
	pFailed: bigint[];
	sConfig: IChannelManagerConfig;
	rConfig: IChannelManagerConfig;
	pConfig: IChannelManagerConfig;
}

let tripleId = 0;

function createTriple(): ITriple {
	tripleId++;
	const pConfig = makeConfig(`P-${tripleId}`);
	const sConfig = makeConfig(`S-${tripleId}`);
	const rConfig = makeConfig(`R-${tripleId}`);
	const pPub = getPublicKey(pConfig.nodePrivateKey!).toString('hex');
	const sPub = getPublicKey(sConfig.nodePrivateKey!).toString('hex');
	const rPub = getPublicKey(rConfig.nodePrivateKey!).toString('hex');

	const pManager = new ChannelManager(pConfig);
	const sManager = new ChannelManager(sConfig);
	const rManager = new ChannelManager(rConfig);
	const pErrors: string[] = [];
	const sErrors: string[] = [];
	const rErrors: string[] = [];
	pManager.on('error', (_id, m: string) => pErrors.push(m));
	sManager.on('error', (_id, m: string) => sErrors.push(m));
	rManager.on('error', (_id, m: string) => rErrors.push(m));

	const pFulfilled: Array<{ htlcId: bigint; preimage: Buffer }> = [];
	const pFailed: bigint[] = [];
	pManager.on('htlc:fulfilled', (_cid, htlcId: bigint, preimage: Buffer) => {
		pFulfilled.push({ htlcId, preimage });
	});
	pManager.on('htlc:failed', (_cid, htlcId: bigint) => {
		pFailed.push(htlcId);
	});

	const psLink = connect(pManager, pPub, sManager, sPub);
	const srLink = connect(sManager, sPub, rManager, rPub);

	const ps = openChannel(pManager, sManager, pPub, sPub);
	const sr = openChannel(sManager, rManager, sPub, rPub);

	return {
		pManager,
		sManager,
		rManager,
		pPub,
		sPub,
		rPub,
		psChannelId: ps.channelId,
		pChannel: ps.openerChannel,
		spChannel: ps.acceptorChannel,
		srChannelId: sr.channelId,
		sChannel: sr.openerChannel,
		rChannel: sr.acceptorChannel,
		srLink,
		psLink,
		pErrors,
		sErrors,
		rErrors,
		pFulfilled,
		pFailed,
		sConfig,
		rConfig,
		pConfig
	};
}

type ParamsInput = Omit<IFforEpochParams, 'rPerCommitmentPoints'> & {
	rPerCommitmentPoints?: Buffer[];
};

/** Variant A terms matching the Appendix A fee schedule. */
function paramsA(overrides?: Partial<ParamsInput>): ParamsInput {
	return {
		variant: 1,
		budgetMsat: 100_000_000n,
		maxPayments: 3,
		minPaymentMsat: 500_000n,
		settlementDeadline: 1000,
		voucherExpiry: 2008,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		escapeGranularityMsat: 0n,
		...overrides
	};
}

/** Take R offline: cut the S–R link and mark both sides disconnected. */
function goOffline(t: ITriple): void {
	t.srLink.down();
	t.sManager.handlePeerDisconnected(t.rPub);
	t.rManager.handlePeerDisconnected(t.sPub);
	expect(t.sChannel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
	expect(t.rChannel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
}

/**
 * Reconnect S–R and exchange channel_reestablish. S's reestablish is
 * delivered to R FIRST (models transport FIFO: S queues its reestablish
 * before any replayed packages), then R's to S — which triggers S's replay
 * and, synchronously through the loopback, the entire reconciliation flow.
 */
function reconnect(t: ITriple): void {
	t.srLink.up();
	const payloadOf = (
		actions: ReturnType<Channel['createReestablish']>
	): Buffer =>
		(
			actions.find((a) => a.type === ChannelActionType.SEND_MESSAGE) as {
				payload: Buffer;
			}
		).payload;
	const sRe = payloadOf(t.sChannel.createReestablish());
	const rRe = payloadOf(t.rChannel.createReestablish());
	t.rManager.handleMessage(t.sPub, MessageType.CHANNEL_REESTABLISH, sRe);
	t.sManager.handleMessage(t.rPub, MessageType.CHANNEL_REESTABLISH, rRe);
}

/** P pays a delegated invoice hash: add the HTLC and run the full dance. */
function pay(
	t: ITriple,
	hash: Buffer,
	amountMsat: bigint,
	cltvExpiry = 900
): void {
	t.pManager.addHtlc(
		t.psChannelId,
		amountMsat,
		hash,
		cltvExpiry,
		Buffer.alloc(1366)
	);
}

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

// ─────────────── Tests ───────────────

describe('FFOR M2: variant-A settlement + reconciliation', function () {
	it('M2 GATE: P pays offline R through S; R returns, reconciles, and converts vouchers to balance', function () {
		const t = createTriple();

		// R opens a variant-A epoch on the S–R channel and goes offline.
		const result = t.rManager.initiateFforEpoch(t.srChannelId, paramsA());
		expect(result.ok, t.rErrors.concat(t.sErrors).join('; ')).to.equal(true);
		const hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
		const sPointN0 = t.rChannel.getFullState().remoteCurrentPerCommitmentPoint!;
		goOffline(t);

		// Payment 1 (1,000,000 msat on H_1) COMPLETES for P while R is offline.
		pay(t, hashes[0], 1_000_000n);
		expect(t.pFulfilled, t.pErrors.concat(t.sErrors).join('; ')).to.have.length(
			1
		);
		// The preimage proves payment AND is S's revocation secret for n0 — the
		// §12.1 variant-A binding, visible to the payer.
		const p1 = t.pFulfilled[0].preimage;
		expect(sha256(p1).equals(hashes[0])).to.equal(true);
		expect(perCommitmentPointFromSecret(p1).equals(sPointN0)).to.equal(true);

		// S persisted the package before settling upstream.
		const sEpoch = t.sChannel.getFforEpoch()!;
		expect(sEpoch.lastSeq).to.equal(1);
		expect(sEpoch.packages).to.have.length(1);
		expect(sEpoch.upstreamFulfilled[0]).to.equal(true);

		// Payments 2 and 3 (Appendix A amounts — exercises the BOLT 3
		// output-index htlc_sig ordering: voucher 2 sorts before voucher 1).
		pay(t, hashes[1], 550_000n);
		pay(t, hashes[2], 50_000_000n);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(3);
		expect(sEpoch.lastSeq).to.equal(3);

		// A duplicate part on a consumed hash is failed upstream (§11.2).
		pay(t, hashes[0], 1_000_000n);
		expect(t.pFailed).to.have.length(1);
		expect(
			t.sErrors.some((e) => e.includes('duplicate delegated payment'))
		).to.equal(true);

		// Balances on P–S: P paid the full HTLC amounts; S holds them.
		const paidMsat = 1_000_000n + 550_000n + 50_000_000n; // 51,550,000
		expect(t.pChannel.getBalances().localMsat).to.equal(
			FUNDING_SATOSHIS * 1000n - paidMsat
		);
		expect(t.spChannel.getBalances().localMsat).to.equal(paidMsat);

		// R returns: reestablish → replay ×3 → reconcile → ack → revoke batch
		// → ff_end. Channel back to OPERATIONAL with 3 live voucher HTLCs.
		reconnect(t);
		const allErrors = t.rErrors.concat(t.sErrors).join('; ');
		expect(t.rChannel.getState(), allErrors).to.equal(ChannelState.NORMAL);
		expect(t.sChannel.getState(), allErrors).to.equal(ChannelState.NORMAL);
		expect(t.rChannel.getFforEpoch()!.state).to.equal(FforEpochState.FF_CLOSED);
		expect(t.sChannel.getFforEpoch()!.state).to.equal(FforEpochState.FF_CLOSED);
		expect(t.rChannel.getFullState().htlcs.size).to.equal(3);
		expect(t.sChannel.getFullState().htlcs.size).to.equal(3);

		// Commitment-number bookkeeping: R adopted C_3 (n_R + 3); S's catch-up
		// is at n0 + 1 (G = 0); S tracks R at n_R + 3.
		const rEpoch = t.rChannel.getFforEpoch()!;
		expect(t.rChannel.getCommitmentNumbers().local).to.equal(rEpoch.nR + 3n);
		expect(t.sChannel.getCommitmentNumbers().local).to.equal(
			rEpoch.sCommitmentNumber! + 1n
		);
		expect(t.sChannel.getCommitmentNumbers().remote).to.equal(rEpoch.nR + 3n);

		// R holds every preimage from the replayed packages.
		for (let k = 0; k < 3; k++) {
			expect(sha256(rEpoch.preimages[k]).equals(hashes[k])).to.equal(true);
		}
		// The n0 pre-revocation from package 1 is in R's shachain store.
		expect(
			t.rChannel
				.getFullState()
				.shaChainStore.getSecret(MAX_INDEX - rEpoch.sCommitmentNumber!)
		).to.not.equal(null);

		// §11.1 step 6: convert the vouchers to plain balance.
		const fulfill = t.rManager.fforFulfillVouchers(t.srChannelId);
		expect(fulfill.ok, t.rErrors.concat(t.sErrors).join('; ')).to.equal(true);
		expect(t.rChannel.getFullState().htlcs.size).to.equal(0);
		expect(t.sChannel.getFullState().htlcs.size).to.equal(0);

		// Final balances: v_k = amount − fee(amount); fee(a) = 1000 + 0.5% · a.
		// v = 994,000 + 546,250 + 49,749,000 = 51,289,250; S's skim = 260,750.
		const vSumMsat = 994_000n + 546_250n + 49_749_000n;
		expect(t.rChannel.getBalances().localMsat).to.equal(vSumMsat);
		expect(t.sChannel.getBalances().localMsat).to.equal(
			FUNDING_SATOSHIS * 1000n - vSumMsat
		);
		// S's total position: +51,550,000 on P–S, −51,289,250 on S–R = the fee.
		expect(paidMsat - vSumMsat).to.equal(260_750n);

		// The channel is fully OPERATIONAL again: a plain payment R→S works.
		const preimage = crypto.randomBytes(32);
		t.rManager.addHtlc(
			t.srChannelId,
			1_000_000n,
			sha256(preimage),
			900,
			Buffer.alloc(1366)
		);
		t.sManager.fulfillHtlc(
			t.srChannelId,
			t.rChannel.getFullState().localHtlcCounter - 1n,
			preimage
		);
		expect(t.rChannel.getBalances().localMsat).to.equal(vSumMsat - 1_000_000n);
	});

	// ─────────────── §8 settlement rejections ───────────────

	it('fails upstream: amount below min_payment_msat (hash stays consumable)', function () {
		const t = createTriple();
		expect(t.rManager.initiateFforEpoch(t.srChannelId, paramsA()).ok).to.equal(
			true
		);
		const hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
		goOffline(t);

		pay(t, hashes[0], 300_000n); // < min_payment 500,000
		expect(t.pFailed).to.have.length(1);
		expect(
			t.sErrors.some((e) => e.includes('below min_payment_msat'))
		).to.equal(true);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(0);

		// The hash was NOT consumed — a compliant retry settles.
		pay(t, hashes[0], 1_000_000n);
		expect(t.pFulfilled).to.have.length(1);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(1);
	});

	it('fails upstream: voucher below the dust floor (would be trimmed)', function () {
		const t = createTriple();
		// 60% proportional skim: fee(500k) = 1000 + 300k → v = 199k < 354k floor.
		expect(
			t.rManager.initiateFforEpoch(
				t.srChannelId,
				paramsA({ feeProportionalMillionths: 600_000 })
			).ok
		).to.equal(true);
		const hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
		goOffline(t);

		pay(t, hashes[0], 500_000n);
		expect(t.pFailed).to.have.length(1);
		expect(
			t.sErrors.some((e) => e.includes('below the voucher dust floor'))
		).to.equal(true);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(0);
	});

	it('fails upstream: cumulative budget exceeded', function () {
		const t = createTriple();
		expect(
			t.rManager.initiateFforEpoch(
				t.srChannelId,
				paramsA({ budgetMsat: 1_500_000n })
			).ok
		).to.equal(true);
		const hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
		goOffline(t);

		pay(t, hashes[0], 1_000_000n); // v_1 = 994,000 ≤ 1.5M
		expect(t.pFulfilled).to.have.length(1);
		pay(t, hashes[1], 550_000n); // cumulative 1,540,250 > 1.5M
		expect(t.pFailed).to.have.length(1);
		expect(t.sErrors.some((e) => e.includes('exceeds budget_msat'))).to.equal(
			true
		);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(1);
	});

	it('fails upstream: out-of-order hash consumption (H_2 before H_1)', function () {
		const t = createTriple();
		expect(t.rManager.initiateFforEpoch(t.srChannelId, paramsA()).ok).to.equal(
			true
		);
		const hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
		goOffline(t);

		pay(t, hashes[1], 1_000_000n);
		expect(t.pFailed).to.have.length(1);
		expect(
			t.sErrors.some((e) => e.includes('out-of-order delegated payment'))
		).to.equal(true);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(0);
	});

	it('fails upstream: settlement deadline / upstream expiry safety delta (height-aware)', function () {
		const t = createTriple();
		expect(t.rManager.initiateFforEpoch(t.srChannelId, paramsA()).ok).to.equal(
			true
		);
		const hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
		goOffline(t);

		// Past D (= 1000): reject. The HTLC's own CLTV (2000) is still valid at
		// the channel layer, so the failure comes from the FFOR deadline check.
		t.sManager.handleNewBlock(1200);
		pay(t, hashes[0], 1_000_000n, 2000);
		expect(t.pFailed.length, t.sErrors.join('; ')).to.be.greaterThan(0);
		expect(t.sErrors.some((e) => e.includes('settlement_deadline'))).to.equal(
			true
		);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(0);

		// Below D but inside the upstream-expiry safety delta: reject too.
		t.sManager.handleNewBlock(980);
		pay(t, hashes[0], 1_000_000n, 1000); // 980 ≥ 1000 − 40
		expect(t.sErrors.some((e) => e.includes('safety delta'))).to.equal(true);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(0);
	});

	// ─────────────── Crash between persist and fulfill ───────────────

	it('S crash between package-persist and upstream-fulfill replays idempotently', function () {
		const t = createTriple();
		expect(t.rManager.initiateFforEpoch(t.srChannelId, paramsA()).ok).to.equal(
			true
		);
		const hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
		goOffline(t);

		// S "crashes" at the FIRST epoch-channel persist where the package
		// exists but the upstream fulfill has not gone out — exactly the §9.2
		// crash window: snapshot S's durable state and cut the P–S link so
		// nothing S does after this instant ever reaches P.
		let snapshot: { sr: string; sp: string } | null = null;
		t.sManager.on('channel:persist', (cid: Buffer) => {
			if (!cid.equals(t.srChannelId) || snapshot) return;
			const epoch = t.sChannel.getFforEpoch();
			if (epoch && epoch.lastSeq === 1 && !epoch.upstreamFulfilled[0]) {
				snapshot = {
					sr: JSON.stringify(serializeChannelState(t.sChannel.getFullState())),
					sp: JSON.stringify(serializeChannelState(t.spChannel.getFullState()))
				};
				t.psLink.down(); // the crash: S's fulfill never reaches P
			}
		});

		pay(t, hashes[0], 1_000_000n);
		expect(t.pFulfilled).to.have.length(0); // the fulfill died with S
		expect(snapshot, 'crash-window snapshot captured').to.not.equal(null);

		// S restarts from the crash-window snapshot: package 1 persisted,
		// upstream HTLC still unfulfilled.
		const s2Manager = new ChannelManager(t.sConfig);
		const s2Errors: string[] = [];
		s2Manager.on('error', (_id, m: string) => s2Errors.push(m));
		const srState = deserializeChannelState(JSON.parse(snapshot!.sr));
		const spState = deserializeChannelState(JSON.parse(snapshot!.sp));
		const s2srChannel = new Channel(srState);
		const s2spChannel = new Channel(spState);
		s2Manager.restoreChannel(s2srChannel, t.rPub);
		s2Manager.restoreChannel(s2spChannel, t.pPub);
		expect(s2srChannel.getFforEpoch()!.lastSeq).to.equal(1);
		expect(s2srChannel.getFforEpoch()!.upstreamFulfilled[0] ?? false).to.equal(
			false
		);

		// P reconnects to the restarted S; the P–S reestablish re-runs the
		// settlement engine, which finds the persisted package and fulfills.
		const pFulfilledBefore = t.pFulfilled.length;
		t.pManager.handlePeerDisconnected(t.sPub);
		connect(s2Manager, t.sPub, t.pManager, t.pPub);
		const payloadOf = (
			actions: ReturnType<Channel['createReestablish']>
		): Buffer =>
			(
				actions.find((a) => a.type === ChannelActionType.SEND_MESSAGE) as {
					payload: Buffer;
				}
			).payload;
		const s2Re = payloadOf(s2spChannel.createReestablish());
		const pRe = payloadOf(t.pChannel.createReestablish());
		t.pManager.handleMessage(t.sPub, MessageType.CHANNEL_REESTABLISH, s2Re);
		s2Manager.handleMessage(t.pPub, MessageType.CHANNEL_REESTABLISH, pRe);

		// The payment NOW completes from P's perspective (the replayed fulfill
		// carries the same preimage), and no duplicate package was created.
		expect(t.pFulfilled.length, s2Errors.join('; ')).to.equal(
			pFulfilledBefore + 1
		);
		expect(
			sha256(t.pFulfilled[t.pFulfilled.length - 1].preimage).equals(hashes[0])
		).to.equal(true);
		const epoch2 = s2srChannel.getFforEpoch()!;
		expect(epoch2.lastSeq).to.equal(1);
		expect(epoch2.packages).to.have.length(1);
		expect(epoch2.upstreamFulfilled[0]).to.equal(true);
	});

	// ─────────────── Escapes bookkeeping (G > 0) ───────────────

	it('reconciles at n0+2 and reveals secret n0+1 when escape sigs were exchanged', function () {
		const t = createTriple();
		expect(
			t.rManager.initiateFforEpoch(
				t.srChannelId,
				paramsA({ escapeGranularityMsat: 50_000_000n }) // J = 2 placeholders
			).ok
		).to.equal(true);
		const hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
		const n0 = t.sChannel.getFforEpoch()!.sCommitmentNumber!;
		// S's per-commitment point for n0+1 — R holds it as its pre-epoch "next".
		const pointN0Plus1 = Buffer.from(
			t.rChannel.getFullState().remoteNextPerCommitmentPoint!
		);
		goOffline(t);

		pay(t, hashes[0], 1_000_000n);
		expect(t.pFulfilled).to.have.length(1);

		reconnect(t);
		const allErrors = t.rErrors.concat(t.sErrors).join('; ');
		expect(t.rChannel.getState(), allErrors).to.equal(ChannelState.NORMAL);
		expect(t.sChannel.getState(), allErrors).to.equal(ChannelState.NORMAL);

		// Catch-up at n0 + 2 (§10: n0+1 was reserved for — and revoked out of —
		// the escape set).
		expect(t.sChannel.getCommitmentNumbers().local).to.equal(n0 + 2n);
		// R holds BOTH revealed secrets: n0 (package 1) and n0+1 (ack TLV 3).
		const rStore = t.rChannel.getFullState().shaChainStore;
		expect(rStore.getSecret(MAX_INDEX - n0)).to.not.equal(null);
		expect(rStore.getSecret(MAX_INDEX - (n0 + 1n))).to.not.equal(null);
		// And the n0+1 secret matches S's point for n0+1 (killing every E_j).
		const secretN0Plus1 = rStore.getSecret(MAX_INDEX - (n0 + 1n))!;
		expect(
			perCommitmentPointFromSecret(secretN0Plus1).equals(pointN0Plus1)
		).to.equal(true);

		// Voucher conversion still works on the n0+2 chain.
		expect(t.rManager.fforFulfillVouchers(t.srChannelId).ok).to.equal(true);
		expect(t.rChannel.getBalances().localMsat).to.equal(994_000n);
		expect(t.rChannel.getFullState().htlcs.size).to.equal(0);
	});

	// ─────────────── Restart across the whole epoch (M1 gate + M2 state) ───────────────

	it('M2 settlement state survives a full S restart before reconciliation', function () {
		const t = createTriple();
		expect(t.rManager.initiateFforEpoch(t.srChannelId, paramsA()).ok).to.equal(
			true
		);
		const hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
		goOffline(t);
		pay(t, hashes[0], 1_000_000n);
		pay(t, hashes[1], 550_000n);
		expect(t.pFulfilled).to.have.length(2);

		// Full S restart from serialized state (both channels).
		const s2Manager = new ChannelManager(t.sConfig);
		s2Manager.on('error', () => {});
		const s2sr = new Channel(
			deserializeChannelState(
				JSON.parse(
					JSON.stringify(serializeChannelState(t.sChannel.getFullState()))
				)
			)
		);
		const s2sp = new Channel(
			deserializeChannelState(
				JSON.parse(
					JSON.stringify(serializeChannelState(t.spChannel.getFullState()))
				)
			)
		);
		s2Manager.restoreChannel(s2sr, t.rPub);
		s2Manager.restoreChannel(s2sp, t.pPub);

		const epoch = s2sr.getFforEpoch()!;
		expect(epoch.lastSeq).to.equal(2);
		expect(epoch.packages).to.have.length(2);
		expect(epoch.preimages).to.have.length(3);
		expect(epoch.upstreamFulfilled).to.deep.equal([true, true]);
		expect(epoch.voucherAmountsMsat).to.deep.equal([994_000n, 546_250n]);

		// R reconnects to the RESTARTED S and reconciliation completes.
		const link = connect(s2Manager, t.sPub, t.rManager, t.rPub);
		link.up();
		const payloadOf = (
			actions: ReturnType<Channel['createReestablish']>
		): Buffer =>
			(
				actions.find((a) => a.type === ChannelActionType.SEND_MESSAGE) as {
					payload: Buffer;
				}
			).payload;
		const sRe = payloadOf(s2sr.createReestablish());
		const rRe = payloadOf(t.rChannel.createReestablish());
		t.rManager.handleMessage(t.sPub, MessageType.CHANNEL_REESTABLISH, sRe);
		s2Manager.handleMessage(t.rPub, MessageType.CHANNEL_REESTABLISH, rRe);

		expect(t.rChannel.getState(), t.rErrors.join('; ')).to.equal(
			ChannelState.NORMAL
		);
		expect(s2sr.getState()).to.equal(ChannelState.NORMAL);
		expect(t.rChannel.getFullState().htlcs.size).to.equal(2);
		expect(t.rManager.fforFulfillVouchers(t.srChannelId).ok).to.equal(true);
		expect(t.rChannel.getBalances().localMsat).to.equal(994_000n + 546_250n);
	});
});
