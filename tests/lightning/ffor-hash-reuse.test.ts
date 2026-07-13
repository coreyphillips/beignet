/**
 * FFOR M8.8 characterization: invoice/hash reuse (spec §13.7).
 *
 * A preimage is a bearer token. Once S holds t_k it can fulfil ANY upstream
 * HTLC carrying H_k, not merely the first. The tower gates only the FIRST
 * settlement on each hash (its ff_release is keyed and idempotent on seq), so
 * a SECOND payment on a consumed hash never reaches the tower at all, and R is
 * offline and sees nothing.
 *
 * These two tests pin the exact shape of the gap:
 *
 *  1. The honest S DOES refuse the duplicate (channel-manager
 *     `_fforSettleDelegated*`: "duplicate delegated payment for consumed
 *     hash"). Single-use is implemented.
 *
 *  2. But that refusal is SELF-IMPOSED BY S. Nothing in the protocol makes it
 *     verifiable by R or T. A malicious S that simply declines to run its own
 *     guard settles the duplicate using only data it already holds; the tower
 *     is never consulted, R's credit stays at one voucher, and no evidence of
 *     the theft exists anywhere. Test 2 asserts that this is currently
 *     possible: it is a CHARACTERIZATION test of an open problem, not a gate.
 *     It should start failing (i.e. the theft should become impossible) only
 *     when BOLT 12 / PTLC payer-and-amount binding lands, per spec §13.5/§13.7.
 *
 * Test 2 models the malicious S with the manager's own PUBLIC fulfillHtlc()
 * and the preimage already sitting in S's persisted epoch state. Nothing is
 * patched, stubbed, or reached into: the point is precisely that S needs no
 * special capability to do this.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { FforVariant, IFforEpochParams } from '../../src/lightning/ffor/types';
import {
	FforTower,
	LoopbackTowerClient,
	MemoryTowerStore,
	generateTowerPreimages,
	IFforTowerProvisioning
} from '../../src/lightning/ffor/tower';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

/** JSON with BigInt + Buffer support, for byte-for-byte state snapshots. */
function snapshot(value: unknown): string {
	return JSON.stringify(value, (_k, v) => {
		if (typeof v === 'bigint') return `b:${v.toString()}`;
		if (Buffer.isBuffer(v)) return `x:${v.toString('hex')}`;
		return v;
	});
}

function makeSeed(id: string): Buffer {
	return sha256(Buffer.from(`ffor-reuse-${id}`));
}
function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	secrets: Buffer[];
} {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(sha256(Buffer.concat([seed, Buffer.from([i])])));
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
		secrets: keys
	};
}
function makeConfig(name: string): IChannelManagerConfig {
	const seed = makeSeed(name);
	const { basepoints, secrets } = makeBasepoints(seed);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, toSelfDelay: 6 },
		localBasepoints: basepoints,
		localPerCommitmentSeed: makeSeed(name + '-commit'),
		localFundingPrivkey: secrets[0],
		htlcBasepointSecret: secrets[4],
		revocationBasepointSecret: secrets[1],
		paymentBasepointSecret: secrets[2],
		delayedPaymentBasepointSecret: secrets[3],
		nodePrivateKey: makeSeed(name + '-node'),
		preferAnchors: true
	};
}

interface ILink {
	down: () => void;
	up: () => void;
}
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
const PAYMENT_MSAT = 1_000_000n;

let reuseId = 0;

interface IScenario {
	pManager: ChannelManager;
	sManager: ChannelManager;
	rManager: ChannelManager;
	sPub: string;
	rPub: string;
	psChannelId: Buffer;
	sChannel: Channel;
	rChannel: Channel;
	tower: FforTower;
	towerStore: MemoryTowerStore;
	hashes: Buffer[];
	towerPreimages: Buffer[];
	pFulfilled: Buffer[];
	pFailed: bigint[];
	sErrors: string[];
}

/** P-S-R, variant-B epoch on S-R, loopback tower on S, R disconnected. */
async function setup(): Promise<IScenario> {
	reuseId++;
	const pConfig = makeConfig(`P-${reuseId}`);
	const sConfig = makeConfig(`S-${reuseId}`);
	const rConfig = makeConfig(`R-${reuseId}`);
	const pPub = getPublicKey(pConfig.nodePrivateKey!).toString('hex');
	const sPub = getPublicKey(sConfig.nodePrivateKey!).toString('hex');
	const rPub = getPublicKey(rConfig.nodePrivateKey!).toString('hex');
	const pManager = new ChannelManager(pConfig);
	const sManager = new ChannelManager(sConfig);
	const rManager = new ChannelManager(rConfig);
	pManager.on('error', () => {});
	rManager.on('error', () => {});
	const sErrors: string[] = [];
	sManager.on('error', (_id, m: string) => sErrors.push(m));
	const pFulfilled: Buffer[] = [];
	const pFailed: bigint[] = [];
	pManager.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
		pFulfilled.push(preimage)
	);
	pManager.on('htlc:failed', (_c, id: bigint) => pFailed.push(id));

	connect(pManager, pPub, sManager, sPub);
	const srLink = connect(sManager, sPub, rManager, rPub);

	const open = (
		om: ChannelManager,
		am: ChannelManager,
		oPub: string
	): { id: Buffer; opener: Channel; acceptor: Channel } => {
		const opener = om.openChannel(
			om === pManager ? sPub : rPub,
			FUNDING_SATOSHIS
		);
		om.createFunding(opener, crypto.randomBytes(32), 0, crypto.randomBytes(64));
		const id = opener.getChannelId()!;
		om.handleFundingConfirmed(id);
		am.handleFundingConfirmed(id);
		const acceptor = am
			.getChannelsByPeer(oPub)
			.find((c) => c.getChannelId()?.equals(id))!;
		return { id, opener, acceptor };
	};
	const ps = open(pManager, sManager, pPub);
	const sr = open(sManager, rManager, sPub);

	const tower = new FforTower(new MemoryTowerStore());
	const towerStore = (tower as unknown as { _store: MemoryTowerStore })._store;
	const K = 3;
	const gen = generateTowerPreimages(K);
	const towerNodeKey = makeSeed(`tower-${reuseId}`);
	const params: Omit<IFforEpochParams, 'rPerCommitmentPoints'> = {
		variant: FforVariant.B,
		budgetMsat: 100_000_000n,
		maxPayments: K,
		minPaymentMsat: 500_000n,
		settlementDeadline: 1000,
		voucherExpiry: 2008,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		escapeGranularityMsat: 0n,
		paymentHashes: gen.paymentHashes,
		towerNodeId: getPublicKey(towerNodeKey),
		towerUri: 'inproc://tower'
	};
	sManager.setFforTowerClient(new LoopbackTowerClient(tower));

	const provisioning: IFforTowerProvisioning = {
		epochId: Buffer.alloc(0),
		params: params as IFforEpochParams,
		preimages: gen.preimages,
		channel: {
			fundingTxid: sr.opener.getFullState().fundingTxid!,
			fundingOutputIndex: sr.opener.getFullState().fundingOutputIndex,
			fundingSatoshis: FUNDING_SATOSHIS,
			channelType: sr.opener.getFullState().channelType!,
			rIsOpener: false,
			rBasepoints: rConfig.localBasepoints,
			sBasepoints: sConfig.localBasepoints,
			rConfig: { ...DEFAULT_CHANNEL_CONFIG, toSelfDelay: 6 },
			sConfig: { ...DEFAULT_CHANNEL_CONFIG, toSelfDelay: 6 },
			preEpochRLocalMsat: 0n,
			preEpochSLocalMsat: FUNDING_SATOSHIS * 1000n,
			nR: sr.acceptor.getCommitmentNumbers().local,
			n0: sr.opener.getCommitmentNumbers().local,
			sPerCommitmentPointN0:
				sr.acceptor.getFullState().remoteCurrentPerCommitmentPoint!,
			frozenFeeratePerKw: 253
		},
		rNodeId: Buffer.from(rPub, 'hex'),
		sNodeId: Buffer.from(sPub, 'hex')
	};

	const res = rManager.initiateFforEpoch(sr.id, params);
	expect(res.ok).to.equal(true);
	const rEpoch = sr.acceptor.getFforEpoch()!;
	provisioning.epochId = rEpoch.epochId;
	provisioning.params = rEpoch.params;
	tower.provision(provisioning);
	tower.setBlockHeight(500);

	// R goes offline for the epoch.
	srLink.down();
	sManager.handlePeerDisconnected(rPub);
	rManager.handlePeerDisconnected(sPub);

	return {
		pManager,
		sManager,
		rManager,
		sPub,
		rPub,
		psChannelId: ps.id,
		sChannel: sr.opener,
		rChannel: sr.acceptor,
		tower,
		towerStore,
		hashes: gen.paymentHashes,
		towerPreimages: gen.preimages,
		pFulfilled,
		pFailed,
		sErrors
	};
}

function flush(): Promise<void> {
	return new Promise((r) => setTimeout(r, 5));
}

describe('FFOR M8.8: invoice/hash reuse (spec §13.7)', function () {
	it('honest S refuses a second payment on a consumed hash', async function () {
		const t = await setup();

		// Payment 1 on H_1 settles normally via the tower.
		t.pManager.addHtlc(
			t.psChannelId,
			PAYMENT_MSAT,
			t.hashes[0],
			900,
			Buffer.alloc(1366)
		);
		await flush();
		expect(t.pFulfilled.length, t.sErrors.join('; ')).to.equal(1);
		expect(t.towerStore.saveLog.length).to.equal(1);

		// A SECOND payer pays the SAME hash H_1. The honest S implements the
		// §13.1 single-use rule and fails it upstream.
		t.pManager.addHtlc(
			t.psChannelId,
			PAYMENT_MSAT,
			t.hashes[0],
			900,
			Buffer.alloc(1366)
		);
		await flush();

		expect(t.pFulfilled.length, 'no second fulfill').to.equal(1);
		expect(t.pFailed.length, 'duplicate failed upstream').to.equal(1);
		expect(
			t.sErrors.some((e) => e.includes('duplicate delegated payment')),
			'S names the duplicate: ' + t.sErrors.join('; ')
		).to.equal(true);
		// The tower was never consulted for the duplicate either way.
		expect(t.towerStore.saveLog.length).to.equal(1);
	});

	it('CHARACTERIZATION (§13.7): the single-use rule is S-side-only; a malicious S claims a second payer on H_1 with the token alone, leaving no evidence at T or R', async function () {
		const t = await setup();

		// Payment 1 on H_1 settles normally via the tower. S extracts t_1, which
		// now sits in its ordinary persisted epoch state as a reusable bearer
		// token.
		t.pManager.addHtlc(
			t.psChannelId,
			PAYMENT_MSAT,
			t.hashes[0],
			900,
			Buffer.alloc(1366)
		);
		await flush();
		expect(t.pFulfilled.length, t.sErrors.join('; ')).to.equal(1);

		const sEpoch = t.sChannel.getFforEpoch()!;
		expect(sEpoch.lastSeq).to.equal(1);
		const token = Buffer.from(sEpoch.preimages[0]);
		expect(sha256(token).equals(t.hashes[0]), 'token opens H_1').to.equal(true);

		// Snapshot everything R or T could ever inspect for evidence, taken AFTER
		// the legitimate payment 1.
		const towerSavesBefore = t.towerStore.saveLog.length;
		const rEpochSnapshot = snapshot(t.rChannel.getFforEpoch());
		const rLastSeqBefore = t.sChannel.getFforEpoch()!.lastSeq;
		expect(towerSavesBefore).to.equal(1);

		// The malicious S. We model "S running code without its self-imposed
		// duplicate guard" as a manager built from S's OWN config (same node
		// identity, same keys), holding only the token — no ffor epoch, no tower.
		// This is the honest representation of the capability: the theft needs
		// nothing beyond the token S already extracted. The reference S declines
		// to do this (test 1); the protocol does not stop an S that doesn't.
		const evilS = new ChannelManager(makeConfig(`S-${reuseId}`));
		evilS.on('error', () => {});
		const evilSPub = getPublicKey(
			makeConfig(`S-${reuseId}`).nodePrivateKey!
		).toString('hex');
		expect(evilSPub, 'evilS is the SAME node identity as S').to.equal(t.sPub);

		// A second, independent payer pays the same invoice / hash H_1. In the
		// real network R's invoice route-hint pins S, so a reused invoice lands
		// here naturally.
		const p2Config = makeConfig(`P2-${reuseId}`);
		const p2Pub = getPublicKey(p2Config.nodePrivateKey!).toString('hex');
		const p2 = new ChannelManager(p2Config);
		p2.on('error', () => {});
		const p2Fulfilled: Buffer[] = [];
		p2.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
			p2Fulfilled.push(preimage)
		);
		connect(p2, p2Pub, evilS, evilSPub);

		const p2Opener = p2.openChannel(evilSPub, FUNDING_SATOSHIS);
		p2.createFunding(
			p2Opener,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		);
		const p2ChannelId = p2Opener.getChannelId()!;
		p2.handleFundingConfirmed(p2ChannelId);
		evilS.handleFundingConfirmed(p2ChannelId);

		const secondHtlcId = p2.addHtlc(
			p2ChannelId,
			PAYMENT_MSAT,
			t.hashes[0],
			900,
			Buffer.alloc(1366)
		);
		await flush();

		// evilS has no ffor epoch, so nothing auto-fails the duplicate. It simply
		// claims the HTLC with the token, via the ordinary public fulfill path.
		const evilUpstream = evilS
			.getChannelsByPeer(p2Pub)
			.find((c) => c.getChannelId()?.equals(p2ChannelId))!;
		const liveId = [...evilUpstream.getFullState().htlcs.values()].find((h) =>
			h.paymentHash.equals(t.hashes[0])
		)?.id;
		expect(
			liveId,
			'the second HTLC is live for the malicious S to claim'
		).to.not.equal(undefined);
		evilS.fulfillHtlc(p2ChannelId, liveId!, token);
		await flush();

		// THE FINDING.

		// 1. The theft succeeded with the token alone. The second payer's payment
		//    completed, claimed by S, with no tower interaction of any kind.
		expect(p2Fulfilled.length, 'second payer was claimed').to.equal(1);
		expect(
			p2Fulfilled[0].equals(token),
			'claimed with the very token from payment 1'
		).to.equal(true);

		// 2. The tower saw nothing. Its gate is seq-keyed and was satisfied by
		//    payment 1; the second settlement never touched it.
		expect(
			t.towerStore.saveLog.length,
			'tower is never consulted for a reused hash'
		).to.equal(towerSavesBefore);

		// 3. R's credit did not grow and R's epoch state is byte-identical. R will
		//    receive exactly one voucher for H_1 no matter how many payers S drains
		//    on it, and there is NO artefact anywhere (package, tower record, chain)
		//    that R could ever use to detect or prove the second settlement.
		expect(
			t.sChannel.getFforEpoch()!.lastSeq,
			'R credited exactly once for H_1'
		).to.equal(rLastSeqBefore);
		expect(
			snapshot(t.rChannel.getFforEpoch()),
			'R epoch state unchanged: R is blind to the theft'
		).to.equal(rEpochSnapshot);

		// The loss, explicit: two payers each parted with PAYMENT_MSAT on H_1; R's
		// epoch records one voucher; S kept the difference. This delta is NOT
		// bounded by budget_msat — it scales with how many payers can be induced
		// onto a consumed hash and never touches the voucher book. That unbounded,
		// evidence-free gap is what §13.5 (PTLC) / BOLT 12 payer+amount binding
		// must close; until then this test documents it.
		expect(secondHtlcId).to.not.equal(undefined);
	});
});
