/**
 * FFOR M7.1: tower transport over BOLT-8 peer messages (spec Appendix C).
 *
 * - Codec round-trips for all 6 FF_TOWER_* messages.
 * - The REAL-transport GATE: two beignet nodes over a real BOLT-8 Noise TCP
 *   connection. T hosts an embedded FforTower (M7.0 SqliteTowerStore) via
 *   ChannelManager.setFforTower + attachToPeerManager; R and S use
 *   PeerTowerClient. The full cycle traverses encode -> peer-send -> decode ->
 *   route -> respond -> decode: R provisions, S releases seq 1 and receives
 *   the preimage, R fetches packages+preimages. Auth rejects provision/release/
 *   fetch from the wrong peer pubkey.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	IChannelConfig
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { getPublicKey, sign } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	FforEpochState,
	FforVariant,
	IFforEpochStateData
} from '../../src/lightning/ffor/types';
import {
	buildSettlementPackage,
	fforSkimFeeMsat
} from '../../src/lightning/ffor/settlement';
import {
	FforTower,
	IFforTowerProvisioning,
	IFforTowerFetchRequest,
	buildTowerFetchRequest,
	generateTowerPreimages
} from '../../src/lightning/ffor/tower';
import { SqliteTowerStore } from '../../src/lightning/ffor/tower-store-sqlite';
import { serializeTowerProvisioning } from '../../src/lightning/ffor/tower-serialization';
import {
	PeerTowerClient,
	encodeTowerProvision,
	decodeTowerProvision,
	encodeTowerAck,
	decodeTowerAck,
	encodeTowerRelease,
	decodeTowerRelease,
	encodeTowerReleaseResp,
	decodeTowerReleaseResp,
	encodeTowerFetch,
	decodeTowerFetch,
	encodeTowerFetchResp,
	decodeTowerFetchResp
} from '../../src/lightning/ffor/tower-transport';

const h2b = (s: string): Buffer => Buffer.from(s, 'hex');
const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

// ─────────────── Appendix A fixture (as in ffor-tower.test.ts) ───────────────

const R_FUNDING_PRIV = h2b(
	'30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749'
);
const S_FUNDING_PRIV = h2b(
	'1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13'
);
const R_PAYMENT_SECRET = h2b(
	'1111111111111111111111111111111111111111111111111111111111111111'
);
const S_REVOCATION_SECRET = h2b(
	'2222222222222222222222222222222222222222222222222222222222222222'
);
const R_DELAYED_SECRET = h2b(
	'3333333333333333333333333333333333333333333333333333333333333333'
);
const S_PAYMENT_SECRET = h2b(
	'4444444444444444444444444444444444444444444444444444444444444444'
);
const R_REVOCATION_SECRET = sha256(
	Buffer.from('ffor/R/revocation-basepoint-secret')
);
const S_DELAYED_SECRET = sha256(
	Buffer.from('ffor/S/delayed-payment-basepoint-secret')
);
const R_PC_SEED = sha256(Buffer.from('ffor/R/per-commitment-seed'));
const S_PC_SEED = sha256(Buffer.from('ffor/S/per-commitment-seed'));
const FUNDING_TXID_INTERNAL = h2b(
	'bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489'
);
const N_R = 42n;
const N0 = 42n;
const T_EXP = 800_000;
const D_DEADLINE = 799_000;
const FEERATE = 2500;
// These node keys are BOTH the FFOR node ids AND the BOLT-8 transport keys, so
// the Noise-authenticated peer pubkey equals rNodeId / sNodeId.
const S_NODE_KEY = sha256(Buffer.from('ffor/S/node-key'));
const S_NODE_ID = getPublicKey(S_NODE_KEY);
const R_NODE_KEY = sha256(Buffer.from('ffor/R/node-key'));
const R_NODE_ID = getPublicKey(R_NODE_KEY);
const T_NODE_KEY = sha256(Buffer.from('ffor/T/node-key'));
const T_NODE_ID = getPublicKey(T_NODE_KEY);

function pcSecret(seed: Buffer, n: bigint): Buffer {
	return generateFromSeed(seed, MAX_INDEX - n);
}
function pcPoint(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(pcSecret(seed, n));
}

const rBasepoints: IChannelBasepoints = {
	fundingPubkey: getPublicKey(R_FUNDING_PRIV),
	revocationBasepoint: getPublicKey(R_REVOCATION_SECRET),
	paymentBasepoint: getPublicKey(R_PAYMENT_SECRET),
	delayedPaymentBasepoint: getPublicKey(R_DELAYED_SECRET),
	htlcBasepoint: getPublicKey(R_PAYMENT_SECRET),
	firstPerCommitmentPoint: pcPoint(R_PC_SEED, 0n)
};
const sBasepoints: IChannelBasepoints = {
	fundingPubkey: getPublicKey(S_FUNDING_PRIV),
	revocationBasepoint: getPublicKey(S_REVOCATION_SECRET),
	paymentBasepoint: getPublicKey(S_PAYMENT_SECRET),
	delayedPaymentBasepoint: getPublicKey(S_DELAYED_SECRET),
	htlcBasepoint: getPublicKey(S_PAYMENT_SECRET),
	firstPerCommitmentPoint: pcPoint(S_PC_SEED, 0n)
};

const channelTypeFlags = FeatureFlags.empty();
channelTypeFlags.setCompulsory(Feature.STATIC_REMOTE_KEY);
channelTypeFlags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
const CHANNEL_TYPE = channelTypeFlags.toBuffer();

const CONFIG: IChannelConfig = {
	dustLimitSatoshis: 546n,
	maxHtlcValueInFlightMsat: 5_000_000_000n,
	channelReserveSatoshis: 10_000n,
	htlcMinimumMsat: 1n,
	toSelfDelay: 144,
	maxAcceptedHtlcs: 483,
	feeratePerKw: FEERATE
};

const TOWER = generateTowerPreimages(4);
const HTLC_AMOUNTS = [1_000_000n, 550_000n, 50_000_000n];

function towerParams(): IFforEpochStateData['params'] {
	return {
		variant: FforVariant.B,
		budgetMsat: 100_000_000n,
		maxPayments: 4,
		minPaymentMsat: 10_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		escapeGranularityMsat: 0n,
		rPerCommitmentPoints: Array.from({ length: 4 }, (_, i) =>
			pcPoint(R_PC_SEED, N_R + BigInt(i + 1))
		),
		paymentHashes: TOWER.paymentHashes,
		towerNodeId: T_NODE_ID,
		towerUri: 'tower.example:9911'
	};
}

function makeSState(): IChannelState {
	const st = createOpenerState({
		temporaryChannelId: Buffer.alloc(32),
		fundingSatoshis: 10_000_000n,
		pushMsat: 3_000_000_000n,
		localConfig: { ...CONFIG },
		localBasepoints: sBasepoints,
		localPerCommitmentSeed: S_PC_SEED
	});
	st.remoteBasepoints = rBasepoints;
	st.remoteConfig = { ...CONFIG };
	st.fundingTxid = FUNDING_TXID_INTERNAL;
	st.fundingOutputIndex = 0;
	st.channelType = CHANNEL_TYPE;
	st.state = ChannelState.NORMAL;
	st.localCommitmentNumber = N0;
	st.remoteCommitmentNumber = N_R;
	return st;
}

function makeSEpoch(): IFforEpochStateData {
	return {
		epochId: Buffer.alloc(32, 0xee),
		role: 'settlement_peer',
		state: FforEpochState.FF_EPOCH,
		params: towerParams(),
		sCommitmentNumber: N0,
		invoices: [],
		escapeSigs: [],
		escapeHtlcSigs: [],
		initSignature: null,
		acceptSignature: null,
		remoteNodeId: R_NODE_ID,
		epochStartHeight: null,
		preimages: [],
		lastSeq: 0,
		packages: [],
		htlcAmountsMsat: [],
		voucherAmountsMsat: [],
		upstreamFulfilled: [],
		upstreamHtlcIds: [],
		sHtlcIdBase: 0n,
		frozenFeeratePerKw: FEERATE,
		nR: N_R,
		rPreEpochPoint: pcPoint(R_PC_SEED, N_R),
		peerLastSeq: null,
		sRevocationSecretN0: pcSecret(S_PC_SEED, N0)
	};
}

function buildPackage(sEpoch: IFforEpochStateData, seq: number): Buffer {
	const sState = makeSState();
	const sSigner = new ChannelSigner(S_FUNDING_PRIV, S_PAYMENT_SECRET);
	sEpoch.htlcAmountsMsat[seq - 1] = HTLC_AMOUNTS[seq - 1];
	sEpoch.voucherAmountsMsat[seq - 1] =
		HTLC_AMOUNTS[seq - 1] - fforSkimFeeMsat(sEpoch, HTLC_AMOUNTS[seq - 1]);
	const { payload } = buildSettlementPackage({
		base: sState,
		signer: sSigner,
		epoch: sEpoch,
		channelId: Buffer.alloc(32, 0xcc),
		seq,
		signFn: (digest: Buffer): Buffer => sign(digest, S_NODE_KEY)
	});
	sEpoch.lastSeq = seq;
	return payload;
}

function provisioning(): IFforTowerProvisioning {
	return {
		epochId: Buffer.alloc(32, 0xee),
		params: towerParams(),
		preimages: TOWER.preimages,
		channel: {
			fundingTxid: FUNDING_TXID_INTERNAL,
			fundingOutputIndex: 0,
			fundingSatoshis: 10_000_000n,
			channelType: CHANNEL_TYPE,
			rIsOpener: false,
			rBasepoints,
			sBasepoints,
			rConfig: { ...CONFIG },
			sConfig: { ...CONFIG },
			preEpochRLocalMsat: 3_000_000_000n,
			preEpochSLocalMsat: 7_000_000_000n,
			nR: N_R,
			n0: N0,
			sPerCommitmentPointN0: pcPoint(S_PC_SEED, N0),
			frozenFeeratePerKw: FEERATE
		},
		rNodeId: R_NODE_ID,
		sNodeId: S_NODE_ID
	};
}

function tmpDbPath(): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), 'ffor-tower-tx-')),
		'tower.db'
	);
}

// ─────────────── Codec round-trips ───────────────

describe('FFOR M7.1: FF_TOWER_* codec round-trips', function () {
	it('provision', function () {
		const rid = crypto.randomBytes(16);
		const json = JSON.stringify(serializeTowerProvisioning(provisioning()));
		const dec = decodeTowerProvision(encodeTowerProvision(rid, json));
		expect(dec.requestId.equals(rid)).to.equal(true);
		expect(dec.provisioningJson).to.equal(json);
	});
	it('ack (ok + error)', function () {
		const rid = crypto.randomBytes(16);
		const ok = decodeTowerAck(encodeTowerAck(rid, true));
		expect(ok.ok).to.equal(true);
		expect(ok.requestId.equals(rid)).to.equal(true);
		const err = decodeTowerAck(encodeTowerAck(rid, false, 'nope'));
		expect(err.ok).to.equal(false);
		expect(err.error).to.equal('nope');
	});
	it('release', function () {
		const rid = crypto.randomBytes(16);
		const pkg = buildPackage(makeSEpoch(), 1);
		const dec = decodeTowerRelease(encodeTowerRelease(rid, pkg));
		expect(dec.requestId.equals(rid)).to.equal(true);
		expect(dec.settlementPayload.equals(pkg)).to.equal(true);
	});
	it('release_resp (ok + error)', function () {
		const rid = crypto.randomBytes(16);
		const pre = crypto.randomBytes(32);
		const ok = decodeTowerReleaseResp(
			encodeTowerReleaseResp(rid, { ok: true, seq: 3, preimage: pre })
		);
		expect(ok.result.ok).to.equal(true);
		if (ok.result.ok) {
			expect(ok.result.seq).to.equal(3);
			expect(ok.result.preimage.equals(pre)).to.equal(true);
		}
		const err = decodeTowerReleaseResp(
			encodeTowerReleaseResp(rid, { ok: false, error: 'bad' })
		);
		expect(err.result.ok).to.equal(false);
	});
	it('fetch', function () {
		const rid = crypto.randomBytes(16);
		const req: IFforTowerFetchRequest = buildTowerFetchRequest(
			Buffer.alloc(32, 0xee),
			R_NODE_KEY
		);
		const dec = decodeTowerFetch(encodeTowerFetch(rid, req));
		expect(dec.req.epochId.equals(req.epochId)).to.equal(true);
		expect(dec.req.nonce.equals(req.nonce)).to.equal(true);
		expect(dec.req.signature.equals(req.signature)).to.equal(true);
	});
	it('fetch_resp (ok + error)', function () {
		const rid = crypto.randomBytes(16);
		const packages = [buildPackage(makeSEpoch(), 1), crypto.randomBytes(400)];
		const preimages = [crypto.randomBytes(32), crypto.randomBytes(32)];
		const ok = decodeTowerFetchResp(
			encodeTowerFetchResp(rid, {
				ok: true,
				lastReleased: 2,
				packages,
				preimages
			})
		);
		expect(ok.resp.ok).to.equal(true);
		expect(ok.resp.lastReleased).to.equal(2);
		expect(ok.resp.packages[0].equals(packages[0])).to.equal(true);
		expect(ok.resp.packages[1].equals(packages[1])).to.equal(true);
		expect(ok.resp.preimages[1].equals(preimages[1])).to.equal(true);
		const err = decodeTowerFetchResp(
			encodeTowerFetchResp(rid, {
				ok: false,
				error: 'x',
				lastReleased: 0,
				packages: [],
				preimages: []
			})
		);
		expect(err.resp.ok).to.equal(false);
	});

	it('provision message fits the 65535-byte LN limit for K = 4', function () {
		const rid = crypto.randomBytes(16);
		const json = JSON.stringify(serializeTowerProvisioning(provisioning()));
		expect(encodeTowerProvision(rid, json).length).to.be.lessThan(65535);
	});
});

// ─────────────── Real BOLT-8 transport gate ───────────────

describe('FFOR M7.1 GATE: tower over a real BOLT-8 connection', function () {
	this.timeout(30_000);

	let towerPm: PeerManager;
	let towerManager: ChannelManager;
	let tower: FforTower;
	let towerStore: SqliteTowerStore;
	let dbDir: string;
	let towerPort: number;

	const clients: PeerTowerClient[] = [];
	const clientPms: PeerManager[] = [];
	// Persistent per-node clients (one Noise connection per node key; reusing a
	// key with a fresh PeerManager would hit the tower's duplicate-inbound
	// rejection). R = recipient, S = settlement peer, X = an unrelated impostor.
	let rClient: PeerTowerClient;
	let sClient: PeerTowerClient;
	let xClient: PeerTowerClient;

	function makeClient(nodeKey: Buffer): PeerTowerClient {
		const pm = new PeerManager({
			localPrivateKey: nodeKey,
			localFeatures: FeatureFlags.empty()
		});
		clientPms.push(pm);
		const c = new PeerTowerClient(pm, {
			towerNodeId: T_NODE_ID,
			address: { host: '127.0.0.1', port: towerPort },
			timeoutMs: 10_000
		});
		clients.push(c);
		return c;
	}

	before(async function () {
		this.timeout(15_000);
		const dbPath = tmpDbPath();
		dbDir = path.dirname(dbPath);
		towerStore = new SqliteTowerStore(dbPath);
		tower = new FforTower(towerStore);
		tower.setBlockHeight(500_000); // < D
		// The tower node hosts the embedded tower via ChannelManager.
		towerManager = new ChannelManager({
			localConfig: { ...CONFIG },
			localBasepoints: sBasepoints, // unused for tower role
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32),
			nodePrivateKey: T_NODE_KEY
		});
		towerManager.setFforTower(tower);
		towerPm = new PeerManager({
			localPrivateKey: T_NODE_KEY,
			localFeatures: FeatureFlags.empty()
		});
		towerManager.attachToPeerManager(towerPm);
		await towerPm.listen(0);
		towerPort = (
			towerPm as unknown as { server: { address(): { port: number } } }
		).server.address().port;

		rClient = makeClient(R_NODE_KEY);
		sClient = makeClient(S_NODE_KEY);
		xClient = makeClient(sha256(Buffer.from('impostor')));
	});

	after(function () {
		for (const c of clients) c.destroy();
		for (const pm of clientPms) pm.destroy();
		towerPm.destroy();
		towerStore.close();
		fs.rmSync(dbDir, { recursive: true, force: true });
	});

	it('R provisions, S releases seq 1 (preimage over the wire), R fetches', async function () {
		// R provisions over BOLT-8.
		await rClient.provision(provisioning());
		// The provisioning actually reached the tower's durable store.
		expect(tower.getEpochAuth(Buffer.alloc(32, 0xee))).to.not.equal(null);

		// S releases seq 1 over BOLT-8 and receives the real preimage.
		const pkg1 = buildPackage(makeSEpoch(), 1);
		const rel = await sClient.requestRelease(pkg1);
		expect(rel.ok, (rel as { error?: string }).error).to.equal(true);
		if (rel.ok) {
			expect(rel.seq).to.equal(1);
			expect(rel.preimage.equals(TOWER.preimages[0])).to.equal(true);
		}

		// R fetches back the stored package + preimage over BOLT-8.
		const fetchReq = buildTowerFetchRequest(Buffer.alloc(32, 0xee), R_NODE_KEY);
		const fetched = await rClient.fetch(fetchReq);
		expect(fetched.ok, fetched.error).to.equal(true);
		expect(fetched.lastReleased).to.equal(1);
		expect(fetched.packages[0].equals(pkg1)).to.equal(true);
		expect(fetched.preimages[0].equals(TOWER.preimages[0])).to.equal(true);
	});

	it('auth: provision from the WRONG peer is rejected', async function () {
		// The bundle claims R is the recipient, but the sender is the impostor.
		let threw = false;
		try {
			await xClient.provision(provisioning());
		} catch (e) {
			threw = true;
			expect((e as Error).message).to.match(/not the epoch recipient/);
		}
		expect(threw, 'provision from wrong peer must reject').to.equal(true);
	});

	it('auth: release from the WRONG peer (not S) is rejected', async function () {
		// R's client (sender = R, not S) requests a release.
		const rel = await rClient.requestRelease(buildPackage(makeSEpoch(), 1));
		expect(rel.ok).to.equal(false);
		if (!rel.ok) {
			expect(rel.error).to.match(/not the epoch settlement peer/);
		}
	});

	it('auth: fetch from the WRONG peer (not R) is rejected', async function () {
		// S's client (sender = S, not R) attempts a fetch. A validly-signed
		// fetch digest is still gated by the Noise peer id.
		const fetchReq = buildTowerFetchRequest(Buffer.alloc(32, 0xee), R_NODE_KEY);
		const res = await sClient.fetch(fetchReq);
		expect(res.ok).to.equal(false);
		expect(res.error).to.match(/not the epoch recipient/);
	});
});
