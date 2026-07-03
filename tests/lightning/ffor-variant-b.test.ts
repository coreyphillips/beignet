/**
 * FFOR M4 Variant B settlement (in-memory, no bitcoind): the S<->tower<->R
 * flow. Three in-process nodes P - S - R plus a loopback tower.
 *
 * - S settles a delegated payment only after the tower releases the preimage
 *   (payer completes); with no preimage of its own S never fulfills unilaterally.
 * - A tower rejection makes S fail the payment upstream (spec §9.4/§11.4).
 * - S crash between tower-release and upstream-fulfill replays idempotently.
 * - R recovers packages + preimages from the tower alone (S gone) and adopts
 *   C_j^R (ready for force-close).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
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
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

function makeSeed(id: string): Buffer {
	return sha256(Buffer.from(`ffor-vb-${id}`));
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

interface IVbScenario {
	pManager: ChannelManager;
	sManager: ChannelManager;
	rManager: ChannelManager;
	sConfig: IChannelManagerConfig;
	rConfig: IChannelManagerConfig;
	sPub: string;
	rPub: string;
	pPub: string;
	psChannelId: Buffer;
	srChannelId: Buffer;
	pChannel: Channel;
	sChannel: Channel;
	rChannel: Channel;
	srLink: ILink;
	psLink: ILink;
	tower: FforTower;
	towerStore: MemoryTowerStore;
	towerPreimages: Buffer[];
	hashes: Buffer[];
	pFulfilled: Buffer[];
	pFailed: bigint[];
	sErrors: string[];
	rErrors: string[];
}

let vbId = 0;

/** P-S-R with a variant-B epoch on S-R and a loopback tower wired to S. */
async function setupVariantB(opts?: {
	rejectTower?: boolean;
}): Promise<IVbScenario> {
	vbId++;
	const pConfig = makeConfig(`P-${vbId}`);
	const sConfig = makeConfig(`S-${vbId}`);
	const rConfig = makeConfig(`R-${vbId}`);
	const pPub = getPublicKey(pConfig.nodePrivateKey!).toString('hex');
	const sPub = getPublicKey(sConfig.nodePrivateKey!).toString('hex');
	const rPub = getPublicKey(rConfig.nodePrivateKey!).toString('hex');
	const pManager = new ChannelManager(pConfig);
	const sManager = new ChannelManager(sConfig);
	const rManager = new ChannelManager(rConfig);
	pManager.on('error', () => {});
	const sErrors: string[] = [];
	const rErrors: string[] = [];
	sManager.on('error', (_id, m: string) => sErrors.push(m));
	rManager.on('error', (_id, m: string) => rErrors.push(m));
	const pFulfilled: Buffer[] = [];
	const pFailed: bigint[] = [];
	pManager.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
		pFulfilled.push(preimage)
	);
	pManager.on('htlc:failed', (_c, id: bigint) => pFailed.push(id));

	const psLink = connect(pManager, pPub, sManager, sPub);
	const srLink = connect(sManager, sPub, rManager, rPub);

	const open = (
		om: ChannelManager,
		am: ChannelManager,
		oPub: string,
		aPub: string
	): { id: Buffer; opener: Channel; acceptor: Channel } => {
		const opener = om.openChannel(aPub, FUNDING_SATOSHIS);
		om.createFunding(opener, crypto.randomBytes(32), 0, crypto.randomBytes(64));
		const id = opener.getChannelId()!;
		om.handleFundingConfirmed(id);
		am.handleFundingConfirmed(id);
		const acceptor = am
			.getChannelsByPeer(oPub)
			.find((c) => c.getChannelId()?.equals(id))!;
		return { id, opener, acceptor };
	};
	const ps = open(pManager, sManager, pPub, sPub);
	const sr = open(sManager, rManager, sPub, rPub);

	// R generates the tower preimages/hashes, provisions the tower, then opens
	// a variant-B epoch carrying those hashes + tower TLVs in ff_init.
	const tower = new FforTower(new MemoryTowerStore());
	const towerStore = (tower as unknown as { _store: MemoryTowerStore })._store;
	const K = 3;
	const gen = generateTowerPreimages(K);
	const towerNodeKey = makeSeed(`tower-${vbId}`);
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

	// Wire the tower to S (loopback), optionally forcing rejections.
	const client = opts?.rejectTower
		? new (class {
				async provision(p: IFforTowerProvisioning): Promise<void> {
					tower.provision(p);
				}
				async requestRelease(): Promise<{ ok: false; error: string }> {
					return { ok: false, error: 'tower refuses (test)' };
				}
				async fetch(
					req: Parameters<LoopbackTowerClient['fetch']>[0]
				): ReturnType<LoopbackTowerClient['fetch']> {
					return tower.handleFetch(req);
				}
		  })()
		: new LoopbackTowerClient(tower);
	sManager.setFforTowerClient(client);

	// Provision the tower with all statics (spec §9.4 + erratum superset).
	const provisioning: IFforTowerProvisioning = {
		epochId: Buffer.alloc(0), // set after initiate returns the real id
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
	expect(res.ok, rErrors.join('; ')).to.equal(true);
	// Provision the tower with the real epoch_id + the COMPLETED params (the
	// channel filled in rPerCommitmentPoints during initiate).
	const rEpoch = sr.acceptor.getFforEpoch()!;
	provisioning.epochId = rEpoch.epochId;
	provisioning.params = rEpoch.params;
	tower.provision(provisioning);
	tower.setBlockHeight(500);

	return {
		pManager,
		sManager,
		rManager,
		sConfig,
		rConfig,
		sPub,
		rPub,
		pPub,
		psChannelId: ps.id,
		srChannelId: sr.id,
		pChannel: ps.opener,
		sChannel: sr.opener,
		rChannel: sr.acceptor,
		srLink,
		psLink,
		tower,
		towerStore,
		towerPreimages: gen.preimages,
		hashes: gen.paymentHashes,
		pFulfilled,
		pFailed,
		sErrors,
		rErrors
	};
}

/** Await the fire-and-forget tower settlement microtasks. */
function flush(): Promise<void> {
	return new Promise((r) => setTimeout(r, 5));
}

describe('FFOR M4: Variant B settlement (in-memory)', function () {
	it('settles a delegated payment only after tower release; payer completes', async function () {
		const t = await setupVariantB();
		t.srLink.down();
		t.sManager.handlePeerDisconnected(t.rPub);
		t.rManager.handlePeerDisconnected(t.sPub);

		t.pManager.addHtlc(
			t.psChannelId,
			1_000_000n,
			t.hashes[0],
			900,
			Buffer.alloc(1366)
		);
		await flush();

		expect(t.pFulfilled.length, t.sErrors.join('; ')).to.equal(1);
		// The preimage is the TOWER's P_1 (not S's secret), and it hashes to H_1.
		expect(t.pFulfilled[0].equals(t.towerPreimages[0])).to.equal(true);
		expect(sha256(t.pFulfilled[0]).equals(t.hashes[0])).to.equal(true);
		const sEpoch = t.sChannel.getFforEpoch()!;
		expect(sEpoch.lastSeq).to.equal(1);
		expect(sEpoch.upstreamFulfilled[0]).to.equal(true);
		// The tower durably stored the package before releasing.
		expect(t.towerStore.saveLog.length).to.equal(1);
	});

	it('fails the payment upstream when the tower rejects (S has no preimage)', async function () {
		const t = await setupVariantB({ rejectTower: true });
		t.srLink.down();
		t.sManager.handlePeerDisconnected(t.rPub);
		t.rManager.handlePeerDisconnected(t.sPub);

		t.pManager.addHtlc(
			t.psChannelId,
			1_000_000n,
			t.hashes[0],
			900,
			Buffer.alloc(1366)
		);
		await flush();

		expect(t.pFulfilled.length).to.equal(0);
		expect(t.pFailed.length).to.equal(1);
		expect(
			t.sErrors.some((e) => e.includes('tower rejected settlement'))
		).to.equal(true);
		// S built + persisted the package but never fulfilled upstream.
		expect(t.sChannel.getFforEpoch()!.upstreamFulfilled[0] ?? false).to.equal(
			false
		);
	});

	it('S crash between release and fulfill replays idempotently (no new tower round)', async function () {
		const t = await setupVariantB();
		t.srLink.down();
		t.sManager.handlePeerDisconnected(t.rPub);
		t.rManager.handlePeerDisconnected(t.sPub);

		// S "crashes" at the moment the preimage is stored but not yet fulfilled:
		// snapshot S's durable state and cut the P-S link so the live fulfill
		// never reaches P.
		let snapshot: { sr: string; sp: string } | null = null;
		t.sManager.on('channel:persist', (cid: Buffer) => {
			if (!cid.equals(t.srChannelId) || snapshot) return;
			const e = t.sChannel.getFforEpoch();
			if (
				e &&
				e.lastSeq === 1 &&
				e.preimages[0]?.length === 32 &&
				!e.upstreamFulfilled[0]
			) {
				snapshot = {
					sr: JSON.stringify(serializeChannelState(t.sChannel.getFullState())),
					sp: JSON.stringify(
						serializeChannelState(
							t.sManager.getChannelsByPeer(t.pPub)[0].getFullState()
						)
					)
				};
				t.psLink.down(); // the crash: S's fulfill never reaches P
			}
		});
		t.pManager.addHtlc(
			t.psChannelId,
			1_000_000n,
			t.hashes[0],
			900,
			Buffer.alloc(1366)
		);
		await flush();
		expect(snapshot, 'crash-window snapshot captured').to.not.equal(null);
		expect(t.pFulfilled.length).to.equal(0); // fulfill died with S
		const towerSavesAtCrash = t.towerStore.saveLog.length;

		// Restart S from the snapshot (package + preimage present, unfulfilled).
		const s2 = new ChannelManager(t.sConfig);
		s2.on('error', () => {});
		s2.setFforTowerClient(new LoopbackTowerClient(t.tower));
		const s2sr = new Channel(deserializeChannelState(JSON.parse(snapshot!.sr)));
		const s2sp = new Channel(deserializeChannelState(JSON.parse(snapshot!.sp)));
		s2.restoreChannel(s2sr, t.rPub);
		s2.restoreChannel(s2sp, t.pPub);
		const e2 = s2sr.getFforEpoch()!;
		expect(e2.lastSeq).to.equal(1);
		expect(e2.upstreamFulfilled[0] ?? false).to.equal(false);
		expect(e2.preimages[0].length).to.equal(32);

		// P reconnects to the restarted S; reestablish replays the settlement
		// engine, which fulfills from the PERSISTED preimage.
		t.pManager.handlePeerDisconnected(t.sPub);
		connect(s2, t.sPub, t.pManager, t.pPub);
		const payloadOf = (as: ReturnType<Channel['createReestablish']>): Buffer =>
			(
				as.find((a) => a.type === ChannelActionType.SEND_MESSAGE) as {
					payload: Buffer;
				}
			).payload;
		const s2Re = payloadOf(s2sp.createReestablish());
		const pRe = payloadOf(t.pChannel.createReestablish());
		t.pManager.handleMessage(t.sPub, MessageType.CHANNEL_REESTABLISH, s2Re);
		s2.handleMessage(t.pPub, MessageType.CHANNEL_REESTABLISH, pRe);
		await flush();

		expect(t.pFulfilled.length).to.equal(1);
		expect(sha256(t.pFulfilled[0]).equals(t.hashes[0])).to.equal(true);
		expect(s2sr.getFforEpoch()!.upstreamFulfilled[0]).to.equal(true);
		// No NEW tower release was needed — the preimage was already persisted.
		expect(t.towerStore.saveLog.length).to.equal(towerSavesAtCrash);
	});

	it('R recovers packages + preimages from the tower alone (S gone) and adopts C_j^R', async function () {
		const t = await setupVariantB();
		t.srLink.down();
		t.sManager.handlePeerDisconnected(t.rPub);
		t.rManager.handlePeerDisconnected(t.sPub);

		// Two delegated payments settle via the tower while R is offline.
		t.pManager.addHtlc(
			t.psChannelId,
			1_000_000n,
			t.hashes[0],
			900,
			Buffer.alloc(1366)
		);
		await flush();
		t.pManager.addHtlc(
			t.psChannelId,
			550_000n,
			t.hashes[1],
			900,
			Buffer.alloc(1366)
		);
		await flush();
		expect(t.pFulfilled.length).to.equal(2);

		// S VANISHES. R returns and recovers everything from the tower alone.
		const recover = await t.rManager.fforRecoverFromTower(
			t.srChannelId,
			new LoopbackTowerClient(t.tower)
		);
		expect(recover.ok, t.rErrors.join('; ')).to.equal(true);

		const rEpoch = t.rChannel.getFforEpoch()!;
		expect(rEpoch.lastSeq).to.equal(2);
		for (let k = 0; k < 2; k++) {
			expect(sha256(rEpoch.preimages[k]).equals(t.hashes[k])).to.equal(true);
		}
		// R can now prepare a force-close of the adopted C_2^R.
		const prep = t.rChannel.fforPrepareForceClose();
		expect(prep).to.equal(null);
		expect(t.rChannel.getCommitmentNumbers().local).to.equal(rEpoch.nR + 2n);
		expect(t.rChannel.getFullState().htlcs.size).to.equal(2);
	});

	it('R tower recovery rejects unauthenticated / wrong-key fetches', async function () {
		const t = await setupVariantB();
		t.srLink.down();
		t.sManager.handlePeerDisconnected(t.rPub);
		t.rManager.handlePeerDisconnected(t.sPub);
		t.pManager.addHtlc(
			t.psChannelId,
			1_000_000n,
			t.hashes[0],
			900,
			Buffer.alloc(1366)
		);
		await flush();

		// A DIFFERENT node (not R) tries to recover: its node key does not
		// authenticate against the tower's provisioned rNodeId.
		const impostor = new ChannelManager(makeConfig(`impostor-${vbId}`));
		impostor.on('error', () => {});
		// Give the impostor R's channel so the call reaches the tower fetch.
		const rState = deserializeChannelState(
			JSON.parse(
				JSON.stringify(serializeChannelState(t.rChannel.getFullState()))
			)
		);
		impostor.restoreChannel(new Channel(rState), t.sPub);
		const res = await impostor.fforRecoverFromTower(
			t.srChannelId,
			new LoopbackTowerClient(t.tower)
		);
		expect(res.ok).to.equal(false);
		expect(res.error).to.match(/authentication|rejected/);
	});
});
