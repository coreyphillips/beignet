/**
 * FFOR (specs/ffor-offline-receive.md) — M1 epoch-establishment tests.
 *
 * Two beignet endpoints (ChannelManager loopback, the splice-test pattern)
 * drive the full setup handshake: happy paths for variants A and B, every
 * setup-time validation rejection producing ff_error, the FF_EPOCH update
 * freeze, zero-settlement cooperative close via ff_end, and the M1 gate —
 * epoch established, both sides restart from storage, epoch state recovered
 * byte-equal and FF_EPOCH restored after reestablish.
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
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import {
	FF_INIT_TYPE,
	IFforInitMessage,
	encodeFforInitMessage,
	signFforMessage
} from '../../src/lightning/ffor/messages';
import {
	FforEpochState,
	IFforEpochParams
} from '../../src/lightning/ffor/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	serializeChannelState,
	serializeFforEpoch
} from '../../src/lightning/storage/serialization';

// ─────────────── Test scaffolding (splice.test.ts pattern) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`ffor-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
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
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeConfig(seedId: number): IChannelManagerConfig & {
	nodePrivateKey: Buffer;
} {
	const seed = makeSeed(seedId);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-key'))
			.digest(),
		// FFOR prerequisite (spec §5): anchor commitments.
		preferAnchors: true
	};
}

function connectManagers(
	managerA: ChannelManager,
	pubkeyA: string,
	managerB: ChannelManager,
	pubkeyB: string
): void {
	managerA.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (peer === pubkeyB) managerB.handleMessage(pubkeyA, type, payload);
		}
	);
	managerB.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (peer === pubkeyA) managerA.handleMessage(pubkeyB, type, payload);
		}
	);
}

const FUNDING_SATOSHIS = 1_000_000n;

interface IPair {
	/** S — settlement peer (the opener: holds the channel's funds). */
	sManager: ChannelManager;
	sChannel: Channel;
	sPubkey: string;
	sErrors: string[];
	/** R — recipient (the acceptor: initiates the FFOR epoch). */
	rManager: ChannelManager;
	rChannel: Channel;
	rPubkey: string;
	rErrors: string[];
	rNodeKey: Buffer;
	channelId: Buffer;
	sConfig: IChannelManagerConfig;
	rConfig: IChannelManagerConfig;
}

let pairSeed = 0;

/**
 * A NORMAL channel pair where S (opener) holds the full 1M-sat balance —
 * exactly the provisioning FFOR needs (the budget converts S's local balance
 * into vouchers).
 */
function createNormalChannelPair(): IPair {
	pairSeed += 10;
	const sConfig = makeConfig(500 + pairSeed);
	const rConfig = makeConfig(501 + pairSeed);
	// Manager peer ids are the NODE ids — ff_init/ff_accept signatures verify
	// against them, exactly as PeerManager routes by node pubkey in production.
	const sPubkey = getPublicKey(sConfig.nodePrivateKey!).toString('hex');
	const rPubkey = getPublicKey(rConfig.nodePrivateKey!).toString('hex');

	const sManager = new ChannelManager(sConfig);
	const rManager = new ChannelManager(rConfig);
	const sErrors: string[] = [];
	const rErrors: string[] = [];
	sManager.on('error', (_id, msg: string) => sErrors.push(msg));
	rManager.on('error', (_id, msg: string) => rErrors.push(msg));

	connectManagers(sManager, sPubkey, rManager, rPubkey);

	const sChannel = sManager.openChannel(rPubkey, FUNDING_SATOSHIS);
	sManager.createFunding(
		sChannel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	);
	const channelId = sChannel.getChannelId()!;
	sManager.handleFundingConfirmed(channelId);
	rManager.handleFundingConfirmed(channelId);

	const rChannels = rManager.getChannelsByPeer(sPubkey);
	expect(rChannels.length).to.equal(1);
	const rChannel = rChannels[0];

	expect(sChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(rChannel.getState()).to.equal(ChannelState.NORMAL);

	return {
		sManager,
		sChannel,
		sPubkey,
		sErrors,
		rManager,
		rChannel,
		rPubkey,
		rErrors,
		rNodeKey: rConfig.nodePrivateKey!,
		channelId,
		sConfig,
		rConfig
	};
}

type ParamsInput = Omit<IFforEpochParams, 'rPerCommitmentPoints'> & {
	rPerCommitmentPoints?: Buffer[];
};

/** Variant A terms sized for the 1M-sat test channel. */
function paramsA(overrides?: Partial<ParamsInput>): ParamsInput {
	return {
		variant: 1,
		budgetMsat: 500_000_000n,
		maxPayments: 5,
		minPaymentMsat: 400_000n,
		settlementDeadline: 1000,
		voucherExpiry: 2008, // = D + 1008 (the enforced reconcile margin)
		feeBaseMsat: 1000,
		feeProportionalMillionths: 100,
		escapeGranularityMsat: 0n,
		...overrides
	};
}

/** Variant B terms: tower hash set + tower TLVs + escapes (G > 0). */
function paramsB(overrides?: Partial<ParamsInput>): ParamsInput {
	return paramsA({
		variant: 2,
		escapeGranularityMsat: 50_000_000n, // J = ceil(500M/50M) = 10 escapes
		paymentHashes: Array.from({ length: 5 }, () => crypto.randomBytes(32)),
		towerNodeId: getPublicKey(makeSeed(9999)),
		towerUri: 'https://tower.example:9911',
		...overrides
	});
}

function point(fill: number): Buffer {
	return Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32, fill)]);
}

/**
 * Craft a signed ff_init directly (bypassing R's local pre-validation) and
 * inject it into S — exercises S's §7.2/§8 checks and its ff_error path.
 * Drives quiescence first (spec §5: setup starts from a quiescent channel).
 */
function injectInit(pair: IPair, params: ParamsInput): void {
	const quiesce = pair.rManager.initiateQuiescence(pair.channelId);
	expect(quiesce.ok).to.equal(true);

	const msg: IFforInitMessage = {
		channelId: pair.channelId,
		epochId: crypto.randomBytes(32),
		variant: params.variant,
		budgetMsat: params.budgetMsat,
		maxPayments: params.maxPayments,
		minPaymentMsat: params.minPaymentMsat,
		settlementDeadline: params.settlementDeadline,
		voucherExpiry: params.voucherExpiry,
		feeBaseMsat: params.feeBaseMsat,
		feeProportionalMillionths: params.feeProportionalMillionths,
		escapeGranularityMsat: params.escapeGranularityMsat,
		rPerCommitmentPoints:
			params.rPerCommitmentPoints ??
			Array.from({ length: params.maxPayments }, (_, i) => point(i + 1)),
		paymentHashes: params.paymentHashes,
		towerNodeId: params.towerNodeId,
		towerUri: params.towerUri,
		signature: Buffer.alloc(64)
	};
	const payload = signFforMessage(
		FF_INIT_TYPE,
		encodeFforInitMessage(msg),
		pair.rNodeKey
	);
	pair.sManager.handleMessage(pair.rPubkey, MessageType.FF_INIT, payload);
}

/** Expect S to have refused the epoch with an ff_error carrying `reason`. */
function expectRejected(pair: IPair, reason: string): void {
	expect(
		pair.sErrors.some((e) => e.includes(reason)),
		pair.sErrors.join('; ')
	).to.equal(true);
	expect(pair.sChannel.getFforEpoch()).to.equal(null);
	expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
	// The ff_error crossed the wire: R (which never created an epoch for the
	// crafted init) surfaces it.
	expect(pair.rErrors.some((e) => e.includes('ff_error from peer'))).to.equal(
		true
	);
}

describe('FFOR epoch establishment (M1)', function () {
	// ─────────────── Happy paths ───────────────

	it('establishes a variant A epoch to FF_EPOCH on both sides', function () {
		const pair = createNormalChannelPair();
		const result = pair.rManager.initiateFforEpoch(pair.channelId, paramsA());
		expect(result.ok, pair.rErrors.concat(pair.sErrors).join('; ')).to.equal(
			true
		);

		// Both channels froze into FF_EPOCH.
		expect(pair.rChannel.getState()).to.equal(ChannelState.FF_EPOCH);
		expect(pair.sChannel.getState()).to.equal(ChannelState.FF_EPOCH);

		const r = pair.rChannel.getFforEpoch()!;
		const s = pair.sChannel.getFforEpoch()!;
		expect(r.role).to.equal('recipient');
		expect(s.role).to.equal('settlement_peer');
		expect(r.state).to.equal(FforEpochState.FF_EPOCH);
		expect(s.state).to.equal(FforEpochState.FF_EPOCH);
		expect(r.epochId.equals(s.epochId)).to.equal(true);

		// Variant A: S generated the K hashes; R adopted them from ff_accept.
		expect(s.params.paymentHashes).to.have.length(5);
		for (let i = 0; i < 5; i++) {
			expect(
				r.params.paymentHashes![i].equals(s.params.paymentHashes![i])
			).to.equal(true);
		}
		// n0 recorded identically on both sides.
		expect(r.sCommitmentNumber).to.equal(
			pair.sChannel.getCommitmentNumbers().local
		);
		expect(s.sCommitmentNumber).to.equal(r.sCommitmentNumber);

		// K amountless invoices flowed R→S and match on both sides.
		expect(r.invoices).to.have.length(5);
		expect(s.invoices).to.deep.equal(r.invoices);
		for (const inv of s.invoices) {
			expect(inv.startsWith('lnbc1')).to.equal(true); // amountless mainnet HRP
		}

		// The signed-message evidence was retained (§12.2).
		expect(s.initSignature).to.not.equal(null);
		expect(s.acceptSignature).to.not.equal(null);
		expect(r.acceptSignature).to.not.equal(null);

		// R pre-shared exactly K per-commitment points.
		expect(r.params.rPerCommitmentPoints).to.have.length(5);
		expect(
			s.params.rPerCommitmentPoints[4].equals(r.params.rPerCommitmentPoints[4])
		).to.equal(true);
	});

	it('establishes a variant B epoch (tower TLVs + escape placeholders)', function () {
		const pair = createNormalChannelPair();
		const params = paramsB();
		const result = pair.rManager.initiateFforEpoch(pair.channelId, params);
		expect(result.ok, pair.rErrors.concat(pair.sErrors).join('; ')).to.equal(
			true
		);

		expect(pair.rChannel.getState()).to.equal(ChannelState.FF_EPOCH);
		expect(pair.sChannel.getState()).to.equal(ChannelState.FF_EPOCH);

		const s = pair.sChannel.getFforEpoch()!;
		// The tower hash set travelled in ff_init.
		for (let i = 0; i < 5; i++) {
			expect(
				s.params.paymentHashes![i].equals(params.paymentHashes![i])
			).to.equal(true);
		}
		expect(s.params.towerNodeId!.equals(params.towerNodeId!)).to.equal(true);
		expect(s.params.towerUri).to.equal('https://tower.example:9911');

		// ff_escape_sigs flowed: J = ceil(500M / 50M) = 10 placeholder sigs
		// (escape-commitment construction/signing is M3/M5).
		expect(s.escapeSigs).to.have.length(10);
		const r = pair.rChannel.getFforEpoch()!;
		expect(r.escapeSigs).to.have.length(10);
	});

	// ─────────────── Setup-time validation rejections (§8 → ff_error) ───────────────

	it('rejects a budget exceeding S spendable balance − reserve − G', function () {
		const pair = createNormalChannelPair();
		// S holds 1e9 msat; reserve 1e7 msat — a full-balance budget must fail.
		injectInit(pair, paramsA({ budgetMsat: 1_000_000_000n }));
		expectRejected(pair, "exceeds settlement peer's spendable");
	});

	it('rejects K above max_accepted_htlcs', function () {
		const pair = createNormalChannelPair();
		injectInit(pair, paramsA({ maxPayments: 500 }));
		expectRejected(pair, 'exceeds max_accepted_htlcs');
	});

	it('rejects T_exp too close to the settlement deadline D', function () {
		const pair = createNormalChannelPair();
		injectInit(pair, paramsA({ voucherExpiry: 1100 })); // D + 100 < D + 1008
		expectRejected(pair, 'too close to settlement_deadline');
	});

	it('rejects min_payment_msat below the voucher dust floor', function () {
		const pair = createNormalChannelPair();
		// Anchor channel: floor = dust_limit (354 sat) = 354_000 msat.
		injectInit(pair, paramsA({ minPaymentMsat: 100_000n }));
		expectRejected(pair, 'below voucher dust floor');
	});

	it('rejects variant B without the tower TLVs', function () {
		const pair = createNormalChannelPair();
		injectInit(pair, paramsB({ towerNodeId: undefined, towerUri: undefined }));
		expectRejected(pair, 'variant B requires tower_node_id');
	});

	it('rejects variant B without payment_hashes', function () {
		const pair = createNormalChannelPair();
		injectInit(pair, paramsB({ paymentHashes: undefined }));
		expectRejected(pair, 'variant B requires payment_hashes');
	});

	it('rejects variant A carrying payment_hashes in ff_init', function () {
		const pair = createNormalChannelPair();
		injectInit(
			pair,
			paramsA({
				paymentHashes: Array.from({ length: 5 }, () => crypto.randomBytes(32))
			})
		);
		expectRejected(pair, 'must not carry payment_hashes');
	});

	it('rejects a tampered ff_init node-key signature', function () {
		const pair = createNormalChannelPair();
		const quiesce = pair.rManager.initiateQuiescence(pair.channelId);
		expect(quiesce.ok).to.equal(true);
		const msg: IFforInitMessage = {
			channelId: pair.channelId,
			epochId: crypto.randomBytes(32),
			...(paramsA() as Omit<ParamsInput, 'rPerCommitmentPoints'>),
			rPerCommitmentPoints: Array.from({ length: 5 }, (_, i) => point(i + 1)),
			signature: Buffer.alloc(64)
		} as IFforInitMessage;
		const payload = signFforMessage(
			FF_INIT_TYPE,
			encodeFforInitMessage(msg),
			pair.rNodeKey
		);
		payload[70] ^= 0x01; // corrupt a signed body byte
		pair.sManager.handleMessage(pair.rPubkey, MessageType.FF_INIT, payload);
		expectRejected(pair, 'signature invalid');
	});

	it('rejects ff_init when the channel is not quiescent', function () {
		const pair = createNormalChannelPair();
		// No quiescence handshake at all.
		const msg: IFforInitMessage = {
			channelId: pair.channelId,
			epochId: crypto.randomBytes(32),
			...(paramsA() as Omit<ParamsInput, 'rPerCommitmentPoints'>),
			rPerCommitmentPoints: Array.from({ length: 5 }, (_, i) => point(i + 1)),
			signature: Buffer.alloc(64)
		} as IFforInitMessage;
		const payload = signFforMessage(
			FF_INIT_TYPE,
			encodeFforInitMessage(msg),
			pair.rNodeKey
		);
		pair.sManager.handleMessage(pair.rPubkey, MessageType.FF_INIT, payload);
		expectRejected(pair, 'not quiescent');
	});

	it('pre-validates locally on the initiator without quiescing', function () {
		const pair = createNormalChannelPair();
		const result = pair.rManager.initiateFforEpoch(
			pair.channelId,
			paramsA({ voucherExpiry: 1100 })
		);
		expect(result.ok).to.equal(false);
		expect(
			pair.rErrors.some((e) => e.includes('too close to settlement_deadline'))
		).to.equal(true);
		// No stfu was sent — the request failed before touching the wire.
		expect(pair.rChannel.isQuiescing()).to.equal(false);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
	});

	it('enforces epoch_id uniqueness per channel', function () {
		const pair = createNormalChannelPair();
		const epochId = crypto.randomBytes(32);
		const first = pair.rManager.initiateFforEpoch(pair.channelId, paramsA(), {
			epochId
		});
		expect(first.ok).to.equal(true);
		expect(pair.rChannel.getState()).to.equal(ChannelState.FF_EPOCH);

		// Close the epoch, then try to reuse the id.
		const end = pair.rManager.endFforEpoch(pair.channelId);
		expect(end.ok).to.equal(true);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);

		const reuse = pair.rManager.initiateFforEpoch(pair.channelId, paramsA(), {
			epochId
		});
		expect(reuse.ok).to.equal(false);
		expect(
			pair.rErrors.some((e) => e.includes('epoch_id already used'))
		).to.equal(true);
	});

	// ─────────────── FF_EPOCH freeze ───────────────

	it('rejects normal update traffic during FF_EPOCH', function () {
		const pair = createNormalChannelPair();
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, paramsA()).ok
		).to.equal(true);

		// Local adds on both sides are refused.
		const rAdd = pair.rChannel.addHtlc(
			1_000_000n,
			crypto.randomBytes(32),
			800,
			Buffer.alloc(1366)
		);
		expect(rAdd[0].type).to.equal(ChannelActionType.ERROR);
		expect((rAdd[0] as { message: string }).message).to.include('FF_EPOCH');

		const sAdd = pair.sChannel.addHtlc(
			1_000_000n,
			crypto.randomBytes(32),
			800,
			Buffer.alloc(1366)
		);
		expect(sAdd[0].type).to.equal(ChannelActionType.ERROR);

		// update_fee is refused (S is the opener).
		const fee = pair.sChannel.updateFee(300);
		expect(fee[0].type).to.equal(ChannelActionType.ERROR);

		// A wire update_add_htlc is refused too.
		const before = pair.sErrors.length;
		pair.sManager.handleMessage(
			pair.rPubkey,
			MessageType.UPDATE_ADD_HTLC,
			encodeUpdateAddHtlcMessage({
				channelId: pair.channelId,
				id: 0n,
				amountMsat: 1_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 800,
				onionRoutingPacket: Buffer.alloc(1366)
			})
		);
		expect(pair.sErrors.length).to.be.greaterThan(before);
		expect(
			pair.sErrors.some((e) => e.includes('Unexpected update_add_htlc'))
		).to.equal(true);
	});

	// ─────────────── ff_end: zero-settlement cooperative close ───────────────

	it('closes a zero-settlement epoch via ff_end back to OPERATIONAL', function () {
		const pair = createNormalChannelPair();
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, paramsA()).ok
		).to.equal(true);

		const end = pair.rManager.endFforEpoch(pair.channelId);
		expect(end.ok).to.equal(true);

		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.rChannel.getFforEpoch()!.state).to.equal(
			FforEpochState.FF_CLOSED
		);
		expect(pair.sChannel.getFforEpoch()!.state).to.equal(
			FforEpochState.FF_CLOSED
		);

		// A NEW epoch (fresh id) can be opened on the same channel.
		const again = pair.rManager.initiateFforEpoch(pair.channelId, paramsA());
		expect(again.ok).to.equal(true);
		expect(
			pair.rChannel.getState(),
			pair.rErrors.concat(pair.sErrors).join('; ')
		).to.equal(ChannelState.FF_EPOCH);
		expect(pair.sChannel.getState()).to.equal(ChannelState.FF_EPOCH);
		expect(pair.rManager.endFforEpoch(pair.channelId).ok).to.equal(true);

		// Normal operation resumes: an HTLC add now emits update_add_htlc.
		const add = pair.sChannel.addHtlc(
			1_000_000n,
			crypto.randomBytes(32),
			800,
			Buffer.alloc(1366)
		);
		expect(add[0].type).to.equal(ChannelActionType.SEND_MESSAGE);
	});

	// ─────────────── Disconnect during setup ───────────────

	it('aborts a mid-setup epoch cleanly on disconnect (nothing durable pre-ff_begin)', function () {
		const pair = createNormalChannelPair();
		// Put S into FF_SETUP without completing the handshake: quiesce, then
		// deliver only a crafted ff_init (R never created an epoch, so its
		// manager errors on S's ff_accept and the handshake stalls there).
		injectInit(pair, paramsA());
		expect(pair.sChannel.getState()).to.equal(ChannelState.FF_SETUP);
		expect(pair.sChannel.getFforEpoch()).to.not.equal(null);

		pair.sChannel.markForReestablish();
		expect(pair.sChannel.getState()).to.equal(
			ChannelState.AWAITING_REESTABLISH
		);
		// The setup was discarded — the channel will come back as NORMAL.
		expect(pair.sChannel.getFforEpoch()).to.equal(null);
		expect(pair.sChannel.getFullState().preReestablishState).to.equal(
			ChannelState.NORMAL
		);
	});

	// ─────────────── M1 GATE: restart both sides, recover the epoch ───────────────

	it('M1 GATE: epoch established → disconnect + full restart from storage → epoch recovered byte-equal', function () {
		const pair = createNormalChannelPair();
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, paramsB()).ok
		).to.equal(true);
		expect(pair.rChannel.getState()).to.equal(ChannelState.FF_EPOCH);
		expect(pair.sChannel.getState()).to.equal(ChannelState.FF_EPOCH);

		const idHex = pair.channelId.toString('hex');
		const fforBlobBefore = {
			r: JSON.stringify(serializeFforEpoch(pair.rChannel.getFullState().ffor!)),
			s: JSON.stringify(serializeFforEpoch(pair.sChannel.getFullState().ffor!))
		};

		// "R disconnects; both sides restart": persist through the real storage
		// layer, then rebuild everything from what it stored.
		const rStorage = new SqliteStorage(':memory:');
		const sStorage = new SqliteStorage(':memory:');
		rStorage.open();
		sStorage.open();
		rStorage.saveChannel(idHex, pair.rChannel.getFullState(), pair.sPubkey);
		sStorage.saveChannel(idHex, pair.sChannel.getFullState(), pair.rPubkey);

		const rLoaded = rStorage.loadChannel(idHex)!;
		const sLoaded = sStorage.loadChannel(idHex)!;
		expect(rLoaded).to.not.equal(null);
		expect(sLoaded).to.not.equal(null);

		const rManager2 = new ChannelManager(pair.rConfig);
		const sManager2 = new ChannelManager(pair.sConfig);
		const errors2: string[] = [];
		rManager2.on('error', (_id, m: string) => errors2.push(`R: ${m}`));
		sManager2.on('error', (_id, m: string) => errors2.push(`S: ${m}`));
		connectManagers(sManager2, pair.sPubkey, rManager2, pair.rPubkey);

		const rChannel2 = new Channel(rLoaded.state);
		const sChannel2 = new Channel(sLoaded.state);
		rManager2.restoreChannel(rChannel2, rLoaded.peerPubkey);
		sManager2.restoreChannel(sChannel2, sLoaded.peerPubkey);

		// Restored channels await reestablish, remembering FF_EPOCH.
		expect(rChannel2.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(sChannel2.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

		// The recovered epoch state is byte-equal BEFORE any reconnection.
		expect(
			JSON.stringify(serializeFforEpoch(rChannel2.getFullState().ffor!))
		).to.equal(fforBlobBefore.r);
		expect(
			JSON.stringify(serializeFforEpoch(sChannel2.getFullState().ffor!))
		).to.equal(fforBlobBefore.s);
		// Params / hashes / points / invoices / sigs survived on both sides.
		const r2 = rChannel2.getFforEpoch()!;
		const s2 = sChannel2.getFforEpoch()!;
		expect(r2.state).to.equal(FforEpochState.FF_EPOCH);
		expect(s2.state).to.equal(FforEpochState.FF_EPOCH);
		expect(r2.params.paymentHashes).to.have.length(5);
		expect(s2.params.rPerCommitmentPoints).to.have.length(5);
		expect(s2.invoices).to.deep.equal(r2.invoices);
		expect(s2.escapeSigs).to.have.length(10);
		expect(s2.initSignature).to.not.equal(null);

		// Reconnect: exchange channel_reestablish both ways.
		const rRe = rChannel2
			.createReestablish()
			.find((a) => a.type === ChannelActionType.SEND_MESSAGE)!;
		const sRe = sChannel2
			.createReestablish()
			.find((a) => a.type === ChannelActionType.SEND_MESSAGE)!;
		sManager2.handleMessage(
			pair.rPubkey,
			MessageType.CHANNEL_REESTABLISH,
			(rRe as { payload: Buffer }).payload
		);
		rManager2.handleMessage(
			pair.sPubkey,
			MessageType.CHANNEL_REESTABLISH,
			(sRe as { payload: Buffer }).payload
		);

		// Both sides are back in FF_EPOCH with the epoch intact.
		expect(rChannel2.getState(), errors2.join('; ')).to.equal(
			ChannelState.FF_EPOCH
		);
		expect(sChannel2.getState(), errors2.join('; ')).to.equal(
			ChannelState.FF_EPOCH
		);
		expect(
			JSON.stringify(serializeFforEpoch(rChannel2.getFullState().ffor!))
		).to.equal(fforBlobBefore.r);

		// The epoch is fully operable post-restart: ff_end closes it.
		const end = rManager2.endFforEpoch(pair.channelId);
		expect(end.ok, errors2.join('; ')).to.equal(true);
		expect(rChannel2.getState()).to.equal(ChannelState.NORMAL);
		expect(sChannel2.getState()).to.equal(ChannelState.NORMAL);

		// The serialized-channel round trip also carries the used-epoch-id set.
		expect(
			serializeChannelState(rChannel2.getFullState()).fforUsedEpochIds
		).to.have.length(1);

		rStorage.close();
		sStorage.close();
	});
});
