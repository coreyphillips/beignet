/**
 * ChannelManager.provideV2ExternalWitness (issue #572): the manager-level
 * entry point over the channel machinery from issue #554, exercised through a
 * full two-manager v2 open whose OPENER contributes one own wallet input plus
 * one EXTERNAL input (witness delivered out of band).
 *
 * The scenario is the fork's 97df373 promote-on-ready stall, end to end: the
 * zero-contribution acceptor signs first (BOLT 2 lower-total ordering) and,
 * zero-conf, fast-tracks its channel_ready while the opener is still
 * withholding tx_signatures on the external hole. The opener must be
 * resolvable by its permanent id when that early channel_ready lands
 * (promotion at AWAITING_TX_SIGNATURES with a v2InFlight record, plus
 * handleChannelReady's temp fallback), and the out-of-band witness delivery
 * through the NEW manager API must release the exchange and bring both sides
 * to NORMAL.
 *
 * Also pinned here: the manager refuses an unknown channel id with an 'error'
 * event, refuses an invalid witness WITHOUT an 'error' event and without
 * touching the open (the channel-throw refusal convention), and answers a
 * post-release duplicate delivery as an ok no-op.
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
import { IV2InFlight } from '../../src/lightning/channel/channel-state';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { encodeChannelReadyMessage } from '../../src/lightning/message/channel-funding';
import {
	decodeTxSignaturesMessage,
	encodeTxInitRbfMessage
} from '../../src/lightning/message/interactive-tx';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { ChannelSigner } from '../../src/lightning/keys/signer';

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

function openerParams(side: ISide): IDualFundingParams {
	return {
		fundingSatoshis: OPENER_FUNDING,
		fundingFeeratePerkw: FEERATE_PERKW,
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
		)
	};
}

interface ITxSigsNeededEvent {
	channelId: Buffer;
	inputIndices: number[];
	externalInputIndices?: number[];
}

interface IWithholdSetup {
	mgrA: ChannelManager;
	mgrB: ChannelManager;
	chA: Channel;
	errors: string[];
	broadcasts: Buffer[];
	aSent: number[];
	bSent: number[];
	needed: ITxSigsNeededEvent[];
	/** Last payload the acceptor sent, per message type (for retransmits). */
	bLastPayload: Map<number, Buffer>;
	extPrevTx: bitcoin.Transaction;
	extPriv: Buffer;
	extPub: Buffer;
	sideB: ISide;
	/** Drain the queued A-to-B direction (B answers synchronously). */
	pump: () => void;
}

const OPENER_FUNDING = 50_000n;
const OWN_UTXO_SATS = 40_000;
const EXT_UTXO_SATS = 30_000;
const FEERATE_PERKW = 1000;

/**
 * Drive a trusted zero-conf v2 open between two ChannelManagers to the point
 * where the opener's tx_signatures release is due but withheld on its
 * unfilled external slot, with the acceptor's tx_signatures AND early
 * channel_ready already processed.
 *
 * The A-to-B direction is queued and pumped manually so the opener's
 * contribution (own + external input) registers between
 * createDualFundedChannel and open_channel2 delivery, exactly as an embedder
 * does over a real transport; the guard arm in autoFundDualFundedOpen must
 * then drive the registered contribution (neither manager has a funding
 * provider, so any selection attempt would fail loudly).
 */
function driveToWithhold(opts?: {
	/**
	 * Stop delivering the peer's (B-to-A) messages at the first one of this
	 * type, leaving it and everything after queued: lets a test observe the
	 * opener BEFORE the peer's tx_signatures arrive.
	 */
	holdPeerFrom?: MessageType;
	/**
	 * Open WITHOUT the zero-conf trusted fast track: exercises guards the
	 * zero-conf refusals would otherwise mask (the RBF ready-window,
	 * issue #581).
	 */
	plain?: boolean;
}): IWithholdSetup {
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

	const needed: ITxSigsNeededEvent[] = [];
	mgrA.on(
		'channel:txsigs-needed',
		(
			channelId: Buffer,
			_fundingTxid: Buffer,
			_fundingOutputIndex: number,
			inputIndices: number[],
			externalInputIndices?: number[]
		) => {
			needed.push({ channelId, inputIndices, externalInputIndices });
		}
	);

	// Both directions queued and relayed by pump(), so the opener's
	// contribution registers before its open_channel2 is delivered and a
	// test can hold the peer's later messages back (holdPeerFrom). Each
	// A-to-B delivery is followed by draining B's responses, matching the
	// per-direction FIFO a real transport gives.
	const aSent: number[] = [];
	const bSent: number[] = [];
	const aToB: Array<[number, Buffer]> = [];
	const bToA: Array<[number, Buffer]> = [];
	const bLastPayload = new Map<number, Buffer>();
	mgrA.on(
		'message:outbound',
		(_peer: string, type: number, payload: Buffer) => {
			aSent.push(type);
			aToB.push([type, payload]);
		}
	);
	mgrB.on(
		'message:outbound',
		(_peer: string, type: number, payload: Buffer) => {
			bSent.push(type);
			bLastPayload.set(type, payload);
			bToA.push([type, payload]);
		}
	);
	const deliverPeerQueue = (): boolean => {
		let moved = false;
		while (bToA.length > 0) {
			if (
				opts?.holdPeerFrom !== undefined &&
				bToA[0][0] === opts.holdPeerFrom
			) {
				return moved;
			}
			const [type, payload] = bToA.shift()!;
			mgrA.handleMessage(sideB.pubkey, type, payload);
			moved = true;
		}
		return moved;
	};
	const pump = (): void => {
		let progressed = true;
		while (progressed) {
			progressed = deliverPeerQueue();
			if (aToB.length > 0) {
				const [type, payload] = aToB.shift()!;
				mgrB.handleMessage(sideA.pubkey, type, payload);
				progressed = true;
			}
		}
	};

	if (!opts?.plain) {
		mgrA.addTrustedPeer(sideB.pubkey);
		mgrB.addTrustedPeer(sideA.pubkey);
	}

	const chA = mgrA.createDualFundedChannel(
		sideB.pubkey,
		openerParams(sideA),
		opts?.plain ? undefined : { trusted: true }
	);

	// Own P2WPKH wallet input with a real signing closure.
	const ownPriv = crypto.randomBytes(32);
	const ownPub = getPublicKey(ownPriv);
	const ownScriptCode = bitcoin.payments.p2pkh({ pubkey: ownPub }).output!;
	const ownPrevTx = new bitcoin.Transaction();
	ownPrevTx.version = 2;
	ownPrevTx.addInput(crypto.randomBytes(32), 0);
	ownPrevTx.addOutput(
		bitcoin.payments.p2wpkh({ pubkey: ownPub }).output!,
		OWN_UTXO_SATS
	);
	const ownInput: ISpliceWalletInput = {
		prevTx: ownPrevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(OWN_UTXO_SATS),
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value): Buffer[] => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				ownScriptCode,
				Number(value),
				bitcoin.Transaction.SIGHASH_ALL
			);
			const der = bitcoin.script.signature.encode(
				Buffer.from(ecc.sign(sighash, ownPriv)),
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [der, ownPub];
		}
	};

	// The EXTERNAL input: a third party's UTXO. The witness comes out of
	// band, so the closure is a throwing stub the machinery must never call.
	const extPriv = crypto.randomBytes(32);
	const extPub = getPublicKey(extPriv);
	const extScript = bitcoin.payments.p2wpkh({ pubkey: extPub }).output!;
	const extPrevTx = new bitcoin.Transaction();
	extPrevTx.version = 2;
	extPrevTx.addInput(crypto.randomBytes(32), 0);
	extPrevTx.addOutput(extScript, EXT_UTXO_SATS);
	const externalInput: ISpliceWalletInput = {
		prevTx: extPrevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(EXT_UTXO_SATS),
		sequence: 0xfffffffd,
		confirmed: true,
		external: true,
		signWitness: () => {
			throw new Error('external input: the witness comes from its owner');
		}
	};

	const changeScript = bitcoin.payments.p2wpkh({
		hash: crypto.randomBytes(20)
	}).output!;
	chA.setDualFundingContribution(
		[ownInput, externalInput],
		changeScript,
		OPENER_FUNDING,
		FEERATE_PERKW
	);

	// Deliver open_channel2 and everything after it. B answers synchronously,
	// so one drain runs the negotiation to the withhold point: B (zero
	// contribution, lower total) signs first and zero-conf fast-tracks its
	// channel_ready; A holds its tx_signatures on the external hole.
	pump();

	return {
		mgrA,
		mgrB,
		chA,
		errors,
		broadcasts,
		aSent,
		bSent,
		needed,
		bLastPayload,
		extPrevTx,
		extPriv,
		extPub,
		sideB,
		pump
	};
}

/**
 * What an EAGER zero-conf peer (the fork, eclair) sends after signing first:
 * its channel_ready, before our withheld tx_signatures ever left. Built from
 * the acceptor's real state so the per-commitment point is the one its own
 * ready would carry.
 */
function earlyChannelReadyFrom(chB: Channel, permanentId: Buffer): Buffer {
	const seed = chB.getFullState().localPerCommitmentSeed;
	return encodeChannelReadyMessage({
		channelId: permanentId,
		secondPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(seed, MAX_INDEX - 1n)
		),
		shortChannelId: crypto.randomBytes(8)
	});
}

/** The external input's index in the negotiated funding tx. */
function externalIndexOf(
	record: IV2InFlight,
	extPrevTx: bitcoin.Transaction
): number {
	const tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
	const idx = tx.ins.findIndex(
		(i) => Buffer.from(i.hash).equals(extPrevTx.getHash()) && i.index === 0
	);
	expect(idx).to.be.gte(0);
	return idx;
}

/** Sign the external P2WPKH input over the negotiated tx as its owner. */
function signExternalP2wpkh(
	record: IV2InFlight,
	extPrevTx: bitcoin.Transaction,
	extPriv: Buffer,
	extPub: Buffer
): Buffer[] {
	const tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
	const idx = externalIndexOf(record, extPrevTx);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: extPub }).output!;
	const sighash = tx.hashForWitnessV0(
		idx,
		scriptCode,
		EXT_UTXO_SATS,
		bitcoin.Transaction.SIGHASH_ALL
	);
	return [
		bitcoin.script.signature.encode(
			Buffer.from(ecc.sign(sighash, extPriv)),
			bitcoin.Transaction.SIGHASH_ALL
		),
		extPub
	];
}

function acceptorChannel(mgrB: ChannelManager): Channel | undefined {
	return mgrB.listChannels()[0];
}

// ─────────────── Tests ───────────────

describe('ChannelManager.provideV2ExternalWitness (issue #572)', function () {
	this.timeout(10_000);

	it('releases the withheld open and survives the peer signing (and channel_ready) first', function () {
		const s = driveToWithhold();
		const record = s.chA.getFullState().v2InFlight!;
		const extIdx = externalIndexOf(record, s.extPrevTx);

		// The withhold: our tx_signatures never left, the peer's already
		// arrived, and the owed external slot was surfaced through the
		// manager event with the complete-set/external-subset split.
		expect(
			s.aSent.filter((t) => t === MessageType.TX_SIGNATURES),
			'opener tx_signatures withheld'
		).to.have.length(0);
		expect(
			s.bSent.filter((t) => t === MessageType.TX_SIGNATURES),
			'acceptor signed first'
		).to.have.length(1);
		expect(s.chA.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(s.needed, 'channel:txsigs-needed observed').to.have.length(1);
		expect(s.needed[0].inputIndices).to.deep.equal([
			...record.ourWalletInputIndices
		]);
		expect(s.needed[0].externalInputIndices).to.deep.equal([extIdx]);

		// The 97df373 pin, half one: while withheld the opener is already
		// resolvable by its permanent id (promotion at AWAITING_TX_SIGNATURES
		// with a v2InFlight record), so an early channel_ready cannot miss.
		const permanentId = s.chA.getChannelId()!;
		expect(
			s.mgrA.getChannel(permanentId),
			'opener resolvable by permanent id while withheld'
		).to.equal(s.chA);

		// Half two: an EAGER peer's channel_ready lands during the withhold
		// (the exact wire sequence the fork stalled on). It must be recorded,
		// not dropped as unknown and not failed as unexpected, and the state
		// must hold so the release still owes our tx_signatures.
		const chB = acceptorChannel(s.mgrB)!;
		s.mgrA.handleMessage(
			s.sideB.pubkey,
			MessageType.CHANNEL_READY,
			earlyChannelReadyFrom(chB, permanentId)
		);
		expect(
			s.errors,
			'early channel_ready neither unknown nor failed'
		).to.deep.equal([]);
		expect(s.chA.getState(), 'still owing tx_signatures').to.equal(
			ChannelState.AWAITING_TX_SIGNATURES
		);
		// TRANSIENT by design: the peer witnesses backing the early ready live
		// only in the session, so the ready must not reach durable state until
		// the release actually completes (issue #572 review).
		expect(s.chA.getFullState().remoteChannelReady ?? false).to.equal(false);

		// Out-of-band delivery through the manager API releases everything:
		// the release batch consumes the recorded remoteChannelReady and the
		// opener completes straight to NORMAL.
		const witness = signExternalP2wpkh(
			record,
			s.extPrevTx,
			s.extPriv,
			s.extPub
		);
		const result = s.mgrA.provideV2ExternalWitness(
			permanentId,
			Buffer.from(s.extPrevTx.getHash()),
			0,
			witness
		);
		expect(result.ok, `delivery accepted (${result.error})`).to.equal(true);
		expect(s.chA.getState(), 'opener NORMAL (zero-conf)').to.equal(
			ChannelState.NORMAL
		);

		// Deliver our queued tx_signatures (and channel_ready) to the peer:
		// it completes too, and its own late channel_ready is absorbed as the
		// BOLT 2 duplicate.
		s.pump();
		expect(chB.getState(), 'acceptor NORMAL').to.equal(ChannelState.NORMAL);
		expect(
			s.mgrA.getTempChannel(s.chA.getTemporaryChannelId()),
			'opener left the temp map'
		).to.equal(undefined);
		expect(s.errors, 'no errors end to end').to.deep.equal([]);

		// The broadcast funding tx carries the delivered external witness at
		// the external input's index.
		expect(s.broadcasts.length, 'funding tx broadcast').to.be.greaterThan(0);
		const fundingTx = bitcoin.Transaction.fromBuffer(s.broadcasts[0]);
		expect(fundingTx.ins[extIdx].witness).to.have.length(2);
		expect(fundingTx.ins[extIdx].witness[1].equals(s.extPub)).to.equal(true);

		// Once both sides are NORMAL the v2 record is consumed, so a late
		// duplicate is a plain refusal that touches nothing.
		const dup = s.mgrA.provideV2ExternalWitness(
			permanentId,
			Buffer.from(s.extPrevTx.getHash()),
			0,
			witness
		);
		expect(dup.ok).to.equal(false);
		expect(dup.error).to.match(/no current v2 in-flight record/);
		expect(s.chA.getState()).to.equal(ChannelState.NORMAL);
	});

	it('refuses an unknown channel id with an error event', function () {
		const s = driveToWithhold();
		const before = s.errors.length;
		const bogus = crypto.randomBytes(32);
		const result = s.mgrA.provideV2ExternalWitness(
			bogus,
			Buffer.from(s.extPrevTx.getHash()),
			0,
			[crypto.randomBytes(71), s.extPub]
		);
		expect(result.ok).to.equal(false);
		expect(result.error).to.match(/Channel not found/);
		expect(s.errors.length, 'lookup failures do emit').to.equal(before + 1);
	});

	it('refuses an invalid witness without touching the open, then a correct one completes', function () {
		const s = driveToWithhold();
		const record = s.chA.getFullState().v2InFlight!;
		const permanentId = s.chA.getChannelId()!;
		const before = s.errors.length;

		// Garbage witness: refused by the channel's validation, converted to
		// a refused result with NO error event and NO state change.
		const garbage = s.mgrA.provideV2ExternalWitness(
			permanentId,
			Buffer.from(s.extPrevTx.getHash()),
			0,
			[crypto.randomBytes(71), s.extPub]
		);
		expect(garbage.ok).to.equal(false);
		expect(garbage.error).to.match(/external witness rejected/);
		expect(s.errors.length, 'a refusal is not a channel failure').to.equal(
			before
		);
		expect(s.chA.getState(), 'still withheld').to.equal(
			ChannelState.AWAITING_TX_SIGNATURES
		);
		expect(
			s.aSent.filter((t) => t === MessageType.TX_SIGNATURES)
		).to.have.length(0);

		// The correct witness still releases everything afterwards.
		const result = s.mgrA.provideV2ExternalWitness(
			permanentId,
			Buffer.from(s.extPrevTx.getHash()),
			0,
			signExternalP2wpkh(record, s.extPrevTx, s.extPriv, s.extPub)
		);
		expect(result.ok, `delivery accepted (${result.error})`).to.equal(true);

		// While the record still stands (our signatures released, the peer's
		// ready not yet in), a duplicate delivery is an ok no-op (2B contract).
		const dup = s.mgrA.provideV2ExternalWitness(
			permanentId,
			Buffer.from(s.extPrevTx.getHash()),
			0,
			signExternalP2wpkh(record, s.extPrevTx, s.extPriv, s.extPub)
		);
		expect(dup.ok).to.equal(true);
		expect(dup.actions).to.deep.equal([]);

		s.pump();
		expect(s.chA.getState()).to.equal(ChannelState.NORMAL);
		expect(acceptorChannel(s.mgrB)!.getState()).to.equal(ChannelState.NORMAL);
	});

	it('a stashed early ready closes the live guards: replays ignored, RBF refused', function () {
		// BOLT 2 closes the RBF window and makes tx_signatures replays
		// ignorable the moment a valid channel_ready is RECEIVED, not the
		// moment it becomes durable: the transient stash must count in every
		// live guard (issue #581 review) or the exchange stays active after
		// a valid ready.
		// PLAIN (non-zero-conf) open: the zero-conf RBF refusal would mask
		// the ready-window guard under test.
		const s = driveToWithhold({ plain: true });
		const record = s.chA.getFullState().v2InFlight!;
		const permanentId = s.chA.getChannelId()!;
		const chB = acceptorChannel(s.mgrB)!;
		s.mgrA.handleMessage(
			s.sideB.pubkey,
			MessageType.CHANNEL_READY,
			earlyChannelReadyFrom(chB, permanentId)
		);
		expect(s.errors).to.deep.equal([]);

		// A replayed tx_signatures is IGNORED, not errored: the peer's
		// witnesses are necessarily already in the session by stash time.
		const before = s.errors.length;
		s.mgrA.handleMessage(
			s.sideB.pubkey,
			MessageType.TX_SIGNATURES,
			s.bLastPayload.get(MessageType.TX_SIGNATURES)!
		);
		expect(s.errors.length, 'replay ignored, never failed').to.equal(before);
		expect(s.chA.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);

		// Outbound RBF is refused: the window closed at the ready.
		const rbf = s.mgrA.initiateFundingRbf(permanentId, FEERATE_PERKW * 2);
		expect(rbf.ok).to.equal(false);
		expect(rbf.error).to.match(/after channel_ready/);

		// Inbound RBF is refused on the wire with tx_abort, never accepted.
		const aSentBefore = s.aSent.length;
		s.mgrA.handleMessage(
			s.sideB.pubkey,
			MessageType.TX_INIT_RBF,
			encodeTxInitRbfMessage({
				channelId: permanentId,
				locktime: 0,
				feerate: FEERATE_PERKW * 2
			})
		);
		const answered = s.aSent.slice(aSentBefore);
		expect(
			answered.filter((t) => t === MessageType.TX_ABORT),
			'inbound RBF refused with tx_abort'
		).to.have.length(1);
		expect(
			answered.filter((t) => t === MessageType.TX_ACK_RBF),
			'inbound RBF never acked'
		).to.have.length(0);

		// The witness delivery still completes the open normally afterwards.
		const result = s.mgrA.provideV2ExternalWitness(
			permanentId,
			Buffer.from(s.extPrevTx.getHash()),
			0,
			signExternalP2wpkh(record, s.extPrevTx, s.extPriv, s.extPub)
		);
		expect(result.ok, `delivery accepted (${result.error})`).to.equal(true);
		// Plain open: no zero-conf fast track, so the release parks the open
		// at the confirmation wait (the stash is consumed at depth).
		expect(s.chA.getState()).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
		expect(
			s.aSent.filter((t) => t === MessageType.TX_SIGNATURES),
			'release sent'
		).to.have.length(1);
	});

	it('an early ready never persists: a restart accepts the retransmitted tx_signatures', function () {
		// The peer witnesses backing an early ready live only in the SESSION.
		// If the ready reached durable state and a later persist (an external
		// witness delivery) wrote it, a restart would keep remoteChannelReady
		// while losing the witnesses: the tx_signatures gate would then
		// swallow the peer's retransmission forever and the open could never
		// complete (issue #572 review). The stash design makes the restart
		// path self-healing: nothing durable, gate open, retransmit accepted.
		const s = driveToWithhold();
		const record = s.chA.getFullState().v2InFlight!;
		const permanentId = s.chA.getChannelId()!;
		const chB = acceptorChannel(s.mgrB)!;
		s.mgrA.handleMessage(
			s.sideB.pubkey,
			MessageType.CHANNEL_READY,
			earlyChannelReadyFrom(chB, permanentId)
		);
		expect(s.errors).to.deep.equal([]);

		// The process dies before any witness arrives: the serialized row
		// must NOT carry the early ready.
		const row = deserializeChannelState(
			serializeChannelState(s.chA.getFullState())
		);
		expect(
			row.remoteChannelReady ?? false,
			'early ready not persisted'
		).to.equal(false);

		const restored = new Channel(
			row,
			new ChannelSigner(crypto.randomBytes(32))
		);
		restored.restoreV2InFlight();

		// The peer retransmits its tx_signatures over reestablish; the
		// restored gate must consume it, not ignore it.
		const retransmit = decodeTxSignaturesMessage(
			s.bLastPayload.get(MessageType.TX_SIGNATURES)!
		);
		restored.handleTxSignatures(retransmit);
		expect(
			restored.getDualFundingSession()?.getRemoteWitnesses() ?? null,
			'peer witnesses accepted after restart'
		).to.not.equal(null);

		// The remaining external witness then completes the exchange.
		const release = restored.provideV2ExternalWitness(
			Buffer.from(s.extPrevTx.getHash()),
			0,
			signExternalP2wpkh(record, s.extPrevTx, s.extPriv, s.extPub)
		);
		expect(
			release.some(
				(a) =>
					(a as { messageType?: number }).messageType ===
					MessageType.TX_SIGNATURES
			),
			'restored channel releases tx_signatures'
		).to.equal(true);
		expect(row.v2InFlight!.sentTxSignatures).to.equal(true);
	});

	it('a PREMATURE channel_ready (before the peer signed) is refused, not recorded', function () {
		// The early tolerance requires the peer's tx_signatures to already be
		// in: a ready recorded any earlier would WEDGE the open, because
		// handleTxSignatures ignores everything once remoteChannelReady is
		// set and the release would wait forever for signatures that can no
		// longer land (issue #572 review).
		const s = driveToWithhold({ holdPeerFrom: MessageType.TX_SIGNATURES });
		expect(s.chA.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		const record = s.chA.getFullState().v2InFlight!;
		expect(record.receivedTxSignatures, 'peer signatures held back').to.equal(
			false
		);
		const permanentId = s.chA.getChannelId()!;
		const chB = acceptorChannel(s.mgrB)!;

		s.mgrA.handleMessage(
			s.sideB.pubkey,
			MessageType.CHANNEL_READY,
			earlyChannelReadyFrom(chB, permanentId)
		);

		expect(
			s.errors.some((e) => /Unexpected channel_ready/.test(e)),
			`premature ready refused (got: ${s.errors.join(' | ')})`
		).to.equal(true);
		expect(
			s.chA.getFullState().remoteChannelReady ?? false,
			'nothing recorded'
		).to.equal(false);
	});

	it('the early-ready arm does not loosen the gate before the commitment exchange', function () {
		// Mid-negotiation (DUAL_FUNDING_V2, no v2InFlight record yet) an
		// incoming channel_ready is still refused: the early tolerance is
		// scoped to the post-commitment tx_signatures wait only.
		const sideA = makeSide();
		const mgrA = new ChannelManager(sideA.config);
		const errors: string[] = [];
		mgrA.on('error', (_id: Buffer | null, msg: string) => errors.push(msg));
		mgrA.on('message:outbound', () => {});
		const chA = mgrA.createDualFundedChannel(
			'02' + 'ab'.repeat(32),
			openerParams(sideA)
		);
		expect(chA.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		expect(chA.getFullState().v2InFlight ?? null).to.equal(null);
		const actions = chA.handleChannelReady({
			channelId: chA.getTemporaryChannelId(),
			secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32)),
			shortChannelId: crypto.randomBytes(8)
		});
		expect(
			actions.some(
				(a) =>
					(a as { message?: string }).message === 'Unexpected channel_ready'
			),
			'pre-commitment ready still refused'
		).to.equal(true);
	});
});
