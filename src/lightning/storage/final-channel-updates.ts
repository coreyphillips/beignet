import { Transaction } from 'bitcoinjs-lib';
import type { BIP32Interface } from 'bip32';
import { buildFinalCommitmentView } from '../channel/final-opening-commitment';
import {
	finalFunderCostMsat,
	finalFundingReserveSats,
	finalSpliceWithdrawalSats
} from '../channel/final-commitment-reserve';
import { MAX_INDEX, generateFromSeed } from '../keys/shachain';
import { getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import { sha256 } from '../crypto/provider';
import { deriveChannelKeys } from '../keys/wallet-keys';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import type { IChannelReestablishMessage } from '../message/channel-reestablish';
import { MessageType } from '../message/types';
import { decodeTlvStream } from '../message/tlv';
import { decodeChannelReadyMessage } from '../message/channel-funding';
import {
	decodeRevokeAndAckMessage,
	encodeRevokeAndAckMessage
} from '../message/channel-commitment';
import {
	decodeUpdateFeeMessage,
	decodeUpdateAddHtlcMessage,
	decodeUpdateFulfillHtlcMessage,
	decodeUpdateFailHtlcMessage,
	decodeUpdateFailMalformedHtlcMessage
} from '../message/channel-update';
import { MAX_LIGHTNING_PAYLOAD } from '../message/custom-records';
import type { IFinalOpeningCandidate } from './final-opening-candidate';
import type { IFinalOpeningNonces } from './final-opening-nonces';
import type { FinalOpeningAuthority } from './final-opening-authority';
import { readyKeys } from './final-opening-ready';
import {
	signFinalUpdate,
	FinalUpdateProtocolError,
	checkUpdateNonce,
	updateVerificationNonce,
	type IFinalUpdateNonce
} from './final-update-signing';
export { FinalUpdateProtocolError } from './final-update-signing';

/** The peer proved that this wallet's commitment history is stale. */
export class FinalUpdateDataLossError extends Error {
	constructor() {
		super('Peer proved a later commitment; original exit is unsafe');
	}
}

export interface IFinalHtlcLimits {
	htlcMinimumMsat: string;
	maxHtlcValueInFlightMsat: string;
	maxAcceptedHtlcs: number;
	channelReserveSats: string;
}
export interface IFinalUpdateLimits {
	local: IFinalHtlcLimits;
	remote: IFinalHtlcLimits;
}
type Side = 'local' | 'peer';

interface WireUpdate {
	direction: Side;
	type: MessageType;
	payload: string;
	ordinal: number;
	localAt?: number;
	remoteAt?: number;
}
interface Funds {
	feeratePerKw?: number;
	local: string;
	peer: string;
	htlcs: { direction: Side; add: string }[];
}
interface Commitment {
	height: number;
	point: string;
	nextPoint: string;
	nextNonce: IFinalUpdateNonce;
	tx: string;
	funds: Funds;
	signed?: string;
	verifyNonce?: string;
	revoke?: string;
	revokeBatch?: string;
	target?: string[];
	sentAt?: number;
	revokeAt?: number;
}
export interface IFinalLedgerState {
	openingRecovery?: IFinalOpeningNonces;
	funding?: IFinalFundingReference;
	alternatives?: Record<string, IFinalLedgerState>;
	initialRemote?: Commitment;
	local: Commitment;
	remote: Commitment;
	inFlight?: Commitment;
	locked: Funds;
	waiting: WireUpdate[];
	last?: WireUpdate;
	lastProof?: {
		commitmentSigned?: string;
		peerCommitmentSigned?: string;
		revocation?: string;
		peerRevocation?: string;
	};
	deliveries: { height: number; update: WireUpdate }[];
	nextLocalId: string;
	nextPeerId: string;
	nextUpdate: number;
	wireSequence: number;
	shachain: ({ height: number; secret: string } | null)[];
	dataLoss?: true;
	awaitingFundingNonce?: true;
}
export interface IFinalUpdateContext {
	funding?: IFinalFundingReference;
	candidate: IFinalOpeningCandidate;
	nonces: IFinalOpeningNonces;
	nonceKey: Buffer;
	identity: string;
	authority: FinalOpeningAuthority;
}

export function finalFundingTxid(ctx: IFinalUpdateContext): Buffer {
	return Transaction.fromHex(
		(ctx.funding ?? ctx.candidate).fundingTxHex
	).getHash();
}
function fundingCapacity(ctx: IFinalUpdateContext): bigint {
	const ref = ctx.funding ?? ctx.candidate;
	return BigInt(
		Transaction.fromHex(ref.fundingTxHex).outs[ref.fundingOutputIndex].value
	);
}
function fundingSigner(ctx: IFinalUpdateContext, root: BIP32Interface) {
	return ctx.funding
		? {
				reference: ctx.funding,
				privateKey: deriveChannelKeys(root, 1, ctx.funding.localFundingKeyIndex)
					.fundingPrivkey
		  }
		: undefined;
}

export function validateUpdateLimits(limits: IFinalUpdateLimits): void {
	if (!limits || Object.keys(limits).sort().join(',') !== 'local,remote')
		throw new Error('Invalid final HTLC limits');
	for (const v of [limits.local, limits.remote]) {
		if (
			!v ||
			Object.keys(v).sort().join(',') !==
				'channelReserveSats,htlcMinimumMsat,maxAcceptedHtlcs,maxHtlcValueInFlightMsat' ||
			![
				v.htlcMinimumMsat,
				v.maxHtlcValueInFlightMsat,
				v.channelReserveSats
			].every(
				(n) =>
					typeof n === 'string' &&
					/^(0|[1-9][0-9]{0,19})$/.test(n) &&
					BigInt(n) <= 0xffffffffffffffffn
			) ||
			!Number.isSafeInteger(v.maxAcceptedHtlcs) ||
			v.maxAcceptedHtlcs < 1 ||
			v.maxAcceptedHtlcs > 483
		)
			throw new Error('Invalid final HTLC limits');
	}
}

const opposite = (dir: Side): Side => (dir === 'local' ? 'peer' : 'local');
function protocol(condition: unknown, reason: string): asserts condition {
	if (!condition) throw new FinalUpdateProtocolError(reason);
}
function rawAdd(hex: string) {
	return decodeUpdateAddHtlcMessage(Buffer.from(hex, 'hex'));
}
function publicHtlcs(book: Funds) {
	return book.htlcs.map(({ direction, add }) => {
		const msg = rawAdd(add);
		return {
			id: msg.id,
			offeredBy: direction,
			amountMsat: msg.amountMsat,
			paymentHash: msg.paymentHash,
			cltvExpiry: msg.cltvExpiry,
			onionPacket: msg.onionRoutingPacket,
			blindingPoint: msg.blindingPoint,
			skimmedFeeMsat: msg.skimmedFeeMsat
		};
	});
}
function decodedUpdate(type: MessageType, payload: Buffer) {
	if (!Buffer.isBuffer(payload) || payload.length > MAX_LIGHTNING_PAYLOAD)
		throw new FinalUpdateProtocolError('Invalid HTLC update size');
	switch (type) {
		case MessageType.UPDATE_FEE:
			return decodeUpdateFeeMessage(payload);
		case MessageType.UPDATE_ADD_HTLC:
			return decodeUpdateAddHtlcMessage(payload);
		case MessageType.UPDATE_FULFILL_HTLC:
			decodeTlvStream(payload, 72, new Set());
			return decodeUpdateFulfillHtlcMessage(payload);
		case MessageType.UPDATE_FAIL_HTLC: {
			const msg = decodeUpdateFailHtlcMessage(payload);
			decodeTlvStream(payload, 42 + msg.reason.length, new Set());
			return msg;
		}
		case MessageType.UPDATE_FAIL_MALFORMED_HTLC:
			protocol(payload.length === 74, 'Invalid malformed HTLC failure length');
			return decodeUpdateFailMalformedHtlcMessage(payload);
		default:
			throw new FinalUpdateProtocolError('Unsupported final HTLC update');
	}
}
function applyFunds(base: Funds, updates: readonly WireUpdate[]): Funds {
	const funds: Funds = { ...base, htlcs: [...base.htlcs] };
	for (const u of updates) {
		const dir = u.direction;
		const msg = decodedUpdate(u.type, Buffer.from(u.payload, 'hex'));
		if ('feeratePerKw' in msg) {
			funds.feeratePerKw = msg.feeratePerKw;
			continue;
		}
		if ('amountMsat' in msg) {
			const balance = BigInt(funds[dir]) - msg.amountMsat;
			protocol(balance >= 0n, 'HTLC exceeds channel balance');
			funds[dir] = balance.toString();
			funds.htlcs.push({ direction: dir, add: u.payload });
		} else {
			const offeredBy = opposite(dir);
			const index = funds.htlcs.findIndex(
				(h) => h.direction === offeredBy && rawAdd(h.add).id === msg.id
			);
			protocol(index >= 0, 'Unknown irrevocable HTLC for resolution');
			const add = rawAdd(funds.htlcs[index].add);
			const payee = 'paymentPreimage' in msg ? dir : offeredBy;
			if ('paymentPreimage' in msg)
				protocol(
					sha256(msg.paymentPreimage).equals(add.paymentHash),
					'Incorrect final HTLC payment preimage'
				);
			if ('failureCode' in msg)
				protocol(
					(msg.failureCode & 0x8000) !== 0 &&
						msg.sha256OfOnion.equals(sha256(add.onionRoutingPacket)),
					'Invalid malformed HTLC failure'
				);
			funds[payee] = (BigInt(funds[payee]) + add.amountMsat).toString();
			funds.htlcs.splice(index, 1);
		}
	}
	return funds;
}

export function initialFinalLedger(
	c: IFinalOpeningCandidate,
	s: IFinalOpeningNonces
): IFinalLedgerState {
	if (
		!s.session?.updateLimits ||
		!s.signing?.fundingTransaction ||
		!s.localReady ||
		!s.peerReady ||
		!s.signing.exit ||
		!s.signing.outgoing
	)
		throw new Error(
			'Final updates require a funded ready session with negotiated HTLC limits'
		);
	const locked = {
		feeratePerKw: s.session.terms.commitmentFeeratePerKw,
		local: (BigInt(c.localContributionSats) * 1000n).toString(),
		peer: (BigInt(c.remoteContributionSats) * 1000n).toString(),
		htlcs: []
	};
	const side = (local: boolean): Commitment => {
		const ready = decodeChannelReadyMessage(
			Buffer.from(local ? s.localReady! : s.peerReady!, 'hex')
		);
		const reconnect = local ? s.localReconnect : s.peerReconnect;
		const basepoints = local
			? s.session!.terms.localBasepoints
			: s.session!.terms.remoteBasepoints;
		const point = basepoints.firstPerCommitmentPoint;
		const tx = local
			? s.signing!.exit!
			: buildFinalCommitmentView(
					c,
					s.session!.terms,
					'remote',
					Buffer.from(point, 'hex'),
					0n,
					{
						localBalanceMsat: BigInt(locked.local),
						remoteBalanceMsat: BigInt(locked.peer)
					},
					[]
			  ).tx.toHex();
		return {
			height: 0,
			point,
			nextPoint: ready.secondPerCommitmentPoint.toString('hex'),
			tx,
			funds: locked,
			nextNonce: {
				pub: reconnect?.nonce ?? ready.nextLocalNonce!.toString('hex'),
				...(local && {
					source: reconnect ? ('reconnect' as const) : ('ready' as const),
					generation: reconnect?.generation ?? 0
				})
			}
		};
	};
	return {
		openingRecovery: JSON.parse(JSON.stringify(s)),
		local: side(true),
		remote: side(false),
		locked,
		waiting: [],
		deliveries: [],
		nextUpdate: 1,
		wireSequence: 0,
		shachain: [],
		nextLocalId: '0',
		nextPeerId: '0'
	};
}

function termsFor(ctx: IFinalUpdateContext, funds: Funds) {
	const opening = ctx.nonces.session!.terms;
	return {
		...opening,
		commitmentFeeratePerKw: funds.feeratePerKw ?? opening.commitmentFeeratePerKw
	};
}
function affectsAvailableFunds(u: WireUpdate): boolean {
	return (
		u.type === MessageType.UPDATE_ADD_HTLC || u.type === MessageType.UPDATE_FEE
	);
}
function reservation(
	ctx: IFinalUpdateContext,
	book: Funds,
	dir: Side,
	additionalUntrimmed = 0
): bigint {
	const terms = termsFor(ctx, book);
	const limits = ctx.nonces.session!.updateLimits!;
	const reserve = ctx.funding
		? finalFundingReserveSats(fundingCapacity(ctx), terms, dir === 'local')
		: BigInt(
				(dir === 'local' ? limits.remote : limits.local).channelReserveSats
		  );
	const paysFees = ctx.candidate.isInitiator === (dir === 'local');
	return (
		reserve * 1000n +
		(paysFees
			? finalFunderCostMsat(terms, publicHtlcs(book), additionalUntrimmed)
			: 0n)
	);
}

export function stageFinalLedgerUpdate(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState,
	dir: Side,
	type: MessageType,
	payload: Buffer
): void {
	let msg: ReturnType<typeof decodedUpdate>;
	try {
		msg = decodedUpdate(type, payload);
	} catch (err) {
		throw new FinalUpdateProtocolError(String(err));
	}
	protocol(
		msg.channelId.toString('hex') === ctx.candidate.channelId,
		'HTLC channel mismatch'
	);
	const hex = payload.toString('hex');
	if (
		type !== MessageType.UPDATE_FEE &&
		s.waiting.some(
			(u) => u.direction === dir && u.type === type && u.payload === hex
		)
	)
		return;
	if (
		type !== MessageType.UPDATE_FEE &&
		s.last?.type === type &&
		s.last.direction === dir &&
		s.last.payload === hex
	)
		return;
	const update: WireUpdate = {
		direction: dir,
		type,
		payload: hex,
		ordinal: s.nextUpdate
	};
	const limits = ctx.nonces.session!.updateLimits!;
	if ('feeratePerKw' in msg) {
		protocol(
			ctx.candidate.isInitiator === (dir === 'local'),
			'Only the opening fee payer can send update_fee as opener'
		);
		const staged = s.waiting.filter(affectsAvailableFunds);
		const prior = applyFunds(s.locked, staged);
		const highest = Math.max(
			termsFor(ctx, s.locked).commitmentFeeratePerKw,
			termsFor(ctx, prior).commitmentFeeratePerKw
		);
		protocol(
			msg.feeratePerKw >= 253 &&
				msg.feeratePerKw <= 100000 &&
				msg.feeratePerKw <= highest * 10,
			'Unacceptable commitment fee rate'
		);
		const book = applyFunds(prior, [update]);
		protocol(
			BigInt(book[dir]) >= reservation(ctx, book, dir),
			'Commitment fee would spend the opener channel reserve'
		);
	} else if ('amountMsat' in msg) {
		const receivingLimit = dir === 'local' ? limits.remote : limits.local;
		const next = dir === 'local' ? 'nextLocalId' : 'nextPeerId';
		protocol(
			msg.id === BigInt(s[next]) &&
				msg.amountMsat > 0n &&
				msg.amountMsat >= BigInt(receivingLimit.htlcMinimumMsat) &&
				msg.cltvExpiry > 0 &&
				msg.cltvExpiry < 500000000,
			'Invalid HTLC add id, amount or expiry'
		);
		// Unlocked removals never increase the sender's available balance.
		const book = applyFunds(s.locked, [
			...s.waiting.filter(affectsAvailableFunds),
			update
		]);
		const offered = publicHtlcs(book).filter((h) => h.offeredBy === dir);
		protocol(
			offered.length <= receivingLimit.maxAcceptedHtlcs &&
				offered.reduce((sum, h) => sum + h.amountMsat, 0n) <=
					BigInt(receivingLimit.maxHtlcValueInFlightMsat),
			'HTLC exceeds negotiated in-flight limits'
		);
		protocol(
			BigInt(book[dir]) >= reservation(ctx, book, dir),
			'HTLC would spend the channel reserve'
		);
		// A non-opener's untrimmed HTLC can also add weight to the opener's commitment.
		if (ctx.candidate.isInitiator !== (dir === 'local')) {
			const payer = dir === 'local' ? 'peer' : 'local';
			const minimum =
				dir === 'local'
					? reservation(ctx, book, payer)
					: finalFunderCostMsat(termsFor(ctx, book), publicHtlcs(book));
			protocol(
				BigInt(book[payer]) >= minimum,
				'Opener cannot fund the additional HTLC commitment cost'
			);
		}
		s[next] = (msg.id + 1n).toString();
	} else {
		applyFunds(s.locked, [update]);
		const resolvedId = msg.id;
		protocol(
			!s.waiting.some(
				(u) =>
					u.direction === dir &&
					u.type !== MessageType.UPDATE_ADD_HTLC &&
					u.type !== MessageType.UPDATE_FEE &&
					Buffer.from(u.payload, 'hex').readBigUInt64BE(32) === resolvedId
			),
			'Multiple resolutions for one HTLC'
		);
	}
	s.nextUpdate++;
	s.waiting.push(update);
}

function forCommit(s: IFinalLedgerState, owner: Side): WireUpdate[] {
	return s.waiting.filter((u) =>
		owner === 'peer'
			? u.direction === 'local' || u.localAt !== undefined
			: u.direction === 'peer' ||
			  (u.remoteAt !== undefined && u.remoteAt <= s.remote.height)
	);
}

function build(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState,
	owner: Side,
	point: string,
	height: number,
	changes: WireUpdate[]
) {
	const funds = applyFunds(s.locked, changes);
	const view = buildFinalCommitmentView(
		ctx.candidate,
		termsFor(ctx, funds),
		owner === 'local' ? 'local' : 'remote',
		Buffer.from(point, 'hex'),
		BigInt(height),
		{
			localBalanceMsat: BigInt(funds.local),
			remoteBalanceMsat: BigInt(funds.peer)
		},
		publicHtlcs(funds),
		ctx.funding
	);
	return { funds, view };
}
function finalize(s: IFinalLedgerState): void {
	const done = s.waiting.filter(
		(u) =>
			u.localAt !== undefined &&
			u.remoteAt !== undefined &&
			u.remoteAt <= s.remote.height
	);
	if (!done.length) return;
	s.locked = applyFunds(s.locked, done);
	s.deliveries.push(
		...done
			.filter((u) => u.type !== MessageType.UPDATE_FEE)
			.map((update) => ({ height: update.localAt!, update }))
	);
	s.last = done[done.length - 1];
	s.lastProof = {
		commitmentSigned: s.remote.signed,
		peerCommitmentSigned: s.local.signed,
		revocation: s.local.revoke,
		peerRevocation: s.remote.revoke
	};
	s.waiting = s.waiting.filter((u) => !done.includes(u));
}

export function signFinalLedger(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState,
	root: BIP32Interface,
	renew = false
): Buffer {
	if (s.inFlight && !renew) return Buffer.from(s.inFlight.signed!, 'hex');
	const old = s.remote;
	const height = old.height + 1;
	const target = s.inFlight
		? s.waiting.filter((u) => u.remoteAt !== undefined && u.remoteAt <= height)
		: forCommit(s, 'peer');
	if (!target.some((u) => u.remoteAt === undefined || u.remoteAt === height))
		throw new Error('No new peer commitment updates');
	const prior = s.inFlight;
	const funds = prior?.funds ?? applyFunds(s.locked, target);
	const view = buildFinalCommitmentView(
		ctx.candidate,
		termsFor(ctx, funds),
		'remote',
		Buffer.from(old.nextPoint, 'hex'),
		BigInt(height),
		{
			localBalanceMsat: BigInt(funds.local),
			remoteBalanceMsat: BigInt(funds.peer)
		},
		publicHtlcs(funds),
		ctx.funding
	);
	const transcript = prior?.target ?? target.map((u) => u.payload);
	const keys = readyKeys(root, ctx.nonces, ctx.identity);
	const raw = signFinalUpdate(
		ctx.candidate,
		view,
		Buffer.from(old.nextPoint, 'hex'),
		height,
		old.nextNonce,
		keys,
		ctx.authority,
		ctx.nonceKey,
		transcript,
		undefined,
		fundingSigner(ctx, root)
	);
	for (const u of target) u.remoteAt ??= height;
	s.inFlight = {
		height,
		point: old.nextPoint,
		nextPoint: '',
		nextNonce: { pub: '' },
		tx: view.tx.toHex(),
		funds,
		target: transcript,
		sentAt: prior?.sentAt ?? ++s.wireSequence,
		signed: raw.toString('hex'),
		verifyNonce: old.nextNonce.pub
	};
	return raw;
}

export function acceptFinalLedgerCommit(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState,
	root: BIP32Interface,
	wire: Buffer
): Buffer {
	if (s.local.signed === wire.toString('hex') && s.local.revoke)
		return Buffer.from(s.local.revoke, 'hex');
	const target = forCommit(s, 'local');
	protocol(
		target.some((u) => u.localAt === undefined),
		'Unexpected empty local commitment update'
	);
	const old = s.local;
	const height = old.height + 1;
	const { funds, view } = build(ctx, s, 'local', old.nextPoint, height, target);
	const keys = readyKeys(root, ctx.nonces, ctx.identity);
	const raw = signFinalUpdate(
		ctx.candidate,
		view,
		Buffer.from(old.nextPoint, 'hex'),
		height,
		old.nextNonce,
		keys,
		ctx.authority,
		ctx.nonceKey,
		target.map((u) => u.payload),
		wire,
		fundingSigner(ctx, root)
	);
	const nextPoint = getPublicKey(
		generateFromSeed(keys.perCommitmentSeed, MAX_INDEX - BigInt(height + 1))
	);
	const nextNonce: IFinalUpdateNonce = { source: 'revocation', pub: '' };
	nextNonce.pub = Buffer.from(
		updateVerificationNonce(
			ctx.authority.nonceContext(ctx.nonceKey),
			fundingSigner(ctx, root)?.privateKey ?? keys.fundingPrivkey,
			height + 1,
			nextNonce
		)
	).toString('hex');
	const revoke = encodeRevokeAndAckMessage({
		channelId: Buffer.from(ctx.candidate.channelId, 'hex'),
		perCommitmentSecret: generateFromSeed(
			keys.perCommitmentSeed,
			MAX_INDEX - BigInt(old.height)
		),
		nextPerCommitmentPoint: nextPoint,
		nextLocalNonces: [
			{
				fundingTxid: finalFundingTxid(ctx),
				nonce: Buffer.from(nextNonce.pub, 'hex')
			}
		]
	});
	for (const u of target) u.localAt ??= height;
	s.local = {
		height,
		point: old.nextPoint,
		nextPoint: nextPoint.toString('hex'),
		nextNonce,
		tx: raw.toString('hex'),
		funds,
		revokeAt: ++s.wireSequence,
		signed: wire.toString('hex'),
		revoke: revoke.toString('hex'),
		verifyNonce: old.nextNonce.pub
	};
	finalize(s);
	return revoke;
}

export function acceptFinalLedgerRevoke(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState,
	wire: Buffer
): void {
	if (s.remote.revoke === wire.toString('hex')) return;
	protocol(s.inFlight, 'Unexpected final revocation');
	let msg: ReturnType<typeof decodeRevokeAndAckMessage>;
	try {
		msg = decodeRevokeAndAckMessage(wire, { finalTaproot: true });
	} catch (err) {
		throw new FinalUpdateProtocolError(String(err));
	}
	const nonce = msg.nextLocalNonces;
	protocol(
		msg.channelId.toString('hex') === ctx.candidate.channelId &&
			nonce?.length === 1 &&
			nonce[0].fundingTxid.equals(finalFundingTxid(ctx)) &&
			isValidPublicKey(msg.nextPerCommitmentPoint) &&
			msg.nextPerCommitmentPoint.toString('hex') !== s.inFlight.point,
		'Invalid final revoke_and_ack'
	);
	checkUpdateNonce(nonce[0].nonce);
	let secretPoint: Buffer;
	try {
		secretPoint = getPublicKey(msg.perCommitmentSecret);
	} catch {
		throw new FinalUpdateProtocolError('Invalid revocation secret');
	}
	protocol(
		secretPoint.toString('hex') === s.remote.point,
		'Revocation secret does not match previous commitment'
	);
	rememberRevocation(s, s.remote.height, msg.perCommitmentSecret);
	protocol(
		nonce[0].nonce.toString('hex') !== s.inFlight.verifyNonce,
		'Peer reused its previous verification nonce'
	);
	s.remote = {
		...s.inFlight,
		nextPoint: msg.nextPerCommitmentPoint.toString('hex'),
		nextNonce: { pub: nonce[0].nonce.toString('hex') },
		revoke: wire.toString('hex')
	};
	delete s.inFlight;
	finalize(s);
}

function hexBytes(value: string | undefined) {
	return value ? Buffer.from(value, 'hex') : undefined;
}
function publicUpdate(u: WireUpdate) {
	return {
		id: BigInt(u.ordinal),
		direction: u.direction,
		type: u.type,
		payload: Buffer.from(u.payload, 'hex')
	};
}
export function finalLedgerStatus(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState
) {
	const event = (u: WireUpdate) => ({
		...publicUpdate(u),
		height: BigInt(u.localAt ?? s.local.height + 1),
		commitmentSigned:
			u.remoteAt !== undefined
				? Buffer.from((s.inFlight ?? s.remote).signed!, 'hex')
				: undefined,
		peerCommitmentSigned:
			u.localAt !== undefined ? Buffer.from(s.local.signed!, 'hex') : undefined,
		revocation:
			u.localAt !== undefined ? Buffer.from(s.local.revoke!, 'hex') : undefined,
		peerRevocation:
			u.remoteAt !== undefined && u.remoteAt <= s.remote.height
				? Buffer.from(s.remote.revoke!, 'hex')
				: undefined
	});
	const available = applyFunds(
		s.locked,
		s.waiting.filter(affectsAvailableFunds)
	);
	const local = BigInt(available.local);
	const terms = ctx.nonces.session!.terms,
		limits = ctx.nonces.session!.updateLimits!.remote;
	const offered = publicHtlcs(available).filter((h) => h.offeredBy === 'local');
	const remainingCap =
		BigInt(limits.maxHtlcValueInFlightMsat) -
		offered.reduce((sum, h) => sum + h.amountMsat, 0n);
	const dust =
		BigInt(
			Math.min(terms.localDustLimitSatoshis, terms.remoteDustLimitSatoshis)
		) * 1000n;
	const min = (a: bigint, b: bigint) => (a < b ? a : b);
	const trimmed = min(dust - 1n, local - reservation(ctx, available, 'local'));
	const remoteCanPay = (extra: number) =>
		ctx.candidate.isInitiator ||
		BigInt(available.peer) >= reservation(ctx, available, 'peer', extra);
	const untrimmed = remoteCanPay(1)
		? local - reservation(ctx, available, 'local', 1)
		: 0n;
	const availableMsat =
		offered.length >= limits.maxAcceptedHtlcs
			? 0n
			: min(
					remainingCap,
					remoteCanPay(0) && trimmed > untrimmed ? trimmed : untrimmed
			  );
	return {
		localHeight: BigInt(s.local.height),
		remoteHeight: BigInt(s.remote.height),
		localBalanceMsat: BigInt(s.locked.local),
		remoteBalanceMsat: BigInt(s.locked.peer),
		feeratePerKw: termsFor(ctx, s.locked).commitmentFeeratePerKw,
		spendableSpliceOutSats:
			s.waiting.length || s.inFlight
				? 0n
				: finalSpliceWithdrawalSats(
						fundingCapacity(ctx),
						termsFor(ctx, s.locked),
						BigInt(s.locked.local),
						publicHtlcs(s.locked),
						ctx.candidate.isInitiator
				  ),
		spendableOutboundMsat:
			availableMsat > 0n && availableMsat >= BigInt(limits.htlcMinimumMsat)
				? availableMsat
				: 0n,
		htlcs: publicHtlcs(s.locked),
		nextLocalHtlcId: BigInt(s.nextLocalId),
		nextPeerHtlcId: BigInt(s.nextPeerId),
		pending: s.waiting[0] ? event(s.waiting[0]) : null,
		last: s.last
			? {
					...publicUpdate(s.last),
					height: BigInt(s.last.localAt!),
					commitmentSigned: hexBytes(s.lastProof?.commitmentSigned),
					peerCommitmentSigned: hexBytes(s.lastProof?.peerCommitmentSigned),
					revocation: hexBytes(s.lastProof?.revocation),
					peerRevocation: hexBytes(s.lastProof?.peerRevocation)
			  }
			: undefined,
		needsPeerCommitment:
			!s.inFlight && forCommit(s, 'peer').some((u) => u.remoteAt === undefined)
	};
}
export function finalLedgerDeliveries(s: IFinalLedgerState) {
	return s.deliveries.map((d) => ({
		...publicUpdate(d.update),
		height: BigInt(d.height)
	}));
}

export function finalLedgerSnapshot(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState
) {
	return {
		localHeight: BigInt(s.local.height),
		remoteHeight: BigInt(s.remote.height),
		localPoint: Buffer.from(s.local.point, 'hex'),
		remotePoint: Buffer.from(s.remote.point, 'hex'),
		localNextPoint: Buffer.from(s.local.nextPoint, 'hex'),
		remoteNextPoint: Buffer.from(s.remote.nextPoint, 'hex'),
		localBalanceMsat: BigInt(s.locked.local),
		remoteBalanceMsat: BigInt(s.locked.peer),
		htlcs: publicHtlcs(s.locked),
		candidate: ctx.candidate,
		terms: termsFor(ctx, s.locked),
		quiescent: !s.waiting.length && !s.inFlight
	};
}

/** BOLT 3 checks a newly disclosed parent against each smaller shachain bucket. */
function rememberRevocation(
	s: IFinalLedgerState,
	height: number,
	secret: Buffer
): void {
	const index = MAX_INDEX - BigInt(height);
	let bits = 0;
	while (bits < 48 && ((index >> BigInt(bits)) & 1n) === 0n) bits++;
	for (let bucket = 0; bucket < bits; bucket++) {
		const prior = s.shachain[bucket];
		protocol(prior, 'Missing preceding revocation secret');
		let derived = Buffer.from(secret);
		const target = MAX_INDEX - BigInt(prior.height);
		for (let bit = bits - 1; bit >= 0; bit--) {
			if ((target >> BigInt(bit)) & 1n) {
				derived[bit >> 3] ^= 1 << bit % 8;
				derived = sha256(derived);
			}
		}
		protocol(
			derived.toString('hex') === prior.secret,
			'Inconsistent peer revocation chain'
		);
	}
	s.shachain[bits] = { height, secret: secret.toString('hex') };
}
export function finalLedgerReconnect(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState,
	root: BIP32Interface
) {
	const keys = readyKeys(root, ctx.nonces, ctx.identity),
		authority = ctx.authority,
		id = ctx.candidate.channelId;
	const promise = authority.advanceReestablishNonce(
		'final-update-reconnect/' +
			id +
			'/' +
			finalFundingTxid(ctx).toString('hex'),
		ctx.nonceKey.toString('hex'),
		undefined,
		(generation) =>
			Buffer.from(
				updateVerificationNonce(
					authority.nonceContext(ctx.nonceKey),
					fundingSigner(ctx, root)?.privateKey ?? keys.fundingPrivkey,
					s.local.height + 1,
					{ pub: '', source: 'update-reconnect', generation }
				)
			)
	);
	s.local.nextNonce = {
		pub: promise.nonce,
		source: 'update-reconnect',
		generation: promise.generation
	};
	return {
		channelId: Buffer.from(id, 'hex'),
		nextCommitmentNumber: BigInt(s.local.height + 1),
		nextRevocationNumber: BigInt(s.remote.height),
		yourLastPerCommitmentSecret: s.remote.revoke
			? decodeRevokeAndAckMessage(Buffer.from(s.remote.revoke, 'hex'), {
					finalTaproot: true
			  }).perCommitmentSecret
			: Buffer.alloc(32),
		myCurrentPerCommitmentPoint: Buffer.from(s.local.point, 'hex'),
		nextLocalNonces: [
			{
				fundingTxid: finalFundingTxid(ctx),
				nonce: Buffer.from(promise.nonce, 'hex')
			}
		]
	};
}
function checkReconnectCounters(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState,
	root: BIP32Interface,
	msg: IChannelReestablishMessage
) {
	const keys = readyKeys(root, ctx.nonces, ctx.identity);
	protocol(
		msg.channelId.toString('hex') === ctx.candidate.channelId &&
			isValidPublicKey(msg.myCurrentPerCommitmentPoint) &&
			msg.nextCommitmentNumber > 0n &&
			msg.nextRevocationNumber >= 0n &&
			msg.nextRevocationNumber <= MAX_INDEX,
		'Invalid final update reestablish'
	);
	const proof =
		msg.nextRevocationNumber === 0n
			? Buffer.alloc(32)
			: generateFromSeed(
					keys.perCommitmentSeed,
					MAX_INDEX - msg.nextRevocationNumber + 1n
			  );
	protocol(
		proof.equals(msg.yourLastPerCommitmentSecret),
		'Peer supplied wrong revocation secret on reconnect'
	);
	// A peer proving possession of a newer secret makes every known local exit unsafe.
	if (msg.nextRevocationNumber > BigInt(s.local.height)) {
		return { dataLoss: true, needAck: false, needCommit: false };
	}
	const needAck = msg.nextRevocationNumber === BigInt(s.local.height - 1);
	protocol(
		needAck || msg.nextRevocationNumber === BigInt(s.local.height),
		'Peer revocation counter is behind'
	);
	const expect = BigInt(s.remote.height + 1);
	const needCommit = !!s.inFlight && msg.nextCommitmentNumber === expect;
	protocol(
		msg.nextCommitmentNumber === expect ||
			(!!s.inFlight && msg.nextCommitmentNumber === expect + 1n),
		'Unexpected peer commitment counter'
	);
	return { dataLoss: false, needAck, needCommit };
}
export function acceptFinalLedgerReconnect(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState,
	root: BIP32Interface,
	msg: IChannelReestablishMessage,
	holdUpdates = false
) {
	const { dataLoss, needAck, needCommit } = checkReconnectCounters(
		ctx,
		s,
		root,
		msg
	);
	if (dataLoss) {
		s.dataLoss = true;
		return [];
	}
	const n = msg.nextLocalNonces;
	protocol(
		n?.length === 1 && n[0].fundingTxid.equals(finalFundingTxid(ctx)),
		'Missing final funding reconnect nonce'
	);
	checkUpdateNonce(n[0].nonce);
	if (!s.inFlight || needCommit)
		s.remote.nextNonce = { pub: n[0].nonce.toString('hex') };
	if (holdUpdates) return [];
	// Unsigned peer updates are forgotten on reconnection and may be replaced.
	const dropped = s.waiting.filter(
		(u) =>
			u.direction === 'peer' &&
			u.localAt === undefined &&
			u.remoteAt === undefined
	);
	s.waiting = s.waiting.filter((u) => !dropped.includes(u));
	s.nextPeerId = (
		BigInt(s.nextPeerId) -
		BigInt(dropped.filter((u) => u.type === MessageType.UPDATE_ADD_HTLC).length)
	).toString();
	const frames: { type: MessageType; payload: Buffer }[] = [];
	const ack = () => {
		if (!needAck || !s.local.revoke) return;
		const payload = Buffer.from(s.local.revoke, 'hex');
		const nonce = decodeRevokeAndAckMessage(payload, { finalTaproot: true })
			.nextLocalNonces![0].nonce;
		s.local.nextNonce = { source: 'revocation', pub: nonce.toString('hex') };
		frames.push({ type: MessageType.REVOKE_AND_ACK, payload });
	};
	const signed = () => {
		if (!needCommit) return;
		frames.push(
			...s.waiting
				.filter(
					(u) => u.direction === 'local' && u.remoteAt === s.inFlight!.height
				)
				.map((u) => ({ type: u.type, payload: Buffer.from(u.payload, 'hex') }))
		);
		frames.push({
			type: MessageType.COMMITMENT_SIGNED,
			payload: signFinalLedger(ctx, s, root, true)
		});
	};
	if ((s.local.revokeAt ?? 0) < (s.inFlight?.sentAt ?? 0)) {
		ack();
		signed();
	} else {
		signed();
		ack();
	}
	frames.push(
		...s.waiting
			.filter((u) => u.direction === 'local' && u.remoteAt === undefined)
			.map((u) => ({ type: u.type, payload: Buffer.from(u.payload, 'hex') }))
	);
	if (
		!s.inFlight &&
		forCommit(s, 'peer').some((u) => u.remoteAt === undefined)
	) {
		frames.push({
			type: MessageType.COMMITMENT_SIGNED,
			payload: signFinalLedger(ctx, s, root)
		});
	}
	return frames;
}
export function resolutionView(c: Commitment, ctx: IFinalUpdateContext) {
	const funding = ctx.funding;
	return {
		feeratePerKw: termsFor(ctx, c.funds).commitmentFeeratePerKw,
		height: BigInt(c.height),
		...(funding && { funding }),
		point: Buffer.from(c.point, 'hex'),
		tx: Buffer.from(c.tx, 'hex'),
		localBalanceMsat: BigInt(c.funds.local),
		remoteBalanceMsat: BigInt(c.funds.peer),
		htlcs: publicHtlcs(c.funds),
		commitmentSigned: c.signed ? Buffer.from(c.signed, 'hex') : undefined,
		secret: undefined as Buffer | undefined
	};
}

/** Revoked remote commitments and observed preimages remain claimable across wallet rollback. */
export function finalResolutionStates(
	ctx: IFinalUpdateContext,
	s: IFinalLedgerState,
	history: Iterable<IFinalLedgerState>
) {
	const opening = initialFinalLedger(ctx.candidate, ctx.nonces);
	const revoked: ReturnType<typeof resolutionView>[] = [];
	const preimages = new Map<string, Buffer>();
	let remote = s.initialRemote ?? opening.remote;
	for (const entry of history) {
		if (entry.remote.height === remote.height + 1) {
			const old = resolutionView(remote, ctx);
			old.secret = decodeRevokeAndAckMessage(
				Buffer.from(entry.remote.revoke!, 'hex'),
				{ finalTaproot: true }
			).perCommitmentSecret;
			revoked.push(old);
		}
		remote = entry.remote;
		for (const update of entry.waiting)
			if (update.type === MessageType.UPDATE_FULFILL_HTLC) {
				const { paymentPreimage } = decodeUpdateFulfillHtlcMessage(
					Buffer.from(update.payload, 'hex')
				);
				preimages.set(paymentPreimage.toString('hex'), paymentPreimage);
			}
	}
	return {
		candidate: ctx.candidate,
		terms: ctx.nonces.session!.terms,
		local: resolutionView(s.local, ctx),
		remote: [s.remote, ...(s.inFlight ? [s.inFlight] : [])].map((c) =>
			resolutionView(c, ctx)
		),
		revoked,
		preimages: [...preimages.values()]
	};
}

/** Keep the payment in flight while any valid commitment or pending proposal contains the offer. */
export function finalOfferedHtlc(s: IFinalLedgerState, id: bigint) {
	const staged = s.waiting
		.filter(
			(u) => u.direction === 'local' && u.type === MessageType.UPDATE_ADD_HTLC
		)
		.map((u) => u.payload);
	const books = [
		s.locked,
		s.local.funds,
		s.remote.funds,
		...(s.inFlight ? [s.inFlight.funds] : [])
	];
	for (const payload of [
		...staged,
		...books.flatMap((b) =>
			b.htlcs.filter((h) => h.direction === 'local').map((h) => h.add)
		)
	]) {
		const h = rawAdd(payload);
		if (h.id === id)
			return {
				amountMsat: h.amountMsat,
				cltvExpiry: h.cltvExpiry,
				paymentHash: h.paymentHash
			};
	}
	return null;
}
