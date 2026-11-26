import type { BIP32Interface } from 'bip32';
import { Transaction } from 'bitcoinjs-lib';
import { validateFinalSpliceExit } from '../channel/final-splice-exits';
import { buildFinalCommitmentView } from '../channel/final-opening-commitment';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import type { IFinalSpliceAttempt } from '../channel/final-splice-state';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage,
	encodeRevokeAndAckMessage
} from '../message/channel-commitment';
import type { IChannelReestablishMessage } from '../message/channel-reestablish';
import { encodeStartBatchMessage } from '../message/splice';
import { MessageType } from '../message/types';
import {
	FinalUpdateProtocolError,
	spliceCommitmentNonceContext
} from './final-update-signing';
import {
	acceptFinalLedgerCommit,
	acceptFinalLedgerReconnect,
	acceptFinalLedgerRevoke,
	contextType,
	finalFundingTxid,
	finalLedgerReconnect,
	finalLedgerSnapshot,
	finalLedgerStatus,
	signFinalLedger,
	type IFinalLedgerState,
	type IFinalUpdateContext
} from './final-channel-updates';

export interface IFundingLedger {
	ctx: IFinalUpdateContext;
	s: IFinalLedgerState;
}
type Candidate = NonNullable<IFinalSpliceAttempt['candidate']>;
function fundId(ref: IFinalFundingReference) {
	return Transaction.fromHex(ref.fundingTxHex).getId();
}
export function withFunding(
	ctx: IFinalUpdateContext,
	ref: IFinalFundingReference
): IFinalUpdateContext {
	return {
		...ctx,
		funding: ref,
		nonceKey: spliceCommitmentNonceContext(
			ctx.candidate.channelId,
			Transaction.fromHex(ref.fundingTxHex).getHash(),
			ref.fundingOutputIndex
		)
	};
}
function startSpliceView(
	ctx: IFinalUpdateContext,
	parent: IFinalLedgerState,
	c: Candidate
): IFinalLedgerState {
	const { alternatives: _history, openingRecovery: _opening, ...rest } = parent;
	const state: IFinalLedgerState = JSON.parse(JSON.stringify(rest));
	const snapshot = finalLedgerSnapshot(ctx, parent);
	if (
		!snapshot.quiescent ||
		BigInt(c.localHeight) !== snapshot.localHeight ||
		BigInt(c.remoteHeight) !== snapshot.remoteHeight
	)
		throw new Error('Splice snapshot disagrees with its parent commitment');
	const funds = {
		...state.locked,
		local: (
			snapshot.localBalanceMsat +
			BigInt(c.localDelta) * 1000n
		).toString(),
		peer: (snapshot.remoteBalanceMsat + BigInt(c.peerDelta) * 1000n).toString()
	};
	const balances = {
		localBalanceMsat: BigInt(funds.local),
		remoteBalanceMsat: BigInt(funds.peer)
	};
	const local = buildFinalCommitmentView(
		ctx.candidate,
		snapshot.terms,
		'local',
		snapshot.localPoint,
		snapshot.localHeight,
		balances,
		snapshot.htlcs,
		c.funding,
		contextType(ctx)
	);
	validateFinalSpliceExit(
		{ expected: local.tx, signed: Transaction.fromHex(c.localExit) },
		Transaction.fromHex(c.funding.fundingTxHex),
		c.funding.fundingOutputIndex
	);
	const remote = buildFinalCommitmentView(
		ctx.candidate,
		snapshot.terms,
		'remote',
		snapshot.remotePoint,
		snapshot.remoteHeight,
		balances,
		snapshot.htlcs,
		c.funding,
		contextType(ctx)
	);
	state.funding = c.funding;
	state.locked = funds;
	state.local = {
		...state.local,
		tx: c.localExit,
		signed: c.peerCommitment,
		funds,
		nextNonce: { pub: c.localNextNonce, source: 'splice' }
	};
	state.remote = {
		...state.remote,
		tx: remote.tx.toHex(),
		signed: c.ourCommitment,
		funds,
		nextNonce: { pub: c.peerNextNonce }
	};
	state.initialRemote = state.remote;
	return state;
}
/** An adopted splice retires its parent. A signed pending splice shares the same update stream as its parent. */
export function finalFundingLedgers(
	ctx: IFinalUpdateContext,
	state: IFinalLedgerState,
	attempts: IFinalSpliceAttempt[],
	includeSignedCandidate = false
) {
	let selected: IFundingLedger = { ctx, s: state };
	let active = [selected];
	for (const a of attempts) {
		if (a.aborted !== undefined || !a.candidate) continue;
		const c = a.candidate as Candidate;
		const key = fundId(c.funding);
		state.alternatives ??= {};
		const s = (state.alternatives[key] ??= startSpliceView(ctx, selected.s, c));
		const view = { ctx: withFunding(ctx, c.funding), s };
		if (a.adopted) {
			selected = view;
			active = [view];
		} else if (a.funded || includeSignedCandidate) active.push(view);
	}
	if (active.length > 20)
		throw new Error('Too many concurrent final funding transactions');
	return active;
}
/** Both locks await a fresh local chain observation before the parent can be retired. */
export function spliceBlocksFinalUpdates(a: IFinalSpliceAttempt): boolean {
	return (
		!!a.awaitingAbortEcho ||
		(a.aborted === undefined &&
			!a.adopted &&
			(!a.funded ||
				a.rbf === 'quiescent' ||
				a.rbf === 'refused' ||
				(!!a.localLock && a.localLock === a.peerLock)))
	);
}
export function fundingAdmission(views: IFundingLedger[]) {
	const primary = finalLedgerStatus(views[0].ctx, views[0].s);
	for (const { ctx, s } of views.slice(1)) {
		const other = finalLedgerStatus(ctx, s);
		if (other.spendableOutboundMsat < primary.spendableOutboundMsat)
			primary.spendableOutboundMsat = other.spendableOutboundMsat;
		if (other.spendableSpliceOutSats < primary.spendableSpliceOutSats)
			primary.spendableSpliceOutSats = other.spendableSpliceOutSats;
	}
	return {
		...primary,
		multipleFunding: views.length > 1,
		awaitingFundingNonce: views.some((v) => v.s.awaitingFundingNonce),
		spliced: !!views[0].ctx.funding
	};
}
export function signatureFrames(id: string, signatures: Buffer[]) {
	const frames = signatures.map((payload) => ({
		type: MessageType.COMMITMENT_SIGNED,
		payload
	}));
	if (frames.length > 1)
		frames.unshift({
			type: MessageType.START_BATCH,
			payload: encodeStartBatchMessage({
				channelId: Buffer.from(id, 'hex'),
				batchSize: frames.length,
				messageType: MessageType.COMMITMENT_SIGNED
			})
		});
	return frames;
}
export function signFundingBatch(
	views: IFundingLedger[],
	root: BIP32Interface
) {
	return views.map(({ ctx, s }) => signFinalLedger(ctx, s, root));
}
function joinRevocations(raw: Buffer[]): Buffer {
	if (raw.length === 1) return raw[0];
	const [first, ...rest] = raw.map((wire) =>
		decodeRevokeAndAckMessage(wire, { finalTaproot: true })
	);
	for (const part of rest)
		if (
			!part.perCommitmentSecret.equals(first.perCommitmentSecret) ||
			!part.nextPerCommitmentPoint.equals(first.nextPerCommitmentPoint)
		)
			throw new Error('Funding commitments disagree about revocation height');
	return encodeRevokeAndAckMessage({
		...first,
		nextLocalNonces: [first, ...rest].flatMap((m) => m.nextLocalNonces!)
	});
}
export function receiveFundingBatch(
	views: IFundingLedger[],
	root: BIP32Interface,
	parts: Buffer[]
): Buffer {
	if (
		!parts.length ||
		parts.length > 20 ||
		(views.length > 1 && parts.length !== views.length)
	)
		throw new FinalUpdateProtocolError(
			'Incomplete batch of active funding commitments'
		);
	const previous = views.map((v) => v.s.local.revokeBatch);
	if (views.length === 1 && parts.length === 1) {
		const view = views[0],
			duplicate = view.s.local.signed === parts[0].toString('hex');
		const ack = acceptFinalLedgerCommit(view.ctx, view.s, root, parts[0]);
		if (duplicate && previous[0]) return Buffer.from(previous[0], 'hex');
		view.s.local.revokeBatch = ack.toString('hex');
		return ack;
	}
	const byTx = new Map<string, Buffer>();
	for (const payload of parts) {
		let id: string | undefined;
		try {
			const message = decodeCommitmentSignedMessage(payload);
			if (
				message.channelId.toString('hex') !== views[0].ctx.candidate.channelId
			)
				throw new Error('Wrong batch channel');
			id = message.fundingTxid?.toString('hex');
		} catch {
			throw new FinalUpdateProtocolError('Invalid commitment in batch');
		}
		if (!id || byTx.has(id))
			throw new FinalUpdateProtocolError(
				'Commitment batch requires distinct funding txids'
			);
		byTx.set(id, payload);
	}
	const ordered = views.map(({ ctx }) =>
		byTx.get(finalFundingTxid(ctx).toString('hex'))
	);
	if (ordered.some((p) => !p))
		throw new FinalUpdateProtocolError(
			'Missing active funding commitment in batch'
		);
	const duplicate = views.every(
		(v, i) => v.s.local.signed === ordered[i]!.toString('hex')
	);
	const ack = joinRevocations(
		views.map(({ ctx, s }, i) =>
			acceptFinalLedgerCommit(ctx, s, root, ordered[i]!)
		)
	);
	if (duplicate && previous[0] && previous.every((p) => p === previous[0]))
		return Buffer.from(previous[0], 'hex');
	for (const { s } of views) s.local.revokeBatch = ack.toString('hex');
	return ack;
}
function nonceFor(
	view: IFundingLedger,
	nonces: IChannelReestablishMessage['nextLocalNonces']
) {
	const result = nonces?.find((n) =>
		n.fundingTxid.equals(finalFundingTxid(view.ctx))
	);
	if (!result)
		throw new FinalUpdateProtocolError(
			'Missing verification nonce for active funding'
		);
	return result;
}
export function receiveFundingRevoke(
	views: IFundingLedger[],
	wire: Buffer
): void {
	let msg: ReturnType<typeof decodeRevokeAndAckMessage>;
	try {
		msg = decodeRevokeAndAckMessage(wire, { finalTaproot: true });
	} catch (err) {
		throw new FinalUpdateProtocolError(String(err));
	}
	const seen = new Set(
		msg.nextLocalNonces?.map((n) => n.nonce.toString('hex'))
	);
	if (seen.size !== msg.nextLocalNonces?.length)
		throw new FinalUpdateProtocolError(
			'Funding commitments share a verification nonce'
		);
	for (const view of views)
		acceptFinalLedgerRevoke(
			view.ctx,
			view.s,
			encodeRevokeAndAckMessage({
				...msg,
				nextLocalNonces: [nonceFor(view, msg.nextLocalNonces)]
			})
		);
}
export function fundingReestablish(
	views: IFundingLedger[],
	root: BIP32Interface
) {
	const all = views.map(({ ctx, s }) => finalLedgerReconnect(ctx, s, root));
	return { ...all[0], nextLocalNonces: all.flatMap((m) => m.nextLocalNonces) };
}
export function receiveFundingReestablish(
	views: IFundingLedger[],
	root: BIP32Interface,
	msg: IChannelReestablishMessage,
	holdUpdates = false
) {
	const seen = new Set(
		msg.nextLocalNonces?.map((n) => n.nonce.toString('hex'))
	);
	if (seen.size !== msg.nextLocalNonces?.length)
		throw new FinalUpdateProtocolError(
			'Funding commitments share a reconnect nonce'
		);
	const all = views.map((view) =>
		acceptFinalLedgerReconnect(
			view.ctx,
			view.s,
			root,
			{
				...msg,
				nextLocalNonces: [nonceFor(view, msg.nextLocalNonces)]
			},
			holdUpdates
		)
	);
	const out: { type: MessageType; payload: Buffer }[] = [];
	for (const [i, frame] of all[0].entries()) {
		const same = all.map((messages) => messages[i]);
		if (same.some((m) => m?.type !== frame.type))
			throw new Error('Funding commitments disagree about replay order');
		if (frame.type === MessageType.COMMITMENT_SIGNED)
			out.push(
				...signatureFrames(
					msg.channelId.toString('hex'),
					same.map((m) => m.payload)
				)
			);
		else if (frame.type === MessageType.REVOKE_AND_ACK)
			out.push({
				type: frame.type,
				payload: views[0].s.local.revokeBatch
					? Buffer.from(views[0].s.local.revokeBatch, 'hex')
					: joinRevocations(same.map((m) => m.payload))
			});
		else out.push(frame);
	}
	return out;
}
