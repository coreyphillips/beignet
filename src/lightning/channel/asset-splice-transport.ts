import {
	receivedAdoptedSpliceSignature,
	type AdoptedSpliceReplayEvent
} from '../storage/asset-splice-release-replay';
import { assetUpdateFundingMembers } from '../storage/asset-splice-exit-proofs';
import { assetUpdateHistory } from '../storage/asset-update-history';
import { INBOUND_HTLC_CLAIM_FORCE_CLOSE_BUFFER } from '../node/config';
import { Transaction } from 'bitcoinjs-lib';
import { sha256 } from '../crypto/provider';
import { isValidPublicKey } from '../crypto/ecdh';
import { deriveChannelKeys } from '../keys/wallet-keys';
import { MessageType as M } from '../message/types';
import { MAX_LIGHTNING_PAYLOAD } from '../message/custom-records';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../message/channel-commitment';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype as Sub
} from '../message/custom';
import {
	encodeTxCompleteMessage,
	decodeTxSignaturesMessage,
	encodeTxSignaturesMessage,
	decodeTxAbortMessage,
	encodeTxAbortMessage
} from '../message/interactive-tx';
import { encodeStfuMessage } from '../message/stfu';
import {
	decodeSpliceMessage,
	decodeSpliceAckMessage,
	encodeSpliceMessage,
	encodeSpliceAckMessage,
	SPLICE_LOCK_DEPTH_ACCEPT_MAX
} from '../message/splice';
import type { IFinalOpeningRuntime } from './final-opening-runtime';
import type { SqliteStorage } from '../storage/sqlite-storage';
import type {
	IAssetSpliceContext,
	IAssetSplicePlanner
} from './asset-splice-agreement';
import {
	AssetSpliceExchange,
	localAssetSpliceProposal
} from './asset-splice-exchange';
import { AssetSpliceConstruction } from './asset-splice-construction';
import type { IAssetSpliceSigningHost } from './asset-splice-signature-round';
import type { IAssetSpliceConfirmationProvider } from './asset-splice-confirmation';
import type { IChannelManagerConfig } from './channel-manager';
import type { IFinalFundingReference } from './final-splice-candidate';
import { MAX_SPLICE_FEERATE_PERKW } from './splice-weight';

export type AssetSpliceHost = IAssetSplicePlanner &
	IAssetSpliceSigningHost &
	IAssetSpliceConfirmationProvider;
export function completeAssetSpliceHost(
	value: unknown
): value is AssetSpliceHost {
	const host = value as Partial<AssetSpliceHost> | undefined;
	return (
		!!host &&
		(
			[
				'proposeSplice',
				'spliceContribution',
				'abandonSplice',
				'describeSplice',
				'prepareSplice',
				'signSpliceExits',
				'verifySpliceExits',
				'retainSpliceExits',
				'signSpliceFunding',
				'verifySpliceFunding',
				'confirmSpliceFunding',
				'retractSpliceFunding'
			] as const
		).every((k) => typeof host[k] === 'function')
	);
}
export interface IStartAssetSplice {
	fundingFeeratePerkw: number;
	minimumDepth: number;
}
const MAX_NEGOTIATING_CHANNELS = 8,
	MAX_QUEUED_FRAMES = 160;
const PROPOSAL_LIFETIME_MS = 120000;
const HTLC_QUIESCENCE_MS = 60000;
type HtlcDeadline = { expiry: number; claimHeight: number };
type SpliceWatchdog = {
	disconnect(peer: string): void;
	close(id: string): void;
	timeoutMs?: number;
};
type Begin = {
	deadline: number;
	htlcDeadline?: HtlcDeadline | null;
	kind: 'peer-splice';
	index: number;
	initiator: boolean;
	parent: IFinalFundingReference;
	root: string;
	state: string;
	priorDigest?: string;
	feerate: number;
	locktime: number;
	depth: number;
};
type Field =
	| 'expired'
	| 'peer-stfu'
	| 'init'
	| 'ack'
	| 'retired'
	| 'peer-share'
	| 'peer-witness'
	| 'assembled';
type Record =
	| Begin
	| { kind: 'peer-splice-stage'; index: number; field: Field; hex: string };
type Round = ReturnType<SqliteStorage['assetSpliceSignatureRound']>;
type Live = {
	begin: Begin;
	peer: string;
	sent: Set<string>;
	exchange?: AssetSpliceExchange;
	ctx?: IAssetSpliceContext;
	construction?: AssetSpliceConstruction;
	round?: Round;
	leaves?: Awaited<ReturnType<Round['verifyExitShares']>>;
	retained?: boolean;
	peerCommitment?: Buffer;
	peerWitness?: Buffer;
	waitingForParent?: boolean;
	parentRetry?: { current: () => boolean };
	replayConstruction?: boolean;
	expired?: boolean;
	expires?: ReturnType<typeof setTimeout>;
};
const interactive = [
	M.TX_ADD_INPUT,
	M.TX_ADD_OUTPUT,
	M.TX_COMPLETE,
	M.TX_REMOVE_INPUT,
	M.TX_REMOVE_OUTPUT
];
function validOptions(fee: number, depth: number) {
	if (
		!Number.isSafeInteger(fee) ||
		fee < 1 ||
		fee > MAX_SPLICE_FEERATE_PERKW ||
		!Number.isSafeInteger(depth) ||
		depth < 1 ||
		depth > SPLICE_LOCK_DEPTH_ACCEPT_MAX
	)
		throw Error('Asset splice feerate or depth exceeds local policy');
}
function attemptId(id: string, b: Begin, key: Buffer) {
	const index = Buffer.alloc(4);
	index.writeUInt32BE(b.parent.fundingOutputIndex);
	return sha256(
		Buffer.concat([
			Buffer.from('asset-splice-attempt/v1\u0000'),
			Buffer.from(id, 'hex'),
			Transaction.fromHex(b.parent.fundingTxHex).getHash(),
			index,
			key
		])
	);
}

/** Each channel advances on one queue. The original device records public key allocation, both offers and exact wires before use. */
export class AssetSpliceTransport {
	private live = new Map<string, Live>();
	private queues = new Map<string, Promise<void>>();
	private pendingFrames = new Map<string, number>();
	private epochs = new Map<string, number>();
	private claimMargin = INBOUND_HTLC_CLAIM_FORCE_CLOSE_BUFFER;
	private retiring = new Set<string>();
	constructor(
		private runtime: IFinalOpeningRuntime,
		private host: AssetSpliceHost,
		private eligible: (peer: string, id: string) => boolean,
		private available: (id: string, txid: string, opening: boolean) => boolean,
		private height: () => number,
		private send: (peer: string, type: number, raw: Buffer) => void,
		private verify: NonNullable<
			IChannelManagerConfig['verifyRemoteFundingInput']
		>,
		private watch: (id: string) => void,
		private broadcast: (raw: Buffer) => void,
		private report: (id: string, reason: string) => void,
		private watchdog?: SpliceWatchdog
	) {}
	private get store() {
		return this.runtime.storage;
	}
	private enqueue(id: string, action: () => Promise<void>) {
		const count = this.pendingFrames.get(id) ?? 0;
		if (count >= MAX_QUEUED_FRAMES)
			return Promise.reject(new Error('Too many queued splice frames'));
		this.pendingFrames.set(id, count + 1);
		const before = this.queues.get(id) ?? Promise.resolve(),
			ticket = this.epochs.get(id) ?? 0;
		const next = before
			.catch(() => undefined)
			.then(async () => {
				if ((this.epochs.get(id) ?? 0) === ticket) await action();
			});
		this.queues.set(id, next);
		void next
			.finally(() => {
				const remaining = this.pendingFrames.get(id)! - 1;
				if (remaining) this.pendingFrames.set(id, remaining);
				else this.pendingFrames.delete(id);
				if (this.queues.get(id) === next) this.queues.delete(id);
			})
			.catch(() => undefined);
		return next;
	}
	private saved(id: string, b: Begin, f: Field) {
		const { records } = this.store.readAssetSpliceJournal<Record>(id);
		const entry = records.find(
			(r) =>
				r.kind === 'peer-splice-stage' && r.index === b.index && r.field === f
		);
		return entry?.kind === 'peer-splice-stage'
			? Buffer.from(entry.hex, 'hex')
			: undefined;
	}
	private record(id: string, b: Begin, f: Field, bytes: Buffer) {
		const old = this.saved(id, b, f);
		if (old) {
			if (!old.equals(bytes))
				throw Error('Conflicting asset splice peer stage');
			return;
		}
		const head = this.store.readAssetSpliceJournal(id);
		this.store.appendAssetSpliceEvent(id, head, {
			kind: 'peer-splice-stage',
			index: b.index,
			field: f,
			hex: bytes.toString('hex')
		} satisfies Record);
	}
	private selected(id: string) {
		const opening = this.store.loadFinalDaemonOpening(id);
		if (
			!opening?.readyExchanged ||
			!opening.funding ||
			opening.exitToBroadcast ||
			!opening.session.assetEvidence ||
			!opening.session.updateLimits
		)
			return;
		const adopted = this.store.loadAdoptedAssetSpliceReceipt(id);
		const parent = adopted?.candidate.funding ?? {
			fundingTxHex: opening.candidate.fundingTxHex,
			fundingOutputIndex: opening.candidate.fundingOutputIndex,
			localFundingPubkey: opening.candidate.localFundingPubkey,
			remoteFundingPubkey: opening.candidate.remoteFundingPubkey,
			localFundingKeyIndex: opening.session.channelKeyIndex
		};
		if (!parent) return;
		const tx = Transaction.fromHex(parent.fundingTxHex);
		if (!this.available(id, tx.getId(), !adopted)) return;
		const updates = this.store.assetSpliceUpdateHead(id);
		if (updates.inProgress) return;
		const secured = updates.committed;
		if (
			secured &&
			!assetUpdateFundingMembers(this.store, id, secured).some(
				(m) =>
					m.fundingTxid === tx.getId() &&
					m.outputIndex === parent.fundingOutputIndex
			)
		)
			return;

		return {
			parent,
			root:
				adopted?.candidate.fundingRoot ??
				opening.session.assetEvidence.fundingRoot,
			state: secured?.height ?? adopted?.stateNumber ?? '0',
			htlcDeadline: this.htlcDeadline(secured?.htlcs ?? []),
			...(secured && { priorDigest: secured.digest }),
			depth: adopted?.minimumDepth ?? opening.candidate.minimumDepth
		};
	}
	private pending(id: string): Begin | undefined {
		const existing = this.live.get(id);
		const head = this.store.readAssetSpliceJournal<Record>(id);
		const last = head.records
			.filter((r): r is Begin => r.kind === 'peer-splice')
			.pop();
		if (!last || this.saved(id, last, 'retired')) return undefined;
		if (this.saved(id, last, 'assembled')) {
			const adopted = this.store.loadAdoptedAssetSpliceReceipt(id);
			if (
				adopted &&
				adopted.parent.fundingTxid ===
					Transaction.fromHex(last.parent.fundingTxHex).getId()
			)
				return undefined;
		}
		if (existing?.begin.index === last.index) return existing.begin;
		// Older records stored the two-minute proposal deadline and the authenticated state digest.
		if (last.htlcDeadline === undefined && last.priorDigest) {
			const state = assetUpdateHistory(this.store, id).states.get(
				BigInt(last.state)
			);
			if (state?.digest !== last.priorDigest)
				throw Error('Unknown asset splice parent state');
			const deadline = this.htlcDeadline(state.htlcs);
			if (deadline)
				return {
					...last,
					htlcDeadline: deadline,
					deadline: last.deadline - PROPOSAL_LIFETIME_MS + HTLC_QUIESCENCE_MS
				};
		}
		return last;
	}
	private session(id: string, b: Begin): Live {
		const current = this.live.get(id);
		if (current?.begin.index === b.index) return current;
		const peer = this.store.loadFinalOpeningSession(id)!.peer;
		if (current?.expires) clearTimeout(current.expires);
		const live: Live = {
			peer,
			begin: b,
			sent: new Set<string>(),
			replayConstruction: true,
			expired: !!this.saved(id, b, 'expired')
		};
		this.live.set(id, live);
		if (!this.saved(id, b, 'assembled') && !live.expired) {
			live.expires = setTimeout(
				() => {
					if (this.live.get(id) !== live || this.saved(id, b, 'assembled'))
						return;
					if (b.htlcDeadline) this.expire(id, live, this.height());
					else if (!this.hasAuthorization(id, live))
						this.failure(id, new Error('Asset splice proposal expired'));
				},
				Math.max(1, b.deadline - Date.now())
			);
			live.expires.unref?.();
		}
		return live;
	}
	private htlcDeadline(
		htlcs: readonly { cltvExpiry: number }[]
	): HtlcDeadline | null {
		if (!htlcs.length) return null;
		const expiry = Math.min(...htlcs.map((h) => h.cltvExpiry));
		return { expiry, claimHeight: expiry - this.claimMargin };
	}
	private atMargin(b: Begin, height: number): boolean {
		return (
			!!b.htlcDeadline &&
			height >=
				Math.min(
					b.htlcDeadline.claimHeight,
					b.htlcDeadline.expiry - this.claimMargin
				)
		);
	}
	private ended(s: Live): boolean {
		const b = s.begin;
		return (
			!!b.htlcDeadline &&
			(Date.now() >= b.deadline ||
				this.atMargin(b, this.height()) ||
				!!s.expired)
		);
	}
	private expire(id: string, s: Live, height: number): void {
		const b = s.begin;
		try {
			if (this.saved(id, b, 'retired') || this.saved(id, b, 'assembled'))
				return;
			if (!this.saved(id, b, 'expired')) {
				this.record(id, b, 'expired', Buffer.alloc(0));
				s.expired = true;
				this.report(id, 'Asset splice reached its HTLC quiescence deadline');
				if (this.live.get(id) === s) {
					this.disconnected(s.peer);
					this.watchdog?.disconnect(s.peer);
				}
			}
			if (this.hasAuthorization(id, s)) {
				// The wallet may have released its asset share. Keep its inputs locked and
				// retry the chain-selected exit on every block until the observation is certain.
				if (
					this.atMargin(b, height) &&
					!this.store.loadFinalDaemonOpening(id)?.exitToBroadcast
				)
					this.watchdog?.close(id);
				return;
			}
			if (this.retiring.has(id)) return;
			this.retiring.add(id);
			void this.enqueue(id, async () => {
				if (!this.hasAuthorization(id, s) && !this.saved(id, b, 'retired'))
					await this.retire(id, s, false);
			})
				.catch((e) =>
					this.report(id, e instanceof Error ? e.message : String(e))
				)
				.finally(() => this.retiring.delete(id));
		} catch (e) {
			this.report(id, e instanceof Error ? e.message : String(e));
		}
	}
	/** Check original-device attempts even when no peer is connected or the wallet just restarted. */
	checkHtlcDeadlines(height: number, claimMargin: number): void {
		this.claimMargin = Math.max(
			INBOUND_HTLC_CLAIM_FORCE_CLOSE_BUFFER,
			claimMargin
		);
		for (const { channelId: id } of this.store.loadFinalOpenings()) {
			try {
				if (
					!this.store.loadFinalOpeningSession(id)?.assetEvidence ||
					this.store.loadFinalDaemonOpening(id)?.exitToBroadcast
				)
					continue;
				const b = this.pending(id);
				if (
					!b?.htlcDeadline ||
					this.saved(id, b, 'assembled') ||
					(!this.atMargin(b, height) &&
						Date.now() < b.deadline &&
						!this.saved(id, b, 'expired'))
				)
					continue;
				const peer = this.store.loadFinalOpeningSession(id)!.peer;
				this.expire(
					id,
					this.live.get(id) ?? { begin: b, peer, sent: new Set() },
					height
				);
			} catch (e) {
				this.report(id, e instanceof Error ? e.message : String(e));
			}
		}
	}
	private startRecord(
		id: string,
		initiator: boolean,
		fee: number,
		depth: number,
		firstDeadline?: number
	): Begin {
		this.store.assertAssetSpliceCanStart(id);
		const parent = this.selected(id);
		if (!parent)
			throw Error(
				'Asset splice requires an active, confirmed original wallet funding output'
			);
		const block = this.height();
		if (
			parent.htlcDeadline &&
			(!Number.isSafeInteger(block) ||
				block < 1 ||
				block >= parent.htlcDeadline.claimHeight)
		) {
			if (!initiator)
				this.watchdog?.disconnect(this.store.loadFinalOpeningSession(id)!.peer);
			throw Error(
				'Asset splice requires every pending HTLC to be outside its claim margin'
			);
		}
		const active = this.store
			.loadFinalOpenings()
			.filter(
				(c) =>
					this.store.loadFinalOpeningSession(c.channelId)?.assetEvidence &&
					!!this.pending(c.channelId)
			);
		if (active.length >= MAX_NEGOTIATING_CHANNELS)
			throw Error('Too many unfinished asset splice attempts');
		const index = this.store.allocateFinalChannelKeyIndex(1);
		const begin: Begin = {
			kind: 'peer-splice',
			deadline:
				firstDeadline ??
				Date.now() +
					(parent.htlcDeadline
						? Math.min(
								HTLC_QUIESCENCE_MS,
								this.watchdog?.timeoutMs ?? HTLC_QUIESCENCE_MS
						  )
						: PROPOSAL_LIFETIME_MS),
			htlcDeadline: parent.htlcDeadline,
			index,
			initiator,
			parent: parent.parent,
			root: parent.root,
			state: parent.state,
			...(parent.priorDigest && { priorDigest: parent.priorDigest }),
			feerate: fee,
			depth,
			locktime: block
		};
		const head = this.store.readAssetSpliceJournal(id);
		this.store.appendAssetSpliceEvent(id, head, begin);
		return begin;
	}
	async start(id: string, options: IStartAssetSplice) {
		await this.enqueue(id, async () => {
			const peer = this.store.loadFinalOpeningSession(id)?.peer;
			validOptions(options.fundingFeeratePerkw, options.minimumDepth);
			if (!peer || !this.eligible(peer, id) || this.pending(id))
				throw Error(
					'Asset splice requires an idle channel and bilateral feature negotiation'
				);
			const b = this.startRecord(
				id,
				true,
				options.fundingFeeratePerkw,
				options.minimumDepth
			);
			await this.drive(id, this.session(id, b));
		});
	}
	private context(id: string, s: Live, initKey: Buffer) {
		if (s.ctx) return s.ctx;
		const b = s.begin,
			tx = Transaction.fromHex(b.parent.fundingTxHex);
		s.ctx = {
			channelId: id,
			peer: s.peer,
			isInitiator: b.initiator,
			attempt: attemptId(id, b, initKey),
			walletGeneration: 4,
			stateNumber: BigInt(b.state),
			...(b.priorDigest && { priorDigest: Buffer.from(b.priorDigest, 'hex') }),
			oldOutpoint: { hash: tx.getHash(), index: b.parent.fundingOutputIndex },
			currentParent: () => {
				if (
					this.live.get(id) !== s ||
					!this.eligible(s.peer, id) ||
					this.ended(s)
				)
					return;
				try {
					this.store.assertAssetSpliceCanStart(id);
				} catch {
					return undefined;
				}
				const v = this.selected(id);
				if (!v) {
					s.waitingForParent = true;
					return;
				}
				if (
					v.parent.fundingTxHex !== b.parent.fundingTxHex ||
					v.parent.fundingOutputIndex !== b.parent.fundingOutputIndex ||
					v.root !== b.root ||
					v.state !== b.state ||
					v.priorDigest !== b.priorDigest
				)
					return;
				return {
					oldOutpoint: {
						hash: tx.getHash(),
						index: b.parent.fundingOutputIndex
					},
					stateNumber: BigInt(b.state),
					...(b.priorDigest && {
						priorDigest: Buffer.from(b.priorDigest, 'hex')
					}),
					walletGeneration: 4 as const
				};
			}
		};
		return s.ctx;
	}
	private sendOnce(
		id: string,
		s: Live,
		key: string,
		type: number,
		bytes: Buffer
	) {
		if (this.live.get(id) !== s || s.sent.has(key)) return;
		this.send(s.peer, type, bytes);
		s.sent.add(key);
	}
	private replayFunding(id: string, s: Live, peerWitness?: Buffer): boolean {
		const init = this.saved(id, s.begin, 'init');
		if (!init) return false;
		const attempt = attemptId(
			id,
			s.begin,
			decodeSpliceMessage(init).fundingPubkey
		).toString('hex');
		const released = this.store.releasedAssetSplice(id, attempt);
		if (!released) return false;
		if (peerWitness) {
			released.receive(peerWitness);
			this.record(id, s.begin, 'peer-witness', peerWitness);
		}
		this.watch(id);
		if (this.store.loadFinalDaemonOpening(id)?.exitToBroadcast) return true;
		this.sendOnce(id, s, 'funding', M.TX_SIGNATURES, released.wire);
		const full = released.transaction();
		if (full && !s.sent.has('broadcast')) {
			this.record(id, s.begin, 'assembled', full.toBuffer());
			this.broadcast(full.toBuffer());
			s.sent.add('broadcast');
		}
		return true;
	}

	/** Retry the same connected attempt once its exact parent is available again. */
	fundingObserved(id: string, txid: string, current: () => boolean): void {
		const s = this.live.get(id);
		if (
			!s?.ctx ||
			s.sent.has('broadcast') ||
			(!s.waitingForParent && !this.queues.has(id)) ||
			Transaction.fromHex(s.begin.parent.fundingTxHex).getId() !== txid ||
			!current()
		)
			return;
		if (s.parentRetry) {
			s.parentRetry.current = current;
			return;
		}
		const retry = { current };
		s.parentRetry = retry;
		void this.enqueue(id, async () => {
			s.parentRetry = undefined;
			if (
				s.waitingForParent &&
				this.live.get(id) === s &&
				this.eligible(s.peer, id) &&
				retry.current() &&
				s.ctx?.currentParent()
			) {
				await this.drive(id, s);
			}
		}).catch((error) => {
			if (s.parentRetry === retry) s.parentRetry = undefined;
			if (this.live.get(id) === s) this.failure(id, error);
		});
	}

	// The peer can finish the frozen transaction while our funding read is pending.
	// Keep one canonical packet per stage, in this connection only. The round
	// verifies its signatures after local proof verification and before release.
	private queueSignature(id: string, s: Live, type: M, payload: Buffer): void {
		const commitment = type === M.COMMITMENT_SIGNED;
		const stored = this.saved(
			id,
			s.begin,
			commitment ? 'peer-share' : 'peer-witness'
		);
		if (stored?.equals(payload)) return;
		const key = commitment ? 'peerCommitment' : 'peerWitness';
		const candidate = s.exchange?.result()?.verified.candidate.tx;
		if (
			!candidate ||
			!s.exchange?.hasLocalExitShares() ||
			(!commitment && !s.sent.has('commitment') && !s.retained) ||
			payload.length > MAX_LIGHTNING_PAYLOAD
		) {
			throw Error(
				commitment
					? 'Premature asset splice commitment'
					: 'Premature asset splice funding witness'
			);
		}
		if (commitment) {
			const wire = decodeCommitmentSignedMessage(payload, {
				customRecords: true
			});
			if (
				!wire.fundingTxid?.equals(candidate.getHash()) ||
				!wire.partialSignatureWithNonce ||
				!encodeCommitmentSignedMessage(wire).equals(payload)
			)
				throw Error('Unmatched asset splice commitment candidate');
		} else {
			const wire = decodeTxSignaturesMessage(payload, { taproot: true });
			if (
				!wire.txid.equals(candidate.getHash()) ||
				!wire.sharedInputPartialSignatureWithNonce ||
				!encodeTxSignaturesMessage(wire).equals(payload)
			)
				throw Error('Unmatched asset splice funding candidate');
		}
		const queued = s[key];
		if (stored || (queued && !queued.equals(payload)))
			throw Error('Conflicting asset splice signature replay');
		s[key] ??= payload;
	}

	private async drive(id: string, s: Live) {
		if (this.live.get(id) !== s || !this.eligible(s.peer, id)) return;
		s.waitingForParent = false;
		const b = s.begin,
			cid = Buffer.from(id, 'hex');
		if (this.replayFunding(id, s)) {
			if (this.ended(s)) this.expire(id, s, this.height());
			return;
		}
		if (this.ended(s)) {
			this.expire(id, s, this.height());
			return;
		}
		if (Date.now() > b.deadline && !this.hasAuthorization(id, s))
			throw Error('Asset splice proposal expired');
		this.sendOnce(
			id,
			s,
			'stfu',
			M.STFU,
			encodeStfuMessage({ channelId: cid, initiator: b.initiator })
		);
		if (!this.saved(id, b, 'peer-stfu')) return;
		const pub = deriveChannelKeys(this.runtime.root, 1, b.index)
			.channelBasepoints.fundingPubkey;
		let init = this.saved(id, b, 'init'),
			ack = this.saved(id, b, 'ack');
		if (!init && !b.initiator) return;
		const ctx = this.context(
			id,
			s,
			init ? decodeSpliceMessage(init).fundingPubkey : pub
		);
		if (!ctx.currentParent()) return;
		if (!init || (!ack && !b.initiator)) {
			await localAssetSpliceProposal(this.store, this.host, ctx);
			if (!ctx.currentParent()) return;
			const relativeSatoshis = this.host.spliceContribution(ctx);
			if (b.initiator) {
				init = encodeSpliceMessage({
					channelId: cid,
					relativeSatoshis,
					fundingPubkey: pub,
					fundingFeeratePerkw: b.feerate,
					locktime: b.locktime,
					lockDepth: b.depth
				});
				this.record(id, b, 'init', init);
			} else {
				const p = decodeSpliceMessage(init!);
				ack = encodeSpliceAckMessage({
					channelId: cid,
					relativeSatoshis,
					fundingPubkey: pub,
					lockDepth: p.lockDepth
				});
				this.record(id, b, 'ack', ack);
			}
		}
		if (b.initiator && init) this.sendOnce(id, s, 'init', M.SPLICE, init);
		if (!b.initiator && ack) this.sendOnce(id, s, 'ack', M.SPLICE_ACK, ack);
		if (!init || !ack) return;
		const session = this.store.loadFinalOpeningSession(id)!,
			limits = session.updateLimits!;
		s.exchange ??= new AssetSpliceExchange(
			this.host,
			ctx,
			{
				parent: b.parent,
				parentRoot: Buffer.from(b.root, 'hex'),
				dust: BigInt(
					Math.max(
						546,
						session.terms.localDustLimitSatoshis,
						session.terms.remoteDustLimitSatoshis
					)
				),
				maxAcceptedHtlcs: b.initiator
					? [limits.local.maxAcceptedHtlcs, limits.remote.maxAcceptedHtlcs]
					: [limits.remote.maxAcceptedHtlcs, limits.local.maxAcceptedHtlcs]
			},
			init,
			ack,
			this.store,
			(raw) => {
				if (this.live.get(id) === s && !this.ended(s))
					this.send(s.peer, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
			}
		);
		await s.exchange.advance();
		const result = s.exchange.result();
		if (!result || this.live.get(id) !== s || !ctx.currentParent()) return;
		const tx = result.verified.candidate.tx;
		if (!s.construction) {
			this.store.reserveAssetSpliceWalletInputs(
				id,
				ctx.attempt.toString('hex'),
				Transaction.fromHex(b.parent.fundingTxHex).getId() +
					':' +
					b.parent.fundingOutputIndex,
				result.verified.candidate.localInputs.map(
					(i) =>
						Buffer.from(tx.ins[i].hash).reverse().toString('hex') +
						':' +
						tx.ins[i].index
				)
			);
			s.round = this.store.assetSpliceSignatureRound(
				this.runtime.root,
				result.layout,
				result.verified,
				b.index
			);
			s.construction = new AssetSpliceConstruction(
				result.layout,
				result.verified,
				s.round.txComplete(),
				this.store
			);
		}
		if (s.replayConstruction) {
			s.replayConstruction = false;
			const previous = s.construction.replay();
			if (previous) this.send(s.peer, previous.type, previous.payload);
		}
		const turn = s.construction.next();
		if (turn) this.send(s.peer, turn.type, turn.payload);
		const built = s.construction.agreement();
		if (!built) return;
		if (!built.candidate.tx.getHash().equals(tx.getHash()))
			throw Error(
				'Splice interactive transaction differs from the agreed candidate'
			);
		const local = encodeTxCompleteMessage(built.local),
			remote = encodeTxCompleteMessage(built.peer);
		if (
			!(await s.exchange.checkpoint(
				built.candidate.tx,
				b.initiator ? [local, remote] : [remote, local]
			))
		)
			return;
		const round = s.round!;
		const pair = await s.exchange.exitShares(() =>
			round.signExitShares(this.host, ctx)
		);
		if (!pair || this.live.get(id) !== s) return;
		const children =
			ctx.stateNumber > 0n
				? await s.exchange.exitHtlcShares(() =>
						round.signExitHtlcs(this.host, ctx, pair)
				  )
				: undefined;
		if (ctx.stateNumber > 0n && !children) return;
		s.leaves ??= await round.verifyExitShares(this.host, ctx, pair, children);
		if (!ctx.currentParent()) return;
		this.sendOnce(
			id,
			s,
			'commitment',
			M.COMMITMENT_SIGNED,
			round.commitmentSigned(s.leaves)
		);
		const peerCommit = s.peerCommitment ?? this.saved(id, b, 'peer-share');
		if (!peerCommit) return;
		s.peerCommitment = undefined;
		round.acceptCommitmentSigned(s.leaves, peerCommit);
		this.record(id, b, 'peer-share', peerCommit);
		if (!s.retained) {
			await round.retainExits(this.host, ctx, s.leaves);
			s.retained = true;
		}
		if (!ctx.currentParent()) return;
		const peerFunding = s.peerWitness ?? this.saved(id, b, 'peer-witness');
		if (peerFunding) {
			s.peerWitness = undefined;
			round.receiveFunding(peerFunding);
			this.record(id, b, 'peer-witness', peerFunding);
		}
		const funding = await round.nextFunding(this.host, ctx, this.verify);
		if (this.live.get(id) !== s) return;
		if (funding) {
			this.watch(id);
			this.sendOnce(id, s, 'funding', M.TX_SIGNATURES, funding);
		}
		const done = round.transaction();
		if (done) {
			this.record(id, b, 'assembled', done.toBuffer());
			this.watch(id);
			if (!s.sent.has('broadcast')) {
				this.broadcast(done.toBuffer());
				s.sent.add('broadcast');
			}
		}
	}
	private async retire(id: string, s: Live, reply: boolean) {
		if (!s.ctx) {
			const init = this.saved(id, s.begin, 'init');
			const key = init
				? decodeSpliceMessage(init).fundingPubkey
				: s.begin.initiator
				? deriveChannelKeys(this.runtime.root, 1, s.begin.index)
						.channelBasepoints.fundingPubkey
				: undefined;
			if (key) this.context(id, s, key);
		}
		if (s.ctx) {
			// A wallet that has already authorized the joint spend refuses to abandon it.
			await this.host.abandonSplice(s.ctx);
			const reserved = this.store
				.readAssetSpliceJournal<{ kind: string; attempt?: string }>(id)
				.records.some(
					(r) =>
						r.kind === 'wallet-inputs' &&
						r.attempt === s.ctx!.attempt.toString('hex')
				);
			if (reserved)
				this.store.releaseAssetSpliceWalletInputs(
					id,
					s.ctx.attempt.toString('hex')
				);
		}
		this.record(id, s.begin, 'retired', Buffer.alloc(0));
		if (reply)
			this.send(
				s.peer,
				M.TX_ABORT,
				encodeTxAbortMessage({
					channelId: Buffer.from(id, 'hex'),
					data: Buffer.from('Splice abandoned')
				})
			);
		if (s.expires) clearTimeout(s.expires);
		this.live.delete(id);
	}
	handle(peer: string, type: M, raw: Buffer): boolean {
		if (raw.length < 32) return false;
		const id = raw.subarray(0, 32).toString('hex');
		if (!this.eligible(peer, id)) return false;
		// Opening reestablish may resend the original nonce and funding frames.
		const openingReplay =
			type === M.TX_COMPLETE
				? this.store.loadFinalPeerTxComplete(id)
				: type === M.TX_SIGNATURES
				? this.store.loadFinalPeerTxSignatures(id)
				: type === M.COMMITMENT_SIGNED
				? this.store.loadReceivedOpeningCommitment(id)
				: undefined;
		if (openingReplay?.equals(raw)) return false;
		if (
			![
				M.STFU,
				M.SPLICE,
				M.SPLICE_ACK,
				M.TX_ABORT,
				M.COMMITMENT_SIGNED,
				M.TX_SIGNATURES,
				...interactive
			].includes(type)
		)
			return false;
		const pending = this.pending(id);
		if (
			pending &&
			(type === M.COMMITMENT_SIGNED || type === M.TX_SIGNATURES) &&
			receivedAdoptedSpliceSignature(
				this.store.readAssetSpliceJournal<AdoptedSpliceReplayEvent>(id).records,
				pending.index,
				type,
				raw
			)
		)
			return true;
		if (type !== M.STFU && !pending) {
			if (type !== M.TX_ABORT) return false;
			const last = this.store
				.readAssetSpliceJournal<Record>(id)
				.records.filter((r): r is Begin => r.kind === 'peer-splice')
				.at(-1);
			// Both peers can abort the same unsigned splice. Consume the terminal acknowledgement after retirement.
			return (
				!!last &&
				!!this.saved(id, last, 'retired') &&
				decodeTxAbortMessage(raw).data.equals(Buffer.from('Splice abandoned'))
			);
		}
		const payload = Buffer.from(raw);
		void this.enqueue(id, async () => {
			let b = this.pending(id);
			if (type === M.STFU) {
				if (payload.length !== 33 || payload[32] > 1)
					throw Error('Malformed asset splice quiescence');
				if (!b) {
					if (!payload[32]) return;
					b = this.startRecord(id, false, 1, 1);
				}
				const s = this.session(id, b);
				if (this.ended(s)) {
					this.expire(id, s, this.height());
					return;
				}
				if (
					payload[32] === 1 &&
					b.initiator &&
					!this.saved(id, b, 'peer-stfu') &&
					!this.store.loadFinalOpening(id)!.isInitiator
				) {
					await this.retire(id, s, false);
					b = this.startRecord(id, false, 1, 1, b.deadline);
					// Both quiescence messages on a simultaneous attempt carry the initiator flag.
					this.session(id, b).sent.add('stfu');
				} else if (!b.initiator && payload[32] !== 1)
					throw Error('Unexpected asset splice quiescence response');
				this.record(id, b, 'peer-stfu', payload);
			}
			if (!b) return;
			const s = this.session(id, b);
			switch (type) {
				case M.SPLICE: {
					if (b.initiator || !this.saved(id, b, 'peer-stfu'))
						throw Error('Unsolicited splice proposal');
					const msg = decodeSpliceMessage(payload);
					validOptions(msg.fundingFeeratePerkw, msg.lockDepth ?? 0);
					if (
						!isValidPublicKey(msg.fundingPubkey) ||
						msg.locktime > this.height() + 1 ||
						!encodeSpliceMessage(msg).equals(payload) ||
						msg.requireConfirmedInputs
					)
						throw Error('Unsupported asset splice proposal');
					this.record(id, b, 'init', payload);
					break;
				}
				case M.SPLICE_ACK: {
					const msg = decodeSpliceAckMessage(payload);
					if (
						!b.initiator ||
						!this.saved(id, b, 'init') ||
						msg.lockDepth !== b.depth ||
						!isValidPublicKey(msg.fundingPubkey) ||
						msg.requireConfirmedInputs ||
						!encodeSpliceAckMessage(msg).equals(payload)
					)
						throw Error('Unmatched asset splice acknowledgement');
					this.record(id, b, 'ack', payload);
					break;
				}
				case M.TX_ABORT: {
					decodeTxAbortMessage(payload);
					// Restore the original context even if the wallet restarted between authorization and abort.
					const init = this.saved(id, b, 'init');
					if (init)
						this.context(id, s, decodeSpliceMessage(init).fundingPubkey);
					await this.retire(id, s, true);
					return;
				}
				case M.COMMITMENT_SIGNED:
					this.queueSignature(id, s, type, payload);
					break;
				case M.TX_SIGNATURES:
					if (this.replayFunding(id, s, payload)) return;
					this.queueSignature(id, s, type, payload);
					break;
				default:
					if (interactive.includes(type)) {
						if (!s.construction)
							throw Error('Premature asset splice construction');
						s.construction.receive(type, payload);
					}
			}
			await this.drive(id, s);
		}).catch((error) => this.failure(id, error));
		return true;
	}
	// Frames may arrive in the same socket read as channel_reestablish. Buffer only
	// the previously agreed attempt for this connection until its channel resumes.
	private readonly restoring = new Map<
		string,
		{
			id: string;
			peer: string;
			frames: { subtype: number; bytes: Buffer }[];
		}
	>();
	reconnected(peer: string) {
		for (const { channelId: id } of this.store.loadFinalOpenings()) {
			if (this.store.loadFinalOpeningSession(id)?.peer !== peer) continue;
			const b = this.pending(id);
			const init = b && this.saved(id, b, 'init');
			if (!b || !init) continue;
			const key = attemptId(
				id,
				b,
				decodeSpliceMessage(init).fundingPubkey
			).toString('hex');
			if (!this.restoring.has(key))
				this.restoring.set(key, { id, peer, frames: [] });
		}
	}
	custom(peer: string, subtype: number, raw: Buffer) {
		const offset = subtype === Sub.ASSET_SPLICE_CONSENT ? 1 : 2;
		if (raw.length < offset + 32) return;
		const attempt = raw.subarray(offset, offset + 32);
		const restoring = this.restoring.get(attempt.toString('hex'));
		if (restoring?.peer === peer) {
			if (restoring.frames.length >= MAX_QUEUED_FRAMES) {
				this.report(restoring.id, 'Too many queued splice frames');
				return;
			}
			restoring.frames.push({ subtype, bytes: Buffer.from(raw) });
			return;
		}
		for (const [id, s] of this.live) {
			if (s.peer !== peer || !s.ctx?.attempt.equals(attempt)) continue;
			const copy = Buffer.from(raw);
			void this.enqueue(id, async () => {
				if (!this.eligible(peer, id) || this.live.get(id) !== s || !s.exchange)
					return;
				if (this.ended(s)) {
					this.expire(id, s, this.height());
					return;
				}
				await s.exchange.receive(subtype, copy);
				await this.drive(id, s);
			}).catch((error) => this.failure(id, error));
			return;
		}
	}
	private hasAuthorization(id: string, s: Live) {
		const init = this.saved(id, s.begin, 'init');
		if (!init) return false;
		const attempt = attemptId(
			id,
			s.begin,
			decodeSpliceMessage(init).fundingPubkey
		).toString('hex');
		const records = this.store.readAssetSpliceJournal<{
			kind: string;
			attempt?: string;
			field?: string;
			local?: boolean;
		}>(id).records;
		return records.some(
			(r) =>
				r.attempt === attempt &&
				(r.kind === 'splice-authorization-start' ||
					(r.kind === 'exchange' && r.field === 'authorization' && r.local))
		);
	}
	private failure(id: string, error: unknown) {
		this.report(id, error instanceof Error ? error.message : String(error));
		const s = this.live.get(id);
		if (!s || (this.pendingFrames.get(id) ?? 0) >= MAX_QUEUED_FRAMES) return;
		void this.enqueue(id, async () => {
			if (
				this.live.get(id) !== s ||
				this.hasAuthorization(id, s) ||
				(s.ctx && !s.ctx.currentParent() && Date.now() < s.begin.deadline)
			)
				return;
			await this.retire(id, s, true);
		}).catch((err) =>
			this.report(id, err instanceof Error ? err.message : String(err))
		);
	}
	destroy() {
		this.restoring.clear();
		for (const s of this.live.values()) this.disconnected(s.peer);
	}

	disconnected(peer: string) {
		for (const [key, route] of this.restoring)
			if (route.peer === peer) this.restoring.delete(key);
		for (const [id, s] of this.live)
			if (s.peer === peer) {
				this.epochs.set(id, (this.epochs.get(id) ?? 0) + 1);
				if (s.expires) clearTimeout(s.expires);
				this.live.delete(id);
			}
	}
	resume(peer: string, id: string) {
		if (!this.eligible(peer, id)) return;
		const b = this.pending(id);
		if (!b || this.store.loadFinalOpeningSession(id)?.peer !== peer) return;
		const s = this.session(id, b);
		const init = this.saved(id, b, 'init');
		const ctx =
			init && this.context(id, s, decodeSpliceMessage(init).fundingPubkey);
		const route = ctx?.attempt.toString('hex');
		const queued = route ? this.restoring.get(route) : undefined;
		if (route) this.restoring.delete(route);
		void this.enqueue(id, async () => {
			await this.drive(id, s);
			if (queued?.id !== id || queued.peer !== peer) return;
			for (const { subtype, bytes } of queued.frames) {
				if (this.live.get(id) !== s || !this.eligible(peer, id) || !s.exchange)
					return;
				await s.exchange.receive(subtype, bytes);
				await this.drive(id, s);
			}
		}).catch((error) =>
			this.report(id, error instanceof Error ? error.message : String(error))
		);
	}
}
