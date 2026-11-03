/**
 * Composite splice-out engine (issue #1922, docs/MULTI-CHANNEL-SPLICE-OUT.md
 * sections 1 to 6): one transaction that spends the funding outpoints of
 * several channels and pays one destination, negotiated as N ordinary splice
 * sessions that agree on one transaction.
 *
 * The wallet is the initiator in every session and adds the identical
 * contribution to each (section 2): in session i channel i's funding outpoint
 * is the shared input, every other channel's funding outpoint rides as an
 * EXTERNAL initiator input with its funding transaction as prev_tx, and the
 * N new funding outputs plus the destination are ordinary initiator outputs,
 * all with serial ids allocated here, once. Peers contribute nothing, so they
 * sign first in every session (section 4); every session holds its
 * commitment_signed until all N negotiated the same txid, and withholds its
 * tx_signatures on the N-1 external slots (the #592 machinery) until this
 * engine has every peer's shared_input_signature and fills every slot of
 * every session in one synchronous step, with RELEASED on disk first.
 *
 * The engine owns the composite record (section 5), persisted through the
 * `composite_splice` recovery mutation so a stage change rides the channel
 * transaction that causes it, and applies the restore table at boot.
 */

import * as bitcoin from 'bitcoinjs-lib';
import type { ChannelManager } from '../channel/channel-manager';
import type { Channel, ICompositeSpliceContribution } from '../channel/channel';
import { ChannelState } from '../channel/types';
import { ChannelSigner } from '../keys/signer';
import { createFundingScript } from '../script/funding';
import {
	estimateSpliceTxWeight,
	spliceFeeSats,
	MAX_SPLICE_FEERATE_PERKW
} from '../channel/splice-weight';
import type {
	CompositeSpliceStage,
	ICompositeSpliceChannel,
	ICompositeSpliceRecord
} from '../channel/composite-splice-record';
import {
	compositeSpliceStageAtLeast,
	compositeSpliceStageIsTerminal
} from '../channel/composite-splice-record';
import type { RecoveryMutation } from '../recovery/types';
import { randomBytes } from '../crypto/provider';
import type { NodeErrorCode } from './events';

/** Default time budget from the first stfu to the last peer tx_signatures. */
export const DEFAULT_COMPOSITE_SPLICE_BUDGET_MS = 60_000;

/** How long a terminal record (LOCKED, ABORTED, CONFLICTED) is kept. */
export const COMPOSITE_SPLICE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

/** Conservative dust floor for the destination (covers all standard outputs). */
const MIN_DESTINATION_SATS = 546n;

export interface ICompositeSpliceOutRequest {
	/** Where the withdrawn amount is paid; omit for the wallet's own address. */
	destinationScript?: Buffer;
	/** sum(debit): what the destination receives, sats. */
	amountSats: bigint;
	fundingFeeratePerkw: number;
	/**
	 * Restrict the set to these channels, all of which must qualify. Default:
	 * every eligible channel, debited largest spendable balance first.
	 */
	channelIds?: Buffer[];
	/** Time budget before RELEASED; default DEFAULT_COMPOSITE_SPLICE_BUDGET_MS. */
	budgetMs?: number;
}

export enum CompositeSpliceRefusalCode {
	INVALID_PARAMS = 'INVALID_PARAMS',
	/** Another composite is live on this node; refused, not queued. */
	BUSY = 'BUSY',
	/** No storage with the compositeSplices group, or no recovery journal. */
	STORAGE_REQUIRED = 'STORAGE_REQUIRED',
	/** A named channel does not exist. */
	CHANNEL_NOT_FOUND = 'CHANNEL_NOT_FOUND',
	/** No channel qualifies; `skipped` says why for each. */
	NO_ELIGIBLE_CHANNELS = 'NO_ELIGIBLE_CHANNELS',
	/** The eligible channels cannot cover amount plus fees. */
	INSUFFICIENT_BALANCE = 'INSUFFICIENT_BALANCE',
	/** One channel covers the amount alone: a plain splice-out does this. */
	SINGLE_CHANNEL_SUFFICES = 'SINGLE_CHANNEL_SUFFICES',
	/** The operation is unknown. */
	NOT_FOUND = 'NOT_FOUND',
	/** The operation passed its point of no return and cannot be aborted. */
	TOO_LATE = 'TOO_LATE'
}

export interface ICompositeSpliceChannelRefusal {
	channelId: Buffer;
	reason: string;
}

export interface ICompositeSplicePlanChannel {
	channelId: Buffer;
	peerPubkey: string;
	debitSats: bigint;
	feeSats: bigint;
	oldCapacitySats: bigint;
	newCapacitySats: bigint;
	/** The most this channel could have given at this fee share. */
	maxDebitSats: bigint;
}

export interface ICompositeSplicePlan {
	destinationScript: Buffer;
	amountSats: bigint;
	/** sum(fee_i): the fee the transaction pays. */
	feeSats: bigint;
	feeratePerkw: number;
	locktime: number;
	/** Estimated weight the fee was priced for. */
	weight: number;
	/** In input order (by funding outpoint). */
	channels: ICompositeSplicePlanChannel[];
	/** Channels considered and left out, with the reason. */
	skipped: ICompositeSpliceChannelRefusal[];
}

export interface ICompositeSpliceRefusal {
	ok: false;
	error: string;
	code: CompositeSpliceRefusalCode;
	skipped?: ICompositeSpliceChannelRefusal[];
}

export type ICompositeSplicePlanResult =
	| { ok: true; plan: ICompositeSplicePlan }
	| ICompositeSpliceRefusal;

export type ICompositeSpliceStartResult =
	| { ok: true; id: Buffer; plan: ICompositeSplicePlan }
	| ICompositeSpliceRefusal;

export interface ICompositeSpliceStageEvent {
	id: Buffer;
	stage: CompositeSpliceStage;
	/** The agreed transaction, internal byte order, from COMMITTED on. */
	txid?: Buffer;
	/** Why the operation ended in ABORTED. */
	reason?: string;
}

/** What the engine needs from the node, narrow so tests can fake it. */
export interface ICompositeSpliceEngineDeps {
	channelManager: ChannelManager;
	/** Storage with the compositeSplices group AND a recovery journal. */
	recordsSupported(): boolean;
	loadAllRecords(): ICompositeSpliceRecord[];
	/**
	 * Stage mutations so the next channel persist `fn` causes commits them in
	 * the same transaction; whatever is still staged when `fn` returns is
	 * committed on its own (LightningNode.withStagedMutations).
	 */
	withMutations(mutations: RecoveryMutation[], fn: () => void): void;
	/** LightningNode.getFundingTxHex: fetches and persists when missing. */
	fundingTxHex(channelId: Buffer): Promise<string | null>;
	peerSupportsSplicing(peerPubkey: string): boolean | null;
	peerSupportsCompositeSpliceInputs(peerPubkey: string): boolean | null;
	/** Validates and resolves the destination (throws on a bad script). */
	resolveDestination(script?: Buffer): Buffer;
	currentHeight(): number;
	/** Drop a terminal record past its retention window (best effort). */
	deleteRecord(id: string): void;
	emitStage(event: ICompositeSpliceStageEvent): void;
	emitError(code: NodeErrorCode, message: string, channelId?: Buffer): void;
	log(event: string, fields: Record<string, unknown>): void;
	now(): number;
}

interface IActiveChannel {
	channel: Channel;
	peerPubkey: string;
	fundingTxid: Buffer;
	fundingOutputIndex: number;
	negotiatedTxid: Buffer | null;
	peerSigned: boolean;
	completed: boolean;
	aborted: boolean;
	/** The manager said this channel is closing, errored or reverted. */
	left: boolean;
}

interface IActive {
	record: ICompositeSpliceRecord;
	channels: Map<string, IActiveChannel>;
	timer: NodeJS.Timeout | null;
	/** Set while the start loop runs, so a synchronous abort inside it is seen. */
	starting: boolean;
}

const ceilDiv = (a: bigint, b: bigint): bigint => (a + b - 1n) / b;
/** A persist with no channel transition to ride: the stage commits alone. */
const standalone = (): void => undefined;

export class CompositeSpliceEngine {
	private active: IActive | null = null;
	private readonly records = new Map<string, ICompositeSpliceRecord>();
	private attached = false;

	constructor(private readonly deps: ICompositeSpliceEngineDeps) {}

	// ─── Lifecycle ───

	/** Subscribe to the channel manager. Idempotent. */
	attach(): void {
		if (this.attached) return;
		this.attached = true;
		const cm = this.deps.channelManager;
		cm.on('splice:negotiated', this.onNegotiated);
		cm.on('channel:splice-txsigs-needed', this.onPeerSigned);
		cm.on('splice:aborted', this.onSpliceAborted);
		cm.on('splice:complete', this.onSpliceComplete);
		cm.on('channel:reestablished', this.onReestablished);
		cm.on('peer:disconnected', this.onPeerDisconnected);
		cm.on('broadcast:tx', this.onBroadcast);
		cm.on('error', this.onChannelError);
		cm.on('channel:force-closing', this.onParticipantLeft);
		cm.on('channel:closed', this.onParticipantLeft);
		cm.on('channel:errored', this.onParticipantLeft);
		cm.on('splice:reverted', this.onParticipantLeft);
	}

	detach(): void {
		if (!this.attached) return;
		this.attached = false;
		const cm = this.deps.channelManager;
		cm.removeListener('splice:negotiated', this.onNegotiated);
		cm.removeListener('channel:splice-txsigs-needed', this.onPeerSigned);
		cm.removeListener('splice:aborted', this.onSpliceAborted);
		cm.removeListener('splice:complete', this.onSpliceComplete);
		cm.removeListener('channel:reestablished', this.onReestablished);
		cm.removeListener('peer:disconnected', this.onPeerDisconnected);
		cm.removeListener('broadcast:tx', this.onBroadcast);
		cm.removeListener('error', this.onChannelError);
		cm.removeListener('channel:force-closing', this.onParticipantLeft);
		cm.removeListener('channel:closed', this.onParticipantLeft);
		cm.removeListener('channel:errored', this.onParticipantLeft);
		cm.removeListener('splice:reverted', this.onParticipantLeft);
		if (this.active?.timer) clearTimeout(this.active.timer);
		this.active = null;
	}

	/**
	 * Apply the restore table of section 5 to every stored record, then look
	 * for composites the records do not describe. Called once at boot, after
	 * the channels are restored and before peers connect.
	 *
	 * Rebroadcasting a released composite is not done here: every
	 * participating channel holds the fully signed transaction in its own
	 * in-flight record, and the node's splice rebroadcast path resumes it
	 * through the durability barrier (reauthorizeSpliceBroadcast), as it does
	 * for a single splice. A direct rebroadcast from the record would skip
	 * that barrier.
	 */
	restore(): void {
		if (!this.deps.recordsSupported()) return;
		let records: ICompositeSpliceRecord[];
		try {
			records = this.deps.loadAllRecords();
		} catch (err) {
			this.deps.emitError(
				'COMPOSITE_SPLICE_RESTORE_FAILED',
				`composite splice records could not be read: ${
					(err as Error)?.message ?? String(err)
				}`
			);
			return;
		}
		const described = new Set<string>();
		for (const record of records) {
			if (record.txid) described.add(record.txid);
			if (compositeSpliceStageIsTerminal(record.stage)) {
				if (
					this.deps.now() - record.updatedAt >
					COMPOSITE_SPLICE_RETENTION_MS
				) {
					this.deleteRecord(record.id);
					continue;
				}
				this.records.set(record.id, record);
				// A crash between the terminal write and the last session unwind
				// leaves a channel holding a splice its record says is over
				// (ABORTED rides the first unwind's persist). Finish the unwind.
				if (record.stage === 'ABORTED' && record.txid) {
					this.forgetUnsentSessions(
						record,
						`composite splice ${record.id.slice(0, 12)} is ABORTED`
					);
				}
				continue;
			}
			this.records.set(record.id, record);
			if (!compositeSpliceStageAtLeast(record.stage, 'RELEASED')) {
				// Nothing of ours left: forget every unsent session (owing the
				// peer a tx_abort) and close the record.
				const reason = `composite splice ${record.stage} at restart`;
				this.forgetUnsentSessions(record, reason);
				this.writeRecord({ ...record, stage: 'ABORTED', reason });
				continue;
			}
			// RELEASED or BROADCAST: the transaction may confirm. Keep tracking
			// the channels to LOCKED (or CONFLICTED) and finish any slot that a
			// session still owes (a crash between two fills).
			if (this.active) {
				this.deps.log('composite_splice_restore_second_live_record', {
					id: record.id,
					active: this.active.record.id
				});
				continue;
			}
			this.active = this.activeFromRecord(record);
			if (this.active) {
				this.fillAllSlots(this.active);
				this.maybeSettled(this.active);
			}
		}
		this.adoptUndescribedComposites(described);
	}

	/**
	 * Forget every session of `record` whose tx_signatures never left, owing
	 * the peer a tx_abort; a session past that point is left alone.
	 */
	private forgetUnsentSessions(
		record: ICompositeSpliceRecord,
		reason: string
	): void {
		for (const c of record.channels) {
			const channelId = Buffer.from(c.channelId, 'hex');
			const channel = this.deps.channelManager.getChannel(channelId);
			if (!channel) continue;
			const inflight = channel.getFullState().spliceInFlight;
			if (
				record.txid &&
				inflight &&
				inflight.spliceTxid.toString('hex') !== record.txid
			) {
				continue; // a later, unrelated splice of this channel
			}
			if (inflight?.sentTxSignatures) continue;
			if (!inflight && !channel.getSpliceSession()) continue;
			const result = this.deps.channelManager.forgetUnsentSplice(
				channelId,
				reason
			);
			if (!result.ok) {
				this.deps.log('composite_splice_restore_forget_refused', {
					id: record.id,
					channelId: c.channelId,
					error: result.error
				});
			}
		}
	}

	/**
	 * The missing-record rule of section 5. Two or more channels whose
	 * in-flight splices name the SAME transaction can only be a composite (a
	 * single splice is one channel's own), so when no record describes that
	 * txid (a journal rebuilt from a snapshot older than the record), one is
	 * synthesized from the channel rows: RELEASED when any session sent its
	 * tx_signatures (the transaction may confirm; fill the slots still owed
	 * and track to LOCKED), ABORTED otherwise (nothing of ours left; forget
	 * every session). The debit and fee split is not recoverable from the
	 * rows, so the record carries each channel's whole relative change as the
	 * debit and says so in its reason.
	 */
	private adoptUndescribedComposites(described: Set<string>): void {
		const cm = this.deps.channelManager;
		const groups = new Map<string, Channel[]>();
		for (const channel of cm.listChannels()) {
			const inflight = channel.getFullState().spliceInFlight;
			if (!inflight) continue;
			const txid = inflight.spliceTxid.toString('hex');
			if (described.has(txid)) continue;
			const group = groups.get(txid) ?? [];
			group.push(channel);
			groups.set(txid, group);
		}
		for (const [txid, group] of groups) {
			if (group.length < 2) continue;
			const now = this.deps.now();
			const released = group.some(
				(ch) => ch.getFullState().spliceInFlight!.sentTxSignatures
			);
			const anyFlight = group[0].getFullState().spliceInFlight!;
			const signedHex =
				group
					.map((ch) => ch.getFullState().spliceInFlight!)
					.find((f) => f.fullySigned)?.spliceTxHex ?? anyFlight.spliceTxHex;
			let tx: bitcoin.Transaction | null = null;
			try {
				tx = bitcoin.Transaction.fromHex(signedHex);
			} catch {
				tx = null;
			}
			const fundingScripts = new Set(
				group.map((ch) => {
					const st = ch.getFullState();
					return st.remoteBasepoints
						? createFundingScript(
								st.localBasepoints.fundingPubkey,
								st.remoteBasepoints.fundingPubkey
						  ).p2wshOutput.toString('hex')
						: '';
				})
			);
			const destination = tx?.outs.find(
				(o) => !fundingScripts.has(Buffer.from(o.script).toString('hex'))
			);
			const channels: ICompositeSpliceChannel[] = group.map((ch) => {
				const st = ch.getFullState();
				const f = st.spliceInFlight!;
				const relative = -f.localRelativeSatoshis;
				return {
					channelId: ch.getChannelId()!.toString('hex'),
					peerPubkey:
						cm.getPeerForChannel(ch.getChannelId()!) ?? '00'.repeat(33),
					fundingTxid: st.fundingTxid!.toString('hex'),
					fundingOutputIndex: st.fundingOutputIndex,
					debitSats: (relative > 0n ? relative : 0n).toString(),
					feeSats: '0',
					oldCapacitySats: st.fundingSatoshis.toString(),
					newCapacitySats: f.newFundingSatoshis.toString(),
					inputSerialId: '0',
					fundingOutputSerialId: '0'
				};
			});
			const amount = destination ? BigInt(destination.value) : 0n;
			const inSum = group.reduce(
				(acc, ch) => acc + ch.getFullState().fundingSatoshis,
				0n
			);
			const outSum =
				tx?.outs.reduce((acc, o) => acc + BigInt(o.value), 0n) ?? inSum;
			const record: ICompositeSpliceRecord = {
				id: randomBytes(32).toString('hex'),
				stage: released ? 'RELEASED' : 'ABORTED',
				channels,
				destinationScript: destination
					? Buffer.from(destination.script).toString('hex')
					: '00',
				destinationSerialId: '0',
				amountSats: amount.toString(),
				feeSats: (inSum > outSum ? inSum - outSum : 0n).toString(),
				feeratePerkw: 253,
				locktime: tx?.locktime ?? 0,
				txid,
				txHex: signedHex,
				reason: released
					? 'synthesized from channel records at restart: no composite record described this transaction; the debit and fee split is not known'
					: 'synthesized from channel records at restart: nothing of ours had left, every session forgotten',
				createdAt: now,
				updatedAt: now
			};
			this.deps.log('composite_splice_restore_synthesized', {
				id: record.id,
				txid,
				stage: record.stage,
				channels: channels.length
			});
			if (!released) {
				this.forgetUnsentSessions(record, record.reason!);
				this.writeRecord(record);
				continue;
			}
			this.writeRecord(record);
			if (this.active) {
				this.deps.log('composite_splice_restore_second_live_record', {
					id: record.id,
					active: this.active.record.id
				});
				continue;
			}
			this.active = this.activeFromRecord(record);
			if (this.active) {
				this.fillAllSlots(this.active);
				this.maybeSettled(this.active);
			}
		}
	}

	/** Drop every terminal record past the retention window. */
	private prune(): void {
		const now = this.deps.now();
		for (const record of [...this.records.values()]) {
			if (!compositeSpliceStageIsTerminal(record.stage)) continue;
			if (now - record.updatedAt <= COMPOSITE_SPLICE_RETENTION_MS) continue;
			this.deleteRecord(record.id);
		}
	}

	private deleteRecord(id: string): void {
		this.records.delete(id);
		try {
			this.deps.deleteRecord(id);
		} catch (err) {
			this.deps.log('composite_splice_prune_failed', {
				id,
				error: (err as Error)?.message ?? String(err)
			});
		}
	}

	// ─── Queries ───

	get(id: Buffer): ICompositeSpliceRecord | null {
		return this.records.get(id.toString('hex')) ?? null;
	}

	list(): ICompositeSpliceRecord[] {
		return [...this.records.values()].sort((a, b) => a.createdAt - b.createdAt);
	}

	/** Whether a live composite holds this channel (section 6). */
	isChannelReserved(channelId: Buffer): boolean {
		return this.active?.channels.has(channelId.toString('hex')) ?? false;
	}

	/**
	 * A peer disconnected (section 4, failure table): before RELEASED a
	 * negotiation does not survive the connection, so the composite ends now
	 * rather than at the end of its budget. After RELEASED the transaction
	 * stands and the channel resumes at reestablish.
	 */
	private readonly onPeerDisconnected = (peerPubkey: string): void => {
		const active = this.active;
		if (!active) return;
		if (compositeSpliceStageAtLeast(active.record.stage, 'RELEASED')) return;
		for (const [hex, entry] of active.channels) {
			if (entry.peerPubkey !== peerPubkey) continue;
			this.abortAll(
				active,
				`peer of session ${hex.slice(0, 12)} disconnected before release`
			);
			return;
		}
	};

	// ─── Planning ───

	async plan(
		request: ICompositeSpliceOutRequest
	): Promise<ICompositeSplicePlanResult> {
		const invalid = this.validateRequest(request);
		if (invalid) return invalid;
		let destination: Buffer;
		try {
			destination = this.deps.resolveDestination(request.destinationScript);
		} catch (err) {
			return {
				ok: false,
				error: (err as Error)?.message ?? String(err),
				code: CompositeSpliceRefusalCode.INVALID_PARAMS
			};
		}
		if (!this.deps.recordsSupported()) {
			return {
				ok: false,
				error:
					'composite splices need a storage backend with the compositeSplices group and a recovery journal',
				code: CompositeSpliceRefusalCode.STORAGE_REQUIRED
			};
		}
		if (this.active) {
			return {
				ok: false,
				error: `a composite splice is already live (${this.active.record.id}); one at a time`,
				code: CompositeSpliceRefusalCode.BUSY
			};
		}

		// Candidates.
		const cm = this.deps.channelManager;
		let candidates: Channel[];
		if (request.channelIds) {
			candidates = [];
			for (const id of request.channelIds) {
				const channel = cm.getChannel(id);
				if (!channel) {
					return {
						ok: false,
						error: `Channel not found: ${id.toString('hex')}`,
						code: CompositeSpliceRefusalCode.CHANNEL_NOT_FOUND
					};
				}
				candidates.push(channel);
			}
		} else {
			candidates = cm.listChannels();
		}

		const skipped: ICompositeSpliceChannelRefusal[] = [];
		const eligible: Array<{
			channel: Channel;
			peerPubkey: string;
			spendable: bigint;
		}> = [];
		for (const channel of candidates) {
			const channelId = channel.getChannelId();
			if (!channelId) continue;
			const reason = await this.ineligible(channel, request.amountSats);
			if (reason) {
				skipped.push({ channelId, reason });
				continue;
			}
			eligible.push({
				channel,
				peerPubkey: cm.getPeerForChannel(channelId)!,
				spendable: this.spendableAtZero(channel)
			});
		}
		if (eligible.length === 0) {
			return {
				ok: false,
				error: 'no channel qualifies for a composite splice',
				code: CompositeSpliceRefusalCode.NO_ELIGIBLE_CHANNELS,
				skipped
			};
		}
		if (request.channelIds && skipped.length > 0) {
			return {
				ok: false,
				error: `a named channel does not qualify: ${skipped[0].reason}`,
				code: CompositeSpliceRefusalCode.NO_ELIGIBLE_CHANNELS,
				skipped
			};
		}
		// Largest spendable balance first (decision 1).
		eligible.sort((a, b) =>
			a.spendable === b.spendable
				? Buffer.compare(a.channel.getChannelId()!, b.channel.getChannelId()!)
				: a.spendable > b.spendable
				? -1
				: 1
		);

		const amount = request.amountSats;
		const feerate = request.fundingFeeratePerkw;
		for (let n = 1; n <= eligible.length; n++) {
			const weight = estimateSpliceTxWeight({
				walletInputCount: 0,
				fundingInputCount: n - 1,
				fundingOutputCount: n - 1,
				destinationScriptLen: destination.length
			});
			const totalFee = spliceFeeSats(weight, feerate);
			if (totalFee >= amount) {
				return {
					ok: false,
					error: `fee (${totalFee} sats at ${feerate} sat/kw over ${n} channels) meets or exceeds the amount (${amount} sats)`,
					code: CompositeSpliceRefusalCode.INVALID_PARAMS,
					skipped
				};
			}
			const feeShare = (d: bigint): bigint =>
				d === 0n ? 0n : ceilDiv(totalFee * d, amount);
			let remaining = amount;
			const chosen: Array<{
				channel: Channel;
				plan: ICompositeSplicePlanChannel;
			}> = [];
			for (const e of eligible.slice(0, n)) {
				const max = this.maxDebit(e.channel, feeShare);
				const debit = remaining < max ? remaining : max;
				if (debit <= 0n) continue;
				const fee = feeShare(debit);
				const old = e.channel.getFundingSatoshis();
				chosen.push({
					channel: e.channel,
					plan: {
						channelId: e.channel.getChannelId()!,
						peerPubkey: e.peerPubkey,
						debitSats: debit,
						feeSats: fee,
						oldCapacitySats: old,
						newCapacitySats: old - debit - fee,
						maxDebitSats: max
					}
				});
				remaining -= debit;
				if (remaining === 0n) break;
			}
			if (remaining > 0n) continue;
			if (chosen.length === 1) {
				// Not a composite: the single-channel path (spliceOut) does this
				// with one session and no record. Refused rather than run as a
				// one-session composite, whose release path waits for external
				// slots that do not exist.
				return {
					ok: false,
					error: `channel ${chosen[0].plan.channelId.toString(
						'hex'
					)} covers the amount alone; use a single-channel splice-out`,
					code: CompositeSpliceRefusalCode.SINGLE_CHANNEL_SUFFICES,
					skipped
				};
			}
			// Input order: by funding outpoint, the order the serial ids follow.
			chosen.sort((a, b) => {
				const sa = a.channel.getFullState();
				const sb = b.channel.getFullState();
				const c = Buffer.compare(sa.fundingTxid!, sb.fundingTxid!);
				return c !== 0 ? c : sa.fundingOutputIndex - sb.fundingOutputIndex;
			});
			const feeSats = chosen.reduce((s, c) => s + c.plan.feeSats, 0n);
			const height = this.deps.currentHeight();
			return {
				ok: true,
				plan: {
					destinationScript: destination,
					amountSats: amount,
					feeSats,
					feeratePerkw: feerate,
					locktime: Number.isSafeInteger(height) && height > 0 ? height : 0,
					weight: estimateSpliceTxWeight({
						walletInputCount: 0,
						fundingInputCount: chosen.length - 1,
						fundingOutputCount: chosen.length - 1,
						destinationScriptLen: destination.length
					}),
					channels: chosen.map((c) => c.plan),
					skipped
				}
			};
		}
		return {
			ok: false,
			error: `the eligible channels cannot cover ${amount} sats plus fees at ${feerate} sat/kw`,
			code: CompositeSpliceRefusalCode.INSUFFICIENT_BALANCE,
			skipped
		};
	}

	private validateRequest(
		request: ICompositeSpliceOutRequest
	): ICompositeSpliceRefusal | null {
		const bad = (error: string): ICompositeSpliceRefusal => ({
			ok: false,
			error,
			code: CompositeSpliceRefusalCode.INVALID_PARAMS
		});
		if (typeof request.amountSats !== 'bigint' || request.amountSats <= 0n) {
			return bad('amountSats must be a positive bigint');
		}
		if (request.amountSats < MIN_DESTINATION_SATS) {
			return bad(
				`amountSats ${request.amountSats} is below the dust floor (${MIN_DESTINATION_SATS} sats)`
			);
		}
		if (
			!Number.isInteger(request.fundingFeeratePerkw) ||
			request.fundingFeeratePerkw < 253 ||
			request.fundingFeeratePerkw > MAX_SPLICE_FEERATE_PERKW
		) {
			return bad(
				`fundingFeeratePerkw must be an integer between 253 and ${MAX_SPLICE_FEERATE_PERKW}`
			);
		}
		if (request.channelIds !== undefined) {
			if (
				!Array.isArray(request.channelIds) ||
				request.channelIds.length === 0
			) {
				return bad('channelIds must be a non-empty array when given');
			}
			const seen = new Set<string>();
			for (const id of request.channelIds) {
				if (!Buffer.isBuffer(id) || id.length !== 32) {
					return bad('every channelId must be a 32-byte Buffer');
				}
				const hex = id.toString('hex');
				if (seen.has(hex)) return bad(`channelId ${hex} repeated`);
				seen.add(hex);
			}
		}
		if (
			request.budgetMs !== undefined &&
			(!Number.isInteger(request.budgetMs) || request.budgetMs <= 0)
		) {
			return bad('budgetMs must be a positive integer when given');
		}
		return null;
	}

	/** Why a channel cannot take part (section 1), or null when it can. */
	private async ineligible(
		channel: Channel,
		amountSats: bigint
	): Promise<string | null> {
		const channelId = channel.getChannelId()!;
		const state = channel.getFullState();
		if (this.isChannelReserved(channelId)) {
			return 'reserved by a live composite splice';
		}
		if (state.state !== ChannelState.NORMAL) {
			return `channel is ${state.state}, not NORMAL`;
		}
		const busy = channel.spliceBusyReason();
		if (busy) return busy;
		if (state.spliceInFlight || channel.isSplicePendingLock()) {
			return 'a splice is pending its lock';
		}
		if (!state.fundingTxid) return 'channel has no funding outpoint';
		if (state.zeroConfEnabled && !state.shortChannelId) {
			return 'funding is not confirmed (zero-conf channel)';
		}
		const peerPubkey = this.deps.channelManager.getPeerForChannel(channelId);
		if (!peerPubkey) return 'peer unknown';
		const splicing = this.deps.peerSupportsSplicing(peerPubkey);
		if (splicing === null) return 'peer is not connected';
		if (!splicing) {
			return 'splicing is not negotiated with this peer (option_splice/option_quiesce required on both sides)';
		}
		const composite = this.deps.peerSupportsCompositeSpliceInputs(peerPubkey);
		if (!composite) {
			return 'peer does not admit composite splice inputs (option_composite_splice_inputs not advertised)';
		}
		if (amountSats < channel.spliceInteractiveTxDustFloor()) {
			return `amount is below this channel's negotiated dust floor (${channel.spliceInteractiveTxDustFloor()} sats)`;
		}
		const hex = await this.deps.fundingTxHex(channelId);
		if (!hex) return 'funding transaction bytes are not available';
		return null;
	}

	/** Spendable balance before any debit: the ranking key. */
	private spendableAtZero(channel: Channel): bigint {
		const state = channel.getFullState();
		const local = channel.getBalances().localMsat / 1000n;
		const stored = state.remoteConfig?.channelReserveSatoshis ?? 0n;
		const derived = channel.spliceReserveWeKeepSats(state.fundingSatoshis);
		const reserve = derived > stored ? derived : stored;
		const kept = reserve + channel.spliceOutCommitmentCostSats();
		return local > kept ? local - kept : 0n;
	}

	/**
	 * The largest debit this channel admits with the given fee share: the
	 * single-channel splice-out predicate (reserve priced at the post-splice
	 * capacity, commitment cost, commitment refusal) over a binary search,
	 * as LightningNode.spliceQuote solves it.
	 */
	private maxDebit(channel: Channel, feeFor: (d: bigint) => bigint): bigint {
		const state = channel.getFullState();
		const old = state.fundingSatoshis;
		const local = channel.getBalances().localMsat / 1000n;
		const stored = state.remoteConfig?.channelReserveSatoshis ?? 0n;
		const commitmentCost = channel.spliceOutCommitmentCostSats();
		const dustFloor = channel.spliceInteractiveTxDustFloor();
		const admits = (d: bigint): boolean => {
			const fee = feeFor(d);
			const postCapacity = old - d - fee;
			if (postCapacity < dustFloor) return false;
			const derived = channel.spliceReserveWeKeepSats(postCapacity);
			const reserve = derived > stored ? derived : stored;
			const spendable = local - reserve - commitmentCost;
			if (d + fee > spendable) return false;
			return channel.spliceOutCommitmentRefusal(d + fee) === null;
		};
		let lo = 0n;
		let hi = local;
		while (lo < hi) {
			const mid = (lo + hi + 1n) / 2n;
			if (admits(mid)) lo = mid;
			else hi = mid - 1n;
		}
		return lo;
	}

	// ─── Start ───

	async start(
		request: ICompositeSpliceOutRequest
	): Promise<ICompositeSpliceStartResult> {
		const planned = await this.plan(request);
		if (!planned.ok) return planned;
		if (this.active) {
			return {
				ok: false,
				error: 'a composite splice started while this one was planned',
				code: CompositeSpliceRefusalCode.BUSY
			};
		}
		const plan = planned.plan;
		const cm = this.deps.channelManager;
		const id = randomBytes(32);
		const idHex = id.toString('hex');
		const now = this.deps.now();

		// Serial ids, allocated once: inputs 0, 2, ..., then the funding
		// outputs, then the destination, all even (initiator).
		const n = plan.channels.length;
		const inputs: ICompositeSpliceContribution['inputs'] = [];
		const outputs: ICompositeSpliceContribution['outputs'] = [];
		const recordChannels: ICompositeSpliceChannel[] = [];
		const channels = new Map<string, IActiveChannel>();
		for (let k = 0; k < n; k++) {
			const c = plan.channels[k];
			const channel = cm.getChannel(c.channelId);
			if (!channel) {
				return {
					ok: false,
					error: `Channel not found: ${c.channelId.toString('hex')}`,
					code: CompositeSpliceRefusalCode.CHANNEL_NOT_FOUND
				};
			}
			const state = channel.getFullState();
			if (
				!state.fundingTxid ||
				!state.fundingTxHex ||
				!state.remoteBasepoints
			) {
				return {
					ok: false,
					error: `channel ${c.channelId.toString(
						'hex'
					)} lost its funding transaction`,
					code: CompositeSpliceRefusalCode.NO_ELIGIBLE_CHANNELS
				};
			}
			const fundingScript = createFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints.fundingPubkey
			).p2wshOutput;
			inputs.push({
				serialId: BigInt(2 * k),
				prevTxid: Buffer.from(state.fundingTxid),
				prevOutputIndex: state.fundingOutputIndex,
				prevTx: Buffer.from(state.fundingTxHex, 'hex'),
				valueSats: state.fundingSatoshis,
				shared: false
			});
			outputs.push({
				serialId: BigInt(2 * (n + k)),
				scriptPubkey: fundingScript,
				amountSats: c.newCapacitySats
			});
			recordChannels.push({
				channelId: c.channelId.toString('hex'),
				peerPubkey: c.peerPubkey,
				fundingTxid: Buffer.from(state.fundingTxid).toString('hex'),
				fundingOutputIndex: state.fundingOutputIndex,
				debitSats: c.debitSats.toString(),
				feeSats: c.feeSats.toString(),
				oldCapacitySats: c.oldCapacitySats.toString(),
				newCapacitySats: c.newCapacitySats.toString(),
				inputSerialId: (2 * k).toString(),
				fundingOutputSerialId: (2 * (n + k)).toString()
			});
			channels.set(c.channelId.toString('hex'), {
				channel,
				peerPubkey: c.peerPubkey,
				fundingTxid: Buffer.from(state.fundingTxid),
				fundingOutputIndex: state.fundingOutputIndex,
				negotiatedTxid: null,
				peerSigned: false,
				completed: false,
				aborted: false,
				left: false
			});
		}
		outputs.push({
			serialId: BigInt(2 * (2 * n)),
			scriptPubkey: plan.destinationScript,
			amountSats: plan.amountSats
		});

		const record: ICompositeSpliceRecord = {
			id: idHex,
			stage: 'PLANNED',
			channels: recordChannels,
			destinationScript: plan.destinationScript.toString('hex'),
			destinationSerialId: (2 * (2 * n)).toString(),
			amountSats: plan.amountSats.toString(),
			feeSats: plan.feeSats.toString(),
			feeratePerkw: plan.feeratePerkw,
			locktime: plan.locktime,
			createdAt: now,
			updatedAt: now
		};
		// PLANNED is durable before the first splice_init (section 5).
		this.prune();
		this.writeRecord(record);
		this.deps.log('composite_splice_stage', { id: idHex, stage: 'PLANNED' });
		this.deps.emitStage({ id, stage: 'PLANNED' });
		const active: IActive = {
			record,
			channels,
			timer: null,
			starting: true
		};
		this.active = active;
		const budget = request.budgetMs ?? DEFAULT_COMPOSITE_SPLICE_BUDGET_MS;
		active.timer = setTimeout(() => {
			if (this.active !== active) return;
			if (compositeSpliceStageAtLeast(active.record.stage, 'RELEASED')) return;
			this.abortAll(active, `composite splice budget of ${budget} ms exceeded`);
		}, budget);
		active.timer.unref?.();

		// NEGOTIATING rides the first channel persist the splice starts cause.
		this.deps.withMutations(
			[
				{
					type: 'composite_splice',
					record: this.setStage(active, 'NEGOTIATING')
				}
			],
			() => {
				for (let k = 0; k < n; k++) {
					if (this.active !== active || active.record.stage === 'ABORTED') {
						break;
					}
					const c = plan.channels[k];
					const entry = channels.get(c.channelId.toString('hex'))!;
					const contribution: ICompositeSpliceContribution = {
						compositeId: id,
						inputs: inputs.map((input, j) => ({ ...input, shared: j === k })),
						outputs
					};
					const refused =
						entry.channel.setCompositeSpliceContribution(contribution);
					if (refused) {
						this.abortAll(
							active,
							`channel refused its composite contribution: ${refused}`
						);
						break;
					}
					const started = cm.initiateSplice(
						c.channelId,
						-(c.debitSats + c.feeSats),
						plan.feeratePerkw,
						plan.locktime
					);
					if (!started.ok) {
						this.abortAll(
							active,
							`splice could not start on ${c.channelId.toString('hex')}: ${
								started.error ?? 'unknown'
							}`
						);
						break;
					}
				}
			}
		);
		active.starting = false;
		if (this.active === active) {
			// Events that fired synchronously inside the loop may have completed
			// a step whose follow-up waited for the loop to end.
			this.maybeReleaseCommitments(active);
			this.maybeRelease(active);
		}
		return { ok: true, id, plan };
	}

	// ─── Abort ───

	/** Operator abort, allowed until RELEASED (section 4). */
	abort(
		id: Buffer,
		reason = 'aborted by the operator'
	): {
		ok: boolean;
		error?: string;
		code?: CompositeSpliceRefusalCode;
	} {
		const idHex = id.toString('hex');
		const active = this.active;
		if (!active || active.record.id !== idHex) {
			const record = this.records.get(idHex);
			if (!record) {
				return {
					ok: false,
					error: 'composite splice not found',
					code: CompositeSpliceRefusalCode.NOT_FOUND
				};
			}
			return {
				ok: false,
				error: `composite splice is ${record.stage} and cannot be aborted`,
				code: CompositeSpliceRefusalCode.TOO_LATE
			};
		}
		if (compositeSpliceStageAtLeast(active.record.stage, 'RELEASED')) {
			return {
				ok: false,
				error: `composite splice is ${active.record.stage}: our signatures have left and the transaction may confirm`,
				code: CompositeSpliceRefusalCode.TOO_LATE
			};
		}
		this.abortAll(active, reason);
		return { ok: true };
	}

	private abortAll(active: IActive, reason: string): void {
		if (this.active !== active) return;
		if (active.record.stage === 'ABORTED') return;
		if (compositeSpliceStageAtLeast(active.record.stage, 'RELEASED')) return;
		if (active.timer) clearTimeout(active.timer);
		active.timer = null;
		this.deps.log('composite_splice_abort', { id: active.record.id, reason });
		// Mark first: the tx_aborts below echo back as splice:aborted events.
		const record = this.setStage(active, 'ABORTED', { reason });
		this.active = null;
		this.deps.withMutations([{ type: 'composite_splice', record }], () => {
			for (const [hex, entry] of active.channels) {
				if (entry.aborted) continue;
				entry.aborted = true;
				const result = this.deps.channelManager.abortSplice(
					Buffer.from(hex, 'hex'),
					reason
				);
				if (!result.ok) {
					this.deps.log('composite_splice_session_abort_refused', {
						id: active.record.id,
						channelId: hex,
						error: result.error
					});
				}
			}
		});
		this.deps.emitError('COMPOSITE_SPLICE_ABORTED', reason);
		this.prune();
	}

	// ─── Manager events ───

	private readonly onNegotiated = (
		channelId: Buffer,
		compositeId: Buffer,
		spliceTxid: Buffer
	): void => {
		const active = this.active;
		if (!active || active.record.id !== compositeId.toString('hex')) return;
		const entry = active.channels.get(channelId.toString('hex'));
		if (!entry) return;
		entry.negotiatedTxid = Buffer.from(spliceTxid);
		if (!active.starting) this.maybeReleaseCommitments(active);
	};

	/** Every session negotiated: same txid releases all, else abort all. */
	private maybeReleaseCommitments(active: IActive): void {
		if (this.active !== active) return;
		if (active.record.stage !== 'NEGOTIATING') return;
		const entries = [...active.channels.values()];
		if (entries.some((e) => !e.negotiatedTxid)) return;
		const id = Buffer.from(active.record.id, 'hex');
		const dropped = entries.find(
			(e) => !e.channel.getCompositeSpliceId()?.equals(id)
		);
		if (dropped) {
			// A disconnect forgot the pre-commitment splice on that channel
			// (markForReestablish) without a word to anyone: the session is gone.
			this.abortAll(
				active,
				`session ${dropped.channel
					.getChannelId()!
					.toString('hex')
					.slice(0, 12)} was dropped before commitment`
			);
			return;
		}
		const txid = entries[0].negotiatedTxid!;
		if (entries.some((e) => !e.negotiatedTxid!.equals(txid))) {
			this.abortAll(active, 'sessions negotiated different transactions');
			return;
		}
		const tx = entries[0].channel.getSpliceTransaction();
		if (!tx || !Buffer.from(tx.getHash()).equals(txid)) {
			this.abortAll(active, 'negotiated splice transaction cannot be resolved');
			return;
		}
		const record = this.setStage(active, 'COMMITTED', {
			txid: txid.toString('hex'),
			txHex: tx.toHex()
		});
		this.deps.withMutations([{ type: 'composite_splice', record }], () => {
			for (const [hex] of active.channels) {
				if (this.active !== active) break;
				const result =
					this.deps.channelManager.releaseCompositeSpliceCommitment(
						Buffer.from(hex, 'hex')
					);
				if (!result.ok) {
					this.abortAll(
						active,
						`commitment could not be sent on ${hex}: ${
							result.error ?? 'unknown'
						}`
					);
					break;
				}
			}
		});
	}

	private readonly onPeerSigned = (channelId: Buffer): void => {
		const active = this.active;
		if (!active) return;
		const entry = active.channels.get(channelId.toString('hex'));
		if (!entry) return;
		// The reminder means our tx_signatures is withheld on the external
		// slots and the peer's has arrived (we sign second in every session).
		const inflight = entry.channel.getFullState().spliceInFlight;
		if (!inflight?.receivedTxSignatures || !inflight.remoteSharedInputSig) {
			return;
		}
		entry.peerSigned = true;
		if (!active.starting) this.maybeRelease(active);
	};

	/** Every peer signed: persist PEERS_SIGNED then RELEASED, fill every slot. */
	private maybeRelease(active: IActive): void {
		if (this.active !== active) return;
		if (active.record.stage !== 'COMMITTED') return;
		const entries = [...active.channels.values()];
		if (entries.some((e) => !e.peerSigned)) return;
		if (active.timer) clearTimeout(active.timer);
		active.timer = null;
		this.setStage(active, 'PEERS_SIGNED');
		const record = this.setStage(active, 'RELEASED');
		// RELEASED rides the PERSIST_STATE of the first fill below, which
		// precedes the first tx_signatures the fill releases (section 4).
		this.deps.withMutations([{ type: 'composite_splice', record }], () => {
			this.fillAllSlots(active);
		});
	}

	/**
	 * Assemble witness j (channel j's own shared-input signature and its
	 * peer's, in the script's key order) and deliver it to every other
	 * session. Idempotent: a slot already filled is skipped by the channel.
	 */
	private fillAllSlots(active: IActive): void {
		const cm = this.deps.channelManager;
		const witnesses = new Map<string, Buffer[]>();
		for (const [hex, entry] of active.channels) {
			const state = entry.channel.getFullState();
			const inflight = state.spliceInFlight;
			if (!inflight?.remoteSharedInputSig || !state.remoteBasepoints) continue;
			const script = createFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints.fundingPubkey
			).witnessScript;
			witnesses.set(
				hex,
				ChannelSigner.buildFundingWitness(
					inflight.ourSharedInputSig,
					inflight.remoteSharedInputSig,
					state.localBasepoints.fundingPubkey,
					state.remoteBasepoints.fundingPubkey,
					script
				)
			);
		}
		for (const [hex, entry] of active.channels) {
			const inflight = entry.channel.getFullState().spliceInFlight;
			if (!inflight || inflight.sentTxSignatures) continue;
			for (const [otherHex, other] of active.channels) {
				if (otherHex === hex) continue;
				const witness = witnesses.get(otherHex);
				if (!witness) continue;
				const result = cm.provideSpliceExternalWitness(
					Buffer.from(hex, 'hex'),
					other.fundingTxid,
					other.fundingOutputIndex,
					witness
				);
				if (!result.ok) {
					this.deps.log('composite_splice_witness_refused', {
						id: active.record.id,
						channelId: hex,
						input: otherHex,
						error: result.error
					});
				}
			}
		}
	}

	private readonly onSpliceAborted = (
		channelId: Buffer,
		reason: string
	): void => {
		const active = this.active;
		if (!active) return;
		const entry = active.channels.get(channelId.toString('hex'));
		if (!entry) return;
		entry.aborted = true;
		if (compositeSpliceStageAtLeast(active.record.stage, 'RELEASED')) {
			// The transaction stands; the channel resumes at reestablish.
			this.deps.log('composite_splice_session_aborted_after_release', {
				id: active.record.id,
				channelId: channelId.toString('hex'),
				reason
			});
			return;
		}
		this.abortAll(
			active,
			`session ${channelId.toString('hex').slice(0, 12)} aborted: ${reason}`
		);
	};

	private readonly onChannelError = (
		channelId: Buffer | null,
		message: string
	): void => {
		const active = this.active;
		if (!active || !channelId) return;
		if (!active.channels.has(channelId.toString('hex'))) return;
		if (compositeSpliceStageAtLeast(active.record.stage, 'RELEASED')) return;
		// A parked splice that lost the stfu tie, a failed build, a peer error:
		// before RELEASED every one of them ends the composite.
		this.abortAll(
			active,
			`session ${channelId.toString('hex').slice(0, 12)} failed: ${message}`
		);
	};

	private readonly onBroadcast = (tx: Buffer): void => {
		const active = this.active;
		if (!active || active.record.stage !== 'RELEASED' || !active.record.txid) {
			return;
		}
		let hash: Buffer;
		try {
			hash = Buffer.from(bitcoin.Transaction.fromBuffer(tx).getHash());
		} catch {
			return;
		}
		if (hash.toString('hex') !== active.record.txid) return;
		// The broadcast bytes are the fully signed transaction; the COMMITTED
		// hex had no witnesses. A restart rebroadcasts from here.
		const record = this.setStage(active, 'BROADCAST', {
			txHex: tx.toString('hex')
		});
		this.deps.withMutations([{ type: 'composite_splice', record }], standalone);
	};

	private readonly onSpliceComplete = (channelId: Buffer): void => {
		const active = this.active;
		if (!active) return;
		const entry = active.channels.get(channelId.toString('hex'));
		if (!entry) return;
		entry.completed = true;
		this.maybeSettled(active);
	};

	/**
	 * A channel that adopted the composite before a restart never emits
	 * splice:complete again; its reestablish is the moment its state can be
	 * read as NORMAL on the composite funding.
	 */
	private readonly onReestablished = (channelId: Buffer): void => {
		const active = this.active;
		if (!active || !active.channels.has(channelId.toString('hex'))) return;
		this.maybeSettled(active);
	};

	/**
	 * A participating channel is closing, closed, errored or reverted its
	 * splice. Before RELEASED that ends the composite like any session
	 * failure. After RELEASED the transaction can no longer confirm whole (an
	 * input is spent elsewhere, or the channel that would adopt it is gone):
	 * the record ends CONFLICTED and the reservation lifts; the surviving
	 * channels' own splice records follow the single-channel rules.
	 */
	private readonly onParticipantLeft = (channelId: Buffer): void => {
		const active = this.active;
		if (!active) return;
		const hex = channelId.toString('hex');
		const entry = active.channels.get(hex);
		if (!entry) return;
		if (!compositeSpliceStageAtLeast(active.record.stage, 'RELEASED')) {
			this.abortAll(active, `session ${hex.slice(0, 12)} left before release`);
			return;
		}
		// Remembered, so the verdict does not depend on the state the channel
		// shows at the moment the event fires.
		entry.left = true;
		this.maybeSettled(active);
	};

	/**
	 * Decide whether a released composite is finished: LOCKED once every
	 * channel runs on it, CONFLICTED once any channel has left without it.
	 */
	private maybeSettled(active: IActive): void {
		if (this.active !== active) return;
		if (!compositeSpliceStageAtLeast(active.record.stage, 'RELEASED')) return;
		const txid = active.record.txid;
		let pending = false;
		// Every channel is looked at: one that left ends the composite even
		// when another is still waiting for its lock (the map order follows
		// the funding outpoints, so stopping at the first pending channel
		// would make the verdict depend on which channel sorts first).
		for (const [hex, entry] of active.channels) {
			if (entry.completed) continue;
			const state = entry.channel.getFullState();
			// Restored channels park their live state in preReestablishState
			// until the peer is back; read that one.
			const live =
				state.state === ChannelState.AWAITING_REESTABLISH
					? state.preReestablishState ?? state.state
					: state.state;
			const onComposite = !!txid && state.fundingTxid?.toString('hex') === txid;
			if (
				live === ChannelState.NORMAL &&
				!state.spliceInFlight &&
				onComposite
			) {
				// Adopted (a completion event is history after a restart).
				entry.completed = true;
				continue;
			}
			const gone =
				entry.left ||
				live === ChannelState.SHUTTING_DOWN ||
				live === ChannelState.NEGOTIATING_CLOSING ||
				live === ChannelState.CLOSED ||
				live === ChannelState.FORCE_CLOSED ||
				live === ChannelState.ERRORED ||
				// Back to NORMAL on a funding that is not the composite's: the
				// channel reverted or replaced the splice.
				(live === ChannelState.NORMAL && !state.spliceInFlight && !onComposite);
			if (gone) {
				const reason = `channel ${hex.slice(
					0,
					12
				)} left (${live}) without adopting the transaction`;
				const record = this.setStage(active, 'CONFLICTED', { reason });
				if (active.timer) clearTimeout(active.timer);
				this.active = null;
				this.deps.withMutations(
					[{ type: 'composite_splice', record }],
					standalone
				);
				this.prune();
				return;
			}
			pending = true;
		}
		if (pending) return;
		const record = this.setStage(active, 'LOCKED');
		this.active = null;
		this.deps.withMutations([{ type: 'composite_splice', record }], standalone);
		this.prune();
	}

	// ─── Record bookkeeping ───

	private setStage(
		active: IActive,
		stage: CompositeSpliceStage,
		extra: Partial<
			Pick<ICompositeSpliceRecord, 'txid' | 'txHex' | 'reason'>
		> = {}
	): ICompositeSpliceRecord {
		const record: ICompositeSpliceRecord = {
			...active.record,
			...extra,
			stage,
			updatedAt: this.deps.now()
		};
		active.record = record;
		this.records.set(record.id, record);
		this.deps.log('composite_splice_stage', {
			id: record.id,
			stage,
			...(record.txid ? { txid: record.txid } : {}),
			...(extra.reason ? { reason: extra.reason } : {})
		});
		this.deps.emitStage({
			id: Buffer.from(record.id, 'hex'),
			stage,
			...(record.txid ? { txid: Buffer.from(record.txid, 'hex') } : {}),
			...(extra.reason ? { reason: extra.reason } : {})
		});
		return record;
	}

	/** Persist a record on its own (no channel transition to ride). */
	private writeRecord(record: ICompositeSpliceRecord): void {
		this.records.set(record.id, record);
		this.deps.withMutations([{ type: 'composite_splice', record }], standalone);
	}

	private activeFromRecord(record: ICompositeSpliceRecord): IActive | null {
		const channels = new Map<string, IActiveChannel>();
		for (const c of record.channels) {
			const channelId = Buffer.from(c.channelId, 'hex');
			const channel = this.deps.channelManager.getChannel(channelId);
			if (!channel) continue;
			const inflight = channel.getFullState().spliceInFlight;
			channels.set(c.channelId, {
				channel,
				peerPubkey: c.peerPubkey,
				fundingTxid: Buffer.from(c.fundingTxid, 'hex'),
				fundingOutputIndex: c.fundingOutputIndex,
				negotiatedTxid: record.txid ? Buffer.from(record.txid, 'hex') : null,
				peerSigned: !!inflight?.remoteSharedInputSig,
				// maybeSettled reads the channel's state for the rest.
				completed: false,
				aborted: false,
				left: false
			});
		}
		if (channels.size === 0) return null;
		return { record, channels, timer: null, starting: false };
	}
}
