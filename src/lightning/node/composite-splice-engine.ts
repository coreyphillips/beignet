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
	/** Rebroadcast a released composite after a restart. */
	rebroadcast(txHex: string, idHex: string): void;
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
		cm.on('broadcast:tx', this.onBroadcast);
		cm.on('error', this.onChannelError);
	}

	detach(): void {
		if (!this.attached) return;
		this.attached = false;
		const cm = this.deps.channelManager;
		cm.removeListener('splice:negotiated', this.onNegotiated);
		cm.removeListener('channel:splice-txsigs-needed', this.onPeerSigned);
		cm.removeListener('splice:aborted', this.onSpliceAborted);
		cm.removeListener('splice:complete', this.onSpliceComplete);
		cm.removeListener('broadcast:tx', this.onBroadcast);
		cm.removeListener('error', this.onChannelError);
		if (this.active?.timer) clearTimeout(this.active.timer);
		this.active = null;
	}

	/**
	 * Apply the restore table of section 5 to every stored record. Called once
	 * at boot, after the channels are restored and before peers connect.
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
		for (const record of records) {
			this.records.set(record.id, record);
			if (compositeSpliceStageIsTerminal(record.stage)) continue;
			if (!compositeSpliceStageAtLeast(record.stage, 'RELEASED')) {
				// Nothing of ours left: forget every unsent session (owing the
				// peer a tx_abort) and close the record.
				const reason = `composite splice ${record.stage} at restart`;
				for (const c of record.channels) {
					const channelId = Buffer.from(c.channelId, 'hex');
					if (!this.deps.channelManager.getChannel(channelId)) continue;
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
				this.writeRecord({ ...record, stage: 'ABORTED', reason });
				continue;
			}
			// RELEASED or BROADCAST: the transaction may confirm. Rebroadcast,
			// keep tracking the channels to LOCKED, and finish any slot that a
			// session still owes (a crash between two fills).
			this.active = this.activeFromRecord(record);
			// Prefer a session's fully signed copy: a crash between RELEASED and
			// BROADCAST leaves the record with the unsigned COMMITTED hex.
			const signed = [...(this.active?.channels.values() ?? [])]
				.map((e) => e.channel.getFullState().spliceInFlight)
				.find((f) => f?.fullySigned)?.spliceTxHex;
			const hex = signed ?? record.txHex;
			if (hex) this.deps.rebroadcast(hex, record.id);
			if (this.active) {
				this.fillAllSlots(this.active);
				this.maybeLocked(this.active);
			}
		}
		// Only one operation can be live; a second RELEASED record (impossible
		// in normal operation) is tracked only through its channels.
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
				aborted: false
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
		this.maybeLocked(active);
	};

	private maybeLocked(active: IActive): void {
		if (this.active !== active) return;
		if (!compositeSpliceStageAtLeast(active.record.stage, 'RELEASED')) return;
		const txid = active.record.txid;
		for (const entry of active.channels.values()) {
			if (entry.completed) continue;
			const state = entry.channel.getFullState();
			// After a restart the completion event is history: the channel's
			// own funding says whether it adopted the composite.
			if (
				txid &&
				state.state === ChannelState.NORMAL &&
				!state.spliceInFlight &&
				state.fundingTxid?.toString('hex') === txid
			) {
				entry.completed = true;
				continue;
			}
			return;
		}
		const record = this.setStage(active, 'LOCKED');
		this.active = null;
		this.deps.withMutations([{ type: 'composite_splice', record }], standalone);
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
				completed: false,
				aborted: false
			});
		}
		if (channels.size === 0) return null;
		return { record, channels, timer: null, starting: false };
	}
}
