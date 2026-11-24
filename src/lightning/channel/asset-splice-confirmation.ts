import type { IAssetSpliceInclusionRecovery } from '../chain/asset-splice-inclusion';
import { decodeSpliceLockedMessage } from '../message/splice';
import {
	publishableAssetSpliceEvidence,
	type AssetSpliceExitEvent,
	type IAssetSpliceExitProofs
} from '../storage/asset-splice-exit-proofs';
import type { SqliteStorage } from '../storage/sqlite-storage';
import type { IFinalFundingReference } from './final-splice-candidate';
import {
	AssetSpliceLock,
	type IAssetSpliceAnchor,
	type IAssetSpliceLockEvent,
	type IAssetSpliceLockTerms
} from './asset-splice-lock';

export interface IWalletSpliceLock {
	channelId: string;
	finalDigest: string;
	fundingTxid: string;
	fundingOutputIndex: number;
	localBlockHash?: string;
	peerFundingTxid?: string;
	adopted: boolean;
	needsReconciliation: boolean;
}
export interface IAssetSpliceConfirmation {
	channelId: string;
	finalDigest: string;
	fundingTxid: string;
	fundingOutputIndex: number;
	blockHash: string;
	blockHeight: number;
	currentLock(): IWalletSpliceLock | undefined;
}
export interface IAssetSpliceConfirmationProvider {
	verifySpliceFunding(ctx: IAssetSpliceConfirmation): Promise<void>;
	confirmSpliceFunding(ctx: IAssetSpliceConfirmation): Promise<void>;
	retractSpliceFunding(ctx: IAssetSpliceConfirmation): Promise<void>;
}
export type AssetSpliceInclusionLookup = (
	height: number,
	recovery: IAssetSpliceInclusionRecovery
) => Promise<IAssetSpliceAnchor>;
interface LockEvent {
	kind: 'asset-splice-lock';
	event: IAssetSpliceLockEvent;
	blockHeight?: number;
}
interface Entry {
	terms: IAssetSpliceLockTerms;
	peer: string;
	parent: string;
	lock: AssetSpliceLock;
	ticket: number;
	verified?: { blockHash: string; height: number };
	sample?: {
		height: number;
		prove: AssetSpliceInclusionLookup;
		current: () => boolean;
	};
	imported?: string;
	retracted?: string;
	sent?: string;
	importing?: { block: string; pending: Promise<void> };
}
const key = (channel: string, txid: string) => channel + '/' + txid;

/** Bearer of no funding keys. Peer locks and wallet imports are bound to each original-device funding receipt. */
export class AssetSpliceConfirmationCoordinator {
	private entries = new Map<string, Entry>();
	constructor(
		private readonly store: SqliteStorage,
		private readonly wallet:
			| Partial<IAssetSpliceConfirmationProvider>
			| undefined,
		private readonly watch: (
			id: string,
			funding: IFinalFundingReference,
			depth: number
		) => void,
		private readonly send: (peer: string, raw: Buffer) => void,
		private readonly adopted?: (id: string, txid: string) => void
	) {}

	private walletAction(
		method: keyof IAssetSpliceConfirmationProvider,
		ctx: IAssetSpliceConfirmation
	): Promise<void> {
		const action = this.wallet?.[method];
		if (!action) throw new Error('Splice proof wallet is unavailable');
		return action.call(this.wallet, ctx);
	}

	private events(terms: IAssetSpliceLockTerms) {
		const head = this.store.readAssetSpliceJournal<LockEvent>(terms.channelId);
		const locks = head.records.filter(
			(v) => v.kind === 'asset-splice-lock' && v.event.terms.txid === terms.txid
		);
		return { head, locks };
	}
	private register(e: IAssetSpliceExitProofs, peer: string): void {
		const b = e.candidate,
			id = e.channelId;
		const terms = {
			channelId: id,
			txid: b.fundingTxid,
			outputIndex: b.outputIndex,
			finalDigest: e.finalDigest,
			minimumDepth: e.minimumDepth
		};
		const k = key(id, terms.txid);
		const existing = this.entries.get(k);
		if (existing) {
			if (
				existing.terms.outputIndex !== terms.outputIndex ||
				existing.terms.minimumDepth !== terms.minimumDepth
			)
				throw new Error('Conflicting watch for the same splice funding');
			return;
		}
		const parent = e.parent.fundingTxid + ':' + e.parent.outputIndex;
		const entry: Entry = {
			terms,
			peer,
			parent,
			ticket: 0,
			lock: new AssetSpliceLock(
				terms,
				{
					read: () => this.events(terms).locks.map((v) => v.event),
					append: (event, expectedLength) => {
						const { head, locks } = this.events(terms);
						if (locks.length !== expectedLength)
							throw new Error('Asset splice lock history changed');
						if (
							event.kind === 'adopt' &&
							[...this.entries.values()].some(
								(other) =>
									other !== entry &&
									other.terms.channelId === id &&
									other.parent === parent &&
									other.lock.state().adopted
							)
						)
							throw new Error(
								'A competing splice already adopted this funding input'
							);
						const height = entry.sample?.height;
						this.store.appendAssetSpliceEvent(id, head, {
							kind: 'asset-splice-lock',
							event,
							...(event.kind === 'local' && { blockHeight: height })
						});
					}
				},
				async (_terms, anchor) => {
					const sample = entry.sample;
					if (!sample?.current())
						throw new Error('Asset splice chain observation expired');
					await this.walletAction(
						'verifySpliceFunding',
						this.context(entry, anchor.blockHash, sample.height)
					);
					if (!sample.current())
						throw new Error('Asset splice chain observation expired');
				}
			)
		};
		this.entries.set(k, entry);
		this.watch(id, b.funding, terms.minimumDepth);
	}

	restore(id?: string): void {
		if (!this.store.canSpliceDualFundedAssets) return;
		for (const channel of id
			? [id]
			: this.store.loadFinalOpenings().map((c) => c.channelId)) {
			const session = this.store.loadFinalOpeningSession(channel);
			if (!session?.assetEvidence) continue;
			const { records } =
				this.store.readAssetSpliceJournal<AssetSpliceExitEvent>(channel);
			for (const e of publishableAssetSpliceEvidence(records, channel))
				this.register(e, session.peer);
		}
	}
	suspend(id: string, txid: string): void {
		const e = this.entries.get(key(id, txid));
		if (!e) return;
		++e.ticket;
		e.lock.suspend();
		e.verified = undefined;
		e.sample = undefined;
	}
	has(id: string, txid: string): boolean {
		return this.entries.has(key(id, txid));
	}
	status(id: string, txid: string) {
		const e = this.entries.get(key(id, txid));
		if (!e) return;
		const state = e.lock.state();
		return {
			...state,
			available:
				state.adopted &&
				!state.needsReconciliation &&
				!!e.sample?.current() &&
				!!e.verified &&
				e.imported === e.verified.blockHash
		};
	}
	private context(
		e: Entry,
		blockHash: string,
		blockHeight: number
	): IAssetSpliceConfirmation {
		const t = e.terms,
			ticket = e.ticket;
		const identity = {
			channelId: t.channelId,
			finalDigest: t.finalDigest,
			fundingTxid: t.txid,
			fundingOutputIndex: t.outputIndex
		};
		return {
			...identity,
			blockHash,
			blockHeight,
			currentLock: () => {
				if (
					e.ticket !== ticket ||
					this.entries.get(key(t.channelId, t.txid)) !== e ||
					(e.sample && !e.sample.current())
				)
					return;
				const h = e.lock.state(),
					local = this.localBlock(e);
				return {
					...identity,
					...(local && { localBlockHash: local.blockHash }),
					...(h.peerLocked && { peerFundingTxid: t.txid }),
					adopted: h.adopted,
					needsReconciliation: h.needsReconciliation
				};
			}
		};
	}
	private localBlock(e: Entry) {
		const locals = this.events(e.terms).locks.filter(
			(r) => r.event.kind === 'local'
		);
		const last = locals[locals.length - 1];
		return last?.event.kind === 'local' && last.blockHeight
			? { blockHash: last.event.blockHash, height: last.blockHeight }
			: undefined;
	}
	private async settled(e: Entry, ticket: number): Promise<void> {
		const h = e.lock.state(),
			local = this.localBlock(e);
		if (!local) return;
		if (h.needsReconciliation) {
			if (e.retracted === local.blockHash) return;
			await this.walletAction(
				'retractSpliceFunding',
				this.context(e, local.blockHash, local.height)
			);
			if (ticket === e.ticket) e.retracted = local.blockHash;
			return;
		}
		const wire = e.lock.outboundLock();
		if (!wire || !e.verified) return;
		if (h.adopted && e.imported !== local.blockHash) {
			const active = e.importing;
			if (active) {
				await active.pending;
				if (ticket !== e.ticket) return;
			}
			if (e.imported !== local.blockHash) {
				const pending = this.walletAction(
					'confirmSpliceFunding',
					this.context(e, local.blockHash, local.height)
				);
				const task = { block: local.blockHash, pending };
				e.importing = task;
				try {
					await pending;
				} finally {
					if (e.importing === task) e.importing = undefined;
				}
				if (
					ticket !== e.ticket ||
					!e.sample?.current() ||
					e.lock.state().needsReconciliation
				)
					return;
				e.imported = local.blockHash;
				const { channelId, txid, finalDigest } = e.terms;
				const head = this.store.readAssetSpliceJournal<{
					kind: string;
					txid?: string;
					blockHash?: string;
					finalDigest?: string;
				}>(channelId);
				if (
					!head.records.some(
						(r) =>
							r.kind === 'asset-splice-imported' &&
							r.txid === txid &&
							r.blockHash === local.blockHash &&
							r.finalDigest === finalDigest
					)
				) {
					this.store.appendAssetSpliceEvent(channelId, head, {
						kind: 'asset-splice-imported',
						txid,
						blockHash: local.blockHash,
						finalDigest
					});
					this.adopted?.(channelId, txid);
				}
			}
		}
		if (
			ticket === e.ticket &&
			e.sample?.current() &&
			e.sent !== local.blockHash
		) {
			this.send(e.peer, wire);
			e.sent = local.blockHash;
		}
	}
	async observe(
		id: string,
		txid: string,
		height: number | undefined,
		prove: AssetSpliceInclusionLookup,
		current: () => boolean
	): Promise<void> {
		const e = this.entries.get(key(id, txid));
		if (!e || !current()) return;
		const ticket = ++e.ticket;
		e.lock.suspend();
		e.verified = undefined;
		e.sample = height && height > 0 ? { height, prove, current } : undefined;
		if (!e.sample) {
			await e.lock.observe(null);
			if (current() && ticket === e.ticket) await this.settled(e, ticket);
			return;
		}
		const anchor = await prove(e.sample.height, {
			store: this.store,
			channelId: id,
			finalDigest: e.terms.finalDigest
		});
		if (ticket !== e.ticket || !current()) return;
		if (anchor.txid !== txid)
			throw new Error('Verified chain transaction differs from splice funding');
		await e.lock.observe(anchor);
		if (ticket !== e.ticket || !current()) return;
		if (e.lock.outboundLock())
			e.verified = { blockHash: anchor.blockHash, height: e.sample.height };
		await this.settled(e, ticket);
	}
	async receive(peer: string, raw: Buffer): Promise<boolean> {
		if (raw.length !== 64) return false;
		const msg = decodeSpliceLockedMessage(raw);
		const id = msg.channelId.toString('hex'),
			txid = msg.fundingTxid!.reverse().toString('hex');
		const e = this.entries.get(key(id, txid));
		if (!e || e.peer !== peer) return false;
		const sample = e.sample;
		e.lock.suspend();
		e.verified = undefined;
		++e.ticket;
		await e.lock.peerLocked(txid);
		if (sample?.current())
			await this.observe(id, txid, sample.height, sample.prove, sample.current);
		return true;
	}
	async reconnected(peer: string): Promise<void> {
		for (const e of this.entries.values())
			if (e.peer === peer) {
				e.sent = undefined;
				const sample = e.sample;
				if (sample?.current())
					await this.observe(
						e.terms.channelId,
						e.terms.txid,
						sample.height,
						sample.prove,
						sample.current
					);
			}
	}
	disconnected(peer: string): void {
		for (const e of this.entries.values())
			if (e.peer === peer) {
				++e.ticket;
				e.lock.suspend();
				e.verified = undefined;
				e.sample = undefined;
				e.sent = undefined;
			}
	}
}
