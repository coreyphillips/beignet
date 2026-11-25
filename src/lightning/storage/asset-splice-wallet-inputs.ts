import type { IAssetSpliceLockEvent } from '../channel/asset-splice-lock';
import { MAX_INTERACTIVE_TX_INPUTS } from '../interactive-tx/validation';
import type {
	IAssetSpliceExitProofs,
	AssetSpliceExitEvent
} from './asset-splice-exit-proofs';

export type AssetWalletInputEvent =
	| { kind: 'wallet-inputs'; attempt: string; parent: string; inputs: string[] }
	| { kind: 'wallet-inputs-aborted'; attempt: string };

export type AssetSpliceLockJournalEvent =
	| {
			kind: 'asset-splice-lock';
			event: IAssetSpliceLockEvent;
			blockHeight?: number;
	  }
	| {
			kind: 'asset-splice-imported';
			finalDigest: string;
			txid: string;
			blockHash: string;
	  };
export type AssetWalletJournalEvent =
	| AssetWalletInputEvent
	| AssetSpliceExitEvent
	| AssetSpliceLockJournalEvent;
const txid = /^[a-f0-9]{64}$/;
export function assetSpliceAttemptId(id: string): void {
	if (typeof id !== 'string' || id.length !== 64 || !txid.test(id))
		throw new Error('Invalid asset splice attempt');
}

export function checkedWalletInputs(inputs: readonly string[]): string[] {
	if (!Array.isArray(inputs) || inputs.length >= MAX_INTERACTIVE_TX_INPUTS)
		throw new Error('Invalid number of local splice inputs');
	const seen = new Set<string>();
	for (const input of inputs) {
		const match =
			typeof input === 'string' &&
			/^([0-9a-f]{64}):(0|[1-9][0-9]{0,9})$/.exec(input);
		if (
			!match ||
			match[0] !== input ||
			Number(match[2]) > 0xffffffff ||
			seen.has(input)
		)
			throw new Error('Invalid or duplicate local splice input');
		seen.add(input);
	}
	return [...seen].sort();
}

export function assetWalletInputState(
	records: readonly AssetWalletJournalEvent[]
) {
	const attempts = new Map<
		string,
		{ parent: string; inputs: string[]; aborted: boolean }
	>();
	const irreversible = new Set<string>();
	const priorProofs = new Map<string, string>();
	const signedParents = new Set<string>();
	for (const event of records) {
		if (event.kind === 'exit-proofs') {
			const { parent, finalDigest } = event.evidence;
			priorProofs.set(
				finalDigest,
				parent.fundingTxid + ':' + parent.outputIndex
			);
		} else if (event.kind === 'funding-reserved') {
			const parent = priorProofs.get(event.finalDigest);
			if (!parent)
				throw new Error('Asset funding reservation lacks its prior receipt');
			signedParents.add(parent);
			for (const input of checkedWalletInputs(event.localInputs))
				irreversible.add(input);
		} else if (event.kind === 'wallet-inputs') {
			assetSpliceAttemptId(event.attempt);
			checkedWalletInputs([event.parent]);
			const inputs = checkedWalletInputs(event.inputs);
			if (attempts.has(event.attempt) || inputs.includes(event.parent))
				throw new Error('Conflicting asset splice wallet input reservation');
			attempts.set(event.attempt, {
				parent: event.parent,
				inputs,
				aborted: false
			});
		} else if (event.kind === 'wallet-inputs-aborted') {
			const attempt = attempts.get(event.attempt);
			if (
				!attempt ||
				attempt.aborted ||
				signedParents.has(attempt.parent) ||
				attempt.inputs.some((input) => irreversible.has(input))
			)
				throw new Error('Invalid asset splice wallet input abort');
			attempt.aborted = true;
		}
	}
	const reserved = new Set(irreversible);
	for (const a of attempts.values()) {
		if (!a.aborted) for (const input of a.inputs) reserved.add(input);
	}
	return { attempts, irreversible, signedParents, reserved };
}

/** Replay bilateral adoption and the independent wallet import in journal order. */
export function assetWalletFundingInfo(
	records: readonly AssetWalletJournalEvent[],
	exits: readonly IAssetSpliceExitProofs[],
	channelId: string,
	opening: string
) {
	let reconciliation = false;
	const previousFundingTxids: string[] = [];
	let active: IAssetSpliceExitProofs | undefined;
	let pending:
		| { receipt: IAssetSpliceExitProofs; blockHash: string }
		| undefined;
	let parent = opening;
	const observations = new Map<string, { peer: boolean; blockHash?: string }>();
	for (const row of records) {
		if (row.kind === 'asset-splice-imported') {
			if (
				!pending ||
				pending.receipt.finalDigest !== row.finalDigest ||
				pending.receipt.candidate.fundingTxid !== row.txid ||
				pending.blockHash !== row.blockHash
			)
				throw new Error(
					'Asset splice wallet import differs from adopted funding'
				);
			previousFundingTxids.push(pending.receipt.parent.fundingTxid);
			active = pending.receipt;
			parent =
				active.candidate.fundingTxid + ':' + active.candidate.outputIndex;
			pending = undefined;
			continue;
		}
		if (row.kind !== 'asset-splice-lock') continue;
		const r = row.event,
			terms = r.terms;
		const e = exits.find((v) => v.finalDigest === terms.finalDigest);
		if (
			!e ||
			terms.channelId !== channelId ||
			e.candidate.fundingTxid !== terms.txid ||
			e.candidate.outputIndex !== terms.outputIndex ||
			e.minimumDepth !== terms.minimumDepth
		)
			throw new Error('Asset splice lock differs from its funding receipt');
		if (r.kind === 'reconcile') {
			reconciliation = true;
			continue;
		}
		const observed = observations.get(terms.finalDigest) ?? { peer: false };
		if (r.kind === 'local') observed.blockHash = r.blockHash;
		else if (r.kind === 'peer') observed.peer = true;
		else if (r.kind === 'adopt') {
			if (
				pending ||
				!observed.peer ||
				observed.blockHash !== r.blockHash ||
				e.parent.fundingTxid + ':' + e.parent.outputIndex !== parent
			)
				throw new Error(
					'Asset splice adopted a disconnected funding reference'
				);
			pending = { receipt: e, blockHash: r.blockHash };
		}
		observations.set(terms.finalDigest, observed);
	}
	return {
		active,
		awaitingImport: !!pending,
		reconciliation,
		previousFundingTxids,
		pending: exits.filter(
			(e) => e.parent.fundingTxid + ':' + e.parent.outputIndex === parent
		)
	};
}

export function requireAssetWalletParent(
	info: ReturnType<typeof assetWalletFundingInfo>
) {
	if (info.reconciliation)
		throw new Error('Asset splice funding needs reconciliation');
	if (info.awaitingImport)
		throw new Error('Asset splice adoption is awaiting its wallet proof');
	return info.active;
}
