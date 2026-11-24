import type { IAssetSpliceLockEvent } from '../channel/asset-splice-lock';
import { MAX_INTERACTIVE_TX_INPUTS } from '../interactive-tx/validation';
import type {
	IAssetSpliceExitProofs,
	AssetSpliceExitEvent
} from './asset-splice-exit-proofs';

export type AssetWalletInputEvent =
	| { kind: 'wallet-inputs'; attempt: string; parent: string; inputs: string[] }
	| { kind: 'wallet-inputs-aborted'; attempt: string };

type JournalEvent =
	| AssetWalletInputEvent
	| AssetSpliceExitEvent
	| IAssetSpliceLockEvent;
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

export function assetWalletInputState(records: readonly JournalEvent[]) {
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

/** Select the funding output acknowledged by the two peers and the original device. */
export function currentAssetWalletParent(
	records: readonly JournalEvent[],
	exits: readonly IAssetSpliceExitProofs[],
	channelId: string,
	opening: string
): string {
	let parent = opening;

	for (const r of records) {
		if (r.kind === 'reconcile')
			throw new Error('Asset splice funding needs reconciliation');
		if (r.kind !== 'adopt') continue;
		const e = exits.find((x) => x.finalDigest === r.terms.finalDigest);
		if (
			!e ||
			r.terms.channelId !== channelId ||
			e.parent.fundingTxid + ':' + e.parent.outputIndex !== parent ||
			e.candidate.fundingTxid !== r.terms.txid ||
			e.candidate.outputIndex !== r.terms.outputIndex
		)
			throw new Error('Asset splice adopted a disconnected funding reference');
		parent = e.candidate.fundingTxid + ':' + e.candidate.outputIndex;
	}
	return parent;
}
