import {
	assetUpdateHistory,
	assetUpdateFundingMembers
} from './asset-update-history';
import { Transaction } from 'bitcoinjs-lib';
import { isDeepStrictEqual } from 'util';
import {
	checkedWalletInputs,
	assetWalletInputState
} from './asset-splice-wallet-inputs';
import { sha256 } from '../crypto/provider';
import { MAX_INDEX } from '../keys/shachain';
import type { SqliteStorage } from './sqlite-storage';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import {
	canonicalSpliceFunding,
	canonicalSpliceHolder,
	spliceRecoveryView,
	type IAssetSpliceHolderRecovery
} from './asset-splice-recovery';
export type {
	IAssetSpliceHolderRecovery,
	IStoredSpliceHtlc,
	IStoredSpliceLeaf
} from './asset-splice-recovery';

export interface IAssetSpliceExitBranch {
	minimumDepth: number;
	funding: IFinalFundingReference;
	localRecovery: IAssetSpliceHolderRecovery;
	remoteRecovery: IAssetSpliceHolderRecovery;
	fundingTxid: string;
	outputIndex: number;
	fundingRoot: string;
	fundingProofs: string;
	localCommitment: string;
	localProofs: string;
	remoteCommitment: string;
	remoteProofs: string;
}

export interface IAssetSpliceExitProofs {
	priorDigest?: string;
	minimumDepth: number;
	channelId: string;
	finalDigest: string;
	stateNumber: string;
	parent: IAssetSpliceExitBranch;
	candidate: IAssetSpliceExitBranch;
}

export interface IAssetSpliceReleaseContext {
	store: SqliteStorage;
	stateNumber: bigint;
	finalDigest: Buffer;
	parentRemote: Transaction;
	candidateRemote: Transaction;
}

export type AssetSpliceExitEvent =
	| { kind: 'exit-proofs'; evidence: IAssetSpliceExitProofs }
	| {
			kind: 'funding-reserved';
			localInputs: string[];
			finalDigest: string;
			stateNumber: string;
			evidenceHash: string;
	  }
	| {
			kind: 'funding-released';
			finalDigest: string;
			stateNumber: string;
			evidenceHash: string;
			wire: string;
	  };

function hex(raw: string, maxBytes: number, exact = false): string {
	if (
		typeof raw !== 'string' ||
		!raw.length ||
		raw.length % 2 ||
		raw.length > maxBytes * 2 ||
		(exact && raw.length !== maxBytes * 2) ||
		!/^[0-9a-f]+$/.test(raw)
	)
		throw new Error('Invalid retained asset splice proof bytes');
	return raw;
}
function positiveDepth(value: number): number {
	if (!Number.isSafeInteger(value) || value < 1 || value > 0xffffffff)
		throw new Error('Invalid asset splice funding depth');
	return value;
}

function branch(v: IAssetSpliceExitBranch): IAssetSpliceExitBranch {
	const fundingTxid = hex(v.fundingTxid, 32, true);
	const { outputIndex } = v;
	if (
		!Number.isSafeInteger(outputIndex) ||
		outputIndex < 0 ||
		outputIndex > 0xffffffff
	)
		throw new Error('Invalid retained asset splice outpoint');
	function commitment(raw: string, local: boolean): string {
		const tx = Transaction.fromHex(hex(raw, 400000));
		if (
			tx.toHex() !== raw ||
			tx.ins.length !== 1 ||
			tx.ins[0].index !== outputIndex ||
			!tx.ins[0].hash.equals(Buffer.from(fundingTxid, 'hex').reverse()) ||
			(local
				? tx.ins[0].witness.length !== 1 || tx.ins[0].witness[0].length !== 64
				: tx.hasWitnesses())
		)
			throw new Error('Retained commitment disagrees with asset funding');
		return raw;
	}
	return {
		minimumDepth: positiveDepth(v.minimumDepth),
		funding: canonicalSpliceFunding(v.funding),
		localRecovery: canonicalSpliceHolder(v.localRecovery),
		remoteRecovery: canonicalSpliceHolder(v.remoteRecovery),
		fundingTxid,
		outputIndex,
		fundingRoot: hex(v.fundingRoot, 32, true),
		fundingProofs: hex(v.fundingProofs, 4 * 1024 * 1024),
		localCommitment: commitment(v.localCommitment, true),
		localProofs: hex(v.localProofs, 4 * 1024 * 1024),
		remoteCommitment: commitment(v.remoteCommitment, false),
		remoteProofs: hex(v.remoteProofs, 4 * 1024 * 1024)
	};
}

function canonical(
	id: string,
	v: IAssetSpliceExitProofs
): IAssetSpliceExitProofs {
	if (
		!v ||
		hex(v.channelId, 32, true) !== id ||
		typeof v.stateNumber !== 'string' ||
		v.stateNumber.length > 15 ||
		!/^(0|[1-9][0-9]*)$/.test(v.stateNumber) ||
		BigInt(v.stateNumber) > MAX_INDEX
	)
		throw new Error('Invalid retained asset splice identity or height');
	const parent = branch(v.parent),
		candidate = branch(v.candidate);
	if (positiveDepth(v.minimumDepth) !== candidate.minimumDepth)
		throw new Error('Candidate splice depth differs from its approved receipt');
	if (v.stateNumber === '0' && v.priorDigest !== undefined)
		throw new Error('Unexpected opening update digest');
	if (parent.fundingTxid === candidate.fundingTxid)
		throw new Error(
			'Retained splice generations must use distinct funding transactions'
		);
	return {
		minimumDepth: v.minimumDepth,
		...(v.stateNumber === '0'
			? {}
			: { priorDigest: hex(v.priorDigest ?? '', 32, true) }),
		channelId: id,
		finalDigest: hex(v.finalDigest, 32, true),
		stateNumber: v.stateNumber,
		parent,
		candidate
	};
}

function verifyRecovery(
	store: SqliteStorage,
	evidence: IAssetSpliceExitProofs
): IAssetSpliceExitProofs {
	const { channelId: id, parent, candidate, stateNumber } = evidence;
	const opening = store.loadFinalOpening(id),
		session = store.loadFinalOpeningSession(id);
	if (!opening || !session?.assetEvidence)
		throw new Error('Missing enrolled asset opening');
	let terms = session.terms;
	if (stateNumber !== '0') {
		const history = assetUpdateHistory(store, id),
			state = history.states.get(BigInt(stateNumber));
		if (
			!state ||
			state.digest !== evidence.priorDigest ||
			!history.stages.has(stateNumber + '/local-revoke') ||
			!history.stages.has(stateNumber + '/peer-revoke')
		)
			throw new Error('Asset splice needs its irrevocable signed predecessor');
		const previous = assetUpdateFundingMembers(store, id, state).find(
			(m) =>
				m.fundingTxid === parent.fundingTxid &&
				m.outputIndex === parent.outputIndex
		);
		if (!previous || !isDeepStrictEqual(branch(previous), parent))
			throw new Error('Asset splice parent differs from signed predecessor');
		terms = { ...terms, commitmentFeeratePerKw: state.feerate };
	}
	const incoming = Transaction.fromHex(
		candidate.funding.fundingTxHex
	).ins.filter(
		(input) =>
			input.hash.equals(Buffer.from(parent.fundingTxid, 'hex').reverse()) &&
			input.index === parent.outputIndex
	);
	if (incoming.length !== 1)
		throw new Error('Candidate does not spend the retained parent outpoint');
	for (const b of [parent, candidate])
		for (const holder of ['local', 'remote'] as const)
			spliceRecoveryView(
				opening,
				terms,
				session.assetEvidence.fundingRoot,
				b,
				holder,
				stateNumber
			);
	return evidence;
}

/** Called after the host has independently verified both sets of asset proofs and reconstructed the exits. */
export function retainAssetSpliceExitProofs(
	store: SqliteStorage,
	id: string,
	supplied: IAssetSpliceExitProofs
): void {
	if (!store.canSpliceDualFundedAssets)
		throw new Error('Proof retention requires the original splice wallet');
	const evidence = verifyRecovery(store, canonical(id, supplied));
	const head = store.readAssetSpliceJournal<AssetSpliceExitEvent>(id);
	for (const row of head.records) {
		if (row.kind !== 'exit-proofs') continue;
		if (row.evidence.finalDigest === evidence.finalDigest) {
			if (
				JSON.stringify(canonical(id, row.evidence)) !== JSON.stringify(evidence)
			)
				throw new Error('Retained asset splice evidence changed');
			return;
		}
		if (
			row.evidence.candidate.fundingTxid === evidence.candidate.fundingTxid &&
			row.evidence.stateNumber === evidence.stateNumber
		)
			throw new Error(
				'Candidate already retained under a different splice digest'
			);
	}
	store.appendAssetSpliceEvent(id, head, { kind: 'exit-proofs', evidence });
}

export function loadAssetSpliceExitProofs(
	store: SqliteStorage,
	id: string,
	digest: string
): IAssetSpliceExitProofs {
	hex(digest, 32, true);
	const rows = store
		.readAssetSpliceJournal<AssetSpliceExitEvent>(id)
		.records.filter(
			(row): row is Extract<AssetSpliceExitEvent, { kind: 'exit-proofs' }> =>
				row.kind === 'exit-proofs' && row.evidence.finalDigest === digest
		);
	if (rows.length !== 1)
		throw new Error('Missing or ambiguous retained asset splice proofs');
	return verifyRecovery(store, canonical(id, rows[0].evidence));
}

function proofHash(evidence: IAssetSpliceExitProofs): Buffer {
	return sha256(Buffer.from(JSON.stringify(evidence)));
}

/** Recover reservations even when a crash interrupted the wallet signature or its delivery. */
export function publishableAssetSpliceEvidence(
	records: readonly AssetSpliceExitEvent[],
	channelId: string
): IAssetSpliceExitProofs[] {
	const proposals = new Map<string, IAssetSpliceExitProofs>();
	const reserved = new Map<string, IAssetSpliceExitProofs>();
	const released = new Set<string>();
	for (const row of records) {
		if (row.kind === 'exit-proofs') {
			const evidence = canonical(channelId, row.evidence);
			if (proposals.has(evidence.finalDigest))
				throw new Error('Duplicate splice proof receipt');
			proposals.set(evidence.finalDigest, evidence);
			continue;
		}
		if (row.kind !== 'funding-reserved' && row.kind !== 'funding-released')
			continue;
		const evidence = proposals.get(row.finalDigest);
		if (
			!evidence ||
			evidence.stateNumber !== row.stateNumber ||
			proofHash(evidence).toString('hex') !== row.evidenceHash ||
			released.has(row.finalDigest)
		)
			throw new Error(
				'Asset funding phase differs from its original proof receipt'
			);
		if (row.kind === 'funding-reserved') {
			if (reserved.has(row.finalDigest))
				throw new Error('Duplicate asset funding reservation');
			reserved.set(row.finalDigest, evidence);
		} else {
			if (!reserved.has(row.finalDigest))
				throw new Error('Asset funding release has no prior reservation');
			hex(row.wire, 65533);
			released.add(row.finalDigest);
		}
	}
	return [...reserved.values()];
}

/** Device-first reservation survives an interruption inside either wallet signer. */
export function recordAssetSpliceFundingPhase(
	store: SqliteStorage,
	evidence: IAssetSpliceExitProofs,
	wire?: Buffer,
	coinSelection: readonly string[] = []
): Buffer {
	const localInputs = checkedWalletInputs(coinSelection);
	const evidenceHash = proofHash(evidence);
	const kind = wire ? 'funding-released' : 'funding-reserved';
	const { finalDigest, stateNumber, channelId } = evidence;
	const head = store.readAssetSpliceJournal<AssetSpliceExitEvent>(channelId);
	const fields = {
		finalDigest,
		stateNumber,
		evidenceHash: evidenceHash.toString('hex')
	};
	const same = head.records.filter(
		(r) =>
			r.kind !== 'exit-proofs' &&
			r.finalDigest === finalDigest &&
			r.stateNumber === stateNumber
	);
	const reserved = same.find((r) => r.kind === 'funding-reserved');
	if (!reserved) {
		const parent =
			evidence.parent.fundingTxid + ':' + evidence.parent.outputIndex;
		const state = assetWalletInputState(head.records);
		const submitted = [...state.attempts.values()].filter(
			(a) => a.parent === parent
		);
		const exact = submitted.some(
			(a) => !a.aborted && isDeepStrictEqual(a.inputs, localInputs)
		);
		if (submitted.length && !exact)
			throw new Error(
				'Splice funding inputs differ from the device reservation'
			);
		if (localInputs.length && !exact) {
			const held = store.loadFinalSpliceWalletOutpoints();
			if (localInputs.some((input) => held.has(input)))
				throw new Error('Splice wallet input is already reserved');
		}
	}
	if (wire && !reserved)
		throw new Error('Asset funding witness has no original reservation');
	const previous = same.find((r) => r.kind === kind);
	if (
		previous &&
		(previous.kind === 'funding-reserved' ||
			previous.kind === 'funding-released')
	) {
		if (
			previous.evidenceHash !== fields.evidenceHash ||
			(previous.kind === 'funding-reserved' &&
				!isDeepStrictEqual(previous.localInputs, localInputs)) ||
			(previous.kind === 'funding-released' &&
				previous.wire !== wire?.toString('hex'))
		)
			throw new Error('Asset funding release differs from retained evidence');
	} else {
		const event: AssetSpliceExitEvent = wire
			? { kind: 'funding-released', ...fields, wire: wire.toString('hex') }
			: { kind: 'funding-reserved', ...fields, localInputs };
		store.appendAssetSpliceEvent(channelId, head, event);
	}
	return evidenceHash;
}
