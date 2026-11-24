import {
	buildAssetOpeningCommitment,
	buildFinalOpeningCommitment,
	type IFinalOpeningTerms
} from '../channel/final-opening-commitment';
import { ASSET_OPEN_OBJECT_LIMIT } from '../message/asset-open';
import type { IFinalOpeningCandidate } from './final-opening-candidate';

interface IStoredAssetLeaf {
	script: string;
	leafVersion?: number;
}

interface IAssetOpeningExitProofs {
	toLocal?: IStoredAssetLeaf;
	toRemote?: IStoredAssetLeaf;
	proofs: string;
}

/** Hex encoding of the provider's verified transfers and each holder's recoverable exit. */
export interface IAssetOpeningEvidence {
	fundingRoot: string;
	layoutDigest: string;
	finalDigest: string;
	fundingProofs: string;
	local: IAssetOpeningExitProofs;
	remote: IAssetOpeningExitProofs;
}

function exactFields(value: object, fields: readonly string[]): void {
	if (
		!value ||
		typeof value !== 'object' ||
		Array.isArray(value) ||
		Object.keys(value).some((key) => !fields.includes(key))
	)
		throw new Error('Invalid asset opening evidence fields');
}

function hex(value: string, maximum: number, minimum = 1): string {
	if (
		typeof value !== 'string' ||
		value.length < 2 * minimum ||
		value.length > 2 * maximum ||
		value.length % 2 ||
		!/^[0-9a-f]+$/.test(value)
	)
		throw new Error('Invalid asset opening proof bytes');
	return value;
}

function leaf(value: IStoredAssetLeaf): IStoredAssetLeaf {
	exactFields(value, ['script', 'leafVersion']);
	const { script, leafVersion } = value;
	if (
		leafVersion !== undefined &&
		(!Number.isInteger(leafVersion) ||
			leafVersion < 0 ||
			leafVersion > 254 ||
			leafVersion % 2)
	)
		throw new Error('Invalid asset opening leaf version');
	return {
		script: hex(script, 10000),
		...(leafVersion !== undefined && { leafVersion })
	};
}

function side(value: IAssetOpeningExitProofs): IAssetOpeningExitProofs {
	exactFields(value, ['toLocal', 'toRemote', 'proofs']);
	if (!value.toLocal && !value.toRemote)
		throw new Error('Missing asset opening exit leaves');
	return {
		...(value.toLocal !== undefined && { toLocal: leaf(value.toLocal) }),
		...(value.toRemote !== undefined && { toRemote: leaf(value.toRemote) }),
		proofs: hex(value.proofs, ASSET_OPEN_OBJECT_LIMIT)
	};
}

export function canonicalAssetOpeningEvidence(
	value: IAssetOpeningEvidence
): IAssetOpeningEvidence {
	exactFields(value, [
		'fundingRoot',
		'layoutDigest',
		'finalDigest',
		'fundingProofs',
		'local',
		'remote'
	]);
	return {
		fundingRoot: hex(value.fundingRoot, 32, 32),
		layoutDigest: hex(value.layoutDigest, 32, 32),
		finalDigest: hex(value.finalDigest, 32, 32),
		fundingProofs: hex(value.fundingProofs, ASSET_OPEN_OBJECT_LIMIT),
		local: side(value.local),
		remote: side(value.remote)
	};
}

export function storedOpeningCommitment(
	candidate: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	owner: 'local' | 'remote',
	evidence?: IAssetOpeningEvidence
) {
	if (!evidence) return buildFinalOpeningCommitment(candidate, terms, owner);
	return buildAssetOpeningCommitment(
		candidate,
		terms,
		owner,
		assetOpeningLeaves(evidence, owner)
	).tx;
}

export function assetOpeningLeaves(
	evidence: IAssetOpeningEvidence,
	owner: 'local' | 'remote'
) {
	const decode = (stored: IStoredAssetLeaf) => ({
		script: Buffer.from(stored.script, 'hex'),
		leafVersion: stored.leafVersion
	});
	const { toLocal, toRemote } = evidence[owner];
	return {
		fundingRoot: Buffer.from(evidence.fundingRoot, 'hex'),
		...(toLocal && { toLocal: decode(toLocal) }),
		...(toRemote && { toRemote: decode(toRemote) })
	};
}
