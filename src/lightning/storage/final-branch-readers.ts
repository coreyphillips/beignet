/**
 * The internal readers that claim a commitment by the branch it spends
 * (#2151 step 2b). They are private members of SqliteStorage, kept out of
 * the API snapshot. Each store attaches them when it is built, so the claim
 * builders in src/lightning/chain reach them without a public member, and a
 * storage double without them takes today's path. The asset conversion
 * transport reads a conversion's parent the same way (#2151 step 3a).
 */
import type { IFinalCommitmentType } from '../channel/final-opening-commitment';
import type { IFinalConversionExits } from './final-conversion-exits';
import type { IFinalChannelTypeRecord } from './final-channel-type';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import type { IFinalPeerSecret } from './final-peer-secrets';
import type { SqliteStorage } from './sqlite-storage';

/** One funding output a channel has had, with the type and era whose rules claim a commitment on it. */
export interface IFinalChannelFunding {
	txid: string;
	outputIndex: number;
	type: 'plain' | 'asset';
	/** The era of the opening (0) or of record k (k); a conversion candidate has its digest instead. */
	era?: number;
	source: 'opening' | 'record' | 'plain-splice' | 'asset-splice' | 'conversion';
	parent?: { txid: string; outputIndex: number };
	digest?: string;
}

/** The live parent of an asset conversion, once every precondition holds. */
export interface IAssetConversionParent {
	type: 'plain' | 'asset';
	channelType: string;
	funding: IFinalFundingReference;
	/** The live funding txid, in display order. */
	txid: string;
	outputIndex: number;
	/** The current state number N. */
	height: bigint;
	/** Whether this side opened the channel. */
	opener: boolean;
	commitmentFeeratePerKw: number;
	/** The balances at N before the commitment fee and the anchors (#2151 step 3b). */
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	/** An asset parent's funding root, lowercase hex. */
	root?: string;
	/** The live funding output's value. */
	parentValueSats: bigint;
	/** An asset parent at N > 0: the committed round's digest, lowercase hex. */
	priorDigest?: string;
}

export type FinalResolutionStates = ReturnType<
	SqliteStorage['loadFinalResolutionStates']
>;

export interface IFinalBranchReaders {
	/** The channel's `channel-type` and `conversion` rows: one count, generation 6 only. */
	finalBranchRows(channelId: string): number;
	finalChannelFundings(channelId: string): IFinalChannelFunding[];
	loadFinalEraResolutionStates(
		channelId: string,
		era: number
	): FinalResolutionStates;
	loadFinalPeerSecret(
		channelId: string,
		height: bigint,
		point: Buffer
	): IFinalPeerSecret;
	/** The retained conversion of a digest, read only behind the row count. */
	finalConversion(
		channelId: string,
		digest: string
	): IFinalConversionExits | null;
	/** The records, oldest first, which bound each era. */
	finalEraRecords(channelId: string): IFinalChannelTypeRecord[];
	/** The type a plain branch's builder passes, or none when it is the opening's own. */
	finalPlainBranchType(
		channelId: string,
		branch: IFinalChannelFunding
	): IFinalCommitmentType | undefined;
	/** Our own commitment at `height` of a past era, revoked since by a later era. */
	finalOwnCommitmentRevoked(
		channelId: string,
		era: number,
		height: bigint
	): boolean;
	/** Every peer secret by height, for diagnostics; it throws on a disagreement and is never on a claim path. */
	loadFinalPeerSecrets(channelId: string): Map<bigint, Buffer>;
	/** Run one claim build with each channel's secret sources read once for every height. */
	finalPeerSecretScope<T>(run: () => T): T;
	/** A conversion's parent, or a throw naming the first precondition it fails. */
	assetConversionParent(channelId: string): IAssetConversionParent;
}

/**
 * A symbol-keyed function on the store, not a declared member: it reaches
 * through the node's fenced storage view, which wraps every function it
 * hands out, so a closed view refuses it like any other call. The symbol is
 * private to this module, so only its importers reach the readers.
 */
const readersKey = Symbol('final-branch-readers');

export function registerFinalBranchReaders(
	storage: object,
	readers: IFinalBranchReaders
): void {
	Object.defineProperty(storage, readersKey, {
		value: (): IFinalBranchReaders => readers,
		enumerable: false,
		// A proxy may hand out a wrapper only for a configurable property.
		configurable: true
	});
}

/** The branch readers of an original store, or none for a storage double. */
export function finalBranchReaders(
	storage: object
): IFinalBranchReaders | undefined {
	const get = (storage as { [readersKey]?: () => IFinalBranchReaders })[
		readersKey
	];
	return typeof get === 'function' ? get() : undefined;
}
