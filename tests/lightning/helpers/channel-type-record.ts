/**
 * #2151 step 2a fixtures: a channel whose type is changed by a recorded
 * `channel-type` journal event.
 *
 * The step's storage surface (loadFinalChannelType, appendFinalChannelType,
 * loadFinalChannelTypeRecords) and its pure helpers are reached through the
 * loose views below, so the test files load on a base without them and each
 * test fails at its first use of a missing name.
 *
 * The record inputs are built only from names that exist today:
 * - the new funding output spends the channel's live funding and pays the
 *   two devices' newly allocated funding keys (with a random root for an
 *   asset record);
 * - the first commitments at the record's state number N are built by the
 *   new type's builder on a twin of the opening (the opening with the new
 *   type and, for its own funding script, the root that type needs), which
 *   is what the type-aware builders of section 5 build;
 * - both devices sign them through signFinalUpdate, each holder's
 *   verification nonce being the splice-source nonce of the new funding's
 *   context at N, and each next nonce the one at N + 1.
 */
import { expect } from 'chai';
import type { BIP32Interface } from 'bip32';
import { Transaction } from 'bitcoinjs-lib';
import {
	buildAssetSpliceCommitment,
	buildFinalCommitmentView,
	type IFinalCommitmentView,
	type IFinalOpeningTerms
} from '../../../src/lightning/channel/final-opening-commitment';
import type { IFinalFundingReference } from '../../../src/lightning/channel/final-splice-candidate';
import { encodeUpdateFeeMessage } from '../../../src/lightning/message/channel-update';
import { MessageType as M } from '../../../src/lightning/message/types';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	ASSET_SPLICE_RECOVERY_TYPE_HEX,
	isAssetOpeningType
} from '../../../src/lightning/features/asset-opening';
import {
	generateFromSeed,
	MAX_INDEX
} from '../../../src/lightning/keys/shachain';
import { deriveChannelKeys } from '../../../src/lightning/keys/wallet-keys';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import type { IAssetSpliceExitBranch } from '../../../src/lightning/storage/asset-splice-exit-proofs';
import {
	assetSpliceUpdateHead,
	assetUpdateHistory
} from '../../../src/lightning/storage/asset-update-history';
import type { IFinalLedgerState } from '../../../src/lightning/storage/final-channel-updates';
import type { FinalOpeningAuthority } from '../../../src/lightning/storage/final-opening-authority';
import type { IFinalOpeningCandidate } from '../../../src/lightning/storage/final-opening-candidate';
import {
	signFinalUpdate,
	spliceCommitmentNonceContext,
	updateVerificationNonce,
	type IFinalUpdateNonce
} from '../../../src/lightning/storage/final-update-signing';
import type { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';

/** The plain final Taproot type with no SCID alias bit (bit 80 alone). */
export const PLAIN_TYPE_HEX = '0100000000000000000000';
export const ASSET_TYPE_HEX = ASSET_SPLICE_RECOVERY_TYPE_HEX;

/** The refusal texts the contract names. */
export const TEXT = {
	original: 'Channel type records require an original conversion wallet',
	sameType: 'Channel type record does not change the type',
	state: 'Channel type record names a different state',
	splice:
		'Splices of a channel with a recorded type change are not supported yet',
	restore:
		'Restore of a channel with a recorded type change is not supported yet',
	behind: 'Peer reestablish is behind the channel type record',
	missing: 'Missing preceding revocation secret',
	mismatch: 'Revocation secret does not match previous commitment',
	inconsistent: 'Inconsistent peer revocation chain',
	nonce: 'Device nonce differs from persisted promise'
} as const;

export type ChannelKind = 'plain' | 'asset';
export type Shachain = IFinalLedgerState['shachain'];
type Funds = IFinalLedgerState['locked'];

export interface IFinalPlainSeedInput {
	local: { tx: string; signed: string; nextNonce: IFinalUpdateNonce };
	remote: { tx: string; nextNonce: IFinalUpdateNonce };
	localRevoke?: string;
	peerRevoke?: string;
	funds: Funds;
	nextLocalId: string;
	nextPeerId: string;
}
export interface IFinalAssetSeedInput {
	members: IAssetSpliceExitBranch[];
	feerate: number;
	nextLocalId: string;
	nextPeerId: string;
	htlcs: [];
	peerNextPoint: string;
	peerNonces: string[];
	localNonces: string[];
	localRevoke?: string;
	peerRevoke?: string;
	digest: string;
}
/** The writer's input: the record without `seed.shachain`, which the writer computes. */
export interface IChannelTypeRecordInput {
	kind: 'channel-type';
	type: ChannelKind;
	channelType: string;
	stateNumber: string;
	funding: IFinalFundingReference;
	parent: { txid: string; outputIndex: number };
	seed: IFinalPlainSeedInput | IFinalAssetSeedInput;
}
export type IChannelTypeRecord = Omit<IChannelTypeRecordInput, 'seed'> & {
	seed: (IFinalPlainSeedInput | IFinalAssetSeedInput) & { shachain: Shachain };
};
export interface IChannelTypeView {
	type: ChannelKind;
	channelType: string;
	source: 'opening' | 'record';
	stateNumber: bigint;
	funding: { txid: string; outputIndex: number };
	record?: IChannelTypeRecord;
}
/** The step 2a storage methods, read loosely. */
export interface IChannelTypeStorage {
	loadFinalChannelType(channelId: string): IChannelTypeView | null;
	appendFinalChannelType(
		channelId: string,
		input: IChannelTypeRecordInput
	): unknown;
	loadFinalChannelTypeRecords(channelId: string): IChannelTypeRecord[];
}
export function typed(store: SqliteStorage): IChannelTypeStorage {
	return store as unknown as IChannelTypeStorage;
}

/**
 * The pure members the contract adds to src/lightning/storage, loaded on use
 * so a missing module fails the test that needs it and not the whole file.
 * Names the contract leaves open are assumed here, in one place:
 * - final-channel-type.ts exports canonicalFinalChannelTypeRecord (named) and
 *   finalAssetSeedDigest(channelId, isInitiator, input), which returns the
 *   symmetric `beignet/channel-type-seed/v1` digest in hex for an asset
 *   record input (its `seed.digest` ignored);
 * - final-channel-updates.ts exports seedFinalLedger (named) and
 *   finalSeedShachain({ prior, secrets, stateNumber }), the writer's pure
 *   shachain step: it extends `prior` (a previous record's shachain, or
 *   none) with each { height, secret, point } through rememberRevocation and
 *   refuses a missing height, a secret whose point differs and an
 *   inconsistent chain.
 */
export interface IStep2aPure {
	canonicalFinalChannelTypeRecord(
		record: IChannelTypeRecord
	): IChannelTypeRecord;
	finalAssetSeedDigest(
		channelId: string,
		isInitiator: boolean,
		input: IChannelTypeRecordInput
	): string;
	seedFinalLedger(input: {
		candidate: IFinalOpeningCandidate;
		nonces: unknown;
		record: IChannelTypeRecord;
		peerPoints: [Buffer, Buffer];
	}): IFinalLedgerState;
	finalSeedShachain(input: {
		prior?: Shachain;
		secrets: { height: number; secret: Buffer; point: Buffer }[];
		stateNumber: number;
	}): Shachain;
}
export function step2a(): IStep2aPure {
	const load = (name: string): Record<string, unknown> => {
		try {
			return require('../../../src/lightning/storage/' + name) as Record<
				string,
				unknown
			>;
		} catch {
			return {};
		}
	};
	const type = load('final-channel-type'),
		updates = load('final-channel-updates');
	const need = (from: Record<string, unknown>, name: string) =>
		((...args: unknown[]) => {
			const f = from[name];
			if (typeof f !== 'function')
				throw new TypeError(name + ' is not a function');
			return (f as (...a: unknown[]) => unknown)(...args);
		}) as never;
	return {
		canonicalFinalChannelTypeRecord: need(
			type,
			'canonicalFinalChannelTypeRecord'
		),
		finalAssetSeedDigest: need(type, 'finalAssetSeedDigest'),
		seedFinalLedger: need(updates, 'seedFinalLedger'),
		finalSeedShachain: need(updates, 'finalSeedShachain')
	};
}

/** A refusal raised by the code under test, not by a missing name. */
export function expectRefusal(run: () => unknown, text?: string | RegExp) {
	let error: Error | undefined;
	try {
		run();
	} catch (e) {
		error = e as Error;
	}
	expect(error, 'expected a refusal').to.be.instanceOf(Error);
	expect(error!.message).to.not.match(
		/is not a function|Cannot read propert|is not defined/
	);
	if (typeof text === 'string') expect(error!.message).to.equal(text);
	else if (text) expect(error!.message).to.match(text);
	return error!;
}
export async function expectRejection(
	run: () => Promise<unknown>,
	text?: string | RegExp
) {
	let error: Error | undefined;
	try {
		await run();
	} catch (e) {
		error = e as Error;
	}
	return expectRefusal(() => {
		if (error) throw error;
	}, text);
}

export function deviceAuthority(store: SqliteStorage): FinalOpeningAuthority {
	return (store as unknown as { openingAuthority: FinalOpeningAuthority })
		.openingAuthority;
}

/** One original device of a channel. */
export interface ITypeDevice {
	store: SqliteStorage;
	root: BIP32Interface;
}

/** The opening as a plain opening of the same terms: plain type, rootless funding script. */
export function plainTwin(c: IFinalOpeningCandidate): IFinalOpeningCandidate {
	const tx = Transaction.fromHex(c.fundingTxHex);
	tx.outs[c.fundingOutputIndex].script = createTaprootFundingScript(
		Buffer.from(c.localFundingPubkey, 'hex'),
		Buffer.from(c.remoteFundingPubkey, 'hex')
	).p2trOutput;
	return { ...c, channelType: PLAIN_TYPE_HEX, fundingTxHex: tx.toHex() };
}
/** The root a twin asset opening's own funding script carries. */
export const TWIN_ROOT = Buffer.alloc(32, 0x5a);
/** The opening as an asset opening of the same terms: recovery type, funding script under TWIN_ROOT. */
export function assetTwin(c: IFinalOpeningCandidate): IFinalOpeningCandidate {
	const tx = Transaction.fromHex(c.fundingTxHex);
	tx.outs[c.fundingOutputIndex].script = createTaprootFundingScript(
		Buffer.from(c.localFundingPubkey, 'hex'),
		Buffer.from(c.remoteFundingPubkey, 'hex'),
		undefined,
		TWIN_ROOT
	).p2trOutput;
	return { ...c, channelType: ASSET_TYPE_HEX, fundingTxHex: tx.toHex() };
}

export const LEAVES = {
	toLocal: { script: Buffer.from('6a01aa', 'hex') },
	toRemote: { script: Buffer.from('6a01bb', 'hex') }
};
const TRANSCRIPT = Buffer.alloc(32, 0x71);

export interface IConversionOptions {
	type: ChannelKind;
	/** The record's state number N; both ledgers must be at N. */
	stateNumber: number;
	/** The live funding the record replaces. */
	parent: { tx: Transaction; index: number };
	/** Satoshis the new funding pays in fee, taken from the opener's balance. */
	fee?: number;
	feerate?: number;
	root?: Buffer;
	/** Key indices of the new funding; allocated on each device by default. */
	keyIndices?: [number, number];
	/** Balances in msat from each device's side, by default the opening's less the fee. */
	balances?: [IBalances, IBalances];
}
export interface IBalances {
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
}

export interface IConversion {
	id: string;
	type: ChannelKind;
	stateNumber: number;
	tx: Transaction;
	refs: [IFinalFundingReference, IFinalFundingReference];
	keyIndices: [number, number];
	root?: Buffer;
	balances: [IBalances, IBalances];
	/** The per-commitment point of device i's own commitment at height h. */
	point(i: number, h: number): Buffer;
	/** Device i's splice-source verification nonce of the new funding at height h. */
	nonceAt(i: number, h: number): string;
	/** The writer input for each device. */
	inputs: [IChannelTypeRecordInput, IChannelTypeRecordInput];
	/** Rebuild device i's view of a holder's commitment at N with other balances, point or feerate. */
	view(
		i: number,
		holder: 'local' | 'remote',
		change?: { balances?: IBalances; point?: Buffer; feerate?: number }
	): IFinalCommitmentView;
}

function openingOf(store: SqliteStorage, id: string) {
	const record = store.loadFinalDaemonOpening(id);
	if (!record) throw new Error('fixture: no funded opening');
	return record;
}

/** The old era's revoke_and_ack bytes completing round N, when N >= 1. */
function oldRevocations(
	store: SqliteStorage,
	id: string,
	n: number,
	oldType: ChannelKind
): { localRevoke?: string; peerRevoke?: string } {
	if (n === 0) return {};
	if (oldType === 'asset') {
		const stages = assetUpdateHistory(store, id).stages;
		return {
			localRevoke: stages.get(n + '/local-revoke'),
			peerRevoke: stages.get(n + '/peer-revoke')
		};
	}
	const state = (
		store as unknown as {
			finalUpdateView(id: string): { state: IFinalLedgerState } | null;
		}
	).finalUpdateView(id)?.state;
	return {
		localRevoke: state?.local.revoke,
		peerRevoke: state?.remote.revoke
	};
}
function oldNextIds(
	store: SqliteStorage,
	id: string,
	oldType: ChannelKind
): { nextLocalId: string; nextPeerId: string } {
	if (oldType === 'asset') {
		const head = assetSpliceUpdateHead(store, id);
		return {
			nextLocalId: String(head.nextLocalId),
			nextPeerId: String(head.nextPeerId)
		};
	}
	const state = (
		store as unknown as {
			finalUpdateView(id: string): { state: IFinalLedgerState } | null;
		}
	).finalUpdateView(id)?.state;
	return {
		nextLocalId: state?.nextLocalId ?? '0',
		nextPeerId: state?.nextPeerId ?? '0'
	};
}

/**
 * Build both devices' record inputs for a change to `o.type` at N on a new
 * funding output that spends `o.parent`. The old type is the one the opening
 * gives unless `oldType` names it.
 */
export function buildConversion(
	devices: readonly ITypeDevice[],
	id: string,
	o: IConversionOptions,
	oldType?: ChannelKind
): IConversion {
	const n = o.stateNumber;
	const openings = devices.map((d) => openingOf(d.store, id));
	const was: ChannelKind =
		oldType ??
		(openings[0].session.assetEvidence ||
		isAssetOpeningType(openings[0].candidate.channelType)
			? 'asset'
			: 'plain');
	const openKeys = devices.map((d, i) =>
		deriveChannelKeys(d.root, 1, openings[i].session.channelKeyIndex)
	);
	const keyIndices = (o.keyIndices ??
		devices.map((d) => d.store.allocateFinalChannelKeyIndex(2))) as [
		number,
		number
	];
	const keys = devices.map((d, i) =>
		deriveChannelKeys(d.root, 1, keyIndices[i])
	);
	const fee = o.fee ?? 600;
	const root =
		o.type === 'asset' ? o.root ?? Buffer.alloc(32, 0x3c) : undefined;
	const parentOut = o.parent.tx.outs[o.parent.index];
	const tx = new Transaction();
	tx.version = 2;
	tx.addInput(o.parent.tx.getHash(), o.parent.index, 0xfffffffd);
	tx.addOutput(
		createTaprootFundingScript(
			keys[0].channelBasepoints.fundingPubkey,
			keys[1].channelBasepoints.fundingPubkey,
			undefined,
			root
		).p2trOutput,
		parentOut.value - fee
	);
	const refs = devices.map(
		(_, i): IFinalFundingReference => ({
			fundingTxHex: tx.toHex(),
			fundingOutputIndex: 0,
			localFundingPubkey:
				keys[i].channelBasepoints.fundingPubkey.toString('hex'),
			remoteFundingPubkey:
				keys[1 - i].channelBasepoints.fundingPubkey.toString('hex'),
			localFundingKeyIndex: keyIndices[i]
		})
	) as [IFinalFundingReference, IFinalFundingReference];
	const balances = (o.balances ??
		openings.map(({ candidate: c }) => ({
			localBalanceMsat:
				(BigInt(c.localContributionSats) - (c.isInitiator ? BigInt(fee) : 0n)) *
				1000n,
			remoteBalanceMsat:
				(BigInt(c.remoteContributionSats) -
					(c.isInitiator ? 0n : BigInt(fee))) *
				1000n
		}))) as [IBalances, IBalances];
	const feerate = o.feerate ?? openings[0].session.terms.commitmentFeeratePerKw;
	const point = (i: number, h: number) =>
		getPublicKey(
			generateFromSeed(openKeys[i].perCommitmentSeed, MAX_INDEX - BigInt(h))
		);
	const nonceKey = spliceCommitmentNonceContext(id, tx.getHash(), 0);
	const nonceAt = (i: number, h: number) =>
		Buffer.from(
			updateVerificationNonce(
				deviceAuthority(devices[i].store).nonceContext(nonceKey),
				keys[i].fundingPrivkey,
				h,
				{ pub: '', source: 'splice' }
			)
		).toString('hex');
	// The candidate the new type's builder and the signer see.
	const twin = (i: number) => {
		const c = openings[i].candidate;
		if (o.type === 'plain')
			return isAssetOpeningType(c.channelType) ? plainTwin(c) : c;
		return isAssetOpeningType(c.channelType) ? c : assetTwin(c);
	};
	const openingRoot = (i: number) => {
		const c = openings[i].candidate;
		return isAssetOpeningType(c.channelType)
			? Buffer.from(openings[i].session.assetEvidence!.fundingRoot, 'hex')
			: TWIN_ROOT;
	};
	const view = (
		i: number,
		holder: 'local' | 'remote',
		change: { balances?: IBalances; point?: Buffer; feerate?: number } = {}
	): IFinalCommitmentView => {
		const terms: IFinalOpeningTerms = {
			...openings[i].session.terms,
			commitmentFeeratePerKw: change.feerate ?? feerate
		};
		const p = change.point ?? point(holder === 'local' ? i : 1 - i, n);
		const b = change.balances ?? balances[i];
		return o.type === 'plain'
			? buildFinalCommitmentView(
					twin(i),
					terms,
					holder,
					p,
					BigInt(n),
					b,
					[],
					refs[i]
			  )
			: buildAssetSpliceCommitment(
					twin(i),
					terms,
					holder,
					p,
					BigInt(n),
					b,
					[],
					refs[i],
					openingRoot(i),
					{ fundingRoot: root!, ...LEAVES }
			  );
	};
	const asset =
		o.type === 'asset'
			? { fundingRoot: root!, transcriptDigest: TRANSCRIPT }
			: undefined;
	// Each holder's local commitment at N, signed by the peer and aggregated by the holder.
	const signedLocal = devices.map((_, i) => {
		const j = 1 - i;
		const promise = nonceAt(i, n);
		const remote = view(j, 'remote');
		expect(remote.tx.toHex(), 'both views of commitment ' + i).to.equal(
			view(i, 'local').tx.toHex()
		);
		const wire = signFinalUpdate(
			twin(j),
			remote,
			point(i, n),
			n,
			{ pub: promise },
			openKeys[j],
			deviceAuthority(devices[j].store),
			nonceKey,
			[],
			undefined,
			{ reference: refs[j], privateKey: keys[j].fundingPrivkey, asset }
		);
		const raw = signFinalUpdate(
			twin(i),
			view(i, 'local'),
			point(i, n),
			n,
			{ pub: promise, source: 'splice' },
			openKeys[i],
			deviceAuthority(devices[i].store),
			nonceKey,
			[],
			wire,
			{ reference: refs[i], privateKey: keys[i].fundingPrivkey, asset }
		);
		return { tx: raw.toString('hex'), signed: wire.toString('hex') };
	});
	const inputs = devices.map((d, i): IChannelTypeRecordInput => {
		const revocations = oldRevocations(d.store, id, n, was);
		const ids = oldNextIds(d.store, id, was);
		const base = {
			kind: 'channel-type' as const,
			type: o.type,
			channelType: o.type === 'plain' ? PLAIN_TYPE_HEX : ASSET_TYPE_HEX,
			stateNumber: String(n),
			funding: refs[i],
			parent: { txid: o.parent.tx.getId(), outputIndex: o.parent.index }
		};
		if (o.type === 'plain')
			return {
				...base,
				seed: {
					local: {
						...signedLocal[i],
						nextNonce: { pub: nonceAt(i, n + 1), source: 'splice' }
					},
					remote: {
						tx: view(i, 'remote').tx.toHex(),
						nextNonce: { pub: nonceAt(1 - i, n + 1) }
					},
					...revocations,
					funds: {
						feeratePerKw: feerate,
						local: String(balances[i].localBalanceMsat),
						peer: String(balances[i].remoteBalanceMsat),
						htlcs: []
					},
					...ids
				}
			};
		const recovery = (holder: number) => {
			const built = view(i, holder === i ? 'local' : 'remote');
			return {
				point: point(holder, n).toString('hex'),
				localBalanceMsat: String(balances[i].localBalanceMsat),
				remoteBalanceMsat: String(balances[i].remoteBalanceMsat),
				toLocal: { script: '6a01aa' },
				toRemote: { script: '6a01bb' },
				ownedOutputIndex:
					(holder === i ? built.outputMap.toLocal : built.outputMap.toRemote) ??
					null,
				htlcs: []
			};
		};
		const member: IAssetSpliceExitBranch = {
			minimumDepth: openings[i].candidate.minimumDepth,
			funding: refs[i],
			localRecovery: recovery(i),
			remoteRecovery: recovery(1 - i),
			fundingTxid: tx.getId(),
			outputIndex: 0,
			fundingRoot: root!.toString('hex'),
			fundingProofs: 'c0d1',
			localCommitment: signedLocal[i].tx,
			localProofs: 'c' + (i + 1),
			remoteCommitment: view(i, 'remote').tx.toHex(),
			remoteProofs: 'c' + (2 - i)
		};
		const input: IChannelTypeRecordInput = {
			...base,
			seed: {
				members: [member],
				feerate,
				...ids,
				htlcs: [],
				peerNextPoint: point(1 - i, n + 1).toString('hex'),
				peerNonces: [nonceAt(1 - i, n + 1)],
				localNonces: [nonceAt(i, n + 1)],
				...revocations,
				digest: '00'.repeat(32)
			}
		};
		try {
			(input.seed as IFinalAssetSeedInput).digest =
				step2a().finalAssetSeedDigest(
					id,
					openings[i].candidate.isInitiator,
					input
				);
		} catch {
			// The base has no digest helper; the record is refused there anyway.
		}
		return input;
	}) as [IChannelTypeRecordInput, IChannelTypeRecordInput];
	return {
		id,
		type: o.type,
		stateNumber: n,
		tx,
		refs,
		keyIndices,
		root,
		balances,
		point,
		nonceAt,
		inputs,
		view
	};
}

/** Append each device's record, as Step 5 will at adoption. */
export function appendBoth(
	devices: readonly ITypeDevice[],
	c: IConversion
): void {
	devices.forEach((d, i) =>
		typed(d.store).appendFinalChannelType(c.id, c.inputs[i])
	);
}

/** A deep copy of an input, for a test that changes one field. */
export function copyInput(i: IChannelTypeRecordInput): IChannelTypeRecordInput {
	return JSON.parse(JSON.stringify(i)) as IChannelTypeRecordInput;
}

/** The opening's funding outpoint. */
export function openingParent(store: SqliteStorage, id: string) {
	const c = store.loadFinalOpening(id)!;
	return {
		tx: Transaction.fromHex(c.fundingTxHex),
		index: c.fundingOutputIndex
	};
}

/** Run asset rounds from the current height to `to`, each a fee change, as signUpdatedFee does. */
export async function assetRounds(
	devices: readonly ITypeDevice[],
	id: string,
	to: number,
	feerate = (h: number) => 1100 + h
): Promise<void> {
	const { assetUpdateTestHost } = await import('./asset-splice-update');
	const from = Number(assetSpliceUpdateHead(devices[0].store, id).nextNumber);
	for (let h = from; h <= to; h++) {
		const rounds = devices.map((d) =>
			d.store.assetSpliceUpdateBatch(
				id,
				d.root,
				BigInt(h),
				[{ kind: 'fee', feeratePerKw: feerate(h) }],
				() => 600000
			)
		);
		const hosts = rounds.map((_, i) => assetUpdateTestHost(i, [], 1));
		const offers = rounds.map((r) => r.offer());
		rounds.forEach((r, i) => r.acceptOffer(offers[1 - i]));
		const joint = (await Promise.all(
			rounds.map((r, i) => r.signAssetShares(hosts[i]))
		)) as [Buffer, Buffer];
		const children = (await Promise.all(
			rounds.map((r, i) => r.signAssetHtlcs(hosts[i], joint))
		)) as [Buffer, Buffer];
		await Promise.all(
			rounds.map((r, i) => r.verifyAssetShares(hosts[i], joint, children))
		);
		const commitments = rounds.map((r) => r.commitments());
		await Promise.all(
			rounds.map((r, i) => r.acceptCommitments(hosts[i], commitments[1 - i]))
		);
		const revokes = rounds.map((r) => r.revocation());
		rounds.forEach((r, i) => r.receiveRevocation(revokes[1 - i]));
	}
}

/** Run plain rounds through the storage update API, each an update_fee from the opener. */
export function plainRounds(
	devices: readonly ITypeDevice[],
	id: string,
	rounds: number,
	feerate = (r: number) => 300 + r
): void {
	const stores = devices.map((d) => d.store);
	const opener = stores[0].loadFinalOpening(id)!.isInitiator ? 0 : 1;
	const exchange = (from: number) => {
		const sig = stores[from].signFinalUpdateCommitment(id, devices[from].root);
		const ack = stores[1 - from].acceptFinalUpdateCommitment(
			id,
			devices[1 - from].root,
			sig
		);
		stores[from].acceptFinalUpdateRevocation(id, ack);
	};
	for (let r = 0; r < rounds; r++) {
		const wire = encodeUpdateFeeMessage({
			channelId: Buffer.from(id, 'hex'),
			feeratePerKw: feerate(r)
		});
		stores[opener].stageFinalHtlcUpdate(id, 'local', M.UPDATE_FEE, wire);
		stores[1 - opener].stageFinalHtlcUpdate(id, 'peer', M.UPDATE_FEE, wire);
		exchange(opener);
		exchange(1 - opener);
		for (const store of stores)
			for (const event of store.loadFinalUpdateDeliveries(id))
				store.ackFinalUpdateDelivery(id, event.id);
	}
}
