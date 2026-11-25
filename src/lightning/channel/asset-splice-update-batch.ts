import { assetReconnectReservation } from '../storage/asset-splice-reestablish';
import {
	encodeAssetUpdateIntent,
	decodeAssetUpdateIntent
} from './asset-splice-update-intent';
import { Transaction } from 'bitcoinjs-lib';
import type { BIP32Interface } from 'bip32';
import { deserialize, serialize } from 'v8';
import { ecc } from '../../utils/ecc';
import { sha256 } from '../crypto/provider';
import { getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import { derivePrivateKey } from '../keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../keys/shachain';
import { deriveChannelKeys, deriveLightningKeys } from '../keys/wallet-keys';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage,
	encodeRevokeAndAckMessage
} from '../message/channel-commitment';
import { MAX_LIGHTNING_PAYLOAD } from '../message/custom-records';
import { decodeTxCompleteMessage } from '../message/interactive-tx';
import { MessageType as M } from '../message/types';
import type { AssetSpliceConstructionEvent } from './asset-splice-construction';
import { ASSET_OPEN_OBJECT_LIMIT } from '../message/asset-open';
import {
	startCommitmentSigningSession,
	verifyPartialCommitmentSig
} from './commitment-musig';
import {
	signTaprootHtlcLeaf,
	verifyTaprootHtlcLeaf
} from '../script/htlc-taproot';
import type { ITaprootAuxLeaf } from '../script/commitment-taproot';
import type { SqliteStorage } from '../storage/sqlite-storage';
import type { FinalOpeningAuthority } from '../storage/final-opening-authority';
import {
	checkUpdateNonce,
	spliceCommitmentNonceContext,
	updateVerificationNonce,
	signFinalUpdate
} from '../storage/final-update-signing';
import {
	assetUpdateHistory,
	type AssetUpdateEvent,
	type IAssetUpdateSecured
} from '../storage/asset-update-history';
import {
	spliceRecoveryView,
	type IAssetSpliceHolderRecovery
} from '../storage/asset-splice-recovery';
import type { IAssetSpliceExitBranch } from '../storage/asset-splice-exit-proofs';
import { buildAssetSpliceCommitment } from './final-opening-commitment';
import type { AssetOpenPair } from './asset-opening-provider';
import type {
	AssetUpdateChange,
	IAssetUpdateMemberEvidence,
	IAssetUpdateRound,
	IAssetSpliceUpdateHost,
	IAssetUpdateHolderEvidence,
	IAssetUpdateSignedMember
} from './asset-splice-update-provider';
import {
	assetUpdateSources,
	applyAssetChanges,
	fundingPoint,
	saveUpdateHtlc,
	type UpdateSource
} from './asset-splice-update-ledger';

type Stage = Extract<AssetUpdateEvent, { kind: 'asset-update-stage' }>['stage'];
type Side = 'local' | 'remote';
interface Offer {
	digest: string;
	point: string;
	nonces: string[];
	signature: string;
}
const hex = (b: Buffer) => b.toString('hex');
const bytes = (s: string) => Buffer.from(s, 'hex');
const pack = (v: unknown) => Buffer.from(JSON.stringify(v));
const clone = <T>(v: T): T => deserialize(serialize(v)) as T;
function tagHash(prefix: string, raw: Buffer) {
	return sha256(Buffer.concat([Buffer.from(prefix + '\0'), raw]));
}
function bounded(b: Buffer, limit = ASSET_OPEN_OBJECT_LIMIT) {
	if (!Buffer.isBuffer(b) || !b.length || b.length > limit)
		throw new Error('Invalid asset update payload size');
	return b;
}
function encodedLeaf(v: ITaprootAuxLeaf | undefined) {
	if (!v) return null;
	if (
		!Buffer.isBuffer(v.script) ||
		!v.script.length ||
		v.script.length > 10000 ||
		(v.leafVersion !== undefined &&
			(!Number.isSafeInteger(v.leafVersion) ||
				v.leafVersion < 0 ||
				v.leafVersion > 254 ||
				v.leafVersion % 2))
	)
		throw new Error('Invalid asset update leaf');
	return {
		script: hex(v.script),
		...(v.leafVersion !== undefined && { leafVersion: v.leafVersion })
	};
}
function storeHolder(v: IAssetUpdateHolderEvidence) {
	return {
		toLocal: encodedLeaf(v.toLocal),
		toRemote: encodedLeaf(v.toRemote),
		proofs: hex(bounded(v.proofs)),
		record: hex(bounded(v.htlcSignatures, MAX_LIGHTNING_PAYLOAD)),
		htlcs: v.htlcs.map((h) => ({
			offeredBy: h.offeredBy,
			id: String(h.id),
			output: encodedLeaf(h.output)!,
			secondLevel: encodedLeaf(h.secondLevel)!
		}))
	};
}
type Stored = ReturnType<typeof storeHolder>;
function unpackHolder(s: Stored): IAssetUpdateHolderEvidence {
	const leaf = (v: Stored['toLocal']) =>
		v ? { script: bytes(v.script), leafVersion: v.leafVersion } : undefined;
	return {
		toLocal: leaf(s.toLocal),
		toRemote: leaf(s.toRemote),
		proofs: bytes(s.proofs),
		htlcSignatures: bytes(s.record),
		htlcs: s.htlcs.map((h) => ({
			id: BigInt(h.id),
			offeredBy: h.offeredBy,
			output: leaf(h.output)!,
			secondLevel: leaf(h.secondLevel)!
		}))
	};
}

/** The accepted funding sample expired while an otherwise current update was running. */
export class AssetUpdateFundingUnavailable extends Error {
	constructor() {
		super('Asset update requires live accepted funding');
	}
}

export class AssetSpliceUpdateBatch {
	private readonly opening;
	private readonly limits;
	private readonly originalRoot: Buffer;
	private readonly base;
	private readonly sources;
	private readonly prior;
	private readonly operations;
	private readonly next;
	private readonly digest: string;
	private readonly membership: string;
	private readonly peerPoint: Buffer;
	private readonly localPoint: Buffer;
	private readonly keys;
	private readonly sourceKeys: Buffer[];
	private readonly identity;

	constructor(
		private readonly store: SqliteStorage,
		private readonly authority: FinalOpeningAuthority,
		private readonly id: string,
		root: BIP32Interface,
		private readonly height: bigint,
		changes: readonly AssetUpdateChange[],
		private readonly currentHeight: () => number | undefined
	) {
		store.assertAssetSpliceAuthority(authority);
		if (typeof height !== 'bigint' || height < 1n || height >= MAX_INDEX)
			throw new Error('Invalid asset commitment height');
		const history = assetUpdateHistory(store, id);
		if (history.latest && BigInt(history.latest.height) > height)
			throw new Error('Asset update height already superseded');
		this.prior = history.states.get(height - 1n);
		if (
			height > 1n &&
			(!this.prior ||
				!history.stages.has(height - 1n + '/peer-revoke') ||
				!history.stages.has(height - 1n + '/local-revoke'))
		)
			throw new Error('Previous asset update is not bilaterally irrevocable');
		const { opening, sources } = assetUpdateSources(store, id, this.prior);
		this.opening = opening;
		this.sources = sources;
		this.membership = this.fundingMembership();
		this.originalRoot = bytes(opening.session.assetEvidence!.fundingRoot);
		this.identity = deriveLightningKeys(root, 1);
		store.assertFinalDaemonIdentity(hex(this.identity.nodePublicKey));
		this.keys = deriveChannelKeys(root, 1, opening.session.channelKeyIndex);
		this.sourceKeys = sources.map((s) => {
			const key = deriveChannelKeys(root, 1, s.funding.localFundingKeyIndex);
			if (
				hex(key.channelBasepoints.fundingPubkey) !==
				s.funding.localFundingPubkey
			)
				throw new Error('Asset update uses a different local funding locator');
			return key.fundingPrivkey;
		});
		this.base = opening.session.terms;
		this.limits = opening.session.updateLimits!;
		const previous = history.stages.get(height - 1n + '/peer-revoke');
		const point = previous
			? decodeRevokeAndAckMessage(bytes(previous), { finalTaproot: true })
					.nextPerCommitmentPoint
			: bytes(opening.session.remoteSecondPerCommitmentPoint ?? '');
		if (!isValidPublicKey(point))
			throw new Error('Missing authenticated next holder point');
		this.peerPoint = point;
		this.localPoint = this.point(height);
		this.operations = decodeAssetUpdateIntent(
			id,
			opening.candidate.isInitiator,
			encodeAssetUpdateIntent(id, opening.candidate.isInitiator, changes)
		);
		this.next = applyAssetChanges(
			this.operations,
			this.prior,
			sources,
			opening.candidate,
			this.base,
			this.limits,
			this.block()
		);
		const op = opening.candidate.isInitiator;
		const members = sources.map((s) => [
			fundingPoint(s.funding),
			s.root,
			...(op
				? [s.localBalanceMsat, s.remoteBalanceMsat]
				: [s.remoteBalanceMsat, s.localBalanceMsat]
			).map(String)
		]);
		this.digest = hex(
			tagHash(
				'asset-update-batch/v1',
				pack([
					id,
					String(height),
					this.prior?.digest ?? null,
					this.next.feerate,
					this.next.signedChanges,
					op
						? [hex(this.localPoint), hex(point)]
						: [hex(point), hex(this.localPoint)],
					members
				])
			)
		);
		if (
			history.digests.has(height) &&
			history.digests.get(height) !== this.digest
		)
			throw new Error('Asset update conflicts with an existing round');
	}
	get fundingCount(): number {
		return this.sources.length;
	}
	private fundingMembership() {
		const history = this.store.readAssetSpliceJournal<{
			kind: string;
			index?: number;
			field?: string;
		}>(this.id).records;
		const ended = new Set(
			history
				.filter(
					(r) =>
						r.kind === 'peer-splice-stage' &&
						(r.field === 'retired' || r.field === 'assembled')
				)
				.map((r) => r.index)
		);
		if (history.some((r) => r.kind === 'peer-splice' && !ended.has(r.index)))
			throw new Error(
				'Asset update requires all splice construction and signing rounds to finish'
			);
		const info = this.store.loadAssetSpliceFundingInfo(this.id);
		if (info.reconciliation || info.awaitingImport)
			throw new Error('Asset funding is not settled');
		return JSON.stringify([
			info.active?.finalDigest ?? '',
			info.pending.map((e) => e.finalDigest).sort()
		]);
	}
	private point(height: bigint) {
		return getPublicKey(
			generateFromSeed(this.keys.perCommitmentSeed, MAX_INDEX - height)
		);
	}
	private block() {
		const h = this.currentHeight();
		if (h === undefined) throw new AssetUpdateFundingUnavailable();
		if (!Number.isSafeInteger(h) || h < 0)
			throw new Error('Invalid asset update chain height');
		return h;
	}
	private fresh() {
		this.store.assertAssetSpliceAuthority(this.authority);
		if (
			this.authority.exitRequest(this.id) ||
			this.membership !== this.fundingMembership()
		)
			throw new Error('Asset update funding changed or is closing');
		const h = this.block();
		if (this.next.htlcs.some((v) => v.cltvExpiry <= h + 18))
			throw new Error('Unresolved asset HTLC requires chain resolution');
		const j = assetUpdateHistory(this.store, this.id);
		if (
			(j.latest && BigInt(j.latest.height) > this.height) ||
			(j.digests.has(this.height) && j.digests.get(this.height) !== this.digest)
		)
			throw new Error('Stale asset update signing height');
		return j;
	}
	private stage(name: Stage) {
		const s = this.fresh().stages.get(this.height + '/' + name);
		return s ? bytes(s) : undefined;
	}
	private save(name: Stage, raw: Buffer) {
		const old = this.stage(name);
		if (old) {
			if (!old.equals(raw)) throw new Error('Conflicting asset update replay');
			return Buffer.from(old);
		}
		const head = this.store.readAssetSpliceJournal(this.id);
		this.store.appendAssetSpliceEvent(this.id, head, {
			kind: 'asset-update-stage',
			id: this.id,
			digest: this.digest,
			height: String(this.height),
			stage: name,
			bytes: hex(raw)
		} satisfies AssetUpdateEvent);
		return Buffer.from(raw);
	}
	private context(s: UpdateSource) {
		return spliceCommitmentNonceContext(
			this.id,
			Transaction.fromHex(s.funding.fundingTxHex).getHash(),
			s.funding.fundingOutputIndex
		);
	}
	private reservation(i: number, h: bigint) {
		const txid = Transaction.fromHex(
			this.sources[i].funding.fundingTxHex
		).getId();
		return (
			assetReconnectReservation(this.store, this.id, true, h, txid) ?? {
				source: 'splice' as const,
				pub: ''
			}
		);
	}
	private nonce(i: number, h = this.height) {
		return Buffer.from(
			updateVerificationNonce(
				this.authority.nonceContext(this.context(this.sources[i])),
				this.sourceKeys[i],
				Number(h),
				this.reservation(i, h)
			)
		);
	}
	private checkOffer(raw: Buffer, local: boolean): Offer {
		const value = JSON.parse(bounded(raw, 8192).toString()) as Offer;
		const { digest, point, nonces, signature } = value;
		if (
			!pack({ digest, point, nonces, signature }).equals(raw) ||
			digest !== this.digest ||
			point !== hex(local ? this.localPoint : this.peerPoint) ||
			!Array.isArray(nonces) ||
			nonces.length !== this.sources.length ||
			new Set(nonces).size !== nonces.length ||
			typeof signature !== 'string' ||
			!/^[0-9a-f]{128}$/.test(signature)
		)
			throw new Error('Asset update peer membership or holder point differs');
		const previous =
			!local &&
			assetUpdateHistory(this.store, this.id).stages.get(
				this.height - 1n + '/peer-revoke'
			);
		const promised = previous
			? decodeRevokeAndAckMessage(bytes(previous), { finalTaproot: true })
					.nextLocalNonces
			: undefined;
		for (const [i, n] of nonces.entries()) {
			const hash = Transaction.fromHex(
				this.sources[i].funding.fundingTxHex
			).getHash();
			let expected = promised?.find((e) => e.fundingTxid.equals(hash))?.nonce;
			if (previous && !expected) {
				const txid = Transaction.fromHex(
					this.sources[i].funding.fundingTxHex
				).getId();
				const frames =
					this.store.readAssetSpliceJournal<AssetSpliceConstructionEvent>(
						this.id
					).records;
				const final = frames
					.filter(
						(f) =>
							f.kind === 'construction-frame' &&
							f.txid === txid &&
							!f.local &&
							f.type === M.TX_COMPLETE
					)
					.at(-1);
				if (final?.kind === 'construction-frame')
					expected = decodeTxCompleteMessage(bytes(final.payload), {
						taproot: true
					}).commitNonces?.next;
			}
			const reconnect =
				!local &&
				assetReconnectReservation(
					this.store,
					this.id,
					false,
					this.height,
					hex(Buffer.from(hash).reverse())
				);
			if (
				reconnect
					? reconnect.pub !== n
					: previous && (!expected || hex(expected) !== n)
			)
				throw new Error(
					'Peer changed the previously promised asset update funding nonce'
				);
			checkUpdateNonce(bytes(n));
			if (n !== hex(bytes(n)) || local !== (n === hex(this.nonce(i))))
				throw new Error('Invalid or reflected asset update nonce');
		}
		const pub = local
			? this.identity.nodePublicKey
			: bytes(this.opening.session.peer);
		if (
			!ecc.verifySchnorr(
				tagHash(
					'asset-update-device-offer/v1',
					pack({ digest, point, nonces })
				),
				pub.subarray(1),
				bytes(signature)
			)
		)
			throw new Error(
				'Missing original device funding membership acknowledgment'
			);
		return value;
	}
	offer(): Buffer {
		this.save(
			'intent',
			encodeAssetUpdateIntent(
				this.id,
				this.opening.candidate.isInitiator,
				this.operations
			)
		);
		const old = this.stage('offer');
		if (old) {
			this.checkOffer(old, true);
			return old;
		}
		const data = {
			digest: this.digest,
			point: hex(this.localPoint),
			nonces: this.sources.map((_, i) => hex(this.nonce(i)))
		};
		return this.save(
			'offer',
			pack({
				...data,
				signature: hex(
					Buffer.from(
						ecc.signSchnorr(
							tagHash('asset-update-device-offer/v1', pack(data)),
							this.identity.nodePrivateKey
						)
					)
				)
			})
		);
	}
	acceptOffer(raw: Buffer) {
		this.checkOffer(raw, false);
		this.offer();
		this.save('peer-offer', raw);
	}
	private both() {
		const p = this.stage('peer-offer');
		if (!p || !this.stage('offer'))
			throw new Error(
				'Both devices must acknowledge the identical asset funding set'
			);
		return this.checkOffer(p, false);
	}
	private build(s: UpdateSource, side: Side, e?: IAssetUpdateHolderEvidence) {
		const point = side === 'local' ? this.localPoint : this.peerPoint;
		return buildAssetSpliceCommitment(
			this.opening.candidate,
			{ ...this.base, commitmentFeeratePerKw: this.next.feerate },
			side,
			point,
			this.height,
			s,
			this.next.htlcs,
			s.funding,
			this.originalRoot,
			{
				fundingRoot: bytes(s.root),
				toLocal: e?.toLocal,
				toRemote: e?.toRemote,
				htlcs: e?.htlcs
			}
		);
	}
	private request(): IAssetUpdateRound {
		const members = this.sources.map((s) => {
			const holder = (side: Side) => {
				const v = this.build(s, side);
				return {
					localBalanceMsat: s.localBalanceMsat,
					remoteBalanceMsat: s.remoteBalanceMsat,
					point: Buffer.from(
						side === 'local' ? this.localPoint : this.peerPoint
					),
					tx: v.tx,
					keys: v.keys,
					toSelfDelay: v.toSelfDelay,
					outputMap: v.outputMap,
					htlcs: clone(this.next.htlcs),
					htlcOutputs: v.htlcs
				};
			};
			return {
				outpoint: fundingPoint(s.funding),
				funding: { ...s.funding },
				fundingRoot: bytes(s.root),
				fundingProofs: bytes(s.proofs),
				local: holder('local'),
				remote: holder('remote')
			};
		});
		return {
			...(this.store.canRecoverAssetSplice && { walletGeneration: 5 as const }),
			channelId: this.id,
			localIsInitiator: this.opening.candidate.isInitiator,
			digest: bytes(this.digest),
			stateNumber: this.height,
			...(this.prior && { priorDigest: bytes(this.prior.digest) }),
			terms: { ...clone(this.base), commitmentFeeratePerKw: this.next.feerate },
			changes: clone(this.operations),
			members
		};
	}
	async signAssetShares(host: IAssetSpliceUpdateHost) {
		this.both();
		const old = this.stage('local-shares');
		if (old) return old;
		const raw = await host.signAssetUpdateViews(this.request());
		return this.save('local-shares', bounded(raw));
	}
	private ownedPair(
		phase: 'local-shares' | 'local-htlcs',
		shares: AssetOpenPair<Buffer>
	): AssetOpenPair<Buffer> {
		const ours = this.stage(phase);
		if (
			!ours ||
			shares.length !== 2 ||
			!ours.equals(shares[this.opening.candidate.isInitiator ? 0 : 1])
		)
			throw new Error('Missing local asset update consent');
		return [Buffer.from(bounded(shares[0])), Buffer.from(bounded(shares[1]))];
	}
	async signAssetHtlcs(
		host: IAssetSpliceUpdateHost,
		shares: AssetOpenPair<Buffer>
	) {
		this.both();
		const pair = this.ownedPair('local-shares', shares);
		const pairDigest = pack(pair.map((b) => hex(sha256(b))));
		const matched = this.stage('joint-shares');
		if (matched && !matched.equals(pairDigest))
			throw new Error('Conflicting asset joint shares');
		const old = this.stage('local-htlcs');
		if (old) {
			if (!matched) throw new Error('Missing signed joint share binding');
			return old;
		}
		let active = true;
		try {
			const raw = await host.signAssetUpdateHtlcs(this.request(), pair, {
				signHtlc: (hash, point, base, outpoint, dir, id, assetId) => {
					this.both();
					if (
						!active ||
						hash.length !== 32 ||
						!this.keys.channelBasepoints.htlcBasepoint.equals(base) ||
						(!point.equals(this.localPoint) && !point.equals(this.peerPoint)) ||
						!this.sources.some((s) => fundingPoint(s.funding) === outpoint) ||
						!this.next.htlcs.some(
							(h) =>
								h.offeredBy === dir &&
								h.id === id &&
								h.allocations.some((a) => a.assetId === assetId)
						)
					)
						throw new Error(
							'Asset HTLC signature request differs from its enrolled holder and issuance'
						);
					const slot = [
							'asset-update-htlc',
							this.id,
							String(this.height),
							outpoint,
							hex(point),
							dir,
							String(id),
							assetId
						].join('/'),
						digest = hex(hash);
					const cached = this.authority.claim(slot, digest);
					if (cached) return cached;
					return this.authority.finish(
						slot,
						digest,
						signTaprootHtlcLeaf(
							hash,
							derivePrivateKey(this.keys.htlcBasepointSecret, point, base)
						)
					);
				}
			});
			const result = Buffer.from(bounded(raw));
			this.save('joint-shares', pairDigest);
			return this.save('local-htlcs', result);
		} finally {
			active = false;
		}
	}
	private checkHolder(
		s: UpdateSource,
		side: Side,
		v: IAssetUpdateHolderEvidence
	) {
		const expected = this.next.htlcs.filter((h) => h.allocations.length);
		if (
			v.htlcs.length !== expected.length ||
			expected.some(
				(h) =>
					!v.htlcs.some((x) => x.id === h.id && x.offeredBy === h.offeredBy)
			)
		)
			throw new Error(
				'Asset update HTLC leaves differ from admitted obligations'
			);
		const view = this.build(s, side, v);
		encodeCommitmentSignedMessage({
			channelId: bytes(this.id),
			signature: Buffer.alloc(64),
			htlcSignatures: view.htlcs.map(() => Buffer.alloc(64)),
			fundingTxid: Transaction.fromHex(s.funding.fundingTxHex).getHash(),
			partialSignatureWithNonce: Buffer.alloc(98),
			customRecords: new Map([
				[65537n, bounded(v.htlcSignatures, MAX_LIGHTNING_PAYLOAD)]
			])
		});
		if (!v.toLocal && !v.toRemote && !v.htlcs.length)
			throw new Error('Missing asset commitment leaves');
		return view;
	}
	async verifyAssetShares(
		host: IAssetSpliceUpdateHost,
		shares: AssetOpenPair<Buffer>,
		htlcShares: AssetOpenPair<Buffer>
	) {
		this.both();
		const both = this.ownedPair('local-shares', shares),
			children = this.ownedPair('local-htlcs', htlcShares);
		const joint = this.stage('joint-shares');
		if (!joint || !joint.equals(pack(both.map((b) => hex(sha256(b))))))
			throw new Error('Asset HTLC shares require both exact joint shares');
		const verified = await host.verifyAssetUpdateViews(
			this.request(),
			both,
			children
		);
		this.fresh();
		if (verified.length !== this.sources.length)
			throw new Error('Incomplete asset proof batch');
		const members = this.sources.map((s, i) => {
			const v = verified[i];
			if (v.outpoint !== fundingPoint(s.funding))
				throw new Error('Asset proof funding order differs');
			this.checkHolder(s, 'local', v.local);
			this.checkHolder(s, 'remote', v.remote);
			return {
				outpoint: v.outpoint,
				local: storeHolder(v.local),
				remote: storeHolder(v.remote)
			};
		});
		this.save(
			'verified',
			bounded(
				pack({
					shares: [...both, ...children].map((b) => hex(sha256(b))),
					members
				}),
				8 * ASSET_OPEN_OBJECT_LIMIT
			)
		);
	}
	private evidence(): IAssetUpdateMemberEvidence[] {
		const v = this.stage('verified');
		if (!v) throw new Error('Missing verified asset update proof batch');
		return (
			JSON.parse(v.toString()).members as {
				outpoint: string;
				local: Stored;
				remote: Stored;
			}[]
		).map((m) => ({
			outpoint: m.outpoint,
			local: unpackHolder(m.local),
			remote: unpackHolder(m.remote)
		}));
	}
	private sign(
		i: number,
		e: IAssetUpdateHolderEvidence,
		verified: string,
		peer?: Buffer
	) {
		const s = this.sources[i],
			point = peer ? this.localPoint : this.peerPoint;
		return signFinalUpdate(
			this.opening.candidate,
			this.checkHolder(s, peer ? 'local' : 'remote', e),
			point,
			Number(this.height),
			{
				...(peer
					? this.reservation(i, this.height)
					: { source: 'splice' as const }),
				pub: peer ? hex(this.nonce(i)) : this.both().nonces[i]
			},
			this.keys,
			this.authority,
			this.context(s),
			[verified],
			peer,
			{
				reference: s.funding,
				privateKey: this.sourceKeys[i],
				asset: {
					fundingRoot: bytes(s.root),
					transcriptDigest: bytes(this.digest)
				}
			}
		);
	}
	commitments(): Buffer[] {
		const old = this.stage('local-commits');
		if (old) return (JSON.parse(old.toString()) as string[]).map(bytes);
		const ev = this.evidence(),
			verified = hex(sha256(this.stage('verified')!));
		const raw = ev.map((e, i) => {
			const bitcoin = this.sign(i, e.remote, verified);
			return encodeCommitmentSignedMessage({
				...decodeCommitmentSignedMessage(bitcoin),
				customRecords: new Map([[65537n, e.remote.htlcSignatures]])
			});
		});
		this.save('local-commits', pack(raw.map(hex)));
		return raw;
	}
	async acceptCommitments(
		host: IAssetSpliceUpdateHost,
		supplied: readonly Buffer[]
	) {
		const ev = this.evidence(),
			outs = this.commitments(),
			raw = supplied.map((x) => Buffer.from(bounded(x, MAX_LIGHTNING_PAYLOAD))),
			verified = hex(sha256(this.stage('verified')!));
		if (raw.length !== this.sources.length)
			throw new Error('Incomplete asset commitment batch');
		const ordered = this.sources.map((s, i) => {
			const decoded = decodeCommitmentSignedMessage(raw[i], {
				customRecords: true
			});
			if (
				!decoded.channelId.equals(bytes(this.id)) ||
				!decoded.fundingTxid?.equals(
					Transaction.fromHex(s.funding.fundingTxHex).getHash()
				) ||
				decoded.customRecords?.size !== 1 ||
				!decoded.customRecords
					.get(65537n)
					?.equals(ev[i].local.htlcSignatures) ||
				!encodeCommitmentSignedMessage(decoded).equals(raw[i])
			)
				throw new Error(
					'Wrong asset commitment funding tag, signatures or order'
				);
			// Fully verify the whole incoming set before any original-device nonce is consumed.
			const view = this.checkHolder(s, 'local', ev[i].local),
				funding = Transaction.fromHex(s.funding.fundingTxHex),
				coin = funding.outs[s.funding.fundingOutputIndex];
			const digest = view.tx.hashForWitnessV1(
					0,
					[coin.script],
					[coin.value],
					Transaction.SIGHASH_DEFAULT
				),
				partial = decoded.partialSignatureWithNonce;
			if (
				!partial ||
				partial.length !== 98 ||
				!decoded.signature.equals(Buffer.alloc(64)) ||
				decoded.htlcSignatures.length !== view.htlcs.length ||
				view.htlcs.some(
					(h, j) =>
						!verifyTaprootHtlcLeaf(
							h.digest,
							view.keys.remoteHtlcPubkey,
							decoded.htlcSignatures[j]
						)
				)
			)
				throw new Error('Invalid asset commitment or HTLC signature');
			const nonce = partial.subarray(32),
				promised = this.nonce(i);
			checkUpdateNonce(nonce);
			const peerKey = bytes(s.funding.remoteFundingPubkey),
				session = startCommitmentSigningSession(
					digest,
					bytes(s.funding.localFundingPubkey),
					peerKey,
					promised,
					nonce,
					bytes(s.root)
				);
			if (
				nonce.equals(promised) ||
				!verifyPartialCommitmentSig(
					session,
					partial.subarray(0, 32),
					peerKey,
					nonce
				)
			)
				throw new Error('Invalid asset commitment peer partial');
			return raw[i];
		});
		const old = this.fresh().states.get(this.height);
		if (old) {
			if (
				JSON.stringify(ordered.map(hex)) !== JSON.stringify(old.peerCommitments)
			)
				throw new Error('Conflicting secured asset update');
			return;
		}
		const exact: IAssetUpdateSignedMember[] = this.sources.map((s, i) => ({
			outpoint: fundingPoint(s.funding),
			local: Transaction.fromBuffer(
				this.sign(i, ev[i].local, verified, ordered[i])
			),
			remote: this.checkHolder(s, 'remote', ev[i].remote).tx,
			localEvidence: ev[i].local,
			remoteEvidence: ev[i].remote
		}));
		const members = this.sources.map((s, i) => {
			const holder = (side: Side): IAssetSpliceHolderRecovery => {
				const v = ev[i][side],
					view = this.checkHolder(s, side, v);
				return {
					point: hex(side === 'local' ? this.localPoint : this.peerPoint),
					localBalanceMsat: String(s.localBalanceMsat),
					remoteBalanceMsat: String(s.remoteBalanceMsat),
					toLocal: encodedLeaf(v.toLocal),
					toRemote: encodedLeaf(v.toRemote),
					ownedOutputIndex:
						(side === 'local'
							? view.outputMap.toLocal
							: view.outputMap.toRemote) ?? null,
					htlcs: this.next.htlcs.map((h) => {
						const htlc = view.htlcs.find(
								(x) => x.htlc.id === h.id && x.htlc.offeredBy === h.offeredBy
							),
							leaf = v.htlcs.find(
								(x) => x.id === h.id && x.offeredBy === h.offeredBy
							);
						return {
							id: String(h.id),
							offeredBy: h.offeredBy,
							amountMsat: String(h.amountMsat),
							paymentHash: hex(h.paymentHash),
							cltvExpiry: h.cltvExpiry,
							outputIndex: htlc?.outputIndex ?? null,
							outputLeaf: encodedLeaf(leaf?.output),
							secondLevelLeaf: encodedLeaf(leaf?.secondLevel)
						};
					})
				};
			};
			const b: IAssetSpliceExitBranch = {
				minimumDepth: s.minimumDepth,
				funding: { ...s.funding },
				fundingTxid: Transaction.fromHex(s.funding.fundingTxHex).getId(),
				outputIndex: s.funding.fundingOutputIndex,
				fundingRoot: s.root,
				fundingProofs: s.proofs,
				localCommitment: exact[i].local.toHex(),
				remoteCommitment: exact[i].remote.toHex(),
				localProofs: hex(ev[i].local.proofs),
				remoteProofs: hex(ev[i].remote.proofs),
				localRecovery: holder('local'),
				remoteRecovery: holder('remote')
			};
			for (const side of ['local', 'remote'] as const)
				spliceRecoveryView(
					this.opening.candidate,
					{ ...this.base, commitmentFeeratePerKw: this.next.feerate },
					hex(this.originalRoot),
					b,
					side,
					String(this.height)
				);
			return b;
		});
		await host.retainAssetUpdateViews(this.request(), exact);
		this.fresh();
		const secured: IAssetUpdateSecured = {
			kind: 'asset-update-secured',
			id: this.id,
			height: String(this.height),
			digest: this.digest,
			feerate: this.next.feerate,
			nextLocalId: String(this.next.next.local),
			nextPeerId: String(this.next.next.peer),
			htlcs: this.next.htlcs.map(saveUpdateHtlc),
			members,
			peerCommitments: ordered.map(hex),
			localCommitments: outs.map(hex)
		};
		const existing = this.fresh().states.get(this.height);
		if (existing) {
			if (JSON.stringify(existing) !== JSON.stringify(secured))
				throw new Error('Conflicting secured update receipt');
			return;
		}
		this.store.appendAssetSpliceEvent(
			this.id,
			this.store.readAssetSpliceJournal(this.id),
			secured
		);
	}
	revocation(): Buffer {
		const s = this.fresh().states.get(this.height);
		if (!s)
			throw new Error(
				'Cannot revoke before all asset exits and their recovery proofs are durable'
			);
		const exits = this.store
				.loadFinalFundingExits(this.id)
				.map((x) => hex(x.exit))
				.sort(),
			expected = s.members.map((b) => b.localCommitment).sort();
		if (JSON.stringify(exits) !== JSON.stringify(expected))
			throw new Error(
				'Current force-close path does not yet select every secured asset exit'
			);
		const raw = encodeRevokeAndAckMessage({
			channelId: bytes(this.id),
			perCommitmentSecret: generateFromSeed(
				this.keys.perCommitmentSeed,
				MAX_INDEX - (this.height - 1n)
			),
			nextPerCommitmentPoint: this.point(this.height + 1n),
			nextLocalNonces: this.sources.map((v, i) => ({
				fundingTxid: Transaction.fromHex(v.funding.fundingTxHex).getHash(),
				nonce: this.nonce(i, this.height + 1n)
			}))
		});
		return this.save('local-revoke', raw);
	}
	receiveRevocation(raw: Buffer) {
		const state = this.fresh().states.get(this.height);
		if (!state)
			throw new Error(
				'Asset update peer revocation arrived before a secured batch'
			);
		const m = decodeRevokeAndAckMessage(raw, { finalTaproot: true });
		const expected =
			this.prior?.members[0].remoteRecovery.point ??
			this.base.remoteBasepoints.firstPerCommitmentPoint;
		if (
			!encodeRevokeAndAckMessage(m).equals(raw) ||
			hex(m.channelId) !== this.id ||
			hex(getPublicKey(m.perCommitmentSecret)) !== expected ||
			!isValidPublicKey(m.nextPerCommitmentPoint) ||
			m.nextPerCommitmentPoint.equals(this.peerPoint) ||
			m.nextLocalNonces?.length !== this.sources.length
		)
			throw new Error('Invalid asset update peer revocation');
		const seen = new Set(this.both().nonces);
		for (const [i, v] of m.nextLocalNonces.entries()) {
			checkUpdateNonce(v.nonce);
			if (
				seen.has(hex(v.nonce)) ||
				!v.fundingTxid.equals(
					Transaction.fromHex(this.sources[i].funding.fundingTxHex).getHash()
				)
			)
				throw new Error('Invalid asset update next funding nonces');
			seen.add(hex(v.nonce));
		}
		this.save('peer-revoke', raw);
	}
}
