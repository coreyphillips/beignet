import { deserialize, serialize } from 'v8';
import {
	assetUpdateFundingMembers,
	assetUpdateHistory
} from '../storage/asset-update-history';
import type {
	IAssetUpdateHtlcSigner,
	IAssetUpdateHtlc,
	IAssetUpdateHolderView
} from './asset-splice-update-provider';
import { readUpdateHtlc } from './asset-splice-update-ledger';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../message/channel-commitment';
import { derivePrivateKey } from '../keys/derivation';
import { signTaprootHtlcLeaf } from '../script/htlc-taproot';
import type { BIP32Interface } from 'bip32';
import { Transaction } from 'bitcoinjs-lib';
import { isDeepStrictEqual } from 'util';
import { deriveChannelKeys, deriveLightningKeys } from '../keys/wallet-keys';
import { ASSET_OPEN_OBJECT_LIMIT } from '../message/asset-open';
import { encodeTxCompleteMessage } from '../message/interactive-tx';
import { MessageType as M } from '../message/types';
import { sha256 } from '../crypto/provider';
import type { FinalOpeningAuthority } from '../storage/final-opening-authority';
import type { FinalFundingWitnessSigner } from '../storage/final-opening-funding';
import {
	loadAssetSpliceExitProofs,
	retainAssetSpliceExitProofs,
	type IAssetSpliceExitProofs,
	type IAssetSpliceExitBranch
} from '../storage/asset-splice-exit-proofs';
import { spliceRecoveryView } from '../storage/asset-splice-recovery';
import {
	spliceCommitmentNonceContext,
	updateVerificationNonce,
	signFinalUpdate
} from '../storage/final-update-signing';
import { assetSpliceSignatureFrame } from '../storage/asset-splice-release-replay';
import type { SqliteStorage } from '../storage/sqlite-storage';
import type { AssetOpenPair, IAssetOpenExit } from './asset-opening-provider';
import type { IAssetSpliceContext } from './asset-splice-agreement';
import { AssetSpliceConstruction } from './asset-splice-construction';
import {
	assetSpliceConstructionView,
	type IAssetSpliceLayout,
	type verifyAssetSpliceCandidate
} from './asset-splice-manifest';
import { validateFinalSpliceReserves } from './final-commitment-reserve';
import { buildAssetSpliceCommitment } from './final-opening-commitment';
import {
	buildFinalSpliceCandidate,
	type IFinalFundingReference,
	type IFinalSpliceTerms
} from './final-splice-candidate';
import { validateFinalSpliceExit } from './final-splice-exits';
import {
	assembleFinalSplice,
	finalSpliceSharedNonce,
	signAssetSpliceFunding,
	verifyFinalSpliceContribution
} from './final-splice-funding';

type Holder = 'local' | 'remote';
type Branch = 'parent' | 'candidate';
type Both<T> = Record<Branch, Record<Holder, T>>;
type Verified = ReturnType<typeof verifyAssetSpliceCandidate>;
export type IAssetSpliceHostHolder = IAssetUpdateHolderView;
export interface IAssetSpliceExitEvidence extends IAssetOpenExit {
	htlcs?: readonly {
		id: string;
		offeredBy: 'local' | 'peer';
		output: NonNullable<IAssetOpenExit['toLocal']>;
		secondLevel: NonNullable<IAssetOpenExit['toLocal']>;
	}[];
	htlcSignatures?: string;
}
export interface IAssetSpliceHostExitViews {
	terms: import('./final-opening-commitment').IFinalOpeningTerms;
	originalInitiator: boolean;
	finalDigest: Buffer;
	layoutDigest: Buffer;
	paymentBasepoints: AssetOpenPair<Buffer>;
	fundingFeeratePerkw: number;
	parent: Record<Holder, IAssetSpliceHostHolder> & {
		funding: IFinalFundingReference;
		fundingRoot: Buffer;
	};
	candidate: Record<Holder, IAssetSpliceHostHolder> & {
		funding: IFinalFundingReference;
		fundingRoot: Buffer;
	};
}
export interface IAssetSpliceSigningHost {
	signSpliceExits(
		ctx: IAssetSpliceContext,
		views: IAssetSpliceHostExitViews
	): Promise<Buffer>;
	signSpliceExitHtlcs?(
		ctx: IAssetSpliceContext,
		views: IAssetSpliceHostExitViews,
		jointShares: AssetOpenPair<Buffer>,
		signer: IAssetUpdateHtlcSigner
	): Promise<Buffer>;
	verifySpliceExits(
		ctx: IAssetSpliceContext,
		views: IAssetSpliceHostExitViews,
		shares: AssetOpenPair<Buffer>,
		htlcShares?: AssetOpenPair<Buffer>
	): Promise<Both<IAssetSpliceExitEvidence>>;
	retainSpliceExits(
		ctx: IAssetSpliceContext,
		views: IAssetSpliceHostExitViews,
		exact: Both<Transaction>
	): Promise<IAssetSpliceExitProofs>;
	signSpliceFunding(
		ctx: IAssetSpliceContext,
		finalDigest: Buffer,
		...args: Parameters<FinalFundingWitnessSigner>
	): Promise<Buffer[][]>;
}

function boundedShares(value: Buffer): Buffer {
	if (
		!Buffer.isBuffer(value) ||
		!value.length ||
		value.length > ASSET_OPEN_OBJECT_LIMIT
	)
		throw Error('Invalid asset splice exit share length');
	return Buffer.from(value);
}
function sharePair(pair: AssetOpenPair<Buffer>): [Buffer, Buffer] {
	if (pair.length !== 2)
		throw Error('Splice exit authorization requires both devices');
	return [boundedShares(pair[0]), boundedShares(pair[1])];
}
export interface VerifiedSpliceExitLeaves {
	readonly digest: string;
}
const retainedLeaves = new WeakMap<
	VerifiedSpliceExitLeaves,
	{
		authority: FinalOpeningAuthority;
		context: IAssetSpliceContext;
		id: string;
		digest: string;
		leaves: Both<IAssetSpliceExitEvidence>;
	}
>();
export type AssetSpliceInputVerifier = (coin: {
	txid: Buffer;
	vout: number;
	scriptPubKey: Buffer;
}) => Promise<'unspent' | 'spent-or-missing' | 'spent' | 'unknown'>;

function proofLeaf(v: IAssetOpenExit['toLocal']) {
	if (!v) return;
	if (!/^(?:[0-9a-f]{2})+$/.test(v.script))
		throw new Error('Invalid asset holder leaf bytes');
	return { script: Buffer.from(v.script, 'hex'), leafVersion: v.leafVersion };
}

export class AssetSpliceSignatureRound {
	private readonly id: string;
	private readonly digest: string;
	private readonly terms: IFinalSpliceTerms;
	private readonly candidate;
	private readonly opening;
	private readonly session;
	private readonly funding: Record<Branch, IFinalFundingReference>;
	private readonly parentBranch: IAssetSpliceExitBranch | undefined;
	private readonly oldSigned: Buffer;
	private readonly ledger;
	private readonly commitmentTerms;
	private readonly keys;
	private readonly oldKey: Buffer;
	private readonly newKey: Buffer;
	private readonly nonceContext: Buffer;
	private readonly candidateProofHash: string;
	private readonly minimumDepth: number;

	constructor(
		private readonly store: SqliteStorage,
		private readonly authority: FinalOpeningAuthority,
		root: BIP32Interface,
		private readonly layout: IAssetSpliceLayout,
		private readonly verified: Verified,
		index: number
	) {
		store.assertAssetSpliceAuthority(authority);
		const frozen = assetSpliceConstructionView(layout, verified);
		if (!frozen.fundingProofHash)
			throw new Error(
				'Asset splice signing requires the authenticated funding proof bytes'
			);
		this.candidateProofHash = frozen.fundingProofHash;
		this.minimumDepth = frozen.minimumDepth;
		this.id = layout.channelId.toString('hex');
		this.digest = frozen.finalDigest;
		this.terms = frozen.terms;
		const opening = store.loadFinalDaemonOpening(this.id);
		if (!opening?.session.assetEvidence || !opening.funding)
			throw new Error(
				'Splice signatures need the funded original asset channel'
			);
		this.opening = opening.candidate;
		this.session = opening.session;
		const sameParent = (b: IAssetSpliceExitBranch) =>
			b.fundingTxid === this.terms.parent.getId() &&
			b.outputIndex === this.terms.parentIndex &&
			b.fundingRoot === this.terms.assetFundingRoots!.parent.toString('hex');
		const released = store
			.readAssetSpliceJournal<{ kind: string; finalDigest?: string }>(this.id)
			.records.some(
				(r) => r.kind === 'funding-released' && r.finalDigest === this.digest
			);
		const active = released
			? loadAssetSpliceExitProofs(store, this.id, this.digest)
			: store.loadAdoptedAssetSpliceReceipt(this.id);
		const latest = store.assetSpliceUpdateHead(this.id);
		if (!released && latest.inProgress)
			throw new Error('Asset commitment update still in progress');
		this.ledger =
			layout.stateNumber > 0n
				? assetUpdateHistory(store, this.id).states.get(layout.stateNumber)
				: undefined;
		if (
			(layout.stateNumber > 0n &&
				(!this.ledger ||
					this.ledger.digest !== layout.priorDigest?.toString('hex'))) ||
			(!released &&
				(latest.committed?.height ?? '0') !== String(layout.stateNumber))
		)
			throw new Error('Asset splice prior digest or height is not current');
		this.commitmentTerms = this.ledger
			? { ...this.session.terms, commitmentFeeratePerKw: this.ledger.feerate }
			: this.session.terms;
		const elected = active && (released ? active.parent : active.candidate);
		if (
			elected
				? !sameParent(elected)
				: this.terms.parent.getId() !==
						Transaction.fromHex(this.opening.fundingTxHex).getId() ||
				  this.terms.parentIndex !== this.opening.fundingOutputIndex
		)
			throw new Error('Asset splice requires the elected funding output');
		const parent = this.ledger
			? assetUpdateFundingMembers(store, this.id, this.ledger).find(sameParent)
			: elected;
		if (this.ledger && !parent)
			throw new Error('Missing signed asset splice member');
		const saved = this.ledger?.htlcs ?? [];
		if (
			layout.parentBalances.htlcs.length !== saved.length ||
			saved.some((h) => {
				const row = layout.parentBalances.htlcs.find(
					(v) =>
						v.id === BigInt(h.id) &&
						(v.offeredBy === 'initiator') ===
							((h.offeredBy === 'local') === this.terms.localIsSpliceInitiator)
				);
				return (
					!row ||
					row.amountMsat !== BigInt(h.amountMsat) ||
					row.cltvExpiry !== h.cltvExpiry ||
					row.paymentHash !== h.paymentHash ||
					!isDeepStrictEqual(
						row.allocations.map((a) => [a.assetId, String(a.units)]).sort(),
						h.allocations.map((a) => [a.assetId, a.units]).sort()
					)
				);
			})
		)
			throw new Error('Splice layout differs from the signed HTLC obligations');
		this.parentBranch = parent;
		const old = parent?.funding ?? {
			fundingTxHex: this.opening.fundingTxHex,
			fundingOutputIndex: this.opening.fundingOutputIndex,
			localFundingPubkey: this.opening.localFundingPubkey,
			remoteFundingPubkey: this.opening.remoteFundingPubkey,
			localFundingKeyIndex: this.session.channelKeyIndex
		};
		if (
			old.fundingTxHex !== this.terms.parent.toHex() ||
			old.fundingOutputIndex !== this.terms.parentIndex ||
			old.localFundingPubkey !== this.terms.oldLocalKey.toString('hex') ||
			old.remoteFundingPubkey !== this.terms.oldPeerKey.toString('hex') ||
			(!parent &&
				(layout.stateNumber !== 0n ||
					opening.session.assetEvidence.fundingRoot !==
						this.terms.assetFundingRoots!.parent.toString('hex')))
		)
			throw new Error('Unrecognized asset splice parent');
		const signed = parent
			? Buffer.from(parent.localCommitment, 'hex')
			: store
					.loadFinalFundingExits(this.id)
					.find(
						(v) =>
							v.fundingTxid.equals(this.terms.parent.getHash()) &&
							Transaction.fromBuffer(v.exit).ins[0].index ===
								this.terms.parentIndex
					)?.exit;
		if (!signed)
			throw new Error('Missing original enforceable parent commitment');
		this.oldSigned = Buffer.from(signed);
		authority.requireAllocatedChannelKey(index);
		this.keys = deriveChannelKeys(root, 1, this.session.channelKeyIndex);
		this.oldKey = deriveChannelKeys(
			root,
			1,
			old.localFundingKeyIndex
		).fundingPrivkey;
		const newKeys = deriveChannelKeys(root, 1, index);
		this.newKey = newKeys.fundingPrivkey;
		if (
			!newKeys.channelBasepoints.fundingPubkey.equals(this.terms.newLocalKey) ||
			!deriveChannelKeys(
				root,
				1,
				old.localFundingKeyIndex
			).channelBasepoints.fundingPubkey.equals(this.terms.oldLocalKey) ||
			!this.keys.channelBasepoints.fundingPubkey.equals(
				Buffer.from(this.opening.localFundingPubkey, 'hex')
			)
		)
			throw new Error(
				'Splice funding key differs from its allocated device derivation'
			);
		const tx = Transaction.fromHex(frozen.transaction);
		this.candidate = buildFinalSpliceCandidate(
			this.terms,
			layout.inputs.map((i) => ({
				...i,
				prevTxid: Buffer.from(i.prevTxid),
				prevTx: i.prevTx && Buffer.from(i.prevTx)
			})),
			layout.outputs.map((o, i) => ({
				serialId: o.serialId,
				amountSats: o.amountSats,
				scriptPubkey: tx.outs[i].script
			}))
		);
		this.funding = {
			parent: old,
			candidate: {
				fundingTxHex: frozen.transaction,
				fundingOutputIndex: this.candidate.fundingIndex,
				localFundingKeyIndex: index,
				localFundingPubkey: this.terms.newLocalKey.toString('hex'),
				remoteFundingPubkey: this.terms.newPeerKey.toString('hex')
			}
		};
		this.nonceContext = spliceCommitmentNonceContext(
			this.id,
			tx.getHash(),
			this.candidate.fundingIndex
		);
		const sums = (indices: number[]) =>
			indices.reduce((n, j) => n + BigInt(this.candidate.values[j]), 0n);
		const shared = BigInt(this.candidate.values[this.candidate.sharedIndex]),
			ours =
				sums(this.candidate.localInputs) +
				(this.terms.localIsSpliceInitiator ? shared : 0n),
			peer =
				sums(this.candidate.peerInputs) +
				(this.terms.localIsSpliceInitiator ? 0n : shared);
		this.first =
			ours < peer ||
			(ours === peer &&
				Buffer.compare(
					deriveLightningKeys(root, 1).nodePublicKey,
					Buffer.from(this.session.peer, 'hex')
				) < 0);
		const ledger = this.balances('candidate', 'local');
		validateFinalSpliceReserves(
			BigInt(tx.outs[this.candidate.fundingIndex].value),
			this.commitmentTerms,
			ledger,
			ledger.htlcs,
			this.opening.isInitiator,
			this.candidate.outputOwners
		);
	}
	private readonly first: boolean;
	private current(ctx?: IAssetSpliceContext) {
		assetSpliceConstructionView(this.layout, this.verified);
		this.store.assertAssetSpliceAuthority(this.authority);
		if (this.authority.exitRequest(this.id))
			throw new Error('Asset splice channel is closing');
		const head = this.store.assetSpliceUpdateHead(this.id);
		if (
			head.inProgress ||
			(head.committed?.digest ?? undefined) !== this.ledger?.digest
		)
			throw new Error('Signed asset funding parent has changed');
		if (!ctx) return;
		const current = ctx.currentParent();
		if (
			ctx.peer !== this.session.peer ||
			ctx.channelId !== this.id ||
			!ctx.attempt.equals(this.layout.attempt) ||
			ctx.isInitiator !== this.terms.localIsSpliceInitiator ||
			ctx.walletGeneration !== 4 ||
			ctx.stateNumber !== this.layout.stateNumber ||
			!ctx.oldOutpoint.hash.equals(this.terms.parent.getHash()) ||
			ctx.oldOutpoint.index !== this.terms.parentIndex ||
			current?.walletGeneration !== 4 ||
			current.stateNumber !== ctx.stateNumber ||
			ctx.priorDigest?.toString('hex') !== this.ledger?.digest ||
			current.priorDigest?.toString('hex') !== this.ledger?.digest ||
			current.oldOutpoint.index !== ctx.oldOutpoint.index ||
			!current.oldOutpoint.hash.equals(ctx.oldOutpoint.hash)
		)
			throw new Error('Asset splice device or current funding state changed');
	}
	private balances(name: Branch, holder: Holder) {
		const h =
			this.parentBranch?.[
				holder === 'local' ? 'localRecovery' : 'remoteRecovery'
			];
		const { localBasepoints, remoteBasepoints } = this.session.terms;
		const point =
			h?.point ??
			(holder === 'local' ? localBasepoints : remoteBasepoints)
				.firstPerCommitmentPoint;
		const htlcs: IAssetUpdateHtlc[] = (this.ledger?.htlcs ?? []).map(
			readUpdateHtlc
		);
		return {
			point: Buffer.from(point, 'hex'),
			localBalanceMsat:
				(h
					? BigInt(h.localBalanceMsat)
					: BigInt(this.opening.localContributionSats) * 1000n) +
				(name === 'candidate' ? this.terms.localDelta * 1000n : 0n),
			remoteBalanceMsat:
				(h
					? BigInt(h.remoteBalanceMsat)
					: BigInt(this.opening.remoteContributionSats) * 1000n) +
				(name === 'candidate' ? this.terms.peerDelta * 1000n : 0n),
			htlcs
		};
	}
	private view(name: Branch, holder: Holder, exit?: IAssetSpliceExitEvidence) {
		const state = this.balances(name, holder);
		const v = buildAssetSpliceCommitment(
			this.opening,
			this.commitmentTerms,
			holder,
			state.point,
			this.layout.stateNumber,
			state,
			state.htlcs,
			this.funding[name],
			Buffer.from(this.session.assetEvidence!.fundingRoot, 'hex'),
			{
				fundingRoot: this.terms.assetFundingRoots![name],
				toLocal: proofLeaf(exit?.toLocal),
				toRemote: proofLeaf(exit?.toRemote),
				htlcs: exit?.htlcs?.map((h) => ({
					id: BigInt(h.id),
					offeredBy: h.offeredBy,
					output: proofLeaf(h.output)!,
					secondLevel: proofLeaf(h.secondLevel)!
				}))
			}
		);
		return { state, v };
	}
	private hostViews(): IAssetSpliceHostExitViews {
		const side = (name: Branch, holder: Holder) => {
			const { v, state } = this.view(name, holder);
			return {
				...state,
				tx: v.tx,
				outputMap: v.outputMap,
				keys: v.keys,
				htlcOutputs: v.htlcs,
				toSelfDelay: v.toSelfDelay
			};
		};
		const branch = (name: Branch) => ({
			funding: { ...this.funding[name] },
			fundingRoot: Buffer.from(this.terms.assetFundingRoots![name]),
			local: side(name, 'local'),
			remote: side(name, 'remote')
		});
		const points = [
			this.session.terms.localBasepoints.paymentBasepoint,
			this.session.terms.remoteBasepoints.paymentBasepoint
		];
		if (!this.terms.localIsSpliceInitiator) points.reverse();
		return {
			terms: deserialize(serialize(this.commitmentTerms)),
			originalInitiator: this.opening.isInitiator,
			finalDigest: Buffer.from(this.digest, 'hex'),
			layoutDigest: Buffer.from(this.verified.layoutDigest),
			fundingFeeratePerkw: this.terms.feerate,
			paymentBasepoints: [
				Buffer.from(points[0], 'hex'),
				Buffer.from(points[1], 'hex')
			],
			parent: branch('parent'),
			candidate: branch('candidate')
		};
	}
	txComplete(): Buffer {
		this.current();
		const height = Number(this.layout.stateNumber);
		const nonce = (n: number) =>
			Buffer.from(
				updateVerificationNonce(
					this.authority.nonceContext(this.nonceContext),
					this.newKey,
					n,
					{ pub: '', source: 'splice' }
				)
			);
		return encodeTxCompleteMessage({
			channelId: Buffer.from(this.id, 'hex'),
			commitNonces: { current: nonce(height), next: nonce(height + 1) },
			fundingInputNonce: finalSpliceSharedNonce(
				this.candidate,
				this.oldKey,
				this.authority
			)
		});
	}
	private agreement() {
		const g = new AssetSpliceConstruction(
			this.layout,
			this.verified,
			this.txComplete(),
			this.store
		).agreement();
		if (!g || g.candidate.tx.toHex() !== this.candidate.tx.toHex())
			throw new Error('Missing completed asset splice construction');
		return g;
	}
	private savedShare(
		phase: 'joint' | 'htlc',
		binding: string,
		payload?: Buffer
	): Buffer | undefined {
		type Share = {
			kind: 'splice-exit-share';
			digest: string;
			phase: typeof phase;
			binding: string;
			bytes: string;
		};
		const head = this.store.readAssetSpliceJournal<Share>(this.id);
		const prior = head.records.filter(
			(s) =>
				s.kind === 'splice-exit-share' &&
				s.digest === this.digest &&
				s.phase === phase
		);
		if (
			prior.length > 1 ||
			(prior[0] &&
				(prior[0].binding !== binding ||
					(payload && prior[0].bytes !== payload.toString('hex'))))
		)
			throw new Error('Conflicting asset splice exit shares');
		if (prior[0]) return boundedShares(Buffer.from(prior[0].bytes, 'hex'));
		if (!payload) return;
		const exact = boundedShares(payload);
		this.store.appendAssetSpliceEvent(this.id, head, {
			kind: 'splice-exit-share',
			digest: this.digest,
			phase,
			binding,
			bytes: exact.toString('hex')
		} satisfies Share);
		return exact;
	}
	async signExitShares(
		host: IAssetSpliceSigningHost,
		ctx: IAssetSpliceContext
	) {
		this.agreement();
		this.current(ctx);
		const cached = this.ledger && this.savedShare('joint', this.ledger.digest);
		if (cached) return cached;
		const raw = await host.signSpliceExits(ctx, this.hostViews());
		this.current(ctx);
		return this.ledger
			? this.savedShare('joint', this.ledger.digest, raw)!
			: boundedShares(raw);
	}
	async signExitHtlcs(
		host: IAssetSpliceSigningHost,
		ctx: IAssetSpliceContext,
		shares: AssetOpenPair<Buffer>
	): Promise<Buffer> {
		this.agreement();
		this.current(ctx);
		if (!this.ledger || !host.signSpliceExitHtlcs)
			throw new Error('Missing signed parent asset HTLC support');
		const pair = sharePair(shares);
		const binding = sha256(Buffer.concat(pair.map((b) => sha256(b)))).toString(
			'hex'
		);
		const cached = this.savedShare('htlc', binding);
		if (cached) return cached;
		const our = await this.signExitShares(host, ctx);
		if (!pair[this.terms.localIsSpliceInitiator ? 0 : 1].equals(our))
			throw new Error('Splice asset joint shares omit local authorization');
		let active = true;
		try {
			const out = await host.signSpliceExitHtlcs(ctx, this.hostViews(), pair, {
				signHtlc: (hash, point, base, outpoint, dir, id, assetId) => {
					this.current(ctx);
					if (
						!active ||
						hash.length !== 32 ||
						!base.equals(this.keys.channelBasepoints.htlcBasepoint) ||
						!['local', 'remote'].some((h) =>
							this.balances('candidate', h as Holder).point.equals(point)
						) ||
						outpoint !==
							this.candidate.tx.getId() + ':' + this.candidate.fundingIndex ||
						!this.ledger?.htlcs.some(
							(h) =>
								h.id === String(id) &&
								h.offeredBy === dir &&
								h.allocations.some((a) => a.assetId === assetId)
						)
					)
						throw Error('Unauthorized candidate asset HTLC signature');
					const slot = [
							'asset-splice-htlc',
							this.id,
							this.digest,
							outpoint,
							point.toString('hex'),
							dir,
							String(id),
							assetId
						].join('/'),
						digest = hash.toString('hex');
					return (
						this.authority.claim(slot, digest) ??
						this.authority.finish(
							slot,
							digest,
							signTaprootHtlcLeaf(
								hash,
								derivePrivateKey(this.keys.htlcBasepointSecret, point, base)
							)
						)
					);
				}
			});
			this.current(ctx);
			return this.savedShare('htlc', binding, out)!;
		} finally {
			active = false;
		}
	}
	async verifyExitShares(
		host: IAssetSpliceSigningHost,
		ctx: IAssetSpliceContext,
		shares: AssetOpenPair<Buffer>,
		htlcShares?: AssetOpenPair<Buffer>
	): Promise<VerifiedSpliceExitLeaves> {
		this.agreement();
		this.current(ctx);
		const joints = sharePair(shares),
			children = htlcShares && sharePair(htlcShares);
		if (this.ledger) {
			if (!children)
				throw new Error(
					'Splicing an updated channel needs both asset HTLC share sets'
				);
			const our = await this.signExitHtlcs(host, ctx, joints);
			if (!our.equals(children[this.terms.localIsSpliceInitiator ? 0 : 1]))
				throw new Error('Missing local asset HTLC authorization');
		} else if (htlcShares)
			throw new Error('Unexpected asset HTLC shares on opening');
		const leaves = await host.verifySpliceExits(
			ctx,
			this.hostViews(),
			joints,
			children
		);
		this.current(ctx);
		const copy = JSON.parse(JSON.stringify(leaves)) as typeof leaves;
		for (const name of ['parent', 'candidate'] as const)
			for (const h of ['local', 'remote'] as const) {
				if (!/^(?:[a-f0-9]{2})+$/.test(copy[name][h].proofs))
					throw new Error('Missing verified holder asset proofs');
				const holder = copy[name][h];
				const required = (this.ledger?.htlcs ?? []).filter(
					(v) => v.allocations.length
				);
				if (
					(holder.htlcs?.length ?? 0) !== required.length ||
					required.some(
						(v) =>
							!holder.htlcs?.some(
								(e) => e.id === v.id && e.offeredBy === v.offeredBy
							)
					) ||
					(this.ledger &&
						!/^(?:[0-9a-f]{2})+$/.test(holder.htlcSignatures ?? ''))
				)
					throw new Error(
						'Incomplete authorized asset HTLC exit leaves or records'
					);
				const rebuilt = this.view(name, h, holder);
				if (
					this.ledger &&
					(!rebuilt.v.tx.outs.length ||
						Buffer.from(holder.htlcSignatures!, 'hex').length >
							(this.layout.commitmentRecordLimits[
								(h === 'local') === this.terms.localIsSpliceInitiator ? 0 : 1
							].find((r) => r.type === 65537n)?.maxBytes ?? 0))
				)
					throw new Error('Asset HTLC signature exceeds the agreed wire bound');
				if (name === 'parent') {
					if (this.ledger && this.parentBranch) {
						const branch = this.parentBranch,
							local = h === 'local',
							recovery = local ? branch.localRecovery : branch.remoteRecovery;
						const expected = Transaction.fromHex(
							local ? branch.localCommitment : branch.remoteCommitment
						);
						const priorLeaves = recovery.htlcs.flatMap((v) =>
							v.outputLeaf && v.secondLevelLeaf
								? [
										{
											id: v.id,
											offeredBy: v.offeredBy,
											output: v.outputLeaf,
											secondLevel: v.secondLevelLeaf
										}
								  ]
								: []
						);
						const index = this.ledger.members.findIndex(
							(m) =>
								m.fundingTxid === branch.fundingTxid &&
								m.outputIndex === branch.outputIndex
						);
						const original =
							index >= 0
								? Buffer.from(
										(local
											? this.ledger.peerCommitments
											: this.ledger.localCommitments)[index],
										'hex'
								  )
								: this.parentCommitmentRecord(local);
						if (
							!original ||
							decodeCommitmentSignedMessage(original, { customRecords: true })
								.customRecords?.get(65537n)
								?.toString('hex') !== holder.htlcSignatures ||
							!expected.getHash().equals(rebuilt.v.tx.getHash()) ||
							!isDeepStrictEqual(priorLeaves, holder.htlcs ?? [])
						)
							throw new Error(
								'Signed parent HTLC leaves or signatures changed'
							);
					}
					const previous = this.parentBranch
						? this.parentBranch[h === 'local' ? 'localProofs' : 'remoteProofs']
						: this.session.assetEvidence![h].proofs;
					const original = this.parentBranch
						? this.parentBranch[
								h === 'local' ? 'localRecovery' : 'remoteRecovery'
						  ]
						: this.session.assetEvidence![h];
					if (
						copy[name][h].proofs !== previous ||
						!isDeepStrictEqual(
							original.toLocal ?? null,
							copy[name][h].toLocal ?? null
						) ||
						!isDeepStrictEqual(
							original.toRemote ?? null,
							copy[name][h].toRemote ?? null
						)
					)
						throw new Error(
							'Splice parent holder proofs differ from enrolled receipt'
						);
				}
			}
		validateFinalSpliceExit(
			{
				expected: this.view('parent', 'local', copy.parent.local).v.tx,
				signed: Transaction.fromBuffer(this.oldSigned)
			},
			this.terms.parent,
			this.terms.parentIndex
		);
		const handle = Object.freeze({
			digest: sha256(Buffer.from(JSON.stringify(copy))).toString('hex')
		});
		retainedLeaves.set(handle, {
			authority: this.authority,
			context: {
				...ctx,
				attempt: Buffer.from(ctx.attempt),
				oldOutpoint: {
					hash: Buffer.from(ctx.oldOutpoint.hash),
					index: ctx.oldOutpoint.index
				},
				currentParent: ctx.currentParent.bind(ctx)
			},
			id: this.id,
			digest: this.digest,
			leaves: copy
		});
		return handle;
	}
	private parentCommitmentRecord(localHolder: boolean): Buffer | undefined {
		const active = this.store.loadAdoptedAssetSpliceReceipt(this.id);
		return (
			active &&
			assetSpliceSignatureFrame(
				this.store,
				this.id,
				active.finalDigest,
				!localHolder,
				M.COMMITMENT_SIGNED
			)
		);
	}
	private exact(
		handle: VerifiedSpliceExitLeaves,
		name: Branch,
		holder: Holder
	) {
		const entry = retainedLeaves.get(handle);
		if (
			!entry ||
			entry.authority !== this.authority ||
			entry.id !== this.id ||
			entry.digest !== this.digest
		)
			throw new Error('Unverified asset splice exit evidence');
		this.current(entry.context);
		return this.view(name, holder, entry.leaves[name][holder]);
	}
	private wire(local: boolean, type: M) {
		return assetSpliceSignatureFrame(
			this.store,
			this.id,
			this.digest,
			local,
			type
		);
	}
	private record(local: boolean, type: M, payload: Buffer) {
		assetSpliceSignatureFrame(
			this.store,
			this.id,
			this.digest,
			local,
			type,
			payload
		);
	}
	private commitment(handle: VerifiedSpliceExitLeaves, peer?: Buffer) {
		const g = this.agreement();
		const { state, v } = this.exact(
			handle,
			'candidate',
			peer ? 'local' : 'remote'
		);
		const evidence =
			retainedLeaves.get(handle)!.leaves.candidate[peer ? 'local' : 'remote'];
		let bitcoin = peer;
		if (this.ledger && peer) {
			const decoded = decodeCommitmentSignedMessage(peer, {
				customRecords: true
			});
			if (
				decoded.customRecords?.size !== 1 ||
				decoded.customRecords.get(65537n)?.toString('hex') !==
					evidence.htlcSignatures ||
				!encodeCommitmentSignedMessage(decoded).equals(peer)
			)
				throw new Error('Candidate commitment asset HTLC signatures differ');
			bitcoin = encodeCommitmentSignedMessage({
				...decoded,
				customRecords: undefined
			});
		}
		const signed = signFinalUpdate(
			this.opening,
			v,
			state.point,
			Number(this.layout.stateNumber),
			{
				pub: (peer ? g.local : g.peer).commitNonces.current.toString('hex'),
				source: 'splice'
			},
			this.keys,
			this.authority,
			this.nonceContext,
			this.ledger ? [handle.digest] : [],
			bitcoin,
			{
				reference: this.funding.candidate,
				privateKey: this.newKey,
				asset: {
					fundingRoot: this.terms.assetFundingRoots!.candidate,
					transcriptDigest: Buffer.from(this.digest, 'hex')
				}
			}
		);
		return this.ledger && !peer
			? encodeCommitmentSignedMessage({
					...decodeCommitmentSignedMessage(signed),
					customRecords: new Map([
						[65537n, Buffer.from(evidence.htlcSignatures!, 'hex')]
					])
			  })
			: signed;
	}
	commitmentSigned(handle: VerifiedSpliceExitLeaves) {
		const raw = this.commitment(handle);
		this.record(true, M.COMMITMENT_SIGNED, raw);
		return raw;
	}
	acceptCommitmentSigned(handle: VerifiedSpliceExitLeaves, wire: Buffer) {
		const raw = this.commitment(handle, wire);
		this.record(false, M.COMMITMENT_SIGNED, wire);
		return raw;
	}
	async retainExits(
		host: IAssetSpliceSigningHost,
		ctx: IAssetSpliceContext,
		handle: VerifiedSpliceExitLeaves
	) {
		this.current(ctx);
		const peer = this.wire(false, M.COMMITMENT_SIGNED);
		if (!peer || !this.wire(true, M.COMMITMENT_SIGNED))
			throw new Error('Both asset splice commitment signatures are required');
		const pair = {
			parent: {
				local: Transaction.fromBuffer(this.oldSigned),
				remote: this.exact(handle, 'parent', 'remote').v.tx
			},
			candidate: {
				local: Transaction.fromBuffer(this.commitment(handle, peer)),
				remote: this.exact(handle, 'candidate', 'remote').v.tx
			}
		};
		const expected = Object.fromEntries(
			Object.entries(pair).map(([name, b]) => [
				name,
				{ local: b.local.toHex(), remote: b.remote.toHex() }
			])
		) as Both<string>;
		const receipt = await host.retainSpliceExits(ctx, this.hostViews(), pair);
		this.current(ctx);
		const leaves = retainedLeaves.get(handle)!.leaves;
		if (
			receipt.channelId !== this.id ||
			receipt.finalDigest !== this.digest ||
			receipt.stateNumber !== String(this.layout.stateNumber) ||
			receipt.priorDigest !== this.ledger?.digest ||
			receipt.minimumDepth !== this.minimumDepth ||
			receipt.candidate.minimumDepth !== this.minimumDepth ||
			receipt.parent.minimumDepth !==
				(this.parentBranch?.minimumDepth ?? this.opening.minimumDepth) ||
			receipt.parent.fundingProofs !==
				(this.parentBranch?.fundingProofs ??
					this.session.assetEvidence!.fundingProofs) ||
			sha256(Buffer.from(receipt.candidate.fundingProofs, 'hex')).toString(
				'hex'
			) !== this.candidateProofHash
		)
			throw new Error('Host returned a different splice proof receipt');
		for (const name of ['parent', 'candidate'] as const) {
			const b = receipt[name];
			for (const holder of ['local', 'remote'] as const) {
				const recovery =
						holder === 'local' ? b.localRecovery : b.remoteRecovery,
					evidence = leaves[name][holder];
				const { v, state } = this.exact(handle, name, holder);
				const expectedHtlcs = state.htlcs.map((h) => {
					const source = v.htlcs.find(
						(x) => x.htlc.id === h.id && x.htlc.offeredBy === h.offeredBy
					);
					const aux = evidence.htlcs?.find(
						(x) => x.id === String(h.id) && x.offeredBy === h.offeredBy
					);
					return {
						id: String(h.id),
						offeredBy: h.offeredBy,
						amountMsat: String(h.amountMsat),
						paymentHash: h.paymentHash.toString('hex'),
						cltvExpiry: h.cltvExpiry,
						outputIndex: source?.outputIndex ?? null,
						outputLeaf: aux?.output ?? null,
						secondLevelLeaf: aux?.secondLevel ?? null
					};
				});
				if (
					recovery.point !== state.point.toString('hex') ||
					recovery.localBalanceMsat !== String(state.localBalanceMsat) ||
					recovery.remoteBalanceMsat !== String(state.remoteBalanceMsat) ||
					!isDeepStrictEqual(recovery.htlcs, expectedHtlcs)
				)
					throw new Error(
						'Retained splice HTLC claim differs from the verified holder'
					);
			}
			if (
				!isDeepStrictEqual(b.funding, this.funding[name]) ||
				b.fundingRoot !== this.terms.assetFundingRoots![name].toString('hex') ||
				b.localCommitment !== expected[name].local ||
				b.remoteCommitment !== expected[name].remote ||
				b.localProofs !== leaves[name].local.proofs ||
				b.remoteProofs !== leaves[name].remote.proofs
			)
				throw new Error(
					'Host receipt differs from the signed asset splice commitments'
				);
		}
		retainAssetSpliceExitProofs(this.store, this.id, receipt);
		return loadAssetSpliceExitProofs(this.store, this.id, this.digest);
	}
	private release() {
		const receipt = loadAssetSpliceExitProofs(this.store, this.id, this.digest);
		if (
			!this.wire(true, M.COMMITMENT_SIGNED) ||
			!this.wire(false, M.COMMITMENT_SIGNED)
		)
			throw new Error('Asset splice commitments are incomplete');
		return receipt;
	}
	private ourFunding() {
		return this.store
			.readAssetSpliceJournal<{
				kind: string;
				finalDigest?: string;
				wire?: string;
			}>(this.id)
			.records.find(
				(r) => r.kind === 'funding-released' && r.finalDigest === this.digest
			)?.wire;
	}
	async nextFunding(
		host: IAssetSpliceSigningHost,
		ctx: IAssetSpliceContext,
		verify: AssetSpliceInputVerifier
	): Promise<Buffer | undefined> {
		const g = this.agreement(),
			e = this.release(),
			saved = this.ourFunding();
		if (saved) {
			const raw = Buffer.from(saved, 'hex');
			this.checkFunding(raw, true, g);
			return raw;
		}
		this.current(ctx);
		if (!this.first && !this.wire(false, M.TX_SIGNATURES)) return;
		for (const [i, coin] of this.candidate.tx.ins.entries()) {
			if (
				(await verify({
					txid: Buffer.from(coin.hash),
					vout: coin.index,
					scriptPubKey: Buffer.from(this.candidate.scripts[i])
				})) !== 'unspent'
			)
				throw new Error('Asset splice input is not verified unspent');
			this.current(ctx);
		}
		const branch = (name: Branch) => {
			const b = e[name];
			return {
				expected: spliceRecoveryView(
					this.opening,
					this.commitmentTerms,
					this.session.assetEvidence!.fundingRoot,
					b,
					'local',
					e.stateNumber
				).view.tx,
				signed: Transaction.fromHex(b.localCommitment)
			};
		};
		const raw = await signAssetSpliceFunding(
			this.candidate,
			this.terms,
			Buffer.from(this.id, 'hex'),
			this.oldKey,
			g.local.fundingInputNonce,
			g.peer.fundingInputNonce,
			this.authority,
			{ parent: branch('parent'), candidate: branch('candidate') },
			async (tx, indices, prevouts) => {
				this.current(ctx);
				const w = await host.signSpliceFunding(
					ctx,
					Buffer.from(this.digest, 'hex'),
					tx,
					indices,
					prevouts
				);
				this.current(ctx);
				return w;
			},
			{
				store: this.store,
				stateNumber: this.layout.stateNumber,
				finalDigest: Buffer.from(this.digest, 'hex'),
				parentRemote: Transaction.fromHex(e.parent.remoteCommitment),
				candidateRemote: Transaction.fromHex(e.candidate.remoteCommitment)
			}
		);
		return raw;
	}
	private checkFunding(
		wire: Buffer,
		local: boolean,
		g: ReturnType<AssetSpliceSignatureRound['agreement']>
	) {
		verifyFinalSpliceContribution(
			this.candidate,
			this.terms,
			Buffer.from(this.id, 'hex'),
			wire,
			local,
			g.local.fundingInputNonce,
			g.peer.fundingInputNonce
		);
	}
	receiveFunding(wire: Buffer) {
		const g = this.agreement();
		this.release();
		if (this.first && !this.ourFunding())
			throw new Error('Unexpected peer asset splice funding signature order');
		this.checkFunding(wire, false, g);
		this.record(false, M.TX_SIGNATURES, wire);
	}
	transaction(): Transaction | undefined {
		const ours = this.ourFunding(),
			peer = this.wire(false, M.TX_SIGNATURES);
		if (!ours || !peer) return;
		const g = this.agreement();
		this.release();
		return Transaction.fromBuffer(
			assembleFinalSplice(
				this.candidate,
				this.terms,
				Buffer.from(this.id, 'hex'),
				g.local.fundingInputNonce,
				g.peer.fundingInputNonce,
				Buffer.from(ours, 'hex'),
				peer
			).toBuffer()
		);
	}
}
