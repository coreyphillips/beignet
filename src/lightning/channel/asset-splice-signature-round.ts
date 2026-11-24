import type { BIP32Interface } from 'bip32';
import { Transaction } from 'bitcoinjs-lib';
import { isDeepStrictEqual } from 'util';
import { deriveChannelKeys, deriveLightningKeys } from '../keys/wallet-keys';
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
import {
	buildAssetSpliceCommitment,
	type IFinalBalances,
	type IFinalCommitmentView,
	type IFinalCommitmentHtlc
} from './final-opening-commitment';
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
export type IAssetSpliceHostHolder = Pick<
	IFinalCommitmentView,
	'tx' | 'outputMap' | 'toSelfDelay'
> &
	IFinalBalances & {
		point: Buffer;
		keys: Pick<
			IFinalCommitmentView['keys'],
			'revocationPubkey' | 'localDelayedPubkey'
		>;
		htlcs: readonly IFinalCommitmentHtlc[];
	};
export interface IAssetSpliceHostExitViews {
	finalDigest: Buffer;
	layoutDigest: Buffer;
	paymentBasepoints: AssetOpenPair<Buffer>;
	fundingFeeratePerkw: number;
	parent: Record<Holder, IAssetSpliceHostHolder> & {
		funding: IFinalFundingReference;
	};
	candidate: Record<Holder, IAssetSpliceHostHolder> & {
		funding: IFinalFundingReference;
	};
}
export interface IAssetSpliceSigningHost {
	signSpliceExits(
		ctx: IAssetSpliceContext,
		views: IAssetSpliceHostExitViews
	): Promise<Buffer>;
	verifySpliceExits(
		ctx: IAssetSpliceContext,
		views: IAssetSpliceHostExitViews,
		shares: AssetOpenPair<Buffer>
	): Promise<Both<IAssetOpenExit>>;
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
		leaves: Both<IAssetOpenExit>;
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
		const parent = active && (released ? active.parent : active.candidate);
		if (
			parent &&
			(!sameParent(parent) ||
				String(layout.stateNumber) !== active!.stateNumber)
		)
			throw new Error('Asset splice parent differs from its enrolled state');
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
			this.session.terms,
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
		const htlcs: IFinalCommitmentHtlc[] = (h?.htlcs ?? []).map((v) => ({
			id: BigInt(v.id),
			offeredBy: v.offeredBy,
			amountMsat: BigInt(v.amountMsat),
			paymentHash: Buffer.from(v.paymentHash, 'hex'),
			cltvExpiry: v.cltvExpiry
		}));
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
	private view(name: Branch, holder: Holder, exit?: IAssetOpenExit) {
		const state = this.balances(name, holder);
		const v = buildAssetSpliceCommitment(
			this.opening,
			this.session.terms,
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
				toRemote: proofLeaf(exit?.toRemote)
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
				keys: {
					revocationPubkey: v.keys.revocationPubkey,
					localDelayedPubkey: v.keys.localDelayedPubkey
				},
				toSelfDelay: v.toSelfDelay
			};
		};
		const branch = (name: Branch) => ({
			funding: { ...this.funding[name] },
			local: side(name, 'local'),
			remote: side(name, 'remote')
		});
		const points = [
			this.session.terms.localBasepoints.paymentBasepoint,
			this.session.terms.remoteBasepoints.paymentBasepoint
		];
		if (!this.terms.localIsSpliceInitiator) points.reverse();
		return {
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
	async signExitShares(
		host: IAssetSpliceSigningHost,
		ctx: IAssetSpliceContext
	) {
		this.agreement();
		this.current(ctx);
		const raw = await host.signSpliceExits(ctx, this.hostViews());
		this.current(ctx);
		return Buffer.from(raw);
	}
	async verifyExitShares(
		host: IAssetSpliceSigningHost,
		ctx: IAssetSpliceContext,
		shares: AssetOpenPair<Buffer>
	): Promise<VerifiedSpliceExitLeaves> {
		this.agreement();
		this.current(ctx);
		const leaves = await host.verifySpliceExits(ctx, this.hostViews(), [
			Buffer.from(shares[0]),
			Buffer.from(shares[1])
		]);
		this.current(ctx);
		const copy = JSON.parse(JSON.stringify(leaves)) as typeof leaves;
		for (const name of ['parent', 'candidate'] as const)
			for (const h of ['local', 'remote'] as const) {
				if (!/^(?:[a-f0-9]{2})+$/.test(copy[name][h].proofs))
					throw new Error('Missing verified holder asset proofs');
				if (name === 'parent') {
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
		return signFinalUpdate(
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
			[],
			peer,
			{
				reference: this.funding.candidate,
				privateKey: this.newKey,
				asset: {
					fundingRoot: this.terms.assetFundingRoots!.candidate,
					transcriptDigest: Buffer.from(this.digest, 'hex')
				}
			}
		);
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
					this.session.terms,
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
