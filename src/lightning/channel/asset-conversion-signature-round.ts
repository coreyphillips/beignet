/**
 * The signing round of an asset conversion (#2151 Step 4b): from the frozen
 * candidate to both branches' exits. It derives the candidate's construction
 * nonces, builds both branches' views by type at the layout's state number,
 * checks the hosts' exit evidence, signs and accepts the candidate's first
 * commitments and checks the host's receipt. It signs no funding, and it
 * writes nothing: the transport retains what it returns. Internal: not in
 * the barrel.
 */
import type { BIP32Interface } from 'bip32';
import { Transaction } from 'bitcoinjs-lib';
import { isDeepStrictEqual } from 'util';
import { sha256 } from '../crypto/provider';
import { getPublicKey } from '../crypto/ecdh';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from '../features/asset-opening';
import { generateFromSeed, MAX_INDEX } from '../keys/shachain';
import { deriveChannelKeys } from '../keys/wallet-keys';
import { encodeTxCompleteMessage } from '../message/interactive-tx';
import { ASSET_OPEN_OBJECT_LIMIT } from '../message/asset-open';
import type { IAssetConversionParent } from '../storage/final-branch-readers';
import { finalBranchReaders } from '../storage/final-branch-readers';
import {
	branchCommitmentType,
	conversionRecoveryView,
	conversionViewContext,
	type IAssetExitBranch,
	type IConversionViewContext,
	type IFinalConversionExits,
	type IFinalExitBranch,
	type IPlainExitBranch
} from '../storage/final-conversion-exits';
import type { FinalOpeningAuthority } from '../storage/final-opening-authority';
import type { IAssetSpliceHolderRecovery } from '../storage/asset-splice-exit-proofs';
import {
	signFinalUpdate,
	spliceCommitmentNonceContext,
	updateVerificationNonce
} from '../storage/final-update-signing';
import type { SqliteStorage } from '../storage/sqlite-storage';
import { ASSET_CONVERSION_TEXTS } from './asset-conversion-terms';
import type {
	IAssetConversionLayout,
	IVerifiedConversionCandidate
} from './asset-conversion-layout';
import type {
	AssetOpenPair,
	IAssetConversionContext,
	IAssetConversionExitEvidence,
	IAssetConversionExitReceipt,
	IAssetConversionHost,
	IAssetConversionHostBranch,
	IAssetConversionHostExitViews,
	IAssetConversionWithdrawal,
	IAssetOpenExit
} from './asset-opening-provider';
import type { IAssetSpliceHostHolder } from './asset-splice-signature-round';
import { SpliceConstructionCore } from './asset-splice-construction';
import {
	buildAssetSpliceCommitment,
	buildFinalCommitmentView,
	type IFinalCommitmentView,
	type IFinalOpeningTerms
} from './final-opening-commitment';
import type { IFinalFundingReference } from './final-splice-candidate';
import { validateFinalSpliceExit } from './final-splice-exits';
import { finalSpliceSharedNonce } from './final-splice-funding';

type Holder = 'local' | 'remote';
type Branch = 'parent' | 'candidate';
/** One holder's commitment view and the state it was built from. */
interface IHolderView {
	state: { point: Buffer; localBalanceMsat: bigint; remoteBalanceMsat: bigint };
	v: IFinalCommitmentView;
}

export const CONVERSION_ROUND_TEXTS = {
	sign: 'Asset conversion host could not sign the exits',
	verify: 'Asset conversion host could not verify the exits',
	retain: 'Asset conversion host could not retain the exits',
	interactive:
		'Asset conversion interactive transaction differs from the agreed candidate',
	evidence: 'Asset conversion exit evidence differs from the signed views',
	parentProofs:
		'Conversion parent holder proofs differ from the enrolled receipt',
	receipt: 'Host receipt differs from the signed asset conversion commitments',
	withdrawal: 'Conversion withdrawal receipt differs from the layout',
	key: 'Asset conversion funding key differs from its device derivation',
	ledger: "Conversion parent differs from the current ledger's commitments",
	construction: 'Missing completed asset conversion construction',
	commitments: 'Both asset conversion commitment signatures are required'
} as const;
const T = CONVERSION_ROUND_TEXTS;

/** The three signing members of a conversion host. */
export type IAssetConversionSigningHost = Pick<
	IAssetConversionHost,
	'signConversionExits' | 'verifyConversionExits' | 'retainConversionExits'
>;

/** What the transport hands the round once the candidate is frozen. */
export interface IConversionRoundFacts {
	channelId: string;
	attempt: Buffer;
	isInitiator: boolean;
	/** The local candidate funding key's index. */
	keyIndex: number;
	layout: IAssetConversionLayout;
	/** The parent read at the proposal point. */
	parent: IAssetConversionParent;
	/** The target channel type, lowercase hex. */
	targetType: string;
	/** The terms' lock depth, the candidate's minimum depth. */
	lockDepth: number;
	/** The candidate's commitment feerate, from the terms. */
	commitmentFeeratePerKw: number;
	verified: IVerifiedConversionCandidate;
}

/** The verified evidence of one attempt's exits. */
export interface VerifiedConversionExits {
	readonly digest: string;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
	!!v && typeof v === 'object' && !Array.isArray(v);
const copyJson = <V>(v: V): V => JSON.parse(JSON.stringify(v)) as V;

function leaf(
	v: IAssetOpenExit['toLocal']
): { script: Buffer; leafVersion?: number } | undefined {
	if (!v) return undefined;
	if (
		!isRecord(v) ||
		typeof v.script !== 'string' ||
		!/^(?:[0-9a-f]{2})+$/.test(v.script)
	)
		throw new Error(T.evidence);
	return { script: Buffer.from(v.script, 'hex'), leafVersion: v.leafVersion };
}
const storedLeaf = (
	v: IAssetOpenExit['toLocal']
): NonNullable<IAssetOpenExit['toLocal']> | null => (v ? { ...v } : null);

export class ConversionSignatureRound {
	private readonly id: string;
	private readonly N: bigint;
	private readonly toAsset: boolean;
	private readonly authority: FinalOpeningAuthority;
	private readonly opening;
	private readonly session;
	private readonly keys;
	private readonly newKey: Buffer;
	private readonly oldKey: Buffer;
	private readonly parentBranch: IFinalExitBranch;
	private readonly funding: Record<Branch, IFinalFundingReference>;
	private readonly candidateTerms: IFinalOpeningTerms;
	private readonly balances: {
		localBalanceMsat: bigint;
		remoteBalanceMsat: bigint;
	};
	private readonly points: Record<Holder, Buffer>;
	private readonly openingRoot?: Buffer;
	private readonly nonceContext: Buffer;
	private readonly evidence = new WeakMap<
		VerifiedConversionExits,
		IAssetConversionExitEvidence
	>();
	private core?: SpliceConstructionCore;
	private local?: Buffer;
	private peer?: Buffer;
	private signedLocal?: Buffer;

	constructor(
		private readonly store: SqliteStorage,
		root: BIP32Interface,
		private readonly f: IConversionRoundFacts
	) {
		const readers = finalBranchReaders(store);
		if (!readers?.conversionSigningAuthority)
			throw new Error(
				'Asset conversion requires an original conversion wallet'
			);
		this.authority = readers.conversionSigningAuthority();
		this.authority.requireAllocatedChannelKey(f.keyIndex);
		this.id = f.channelId;
		this.N = f.parent.height;
		this.toAsset = f.parent.type === 'plain';
		const opening = store.loadFinalDaemonOpening(this.id);
		const session = store.loadFinalOpeningSession(this.id);
		if (!opening || !session)
			throw new Error('Asset conversion requires a funded ready channel');
		this.opening = opening.candidate;
		this.session = session;
		const terms = f.verified.terms;
		this.keys = deriveChannelKeys(root, 1, session.channelKeyIndex);
		const newKeys = deriveChannelKeys(root, 1, f.keyIndex);
		this.newKey = newKeys.fundingPrivkey;
		const old = deriveChannelKeys(
			root,
			1,
			f.parent.funding.localFundingKeyIndex
		);
		this.oldKey = old.fundingPrivkey;
		if (
			!newKeys.channelBasepoints.fundingPubkey.equals(terms.newLocalKey) ||
			!old.channelBasepoints.fundingPubkey.equals(terms.oldLocalKey) ||
			f.parent.funding.localFundingPubkey !==
				terms.oldLocalKey.toString('hex') ||
			!this.keys.channelBasepoints.fundingPubkey.equals(
				Buffer.from(this.opening.localFundingPubkey, 'hex')
			)
		)
			throw new Error(T.key);
		// The candidate keeps the channel's parameters (4.2).
		const [dust0, dust1] = f.layout.candidateDustSats;
		const [localDust, remoteDust] = f.isInitiator
			? [dust0, dust1]
			: [dust1, dust0];
		if (
			localDust !== BigInt(session.terms.localDustLimitSatoshis) ||
			remoteDust !== BigInt(session.terms.remoteDustLimitSatoshis)
		)
			throw new Error(ASSET_CONVERSION_TEXTS.parameters);
		this.openingRoot = session.assetEvidence
			? Buffer.from(session.assetEvidence.fundingRoot, 'hex')
			: undefined;
		this.parentBranch = this.buildParent();
		const ledger = readers.currentLedgerCommitments(this.id, Number(this.N));
		if (
			!ledger ||
			ledger.local !== this.parentBranch.localCommitment ||
			ledger.remote !== this.parentBranch.remoteCommitment
		)
			throw new Error(T.ledger);
		const tx = f.verified.candidate.tx;
		this.funding = {
			parent: { ...f.parent.funding },
			candidate: {
				fundingTxHex: tx.toHex(),
				fundingOutputIndex: f.verified.candidate.fundingIndex,
				localFundingPubkey: terms.newLocalKey.toString('hex'),
				remoteFundingPubkey: terms.newPeerKey.toString('hex'),
				localFundingKeyIndex: f.keyIndex
			}
		};
		this.candidateTerms = {
			...session.terms,
			commitmentFeeratePerKw: f.commitmentFeeratePerKw
		};
		const [b0, b1] = f.layout.firstCommitment.balanceMsat;
		this.balances = f.isInitiator
			? { localBalanceMsat: b0, remoteBalanceMsat: b1 }
			: { localBalanceMsat: b1, remoteBalanceMsat: b0 };
		this.points = {
			local: getPublicKey(
				generateFromSeed(this.keys.perCommitmentSeed, MAX_INDEX - this.N)
			),
			remote: Buffer.from(this.parentBranch.remoteRecovery.point, 'hex')
		};
		this.nonceContext = spliceCommitmentNonceContext(
			this.id,
			tx.getHash(),
			f.verified.candidate.fundingIndex
		);
	}

	/** The parent branch of the current type at N on the live funding (4.3). */
	private buildParent(): IFinalExitBranch {
		const p = this.f.parent;
		if (p.type === 'asset') {
			const branch = finalBranchReaders(this.store)!.conversionAssetParent(
				this.id
			);
			if (!branch) throw new Error(T.ledger);
			return branch;
		}
		const readers = finalBranchReaders(this.store)!;
		const ledger = readers.currentLedgerCommitments(this.id, Number(this.N));
		const states = this.store.loadFinalResolutionStates(this.id);
		if (!ledger || !states || states.remote.length !== 1)
			throw new Error(T.ledger);
		const recovery = (
			s: NonNullable<typeof states>['local']
		): IPlainExitBranch['localRecovery'] => ({
			point: s.point.toString('hex'),
			localBalanceMsat: String(s.localBalanceMsat),
			remoteBalanceMsat: String(s.remoteBalanceMsat),
			feeratePerKw: s.feeratePerKw,
			htlcs: []
		});
		return {
			type: 'plain',
			channelType: p.channelType,
			minimumDepth: this.opening.minimumDepth,
			funding: { ...p.funding },
			fundingTxid: p.txid,
			outputIndex: p.outputIndex,
			localCommitment: ledger.local,
			remoteCommitment: ledger.remote,
			localRecovery: recovery(states.local),
			remoteRecovery: recovery(states.remote[0])
		};
	}

	private get viewContext(): IConversionViewContext {
		return conversionViewContext(
			this.opening,
			this.session.terms,
			this.session.assetEvidence?.fundingRoot
		);
	}

	/** A parent holder's view: a plain branch as retain rebuilds it, an asset one with the given leaves. */
	private parentView(
		holder: Holder,
		exit?: IAssetOpenExit | null
	): IHolderView {
		const b = this.parentBranch;
		const recovery = holder === 'local' ? b.localRecovery : b.remoteRecovery;
		const state = {
			point: Buffer.from(recovery.point, 'hex'),
			localBalanceMsat: BigInt(recovery.localBalanceMsat),
			remoteBalanceMsat: BigInt(recovery.remoteBalanceMsat)
		};
		if (b.type === 'plain')
			return {
				state,
				v: (
					conversionRecoveryView(
						this.viewContext,
						b,
						holder,
						String(this.N)
					) as { view: IFinalCommitmentView }
				).view
			};
		const v = buildAssetSpliceCommitment(
			this.opening,
			{ ...this.session.terms, commitmentFeeratePerKw: b.feeratePerKw },
			holder,
			state.point,
			this.N,
			state,
			[],
			b.funding,
			this.openingRoot ?? Buffer.alloc(0),
			{
				fundingRoot: Buffer.from(b.fundingRoot, 'hex'),
				toLocal: leaf(exit?.toLocal),
				toRemote: leaf(exit?.toRemote)
			},
			branchCommitmentType(ASSET_SPLICE_RECOVERY_TYPE_HEX, this.openingRoot)
		);
		return { state, v };
	}

	/** A candidate holder's view in the target type (4.4), an asset one with the given leaves. */
	private candidateView(
		holder: Holder,
		exit?: IAssetOpenExit | null
	): IHolderView {
		const state = { point: this.points[holder], ...this.balances };
		const v = this.toAsset
			? buildAssetSpliceCommitment(
					this.opening,
					this.candidateTerms,
					holder,
					state.point,
					this.N,
					this.balances,
					[],
					this.funding.candidate,
					this.openingRoot ?? Buffer.alloc(0),
					{
						fundingRoot: this.f.verified.fundingRoot!,
						toLocal: leaf(exit?.toLocal),
						toRemote: leaf(exit?.toRemote)
					},
					branchCommitmentType(ASSET_SPLICE_RECOVERY_TYPE_HEX, this.openingRoot)
			  )
			: buildFinalCommitmentView(
					this.opening,
					this.candidateTerms,
					holder,
					state.point,
					this.N,
					this.balances,
					[],
					this.funding.candidate,
					branchCommitmentType(this.f.targetType, this.openingRoot)
			  );
		return { state, v };
	}

	/** This side's last `tx_complete`: the candidate's commit nonces at N and N+1 and the shared input nonce. */
	txComplete(): Buffer {
		const height = Number(this.N);
		const nonce = (n: number): Buffer =>
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
				this.f.verified.candidate,
				this.oldKey,
				this.authority
			)
		});
	}

	/** The interactive construction of the frozen candidate, its frames in memory only. */
	construction(): SpliceConstructionCore {
		if (this.core) return this.core;
		const records: unknown[] = [];
		this.core = new SpliceConstructionCore(
			{
				channelId: Buffer.from(this.id, 'hex'),
				attempt: this.f.attempt,
				finalDigest: this.f.verified.finalDigest.toString('hex'),
				transaction: this.f.verified.candidate.tx.toHex(),
				terms: this.f.verified.terms,
				inputs: this.f.layout.inputs,
				outputs: this.f.layout.outputs
			},
			this.txComplete(),
			{
				read: (): { records: unknown[] } => ({ records: [...records] }),
				append: (_head, entry): void => {
					records.push(entry);
				}
			}
		);
		return this.core;
	}

	/** The completed construction, which must build the frozen candidate. */
	agreement(): NonNullable<ReturnType<SpliceConstructionCore['agreement']>> {
		const g = this.construction().agreement();
		if (!g) throw new Error(T.construction);
		if (
			!g.candidate.tx.getHash().equals(this.f.verified.candidate.tx.getHash())
		)
			throw new Error(T.interactive);
		return g;
	}

	/** The views both hosts sign and verify the exits against, built without leaves. */
	hostViews(): IAssetConversionHostExitViews {
		const holderView = (
			name: Branch,
			holder: Holder
		): IAssetSpliceHostHolder => {
			const { state, v } =
				name === 'parent'
					? this.parentView(holder)
					: this.candidateView(holder);
			return {
				point: Buffer.from(state.point),
				localBalanceMsat: state.localBalanceMsat,
				remoteBalanceMsat: state.remoteBalanceMsat,
				htlcs: [],
				tx: v.tx,
				outputMap: v.outputMap,
				keys: v.keys,
				htlcOutputs: v.htlcs,
				toSelfDelay: v.toSelfDelay
			};
		};
		const branch = (name: Branch): IAssetConversionHostBranch => {
			const asset = name === 'parent' ? !this.toAsset : this.toAsset;
			const channelType =
				name === 'parent' ? this.f.parent.channelType : this.f.targetType;
			const base = {
				channelType,
				funding: { ...this.funding[name] },
				local: holderView(name, 'local'),
				remote: holderView(name, 'remote')
			};
			if (!asset) return { type: 'plain', ...base };
			const root =
				name === 'parent'
					? Buffer.from(
							(this.parentBranch as IAssetExitBranch).fundingRoot,
							'hex'
					  )
					: Buffer.from(this.f.verified.fundingRoot!);
			return { type: 'asset', ...base, fundingRoot: root };
		};
		const points = [
			this.session.terms.localBasepoints.paymentBasepoint,
			this.session.terms.remoteBasepoints.paymentBasepoint
		];
		if (!this.f.isInitiator) points.reverse();
		const withdrawals = this.withdrawals();
		return {
			terms: copyJson(this.candidateTerms),
			originalInitiator: this.opening.isInitiator,
			finalDigest: Buffer.from(this.f.verified.finalDigest),
			layoutDigest: Buffer.from(this.f.verified.layoutDigest),
			fundingFeeratePerkw: this.f.layout.feeratePerKw,
			paymentBasepoints: [
				Buffer.from(points[0], 'hex'),
				Buffer.from(points[1], 'hex')
			],
			parent: branch('parent'),
			candidate: branch('candidate'),
			...(withdrawals && { withdrawals })
		};
	}

	/** To bitcoin: the layout's withdrawal movements, by output index and owner. */
	private withdrawals(): IAssetConversionWithdrawal[] | undefined {
		if (this.toAsset) return undefined;
		const own = this.f.isInitiator ? 0n : 1n;
		return this.f.layout.movements.map((m) => ({
			assetId: m.assetId,
			from: m.from,
			outputSerial: m.outputSerial,
			outputIndex: this.f.layout.outputs.findIndex(
				(o) => o.serialId === m.outputSerial
			),
			units: m.units,
			owner: (m.outputSerial & 1n) === own ? 'local' : 'remote'
		}));
	}

	/** This side's exit share from the host, 1 byte to 4 MiB. */
	async signExitShares(
		host: IAssetConversionSigningHost,
		ctx: IAssetConversionContext
	): Promise<Buffer> {
		return this.exitShare(
			await host.signConversionExits(ctx, this.hostViews())
		);
	}

	/** A host's exit share: 1 byte to 4 MiB. */
	exitShare(share: unknown): Buffer {
		if (
			!Buffer.isBuffer(share) ||
			!share.length ||
			share.length > ASSET_OPEN_OBJECT_LIMIT
		)
			throw new Error(T.sign);
		return Buffer.from(share);
	}

	/** Both shares verified by the host, and its evidence checked against the views (4.4). */
	async verifyExitShares(
		host: IAssetConversionSigningHost,
		ctx: IAssetConversionContext,
		shares: AssetOpenPair<Buffer>
	): Promise<VerifiedConversionExits> {
		const answer = await host.verifyConversionExits(ctx, this.hostViews(), [
			Buffer.from(shares[0]),
			Buffer.from(shares[1])
		]);
		if (!isRecord(answer)) throw new Error(T.verify);
		return this.checkEvidence(answer);
	}

	/** The evidence checks of 4.4: only the asset branch has evidence, its proofs and leaves, and the parent. */
	checkEvidence(answer: unknown): VerifiedConversionExits {
		let copy: IAssetConversionExitEvidence;
		try {
			copy = copyJson(answer) as IAssetConversionExitEvidence;
			if (!isRecord(copy)) throw new Error(T.evidence);
			const assetName: Branch = this.toAsset ? 'candidate' : 'parent';
			const plainName: Branch = this.toAsset ? 'parent' : 'candidate';
			if (copy[plainName] !== null || !isRecord(copy[assetName]))
				throw new Error(T.evidence);
			for (const h of ['local', 'remote'] as const) {
				const e = copy[assetName]![h];
				if (
					!isRecord(e) ||
					typeof e.proofs !== 'string' ||
					!/^(?:[0-9a-f]{2})+$/.test(e.proofs)
				)
					throw new Error(T.evidence);
				leaf(e.toLocal);
				leaf(e.toRemote);
			}
		} catch {
			throw new Error(T.evidence);
		}
		if (!this.toAsset) {
			const b = this.parentBranch as IAssetExitBranch;
			for (const h of ['local', 'remote'] as const) {
				const e = copy.parent![h];
				const recovery = h === 'local' ? b.localRecovery : b.remoteRecovery;
				if (
					e.proofs !== (h === 'local' ? b.localProofs : b.remoteProofs) ||
					!isDeepStrictEqual(recovery.toLocal ?? null, e.toLocal ?? null) ||
					!isDeepStrictEqual(recovery.toRemote ?? null, e.toRemote ?? null)
				)
					throw new Error(T.parentProofs);
			}
		}
		try {
			validateFinalSpliceExit(
				{
					expected: this.parentView('local', copy.parent?.local).v.tx,
					signed: Transaction.fromHex(this.parentBranch.localCommitment)
				},
				this.f.verified.terms.parent,
				this.f.verified.terms.parentIndex
			);
		} catch {
			throw new Error(T.evidence);
		}
		const handle = Object.freeze({
			digest: sha256(Buffer.from(JSON.stringify(copy))).toString('hex')
		});
		this.evidence.set(handle, copy);
		return handle;
	}

	private leaves(
		handle: VerifiedConversionExits
	): IAssetConversionExitEvidence {
		const e = this.evidence.get(handle);
		if (!e) throw new Error(T.evidence);
		return e;
	}

	/** Sign the peer's candidate commitment, or aggregate the peer's share into our own. */
	private commitment(handle: VerifiedConversionExits, peer?: Buffer): Buffer {
		const g = this.agreement();
		const holder: Holder = peer ? 'local' : 'remote';
		const exit = this.leaves(handle).candidate?.[holder];
		const { state, v } = this.candidateView(holder, exit);
		return signFinalUpdate(
			this.opening,
			v,
			state.point,
			Number(this.N),
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
				...(this.toAsset && {
					asset: {
						fundingRoot: this.f.verified.fundingRoot!,
						transcriptDigest: Buffer.from(this.f.verified.finalDigest)
					}
				})
			},
			this.toAsset ? ASSET_SPLICE_RECOVERY_TYPE_HEX : this.f.targetType
		);
	}

	/** Our candidate `commitment_signed`, made once. */
	commitmentSigned(handle: VerifiedConversionExits): Buffer {
		this.local ??= this.commitment(handle);
		return Buffer.from(this.local);
	}

	/** The peer's candidate `commitment_signed`: its partial verified and our local exit aggregated. */
	acceptCommitmentSigned(handle: VerifiedConversionExits, wire: Buffer): void {
		if (this.peer) return;
		const signed = this.commitment(handle, wire);
		this.peer = Buffer.from(wire);
		this.signedLocal = Buffer.from(signed);
	}

	/** The two branches the engine retains: its own parent and candidate with the exact commitments. */
	private expected(handle: VerifiedConversionExits): IFinalConversionExits {
		const leaves = this.leaves(handle);
		const candidateRemote = this.candidateView(
			'remote',
			leaves.candidate?.remote
		).v.tx;
		const local = Transaction.fromBuffer(this.signedLocal!);
		const base = {
			minimumDepth: this.f.lockDepth,
			funding: { ...this.funding.candidate },
			fundingTxid: this.f.verified.candidate.tx.getId(),
			outputIndex: this.f.verified.candidate.fundingIndex
		};
		const balances = (
			holder: Holder
		): {
			point: string;
			localBalanceMsat: string;
			remoteBalanceMsat: string;
		} => ({
			point: this.points[holder].toString('hex'),
			localBalanceMsat: String(this.balances.localBalanceMsat),
			remoteBalanceMsat: String(this.balances.remoteBalanceMsat)
		});
		let candidate: IFinalExitBranch;
		if (!this.toAsset)
			candidate = {
				type: 'plain',
				channelType: this.f.targetType,
				...base,
				localCommitment: local.toHex(),
				remoteCommitment: candidateRemote.toHex(),
				localRecovery: {
					...balances('local'),
					feeratePerKw: this.candidateTerms.commitmentFeeratePerKw,
					htlcs: []
				},
				remoteRecovery: {
					...balances('remote'),
					feeratePerKw: this.candidateTerms.commitmentFeeratePerKw,
					htlcs: []
				}
			};
		else {
			const e = leaves.candidate!;
			const recovery = (holder: Holder): IAssetSpliceHolderRecovery => {
				const v = this.candidateView(holder, e[holder]).v;
				return {
					...balances(holder),
					ownedOutputIndex:
						(holder === 'local' ? v.outputMap.toLocal : v.outputMap.toRemote) ??
						null,
					toLocal: storedLeaf(e[holder].toLocal),
					toRemote: storedLeaf(e[holder].toRemote),
					htlcs: []
				};
			};
			candidate = {
				type: 'asset',
				feeratePerKw: this.candidateTerms.commitmentFeeratePerKw,
				...base,
				fundingRoot: this.f.verified.fundingRoot!.toString('hex'),
				fundingProofs: this.f.verified.fundingProofs!.toString('hex'),
				localCommitment: local.toHex(),
				localProofs: e.local.proofs,
				remoteCommitment: candidateRemote.toHex(),
				remoteProofs: e.remote.proofs,
				localRecovery: recovery('local'),
				remoteRecovery: recovery('remote')
			} as IFinalExitBranch;
		}
		return {
			stateNumber: String(this.N),
			digest: this.f.verified.finalDigest.toString('hex'),
			parent: copyJson(this.parentBranch),
			candidate
		};
	}

	/**
	 * The host retains both branches and, to bitcoin on the buyer's side, the
	 * withdrawal receipts; the engine checks its receipt (9.4) and returns
	 * the exits to retain. Nothing is written here.
	 */
	async retainExits(
		host: IAssetConversionSigningHost,
		ctx: IAssetConversionContext,
		handle: VerifiedConversionExits
	): Promise<IFinalConversionExits> {
		const exact = this.exact(handle);
		const receipt = await host.retainConversionExits(
			ctx,
			this.hostViews(),
			exact
		);
		if (!isRecord(receipt)) throw new Error(T.retain);
		return this.checkReceipt(
			receipt as unknown as IAssetConversionExitReceipt,
			handle
		);
	}

	/**
	 * The exact set the host retains: the parent's signed local exit and its
	 * remote commitment, the candidate's aggregated local commitment and its
	 * remote commitment.
	 */
	exact(
		handle: VerifiedConversionExits
	): Record<Branch, Record<Holder, Transaction>> {
		if (!this.local || !this.peer || !this.signedLocal)
			throw new Error(T.commitments);
		const leaves = this.leaves(handle);
		return {
			parent: {
				local: Transaction.fromHex(this.parentBranch.localCommitment),
				remote: Transaction.fromHex(this.parentBranch.remoteCommitment)
			},
			candidate: {
				local: Transaction.fromBuffer(this.signedLocal),
				remote: this.candidateView('remote', leaves.candidate?.remote).v.tx
			}
		};
	}

	/** The receipt against the engine's own branches and the layout's withdrawals (9.4). */
	checkReceipt(
		receipt: IAssetConversionExitReceipt,
		handle: VerifiedConversionExits
	): IFinalConversionExits {
		const exits = this.expected(handle);
		let same = false;
		try {
			same =
				receipt.channelId === this.id &&
				receipt.finalDigest === exits.digest &&
				receipt.stateNumber === exits.stateNumber &&
				isDeepStrictEqual(copyJson(receipt.parent), exits.parent) &&
				isDeepStrictEqual(
					copyJson(receipt.candidate),
					copyJson(exits.candidate)
				);
		} catch {
			same = false;
		}
		if (!same) throw new Error(T.receipt);
		const owned = (this.withdrawals() ?? []).filter((w) => w.owner === 'local');
		const given = Array.isArray(receipt.withdrawals)
			? receipt.withdrawals
			: null;
		// One receipt per owned withdrawal, matched one to one.
		const used = new Set<number>();
		if (
			!given ||
			given.length !== owned.length ||
			owned.some((w) => {
				const k = given.findIndex(
					(r, i) =>
						!used.has(i) &&
						isRecord(r) &&
						r.outputIndex === w.outputIndex &&
						r.assetId === w.assetId &&
						r.units === w.units.toString() &&
						typeof r.proof === 'string' &&
						r.proof.length > 0 &&
						r.proof.length <= ASSET_OPEN_OBJECT_LIMIT * 2 &&
						/^(?:[0-9a-f]{2})+$/.test(r.proof)
				);
				if (k < 0) return true;
				used.add(k);
				return false;
			})
		)
			throw new Error(T.withdrawal);
		return exits;
	}
}
