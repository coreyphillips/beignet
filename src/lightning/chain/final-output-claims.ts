import { Transaction } from 'bitcoinjs-lib';
import { getPerCommitmentPoint } from '../channel/channel-helpers';
import {
	buildFinalOpeningCommitment,
	buildFinalCommitmentView,
	type IFinalCommitmentView
} from '../channel/final-opening-commitment';
import type { IFinalOpeningRuntime } from '../channel/final-opening-runtime';
import { derivePrivateKey, deriveRevocationPrivkey } from '../keys/derivation';
import { deriveChannelKeys } from '../keys/wallet-keys';
import {
	buildTaprootToLocalOutput,
	buildTaprootSecondLevelOutput,
	tweakTaprootKeyPathPrivkey,
	buildTaprootToRemoteOutput,
	type ITaprootLeafSpend
} from '../script/commitment-taproot';
import { signTaprootHtlcLeaf, tapleafHash } from '../script/htlc-taproot';
import { decodeCommitmentSignedMessage } from '../message/channel-commitment';
import { sha256 } from '../crypto/provider';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import type { IFundingProvider } from '../node/types';
import { attachFeeInputsToZeroFeeHtlcTx } from './sweep';
import { satPerVbyteToSatPerKw } from './types';
import { isDustOutput } from './closing';
import type { IAuxiliaryDualFunding } from '../channel/asset-opening-provider';
import type { IFinalCommitmentType } from '../channel/final-opening-commitment';
import {
	finalBranchReaders,
	type IFinalChannelFunding
} from '../storage/final-branch-readers';
import {
	finalSpendBranch,
	hasFinalBranchRows,
	spendsBranch
} from './final-spend-branch';

type AssetClaimBuilder =
	typeof import('./asset-opening-claims').assetOpeningOutputClaims;

export interface IFinalOutputClaim {
	outputIndex: number;
	relativeDelay: number;
	absoluteHeight: number;
	/** Absent when the output is uneconomic at the current rate but its spend still settles a payment. */
	tx: Transaction | null;
	/** Builds an asset-preserving payout only once the exact outpoint is spendable. */
	recover?: (sponsored?: Transaction) => Promise<Transaction | null>;
	/** Asset HTLC proofs must bind a confirmed block and its observed parent. */
	confirmedOnly?: boolean;
	/** The reconstructed local balance output of a dual-funded asset opening. */
	assetBalanceOutput?: boolean;
	/** Recognizes the authorized payout of this balance outpoint after restart. */
	matchesAssetPayout?: (spend: Transaction) => boolean;
	/** Import an exact confirmed terminal payout using its original-device receipt. */
	confirmAssetPayout?: (spend: Transaction) => Promise<boolean>;
	sponsor?: boolean;
	paymentHash?: Buffer;
	htlcId?: bigint;
	child?: (tx: Transaction, inputIndex: number) => IFinalOutputClaim | null;
}

/** Price the exact witness and destination before signing a wallet-owned leaf. */
export function finalLeafClaim(
	parent: Transaction,
	index: number,
	outputScript: Buffer,
	leaf: ITaprootLeafSpend,
	privateKey: Buffer,
	destination: Buffer,
	feeRate: number,
	delay: number,
	height = 0,
	stack: Buffer[] = []
): IFinalOutputClaim | null {
	const output = parent.outs[index];
	if (
		!output?.script.equals(outputScript) ||
		!Number.isFinite(feeRate) ||
		feeRate <= 0
	)
		return null;
	const tx = new Transaction();
	tx.version = 2;
	tx.locktime = height;
	tx.addInput(parent.getHash(), index, delay);
	tx.addOutput(destination, output.value);
	const tail = [...stack, leaf.script, leaf.controlBlock];
	tx.setWitness(0, [Buffer.alloc(64), ...tail]);
	const amount = output.value - Math.ceil(tx.virtualSize() * feeRate);
	if (
		!Number.isSafeInteger(amount) ||
		amount <= 0 ||
		isDustOutput(destination, BigInt(amount))
	)
		return null;
	tx.outs[0].value = amount;
	const digest = tx.hashForWitnessV1(
		0,
		[output.script],
		[output.value],
		Transaction.SIGHASH_DEFAULT,
		tapleafHash(leaf.script, leaf.leafVersion)
	);
	tx.setWitness(0, [signTaprootHtlcLeaf(digest, privateKey), ...tail]);
	return {
		outputIndex: index,
		relativeDelay: delay,
		absoluteHeight: height,
		tx
	};
}

/** Sweep a breached HTLC or its delayed child through the Taproot internal revocation key. */
function keyPathClaim(
	parent: Transaction,
	index: number,
	output: { output: Buffer; merkleRoot: Buffer },
	secret: Buffer,
	destination: Buffer,
	feeRate: number
): IFinalOutputClaim | null {
	const coin = parent.outs[index];
	if (!coin?.script.equals(output.output)) return null;
	const tx = new Transaction();
	tx.version = 2;
	tx.addInput(parent.getHash(), index, 0xfffffffd);
	tx.addOutput(destination, coin.value);
	tx.setWitness(0, [Buffer.alloc(64)]);
	const amount = coin.value - Math.ceil(tx.virtualSize() * feeRate);
	if (
		!Number.isSafeInteger(amount) ||
		amount <= 0 ||
		isDustOutput(destination, BigInt(amount))
	)
		return null;
	tx.outs[0].value = amount;
	const key = tweakTaprootKeyPathPrivkey(secret, output.merkleRoot);
	const digest = tx.hashForWitnessV1(
		0,
		[coin.script],
		[coin.value],
		Transaction.SIGHASH_DEFAULT
	);
	tx.setWitness(0, [signTaprootHtlcLeaf(digest, key)]);
	return { outputIndex: index, relativeDelay: 0, absoluteHeight: 0, tx };
}

/**
 * Claims for one final channel, by that channel's own kind: a plain channel
 * from the plain builder, an asset channel from the asset builder, and an
 * unknown channel from neither. A wallet that runs both kinds of channel
 * decides per channel, not once per wallet.
 *
 * A channel with a `channel-type` record or a conversion exit is claimed by
 * the branch the commitment spends (#2151 step 2b): the type and era of that
 * funding output decide the builder and its views, and an outpoint the
 * channel never had gives no claim. Every other channel takes today's path
 * after one row count.
 */
export function finalChannelOutputClaims(
	runtime: IFinalOpeningRuntime,
	id: Buffer,
	parent: Transaction,
	destination: Buffer,
	feeRate: number,
	provider: IAuxiliaryDualFunding | undefined,
	trimmed:
		| ((hash: Buffer, htlcId: bigint, preimage?: Buffer) => void)
		| undefined,
	kindOf: (channelId: string) => 'plain' | 'asset' | null,
	builders: {
		plain?: typeof finalOpeningOutputClaims;
		asset?: AssetClaimBuilder;
	} = {},
	branch?: IFinalChannelFunding | null
): IFinalOutputClaim[] {
	const channelId = id.toString('hex');
	const spend =
		branch !== undefined
			? branch
			: hasFinalBranchRows(runtime.storage, channelId)
			? finalSpendBranch(runtime.storage, channelId, parent)
			: undefined;
	if (spend === null) return [];
	// One claim build reads each source of peer secrets once.
	const readers = spend && finalBranchReaders(runtime.storage);
	if (readers)
		return readers.finalPeerSecretScope(() =>
			dispatch(
				spend,
				kindOf,
				builders,
				runtime,
				id,
				parent,
				destination,
				feeRate,
				provider,
				trimmed
			)
		);
	return dispatch(
		spend,
		kindOf,
		builders,
		runtime,
		id,
		parent,
		destination,
		feeRate,
		provider,
		trimmed
	);
}

function dispatch(
	spend: IFinalChannelFunding | undefined,
	kindOf: (channelId: string) => 'plain' | 'asset' | null,
	builders: {
		plain?: typeof finalOpeningOutputClaims;
		asset?: AssetClaimBuilder;
	},
	runtime: IFinalOpeningRuntime,
	id: Buffer,
	parent: Transaction,
	destination: Buffer,
	feeRate: number,
	provider: IAuxiliaryDualFunding | undefined,
	trimmed:
		| ((hash: Buffer, htlcId: bigint, preimage?: Buffer) => void)
		| undefined
): IFinalOutputClaim[] {
	const kind = spend ? spend.type : kindOf(id.toString('hex'));
	const branchArgs: [] | [IFinalChannelFunding] = spend ? [spend] : [];
	if (kind === 'plain')
		return (builders.plain ?? finalOpeningOutputClaims)(
			runtime,
			id,
			parent,
			destination,
			feeRate,
			trimmed,
			...branchArgs
		);
	if (kind === 'asset')
		return (
			builders.asset ??
			// Loaded on use: the asset builder imports this module's leaf claims.
			(
				require('./asset-opening-claims') as typeof import('./asset-opening-claims')
			).assetOpeningOutputClaims
		)(
			runtime,
			id,
			parent,
			destination,
			feeRate,
			provider,
			trimmed,
			...branchArgs
		);
	return [];
}

/**
 * A channel with a `channel-type` record is claimed by branch (#2151 step
 * 2b): a builder called without a branch gives it no claims, as in step 2a.
 */
export function recordedChannelType(
	storage: IFinalOpeningRuntime['storage'],
	channelId: string
): boolean {
	const records = (
		storage as {
			loadFinalChannelTypeRecords?: (id: string) => readonly unknown[];
		}
	).loadFinalChannelTypeRecords;
	return (
		typeof records === 'function' && records.call(storage, channelId).length > 0
	);
}

/** Rebuild only a journaled commitment, including every eligible output of revoked remote states. */
export function finalOpeningOutputClaims(
	runtime: IFinalOpeningRuntime,
	id: Buffer,
	parent: Transaction,
	destination: Buffer,
	feeRate: number,
	trimmed?: (hash: Buffer, htlcId: bigint, preimage?: Buffer) => void,
	branch?: IFinalChannelFunding
): IFinalOutputClaim[] {
	const storage = runtime.storage;
	if (
		!storage.canUpdateFinalCommitments ||
		!Number.isFinite(feeRate) ||
		feeRate <= 0
	)
		return [];
	const channelId = id.toString('hex'),
		session = storage.loadFinalOpeningSession(channelId);
	let ledger: ReturnType<typeof storage.loadFinalResolutionStates>;
	let as: IFinalCommitmentType | undefined;
	let peerSecret:
		| ((s: { height: bigint; point: Buffer }) => Buffer | undefined)
		| undefined;
	let ownRevoked = (_height: bigint): boolean => false;
	if (!branch) {
		if (recordedChannelType(storage, channelId)) return [];
		// Plain channels only: an asset channel is claimed by assetOpeningOutputClaims.
		if (!session || session.assetEvidence) return [];
		ledger = storage.loadFinalResolutionStates(channelId);
	} else {
		// A plain branch of any era: its views, its type, and the store's secrets.
		const readers = finalBranchReaders(storage);
		if (
			!session ||
			!readers ||
			branch.type !== 'plain' ||
			!spendsBranch(parent, branch)
		)
			return [];
		if (branch.source === 'conversion') {
			ledger = conversionResolutionStates(
				storage,
				channelId,
				readers.finalConversion(channelId, branch.digest ?? '')
			);
		} else {
			const era = branch.era ?? 0;
			ledger = readers.loadFinalEraResolutionStates(channelId, era);
			peerSecret = (s): Buffer | undefined =>
				readers.loadFinalPeerSecret(channelId, s.height, s.point).secret ??
				undefined;
			ownRevoked = (height): boolean =>
				readers.finalOwnCommitmentRevoked(channelId, era, height);
		}
		as = readers.finalPlainBranchType(channelId, branch);
		if (!ledger && (branch.source !== 'opening' || session.assetEvidence))
			return [];
	}
	const opening = ledger
		? undefined
		: storage.loadFinalDaemonOpening(channelId);
	if (!ledger && !opening?.funding) return [];
	type Resolution = NonNullable<typeof ledger>;
	const openingView = (side: 'local' | 'remote'): Resolution['local'] => {
		const { candidate } = opening!;
		const terms = session.terms;
		const rootKeys = deriveChannelKeys(
			runtime.root,
			1,
			session.channelKeyIndex
		);
		const point =
			side === 'local'
				? getPerCommitmentPoint(rootKeys.perCommitmentSeed, 0n)
				: Buffer.from(terms.remoteBasepoints.firstPerCommitmentPoint, 'hex');
		const tx = buildFinalOpeningCommitment(candidate, terms, side);
		return {
			height: 0n,
			feeratePerKw: terms.commitmentFeeratePerKw,
			point,
			tx: tx.toBuffer(),
			htlcs: [],
			localBalanceMsat: BigInt(candidate.localContributionSats) * 1000n,
			remoteBalanceMsat: BigInt(candidate.remoteContributionSats) * 1000n,
			secret: undefined,
			commitmentSigned: undefined
		};
	};
	const states: Resolution = ledger ?? {
		candidate: opening!.candidate,
		terms: session.terms,
		local: openingView('local'),
		locals: [],
		remote: [openingView('remote')],
		revoked: [],
		preimages: []
	};
	const matches = (s: typeof states.local): boolean =>
		Transaction.fromBuffer(s.tx).getId() === parent.getId();
	const local = (states.locals?.length ? states.locals : [states.local]).find(
		matches
	);
	let state:
		| (typeof states.local & { funding?: IFinalFundingReference })
		| undefined =
		local ?? states.revoked.find(matches) ?? states.remote.find(matches);
	if (!state) return [];
	// A branch's peer commitment is revoked when any ledger holds its height's
	// secret; our own commitment revoked since by a later era is never claimed.
	if (local && ownRevoked(state.height)) return [];
	if (!local && peerSecret) {
		const secret = peerSecret(state) ?? state.secret;
		if (secret) state = { ...state, secret };
	}
	const { candidate, terms } = states;
	const view = buildFinalCommitmentView(
		candidate,
		{ ...terms, commitmentFeeratePerKw: state.feeratePerKw },
		local ? 'local' : 'remote',
		state.point,
		state.height,
		state,
		state.htlcs,
		state.funding,
		...(as ? [as] : [])
	);
	if (view.tx.getId() !== parent.getId())
		throw new Error('Final commitment does not match its resolution data');
	if (trimmed) {
		const offeredOutputs = new Set(
			view.htlcs
				.filter((h) => h.htlc.offeredBy === 'local')
				.map((h) => h.htlc.id)
		);
		for (const htlc of state.htlcs) {
			if (htlc.offeredBy !== 'local' || offeredOutputs.has(htlc.id)) continue;
			const preimage = states.preimages.find((p) =>
				sha256(p).equals(htlc.paymentHash)
			);
			trimmed(htlc.paymentHash, htlc.id, preimage);
		}
	}
	const keys = deriveChannelKeys(runtime.root, 1, session.channelKeyIndex);
	const delayedKey = derivePrivateKey(
		keys.delayedPaymentBasepointSecret,
		state.point,
		keys.channelBasepoints.delayedPaymentBasepoint
	);
	const htlcKey = derivePrivateKey(
		keys.htlcBasepointSecret,
		state.point,
		keys.channelBasepoints.htlcBasepoint
	);
	const revoked =
		state.secret &&
		deriveRevocationPrivkey(
			keys.revocationBasepointSecret,
			state.secret,
			keys.channelBasepoints.revocationBasepoint,
			state.point
		);
	const toLocal = buildTaprootToLocalOutput(
		view.keys.revocationPubkey,
		view.keys.localDelayedPubkey,
		view.toSelfDelay,
		undefined,
		'final'
	);
	const toRemote = buildTaprootToRemoteOutput(
		keys.channelBasepoints.paymentBasepoint,
		undefined,
		'final'
	);
	const second = buildTaprootSecondLevelOutput(
		view.keys.revocationPubkey,
		view.keys.localDelayedPubkey,
		view.toSelfDelay,
		undefined,
		'final'
	);
	const claims: IFinalOutputClaim[] = [];
	const add = (c: IFinalOutputClaim | null): void => {
		if (c) claims.push(c);
	};
	const index = (script: Buffer): number =>
		parent.outs.findIndex((out) => out.script.equals(script));
	if (local)
		add(
			finalLeafClaim(
				parent,
				index(toLocal.output),
				toLocal.output,
				toLocal.delay,
				delayedKey,
				destination,
				feeRate,
				view.toSelfDelay
			)
		);
	else {
		add(
			finalLeafClaim(
				parent,
				index(toRemote.output),
				toRemote.output,
				toRemote.spend,
				keys.paymentBasepointSecret,
				destination,
				feeRate,
				1
			)
		);
		if (revoked)
			add(
				finalLeafClaim(
					parent,
					index(toLocal.output),
					toLocal.output,
					toLocal.revoke,
					revoked,
					destination,
					feeRate,
					0
				)
			);
	}
	const sigs =
		local?.commitmentSigned &&
		decodeCommitmentSignedMessage(local.commitmentSigned).htlcSignatures;
	for (const [n, h] of view.htlcs.entries()) {
		const preimage = states.preimages.find((p) =>
			sha256(p).equals(h.htlc.paymentHash)
		);
		const claim = finalHtlcClaim({
			h,
			parent,
			local: !!local,
			revoked,
			delayedKey,
			htlcKey,
			destination,
			feeRate,
			preimage,
			peerSignature: sigs?.[n],
			second,
			toSelfDelay: view.toSelfDelay
		});
		if (claim) claims.push(claim);
	}
	return claims;
}

/** A pending plain candidate's views: its local and remote commitments at the conversion's height, and no revoked state. */
function conversionResolutionStates(
	storage: IFinalOpeningRuntime['storage'],
	channelId: string,
	exits: ReturnType<
		NonNullable<ReturnType<typeof finalBranchReaders>>['finalConversion']
	>
): ReturnType<typeof storage.loadFinalResolutionStates> {
	const opening = storage.loadFinalDaemonOpening(channelId);
	const branch = exits?.candidate;
	if (!opening || !exits || branch?.type !== 'plain') return null;
	const height = BigInt(exits.stateNumber);
	type View = NonNullable<
		ReturnType<typeof storage.loadFinalResolutionStates>
	>['local'];
	const view = (holder: 'local' | 'remote'): View => {
		const r = holder === 'local' ? branch.localRecovery : branch.remoteRecovery;
		return {
			feeratePerKw: r.feeratePerKw,
			height,
			funding: branch.funding,
			point: Buffer.from(r.point, 'hex'),
			tx: Buffer.from(
				holder === 'local' ? branch.localCommitment : branch.remoteCommitment,
				'hex'
			),
			localBalanceMsat: BigInt(r.localBalanceMsat),
			remoteBalanceMsat: BigInt(r.remoteBalanceMsat),
			htlcs: [],
			commitmentSigned: undefined as Buffer | undefined,
			secret: undefined as Buffer | undefined
		};
	};
	const local = view('local');
	return {
		candidate: opening.candidate,
		terms: opening.session.terms,
		local,
		locals: [local],
		remote: [view('remote')],
		revoked: [],
		preimages: []
	};
}

export function finalHtlcClaim(params: {
	h: IFinalCommitmentView['htlcs'][number];
	parent: Transaction;
	local: boolean;
	revoked?: Buffer;
	delayedKey: Buffer;
	htlcKey: Buffer;
	destination: Buffer;
	feeRate: number;
	preimage?: Buffer;
	peerSignature?: Buffer;
	second: ReturnType<typeof buildTaprootSecondLevelOutput>;
	toSelfDelay: number;
}): IFinalOutputClaim | null {
	const {
		h,
		parent,
		local,
		revoked,
		delayedKey,
		htlcKey,
		destination,
		feeRate,
		preimage,
		peerSignature,
		second,
		toSelfDelay
	} = params;
	const { outputIndex, htlc, tree } = h;
	const offered = htlc.offeredBy === 'local';
	let claim: IFinalOutputClaim | null;
	if (revoked) {
		claim = keyPathClaim(
			parent,
			outputIndex,
			tree,
			revoked,
			destination,
			feeRate
		);
	} else if (!offered && !preimage) {
		return null;
	} else if (!local) {
		const leaf = offered ? tree.timeout : tree.success;
		claim = finalLeafClaim(
			parent,
			outputIndex,
			tree.output,
			leaf,
			htlcKey,
			destination,
			feeRate,
			1,
			offered ? htlc.cltvExpiry : 0,
			offered ? [] : [preimage!]
		);
	} else {
		if (!peerSignature)
			throw new Error('Missing authenticated peer HTLC signature');
		const flag = Buffer.of(0x83);
		const remoteSig = Buffer.concat([peerSignature, flag]),
			ours = Buffer.concat([signTaprootHtlcLeaf(h.digest, htlcKey), flag]);
		const child = h.secondLevelTx.clone();
		child.setWitness(0, [
			remoteSig,
			ours,
			...(!offered ? [preimage!] : []),
			h.leaf.script,
			h.leaf.controlBlock
		]);
		claim = {
			outputIndex,
			relativeDelay: 1,
			absoluteHeight: offered ? htlc.cltvExpiry : 0,
			tx: child,
			sponsor: true
		};
	}
	if (!claim) {
		if (!offered && !revoked) return null;
		claim = { outputIndex, absoluteHeight: 0, relativeDelay: 0, tx: null };
	}
	if (offered) {
		claim.paymentHash = htlc.paymentHash;
		if (!revoked) claim.htlcId = htlc.id;
	}
	if (local || revoked)
		claim.child = (spender, inputIndex): IFinalOutputClaim | null => {
			// SIGHASH_SINGLE fixes the delayed output at the spending input's index,
			// including transactions aggregated with other HTLCs and wallet inputs.
			if (
				!spender.outs[inputIndex]?.script.equals(second.output) ||
				spender.outs[inputIndex].value !== parent.outs[outputIndex].value
			)
				return null;
			return revoked
				? keyPathClaim(
						spender,
						inputIndex,
						second,
						revoked,
						destination,
						feeRate
				  )
				: finalLeafClaim(
						spender,
						inputIndex,
						second.output,
						second.delay,
						delayedKey,
						destination,
						feeRate,
						toSelfDelay
				  );
		};
	return claim;
}

export async function sponsorFinalClaim(
	runtime: IFinalOpeningRuntime,
	wallet: IFundingProvider | null,
	id: Buffer,
	child: Transaction,
	rate: number
): Promise<Transaction> {
	const key = child.getId(),
		channel = id.toString('hex');
	const retained = runtime.storage.finalSponsoredClaim(channel, key);
	if (retained) {
		await wallet?.pledgeTransactionInputs?.(retained.toString('hex'));
		return Transaction.fromBuffer(retained);
	}
	if (!wallet?.selectFeeBumpInputs)
		throw new Error('No fee wallet available for final HTLC child');
	const { inputs, changeScript } = await wallet.selectFeeBumpInputs(
		BigInt(Math.ceil(child.virtualSize() * rate)),
		satPerVbyteToSatPerKw(rate),
		{
			confirmedOnly: true,
			excludeTxids: [Buffer.from(child.ins[0].hash).reverse().toString('hex')]
		}
	);
	const { tx } = attachFeeInputsToZeroFeeHtlcTx({
		htlcTx: child,
		htlcWitness: child.ins[0].witness,
		walletInputs: inputs,
		changeScript,
		feeratePerVbyte: rate
	});
	const raw = runtime.storage.finalSponsoredClaim(channel, key, tx.toHex());
	if (!raw) throw new Error('Could not retain signed final HTLC child');
	return Transaction.fromBuffer(raw);
}
