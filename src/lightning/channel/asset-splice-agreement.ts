import { Transaction } from 'bitcoinjs-lib';
import { REGTEST_CHAIN_HASH } from '../chain/hashes';
import { sha256 } from '../crypto/provider';
import type { IAssetSpliceWireRecordLimit } from '../features/asset-splice';
import { decodeSpliceMessage, decodeSpliceAckMessage } from '../message/splice';
import type { IFinalFundingReference } from './final-splice-candidate';
import type {
	AssetOpenPair,
	IAssetOpenFunding,
	IAssetOpenPlan
} from './asset-opening-provider';
import {
	assetSpliceLayoutDigest,
	verifyAssetSpliceCandidate,
	type IAssetSpliceLayout
} from './asset-splice-manifest';

type Pair<T> = AssetOpenPair<T>;
interface ParentView {
	oldOutpoint: { hash: Buffer; index: number };
	stateNumber: bigint;
	walletGeneration: 4;
}

export interface IAssetSpliceContext extends ParentView {
	channelId: string;
	peer: string;
	attempt: Buffer;
	isInitiator: boolean;
	/** Sourced from the enrolled device after quiescence and before each signature. */
	currentParent(): ParentView | undefined;
}
export interface IAssetSpliceBitcoin {
	fundingKeys: Pair<Buffer>;
	lockTime: number;
	minimumDepth: number;
	maxAcceptedHtlcs: Pair<number>;
}
export interface IAssetSpliceDescription {
	inputs: readonly {
		serialId: bigint;
		txid: Buffer;
		vout: number;
		sequence: number;
		isShared: boolean;
		prevTx?: Buffer;
	}[];
	outputs: readonly {
		serialId: bigint;
		kind: 'funding' | 'withdrawal' | 'change';
		valueSats: bigint;
		descriptorHash: Buffer;
	}[];
	movements: IAssetSpliceLayout['movements'];
	parentBalances: IAssetSpliceLayout['parentBalances'];
	feeBudgets: readonly bigint[];
	relativeSatoshis: readonly bigint[];
	commitmentRecordLimits: readonly (readonly IAssetSpliceWireRecordLimit[])[];
}
export interface IAssetSpliceWalletPlan extends IAssetOpenPlan {
	finalize(
		consents: Pair<Buffer>,
		authorizations: Pair<Buffer>
	): Promise<IAssetOpenFunding & { layoutDigest: Buffer }>;
}
export interface IAssetSplicePlanner {
	proposeSplice(ctx: IAssetSpliceContext): Promise<Buffer>;
	spliceContribution(ctx: IAssetSpliceContext): bigint;
	abandonSplice(ctx: IAssetSpliceContext): Promise<void>;
	describeSplice(
		ctx: IAssetSpliceContext,
		proposals: Pair<Buffer>,
		bitcoin: IAssetSpliceBitcoin
	): Promise<IAssetSpliceDescription>;
	prepareSplice(
		ctx: IAssetSpliceContext,
		proposals: Pair<Buffer>,
		bitcoin: IAssetSpliceBitcoin,
		layout: Buffer
	): Promise<IAssetSpliceWalletPlan>;
}
export interface IAssetSpliceChannelTerms {
	parent: IFinalFundingReference;
	parentRoot: Buffer;
	maxAcceptedHtlcs: Pair<number>;
	dust: bigint;
}

function fresh(ctx: IAssetSpliceContext): void {
	const current = ctx.currentParent();
	if (
		ctx.walletGeneration !== 4 ||
		current?.walletGeneration !== 4 ||
		current.stateNumber !== ctx.stateNumber ||
		current.oldOutpoint.index !== ctx.oldOutpoint.index ||
		!current.oldOutpoint.hash.equals(ctx.oldOutpoint.hash)
	)
		throw new Error(
			'Stale local asset splice funding generation or commitment state'
		);
}

function pair<T>(values: readonly T[]): Pair<T> {
	if (!Array.isArray(values) || values.length !== 2)
		throw new Error('Asset splice requires two contributions');
	return [values[0], values[1]];
}

/** Convert the host's verified transfers to the same transcript used by BOLT interactive construction. */
export async function prepareAssetSpliceAgreement(
	host: IAssetSplicePlanner,
	source: IAssetSpliceContext,
	channel: IAssetSpliceChannelTerms,
	offered: Buffer,
	accepted: Buffer,
	originals: Pair<Buffer>
) {
	const ctx: IAssetSpliceContext = {
		...source,
		attempt: Buffer.from(source.attempt),
		oldOutpoint: {
			...source.oldOutpoint,
			hash: Buffer.from(source.oldOutpoint.hash)
		},
		currentParent: source.currentParent.bind(source)
	};
	fresh(ctx);
	const init = Buffer.from(offered),
		ack = Buffer.from(accepted);
	const request = decodeSpliceMessage(init),
		reply = decodeSpliceAckMessage(ack);
	const parent = Transaction.fromHex(channel.parent.fundingTxHex);
	const parentRoot = Buffer.from(channel.parentRoot);
	const parentIndex = channel.parent.fundingOutputIndex,
		dust = channel.dust;
	if (
		!parent.getHash().equals(ctx.oldOutpoint.hash) ||
		parentIndex !== ctx.oldOutpoint.index ||
		request.channelId.toString('hex') !== ctx.channelId ||
		!reply.channelId.equals(request.channelId) ||
		!request.lockDepth ||
		request.lockDepth !== reply.lockDepth
	)
		throw new Error(
			'Asset splice does not agree with the local parent or depth'
		);
	const bitcoin: IAssetSpliceBitcoin = {
		fundingKeys: [request.fundingPubkey, reply.fundingPubkey],
		lockTime: request.locktime,
		minimumDepth: request.lockDepth,
		maxAcceptedHtlcs: pair(channel.maxAcceptedHtlcs)
	};
	const keys = [
		channel.parent.localFundingPubkey,
		channel.parent.remoteFundingPubkey
	];
	if (!ctx.isInitiator) keys.reverse();
	const proposals = pair(originals.map((p) => Buffer.from(p)));
	const blobs = () => pair(proposals.map((p) => Buffer.from(p)));
	const desc = await host.describeSplice(ctx, blobs(), bitcoin);
	fresh(ctx);
	if (
		desc.relativeSatoshis.length !== 2 ||
		desc.relativeSatoshis[0] !== request.relativeSatoshis ||
		desc.relativeSatoshis[1] !== reply.relativeSatoshis
	)
		throw new Error('Wallet and BOLT splice contributions differ');
	const layout: IAssetSpliceLayout = {
		attempt: ctx.attempt,
		chainHash: REGTEST_CHAIN_HASH,
		channelId: Buffer.from(ctx.channelId, 'hex'),
		init,
		ack,
		parent,
		parentIndex,
		parentRoot,
		parentKeys: pair(keys.map((k) => Buffer.from(k, 'hex'))),
		stateNumber: ctx.stateNumber,
		dust,
		feeBudgets: pair(desc.feeBudgets),
		maxAcceptedHtlcs: bitcoin.maxAcceptedHtlcs,
		commitmentRecordLimits: pair(desc.commitmentRecordLimits),
		parentBalances: desc.parentBalances,
		movements: desc.movements,
		proposalDigests: pair(proposals.map((p) => sha256(p))),
		inputs: desc.inputs.map((i) => ({
			serialId: i.serialId,
			prevTxid: i.txid,
			prevOutputIndex: i.vout,
			sequence: i.sequence,
			isShared: i.isShared,
			prevTx: i.prevTx
		})),
		outputs: desc.outputs.map((o) => ({
			serialId: o.serialId,
			role: o.kind,
			amountSats: o.valueSats,
			descriptorHash: o.descriptorHash
		}))
	};
	const layoutDigest = assetSpliceLayoutDigest(layout);
	const plan = await host.prepareSplice(
		ctx,
		blobs(),
		bitcoin,
		Buffer.from(layoutDigest)
	);
	const walletDigest = Buffer.from(plan.digest);
	function check() {
		fresh(ctx);
		if (
			walletDigest.length !== 32 ||
			!walletDigest.equals(plan.digest) ||
			!assetSpliceLayoutDigest(layout).equals(layoutDigest)
		)
			throw new Error('Asset splice plan changed after local verification');
	}
	check();
	const agreement = sha256(
		Buffer.concat([
			Buffer.from('asset-splice-agreement/v1\0'),
			layoutDigest,
			walletDigest
		])
	);
	return {
		layout,
		layoutDigest: Buffer.from(layoutDigest),
		agreement: Buffer.from(agreement),
		walletDigest: Buffer.from(walletDigest),
		async consent(peerAgreement: Buffer) {
			check();
			if (!agreement.equals(peerAgreement))
				throw new Error('Asset splice layout acknowledgement differs');
			const result = await plan.consent();
			check();
			return Buffer.from(result);
		},
		async authorize(peerAgreement: Buffer, both: Pair<Buffer>) {
			check();
			if (!agreement.equals(peerAgreement))
				throw new Error('Asset splice layout acknowledgement differs');
			const result = await plan.authorize(
				pair(both.map((v) => Buffer.from(v)))
			);
			check();
			return Buffer.from(result);
		},
		async finalize(both: Pair<Buffer>, authorizations: Pair<Buffer>) {
			check();
			const auth = pair(authorizations.map((v) => Buffer.from(v)));
			const result = await plan.finalize(
				pair(both.map((v) => Buffer.from(v))),
				pair(auth.map((v) => Buffer.from(v)))
			);
			check();
			const verified = {
				layoutDigest: Buffer.from(result.layoutDigest),
				transaction: Buffer.from(result.transaction),
				fundingRoot: Buffer.from(result.fundingRoot),
				proofDigest: Buffer.from(result.proofDigest),
				fundingProofs: Buffer.from(result.fundingProofs)
			};
			const hashes = pair(auth.map((v) => sha256(v)));
			return {
				get funding() {
					return {
						layoutDigest: Buffer.from(verified.layoutDigest),
						transaction: Buffer.from(verified.transaction),
						fundingRoot: Buffer.from(verified.fundingRoot),
						proofDigest: Buffer.from(verified.proofDigest),
						fundingProofs: Buffer.from(verified.fundingProofs)
					};
				},
				verifyFrozen(interactiveTx: Transaction) {
					check();
					return verifyAssetSpliceCandidate(
						layout,
						layoutDigest,
						ctx.isInitiator,
						interactiveTx,
						verified,
						hashes
					);
				}
			};
		}
	};
}
