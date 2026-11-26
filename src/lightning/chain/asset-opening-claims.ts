import {
	confirmAssetPayout,
	detached,
	retainAssetPayout
} from './asset-payout-receipt';
import { assetHtlcClaims } from './asset-htlc-claims';
import { ecc } from '../../utils/ecc';
import { getPublicKey, privateAdd } from '../crypto/ecdh';
import { Transaction } from 'bitcoinjs-lib';
import type { IAuxiliaryDualFunding } from '../channel/asset-opening-provider';
import {
	matchedAssetPayoutViews,
	retainedAssetFundingLineage
} from './asset-splice-output-view';
import { generateFromSeed, MAX_INDEX } from '../keys/shachain';
import type { IFinalOpeningRuntime } from '../channel/final-opening-runtime';
import {
	assetPayoutRevocationTweak,
	type IAssetPayoutScope
} from '../channel/asset-payout-revocation';
import { derivePrivateKey, deriveRevocationPrivkey } from '../keys/derivation';
import { deriveChannelKeys } from '../keys/wallet-keys';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	type ITaprootLeafSpend
} from '../script/commitment-taproot';
import { tapleafHash, signTaprootHtlcLeaf } from '../script/htlc-taproot';
import { MAX_STANDARD_TX_WEIGHT } from '../interactive-tx/validation';
import {
	finalLeafClaim,
	type IFinalOutputClaim,
	recordedChannelType
} from './final-output-claims';

/** Identify the wallet's output by reconstructing the complete signed commitment and its tree. */
export function assetOpeningOutputClaims(
	runtime: IFinalOpeningRuntime,
	channelId: Buffer,
	observed: Transaction,
	destination: Buffer,
	feeRate: number,
	provider?: IAuxiliaryDualFunding,
	trimmed?: (hash: Buffer, htlcId: bigint, preimage?: Buffer) => void
): IFinalOutputClaim[] {
	const { storage, root } = runtime,
		id = channelId.toString('hex');
	if (
		!storage.canOpenDualFundedAssets ||
		!Number.isFinite(feeRate) ||
		feeRate <= 0
	)
		return [];
	const opening = storage.loadFinalDaemonOpening(id);
	if (
		recordedChannelType(storage, id) ||
		!opening?.session.assetEvidence ||
		!storage.loadFinalLocalTxSignatures(id)
	)
		return [];
	const { candidate, session } = opening;
	const parent = detached(observed);
	const keys = deriveChannelKeys(root, 1, session.channelKeyIndex);
	const [match] = matchedAssetPayoutViews(storage, id, parent);
	if (!match) return [];
	const {
		revoked,
		holder,
		view,
		assets,
		point,
		state,
		fundingProofs,
		exitProofs,
		splice,
		update
	} = match;
	if (revoked && !getPublicKey(revoked).equals(point))
		throw Error('Asset payout revocation differs from its commitment point');
	const virtualPayout: IAssetPayoutScope | undefined =
		storage.canRecoverAssetSplice
			? {
					channelId: id,
					fundingTxid: Buffer.from(parent.ins[0].hash)
						.reverse()
						.toString('hex'),
					fundingOutputIndex: parent.ins[0].index,
					stateNumber: String(state),
					revocationPubkey: Buffer.from(view.keys.revocationPubkey)
			  }
			: undefined;
	const balances = (revoked ? [false, true] : [false]).flatMap(
		(penalty): IFinalOutputClaim[] => {
			const local = holder === 'local' || penalty;
			const outputIndex = local
				? view.outputMap.toLocal
				: view.outputMap.toRemote;
			if (outputIndex === undefined) return [];
			const aux = local ? assets.toLocal : assets.toRemote;
			const format = aux ? { finalLeaf: aux } : 'final';
			const delay = penalty ? 0 : local ? view.toSelfDelay : 1;
			let leaf: ITaprootLeafSpend, secret: Buffer, output: Buffer;
			if (local) {
				if (
					!penalty &&
					(splice || update) &&
					!getPublicKey(
						generateFromSeed(keys.perCommitmentSeed, MAX_INDEX - state)
					).equals(point)
				)
					throw new Error(
						'Watched asset commitment point differs from this wallet'
					);
				const tree = buildTaprootToLocalOutput(
					view.keys.revocationPubkey,
					view.keys.localDelayedPubkey,
					view.toSelfDelay,
					undefined,
					format
				);
				leaf = penalty ? tree.revoke : tree.delay;
				output = tree.output;
				secret = penalty
					? deriveRevocationPrivkey(
							keys.revocationBasepointSecret,
							revoked!,
							keys.channelBasepoints.revocationBasepoint,
							point
					  )
					: derivePrivateKey(
							keys.delayedPaymentBasepointSecret,
							point,
							keys.channelBasepoints.delayedPaymentBasepoint
					  );
			} else {
				const tree = buildTaprootToRemoteOutput(
					keys.channelBasepoints.paymentBasepoint,
					undefined,
					format
				);
				leaf = tree.spend;
				output = tree.output;
				secret = keys.paymentBasepointSecret;
			}
			if (!parent.outs[outputIndex].script.equals(output))
				throw new Error('Wrong asset payout script');
			const balanceOutput = {
				outputIndex,
				relativeDelay: delay,
				absoluteHeight: 0,
				tx: null,
				assetBalanceOutput: true
			};
			if (!aux) {
				const claim = finalLeafClaim(
					parent,
					outputIndex,
					output,
					leaf,
					secret,
					destination,
					feeRate,
					delay
				);
				return [
					{
						...balanceOutput,
						...claim,
						...(virtualPayout && {
							matchesAssetPayout: (spend: Transaction) => {
								const witness = spend.ins.find(
									(input) =>
										input.index === outputIndex &&
										input.hash.equals(parent.getHash())
								)?.witness;
								return (
									!!witness &&
									witness.length === 3 &&
									witness[1].equals(leaf.script) &&
									witness[2].equals(leaf.controlBlock)
								);
							}
						})
					}
				];
			}
			const payoutIndex = virtualPayout ? outputIndex : undefined;
			const retained = () =>
				storage.assetOpeningPayout(id, parent.getId(), undefined, payoutIndex);
			const claim = {
				...balanceOutput,
				...(virtualPayout && {
					confirmAssetPayout: confirmAssetPayout(
						storage,
						provider,
						id,
						parent.getId(),
						outputIndex
					)
				})
			};
			if (
				!provider ||
				(virtualPayout && provider.assetSpliceRecoveryVersion !== 1)
			)
				return [claim];
			const recover = async (): Promise<Transaction | null> => {
				const cached = retained();
				if (cached) return Transaction.fromBuffer(cached);
				let authorized:
						| { txid: string; index: number; stack: Buffer[] }
						| undefined,
					active = true;
				const signSweep = (
					tx: Transaction,
					prevTxs: readonly Transaction[]
				): Buffer[] => {
					if (
						!active ||
						tx.version !== 2 ||
						!tx.ins.length ||
						!tx.outs.length ||
						tx.weight() > MAX_STANDARD_TX_WEIGHT ||
						prevTxs.length !== tx.ins.length
					)
						throw new Error('Invalid asset payout transaction');
					const index = tx.ins.findIndex(
						(input) =>
							input.hash.equals(parent.getHash()) && input.index === outputIndex
					);
					if (index < 0 || tx.ins[index].sequence !== delay)
						throw new Error('Wrong asset payout outpoint or sequence');
					const seen = new Set<string>();
					const coins = tx.ins.map((input, i) => {
						const prev = prevTxs[i],
							coin = prev?.outs[input.index],
							key = input.hash.toString('hex') + ':' + input.index;
						if (
							!coin ||
							!prev.getHash().equals(input.hash) ||
							seen.has(key) ||
							(i !== index && input.hash.equals(parent.getHash()))
						)
							throw new Error('Wrong asset payout prevout');
						seen.add(key);
						return coin;
					});
					if (authorized && authorized.txid !== tx.getId())
						throw new Error('Asset payout transaction changed');
					const digest = tx.hashForWitnessV1(
						index,
						coins.map((c) => c.script),
						coins.map((c) => c.value),
						Transaction.SIGHASH_DEFAULT,
						tapleafHash(leaf.script, leaf.leafVersion)
					);
					const stack = [
						signTaprootHtlcLeaf(digest, secret),
						leaf.script,
						leaf.controlBlock
					];
					authorized = { txid: tx.getId(), index, stack };
					return stack.map((b) => Buffer.from(b));
				};
				const signedVirtual = new Map<string, Buffer>();
				const signVirtual = (assetId: string, digest: Buffer): Buffer => {
					if (
						!penalty ||
						!virtualPayout ||
						!active ||
						!Buffer.isBuffer(digest) ||
						digest.length !== 32
					)
						throw Error('Invalid asset revocation signing request');
					const previous = signedVirtual.get(assetId);
					if (previous && !previous.equals(digest))
						throw Error('Asset revocation payout changed during signing');
					const key = privateAdd(
						secret,
						assetPayoutRevocationTweak(virtualPayout, assetId)
					);
					signedVirtual.set(assetId, Buffer.from(digest));
					return signTaprootHtlcLeaf(digest, key);
				};
				let tx: Transaction | null;
				try {
					tx = await provider.recoverOutput({
						...(virtualPayout && {
							walletGeneration: 5 as const,
							fundingLineage: retainedAssetFundingLineage(
								storage,
								id,
								candidate,
								virtualPayout.fundingTxid,
								virtualPayout.fundingOutputIndex
							),
							virtualPayout: {
								...virtualPayout,
								revocationPubkey: Buffer.from(virtualPayout.revocationPubkey)
							}
						}),
						...(penalty && { revocation: { signVirtual } }),
						candidate: {
							...candidate,
							inputs: candidate.inputs.map((input) => ({ ...input })),
							outputSerialIds: [...candidate.outputSerialIds]
						},
						holder,
						parent: detached(parent),
						outputIndex,
						delay,
						feeRate,
						fundingProofs: Buffer.from(fundingProofs, 'hex'),
						exitProofs: Buffer.from(exitProofs, 'hex'),
						...(splice && { splice: { ...splice } }),
						...(update && { update: { ...update } }),
						signSweep
					});
				} finally {
					active = false;
				}
				if (!tx) return null;
				tx = detached(tx);
				// The host can commit its completed proof and sweep immediately before a crash.
				// Its version-one payout has one input, whose prevout is fully known here.
				if (
					!authorized &&
					tx.version === 2 &&
					tx.ins.length === 1 &&
					tx.outs.length &&
					tx.ins[0].index === outputIndex &&
					tx.ins[0].hash.equals(parent.getHash()) &&
					tx.ins[0].sequence === delay
				) {
					const stack = tx.ins[0].witness,
						coin = parent.outs[outputIndex];
					const digest = tx.hashForWitnessV1(
						0,
						[coin.script],
						[coin.value],
						Transaction.SIGHASH_DEFAULT,
						tapleafHash(leaf.script, leaf.leafVersion)
					);
					if (
						stack.length === 3 &&
						stack[1].equals(leaf.script) &&
						stack[2].equals(leaf.controlBlock) &&
						stack[0].length === 64 &&
						ecc.verifySchnorr(
							digest,
							getPublicKey(secret).subarray(1),
							stack[0]
						)
					) {
						authorized = { txid: tx.getId(), index: 0, stack };
					}
				}
				if (
					!authorized ||
					tx.getId() !== authorized.txid ||
					tx.weight() > MAX_STANDARD_TX_WEIGHT ||
					tx.ins.some((input) => !input.witness.length) ||
					tx.ins[authorized.index].witness.length !== authorized.stack.length ||
					authorized.stack.some(
						(e, i) => !e.equals(tx!.ins[authorized!.index].witness[i])
					)
				)
					throw new Error('Provider returned an unauthorized asset payout');
				if (virtualPayout)
					return retainAssetPayout(
						storage,
						provider,
						id,
						parent.getId(),
						outputIndex,
						tx
					);
				return Transaction.fromBuffer(
					storage.assetOpeningPayout(
						id,
						parent.getId(),
						tx.toBuffer(),
						payoutIndex
					)!
				);
			};
			return [{ ...claim, recover }];
		}
	);
	return balances.concat(
		assetHtlcClaims(
			runtime,
			id,
			parent,
			destination,
			feeRate,
			match,
			provider,
			trimmed
		)
	);
}
