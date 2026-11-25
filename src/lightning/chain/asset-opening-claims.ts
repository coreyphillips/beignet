import { ecc } from '../../utils/ecc';
import { getPublicKey } from '../crypto/ecdh';
import { Transaction } from 'bitcoinjs-lib';
import type { IAuxiliaryDualFunding } from '../channel/asset-opening-provider';
import { matchedAssetPayoutViews } from './asset-splice-output-view';
import { generateFromSeed, MAX_INDEX } from '../keys/shachain';
import type { IFinalOpeningRuntime } from '../channel/final-opening-runtime';
import { derivePrivateKey } from '../keys/derivation';
import { deriveChannelKeys } from '../keys/wallet-keys';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	type ITaprootLeafSpend
} from '../script/commitment-taproot';
import { tapleafHash, signTaprootHtlcLeaf } from '../script/htlc-taproot';
import { MAX_STANDARD_TX_WEIGHT } from '../interactive-tx/validation';
import { finalLeafClaim, type IFinalOutputClaim } from './final-output-claims';

/** Identify the wallet's output by reconstructing the complete signed commitment and its tree. */
export function assetOpeningOutputClaims(
	runtime: IFinalOpeningRuntime,
	channelId: Buffer,
	parent: Transaction,
	destination: Buffer,
	feeRate: number,
	provider?: IAuxiliaryDualFunding
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
		!opening?.session.assetEvidence ||
		!storage.loadFinalLocalTxSignatures(id)
	)
		return [];
	const { candidate, session } = opening;
	const keys = deriveChannelKeys(root, 1, session.channelKeyIndex);
	for (const {
		holder,
		view,
		assets,
		point,
		state,
		fundingProofs,
		exitProofs,
		splice,
		update
	} of matchedAssetPayoutViews(storage, id, parent)) {
		const local = holder === 'local';
		const outputIndex = local
			? view.outputMap.toLocal
			: view.outputMap.toRemote;
		if (outputIndex === undefined) return [];
		const aux = local ? assets.toLocal : assets.toRemote;
		const format = aux ? { finalLeaf: aux } : 'final';
		const delay = local ? view.toSelfDelay : 1;
		let leaf: ITaprootLeafSpend, secret: Buffer, output: Buffer;
		if (local) {
			if (
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
				delay,
				undefined,
				format
			);
			leaf = tree.delay;
			output = tree.output;
			secret = derivePrivateKey(
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
			return [{ ...balanceOutput, ...claim }];
		}
		if (!provider) return [balanceOutput];
		const recover = async (): Promise<Transaction | null> => {
			const retained = storage.assetOpeningPayout(id, parent.getId());
			if (retained) return Transaction.fromBuffer(retained);
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
			let tx: Transaction | null;
			try {
				tx = await provider.recoverOutput({
					candidate,
					holder,
					parent: parent.clone(),
					outputIndex,
					delay,
					feeRate,
					fundingProofs: Buffer.from(fundingProofs, 'hex'),
					exitProofs: Buffer.from(exitProofs, 'hex'),
					...(splice && { splice }),
					...(update && { update }),
					signSweep
				});
			} finally {
				active = false;
			}
			if (!tx) return null;
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
					ecc.verifySchnorr(digest, getPublicKey(secret).subarray(1), stack[0])
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
			return Transaction.fromBuffer(
				storage.assetOpeningPayout(id, parent.getId(), tx.toBuffer())!
			);
		};
		return [{ ...balanceOutput, recover }];
	}
	return [];
}
