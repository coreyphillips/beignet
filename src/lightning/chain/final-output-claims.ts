import { Transaction } from 'bitcoinjs-lib';
import { getPerCommitmentPoint } from '../channel/channel-helpers';
import {
	buildFinalOpeningCommitment,
	buildFinalCommitmentView
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

export interface IFinalOutputClaim {
	outputIndex: number;
	relativeDelay: number;
	absoluteHeight: number;
	/** Absent when the output is uneconomic at the current rate but its spend still settles a payment. */
	tx: Transaction | null;
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

/** Rebuild only a journaled commitment, including every eligible output of revoked remote states. */
export function finalOpeningOutputClaims(
	runtime: IFinalOpeningRuntime,
	id: Buffer,
	parent: Transaction,
	destination: Buffer,
	feeRate: number,
	trimmed?: (hash: Buffer, htlcId: bigint, preimage?: Buffer) => void
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
	if (!session) return [];
	const ledger = storage.loadFinalResolutionStates(channelId);
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
	const state:
		| (typeof states.local & { funding?: IFinalFundingReference })
		| undefined =
		local ?? states.revoked.find(matches) ?? states.remote.find(matches);
	if (!state) return [];
	const { candidate, terms } = states;
	const view = buildFinalCommitmentView(
		candidate,
		{ ...terms, commitmentFeeratePerKw: state.feeratePerKw },
		local ? 'local' : 'remote',
		state.point,
		state.height,
		state,
		state.htlcs,
		state.funding
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
		const { outputIndex, htlc, tree } = h;
		const preimage = states.preimages.find((p) =>
			sha256(p).equals(htlc.paymentHash)
		);
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
			continue;
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
			if (!sigs || !sigs[n])
				throw new Error('Missing authenticated peer HTLC signature');
			const flag = Buffer.of(0x83);
			const remoteSig = Buffer.concat([sigs[n], flag]),
				ours = Buffer.concat([signTaprootHtlcLeaf(h.digest, htlcKey), flag]);
			h.secondLevelTx.setWitness(0, [
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
				tx: h.secondLevelTx,
				sponsor: true
			};
		}
		if (!claim) {
			if (!offered && !revoked) continue;
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
							view.toSelfDelay
					  );
			};
		claims.push(claim);
	}
	return claims;
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
