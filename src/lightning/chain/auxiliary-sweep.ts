/**
 * What the chain code asks about an asset channel (issue #2093).
 *
 * An output of a commitment of an asset channel that carries units has one
 * more leaf in its script tree, named by the provider when the commitment
 * was built, and a spend of it has an asset side that only the provider can
 * make. Everything here answers for a channel with asset state, and says
 * nothing (undefined, an empty list, true) for a channel without: the
 * resolver and the monitor ask at guarded places and are otherwise as they
 * were.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import { secondLevelRevocationKey } from '../channel/child-revocation';
import {
	auxiliaryProviderError,
	type IAuxiliaryCommitmentData,
	type IAuxiliarySweepInput,
	type IAuxiliarySweepSigningRequest
} from '../channel/auxiliary';
import type { IChannelState } from '../channel/channel-state';
import { HtlcDirection } from '../channel/types';
import {
	tweakTaprootKeyPathPrivkey,
	type ITaprootAuxLeaf
} from '../script/commitment-taproot';
import { signTaprootHtlcLeaf } from '../script/htlc-taproot';
import { type ITrackedOutput, OutputType } from './types';

/** The least an output that carries units may hold: the dust limit of a P2TR output. */
export const AUXILIARY_SWEEP_OUTPUT_MINIMUM = 330;

/** The most the asset side of one sweep may be, as the provider hands it back. */
export const MAX_AUXILIARY_SWEEP_DATA_BYTES = 4 * 1024 * 1024;

const channelOf = (state: IChannelState): string =>
	(state.channelId ?? state.temporaryChannelId).toString('hex');

/**
 * The asset side of one commitment as this node holds it, or undefined: the
 * channel is not an asset channel, or it no longer holds that commitment.
 */
export function auxiliaryCommitmentView(
	state: IChannelState,
	isOurs: boolean,
	commitmentNumber: bigint | undefined
): IAuxiliaryCommitmentData | undefined {
	if (!state.auxiliaryState || commitmentNumber === undefined) return undefined;
	if (isOurs)
		return state.auxiliaryState.localCommitments.get(commitmentNumber);
	// A revoked commitment of the peer that is on the chain: its view was
	// read back from the store of revoked views when it was seen.
	return (
		state.auxiliaryState.remoteCommitments.get(commitmentNumber) ??
		state.auxiliaryState.revokedCommitments?.get(commitmentNumber)
	);
}

/**
 * The asset leaf the view of a commitment names for one of its outputs, for
 * telling the outputs of a transaction apart. Undefined when the output
 * carries no units, when the view is not held, and for a channel that is
 * not an asset channel: such an output is looked for as an ordinary one.
 */
export function auxiliaryOutputLeaf(
	state: IChannelState,
	isOurs: boolean,
	commitmentNumber: bigint | undefined,
	outputIndex: number
): ITaprootAuxLeaf | undefined {
	return auxiliaryCommitmentView(
		state,
		isOurs,
		commitmentNumber
	)?.outputLeaves.get(outputIndex);
}

/**
 * Every asset leaf the view of a commitment names, for telling whose
 * commitment a transaction is before its outputs are known by index. Empty
 * for a channel that is not an asset channel.
 */
export function auxiliaryLeafCandidates(
	state: IChannelState,
	isOurs: boolean,
	commitmentNumber: bigint | undefined
): ITaprootAuxLeaf[] {
	return [
		...(auxiliaryCommitmentView(
			state,
			isOurs,
			commitmentNumber
		)?.outputLeaves.values() ?? [])
	];
}

/**
 * The asset leaf of an output this node tracks, or undefined when the
 * output was found to carry no units. An output found to carry units whose
 * commitment view is gone cannot be spent: it throws, naming the channel.
 */
export function trackedAuxiliaryLeaf(
	state: IChannelState,
	isOurs: boolean,
	output: ITrackedOutput
): ITaprootAuxLeaf | undefined {
	if (output.auxiliaryCommitmentNumber === undefined) return undefined;
	const leaf = auxiliaryOutputLeaf(
		state,
		isOurs,
		output.auxiliaryCommitmentNumber,
		output.outputIndex
	);
	if (!leaf) {
		throw new Error(
			`The asset side of commitment ${
				output.auxiliaryCommitmentNumber
			} is not held: output ${output.txid}:${
				output.outputIndex
			} cannot be spent (channel ${channelOf(state)})`
		);
	}
	return leaf;
}

/**
 * What a sweep of an output that carries units weighs more than the sweep
 * of an ordinary one: the longer proof of its leaf, and a P2TR output in
 * place of the destination.
 */
export function auxiliarySweepVbytes(destinationScript: Buffer): number {
	return 8 + Math.max(0, 34 - destinationScript.length);
}

/** A BIP340 signature under SIGHASH_DEFAULT, as every spend here signs. */
export const AUXILIARY_SPEND_SIGNATURE_BYTES = 64;

/**
 * The virtual size of a spend of one output that carries units, once it is
 * signed: one input whose witness has items of the given sizes, and one
 * output, which holds the script of 34 bytes the provider puts in place of
 * the destination. Wallet inputs that bring a fee are not counted.
 *
 * The fee of every such spend is computed from this, the size it really
 * has. An estimate by the type of the output fell short of it (133 vbytes
 * for a to_local of 146, 130 for a to_remote of 137), and a sweep signed at
 * the floor rate was below the relay floor and refused.
 */
export function auxiliarySpendVbytes(
	witnessItemSizes: readonly number[],
	destinationScript: Buffer
): number {
	const varint = (n: number): number => (n < 0xfd ? 1 : n <= 0xffff ? 3 : 5);
	const script = Math.max(34, destinationScript.length);
	const base = 4 + 1 + 41 + 1 + 8 + varint(script) + script + 4;
	const witness =
		2 +
		varint(witnessItemSizes.length) +
		witnessItemSizes.reduce((sum, size) => sum + varint(size) + size, 0);
	return Math.ceil((base * 4 + witness) / 4);
}

/** One input of a sweep, with the key that signs its Bitcoin witness. */
export interface IAuxiliarySweepSource
	extends Omit<IAuxiliarySweepInput, 'transactionInputIndex' | 'publicKey'> {
	output: ITrackedOutput;
	privateKey: Buffer;
	/**
	 * Other keys of this node the asset side of this input is signed with:
	 * the channel's revocation key, when the output itself is spent with a
	 * key scoped to one commitment. Never given to the provider.
	 */
	additionalPrivateKeys?: Buffer[];
}

/** What the asset side of a sweep came to. */
export type AuxiliarySweepPreparation =
	/** Nothing of the sweep carries units: it is an ordinary sweep. */
	| { assets: false }
	/** The provider made the asset side; `data` goes with the transaction. */
	| { assets: true; ok: true; data: Buffer }
	/** The provider would not, or answered what cannot be used. */
	| { assets: true; ok: false; refusal: string };

/**
 * Have the provider make the asset side of a sweep, before the Bitcoin
 * witness is signed. The provider is handed a copy of the transaction and
 * may name the script of an output that receives units; it is asked to
 * sign nothing with a key of this node except through `sign`, which signs
 * only with the key of the input it names.
 *
 * Never throws for what the provider does: a refusal comes back as one,
 * naming the channel, with the transaction untouched.
 */
export function prepareAuxiliarySweep(
	state: IChannelState,
	isOurs: boolean,
	transaction: bitcoin.Transaction,

	sources: IAuxiliarySweepSource[],
	destinationScript: Buffer,
	options?: {
		/** The outputs are signed for already: no script of theirs may change. */
		fixedOutputs?: boolean;
	}
): AuxiliarySweepPreparation {
	if (!state.auxiliaryState) return { assets: false };
	const carrying = sources.filter(
		(source) => source.output.auxiliaryCommitmentNumber !== undefined
	);
	if (carrying.length === 0) return { assets: false };
	const refused = (cause: unknown): AuxiliarySweepPreparation => ({
		assets: true,
		ok: false,
		refusal: auxiliaryProviderError(state, 'a sweep', cause).message
	});
	const commitmentNumber = carrying[0].output.auxiliaryCommitmentNumber!;
	if (
		carrying.some(
			(source) => source.output.auxiliaryCommitmentNumber !== commitmentNumber
		)
	) {
		return refused(new Error('its inputs are of different commitments'));
	}
	const provider = state.auxiliaryProvider;
	if (!provider?.prepareSweep) {
		return refused(
			new Error('the provider cannot spend an output that carries units')
		);
	}
	const signers: Buffer[][] = [];

	const inputs: IAuxiliarySweepInput[] = sources.map(
		(source, transactionInputIndex) => {
			const { output, privateKey, additionalPrivateKeys, ...described } =
				source;
			signers.push([privateKey, ...(additionalPrivateKeys ?? [])]);
			return {
				...described,
				transactionInputIndex,
				publicKey: Buffer.from(ecc.pointFromScalar(privateKey, true)!),
				htlcId: described.htlcId ?? output.htlcId,
				paymentHash: described.paymentHash ?? output.paymentHash,
				cltvExpiry: described.cltvExpiry ?? output.cltvExpiry,
				direction:
					described.direction ??
					(output.outputType === OutputType.OFFERED_HTLC
						? HtlcDirection.OFFERED
						: output.outputType === OutputType.RECEIVED_HTLC
						? HtlcDirection.RECEIVED
						: undefined)
			};
		}
	);
	const sign = (request: IAuxiliarySweepSigningRequest): Buffer => {
		const source = sources[request.transactionInputIndex];
		const signer = Buffer.isBuffer(request.publicKey)
			? signers[request.transactionInputIndex]?.find((key) =>
					Buffer.from(ecc.pointFromScalar(key, true)!).equals(request.publicKey)
			  )
			: undefined;
		if (
			!source ||
			!Buffer.isBuffer(request.publicKey) ||
			!signer ||
			!Buffer.isBuffer(request.sigHash) ||
			request.sigHash.length !== 32
		) {
			throw new Error(
				'An asset sweep asked for a signature by another key than the one of its input, or over what is not a digest'
			);
		}
		let privateKey = Buffer.from(signer);
		if (request.singleTweak !== undefined) {
			if (
				!Buffer.isBuffer(request.singleTweak) ||
				request.singleTweak.length !== 32
			) {
				throw new Error('An asset sweep named a key tweak that is not one');
			}
			const tweaked = ecc.privateAdd(privateKey, request.singleTweak);
			if (!tweaked) throw new Error('An asset sweep key tweak came to zero');
			privateKey = Buffer.from(tweaked);
		}
		if (request.taprootMerkleRoot !== undefined) {
			if (
				!Buffer.isBuffer(request.taprootMerkleRoot) ||
				request.taprootMerkleRoot.length !== 32
			) {
				throw new Error('An asset sweep named a taproot root that is not one');
			}
			privateKey = tweakTaprootKeyPathPrivkey(
				privateKey,
				request.taprootMerkleRoot
			);
		}
		return signTaprootHtlcLeaf(request.sigHash, privateKey);
	};
	let scripts: Array<[number, Buffer]>;
	let data: Buffer;
	try {
		const result = provider.prepareSweep({
			secondLevelRevocationKey: auxiliaryCommitmentView(
				state,
				isOurs,
				commitmentNumber
			)?.secondLevelRevocationKey,
			state,
			side: isOurs ? 'local' : 'remote',
			commitmentNumber,
			transaction: transaction.clone(),
			inputs,
			destinationScript: Buffer.from(destinationScript),
			sign
		});
		// The answer is read once, here, by the rules of whoever reads it
		// back: bytes that are bytes, and scripts of outputs that exist.
		if (!result || typeof result !== 'object') {
			throw new Error('it answered nothing');
		}
		if (
			!Buffer.isBuffer(result.customData) ||
			result.customData.length === 0 ||
			result.customData.length > MAX_AUXILIARY_SWEEP_DATA_BYTES
		) {
			throw new Error(
				'it answered without the asset side of the sweep, or with one too large to keep'
			);
		}
		if (!(result.outputScripts instanceof Map) || !result.outputScripts.size) {
			throw new Error('it named no output that receives the units');
		}
		scripts = [...result.outputScripts];
		for (const [index, script] of scripts) {
			if (
				!Number.isInteger(index) ||
				index < 0 ||
				index >= transaction.outs.length ||
				!Buffer.isBuffer(script) ||
				script.length !== 34 ||
				script[0] !== 0x51 ||
				script[1] !== 0x20
			) {
				throw new Error(
					'it named an output the sweep does not have, or a script that is not P2TR'
				);
			}
			if (transaction.outs[index].value < AUXILIARY_SWEEP_OUTPUT_MINIMUM) {
				throw new Error(
					'it named an output that holds less than an output of units may'
				);
			}

			if (
				options?.fixedOutputs &&
				!transaction.outs[index].script.equals(script)
			) {
				throw new Error(
					'it named another script for an output whose script is signed for already'
				);
			}
		}
		data = Buffer.from(result.customData);
	} catch (cause) {
		return refused(cause);
	}
	for (const [index, script] of scripts) {
		transaction.outs[index].script = Buffer.from(script);
	}
	madeFor.set(transaction, data);
	return { assets: true, ok: true, data };
}

/** The asset side the provider made for each transaction built here. */
const madeFor = new WeakMap<bitcoin.Transaction, Buffer>();

/**
 * The asset side the provider made for a transaction, for a path that is
 * handed the transaction without what was resolved with it. Undefined for
 * a transaction without one.
 */
export function auxiliarySweepDataOf(
	transaction: bitcoin.Transaction
): Buffer | undefined {
	return madeFor.get(transaction);
}

/**
 * A spend of the output confirmed: the asset side of that very transaction
 * is the one the output holds from here on, whichever was signed last.
 */
export function selectAuxiliarySweep(
	output: ITrackedOutput,
	txid: string
): void {
	const confirmed = output.auxiliarySweepAttempts?.[txid]?.auxiliaryData;
	if (confirmed) output.auxiliaryData = Buffer.from(confirmed);
}

/**
 * Keep the asset side of a sweep with the transaction it belongs to: on the
 * output as its present sweep, and by transaction id among the sweeps signed
 * for the output. Every sweep that was offered for broadcast is kept, since
 * any of them may be the one that confirms; one that was signed and replaced
 * before it was ever offered (a held sweep rebuilt at a new fee rate) cannot
 * confirm and is let go, so a long wait does not grow the row.
 * Asked after the monitor stored the sweep; does nothing when the sweep has
 * no asset side.
 */
export function noteAuxiliarySweep(
	output: ITrackedOutput,
	data: Buffer | undefined
): void {
	if (!data || !output.sweepTxHex) return;
	output.auxiliaryData = Buffer.from(data);
	delete output.auxiliaryRefusal;
	delete output.auxiliaryFeeFunding;
	const txid = bitcoin.Transaction.fromHex(output.sweepTxHex).getId();
	const kept: NonNullable<ITrackedOutput['auxiliarySweepAttempts']> = {};
	for (const [id, attempt] of Object.entries(
		output.auxiliarySweepAttempts ?? {}
	)) {
		if (attempt.offered && id !== txid) kept[id] = attempt;
	}
	kept[txid] = {
		transaction: output.sweepTxHex,
		auxiliaryData: Buffer.from(data),
		...(output.auxiliarySweepAttempts?.[txid]?.offered ? { offered: true } : {})
	};
	output.auxiliarySweepAttempts = kept;
}

/**
 * Mark the sweep the monitor is about to offer for broadcast: from here on
 * it may confirm, and its asset side stays with the output. True when the
 * transaction is a recorded sweep of units of this output; does nothing and
 * says false for any other.
 */
export function noteAuxiliarySweepOffered(
	output: ITrackedOutput,
	transaction: Buffer
): boolean {
	if (!output.auxiliarySweepAttempts) return false;
	const attempt =
		output.auxiliarySweepAttempts[
			bitcoin.Transaction.fromBuffer(transaction).getId()
		];
	if (!attempt) return false;
	attempt.offered = true;
	return true;
}

/**
 * What finishes a spend of an output of an asset channel whose fee wallet
 * inputs bring: a second-level HTLC transaction, whose outputs the peer
 * signed for, or a claim that cannot pay its own fee and leave what an
 * output of units must hold.
 */
export interface IAuxiliaryFeeFunding {
	/** The script and the value of the output the spend's own input spends. */
	prevout: { script: Buffer; value: bigint };
	/**
	 * The virtual size the spend has without its wallet inputs once it is
	 * finished, for a spend that is signed only then: what the fee pool is
	 * asked to pay for beside its own inputs. Not set on a spend that is
	 * signed already, whose size is read from it.
	 */
	ownVbytes?: number;
	/**
	 * `funded` is the spend with the wallet inputs after its own input and
	 * its outputs as they were; `prevouts` is aligned with its inputs. The
	 * provider makes the asset side of that very transaction, and the
	 * witness of its first input is set. Never throws for what the provider
	 * does.
	 */
	finalize(
		funded: bitcoin.Transaction,
		prevouts: { scripts: Buffer[]; values: bigint[] }
	): { ok: true; data?: Buffer } | { ok: false; refusal: string };
}

/** What the second-level output of an HTLC that carries units is found by. */
export interface IAuxiliarySecondLevelSource {
	auxiliaryCommitmentNumber: bigint;
	auxiliaryHtlc: { id: bigint; direction: HtlcDirection };
	auxiliaryParentData?: Buffer;
}

/**
 * The HTLC a second-level transaction belongs to, read from the HTLC output
 * it spends or from its own output once that is tracked. Undefined for an
 * output without units and for a channel that is not an asset channel.
 */
export function auxiliarySecondLevelSource(
	state: IChannelState,
	output: ITrackedOutput | undefined
): IAuxiliarySecondLevelSource | undefined {
	if (
		!state.auxiliaryState ||
		output?.auxiliaryCommitmentNumber === undefined
	) {
		return undefined;
	}
	if (output.isSecondLevelHtlc) {
		if (!output.auxiliaryHtlc) return undefined;
		return {
			auxiliaryCommitmentNumber: output.auxiliaryCommitmentNumber,
			auxiliaryHtlc: { ...output.auxiliaryHtlc },
			...(output.auxiliaryParentData
				? { auxiliaryParentData: Buffer.from(output.auxiliaryParentData) }
				: {})
		};
	}
	if (
		output.htlcId === undefined ||
		(output.outputType !== OutputType.OFFERED_HTLC &&
			output.outputType !== OutputType.RECEIVED_HTLC)
	) {
		return undefined;
	}
	return {
		auxiliaryCommitmentNumber: output.auxiliaryCommitmentNumber,
		auxiliaryHtlc: {
			id: output.htlcId,
			direction:
				output.outputType === OutputType.OFFERED_HTLC
					? HtlcDirection.OFFERED
					: HtlcDirection.RECEIVED
		},
		...(output.auxiliaryData
			? { auxiliaryParentData: Buffer.from(output.auxiliaryData) }
			: {})
	};
}

/**
 * The key and the asset leaf of the second-level output of an HTLC, as the
 * commitment round signed them. Without a source, the key given and no
 * leaf: the second-level output is the ordinary one. Throws, naming the
 * channel, when the view of the commitment is not held.
 */
export function auxiliarySecondLevel(
	state: IChannelState,
	isOurs: boolean,
	source: IAuxiliarySecondLevelSource | undefined,
	revocationPubkey: Buffer
): { revocationKey: Buffer; leaf?: ITaprootAuxLeaf } {
	if (!source) return { revocationKey: revocationPubkey };
	const view = auxiliaryCommitmentView(
		state,
		isOurs,
		source.auxiliaryCommitmentNumber
	);
	if (!view) {
		throw new Error(
			`The asset side of commitment ${
				source.auxiliaryCommitmentNumber
			} is not held: the second-level transaction of HTLC ${
				source.auxiliaryHtlc.id
			} cannot be made (channel ${channelOf(state)})`
		);
	}
	return {
		revocationKey: secondLevelRevocationKey(state, view, revocationPubkey, 1n),
		leaf: view.secondLevelLeaves.get(
			`${source.auxiliaryHtlc.direction}:${source.auxiliaryHtlc.id}`
		)
	};
}
