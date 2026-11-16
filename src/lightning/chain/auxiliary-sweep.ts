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
	return (
		isOurs
			? state.auxiliaryState.localCommitments
			: state.auxiliaryState.remoteCommitments
	).get(commitmentNumber);
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

/** One input of a sweep, with the key that signs its Bitcoin witness. */
export interface IAuxiliarySweepSource
	extends Omit<IAuxiliarySweepInput, 'transactionInputIndex' | 'publicKey'> {
	output: ITrackedOutput;
	privateKey: Buffer;
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
	destinationScript: Buffer
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
	const inputs: IAuxiliarySweepInput[] = sources.map(
		(source, transactionInputIndex) => {
			const { output, privateKey, ...described } = source;
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
		const input = inputs[request.transactionInputIndex];
		if (
			!source ||
			!Buffer.isBuffer(request.publicKey) ||
			!input.publicKey.equals(request.publicKey) ||
			!Buffer.isBuffer(request.sigHash) ||
			request.sigHash.length !== 32
		) {
			throw new Error(
				'An asset sweep asked for a signature by another key than the one of its input, or over what is not a digest'
			);
		}
		let privateKey = Buffer.from(source.privateKey);
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
		}
		data = Buffer.from(result.customData);
	} catch (cause) {
		return refused(cause);
	}
	for (const [index, script] of scripts) {
		transaction.outs[index].script = Buffer.from(script);
	}
	return { assets: true, ok: true, data };
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
