import type { Channel } from './channel';
import { ChannelState } from './types';
import { isFinalTaprootTypeHex } from './commitment-profile';
import type { IFinalOpeningTerms } from './final-opening-commitment';
import type { IChannelBasepoints } from '../keys/derivation';
import { buildSpliceTx } from './splice-tx';
import { generateNonce } from '../crypto/musig';
import { randomBytes } from '../crypto/provider';
import { encodeTxCompleteMessage } from '../message/interactive-tx';
import { createTaprootFundingScript } from '../script/funding-taproot';
import {
	type IFinalOpeningCandidate,
	validateFinalOpening
} from '../storage/final-opening-candidate';

// Enrollment belongs to the admitted, ephemeral negotiation. Stored channels
// cannot acquire this capability by supplying a field in a serialized row.
const enrolled = new WeakSet<Channel>();

export function enrollFinalNegotiation(channel: Channel): void {
	if (channel.getState() !== ChannelState.NONE)
		throw Error('Final opening must be enrolled before negotiation');
	enrolled.add(channel);
}

export function isFinalNegotiation(channel: Channel): boolean {
	return enrolled.has(channel);
}

function openingPoints(
	points: IChannelBasepoints
): IFinalOpeningTerms['localBasepoints'] {
	return {
		fundingPubkey: points.fundingPubkey.toString('hex'),
		revocationBasepoint: points.revocationBasepoint.toString('hex'),
		paymentBasepoint: points.paymentBasepoint.toString('hex'),
		delayedPaymentBasepoint: points.delayedPaymentBasepoint.toString('hex'),
		htlcBasepoint: points.htlcBasepoint.toString('hex'),
		firstPerCommitmentPoint: points.firstPerCommitmentPoint.toString('hex')
	};
}

function bySerial(a: { serialId: bigint }, b: { serialId: bigint }): number {
	return a.serialId < b.serialId ? -1 : a.serialId > b.serialId ? 1 : 0;
}

export function snapshotFinalOpening(channel: Channel): {
	candidate: IFinalOpeningCandidate;
	terms: IFinalOpeningTerms;
} | null {
	if (!enrolled.has(channel)) return null;
	const session = channel.getDualFundingSession();
	const builder = session?.getTxBuilder();
	const open = session?.getOpenMsg();
	const accept = session?.getAcceptMsg();
	const id = channel.getChannelId();
	if (!session || !builder || !open || !accept || !id) return null;
	const channelType = open.channelType?.toString('hex');
	if (
		!channelType ||
		!isFinalTaprootTypeHex(channelType) ||
		channelType !== accept.channelType?.toString('hex')
	)
		throw Error('Final opening type mismatch');
	const script = createTaprootFundingScript(
		open.fundingPubkey,
		accept.fundingPubkey
	).p2trOutput;
	const outputs = builder.getOutputs().sort(bySerial);
	const fundingOutputIndex = outputs.findIndex((o) =>
		o.scriptPubkey.equals(script)
	);
	if (fundingOutputIndex < 0) return null;
	const inputs = builder.getInputs().sort(bySerial);
	const isInitiator = session.isInitiator();
	const [local, remote] = isInitiator ? [open, accept] : [accept, open];
	const tx = buildSpliceTx(
		inputs,
		outputs.map((o) => ({
			serialId: o.serialId,
			script: o.scriptPubkey,
			valueSats: o.amountSats
		})),
		open.locktime
	);
	const candidate: IFinalOpeningCandidate = {
		channelId: id.toString('hex'),
		channelType,
		localFundingPubkey: local.fundingPubkey.toString('hex'),
		remoteFundingPubkey: remote.fundingPubkey.toString('hex'),
		fundingTxHex: tx.toHex(),
		fundingOutputIndex,
		isInitiator,
		fundingFeeratePerKw: open.fundingFeeratePerkw,
		minimumDepth: accept.minimumDepth,
		localContributionSats: Number(local.fundingSatoshis),
		remoteContributionSats: Number(remote.fundingSatoshis),
		inputs: inputs.map((input) => {
			if (!input.prevTx)
				throw Error('Missing final funding previous transaction');
			return {
				prevTxHex: input.prevTx.toString('hex'),
				isLocal: (input.serialId % 2n === 0n) === isInitiator,
				serialId: input.serialId.toString()
			};
		}),
		outputSerialIds: outputs.map((o) => o.serialId.toString())
	};
	validateFinalOpening(candidate);
	return {
		candidate,
		terms: {
			localBasepoints: openingPoints(local),
			remoteBasepoints: openingPoints(remote),
			localToSelfDelay: local.toSelfDelay,
			remoteToSelfDelay: remote.toSelfDelay,
			localDustLimitSatoshis: Number(local.dustLimitSatoshis),
			remoteDustLimitSatoshis: Number(remote.dustLimitSatoshis),
			commitmentFeeratePerKw: open.commitmentFeeratePerkw
		}
	};
}

// These public nonces acknowledge an unfinished construction turn only. No
// signing handle is retained. A complete candidate uses the durable signer.
export function disposableFinalTxComplete(channel: Channel): Buffer {
	const id = channel.getChannelId();
	if (!enrolled.has(channel) || !id || snapshotFinalOpening(channel))
		throw Error('Disposable completion requires an unfinished final opening');
	const publicKey = channel.getFullState().localBasepoints.fundingPubkey;
	const nonce = (): Buffer =>
		Buffer.from(
			generateNonce({
				publicKey,
				sessionId: randomBytes(32),
				extraInput: Buffer.from('beignet-final-opening-disposable-v1')
			})
		);
	return encodeTxCompleteMessage({
		channelId: id,
		commitNonces: { current: nonce(), next: nonce() }
	});
}
