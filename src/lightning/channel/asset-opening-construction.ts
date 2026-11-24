import { Transaction } from 'bitcoinjs-lib';
import { MessageType } from '../message/types';
import {
	encodeTxAddInputMessage,
	encodeTxAddOutputMessage
} from '../message/interactive-tx';
import { ASSET_OPENING_TYPE_HEX } from '../features/asset-opening';
import {
	validateAssetOpening,
	type IFinalOpeningCandidate
} from '../storage/final-opening-candidate';
import type {
	IAssetOpenContext,
	IAssetOpenDescription,
	IAssetOpenFunding
} from './asset-opening-provider';

export interface IAssetConstructionTurn {
	initiator: boolean;
	type: MessageType;
	payload?: Buffer;
}

export function assetOpeningConstruction(
	ctx: IAssetOpenContext,
	description: IAssetOpenDescription,
	funding: IAssetOpenFunding
): { candidate: IFinalOpeningCandidate; turns: IAssetConstructionTurn[] } {
	const tx = Transaction.fromBuffer(funding.transaction);
	if (!tx.toBuffer().equals(funding.transaction))
		throw new Error('Noncanonical funding transaction');
	const local = ctx.isInitiator ? ctx.open : ctx.accept;
	const remote = ctx.isInitiator ? ctx.accept : ctx.open;
	const candidate: IFinalOpeningCandidate = {
		channelId: ctx.channelId.toString('hex'),
		channelType: ASSET_OPENING_TYPE_HEX,
		localFundingPubkey: local.fundingPubkey.toString('hex'),
		remoteFundingPubkey: remote.fundingPubkey.toString('hex'),
		fundingTxHex: tx.toHex(),
		fundingOutputIndex: description.outputs.findIndex(
			(o) => o.kind === 'funding'
		),
		isInitiator: ctx.isInitiator,
		fundingFeeratePerKw: ctx.open.fundingFeeratePerkw,
		minimumDepth: ctx.accept.minimumDepth,
		localContributionSats: Number(local.fundingSatoshis),
		remoteContributionSats: Number(remote.fundingSatoshis),
		inputs: description.inputs.map((i) => ({
			prevTxHex: i.prevTx.toString('hex'),
			isLocal: ((i.serialId & 1n) === 0n) === ctx.isInitiator,
			serialId: i.serialId.toString()
		})),
		outputSerialIds: description.outputs.map((o) => o.serialId.toString())
	};
	validateAssetOpening(candidate, funding.fundingRoot);
	const sides: IAssetConstructionTurn[][] = [[], []];
	for (const input of description.inputs) {
		const side = Number(input.serialId & 1n);
		sides[side].push({
			initiator: side === 0,
			type: MessageType.TX_ADD_INPUT,
			payload: encodeTxAddInputMessage({
				channelId: ctx.channelId,
				serialId: input.serialId,
				prevTx: input.prevTx,
				prevTxVout: input.vout,
				sequence: input.sequence
			})
		});
	}
	for (const [i, output] of description.outputs.entries()) {
		const side = Number(output.serialId & 1n);
		sides[side].push({
			initiator: side === 0,
			type: MessageType.TX_ADD_OUTPUT,
			payload: encodeTxAddOutputMessage({
				channelId: ctx.channelId,
				serialId: output.serialId,
				amountSats: output.valueSats,
				scriptPubkey: tx.outs[i].script
			})
		});
	}
	const positions = [0, 0],
		turns: IAssetConstructionTurn[] = [];
	let consecutive = 0;
	while (consecutive < 2) {
		const side = turns.length % 2;
		const next = sides[side][positions[side]++];
		if (next) {
			turns.push(next);
			consecutive = 0;
		} else {
			turns.push({ initiator: side === 0, type: MessageType.TX_COMPLETE });
			consecutive++;
		}
	}
	return { candidate, turns };
}
