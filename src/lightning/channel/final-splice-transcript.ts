import { Transaction } from 'bitcoinjs-lib';
import { InteractiveTxBuilder } from '../interactive-tx/builder';
import { MessageType as M } from '../message/types';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxRemoveInputMessage,
	decodeTxRemoveOutputMessage,
	decodeTxCompleteMessage,
	encodeTxAddInputMessage,
	encodeTxAddOutputMessage
} from '../message/interactive-tx';
import { decodeSpliceMessage, decodeSpliceAckMessage } from '../message/splice';
import { createTaprootFundingScript } from '../script/funding-taproot';
import { isValidPublicKey } from '../crypto/ecdh';
import type { IFinalSpliceAttempt } from './final-splice-state';
import {
	buildFinalSpliceCandidate,
	type IFinalSpliceTerms
} from './final-splice-candidate';

export function lastSpliceWire(
	attempt: Pick<IFinalSpliceAttempt, 'messages'>,
	local: boolean,
	type: M
) {
	return [...attempt.messages]
		.reverse()
		.find((m) => m.local === local && m.type === type);
}
export function spliceTerms(
	a: IFinalSpliceAttempt,
	dust: bigint
): IFinalSpliceTerms | undefined {
	const i = a.intent;
	const init = lastSpliceWire(a, i.initiator, M.SPLICE),
		ack = lastSpliceWire(a, !i.initiator, M.SPLICE_ACK);
	if (!init || !ack) return undefined;
	const proposal = decodeSpliceMessage(Buffer.from(init.payload, 'hex'));
	const reply = decodeSpliceAckMessage(Buffer.from(ack.payload, 'hex'));
	const [own, peer] = i.initiator ? [proposal, reply] : [reply, proposal];
	if (
		own.fundingPubkey.toString('hex') !== i.localFundingPubkey ||
		!isValidPublicKey(peer.fundingPubkey) ||
		own.relativeSatoshis !== BigInt(i.localDelta) ||
		(i.initiator &&
			(proposal.fundingFeeratePerkw !== i.feerate ||
				proposal.locktime !== i.locktime)) ||
		proposal.lockDepth !== undefined ||
		reply.lockDepth !== undefined ||
		proposal.requireConfirmedInputs ||
		reply.requireConfirmedInputs
	)
		throw new Error('Splice terms differ from the agreed contribution');
	return {
		parent: Transaction.fromHex(i.parent.fundingTxHex),
		parentIndex: i.parent.fundingOutputIndex,
		oldLocalKey: Buffer.from(i.parent.localFundingPubkey, 'hex'),
		oldPeerKey: Buffer.from(i.parent.remoteFundingPubkey, 'hex'),
		newLocalKey: own.fundingPubkey,
		newPeerKey: peer.fundingPubkey,
		localIsSpliceInitiator: i.initiator,
		localDelta: own.relativeSatoshis,
		peerDelta: peer.relativeSatoshis,
		localFeeBudget: BigInt(i.feeBudget),
		dust,
		feerate: proposal.fundingFeeratePerkw,
		locktime: proposal.locktime
	};
}
export function localSpliceContributions(
	channelId: Buffer,
	a: IFinalSpliceAttempt,
	terms: IFinalSpliceTerms
) {
	const messages: { type: M; payload: Buffer }[] = [];
	let serialId = a.intent.initiator ? 0n : 1n;
	const input = (
		prevTx: Buffer,
		prevTxVout: number,
		sequence: number,
		sharedInputTxid?: Buffer
	) => {
		messages.push({
			type: M.TX_ADD_INPUT,
			payload: encodeTxAddInputMessage({
				channelId,
				serialId,
				prevTx,
				prevTxVout,
				sequence,
				sharedInputTxid
			})
		});
		serialId += 2n;
	};
	const output = (scriptPubkey: Buffer, amountSats: bigint) => {
		messages.push({
			type: M.TX_ADD_OUTPUT,
			payload: encodeTxAddOutputMessage({
				channelId,
				serialId,
				scriptPubkey,
				amountSats
			})
		});
		serialId += 2n;
	};
	if (a.intent.initiator)
		input(
			Buffer.alloc(0),
			terms.parentIndex,
			0xfffffffd,
			terms.parent.getHash()
		);
	for (const x of a.intent.inputs)
		input(Buffer.from(x.prevTxHex, 'hex'), x.vout, x.sequence);
	if (a.intent.initiator)
		output(
			createTaprootFundingScript(
				terms.newLocalKey,
				terms.newPeerKey,
				undefined,
				terms.assetFundingRoots?.candidate
			).p2trOutput,
			BigInt(terms.parent.outs[terms.parentIndex].value) +
				terms.localDelta +
				terms.peerDelta
		);
	for (const x of a.intent.outputs)
		output(Buffer.from(x.script, 'hex'), BigInt(x.value));
	return messages;
}
export function spliceConstruction(
	a: IFinalSpliceAttempt,
	terms: IFinalSpliceTerms
) {
	const builder = new InteractiveTxBuilder(a.intent.initiator, terms.locktime);
	builder.setDustLimit(terms.dust);
	let previous: boolean | undefined,
		localComplete: Buffer | undefined,
		peerComplete: Buffer | undefined;
	for (const m of a.messages) {
		if (m.type < M.TX_ADD_INPUT || m.type > M.TX_COMPLETE) continue;
		if (
			previous === m.local ||
			(previous === undefined && m.local !== a.intent.initiator) ||
			(localComplete && peerComplete)
		)
			throw new Error('Unexpected interactive splice turn');
		previous = m.local;
		const raw = Buffer.from(m.payload, 'hex');
		if (m.type === M.TX_COMPLETE) {
			const promise = decodeTxCompleteMessage(raw, { taproot: true });
			if (!promise.commitNonces || !promise.fundingInputNonce)
				throw new Error(
					'Final splice requires current, next and shared nonces'
				);
			for (const n of [
				promise.commitNonces.current,
				promise.commitNonces.next,
				promise.fundingInputNonce
			])
				if (
					!isValidPublicKey(n.subarray(0, 33)) ||
					!isValidPublicKey(n.subarray(33))
				)
					throw new Error('Malformed splice verification nonce');
			if (
				new Set(
					[
						promise.commitNonces.current,
						promise.commitNonces.next,
						promise.fundingInputNonce
					].map((b) => b.toString('hex'))
				).size !== 3
			)
				throw new Error('Repeated splice nonce');
			if (m.local) localComplete = raw;
			else peerComplete = raw;
			continue;
		}
		localComplete = undefined;
		peerComplete = undefined;
		let failure: string | null;
		const serial = raw.readBigUInt64BE(32);
		if ((serial % 2n === 0n) !== (m.local === a.intent.initiator))
			throw new Error('Invalid interactive splice serial parity');
		if (m.type === M.TX_ADD_INPUT) {
			const msg = decodeTxAddInputMessage(raw, { taproot: true });
			const prev = msg.prevTx.length
				? msg.prevTx
				: m.resolvedPrevTx
				? Buffer.from(m.resolvedPrevTx, 'hex')
				: undefined;
			const tx = prev && Transaction.fromBuffer(prev);
			if (
				msg.prevTxOut &&
				(!tx ||
					!tx.getHash().equals(msg.prevTxOut.txid) ||
					!tx.outs[msg.prevTxVout]?.script.equals(msg.prevTxOut.script) ||
					BigInt(tx.outs[msg.prevTxVout].value) !== msg.prevTxOut.amount)
			)
				throw new Error('Unverified compact splice prevout');
			const prevTxid = msg.sharedInputTxid ?? tx?.getHash();
			if (
				!prevTxid ||
				(msg.sharedInputTxid &&
					(prev ||
						!prevTxid.equals(terms.parent.getHash()) ||
						msg.prevTxVout !== terms.parentIndex))
			)
				throw new Error('Invalid shared splice input');
			const value = {
				serialId: serial,
				prevTxid,
				prevOutputIndex: msg.prevTxVout,
				prevTx: prev,
				sequence: msg.sequence,
				isShared: !!msg.sharedInputTxid
			};
			failure = m.local ? builder.addInput(value) : builder.addPeerInput(value);
		} else if (m.type === M.TX_ADD_OUTPUT) {
			const v = decodeTxAddOutputMessage(raw);
			failure = m.local ? builder.addOutput(v) : builder.addPeerOutput(v);
		} else if (m.type === M.TX_REMOVE_INPUT) {
			decodeTxRemoveInputMessage(raw);
			failure = m.local
				? builder.removeInput(serial)
				: builder.removePeerInput(serial);
		} else {
			decodeTxRemoveOutputMessage(raw);
			failure = m.local
				? builder.removeOutput(serial)
				: builder.removePeerOutput(serial);
		}
		if (failure) throw new Error(failure);
	}
	return {
		localTurn: previous === undefined ? a.intent.initiator : !previous,
		localComplete,
		peerComplete,
		build: () =>
			buildFinalSpliceCandidate(
				terms,
				builder.getInputs(),
				builder.getOutputs()
			)
	};
}
