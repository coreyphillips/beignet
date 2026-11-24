import type { BIP32Interface } from 'bip32';
import { Transaction } from 'bitcoinjs-lib';
import { deriveChannelKeys, deriveLightningKeys } from '../keys/wallet-keys';
import { MessageType } from '../message/types';
import type { SqliteStorage } from '../storage/sqlite-storage';
import type { IFinalOpeningCandidate } from '../storage/final-opening-candidate';
import type { FinalFundingWitnessSigner } from '../storage/final-opening-funding';

export interface IFinalOpeningRuntime {
	storage: SqliteStorage;
	root: BIP32Interface;
}
export interface IFinalOpeningMessage {
	type: MessageType;
	payload: Buffer;
}
export interface IFinalOpeningResponse {
	messages: IFinalOpeningMessage[];
	fundingTx?: Buffer;
}

/** Interactive funding order uses raw input amounts, before change or fees. */
function localSendsFirst(
	candidate: IFinalOpeningCandidate,
	node: Buffer,
	peer: string
): boolean {
	const tx = Transaction.fromHex(candidate.fundingTxHex);
	let balance = 0n;
	for (const [i, input] of candidate.inputs.entries()) {
		const value = BigInt(
			Transaction.fromHex(input.prevTxHex).outs[tx.ins[i].index].value
		);
		balance += input.isLocal ? value : -value;
	}
	return balance === 0n
		? Buffer.compare(node, Buffer.from(peer, 'hex')) < 0
		: balance < 0n;
}

/** Drive a remembered regtest opening. Every returned wire message has already committed. */
export function resumeFinalOpening(
	runtime: IFinalOpeningRuntime,
	peer: string,
	id: string,
	message?: IFinalOpeningMessage,
	signWallet?: FinalFundingWitnessSigner
): IFinalOpeningResponse {
	const { storage, root } = runtime;
	const session = storage.loadFinalOpeningSession(id);
	if (!session || session.peer !== peer)
		throw new Error('Opening does not belong to this peer');
	const candidate = storage.loadFinalOpening(id)!;
	const localNonce = storage.loadFinalLocalTxComplete(id);
	const ourShare = storage.loadFinalPeerCommitment(id);
	const ourFunding = storage.loadFinalLocalTxSignatures(id);
	const theirFunding = storage.loadFinalPeerTxSignatures(id);
	const localFirst = localSendsFirst(
		candidate,
		deriveLightningKeys(root, 1).nodePublicKey,
		peer
	);
	const messages: IFinalOpeningMessage[] = [];
	const original = storage.canSignFinalOpening;
	if (message) {
		switch (message.type) {
			case MessageType.TX_COMPLETE:
				storage.rememberFinalPeerTxComplete(id, message.payload);
				break;
			case MessageType.COMMITMENT_SIGNED:
				storage.acceptFinalPeerCommitment(
					id,
					session.terms,
					root,
					session.channelKeyIndex,
					message.payload
				);
				break;
			case MessageType.TX_SIGNATURES:
				if (localFirst && !ourFunding)
					throw new Error('Premature peer funding witnesses');
				storage.rememberFinalPeerTxSignatures(id, message.payload);
				break;
			default:
				throw new Error('Unexpected message for a remembered opening');
		}
	}
	let nonce = localNonce;
	if (!nonce && original) {
		const keys = deriveChannelKeys(root, 1, session.channelKeyIndex);
		nonce = storage.finalOpeningTxComplete(id, keys.fundingPrivkey);
	}
	if (nonce && (!message || !localNonce))
		messages.push({ type: MessageType.TX_COMPLETE, payload: nonce });
	const exit = storage.loadFinalOpeningExit(id);
	let share = ourShare;
	if (
		!share &&
		original &&
		nonce &&
		storage.loadFinalPeerTxComplete(id) &&
		(exit || candidate.inputs.some((i) => i.isLocal))
	) {
		share = storage.signFinalPeerCommitment(
			id,
			session.terms,
			root,
			session.channelKeyIndex
		);
	}
	if (share && (!message || !ourShare))
		messages.push({ type: MessageType.COMMITMENT_SIGNED, payload: share });
	let funding = ourFunding;
	if (
		!funding &&
		original &&
		exit &&
		share &&
		(signWallet || !candidate.inputs.some((input) => input.isLocal)) &&
		(localFirst || storage.loadFinalPeerTxSignatures(id))
	) {
		funding = storage.finalOpeningTxSignatures(
			id,
			signWallet ??
				(() => {
					throw new Error('Unexpected local funding input');
				})
		);
	}
	if (funding && (!message || !ourFunding))
		messages.push({ type: MessageType.TX_SIGNATURES, payload: funding });
	const full = storage.loadFinalFundingTransaction(id);
	return full && (!message || !theirFunding || !ourFunding)
		? { messages, fundingTx: full }
		: { messages };
}
