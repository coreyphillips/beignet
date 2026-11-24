import { Transaction } from 'bitcoinjs-lib';
import type { IFundingProvider } from '../node/types';
import { MessageType } from '../message/types';
import { decodeTxCompleteMessage } from '../message/interactive-tx';
import {
	decodeChannelReestablishMessage,
	encodeChannelReestablishMessage
} from '../message/channel-reestablish';
import type { IFinalOpeningCandidate } from '../storage/final-opening-candidate';
import type { IChannelManagerConfig } from './channel-manager';
import {
	resumeFinalOpening,
	type IFinalOpeningMessage,
	type IFinalOpeningRuntime
} from './final-opening-runtime';

interface IOpeningQueue {
	peer: string;
	tail: Promise<void>;
	pending: number;
}

/** Bind the durable opening transcript to one peer and serialize wallet and chain lookups. */
export class FinalOpeningTransport {
	private readonly queues = new Map<string, IOpeningQueue>();

	constructor(
		private readonly runtime: IFinalOpeningRuntime,
		private readonly verifyInput: NonNullable<
			IChannelManagerConfig['verifyRemoteFundingInput']
		>,
		private readonly wallet: () => IFundingProvider | null,
		private readonly send: (
			peer: string,
			type: MessageType,
			payload: Buffer
		) => void,
		private readonly funded: (
			candidate: IFinalOpeningCandidate,
			tx: Buffer
		) => void,
		private readonly refuse: (id: Buffer, reason: string) => void
	) {}

	disconnected(peer: string): void {
		for (const [id, queue] of this.queues) {
			if (queue.peer === peer) this.queues.delete(id);
		}
	}

	reconnected(peer: string): void {
		const { storage } = this.runtime;
		for (const candidate of storage.loadFinalOpenings()) {
			const id = candidate.channelId;
			const session = storage.loadFinalOpeningSession(id);
			if (session?.peer !== peer) continue;
			const nonce = storage.loadFinalLocalTxComplete(id);
			const pair =
				nonce && decodeTxCompleteMessage(nonce, { taproot: true }).commitNonces;
			const fundingTxid = Transaction.fromHex(candidate.fundingTxHex).getHash();
			const missingCommitment = !storage.loadFinalOpeningExit(id);
			this.send(
				peer,
				MessageType.CHANNEL_REESTABLISH,
				encodeChannelReestablishMessage({
					channelId: Buffer.from(id, 'hex'),
					nextCommitmentNumber: missingCommitment ? 0n : 1n,
					nextRevocationNumber: 0n,
					yourLastPerCommitmentSecret: Buffer.alloc(32),
					myCurrentPerCommitmentPoint: Buffer.from(
						session.terms.localBasepoints.firstPerCommitmentPoint,
						'hex'
					),
					nextFundingTxid: fundingTxid,
					nextFundingRetransmitFlags: missingCommitment && pair ? 1 : 0,
					...(pair && {
						nextLocalNonces: [{ fundingTxid, nonce: pair.next }],
						...(missingCommitment && { currentCommitNonce: pair.current })
					})
				})
			);
		}
	}

	private validateReestablish(
		id: string,
		candidate: IFinalOpeningCandidate,
		payload: Buffer
	): void {
		const msg = decodeChannelReestablishMessage(payload, {
			finalTaproot: true
		});
		const fundingTxid = Transaction.fromHex(candidate.fundingTxHex).getHash();
		if (
			!msg.nextFundingTxid?.equals(fundingTxid) ||
			msg.nextCommitmentNumber > 1n ||
			msg.nextRevocationNumber !== 0n ||
			!msg.yourLastPerCommitmentSecret.equals(Buffer.alloc(32)) ||
			msg.myCurrentFundingLocked ||
			msg.ffor ||
			(msg.nextFundingRetransmitFlags ?? 0) > 1
		)
			throw new Error('Reestablish does not match the first funding candidate');
		const session = this.runtime.storage.loadFinalOpeningSession(id)!;
		if (
			msg.myCurrentPerCommitmentPoint.toString('hex') !==
			session.terms.remoteBasepoints.firstPerCommitmentPoint
		)
			throw new Error('Reestablish changed the opening commitment point');
		const peerNonce = this.runtime.storage.loadFinalPeerTxComplete(id);
		const pair =
			peerNonce &&
			decodeTxCompleteMessage(peerNonce, { taproot: true }).commitNonces;
		if (
			(pair && !msg.nextLocalNonces) ||
			!!msg.currentCommitNonce !==
				((msg.nextFundingRetransmitFlags ?? 0) === 1) ||
			(msg.currentCommitNonce && msg.nextCommitmentNumber !== 0n)
		)
			throw new Error('Incomplete final opening reestablish nonces');
		if (
			msg.nextLocalNonces &&
			(msg.nextLocalNonces.length !== 1 ||
				!msg.nextLocalNonces[0].fundingTxid.equals(fundingTxid) ||
				(pair && !msg.nextLocalNonces[0].nonce.equals(pair.next)))
		)
			throw new Error('Reestablish changed the remembered next opening nonce');
		if (
			msg.currentCommitNonce &&
			pair &&
			!msg.currentCommitNonce.equals(pair.current)
		)
			throw new Error(
				'Reestablish changed the remembered current opening nonce'
			);
	}

	queue(peer: string, id: string, message?: IFinalOpeningMessage): void {
		let queue = this.queues.get(id);
		if (!queue) {
			queue = { peer, tail: Promise.resolve(), pending: 0 };
			this.queues.set(id, queue);
		}
		if (queue.peer !== peer)
			throw new Error('Opening does not belong to this peer');
		if (queue.pending >= 16)
			throw new Error('Too many pending opening messages');
		const active = queue;
		active.pending++;
		active.tail = active.tail
			.then(async () => {
				if (this.queues.get(id) !== active) return;
				const { storage } = this.runtime;
				const session = storage.loadFinalOpeningSession(id);
				if (session?.peer !== peer)
					throw new Error('Opening does not belong to this peer');
				const candidate = storage.loadFinalOpening(id)!;
				const replay = message?.type === MessageType.CHANNEL_REESTABLISH;
				if (replay) {
					this.validateReestablish(id, candidate, message.payload);
					// Existing messages must also replay when an input has since been spent
					// or the chain backend is temporarily unavailable.
					for (const [type, payload] of [
						[MessageType.TX_COMPLETE, storage.loadFinalLocalTxComplete(id)],
						[
							MessageType.COMMITMENT_SIGNED,
							storage.loadFinalPeerCommitment(id)
						],
						[MessageType.TX_SIGNATURES, storage.loadFinalLocalTxSignatures(id)]
					] as const) {
						if (payload) this.send(peer, type, payload);
					}
					const full = storage.loadFinalFundingTransaction(id);
					if (full) this.funded(candidate, full);
					if (storage.loadFinalLocalTxComplete(id)) return;
				}
				// Secure the inbound commitment even if the chain verifier is offline.
				// Its peer and immutable candidate were bound before we offered a nonce.
				if (message?.type === MessageType.COMMITMENT_SIGNED)
					storage.acceptFinalPeerCommitment(
						id,
						session.terms,
						this.runtime.root,
						session.channelKeyIndex,
						message.payload
					);
				let signer;
				if (
					storage.canSignFinalOpening &&
					!storage.loadFinalLocalTxSignatures(id)
				) {
					const wallet = this.wallet();
					if (!wallet?.resolveFinalOpeningInputs)
						throw new Error('Missing opening wallet verifier');
					const tx = Transaction.fromHex(candidate.fundingTxHex);
					for (const [i, input] of candidate.inputs.entries()) {
						const prev = Transaction.fromHex(input.prevTxHex);
						const vout = tx.ins[i].index;
						const verdict = await this.verifyInput({
							txid: prev.getHash(),
							vout,
							scriptPubKey: prev.outs[vout].script
						});
						if (verdict !== 'unspent')
							throw new Error('Opening input is not verified unspent');
					}
					signer = await wallet.resolveFinalOpeningInputs(
						candidate,
						session.terms
					);
				}
				if (this.queues.get(id) !== active) return;
				const response = resumeFinalOpening(
					this.runtime,
					peer,
					id,
					replay ? undefined : message,
					signer
				);
				for (const { type, payload } of response.messages)
					this.send(peer, type, payload);
				if (response.fundingTx) this.funded(candidate, response.fundingTx);
			})
			.catch((err: unknown) => {
				if (this.queues.get(id) === active)
					this.refuse(
						Buffer.from(id, 'hex'),
						err instanceof Error ? err.message : String(err)
					);
			})
			.finally(() => {
				active.pending--;
				if (!active.pending && this.queues.get(id) === active)
					this.queues.delete(id);
			});
	}
}
