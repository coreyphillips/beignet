import { Transaction } from 'bitcoinjs-lib';
import { isValidPublicKey } from '../crypto/ecdh';
import { ChannelState } from './types';
import type { IFundingProvider } from '../node/types';
import { MessageType } from '../message/types';
import { decodeTxCompleteMessage } from '../message/interactive-tx';
import {
	decodeChannelReestablishMessage,
	encodeChannelReestablishMessage
} from '../message/channel-reestablish';
import { FinalChannelReadyProtocolError } from '../storage/final-opening-ready';
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

interface IOpeningConnection {
	peer: string;
	established: boolean;
	readySent: boolean;
	peerReestablish?: Buffer;
}

/** Bind the durable opening transcript to one peer and serialize wallet and chain lookups. */
export class FinalOpeningTransport {
	private readonly queues = new Map<string, IOpeningQueue>();
	private readonly connections = new Map<string, IOpeningConnection>();
	private readonly confirmed = new Set<string>();
	private readonly openingsByPeer = new Map<string, Set<string>>();

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
		private readonly refuse: (id: Buffer, reason: string) => void,
		private readonly negotiated: (peer: string) => {
			alias: boolean;
			splice: boolean;
		} = () => ({ alias: false, splice: false }),
		private readonly fail?: (peer: string, id: Buffer, reason: string) => void
	) {
		for (const {
			candidate,
			session,
			exitToBroadcast
		} of runtime.storage.loadFinalDaemonOpenings()) {
			if (!exitToBroadcast) this.track(session.peer, candidate.channelId);
		}
	}

	peers(): IterableIterator<string> {
		return this.openingsByPeer.keys();
	}

	count(peer: string): number {
		return this.openingsByPeer.get(peer)?.size ?? 0;
	}

	private track(peer: string, id: string): void {
		const openings = this.openingsByPeer.get(peer) ?? new Set<string>();
		openings.add(id);
		this.openingsByPeer.set(peer, openings);
	}

	closed(peer: string, id: string): void {
		const openings = this.openingsByPeer.get(peer);
		if (!openings) return;
		openings.delete(id);
		if (!openings.size) this.openingsByPeer.delete(peer);
		this.connections.delete(id);
		this.queues.delete(id);
	}

	opened(peer: string, id: string): void {
		this.track(peer, id);
		this.connections.set(id, { peer, established: true, readySent: false });
	}

	fundingDepth(id: string, confirmed: boolean): void {
		if (confirmed) {
			this.confirmed.add(id);
			this.sendReady(id);
		} else {
			this.confirmed.delete(id);
			const connection = this.connections.get(id);
			if (connection) connection.readySent = false;
		}
	}

	hasDepth(id: string): boolean {
		return this.confirmed.has(id);
	}

	state(id: string, funded: boolean, exchanged: boolean): ChannelState {
		if (!funded) return ChannelState.AWAITING_TX_SIGNATURES;
		if (!this.confirmed.has(id)) return ChannelState.AWAITING_FUNDING_CONFIRMED;
		const connection = this.connections.get(id);
		if (exchanged && !connection?.established)
			return ChannelState.AWAITING_REESTABLISH;
		return exchanged && connection?.readySent
			? ChannelState.CHANNEL_READY
			: ChannelState.AWAITING_CHANNEL_READY;
	}

	private sendReady(id: string): void {
		const connection = this.connections.get(id);
		if (
			!connection?.established ||
			connection.readySent ||
			!this.confirmed.has(id)
		)
			return;
		const { storage, root } = this.runtime;
		const opening = storage.loadFinalDaemonOpening(id);
		if (!opening?.funding || opening.exitToBroadcast) return;
		const payload = storage.finalOpeningChannelReady(id, root);
		// Mark before synchronous transport observers can re-enter this path.
		connection.readySent = true;
		try {
			this.send(connection.peer, MessageType.CHANNEL_READY, payload);
		} catch (error) {
			connection.readySent = false;
			throw error;
		}
	}

	disconnected(peer: string): void {
		for (const [id, connection] of this.connections) {
			if (connection.peer === peer) this.connections.delete(id);
		}
		for (const [id, queue] of this.queues) {
			if (queue.peer === peer) this.queues.delete(id);
		}
	}

	reconnected(peer: string): void {
		const { storage } = this.runtime;
		for (const id of this.openingsByPeer.get(peer) ?? []) {
			const opening = storage.loadFinalDaemonOpening(id)!;
			const { session, candidate } = opening;
			if (session.peer !== peer) throw new Error('Final opening peer changed');
			if (opening.exitToBroadcast || this.connections.has(id)) continue;
			const nonce = storage.loadFinalLocalTxComplete(id);
			const pair =
				nonce && decodeTxCompleteMessage(nonce, { taproot: true }).commitNonces;
			const fundingTxid = Transaction.fromHex(candidate.fundingTxHex).getHash();
			const missingCommitment = !storage.loadFinalOpeningExit(id);
			const next = opening.funding
				? storage.renewFinalReestablishNonce(id, this.runtime.root)
				: pair && pair.next;
			const locked =
				this.confirmed.has(id) &&
				this.negotiated(peer).splice &&
				storage.loadFinalLocalChannelReady(id);
			const payload = encodeChannelReestablishMessage({
				channelId: Buffer.from(id, 'hex'),
				// Interactive retransmission is requested by the flag and TLV 24.
				// The next update after commitment zero remains commitment one.
				nextCommitmentNumber: 1n,
				nextRevocationNumber: 0n,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: Buffer.from(
					session.terms.localBasepoints.firstPerCommitmentPoint,
					'hex'
				),
				...(!opening.funding && {
					nextFundingTxid: fundingTxid,
					nextFundingRetransmitFlags: missingCommitment && pair ? 1 : 0,
					...(missingCommitment && pair && { currentCommitNonce: pair.current })
				}),
				...(next && { nextLocalNonces: [{ fundingTxid, nonce: next }] }),
				...(locked && {
					myCurrentFundingLocked: { txid: fundingTxid, retransmitFlags: 0 }
				})
			});
			this.connections.set(id, { peer, established: false, readySent: false });
			this.send(peer, MessageType.CHANNEL_REESTABLISH, payload);
		}
	}

	private validateReestablish(
		id: string,
		candidate: IFinalOpeningCandidate,
		payload: Buffer
	): boolean {
		let msg: ReturnType<typeof decodeChannelReestablishMessage>;
		try {
			msg = decodeChannelReestablishMessage(payload, { finalTaproot: true });
		} catch {
			throw new FinalChannelReadyProtocolError(
				'Malformed final channel_reestablish'
			);
		}
		const fundingTxid = Transaction.fromHex(candidate.fundingTxHex).getHash();
		if (
			msg.channelId.toString('hex') !== id ||
			(msg.nextFundingTxid && !msg.nextFundingTxid.equals(fundingTxid)) ||
			(!msg.nextFundingTxid && msg.nextCommitmentNumber !== 1n) ||
			msg.nextCommitmentNumber > 1n ||
			msg.nextRevocationNumber !== 0n ||
			!msg.yourLastPerCommitmentSecret.equals(Buffer.alloc(32)) ||
			(msg.myCurrentFundingLocked &&
				(!msg.myCurrentFundingLocked.txid.equals(fundingTxid) ||
					msg.myCurrentFundingLocked.retransmitFlags !== 0 ||
					msg.nextFundingTxid)) ||
			msg.ffor ||
			(msg.nextFundingRetransmitFlags ?? 0) > 1
		)
			throw new Error('Reestablish does not match the first funding candidate');
		const session = this.runtime.storage.loadFinalOpeningSession(id)!;
		if (
			!isValidPublicKey(msg.myCurrentPerCommitmentPoint) ||
			(msg.nextFundingTxid &&
				msg.myCurrentPerCommitmentPoint.toString('hex') !==
					session.terms.remoteBasepoints.firstPerCommitmentPoint)
		)
			throw new Error('Reestablish changed the opening commitment point');
		const peerNonce = this.runtime.storage.loadFinalPeerTxComplete(id);
		const pair =
			peerNonce &&
			decodeTxCompleteMessage(peerNonce, { taproot: true }).commitNonces;
		if (
			((pair || !msg.nextFundingTxid) && !msg.nextLocalNonces) ||
			!!msg.currentCommitNonce !== ((msg.nextFundingRetransmitFlags ?? 0) === 1)
		)
			throw new FinalChannelReadyProtocolError(
				'Incomplete final opening reestablish nonces'
			);
		if (
			msg.nextLocalNonces &&
			(msg.nextLocalNonces.length !== 1 ||
				!msg.nextLocalNonces[0].fundingTxid.equals(fundingTxid) ||
				(msg.nextFundingTxid &&
					pair &&
					!msg.nextLocalNonces[0].nonce.equals(pair.next)))
		)
			throw new FinalChannelReadyProtocolError(
				'Invalid reestablish nonce for the opening funding'
			);
		if (
			msg.currentCommitNonce &&
			pair &&
			!msg.currentCommitNonce.equals(pair.current)
		)
			throw new Error(
				'Reestablish changed the remembered current opening nonce'
			);
		// An opening still missing witnesses must replay its original commitments.
		// A funded peer's new verification nonce is for the first update only.
		if (!msg.nextFundingTxid)
			this.runtime.storage.rememberFinalPeerReestablishNonce(
				id,
				msg.nextLocalNonces![0].nonce
			);
		return !!msg.nextFundingTxid;
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
				const opening = storage.loadFinalDaemonOpening(id)!;
				if (opening.exitToBroadcast) return;
				const candidate = opening.candidate;
				const replay = message?.type === MessageType.CHANNEL_REESTABLISH;
				const connection = this.connections.get(id);
				if (replay) {
					if (!connection || connection.peer !== peer)
						throw new Error('Unexpected final channel_reestablish');
					if (connection.peerReestablish?.equals(message.payload)) return;
					if (connection.established)
						throw new FinalChannelReadyProtocolError(
							'Unexpected second final channel_reestablish'
						);
					const needsFunding = this.validateReestablish(
						id,
						candidate,
						message.payload
					);
					connection.peerReestablish = Buffer.from(message.payload);
					connection.established = true;
					if (!needsFunding) {
						this.sendReady(id);
						if (opening.funding) return;
					}
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
					if (full) {
						this.funded(candidate, full);
						this.sendReady(id);
					}
					if (storage.loadFinalLocalTxComplete(id)) return;
				}
				if (connection && !connection.established)
					throw new Error('Waiting for final channel_reestablish');
				if (message?.type === MessageType.CHANNEL_READY) {
					if (!connection?.established)
						throw new Error(
							'Final channel_ready requires an established connection'
						);
					storage.rememberFinalPeerChannelReady(
						id,
						message.payload,
						this.negotiated(peer).alias
					);
					this.sendReady(id);
					return;
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
				if (response.fundingTx) {
					this.funded(candidate, response.fundingTx);
					this.sendReady(id);
				}
			})
			.catch((err: unknown) => {
				if (this.queues.get(id) !== active) return;
				const channelId = Buffer.from(id, 'hex');
				if (err instanceof FinalChannelReadyProtocolError && this.fail) {
					const connection = this.connections.get(id);
					if (connection) connection.established = false;
					try {
						this.fail(peer, channelId, err.message);
					} catch (localError) {
						this.refuse(channelId, String(localError));
					}
				} else {
					this.refuse(
						channelId,
						err instanceof Error ? err.message : String(err)
					);
				}
			})
			.finally(() => {
				active.pending--;
				if (!active.pending && this.queues.get(id) === active)
					this.queues.delete(id);
			});
	}
}
