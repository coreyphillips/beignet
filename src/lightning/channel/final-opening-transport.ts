import { acceptAssetSpliceReestablish } from '../storage/asset-splice-reestablish';
import { decodeStartBatchMessage } from '../message/splice';
import type { FinalSpliceTransport } from './final-splice-transport';
import type { IFinalCloseRequest } from '../storage/final-simple-close';
import { FinalCloseProtocolError } from '../storage/final-simple-close';
import {
	FinalCommitmentTransport,
	isFinalCommitmentUpdate
} from './final-commitment-transport';
import { FinalUpdateProtocolError } from '../storage/final-channel-updates';
import { deriveChannelKeys, deriveLightningKeys } from '../keys/wallet-keys';
import { Transaction } from 'bitcoinjs-lib';
import { isValidPublicKey } from '../crypto/ecdh';
import { ChannelState } from './types';
import type { IFundingProvider } from '../node/types';
import { MessageType } from '../message/types';
import {
	decodeTxCompleteMessage,
	encodeTxAbortMessage,
	decodeTxAbortMessage
} from '../message/interactive-tx';
import {
	decodeChannelReestablishMessage,
	encodeChannelReestablishMessage
} from '../message/channel-reestablish';
import { FinalChannelReadyProtocolError } from '../storage/final-opening-ready';
import type { IFinalOpeningCandidate } from '../storage/final-opening-candidate';
import type { IChannelManagerConfig } from './channel-manager';
import {
	localSendsFirst,
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
	pendingAssetReady?: Buffer;
	openingRbfRefused?: boolean;
	peerReestablish?: Buffer;
	deferred?: IFinalOpeningMessage[];
	deferredSplice?: IFinalOpeningMessage[];
}

/** Bind the durable opening transcript to one peer and serialize wallet and chain lookups. */
export class FinalOpeningTransport {
	private readonly commitments: FinalCommitmentTransport;
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
		private readonly fail?: (peer: string, id: Buffer, reason: string) => void,
		deliver: (id: string, message: IFinalOpeningMessage) => void = () =>
			undefined,
		private readonly permitUpdates: (id: string) => boolean = () => true,
		private readonly closeContext?: () => Omit<
			IFinalCloseRequest,
			'message' | 'start'
		>,
		private readonly broadcastClose?: (tx: Buffer) => void,
		private readonly splice?: FinalSpliceTransport,
		private readonly reconnectFunding?: (peer: string) => void,
		private readonly resumeAssetSplice?: (peer: string, id: string) => void
	) {
		this.commitments = new FinalCommitmentTransport(
			runtime,
			(id) => this.updatesReady(id),
			(id, msg) =>
				this.send(this.connections.get(id)!.peer, msg.type, msg.payload),
			deliver
		);
		for (const {
			candidate,
			session,
			exitToBroadcast
		} of runtime.storage.loadFinalDaemonOpenings()) {
			if (!exitToBroadcast) this.track(session.peer, candidate.channelId);
		}
	}

	connected(id: string): boolean {
		return !!this.connections.get(id)?.established;
	}
	updatesReady(id: string): boolean {
		const connection = this.connections.get(id);
		if (
			!this.runtime.storage.canUpdateFinalCommitments ||
			!connection?.established ||
			!connection.readySent ||
			!this.confirmed.has(id) ||
			!this.permitUpdates(id)
		)
			return false;
		const opening = this.runtime.storage.loadFinalDaemonOpening(id);
		return !!opening?.readyExchanged && !opening.exitToBroadcast;
	}

	private reconnectAfterFundingReplay(id: string): boolean {
		const conn = this.connections.get(id);
		if (
			!conn ||
			!this.runtime.storage.loadFinalUpdateStatus(id)?.awaitingFundingNonce
		)
			return false;
		// The witness owner has queued the original tx_signatures; a new socket now exchanges both funding nonces.
		conn.established = false;
		this.reconnectFunding?.(conn.peer);
		return true;
	}

	initiateShutdown(id: string, script: Buffer): void {
		this.driveClose(id, undefined, script);
	}

	private driveClose(
		id: string,
		message?: IFinalOpeningMessage,
		script?: Buffer
	): void {
		if (!this.closeContext || !this.updatesReady(id))
			throw new Error(
				'Final close requires live funding and an authenticated peer'
			);
		const request = this.closeContext();
		const { storage, root } = this.runtime;
		const result = storage.finalSimpleCloseStep(id, root, {
			...request,
			...(script && { script, start: true }),
			message
		});
		const peer = this.connections.get(id)!.peer;
		if (result.transaction) this.broadcastClose?.(result.transaction);
		for (const response of result.messages)
			this.send(peer, response.type, response.payload);
	}

	private replayClose(id: string): void {
		if (!this.updatesReady(id)) return;
		const close = this.runtime.storage.loadFinalSimpleClose(id);
		if (!close) return;
		const peer = this.connections.get(id)!.peer;
		for (const [type, hex] of [
			[MessageType.SHUTDOWN, close.localShutdown],
			[MessageType.CLOSING_COMPLETE, close.localProposal],
			[MessageType.CLOSING_SIG, close.localReply]
		] as const)
			if (hex) this.send(peer, type, Buffer.from(hex, 'hex'));
		if (!close.localProposal && !close.localReply) this.driveClose(id);
	}

	private readonly batches = new Map<
		string,
		{ id: string; size: number; parts: Buffer[] }
	>();

	/** Collect at the peer demultiplexer before unrelated per-channel queues can reorder frames. */
	collectCommitmentBatch(peer: string, type: number, payload: Buffer): boolean {
		const active = this.batches.get(peer);
		if (active) {
			if (
				type !== MessageType.COMMITMENT_SIGNED ||
				payload.length < 32 ||
				payload.subarray(0, 32).toString('hex') !== active.id
			) {
				this.batches.delete(peer);
				this.queue(peer, active.id, {
					type: MessageType.START_BATCH,
					payload: Buffer.from(active.id, 'hex'),
					batchError: 'Unexpected message inside final funding commitment batch'
				});
				return true;
			}
			active.parts.push(Buffer.from(payload));
			if (active.parts.length === active.size) {
				this.batches.delete(peer);
				this.queue(peer, active.id, {
					type: MessageType.COMMITMENT_SIGNED,
					payload: active.parts[0],
					signatureBatch: active.parts
				});
			}
			return true;
		}
		if (
			type !== MessageType.START_BATCH ||
			!this.runtime.storage.canUpdateFinalCommitments ||
			payload.length < 32
		)
			return false;
		const id = payload.subarray(0, 32).toString('hex');
		const opening = this.runtime.storage.loadFinalDaemonOpening(id);
		if (!opening?.readyExchanged || opening.session.peer !== peer) return false;
		try {
			const msg = decodeStartBatchMessage(payload);
			if (msg.batchSize > 20)
				throw new Error('Final commitment batch exceeds 20 messages');
			if (
				msg.batchSize > 1 &&
				msg.messageType === MessageType.COMMITMENT_SIGNED
			)
				this.batches.set(peer, { id, size: msg.batchSize, parts: [] });
		} catch (error) {
			this.queue(peer, id, {
				type: MessageType.START_BATCH,
				payload: Buffer.from(payload),
				batchError: String(error)
			});
		}
		return true;
	}

	localUpdate(id: string, type: MessageType, payload: Buffer): void {
		this.commitments.local(id, type, payload);
	}

	/** Irrevocable wallet settlements survive peer disconnect, exit intent and chain spend. */
	restoreFinalSettlements(id: string): void {
		this.commitments.deliverLocked(id, true);
	}

	private resumeUpdates(id: string): void {
		const connection = this.connections.get(id);
		if (!connection || !this.confirmed.has(id)) return;
		const splice = connection.deferredSplice;
		delete connection.deferredSplice;
		for (const msg of splice ?? []) this.queue(connection.peer, id, msg);
		if (
			!splice?.length &&
			connection.established &&
			this.splice?.awaitingDepth(id)
		)
			this.enqueue(connection.peer, id, undefined, true);
		const deferred = connection.deferred;
		delete connection.deferred;
		for (const msg of deferred ?? []) this.queue(connection.peer, id, msg);
		if (this.updatesReady(id)) this.commitments.deliverLocked(id);
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
		this.splice?.forget(id);
		if (this.batches.get(peer)?.id === id) this.batches.delete(peer);
		const openings = this.openingsByPeer.get(peer);
		if (!openings) return;
		openings.delete(id);
		if (!openings.size) this.openingsByPeer.delete(peer);
		this.connections.delete(id);
		this.queues.delete(id);
	}

	opened(peer: string, id: string, reconnected = false): void {
		this.track(peer, id);
		if (reconnected) {
			this.reconnected(peer, id);
			return;
		}
		this.connections.set(id, { peer, established: true, readySent: false });
	}

	// A disconnect can replace the peer queue while the host is still signing.
	private readonly assetFunding = new Map<string, Promise<Buffer>>();
	private readonly assetSpendable = new Set<string>();
	private readonly assetDepth = new Map<
		string,
		{
			atDepth?: boolean;
			height?: number;
			imported: boolean;
			tail: Promise<void>;
		}
	>();

	private releaseAssetFunding(
		id: string,
		peer: string,
		candidate: IFinalOpeningCandidate
	): Promise<Buffer> | undefined {
		const { storage, root, dualFunding } = this.runtime;
		if (
			!storage.canOpenDualFundedAssets ||
			!storage.loadFinalOpeningExit(id) ||
			!storage.loadFinalPeerCommitment(id) ||
			(!localSendsFirst(
				candidate,
				deriveLightningKeys(root, 1).nodePublicKey,
				peer
			) &&
				!storage.loadFinalPeerTxSignatures(id))
		)
			return;
		const previous = this.assetFunding.get(id);
		if (previous) return previous;
		const evidence = storage.loadAssetOpeningEvidence(id);
		if (!dualFunding || !evidence)
			throw new Error('Missing asset funding provider or proof material');
		const pending = (async () => {
			const inputs = storage.prepareAssetOpeningWitnesses(id);
			for (const [i, input] of inputs.tx.ins.entries()) {
				const result = await this.verifyInput({
					txid: input.hash,
					vout: input.index,
					scriptPubKey: inputs.prevouts.scripts[i]
				});
				if (result !== 'unspent')
					throw new Error('Opening input is not verified unspent');
			}
			if (storage.loadFinalDaemonOpening(id)?.exitToBroadcast)
				throw new Error('Asset opening is closing');
			const stacks = await dualFunding.signFunding(
				candidate,
				Buffer.from(evidence.fundingProofs, 'hex'),
				inputs.tx,
				inputs.local,
				inputs.prevouts
			);
			return storage.storeAssetOpeningWitnesses(id, stacks);
		})().finally(() => this.assetFunding.delete(id));
		this.assetFunding.set(id, pending);
		return pending;
	}

	/** Channel readiness needs an unspent output as well as accepted proof imports. */
	assetFundingSpendable(id: string, spendable: boolean): void {
		if (spendable) this.assetSpendable.add(id);
		else this.assetSpendable.delete(id);
		const ready = spendable && !!this.assetDepth.get(id)?.imported;
		if (this.hasDepth(id) !== ready) this.setDepth(id, ready);
		const connection = this.connections.get(id);
		if (ready && connection?.pendingAssetReady) {
			const payload = connection.pendingAssetReady;
			delete connection.pendingAssetReady;
			this.queue(connection.peer, id, {
				type: MessageType.CHANNEL_READY,
				payload
			});
		}
	}

	/** The splice wallet verifies and imports its own proofs before passing true here. */
	assetSpliceSpendable(id: string, ready: boolean): void {
		this.assetSpendable.delete(id);
		if (this.hasDepth(id) !== ready) this.setDepth(id, ready);
	}

	/** A replacement tip can move the same transaction into another block at the same height. */
	invalidateAssetFundingAnchor(id: string): void {
		const old = this.assetDepth.get(id);
		if (!old) return;
		this.assetDepth.set(id, { tail: old.tail, imported: false });
		this.assetFundingSpendable(id, false);
	}

	/** Proof ownership follows accepted funding history, including after a unilateral spend. */
	assetFundingAnchor(id: string, atDepth: boolean, height?: number): void {
		const prior = this.assetDepth.get(id);
		if (prior?.atDepth === atDepth && (!atDepth || prior.height === height))
			return;
		const { storage, dualFunding } = this.runtime;
		if (!storage.canOpenDualFundedAssets || !dualFunding) return;
		const opening = storage.loadFinalDaemonOpening(id);
		if (!opening?.session.assetEvidence) return;
		const { candidate, session } = opening;
		const proof = Buffer.from(session.assetEvidence!.fundingProofs, 'hex');
		const state = { atDepth, height, imported: false, tail: Promise.resolve() };
		this.assetDepth.set(id, state);
		this.assetFundingSpendable(id, this.assetSpendable.has(id));
		state.tail = (prior?.tail ?? Promise.resolve())
			.then(async () => {
				if (!atDepth) {
					await dualFunding.retractFunding(candidate);
					return;
				}
				if (this.assetDepth.get(id) !== state) return;
				if (!storage.loadFinalFundingTransaction(id))
					throw new Error('Asset funding witnesses are incomplete');
				await dualFunding.confirmFunding(candidate, proof);
				if (this.assetDepth.get(id) !== state) return;
				state.imported = true;
				this.assetFundingSpendable(id, this.assetSpendable.has(id));
			})
			.catch((error) => {
				if (this.assetDepth.get(id) === state) {
					this.assetDepth.delete(id);
					this.setDepth(id, false);
				}
				this.refuse(Buffer.from(id, 'hex'), String(error));
			});
	}

	fundingDepth(id: string, confirmed: boolean): void {
		if (
			this.runtime.storage.canOpenDualFundedAssets &&
			this.runtime.storage.loadAssetOpeningEvidence(id)
		) {
			this.assetFundingSpendable(id, confirmed);
			this.assetFundingAnchor(id, confirmed);
			return;
		}
		this.splice?.fundingDepth(id, confirmed);
		this.setDepth(id, confirmed);
	}

	private setDepth(id: string, confirmed: boolean): void {
		if (confirmed) {
			this.confirmed.add(id);
			this.sendReady(id);
			this.resumeUpdates(id);
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
		const status =
			storage.canUpdateFinalCommitments && storage.loadFinalUpdateStatus(id);
		if (status && (status.localHeight > 0n || status.remoteHeight > 0n)) {
			connection.readySent = true;
			return;
		}
		const payload = storage.finalOpeningChannelReady(id, root);
		// Mark before synchronous transport observers can re-enter this path.
		connection.readySent = true;
		try {
			this.send(connection.peer, MessageType.CHANNEL_READY, payload);
			this.resumeAssetSplice?.(connection.peer, id);
		} catch (error) {
			connection.readySent = false;
			throw error;
		}
	}

	disconnected(peer: string): void {
		this.batches.delete(peer);
		for (const [id, connection] of this.connections) {
			if (connection.peer === peer) this.connections.delete(id);
		}
		for (const [id, queue] of this.queues) {
			if (queue.peer === peer) this.queues.delete(id);
		}
	}

	reconnected(peer: string, onlyId?: string): void {
		const { storage } = this.runtime;
		for (const id of this.openingsByPeer.get(peer) ?? []) {
			if (onlyId && id !== onlyId) continue;
			const opening = storage.loadFinalDaemonOpening(id)!;
			const { session, candidate } = opening;
			if (session.peer !== peer) throw new Error('Final opening peer changed');
			if (opening.exitToBroadcast || this.connections.has(id)) continue;
			const update =
				storage.canUpdateFinalCommitments && storage.loadFinalUpdateStatus(id);
			if (
				update &&
				(update.pending ||
					update.last ||
					storage.loadFinalSpliceAttempts(id).length)
			) {
				const fields = storage.finalUpdateReestablish(id, this.runtime.root);
				const attempts = storage.loadFinalSpliceAttempts(id);
				const adopted = [...attempts].reverse().find((a) => a.adopted);
				const fundingTxid = Transaction.fromHex(
					adopted?.candidate?.funding.fundingTxHex ?? candidate.fundingTxHex
				).getHash();
				const locked = this.confirmed.has(id) && this.negotiated(peer).splice;
				const payload = encodeChannelReestablishMessage({
					...fields,
					...(locked && {
						myCurrentFundingLocked: { txid: fundingTxid, retransmitFlags: 0 }
					}),
					...this.splice?.reconnectFields(id)
				});
				this.connections.set(id, {
					peer,
					established: false,
					readySent: false
				});
				this.send(peer, MessageType.CHANNEL_REESTABLISH, payload);
				continue;
			}
			if (
				session.assetEvidence &&
				storage.canSpliceDualFundedAssets &&
				opening.funding &&
				opening.readyExchanged &&
				this.negotiated(peer).splice
			) {
				const fields = storage.assetSpliceReconnect(
					id,
					this.runtime.root,
					this.confirmed.has(id)
				);
				this.connections.set(id, {
					peer,
					established: false,
					readySent: false
				});
				this.send(
					peer,
					MessageType.CHANNEL_REESTABLISH,
					encodeChannelReestablishMessage(fields)
				);
				continue;
			}
			if (session.assetEvidence && storage.canOpenDualFundedAssets) {
				// Admission and nonce persistence can be separated by a power cut.
				// Reestablish must carry the verification nonce promised during construction.
				if (!storage.loadFinalLocalTxComplete(id)) {
					const keys = deriveChannelKeys(
						this.runtime.root,
						1,
						session.channelKeyIndex
					);
					storage.finalOpeningTxComplete(id, keys.fundingPrivkey);
				}
				if (!storage.loadFinalPeerTxComplete(id)) {
					const promised = storage.loadAssetOpenStage(id, 'peerNonce');
					if (promised) storage.rememberFinalPeerTxComplete(id, promised);
				}
			}
			const nonce = storage.loadFinalLocalTxComplete(id);
			const pair =
				nonce && decodeTxCompleteMessage(nonce, { taproot: true }).commitNonces;
			const fundingTxid = Transaction.fromHex(candidate.fundingTxHex).getHash();
			const missingCommitment =
				!opening.funding && !storage.loadFinalOpeningExit(id);
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
		this.enqueue(peer, id, message, false);
	}
	private enqueue(
		peer: string,
		id: string,
		message: IFinalOpeningMessage | undefined,
		resumeSplice: boolean
	): void {
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
				if (message?.batchError)
					throw new FinalUpdateProtocolError(message.batchError);
				const replay = message?.type === MessageType.CHANNEL_REESTABLISH;
				const connection = this.connections.get(id);
				if (resumeSplice) {
					if (connection?.established && this.splice?.awaitingDepth(id))
						await this.splice.drive(id, () => this.queues.get(id) === active);
					return;
				}
				const update =
					storage.canUpdateFinalCommitments &&
					storage.loadFinalUpdateStatus(id);
				const splicing =
					update && storage.loadFinalSpliceAttempts(id).length > 0;
				if (!splicing && connection?.established && message) {
					if (
						message.type === MessageType.TX_INIT_RBF ||
						message.type === MessageType.TX_ACK_RBF
					) {
						connection.openingRbfRefused = true;
						this.send(
							peer,
							MessageType.TX_ABORT,
							encodeTxAbortMessage({
								channelId: Buffer.from(id, 'hex'),
								data: Buffer.from('Opening fee replacement is unavailable')
							})
						);
						return;
					}
					if (
						message.type === MessageType.TX_ABORT &&
						connection.openingRbfRefused
					) {
						decodeTxAbortMessage(message.payload);
						delete connection.openingRbfRefused;
						return;
					}
				}
				const activeUpdate =
					update && (update.pending || update.last || splicing);
				if (
					message &&
					!message.signatureBatch &&
					this.splice?.handles(id, message.type, message.payload)
				) {
					if (!connection?.established || !this.negotiated(peer).splice)
						throw new Error(
							'Splice requires an authenticated peer and negotiated features'
						);
					if (
						!this.confirmed.has(id) &&
						this.splice.requiresDepth(id, message.type)
					) {
						const deferred =
							connection.deferredSplice ?? (connection.deferredSplice = []);
						if (deferred.length >= 16)
							throw new Error(
								'Too many splice messages awaiting funding depth'
							);
						deferred.push(message);
						return;
					}
					if (message.type === MessageType.TX_ABORT)
						delete connection.deferredSplice;
					await this.splice.receive(
						id,
						message,
						this.updatesReady(id),
						() => this.queues.get(id) === active
					);
					if (message.type === MessageType.TX_SIGNATURES)
						this.reconnectAfterFundingReplay(id);
					return;
				}
				const updateMessage =
					message &&
					(isFinalCommitmentUpdate(message.type) ||
						message.type === MessageType.REVOKE_AND_ACK ||
						(message.type === MessageType.COMMITMENT_SIGNED &&
							update &&
							opening.readyExchanged));
				if (
					connection &&
					message &&
					!this.confirmed.has(id) &&
					((replay && activeUpdate) ||
						(opening.readyExchanged && updateMessage))
				) {
					const deferred = connection.deferred ?? (connection.deferred = []);
					if (deferred.length >= 16)
						throw new Error(
							'Too many final commitment messages awaiting funding depth'
						);
					deferred.push(message);
					return;
				}
				if (replay) {
					if (!connection || connection.peer !== peer)
						throw new Error('Unexpected final channel_reestablish');
					if (connection.peerReestablish?.equals(message.payload)) return;
					if (connection.established)
						throw new FinalChannelReadyProtocolError(
							'Unexpected second final channel_reestablish'
						);
					if (activeUpdate) {
						// Reconnect may regenerate an outstanding commitment signature.
						if (!this.permitUpdates(id) && update.pending)
							throw new Error(
								'Final update retransmission is waiting for the funding transition'
							);
						let msg: ReturnType<typeof decodeChannelReestablishMessage>;
						try {
							msg = decodeChannelReestablishMessage(message.payload, {
								finalTaproot: true
							});
						} catch {
							throw new FinalChannelReadyProtocolError(
								'Malformed final channel_reestablish'
							);
						}
						if (splicing) this.splice?.validateReconnect(id, msg);
						const responses = storage.acceptFinalUpdateReestablish(
							id,
							this.runtime.root,
							msg
						);
						if (splicing)
							await this.splice?.reestablished(
								id,
								msg,
								() => this.queues.get(id) === active
							);
						if (this.queues.get(id) !== active) return;
						connection.peerReestablish = Buffer.from(message.payload);
						connection.established = true;
						// BOLT 2 only retransmits channel_ready when both next counters are one.
						if (msg.nextCommitmentNumber === 1n && update.localHeight === 0n)
							this.sendReady(id);
						else connection.readySent = true;

						if (splicing && this.reconnectAfterFundingReplay(id)) return;
						if (this.queues.get(id) !== active) return;
						for (const response of responses)
							this.send(peer, response.type, response.payload);
						this.resumeUpdates(id);
						this.replayClose(id);
						return;
					}
					if (
						session.assetEvidence &&
						storage.canSpliceDualFundedAssets &&
						opening.funding &&
						opening.readyExchanged &&
						this.negotiated(peer).splice
					) {
						const msg = decodeChannelReestablishMessage(message.payload, {
							finalTaproot: true
						});
						// A peer still finishing the initial exchange can request the original witnesses.
						if (
							!msg.nextFundingTxid?.equals(
								Transaction.fromHex(candidate.fundingTxHex).getHash()
							)
						) {
							acceptAssetSpliceReestablish(storage, id, this.runtime.root, msg);
							connection.peerReestablish = Buffer.from(message.payload);
							connection.established = true;
							if (
								msg.nextCommitmentNumber === 1n &&
								!storage.assetSpliceUpdateHead(id).committed
							) {
								this.sendReady(id);
								if (!connection.readySent) this.resumeAssetSplice?.(peer, id);
							} else {
								connection.readySent = true;
								this.resumeAssetSplice?.(peer, id);
							}
							return;
						}
					}
					const needsFunding = this.validateReestablish(
						id,
						candidate,
						message.payload
					);
					connection.peerReestablish = Buffer.from(message.payload);
					connection.established = true;
					if (!needsFunding) {
						this.sendReady(id);
						this.replayClose(id);
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
					if (
						storage.loadFinalLocalTxComplete(id) &&
						(!session.assetEvidence || storage.loadFinalLocalTxSignatures(id))
					)
						return;
				}
				if (connection && !connection.established)
					throw new Error('Waiting for final channel_reestablish');
				if (message?.type === MessageType.CHANNEL_READY) {
					if (!connection?.established)
						throw new Error(
							'Final channel_ready requires an established connection'
						);
					if (session.assetEvidence && !this.hasDepth(id)) {
						if (
							connection.pendingAssetReady &&
							!connection.pendingAssetReady.equals(message.payload)
						)
							throw new FinalChannelReadyProtocolError(
								'Changed asset channel_ready'
							);
						connection.pendingAssetReady = Buffer.from(message.payload);
						return;
					}
					storage.rememberFinalPeerChannelReady(
						id,
						message.payload,
						this.negotiated(peer).alias
					);
					this.sendReady(id);
					this.resumeUpdates(id);
					return;
				}
				if (
					message &&
					(message.type === MessageType.SHUTDOWN ||
						message.type === MessageType.CLOSING_COMPLETE ||
						message.type === MessageType.CLOSING_SIG)
				) {
					this.driveClose(id, message);
					return;
				}
				if (updateMessage) {
					this.commitments.receive(id, message!);
					if (storage.finalSimpleCloseStarted(id)) this.driveClose(id);
					return;
				}
				if (
					storage.canSpliceDualFundedAssets &&
					opening.readyExchanged &&
					opening.funding &&
					session.assetEvidence &&
					message
				) {
					const saved =
						message.type === MessageType.TX_COMPLETE
							? storage.loadFinalPeerTxComplete(id)
							: message.type === MessageType.COMMITMENT_SIGNED
							? storage.loadReceivedOpeningCommitment(id)
							: message.type === MessageType.TX_SIGNATURES
							? storage.loadFinalPeerTxSignatures(id)
							: undefined;
					if (saved) {
						if (
							!saved.equals(message.payload) &&
							!storage.receivedAssetSpliceWire(
								id,
								message.type,
								message.payload
							)
						)
							throw Error(
								'Opening replay differs from the secured original funding'
							);
						return;
					}
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
					!session.assetEvidence &&
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
				if (session.assetEvidence && !storage.loadFinalLocalTxSignatures(id)) {
					const released = await this.releaseAssetFunding(id, peer, candidate);
					if (
						this.queues.get(id) !== active ||
						storage.loadFinalDaemonOpening(id)?.exitToBroadcast
					)
						return;
					if (released) {
						this.send(peer, MessageType.TX_SIGNATURES, released);
						response.fundingTx =
							storage.loadFinalFundingTransaction(id) ?? undefined;
					}
				}
				if (response.fundingTx) {
					this.funded(candidate, response.fundingTx);
					this.sendReady(id);
				}
			})
			.catch((err: unknown) => {
				if (this.queues.get(id) !== active) return;
				const channelId = Buffer.from(id, 'hex');
				if (
					(err instanceof FinalChannelReadyProtocolError ||
						err instanceof FinalUpdateProtocolError ||
						err instanceof FinalCloseProtocolError) &&
					this.fail
				) {
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
