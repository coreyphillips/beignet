import type {
	IFinalOpeningMessage,
	IFinalOpeningRuntime
} from './final-opening-runtime';
import { signatureFrames } from '../storage/final-funding-updates';
import { MessageType } from '../message/types';
import { ASSET_CONVERSION_TEXTS } from './asset-conversion-terms';

export function isFinalCommitmentUpdate(type: MessageType): boolean {
	return (
		type === MessageType.UPDATE_FEE ||
		type === MessageType.UPDATE_ADD_HTLC ||
		type === MessageType.UPDATE_FULFILL_HTLC ||
		type === MessageType.UPDATE_FAIL_HTLC ||
		type === MessageType.UPDATE_FAIL_MALFORMED_HTLC
	);
}

/** Drive both commitment views of a final channel from its durable transcript. */
export class FinalCommitmentTransport {
	private readonly delivering = new Set<string>();

	constructor(
		private readonly runtime: IFinalOpeningRuntime,
		private readonly ready: (id: string) => boolean,
		private readonly send: (id: string, message: IFinalOpeningMessage) => void,
		private readonly deliver: (
			id: string,
			message: IFinalOpeningMessage
		) => void,
		/** A conversion holds the channel against local adds and fee updates (#2151). */
		private readonly held: (id: string) => boolean = () => false,
		/** A live conversion attempt's record on disk keeps the channel quiet: no local update of any type (#2151 Step 4a). */
		private readonly quiet: (id: string) => boolean = () => false
	) {}

	private requireReady(id: string): void {
		if (!this.runtime.storage.canUpdateFinalCommitments || !this.ready(id))
			throw new Error(
				'Final commitment exchange requires an authenticated, confirmed update-capable channel'
			);
	}

	local(id: string, type: MessageType, payload: Buffer): void {
		this.requireReady(id);
		if (!isFinalCommitmentUpdate(type))
			throw new Error('Invalid final commitment update');
		if (
			((type === MessageType.UPDATE_ADD_HTLC ||
				type === MessageType.UPDATE_FEE) &&
				this.held(id)) ||
			this.quiet(id)
		)
			throw new Error(ASSET_CONVERSION_TEXTS.held);
		const { storage, root } = this.runtime;
		storage.stageFinalHtlcUpdate(id, 'local', type, payload);
		const signatures = storage.loadFinalUpdateStatus(id)?.needsPeerCommitment
			? storage.signFinalUpdateCommitmentBatch(id, root)
			: [];
		this.send(id, { type, payload });
		for (const frame of signatureFrames(id, signatures)) this.send(id, frame);
	}

	receive(id: string, message: IFinalOpeningMessage): void {
		this.requireReady(id);
		const { storage, root } = this.runtime;
		if (isFinalCommitmentUpdate(message.type)) {
			storage.stageFinalHtlcUpdate(id, 'peer', message.type, message.payload);
			return;
		}
		if (message.type === MessageType.COMMITMENT_SIGNED) {
			const revocation = storage.acceptFinalUpdateCommitmentBatch(
				id,
				root,
				message.signatureBatch ?? [message.payload]
			);
			this.send(id, { type: MessageType.REVOKE_AND_ACK, payload: revocation });
		} else if (message.type === MessageType.REVOKE_AND_ACK) {
			storage.acceptFinalUpdateRevocation(id, message.payload);
		} else {
			throw new Error('Unexpected message for a final commitment');
		}
		if (storage.loadFinalUpdateStatus(id)?.needsPeerCommitment) {
			this.requireReady(id);
			const signatures = storage.signFinalUpdateCommitmentBatch(id, root);
			for (const frame of signatureFrames(id, signatures)) this.send(id, frame);
		}
		this.deliverLocked(id);
	}

	/** The store retains each wallet event until its synchronous consumer returns. */
	deliverLocked(id: string, removalsOnly = false): void {
		if (this.delivering.has(id) || (!removalsOnly && !this.ready(id))) return;
		this.delivering.add(id);
		try {
			const { storage } = this.runtime;
			for (const delivery of storage.loadFinalUpdateDeliveries(id)) {
				if (
					removalsOnly &&
					(delivery.type === MessageType.UPDATE_ADD_HTLC ||
						delivery.direction !== 'peer')
				)
					continue;
				if (delivery.direction === 'peer') this.deliver(id, delivery);
				storage.ackFinalUpdateDelivery(id, delivery.id);
			}
		} finally {
			this.delivering.delete(id);
		}
	}
}
