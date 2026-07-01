/**
 * Async payments (draft) — AsyncPaymentManager.
 *
 * Two roles, wired through onion messages:
 *  - LSP: parks a forward destined for an offline receiver (registerHeldForward),
 *    then releases it when a release_held_htlc onion message arrives.
 *  - Receiver: on a wake message, emits so the host reconnects to the LSP and
 *    triggers the release; can send release_held_htlc to the LSP.
 *
 * This is transport glue only — the actual park/forward lives in the node; the
 * manager just maps release/wake messages to callbacks and sends them.
 */

import { EventEmitter } from 'events';
import { OnionMessageManager } from '../onion-message/manager';
import {
	RELEASE_HELD_HTLC_TLV_TYPE,
	ASYNC_WAKE_TLV_TYPE,
	IHeldForward
} from './types';

export class AsyncPaymentManager extends EventEmitter {
	private onionManager: OnionMessageManager | null = null;
	/** Forwards parked for offline receivers, keyed by payment hash hex. */
	private heldForwards: Map<string, IHeldForward> = new Map();

	/**
	 * Attach the onion message manager and register handlers for the async
	 * release/wake TLVs.
	 */
	attachOnionMessageManager(onionManager: OnionMessageManager): void {
		this.onionManager = onionManager;
		onionManager.registerTlvHandler(
			RELEASE_HELD_HTLC_TLV_TYPE,
			(_fromPeer, _type, data) => {
				if (data.length === 32) {
					this.handleRelease(data);
				}
			}
		);
		onionManager.registerTlvHandler(
			ASYNC_WAKE_TLV_TYPE,
			(_fromPeer, _type, data) => {
				// data is the payment hash the sender wants paid.
				this.emit('wake', data.length === 32 ? data : undefined);
			}
		);
	}

	/**
	 * LSP: register a parked forward awaiting release. Replaces any existing
	 * entry for the same hash (latest park wins).
	 */
	registerHeldForward(held: IHeldForward): void {
		this.heldForwards.set(held.paymentHash.toString('hex'), held);
	}

	/** Whether a forward is currently parked for this payment hash. */
	hasHeldForward(paymentHash: Buffer): boolean {
		return this.heldForwards.has(paymentHash.toString('hex'));
	}

	/** LSP: release a parked forward by payment hash (manual or on message). */
	handleRelease(paymentHash: Buffer): boolean {
		const key = paymentHash.toString('hex');
		const held = this.heldForwards.get(key);
		if (!held) return false;
		this.heldForwards.delete(key);
		held.release();
		this.emit('released', paymentHash);
		return true;
	}

	/** LSP: fail and drop a parked forward (e.g. CLTV nearing expiry). */
	failHeldForward(paymentHash: Buffer): boolean {
		const key = paymentHash.toString('hex');
		const held = this.heldForwards.get(key);
		if (!held) return false;
		this.heldForwards.delete(key);
		held.fail();
		return true;
	}

	/** List payment hashes of currently parked forwards. */
	listHeldForwards(): Buffer[] {
		return [...this.heldForwards.values()].map((h) => h.paymentHash);
	}

	/**
	 * Receiver: tell the LSP to release the held HTLC for a payment hash.
	 */
	sendRelease(lspNodeId: Buffer, paymentHash: Buffer): void {
		if (!this.onionManager) throw new Error('onion manager not attached');
		this.onionManager.sendOnionMessage(
			lspNodeId,
			new Map([[RELEASE_HELD_HTLC_TLV_TYPE, paymentHash]])
		);
	}

	/**
	 * Sender: nudge an offline receiver to come online for a payment hash.
	 */
	sendWake(receiverNodeId: Buffer, paymentHash: Buffer): void {
		if (!this.onionManager) throw new Error('onion manager not attached');
		this.onionManager.sendOnionMessage(
			receiverNodeId,
			new Map([[ASYNC_WAKE_TLV_TYPE, paymentHash]])
		);
	}
}
