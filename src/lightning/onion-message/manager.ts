/**
 * BOLT 7.5: Onion Message Manager
 *
 * High-level manager for sending and receiving onion messages.
 * Handles construction, processing, forwarding, and rate limiting.
 */

import { EventEmitter } from 'events';
import {
	IOnionMessage,
	IOnionMessagePayload,
	ISendOnionMessageOptions,
	IRateLimitConfig
} from './types';
import {
	encodeOnionMessage as encodeOnionMessageWire,
	decodeOnionMessage as decodeOnionMessageWire
} from './codec';
import {
	constructSimpleOnionMessage,
	constructMultiHopOnionMessage,
	constructReplyOnionMessage
} from './construct';
import { processOnionMessage } from './process';
import { IBlindedPath } from '../onion/blinded-path';

/** TLV type handler callback */
type TlvHandler = (
	fromPeer: string,
	tlvType: number,
	data: Buffer,
	replyPath?: IBlindedPath
) => void;

/**
 * Rate limiter state for a single peer.
 */
interface IPeerRateLimit {
	timestamps: number[];
}

/**
 * Onion Message Manager.
 *
 * Events:
 * - 'message:received' (fromPeer: string, payload: IOnionMessagePayload)
 * - 'message:forwarded' (fromPeer: string, nextNodeId: string)
 * - 'message:error' (fromPeer: string, error: Error)
 * - 'message:send' (toPeer: string, type: number, payload: Buffer)
 */
export class OnionMessageManager extends EventEmitter {
	private nodePrivkey: Buffer;
	private rateLimits: Map<string, IPeerRateLimit> = new Map();
	private rateLimitConfig: IRateLimitConfig;
	private tlvHandlers: Map<number, TlvHandler[]> = new Map();
	private sendMessage:
		| ((toPeer: string, type: number, payload: Buffer) => void)
		| null = null;

	constructor(
		nodePrivkey: Buffer,
		rateLimitConfig?: Partial<IRateLimitConfig>
	) {
		super();
		this.nodePrivkey = nodePrivkey;
		this.rateLimitConfig = {
			maxPerWindow: rateLimitConfig?.maxPerWindow ?? 10,
			windowMs: rateLimitConfig?.windowMs ?? 60_000
		};
	}

	/**
	 * Set the function used to send messages to peers.
	 * This is typically wired to PeerManager.sendToPeer().
	 */
	setSendFunction(
		fn: (toPeer: string, type: number, payload: Buffer) => void
	): void {
		this.sendMessage = fn;
	}

	/**
	 * Register a handler for a specific TLV type in received onion messages.
	 * The handler is called when a message arrives containing the specified TLV type.
	 */
	registerTlvHandler(tlvType: number, handler: TlvHandler): void {
		const handlers = this.tlvHandlers.get(tlvType) || [];
		handlers.push(handler);
		this.tlvHandlers.set(tlvType, handlers);
	}

	/**
	 * Unregister all handlers for a specific TLV type.
	 */
	unregisterTlvHandler(tlvType: number): void {
		this.tlvHandlers.delete(tlvType);
	}

	/**
	 * Send an onion message to a destination.
	 *
	 * @param destination - 33-byte destination node public key
	 * @param messageData - Application data as Map<tlvType, value>
	 * @param options - Optional: reply path
	 */
	sendOnionMessage(
		destination: Buffer,
		messageData: Map<number, Buffer>,
		options?: ISendOnionMessageOptions
	): void {
		if (!this.sendMessage) {
			throw new Error('Send function not configured');
		}

		const msg = constructSimpleOnionMessage(
			destination,
			messageData,
			undefined,
			options
		);
		const wirePayload = encodeOnionMessageWire(msg);

		// For single-hop messages, send directly to the destination
		const destHex = destination.toString('hex');
		this.sendMessage(destHex, 513, wirePayload);
		this.emit('message:send', destHex, 513, wirePayload);
	}

	/**
	 * Send a multi-hop onion message through intermediate nodes.
	 *
	 * @param intermediateNodes - Array of intermediate node public keys
	 * @param destination - Final destination public key
	 * @param messageData - Application data for the final hop
	 * @param options - Optional: reply path
	 */
	sendMultiHopOnionMessage(
		intermediateNodes: Buffer[],
		destination: Buffer,
		messageData: Map<number, Buffer>,
		options?: ISendOnionMessageOptions
	): void {
		if (!this.sendMessage) {
			throw new Error('Send function not configured');
		}

		const msg = constructMultiHopOnionMessage(
			intermediateNodes,
			destination,
			messageData,
			undefined,
			options
		);
		const wirePayload = encodeOnionMessageWire(msg);

		// Send to the first node in the path
		const firstHop =
			intermediateNodes.length > 0
				? intermediateNodes[0].toString('hex')
				: destination.toString('hex');
		this.sendMessage(firstHop, 513, wirePayload);
		this.emit('message:send', firstHop, 513, wirePayload);
	}

	/**
	 * Send a reply using a blinded reply path.
	 *
	 * @param replyPath - The blinded path received in the original message
	 * @param messageData - Application data for the reply
	 */
	sendReply(replyPath: IBlindedPath, messageData: Map<number, Buffer>): void {
		if (!this.sendMessage) {
			throw new Error('Send function not configured');
		}

		const msg = constructReplyOnionMessage(replyPath, messageData);
		const wirePayload = encodeOnionMessageWire(msg);

		// Send to the introduction node
		const introHex = replyPath.introductionNodeId.toString('hex');
		this.sendMessage(introHex, 513, wirePayload);
		this.emit('message:send', introHex, 513, wirePayload);
	}

	/**
	 * Handle an incoming onion message from a peer.
	 * Processes the onion and either forwards or delivers the message.
	 *
	 * @param fromPeer - Hex-encoded public key of the sending peer
	 * @param payload - Wire-encoded onion_message payload (excluding 2-byte type prefix)
	 */
	handleMessage(fromPeer: string, payload: Buffer): void {
		// Rate limiting check
		if (!this.checkRateLimit(fromPeer)) {
			const err = new Error(`Rate limit exceeded for peer ${fromPeer}`);
			this.emit('message:error', fromPeer, err);
			return;
		}

		let msg: IOnionMessage;
		try {
			msg = decodeOnionMessageWire(payload);
		} catch (err) {
			this.emit('message:error', fromPeer, err as Error);
			return;
		}

		try {
			const result = processOnionMessage(
				msg.onionRoutingPacket,
				this.nodePrivkey,
				msg.blindingPoint
			);

			if (result.type === 'delivery') {
				// Final destination — emit event and invoke TLV handlers
				this.emit('message:received', fromPeer, result.payload);
				this.invokeTlvHandlers(fromPeer, result.payload);
			} else {
				// Intermediate — forward to next hop
				const nextNodeHex = result.nextNodeId.toString('hex');

				if (this.sendMessage) {
					const nextWirePayload = encodeOnionMessageWire(
						result.nextOnionMessage
					);
					this.sendMessage(nextNodeHex, 513, nextWirePayload);
				}

				this.emit('message:forwarded', fromPeer, nextNodeHex);
			}
		} catch (err) {
			this.emit('message:error', fromPeer, err as Error);
		}
	}

	/**
	 * Update rate limit configuration.
	 */
	setRateLimitConfig(config: Partial<IRateLimitConfig>): void {
		if (config.maxPerWindow !== undefined) {
			this.rateLimitConfig.maxPerWindow = config.maxPerWindow;
		}
		if (config.windowMs !== undefined) {
			this.rateLimitConfig.windowMs = config.windowMs;
		}
	}

	/**
	 * Get the current rate limit configuration.
	 */
	getRateLimitConfig(): IRateLimitConfig {
		return { ...this.rateLimitConfig };
	}

	/**
	 * Clear rate limit state for all peers.
	 */
	clearRateLimits(): void {
		this.rateLimits.clear();
	}

	/**
	 * Destroy the manager, cleaning up all state.
	 */
	destroy(): void {
		this.rateLimits.clear();
		this.tlvHandlers.clear();
		this.sendMessage = null;
		this.removeAllListeners();
	}

	// ─────────────── Private ───────────────

	/**
	 * Check and update rate limit for a peer.
	 * @returns true if the message is allowed, false if rate-limited
	 */
	private checkRateLimit(peer: string): boolean {
		const now = Date.now();
		let state = this.rateLimits.get(peer);
		if (!state) {
			state = { timestamps: [] };
			this.rateLimits.set(peer, state);
		}

		// Remove expired timestamps
		const cutoff = now - this.rateLimitConfig.windowMs;
		state.timestamps = state.timestamps.filter((t) => t > cutoff);

		// Check limit
		if (state.timestamps.length >= this.rateLimitConfig.maxPerWindow) {
			return false;
		}

		// Record this message
		state.timestamps.push(now);
		return true;
	}

	/**
	 * Invoke registered TLV handlers for a received message payload.
	 */
	private invokeTlvHandlers(
		fromPeer: string,
		payload: IOnionMessagePayload
	): void {
		for (const [tlvType, data] of payload.messageTlvs) {
			const handlers = this.tlvHandlers.get(tlvType);
			if (handlers) {
				for (const handler of handlers) {
					handler(fromPeer, tlvType, data, payload.replyPath);
				}
			}
		}
	}
}
