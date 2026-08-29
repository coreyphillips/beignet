/**
 * A loopback peer network for the direct-funding transport tests (issue #611).
 *
 * `deliver` mirrors `LightningNode.handlePeerMessage` exactly: every
 * 'custom-message' listener runs inside ONE try/catch, so a listener that
 * throws both swallows its own error and skips every listener after it. The
 * lanes are written against that shape, and these tests only prove it because
 * the harness reproduces it rather than isolating each listener itself.
 */

import crypto from 'crypto';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { BEIGNET_CUSTOM_PROTOCOL_VERSION } from '../../../src/lightning/message/custom';
import {
	IDfCustomMessage,
	IDfPeerMessaging
} from '../../../src/lightning/direct-funding/transport';

export class FakeDfNetwork {
	readonly peers = new Map<string, FakeDfPeer>();
	/** Node ids that refuse an inbound dial. */
	readonly undialable = new Set<string>();

	add(label: string): FakeDfPeer {
		const privkey = crypto.createHash('sha256').update(label).digest();
		const peer = new FakeDfPeer(this, privkey);
		this.peers.set(peer.id, peer);
		return peer;
	}

	connect(a: FakeDfPeer, b: FakeDfPeer): void {
		a.connections.add(b.id);
		b.connections.add(a.id);
	}
}

export class FakeDfPeer implements IDfPeerMessaging {
	readonly connections = new Set<string>();
	readonly listeners = new Set<(msg: IDfCustomMessage) => void>();
	/** Errors a listener let escape, i.e. what would cost a real peer its link. */
	readonly escapedErrors: unknown[] = [];
	readonly sent: Array<{ to: string; subtype: number; payload: Buffer }> = [];
	dialAttempts = 0;
	readonly pubkey: Buffer;
	readonly id: string;

	constructor(
		private readonly net: FakeDfNetwork,
		/** Also the onion-message manager's key, so both views agree on node ids. */
		readonly privkey: Buffer
	) {
		this.pubkey = getPublicKey(privkey);
		this.id = this.pubkey.toString('hex');
	}

	nodeIdHex(): string {
		return this.id;
	}

	isPeerConnected(peerPubkeyHex: string): boolean {
		return this.connections.has(peerPubkeyHex);
	}

	async connectPeer(peerPubkeyHex: string): Promise<void> {
		this.dialAttempts++;
		const target = this.net.peers.get(peerPubkeyHex);
		if (!target || this.net.undialable.has(peerPubkeyHex)) {
			throw new Error(`Failed to connect to peer ${peerPubkeyHex}`);
		}
		this.net.connect(this, target);
	}

	sendCustomMessage(
		peerPubkeyHex: string,
		subtype: number,
		payload: Buffer
	): void {
		if (!this.connections.has(peerPubkeyHex)) {
			throw new Error(`Not connected to peer ${peerPubkeyHex}`);
		}
		this.sent.push({ to: peerPubkeyHex, subtype, payload });
		this.net.peers
			.get(peerPubkeyHex)
			?.deliver({ peerPubkey: this.id, subtype, payload });
	}

	onCustomMessage(cb: (msg: IDfCustomMessage) => void): () => void {
		this.listeners.add(cb);
		return () => {
			this.listeners.delete(cb);
		};
	}

	/**
	 * The node's dispatch, faithfully: one try/catch around all listeners. The
	 * version defaults to the one this build speaks, so a test that says nothing
	 * about it gets an ordinary peer.
	 */
	deliver(msg: Omit<IDfCustomMessage, 'version'> & { version?: number }): void {
		const full: IDfCustomMessage = {
			version: msg.version ?? BEIGNET_CUSTOM_PROTOCOL_VERSION,
			peerPubkey: msg.peerPubkey,
			subtype: msg.subtype,
			payload: msg.payload
		};
		try {
			for (const listener of [...this.listeners]) listener(full);
		} catch (err) {
			this.escapedErrors.push(err);
		}
	}
}

/** Collect structured log lines the way the node's 'log' event would. */
export function recordingLog(): {
	log: (action: string, data: Record<string, unknown>) => void;
	lines: Array<{ action: string; data: Record<string, unknown> }>;
	reasons: () => string[];
} {
	const lines: Array<{ action: string; data: Record<string, unknown> }> = [];
	return {
		log: (action, data): void => {
			lines.push({ action, data });
		},
		lines,
		reasons: () => lines.map((l) => String(l.data.reason))
	};
}
