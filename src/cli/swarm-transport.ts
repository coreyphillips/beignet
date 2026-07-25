import { BeignetNode } from './beignet-node';
import {
	DfTransport,
	IDirectFundingReceiverDeps,
	dispatchOffer
} from './direct-funding';
import { BeignetCustomSubtype } from '../lightning/message/custom';

// hyperswarm ships no type definitions; loaded untyped on purpose.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const Hyperswarm = require('hyperswarm');

/**
 * Direct funding over hyperswarm: the receiver announces itself on a DHT
 * topic derived from its NODE PUBKEY, so a sender holding only the pubkey
 * from a payment request can find and talk to it — no host, no port, no
 * dialable address, NAT hole-punching included. The socket carries the same
 * JSON frames as the Lightning custom-message transport:
 *
 *   [u32 length BE][u16 subtype BE][json payload]
 *
 * This lane carries ONLY the direct-funding protocol (offer, sign, witness,
 * receipt); it is not a Lightning peer connection, and every message on it
 * is validated exactly as on the Lightning lane (ownership proofs in,
 * attestation out), so the transport being anonymous costs nothing.
 */

const FRAME_HEADER = 6;
const MAX_FRAME = 1_048_576; // generous: a prev tx in hex dominates

/** Wrap a duplex socket in the direct-funding frame protocol. */
export function socketTransport(socket: {
	write: (b: Buffer) => void;
	on: (ev: string, cb: (arg?: unknown) => void) => void;
	destroy?: () => void;
}): DfTransport {
	const listeners = new Set<(subtype: number, payload: Buffer) => void>();
	let buf = Buffer.alloc(0);
	socket.on('data', (chunk) => {
		buf = Buffer.concat([buf, chunk as Buffer]);
		for (;;) {
			if (buf.length < FRAME_HEADER) return;
			const len = buf.readUInt32BE(0);
			if (len > MAX_FRAME) {
				socket.destroy?.();
				return;
			}
			if (buf.length < 4 + len) return;
			const subtype = buf.readUInt16BE(4);
			const payload = buf.subarray(FRAME_HEADER, 4 + len);
			buf = buf.subarray(4 + len);
			for (const cb of [...listeners]) cb(subtype, payload);
		}
	});
	return {
		send: (subtype, payload) => {
			const body = Buffer.from(JSON.stringify(payload), 'utf8');
			const frame = Buffer.alloc(FRAME_HEADER + body.length);
			frame.writeUInt32BE(body.length + 2, 0);
			frame.writeUInt16BE(subtype, 4);
			body.copy(frame, FRAME_HEADER);
			socket.write(frame);
		},
		onMessage: (cb) => {
			listeners.add(cb);
			return () => listeners.delete(cb);
		}
	};
}

/**
 * Receiver side: announce on this node's topic and answer funding offers
 * arriving over swarm sockets. Returns a stop handle.
 */
export interface ISwarmReceiver {
	stop: () => Promise<void>;
	/** This instance's Noise public key (hex). Payment requests pin it so a
	 *  sender refuses to talk to a topic squatter. Stable across requests for
	 *  now; per-request Noise identities are a documented later stage. */
	noisePublicKeyHex: string;
	/** Announce a per-request rendezvous topic. */
	join: (topic: Buffer) => void;
	/** Stop announcing a topic (existing sockets keep their own lifecycle;
	 *  the request-level receipt check already rejects stale offers). */
	leave: (topic: Buffer) => Promise<void>;
}

export function startSwarmReceiver(
	node: BeignetNode,
	deps: IDirectFundingReceiverDeps,
	log: (line: string) => void
): ISwarmReceiver {
	const swarm = new Hyperswarm();
	swarm.on('connection', (socket: any) => {
		// One swarm serves every topic; hyperswarm does not say which topic
		// produced a connection. Requests are identified by the OFFER content
		// (receipt hash), so the ambiguity costs nothing.
		const transport = socketTransport(socket);
		socket.on('error', () => {
			/* peer went away; nothing to do */
		});
		transport.onMessage((subtype, payload) => {
			if (subtype !== BeignetCustomSubtype.DIRECT_FUNDING_OFFER) return;
			void dispatchOffer(node, deps, transport, payload, {
				senderAnonymous: true
			}).catch((e) => {
				deps.onEvent?.('direct-funding-failed', e.message);
			});
		});
	});
	// No standing topic: rendezvous topics are joined per outstanding
	// request and left on use or expiry, so this node has no static DHT
	// presence at all.
	log('direct-funding swarm ready (per-request rendezvous only)');
	return {
		noisePublicKeyHex: Buffer.from(swarm.keyPair.publicKey).toString('hex'),
		join: (topic: Buffer) => {
			swarm.join(topic, { server: true, client: false });
		},
		leave: async (topic: Buffer) => {
			try {
				await swarm.leave(topic);
			} catch {
				/* already left */
			}
		},
		stop: async () => {
			try {
				await swarm.destroy();
			} catch {
				/* already down */
			}
		}
	};
}

/**
 * Sender side: find the recipient on the DHT by pubkey and hand back a
 * transport over the first connection. The caller closes when done.
 */
export function swarmConnect(
	topic: Buffer,
	opts: {
		/** Receiver's Noise public key from the payment request. When set, a
		 *  connection from any OTHER key is dropped and the search continues:
		 *  a topic squatter never receives a single protocol byte. */
		expectedNoiseKeyHex?: string;
		timeoutMs?: number;
	} = {}
): Promise<{ transport: DfTransport; close: () => Promise<void> }> {
	const swarm = new Hyperswarm();
	const close = async (): Promise<void> => {
		try {
			await swarm.destroy();
		} catch {
			/* already down */
		}
	};
	const expected = opts.expectedNoiseKeyHex
		? Buffer.from(opts.expectedNoiseKeyHex, 'hex')
		: null;
	return new Promise((resolve, reject) => {
		let done = false;
		const timer = setTimeout(() => {
			done = true;
			void close();
			reject(
				new Error(
					expected
						? 'could not reach the receiver identified in the payment request (identity-checked; squatters were ignored)'
						: 'could not find the recipient on the network (is their wallet online?)'
				)
			);
		}, opts.timeoutMs ?? 30_000);
		swarm.on('connection', (socket: any) => {
			if (done) return;
			if (expected) {
				const remote: Buffer | undefined = socket.remotePublicKey;
				if (
					!remote ||
					remote.length !== expected.length ||
					!nodeCryptoTimingSafeEqual(remote, expected)
				) {
					// Not the receiver the request named: say nothing, keep looking.
					try {
						socket.destroy();
					} catch {
						/* gone */
					}
					return;
				}
			}
			done = true;
			clearTimeout(timer);
			socket.on('error', () => {
				/* handled by protocol timeouts */
			});
			resolve({ transport: socketTransport(socket), close });
		});
		swarm.join(topic, { server: false, client: true });
	});
}

// eslint-disable-next-line @typescript-eslint/no-var-requires
const nodeCryptoTimingSafeEqual: (a: Buffer, b: Buffer) => boolean =
	require('crypto').timingSafeEqual;
