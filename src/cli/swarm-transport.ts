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
 * Receiver side: one Hyperswarm instance PER OUTSTANDING REQUEST, each with
 * a fresh Noise keypair and its own DHT node. Two of this wallet's requests
 * therefore share no observable identity: an active observer who connects
 * to both rendezvous topics meets two unrelated Noise keys, and nothing
 * links them to each other or to the Lightning node. A wallet with no
 * outstanding requests runs no swarm and no DHT node at all.
 */
export interface ISwarmReceiver {
	/** Announce a rendezvous topic under a fresh Noise identity minted for
	 *  this request alone; returns that identity's public key (hex) for the
	 *  envelope to pin. */
	addRequest: (topic: Buffer) => string;
	/** Stop announcing and schedule the request's swarm, DHT node, and
	 *  Noise identity for teardown. The teardown is delayed a grace period
	 *  so a receipt frame still in flight on an open socket can drain. */
	removeRequest: (topic: Buffer) => void;
	stop: () => Promise<void>;
}

const TEARDOWN_GRACE_MS = 30_000;

export function startSwarmReceiver(
	node: BeignetNode,
	deps: IDirectFundingReceiverDeps,
	log: (line: string) => void
): ISwarmReceiver {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any -- hyperswarm is untyped
	const swarms = new Map<string, any>();
	let stopped = false;
	const destroySwarm = async (swarm: any): Promise<void> => {
		try {
			await swarm.destroy();
		} catch {
			/* already down */
		}
	};
	log('direct-funding swarm ready (per-request rendezvous and identity)');
	return {
		addRequest: (topic: Buffer): string => {
			if (stopped) throw new Error('swarm receiver is stopped');
			const swarm = new Hyperswarm();
			swarm.on('connection', (socket: any) => {
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
			swarm.join(topic, { server: true, client: false });
			swarms.set(topic.toString('hex'), swarm);
			return Buffer.from(swarm.keyPair.publicKey).toString('hex');
		},
		removeRequest: (topic: Buffer): void => {
			const key = topic.toString('hex');
			const swarm = swarms.get(key);
			if (!swarm) return;
			swarms.delete(key);
			// Stop announcing right away; destroy after a grace period so the
			// final receipt frame can drain to a connected sender.
			void (async () => {
				try {
					await swarm.leave(topic);
				} catch {
					/* already left */
				}
			})();
			const timer = setTimeout(() => {
				void destroySwarm(swarm);
			}, TEARDOWN_GRACE_MS);
			timer.unref?.();
		},
		stop: async () => {
			stopped = true;
			const all = [...swarms.values()];
			swarms.clear();
			await Promise.all(all.map(destroySwarm));
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
