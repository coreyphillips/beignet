import { BeignetNode } from './beignet-node';
import {
	DfTransport,
	IDirectFundingReceiverDeps,
	handleOffer,
	dfTopic
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
export function startSwarmReceiver(
	node: BeignetNode,
	deps: IDirectFundingReceiverDeps,
	nodePubkeyHex: string,
	log: (line: string) => void
): { stop: () => Promise<void> } {
	const swarm = new Hyperswarm();
	swarm.on('connection', (socket: any) => {
		const transport = socketTransport(socket);
		socket.on('error', () => {
			/* peer went away; nothing to do */
		});
		transport.onMessage((subtype, payload) => {
			if (subtype !== BeignetCustomSubtype.DIRECT_FUNDING_OFFER) return;
			void handleOffer(node, deps, transport, payload).catch((e) => {
				deps.onEvent?.('direct-funding-failed', e.message);
			});
		});
	});
	swarm.join(dfTopic(nodePubkeyHex), { server: true, client: false });
	log(`direct-funding swarm listener up (topic from ${nodePubkeyHex.slice(0, 12)})`);
	return {
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
	recipientPubkeyHex: string,
	timeoutMs = 30_000
): Promise<{ transport: DfTransport; close: () => Promise<void> }> {
	const swarm = new Hyperswarm();
	const close = async (): Promise<void> => {
		try {
			await swarm.destroy();
		} catch {
			/* already down */
		}
	};
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => {
			void close();
			reject(
				new Error(
					'could not find the recipient on the network (is their wallet online?)'
				)
			);
		}, timeoutMs);
		swarm.on('connection', (socket: any) => {
			clearTimeout(timer);
			socket.on('error', () => {
				/* handled by protocol timeouts */
			});
			resolve({ transport: socketTransport(socket), close });
		});
		swarm.join(dfTopic(recipientPubkeyHex), { server: false, client: true });
	});
}
