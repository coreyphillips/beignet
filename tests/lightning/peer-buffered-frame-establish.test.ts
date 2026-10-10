/**
 * Establishment over coalesced frames (issue #1491): an invalid frame that
 * arrives in the same chunk as the peer's init closes the connection while
 * the buffered bytes drain, and the establishment must fail instead of
 * reporting connect for a closed transport.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import net from 'net';
import { EventEmitter } from 'events';
import { Peer } from '../../src/lightning/transport/peer';
import { IDuplexTransport } from '../../src/lightning/transport/duplex-transport';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

// An encrypted length prefix's size; zeros never authenticate.
const INVALID_CIPHERTEXT = Buffer.alloc(18, 0);
// The responder writes act 2 then its init; the initiator writes acts 1
// and 3 then its init.
const RESPONDER_INIT_WRITE = 1;
const INITIATOR_INIT_WRITE = 2;

/**
 * One end of an in-memory link. It can append invalid bytes to one write,
 * and hold one write back so it arrives in the same chunk as the next.
 */
class MemoryTransport extends EventEmitter implements IDuplexTransport {
	remote: MemoryTransport | null = null;
	readonly writableLength = 0;
	private writes = 0;
	private destroyed = false;
	private held: Buffer | null = null;

	constructor(
		private readonly tamperedWrite: number | null,
		private readonly heldWrite: number | null = null
	) {
		super();
	}

	write(data: Uint8Array, cb?: (err?: Error) => void): boolean {
		let chunk = Buffer.from(data);
		const index = this.writes++;
		if (index === this.tamperedWrite) {
			chunk = Buffer.concat([chunk, INVALID_CIPHERTEXT]);
		}
		queueMicrotask(() => cb?.());
		if (index === this.heldWrite) {
			this.held = chunk;
			return true;
		}
		if (this.held) {
			chunk = Buffer.concat([this.held, chunk]);
			this.held = null;
		}
		const remote = this.remote;
		setImmediate(() => {
			if (remote && !remote.destroyed) remote.emit('data', chunk);
		});
		return true;
	}

	setTimeout(): this {
		return this;
	}

	setKeepAlive(): this {
		return this;
	}

	destroy(): this {
		if (this.destroyed) return this;
		this.destroyed = true;
		setImmediate(() => {
			this.emit('close', false);
			this.remote?.destroy();
		});
		return this;
	}
}

interface IOutcome {
	error: Error | null;
	connects: number;
	errors: number;
	state: string;
	pingTimer: unknown;
}

function watch(peer: Peer): { connects: number; errors: number } {
	const counts = { connects: 0, errors: 0 };
	peer.on('connect', () => counts.connects++);
	peer.on('error', () => counts.errors++);
	return counts;
}

async function outcome(
	peer: Peer,
	establishment: Promise<void>,
	counts: { connects: number; errors: number }
): Promise<IOutcome> {
	const error = await establishment.then(
		() => null,
		(err: Error) => err
	);
	return {
		error,
		connects: counts.connects,
		errors: counts.errors,
		state: peer.getState(),
		pingTimer: (peer as unknown as { pingTimer: unknown }).pingTimer
	};
}

function expectRefused(result: IOutcome): void {
	expect(result.errors).to.be.greaterThan(0);
	expect(result.error).to.be.instanceOf(Error);
	expect(result.connects).to.equal(0);
	expect(result.state).to.equal('disconnected');
	expect(result.pingTimer).to.equal(null);
}

describe('Peer establishment with coalesced invalid frames (issue #1491)', () => {
	const responderKey = crypto.randomBytes(32);
	const peers: Peer[] = [];

	function memoryPeers(tampered: 'initiator' | 'responder'): {
		initiator: Peer;
		responder: Peer;
		responderSide: MemoryTransport;
	} {
		const initiatorSide = new MemoryTransport(
			tampered === 'initiator' ? INITIATOR_INIT_WRITE : null
		);
		const responderSide = new MemoryTransport(
			tampered === 'responder' ? RESPONDER_INIT_WRITE : null
		);
		initiatorSide.remote = responderSide;
		responderSide.remote = initiatorSide;
		const initiator = new Peer({
			localPrivateKey: crypto.randomBytes(32),
			remotePublicKey: getPublicKey(responderKey),
			host: 'memory',
			port: 0,
			createSocket: (): Promise<IDuplexTransport> =>
				Promise.resolve(initiatorSide)
		});
		const responder = new Peer({
			localPrivateKey: responderKey,
			remotePublicKey: Buffer.alloc(33, 0),
			host: 'memory',
			port: 0
		});
		peers.push(initiator, responder);
		return { initiator, responder, responderSide };
	}

	afterEach(() => {
		for (const peer of peers.splice(0)) peer.disconnect();
	});

	it('rejects a custom-transport dial', async () => {
		const { initiator, responder, responderSide } = memoryPeers('responder');
		responder.on('error', () => undefined);
		const counts = watch(initiator);
		const accepting = responder.acceptInbound(responderSide).catch(() => {
			// Only the dialing side is under test.
		});

		const result = await outcome(initiator, initiator.connect(), counts);
		await accepting;
		expectRefused(result);
	});

	it('rejects an inbound acceptance', async () => {
		const { initiator, responder, responderSide } = memoryPeers('initiator');
		initiator.on('error', () => undefined);
		const counts = watch(responder);
		const dialing = initiator.connect().catch(() => {
			// Only the accepting side is under test.
		});

		const result = await outcome(
			responder,
			responder.acceptInbound(responderSide),
			counts
		);
		await dialing;
		expectRefused(result);
	});

	it('leaves a replacement accepted by a drained frame handler alone', async () => {
		const dialerKey = crypto.randomBytes(32);
		const link = (heldWrite: number | null): MemoryTransport[] => {
			const dialSide = new MemoryTransport(null, heldWrite);
			const acceptSide = new MemoryTransport(null);
			dialSide.remote = acceptSide;
			acceptSide.remote = dialSide;
			return [dialSide, acceptSide];
		};
		const dialer = (side: MemoryTransport): Peer => {
			const peer = new Peer({
				localPrivateKey: dialerKey,
				remotePublicKey: getPublicKey(responderKey),
				host: 'memory',
				port: 0,
				createSocket: (): Promise<IDuplexTransport> => Promise.resolve(side)
			});
			peers.push(peer);
			return peer;
		};
		// The first dialer's init is held and goes out with the odd message
		// it sends on connect, so the responder drains that message.
		const [firstDialSide, firstAcceptSide] = link(INITIATOR_INIT_WRITE);
		const [secondDialSide, secondAcceptSide] = link(null);
		const firstDialer = dialer(firstDialSide);
		const secondDialer = dialer(secondDialSide);
		const responder = new Peer({
			localPrivateKey: responderKey,
			remotePublicKey: Buffer.alloc(33, 0),
			host: 'memory',
			port: 0,
			handshakeTimeout: 2_000
		});
		peers.push(responder);
		const settle = (p: Promise<void>): Promise<Error | null> =>
			p.then(
				() => null,
				(err: Error) => err
			);

		firstDialer.once('connect', () =>
			firstDialer.sendMessage(32769, Buffer.alloc(4))
		);
		let replacement: Promise<Error | null> | undefined;
		let redial: Promise<Error | null> | undefined;
		responder.once('message', () => {
			responder.disconnect();
			replacement = settle(responder.acceptInbound(secondAcceptSide));
			redial = settle(secondDialer.connect());
		});

		const accepting = settle(responder.acceptInbound(firstAcceptSide));
		await settle(firstDialer.connect());
		const original = await accepting;
		expect(original?.message).to.equal(
			'Connection closed while draining buffered frames'
		);
		expect(await replacement).to.equal(null);
		expect(await redial).to.equal(null);
		expect(responder.getState()).to.equal('ready');
		expect(secondDialer.getState()).to.equal('ready');
	});

	it('rejects a direct TCP dial', async () => {
		const server = net.createServer((socket) => {
			const write = socket.write.bind(socket) as (
				data: Uint8Array,
				cb?: (err?: Error | null) => void
			) => boolean;
			let writes = 0;
			(socket as { write: unknown }).write = (
				data: Uint8Array,
				cb?: (err?: Error | null) => void
			): boolean =>
				write(
					writes++ === RESPONDER_INIT_WRITE
						? Buffer.concat([data, INVALID_CIPHERTEXT])
						: data,
					cb
				);
			const responder = new Peer({
				localPrivateKey: responderKey,
				remotePublicKey: Buffer.alloc(33, 0),
				host: '127.0.0.1',
				port: 0
			});
			responder.on('error', () => undefined);
			peers.push(responder);
			responder.acceptInbound(socket).catch(() => {
				// Only the dialing side is under test.
			});
		});
		await new Promise<void>((resolve) =>
			server.listen(0, '127.0.0.1', resolve)
		);
		try {
			const initiator = new Peer({
				localPrivateKey: crypto.randomBytes(32),
				remotePublicKey: getPublicKey(responderKey),
				host: '127.0.0.1',
				port: (server.address() as net.AddressInfo).port
			});
			peers.push(initiator);
			const counts = watch(initiator);

			expectRefused(await outcome(initiator, initiator.connect(), counts));
		} finally {
			for (const peer of peers.splice(0)) peer.disconnect();
			await new Promise((resolve) => server.close(resolve));
		}
	});
});
