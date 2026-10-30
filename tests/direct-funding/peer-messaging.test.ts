import { expect } from 'chai';
import { EventEmitter } from 'events';
import { randomBytes } from 'crypto';
import {
	NodePeerMessaging,
	INodePeerMessagingOptions
} from '../../src/direct-funding/peer-messaging';
import { Peer } from '../../src/lightning/transport/peer';
import { IDuplexTransport } from '../../src/lightning/transport/duplex-transport';
import { Network } from '../../src/lightning/invoice/types';
import { chainHashForNetwork } from '../../src/lightning/direct-funding/types';
import { ecc } from '../../src/utils/ecc';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	decodeCustomMessage,
	encodeCustomMessage
} from '../../src/lightning/message/custom';

/** Carries real encrypted BOLT 8 packets without requiring a listening port. */
class MemorySocket extends EventEmitter implements IDuplexTransport {
	remote?: MemorySocket;
	readonly writableLength = 0;
	destroyed = false;
	readonly sent: Buffer[] = [];

	write(
		data: Uint8Array | string,
		callback?: (err?: Error | null) => void
	): boolean {
		if (this.destroyed) throw new Error('socket is closed');
		const copy = Buffer.from(data);
		this.sent.push(copy);
		queueMicrotask(() => callback?.());
		setImmediate(() => {
			if (!this.remote?.destroyed) this.remote?.emit('data', copy);
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

function pubkey(key: Buffer): string {
	return Buffer.from(ecc.pointFromScalar(key)!).toString('hex');
}

async function waitFor(condition: () => boolean): Promise<void> {
	const end = Date.now() + 2_000;
	while (!condition()) {
		if (Date.now() >= end) throw new Error('condition did not become true');
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
}

async function refuses(
	promise: Promise<unknown>,
	message?: string
): Promise<void> {
	let error: unknown;
	try {
		await promise;
	} catch (err) {
		error = err;
	}
	expect(error).to.be.instanceOf(Error);
	if (message) expect((error as Error).message).to.include(message);
}

describe('Standalone Node direct-funding peer messaging', () => {
	const clients: NodePeerMessaging[] = [];
	const remotes: Peer[] = [];

	function harness(
		options: Partial<INodePeerMessagingOptions> = {},
		remoteNetwork = Network.REGTEST
	): {
		client: NodePeerMessaging;
		remoteId: string;
		remotePeers: Peer[];
		packets: MemorySocket[];
	} {
		const remoteKey = randomBytes(32);
		const remotePeers: Peer[] = [];
		const packets: MemorySocket[] = [];
		const client = new NodePeerMessaging({
			network: Network.REGTEST,
			connectionTimeoutMs: 1_000,
			reconnectDelayMs: 5,
			createSocket: async (): Promise<IDuplexTransport> => {
				const outbound = new MemorySocket();
				const inbound = new MemorySocket();
				outbound.remote = inbound;
				inbound.remote = outbound;
				const peer = new Peer({
					localPrivateKey: remoteKey,
					remotePublicKey: Buffer.alloc(33),
					host: 'memory',
					port: 9735,
					networks: [chainHashForNetwork(remoteNetwork)],
					handshakeTimeout: 1_000
				});
				remotePeers.push(peer);
				remotes.push(peer);
				packets.push(outbound);
				peer.on('error', () => undefined);
				void peer.acceptInbound(inbound).catch(() => undefined);
				return outbound;
			},
			...options
		});
		clients.push(client);
		return { client, remoteId: pubkey(remoteKey), remotePeers, packets };
	}

	afterEach(() => {
		for (const client of clients.splice(0)) client.close();
		for (const remote of remotes.splice(0)) remote.disconnect();
	});

	it('authenticates and exchanges custom messages over real Noise encryption without channels', async () => {
		const { client, remoteId, remotePeers, packets } = harness();
		let connected = '';
		client.onPeerConnect((id) => {
			connected = id;
		});
		await client.connectPeer(remoteId, 'memory', 9735);
		expect(client.isPeerConnected(remoteId.toUpperCase())).to.equal(true);
		expect(connected).to.equal(remoteId);
		expect(remotePeers[0].remotePublicKey.toString('hex')).to.equal(
			client.nodeIdHex()
		);
		const received: string[] = [];
		remotePeers[0].on('message', (type: number, payload: Buffer) => {
			expect(type).to.equal(BEIGNET_CUSTOM_MESSAGE_TYPE);
			const frame = decodeCustomMessage(payload);
			expect(frame.subtype).to.equal(16);
			received.push(frame.payload.toString());
			remotePeers[0].sendMessage(
				type,
				encodeCustomMessage(17, Buffer.from('acknowledged'))
			);
		});
		let reply = '';
		const detach = client.onCustomMessage((message) => {
			expect(message.peerPubkey).to.equal(remoteId);
			expect(message.version).to.equal(1);
			reply = message.payload.toString();
		});
		client.sendCustomMessage(
			remoteId,
			16,
			Buffer.from('private protocol payload')
		);
		await waitFor(() => reply !== '');
		expect(reply).to.equal('acknowledged');
		expect(received).to.deep.equal(['private protocol payload']);
		expect(
			packets[0].sent.some((packet) =>
				packet.includes(Buffer.from('private protocol payload'))
			)
		).to.equal(false);
		detach();
	});

	it('shares concurrent connection attempts and normalizes peer identity case', async () => {
		const { client, remoteId, remotePeers } = harness();
		await Promise.all([
			client.connectPeer(remoteId, 'memory', 9735),
			client.connectPeer(remoteId.toUpperCase(), 'memory', 9735)
		]);
		expect(remotePeers).to.have.length(1);
	});

	it('isolates throwing and asynchronous subscribers and gives each its own payload', async () => {
		const errors: string[] = [];
		const { client, remoteId, remotePeers } = harness({
			onError: (error) => {
				errors.push(error.message);
			}
		});
		client.onPeerConnect(() => {
			throw new Error('connect observer failed');
		});
		client.onCustomMessage((message) => {
			message.payload.fill(0);
			throw new Error('message observer failed');
		});
		// An async callback is legal JavaScript even though the public callback is void.
		// eslint-disable-next-line @typescript-eslint/no-misused-promises
		client.onCustomMessage(async () => {
			throw new Error('async observer failed');
		});
		let received = '';
		client.onCustomMessage((message) => {
			received = message.payload.toString();
		});
		await client.connectPeer(remoteId, 'memory', 9735);
		remotePeers[0].sendMessage(
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			encodeCustomMessage(21, Buffer.from('receipt'))
		);
		await waitFor(() => errors.includes('async observer failed'));
		expect(received).to.equal('receipt');
		expect(errors).to.include('connect observer failed');
		expect(errors).to.include('message observer failed');
		expect(client.isPeerConnected(remoteId)).to.equal(true);
	});

	it('drops malformed, unknown-version and unrelated custom messages without losing the connection', async () => {
		const errors: string[] = [];
		const { client, remoteId, remotePeers } = harness({
			onError: (error) => {
				errors.push(error.message);
			}
		});
		let received = 0;
		client.onCustomMessage(() => {
			received++;
		});
		await client.connectPeer(remoteId, 'memory', 9735);
		const remote = remotePeers[0];
		remote.sendMessage(BEIGNET_CUSTOM_MESSAGE_TYPE, Buffer.from([1]));
		remote.sendMessage(
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			encodeCustomMessage(16, Buffer.from([1]), 2)
		);
		remote.sendMessage(
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			encodeCustomMessage(80, Buffer.from([1]))
		);
		remote.sendMessage(
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			encodeCustomMessage(22, Buffer.from([1]))
		);
		await waitFor(() => received === 1);
		expect(errors).to.include('custom message too short');
		expect(client.isPeerConnected(remoteId)).to.equal(true);
		expect(() =>
			client.sendCustomMessage(remoteId, 16, Buffer.alloc(65_535))
		).to.throw('maximum');
		expect(() =>
			client.sendCustomMessage(remoteId, 80, Buffer.alloc(0))
		).to.throw('unsupported');
	});

	it('rejects a different advertised chain during init', async () => {
		const { client, remoteId } = harness({}, Network.MAINNET);
		await refuses(client.connectPeer(remoteId, 'memory', 9735));
		expect(client.isPeerConnected(remoteId)).to.equal(false);
	});

	it('rejects a peer whose Noise identity differs from the requested node', async () => {
		const { client } = harness({ connectionTimeoutMs: 100 });
		const wrongId = pubkey(randomBytes(32));
		await refuses(client.connectPeer(wrongId, 'memory', 9735));
		expect(client.isPeerConnected(wrongId)).to.equal(false);
	});

	it('enforces a hard total deadline and destroys a socket returned after timeout', async () => {
		let deliver: ((socket: IDuplexTransport) => void) | undefined;
		const { client, remoteId } = harness({
			connectionTimeoutMs: 20,
			createSocket: () =>
				new Promise((resolve) => {
					deliver = resolve;
				})
		});
		await refuses(client.connectPeer(remoteId, 'memory', 9735));
		const late = new MemorySocket();
		deliver!(late);
		await waitFor(() => late.destroyed);
		expect(client.isPeerConnected(remoteId)).to.equal(false);
	});

	it('lets a short waiter time out without cancelling a shared longer dial', async () => {
		let release: (() => void) | undefined;
		const setup = harness();
		// Reuse this harness's factory for a second client, with an intentional delay.
		const factory = (
			setup.client as unknown as { options: INodePeerMessagingOptions }
		).options.createSocket;
		setup.client.close();
		const delayed = new NodePeerMessaging({
			network: Network.REGTEST,
			connectionTimeoutMs: 1_000,
			createSocket: async (host, port): Promise<IDuplexTransport> => {
				await new Promise<void>((resolve) => {
					release = resolve;
				});
				return factory!(host, port);
			}
		});
		clients.push(delayed);
		const long = delayed.connectPeer(setup.remoteId, 'memory', 9735);
		await refuses(
			delayed.connectPeer(setup.remoteId, 'memory', 9735, 10),
			'timed out'
		);
		release!();
		await long;
		expect(delayed.isPeerConnected(setup.remoteId)).to.equal(true);
		expect(setup.remotePeers).to.have.length(1);
	});

	it('reconnects an established connection, but a warm-only connection can be left closed', async () => {
		const { client, remoteId, remotePeers } = harness();
		await client.connectPeer(remoteId, 'memory', 9735, undefined, {
			reconnect: false
		});
		remotePeers[0].disconnect();
		await waitFor(() => !client.isPeerConnected(remoteId));
		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(remotePeers).to.have.length(1);
		await client.connectPeer(remoteId, 'memory', 9735, undefined, {
			reconnect: false
		});
		client.keepReconnecting(remoteId.toUpperCase());
		remotePeers[1].disconnect();
		await waitFor(
			() => remotePeers.length === 3 && client.isPeerConnected(remoteId)
		);
	});

	it('bounds peers and cancels pending work when closed', async () => {
		let deliver: ((socket: IDuplexTransport) => void) | undefined;
		const { client, remoteId } = harness({
			maxPeers: 1,
			createSocket: () =>
				new Promise((resolve) => {
					deliver = resolve;
				})
		});
		const pending = client.connectPeer(remoteId, 'memory', 9735);
		await waitFor(() => deliver !== undefined);
		await refuses(
			client.connectPeer(pubkey(randomBytes(32)), 'memory', 9735),
			'limit reached'
		);
		client.close();
		await refuses(pending, 'aborted');
		const late = new MemorySocket();
		deliver!(late);
		await waitFor(() => late.destroyed);
		await refuses(client.connectPeer(remoteId, 'memory', 9735), 'closed');
		expect(() =>
			client.sendCustomMessage(remoteId, 16, Buffer.alloc(0))
		).to.throw('closed');
	});

	it('releases individual peer slots and can cancel a dial before it opens a socket', async () => {
		const { client, remoteId, remotePeers } = harness({ maxPeers: 1 });
		const cancelled = client.connectPeer(remoteId, 'memory', 9735);
		client.disconnectPeer(remoteId);
		await refuses(cancelled, 'cancelled');
		expect(remotePeers).to.have.length(0);
		await client.connectPeer(remoteId, 'memory', 9735);
		client.disconnectPeer(remoteId.toUpperCase());
		expect(client.isPeerConnected(remoteId)).to.equal(false);
		await client.connectPeer(remoteId, 'memory', 9735);
		expect(remotePeers).to.have.length(2);
	});

	it('copies supplied identity material and rejects invalid configuration', async () => {
		const key = randomBytes(32);
		const expected = pubkey(key);
		const { client } = harness({ identityKey: key });
		key.fill(0);
		expect(client.nodeIdHex()).to.equal(expected);
		expect(
			() =>
				new NodePeerMessaging({
					network: Network.REGTEST,
					identityKey: Buffer.alloc(32)
				})
		).to.throw('private key');
		await refuses(
			client.connectPeer(client.nodeIdHex(), 'memory', 9735),
			'itself'
		);
		await refuses(client.connectPeer('not-a-node', 'memory', 9735), 'identity');
		await refuses(
			client.connectPeer(pubkey(randomBytes(32)), 'memory', 0),
			'address'
		);
	});
});
