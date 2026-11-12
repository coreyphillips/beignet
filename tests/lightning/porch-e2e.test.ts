/**
 * Porch end to end (issue #1980): a node that waits at a relay, a visitor
 * that holds only a link, and a real relay between them. A channel is opened
 * and paid across in both directions, and every outbound connection either
 * process makes is recorded, because the point of the exercise is where the
 * node's connections go: to the relay, and nowhere a visitor chose.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import net from 'net';
import { PorchRelay } from '../../src/cli/porch-relay';
import {
	BITCOIN_CHAIN_HASH,
	ChannelState
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeNodeAnnouncementMessage } from '../../src/lightning/gossip/messages';
import {
	ADDRESS_TYPE_IPV4,
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import { signNodeAnnouncement } from '../../src/lightning/gossip/validation';
import { Network } from '../../src/lightning/invoice/types';
import {
	LnCoinType,
	deriveLightningKeysFromMnemonic
} from '../../src/lightning/keys/wallet-keys';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	LightningNodeSeedOptions,
	PaymentStatus
} from '../../src/lightning/node/types';
import type { PeerManager } from '../../src/lightning/transport/peer-manager';
import { parsePeerUri } from '../../src/lightning/transport/peer-uri';
import {
	derivePorchDefaultTag,
	derivePorchHostSecret,
	porchRouteId
} from '../../src/lightning/transport/porch';
import type { IPorchHostStatus } from '../../src/lightning/transport/porch-host';
import { nodeWebSocketVia } from '../../src/lightning/transport/websocket-node-client';
import * as bip39 from 'bip39';

const HOME_MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const VISITOR_MNEMONIC =
	'legal winner thank year wave sausage worth useful legal winner thank yellow';

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(
	cond: () => boolean,
	label: string,
	timeoutMs = 15_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!cond()) {
		if (Date.now() > deadline)
			throw new Error(`Timed out waiting for ${label}`);
		await sleep(20);
	}
}

/** A port nothing is listening on, for a relay whose name includes it. */
async function freePort(): Promise<number> {
	const server = net.createServer();
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const { port } = server.address() as net.AddressInfo;
	await new Promise<void>((resolve) => server.close(() => resolve()));
	return port;
}

/** A TCP server that only records whether anything connected to it. */
async function trapServer(): Promise<{
	port: number;
	contacted: () => boolean;
	close: () => Promise<void>;
}> {
	let contacted = false;
	const server = net.createServer((socket) => {
		contacted = true;
		socket.destroy();
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	return {
		port: (server.address() as net.AddressInfo).port,
		contacted: () => contacted,
		close: () => new Promise<void>((resolve) => server.close(() => resolve()))
	};
}

/**
 * A SOCKS5 proxy that sends every CONNECT to one local port, whatever host
 * was asked for, and records what it was asked for and how.
 */
async function socksTo(targetPort: number): Promise<{
	port: number;
	requested: Array<{ type: number; host: string; port: number }>;
	close: () => Promise<void>;
}> {
	const requested: Array<{ type: number; host: string; port: number }> = [];
	const sockets = new Set<net.Socket>();
	const server = net.createServer((client) => {
		sockets.add(client);
		client.on('error', () => undefined);
		client.on('close', () => sockets.delete(client));
		client.once('data', () => {
			client.write(Buffer.from([0x05, 0x00]));
			client.once('data', (request: Buffer) => {
				const type = request[3];
				let host = '';
				let rest = request.subarray(4);
				if (type === 0x03) {
					host = rest.subarray(1, 1 + rest[0]).toString();
					rest = rest.subarray(1 + rest[0]);
				} else if (type === 0x01) {
					host = Array.from(rest.subarray(0, 4)).join('.');
					rest = rest.subarray(4);
				}
				requested.push({ type, host, port: rest.readUInt16BE(0) });
				const target = net.connect(targetPort, '127.0.0.1');
				sockets.add(target);
				target.on('error', () => client.destroy());
				target.on('close', () => sockets.delete(target));
				target.once('connect', () => {
					const reply = Buffer.alloc(10);
					reply[0] = 0x05;
					reply[3] = 0x01;
					client.write(reply);
					client.pipe(target);
					target.pipe(client);
				});
			});
		});
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	return {
		port: (server.address() as net.AddressInfo).port,
		requested,
		close: (): Promise<void> => {
			for (const socket of sockets) socket.destroy();
			return new Promise<void>((resolve) => server.close(() => resolve()));
		}
	};
}

/**
 * Record the destination of every outbound TCP connection made in this
 * process while it is installed. Accepted sockets never call connect(), so
 * what is recorded is exactly the dials.
 */
function recordDials(): { ports: number[]; restore: () => void } {
	const ports: number[] = [];
	const proto = net.Socket.prototype as unknown as {
		connect: (...args: unknown[]) => net.Socket;
	};
	const original = proto.connect;
	proto.connect = function (this: net.Socket, ...args: unknown[]): net.Socket {
		// net.connect() normalises its arguments into one array before it
		// calls this; a direct socket.connect(port, host) does not.
		const first = Array.isArray(args[0]) ? args[0][0] : args[0];
		const port =
			typeof first === 'object' && first !== null
				? Number((first as { port?: unknown }).port)
				: Number(first);
		ports.push(port);
		return original.apply(this, args);
	};
	return {
		ports,
		restore: (): void => {
			proto.connect = original;
		}
	};
}

function makeNode(
	mnemonic: string,
	options: Partial<LightningNodeSeedOptions> = {}
): LightningNode {
	// The channel below is opened with the manually driven v1 funding flow,
	// so dual funding is left out of the features, as in the WebSocket
	// transport's own channel test.
	const features = LightningNode.defaultFeatures();
	features.clearBit(28);
	features.clearBit(29);
	const node = LightningNode.fromMnemonic(mnemonic, {
		network: Network.REGTEST,
		enableNetworking: true,
		localFeatures: features,
		...options
	});
	node.on('node:error', () => undefined);
	return node;
}

/** Publish a synthetic direct channel into a node's graph for routing. */
function buildDirectGraph(
	payer: LightningNode,
	payee: LightningNode,
	channelId: Buffer
): void {
	const payerPub = Buffer.from(payer.getNodeId(), 'hex');
	const payeePub = Buffer.from(payee.getNodeId(), 'hex');
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });
	const payerIsNode1 = Buffer.compare(payerPub, payeePub) < 0;
	const channel: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: payerIsNode1 ? payerPub : payeePub,
		nodeId2: payerIsNode1 ? payeePub : payerPub,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};
	payer.getGraph().addChannelAnnouncement(channel);
	const update: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
	payer.getGraph().applyChannelUpdate(update);
	payer.getGraph().applyChannelUpdate({ ...update, channelFlags: 1 });
	payer.registerChannelScid(channelId, scid);
}

/** A node_announcement, signed by its node, that names one loopback port. */
function announcement(privateKey: Buffer, port: number): Buffer {
	const payload = encodeNodeAnnouncementMessage({
		signature: Buffer.alloc(64),
		features: Buffer.alloc(0),
		timestamp: Math.floor(Date.now() / 1000),
		nodeId: getPublicKey(privateKey),
		rgbColor: Buffer.from([0, 0, 0]),
		alias: Buffer.alloc(32),
		addresses: [{ type: ADDRESS_TYPE_IPV4, host: '127.0.0.1', port }]
	});
	signNodeAnnouncement(payload, privateKey).copy(payload, 0);
	return payload;
}

async function pay(
	payer: LightningNode,
	payee: LightningNode,
	amountMsat: bigint
): Promise<void> {
	const invoice = payee.createInvoice({ amountMsat, description: 'porch' });
	const payment = payer.sendPayment(invoice.bolt11);
	await waitFor(
		() =>
			payer.getPayment(payment.paymentHash)?.status === PaymentStatus.COMPLETED,
		`a payment of ${amountMsat} msat`
	);
}

describe('Porch end to end', function () {
	this.timeout(60_000);

	let relay: PorchRelay | undefined;
	const nodes: LightningNode[] = [];
	const closers: Array<() => Promise<void>> = [];
	let dials: ReturnType<typeof recordDials> | undefined;

	afterEach(async function () {
		dials?.restore();
		dials = undefined;
		for (const node of nodes.splice(0)) node.destroy();
		await relay?.close();
		relay = undefined;
		for (const close of closers.splice(0)) await close();
	});

	it('opens a channel and pays both ways through a relay, and the node dials nothing else', async function () {
		const relayPort = await freePort();
		const relayName = `127.0.0.1:${relayPort}`;
		relay = new PorchRelay({ authorities: [relayName] });
		await relay.listen(relayPort, '127.0.0.1');

		dials = recordDials();
		const home = makeNode(HOME_MNEMONIC, {
			porch: { relays: [`ws://${relayName}`] }
		});
		const visitor = makeNode(VISITOR_MNEMONIC);
		nodes.push(home, visitor);

		// The node is reachable once a standby is registered, and says so.
		const statuses: IPorchHostStatus[] = [];
		home.on('porch:status', (status) => statuses.push(status));
		expect(home.getPorchStatus()).to.deep.equal([
			{ relay: `ws://${relayName}`, state: 'stopped', idle: 0, circuits: 0 }
		]);
		home.listenPorch();
		await waitFor(
			() => home.getPorchStatus()[0].state === 'ready',
			'the node registering'
		);
		expect(statuses.map((status) => status.state)).to.include('ready');

		// The link: the seed's own host key and default tag, and nothing that
		// says where the node is.
		const seed = bip39.mnemonicToSeedSync(HOME_MNEMONIC);
		const tag = derivePorchDefaultTag(seed);
		const routeId = porchRouteId(
			getPublicKey(derivePorchHostSecret(seed)),
			tag
		);
		expect(home.getPorchLinks()).to.deep.equal([
			{
				relay: `ws://${relayName}`,
				tag: tag.toString('hex'),
				uri: `${home.getNodeId()}@ws://${relayName}/v1/p/${routeId}`
			}
		]);

		// All the visitor has is that string.
		const link = parsePeerUri(home.getPorchLinks()[0].uri);
		await visitor.connectPeer(
			link.pubkey,
			link.host,
			link.port,
			link.transport
		);
		await waitFor(() => home.listPeers().length === 1, 'the visitor arriving');
		const [peer] = home.listPeers();
		expect(peer.pubkey).to.equal(visitor.getNodeId());
		expect(peer.state).to.equal('ready');
		// What the node knows of where the visitor is: the relay's name.
		expect(peer.host).to.equal(`porch:${relayName}`);
		expect(peer.port).to.equal(0);
		expect(peer.transport).to.equal('ws');
		expect(peer.porch).to.deep.equal({
			relay: relayName,
			tag: tag.toString('hex')
		});
		expect(home.getPorchStatus()[0].circuits).to.equal(1);

		// A channel, opened by the visitor.
		const accepted = new Promise<void>((resolve) => {
			visitor.getChannelManager().once('channel:accepted', () => resolve());
		});
		const channel = visitor.openChannel(home.getNodeId(), 1_000_000n);
		await accepted;
		const channelId = visitor.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		);
		expect(channelId).to.not.equal(null);
		const homeChannel = (): ReturnType<
			ReturnType<LightningNode['getChannelManager']>['listChannels']
		>[number] => home.getChannelManager().listChannels()[0];
		await waitFor(
			() =>
				home.getChannelManager().listChannels().length === 1 &&
				homeChannel().getChannelId() !== null,
			'the node seeing the funding'
		);
		await waitFor(
			() =>
				visitor.getChannel(channelId!)?.state ===
				ChannelState.AWAITING_FUNDING_CONFIRMED,
			'the visitor seeing the funding signed'
		);
		visitor.handleFundingConfirmed(channelId!);
		home.handleFundingConfirmed(homeChannel().getChannelId()!);
		await waitFor(
			() =>
				visitor.getChannel(channelId!)?.state === ChannelState.NORMAL &&
				homeChannel().getState() === 'NORMAL',
			'the channel becoming usable'
		);

		// Paid in both directions, across the relay.
		buildDirectGraph(visitor, home, channelId!);
		buildDirectGraph(home, visitor, channelId!);
		const homeBalance = (): bigint => home.listChannels()[0].localBalanceMsat;
		expect(homeBalance()).to.equal(0n);
		await pay(visitor, home, 200_000_000n);
		// The payer has its preimage a round trip before the payee's side of
		// the channel is settled, and the payee cannot spend it until then.
		await waitFor(
			() => homeBalance() === 200_000_000n,
			'the first payment settling'
		);
		await pay(home, visitor, 50_000_000n);
		await waitFor(
			() => homeBalance() === 150_000_000n,
			'the second payment settling'
		);

		// The relay carried it and holds nothing but the connections.
		expect(relay.stats()).to.include({ hosts: 1, circuits: 1 });

		// The visitor now names an address of its own choosing, as a channel
		// peer may, and drops. A node that dialed it would show the visitor
		// where it is.
		const trap = await trapServer();
		closers.push(trap.close);
		const internal = home as unknown as {
			handleNodeAnnouncement(payload: Buffer): void;
			peerManager: PeerManager;
		};
		const visitorKey = deriveLightningKeysFromMnemonic(
			VISITOR_MNEMONIC,
			undefined,
			LnCoinType.REGTEST
		).nodePrivateKey;
		expect(getPublicKey(visitorKey).toString('hex')).to.equal(
			visitor.getNodeId()
		);
		internal.handleNodeAnnouncement(announcement(visitorKey, trap.port));
		expect(
			internal.peerManager.getAnnouncedAddresses(visitor.getNodeId())
		).to.deep.equal([{ host: '127.0.0.1', port: trap.port }]);
		expect(internal.peerManager.canDialLearnedAddress('127.0.0.1')).to.equal(
			false
		);
		// Nothing of the visitor's was kept to dial later.
		expect(internal.peerManager.getPeerAddress(visitor.getNodeId())).to.equal(
			undefined
		);

		visitor.destroy();
		await waitFor(() => home.listPeers().length === 0, 'the visitor leaving');
		// The first reconnect round fires about a second after the drop.
		await sleep(3_000);
		expect(trap.contacted()).to.equal(false);
		expect(home.listPeers()).to.have.length(0);

		// Every connection made by either node went to the relay.
		expect(dials.ports.length).to.be.greaterThan(2);
		expect([...new Set(dials.ports)]).to.deep.equal([relayPort]);
		// And the node is still waiting there for the next visitor.
		expect(home.getPorchStatus()[0]).to.include({
			state: 'ready',
			circuits: 0
		});
	});

	it("reaches the relay only through the proxy under via 'tor', by name", async function () {
		relay = new PorchRelay({ authorities: ['relay.test'] });
		await relay.listen(0, '127.0.0.1');
		const relayPort = (relay.address() as net.AddressInfo).port;
		const socks = await socksTo(relayPort);
		closers.push(socks.close);

		dials = recordDials();
		const home = makeNode(HOME_MNEMONIC, {
			socks5Proxy: { host: '127.0.0.1', port: socks.port },
			// Peers at public hosts would be dialed directly under this scope:
			// the relay is not, because of `via`.
			socks5ProxyScope: 'onion',
			porch: { relays: ['ws://relay.test'], via: 'tor' }
		});
		// The visitor is somewhere else, with a resolver of its own.
		let visitorDials = 0;
		const visitor = makeNode(VISITOR_MNEMONIC, {
			webSocketImpl: nodeWebSocketVia((): net.Socket => {
				visitorDials++;
				return net.connect(relayPort, '127.0.0.1');
			})
		});
		nodes.push(home, visitor);

		home.listenPorch();
		await waitFor(
			() => home.getPorchStatus()[0].idle === 2,
			'the node registering through the proxy'
		);
		const link = parsePeerUri(home.getPorchLinks()[0].uri);
		expect(link.host).to.equal('relay.test');
		await visitor.connectPeer(
			link.pubkey,
			link.host,
			link.port,
			link.transport
		);
		await waitFor(
			() => home.listPeers()[0]?.state === 'ready',
			'the visitor arriving'
		);
		expect(home.listPeers()[0].host).to.equal('porch:relay.test');
		await waitFor(
			() => home.getPorchStatus()[0].idle === 2,
			'the standby being replaced'
		);

		// The proxy was asked for the relay by name each time, so nothing on
		// the node's side resolved it or could have dialed it.
		expect(socks.requested.length).to.be.at.least(3);
		for (const request of socks.requested) {
			expect(request).to.deep.equal({
				type: 0x03,
				host: 'relay.test',
				port: 80
			});
		}
		// Every dial is accounted for: the node's to the proxy, the proxy's
		// own to the relay, and the visitor's. None is the node's to the relay.
		const toProxy = dials.ports.filter((port) => port === socks.port).length;
		const toRelay = dials.ports.filter((port) => port === relayPort).length;
		expect(toProxy).to.equal(socks.requested.length);
		expect(toRelay).to.equal(socks.requested.length + visitorDials);
		expect(dials.ports).to.have.length(toProxy + toRelay);
		expect(visitorDials).to.equal(1);
	});
});
