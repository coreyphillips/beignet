import net from 'net';
import { once } from 'events';
import { SocksClient } from 'socks';
const sinon = require('sinon');
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { Feature } from '../../src/lightning/features/flags';
import { deriveLightningKeysFromMnemonic } from '../../src/lightning/keys/wallet-keys';
import { buildGraph } from './helpers/loopback-nodes';
/** Real QUIC and BOLT 8, with explicit local addresses and no public services. */
import { expect } from 'chai';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { createNodeIrohEndpoint } from '../../src/lightning/transport/iroh-node';
import {
	IIrohEndpoint,
	IrohEndpointFactory
} from '../../src/lightning/transport/iroh';
import { parsePeerUri } from '../../src/lightning/transport/peer-uri';

async function until(check: () => boolean, timeout = 8_000): Promise<void> {
	const start = Date.now();
	while (!check()) {
		if (Date.now() - start > timeout)
			throw new Error('Iroh condition timed out');
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

describe('Iroh native transport', function () {
	this.timeout(20_000);
	const endpoints: IIrohEndpoint[] = [];
	const byId = new Map<string, IIrohEndpoint>();
	const managers: PeerManager[] = [];
	const factory: IrohEndpointFactory = async (options) => {
		const endpoint = await createNodeIrohEndpoint({
			...options,
			discovery: false,
			relays: []
		});
		endpoints.push(endpoint);
		await until(() => !!endpoint.address().directAddresses?.length);
		byId.set(endpoint.address().endpointId, endpoint);
		return {
			address: () => endpoint.address(),
			listen: (accept, error) => endpoint.listen(accept, error),
			stopListening: () => endpoint.stopListening(),
			close: () => endpoint.close(),
			connect: (address, timeout) =>
				endpoint.connect(
					{
						...address,
						directAddresses: byId.get(address.endpointId)?.address()
							.directAddresses
					},
					timeout
				)
		};
	};
	function manager(n: number, autoReconnect = false): PeerManager {
		const pm = new PeerManager({
			localPrivateKey: Buffer.alloc(32, n),
			autoReconnect,
			maxReconnectDelay: 500,
			iroh: { secretKey: Buffer.alloc(32, n + 10), factory }
		});
		managers.push(pm);
		return pm;
	}
	before(function () {
		try {
			require('@number0/iroh/index.js');
		} catch {
			this.skip();
		}
	});
	afterEach(async () => {
		for (const pm of managers.splice(0)) pm.destroy();
		await Promise.all(endpoints.splice(0).map((endpoint) => endpoint.close()));
		byId.clear();
	});

	it('authenticates node keys over QUIC and reports direct diagnostics on both ends', async () => {
		const receiver = manager(1);
		const sender = manager(2);
		await receiver.listenIroh();
		const address = parsePeerUri(receiver.getIrohConnectionString()!);
		await sender.connectPeer(
			address.pubkey,
			address.host,
			address.port,
			address.transport
		);
		await until(() => receiver.listPeers().length === 1);
		expect(sender.listPeers()[0].transport).to.equal('iroh');
		expect(receiver.listPeers()[0].transport).to.equal('iroh');
		expect(sender.listPeers()[0].iroh?.path).to.equal('direct');
		expect(sender.listPeers()[0].iroh?.rttMs).to.be.a('number');
		expect(receiver.listPeers()[0].pubkey).to.equal(
			getPublicKey(Buffer.alloc(32, 2)).toString('hex')
		);
		expect(sender.getPeerAddress(address.pubkey)?.transport).to.deep.equal(
			address.transport
		);
	});

	it('rejects a mismatched Lightning node key even when the Iroh id is correct', async () => {
		const receiver = manager(1);
		const sender = manager(2);
		await receiver.listenIroh();
		const address = parsePeerUri(receiver.getIrohConnectionString()!);
		const wrongKey = getPublicKey(Buffer.alloc(32, 3)).toString('hex');
		const error = await sender
			.connectPeer(wrongKey, address.host, 0, address.transport)
			.then(
				() => null,
				(err: Error) => err
			);
		expect(error).to.be.instanceOf(Error);
		expect(sender.listPeers()).to.have.length(0);
		expect(receiver.listPeers()).to.have.length(0);
	});

	it('redials Iroh automatically and restores the endpoint id after restart', async () => {
		const receiver = manager(1);
		const sender = manager(2, true);
		await receiver.listenIroh();
		const address = parsePeerUri(receiver.getIrohConnectionString()!);
		await sender.connectPeer(
			address.pubkey,
			address.host,
			0,
			address.transport
		);
		await until(() => receiver.listPeers().length === 1);
		receiver.destroy();
		await endpoints[0].close();
		await until(() => sender.listPeers().length === 0);
		const restored = manager(1);
		await restored.listenIroh();
		expect(parsePeerUri(restored.getIrohConnectionString()!).host).to.equal(
			address.host
		);
		await until(
			() => sender.listPeers().length === 1 && restored.listPeers().length === 1
		);
		expect(sender.listPeers()[0].transport).to.equal('iroh');
	});

	it('opens a channel and pays before and after a reconnect over real QUIC', async () => {
		const mnemonics = [
			'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'
		];
		const nodes = mnemonics.map((mnemonic, index) => {
			const features = LightningNode.defaultFeatures();
			features.clearBit(Feature.DUAL_FUND + 1);
			return new LightningNode({
				...deriveLightningKeysFromMnemonic(mnemonic),
				network: Network.REGTEST,
				enableNetworking: true,
				localFeatures: features,
				iroh: { factory, secretKey: Buffer.alloc(32, index + 30) }
			});
		});
		const [alice, bob] = nodes;
		try {
			await bob.listenIroh();
			const address = parsePeerUri(bob.getIrohConnectionString()!);
			await alice.connectPeer(
				address.pubkey,
				address.host,
				0,
				address.transport
			);
			await until(() => bob.listPeers().length === 1);
			const accepted = new Promise<void>((resolve) =>
				alice.getChannelManager().once('channel:accepted', () => resolve())
			);
			const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
			await accepted;
			// Synthetic funding keeps this transport test independent of a Bitcoin daemon.
			const channelId = alice.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			)!;
			await until(
				() =>
					alice.getChannel(channelId)?.state ===
						ChannelState.AWAITING_FUNDING_CONFIRMED &&
					bob.getChannelManager().listChannels()[0]?.getChannelId() !== null
			);
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			await until(
				() =>
					alice.getChannel(channelId)?.state === ChannelState.NORMAL &&
					bob.getChannel(channelId)?.state === ChannelState.NORMAL
			);
			alice.handleNewBlock(795_000);
			bob.handleNewBlock(795_000);
			buildGraph(alice, bob, [channelId]);
			for (let n = 0; n < 2; n++) {
				const invoice = bob.createInvoice({
					amountMsat: 1_000_000n,
					description: 'Iroh transport payment'
				});
				const payment = alice.sendPayment(invoice.bolt11);
				await until(() => payment.status === PaymentStatus.COMPLETED);
				if (n === 0) {
					alice.disconnectPeer(bob.getNodeId());
					await until(() => bob.listPeers().length === 0);
					await alice.connectPeer(
						address.pubkey,
						address.host,
						0,
						address.transport
					);
					await until(
						() =>
							alice.getChannel(channelId)?.state === ChannelState.NORMAL &&
							bob.getChannel(channelId)?.state === ChannelState.NORMAL
					);
				}
			}
			expect(alice.listPeers()[0].iroh?.path).to.equal('direct');
		} finally {
			for (const node of nodes) node.destroy();
		}
	});

	it('authenticates over the configured Tor fallback without racing two Noise sessions', async () => {
		const receiver = manager(1);
		await receiver.listen(0, '127.0.0.1');
		const port = (
			receiver as unknown as { server: net.Server }
		).server.address() as net.AddressInfo;
		const onion = 'a'.repeat(56) + '.onion';
		let dials = 0;
		const stub = sinon
			.stub(SocksClient, 'createConnection')
			.callsFake(
				async (options: {
					destination: { host: string; port: number };
				}): Promise<{ socket: net.Socket }> => {
					dials++;
					expect(options.destination).to.deep.equal({
						host: onion,
						port: 9735
					});
					const socket = net.connect(port.port, '127.0.0.1');
					await once(socket, 'connect');
					return { socket };
				}
			);
		const sender = new PeerManager({
			localPrivateKey: Buffer.alloc(32, 2),
			iroh: {
				secretKey: Buffer.alloc(32, 12),
				factory: async (): Promise<IIrohEndpoint> => {
					throw new Error('Iroh unavailable');
				}
			}
		});
		managers.push(sender);
		const peer = getPublicKey(Buffer.alloc(32, 1)).toString('hex');
		const options = {
			type: 'iroh' as const,
			endpointId: 'ab'.repeat(32),
			fallbackOnion: { host: onion, port: 9735 }
		};
		try {
			await sender.connectPeer(peer, options.endpointId, 0, options);
			await until(() => receiver.listPeers().length === 1);
			expect(sender.listPeers()[0].transport).to.equal('tcp');
			expect(sender.getPeerAddress(peer)?.transport).to.deep.equal(options);
			expect(dials).to.equal(1);
		} finally {
			stub.restore();
		}
	});

	it('stops accepting and hides the connection string when listening stops', async () => {
		const receiver = manager(1);
		await receiver.listenIroh();
		expect(receiver.isListening()).to.equal(true);
		receiver.stopListening();
		expect(receiver.getIrohConnectionString()).to.equal(undefined);
		expect(receiver.isListening()).to.equal(false);
		await receiver.listenIroh();
		expect(receiver.getIrohConnectionString()).to.be.a('string');
		receiver.freezeConnections();
		expect(receiver.getIrohConnectionString()).to.equal(undefined);
		expect(receiver.isListening()).to.equal(false);
	});
});
