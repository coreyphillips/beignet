/**
 * Connect by node id alone: connectPeer(pubkey) without host/port resolves
 * the dial address from the gossip graph's node_announcement addresses
 * (tried in announced order, Tor skipped unless a socks5Proxy is configured),
 * falling back to DNS bootstrap when the graph has none, and reports every
 * attempt in the error when nothing connects.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	INodeAddress,
	ADDRESS_TYPE_IPV4,
	ADDRESS_TYPE_TORV3,
	ADDRESS_TYPE_DNS
} from '../../src/lightning/gossip/types';
import { nodeAddressToHostPort } from '../../src/lightning/gossip/messages';
import { IPeerAddress } from '../../src/lightning/bootstrap';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`connect-id-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(extra?: Partial<INodeConfig>): LightningNode {
	const seed = makeSeed(1);
	const node = new LightningNode({
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(101),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		enableNetworking: true,
		...extra
	});
	node.on('node:error', () => {});
	return node;
}

// A remote node id we resolve addresses for.
const TARGET_PUBKEY = getPublicKey(makeSeed(42)).toString('hex');
// 35-byte Tor v3 descriptor payload as stored in the graph (hex).
const TORV3_HEX = Buffer.concat([
	crypto.createHash('sha256').update('onion-pubkey').digest(), // 32
	Buffer.from([0xab, 0xcd]), // checksum (unchecked when re-encoding)
	Buffer.from([0x03]) // version
]).toString('hex');

/** Record every pm.connectPeer dial; succeed only for hosts in `goodHosts`. */
function stubDialer(
	node: LightningNode,
	goodHosts: string[]
): Array<{ host: string; port: number }> {
	const dials: Array<{ host: string; port: number }> = [];
	const pm = node.getPeerManager()!;
	pm.connectPeer = async (
		_pubkey: string,
		host: string,
		port: number
	): Promise<void> => {
		dials.push({ host, port });
		if (!goodHosts.includes(host)) {
			throw new Error(`dial refused: ${host}`);
		}
	};
	return dials;
}

function injectAnnouncement(
	node: LightningNode,
	addresses: INodeAddress[]
): void {
	const graph = node.getGraph() as unknown as {
		_nodes: Map<string, unknown>;
	};
	graph._nodes.set(TARGET_PUBKEY, {
		nodeId: Buffer.from(TARGET_PUBKEY, 'hex'),
		announcement: { addresses },
		channels: new Set()
	});
}

function stubBootstrap(node: LightningNode, peers: IPeerAddress[]): void {
	node.bootstrapPeers = async (): Promise<IPeerAddress[]> => peers;
}

describe('Connect peer by node id', function () {
	it('still connects with explicit host and port', async function () {
		const node = makeNode();
		const dials = stubDialer(node, ['9.9.9.9']);
		await node.connectPeer(TARGET_PUBKEY, '9.9.9.9', 9735);
		expect(dials).to.deep.equal([{ host: '9.9.9.9', port: 9735 }]);
		node.destroy();
	});

	it('rejects host without port (and vice versa)', async function () {
		const node = makeNode();
		stubDialer(node, []);
		try {
			await node.connectPeer(TARGET_PUBKEY, '9.9.9.9');
			expect.fail('should have thrown');
		} catch (err) {
			expect((err as Error).message).to.include('provided together');
		}
		node.destroy();
	});

	it('resolves the dial address from the gossip graph', async function () {
		const node = makeNode();
		const dials = stubDialer(node, ['1.2.3.4']);
		injectAnnouncement(node, [
			{ type: ADDRESS_TYPE_IPV4, host: '1.2.3.4', port: 9736 }
		]);
		await node.connectPeer(TARGET_PUBKEY);
		expect(dials).to.deep.equal([{ host: '1.2.3.4', port: 9736 }]);
		node.destroy();
	});

	it('tries graph addresses in announced order until one connects', async function () {
		const node = makeNode();
		const dials = stubDialer(node, ['5.6.7.8']);
		injectAnnouncement(node, [
			{ type: ADDRESS_TYPE_IPV4, host: '1.2.3.4', port: 9735 },
			{ type: ADDRESS_TYPE_IPV4, host: '5.6.7.8', port: 9737 }
		]);
		await node.connectPeer(TARGET_PUBKEY);
		expect(dials).to.deep.equal([
			{ host: '1.2.3.4', port: 9735 },
			{ host: '5.6.7.8', port: 9737 }
		]);
		node.destroy();
	});

	it('skips Tor addresses when no socks5Proxy is configured', async function () {
		const node = makeNode();
		const dials = stubDialer(node, ['clear.example.com']);
		injectAnnouncement(node, [
			{ type: ADDRESS_TYPE_TORV3, host: TORV3_HEX, port: 9735 },
			{ type: ADDRESS_TYPE_DNS, host: 'clear.example.com', port: 9735 }
		]);
		await node.connectPeer(TARGET_PUBKEY);
		expect(dials).to.deep.equal([{ host: 'clear.example.com', port: 9735 }]);
		node.destroy();
	});

	it('dials the .onion hostname when a socks5Proxy is configured', async function () {
		const node = makeNode({ socks5Proxy: { host: '127.0.0.1', port: 9050 } });
		const onion = nodeAddressToHostPort({
			type: ADDRESS_TYPE_TORV3,
			host: TORV3_HEX,
			port: 9735
		})!;
		expect(onion.host).to.match(/^[a-z2-7]{56}\.onion$/);
		const dials = stubDialer(node, [onion.host]);
		injectAnnouncement(node, [
			{ type: ADDRESS_TYPE_TORV3, host: TORV3_HEX, port: 9735 }
		]);
		await node.connectPeer(TARGET_PUBKEY);
		expect(dials).to.deep.equal([{ host: onion.host, port: 9735 }]);
		node.destroy();
	});

	it('falls back to DNS bootstrap when the graph has no addresses', async function () {
		const node = makeNode();
		const dials = stubDialer(node, ['44.55.66.77']);
		stubBootstrap(node, [
			{
				pubkey: Buffer.from(TARGET_PUBKEY, 'hex'),
				host: '44.55.66.77',
				port: 9735
			},
			// Different node id must be ignored.
			{ pubkey: getPublicKey(makeSeed(43)), host: '99.99.99.99', port: 9735 }
		]);
		await node.connectPeer(TARGET_PUBKEY);
		expect(dials).to.deep.equal([{ host: '44.55.66.77', port: 9735 }]);
		node.destroy();
	});

	it('reports every attempt when nothing connects (graph + skipped Tor)', async function () {
		const node = makeNode();
		stubDialer(node, []);
		injectAnnouncement(node, [
			{ type: ADDRESS_TYPE_IPV4, host: '1.2.3.4', port: 9735 },
			{ type: ADDRESS_TYPE_TORV3, host: TORV3_HEX, port: 9735 }
		]);
		try {
			await node.connectPeer(TARGET_PUBKEY);
			expect.fail('should have thrown');
		} catch (err) {
			const msg = (err as Error).message;
			expect(msg).to.include(TARGET_PUBKEY);
			expect(msg).to.include('graph 1.2.3.4:9735');
			expect(msg).to.include('skipped 1 Tor address(es)');
		}
		node.destroy();
	});

	it('reports DNS results in the error when the graph is empty', async function () {
		const node = makeNode();
		stubDialer(node, []);
		stubBootstrap(node, [
			{
				pubkey: Buffer.from(TARGET_PUBKEY, 'hex'),
				host: '44.55.66.77',
				port: 9735
			}
		]);
		try {
			await node.connectPeer(TARGET_PUBKEY);
			expect.fail('should have thrown');
		} catch (err) {
			const msg = (err as Error).message;
			expect(msg).to.include('dns 44.55.66.77:9735');
		}
		node.destroy();
	});

	it('says so when DNS bootstrap has no address for the node id', async function () {
		const node = makeNode();
		stubDialer(node, []);
		stubBootstrap(node, []);
		try {
			await node.connectPeer(TARGET_PUBKEY);
			expect.fail('should have thrown');
		} catch (err) {
			expect((err as Error).message).to.include(
				'DNS bootstrap returned no address'
			);
		}
		node.destroy();
	});
});
