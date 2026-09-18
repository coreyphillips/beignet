/**
 * A request that goes straight to a node this one may share no channel with
 * (an FFOR witness, an offer's introduction node) dials that node from its
 * node announcement when it is not a ready peer (issue #885). Every node
 * here talks over a real BOLT 8 socket, and nothing connects beforehand.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import net from 'net';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { Feature } from '../../src/lightning/features/flags';
import { ADDRESS_TYPE_IPV4 } from '../../src/lightning/gossip/types';
import { constructBlindedPath } from '../../src/lightning/onion/blinded-path';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	TIP,
	activate,
	createWorld,
	makeBasepoints,
	record,
	sha
} from './helpers/ffor-world';

function networkedConfig(label: string): Partial<INodeConfig> {
	const seed = sha(`request-dial-${label}`);
	const features = LightningNode.defaultFeatures();
	features.clearBit(Feature.DUAL_FUND + 1);
	return {
		nodePrivateKey: sha(seed, 'node-identity'),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: sha(seed, 'per-commitment'),
		fundingPrivkey: sha(seed, Buffer.from([0])),
		htlcBasepointSecret: sha(seed, Buffer.from([4])),
		enableNetworking: true,
		localFeatures: features
	};
}

function networkedNode(
	label: string,
	extra: Partial<INodeConfig> = {}
): LightningNode {
	const node = new LightningNode({
		...(networkedConfig(label) as INodeConfig),
		...extra
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function listenPort(node: LightningNode): number {
	return (
		node.getPeerManager() as unknown as {
			server: { address(): { port: number } };
		}
	).server.address().port;
}

/** A port nothing listens on. */
async function closedPort(): Promise<number> {
	const server = net.createServer();
	await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
	const { port } = server.address() as net.AddressInfo;
	await new Promise<void>((r) => server.close(() => r()));
	return port;
}

/** `target` announced on `viewer`'s graph at 127.0.0.1:`port`, verified. */
function announce(viewer: LightningNode, target: string, port: number): void {
	const graph = viewer.getGraph();
	const targetKey = Buffer.from(target, 'hex');
	const other = getPublicKey(sha('request-dial-other', target));
	const targetFirst = Buffer.compare(targetKey, other) < 0;
	expect(
		graph.addChannelAnnouncement(
			{
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: REGTEST_CHAIN_HASH,
				shortChannelId: crypto.randomBytes(8),
				nodeId1: targetFirst ? targetKey : other,
				nodeId2: targetFirst ? other : targetKey,
				bitcoinKey1: Buffer.alloc(33, 2),
				bitcoinKey2: Buffer.alloc(33, 3)
			},
			{ verified: true }
		)
	).to.equal(true);
	expect(
		graph.applyNodeAnnouncement(
			{
				signature: Buffer.alloc(64),
				features: Buffer.alloc(0),
				timestamp: Math.floor(Date.now() / 1000),
				nodeId: targetKey,
				rgbColor: Buffer.alloc(3),
				alias: Buffer.alloc(32),
				addresses: [{ type: ADDRESS_TYPE_IPV4, host: '127.0.0.1', port }]
			},
			{ verified: true }
		)
	).to.equal(true);
}

function connected(node: LightningNode, peer: string): boolean {
	return node.getPeerManager()?.getPeer(peer)?.getState() === 'ready';
}

describe('Requests dial a target that is not a peer (issue #885)', function () {
	this.timeout(60_000);

	it('FFOR: provisioning and the fetch after a disconnect dial the witness from its announcement', async () => {
		const w = createWorld({ rExtra: { enableNetworking: true } });
		const witness = networkedNode('witness', {
			fforWitness: { enabled: true }
		});
		try {
			activate(w);
			await witness.listen(0, '127.0.0.1');
			witness.handleNewBlock(TIP);
			const witnessId = witness.getNodeId();
			announce(w.r, witnessId, listenPort(witness));
			expect(connected(w.r, witnessId)).to.equal(false);

			const { mailboxId } = await w.r.provisionFforWitness(w.srHex, witnessId);
			expect(connected(w.r, witnessId)).to.equal(true);
			expect(witness.getFforWitnessService()!.listMailboxes()[0].id).to.equal(
				mailboxId.toString('hex')
			);
			expect(record(w.r, w.srHex).witnesses[0].ackedAt).to.not.equal(null);
			// The dial exists for the request alone: the witness is no
			// reconnect target once the connection closes.
			expect(
				(
					w.r.getPeerManager() as unknown as { noReconnectPeers: Set<string> }
				).noReconnectPeers.has(witnessId)
			).to.equal(true);

			// R loses the connection (a restart, a dropped link): the return's
			// fetch dials again.
			w.r.disconnectPeer(witnessId);
			expect(connected(w.r, witnessId)).to.equal(false);
			const fetched = await w.r.fetchFforWitnessRecords(w.srHex);
			expect(fetched).to.have.length(1);
			expect(fetched[0].ok, fetched[0].error).to.equal(true);
			expect(connected(w.r, witnessId)).to.equal(true);
		} finally {
			w.r.destroy();
			witness.destroy();
		}
	});

	it('FFOR: a witness that cannot be dialed fails the provision with the dial error', async () => {
		const w = createWorld({ rExtra: { enableNetworking: true } });
		try {
			activate(w);
			const witnessId = getPublicKey(sha('request-dial-unreachable')).toString(
				'hex'
			);
			announce(w.r, witnessId, await closedPort());
			let refused: Error | null = null;
			try {
				await w.r.provisionFforWitness(w.srHex, witnessId, {
					timeoutMs: 1_000
				});
			} catch (err) {
				refused = err as Error;
			}
			expect(refused?.message).to.match(
				/did not answer type \d+ \(Unable to resolve a connection to/
			);
			expect(record(w.r, w.srHex).witnesses).to.have.length(0);
		} finally {
			w.r.destroy();
		}
	});

	it("BOLT 12: an invoice request dials the offer path's introduction node", async () => {
		const issuer = networkedNode('issuer');
		const payer = networkedNode('payer');
		try {
			await issuer.listen(0, '127.0.0.1');
			const issuerId = issuer.getNodeId();
			const { offer } = issuer.createOffer({
				description: 'dial me',
				amount: 5_000n,
				paths: [
					constructBlindedPath(
						crypto.randomBytes(32),
						[Buffer.from(issuerId, 'hex')],
						[{}]
					)
				]
			});
			announce(payer, issuerId, listenPort(issuer));
			expect(connected(payer, issuerId)).to.equal(false);

			const invoice = await payer.requestInvoice(offer, { timeoutMs: 20_000 });
			expect(invoice.amount).to.equal(5_000n);
			expect(connected(payer, issuerId)).to.equal(true);
		} finally {
			payer.destroy();
			issuer.destroy();
		}
	});
});
