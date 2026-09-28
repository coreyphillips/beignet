/**
 * Issue #1104: a channel opened with an upper-case peer pubkey must still
 * work over a connection the peer dials. Inbound connections register the
 * lowercase key the handshake produces, so every entry point that takes a
 * pubkey, and every stored row that names one, has to land on that key.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { INodeConfig } from '../../src/lightning/node/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(
	cond: () => boolean,
	label: string,
	timeoutMs = 10_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!cond()) {
		if (Date.now() > deadline)
			throw new Error(`Timed out waiting for ${label}`);
		await sleep(25);
	}
}

function seed(id: number, label: string): Buffer {
	return crypto
		.createHash('sha256')
		.update(`peer-pubkey-case-${label}-${id}`)
		.digest();
}

function makeNode(
	id: number,
	overrides: Partial<INodeConfig> = {}
): LightningNode {
	const secrets: Buffer[] = [];
	for (let i = 0; i < 5; i++) secrets.push(seed(id, `basepoint-${i}`));
	// v1 funding is driven by hand below; without dual fund both ends keep
	// openChannel on the v1 flow.
	const features = LightningNode.defaultFeatures();
	features.clearBit(28);
	features.clearBit(29);
	const node = new LightningNode({
		nodePrivateKey: seed(id, 'node'),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: {
			fundingPubkey: getPublicKey(secrets[0]),
			revocationBasepoint: getPublicKey(secrets[1]),
			paymentBasepoint: getPublicKey(secrets[2]),
			delayedPaymentBasepoint: getPublicKey(secrets[3]),
			htlcBasepoint: getPublicKey(secrets[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		perCommitmentSeed: seed(id, 'commitment'),
		fundingPrivkey: secrets[0],
		htlcBasepointSecret: secrets[4],
		enableNetworking: true,
		// Only the remote brings the connection back in these tests.
		autoReconnect: false,
		localFeatures: features,
		...overrides
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

async function listenLocal(node: LightningNode): Promise<number> {
	await node.listen(0, '127.0.0.1');
	const server = (node.getPeerManager() as unknown as { server: net.Server })
		.server;
	return (server.address() as net.AddressInfo).port;
}

function channelState(node: LightningNode): ChannelState | undefined {
	return node.getChannelManager().listChannels()[0]?.getState();
}

describe('Mixed-case peer pubkeys (issue #1104)', function () {
	this.timeout(30_000);

	it('reestablishes a channel opened with an upper-case pubkey over an inbound connection past maxInboundPeers', async function () {
		// No inbound slot at all: only the channel-peer exemption lets the
		// peer back in.
		const alice = makeNode(1, { maxInboundPeers: 0 });
		const bob = makeNode(2);
		try {
			const alicePort = await listenLocal(alice);
			const bobPort = await listenLocal(bob);
			const bobId = bob.getNodeId();
			const bobUpper = bobId.toUpperCase();
			expect(bobUpper).to.not.equal(bobId);

			await alice.connectPeer(bobUpper, '127.0.0.1', bobPort);
			const accepted = new Promise<void>((resolve) => {
				alice.getChannelManager().once('channel:accepted', () => resolve());
			});
			const channel = alice.openChannel(bobUpper, 1_000_000n);
			await accepted;
			const channelId = alice.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			);
			expect(channelId).to.not.equal(null);
			await waitFor(
				() =>
					channelState(alice) === ChannelState.AWAITING_FUNDING_CONFIRMED &&
					bob.getChannelManager().listChannels()[0]?.getChannelId() != null,
				'funding signed'
			);
			alice.handleFundingConfirmed(channelId!);
			bob.handleFundingConfirmed(
				bob.getChannelManager().listChannels()[0].getChannelId()!
			);
			await waitFor(
				() =>
					channelState(alice) === ChannelState.NORMAL &&
					channelState(bob) === ChannelState.NORMAL,
				'channel NORMAL'
			);
			expect(alice.getChannelManager().getPeerForChannel(channelId!)).to.equal(
				bobId
			);

			alice.disconnectPeer(bobUpper);
			await waitFor(
				() =>
					alice.listPeers().length === 0 &&
					bob.listPeers().length === 0 &&
					channelState(alice) === ChannelState.AWAITING_REESTABLISH &&
					channelState(bob) === ChannelState.AWAITING_REESTABLISH,
				'both sides disconnected'
			);

			let reestablishFromAlice = 0;
			bob.getPeerManager()!.on('message', (pubkey: string, type: number) => {
				if (
					pubkey === alice.getNodeId() &&
					type === MessageType.CHANNEL_REESTABLISH
				) {
					reestablishFromAlice++;
				}
			});
			await bob.connectPeer(alice.getNodeId(), '127.0.0.1', alicePort);

			await waitFor(
				() =>
					reestablishFromAlice > 0 &&
					channelState(alice) === ChannelState.NORMAL &&
					channelState(bob) === ChannelState.NORMAL,
				'channel reestablished'
			);
			expect(alice.listPeers().map((p) => p.pubkey)).to.deep.equal([bobId]);
		} finally {
			alice.destroy();
			bob.destroy();
		}
	});

	it('loads rows stored under an upper-case peer id under the lowercase key', async function () {
		const dbPath = path.join(
			os.tmpdir(),
			`peer-pubkey-case-${crypto.randomBytes(6).toString('hex')}.db`
		);
		const openStorage = (): SqliteStorage => {
			const storage = new SqliteStorage(dbPath);
			storage.open();
			return storage;
		};
		let alice = makeNode(1, { storage: openStorage() });
		const bob = makeNode(2);
		try {
			const bobPort = await listenLocal(bob);
			const bobId = bob.getNodeId();
			const bobUpper = bobId.toUpperCase();

			await alice.connectPeer(bobId, '127.0.0.1', bobPort);
			const accepted = new Promise<void>((resolve) => {
				alice.getChannelManager().once('channel:accepted', () => resolve());
			});
			const channel = alice.openChannel(bobId, 1_000_000n);
			await accepted;
			const channelId = alice.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			)!;
			await waitFor(
				() =>
					channelState(alice) === ChannelState.AWAITING_FUNDING_CONFIRMED &&
					bob.getChannelManager().listChannels()[0]?.getChannelId() != null,
				'funding signed'
			);
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(
				bob.getChannelManager().listChannels()[0].getChannelId()!
			);
			await waitFor(
				() =>
					channelState(alice) === ChannelState.NORMAL &&
					channelState(bob) === ChannelState.NORMAL,
				'channel NORMAL'
			);

			alice.destroy();
			await waitFor(() => bob.listPeers().length === 0, 'bob sees the drop');

			// The rows an open by upper-case pubkey wrote before the fix.
			const storage = openStorage();
			const idHex = channelId.toString('hex');
			storage.saveChannel(idHex, storage.loadChannel(idHex)!.state, bobUpper);
			storage.deletePeerAddress(bobId);
			storage.savePeerAddress(bobUpper, '203.0.113.9', 9735);
			storage.saveMetadata(
				'zero_conf_trusted_peers',
				JSON.stringify([bobUpper])
			);

			alice = makeNode(1, { storage, maxInboundPeers: 0 });
			const alicePort = await listenLocal(alice);
			expect(alice.getChannelManager().getPeerForChannel(channelId)).to.equal(
				bobId
			);
			expect(alice.listTrustedPeers()).to.deep.equal([bobId]);
			const scbAddresses = (): string[] =>
				alice.buildStaticChannelBackupData().channels[0].peerAddresses;
			expect(scbAddresses()).to.deep.equal(['203.0.113.9:9735']);
			// A peer with rows in both forms: the lowercase one is the newer.
			storage.savePeerAddress(bobId, '127.0.0.1', bobPort);
			expect(scbAddresses()).to.deep.equal([`127.0.0.1:${bobPort}`]);

			await bob.connectPeer(alice.getNodeId(), '127.0.0.1', alicePort);
			await waitFor(
				() =>
					channelState(alice) === ChannelState.NORMAL &&
					channelState(bob) === ChannelState.NORMAL,
				'channel reestablished after restart'
			);
		} finally {
			alice.destroy();
			bob.destroy();
			for (const suffix of ['', '-wal', '-shm']) {
				fs.rmSync(`${dbPath}${suffix}`, { force: true });
			}
		}
	});
});
