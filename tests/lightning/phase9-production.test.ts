/**
 * Phase 9: Inbound Connections + Production Wiring tests.
 *
 * 9A: PeerManager TCP listener for inbound connections
 * 9B: ElectrumBackend structure
 * 9C: Crash recovery from SQLite storage
 */

import { expect } from 'chai';
import crypto from 'crypto';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { Peer } from '../../src/lightning/transport/peer';
import { FeatureFlags } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

// ── Helpers ────────────────────────────────────────────────────────

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
	};
}

function makeNode(opts?: {
	enableNetworking?: boolean;
	storage?: SqliteStorage;
}): LightningNode {
	return new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		perCommitmentSeed: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(),
		fundingPrivkey: crypto.randomBytes(32),
		enableNetworking: opts?.enableNetworking,
		storage: opts?.storage
	});
}

function tmpDbPath(): string {
	return path.join(
		os.tmpdir(),
		`beignet-test-${crypto.randomBytes(8).toString('hex')}.db`
	);
}

// ── Tests ──────────────────────────────────────────────────────────

describe('Phase 9: Production Wiring', function () {
	describe('9A: PeerManager TCP Listener', function () {
		it('should start and stop listening', async function () {
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32)
			});

			expect(pm.isListening()).to.be.false;
			await pm.listen(0); // port 0 = random available port
			expect(pm.isListening()).to.be.true;

			pm.stopListening();
			expect(pm.isListening()).to.be.false;
			pm.destroy();
		});

		it('should reject double listen', async function () {
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32)
			});

			await pm.listen(0);
			try {
				await pm.listen(0);
				expect.fail('Should have thrown');
			} catch (err: any) {
				expect(err.message).to.include('Already listening');
			}
			pm.destroy();
		});

		it('should stop listening on destroy', async function () {
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32)
			});

			await pm.listen(0);
			expect(pm.isListening()).to.be.true;
			pm.destroy();
			expect(pm.isListening()).to.be.false;
		});

		it('should accept inbound TCP connection and complete handshake', async function () {
			this.timeout(10_000);
			const serverKey = crypto.randomBytes(32);
			const pm = new PeerManager({
				localPrivateKey: serverKey,
				localFeatures: FeatureFlags.empty()
			});

			await pm.listen(0);
			// Get the actual port
			const addr = (pm as any).server.address();
			const port = addr.port;

			// Create an outbound peer to connect to our listener
			const clientKey = crypto.randomBytes(32);
			// getPublicKey imported at top
			const serverPubkey = getPublicKey(serverKey);

			const client = new Peer({
				localPrivateKey: clientKey,
				remotePublicKey: serverPubkey,
				host: '127.0.0.1',
				port,
				localFeatures: FeatureFlags.empty()
			});

			// Wait for peer:connect event from PeerManager
			const connectPromise = new Promise<string>((resolve) => {
				pm.on('peer:connect', (pubkey: string) => {
					resolve(pubkey);
				});
			});

			await client.connect();
			const connectedPubkey = await connectPromise;

			// The connected pubkey should be the client's pubkey
			const clientPubkey = getPublicKey(clientKey).toString('hex');
			expect(connectedPubkey).to.equal(clientPubkey);

			// Peer should be listed
			const peers = pm.listPeers();
			expect(peers.length).to.equal(1);
			expect(peers[0].pubkey).to.equal(clientPubkey);

			client.disconnect();
			pm.destroy();
		});

		it('should reject duplicate inbound connections', async function () {
			this.timeout(10_000);
			const serverKey = crypto.randomBytes(32);
			const pm = new PeerManager({
				localPrivateKey: serverKey,
				localFeatures: FeatureFlags.empty()
			});

			await pm.listen(0);
			const addr = (pm as any).server.address();
			const port = addr.port;

			// getPublicKey imported at top
			const serverPubkey = getPublicKey(serverKey);
			const clientKey = crypto.randomBytes(32);

			// First connection
			const client1 = new Peer({
				localPrivateKey: clientKey,
				remotePublicKey: serverPubkey,
				host: '127.0.0.1',
				port,
				localFeatures: FeatureFlags.empty()
			});

			const firstConnect = new Promise<void>((resolve) => {
				pm.once('peer:connect', () => resolve());
			});
			await client1.connect();
			await firstConnect;

			// Second connection with same key — should be rejected
			const client2 = new Peer({
				localPrivateKey: clientKey,
				remotePublicKey: serverPubkey,
				host: '127.0.0.1',
				port,
				localFeatures: FeatureFlags.empty()
			});

			// Wait briefly for the second connection attempt to be processed
			await client2.connect();
			await new Promise((r) => setTimeout(r, 200));

			// Should still have only one peer
			expect(pm.listPeers().length).to.equal(1);

			client1.disconnect();
			client2.disconnect();
			pm.destroy();
		});
	});

	describe('9A: LightningNode listen/stopListening', function () {
		it('should expose listen() when networking enabled', async function () {
			const node = makeNode({ enableNetworking: true });
			expect(node.isListening()).to.be.false;
			await node.listen(0);
			expect(node.isListening()).to.be.true;
			node.stopListening();
			expect(node.isListening()).to.be.false;
			node.destroy();
		});

		it('should throw listen() when networking disabled', async function () {
			const node = makeNode();
			try {
				await node.listen(9735);
				expect.fail('Should have thrown');
			} catch (err: any) {
				expect(err.message).to.include('not enabled');
			}
			node.destroy();
		});

		it('should stop listening on destroy', async function () {
			const node = makeNode({ enableNetworking: true });
			await node.listen(0);
			expect(node.isListening()).to.be.true;
			node.destroy();
			expect(node.isListening()).to.be.false;
		});
	});

	describe('9B: ElectrumBackend', function () {
		it('should implement IChainBackend interface', function () {
			// Verify the class has all required methods
			const methods = [
				'subscribeToHeaders',
				'subscribeToScriptHash',
				'getScriptHashHistory',
				'getTransaction',
				'broadcastTransaction'
			];

			for (const method of methods) {
				expect(ElectrumBackend.prototype).to.have.property(method);
				expect(typeof (ElectrumBackend.prototype as any)[method]).to.equal(
					'function'
				);
			}
		});

		it('should have notifyNewBlock method for external block notifications', function () {
			expect(ElectrumBackend.prototype).to.have.property('notifyNewBlock');
			expect(typeof ElectrumBackend.prototype.notifyNewBlock).to.equal(
				'function'
			);
		});

		it('should be assignable to IChainBackend', function () {
			// TypeScript compile-time check — if this compiles, the interface is satisfied
			const _check: IChainBackend = {} as ElectrumBackend;
			expect(_check).to.exist;
		});
	});

	describe('9C: Crash Recovery (SQLite)', function () {
		let dbPath: string;

		beforeEach(function () {
			dbPath = tmpDbPath();
		});

		afterEach(function () {
			try {
				fs.unlinkSync(dbPath);
			} catch {
				/* ignore */
			}
		});

		it('should persist and restore channel state', function () {
			const storage = new SqliteStorage(dbPath);
			storage.open();

			// Create a channel state and save it
			const channelId = crypto.randomBytes(32);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 500_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.channelId = channelId;
			state.state = ChannelState.NORMAL;
			state.localBalanceMsat = 400_000_000n;
			state.remoteBalanceMsat = 100_000_000n;
			state.localCommitmentNumber = 5n;

			const peerPubkey = crypto.randomBytes(33).toString('hex');
			storage.saveChannel(channelId.toString('hex'), state, peerPubkey);
			storage.close();

			// Reopen and restore
			const storage2 = new SqliteStorage(dbPath);
			storage2.open();

			const loaded = storage2.loadChannel(channelId.toString('hex'));
			expect(loaded).to.not.be.null;
			expect(loaded!.peerPubkey).to.equal(peerPubkey);
			expect(loaded!.state.state).to.equal(ChannelState.NORMAL);
			expect(loaded!.state.localBalanceMsat).to.equal(400_000_000n);
			expect(loaded!.state.remoteBalanceMsat).to.equal(100_000_000n);
			expect(loaded!.state.localCommitmentNumber).to.equal(5n);
			expect(loaded!.state.fundingSatoshis).to.equal(500_000n);

			storage2.close();
		});

		it('should persist and restore payments', function () {
			const storage = new SqliteStorage(dbPath);
			storage.open();

			const paymentHash = crypto.randomBytes(32);
			const payment = {
				paymentHash,
				amountMsat: 50_000n,
				status: 'COMPLETED' as any,
				direction: 'OUTGOING' as any,
				createdAt: Date.now()
			};

			storage.savePayment(paymentHash.toString('hex'), payment as any);
			storage.close();

			const storage2 = new SqliteStorage(dbPath);
			storage2.open();

			const payments = storage2.loadAllPayments();
			expect(payments.length).to.equal(1);
			expect(payments[0].paymentHash).to.equal(paymentHash.toString('hex'));

			storage2.close();
		});

		it('should persist and restore preimages', function () {
			const storage = new SqliteStorage(dbPath);
			storage.open();

			const paymentHash = crypto.randomBytes(32);
			const preimage = crypto.randomBytes(32);

			storage.savePreimage(paymentHash.toString('hex'), preimage);
			storage.close();

			const storage2 = new SqliteStorage(dbPath);
			storage2.open();

			const preimages = storage2.loadAllPreimages();
			expect(preimages.length).to.equal(1);
			expect(preimages[0].paymentHash).to.equal(paymentHash.toString('hex'));
			expect(preimages[0].preimage.equals(preimage)).to.be.true;

			storage2.close();
		});

		it('should persist and restore SCID mappings', function () {
			const storage = new SqliteStorage(dbPath);
			storage.open();

			const scidHex = crypto.randomBytes(8).toString('hex');
			const channelId = crypto.randomBytes(32);

			storage.saveScidMapping(scidHex, channelId);
			storage.close();

			const storage2 = new SqliteStorage(dbPath);
			storage2.open();

			const mappings = storage2.loadAllScidMappings();
			expect(mappings.length).to.equal(1);
			expect(mappings[0].scidHex).to.equal(scidHex);
			expect(mappings[0].channelId.equals(channelId)).to.be.true;

			storage2.close();
		});

		it('should persist forwarded HTLCs across restart', function () {
			const storage = new SqliteStorage(dbPath);
			storage.open();

			const outKey = 'channel1:5';
			const inChannelId = crypto.randomBytes(32);
			const inHtlcId = 3n;

			storage.saveForwardedHtlc(outKey, inChannelId, inHtlcId);
			storage.close();

			const storage2 = new SqliteStorage(dbPath);
			storage2.open();

			const fwds = storage2.loadAllForwardedHtlcs();
			expect(fwds.length).to.equal(1);
			expect(fwds[0].outKey).to.equal(outKey);
			expect(fwds[0].inChannelId.equals(inChannelId)).to.be.true;
			expect(fwds[0].inHtlcId).to.equal(inHtlcId);

			storage2.close();
		});

		it('should restore channel with SCID alias fields', function () {
			const storage = new SqliteStorage(dbPath);
			storage.open();

			const channelId = crypto.randomBytes(32);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.channelId = channelId;
			state.state = ChannelState.NORMAL;
			state.scidAlias = crypto.randomBytes(8);
			state.remoteScidAlias = crypto.randomBytes(8);

			storage.saveChannel(channelId.toString('hex'), state, 'peer1');
			storage.close();

			const storage2 = new SqliteStorage(dbPath);
			storage2.open();

			const loaded = storage2.loadChannel(channelId.toString('hex'));
			expect(loaded).to.not.be.null;
			expect(loaded!.state.scidAlias).to.not.be.null;
			expect(loaded!.state.scidAlias!.equals(state.scidAlias!)).to.be.true;
			expect(loaded!.state.remoteScidAlias).to.not.be.null;
			expect(loaded!.state.remoteScidAlias!.equals(state.remoteScidAlias!)).to
				.be.true;

			storage2.close();
		});

		it('should restore channel with reestablish cache fields', function () {
			const storage = new SqliteStorage(dbPath);
			storage.open();

			const channelId = crypto.randomBytes(32);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.channelId = channelId;
			state.state = ChannelState.AWAITING_REESTABLISH;
			state.preReestablishState = ChannelState.NORMAL;
			state.lastSentCommitmentSigned = crypto.randomBytes(64);
			state.lastSentHtlcSignatures = [crypto.randomBytes(64)];
			state.lastSentRevokeSecret = crypto.randomBytes(32);
			state.lastSentRevokeNextPoint = crypto.randomBytes(33);

			storage.saveChannel(channelId.toString('hex'), state, 'peer2');
			storage.close();

			const storage2 = new SqliteStorage(dbPath);
			storage2.open();

			const loaded = storage2.loadChannel(channelId.toString('hex'));
			expect(loaded).to.not.be.null;
			expect(loaded!.state.state).to.equal(ChannelState.AWAITING_REESTABLISH);
			expect(loaded!.state.preReestablishState).to.equal(ChannelState.NORMAL);
			expect(
				loaded!.state.lastSentCommitmentSigned!.equals(
					state.lastSentCommitmentSigned!
				)
			).to.be.true;
			expect(loaded!.state.lastSentHtlcSignatures.length).to.equal(1);
			expect(
				loaded!.state.lastSentRevokeSecret!.equals(state.lastSentRevokeSecret!)
			).to.be.true;
			expect(
				loaded!.state.lastSentRevokeNextPoint!.equals(
					state.lastSentRevokeNextPoint!
				)
			).to.be.true;

			storage2.close();
		});

		it('should restore channel with closing negotiation fields', function () {
			const storage = new SqliteStorage(dbPath);
			storage.open();

			const channelId = crypto.randomBytes(32);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.channelId = channelId;
			state.state = ChannelState.NORMAL;
			state.lastProposedClosingFeeSat = 500n;
			state.closingFeeMin = 250n;
			state.closingFeeMax = 1000n;
			state.theirLastClosingFeeSat = 600n;

			storage.saveChannel(channelId.toString('hex'), state, 'peer3');
			storage.close();

			const storage2 = new SqliteStorage(dbPath);
			storage2.open();

			const loaded = storage2.loadChannel(channelId.toString('hex'));
			expect(loaded).to.not.be.null;
			expect(loaded!.state.lastProposedClosingFeeSat).to.equal(500n);
			expect(loaded!.state.closingFeeMin).to.equal(250n);
			expect(loaded!.state.closingFeeMax).to.equal(1000n);
			expect(loaded!.state.theirLastClosingFeeSat).to.equal(600n);

			storage2.close();
		});

		it('should restore LightningNode from storage', function () {
			const dbPath1 = tmpDbPath();
			const storage1 = new SqliteStorage(dbPath1);
			storage1.open();

			const nodeKey = crypto.randomBytes(32);
			const seed = crypto.randomBytes(32);
			const bp = makeBasepoints();
			const fundingPrivkey = crypto.randomBytes(32);

			// Create node, create an invoice, then destroy
			const node1 = new LightningNode({
				nodePrivateKey: nodeKey,
				perCommitmentSeed: seed,
				channelBasepoints: bp,
				fundingPrivkey,
				storage: storage1
			});

			const invoiceStr = node1.createInvoice({
				amountMsat: 10_000n,
				description: 'test recovery'
			});
			expect(invoiceStr.bolt11).to.be.a('string');

			node1.destroy();
			storage1.close();

			// Reopen storage and create new node with same keys
			const storage2 = new SqliteStorage(dbPath1);
			storage2.open();

			const node2 = new LightningNode({
				nodePrivateKey: nodeKey,
				perCommitmentSeed: seed,
				channelBasepoints: bp,
				fundingPrivkey,
				storage: storage2
			});

			// Node should exist and have same ID
			const info1 = node1.getNodeInfo();
			const info2 = node2.getNodeInfo();
			expect(info2.nodeId).to.equal(info1.nodeId);

			node2.destroy();
			storage2.close();
			try {
				fs.unlinkSync(dbPath1);
			} catch {
				/* ignore */
			}
		});
	});

	describe('Peer inbound support', function () {
		it('Peer.remotePublicKey should be mutable for inbound', function () {
			const peer = new Peer({
				localPrivateKey: crypto.randomBytes(32),
				remotePublicKey: Buffer.alloc(33, 0),
				host: 'localhost',
				port: 9735
			});

			// Should be able to assign (not readonly)
			const newKey = crypto.randomBytes(33);
			peer.remotePublicKey = newKey;
			expect(peer.remotePublicKey.equals(newKey)).to.be.true;
		});
	});
});
