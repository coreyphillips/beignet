/**
 * BOLT 1 peer storage (option_provide_storage) tests.
 *
 * Covers the message codecs, feature-bit advertising, the server side
 * (store one blob per channel/trusted peer, rate limit, return it on
 * reconnect), the client side (distribute our blob only to capable peers,
 * config gate), BeignetNode's validation of retrieved blobs, and the
 * storage round-trip including the encrypted-at-rest guarantee.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import os from 'os';
import path from 'path';
import fs from 'fs';
import * as bip39 from 'bip39';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { MessageType } from '../../src/lightning/message/types';
import {
	PEER_STORAGE_MAX_BYTES,
	encodePeerStorageMessage,
	decodePeerStorageMessage,
	encodePeerStorageRetrievalMessage,
	decodePeerStorageRetrievalMessage
} from '../../src/lightning/message/peer-storage';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { ChannelState } from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	encodeScb,
	IStaticChannelBackup
} from '../../src/lightning/backup/scb';
import { BeignetNode } from '../../src/cli/beignet-node';

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
	privateKey?: Buffer;
	peerStorageEnabled?: boolean;
}): LightningNode {
	return new LightningNode({
		nodePrivateKey: opts?.privateKey ?? crypto.randomBytes(32),
		perCommitmentSeed: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(),
		fundingPrivkey: crypto.randomBytes(32),
		enableNetworking: opts?.enableNetworking,
		storage: opts?.storage,
		peerStorageEnabled: opts?.peerStorageEnabled
	});
}

function tmpDbPath(): string {
	return path.join(
		os.tmpdir(),
		`beignet-peer-storage-${crypto.randomBytes(8).toString('hex')}.db`
	);
}

async function waitFor(cond: () => boolean, timeoutMs = 8_000): Promise<void> {
	const start = Date.now();
	while (!cond()) {
		if (Date.now() - start > timeoutMs) {
			throw new Error('waitFor timed out');
		}
		await new Promise((r) => setTimeout(r, 25));
	}
}

const PEER_PK = '02'.repeat(33);

/** Feed a raw peer_storage payload into a node's private handler. */
function deliverPeerStorage(
	node: LightningNode,
	pubkey: string,
	payload: Buffer
): void {
	(node as any).handlePeerStorageMessage(pubkey, payload);
}

// ── Tests ──────────────────────────────────────────────────────────

describe('Peer Storage (BOLT 1 option_provide_storage)', function () {
	describe('message codecs', function () {
		it('assigns the spec message type numbers 7 and 9', function () {
			expect(MessageType.PEER_STORAGE).to.equal(7);
			expect(MessageType.PEER_STORAGE_RETRIEVAL).to.equal(9);
		});

		it('round-trips a peer_storage message', function () {
			const blob = crypto.randomBytes(1024);
			const encoded = encodePeerStorageMessage({ blob });
			expect(encoded.readUInt16BE(0)).to.equal(1024);
			const decoded = decodePeerStorageMessage(encoded);
			expect(decoded.blob.equals(blob)).to.equal(true);
		});

		it('round-trips a peer_storage_retrieval message', function () {
			const blob = crypto.randomBytes(333);
			const decoded = decodePeerStorageRetrievalMessage(
				encodePeerStorageRetrievalMessage({ blob })
			);
			expect(decoded.blob.equals(blob)).to.equal(true);
		});

		it('round-trips an empty blob', function () {
			const decoded = decodePeerStorageMessage(
				encodePeerStorageMessage({ blob: Buffer.alloc(0) })
			);
			expect(decoded.blob.length).to.equal(0);
		});

		it('round-trips the maximum 65531-byte blob', function () {
			const blob = crypto.randomBytes(PEER_STORAGE_MAX_BYTES);
			const decoded = decodePeerStorageMessage(
				encodePeerStorageMessage({ blob })
			);
			expect(decoded.blob.equals(blob)).to.equal(true);
		});

		it('rejects encoding a blob above the cap', function () {
			const blob = Buffer.alloc(PEER_STORAGE_MAX_BYTES + 1);
			expect(() => encodePeerStorageMessage({ blob })).to.throw('too large');
			expect(() => encodePeerStorageRetrievalMessage({ blob })).to.throw(
				'too large'
			);
		});

		it('rejects decoding a declared length above the cap', function () {
			const payload = Buffer.alloc(2 + PEER_STORAGE_MAX_BYTES + 1);
			payload.writeUInt16BE(PEER_STORAGE_MAX_BYTES + 1, 0);
			expect(() => decodePeerStorageMessage(payload)).to.throw('too large');
		});

		it('rejects truncated and too-short payloads', function () {
			const truncated = Buffer.alloc(7);
			truncated.writeUInt16BE(100, 0);
			expect(() => decodePeerStorageMessage(truncated)).to.throw('truncated');
			expect(() => decodePeerStorageMessage(Buffer.alloc(1))).to.throw(
				'too short'
			);
		});
	});

	describe('feature bit', function () {
		it('defaultFeatures advertises option_provide_storage as optional (bit 43)', function () {
			const flags = LightningNode.defaultFeatures();
			expect(Feature.PROVIDE_STORAGE).to.equal(42);
			expect(flags.isOptional(Feature.PROVIDE_STORAGE)).to.equal(true);
			expect(flags.isCompulsory(Feature.PROVIDE_STORAGE)).to.equal(false);
			expect(flags.hasBit(43)).to.equal(true);
		});

		it('peerStorageEnabled: false strips the bit from advertised features', function () {
			const node = makeNode({
				enableNetworking: true,
				peerStorageEnabled: false
			});
			const advertised = (node as any).peerManager
				.localFeatures as FeatureFlags;
			expect(advertised.hasFeature(Feature.PROVIDE_STORAGE)).to.equal(false);
			node.destroy();
		});

		it('the bit is advertised by default', function () {
			const node = makeNode({ enableNetworking: true });
			const advertised = (node as any).peerManager
				.localFeatures as FeatureFlags;
			expect(advertised.isOptional(Feature.PROVIDE_STORAGE)).to.equal(true);
			node.destroy();
		});
	});

	describe('server side: storing blobs for peers', function () {
		it('stores the blob for a trusted peer and persists it', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const node = makeNode({ storage });
			node.addTrustedPeer(PEER_PK);
			const blob = crypto.randomBytes(64);
			deliverPeerStorage(node, PEER_PK, encodePeerStorageMessage({ blob }));
			const held = (node as any).peerStorageBlobs.get(PEER_PK);
			expect(held.blob.equals(blob)).to.equal(true);
			const persisted = storage.loadPeerStorageBlob(PEER_PK);
			expect(persisted!.blob.equals(blob)).to.equal(true);
			node.destroy();
			storage.close();
		});

		it('stores the blob for a peer with a non-CLOSED channel', function () {
			const node = makeNode();
			const cm = (node as any).channelManager;
			const channelId = Buffer.alloc(32, 1);
			cm.listChannels = (): unknown[] => [
				{
					getChannelId: (): Buffer => channelId,
					getState: (): ChannelState => ChannelState.NORMAL
				}
			];
			cm.getPeerForChannel = (): string => PEER_PK;
			cm.isTrustedPeer = (): boolean => false;
			const blob = crypto.randomBytes(32);
			deliverPeerStorage(node, PEER_PK, encodePeerStorageMessage({ blob }));
			expect(
				(node as any).peerStorageBlobs.get(PEER_PK).blob.equals(blob)
			).to.equal(true);
			node.destroy();
		});

		it('ignores blobs when the only channel with the peer is CLOSED', function () {
			const node = makeNode();
			const cm = (node as any).channelManager;
			const channelId = Buffer.alloc(32, 2);
			cm.listChannels = (): unknown[] => [
				{
					getChannelId: (): Buffer => channelId,
					getState: (): ChannelState => ChannelState.CLOSED
				}
			];
			cm.getPeerForChannel = (): string => PEER_PK;
			cm.isTrustedPeer = (): boolean => false;
			deliverPeerStorage(
				node,
				PEER_PK,
				encodePeerStorageMessage({ blob: crypto.randomBytes(8) })
			);
			expect((node as any).peerStorageBlobs.has(PEER_PK)).to.equal(false);
			node.destroy();
		});

		it('ignores blobs from a stranger (no channels, not trusted)', function () {
			const node = makeNode();
			deliverPeerStorage(
				node,
				PEER_PK,
				encodePeerStorageMessage({ blob: crypto.randomBytes(8) })
			);
			expect((node as any).peerStorageBlobs.has(PEER_PK)).to.equal(false);
			node.destroy();
		});

		it('rate-limits to one accepted blob per peer per 60s', function () {
			const node = makeNode();
			node.addTrustedPeer(PEER_PK);
			const first = Buffer.from('first blob');
			const second = Buffer.from('second blob');
			deliverPeerStorage(
				node,
				PEER_PK,
				encodePeerStorageMessage({ blob: first })
			);
			deliverPeerStorage(
				node,
				PEER_PK,
				encodePeerStorageMessage({ blob: second })
			);
			expect(
				(node as any).peerStorageBlobs.get(PEER_PK).blob.equals(first)
			).to.equal(true);
			// After the window the newer blob replaces the old (one blob per peer)
			(node as any).peerStorageLastAccepted.set(PEER_PK, Date.now() - 61_000);
			deliverPeerStorage(
				node,
				PEER_PK,
				encodePeerStorageMessage({ blob: second })
			);
			expect(
				(node as any).peerStorageBlobs.get(PEER_PK).blob.equals(second)
			).to.equal(true);
			node.destroy();
		});

		it('drops malformed payloads without throwing', function () {
			const node = makeNode();
			node.addTrustedPeer(PEER_PK);
			expect(() =>
				deliverPeerStorage(node, PEER_PK, Buffer.from([0xff]))
			).to.not.throw();
			expect((node as any).peerStorageBlobs.has(PEER_PK)).to.equal(false);
			node.destroy();
		});

		it('ignores blobs entirely when peerStorageEnabled is false', function () {
			const node = makeNode({ peerStorageEnabled: false });
			node.addTrustedPeer(PEER_PK);
			deliverPeerStorage(
				node,
				PEER_PK,
				encodePeerStorageMessage({ blob: crypto.randomBytes(8) })
			);
			expect((node as any).peerStorageBlobs.has(PEER_PK)).to.equal(false);
			node.destroy();
		});
	});

	describe('client side: retrieval handling', function () {
		it('keeps the newest blob per peer and emits peer_storage:retrieved', function () {
			const node = makeNode();
			const events: Array<{ pubkey: string; blob: Buffer }> = [];
			node.on('peer_storage:retrieved', (pubkey: string, blob: Buffer) => {
				events.push({ pubkey, blob });
			});
			const first = Buffer.from('held blob v1');
			const second = Buffer.from('held blob v2');
			(node as any).handlePeerStorageRetrievalMessage(
				PEER_PK,
				encodePeerStorageRetrievalMessage({ blob: first })
			);
			(node as any).handlePeerStorageRetrievalMessage(
				PEER_PK,
				encodePeerStorageRetrievalMessage({ blob: second })
			);
			expect(events.length).to.equal(2);
			expect(events[0].pubkey).to.equal(PEER_PK);
			const retrieved = node.getRetrievedPeerStorage();
			expect(retrieved.length).to.equal(1);
			expect(retrieved[0].peerPubkey).to.equal(PEER_PK);
			expect(retrieved[0].blob.equals(second)).to.equal(true);
			node.destroy();
		});

		it('drops malformed retrieval payloads without throwing or emitting', function () {
			const node = makeNode();
			let emitted = 0;
			node.on('peer_storage:retrieved', () => {
				emitted++;
			});
			expect(() =>
				(node as any).handlePeerStorageRetrievalMessage(
					PEER_PK,
					Buffer.from([0x00])
				)
			).to.not.throw();
			expect(emitted).to.equal(0);
			expect(node.getRetrievedPeerStorage().length).to.equal(0);
			node.destroy();
		});
	});

	describe('client side: distributePeerStorage', function () {
		it('throws on an oversized blob', function () {
			const node = makeNode();
			expect(() =>
				node.distributePeerStorage(Buffer.alloc(PEER_STORAGE_MAX_BYTES + 1))
			).to.throw('too large');
			node.destroy();
		});

		it('sends only to connected peers advertising the feature bit', function () {
			const node = makeNode({ enableNetworking: true });
			const capablePk = '03'.repeat(33);
			const incapablePk = '02'.repeat(33);
			const capableFeatures = FeatureFlags.empty();
			capableFeatures.setOptional(Feature.PROVIDE_STORAGE);
			const sent: Array<{ pubkey: string; type: number; payload: Buffer }> = [];
			(node as any).peerManager = {
				listPeers: (): unknown[] => [
					{ pubkey: capablePk },
					{ pubkey: incapablePk }
				],
				getPeer: (pk: string): unknown => ({
					getRemoteInit: (): unknown => ({
						features: pk === capablePk ? capableFeatures : FeatureFlags.empty()
					})
				}),
				sendToPeer: (pubkey: string, type: number, payload: Buffer): void => {
					sent.push({ pubkey, type, payload });
				},
				destroy: (): void => {}
			};
			const blob = Buffer.from('our scb blob');
			const count = node.distributePeerStorage(blob);
			expect(count).to.equal(1);
			expect(sent.length).to.equal(1);
			expect(sent[0].pubkey).to.equal(capablePk);
			expect(sent[0].type).to.equal(MessageType.PEER_STORAGE);
			expect(
				decodePeerStorageMessage(sent[0].payload).blob.equals(blob)
			).to.equal(true);
			node.destroy();
		});

		it('is a no-op when peerStorageEnabled is false', function () {
			const node = makeNode({
				enableNetworking: true,
				peerStorageEnabled: false
			});
			let sends = 0;
			(node as any).peerManager.sendToPeer = (): void => {
				sends++;
			};
			const count = node.distributePeerStorage(Buffer.from('blob'));
			expect(count).to.equal(0);
			expect(sends).to.equal(0);
			expect((node as any).ourPeerStorageBlob).to.equal(null);
			node.destroy();
		});
	});

	describe('retrieval on reconnect (two nodes over TCP)', function () {
		it('server returns the stored blob via peer_storage_retrieval when the peer reconnects', async function () {
			this.timeout(20_000);
			const aKey = crypto.randomBytes(32);
			const bKey = crypto.randomBytes(32);
			const aPub = getPublicKey(aKey).toString('hex');
			const bPub = getPublicKey(bKey).toString('hex');
			const a = makeNode({ enableNetworking: true, privateKey: aKey });
			const b = makeNode({ enableNetworking: true, privateKey: bKey });
			try {
				await a.listen(0);
				const port = (a as any).peerManager.server.address().port as number;
				// B has no channel yet; trust stands in for the fund relationship.
				a.addTrustedPeer(bPub);

				await b.connectPeer(aPub, '127.0.0.1', port);
				const blob = Buffer.from(`scb-${'x'.repeat(200)}`);
				expect(b.distributePeerStorage(blob)).to.equal(1);
				await waitFor(() => (a as any).peerStorageBlobs.has(bPub));

				const retrieved = new Promise<{ pubkey: string; blob: Buffer }>(
					(resolve) => {
						b.on('peer_storage:retrieved', (pubkey: string, bl: Buffer) => {
							resolve({ pubkey, blob: bl });
						});
					}
				);
				b.disconnectPeer(aPub);
				// Let A observe the close before reconnecting (it rejects duplicates)
				await waitFor(() => (a as any).peerManager.listPeers().length === 0);
				await b.connectPeer(aPub, '127.0.0.1', port);

				const result = await retrieved;
				expect(result.pubkey).to.equal(aPub);
				expect(result.blob.equals(blob)).to.equal(true);
				const held = b.getRetrievedPeerStorage();
				expect(held.length).to.equal(1);
				expect(held[0].peerPubkey).to.equal(aPub);
				expect(held[0].blob.equals(blob)).to.equal(true);
			} finally {
				a.destroy();
				b.destroy();
			}
		});
	});

	describe('BeignetNode: retrieved blob validation', function () {
		const mnemonic =
			'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
		const seed = bip39.mnemonicToSeedSync(mnemonic);

		function makeScbBlob(createdAt: number, withSeed: Buffer = seed): Buffer {
			const backup: IStaticChannelBackup = {
				version: 1,
				network: 'REGTEST',
				createdAt,
				channels: []
			};
			return Buffer.from(encodeScb(backup, withSeed), 'utf8');
		}

		function makeFakeBeignet(): {
			handle: (pubkey: string, blob: Buffer) => void;
			get: () => {
				encoded: string;
				createdAt: number;
				fromPeer: string;
			} | null;
		} {
			// The handler only touches mnemonic/log/_peerRetrievedScb, so it can be
			// exercised without an Electrum-connected BeignetNode instance.
			const fake = {
				mnemonic,
				log: (): void => {},
				_peerRetrievedScb: null
			};
			return {
				handle: (pubkey: string, blob: Buffer): void =>
					(BeignetNode.prototype as any).handleRetrievedPeerStorage.call(
						fake,
						pubkey,
						blob
					),
				get: () =>
					(BeignetNode.prototype as any).getPeerRetrievedBackup.call(fake)
			};
		}

		it('ignores blobs that do not decode as our SCB', function () {
			const fake = makeFakeBeignet();
			fake.handle('peer1', Buffer.from('complete garbage'));
			fake.handle('peer1', makeScbBlob(5000, crypto.randomBytes(64)));
			expect(fake.get()).to.equal(null);
		});

		it('keeps the newest valid blob by createdAt', function () {
			const fake = makeFakeBeignet();
			fake.handle('peer1', makeScbBlob(1000));
			expect(fake.get()!.createdAt).to.equal(1000);
			expect(fake.get()!.fromPeer).to.equal('peer1');
			fake.handle('peer2', makeScbBlob(2000));
			expect(fake.get()!.createdAt).to.equal(2000);
			expect(fake.get()!.fromPeer).to.equal('peer2');
			// A stale blob from a third peer must not clobber the newer one
			fake.handle('peer3', makeScbBlob(1500));
			expect(fake.get()!.createdAt).to.equal(2000);
			expect(fake.get()!.fromPeer).to.equal('peer2');
		});

		it('BeignetNodeOptions accepts peerStorageEnabled', function () {
			const opts: import('../../src/cli/beignet-node').BeignetNodeOptions = {
				network: 'regtest',
				peerStorageEnabled: false
			};
			expect(opts.peerStorageEnabled).to.equal(false);
		});
	});

	describe('storage round-trip', function () {
		it('schema version is 5 with the peer_storage_blobs migration', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			expect(SqliteStorage.CURRENT_SCHEMA_VERSION).to.equal(5);
			expect(storage.getSchemaVersion()).to.equal(5);
			storage.close();
		});

		it('saves, overwrites, loads, and deletes a blob', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const first = crypto.randomBytes(48);
			const second = crypto.randomBytes(48);
			storage.savePeerStorageBlob(PEER_PK, first, 111);
			storage.savePeerStorageBlob(PEER_PK, second, 222);
			const loaded = storage.loadPeerStorageBlob(PEER_PK);
			expect(loaded!.blob.equals(second)).to.equal(true);
			expect(loaded!.receivedAt).to.equal(222);
			expect(storage.loadPeerStorageBlob('03'.repeat(33))).to.equal(null);
			storage.deletePeerStorageBlob(PEER_PK);
			expect(storage.loadPeerStorageBlob(PEER_PK)).to.equal(null);
			storage.close();
		});

		it('keeps blobs encrypted at rest', function () {
			const dbPath = tmpDbPath();
			const key = crypto.randomBytes(32);
			const marker = 'peer-storage-cleartext-marker-1234567890';
			try {
				const storage = new SqliteStorage(dbPath, undefined, {
					encryptionKey: key
				});
				storage.open();
				storage.savePeerStorageBlob(PEER_PK, Buffer.from(marker), Date.now());
				const loaded = storage.loadPeerStorageBlob(PEER_PK);
				expect(loaded!.blob.toString()).to.equal(marker);
				storage.checkpoint();
				storage.close();

				const raw = fs.readFileSync(dbPath, 'latin1');
				expect(raw).to.include('enc1:');
				expect(raw).to.not.include(marker);
				// The stored form is base64 before encryption; that must not leak either
				expect(raw).to.not.include(Buffer.from(marker).toString('base64'));

				// Round-trips through a reopen with the same key
				const reopened = new SqliteStorage(dbPath, undefined, {
					encryptionKey: key
				});
				reopened.open();
				expect(reopened.loadPeerStorageBlob(PEER_PK)!.blob.toString()).to.equal(
					marker
				);
				reopened.close();
			} finally {
				for (const suffix of ['', '-wal', '-shm']) {
					fs.rmSync(dbPath + suffix, { force: true });
				}
			}
		});
	});
});
