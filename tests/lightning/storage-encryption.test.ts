import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as bip39 from 'bip39';
import {
	deriveStorageKey,
	encryptValue,
	decryptValue,
	isEncryptedValue,
	StorageEncryptedError
} from '../../src/lightning/storage/encryption';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	DEFAULT_CHANNEL_CONFIG,
	ChannelState
} from '../../src/lightning/channel/types';
import {
	ShaChainStore,
	MAX_INDEX,
	generateFromSeed
} from '../../src/lightning/keys/shachain';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { BeignetNode } from '../../src/cli/beignet-node';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`seed-${id}`))
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
		firstPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(makeSeed(99), MAX_INDEX)
		)
	};
}

function createTestChannelState() {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(makeSeed(1)),
		localPerCommitmentSeed: makeSeed(3)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.localBalanceMsat = 800_000_000n;
	state.remoteBalanceMsat = 200_000_000n;
	state.remoteBasepoints = makeBasepoints(makeSeed(2));
	state.remoteCurrentPerCommitmentPoint =
		state.remoteBasepoints.firstPerCommitmentPoint;
	return state;
}

/** Read the raw DB bytes including a WAL file if one is still present. */
function readRawDbBytes(dbPath: string): string {
	let raw = fs.readFileSync(dbPath, 'latin1');
	const walPath = `${dbPath}-wal`;
	if (fs.existsSync(walPath)) {
		raw += fs.readFileSync(walPath, 'latin1');
	}
	return raw;
}

const TEST_KEY = deriveStorageKey(
	Buffer.from('storage-encryption-test-secret')
);

describe('Storage Encryption', function () {
	describe('encryption module', function () {
		it('round-trips encrypt/decrypt', function () {
			const plaintext = 'hello lightning secrets 0123456789abcdef';
			const encrypted = encryptValue(TEST_KEY, plaintext);
			expect(encrypted.startsWith('enc1:')).to.be.true;
			expect(encrypted).to.not.include(plaintext);
			expect(decryptValue(TEST_KEY, encrypted)).to.equal(plaintext);
		});

		it('produces distinct ciphertexts per call (random IV)', function () {
			const a = encryptValue(TEST_KEY, 'same-plaintext');
			const b = encryptValue(TEST_KEY, 'same-plaintext');
			expect(a).to.not.equal(b);
			expect(decryptValue(TEST_KEY, a)).to.equal('same-plaintext');
			expect(decryptValue(TEST_KEY, b)).to.equal('same-plaintext');
		});

		it('detects tampering via the auth tag', function () {
			const encrypted = encryptValue(TEST_KEY, 'tamper-me');
			const payload = Buffer.from(encrypted.slice('enc1:'.length), 'base64');
			// Flip a ciphertext byte (past the 12-byte IV and 16-byte tag)
			payload[payload.length - 1] ^= 0x01;
			const tampered = 'enc1:' + payload.toString('base64');
			expect(() => decryptValue(TEST_KEY, tampered)).to.throw();
		});

		it('rejects decryption with the wrong key', function () {
			const other = deriveStorageKey(Buffer.from('another-secret'));
			const encrypted = encryptValue(TEST_KEY, 'secret');
			expect(() => decryptValue(other, encrypted)).to.throw();
		});

		it('isEncryptedValue recognizes the enc1 prefix', function () {
			expect(isEncryptedValue(encryptValue(TEST_KEY, 'x'))).to.be.true;
			expect(isEncryptedValue('plaintext')).to.be.false;
			expect(isEncryptedValue('{"json":true}')).to.be.false;
			expect(isEncryptedValue('')).to.be.false;
		});

		it('deriveStorageKey is deterministic and secret-dependent', function () {
			const secret = crypto.randomBytes(64);
			const k1 = deriveStorageKey(secret);
			const k2 = deriveStorageKey(secret);
			const k3 = deriveStorageKey(crypto.randomBytes(64));
			expect(k1.length).to.equal(32);
			expect(k1.equals(k2)).to.be.true;
			expect(k1.equals(k3)).to.be.false;
		});
	});

	describe('SqliteStorage with encryptionKey', function () {
		let tmpDir: string;
		let dbPath: string;

		beforeEach(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-enc-'));
			dbPath = path.join(tmpDir, 'test.db');
		});

		afterEach(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		function openEncrypted(): SqliteStorage {
			const storage = new SqliteStorage(dbPath, undefined, {
				encryptionKey: TEST_KEY
			});
			storage.open({ synchronous: 'NORMAL' });
			return storage;
		}

		it('round-trips channel state, preimage and payment secret', function () {
			const storage = openEncrypted();
			const state = createTestChannelState();
			const channelId = state.channelId!.toString('hex');
			storage.saveChannel(channelId, state, '02'.repeat(33));

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			storage.savePreimage(paymentHash.toString('hex'), preimage);

			const secret = crypto.randomBytes(32);
			storage.savePaymentSecret(paymentHash.toString('hex'), secret);

			const loadedChannel = storage.loadChannel(channelId);
			expect(loadedChannel).to.not.be.null;
			expect(loadedChannel!.state.channelId!.equals(state.channelId!)).to.be
				.true;
			expect(loadedChannel!.state.localBalanceMsat).to.equal(800_000_000n);
			expect(loadedChannel!.peerPubkey).to.equal('02'.repeat(33));
			expect(storage.loadAllChannels()).to.have.lengthOf(1);

			const loadedPreimage = storage.loadPreimage(paymentHash.toString('hex'));
			expect(loadedPreimage!.equals(preimage)).to.be.true;
			expect(storage.loadAllPreimages()[0].preimage.equals(preimage)).to.be
				.true;

			const secrets = storage.loadAllPaymentSecrets();
			expect(secrets).to.have.lengthOf(1);
			expect(secrets[0].secret.equals(secret)).to.be.true;
			storage.close();
		});

		it('round-trips HTLC onion shared secrets encrypted', function () {
			const storage = openEncrypted();
			const secret = crypto.randomBytes(32);
			storage.saveHtlcSharedSecret('chan1:5', secret);

			const loaded = storage.loadAllHtlcSharedSecrets();
			expect(loaded).to.have.lengthOf(1);
			expect(loaded[0].key).to.equal('chan1:5');
			expect(loaded[0].secret.equals(secret)).to.be.true;
			storage.close();

			const raw = fs.readFileSync(dbPath);
			expect(raw.includes(secret.toString('hex'))).to.be.false;
		});

		it('round-trips channel key indices and computes the next index', function () {
			const storage = openEncrypted();
			storage.saveChannelKeyIndex('chan-a', 1);
			storage.saveChannelKeyIndex('chan-b', 7);
			storage.saveChannelKeyIndex('chan-c', 3);
			expect(storage.loadChannelKeyIndex('chan-b')).to.equal(7);
			expect(storage.loadChannelKeyIndex('missing')).to.be.null;
			expect(storage.loadNextChannelIndex()).to.equal(8);
			storage.close();
		});

		it('keeps secrets out of the raw database file', function () {
			const storage = openEncrypted();
			// Distinctive markers that must never hit disk in cleartext
			const preimage = Buffer.from('11deadbeefcafe22'.repeat(4), 'hex');
			storage.savePreimage('aa'.repeat(32), preimage);
			storage.savePaymentSecret(
				'bb'.repeat(32),
				Buffer.from('33feedfacebeef44'.repeat(4), 'hex')
			);
			storage.checkpoint();
			storage.close();

			const raw = readRawDbBytes(dbPath);
			expect(raw).to.include('enc1:');
			expect(raw).to.not.include('11deadbeefcafe22'.repeat(4));
			expect(raw).to.not.include('33feedfacebeef44'.repeat(4));
			// Lookup keys stay plaintext by design
			expect(raw).to.include('aa'.repeat(32));
		});

		it('migrates a plaintext database in place on open', function () {
			const plain = new SqliteStorage(dbPath);
			plain.open({ synchronous: 'NORMAL' });
			const state = createTestChannelState();
			const channelId = state.channelId!.toString('hex');
			plain.saveChannel(channelId, state, '03'.repeat(33));
			const preimage = Buffer.from('55feedc0dedead66'.repeat(4), 'hex');
			plain.savePreimage('cc'.repeat(32), preimage);
			plain.saveChannelKeyIndex('chan-a', 4);
			plain.checkpoint();
			plain.close();

			// Plaintext marker present before migration
			expect(readRawDbBytes(dbPath)).to.include('55feedc0dedead66'.repeat(4));

			const storage = openEncrypted();
			const loadedChannel = storage.loadChannel(channelId);
			expect(loadedChannel!.state.channelId!.equals(state.channelId!)).to.be
				.true;
			expect(storage.loadPreimage('cc'.repeat(32))!.equals(preimage)).to.be
				.true;
			expect(storage.loadChannelKeyIndex('chan-a')).to.equal(4);
			expect(storage.loadNextChannelIndex()).to.equal(5);
			storage.checkpoint();
			storage.close();

			const raw = readRawDbBytes(dbPath);
			expect(raw).to.include('enc1:');
			expect(raw).to.not.include('55feedc0dedead66'.repeat(4));

			// Reopen is idempotent: rows stay readable
			const again = openEncrypted();
			expect(again.loadPreimage('cc'.repeat(32))!.equals(preimage)).to.be.true;
			again.close();
		});

		it('fails clearly when an encrypted database is opened without a key', function () {
			const storage = openEncrypted();
			storage.savePreimage('dd'.repeat(32), crypto.randomBytes(32));
			storage.saveChannel(
				'ee'.repeat(32),
				createTestChannelState(),
				'02'.repeat(33)
			);
			storage.close();

			const corruptions: unknown[] = [];
			const keyless = new SqliteStorage(dbPath, (err) => corruptions.push(err));
			keyless.open({ synchronous: 'NORMAL' });
			expect(() => keyless.loadPreimage('dd'.repeat(32))).to.throw(
				'storage is encrypted; encryptionKey required'
			);
			// loadAll* must propagate the missing-key error, not skip rows as corrupt
			expect(() => keyless.loadAllPreimages()).to.throw(StorageEncryptedError);
			expect(() => keyless.loadAllChannels()).to.throw(
				'storage is encrypted; encryptionKey required'
			);
			expect(corruptions).to.have.lengthOf(0);
			keyless.close();
		});

		it('still reports genuinely corrupt rows via onCorruptRow', function () {
			const storage = openEncrypted();
			storage.saveChannel(
				'ff'.repeat(32),
				createTestChannelState(),
				'02'.repeat(33)
			);
			storage.close();

			const corruptions: unknown[] = [];
			const reopened = new SqliteStorage(
				dbPath,
				(err) => corruptions.push(err),
				{ encryptionKey: TEST_KEY }
			);
			reopened.open({ synchronous: 'NORMAL' });
			// Tamper with the stored ciphertext so the auth check fails
			reopened.transaction(() => {
				(
					reopened as unknown as {
						db: {
							prepare: (sql: string) => {
								run: (...args: unknown[]) => void;
							};
						};
					}
				).db
					.prepare('UPDATE channels SET state_json = ? WHERE channel_id = ?')
					.run(
						'enc1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
						'ff'.repeat(32)
					);
			});
			expect(reopened.loadAllChannels()).to.have.lengthOf(0);
			expect(corruptions).to.have.lengthOf(1);
			reopened.close();
		});

		it('records shachain-bearing state without leaking JSON structure', function () {
			// The serialized channel JSON contains recognizable field names; none
			// should appear in the raw file when encryption is on
			const storage = openEncrypted();
			const state = createTestChannelState();
			const store = new ShaChainStore();
			store.addSecret(MAX_INDEX, generateFromSeed(makeSeed(5), MAX_INDEX));
			storage.saveChannel(
				state.channelId!.toString('hex'),
				state,
				'02'.repeat(33)
			);
			storage.checkpoint();
			storage.close();
			const raw = readRawDbBytes(dbPath);
			expect(raw).to.not.include('localBalanceMsat');
			expect(raw).to.not.include('fundingSatoshis');
		});
	});

	describe('BeignetNode storage encryption wiring', function () {
		const MNEMONIC =
			'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
		let tmpDir: string;

		beforeEach(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-node-enc-'));
		});

		afterEach(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		it('encrypts the node database by default with the BIP39-seed-derived key', async function () {
			this.timeout(60_000);
			const marker = 'unique-invoice-marker-3f9a1c';
			const node = await BeignetNode.create({
				mnemonic: MNEMONIC,
				network: 'regtest',
				dataDir: tmpDir,
				logLevel: 'silent',
				rapidGossipSync: false,
				autoGossipSync: false
			});
			let paymentHash: string;
			try {
				const invoice = node.createInvoice(1000, marker);
				paymentHash = invoice.paymentHash;
			} finally {
				await node.destroy();
			}

			const dbPath = path.join(tmpDir, 'regtest.db');
			const raw = readRawDbBytes(dbPath);
			expect(raw).to.include('enc1:');
			expect(raw).to.not.include(marker);

			// The key BeignetNode derives is HKDF over the BIP39 seed of the
			// mnemonic - opening with that key must read the invoice back
			const key = deriveStorageKey(bip39.mnemonicToSeedSync(MNEMONIC));
			const storage = new SqliteStorage(dbPath, undefined, {
				encryptionKey: key
			});
			storage.open({ synchronous: 'NORMAL' });
			const invoices = storage.loadAllInvoices();
			const found = invoices.find((i) => i.paymentHashHex === paymentHash);
			expect(found, 'invoice readable with seed-derived key').to.not.be
				.undefined;
			expect(found!.invoice.description).to.equal(marker);
			storage.close();
		});

		it('storageEncryption: false keeps storage in plaintext', async function () {
			this.timeout(60_000);
			const marker = 'plaintext-invoice-marker-7b2e4d';
			const node = await BeignetNode.create({
				mnemonic: MNEMONIC,
				network: 'regtest',
				dataDir: tmpDir,
				logLevel: 'silent',
				rapidGossipSync: false,
				autoGossipSync: false,
				storageEncryption: false
			});
			try {
				node.createInvoice(1000, marker);
			} finally {
				await node.destroy();
			}

			const raw = readRawDbBytes(path.join(tmpDir, 'regtest.db'));
			expect(raw).to.include(marker);
			expect(raw).to.not.include('enc1:');
		});
	});
});
