import { expect } from 'chai';
import sinon from 'sinon';
import Database from 'better-sqlite3';
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

// Electrum intentionally unreachable: nothing below needs a live chain, and a
// refused loopback connect returns ECONNREFUSED instantly. Without this the
// regtest default in src/cli/beignet-node.ts is a remote public host, so these
// nominally offline tests dial a third party over the internet and fail
// whenever it is unreachable. BeignetNode.init tolerates a failed connect:
// resolveWalletSweepScript falls back to a locally derived index-0 address.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

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

		it('keeps node metadata out of the raw database file', function () {
			const storage = openEncrypted();
			const row = JSON.stringify({
				id: 'swap-1',
				paymentHash: '77'.repeat(32),
				amountSat: 123456789
			});
			storage.saveMetadata('swap:row:swap-1', row);
			// A ledger tombstone is an empty value.
			storage.saveMetadata('swap:row:gone', '');
			expect(storage.loadMetadata('swap:row:swap-1')).to.equal(row);
			expect(storage.loadMetadata('swap:row:gone')).to.equal('');
			expect(storage.loadMetadata('swap:row:missing')).to.equal(null);
			storage.checkpoint();
			storage.close();

			const raw = readRawDbBytes(dbPath);
			expect(raw).to.not.include('77'.repeat(32));
			expect(raw).to.not.include('amountSat');
			expect(raw).to.include('swap:row:swap-1');
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
			storage.saveMetadata('jit:held', '[]');
			storage.close();

			const corruptions: unknown[] = [];
			const keyless = new SqliteStorage(dbPath, (err) => corruptions.push(err));
			keyless.open({ synchronous: 'NORMAL' });
			expect(() => keyless.loadPreimage('dd'.repeat(32))).to.throw(
				'storage is encrypted; encryptionKey required'
			);
			expect(() => keyless.loadMetadata('jit:held')).to.throw(
				StorageEncryptedError
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

		describe('the encryption pass on open', function () {
			/** The sensitive tables and columns, as the storage declares them. */
			const SENSITIVE = (
				SqliteStorage as unknown as {
					ENCRYPTED_COLUMNS: ReadonlyArray<{
						table: string;
						pk: string;
						columns: string[];
					}>;
				}
			).ENCRYPTED_COLUMNS;

			function rawDb(storage: SqliteStorage): Database.Database {
				return (storage as unknown as { db: Database.Database }).db;
			}

			/**
			 * Open with the key, counting per table the rows the encryption
			 * pass selects. On a database an earlier open already migrated,
			 * the pass is the only code that calls all() during open, so the
			 * statements are wrapped as they are prepared.
			 */
			function openCountingSelected(): {
				storage: SqliteStorage;
				selected: Record<string, number>;
			} {
				const storage = new SqliteStorage(dbPath, undefined, {
					encryptionKey: TEST_KEY
				});
				const db = rawDb(storage);
				const prepare = db.prepare.bind(db);
				const selected: Record<string, number> = {};
				const stub = sinon.stub(db, 'prepare').callsFake((source: string) => {
					const statement = prepare(source) as unknown as {
						all: (...params: unknown[]) => unknown[];
					};
					const table = /\bFROM (\w+)/.exec(source)?.[1];
					const all = statement.all.bind(statement);
					statement.all = (...params: unknown[]): unknown[] => {
						const rows = all(...params);
						if (table) selected[table] = (selected[table] ?? 0) + rows.length;
						return rows;
					};
					return statement;
				});
				try {
					storage.open({ synchronous: 'NORMAL' });
				} finally {
					stub.restore();
				}
				return { storage, selected };
			}

			/** Rows selected per sensitive table: the counts given, else none. */
			function selectedRows(
				plaintextRows: Record<string, number>
			): Record<string, number> {
				return Object.fromEntries(
					SENSITIVE.map(({ table }) => [table, plaintextRows[table] ?? 0])
				);
			}

			/** Every sensitive value as stored, by table, row key and column. */
			function storedValues(): Record<string, unknown> {
				const db = new Database(dbPath);
				try {
					const values: Record<string, unknown> = {};
					for (const { table, pk, columns } of SENSITIVE) {
						const rows = db
							.prepare(`SELECT ${pk}, ${columns.join(', ')} FROM ${table}`)
							.all() as Array<Record<string, unknown>>;
						for (const row of rows) {
							for (const col of columns) {
								values[`${table}/${String(row[pk])}/${col}`] = row[col];
							}
						}
					}
					return values;
				} finally {
					db.close();
				}
			}

			it('encrypts legacy plaintext rows of every storage class', function () {
				const plain = new SqliteStorage(dbPath);
				plain.open({ synchronous: 'NORMAL' });
				const state = createTestChannelState();
				const channelId = state.channelId!.toString('hex');
				plain.saveChannel(channelId, state, '03'.repeat(33));
				const preimage = crypto.randomBytes(32);
				plain.savePreimage('aa'.repeat(32), preimage);
				// channel_index is an INTEGER column, so plaintext rows hold integers.
				plain.saveChannelKeyIndex('chan-a', 4);
				const inChannelId = crypto.randomBytes(32);
				plain.saveForwardedHtlc('out:1', inChannelId, 7n);
				const pathId = crypto.randomBytes(32);
				plain.saveOffer('offer-1', 'lno1withpath', pathId, 1000);
				plain.saveOffer('offer-2', 'lno1nopath', null, 2000);
				plain.saveMetadata('swap:row:legacy', '{"id":"legacy"}');
				// A BLOB where TEXT belongs: nothing writes one today, but the
				// per-column check would rewrite it, so the pass must select it.
				rawDb(plain)
					.prepare('INSERT INTO wallet_data (key, value) VALUES (?, ?)')
					.run('legacy-blob', Buffer.from('legacy wallet bytes'));
				plain.close();

				const { storage, selected } = openCountingSelected();
				expect(selected).to.deep.equal(
					selectedRows({
						channels: 1,
						preimages: 1,
						channel_key_indices: 1,
						forwarded_htlcs: 1,
						offers: 2,
						wallet_data: 1,
						metadata: 1
					})
				);
				expect(storage.loadMetadata('swap:row:legacy')).to.equal(
					'{"id":"legacy"}'
				);
				expect(
					storage
						.loadChannel(channelId)!
						.state.channelId!.equals(state.channelId!)
				).to.equal(true);
				expect(
					storage.loadPreimage('aa'.repeat(32))!.equals(preimage)
				).to.equal(true);
				expect(storage.loadChannelKeyIndex('chan-a')).to.equal(4);
				const [forwarded] = storage.loadAllForwardedHtlcs();
				expect(forwarded.inChannelId.equals(inChannelId)).to.equal(true);
				expect(forwarded.inHtlcId).to.equal(7n);
				const offers = storage
					.loadAllOffers()
					.sort((a, b) => a.createdAt - b.createdAt);
				expect(offers.map((offer) => offer.encoded)).to.deep.equal([
					'lno1withpath',
					'lno1nopath'
				]);
				expect(offers[0].pathId!.equals(pathId)).to.equal(true);
				expect(offers[1].pathId).to.equal(null);
				storage.close();

				const stored = storedValues();
				// A NULL stays NULL; every other value is ciphertext now.
				expect(stored['offers/offer-2/path_id']).to.equal(null);
				for (const [where, value] of Object.entries(stored)) {
					if (value === null) continue;
					expect(
						typeof value === 'string' && isEncryptedValue(value),
						where
					).to.equal(true);
				}
				expect(
					decryptValue(
						TEST_KEY,
						stored['wallet_data/legacy-blob/value'] as string
					)
				).to.equal('legacy wallet bytes');
			});

			it('selects no row of an encrypted database, and rewrites none, on every reopen', function () {
				const storage = openEncrypted();
				const state = createTestChannelState();
				storage.saveChannel(
					state.channelId!.toString('hex'),
					state,
					'02'.repeat(33)
				);
				const preimage = crypto.randomBytes(32);
				storage.savePreimage('bb'.repeat(32), preimage);
				storage.saveChannelKeyIndex('chan-b', 9);
				storage.saveForwardedHtlc('out:2', crypto.randomBytes(32), 3n);
				storage.saveOffer(
					'offer-3',
					'lno1encrypted',
					crypto.randomBytes(32),
					3000
				);
				storage.savePeerStorageBlob(
					'02'.repeat(33),
					crypto.randomBytes(64),
					4000
				);
				storage.saveMetadata('blockHeight', '800000');
				storage.close();
				const before = storedValues();

				for (const reopen of [1, 2]) {
					const again = openCountingSelected();
					expect(again.selected, `reopen ${reopen}`).to.deep.equal(
						selectedRows({})
					);
					expect(
						again.storage.loadPreimage('bb'.repeat(32))!.equals(preimage)
					).to.equal(true);
					expect(again.storage.loadChannelKeyIndex('chan-b')).to.equal(9);
					expect(again.storage.loadMetadata('blockHeight')).to.equal('800000');
					again.storage.close();
				}
				// Same ciphertext byte for byte: nothing was encrypted twice.
				expect(storedValues()).to.deep.equal(before);
			});

			it('in mixed tables, rewrites only the plaintext rows and columns', function () {
				const hashA = 'a1'.repeat(32);
				const hashB = 'b2'.repeat(32);
				const encrypted = openEncrypted();
				const preimageA = crypto.randomBytes(32);
				encrypted.savePreimage(hashA, preimageA);
				encrypted.saveForwardedHtlc('out:a', crypto.randomBytes(32), 1n);
				const pathId = crypto.randomBytes(32);
				encrypted.saveOffer('offer-m', 'lno1mixed', pathId, 5000);
				encrypted.close();

				// An open without the key writes plaintext beside the ciphertext.
				const plain = new SqliteStorage(dbPath);
				plain.open({ synchronous: 'NORMAL' });
				const preimageB = crypto.randomBytes(32);
				plain.savePreimage(hashB, preimageB);
				plain.saveForwardedHtlc('out:b', crypto.randomBytes(32), 2n);
				plain.saveChannelKeyIndex('chan-m', 3);
				// One row with an encrypted column beside a plaintext one.
				rawDb(plain)
					.prepare('UPDATE offers SET path_id = ? WHERE offer_id = ?')
					.run(pathId.toString('hex'), 'offer-m');
				plain.close();
				const before = storedValues();

				const { storage, selected } = openCountingSelected();
				expect(selected).to.deep.equal(
					selectedRows({
						preimages: 1,
						forwarded_htlcs: 1,
						offers: 1,
						channel_key_indices: 1
					})
				);
				storage.close();

				const after = storedValues();
				// Ciphertext that was already there is left as it was ...
				for (const where of [
					`preimages/${hashA}/preimage`,
					'forwarded_htlcs/out:a/in_channel_id',
					'forwarded_htlcs/out:a/in_htlc_id',
					'offers/offer-m/encoded'
				]) {
					expect(isEncryptedValue(before[where] as string), where).to.equal(
						true
					);
					expect(after[where], where).to.equal(before[where]);
				}
				// ... and every value is ciphertext now.
				for (const [where, value] of Object.entries(after)) {
					expect(
						typeof value === 'string' && isEncryptedValue(value),
						where
					).to.equal(true);
				}

				const again = openCountingSelected();
				expect(again.selected).to.deep.equal(selectedRows({}));
				expect(again.storage.loadPreimage(hashA)!.equals(preimageA)).to.equal(
					true
				);
				expect(again.storage.loadPreimage(hashB)!.equals(preimageB)).to.equal(
					true
				);
				const [offer] = again.storage.loadAllOffers();
				expect(offer.encoded).to.equal('lno1mixed');
				expect(offer.pathId!.equals(pathId)).to.equal(true);
				expect(
					again.storage
						.loadAllForwardedHtlcs()
						.map((htlc) => htlc.inHtlcId)
						.sort()
				).to.deep.equal([1n, 2n]);
				expect(again.storage.loadChannelKeyIndex('chan-m')).to.equal(3);
				again.storage.close();
			});

			describe('scrubbing the migrated plaintext', function () {
				// Forty held parts serialize past 10 KB, so each value spans
				// overflow pages that the encrypted rewrite frees.
				const digest = (label: string): string =>
					crypto.createHash('sha256').update(label).digest('hex');
				const parts = Array.from({ length: 40 }, (_, i) => ({
					inChannelIdHex: digest(`channel-${i}`),
					inHtlcId: String(i),
					paymentHashHex: digest(`payment-${i}`),
					amountMsat: String(918_273_645_000 + i),
					incomingCltvExpiry: 800_000 + i,
					disposition: 'fail'
				}));
				const held = JSON.stringify(parts);
				const wallet = JSON.stringify({ utxos: parts });
				const secrets = parts.flatMap((part) => [
					part.paymentHashHex,
					part.inChannelIdHex,
					part.amountMsat
				]);

				/** The secrets readable in the raw database and WAL files. */
				function leaked(): string[] {
					const raw = readRawDbBytes(dbPath);
					return secrets.filter((secret) => raw.includes(secret));
				}

				function savePlaintext(): void {
					expect(held.length).to.be.greaterThan(10_000);
					const plain = new SqliteStorage(dbPath);
					plain.open({ synchronous: 'NORMAL' });
					plain.saveMetadata('jit:held', held);
					plain.saveWalletData('wallet', wallet);
					plain.close();
					expect(leaked()).to.deep.equal(secrets);
				}

				function scrubPending(storage: SqliteStorage): boolean {
					const row = rawDb(storage)
						.prepare('SELECT 1 FROM encryption_scrub_pending')
						.get();
					return row !== undefined;
				}

				it('leaves no migrated plaintext in the database or WAL file', function () {
					savePlaintext();
					const storage = openEncrypted();
					// Straight after open, before the caller checkpoints or
					// closes; the WAL is read alongside the file.
					expect(leaked()).to.deep.equal([]);
					expect(scrubPending(storage)).to.equal(false);
					expect(storage.loadMetadata('jit:held')).to.equal(held);
					expect(storage.loadWalletData('wallet')).to.equal(wallet);
					storage.checkpoint();
					storage.close();
					expect(leaked()).to.deep.equal([]);
					const stored = storedValues();
					expect(isEncryptedValue(stored['metadata/jit:held/value'] as string))
						.to.be.true;
					expect(isEncryptedValue(stored['wallet_data/wallet/value'] as string))
						.to.be.true;

					const again = openEncrypted();
					expect(again.loadMetadata('jit:held')).to.equal(held);
					expect(again.loadWalletData('wallet')).to.equal(wallet);
					again.close();
					expect(storedValues()).to.deep.equal(stored);
					expect(leaked()).to.deep.equal([]);
				});

				it('retries a failed VACUUM on the next open', function () {
					savePlaintext();
					const storage = new SqliteStorage(dbPath, undefined, {
						encryptionKey: TEST_KEY
					});
					const db = rawDb(storage);
					const exec = db.exec.bind(db);
					const stub = sinon.stub(db, 'exec').callsFake((source: string) => {
						if (source === 'VACUUM') {
							throw new Error('SQLITE_FULL: database or disk is full');
						}
						return exec(source);
					});
					try {
						storage.open({ synchronous: 'NORMAL' });
					} finally {
						stub.restore();
					}
					expect(scrubPending(storage)).to.equal(true);
					expect(storage.loadMetadata('jit:held')).to.equal(held);
					storage.checkpoint();
					storage.close();
					expect(leaked()).to.not.be.empty;

					const again = openEncrypted();
					expect(leaked()).to.deep.equal([]);
					expect(scrubPending(again)).to.equal(false);
					expect(again.loadMetadata('jit:held')).to.equal(held);
					expect(again.loadWalletData('wallet')).to.equal(wallet);
					again.close();
				});

				it('retries a checkpoint a reader held back on the next open', function () {
					savePlaintext();
					// A read transaction from before the migration pins the
					// plaintext pages, so the checkpoint cannot copy over them.
					const reader = new Database(dbPath);
					reader.exec('BEGIN');
					reader.prepare('SELECT value FROM metadata').get();
					const storage = new SqliteStorage(dbPath, undefined, {
						encryptionKey: TEST_KEY
					});
					const db = rawDb(storage);
					const pragma = db.pragma.bind(db);
					// No busy timeout, so the blocked checkpoint returns at once
					// instead of after five seconds.
					const stub = sinon
						.stub(db, 'pragma')
						.callsFake((source: string, options?: Database.PragmaOptions) =>
							pragma(
								source === 'busy_timeout = 5000' ? 'busy_timeout = 0' : source,
								options
							)
						);
					try {
						storage.open({ synchronous: 'NORMAL' });
					} finally {
						stub.restore();
					}
					expect(scrubPending(storage)).to.equal(true);
					expect(leaked()).to.not.be.empty;
					reader.exec('COMMIT');
					reader.close();

					// The first connection stays open, so no close-time
					// checkpoint can do the scrub's work.
					const again = openEncrypted();
					expect(leaked()).to.deep.equal([]);
					expect(scrubPending(again)).to.equal(false);
					expect(again.loadMetadata('jit:held')).to.equal(held);
					expect(again.loadWalletData('wallet')).to.equal(wallet);
					again.close();
					storage.close();
				});
			});
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
				autoGossipSync: false,
				...OFFLINE_ELECTRUM
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
				storageEncryption: false,
				...OFFLINE_ELECTRUM
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
