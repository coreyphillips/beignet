import { expect } from 'chai';
import Database from 'better-sqlite3';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeTxCompleteMessage } from '../../src/lightning/message/interactive-tx';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { localFundingSecret, opening, wallet } from './helpers/final-opening';
import { seedFor } from './helpers/taproot-revoked-fixture';

function peerPromise(id: string, first = 700): Buffer {
	const publicNonce = (n: number): Buffer =>
		Buffer.concat([getPublicKey(seedFor(n)), getPublicKey(seedFor(n + 1))]);
	return encodeTxCompleteMessage({
		channelId: Buffer.from(id, 'hex'),
		commitNonces: { current: publicNonce(first), next: publicNonce(first + 2) }
	});
}

describe('Device authority for opening nonces', () => {
	let directory: string;
	let file: string;
	let copy: string;

	beforeEach(() => {
		directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-opening-authority-')
		);
		file = path.join(directory, 'regtest.db');
		copy = path.join(directory, 'backup.db');
	});
	afterEach(() => {
		fs.rmSync(directory, { recursive: true, force: true });
	});

	it('creates a private signer only at original provisioning and keeps it after restart', () => {
		SqliteStorage.createFinalWallet(file, wallet).close();
		const signer = file + '.opening-signer';
		expect(fs.statSync(signer).mode & 0o077).to.equal(0);
		const original = SqliteStorage.openFinalWallet(file, wallet);
		const c = opening();
		let bytes: Buffer;
		try {
			original.rememberFinalOpening(c);
			expect(original.loadFinalLocalTxComplete(c.channelId)).to.equal(null);
			bytes = original.finalOpeningTxComplete(c.channelId, localFundingSecret);
		} finally {
			original.close();
		}
		const reopened = SqliteStorage.openFinalWallet(file, wallet);
		try {
			expect(reopened.loadFinalLocalTxComplete(c.channelId)).to.deep.equal(
				bytes
			);
			reopened.rememberFinalOpening(opening(true));
		} finally {
			reopened.close();
		}
	});

	it('preserves backup lineage across independent wallet creations with identical credentials', async () => {
		const first = SqliteStorage.createFinalWallet(file, wallet);
		const other = SqliteStorage.createFinalWallet(
			path.join(directory, 'other.db'),
			wallet
		);
		const c = opening();
		const repeated = path.join(directory, 'repeated.db');
		try {
			first.rememberFinalOpening(c);
			await first.backup(copy);
			await first.backup(copy);
			await first.backup(repeated);
			other.rememberFinalOpening(opening(true));
			let rejected = false;
			await other.backup(copy).catch(() => {
				rejected = true;
			});
			expect(rejected).to.equal(true);
			const previous = SqliteStorage.openFinalWallet(copy, wallet);
			try {
				expect(previous.loadFinalOpenings()).to.deep.equal([c]);
				await previous.backup(repeated);
			} finally {
				previous.close();
			}
			const same = SqliteStorage.openFinalWallet(repeated, wallet);
			try {
				expect(same.loadFinalOpenings()).to.deep.equal([c]);
			} finally {
				same.close();
			}
		} finally {
			first.close();
			other.close();
		}
	});

	it('opens and copies the previous final wallet format for recovery without a device binding', async () => {
		const c = opening();
		const store = SqliteStorage.createFinalWallet(file, wallet);
		const peer = peerPromise(c.channelId);
		try {
			store.rememberFinalOpening(c);
			store.rememberFinalPeerTxComplete(c.channelId, peer);
			await store.backup(copy);
		} finally {
			store.close();
		}
		const oldFormat = new Database(copy, { fileMustExist: true });
		try {
			oldFormat.exec(
				'ALTER TABLE final_wallet_format DROP COLUMN signer_binding'
			);
		} finally {
			oldFormat.close();
		}
		const destination = path.join(directory, 'from-previous.db');
		const restored = SqliteStorage.openFinalWallet(copy, wallet);
		try {
			expect(restored.loadFinalPeerTxComplete(c.channelId)).to.deep.equal(peer);
			expect(() =>
				restored.finalOpeningTxComplete(c.channelId, localFundingSecret)
			).to.throw();
			await restored.backup(destination);
		} finally {
			restored.close();
		}
		const fresh = SqliteStorage.openFinalWallet(destination, wallet);
		try {
			expect(fresh.loadFinalOpenings()).to.deep.equal([c]);
			expect(fresh.loadFinalPeerTxComplete(c.channelId)).to.deep.equal(peer);
			expect(() => fresh.rememberFinalOpening(opening(true))).to.throw();
		} finally {
			fresh.close();
		}
	});

	it('preserves a preexisting signer path when wallet creation cannot claim it', () => {
		const signer = file + '.opening-signer';
		fs.writeFileSync(signer, 'existing fixture');
		expect(() =>
			SqliteStorage.createFinalWallet(file, wallet).close()
		).to.throw();
		expect(fs.existsSync(file)).to.equal(false);
		expect(fs.readFileSync(signer, 'utf8')).to.equal('existing fixture');
	});

	for (const method of ['online backup', 'file copy']) {
		it(
			'permits only replay from the ' +
				method +
				' taken before nonce reservation',
			async () => {
				const c = opening();
				const original = SqliteStorage.createFinalWallet(file, wallet);
				try {
					original.rememberFinalOpening(c);
					if (method === 'online backup') await original.backup(copy);
				} finally {
					original.close();
				}
				if (method === 'file copy') fs.copyFileSync(file, copy);
				expect(fs.existsSync(copy + '.opening-signer')).to.equal(false);
				const restored = SqliteStorage.openFinalWallet(copy, wallet);
				try {
					expect(restored.loadFinalOpening(c.channelId)).to.deep.equal(c);
					expect(() =>
						restored.finalOpeningTxComplete(c.channelId, localFundingSecret)
					).to.throw();
					expect(() =>
						restored.rememberFinalPeerTxComplete(
							c.channelId,
							peerPromise(c.channelId)
						)
					).to.throw();
					expect(() => restored.rememberFinalOpening(opening(true))).to.throw();
					expect(restored.loadFinalLocalTxComplete(c.channelId)).to.equal(null);
					expect(restored.loadFinalPeerTxComplete(c.channelId)).to.equal(null);
					expect(restored.loadFinalOpenings()).to.deep.equal([c]);
				} finally {
					restored.close();
				}
				expect(fs.existsSync(copy + '.opening-signer')).to.equal(false);
			}
		);
	}

	it('replays recorded local and peer bytes from the backup without opening a signer', async () => {
		const original = SqliteStorage.createFinalWallet(file, wallet);
		const c = opening();
		const peer = peerPromise(c.channelId);
		let sent: Buffer;
		try {
			original.rememberFinalOpening(c);
			original.rememberFinalPeerTxComplete(c.channelId, peer);
			sent = original.finalOpeningTxComplete(c.channelId, localFundingSecret);
			await original.backup(copy);
		} finally {
			original.close();
		}
		const restored = SqliteStorage.openFinalWallet(copy, wallet);
		try {
			const payload = restored.loadFinalLocalTxComplete(c.channelId)!;
			expect(payload).to.deep.equal(sent);
			payload.fill(0);
			expect(restored.loadFinalLocalTxComplete(c.channelId)).to.deep.equal(
				sent
			);
			expect(restored.loadFinalPeerTxComplete(c.channelId)).to.deep.equal(peer);
			expect(() =>
				restored.rememberFinalPeerTxComplete(
					c.channelId,
					peerPromise(c.channelId, 709)
				)
			).to.throw();
			expect(() => restored.rememberFinalOpening(opening(true))).to.throw();
		} finally {
			restored.close();
		}
		expect(fs.existsSync(copy + '.opening-signer')).to.equal(false);
	});

	it('refuses a new promise with the original pathname and companion after restoring a backup in place', async () => {
		const c = opening();
		const original = SqliteStorage.createFinalWallet(file, wallet);
		try {
			original.rememberFinalOpening(c);
			await original.backup(copy);
		} finally {
			original.close();
		}
		const originalInode = fs.statSync(file).ino;
		fs.copyFileSync(copy, file);
		expect(fs.statSync(file).ino).to.equal(originalInode);
		const restored = SqliteStorage.openFinalWallet(file, wallet);
		try {
			expect(restored.loadFinalOpening(c.channelId)).to.deep.equal(c);
			expect(() =>
				restored.finalOpeningTxComplete(c.channelId, localFundingSecret)
			).to.throw();
			expect(() =>
				restored.rememberFinalPeerTxComplete(
					c.channelId,
					peerPromise(c.channelId)
				)
			).to.throw();
			expect(() => restored.rememberFinalOpening(opening(true))).to.throw();
		} finally {
			restored.close();
		}
	});

	it('does not grant signing to a copied database beside a different wallet companion', () => {
		const c = opening();
		const original = SqliteStorage.createFinalWallet(file, wallet);
		original.rememberFinalOpening(c);
		original.close();
		SqliteStorage.createFinalWallet(copy, wallet).close();
		fs.copyFileSync(file, copy);
		const other = SqliteStorage.openFinalWallet(copy, wallet);
		try {
			expect(other.loadFinalOpening(c.channelId)).to.deep.equal(c);
			expect(() =>
				other.finalOpeningTxComplete(c.channelId, localFundingSecret)
			).to.throw();
			expect(() => other.rememberFinalOpening(opening(true))).to.throw();
		} finally {
			other.close();
		}
	});

	it('does not recreate a missing authority on its original database', () => {
		const c = opening();
		const original = SqliteStorage.createFinalWallet(file, wallet);
		original.rememberFinalOpening(c);
		const saved = original.finalOpeningTxComplete(
			c.channelId,
			localFundingSecret
		);
		original.close();
		const signer = file + '.opening-signer';
		fs.renameSync(signer, signer + '.held');
		const restored = SqliteStorage.openFinalWallet(file, wallet);
		try {
			expect(restored.loadFinalLocalTxComplete(c.channelId)).to.deep.equal(
				saved
			);
			expect(() => restored.rememberFinalOpening(opening(true))).to.throw();
			expect(() =>
				restored.rememberFinalPeerTxComplete(
					c.channelId,
					peerPromise(c.channelId)
				)
			).to.throw();
		} finally {
			restored.close();
		}
		expect(fs.existsSync(signer)).to.equal(false);
	});

	it('keeps an existing signer out of ordinary SQLite open and backup paths', async () => {
		SqliteStorage.createFinalWallet(file, wallet).close();
		const signer = file + '.opening-signer';
		expect(() => {
			const mistaken = new SqliteStorage(signer);
			try {
				mistaken.open();
			} finally {
				mistaken.close();
			}
		}).to.throw();
		const legacy = new SqliteStorage(path.join(directory, 'ordinary.db'));
		legacy.open();
		let failed = false;
		try {
			await legacy.backup(signer).catch(() => {
				failed = true;
			});
			expect(failed).to.equal(true);
		} finally {
			legacy.close();
		}
		const original = SqliteStorage.openFinalWallet(file, wallet);
		try {
			original.rememberFinalOpening(opening());
		} finally {
			original.close();
		}
	});

	it('permits recovery of the wallet when its same-inode signer companion is unreadable', () => {
		const c = opening();
		const original = SqliteStorage.createFinalWallet(file, wallet);
		original.rememberFinalOpening(c);
		const saved = original.finalOpeningTxComplete(
			c.channelId,
			localFundingSecret
		);
		original.close();
		const signer = file + '.opening-signer';
		fs.writeFileSync(signer, 'damaged signer');
		const restored = SqliteStorage.openFinalWallet(file, wallet);
		try {
			expect(restored.loadFinalLocalTxComplete(c.channelId)).to.deep.equal(
				saved
			);
			expect(() => restored.rememberFinalOpening(opening(true))).to.throw();
		} finally {
			restored.close();
		}
		expect(fs.readFileSync(signer, 'utf8')).to.equal('damaged signer');
	});

	it('preserves a truncated original wallet marked by its surviving signer companion', async () => {
		SqliteStorage.createFinalWallet(file, wallet).close();
		fs.truncateSync(file, 24);
		const legacy = new SqliteStorage(path.join(directory, 'ordinary.db'));
		legacy.open();
		let failed = false;
		try {
			await legacy.backup(file).catch(() => {
				failed = true;
			});
			expect(failed).to.equal(true);
		} finally {
			legacy.close();
		}
		expect(fs.statSync(file).size).to.equal(24);
	});

	it('preserves local and peer replay records across two backups and unrelated recovery metadata writes', async () => {
		const c = opening();
		const store = SqliteStorage.createFinalWallet(file, wallet);
		const peer = peerPromise(c.channelId);
		let local: Buffer;
		try {
			store.rememberFinalOpening(c);
			store.rememberFinalPeerTxComplete(c.channelId, peer);
			local = store.finalOpeningTxComplete(c.channelId, localFundingSecret);
			await store.backup(copy);
		} finally {
			store.close();
		}
		const second = path.join(directory, 'second.db');
		const restored = SqliteStorage.openFinalWallet(copy, wallet);
		try {
			restored.saveWalletData('recovery-note', 'read from backup');
			await restored.backup(second);
		} finally {
			restored.close();
		}
		const twice = SqliteStorage.openFinalWallet(second, wallet);
		try {
			expect(twice.loadWalletData('recovery-note')).to.equal(
				'read from backup'
			);
			expect(twice.loadFinalLocalTxComplete(c.channelId)).to.deep.equal(local);
			expect(twice.loadFinalPeerTxComplete(c.channelId)).to.deep.equal(peer);
			expect(() => twice.rememberFinalOpening(opening(true))).to.throw();
		} finally {
			twice.close();
		}
	});

	it('refuses generic channel cleanup against a reserved opening ID', () => {
		const store = SqliteStorage.createFinalWallet(file, wallet);
		const c = opening();
		try {
			store.rememberFinalOpening(c);
			expect(() => store.deleteChannel(c.channelId)).to.throw();
			expect(store.loadFinalOpening(c.channelId)).to.deep.equal(c);
		} finally {
			store.close();
		}
	});

	for (const damage of ['lost', 'misindexed']) {
		it(
			'serves replay without new signing when authoritative claim rows are ' +
				damage,
			() => {
				const c = opening();
				const store = SqliteStorage.createFinalWallet(file, wallet);
				store.rememberFinalOpening(c);
				const sent = store.finalOpeningTxComplete(
					c.channelId,
					localFundingSecret
				);
				store.close();
				const signer = new Database(file + '.opening-signer', {
					fileMustExist: true
				});
				try {
					expect(
						signer
							.prepare(
								damage === 'lost'
									? 'DELETE FROM claims'
									: "UPDATE claims SET slot = 'other' WHERE slot = (SELECT slot FROM claims ORDER BY slot LIMIT 1)"
							)
							.run().changes
					).to.be.greaterThan(0);
				} finally {
					signer.close();
				}
				const replay = SqliteStorage.openFinalWallet(file, wallet);
				try {
					expect(replay.loadFinalLocalTxComplete(c.channelId)).to.deep.equal(
						sent
					);
					expect(() => replay.rememberFinalOpening(opening(true))).to.throw();
					expect(() =>
						replay.rememberFinalPeerTxComplete(
							c.channelId,
							peerPromise(c.channelId)
						)
					).to.throw();
				} finally {
					replay.close();
				}
			}
		);
	}

	it('keeps a raw wallet rollback from changing the original peer transcript or publishing a second nonce pair', () => {
		const c = opening();
		const original = SqliteStorage.createFinalWallet(file, wallet);
		original.rememberFinalOpening(c);
		original.close();
		fs.copyFileSync(file, copy);
		const live = SqliteStorage.openFinalWallet(file, wallet);
		const firstPeer = peerPromise(c.channelId);
		let firstLocal: Buffer;
		try {
			live.rememberFinalPeerTxComplete(c.channelId, firstPeer);
			firstLocal = live.finalOpeningTxComplete(c.channelId, localFundingSecret);
		} finally {
			live.close();
		}
		fs.copyFileSync(copy, file);
		const restored = SqliteStorage.openFinalWallet(file, wallet);
		try {
			expect(() =>
				restored.rememberFinalPeerTxComplete(
					c.channelId,
					peerPromise(c.channelId, 740)
				)
			).to.throw();
			let replay: Buffer | undefined;
			try {
				replay = restored.finalOpeningTxComplete(
					c.channelId,
					localFundingSecret
				);
			} catch {
				// A stale copy may have no release record from which to replay.
			}
			if (replay) expect(replay).to.deep.equal(firstLocal);
		} finally {
			restored.close();
		}
	});
});
