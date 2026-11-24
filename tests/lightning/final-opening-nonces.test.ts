import { expect } from 'chai';
import Database from 'better-sqlite3';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	getPublicKey,
	isValidPublicKey
} from '../../src/lightning/crypto/ecdh';
import {
	decodeTxCompleteMessage,
	encodeTxCompleteMessage
} from '../../src/lightning/message/interactive-tx';
import {
	localOpeningTxComplete,
	type IFinalOpeningNonces
} from '../../src/lightning/storage/final-opening-nonces';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	localFundingSecret,
	remoteFundingSecret,
	opening,
	wallet
} from './helpers/final-opening';
import { seedFor } from './helpers/taproot-revoked-fixture';

function publicNonce(id: number): Buffer {
	return Buffer.concat([
		getPublicKey(seedFor(id)),
		getPublicKey(seedFor(id + 1))
	]);
}

function peerComplete(channelId: string, first = 331): Buffer {
	return encodeTxCompleteMessage({
		channelId: Buffer.from(channelId, 'hex'),
		commitNonces: { current: publicNonce(first), next: publicNonce(first + 2) }
	});
}

function readNonces(channelId: string, wire: Buffer): string[] {
	// tx_complete consists of the channel ID followed by TLV 4 with two nonces.
	expect(wire.length).to.equal(166);
	expect(wire.subarray(0, 32).toString('hex')).to.equal(channelId);
	expect(wire.subarray(32, 34).toString('hex')).to.equal('0484');
	const values = [wire.subarray(34, 100), wire.subarray(100, 166)];
	for (const value of values) {
		expect(isValidPublicKey(value.subarray(0, 33))).to.equal(true);
		expect(isValidPublicKey(value.subarray(33))).to.equal(true);
	}
	return values.map((value) => value.toString('hex'));
}

describe('Final opening commitment nonce reservation', () => {
	let directory: string;
	let file: string;
	let store: SqliteStorage;
	beforeEach(() => {
		directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-opening-nonces-')
		);
		file = path.join(directory, 'regtest.db');
		store = SqliteStorage.createFinalWallet(file, wallet);
	});
	afterEach(() => {
		store.close();
		fs.rmSync(directory, { recursive: true, force: true });
	});

	it('reserves distinct nonce pairs for both funding roles even with the same funding key, and replays exact bytes after restart', () => {
		const a = opening();
		const b = opening(true);
		expect(a.localFundingPubkey).to.equal(b.localFundingPubkey);
		const wires: Buffer[] = [];
		const points: string[] = [];
		for (const candidate of [a, b]) {
			store.rememberFinalOpening(candidate);
			const bytes = store.finalOpeningTxComplete(
				candidate.channelId,
				localFundingSecret
			);
			wires.push(Buffer.from(bytes));
			points.push(...readNonces(candidate.channelId, bytes));
			bytes.fill(0);
		}
		expect(new Set(points).size).to.equal(4);
		store.close();
		store = SqliteStorage.openFinalWallet(file, wallet);
		for (const [index, candidate] of [a, b].entries()) {
			expect(
				store.finalOpeningTxComplete(candidate.channelId, localFundingSecret)
			).to.deep.equal(wires[index]);
		}
	});

	it('requires a remembered candidate and its local funding key before returning any nonce bytes', () => {
		const candidate = opening();
		const id = candidate.channelId;
		expect(() =>
			store.finalOpeningTxComplete(id, localFundingSecret)
		).to.throw();
		expect(() =>
			store.rememberFinalPeerTxComplete(id, peerComplete(id))
		).to.throw();
		store.rememberFinalOpening(candidate);
		expect(() =>
			store.finalOpeningTxComplete(id, remoteFundingSecret)
		).to.throw();
		const bytes = store.finalOpeningTxComplete(id, localFundingSecret);
		expect(() =>
			store.finalOpeningTxComplete(id, remoteFundingSecret)
		).to.throw();
		expect(store.finalOpeningTxComplete(id, localFundingSecret)).to.deep.equal(
			bytes
		);
	});

	it('binds the exact peer payload once, including when its tx_complete arrives first', () => {
		const candidate = opening(true);
		const id = candidate.channelId;
		const peer = peerComplete(id);
		store.rememberFinalOpening(candidate);
		expect(store.loadFinalPeerTxComplete(id)).to.equal(null);
		store.rememberFinalPeerTxComplete(id, Buffer.from(peer));
		store.rememberFinalPeerTxComplete(id, Buffer.from(peer));
		const restored = store.loadFinalPeerTxComplete(id)!;
		restored.fill(0);
		expect(() =>
			store.rememberFinalPeerTxComplete(id, peerComplete(id, 341))
		).to.throw();
		readNonces(id, store.finalOpeningTxComplete(id, localFundingSecret));
		store.close();
		store = SqliteStorage.openFinalWallet(file, wallet);
		expect(store.loadFinalPeerTxComplete(id)).to.deep.equal(peer);
		expect(() =>
			store.rememberFinalPeerTxComplete(id, peerComplete(id, 351))
		).to.throw();
		store.rememberFinalPeerTxComplete(id, peer);
	});

	it('refuses a foreign candidate, malformed or repeated commitment nonces, and splice nonces on an opening', () => {
		const candidate = opening();
		store.rememberFinalOpening(candidate);
		const id = candidate.channelId;
		const peer = peerComplete(id);
		const decoded = decodeTxCompleteMessage(peer, { taproot: true });
		const nonces = decoded.commitNonces!;
		const badPoint = Buffer.from(peer);
		badPoint[34 + 33] = 4;
		for (const malformed of [
			peerComplete(opening(true).channelId),
			peer.subarray(0, 32),
			peer.subarray(0, peer.length - 1),
			badPoint,
			encodeTxCompleteMessage({
				...decoded,
				commitNonces: { current: nonces.current, next: nonces.current }
			}),
			encodeTxCompleteMessage({
				...decoded,
				fundingInputNonce: publicNonce(361)
			})
		]) {
			expect(() => store.rememberFinalPeerTxComplete(id, malformed)).to.throw();
			expect(store.loadFinalPeerTxComplete(id)).to.equal(null);
		}
		store.rememberFinalPeerTxComplete(id, peer);
		expect(store.loadFinalPeerTxComplete(id)).to.deep.equal(peer);
	});

	it('authenticates each saved nonce record against its own funding candidate', async () => {
		const a = opening();
		const b = opening(true);
		const fileCopy = path.join(directory, 'copy.db');
		for (const candidate of [a, b]) {
			store.rememberFinalOpening(candidate);
			store.finalOpeningTxComplete(candidate.channelId, localFundingSecret);
			store.rememberFinalPeerTxComplete(
				candidate.channelId,
				peerComplete(candidate.channelId)
			);
		}
		await store.backup(fileCopy);
		const copy = new Database(fileCopy, { fileMustExist: true });
		try {
			copy
				.prepare(
					'UPDATE final_opening_candidates SET nonces_json = (SELECT nonces_json FROM final_opening_candidates WHERE channel_id = ?) WHERE channel_id = ?'
				)
				.run(a.channelId, b.channelId);
		} finally {
			copy.close();
		}
		expect(() =>
			SqliteStorage.openFinalWallet(fileCopy, wallet).close()
		).to.throw();
		expect(store.loadFinalPeerTxComplete(b.channelId)).to.deep.equal(
			peerComplete(b.channelId)
		);
	});

	it('requires the saved salt and funding key to reproduce the promised local nonces', () => {
		const candidate = opening();
		const context = seedFor(503);
		const nonces: IFinalOpeningNonces = {};
		const emit = (): Buffer =>
			localOpeningTxComplete(
				nonces,
				candidate.channelId,
				candidate.localFundingPubkey,
				localFundingSecret,
				context
			);
		const original = emit();
		expect(emit()).to.deep.equal(original);
		nonces.local!.salt = seedFor(504).toString('hex');
		expect(emit).to.throw();
	});

	it('returns nonce bytes only when the original database retains the reservation', () => {
		const candidate = opening();
		store.rememberFinalOpening(candidate);
		const db = (store as unknown as { db: Database.Database }).db;
		db.exec(`CREATE TRIGGER preserve_old_row AFTER UPDATE OF nonces_json ON final_opening_candidates
			BEGIN
				UPDATE final_opening_candidates SET nonces_json = OLD.nonces_json WHERE channel_id = OLD.channel_id;
			END`);
		expect(() =>
			store.finalOpeningTxComplete(candidate.channelId, localFundingSecret)
		).to.throw();
	});

	it('refuses nested writes and returns nothing when the independent durable write fails', () => {
		const candidate = opening();
		const id = candidate.channelId;
		const peer = peerComplete(id);
		store.rememberFinalOpening(candidate);
		expect(() =>
			store.transaction(() =>
				store.finalOpeningTxComplete(id, localFundingSecret)
			)
		).to.throw();
		expect(() =>
			store.transaction(() => store.rememberFinalPeerTxComplete(id, peer))
		).to.throw();
		const raw = (store as unknown as { db: Database.Database }).db;
		let returned: Buffer | undefined;
		raw.pragma('query_only = ON');
		try {
			expect(() => {
				returned = store.finalOpeningTxComplete(id, localFundingSecret);
			}).to.throw();
			expect(returned).to.equal(undefined);
			expect(() => store.rememberFinalPeerTxComplete(id, peer)).to.throw();
		} finally {
			raw.pragma('query_only = OFF');
		}
		store.close();
		store = SqliteStorage.openFinalWallet(file, wallet);
		expect(store.loadFinalPeerTxComplete(id)).to.equal(null);
		readNonces(id, store.finalOpeningTxComplete(id, localFundingSecret));
		store.rememberFinalPeerTxComplete(id, peer);
		expect(store.loadFinalPeerTxComplete(id)).to.deep.equal(peer);
	});
});
