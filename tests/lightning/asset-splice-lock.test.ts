import { expect } from 'chai';
import Database from 'better-sqlite3';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
	AssetSpliceLock,
	type IAssetSpliceLockEvent
} from '../../src/lightning/channel/asset-splice-lock';
import { encodeSpliceLockedMessage } from '../../src/lightning/message/splice';

const terms = {
	channelId: 'cc'.repeat(32),
	txid: Array.from({ length: 32 }, (_, i) =>
		i.toString(16).padStart(2, '0')
	).join(''),
	outputIndex: 1,
	finalDigest: 'dd'.repeat(32),
	minimumDepth: 3
};
const anchor = {
	txid: terms.txid,
	blockHash: 'ab'.repeat(32),
	confirmations: 3
};
const wire = encodeSpliceLockedMessage({
	channelId: Buffer.from(terms.channelId, 'hex'),
	fundingTxid: Buffer.from(terms.txid, 'hex').reverse()
});

function deferred() {
	let resolve!: () => void;
	const promise = new Promise<void>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}

describe('Asset splice adoption at a proven funding block', () => {
	let dir: string, db: Database.Database;
	let verified: string[];
	let verify: (t: typeof terms, a: typeof anchor) => Promise<void>;
	function open() {
		db = new Database(join(dir, 'wallet.db'));
		db.exec(
			'CREATE TABLE IF NOT EXISTS splice_test_log (id INTEGER PRIMARY KEY, entry TEXT NOT NULL)'
		);
	}
	function read(): IAssetSpliceLockEvent[] {
		const rows = db
			.prepare('SELECT entry FROM splice_test_log ORDER BY id')
			.all() as { entry: string }[];
		return rows.map((row) => JSON.parse(row.entry));
	}
	function gate(identity = terms) {
		return new AssetSpliceLock(
			identity,
			{
				read,
				append(event: IAssetSpliceLockEvent) {
					db.prepare('INSERT INTO splice_test_log(entry) VALUES (?)').run(
						JSON.stringify(event)
					);
				}
			},
			verify
		);
	}
	function restart() {
		db.close();
		open();
		return gate();
	}
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'asset-splice-lock-'));
		verified = [];
		verify = async (t, a) => {
			expect(t).to.deep.equal(terms);
			expect(a.confirmations).to.be.at.least(terms.minimumDepth);
			verified.push(a.blockHash);
		};
		open();
	});
	afterEach(() => {
		db.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it('remembers an early peer lock but waits for local depth and successful proof verification', async () => {
		const started = deferred(),
			finish = deferred();
		const check = verify;
		verify = async (t, a) => {
			await check(t, a);
			started.resolve();
			await finish.promise;
		};
		const lock = gate();
		await lock.peerLocked(terms.txid);
		await lock.observe({ ...anchor, confirmations: 1 });
		expect(lock.state().peerLocked).to.equal(true);
		expect(lock.state().adopted).to.equal(false);
		expect(lock.outboundLock()).to.equal(undefined);
		expect(verified).to.deep.equal([]);
		const pending = lock.observe(anchor);
		await started.promise;
		expect(lock.outboundLock()).to.equal(undefined);
		expect(lock.state().adopted).to.equal(false);
		finish.resolve();
		await pending;
		expect(lock.outboundLock()).to.deep.equal(wire);
		expect(lock.state().localLocked).to.equal(true);
		expect(lock.state().adopted).to.equal(true);
	});

	it('restores the durable local lock, rechecks its anchor and applies a matching peer lock only once', async () => {
		let lock = gate();
		await lock.observe(anchor);
		expect(lock.outboundLock()).to.deep.equal(wire);
		expect(lock.state().adopted).to.equal(false);
		lock = restart();
		expect(lock.outboundLock()).to.equal(undefined);
		await lock.peerLocked(terms.txid);
		expect(lock.state().adopted).to.equal(false);
		await lock.observe(anchor);
		expect(lock.state().adopted).to.equal(true);
		expect(lock.outboundLock()).to.deep.equal(wire);
		expect(verified).to.deep.equal([anchor.blockHash, anchor.blockHash]);
		const once = read();
		await lock.peerLocked(terms.txid);
		await lock.observe({ ...anchor, confirmations: 4 });
		expect(read()).to.deep.equal(once);
		lock = restart();
		expect(lock.state().adopted).to.equal(true);
		await lock.observe(anchor);
		await lock.peerLocked(terms.txid);
		expect(read()).to.deep.equal(once);
	});

	it('invalidates an in-flight verification when the funding confirmation leaves the chain', async () => {
		const started = deferred(),
			finish = deferred();
		const replacement = { ...anchor, blockHash: '34'.repeat(32) };
		const check = verify;
		verify = async (t, a) => {
			await check(t, a);
			if (a.blockHash === anchor.blockHash) {
				started.resolve();
				await finish.promise;
			}
		};
		const lock = gate();
		await lock.peerLocked(terms.txid);
		const first = lock.observe(anchor);
		await started.promise;
		const removed = lock.observe(null);
		finish.resolve();
		await Promise.all([first, removed]);
		expect(lock.state().adopted).to.equal(false);
		expect(lock.outboundLock()).to.equal(undefined);
		await lock.observe({ ...replacement, confirmations: 2 });
		expect(lock.outboundLock()).to.equal(undefined);
		await lock.observe(replacement);
		expect(lock.state().adopted).to.equal(true);
		expect(verified).to.deep.equal([anchor.blockHash, replacement.blockHash]);
	});

	it('discards the first proof when another funding block at the same depth arrives without an intervening absence', async () => {
		const firstStarted = deferred(),
			releaseFirst = deferred();
		const nextStarted = deferred(),
			releaseNext = deferred();
		const replacement = { ...anchor, blockHash: '47'.repeat(32) };
		verify = async (_terms, a) => {
			const old = a.blockHash === anchor.blockHash;
			(old ? firstStarted : nextStarted).resolve();
			await (old ? releaseFirst : releaseNext).promise;
		};
		const lock = gate();
		await lock.peerLocked(terms.txid);
		const first = lock.observe(anchor);
		await firstStarted.promise;
		const next = lock.observe(replacement);
		releaseFirst.resolve();
		await nextStarted.promise;
		expect(lock.state().adopted).to.equal(false);
		expect(lock.outboundLock()).to.equal(undefined);
		releaseNext.resolve();
		await Promise.all([first, next]);
		expect(lock.state().adopted).to.equal(true);
	});

	it('retries a rejected local proof and marks a later reorg of adopted funding for reconciliation', async () => {
		let valid = false;
		const check = verify;
		verify = async (t, a) => {
			await check(t, a);
			if (!valid) throw Error('Rejected funding proof');
		};
		let lock = gate();
		await lock.peerLocked(terms.txid);
		await lock.observe(anchor).catch(() => undefined);
		expect(lock.state().adopted).to.equal(false);
		expect(lock.outboundLock()).to.equal(undefined);
		valid = true;
		await lock.observe(anchor);
		expect(lock.state().adopted).to.equal(true);
		await lock.observe(null);
		expect(lock.state().needsReconciliation).to.equal(true);
		expect(lock.outboundLock()).to.equal(undefined);
		lock = restart();
		expect(lock.state().adopted).to.equal(true);
		expect(lock.state().needsReconciliation).to.equal(true);
	});

	it('withholds adoption for a competing chain spend or conflicting peer lock, including after reconnect', async () => {
		let lock = gate();
		const competitor = '98'.repeat(32);
		await lock.observe({ ...anchor, txid: competitor }).catch(() => undefined);
		expect(lock.outboundLock()).to.equal(undefined);
		expect(verified).to.deep.equal([]);
		await lock.peerLocked(competitor).catch(() => undefined);
		lock = restart();
		await lock.observe(anchor);
		await lock.peerLocked(terms.txid).catch(() => undefined);
		expect(lock.state().adopted).to.equal(false);
	});

	it('rejects reuse of a durable lock under different channel, outpoint, proof or depth terms', async () => {
		await gate().peerLocked(terms.txid);
		for (const changed of [
			{ channelId: '91'.repeat(32) },
			{ txid: '92'.repeat(32) },
			{ outputIndex: 0 },
			{ finalDigest: '93'.repeat(32) },
			{ minimumDepth: terms.minimumDepth - 1 }
		])
			expect(() => gate({ ...terms, ...changed }).state()).to.throw();
	});
});
