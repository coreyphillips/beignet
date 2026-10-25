/**
 * Startup history benchmark (issue #1861): what a lightning node's restore
 * costs over a SQLite store holding a lifetime of payments. Each row count
 * gets a fresh store with one payment, invoice, preimage and payment secret
 * per hash, and the node is built over it in a fresh child process, so one
 * size's garbage cannot hide another's peak. Usage:
 *   npx ts-node scripts/bench-startup-history.ts
 * BENCH_ROWS sets the row counts (default 10000,50000,100000), and
 * BENCH_ENCRYPTED=1 stores the rows encrypted, as a daemon with a storage
 * key does.
 *
 * Columns: readyMs is the constructor's run, which is where restore
 * happens; rows the rows the node decoded (payments, invoices, preimages,
 * secrets); peakHeapMiB and peakRssMiB how far the committed heap and the
 * resident set grew across it, which V8 does not hand back at once and so
 * stand for the peak; retainedMiB the heap still held after a full
 * collection.
 */
import { fork } from 'child_process';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as v8 from 'v8';
import { DEFAULT_CHANNEL_CONFIG } from '../src/lightning/channel/types';
import { getPublicKey } from '../src/lightning/crypto/ecdh';
import { Network } from '../src/lightning/invoice/types';
import { LightningNode } from '../src/lightning/node/lightning-node';
import { PaymentDirection, PaymentStatus } from '../src/lightning/node/types';
import { SqliteStorage } from '../src/lightning/storage/sqlite-storage';

const ROWS = (process.env.BENCH_ROWS ?? '10000,50000,100000')
	.split(',')
	.map(Number);
const ENCRYPTION_KEY =
	process.env.BENCH_ENCRYPTED === '1'
		? crypto.createHash('sha256').update('bench-key').digest()
		: undefined;
const MiB = 1024 * 1024;

const sha256 = (data: Buffer | string): Buffer =>
	crypto.createHash('sha256').update(data).digest();

const openStorage = (dbPath: string): SqliteStorage => {
	const storage = new SqliteStorage(dbPath, undefined, {
		encryptionKey: ENCRYPTION_KEY
	});
	storage.open({ synchronous: 'NORMAL' });
	return storage;
};

const seed = (dbPath: string, rows: number): void => {
	const storage = openStorage(dbPath);
	const db = (
		storage as unknown as { db: { transaction(fn: () => void): () => void } }
	).db;
	db.transaction(() => {
		for (let i = 0; i < rows; i++) {
			const preimage = sha256(`bench-preimage-${i}`);
			const hash = sha256(preimage);
			const hex = hash.toString('hex');
			const createdAt = 1_700_000_000_000 + i;
			storage.savePayment(hex, {
				paymentHash: hash,
				preimage,
				amountMsat: 50_000n,
				status: PaymentStatus.COMPLETED,
				direction:
					i % 2 ? PaymentDirection.OUTGOING : PaymentDirection.INCOMING,
				createdAt,
				completedAt: createdAt + 500,
				metadata: { note: `bench payment ${i}` }
			});
			storage.saveInvoice(hex, {
				paymentHash: hex,
				bolt11: 'lnbcrt500n1'.padEnd(360, 'q'),
				amountMsat: 50_000n,
				description: `bench invoice ${i}`,
				expiry: 3600,
				createdAt: Math.floor(createdAt / 1000)
			});
			storage.savePreimage(hex, preimage);
			storage.savePaymentSecret(hex, sha256(`bench-secret-${i}`));
		}
	})();
	storage.close();
};

const nodeKey = (label: string): Buffer => sha256(`bench-node-${label}`);

const child = (dbPath: string): void => {
	const gc = (global as { gc?: () => void }).gc;
	if (!gc) throw new Error('run with --expose-gc');
	const storage = openStorage(dbPath);
	gc();
	const heapBefore = v8.getHeapStatistics().total_heap_size;
	const usedBefore = process.memoryUsage().heapUsed;
	const rssBefore = process.memoryUsage.rss();
	const start = performance.now();
	const node = new LightningNode({
		nodePrivateKey: nodeKey('node'),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: {
			fundingPubkey: getPublicKey(nodeKey('funding')),
			revocationBasepoint: getPublicKey(nodeKey('revocation')),
			paymentBasepoint: getPublicKey(nodeKey('payment')),
			delayedPaymentBasepoint: getPublicKey(nodeKey('delayed')),
			htlcBasepoint: getPublicKey(nodeKey('htlc')),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		perCommitmentSeed: nodeKey('commitment'),
		fundingPrivkey: nodeKey('funding'),
		storage
	});
	const readyMs = performance.now() - start;
	const peakHeap = v8.getHeapStatistics().total_heap_size - heapBefore;
	const peakRss = process.memoryUsage.rss() - rssBefore;
	gc();
	const retained = process.memoryUsage().heapUsed - usedBefore;
	const internals = node as unknown as {
		preimages: Map<string, Buffer>;
		paymentSecrets: Map<string, Buffer>;
	};
	const rows =
		node.listPayments().length +
		node.listInvoices().length +
		internals.preimages.size +
		internals.paymentSecrets.size;
	process.send!({
		readyMs: Math.round(readyMs),
		rows,
		peakHeapMiB: +(peakHeap / MiB).toFixed(1),
		peakRssMiB: +(peakRss / MiB).toFixed(1),
		retainedMiB: +(retained / MiB).toFixed(1)
	});
	node.destroy();
	storage.close();
};

const measure = (dbPath: string): Promise<Record<string, number>> =>
	new Promise((resolve, reject) => {
		const proc = fork(__filename, ['child', dbPath], {
			execArgv: ['-r', 'ts-node/register', '--expose-gc']
		});
		proc.once('message', (result) => resolve(result as Record<string, number>));
		proc.once('exit', (code) => {
			if (code !== 0) reject(new Error(`child exited ${code}`));
		});
	});

const main = async (): Promise<void> => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-startup-'));
	try {
		for (const rows of ROWS) {
			const dbPath = path.join(dir, `history-${rows}.db`);
			seed(dbPath, rows);
			console.log({ history: rows, ...(await measure(dbPath)) });
		}
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
};

if (process.argv[2] === 'child') {
	child(process.argv[3]);
} else {
	main().catch((err) => {
		console.error(err);
		process.exit(1);
	});
}
