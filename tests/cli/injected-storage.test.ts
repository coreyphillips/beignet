/**
 * BeignetNode on the storage passed as options.storage (issue #1708), the
 * React Native case: no SQLite is loaded and, without a dataDir, no file is
 * written. Features that copy or install a SQLite file are refused, before
 * the backend is opened when they are options.
 *
 * Offline suite: the node boots against an unreachable Electrum server.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import sinon from 'sinon';
import {
	BeignetNode,
	BeignetNodeOptions,
	defaultDataDirForMnemonic
} from '../../src/cli/beignet-node';
import { startDaemon } from '../../src/cli/daemon';
import { PaymentFilter } from '../../src/cli/types';
import {
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { generateMnemonic } from '../../src/utils/helpers';

// A refused loopback connect returns at once, where the regtest default is
// a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65527,
	electrumTls: false
};

const BOOT: BeignetNodeOptions = {
	network: 'regtest',
	logLevel: 'silent',
	rapidGossipSync: false,
	autoGossipSync: false,
	...OFFLINE_ELECTRUM
};

const BASE_MS = 1_700_000_000_000;

const recordOf = (
	i: number,
	overrides: Partial<IPaymentInfo> = {}
): IPaymentInfo => ({
	paymentHash: crypto.randomBytes(32),
	amountMsat: BigInt(1_000 + i) * 1000n,
	status: i % 7 === 0 ? PaymentStatus.FAILED : PaymentStatus.COMPLETED,
	direction:
		i % 3 === 0 ? PaymentDirection.INCOMING : PaymentDirection.OUTGOING,
	// Three rows to a millisecond, so the hash tie-break is exercised.
	createdAt: BASE_MS + Math.floor(i / 3),
	completedAt: BASE_MS + Math.floor(i / 3) + 10,
	metadata: { label: `row-${i}`, ...(i % 2 === 0 ? { even: 'yes' } : {}) },
	...overrides
});

const hex = (p: IPaymentInfo): string => p.paymentHash.toString('hex');

/** The listing by its definition: every record, live ones winning, sorted, filtered, sliced. */
const referenceListing = (
	rows: IPaymentInfo[],
	live: IPaymentInfo[],
	filter: PaymentFilter = {}
): string[] => {
	const byHash = new Map<string, IPaymentInfo>();
	for (const p of [...rows, ...live]) byHash.set(hex(p), p);
	let list = [...byHash]
		.sort(([ha, a], [hb, b]) =>
			a.createdAt !== b.createdAt
				? b.createdAt - a.createdAt
				: ha < hb
				? 1
				: ha > hb
				? -1
				: 0
		)
		.map(([, p]) => p);
	if (filter.status) list = list.filter((p) => p.status === filter.status);
	if (filter.direction) {
		list = list.filter((p) => p.direction === filter.direction);
	}
	if (filter.since !== undefined) {
		list = list.filter((p) => p.createdAt >= filter.since!);
	}
	if (filter.metadataKey !== undefined) {
		list = list.filter((p) =>
			filter.metadataValue !== undefined
				? p.metadata?.[filter.metadataKey!] === filter.metadataValue
				: p.metadata !== undefined &&
				  Object.prototype.hasOwnProperty.call(p.metadata, filter.metadataKey!)
		);
	}
	if (filter.offset) list = list.slice(filter.offset);
	if (filter.limit) list = list.slice(0, filter.limit);
	return list.map(hex);
};

/** Every require whose request names SQLite, while `run` runs. */
async function sqliteRequestsDuring<T>(
	run: () => Promise<T>
): Promise<{ result: T; requests: string[] }> {
	const Module = require('module') as {
		_load: (request: string, ...rest: unknown[]) => unknown;
	};
	const load = Module._load;
	const requests: string[] = [];
	Module._load = function (request: string, ...rest: unknown[]): unknown {
		if (/sqlite/i.test(request)) requests.push(request);
		return load.call(this, request, ...rest);
	};
	try {
		return { result: await run(), requests };
	} finally {
		Module._load = load;
	}
}

const expectRefusal = (err: unknown, pattern: RegExp): void => {
	expect(err, 'refused').to.be.instanceOf(Error);
	expect((err as { code?: string }).code).to.equal('INVALID_PARAMS');
	expect((err as Error).message).to.match(pattern);
};

describe('BeignetNode on injected storage (issue #1708)', function () {
	this.timeout(60_000);

	afterEach(() => {
		sinon.restore();
	});

	it('boots on the backend without loading SQLite or writing a file, and keeps its state there across a restart', async () => {
		const storage = new MemoryStorage();
		const mnemonic = generateMnemonic();
		const defaultDir = defaultDataDirForMnemonic(mnemonic);
		const { result: node, requests } = await sqliteRequestsDuring(() =>
			BeignetNode.create({ ...BOOT, mnemonic, storage })
		);
		let invoiceHash: string;
		try {
			expect(requests).to.deep.equal([]);
			expect(node.getStorageBackend()).to.equal(storage);
			expect(() => node.getStorage()).to.throw(/getStorageBackend/);
			expect(node.storageFiles()).to.deep.equal([]);

			const scb = node.exportStaticChannelBackup();
			expect(scb.path).to.equal('');
			expect(scb.encoded).to.be.a('string').that.is.not.empty;

			let backupError: unknown;
			await node.backup('/nonexistent/backup.db').catch((e) => {
				backupError = e;
			});
			expectRefusal(backupError, /SQLite/);
			let restoreError: unknown;
			await node.restoreFromCapsules().catch((e) => {
				restoreError = e;
			});
			expect((restoreError as { code?: string }).code).to.equal(
				'CAPSULE_RESTORE_UNSUPPORTED'
			);

			// The queue's rows are SQLite tables; on this backend it lives in
			// memory rather than reading tables the backend does not have.
			expect(node.getPaymentQueue().list()).to.deep.equal([]);

			const invoice = node.createInvoice(1_000, 'injected storage');
			invoiceHash = invoice.paymentHash;
			expect(storage.loadAllInvoices().map((i) => i.paymentHashHex)).to.include(
				invoiceHash
			);
		} finally {
			await node.destroy();
		}
		expect(fs.existsSync(defaultDir), defaultDir).to.equal(false);

		const again = await BeignetNode.create({ ...BOOT, mnemonic, storage });
		try {
			expect(again.listInvoices().map((i) => i.paymentHash)).to.include(
				invoiceHash
			);
		} finally {
			await again.destroy();
		}
	});

	it('lists stored payments and paid invoices by the rules the SQLite lookup columns apply', async () => {
		const storage = new MemoryStorage();
		const node = await BeignetNode.create({
			...BOOT,
			mnemonic: generateMnemonic(),
			storage
		});
		try {
			// Rows only, as the engine leaves them once it prunes its records.
			const rows = Array.from({ length: 60 }, (_, i) => recordOf(i));
			for (const p of rows) storage.savePayment(hex(p), p);
			const live = (
				node.getNode() as unknown as { payments: Map<string, IPaymentInfo> }
			).payments;
			expect(live.size, 'no live records').to.equal(0);
			const overRow: IPaymentInfo = {
				...rows[10],
				metadata: { label: 'live' }
			};
			const liveOnly = recordOf(30, { metadata: { label: 'live-only' } });
			for (const p of [overRow, liveOnly]) live.set(hex(p), p);
			const filters: PaymentFilter[] = [
				{},
				{ offset: 5, limit: 10 },
				{ direction: 'INCOMING' },
				{ status: 'FAILED' },
				{ since: rows[30].createdAt, offset: 2, limit: 5 },
				{ metadataKey: 'even' },
				{ metadataKey: 'label', metadataValue: 'live' },
				// The row holds this label; the live record over it does not.
				{ metadataKey: 'label', metadataValue: 'row-10' },
				{ metadataKey: 'toString' }
			];
			for (const filter of filters) {
				expect(
					node.listPayments(filter).map((p) => p.paymentHash),
					JSON.stringify(filter)
				).to.deep.equal(referenceListing(rows, [overRow, liveOnly], filter));
			}

			const invoice = node.createInvoice(2_000, 'paid from a row');
			// Gone from memory, as the engine's prune leaves it, so only a
			// row can say it was paid.
			live.delete(invoice.paymentHash);
			expect(
				node.listInvoices().find((i) => i.paymentHash === invoice.paymentHash)
					?.status
			).to.equal('PENDING');
			const paid = recordOf(1, {
				paymentHash: Buffer.from(invoice.paymentHash, 'hex'),
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.INCOMING
			});
			storage.savePayment(invoice.paymentHash, paid);
			expect(
				node.listInvoices().find((i) => i.paymentHash === invoice.paymentHash)
					?.status
			).to.equal('PAID');
		} finally {
			await node.destroy();
		}
	});

	it('refuses a backend it cannot run on, and options that need SQLite or a dataDir, before opening it', async () => {
		const storage = new MemoryStorage();
		const open = sinon.spy(storage, 'open');
		const withoutWalletData = new Proxy(storage, {
			get: (target, prop): unknown =>
				prop === 'saveWalletData' || prop === 'loadWalletData'
					? undefined
					: Reflect.get(target, prop, target)
		});
		const cases: Array<[Partial<BeignetNodeOptions>, RegExp]> = [
			[
				{ storage: {} as unknown as MemoryStorage },
				/does not implement open, close/
			],
			[{ storage: withoutWalletData }, /walletData capability/],
			[{ storage, backupPath: '/tmp/beignet-backup.db' }, /backupPath/],
			[{ storage, recoveryAutoApply: true }, /recoveryAutoApply/],
			[{ storage, guardianServe: true }, /guardianServe .* dataDir/]
		];
		for (const [opts, pattern] of cases) {
			let error: unknown;
			await BeignetNode.create({ ...BOOT, ...opts }).then(
				(node) => node.destroy(),
				(e) => {
					error = e;
				}
			);
			expectRefusal(error, pattern);
		}
		let daemonError: unknown;
		await startDaemon({
			...BOOT,
			storage,
			daemonPort: 0
		} as unknown as Parameters<typeof startDaemon>[0]).then(
			(daemon) => daemon.stop(),
			(e) => {
				daemonError = e;
			}
		);
		expectRefusal(daemonError, /takes no storage/);
		expect(open.called).to.equal(false);
	});
});
