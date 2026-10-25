/**
 * Refresh copy benchmark (issue #1856): what a refresh that finds nothing new
 * costs when its caller takes the copy of the data refreshWallet answers
 * with, and when it only waits for the refresh, as Electrum, the daemon and
 * the wallet's own refreshes do. Before #1856 every refresh paid for the
 * copy. The wallet holds one receive address and one confirmed receive per
 * record, and each step of the refresh answers as a server with nothing new
 * would, so the copy is all that differs. Usage:
 *   NODE_OPTIONS=--expose-gc npx ts-node scripts/bench-refresh-copy.ts [runs]
 * BENCH_RECORDS sets the record counts (default 1000,10000,50000). The two
 * kinds of refresh are interleaved so machine load hits them alike, after a
 * warmup run of each.
 *
 * Columns, as medians over the runs: ms from call to settle; maxLagMs, the
 * longest the event loop went without serving a probe timer; allocMiB, what
 * the refresh allocated (heap growth plus what collections freed while it
 * ran); retainedMiB, the heap the caller's answer holds after a full
 * collection.
 */
import * as net from 'net';
import * as tls from 'tls';
import * as v8 from 'v8';
import { EAddressType, EAvailableNetworks, ok, Wallet } from '../src';
import { createConsoleLogger } from '../src/logger';
import { refreshLiveWallet } from '../src/wallet/live-data';
import { seedWalletRecords } from '../tests/wallet-records-fixture';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const RUNS = Number(process.argv[2] ?? 7);
const RECORDS = (process.env.BENCH_RECORDS ?? '1000,10000,50000')
	.split(',')
	.map(Number);
const MiB = 1024 * 1024;

const gc = (): void => {
	(global as { gc?: () => void }).gc?.();
};

interface IRun {
	ms: number;
	maxLagMs: number;
	allocMiB: number;
	retainedMiB: number;
}

const median = (xs: number[]): number => {
	const sorted = [...xs].sort((a, b) => a - b);
	return sorted[Math.floor(sorted.length / 2)];
};

const openWallet = async (records: number): Promise<Wallet> => {
	const res = await Wallet.create({
		mnemonic: MNEMONIC,
		network: EAvailableNetworks.regtest,
		addressType: EAddressType.p2wpkh,
		electrumOptions: { net, tls },
		remainOffline: true,
		disableRefreshOnCreate: true,
		logger: createConsoleLogger('silent')
	});
	if (res.isErr()) throw res.error;
	const wallet = res.value;
	Object.assign(wallet, {
		setZeroIndexAddresses: async () => ok('unchanged'),
		updateAddressIndexes: async () => ok('unchanged'),
		refreshUtxos: async () => ok({ utxos: [], balance: 0 }),
		updateTransactions: async () => ok(undefined),
		updateFeeEstimates: async () => ok(wallet.feeEstimates)
	});
	Object.assign(wallet.electrum, {
		subscribeToAddresses: async () => ok('unchanged')
	});
	seedWalletRecords(wallet, records);
	return wallet;
};

/** Times one refresh, and measures its event loop lag and allocation. */
const measure = async (refresh: () => Promise<unknown>): Promise<IRun> => {
	gc();
	const baseline = process.memoryUsage().heapUsed;
	let maxLagMs = 0;
	let last = Date.now();
	let probing = true;
	const probe = (): void => {
		const now = Date.now();
		maxLagMs = Math.max(maxLagMs, now - last);
		last = now;
		if (probing) setTimeout(probe, 1);
	};
	setTimeout(probe, 1);
	const profiler = new v8.GCProfiler();
	profiler.start();
	const start = process.hrtime.bigint();
	const answer = await refresh();
	const ms = Number(process.hrtime.bigint() - start) / 1e6;
	const end = process.memoryUsage().heapUsed;
	const profile = profiler.stop();
	probing = false;
	maxLagMs = Math.max(maxLagMs, Date.now() - last);
	const freed = (profile?.statistics ?? []).reduce(
		(sum, gcRun) =>
			sum +
			gcRun.beforeGC.heapStatistics.usedHeapSize -
			gcRun.afterGC.heapStatistics.usedHeapSize,
		0
	);
	gc();
	const retained = process.memoryUsage().heapUsed - baseline;
	// Held until here, so the collection above cannot take it.
	void answer;
	return {
		ms,
		maxLagMs,
		allocMiB: (end - baseline + freed) / MiB,
		retainedMiB: Math.max(0, retained) / MiB
	};
};

const summarise = (label: string, runs: IRun[]): string =>
	[
		label.padEnd(14),
		median(runs.map((r) => r.ms))
			.toFixed(2)
			.padStart(9),
		median(runs.map((r) => r.maxLagMs))
			.toFixed(0)
			.padStart(9),
		median(runs.map((r) => r.allocMiB))
			.toFixed(2)
			.padStart(10),
		median(runs.map((r) => r.retainedMiB))
			.toFixed(2)
			.padStart(12)
	].join(' ');

const main = async (): Promise<void> => {
	if (!(global as { gc?: () => void }).gc) {
		console.log('Run node with --expose-gc for allocation figures.');
	}
	console.log(
		`Node ${process.version} ${process.platform}/${process.arch}, ${RUNS} runs`
	);
	for (const records of RECORDS) {
		const wallet = await openWallet(records);
		const waited = (): Promise<unknown> => refreshLiveWallet(wallet);
		const answered = (): Promise<unknown> => wallet.refreshWallet();
		await measure(waited);
		await measure(answered);
		const waits: IRun[] = [];
		const answers: IRun[] = [];
		for (let i = 0; i < RUNS; i++) {
			waits.push(await measure(waited));
			answers.push(await measure(answered));
		}
		console.log(`\n${records} records`);
		console.log('refresh               ms  maxLagMs   allocMiB  retainedMiB');
		console.log(summarise('refreshWallet', answers));
		console.log(summarise('waited only', waits));
		await wallet.stop();
	}
};

main().then(
	() => process.exit(0),
	(e) => {
		console.error(e);
		process.exit(1);
	}
);
