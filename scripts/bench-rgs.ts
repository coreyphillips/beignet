/**
 * Rapid Gossip Sync import benchmark: the 0.27.0 one-pass parser (the test
 * oracle) against the cooperative importer, run synchronously and in
 * slices, on a full mainnet snapshot. Each run applies the snapshot to a
 * fresh graph; modes are interleaved so machine load hits them alike, and
 * the median run is reported. Usage:
 *   npx ts-node scripts/bench-rgs.ts [runs]
 * Downloads https://rapidsync.lightningdevkit.org/snapshot/0 unless
 * RGS_SNAPSHOT_FILE names a saved copy. RGS_SLICE_MS overrides the async
 * slice (default LightningNode.RAPID_GOSSIP_SLICE_MS). Run node with
 * --expose-gc to collect between runs.
 *
 * Columns: wall is start to finish; busy is time spent applying (all of it
 * for a one-pass run); maxSlice is the longest stretch without a yield;
 * maxLag is the longest the event loop went without serving a probe timer.
 */
import * as fs from 'fs';
import { NetworkGraph } from '../src/lightning/gossip/network-graph';
import {
	applyRapidGossipSnapshot,
	applyRapidGossipSnapshotAsync,
	fetchRapidGossipSnapshot,
	DEFAULT_RGS_URL,
	IRapidGossipResult
} from '../src/lightning/gossip/rapid-sync';
import { LightningNode } from '../src/lightning/node/lightning-node';
import { applyRapidGossipSnapshotReference } from '../tests/lightning/helpers/rapid-sync-reference';

interface IRun {
	wallMs: number;
	busyMs: number;
	slices: number;
	maxSliceMs: number;
	maxLagMs: number;
	result: IRapidGossipResult;
}

type TMode = (data: Buffer) => Promise<IRun>;

/** Longest gap between probe timers while `work` runs. */
async function withLagProbe(
	work: () => Promise<Omit<IRun, 'maxLagMs'>>
): Promise<IRun> {
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
	const run = await work();
	probing = false;
	// The probe never fired during a one-pass run, so the final gap counts.
	maxLagMs = Math.max(maxLagMs, Date.now() - last);
	return { ...run, maxLagMs };
}

const oneShot =
	(apply: (graph: NetworkGraph, data: Buffer) => IRapidGossipResult): TMode =>
	(data) =>
		withLagProbe(async () => {
			const start = Date.now();
			const result = apply(new NetworkGraph(), data);
			const ms = Date.now() - start;
			return { wallMs: ms, busyMs: ms, slices: 1, maxSliceMs: ms, result };
		});

const sliced =
	(sliceMs: number): TMode =>
	(data) =>
		withLagProbe(async () => {
			let busyMs = 0;
			let slices = 0;
			let maxSliceMs = 0;
			const start = Date.now();
			const result = await applyRapidGossipSnapshotAsync(
				new NetworkGraph(),
				data,
				{
					sliceMs,
					onSlice: (ms) => {
						busyMs += ms;
						slices++;
						maxSliceMs = Math.max(maxSliceMs, ms);
					}
				}
			);
			const wallMs = Date.now() - start;
			return { wallMs, busyMs, slices, maxSliceMs, result };
		});

const median = (xs: number[]): number => {
	const s = [...xs].sort((a, b) => a - b);
	return s[Math.floor(s.length / 2)];
};

const main = async (): Promise<void> => {
	const runs = Number(process.argv[2] ?? 7);
	const file = process.env.RGS_SNAPSHOT_FILE;
	const sliceMs = Number(
		process.env.RGS_SLICE_MS ?? LightningNode.RAPID_GOSSIP_SLICE_MS
	);
	const data = file
		? fs.readFileSync(file)
		: await fetchRapidGossipSnapshot(DEFAULT_RGS_URL);
	console.log(
		`snapshot: ${file ?? DEFAULT_RGS_URL} (${data.length} bytes), ` +
			`${runs} runs per mode, node ${process.version}`
	);

	const modes: Array<[string, TMode]> = [
		['oracle-sync', oneShot(applyRapidGossipSnapshotReference)],
		['new-sync', oneShot(applyRapidGossipSnapshot)],
		[`new-async (${sliceMs}ms)`, sliced(sliceMs)]
	];
	const gc = (globalThis as { gc?: () => void }).gc;
	const results = new Map<string, IRun[]>(modes.map(([name]) => [name, []]));
	// One warm-up pass, then interleaved measured runs.
	for (let r = -1; r < runs; r++) {
		for (const [name, mode] of modes) {
			gc?.();
			const run = await mode(data);
			if (r >= 0) results.get(name)!.push(run);
		}
	}

	const rows = modes.map(([name]) => {
		const rs = results.get(name)!;
		const { channelsAdded, updatesApplied } = rs[0].result;
		return {
			mode: name,
			wallMs: median(rs.map((r) => r.wallMs)),
			busyMs: median(rs.map((r) => r.busyMs)),
			slices: median(rs.map((r) => r.slices)),
			maxSliceMs: median(rs.map((r) => r.maxSliceMs)),
			maxLagMs: median(rs.map((r) => r.maxLagMs)),
			channels: channelsAdded,
			updates: updatesApplied
		};
	});
	console.table(rows);
};

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
