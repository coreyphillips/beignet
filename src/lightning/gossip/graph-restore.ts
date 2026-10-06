/**
 * Bringing back the network map a node stored, in one pass or a time slice
 * at a time (LightningNode's cooperative graph restore).
 *
 * This is the gossip block restoreFromStorage ran inline, moved here with
 * the same outcome: channel rows past the freshness cutoff are left out and
 * condemned, every other channel row is restored in storage order, and node
 * rows follow once every channel row is in, a node row with no channel
 * behind it on disk condemned rather than restored. Condemned rows are only
 * deleted when the caller runs `staleRowDeletes`, after the last step.
 */
import { IStorageBackend } from '../storage/types';
import { NetworkGraph } from './network-graph';
import {
	IGraphChannel,
	IGraphNode,
	gossipTimestampTooFarFuture
} from './types';

/** Rows read in a page when a restore starts, before it has timed any. */
const FIRST_PAGE_ROWS = 16;
/** The most rows one page reads, however cheap they turn out to be. */
const MAX_PAGE_ROWS = 2048;
/** Rows restored between two checks of the slice's clock. */
const ROWS_PER_CLOCK_CHECK = 16;

type TGraphRestoreStorage = Pick<
	IStorageBackend,
	| 'loadAllGossipChannels'
	| 'loadAllGossipNodes'
	| 'loadGossipChannelsAfter'
	| 'loadGossipNodesAfter'
	| 'deleteGossipChannel'
	| 'deleteGossipNode'
>;

/** What a restore read and how long each kind of work took, in ms. */
export interface IGossipGraphRestoreCounts {
	channelRows: number;
	staleChannels: number;
	nodeRows: number;
	orphanNodes: number;
	/** Reading and parsing the channel rows. */
	loadChannelsMs: number;
	restoreChannelsMs: number;
	/** Reading and parsing the node rows. */
	loadNodesMs: number;
	restoreNodesMs: number;
}

export class GossipGraphRestore {
	/**
	 * Every row the restore condemned, to delete together once it is done.
	 * One at a time is the same fsync storm as the hourly prune (see
	 * batchStorageDeletes), and it runs before the daemon can listen, so it
	 * surfaces as a node that takes minutes to start rather than as a node
	 * that stalls.
	 */
	readonly staleRowDeletes: Array<() => void> = [];
	/**
	 * Endpoints of every channel row that stays on disk past the stale
	 * filter. Node-row orphanhood is decided against DISK, not the capped
	 * in-memory graph: restoreChannel keeps verified overflow rows on disk
	 * without admitting them, and their node rows must survive alongside
	 * them. Rows restoreChannel itself trims from disk leave their endpoints
	 * here; those node rows are cleaned one boot later, once their channel
	 * rows are gone.
	 */
	private readonly diskChannelEndpoints = new Set<string>();
	private phase: 'channels' | 'nodes' | 'done' = 'channels';
	private channels: IGraphChannel[] = [];
	private nodes: IGraphNode[] = [];
	private next = 0;
	private cursor = 0;
	private exhausted = false;
	private pageRows = FIRST_PAGE_ROWS;
	private readonly counts: IGossipGraphRestoreCounts = {
		channelRows: 0,
		staleChannels: 0,
		nodeRows: 0,
		orphanNodes: 0,
		loadChannelsMs: 0,
		restoreChannelsMs: 0,
		loadNodesMs: 0,
		restoreNodesMs: 0
	};

	/**
	 * `cutoff` is the freshness bound in unix seconds: a channel row whose
	 * newest believable update is older is stale. Far-future timestamps do
	 * not count toward freshness, since restoreChannel drops those slots and
	 * such a row is equally short-lived. With `paged` set and a storage that
	 * can page, rows are read a page at a time, each page sized to about half
	 * the slice; otherwise each kind of row is read whole on its first step,
	 * as the inline restore always did.
	 */
	constructor(
		private readonly graph: NetworkGraph,
		private readonly storage: TGraphRestoreStorage,
		private readonly cutoff: number,
		private readonly paged = false
	) {}

	/**
	 * Restores rows until `budgetMs` has passed or none are left, and says
	 * whether none are left. A page is read whole once begun, so a step can
	 * run past its budget by one page.
	 */
	step(budgetMs: number): boolean {
		const started = Date.now();
		const spent = (): boolean => Date.now() - started >= budgetMs;
		while (this.phase !== 'done') {
			if (this.phase === 'channels') {
				if (this.next >= this.channels.length) {
					if (this.exhausted) {
						this.channels = [];
						this.startPhase('nodes');
						continue;
					}
					this.channels = this.readPage('channels', budgetMs);
				}
				const restoring = Date.now();
				let checked = 0;
				while (this.next < this.channels.length) {
					this.restoreChannel(this.channels[this.next++]);
					if (++checked % ROWS_PER_CLOCK_CHECK === 0 && spent()) break;
				}
				this.counts.restoreChannelsMs += Date.now() - restoring;
			} else {
				if (this.next >= this.nodes.length) {
					if (this.exhausted) {
						this.nodes = [];
						this.phase = 'done';
						break;
					}
					this.nodes = this.readPage('nodes', budgetMs);
				}
				const restoring = Date.now();
				let checked = 0;
				while (this.next < this.nodes.length) {
					this.restoreNode(this.nodes[this.next++]);
					if (++checked % ROWS_PER_CLOCK_CHECK === 0 && spent()) break;
				}
				this.counts.restoreNodesMs += Date.now() - restoring;
			}
			if (spent()) return false;
		}
		return true;
	}

	/** What the restore has read and done so far. */
	stats(): IGossipGraphRestoreCounts {
		return { ...this.counts };
	}

	private startPhase(phase: 'nodes'): void {
		this.phase = phase;
		this.next = 0;
		this.cursor = 0;
		this.exhausted = false;
		this.pageRows = FIRST_PAGE_ROWS;
	}

	/** Reads the next page of the phase's rows, or all of them unpaged. */
	private readPage(kind: 'channels', budgetMs: number): IGraphChannel[];
	private readPage(kind: 'nodes', budgetMs: number): IGraphNode[];
	private readPage(
		kind: 'channels' | 'nodes',
		budgetMs: number
	): IGraphChannel[] | IGraphNode[] {
		const reading = Date.now();
		const page =
			kind === 'channels'
				? this.paged && this.storage.loadGossipChannelsAfter
					? this.storage.loadGossipChannelsAfter(this.cursor, this.pageRows)
					: null
				: this.paged && this.storage.loadGossipNodesAfter
				? this.storage.loadGossipNodesAfter(this.cursor, this.pageRows)
				: null;
		let rows: IGraphChannel[] | IGraphNode[];
		if (page) {
			rows = page.rows;
			this.cursor = page.cursor;
			this.exhausted = page.done;
		} else {
			rows =
				kind === 'channels'
					? this.storage.loadAllGossipChannels()
					: this.storage.loadAllGossipNodes();
			this.exhausted = true;
		}
		const ms = Date.now() - reading;
		this.next = 0;
		if (kind === 'channels') {
			this.counts.channelRows += rows.length;
			this.counts.loadChannelsMs += ms;
		} else {
			this.counts.nodeRows += rows.length;
			this.counts.loadNodesMs += ms;
		}
		// The next page aims at half the slice, by what this one cost a row.
		if (page && rows.length > 0 && Number.isFinite(budgetMs)) {
			const perRow = Math.max(ms, 1) / rows.length;
			this.pageRows = Math.min(
				MAX_PAGE_ROWS,
				Math.max(FIRST_PAGE_ROWS, Math.floor(budgetMs / 2 / perRow))
			);
		}
		return rows;
	}

	private restoreChannel(channel: IGraphChannel): void {
		const ts1 =
			channel.update1 && !gossipTimestampTooFarFuture(channel.update1.timestamp)
				? channel.update1.timestamp
				: 0;
		const ts2 =
			channel.update2 && !gossipTimestampTooFarFuture(channel.update2.timestamp)
				? channel.update2.timestamp
				: 0;
		if (Math.max(ts1, ts2) < this.cutoff) {
			this.counts.staleChannels++;
			if (typeof this.storage.deleteGossipChannel === 'function') {
				const scidHex = channel.shortChannelId.toString('hex');
				this.staleRowDeletes.push(() =>
					this.storage.deleteGossipChannel!(scidHex)
				);
			}
			return;
		}
		this.diskChannelEndpoints.add(channel.nodeId1.toString('hex'));
		this.diskChannelEndpoints.add(channel.nodeId2.toString('hex'));
		this.graph.restoreChannel(channel);
	}

	/**
	 * Every channel row is in by now, and each created a graph node entry for
	 * its endpoints. A node row absent from the graph AND from the surviving
	 * disk channel rows' endpoints has no channel behind it: an orphan leaked
	 * before node rows were deleted alongside their last channel (issue
	 * #447). Restoring it would resurrect the leak in memory, so it is
	 * condemned and skipped. A node row referenced only by a retained
	 * overflow channel row is kept on disk but not restored; it returns with
	 * its channel on a later boot. Channel peer reconnects are unaffected:
	 * their addresses live in the announced peer address capture, not in
	 * gossip_nodes.
	 */
	private restoreNode(node: IGraphNode): void {
		if (!this.graph.getNode(node.nodeId)) {
			const nodeIdHex = node.nodeId.toString('hex');
			if (this.diskChannelEndpoints.has(nodeIdHex)) return;
			this.counts.orphanNodes++;
			if (typeof this.storage.deleteGossipNode === 'function') {
				this.staleRowDeletes.push(() =>
					this.storage.deleteGossipNode!(nodeIdHex)
				);
			}
			return;
		}
		this.graph.restoreNode(node);
	}
}
