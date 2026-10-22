/**
 * A conformance suite for IStorageBackend implementations: what the node
 * relies on a backend for, checked against any backend. SqliteStorage and
 * MemoryStorage both pass it. From a mocha, Jest or Vitest test file:
 *
 *   runStorageConformanceSuite(() => new MyStorage());
 *
 * Every check builds its own backend with the factory, opens it and closes
 * it, so the factory must return a new, empty backend on each call. A check
 * for a capability group the backend does not implement is skipped.
 */

import type { IChannelState } from '../channel/channel-state';
import { createOpenerState } from '../channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../channel/types';
import type { IHtlcSnapshotEntry } from '../channel/types';
import type { IChannelBasepoints } from '../keys/derivation';
import type { IChainMonitorState } from '../chain/chain-monitor';
import { MonitorState, OutputStatus, OutputType } from '../chain/types';
import type { IPaymentInfo } from '../node/payment-types';
import { PaymentDirection, PaymentStatus } from '../node/payment-types';
import type { IGraphChannel, IGraphNode } from '../gossip/types';
import type { IFforVoucherArchive } from '../ffor/voucher-archive';
import type { IWatchtowerSession } from '../watchtower/types';
import { sha256 } from '../crypto/provider';
import type {
	IInvoiceInfo,
	IStorageBackend,
	IStorageCapabilities,
	IStoredRecoveryFrame,
	StorageCapability
} from './types';
import {
	STORAGE_CORE_MEMBERS,
	hasRecoveryStorage,
	hasStorageCapability,
	partialStorageCapabilities
} from './capabilities';
import {
	serializeChainMonitorState,
	serializeChannelState,
	serializeGraphChannel,
	serializeGraphNode,
	serializeInvoiceInfo,
	serializePaymentInfo
} from './serialization';

/** One check of the suite, runnable without a test framework. */
export interface IStorageConformanceCheck {
	/** What the check proves; the test name. */
	name: string;
	/** The capability group the check needs; absent for a core check. */
	capability?: StorageCapability;
	/**
	 * Run the check against a new backend from the factory. Throws when the
	 * backend fails it; 'skipped' when it lacks the capability.
	 */
	run(): 'passed' | 'skipped';
}

// ─── Assertions ───

function fail(message: string): never {
	throw new Error(`storage conformance: ${message}`);
}

function ensure(condition: boolean, message: string): void {
	if (!condition) fail(message);
}

/**
 * A JSON form of a value that two equal values share whatever their key
 * order: Buffers as hex, bigints, Maps and Sets tagged, undefined dropped.
 */
function canonical(value: unknown): unknown {
	if (typeof value === 'bigint') return { $bigint: value.toString() };
	if (value instanceof Uint8Array) {
		return { $hex: Buffer.from(value).toString('hex') };
	}
	if (value instanceof Map) {
		return { $map: [...value].map(([k, v]) => [canonical(k), canonical(v)]) };
	}
	if (value instanceof Set) return { $set: [...value].map(canonical) };
	if (Array.isArray(value)) {
		return value.map((item) => (item === undefined ? null : canonical(item)));
	}
	if (value !== null && typeof value === 'object') {
		const out: Record<string, unknown> = {};
		for (const key of Object.keys(value).sort()) {
			const item = (value as Record<string, unknown>)[key];
			if (item !== undefined) out[key] = canonical(item);
		}
		return out;
	}
	return value;
}

function show(value: unknown): string {
	const text = JSON.stringify(canonical(value)) ?? 'undefined';
	return text.length > 400 ? `${text.slice(0, 400)}...` : text;
}

function same(actual: unknown, expected: unknown, what: string): void {
	const a = JSON.stringify(canonical(actual));
	const e = JSON.stringify(canonical(expected));
	if (a !== e) fail(`${what}: expected ${show(expected)}, got ${show(actual)}`);
}

/** Order-insensitive `same`, for loaders that promise no order. */
function sameSet<T>(
	actual: T[],
	expected: T[],
	key: (item: T) => string,
	what: string
): void {
	const sort = (items: T[]): T[] =>
		[...items].sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
	same(sort(actual), sort(expected), what);
}

function throwsError(fn: () => unknown): boolean {
	try {
		fn();
	} catch {
		return true;
	}
	return false;
}

// ─── Fixtures ───

/** `length` deterministic bytes, distinct per seed. */
function bytes(seed: number, length = 32): Buffer {
	const out = Buffer.alloc(length);
	for (let i = 0; i < length; i++) out[i] = (seed * 131 + i * 7 + 1) & 0xff;
	return out;
}

function hexId(seed: number): string {
	return bytes(seed).toString('hex');
}

function point(seed: number): Buffer {
	const key = bytes(seed, 33);
	key[0] = 0x02;
	return key;
}

function basepoints(seed: number): IChannelBasepoints {
	return {
		fundingPubkey: point(seed),
		revocationBasepoint: point(seed + 1),
		paymentBasepoint: point(seed + 2),
		delayedPaymentBasepoint: point(seed + 3),
		htlcBasepoint: point(seed + 4),
		firstPerCommitmentPoint: point(seed + 5)
	};
}

function snapshotEntries(seed: number): IHtlcSnapshotEntry[] {
	return [
		{
			paymentHash: bytes(seed),
			amountMsat: 2_500_000n + BigInt(seed),
			cltvExpiry: 800_100 + seed,
			direction: HtlcDirection.OFFERED
		}
	];
}

/** A channel in NORMAL with one HTLC, and the given revoked snapshots. */
function channelState(seed: number, snapshots: string[] = []): IChannelState {
	const state = createOpenerState({
		temporaryChannelId: bytes(seed),
		fundingSatoshis: 1_000_000n,
		pushMsat: 1_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: basepoints(seed + 10),
		localPerCommitmentSeed: bytes(seed + 20)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = bytes(seed + 30);
	state.fundingTxid = bytes(seed + 40);
	state.localCommitmentNumber = 7n;
	state.remoteCommitmentNumber = 6n;
	state.localBalanceMsat = 600_000_000n;
	state.remoteBalanceMsat = 399_000_000n;
	state.remoteBasepoints = basepoints(seed + 50);
	state.remoteCurrentPerCommitmentPoint = point(seed + 60);
	state.localHtlcCounter = 1n;
	state.htlcs.set('offered-0', {
		id: 0n,
		amountMsat: 1_000_000n,
		paymentHash: bytes(seed + 70),
		cltvExpiry: 800_144,
		onionRoutingPacket: bytes(seed + 80, 1366),
		direction: HtlcDirection.OFFERED,
		state: HtlcState.COMMITTED
	});
	if (snapshots.length > 0) {
		state.revokedHtlcSnapshots = new Map(
			snapshots.map((n) => [n, snapshotEntries(Number(n))])
		);
	}
	return state;
}

/** A channel as the library serializes it, its whole snapshot history included. */
function channelForm(state: IChannelState): unknown {
	return serializeChannelState(state, { htlcHistory: 'all' });
}

function payment(seed: number): IPaymentInfo {
	return {
		paymentHash: bytes(seed),
		preimage: bytes(seed + 1),
		// Past 2^53, so a backend that goes through a JS number loses it.
		amountMsat: 9_007_199_254_740_993n + BigInt(seed),
		sentMsat: 9_007_199_254_741_993n,
		status: PaymentStatus.COMPLETED,
		direction: PaymentDirection.OUTGOING,
		sharedSecrets: [bytes(seed + 2), bytes(seed + 3)],
		retryCount: 2,
		createdAt: 1_700_000_000_000 + seed,
		completedAt: 1_700_000_001_000 + seed,
		metadata: { label: `payment ${seed}` }
	};
}

function chainMonitor(seed: number): IChainMonitorState {
	return {
		monitorState: MonitorState.RESOLVING,
		commitmentBroadcast: null,
		trackedOutputs: [
			{
				txid: hexId(seed),
				outputIndex: 1,
				amount: 50_000n,
				outputType: OutputType.OFFERED_HTLC,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 800_000,
				paymentHash: bytes(seed + 1),
				htlcId: 3n,
				cltvExpiry: 800_200,
				witnessScript: bytes(seed + 2, 70)
			}
		],
		currentBlockHeight: 800_010 + seed,
		knownPreimages: { [hexId(seed + 3)]: hexId(seed + 4) }
	};
}

function gossipChannel(seed: number): IGraphChannel {
	const shortChannelId = bytes(seed, 8);
	return {
		shortChannelId,
		nodeId1: point(seed + 1),
		nodeId2: point(seed + 2),
		features: Buffer.alloc(0),
		announcement: {
			nodeSignature1: bytes(seed + 3, 64),
			nodeSignature2: bytes(seed + 4, 64),
			bitcoinSignature1: bytes(seed + 5, 64),
			bitcoinSignature2: bytes(seed + 6, 64),
			features: Buffer.alloc(0),
			chainHash: bytes(seed + 7),
			shortChannelId,
			nodeId1: point(seed + 1),
			nodeId2: point(seed + 2),
			bitcoinKey1: point(seed + 8),
			bitcoinKey2: point(seed + 9)
		},
		announcementVerified: true,
		fundingVerified: true
	};
}

function gossipNode(seed: number): IGraphNode {
	return {
		nodeId: point(seed),
		channels: new Set([hexId(seed + 1).slice(0, 16)]),
		announcement: {
			signature: bytes(seed + 2, 64),
			features: Buffer.from([0x02]),
			timestamp: 1_700_000_000 + seed,
			nodeId: point(seed),
			rgbColor: Buffer.from([1, 2, 3]),
			alias: bytes(seed + 3),
			addresses: []
		},
		announcementVerified: true
	};
}

function invoice(seed: number): IInvoiceInfo {
	return {
		paymentHash: hexId(seed),
		bolt11: `lnbcrt${seed}invoice`,
		amountMsat: 9_007_199_254_740_993n,
		description: `invoice ${seed}`,
		expiry: 3600,
		createdAt: 1_700_000_000 + seed,
		hold: true,
		bolt12: false,
		cancelledAt: 1_700_000_100_000,
		jitFee: { flatFeeSat: 2000, feePpm: 1000 },
		minFinalCltvExpiry: 144
	};
}

function fforVoucher(seed: number, withPreimage: boolean): IFforVoucherArchive {
	const preimage = bytes(seed + 1);
	return {
		channelId: hexId(seed + 2),
		epochId: hexId(seed + 3),
		slot: 1 + (seed % 400),
		role: 'R',
		paymentHash: sha256(preimage).toString('hex'),
		amountMsat: '1000000',
		htlcId: '4',
		voucherExpiry: 800_500,
		concurrentVersion: 0,
		...(withPreimage ? { preimage: preimage.toString('hex') } : {})
	};
}

function watchtowerSession(seed: number, towerUri: string): IWatchtowerSession {
	return {
		towerUri,
		towerPubkey: point(seed).toString('hex'),
		sessionId: point(seed + 1).toString('hex'),
		blobType: 2,
		maxUpdates: 1024,
		sweepFeeRate: '2500',
		seqNum: 0,
		lastApplied: 0,
		createdAt: 1_700_000_000_000 + seed,
		dialsWithSessionKey: true
	};
}

function frame(sequence: number): IStoredRecoveryFrame {
	return {
		sequence,
		writerEpoch: 1,
		frameHash: bytes(sequence + 500),
		previousFrameHash: bytes(sequence + 499),
		ciphertext: bytes(sequence + 600, 48),
		createdAt: 1_700_000_000_000 + sequence
	};
}

// ─── Checks ───

type Body<S> = (storage: S) => void;

/**
 * The checks of the suite against backends from `factory`. A runner other
 * than mocha, Jest or Vitest can call run() on each itself.
 */
export function storageConformanceChecks(
	factory: () => IStorageBackend
): IStorageConformanceCheck[] {
	const checks: IStorageConformanceCheck[] = [];

	const withBackend = (body: Body<IStorageBackend>): void => {
		const storage = factory();
		storage.open();
		try {
			body(storage);
		} finally {
			storage.close();
		}
	};

	const core = (name: string, body: Body<IStorageBackend>): void => {
		checks.push({
			name,
			run: () => {
				withBackend(body);
				return 'passed';
			}
		});
	};

	const optional = <K extends StorageCapability>(
		capability: K,
		name: string,
		body: Body<IStorageBackend & IStorageCapabilities[K]>
	): void => {
		checks.push({
			name: `${capability}: ${name}`,
			capability,
			run: () => {
				let status: 'passed' | 'skipped' = 'passed';
				withBackend((storage) => {
					if (!hasStorageCapability(storage, capability)) {
						status = 'skipped';
						return;
					}
					body(storage);
				});
				return status;
			}
		});
	};

	// ─── Shape ───

	core('implements every IStorageCore method', (storage) => {
		const methods = storage as unknown as Record<string, unknown>;
		const missing = Object.keys(STORAGE_CORE_MEMBERS).filter(
			(member) => typeof methods[member] !== 'function'
		);
		ensure(missing.length === 0, `missing core methods: ${missing.join(', ')}`);
	});

	core('implements each capability group whole or not at all', (storage) => {
		const partial = partialStorageCapabilities(storage);
		ensure(
			partial.length === 0,
			`partly implemented capability groups: ${partial.join(', ')}`
		);
	});

	core('a new backend is empty', (storage) => {
		ensure(storage.loadAllChannels().length === 0, 'channels are stored');
		ensure(storage.loadAllPayments().length === 0, 'payments are stored');
		ensure(storage.loadAllPreimages().length === 0, 'preimages are stored');
		ensure(storage.loadAllInvoices().length === 0, 'invoices are stored');
		ensure(storage.loadMissionControl() === null, 'mission control is stored');
		ensure(
			storage.loadNextChannelIndex() === 1,
			'loadNextChannelIndex is not 1 with no key index stored'
		);
	});

	// ─── Channels ───

	core('channels round-trip, overwrite and delete', (storage) => {
		const a = channelState(1);
		const b = channelState(2);
		const idA = a.channelId!.toString('hex');
		const idB = b.channelId!.toString('hex');
		ensure(storage.loadChannel(idA) === null, 'missing channel is not null');
		storage.saveChannel(idA, a, 'peer-a');
		storage.saveChannel(idB, b, 'peer-b');
		const loaded = storage.loadChannel(idA);
		ensure(loaded !== null, 'saved channel did not load');
		same(loaded!.peerPubkey, 'peer-a', 'loadChannel peerPubkey');
		same(channelForm(loaded!.state), channelForm(a), 'loadChannel state');
		sameSet(
			storage
				.loadAllChannels()
				.map((row) => [row.channelId, row.peerPubkey, channelForm(row.state)]),
			[
				[idA, 'peer-a', channelForm(a)],
				[idB, 'peer-b', channelForm(b)]
			],
			(row) => row[0] as string,
			'loadAllChannels'
		);

		const changed = channelState(1);
		changed.localCommitmentNumber = 8n;
		storage.saveChannel(idA, changed, 'peer-a2');
		const overwritten = storage.loadChannel(idA)!;
		same(overwritten.peerPubkey, 'peer-a2', 'overwritten peerPubkey');
		same(
			overwritten.state.localCommitmentNumber,
			8n,
			'overwritten channel state'
		);
		ensure(storage.loadAllChannels().length === 2, 'overwrite added a row');

		storage.deleteChannel(idA);
		ensure(storage.loadChannel(idA) === null, 'deleted channel still loads');
		same(
			storage.loadAllChannels().map((row) => row.channelId),
			[idB],
			'channels after delete'
		);
		storage.deleteChannel(idA);
	});

	core(
		'saveChannel adds revoked HTLC snapshots to the stored ones',
		(storage) => {
			const first = channelState(3, ['5', '6']);
			const id = first.channelId!.toString('hex');
			storage.saveChannel(id, first, 'peer');
			// A state carrying only a newer snapshot, as a journal delta does.
			storage.saveChannel(id, channelState(3, ['10']), 'peer');
			// And one carrying none.
			storage.saveChannel(id, channelState(3), 'peer');
			const expected = ['5', '6', '10'].map((n) => [
				n,
				snapshotEntries(Number(n))
			]);
			const entries = (state: IChannelState): unknown[] =>
				[...(state.revokedHtlcSnapshots ?? [])].sort(([a], [b]) =>
					a.length !== b.length ? a.length - b.length : a < b ? -1 : 1
				);
			same(
				entries(storage.loadChannel(id)!.state),
				expected,
				'loadChannel revokedHtlcSnapshots'
			);
			same(
				entries(storage.loadAllChannels()[0].state),
				expected,
				'loadAllChannels revokedHtlcSnapshots'
			);

			// Deleting the channel deletes them, so a channel saved again under
			// the same id starts with none.
			storage.deleteChannel(id);
			storage.saveChannel(id, channelState(3), 'peer');
			ensure(
				!storage.loadChannel(id)!.state.revokedHtlcSnapshots?.size,
				'deleteChannel kept the revoked HTLC snapshots'
			);
		}
	);

	core('stores copies, not the objects it is given', (storage) => {
		const state = channelState(4);
		const id = state.channelId!.toString('hex');
		storage.saveChannel(id, state, 'peer');
		state.localCommitmentNumber = 99n;
		state.channelId!.fill(0);
		const loaded = storage.loadChannel(id)!.state;
		same(loaded.localCommitmentNumber, 7n, 'state changed after save');
		same(loaded.channelId, channelState(4).channelId, 'channelId bytes');
		loaded.localCommitmentNumber = 98n;
		same(
			storage.loadChannel(id)!.state.localCommitmentNumber,
			7n,
			'state changed through a loaded object'
		);

		const info = payment(5);
		const hash = info.paymentHash.toString('hex');
		storage.savePayment(hash, info);
		info.status = PaymentStatus.FAILED;
		same(
			storage.loadPayment(hash)!.status,
			PaymentStatus.COMPLETED,
			'payment changed after save'
		);

		const preimage = bytes(6);
		storage.savePreimage('hash', preimage);
		preimage.fill(0);
		same(storage.loadPreimage('hash'), bytes(6), 'preimage bytes after save');
		storage.loadPreimage('hash')!.fill(1);
		same(
			storage.loadPreimage('hash'),
			bytes(6),
			'preimage changed through a loaded buffer'
		);
	});

	// ─── Payments, preimages and HTLC bookkeeping ───

	core('payments round-trip, overwrite and delete', (storage) => {
		const a = payment(10);
		const b = payment(11);
		const hashA = a.paymentHash.toString('hex');
		const hashB = b.paymentHash.toString('hex');
		ensure(storage.loadPayment(hashA) === null, 'missing payment is not null');
		storage.savePayment(hashA, a);
		storage.savePayment(hashB, b);
		same(
			serializePaymentInfo(storage.loadPayment(hashA)!),
			serializePaymentInfo(a),
			'loadPayment'
		);
		sameSet(
			storage
				.loadAllPayments()
				.map((row) => [row.paymentHash, serializePaymentInfo(row.payment)]),
			[
				[hashA, serializePaymentInfo(a)],
				[hashB, serializePaymentInfo(b)]
			],
			(row) => row[0] as string,
			'loadAllPayments'
		);
		storage.savePayment(hashA, { ...a, status: PaymentStatus.FAILED });
		same(
			storage.loadPayment(hashA)!.status,
			PaymentStatus.FAILED,
			'overwritten payment'
		);
		storage.deletePayment(hashA);
		ensure(storage.loadPayment(hashA) === null, 'deleted payment still loads');
		same(
			storage.loadAllPayments().map((row) => row.paymentHash),
			[hashB],
			'payments after delete'
		);
		storage.deletePayment(hashA);
	});

	core('preimages round-trip and delete', (storage) => {
		ensure(storage.loadPreimage('a') === null, 'missing preimage is not null');
		storage.savePreimage('a', bytes(20));
		storage.savePreimage('b', bytes(21));
		same(storage.loadPreimage('a'), bytes(20), 'loadPreimage');
		sameSet(
			storage.loadAllPreimages(),
			[
				{ paymentHash: 'a', preimage: bytes(20) },
				{ paymentHash: 'b', preimage: bytes(21) }
			],
			(row) => row.paymentHash,
			'loadAllPreimages'
		);
		storage.deletePreimage('a');
		ensure(storage.loadPreimage('a') === null, 'deleted preimage still loads');
		same(storage.loadAllPreimages().length, 1, 'preimages after delete');
		storage.deletePreimage('a');
	});

	core(
		'payment secrets and HTLC shared secrets round-trip and delete',
		(storage) => {
			storage.savePaymentSecret('p1', bytes(30));
			storage.savePaymentSecret('p2', bytes(31));
			storage.savePaymentSecret('p1', bytes(32));
			sameSet(
				storage.loadAllPaymentSecrets(),
				[
					{ paymentHashHex: 'p1', secret: bytes(32) },
					{ paymentHashHex: 'p2', secret: bytes(31) }
				],
				(row) => row.paymentHashHex,
				'loadAllPaymentSecrets'
			);
			storage.deletePaymentSecret('p1');
			same(
				storage.loadAllPaymentSecrets(),
				[{ paymentHashHex: 'p2', secret: bytes(31) }],
				'payment secrets after delete'
			);

			storage.saveHtlcSharedSecret('k1', bytes(33));
			storage.saveHtlcSharedSecret('k2', bytes(34));
			storage.deleteHtlcSharedSecret('k1');
			storage.deleteHtlcSharedSecret('missing');
			same(
				storage.loadAllHtlcSharedSecrets(),
				[{ key: 'k2', secret: bytes(34) }],
				'loadAllHtlcSharedSecrets'
			);
		}
	);

	core('SCID mappings, HTLC payment map and forwarded HTLCs', (storage) => {
		storage.saveScidMapping('scid1', bytes(40));
		storage.saveScidMapping('scid2', bytes(41));
		storage.saveScidMapping('scid1', bytes(42));
		sameSet(
			storage.loadAllScidMappings(),
			[
				{ scidHex: 'scid1', channelId: bytes(42) },
				{ scidHex: 'scid2', channelId: bytes(41) }
			],
			(row) => row.scidHex,
			'loadAllScidMappings'
		);

		storage.saveHtlcPaymentMapping('h1', 'hash1');
		storage.saveHtlcPaymentMapping('h2', 'hash2');
		storage.deleteHtlcPaymentMapping('h1');
		same(
			storage.loadAllHtlcPaymentMappings(),
			[{ key: 'h2', paymentHashHex: 'hash2' }],
			'loadAllHtlcPaymentMappings'
		);

		const bigId = 18_446_744_073_709_551_615n;
		storage.saveForwardedHtlc('out1', bytes(43), bigId);
		storage.saveForwardedHtlc('out2', bytes(44), 0n);
		storage.deleteForwardedHtlc('out2');
		same(
			storage.loadAllForwardedHtlcs(),
			[{ outKey: 'out1', inChannelId: bytes(43), inHtlcId: bigId }],
			'loadAllForwardedHtlcs'
		);
	});

	core('chain monitors round-trip and overwrite', (storage) => {
		ensure(
			storage.loadChainMonitor('c1') === null,
			'missing chain monitor is not null'
		);
		storage.saveChainMonitor('c1', chainMonitor(50));
		storage.saveChainMonitor('c2', chainMonitor(51));
		same(
			serializeChainMonitorState(storage.loadChainMonitor('c1')!),
			serializeChainMonitorState(chainMonitor(50)),
			'loadChainMonitor'
		);
		storage.saveChainMonitor('c1', chainMonitor(52));
		sameSet(
			storage
				.loadAllChainMonitors()
				.map((row) => [row.channelId, serializeChainMonitorState(row.state)]),
			[
				['c1', serializeChainMonitorState(chainMonitor(52))],
				['c2', serializeChainMonitorState(chainMonitor(51))]
			],
			(row) => row[0],
			'loadAllChainMonitors'
		);
	});

	core('gossip channels and nodes round-trip and overwrite', (storage) => {
		storage.saveGossipChannel('scid1', gossipChannel(60));
		storage.saveGossipChannel('scid2', gossipChannel(61));
		storage.saveGossipChannel('scid1', gossipChannel(62));
		sameSet(
			storage.loadAllGossipChannels().map((c) => serializeGraphChannel(c)),
			[gossipChannel(62), gossipChannel(61)].map((c) =>
				serializeGraphChannel(c)
			),
			(json) => json,
			'loadAllGossipChannels'
		);
		storage.saveGossipNode('node1', gossipNode(63));
		storage.saveGossipNode('node1', gossipNode(64));
		same(
			storage.loadAllGossipNodes().map((n) => serializeGraphNode(n)),
			[serializeGraphNode(gossipNode(64))],
			'loadAllGossipNodes'
		);
	});

	core('invoices round-trip, overwrite and delete', (storage) => {
		const full = invoice(70);
		const amountless: IInvoiceInfo = {
			paymentHash: hexId(71),
			bolt11: 'lnbcrt1amountless',
			expiry: 600,
			createdAt: 1_700_000_000
		};
		storage.saveInvoice(full.paymentHash, full);
		storage.saveInvoice(amountless.paymentHash, amountless);
		sameSet(
			storage
				.loadAllInvoices()
				.map((row) => [row.paymentHashHex, serializeInvoiceInfo(row.invoice)]),
			[
				[full.paymentHash, serializeInvoiceInfo(full)],
				[amountless.paymentHash, serializeInvoiceInfo(amountless)]
			],
			(row) => row[0] as string,
			'loadAllInvoices'
		);
		ensure(
			storage
				.loadAllInvoices()
				.find((row) => row.paymentHashHex === amountless.paymentHash)!.invoice
				.amountMsat === undefined,
			'an amount-less invoice loads with an amount'
		);
		storage.deleteInvoice(full.paymentHash);
		same(
			storage.loadAllInvoices().map((row) => row.paymentHashHex),
			[amountless.paymentHash],
			'invoices after delete'
		);
		storage.deleteInvoicePathId('never-stored');
	});

	core('mission control, metadata and peer addresses', (storage) => {
		storage.saveMissionControl('{"a":1}');
		storage.saveMissionControl('{"a":2}');
		same(storage.loadMissionControl(), '{"a":2}', 'loadMissionControl');

		ensure(storage.loadMetadata('k') === null, 'missing metadata is not null');
		storage.saveMetadata('k', 'v1');
		storage.saveMetadata('k', 'v2');
		same(storage.loadMetadata('k'), 'v2', 'loadMetadata');

		storage.savePeerAddress('pk1', '127.0.0.1', 9735);
		storage.savePeerAddress('pk2', 'example.com', 443, {
			type: 'ws',
			url: 'wss://example.com/ln'
		});
		storage.savePeerAddress('pk3', '10.0.0.1', 9736);
		storage.savePeerAddress('pk1', '127.0.0.2', 9737);
		storage.deletePeerAddress('pk3');
		sameSet(
			storage.loadAllPeerAddresses(),
			[
				{ pubkey: 'pk1', host: '127.0.0.2', port: 9737 },
				{
					pubkey: 'pk2',
					host: 'example.com',
					port: 443,
					transport: { type: 'ws', url: 'wss://example.com/ln' }
				}
			],
			(row) => row.pubkey,
			'loadAllPeerAddresses'
		);
	});

	core('channel key indices outlive their channel', (storage) => {
		storage.saveChannelKeyIndex('c1', 3);
		storage.saveChannelKeyIndex('c2', 9);
		same(storage.loadChannelKeyIndex('c2'), 9, 'loadChannelKeyIndex');
		ensure(
			storage.loadChannelKeyIndex('missing') === null,
			'missing key index is not null'
		);
		same(storage.loadNextChannelIndex(), 10, 'loadNextChannelIndex');
		const state = channelState(80);
		storage.saveChannel('c2', state, 'peer');
		storage.deleteChannel('c2');
		same(
			storage.loadChannelKeyIndex('c2'),
			9,
			'deleteChannel removed the key index'
		);
		same(
			storage.loadNextChannelIndex(),
			10,
			'loadNextChannelIndex after deleteChannel'
		);
	});

	// ─── Transactions ───

	core('transaction returns what its function returns', (storage) => {
		same(
			storage.transaction(() => 42),
			42,
			'transaction result'
		);
		storage.transaction(() => storage.saveMetadata('k', 'v'));
		same(storage.loadMetadata('k'), 'v', 'committed write');
	});

	core('a transaction reads its own writes', (storage) => {
		storage.transaction(() => {
			storage.saveMetadata('k', 'inside');
			same(storage.loadMetadata('k'), 'inside', 'read inside a transaction');
			storage.savePreimage('h', bytes(90));
			same(storage.loadPreimage('h'), bytes(90), 'preimage inside');
		});
	});

	core(
		'a throw rolls back every write of the transaction and rethrows',
		(storage) => {
			const kept = channelState(91);
			const keptId = kept.channelId!.toString('hex');
			storage.saveChannel(keptId, kept, 'peer');
			storage.saveMetadata('overwritten', 'before');
			storage.savePreimage('deleted', bytes(92));
			storage.saveChannelKeyIndex(keptId, 1);
			const before = snapshotOf(storage);

			const error = new Error('abort');
			let thrown: unknown;
			try {
				storage.transaction(() => {
					const added = channelState(93, ['4']);
					storage.saveChannel(added.channelId!.toString('hex'), added, 'peer');
					const changed = channelState(91, ['2']);
					changed.localCommitmentNumber = 20n;
					storage.saveChannel(keptId, changed, 'peer2');
					storage.savePayment('pay', payment(94));
					storage.savePreimage('added', bytes(95));
					storage.deletePreimage('deleted');
					storage.saveMetadata('overwritten', 'after');
					storage.saveChannelKeyIndex('new', 7);
					storage.saveForwardedHtlc('out', bytes(96), 1n);
					storage.saveHtlcPaymentMapping('h', 'pay');
					storage.savePaymentSecret('pay', bytes(97));
					storage.saveHtlcSharedSecret('s', bytes(98));
					storage.saveInvoice('pay', invoice(99));
					storage.saveChainMonitor(keptId, chainMonitor(100));
					if (hasRecoveryStorage(storage)) {
						const id = storage.saveOutboxMessage({
							peerId: 'peer',
							channelId: keptId,
							messageType: 132,
							wireMessage: bytes(101, 80),
							disposition: 'pending_send'
						});
						storage.saveRecoveryFrame(frame(1));
						storage.setOutboxFrameSequence([id], 1);
						storage.setRecoveryMeta('tip', '1');
					}
					throw error;
				});
			} catch (caught) {
				thrown = caught;
			}
			ensure(thrown === error, 'transaction did not rethrow the error');
			same(
				snapshotOf(storage),
				before,
				'state after a rolled-back transaction'
			);

			// Still usable: the next transaction commits.
			storage.transaction(() => storage.saveMetadata('after', 'commit'));
			same(storage.loadMetadata('after'), 'commit', 'write after a rollback');
		}
	);

	core('inTransaction reports an open transaction', (storage) => {
		if (!storage.inTransaction) return;
		ensure(!storage.inTransaction(), 'inTransaction outside a transaction');
		storage.transaction(() =>
			ensure(storage.inTransaction!(), 'inTransaction false inside one')
		);
		throwsError(() =>
			storage.transaction(() => {
				throw new Error('abort');
			})
		);
		ensure(!storage.inTransaction(), 'inTransaction after a rollback');
	});

	// ─── Optional groups ───

	optional('ffor', 'vouchers round-trip and merge evidence', (s) => {
		const bare = fforVoucher(110, false);
		const id = `${bare.channelId}:${bare.epochId}:${bare.slot}`;
		ensure(s.loadFforVoucher(id) === null, 'missing voucher is not null');
		s.saveFforVoucher(fforVoucher(110, true));
		// A later save without the preimage must not drop it.
		s.saveFforVoucher(bare);
		same(s.loadFforVoucher(id), fforVoucher(110, true), 'loadFforVoucher');
		s.saveFforVoucher(fforVoucher(111, false));
		same(s.loadAllFforVouchers().length, 2, 'loadAllFforVouchers row count');
		ensure(
			throwsError(() => s.saveFforVoucher({ ...bare, amountMsat: '2000000' })),
			'a save that changes the voucher identity did not throw'
		);
	});

	optional('invoicePathIds', 'path ids round-trip and delete', (s) => {
		s.saveInvoicePathId('p1', bytes(120));
		s.saveInvoicePathId('p2', bytes(121));
		s.deleteInvoicePathId('p1');
		same(
			s.loadAllInvoicePathIds(),
			[{ paymentHashHex: 'p2', pathId: bytes(121) }],
			'loadAllInvoicePathIds'
		);
	});

	optional(
		'announcedPeerAddresses',
		'the newest announcement replaces the stored one',
		(s) => {
			s.saveAnnouncedPeerAddresses('pk', 100, [
				{ host: '1.2.3.4', port: 9735 }
			]);
			s.saveAnnouncedPeerAddresses('pk', 200, []);
			same(
				s.loadAllAnnouncedPeerAddresses(),
				[{ pubkey: 'pk', timestamp: 200, addresses: [] }],
				'loadAllAnnouncedPeerAddresses'
			);
		}
	);

	optional(
		'channelKeyIndexHistory',
		'the history includes deleted channels and index 0',
		(s) => {
			ensure(!s.hasChannelKeyIndices(), 'hasChannelKeyIndices when empty');
			s.saveChannelKeyIndex('c0', 0);
			ensure(s.hasChannelKeyIndices(), 'hasChannelKeyIndices with index 0');
			same(s.loadNextChannelIndex(), 1, 'loadNextChannelIndex after index 0');
			s.saveChannel('c0', channelState(130), 'peer');
			s.deleteChannel('c0');
			same(
				s.loadAllChannelKeyIndices(),
				[{ channelId: 'c0', channelIndex: 0 }],
				'loadAllChannelKeyIndices'
			);
		}
	);

	optional('metadataScan', 'prefix scans are literal and ordered', (s) => {
		for (const key of ['swap:b', 'swap:a', 'swap_x', 'swapz', 'other']) {
			s.saveMetadata(key, `v-${key}`);
		}
		same(
			s.loadMetadataByPrefix('swap:'),
			[
				{ key: 'swap:a', value: 'v-swap:a' },
				{ key: 'swap:b', value: 'v-swap:b' }
			],
			'loadMetadataByPrefix'
		);
		same(
			s.loadMetadataByPrefix('swap_').map((row) => row.key),
			['swap_x'],
			'loadMetadataByPrefix with an underscore'
		);
		s.deleteMetadata('swap:a');
		s.deleteMetadata('missing');
		ensure(s.loadMetadata('swap:a') === null, 'deleted metadata still loads');
	});

	optional('walletData', 'values round-trip', (s) => {
		ensure(s.loadWalletData('k') === null, 'missing wallet data is not null');
		s.saveWalletData('k', '{"utxos":[]}');
		same(s.loadWalletData('k'), '{"utxos":[]}', 'loadWalletData');
	});

	optional(
		'gossipPaging',
		'pages read every row once, in loadAll order',
		(s) => {
			const empty = s.loadGossipChannelsAfter(0, 10);
			ensure(
				empty.rows.length === 0 && empty.done && empty.cursor === 0,
				'a page of an empty table'
			);
			for (let i = 0; i < 7; i++) {
				s.saveGossipChannel(`scid${i}`, gossipChannel(140 + i));
				s.saveGossipNode(`node${i}`, gossipNode(150 + i));
			}
			// A replaced row is read once, wherever the backend puts it.
			s.saveGossipChannel('scid2', gossipChannel(160));
			const pages = <T>(
				read: (
					after: number,
					limit: number
				) => {
					rows: T[];
					cursor: number;
					done: boolean;
				}
			): T[] => {
				const rows: T[] = [];
				let cursor = 0;
				for (let guard = 0; guard < 100; guard++) {
					const page = read(cursor, 3);
					ensure(page.rows.length <= 3, 'a page longer than its limit');
					rows.push(...page.rows);
					if (page.done) return rows;
					ensure(page.cursor > cursor, 'a page cursor that does not advance');
					cursor = page.cursor;
				}
				return fail('paging never finished');
			};
			same(
				pages((after, limit) => s.loadGossipChannelsAfter(after, limit)).map(
					(c) => serializeGraphChannel(c)
				),
				s.loadAllGossipChannels().map((c) => serializeGraphChannel(c)),
				'paged channels'
			);
			same(
				pages((after, limit) => s.loadGossipNodesAfter(after, limit)).map((n) =>
					serializeGraphNode(n)
				),
				s.loadAllGossipNodes().map((n) => serializeGraphNode(n)),
				'paged nodes'
			);
			same(s.loadAllGossipChannels().length, 7, 'gossip channel count');
		}
	);

	optional('gossipPruning', 'deletes remove rows', (s) => {
		s.saveGossipChannel('scid1', gossipChannel(170));
		s.saveGossipChannel('scid2', gossipChannel(171));
		s.saveGossipNode('node1', gossipNode(172));
		s.deleteGossipChannel('scid1');
		s.deleteGossipNode('node1');
		s.deleteGossipNode('missing');
		same(
			s.loadAllGossipChannels().map((c) => serializeGraphChannel(c)),
			[serializeGraphChannel(gossipChannel(171))],
			'gossip channels after delete'
		);
		ensure(s.loadAllGossipNodes().length === 0, 'deleted gossip node loads');
	});

	optional('channelPolicies', 'policies round-trip and delete', (s) => {
		const policy = {
			feeBaseMsat: 1000,
			feeProportionalMillionths: 100,
			cltvExpiryDelta: 80,
			htlcMinimumMsat: '1000',
			htlcMaximumMsat: '18446744073709551615'
		};
		s.saveChannelPolicy('c1', policy);
		s.saveChannelPolicy('c2', { feeBaseMsat: 0 });
		s.deleteChannelPolicy('c2');
		same(
			s.loadAllChannelPolicies(),
			[{ channelId: 'c1', policy }],
			'loadAllChannelPolicies'
		);
	});

	optional('peerStorageBlobs', 'one blob per peer, newest wins', (s) => {
		ensure(s.loadPeerStorageBlob('pk') === null, 'missing blob is not null');
		s.savePeerStorageBlob('pk', bytes(180, 100), 1);
		s.savePeerStorageBlob('pk', bytes(181, 65531), 2);
		same(
			s.loadPeerStorageBlob('pk'),
			{ blob: bytes(181, 65531), receivedAt: 2 },
			'loadPeerStorageBlob'
		);
		s.deletePeerStorageBlob('pk');
		ensure(s.loadPeerStorageBlob('pk') === null, 'deleted blob still loads');
	});

	optional(
		'forwarding',
		'events list newest first, filter and sum exactly',
		(s) => {
			const big = 9_007_199_254_740_993n;
			const event = (
				settledAt: number,
				inChannelId: string,
				outChannelId: string,
				fee: bigint
			): {
				settledAt: number;
				inChannelId: string;
				outChannelId: string;
				amountInMsat: bigint;
				amountOutMsat: bigint;
				feeMsat: bigint;
			} => ({
				settledAt,
				inChannelId,
				outChannelId,
				amountInMsat: big + fee,
				amountOutMsat: big,
				feeMsat: fee
			});
			s.saveForwardingEvent(event(100, 'a', 'b', 1n));
			s.saveForwardingEvent({
				...event(300, 'b', 'c', 2n),
				inScid: '1x2x3',
				outScid: '4x5x6'
			});
			s.saveForwardingEvent(event(200, 'c', 'd', 3n));
			const all = s.listForwardingEvents();
			same(
				all.map((e) => e.settledAt),
				[300, 200, 100],
				'listForwardingEvents order'
			);
			ensure(
				new Set(all.map((e) => e.id)).size === 3,
				'forwarding event ids are not distinct'
			);
			same(
				[all[0].inScid, all[0].outScid],
				['1x2x3', '4x5x6'],
				'forwarding event scids'
			);
			same(
				s
					.listForwardingEvents({ since: 150, until: 250 })
					.map((e) => e.feeMsat),
				[3n],
				'listForwardingEvents since/until'
			);
			same(
				s.listForwardingEvents({ channelId: 'b' }).map((e) => e.settledAt),
				[300, 100],
				'listForwardingEvents channelId'
			);
			same(
				s.listForwardingEvents({ limit: 1, offset: 1 }).map((e) => e.settledAt),
				[200],
				'listForwardingEvents limit/offset'
			);
			same(
				s.getForwardingSummary(),
				{ count: 3, volumeOutMsat: big * 3n, feesEarnedMsat: 6n },
				'getForwardingSummary'
			);
			same(
				s.getForwardingSummary({ since: 200 }),
				{ count: 2, volumeOutMsat: big * 2n, feesEarnedMsat: 5n },
				'getForwardingSummary since'
			);
		}
	);

	optional('actionLog', 'entries list newest first and filter', (s) => {
		const entry = (
			category: string,
			timestamp: number
		): {
			category: string;
			action: string;
			timestamp: number;
			data: string;
		} => ({
			category,
			action: `${category}-${timestamp}`,
			timestamp,
			data: '{}'
		});
		s.saveActionLog(entry('payment', 1));
		s.saveActionLog(entry('channel', 3));
		s.saveActionLog(entry('payment', 2));
		same(
			s.loadActionLog().map((e) => e.timestamp),
			[3, 2, 1],
			'loadActionLog order'
		);
		same(
			s.loadActionLog({ category: 'payment', since: 2 }),
			[entry('payment', 2)],
			'loadActionLog category/since'
		);
		same(
			s.loadActionLog({ limit: 1 }).map((e) => e.timestamp),
			[3],
			'loadActionLog limit'
		);
	});

	optional('watchtower', 'sessions and the update backlog round-trip', (s) => {
		const one = watchtowerSession(190, 'tower-1');
		const two = watchtowerSession(192, 'tower-2');
		s.saveWatchtowerSession(one, bytes(194));
		s.saveWatchtowerSession(two, bytes(195));
		s.setWatchtowerSessionProgress(one.sessionId, 5, 4);
		sameSet(
			s.loadWatchtowerSessions(),
			[
				{ ...one, seqNum: 5, lastApplied: 4, sessionKey: bytes(194) },
				{ ...two, sessionKey: bytes(195) }
			],
			(row) => row.sessionId,
			'loadWatchtowerSessions'
		);

		const update = (
			towerUri: string,
			n: number
		): {
			towerUri: string;
			channelId: string;
			blobType: number;
			hint: string;
			encryptedBlob: string;
			seqNum: number;
			acked: boolean;
			createdAt: number;
		} => ({
			towerUri,
			channelId: hexId(n),
			blobType: 2,
			hint: bytes(n, 16).toString('hex'),
			encryptedBlob: bytes(n + 1, 120).toString('hex'),
			seqNum: 0,
			acked: false,
			createdAt: n
		});
		const first = s.addWatchtowerUpdate(update('tower-1', 1));
		const second = s.addWatchtowerUpdate(update('tower-1', 2));
		const third = s.addWatchtowerUpdate(update('tower-2', 3));
		ensure(first < second && second < third, 'update ids do not increase');
		s.markWatchtowerUpdateAcked(first, 1);
		same(
			s.loadPendingWatchtowerUpdates(),
			[
				{ id: second, ...update('tower-1', 2) },
				{ id: third, ...update('tower-2', 3) }
			],
			'loadPendingWatchtowerUpdates'
		);
		s.deleteWatchtowerTower('tower-1');
		same(
			s.loadWatchtowerSessions().map((row) => row.towerUri),
			['tower-2'],
			'sessions after deleteWatchtowerTower'
		);
		same(
			s.loadPendingWatchtowerUpdates().map((row) => row.id),
			[third],
			'updates after deleteWatchtowerTower'
		);
	});

	optional(
		'recoveryOutbox',
		'rows keep order, filter, update and prune',
		(s) => {
			const message = (
				channelId: string | undefined,
				messageType: number,
				seed: number
			): {
				peerId: string;
				channelId?: string;
				messageType: number;
				wireMessage: Buffer;
				disposition: 'pending_send';
			} => ({
				peerId: 'peer',
				...(channelId ? { channelId } : {}),
				messageType,
				wireMessage: bytes(seed, 40),
				disposition: 'pending_send'
			});
			const ids = [
				s.saveOutboxMessage(message('c1', 132, 1)),
				s.saveOutboxMessage(message('c1', 133, 2)),
				s.saveOutboxMessage(message('c2', 132, 3)),
				s.saveOutboxMessage(message(undefined, 1, 4)),
				s.saveOutboxMessage(message('c1', 132, 5))
			];
			ensure(
				ids.every((id, i) => i === 0 || id > ids[i - 1]),
				'outbox ids do not increase'
			);
			const all = s.loadOutboxMessages();
			same(
				all.map((row) => row.id),
				ids,
				'loadOutboxMessages order'
			);
			same(
				all.map((row) => [
					row.peerId,
					row.channelId,
					row.messageType,
					row.wireMessage,
					row.disposition,
					row.frameSequence
				]),
				[
					['peer', 'c1', 132, bytes(1, 40), 'pending_send', null],
					['peer', 'c1', 133, bytes(2, 40), 'pending_send', null],
					['peer', 'c2', 132, bytes(3, 40), 'pending_send', null],
					['peer', undefined, 1, bytes(4, 40), 'pending_send', null],
					['peer', 'c1', 132, bytes(5, 40), 'pending_send', null]
				],
				'loadOutboxMessages rows'
			);
			ensure(
				all.every((row) => typeof row.createdAt === 'number'),
				'outbox createdAt is not a number'
			);
			same(
				s.loadOutboxMessages('c1').map((row) => row.id),
				[ids[0], ids[1], ids[4]],
				'loadOutboxMessages for a channel'
			);
			same(s.countOutboxMessages('c1'), 3, 'countOutboxMessages');

			s.setOutboxDisposition(ids[0], 'sent_unacked');
			same(
				s.loadOutboxMessages('c1')[0].disposition,
				'sent_unacked',
				'setOutboxDisposition'
			);
			s.deleteOutboxMessages('c1', [133]);
			same(
				s.loadOutboxMessages('c1').map((row) => row.id),
				[ids[0], ids[4]],
				'deleteOutboxMessages by type'
			);
			s.pruneOutboxMessages('c1', 1);
			same(
				s.loadOutboxMessages('c1').map((row) => row.id),
				[ids[4]],
				'pruneOutboxMessages'
			);
			s.deleteOutboxMessages('c2');
			same(s.countOutboxMessages('c2'), 0, 'deleteOutboxMessages');

			// Retransmission needs the channel row, so the rows go with it.
			const state = channelState(200);
			s.saveChannel('c1', state, 'peer');
			s.deleteChannel('c1');
			same(s.countOutboxMessages('c1'), 0, 'outbox rows after deleteChannel');
			same(
				s.loadOutboxMessages().map((row) => row.id),
				[ids[3]],
				'outbox after deleteChannel'
			);
		}
	);

	optional(
		'recoveryJournal',
		'frames append, read in order and compact',
		(s) => {
			ensure(s.recoveryFrameStats() === null, 'frame stats with no frames');
			for (const sequence of [1, 2, 3, 4]) s.saveRecoveryFrame(frame(sequence));
			ensure(
				throwsError(() => s.saveRecoveryFrame(frame(2))),
				'a frame saved twice under one sequence did not throw'
			);
			same(
				s.loadRecoveryFrames(),
				[1, 2, 3, 4].map(frame),
				'loadRecoveryFrames'
			);
			same(
				s.loadRecoveryFrames(2),
				[3, 4].map(frame),
				'loadRecoveryFrames after a sequence'
			);
			same(s.loadRecoveryFrame(3), frame(3), 'loadRecoveryFrame');
			ensure(s.loadRecoveryFrame(9) === null, 'missing frame is not null');
			const { sequence, writerEpoch, frameHash, previousFrameHash } = frame(3);
			same(
				s.loadRecoveryFrameHeader(3),
				{ sequence, writerEpoch, frameHash, previousFrameHash },
				'loadRecoveryFrameHeader'
			);
			ensure(
				s.loadRecoveryFrameHeader(9) === null,
				'missing frame header is not null'
			);
			same(
				s.recoveryFrameStats(),
				{ count: 4, minSequence: 1, maxSequence: 4 },
				'recoveryFrameStats'
			);
			s.deleteRecoveryFramesBelow(3);
			same(
				s.loadRecoveryFrames().map((f) => f.sequence),
				[3, 4],
				'frames after deleteRecoveryFramesBelow'
			);
			same(
				s.recoveryFrameStats(),
				{ count: 2, minSequence: 3, maxSequence: 4 },
				'recoveryFrameStats after compaction'
			);
		}
	);

	optional('recoveryJournal', 'metadata round-trips and enumerates', (s) => {
		ensure(s.getRecoveryMeta('tip') === null, 'missing meta is not null');
		s.setRecoveryMeta('tip', 'a');
		s.setRecoveryMeta('tip', 'b');
		s.setRecoveryMeta('epoch', '1');
		s.setRecoveryMeta('lease', 'secret');
		s.deleteRecoveryMeta('lease');
		s.deleteRecoveryMeta('missing');
		same(s.getRecoveryMeta('tip'), 'b', 'getRecoveryMeta');
		same(
			[...s.listRecoveryMetaKeys()].sort(),
			['epoch', 'tip'],
			'listRecoveryMetaKeys'
		);
		if (hasStorageCapability(s, 'recoveryOutbox')) {
			const id = s.saveOutboxMessage({
				peerId: 'peer',
				channelId: 'c',
				messageType: 132,
				wireMessage: bytes(210, 10),
				disposition: 'pending_send'
			});
			s.setOutboxFrameSequence([id], 7);
			s.setOutboxFrameSequence([], 8);
			same(
				s.loadOutboxMessages('c')[0].frameSequence,
				7,
				'setOutboxFrameSequence'
			);
		}
	});

	optional('offers', 'a re-saved offer keeps its creation and path id', (s) => {
		s.saveOffer('o1', 'lno1first', bytes(220, 16), 100, true);
		s.saveOffer('o1', 'lno1second', null, 200, false);
		s.saveOffer('o2', 'lno1plain', null, 300);
		s.saveOffer('o3', 'lno1gone', null, 400);
		s.deleteOffer('o3');
		sameSet(
			s.loadAllOffers().map((row) => ({ ...row, asyncHold: !!row.asyncHold })),
			[
				{
					offerIdHex: 'o1',
					encoded: 'lno1second',
					pathId: bytes(220, 16),
					createdAt: 100,
					asyncHold: false
				},
				{
					offerIdHex: 'o2',
					encoded: 'lno1plain',
					pathId: null,
					createdAt: 300,
					asyncHold: false
				}
			],
			(row) => row.offerIdHex,
			'loadAllOffers'
		);
	});

	return checks;
}

/**
 * Everything a rolled-back transaction must leave as it was, read through
 * the loaders the conformance check writes to.
 */
function snapshotOf(storage: IStorageBackend): unknown {
	const byKey = <T>(rows: T[], key: (row: T) => string): T[] =>
		[...rows].sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
	return {
		channels: byKey(
			storage.loadAllChannels().map((row) => ({
				channelId: row.channelId,
				peerPubkey: row.peerPubkey,
				state: channelForm(row.state)
			})),
			(row) => row.channelId
		),
		payments: byKey(
			storage.loadAllPayments().map((row) => ({
				paymentHash: row.paymentHash,
				payment: serializePaymentInfo(row.payment)
			})),
			(row) => row.paymentHash
		),
		preimages: byKey(storage.loadAllPreimages(), (row) => row.paymentHash),
		metadata: storage.loadMetadata('overwritten'),
		nextChannelIndex: storage.loadNextChannelIndex(),
		newKeyIndex: storage.loadChannelKeyIndex('new'),
		forwarded: storage.loadAllForwardedHtlcs(),
		htlcPaymentMap: storage.loadAllHtlcPaymentMappings(),
		paymentSecrets: storage.loadAllPaymentSecrets(),
		sharedSecrets: storage.loadAllHtlcSharedSecrets(),
		invoices: storage.loadAllInvoices().length,
		chainMonitors: storage.loadAllChainMonitors().length,
		...(hasRecoveryStorage(storage)
			? {
					outbox: storage.loadOutboxMessages(),
					frames: storage.loadRecoveryFrames(),
					meta: storage.listRecoveryMetaKeys()
			  }
			: {})
	};
}

/**
 * Register the conformance checks as tests under one describe block, with
 * the global describe and it of mocha, Jest or Vitest. A check whose
 * capability group the backend lacks is reported as skipped where the
 * runner supports that (mocha), and passes otherwise.
 */
export function runStorageConformanceSuite(
	factory: () => IStorageBackend,
	options: { name?: string } = {}
): void {
	const runner = globalThis as unknown as {
		describe?: (name: string, body: () => void) => void;
		it?: (
			name: string,
			body: (this: { skip?: () => void } | undefined) => void
		) => void;
	};
	const suite = runner.describe;
	const test = runner.it;
	if (typeof suite !== 'function' || typeof test !== 'function') {
		throw new Error(
			'runStorageConformanceSuite needs a test runner with global describe and it'
		);
	}
	suite(options.name ?? 'IStorageBackend conformance', () => {
		for (const check of storageConformanceChecks(factory)) {
			test(check.name, function () {
				if (check.run() === 'skipped') this?.skip?.();
			});
		}
	});
}
