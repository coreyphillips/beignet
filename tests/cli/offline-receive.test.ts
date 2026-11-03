/**
 * The automatic-receive coordinator (issue #729) and its direct-funding
 * fallback.
 *
 * The rule these cells hold to: automatic offline receiving is only for a
 * channel that ALREADY exists with the peer and whose inbound covers the
 * amount. It never obtains inbound liquidity by opening one, so the receiver no
 * longer sends the `allocate` message at all; with no suitable channel the
 * request becomes a direct-funding request, which the payer settles on chain
 * and which reserves nothing here.
 */

import assert from 'assert';
import type { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import { OfflineReceive } from '../../src/cli/offline-receive';

const channelId = '11'.repeat(32),
	epochId = '22'.repeat(32),
	peer = '02' + '3b'.repeat(32),
	otherPeer = '03' + '7c'.repeat(32),
	spareId = '66'.repeat(32),
	spareEpochId = '88'.repeat(32),
	spareHash = 'aa'.repeat(32),
	receiptHash = '99'.repeat(32);

type Slot = {
	state: string;
	amountMsat: string;
	bolt11?: string;
	paymentHash?: string;
};
type Epoch = {
	channelId: string;
	epochId: string;
	state: string;
	concurrentVersion?: 1 | 2;
	slots: Slot[];
};
type Channel = {
	channelId: string;
	state: string;
	peerPubkey?: string;
	htlcUsable?: boolean;
	localBalanceSats?: number;
	remoteBalanceSats?: number;
	htlcCount?: number;
	ffor?: { reservedInboundSats: number; unresolvedSlots: number };
};
type Peer = {
	pubkey: string;
	host: string;
	port: number;
	state: string;
	transport?: 'tcp' | 'ws' | 'iroh';
	/** The peer dialed us: never dialed back, so its listed port is its socket's. */
	inbound?: boolean;
};
type Json = Record<string, unknown>;
type Failure = Error & { code?: string };
type Primary = { pubkey: string; host?: string; port?: number };
type Opts = {
	/** Add an empty inbound channel with the peer that a request may reserve. */
	spare?: boolean;
	jobs?: Json[];
	peers?: Peer[];
	config?: Json;
	/** The ranked primaries, highest rank first, for a quote that names no peer. */
	primaries?: Primary[];
};

/**
 * The coordinator reaches for a handful of node methods and nothing else, so a
 * bag of stubs is the whole node as far as it is concerned. The returned
 * harness is loosely typed on purpose: cells reach into the stub to re-point a
 * method mid-test.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function fixture(overrides: Json = {}, opts: Opts = {}): any {
	let now = 1000000,
		queries = 0,
		closes = 0,
		minted = 0,
		started = 0;
	const job: Json = {
		id: 'test',
		peer,
		amountSats: 20000,
		channelId,
		epochId,
		expiresAt: now + 600000,
		...overrides
	};
	const epoch: Epoch = {
		channelId,
		epochId,
		state: 'ACTIVE',
		slots: [{ state: 'exposed', amountMsat: '20000000', bolt11: 'invoice' }]
	};
	const epochs: Epoch[] = [epoch];
	// The reservation lane the reconciliation cells drive. It carries no
	// peerPubkey, so a fresh request never mistakes it for a usable channel.
	const channels: Channel[] = [{ channelId, state: 'NORMAL' }];
	if (opts.spare)
		channels.push({
			channelId: spareId,
			peerPubkey: peer,
			state: 'NORMAL',
			htlcUsable: true,
			localBalanceSats: 0,
			remoteBalanceSats: 100000
		});
	const config: Json = {
		lspPubkey: null,
		lspHost: null,
		lspPort: null,
		targetInboundSat: 0,
		trusted: false,
		allowSplice: false,
		allowUnpairedSplice: false,
		unpairedSpliceDepth: 3,
		minAmountSat: 5000,
		...(opts.config ?? {})
	};
	const configured: Json[] = [];
	const peerList: Peer[] = opts.peers ?? [
		{ pubkey: peer, host: 'lsp.example', port: 9735, state: 'ready' }
	];
	/** Every direct-funding request this coordinator had the node mint. */
	const mints: Json[] = [];
	/** Every op this coordinator put on the wire toward the peer. */
	const sent: Json[] = [];
	const saved: unknown[] = [];
	const node: Json = {
		fforConcurrentNegotiated: () => false,
		listChannels: () => channels,
		listPeers: () => peerList,
		// What this node dialed the peer at: its listed address unless it came
		// to us, in which case nothing (see Peer.inbound).
		getPeerAddress: (pubkey: string) => {
			const entry = peerList.find((p) => p.pubkey === pubkey && !p.inbound);
			return entry
				? {
						host: entry.host,
						port: entry.port,
						...(entry.transport ? { transport: entry.transport } : {})
				  }
				: undefined;
		},
		getInfo: () => ({ blockHeight: 800000 }),
		fforEpochs: () => epochs,
		fforEpoch: (id: string) => epochs.find((e) => e.channelId === id),
		decodeInvoice: () => ({ timestamp: 1000, expiry: 600 }),
		getDirectFundingConfig: () => ({ ...config }),
		// Rank order is selection order here: no thresholds in these cells.
		listPrimaries: () => ({
			fillThresholdSat: null,
			receiveTarget: opts.primaries?.[0]?.pubkey ?? null,
			primaries: (opts.primaries ?? []).map((p, i) => ({
				pubkey: p.pubkey,
				rank: i + 1,
				host: p.host ?? null,
				port: p.port ?? null,
				uri: null,
				thresholdSat: null,
				balanceSat: 0,
				channelCount: 0,
				belowThreshold: true,
				isReceiveTarget: i === 0,
				selectionOrder: i + 1
			}))
		}),
		configureDirectFunding: (update: Json) => {
			configured.push(update);
			Object.assign(config, update);
			return { ...config };
		},
		createDirectFundingRequest: (body: {
			amountSats: number;
			lspPubkey?: string;
		}) => {
			minted++;
			mints.push(body);
			return {
				request: `df-request-${minted}-${body.amountSats}`,
				paymentHash: receiptHash,
				expiresAt: now + 900000
			};
		},
		fforStartEpoch: (params: {
			channelId: string;
			voucherAmountsMsat: string[];
			concurrentVersion?: 1 | 2;
		}) => {
			started++;
			const fresh = {
				channelId: params.channelId,
				epochId: spareEpochId,
				state: 'ACTIVE',
				...(params.concurrentVersion
					? { concurrentVersion: params.concurrentVersion }
					: {}),
				slots: [
					{
						state: 'exposed',
						amountMsat: params.voucherAmountsMsat[0],
						bolt11: 'lnbcrt-spare',
						paymentHash: spareHash
					}
				]
			};
			epochs.push(fresh);
			return fresh;
		},
		getStorageBackend: () => ({
			loadAllInvoices: () => [{ paymentHashHex: spareHash }]
		}),
		getFforReceiveService: () => ({
			request: async (_peer: string, body: Json) => {
				sent.push(body);
				return { version: 1, feeBaseMsat: 0, feePpm: 0 };
			},
			receipts: async () => {
				queries++;
			}
		}),
		fforRecover: async (body: { channelId: string }) => {
			assert.deepEqual(body, { channelId });
			closes++;
			epoch.state = 'CLOSED';
		}
	};
	const coordinator = new OfflineReceive(
		node as unknown as BeignetNode,
		(jobs) => saved.push(jobs),
		// Pre-split journals are hand-built JSON on purpose (the kind-less
		// cell); the coordinator validates them at construction.
		(opts.jobs ?? [job]) as unknown as ConstructorParameters<
			typeof OfflineReceive
		>[2],
		() => now
	);
	return {
		coordinator,
		node,
		epoch,
		job,
		sent,
		saved,
		config,
		configured,
		mints,
		channels,
		get queries() {
			return queries;
		},
		get closes() {
			return closes;
		},
		get minted() {
			return minted;
		},
		get started() {
			return started;
		},
		get now() {
			return now;
		},
		set now(v: number) {
			now = v;
		}
	};
}

describe('concurrent automatic receive', () => {
	const terms = {
		version: 1,
		feeBaseMsat: 0,
		feePpm: 0,
		concurrent: true,
		concurrentVersion: 2
	};
	function funded() {
		const f = fixture({}, { jobs: [], spare: true });
		f.channels[1].localBalanceSats = 50000;
		f.node.fforConcurrentNegotiated = () => true;
		f.node.getFforReceiveService = () => ({ request: async () => terms });
		return f;
	}
	const body = (quote: unknown) => ({
		requestId: 'concurrent-request-1',
		amountSats: 20000,
		quote
	});
	it('creates a version 2 invoice on the funded home channel and persists its profile', async () => {
		const f = funded();
		const quote = await f.coordinator.quote(peer, 20000);
		assert.equal(quote.mode, 'bolt11');
		assert.equal(quote.concurrentVersion, 2);
		const invoice = await f.coordinator.create(body(quote), peer);
		assert.equal(invoice.concurrent, true);
		assert.equal(invoice.concurrentVersion, 2);
		assert.equal(f.started, 1);
		assert.equal(f.minted, 0);
		assert.deepEqual([...f.coordinator.reservedIds()], [spareId]);
		const [job] = f.coordinator.status().requests;
		assert.equal(job.concurrentVersion, 2);
		assert.deepEqual(await f.coordinator.create(body(quote), peer), invoice);
	});
	it('waits for the signed profile echo before checking a newly negotiating epoch', async () => {
		const f = funded();
		const start = f.node.fforStartEpoch;
		f.node.fforStartEpoch = (params: unknown) => {
			const epoch = start(params);
			epoch.state = 'NEGOTIATING';
			delete epoch.concurrentVersion;
			setImmediate(() => {
				epoch.concurrentVersion = 2;
				epoch.state = 'ACTIVE';
			});
			return epoch;
		};
		const quote = await f.coordinator.quote(peer, 20000);
		const invoice = await f.coordinator.create(body(quote), peer);
		assert.equal(invoice.concurrentVersion, 2);
		assert.equal(f.started, 1);
	});
	it('keeps a busy request pending, then resumes the same profile after payments settle', async () => {
		const f = funded();
		f.channels[1].htlcCount = 1;
		const quote = await f.coordinator.quote(peer, 20000);
		await assert.rejects(
			f.coordinator.create(body(quote), peer),
			(e: Failure) => e.code === 'RECEIVE_PENDING'
		);
		assert.equal(f.started, 0);
		f.channels[1].htlcCount = 0;
		const invoice = await f.coordinator.create(body(quote), peer);
		assert.equal(invoice.concurrentVersion, 2);
		assert.equal(f.coordinator.status().requests.length, 1);
	});
	it('refreshes an expired quote for the same busy request after restart', async () => {
		const f = funded();
		f.channels[1].htlcCount = 1;
		const quote = await f.coordinator.quote(peer, 20000);
		await assert.rejects(
			f.coordinator.create(body(quote), peer),
			(e: Failure) => e.code === 'RECEIVE_PENDING'
		);
		f.now += 61000;
		f.channels[1].htlcCount = 0;
		const restarted = new OfflineReceive(
			f.node,
			() => {},
			f.coordinator.status().requests,
			() => f.now
		);
		const refreshed = await restarted.quote(
			peer,
			20000,
			'concurrent-request-1'
		);
		assert.equal(refreshed.mode, 'bolt11');
		assert.equal(refreshed.concurrentVersion, 2);
		const invoice = await restarted.create(body(refreshed), peer);
		assert.equal(invoice.concurrentVersion, 2);
		assert.equal(f.started, 1);
	});
	it('does not change a persisted profile when the peer offers different terms after restart', async () => {
		const f = funded();
		f.channels[1].htlcCount = 1;
		const quote = await f.coordinator.quote(peer, 20000);
		await assert.rejects(f.coordinator.create(body(quote), peer));
		const restarted = new OfflineReceive(
			f.node,
			() => {},
			f.coordinator.status().requests,
			() => f.now
		);
		f.channels[1].htlcCount = 0;
		const changed = {
			...quote,
			terms: { ...quote.terms, concurrentVersion: 1 }
		};
		await assert.rejects(
			restarted.create(body(changed), peer),
			(e: Failure) => e.code === 'INVALID_REVIEW'
		);
		assert.equal(f.started, 0);
		assert.equal(restarted.status().requests[0].concurrentVersion, 2);
	});
	it('keeps an interrupted bolt11 request on its persisted route when capacity becomes unavailable', async () => {
		const f = funded();
		const quote = await f.coordinator.quote(peer, 20000);
		f.node.getFforReceiveService = () => ({
			request: async () => {
				f.channels[1].remoteBalanceSats = 0;
				return terms;
			}
		});
		await assert.rejects(
			f.coordinator.create(body(quote), peer),
			(e: Failure) => e.code === 'RECEIVE_UNAVAILABLE'
		);
		await assert.rejects(
			f.coordinator.create(body(quote), peer),
			(e: Failure) => e.code === 'RECEIVE_UNAVAILABLE'
		);
		assert.equal(f.minted, 0);
		const [job] = f.coordinator.status().requests;
		assert.equal(job.kind, 'bolt11');
		assert.equal(job.concurrentVersion, 2);
		assert.doesNotThrow(() => new OfflineReceive(f.node, () => {}, [job]));
	});
	it('uses direct funding for a funded channel when the peer has not opted into concurrent settlement', async () => {
		const f = funded();
		f.node.getFforReceiveService = () => ({
			request: async () => ({ version: 1, feeBaseMsat: 0, feePpm: 0 })
		});
		const quote = await f.coordinator.quote(peer, 20000);
		assert.equal(quote.mode, 'direct-funding');
		const invoice = await f.coordinator.create(body(quote), peer);
		assert.equal(invoice.kind, 'direct-funding');
		assert.equal(f.started, 0);
	});
	it('syncs a live request without closing it and retains expired unknown reservations while draining', async () => {
		const f = fixture({ concurrent: true, concurrentVersion: 2 });
		f.epoch.concurrentVersion = 2;
		f.channels[0].ffor = { reservedInboundSats: 20000, unresolvedSlots: 1 };
		let syncs = 0,
			closes = 0;
		f.node.fforSync = () => {
			syncs++;
			return f.epoch;
		};
		f.node.fforCloseEpoch = () => {
			closes++;
			f.epoch.state = 'DRAINING';
		};
		await f.coordinator.sync();
		assert.equal(syncs, 1);
		assert.equal(closes, 0);
		const [status] = f.coordinator.status().requests;
		assert.equal(status.concurrent, true);
		assert.equal(status.reservedInboundSats, 20000);
		assert.equal(status.unresolvedSlots, 1);
		f.now = f.job.expiresAt + 120000;
		await f.coordinator.sync();
		assert.equal(closes, 1);
		await f.coordinator.sync();
		assert.deepEqual([...f.coordinator.reservedIds()], [channelId]);
		assert.notEqual(f.job.done, true);
		assert.equal(f.closes, 0);
	});
	it('closes after terminal credit, releases a closed book, and never treats proof custody as payment', async () => {
		const f = fixture({ concurrent: true, concurrentVersion: 2 });
		f.epoch.concurrentVersion = 2;
		f.node.fforSync = () => f.epoch;
		let closes = 0;
		f.node.fforCloseEpoch = () => {
			closes++;
			f.epoch.state = 'CLOSED';
		};
		f.epoch.slots[0].state = 'settled';
		await f.coordinator.sync();
		assert.equal(closes, 0);
		f.epoch.slots[0].state = 'redeemed';
		await f.coordinator.sync();
		await f.coordinator.sync();
		assert.equal(closes, 1);
		assert.equal(f.coordinator.reservedIds().size, 0);
	});
	it('releases a setup refusal before the signed profile echo arrived', async () => {
		const f = fixture({ concurrent: true, concurrentVersion: 2 });
		f.epoch.state = 'ABORTED';
		await f.coordinator.sync();
		assert.equal(f.job.done, true);
		assert.equal(f.coordinator.reservedIds().size, 0);
		assert.equal(f.queries, 0);
	});
	it('validates the persisted profile and leaves baseline journals readable', () => {
		assert.doesNotThrow(() => fixture());
		assert.throws(
			() => fixture({ concurrent: true }),
			/Invalid receive journal/
		);
		assert.throws(
			() => fixture({ concurrentVersion: 2 }),
			/Invalid receive journal/
		);
		assert.throws(
			() => fixture({ concurrent: true, concurrentVersion: 3 }),
			/Invalid receive journal/
		);
	});
});

it('reopening an unpaid request queries receipts without closing its reservation', async () => {
	const f = fixture();
	await f.coordinator.sync();
	await f.coordinator.sync();
	assert.equal(f.queries, 2);
	assert.equal(f.closes, 0);
});
it('paid receipt closes once and terminal state releases the reservation', async () => {
	const f = fixture();
	f.epoch.slots[0].state = 'settled';
	await f.coordinator.sync();
	await f.coordinator.sync();
	assert.equal(f.closes, 1);
	assert.equal(f.coordinator.reservedIds().size, 0);
});
it('expired invoices keep a settlement grace period and failed queries never close them', async () => {
	const f = fixture({ expiresAt: 1000000 });
	f.now = 1119999;
	await f.coordinator.sync();
	assert.equal(f.closes, 0);
	f.now = 1120000;
	f.node.getFforReceiveService = () => ({
		receipts: async () => {
			throw Error('offline');
		}
	});
	await f.coordinator.sync();
	assert.equal(f.closes, 0);
	f.node.getFforReceiveService = () => ({ receipts: async () => {} });
	await f.coordinator.sync();
	assert.equal(f.closes, 1);
});
it('startup repairs expiry from the durable invoice before deciding whether to release', async () => {
	const f = fixture({ expiresAt: undefined });
	await f.coordinator.sync();
	assert.equal(f.job.expiresAt, 1600000);
	assert.equal(f.closes, 0);
});
it('a replaced epoch is never recovered through an older request', async () => {
	const f = fixture();
	f.epoch.epochId = '55'.repeat(32);
	await f.coordinator.sync();
	assert.equal(f.queries, 0);
	assert.equal(f.closes, 0);
});
it('an unused reservation from interrupted creation is released, not exposed as a new invoice', async () => {
	const f = fixture({ expiresAt: undefined });
	f.epoch.slots = [{ state: 'unissued', amountMsat: '20000000' }];
	await f.coordinator.sync();
	assert.equal(f.closes, 1);
});
it('stopping prevents background mutations and corrupt journals fail closed', async () => {
	const f = fixture();
	f.coordinator.stop();
	await f.coordinator.sync();
	assert.equal(f.queries, 0);
	assert.throws(
		() => new OfflineReceive(f.node, () => {}, [{} as never]),
		/Invalid receive journal/
	);
	assert.throws(
		() =>
			new OfflineReceive(f.node, () => {}, [
				{ id: 'x', peer, amountSats: 1, kind: 'allocate' } as never
			]),
		/Invalid receive journal/
	);
});

it('below-minimum requests fail before any peer round trip', async () => {
	const f = fixture();
	await assert.rejects(f.coordinator.quote(peer, 1), {
		code: 'AMOUNT_TOO_SMALL'
	});
	assert.equal(f.queries, 0);
	assert.equal(f.sent.length, 0);
});
it('changed sender fees fail before a reservation or channel is created', async () => {
	const f = fixture({}, { spare: true, jobs: [] });
	f.now = 1000;
	f.node.getFforReceiveService = () => ({
		request: async () => ({ version: 1, feeBaseMsat: 1, feePpm: 0 })
	});
	await assert.rejects(
		f.coordinator.create(
			{
				requestId: 'review-1234567890',
				amountSats: 20000,
				quote: {
					peer,
					amountSats: 20000,
					terms: { feeBaseMsat: 0, feePpm: 0 },
					expiresAt: 2000
				}
			},
			peer
		),
		{ code: 'FEE_CHANGED' }
	);
	assert.equal(f.saved.length, 0);
	assert.equal(f.started, 0);
});

it('a journal failure stops subsequent reconciliation', async () => {
	const f = fixture();
	const c = new OfflineReceive(
		f.node,
		() => {
			throw Error('disk full');
		},
		[f.job]
	);
	f.job.expiresAt = undefined;
	await assert.rejects(c.sync(), /disk full/);
	await c.sync();
	assert.equal(f.closes, 0);
	assert.equal(c.status().available, false);
});
it('a repeated request returns the saved invoice without preparing another', async () => {
	const f = fixture({
		id: 'request-123456789',
		invoice: { bolt11: 'saved', paymentHash: 'hash', offlineReceive: true }
	});
	const invoice = await f.coordinator.create(
		{
			requestId: f.job.id,
			amountSats: 20000,
			quote: { peer, amountSats: 20000, expiresAt: 2000000 }
		},
		peer
	);
	assert.equal(invoice.bolt11, 'saved');
	assert.equal(invoice.kind, 'bolt11');
	assert.equal(f.queries, 0);
	assert.equal(f.sent.length, 0);
});
it('invalid peers and expired quotes fail before any preparation', async () => {
	const f = fixture();
	await assert.rejects(f.coordinator.quote('nope', 20000), {
		code: 'INVALID_PARAMS'
	});
	await assert.rejects(
		f.coordinator.create(
			{
				requestId: 'request-123456789',
				amountSats: 20000,
				quote: { peer, amountSats: 20000, expiresAt: 1 }
			},
			peer
		),
		{ code: 'QUOTE_EXPIRED' }
	);
	assert.equal(f.queries, 0);
	assert.equal(f.sent.length, 0);
});

describe('receive route selection', () => {
	it('quotes bolt11 against a suitable channel and direct funding without one', async () => {
		const withChannel = fixture({}, { spare: true, jobs: [] });
		const bolt11 = await withChannel.coordinator.quote(peer, 20000);
		assert.deepEqual(bolt11, {
			available: true,
			mode: 'bolt11',
			peer,
			amountSats: 20000,
			feeSats: 0,
			terms: { feeBaseMsat: 0, feePpm: 0 },
			expiresAt: 1060000
		});
		assert.deepEqual(withChannel.sent, [{ op: 'quote' }]);

		const without = fixture({}, { jobs: [] });
		const df = await without.coordinator.quote(peer, 20000);
		assert.deepEqual(df, {
			available: true,
			mode: 'direct-funding',
			peer,
			amountSats: 20000,
			feeSats: 0,
			minAmountSat: 5000,
			expiresAt: 1060000
		});
		// The fallback prices nothing at the peer, so it costs no round trip.
		assert.equal(without.sent.length, 0);
	});

	it('does not count a channel another request has already reserved', async () => {
		// The spare channel is the only candidate, and a live request holds it.
		const f = fixture(
			{ id: 'holder', channelId: spareId, epochId: undefined },
			{ spare: true }
		);
		assert.equal(
			(await f.coordinator.quote(peer, 20000)).mode,
			'direct-funding'
		);
	});

	it('refuses either mode while the peer is not connected', async () => {
		for (const peers of [
			[],
			[{ pubkey: peer, host: 'h', port: 1, state: 'disconnected' }],
			[{ pubkey: otherPeer, host: 'h', port: 1, state: 'connected' }]
		]) {
			const f = fixture({}, { spare: true, jobs: [], peers });
			await assert.rejects(f.coordinator.quote(peer, 20000), (e: Failure) => {
				assert.equal(e.code, 'RECEIVE_UNAVAILABLE');
				assert.match(e.message, /Connect to your node/);
				return true;
			});
			assert.equal(f.sent.length, 0);
		}
	});

	it('names the minimum of the mode the amount would actually take', async () => {
		const f = fixture({}, { jobs: [], config: { minAmountSat: 25000 } });
		await assert.rejects(f.coordinator.quote(peer, 20000), (e: Failure) => {
			assert.equal(e.code, 'AMOUNT_TOO_SMALL');
			assert.match(e.message, /25000/);
			return true;
		});
		// The same amount is fine on a channel that already exists: there the
		// floor is the dust limit, not the direct-funding minimum.
		const ok = fixture(
			{},
			{ spare: true, jobs: [], config: { minAmountSat: 25000 } }
		);
		assert.equal((await ok.coordinator.quote(peer, 20000)).mode, 'bolt11');
	});
});

describe('receive steered through the primaries (issue #1922)', () => {
	const ready = (pubkey: string): Peer => ({
		pubkey,
		host: 'lsp.example',
		port: 9735,
		state: 'ready'
	});
	const body = (quote: unknown): Json => ({
		requestId: 'request-123456789',
		amountSats: 20000,
		description: 'coffee',
		quote
	});

	it('needs a peer when no primary is configured', async () => {
		const f = fixture({}, { jobs: [] });
		await assert.rejects(
			f.coordinator.quote(undefined, 20000),
			(e: Failure) => {
				assert.equal(e.code, 'INVALID_PARAMS');
				assert.match(e.message, /configure primaries/);
				return true;
			}
		);
		assert.equal(f.sent.length, 0);
	});

	it('quotes the first primary that is connected, naming the ones passed over', async () => {
		const f = fixture(
			{},
			{
				spare: true,
				jobs: [],
				peers: [ready(peer)],
				primaries: [{ pubkey: otherPeer }, { pubkey: peer }]
			}
		);
		const quote = await f.coordinator.quote(undefined, 20000);
		assert.equal(quote.mode, 'bolt11');
		assert.equal(quote.peer, peer);
		assert.deepEqual(quote.terms, { feeBaseMsat: 0, feePpm: 0 });
		assert.deepEqual(
			quote.skipped.map((s: Json) => [s.pubkey, s.rank, s.stage, s.code]),
			[[otherPeer, 1, 'connect', 'PEER_NOT_CONNECTED']]
		);
		// Only the chosen peer was asked anything.
		assert.deepEqual(f.sent, [{ op: 'quote' }]);
	});

	it('binds the request to the primary it was quoted at, whatever direct funding is configured for', async () => {
		// Neither primary has a channel, so both would be direct-funding; the
		// node's policy names the second, and the first is still the one the
		// quote picks and the create mints for. The policy is not touched.
		const f = fixture(
			{},
			{
				jobs: [],
				peers: [ready(otherPeer), ready(peer)],
				config: { lspPubkey: peer, lspHost: 'lsp.example', lspPort: 9735 },
				primaries: [{ pubkey: otherPeer }, { pubkey: peer }]
			}
		);
		const quote = await f.coordinator.quote(undefined, 20000);
		assert.equal(quote.mode, 'direct-funding');
		assert.equal(quote.peer, otherPeer);
		assert.equal(quote.skipped, undefined);
		const created = await f.coordinator.create(body(quote));
		assert.equal(created.kind, 'direct-funding');
		assert.equal(created.peer, otherPeer);
		assert.deepEqual(f.mints, [{ amountSats: 20000, lspPubkey: otherPeer }]);
		assert.deepEqual(f.configured, []);
		assert.equal(f.config.lspPubkey, peer);
		assert.equal(f.sent.length, 0);
	});

	it('passes over a primary whose relay a payer could not be told how to reach', async () => {
		// The first primary is up over WebSocket and stores no address, so a
		// request bound to it would carry no relay descriptor; the second is
		// reached over TCP.
		const f = fixture(
			{},
			{
				jobs: [],
				peers: [
					{ ...ready(otherPeer), transport: 'ws' },
					{ ...ready(peer), transport: 'tcp' }
				],
				primaries: [{ pubkey: otherPeer }, { pubkey: peer }]
			}
		);
		const quote = await f.coordinator.quote(undefined, 20000);
		assert.equal(quote.mode, 'direct-funding');
		assert.equal(quote.peer, peer);
		assert.equal(quote.skipped.length, 1);
		assert.equal(quote.skipped[0].pubkey, otherPeer);
		assert.equal(quote.skipped[0].code, 'RECEIVE_UNAVAILABLE');
		assert.match(quote.skipped[0].message, /No address is known/);
	});

	it("passes over a primary that dialed us, whose listed port is its socket's source port", async () => {
		// The first primary is up, but it connected to this node: nothing was
		// ever dialed, so the port listed for it is ephemeral and no payer could
		// reach a relay there. The second was dialed, at its listening port.
		const f = fixture(
			{},
			{
				jobs: [],
				peers: [
					{ ...ready(otherPeer), host: '10.0.0.5', port: 54123, inbound: true },
					ready(peer)
				],
				primaries: [{ pubkey: otherPeer }, { pubkey: peer }]
			}
		);
		const quote = await f.coordinator.quote(undefined, 20000);
		assert.equal(quote.mode, 'direct-funding');
		assert.equal(quote.peer, peer);
		assert.deepEqual(
			quote.skipped.map((s: Json) => [s.pubkey, s.stage, s.code]),
			[[otherPeer, 'attempt', 'RECEIVE_UNAVAILABLE']]
		);
		const created = await f.coordinator.create(body(quote));
		assert.equal(created.peer, peer);
		assert.deepEqual(f.mints, [{ amountSats: 20000, lspPubkey: peer }]);
	});

	it('takes the relay address stored with the primary when the connection has none', async () => {
		const f = fixture(
			{},
			{
				jobs: [],
				peers: [{ pubkey: peer, host: '', port: 0, state: 'ready' }],
				primaries: [{ pubkey: peer, host: 'relay.example', port: 9737 }]
			}
		);
		const quote = await f.coordinator.quote(undefined, 20000);
		assert.equal(quote.peer, peer);
		const created = await f.coordinator.create(body(quote));
		assert.equal(created.kind, 'direct-funding');
		assert.deepEqual(f.mints, [{ amountSats: 20000, lspPubkey: peer }]);
		// No policy was written: this node never dialed the peer, so there is
		// no address to write.
		assert.deepEqual(f.configured, []);
		assert.equal(f.config.lspPubkey, null);
	});

	it("measures the amount against each primary's own route", async () => {
		// 20000 sats is under the 25000 direct-funding minimum the first
		// primary would need, but fine on the channel the second has.
		const f = fixture(
			{},
			{
				spare: true,
				jobs: [],
				peers: [ready(otherPeer), ready(peer)],
				config: { minAmountSat: 25000 },
				primaries: [{ pubkey: otherPeer }, { pubkey: peer }]
			}
		);
		const quote = await f.coordinator.quote(undefined, 20000);
		assert.equal(quote.mode, 'bolt11');
		assert.equal(quote.peer, peer);
		assert.equal(quote.skipped[0].code, 'AMOUNT_TOO_SMALL');
		assert.match(quote.skipped[0].message, /25000/);
	});

	it('passes over a primary whose node does not serve the receive', async () => {
		const f = fixture(
			{},
			{
				jobs: [],
				peers: [ready(otherPeer), ready(peer)],
				primaries: [{ pubkey: otherPeer }, { pubkey: peer }]
			}
		);
		// Both primaries have a channel, and only the second answers the
		// fee quote; the first's refusal carries its own message.
		f.channels.push(
			{
				channelId: '77'.repeat(32),
				peerPubkey: otherPeer,
				state: 'NORMAL',
				htlcUsable: true,
				localBalanceSats: 0,
				remoteBalanceSats: 100000
			},
			{
				channelId: spareId,
				peerPubkey: peer,
				state: 'NORMAL',
				htlcUsable: true,
				localBalanceSats: 0,
				remoteBalanceSats: 100000
			}
		);
		// The service turns a peer's refusal into the coordinator's own typed
		// error, carrying the peer's message.
		f.node.getFforReceiveService = () => ({
			request: async (to: string, request: Json) => {
				f.sent.push({ ...request, to });
				if (to === otherPeer)
					throw new BeignetError(
						'RECEIVE_UNAVAILABLE',
						'Your node does not provide offline receiving.'
					);
				return { version: 1, feeBaseMsat: 0, feePpm: 0 };
			},
			receipts: async () => undefined
		});
		const quote = await f.coordinator.quote(undefined, 20000);
		assert.equal(quote.peer, peer);
		assert.equal(quote.mode, 'bolt11');
		assert.equal(quote.skipped[0].pubkey, otherPeer);
		assert.match(
			quote.skipped[0].message,
			/does not provide offline receiving/
		);
		assert.deepEqual(f.sent, [
			{ op: 'quote', to: otherPeer },
			{ op: 'quote', to: peer }
		]);
	});

	it('fails typed when no primary qualifies', async () => {
		const f = fixture(
			{},
			{
				jobs: [],
				peers: [],
				primaries: [{ pubkey: otherPeer }, { pubkey: peer }]
			}
		);
		await assert.rejects(
			f.coordinator.quote(undefined, 20000),
			(e: Failure) => {
				assert.equal(e.code, 'NO_PRIMARY_AVAILABLE');
				assert.match(e.message, /2 of 2 tried/);
				assert.match(
					e.message,
					new RegExp(
						`${otherPeer.slice(0, 16)} \\(rank 1\\): PEER_NOT_CONNECTED`
					)
				);
				assert.match(
					e.message,
					new RegExp(`${peer.slice(0, 16)} \\(rank 2\\): PEER_NOT_CONNECTED`)
				);
				return true;
			}
		);
	});

	it('a request under way keeps its own peer, whatever the ranks say', async () => {
		const f = fixture(
			{ id: 'request-123456789', expiresAt: undefined, epochId: undefined },
			{
				spare: true,
				peers: [ready(otherPeer), ready(peer)],
				primaries: [{ pubkey: otherPeer }, { pubkey: peer }]
			}
		);
		f.channels.push({
			channelId: '77'.repeat(32),
			peerPubkey: otherPeer,
			state: 'NORMAL',
			htlcUsable: true,
			localBalanceSats: 0,
			remoteBalanceSats: 100000
		});
		const quote = await f.coordinator.quote(
			undefined,
			20000,
			'request-123456789'
		);
		assert.equal(quote.peer, peer);
		assert.equal(quote.skipped, undefined);
	});

	it('binds a create that names no peer to the one its quote named', async () => {
		const f = fixture(
			{},
			{
				spare: true,
				jobs: [],
				peers: [ready(otherPeer), ready(peer)],
				primaries: [{ pubkey: otherPeer }, { pubkey: peer }]
			}
		);
		f.channels.push({
			channelId: '77'.repeat(32),
			peerPubkey: otherPeer,
			state: 'NORMAL',
			htlcUsable: true,
			localBalanceSats: 0,
			remoteBalanceSats: 100000
		});
		const quote = await f.coordinator.quote(undefined, 20000);
		assert.equal(quote.peer, otherPeer);
		// The ranks change between review and create: the request does not.
		f.node.listPrimaries = () => ({
			fillThresholdSat: null,
			receiveTarget: peer,
			primaries: []
		});
		const created = await f.coordinator.create(body(quote));
		assert.equal(created.kind, 'bolt11');
		assert.equal(f.coordinator.status().requests[0].peer, otherPeer);
		assert.deepEqual([...f.coordinator.reservedIds()], ['77'.repeat(32)]);
	});

	it("a create naming a peer other than its quote's is a stale review", async () => {
		const f = fixture({}, { spare: true, jobs: [] });
		const quote = await f.coordinator.quote(peer, 20000);
		await assert.rejects(
			f.coordinator.create(body(quote), otherPeer),
			(e: Failure) => e.code === 'INVALID_REVIEW'
		);
		await assert.rejects(
			f.coordinator.create(body({ ...quote, peer: 42 })),
			(e: Failure) => e.code === 'INVALID_REVIEW'
		);
		assert.equal(f.started, 0);
	});
});

describe('receive request creation', () => {
	const body = (quote: unknown): Json => ({
		requestId: 'request-123456789',
		amountSats: 20000,
		description: 'coffee',
		quote
	});

	it('a suitable channel still produces a bolt11 invoice', async () => {
		const f = fixture({}, { spare: true, jobs: [] });
		const quote = await f.coordinator.quote(peer, 20000);
		const created = await f.coordinator.create(body(quote), peer);
		assert.equal(created.kind, 'bolt11');
		assert.equal(created.bolt11, 'lnbcrt-spare');
		assert.equal(created.paymentHash, spareHash);
		assert.equal(created.amountSats, 20000);
		assert.equal(created.offlineReceive, true);
		assert.equal(created.expiresAt, 1600000);
		assert.equal(f.minted, 0);
		assert.equal(f.started, 1);
		assert.deepEqual([...f.coordinator.reservedIds()], [spareId]);
		// Only the fee quote goes on the wire. Never an allocate.
		assert.deepEqual(f.sent, [{ op: 'quote' }, { op: 'quote' }]);
	});

	it('no suitable channel mints a direct-funding request and configures the peer', async () => {
		const f = fixture({}, { jobs: [] });
		const quote = await f.coordinator.quote(peer, 20000);
		const created = await f.coordinator.create(body(quote), peer);
		assert.deepEqual(created, {
			kind: 'direct-funding',
			request: 'df-request-1-20000',
			paymentHash: receiptHash,
			expiresAt: 1900000,
			amountSats: 20000,
			peer,
			offlineReceive: false
		});
		assert.deepEqual(f.configured, [
			{ lspPubkey: peer, lspHost: 'lsp.example', lspPort: 9735 }
		]);
		// Nothing was asked of the peer, nothing was reserved, no epoch started.
		assert.equal(f.sent.length, 0);
		assert.equal(f.started, 0);
		const status = f.coordinator.status();
		assert.deepEqual(status.reservedChannelIds, []);
		assert.equal(status.requests.length, 1);
		assert.equal(status.requests[0].kind, 'direct-funding');
		assert.equal(status.requests[0].request, 'df-request-1-20000');
		assert.equal(status.requests[0].channelId, undefined);
		assert.equal(status.requests[0].epochId, undefined);
	});

	it('reuses a config that already names this peer, without touching it', async () => {
		const f = fixture(
			{},
			{
				jobs: [],
				config: {
					// Stored uppercase: the same peer, however the operator typed it.
					lspPubkey: peer.toUpperCase(),
					lspHost: 'set-by-operator',
					lspPort: 19735,
					targetInboundSat: 500000,
					trusted: true,
					allowSplice: true
				}
			}
		);
		const quote = await f.coordinator.quote(peer, 20000);
		const created = await f.coordinator.create(body(quote), peer);
		assert.equal(created.kind, 'direct-funding');
		assert.deepEqual(f.configured, []);
		assert.equal(f.config.lspHost, 'set-by-operator');
		assert.equal(f.config.lspPort, 19735);
		assert.equal(f.config.targetInboundSat, 500000);
		assert.equal(f.config.trusted, true);
		assert.equal(f.config.allowSplice, true);
	});

	it('mints for another peer without retargeting the configured one (issue #1922)', async () => {
		// The other peer is a configured primary: a named peer has to be one,
		// or the configured peer itself.
		const f = fixture(
			{},
			{
				jobs: [],
				config: { lspPubkey: otherPeer },
				primaries: [{ pubkey: peer }]
			}
		);
		const quote = await f.coordinator.quote(peer, 20000);
		const created = await f.coordinator.create(body(quote), peer);
		assert.equal(created.kind, 'direct-funding');
		assert.equal(created.peer, peer);
		// The request carries its own peer; the policy stays the operator's.
		assert.deepEqual(f.mints, [{ amountSats: 20000, lspPubkey: peer }]);
		assert.deepEqual(f.configured, []);
		assert.equal(f.config.lspPubkey, otherPeer);
		assert.equal(f.coordinator.status().requests.length, 1);
	});

	it('refuses a peer that is neither a primary nor the configured one once a policy exists', async () => {
		// Up and dialed, so a request could carry a relay for it, but the
		// operator never configured it: the peer a direct-funded channel opens
		// with holds every payment it receives, so the choice stays theirs.
		const f = fixture(
			{},
			{
				jobs: [],
				config: { lspPubkey: otherPeer, lspHost: 'lsp.example', lspPort: 9735 }
			}
		);
		const quote = await f.coordinator.quote(peer, 20000);
		await assert.rejects(
			f.coordinator.create(body(quote), peer),
			(e: Failure) => {
				assert.equal(e.code, 'RECEIVE_UNAVAILABLE');
				assert.match(e.message, /neither a configured primary/);
				return true;
			}
		);
		assert.equal(f.minted, 0);
		assert.deepEqual(f.configured, []);
	});

	it('refuses a peer no payer could be told how to reach', async () => {
		const f = fixture(
			{},
			{
				jobs: [],
				peers: [
					{
						pubkey: peer,
						host: 'ws.example',
						port: 443,
						state: 'ready',
						transport: 'ws'
					}
				]
			}
		);
		const quote = await f.coordinator.quote(peer, 20000);
		await assert.rejects(
			f.coordinator.create(body(quote), peer),
			(e: Failure) => {
				assert.equal(e.code, 'RECEIVE_UNAVAILABLE');
				assert.match(e.message, /No address is known/);
				return true;
			}
		);
		assert.equal(f.minted, 0);
		assert.equal(f.coordinator.status().requests.length, 0);
	});

	it('writes no policy for a peer up over ws whose relay the primaries store (issue #1922)', async () => {
		// The request is fine: its relay is the address stored with the primary.
		// The policy is not written, since an unbound request later would take
		// its relay from there and a ws address is no use to a payer.
		const f = fixture(
			{},
			{
				jobs: [],
				peers: [
					{
						pubkey: peer,
						host: 'ws.example',
						port: 443,
						state: 'ready',
						transport: 'ws'
					}
				],
				primaries: [{ pubkey: peer, host: 'relay.example', port: 9737 }]
			}
		);
		const quote = await f.coordinator.quote(peer, 20000);
		const created = await f.coordinator.create(body(quote), peer);
		assert.equal(created.kind, 'direct-funding');
		assert.deepEqual(f.mints, [{ amountSats: 20000, lspPubkey: peer }]);
		assert.deepEqual(f.configured, []);
		assert.equal(f.config.lspPubkey, null);
	});

	it('refuses a peer that dialed us when nothing stores its address', async () => {
		const f = fixture(
			{},
			{
				jobs: [],
				peers: [
					{
						pubkey: peer,
						host: '10.0.0.5',
						port: 54123,
						state: 'ready',
						inbound: true
					}
				]
			}
		);
		const quote = await f.coordinator.quote(peer, 20000);
		await assert.rejects(
			f.coordinator.create(body(quote), peer),
			(e: Failure) => {
				assert.equal(e.code, 'RECEIVE_UNAVAILABLE');
				assert.match(e.message, /No address is known/);
				return true;
			}
		);
		assert.deepEqual(f.configured, []);
		assert.equal(f.minted, 0);
	});

	it('is idempotent on requestId while the request lives, and replaces it once expired', async () => {
		const f = fixture({}, { jobs: [] });
		const quote = await f.coordinator.quote(peer, 20000);
		const first = await f.coordinator.create(body(quote), peer);
		const retry = await f.coordinator.create(body(quote), peer);
		assert.deepEqual(retry, first);
		assert.equal(f.minted, 1);
		assert.equal(f.configured.length, 1);
		// Past the envelope's own expiry there is nothing left to hand a payer,
		// so the same id mints a replacement instead of replaying a dead one.
		f.now = first.expiresAt + 1;
		const replaced = await f.coordinator.create(
			body({ ...quote, expiresAt: f.now + 60000 }),
			peer
		);
		assert.notEqual(replaced.request, first.request);
		assert.equal(f.minted, 2);
		assert.equal(f.coordinator.status().requests.length, 1);
	});

	it('reconciliation leaves a direct-funding request entirely alone', async () => {
		const f = fixture(
			{},
			{
				jobs: [
					{
						id: 'df',
						peer,
						amountSats: 20000,
						kind: 'direct-funding',
						request: 'df-request-1-20000',
						paymentHash: receiptHash,
						expiresAt: 1
					}
				]
			}
		);
		await f.coordinator.sync();
		assert.equal(f.queries, 0);
		assert.equal(f.closes, 0);
		assert.deepEqual([...f.coordinator.reservedIds()], []);
	});

	it('a journal written before the split loads, and reads back as bolt11', () => {
		const f = fixture({ allocationId: '44'.repeat(16) });
		const [entry] = f.coordinator.status().requests;
		assert.equal(entry.kind, 'bolt11');
		assert.equal(entry.allocationId, '44'.repeat(16));
		assert.deepEqual([...f.coordinator.reservedIds()], [channelId]);
	});
});
