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
	slots: Slot[];
};
type Channel = {
	channelId: string;
	state: string;
	peerPubkey?: string;
	htlcUsable?: boolean;
	localBalanceSats?: number;
	remoteBalanceSats?: number;
};
type Peer = { pubkey: string; host: string; port: number; state: string };
type Json = Record<string, unknown>;
type Failure = Error & { code?: string };
type Opts = {
	/** Add an empty inbound channel with the peer that a request may reserve. */
	spare?: boolean;
	jobs?: Json[];
	peers?: Peer[];
	config?: Json;
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
	/** Every op this coordinator put on the wire toward the peer. */
	const sent: Json[] = [];
	const saved: unknown[] = [];
	const node: Json = {
		listChannels: () => channels,
		listPeers: () =>
			opts.peers ?? [
				{ pubkey: peer, host: 'lsp.example', port: 9735, state: 'ready' }
			],
		getInfo: () => ({ blockHeight: 800000 }),
		fforEpochs: () => epochs,
		fforEpoch: (id: string) => epochs.find((e) => e.channelId === id),
		decodeInvoice: () => ({ timestamp: 1000, expiry: 600 }),
		getDirectFundingConfig: () => ({ ...config }),
		configureDirectFunding: (update: Json) => {
			configured.push(update);
			Object.assign(config, update);
			return { ...config };
		},
		createDirectFundingRequest: (body: { amountSats: number }) => {
			minted++;
			return {
				request: `df-request-${minted}-${body.amountSats}`,
				paymentHash: receiptHash,
				expiresAt: now + 900000
			};
		},
		fforStartEpoch: (params: {
			channelId: string;
			voucherAmountsMsat: string[];
		}) => {
			started++;
			const fresh = {
				channelId: params.channelId,
				epochId: spareEpochId,
				state: 'ACTIVE',
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
		getStorage: () => ({
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

	it('refuses rather than retargeting a node configured for another peer', async () => {
		const f = fixture({}, { jobs: [], config: { lspPubkey: otherPeer } });
		const quote = await f.coordinator.quote(peer, 20000);
		await assert.rejects(
			f.coordinator.create(body(quote), peer),
			(e: Failure) => {
				assert.equal(e.code, 'RECEIVE_UNAVAILABLE');
				assert.match(e.message, /configured for another peer/);
				return true;
			}
		);
		assert.equal(f.minted, 0);
		assert.equal(f.config.lspPubkey, otherPeer);
		assert.equal(f.coordinator.status().requests.length, 0);
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
