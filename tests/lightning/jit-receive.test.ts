/**
 * JIT channel receive engine, LSP side (issue #594, LFBW port #532 3A).
 *
 * The engine holds HTLCs addressed to intercept SCIDs it minted, funds a
 * channel to the client, then forwards. Everything here is about the two
 * obligations that make that safe: every held part is resolved exactly once,
 * and nothing is fronted outside the configured caps.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { EventEmitter } from 'events';
import {
	IHeldJitPart,
	IJitManagerDeps,
	IJitReceiveAuthorization,
	IJitReceiveConfig,
	IJitReceiveQuoteRequest,
	IPersistedHeldPart,
	JIT_INTERCEPT_SCID_BLOCK,
	JitReceiveManager,
	decodeJitAck,
	decodeJitAuthorization,
	decodeJitQuote,
	decodeJitQuoteRequest,
	encodeJitAck,
	encodeJitAuthorization,
	encodeJitQuote,
	encodeJitQuoteRequest,
	mintInterceptScid
} from '../../src/lightning/liquidity/jit-receive';
import {
	ChannelFundingUnavailableCode,
	ChannelFundingUnavailableError,
	FundingWaitTimeoutError,
	InvalidChannelOpenError
} from '../../src/lightning/node/types';
import { decodeShortChannelId } from '../../src/lightning/gossip/types';
import { ROUTING_INFO_LENGTH } from '../../src/lightning/onion/types';

const TEMPORARY_CHANNEL_FAILURE = 0x1007;
const EXPIRY_TOO_SOON = 0x4010;
const CLIENT = '02' + 'aa'.repeat(32);
const OTHER_CLIENT = '03' + 'bb'.repeat(32);

// ── Harness ────────────────────────────────────────────────────────

interface IHarness {
	manager: JitReceiveManager;
	forwarded: Array<{ channelId: string; part: IHeldJitPart }>;
	failed: Array<{ part: IHeldJitPart; code: number }>;
	opens: bigint[];
	splices: Array<{ channelId: string; amountSats: bigint }>;
	metadata: Map<string, string>;
	jitClients: string[];
	height: { value: number };
	/** Swappable behaviours, so a test can stall or refuse one funding. */
	openResult: { fn: (fundingSats: bigint) => Promise<Buffer> };
	spliceResult: { fn: (amountSats: bigint) => Promise<void> };
	restoredFail: { fn: (part: IPersistedHeldPart) => boolean };
	scidInUse: { fn: (scidHex: string) => boolean };
	channelPeer: { fn: (channelId: Buffer) => string | null };
	/** Set false to make every upstream failure refuse (a reestablishing channel). */
	failsDeliver: { value: boolean };
	storageWrites: { failKeys: Set<string> };
	/** What the node could front on-chain right now; null = no figure. */
	fundable: { value: bigint | null };
}

function makeHarness(
	config: Partial<IJitReceiveConfig> = {},
	seed?: { metadata?: Map<string, string> }
): IHarness {
	const metadata = seed?.metadata ?? new Map<string, string>();
	const openChannelId = crypto.randomBytes(32);
	const h: IHarness = {
		manager: undefined as unknown as JitReceiveManager,
		forwarded: [],
		failed: [],
		opens: [],
		splices: [],
		metadata,
		jitClients: [],
		height: { value: 800_000 },
		openResult: { fn: async (): Promise<Buffer> => openChannelId },
		spliceResult: { fn: async (): Promise<void> => undefined },
		restoredFail: { fn: (): boolean => true },
		scidInUse: { fn: (): boolean => false },
		channelPeer: { fn: (): string | null => CLIENT },
		failsDeliver: { value: true },
		storageWrites: { failKeys: new Set<string>() },
		fundable: { value: null }
	};

	const deps: IJitManagerDeps = {
		currentBlockHeight: () => h.height.value,
		isScidInUse: (scidHex) => h.scidInUse.fn(scidHex),
		openZeroConfChannelAndWait: async (_pubkey, fundingSats) => {
			h.opens.push(fundingSats);
			return h.openResult.fn(fundingSats);
		},
		forwardOnto: (channelId, part) => {
			h.forwarded.push({ channelId: channelId.toString('hex'), part });
		},
		failureCodes: {
			temporaryChannelFailure: TEMPORARY_CHANNEL_FAILURE,
			expiryTooSoon: EXPIRY_TOO_SOON
		},
		setJitClients: (pubkeys) => {
			h.jitClients = [...pubkeys];
		},
		peerForChannel: (channelId) => h.channelPeer.fn(channelId),
		spliceInAndWait: async (channelId, amountSats) => {
			h.splices.push({ channelId: channelId.toString('hex'), amountSats });
			return h.spliceResult.fn(amountSats);
		},
		maxFundableSats: () => h.fundable.value,
		storage: {
			saveMetadata: (k, v) => {
				if (h.storageWrites.failKeys.has(k)) {
					throw new Error(`storage refused ${k}`);
				}
				metadata.set(k, v);
			},
			loadMetadata: (k) => metadata.get(k) ?? null
		},
		failRestoredHtlc: (part) => h.restoredFail.fn(part)
	};

	// Upstream failures are recorded through each part's own failIncoming
	// closure (see makePart), which is what the node hands the engine.
	h.manager = new JitReceiveManager(deps, {
		enabled: true,
		fundingRetryDelayMs: 1,
		...config
	});
	return h;
}

function makePart(
	h: IHarness,
	opts: {
		amountMsat?: bigint;
		paymentHash?: Buffer;
		incomingCltvExpiry?: number;
		forwardCltv?: number;
	} = {}
): IHeldJitPart {
	const part: IHeldJitPart = {
		inChannelId: crypto.randomBytes(32),
		inHtlcId: BigInt(Math.floor(Math.random() * 1_000_000)),
		paymentHash: opts.paymentHash ?? crypto.randomBytes(32),
		forwardAmountMsat: opts.amountMsat ?? 1_000_000n,
		forwardCltv: opts.forwardCltv ?? 800_100,
		incomingCltvExpiry: opts.incomingCltvExpiry ?? 800_200,
		nextPacket: {
			version: 0,
			ephemeralKey: crypto.randomBytes(33),
			routingInfo: Buffer.alloc(ROUTING_INFO_LENGTH),
			hmac: crypto.randomBytes(32)
		},
		failIncoming: (code: number): boolean => {
			h.failed.push({ part, code });
			return h.failsDeliver.value;
		}
	};
	return part;
}

function auth(
	overrides: Partial<IJitReceiveAuthorization> = {}
): IJitReceiveAuthorization {
	return {
		requestId: crypto.randomBytes(8),
		maxAmountMsat: 100_000_000n,
		targetRemainingInboundSat: 50_000n,
		expirySeconds: 600,
		...overrides
	};
}

function quoteReq(
	overrides: Partial<IJitReceiveQuoteRequest> = {}
): IJitReceiveQuoteRequest {
	return {
		requestId: crypto.randomBytes(8),
		maxAmountMsat: 100_000_000n,
		targetRemainingInboundSat: 50_000n,
		...overrides
	};
}

function waitFor<T = unknown>(
	emitter: EventEmitter,
	event: string,
	timeoutMs = 3_000
): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		const timer = setTimeout(
			() => reject(new Error(`timed out waiting for ${event}`)),
			timeoutMs
		);
		emitter.once(event, (data: T) => {
			clearTimeout(timer);
			resolve(data);
		});
	});
}

// ── Wire codecs ────────────────────────────────────────────────────

describe('JIT receive wire payloads', function () {
	it('round-trips an authorization, bound and unbound', function () {
		const bound = auth({
			paymentHash: crypto.randomBytes(32),
			expectedTotalMsat: 42_000n,
			acceptsSkimmedFee: true
		});
		const back = decodeJitAuthorization(encodeJitAuthorization(bound));
		expect(back.requestId.equals(bound.requestId)).to.equal(true);
		expect(back.paymentHash!.equals(bound.paymentHash!)).to.equal(true);
		expect(back.maxAmountMsat).to.equal(bound.maxAmountMsat);
		expect(back.expectedTotalMsat).to.equal(42_000n);
		expect(back.targetRemainingInboundSat).to.equal(50_000n);
		expect(back.expirySeconds).to.equal(600);
		expect(back.acceptsSkimmedFee).to.equal(true);

		const unbound = decodeJitAuthorization(encodeJitAuthorization(auth()));
		expect(unbound.paymentHash).to.equal(undefined);
		expect(unbound.expectedTotalMsat).to.equal(undefined);
		expect(unbound.acceptsSkimmedFee).to.equal(false);
	});

	it('reads an authorization without the skim flag as not accepting one', function () {
		// The flag byte is the last one: a payload that predates it must decode
		// as a client that never agreed to a skimmed HTLC, never as one that did.
		const legacy = encodeJitAuthorization(
			auth({ acceptsSkimmedFee: true })
		).subarray(0, 68);
		expect(decodeJitAuthorization(legacy).acceptsSkimmedFee).to.equal(false);
	});

	it('round-trips an ack including its refusal reason', function () {
		const ack = {
			requestId: crypto.randomBytes(8),
			interceptScid: crypto.randomBytes(8),
			accepted: false,
			flatFeeSat: 1_000n,
			feePpm: 2_500,
			reason: 'max fundable is 1000000 sats'
		};
		const back = decodeJitAck(encodeJitAck(ack));
		expect(back.accepted).to.equal(false);
		expect(back.flatFeeSat).to.equal(1_000n);
		expect(back.feePpm).to.equal(2_500);
		expect(back.reason).to.equal(ack.reason);
	});

	it('refuses a truncated authorization and an ack whose reason runs past the payload', function () {
		expect(() => decodeJitAuthorization(Buffer.alloc(67))).to.throw(
			/too short/
		);
		const ack = encodeJitAck({
			requestId: Buffer.alloc(8),
			interceptScid: Buffer.alloc(8),
			accepted: true,
			flatFeeSat: 0n,
			feePpm: 0,
			reason: 'hello'
		});
		// A silently truncated reason reads as a legitimate (wrong) message.
		expect(() => decodeJitAck(ack.subarray(0, ack.length - 2))).to.throw(
			/runs past the payload/
		);
	});
});

// ── Quote wire payloads (issue #687) ───────────────────────────────

describe('JIT quote wire payloads', function () {
	it('round-trips a quote request and a quote including its reason', function () {
		const req = quoteReq();
		const back = decodeJitQuoteRequest(encodeJitQuoteRequest(req));
		expect(back.requestId.equals(req.requestId)).to.equal(true);
		expect(back.maxAmountMsat).to.equal(100_000_000n);
		expect(back.targetRemainingInboundSat).to.equal(50_000n);

		const quote = {
			requestId: req.requestId,
			accepted: false,
			flatFeeSat: 1_000n,
			feePpm: 2_500,
			maxClientFundingSats: 400_000n,
			fundingSats: 0n,
			reason: 'the provider funds at most 400000 sats for one receive'
		};
		const q = decodeJitQuote(encodeJitQuote(quote));
		expect(q.requestId.equals(req.requestId)).to.equal(true);
		expect(q.accepted).to.equal(false);
		expect(q.flatFeeSat).to.equal(1_000n);
		expect(q.feePpm).to.equal(2_500);
		expect(q.maxClientFundingSats).to.equal(400_000n);
		expect(q.fundingSats).to.equal(0n);
		expect(q.reason).to.equal(quote.reason);

		const accepted = decodeJitQuote(
			encodeJitQuote({
				...quote,
				accepted: true,
				fundingSats: 160_000n,
				reason: undefined
			})
		);
		expect(accepted.accepted).to.equal(true);
		expect(accepted.fundingSats).to.equal(160_000n);
		expect(accepted.reason).to.equal(undefined);
	});

	it('refuses a truncated request and a quote whose reason runs past the payload', function () {
		expect(() => decodeJitQuoteRequest(Buffer.alloc(23))).to.throw(/too short/);
		const quote = encodeJitQuote({
			requestId: Buffer.alloc(8),
			accepted: true,
			flatFeeSat: 0n,
			feePpm: 0,
			maxClientFundingSats: 0n,
			fundingSats: 0n,
			reason: 'hello'
		});
		expect(() => decodeJitQuote(quote.subarray(0, quote.length - 2))).to.throw(
			/runs past the payload/
		);
	});
});

// ── SCID minting ───────────────────────────────────────────────────

describe('JIT intercept SCID minting', function () {
	it('mints in a block height no confirmed channel can ever reach', function () {
		const scid = mintInterceptScid(() => false)!;
		expect(scid.length).to.equal(8);
		expect(decodeShortChannelId(scid).block).to.equal(JIT_INTERCEPT_SCID_BLOCK);
	});

	it('never hands back an SCID that is already taken', function () {
		const taken = new Set<string>();
		for (let i = 0; i < 20; i++) {
			const scid = mintInterceptScid((hex) => taken.has(hex))!;
			expect(taken.has(scid.toString('hex'))).to.equal(false);
			taken.add(scid.toString('hex'));
		}
	});

	it('refuses rather than colliding when every candidate is taken', function () {
		expect(mintInterceptScid(() => true)).to.equal(null);
	});
});

// ── Intent registration ────────────────────────────────────────────

describe('JIT intent registration', function () {
	it('mints the SCID itself and returns it in the ack', function () {
		const h = makeHarness({ flatFeeSat: 500n, feePpm: 1_000 });
		const request = auth({ acceptsSkimmedFee: true });
		const ack = h.manager.registerIntent(CLIENT, request);
		expect(ack.accepted).to.equal(true);
		expect(ack.requestId.equals(request.requestId)).to.equal(true);
		expect(ack.flatFeeSat).to.equal(500n);
		expect(ack.feePpm).to.equal(1_000);
		expect(decodeShortChannelId(ack.interceptScid).block).to.equal(
			JIT_INTERCEPT_SCID_BLOCK
		);
		expect(h.manager.listIntents()).to.have.length(1);
	});

	it('gives two clients different SCIDs, so neither can take the other over', function () {
		const h = makeHarness();
		const first = h.manager.registerIntent(CLIENT, auth());
		const second = h.manager.registerIntent(OTHER_CLIENT, auth());
		expect(first.interceptScid.equals(second.interceptScid)).to.equal(false);
		expect(h.manager.listIntents()).to.have.length(2);
	});

	it('refuses an SCID that would shadow a real channel', function () {
		const h = makeHarness();
		h.scidInUse.fn = (): boolean => true;
		const ack = h.manager.registerIntent(CLIENT, auth());
		expect(ack.accepted).to.equal(false);
		expect(ack.reason).to.match(/free intercept scid/);
		expect(ack.interceptScid.equals(Buffer.alloc(8))).to.equal(true);
	});

	it('refuses more than the per-client funding cap', function () {
		const h = makeHarness({ maxClientFundingSats: 100_000n });
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ maxAmountMsat: 200_000_000n })
		);
		expect(ack.accepted).to.equal(false);
		expect(ack.reason).to.match(/max fundable/);
	});

	it('refuses a zero amount and a zero expiry', function () {
		const h = makeHarness();
		expect(
			h.manager.registerIntent(CLIENT, auth({ maxAmountMsat: 0n })).accepted
		).to.equal(false);
		expect(
			h.manager.registerIntent(CLIENT, auth({ expirySeconds: 0 })).accepted
		).to.equal(false);
	});

	it('bounds live intents per peer and overall', function () {
		const h = makeHarness({ maxLiveIntentsPerPeer: 1, maxLiveIntents: 2 });
		const first = h.manager.registerIntent(CLIENT, auth());
		expect(first.accepted).to.equal(true);
		// Asking again retires the wallet's own idle intent rather than
		// refusing (issue #674): the cap bounds what one peer holds open.
		const second = h.manager.registerIntent(CLIENT, auth());
		expect(second.accepted).to.equal(true);
		expect(second.interceptScid.equals(first.interceptScid)).to.equal(false);
		expect(h.manager.listIntents()).to.have.length(1);
		expect(h.manager.registerIntent(OTHER_CLIENT, auth()).accepted).to.equal(
			true
		);
		const third = h.manager.registerIntent('02' + 'cc'.repeat(32), auth());
		expect(third.accepted).to.equal(false);
		expect(third.reason).to.match(/maximum number of live intents/);
	});

	// Issue #674: two unpaid invoices are an ordinary afternoon for a wallet.
	// Its next request must not be refused for an hour, but an intent a
	// payment is already held against is not idle and is never retired.
	it("supersedes the wallet's oldest idle intent, never one with a held part", function () {
		const h = makeHarness({ maxLiveIntentsPerPeer: 2 });
		const superseded: string[] = [];
		h.manager.on('jit:intent-superseded', (d: { scidHex: string }) =>
			superseded.push(d.scidHex)
		);
		const a = h.manager.registerIntent(CLIENT, auth({ expirySeconds: 100 }));
		const b = h.manager.registerIntent(CLIENT, auth({ expirySeconds: 200 }));
		const c = h.manager.registerIntent(CLIENT, auth({ expirySeconds: 300 }));
		expect(c.accepted).to.equal(true);
		expect(superseded).to.deep.equal([a.interceptScid.toString('hex')]);
		expect(
			h.manager.listIntents().map((i) => i.interceptScidHex)
		).to.have.members([
			b.interceptScid.toString('hex'),
			c.interceptScid.toString('hex')
		]);
		// A part held against b makes it busy: the next request retires c
		// (the idle one) and b stays.
		expect(
			h.manager.tryInterceptUnknownScid(
				b.interceptScid.toString('hex'),
				makePart(h, { amountMsat: 1_000_000n })
			)
		).to.equal(true);
		const d = h.manager.registerIntent(CLIENT, auth({ expirySeconds: 400 }));
		expect(d.accepted).to.equal(true);
		expect(superseded).to.deep.equal([
			a.interceptScid.toString('hex'),
			c.interceptScid.toString('hex')
		]);
		expect(h.manager.listIntents().map((i) => i.interceptScidHex)).to.include(
			b.interceptScid.toString('hex')
		);
		// Two busy intents: nothing idle to retire, so the cap refuses.
		expect(
			h.manager.tryInterceptUnknownScid(
				d.interceptScid.toString('hex'),
				makePart(h, { amountMsat: 1_000_000n })
			)
		).to.equal(true);
		const e = h.manager.registerIntent(CLIENT, auth({ expirySeconds: 500 }));
		expect(e.accepted).to.equal(false);
		expect(e.reason).to.match(/per peer/);
	});

	it('derives the outbound zero-conf authorization from the live intents', function () {
		const h = makeHarness({ intentTtlMs: 20 });
		h.manager.registerIntent(CLIENT, auth());
		expect(h.jitClients).to.deep.equal([CLIENT]);
		// An expired intent takes the authorization with it: the set is
		// derived, never a standing grant.
		h.manager.listIntents()[0].expiresAt = Date.now() - 1;
		h.manager.scanExpiringHolds();
		expect(h.jitClients).to.deep.equal([]);
	});
});

// ── Interception ───────────────────────────────────────────────────

// ── Quotes (issue #687) ────────────────────────────────────────────

describe('JIT quote', function () {
	it('prices a receive without registering anything', function () {
		const h = makeHarness({
			flatFeeSat: 500n,
			feePpm: 1_000,
			fundingBufferSats: 10_000n
		});
		const events: string[] = [];
		h.manager.on('jit:intent', () => events.push('jit:intent'));
		const req = quoteReq({
			maxAmountMsat: 2_000_500n,
			targetRemainingInboundSat: 25_000n
		});
		const q = h.manager.quote(CLIENT, req);
		expect(q.accepted).to.equal(true);
		expect(q.requestId.equals(req.requestId)).to.equal(true);
		expect(q.flatFeeSat).to.equal(500n);
		expect(q.feePpm).to.equal(1_000);
		expect(q.maxClientFundingSats).to.equal(1_000_000n);
		// ceil(2000.5) + 25000 target + 10000 buffer: the open path's formula.
		expect(q.fundingSats).to.equal(37_001n);
		expect(q.reason).to.equal(undefined);
		expect(h.manager.listIntents()).to.have.length(0);
		expect(h.jitClients).to.deep.equal([]);
		expect(events).to.deep.equal([]);
		expect(h.metadata.has('jit:intents')).to.equal(false);
	});

	it('reports the clamped funding and refuses past the per-client cap', function () {
		const h = makeHarness({
			maxClientFundingSats: 30_000n,
			fundingBufferSats: 10_000n
		});
		const clamped = h.manager.quote(
			CLIENT,
			quoteReq({
				maxAmountMsat: 20_000_000n,
				targetRemainingInboundSat: 500_000n
			})
		);
		expect(clamped.accepted).to.equal(true);
		expect(clamped.fundingSats).to.equal(30_000n);
		const over = h.manager.quote(
			CLIENT,
			quoteReq({ maxAmountMsat: 40_000_000n })
		);
		expect(over.accepted).to.equal(false);
		expect(over.reason).to.equal(
			'the provider funds at most 30000 sats for one receive'
		);
		expect(over.fundingSats).to.equal(0n);
		expect(over.flatFeeSat, 'the fee still rides a refusal').to.equal(0n);
		expect(over.maxClientFundingSats).to.equal(30_000n);
	});

	it('refuses a zero amount', function () {
		const h = makeHarness();
		const q = h.manager.quote(CLIENT, quoteReq({ maxAmountMsat: 0n }));
		expect(q.accepted).to.equal(false);
		expect(q.reason).to.equal('the amount must be positive');
	});

	it('ignores idle intents the next registration would retire', function () {
		// Issue #674 lets a fresh authorization retire an idle intent, so a
		// wallet at its per-peer cap with nothing spent against those intents
		// is not refused a price it would be granted a moment later.
		const h = makeHarness({ maxLiveIntentsPerPeer: 2 });
		expect(h.manager.registerIntent(CLIENT, auth()).accepted).to.equal(true);
		expect(h.manager.registerIntent(CLIENT, auth()).accepted).to.equal(true);
		expect(h.manager.quote(CLIENT, quoteReq()).accepted).to.equal(true);
	});

	it('refuses while the wallet has a funding running and slots are full', async function () {
		const h = makeHarness({
			maxLiveIntentsPerPeer: 1,
			maxConcurrentFundings: 1
		});
		h.openResult.fn = (): Promise<Buffer> => new Promise(() => undefined);
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ expectedTotalMsat: 2_000_000n })
		);
		const funding = waitFor(h.manager, 'jit:funding');
		h.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(h, { amountMsat: 2_000_000n })
		);
		await funding;
		const own = h.manager.quote(CLIENT, quoteReq());
		expect(own.accepted).to.equal(false);
		expect(own.reason).to.equal(
			'the provider is already funding 1 receive(s) for this wallet; wait for one to finish'
		);
		const other = h.manager.quote(OTHER_CLIENT, quoteReq());
		expect(other.accepted).to.equal(false);
		expect(other.reason).to.equal(
			'the provider has its maximum number of channel fundings in flight; try again shortly'
		);
	});

	it('refuses past the lifetime budget and when the on-chain funds are short', function () {
		const h = makeHarness({
			maxTotalFundingSats: 40_000n,
			fundingBufferSats: 10_000n
		});
		const budget = h.manager.quote(
			CLIENT,
			quoteReq({
				maxAmountMsat: 20_000_000n,
				targetRemainingInboundSat: 20_000n
			})
		);
		expect(budget.accepted).to.equal(false);
		expect(budget.reason).to.equal(
			'the provider has reached its lifetime funding budget'
		);

		const within = quoteReq({
			maxAmountMsat: 5_000_000n,
			targetRemainingInboundSat: 5_000n
		});
		expect(h.manager.quote(CLIENT, within).accepted).to.equal(true);
		h.fundable.value = 19_999n;
		const short = h.manager.quote(CLIENT, within);
		expect(short.accepted).to.equal(false);
		expect(short.reason).to.equal(
			'the provider does not hold enough on-chain funds to front this receive right now'
		);
		h.fundable.value = 20_000n;
		expect(h.manager.quote(CLIENT, within).accepted).to.equal(true);
	});
});

describe('JIT interception', function () {
	it('holds an HTLC for a live intent and funds against the held total', async function () {
		const h = makeHarness({ fundingBufferSats: 10_000n });
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ targetRemainingInboundSat: 25_000n })
		);
		const scidHex = ack.interceptScid.toString('hex');
		const part = makePart(h, { amountMsat: 2_000_000n });

		expect(h.manager.tryInterceptUnknownScid(scidHex, part)).to.equal(true);
		await waitFor(h.manager, 'jit:forwarded');

		// 2000 sat received + 25000 target inbound + 10000 buffer.
		expect(h.opens).to.deep.equal([37_000n]);
		expect(h.forwarded).to.have.length(1);
		expect(h.failed).to.have.length(0);
		// The intent is consumed once its payment has been forwarded.
		expect(h.manager.listIntents()).to.have.length(0);
	});

	it('falls through for an unknown SCID and for a hash the intent did not bind', function () {
		const h = makeHarness();
		const bound = crypto.randomBytes(32);
		const ack = h.manager.registerIntent(CLIENT, auth({ paymentHash: bound }));
		const scidHex = ack.interceptScid.toString('hex');

		expect(
			h.manager.tryInterceptUnknownScid('ff'.repeat(8), makePart(h))
		).to.equal(false);
		expect(h.manager.tryInterceptUnknownScid(scidHex, makePart(h))).to.equal(
			false
		);
		expect(
			h.manager.tryInterceptUnknownScid(
				scidHex,
				makePart(h, { paymentHash: bound })
			)
		).to.equal(true);
	});

	it('refuses a part that leaves too little CLTV cushion, or is already at its deadline', function () {
		const h = makeHarness({ minCltvDeltaBlocks: 40 });
		const ack = h.manager.registerIntent(CLIENT, auth());
		const scidHex = ack.interceptScid.toString('hex');

		const thinCushion = makePart(h, {
			forwardCltv: 800_190,
			incomingCltvExpiry: 800_200
		});
		expect(h.manager.tryInterceptUnknownScid(scidHex, thinCushion)).to.equal(
			false
		);
		// Held right at the revocation margin, the next block would revoke it:
		// failing now tells the sender immediately instead.
		const atDeadline = makePart(h, {
			forwardCltv: 800_000,
			incomingCltvExpiry: h.height.value + 5
		});
		expect(h.manager.tryInterceptUnknownScid(scidHex, atDeadline)).to.equal(
			false
		);
	});

	it('refuses a part that would take the held total past the intent cap', function () {
		const h = makeHarness();
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ maxAmountMsat: 3_000_000n, expectedTotalMsat: 3_000_000n })
		);
		const scidHex = ack.interceptScid.toString('hex');
		expect(
			h.manager.tryInterceptUnknownScid(
				scidHex,
				makePart(h, { amountMsat: 2_000_000n })
			)
		).to.equal(true);
		expect(
			h.manager.tryInterceptUnknownScid(
				scidHex,
				makePart(h, { amountMsat: 2_000_000n })
			)
		).to.equal(false);
		expect(h.manager.heldTotalMsat(scidHex)).to.equal(2_000_000n);
	});
});

// ── MPP aggregation ────────────────────────────────────────────────

describe('JIT MPP aggregation', function () {
	it('waits for the declared total before funding, then forwards the whole set', async function () {
		const h = makeHarness();
		const hash = crypto.randomBytes(32);
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ paymentHash: hash, expectedTotalMsat: 3_000_000n })
		);
		const scidHex = ack.interceptScid.toString('hex');

		h.manager.tryInterceptUnknownScid(
			scidHex,
			makePart(h, { amountMsat: 1_000_000n, paymentHash: hash })
		);
		expect(h.opens).to.have.length(0);

		h.manager.tryInterceptUnknownScid(
			scidHex,
			makePart(h, { amountMsat: 2_000_000n, paymentHash: hash })
		);
		await waitFor(h.manager, 'jit:forwarded');
		expect(h.opens).to.have.length(1);
		expect(h.forwarded).to.have.length(2);
	});

	it('fails an incomplete set when the aggregation window closes', async function () {
		const h = makeHarness({ aggregationTimeoutMs: 20 });
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ expectedTotalMsat: 5_000_000n })
		);
		const scidHex = ack.interceptScid.toString('hex');
		h.manager.tryInterceptUnknownScid(
			scidHex,
			makePart(h, { amountMsat: 1_000_000n })
		);

		await new Promise((r) => setTimeout(r, 60));
		expect(h.opens).to.have.length(0);
		expect(h.forwarded).to.have.length(0);
		expect(h.failed).to.have.length(1);
		expect(h.failed[0].code).to.equal(TEMPORARY_CHANNEL_FAILURE);
	});
});

// ── Opening fee ────────────────────────────────────────────────────

describe('JIT opening fee', function () {
	it('refuses an intent from a client that will not accept the skim', function () {
		// The fee is deducted from a forward whose onion still names the full
		// amount, and BOLT 4 has the final hop fail anything short of it. A
		// client that has not agreed to that gets a refusal, not a channel it
		// would have paid for and a payment that then fails.
		const h = makeHarness({ flatFeeSat: 100n });
		const ack = h.manager.registerIntent(CLIENT, auth());
		expect(ack.accepted).to.equal(false);
		expect(ack.reason).to.match(/skimmed/);
		expect(h.manager.listIntents()).to.have.length(0);
		// Advertised all the same, so the client knows what to agree to.
		expect(ack.flatFeeSat).to.equal(0n);
		expect(
			h.manager.registerIntent(CLIENT, auth({ acceptsSkimmedFee: true }))
				.accepted
		).to.equal(true);
	});

	it('skims nothing from a client that never agreed to it', async function () {
		// A fee configured after the intent was registered (or restored from a
		// record that predates the flag) must still not shrink the forward.
		const h = makeHarness({ flatFeeSat: 100n });
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ acceptsSkimmedFee: true })
		);
		h.manager.listIntents()[0].acceptsSkimmedFee = false;
		h.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(h, { amountMsat: 1_000_000n })
		);
		await waitFor(h.manager, 'jit:forwarded');
		expect(h.forwarded[0].part.forwardAmountMsat).to.equal(1_000_000n);
	});

	it('deducts the fee once, from the largest part', async function () {
		const h = makeHarness({ flatFeeSat: 100n, feePpm: 1_000 });
		const hash = crypto.randomBytes(32);
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({
				paymentHash: hash,
				expectedTotalMsat: 3_000_000n,
				acceptsSkimmedFee: true
			})
		);
		const scidHex = ack.interceptScid.toString('hex');
		h.manager.tryInterceptUnknownScid(
			scidHex,
			makePart(h, { amountMsat: 1_000_000n, paymentHash: hash })
		);
		h.manager.tryInterceptUnknownScid(
			scidHex,
			makePart(h, { amountMsat: 2_000_000n, paymentHash: hash })
		);
		await waitFor(h.manager, 'jit:forwarded');

		// 100 sat flat + 1000ppm of 3_000_000 msat = 100_000 + 3_000 msat.
		const amounts = h.forwarded
			.map((f) => f.part.forwardAmountMsat)
			.sort((a, b) => Number(a - b));
		expect(amounts).to.deep.equal([1_000_000n, 2_000_000n - 103_000n]);
	});

	it('fails every part, and drops none, when the fee exceeds the largest part', async function () {
		// The fork threw AFTER emptying the held map, so the outer catch failed
		// an empty set and the parts were silently dropped: an HTLC left to
		// ride to its CLTV on somebody else's channel.
		const h = makeHarness({ flatFeeSat: 5_000n });
		const hash = crypto.randomBytes(32);
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({
				paymentHash: hash,
				expectedTotalMsat: 2_000_000n,
				acceptsSkimmedFee: true
			})
		);
		const scidHex = ack.interceptScid.toString('hex');
		h.manager.tryInterceptUnknownScid(
			scidHex,
			makePart(h, { amountMsat: 1_000_000n, paymentHash: hash })
		);
		const failure = waitFor<{ reason: string }>(h.manager, 'jit:failed');
		h.manager.tryInterceptUnknownScid(
			scidHex,
			makePart(h, { amountMsat: 1_000_000n, paymentHash: hash })
		);

		expect((await failure).reason).to.match(/exceeds the largest held part/);
		expect(h.failed).to.have.length(2);
		expect(h.forwarded).to.have.length(0);
		// Refused before anything was fronted.
		expect(h.opens).to.have.length(0);
	});
});

// ── Caps ───────────────────────────────────────────────────────────

describe('JIT funding caps', function () {
	it('clamps the zero-conf open to the per-client cap', async function () {
		const h = makeHarness({
			maxClientFundingSats: 30_000n,
			fundingBufferSats: 10_000n
		});
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ maxAmountMsat: 20_000_000n, targetRemainingInboundSat: 500_000n })
		);
		h.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(h, { amountMsat: 20_000_000n })
		);
		await waitFor(h.manager, 'jit:forwarded');
		expect(h.opens).to.deep.equal([30_000n]);
	});

	it('clamps the splice to the same per-client cap', async function () {
		// The fork clamped the open path only, so a splice could front any
		// amount the queue happened to add up to.
		const h = makeHarness({
			maxClientFundingSats: 25_000n,
			fundingBufferSats: 10_000n
		});
		h.manager.registerIntent(
			CLIENT,
			auth({ maxAmountMsat: 20_000_000n, targetRemainingInboundSat: 500_000n })
		);
		const channelId = crypto.randomBytes(32);
		expect(
			h.manager.tryHoldForSplice(
				channelId,
				makePart(h, { amountMsat: 20_000_000n })
			)
		).to.equal(true);
		await waitFor(h.manager, 'jit:forwarded');
		expect(h.splices).to.have.length(1);
		expect(h.splices[0].amountSats).to.equal(25_000n);
	});

	it('refuses to front past the cumulative cap', async function () {
		const h = makeHarness({
			maxTotalFundingSats: 40_000n,
			fundingBufferSats: 10_000n
		});
		const first = h.manager.registerIntent(
			CLIENT,
			auth({ targetRemainingInboundSat: 20_000n })
		);
		h.manager.tryInterceptUnknownScid(
			first.interceptScid.toString('hex'),
			makePart(h, { amountMsat: 1_000_000n })
		);
		await waitFor(h.manager, 'jit:forwarded');
		expect(h.manager.getFrontedTotalSats()).to.equal(31_000n);

		const second = h.manager.registerIntent(
			OTHER_CLIENT,
			auth({ targetRemainingInboundSat: 20_000n })
		);
		const failure = waitFor<{ reason: string }>(h.manager, 'jit:failed');
		h.manager.tryInterceptUnknownScid(
			second.interceptScid.toString('hex'),
			makePart(h, { amountMsat: 1_000_000n })
		);
		expect((await failure).reason).to.match(/cumulative JIT funding cap/);
		expect(h.opens).to.have.length(1);
		expect(h.failed).to.have.length(1);
	});

	it('refuses to hold once every funding slot is busy', async function () {
		const h = makeHarness({ maxConcurrentFundings: 1 });
		let releaseOpen = (): void => undefined;
		h.openResult.fn = (): Promise<Buffer> =>
			new Promise<Buffer>((resolve) => {
				releaseOpen = (): void => resolve(crypto.randomBytes(32));
			});
		const first = h.manager.registerIntent(CLIENT, auth());
		h.manager.tryInterceptUnknownScid(
			first.interceptScid.toString('hex'),
			makePart(h)
		);
		await new Promise((r) => setImmediate(r));

		const second = h.manager.registerIntent(OTHER_CLIENT, auth());
		expect(
			h.manager.tryInterceptUnknownScid(
				second.interceptScid.toString('hex'),
				makePart(h)
			)
		).to.equal(false);
		releaseOpen();
		await waitFor(h.manager, 'jit:forwarded');
	});
});

// ── Deadline backstop ──────────────────────────────────────────────

describe('JIT hold deadlines', function () {
	it('revokes a held part at its inbound CLTV margin and fails it upstream', function () {
		const h = makeHarness({ holdExpiryMarginBlocks: 18 });
		const ack = h.manager.registerIntent(CLIENT, auth());
		const scidHex = ack.interceptScid.toString('hex');
		const part = makePart(h, {
			amountMsat: 1_000_000n,
			forwardCltv: 800_000,
			incomingCltvExpiry: 800_100,
			paymentHash: crypto.randomBytes(32)
		});
		// Two parts so the intent waits for the set rather than funding.
		h.manager.registerIntent(CLIENT, auth());
		h.manager.tryInterceptUnknownScid(scidHex, part);

		h.height.value = 800_090;
		h.manager.scanExpiringHolds();

		expect(h.failed).to.have.length(1);
		expect(h.failed[0].code).to.equal(EXPIRY_TOO_SOON);
		expect(part.revoked).to.equal(true);
		expect(h.manager.heldTotalMsat(scidHex)).to.equal(0n);
	});

	it('revokes the whole MPP set when one part reaches its deadline', async function () {
		// The parts held for one intent are one payment: forwarding the
		// survivors could only park HTLCs on the client's fresh channel until
		// they time out, since the sender can never complete the set.
		const h = makeHarness({ holdExpiryMarginBlocks: 18 });
		const hash = crypto.randomBytes(32);
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ paymentHash: hash, expectedTotalMsat: 9_000_000n })
		);
		const scidHex = ack.interceptScid.toString('hex');
		const near = makePart(h, {
			paymentHash: hash,
			forwardCltv: 800_000,
			incomingCltvExpiry: 800_100
		});
		const far = makePart(h, {
			paymentHash: hash,
			forwardCltv: 800_000,
			incomingCltvExpiry: 900_000
		});
		expect(h.manager.tryInterceptUnknownScid(scidHex, near)).to.equal(true);
		expect(h.manager.tryInterceptUnknownScid(scidHex, far)).to.equal(true);

		h.height.value = 800_090;
		h.manager.scanExpiringHolds();

		expect(h.failed).to.have.length(2);
		expect(near.revoked).to.equal(true);
		expect(far.revoked).to.equal(true);
		expect(h.manager.heldTotalMsat(scidHex)).to.equal(0n);
		expect(h.opens).to.have.length(0);
	});

	it('never forwards a part the deadline already revoked', async function () {
		const h = makeHarness({ holdExpiryMarginBlocks: 18 });
		let releaseOpen = (): void => undefined;
		h.openResult.fn = (): Promise<Buffer> =>
			new Promise<Buffer>((resolve) => {
				releaseOpen = (): void => resolve(crypto.randomBytes(32));
			});
		const ack = h.manager.registerIntent(CLIENT, auth());
		const part = makePart(h, {
			forwardCltv: 800_000,
			incomingCltvExpiry: 800_100
		});
		h.manager.tryInterceptUnknownScid(ack.interceptScid.toString('hex'), part);
		await new Promise((r) => setImmediate(r));

		// The backstop fires while the funding is still running, then the
		// funding completes: the fork forwarded here, paying downstream for an
		// inbound leg it had already refunded.
		const reasons: string[] = [];
		h.manager.on('jit:failed', (d: { reason: string }) =>
			reasons.push(d.reason)
		);
		h.height.value = 800_090;
		h.manager.scanExpiringHolds();
		releaseOpen();
		await new Promise((r) => setTimeout(r, 50));

		expect(h.forwarded).to.have.length(0);
		expect(part.revoked).to.equal(true);
		// Exactly one upstream resolution: the deadline's, never a second.
		expect(h.failed.map((f) => f.code)).to.deep.equal([EXPIRY_TOO_SOON]);
		expect(reasons.join(' ')).to.match(/deadline|resolved before funding/);
	});
});

// ── Funding retry classification ───────────────────────────────────

describe('JIT funding retries', function () {
	it('retries a transient refusal within the budget', async function () {
		const h = makeHarness({ fundingAttempts: 3 });
		let calls = 0;
		h.openResult.fn = async (): Promise<Buffer> => {
			if (++calls < 3) {
				throw new ChannelFundingUnavailableError(
					ChannelFundingUnavailableCode.INSUFFICIENT_BALANCE,
					'coins pledged to another funding'
				);
			}
			return crypto.randomBytes(32);
		};
		const ack = h.manager.registerIntent(CLIENT, auth());
		h.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(h)
		);
		await waitFor(h.manager, 'jit:forwarded');
		expect(calls).to.equal(3);
		expect(h.forwarded).to.have.length(1);
	});

	it('does not retry a refusal the arguments themselves caused', async function () {
		const h = makeHarness({ fundingAttempts: 5 });
		let calls = 0;
		h.openResult.fn = async (): Promise<Buffer> => {
			calls++;
			throw new InvalidChannelOpenError('pushMsat exceeds fundingSatoshis');
		};
		const ack = h.manager.registerIntent(CLIENT, auth());
		const failure = waitFor(h.manager, 'jit:failed');
		h.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(h)
		);
		await failure;
		expect(calls).to.equal(1);
		expect(h.failed).to.have.length(1);
	});

	it('never starts a second funding beside one that only timed out', async function () {
		// The wait helper stops listening; it does not cancel the open. A retry
		// would run a duplicate open, of our coins, beside the live one.
		const h = makeHarness({ fundingAttempts: 5, fundingBufferSats: 10_000n });
		let calls = 0;
		h.openResult.fn = async (): Promise<Buffer> => {
			calls++;
			throw new FundingWaitTimeoutError('not ready within 1ms');
		};
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ targetRemainingInboundSat: 20_000n })
		);
		const failure = waitFor<{ reason: string }>(h.manager, 'jit:failed');
		h.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(h, { amountMsat: 1_000_000n })
		);
		expect((await failure).reason).to.match(/not ready within/);
		expect(calls).to.equal(1);
		expect(h.failed).to.have.length(1);
		// The open may still land, so the budget is charged rather than refunded.
		expect(h.manager.getFrontedTotalSats()).to.equal(31_000n);
	});

	it('gives up when the hold budget runs out', async function () {
		const h = makeHarness({
			fundingAttempts: 10,
			maxHoldMs: 30,
			fundingRetryDelayMs: 20
		});
		h.openResult.fn = async (): Promise<Buffer> => {
			throw new Error('peer went away');
		};
		const ack = h.manager.registerIntent(CLIENT, auth());
		const failure = waitFor<{ reason: string }>(h.manager, 'jit:failed');
		h.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(h)
		);
		expect((await failure).reason).to.match(/hold budget|peer went away/);
		expect(h.failed).to.have.length(1);
	});
});

// ── Splice path ────────────────────────────────────────────────────

describe('JIT on-the-fly splice', function () {
	it('declines a channel whose peer is not a JIT client', function () {
		const h = makeHarness();
		h.channelPeer.fn = (): string | null => null;
		expect(
			h.manager.tryHoldForSplice(crypto.randomBytes(32), makePart(h))
		).to.equal(false);
	});

	it('declines a peer with no live intent the part fits', function () {
		// Being a JIT client is derived from holding ANY live intent, so it
		// cannot be the authorization: a 1 msat intent would otherwise buy a
		// splice, of our coins, for every unrelated payment this peer receives.
		const h = makeHarness();
		const channelId = crypto.randomBytes(32);
		expect(h.manager.tryHoldForSplice(channelId, makePart(h))).to.equal(false);

		h.manager.registerIntent(CLIENT, auth({ maxAmountMsat: 1n }));
		expect(
			h.manager.tryHoldForSplice(
				channelId,
				makePart(h, { amountMsat: 1_000_000n })
			)
		).to.equal(false);
		expect(h.splices).to.have.length(0);

		// Another client's intent is not this peer's authorization either.
		h.manager.registerIntent(OTHER_CLIENT, auth());
		expect(
			h.manager.tryHoldForSplice(
				channelId,
				makePart(h, { amountMsat: 1_000_000n })
			)
		).to.equal(false);
	});

	it('declines a part the intent did not bind, and spends the intent once', async function () {
		const h = makeHarness();
		const bound = crypto.randomBytes(32);
		h.manager.registerIntent(CLIENT, auth({ paymentHash: bound }));
		const channelId = crypto.randomBytes(32);

		expect(h.manager.tryHoldForSplice(channelId, makePart(h))).to.equal(false);
		expect(
			h.manager.tryHoldForSplice(channelId, makePart(h, { paymentHash: bound }))
		).to.equal(true);
		await waitFor(h.manager, 'jit:forwarded');
		// Consumed by the payment it funded, exactly as the open path consumes
		// its own: a second payment needs a second intent.
		expect(h.manager.listIntents()).to.have.length(0);
		expect(
			h.manager.tryHoldForSplice(channelId, makePart(h, { paymentHash: bound }))
		).to.equal(false);
		expect(h.splices).to.have.length(1);
	});

	it('refuses to queue past what the intent registered for', function () {
		const h = makeHarness();
		h.manager.registerIntent(CLIENT, auth({ maxAmountMsat: 3_000_000n }));
		const channelId = crypto.randomBytes(32);
		// Stall the splice so the second part meets a queue, not a fresh intent.
		h.spliceResult.fn = (): Promise<void> => new Promise<void>(() => undefined);
		expect(
			h.manager.tryHoldForSplice(
				channelId,
				makePart(h, { amountMsat: 2_000_000n })
			)
		).to.equal(true);
		expect(
			h.manager.tryHoldForSplice(
				channelId,
				makePart(h, { amountMsat: 2_000_000n })
			)
		).to.equal(false);
	});

	it('retries the forward once, and never a second time', async function () {
		const h = makeHarness();
		h.manager.registerIntent(CLIENT, auth());
		const channelId = crypto.randomBytes(32);
		const part = makePart(h);
		expect(h.manager.tryHoldForSplice(channelId, part)).to.equal(true);
		await waitFor(h.manager, 'jit:forwarded');
		expect(h.forwarded).to.have.length(1);
		expect(part.spliceRetried).to.equal(true);
		// The re-entry a refused retry produces must stop here.
		expect(h.manager.tryHoldForSplice(channelId, part)).to.equal(false);
	});

	it('sizes the splice from the intent, fee included', async function () {
		const h = makeHarness({ flatFeeSat: 100n, fundingBufferSats: 10_000n });
		h.manager.registerIntent(
			CLIENT,
			auth({ targetRemainingInboundSat: 25_000n, acceptsSkimmedFee: true })
		);
		h.manager.tryHoldForSplice(
			crypto.randomBytes(32),
			makePart(h, { amountMsat: 2_000_000n })
		);
		await waitFor(h.manager, 'jit:forwarded');
		// 2000 sat received + 25000 target inbound + 10000 buffer, the same
		// arithmetic the open path does.
		expect(h.splices[0].amountSats).to.equal(37_000n);
		// The configured fee is charged on this path too; the fork's splice
		// forwarded the whole amount and earned nothing.
		expect(h.forwarded[0].part.forwardAmountMsat).to.equal(
			2_000_000n - 100_000n
		);
	});

	it('fails the queue upstream when the splice never locks', async function () {
		const h = makeHarness({ fundingAttempts: 1 });
		h.manager.registerIntent(CLIENT, auth());
		h.spliceResult.fn = async (): Promise<void> => {
			throw new Error('splice aborted by peer');
		};
		const failure = waitFor(h.manager, 'jit:failed');
		h.manager.tryHoldForSplice(crypto.randomBytes(32), makePart(h));
		await failure;
		expect(h.failed).to.have.length(1);
		expect(h.failed[0].code).to.equal(TEMPORARY_CHANNEL_FAILURE);
		expect(h.forwarded).to.have.length(0);
	});
});

// ── Persistence and restart ────────────────────────────────────────

describe('JIT persistence across a restart', function () {
	it('brings back live intents and fails every part that was held', function () {
		const first = makeHarness();
		// Two intents, and the intercepted one declares a larger total, so the
		// part is still held (not funded) when the process goes away.
		const ack = first.manager.registerIntent(
			CLIENT,
			auth({ expectedTotalMsat: 9_000_000n })
		);
		first.manager.registerIntent(CLIENT, auth());
		first.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(first, { amountMsat: 1_000_000n })
		);

		const second = makeHarness({}, { metadata: first.metadata });
		const failedRows: IPersistedHeldPart[] = [];
		second.restoredFail.fn = (part): boolean => {
			failedRows.push(part);
			return true;
		};
		second.manager.restore();

		// The invoices already out there stay payable.
		expect(
			second.manager.listIntents().map((i) => i.walletPubkeyHex)
		).to.deep.equal([CLIENT, CLIENT]);
		expect(second.jitClients).to.deep.equal([CLIENT]);
		// A half-done funding is never resumed; the held part is failed.
		expect(failedRows).to.have.length(1);
		expect(failedRows[0].disposition).to.equal('fail');
		expect(failedRows[0].amountMsat).to.equal('1000000');
		expect(failedRows[0].incomingCltvExpiry).to.equal(800_200);
		expect(second.metadata.get('jit:held')).to.equal('[]');
	});

	it('keeps retrying a part whose channel has not reestablished yet', function () {
		const first = makeHarness();
		const ack = first.manager.registerIntent(
			CLIENT,
			auth({ expectedTotalMsat: 9_000_000n })
		);
		first.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(first)
		);

		const second = makeHarness({}, { metadata: first.metadata });
		let ready = false;
		second.restoredFail.fn = (): boolean => ready;
		second.manager.restore();
		expect(JSON.parse(second.metadata.get('jit:held')!)).to.have.length(1);

		ready = true;
		second.manager.sweep();
		expect(JSON.parse(second.metadata.get('jit:held')!)).to.have.length(0);
	});

	it('drops expired intents and carries the fronted total forward', async function () {
		const first = makeHarness({ intentTtlMs: 5 });
		const ack = first.manager.registerIntent(CLIENT, auth());
		first.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(first)
		);
		await waitFor(first.manager, 'jit:forwarded');
		const fronted = first.manager.getFrontedTotalSats();
		expect(Number(fronted)).to.be.greaterThan(0);

		first.manager.registerIntent(OTHER_CLIENT, auth({ expirySeconds: 1 }));
		await new Promise((r) => setTimeout(r, 20));

		const second = makeHarness({}, { metadata: first.metadata });
		second.manager.restore();
		expect(second.manager.listIntents()).to.have.length(0);
		expect(second.manager.getFrontedTotalSats()).to.equal(fronted);
	});

	it('never forwards while the durable hold record still says fail', async function () {
		// The row is an instruction to refund after a restart. Forwarding with
		// it still on disk pays downstream for a leg the next boot refunds.
		const h = makeHarness();
		let releaseOpen = (): void => undefined;
		h.openResult.fn = (): Promise<Buffer> =>
			new Promise<Buffer>((resolve) => {
				releaseOpen = (): void => resolve(crypto.randomBytes(32));
			});
		const ack = h.manager.registerIntent(CLIENT, auth());
		h.manager.tryInterceptUnknownScid(
			ack.interceptScid.toString('hex'),
			makePart(h)
		);
		await new Promise((r) => setImmediate(r));

		h.storageWrites.failKeys.add('jit:held');
		const failure = waitFor<{ reason: string }>(h.manager, 'jit:failed');
		releaseOpen();
		expect((await failure).reason).to.match(/durable hold record/);
		expect(h.forwarded).to.have.length(0);
		expect(h.failed).to.have.length(1);
	});

	it('keeps owing a failure the inbound channel could not carry', function () {
		// A held part is failed long after it arrived, so its channel may be
		// reestablishing by then. The refund cannot simply evaporate: the part
		// joins the durable queue and the sweep retries it.
		const h = makeHarness({ aggregationTimeoutMs: 20 });
		h.failsDeliver.value = false;
		const ack = h.manager.registerIntent(
			CLIENT,
			auth({ expectedTotalMsat: 5_000_000n })
		);
		const part = makePart(h, { amountMsat: 1_000_000n });
		h.manager.tryInterceptUnknownScid(ack.interceptScid.toString('hex'), part);

		return new Promise<void>((resolve) => setTimeout(resolve, 60)).then(() => {
			expect(h.failed).to.have.length(1);
			expect(JSON.parse(h.metadata.get('jit:held')!)).to.have.length(1);
			expect(
				h.manager.hasRestoredHold(
					part.inChannelId.toString('hex'),
					part.inHtlcId
				)
			).to.equal(true);

			const swept: IPersistedHeldPart[] = [];
			h.restoredFail.fn = (row): boolean => {
				swept.push(row);
				return true;
			};
			h.manager.sweep();
			expect(swept).to.have.length(1);
			expect(swept[0].inHtlcId).to.equal(part.inHtlcId.toString());
			expect(JSON.parse(h.metadata.get('jit:held')!)).to.have.length(0);
		});
	});

	it('survives corrupt persisted state rather than taking the node down', function () {
		const metadata = new Map<string, string>([
			['jit:intents', '{not json'],
			['jit:held', 'also not json']
		]);
		const h = makeHarness({}, { metadata });
		expect(() => h.manager.restore()).to.not.throw();
		expect(h.manager.listIntents()).to.have.length(0);
	});
});
