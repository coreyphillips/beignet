/**
 * Fakes for the reverse swap engine tests (issue #737): a scripted chain
 * source, a hold-invoice model and a funding wallet, each recording what
 * the engine asked of it so a test can assert ordering (persist before act)
 * and counts (a transaction built once, a hold cancelled once).
 */

import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { encode as encodeInvoice } from '../../../src/lightning/invoice/encode';
import { Network } from '../../../src/lightning/invoice/types';
import { computeScriptHash } from '../../../src/lightning/chain/chain-watcher';
import { MemoryLedgerStore } from '../../../src/lightning/storage/durable-ledger';
import { decode as decodeInvoice } from '../../../src/lightning/invoice/decode';
import {
	IHeldInvoicePart,
	IHeldInvoiceSnapshot,
	IOutgoingPaymentResolution,
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../../src/lightning/node/types';
import {
	IReverseSwapProviderConfig,
	IReverseSwapProviderDeps,
	ISubmarineSwapProviderConfig,
	ISubmarineSwapProviderDeps,
	ISwapChainSource,
	ISwapRecord,
	ReverseSwapProvider,
	SUBMARINE_SWAP_EVENTS,
	SubmarineSwapProvider,
	SwapChainResolver,
	SwapLedger,
	buildSwapClaimTx,
	buildSwapRefundTx,
	deriveSwapKey
} from '../../../src/lightning/swaps';
import { FakeDfNetwork, FakeDfPeer } from './df-transport';

export const HOLD_CANCEL_MARGIN = 18;

/** A chain the test scripts: history by script hash, raw bytes by txid. */
export class FakeSwapChain implements ISwapChainSource {
	height = 1000;
	private readonly history = new Map<
		string,
		Array<{ txid: string; height: number }>
	>();
	private readonly txs = new Map<string, Buffer>();
	readonly broadcasts: string[] = [];
	failBroadcasts = 0;
	/** Broadcasts that relay the bytes and then throw (a dropped connection). */
	relayThenFail = 0;

	currentHeight(): number {
		return this.height;
	}
	async getTransaction(txid: string): Promise<Buffer> {
		const raw = this.txs.get(txid);
		if (!raw) throw new Error(`unknown tx ${txid}`);
		return raw;
	}
	async getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>> {
		return [...(this.history.get(scriptHash) ?? [])];
	}
	async broadcastTransaction(rawTxHex: string): Promise<string> {
		if (this.failBroadcasts > 0) {
			this.failBroadcasts--;
			throw new Error('broadcast refused');
		}
		if (this.relayThenFail > 0) {
			this.relayThenFail--;
			this.place(bitcoin.Transaction.fromHex(rawTxHex), 0);
			throw new Error('connection dropped after relay');
		}
		this.broadcasts.push(rawTxHex);
		const tx = bitcoin.Transaction.fromHex(rawTxHex);
		// A broadcast lands in the mempool of every script it touches.
		this.place(tx, 0);
		return tx.getId();
	}

	/** Record a transaction at a height under every output script it pays and every output it spends. */
	place(tx: bitcoin.Transaction, height: number): void {
		this.txs.set(tx.getId(), tx.toBuffer());
		const scripts = new Set<string>();
		for (const out of tx.outs) scripts.add(computeScriptHash(out.script));
		for (const input of tx.ins) {
			const parentId = Buffer.from(input.hash).reverse().toString('hex');
			const parent = this.txs.get(parentId);
			if (!parent) continue;
			const parentTx = bitcoin.Transaction.fromBuffer(parent);
			const spent = parentTx.outs[input.index];
			if (spent) scripts.add(computeScriptHash(spent.script));
		}
		for (const scriptHash of scripts) {
			const list = this.history.get(scriptHash) ?? [];
			const existing = list.find((h) => h.txid === tx.getId());
			if (existing) existing.height = height;
			else list.push({ txid: tx.getId(), height });
			this.history.set(scriptHash, list);
		}
	}

	confirm(txid: string, height: number): void {
		for (const list of this.history.values()) {
			const entry = list.find((h) => h.txid === txid);
			if (entry) entry.height = height;
		}
	}

	evict(txid: string): void {
		for (const [key, list] of this.history) {
			this.history.set(
				key,
				list.filter((h) => h.txid !== txid)
			);
		}
	}

	mempoolHas(txid: string): boolean {
		for (const list of this.history.values()) {
			if (list.some((h) => h.txid === txid)) return true;
		}
		return false;
	}
}

/** The node's hold-invoice surface, as the engine sees it. */
export class FakeHolds {
	readonly invoices = new Map<
		string,
		{ amountMsat: bigint; bolt11: string; minFinalCltvExpiry: number }
	>();
	readonly parts = new Map<string, IHeldInvoicePart[]>();
	readonly settled: Array<{ hash: string; preimage: string }> = [];
	readonly cancelled: string[] = [];
	readonly heldListeners = new Set<(e: { paymentHash: Buffer }) => void>();
	readonly cancelListeners = new Set<
		(e: { paymentHash: Buffer; reason: string }) => void
	>();
	settledHashes = new Set<string>();
	cancelledHashes = new Set<string>();
	failCreate = false;
	settleReturns: boolean | undefined;
	settleThrows = false;
	/** Hashes the node already holds a record for (invoice, payment, hold). */
	readonly inUse = new Set<string>();

	constructor(
		private readonly privkey: Buffer,
		private readonly height: () => number
	) {}

	createHoldInvoice(options: {
		paymentHash: Buffer;
		amountMsat: bigint;
		expirySeconds: number;
		minFinalCltvExpiry: number;
		description: string;
	}): { bolt11: string } {
		if (this.failCreate) throw new Error('invoice refused');
		const bolt11 = encodeInvoice({
			network: Network.REGTEST,
			amountMsat: options.amountMsat,
			paymentHash: options.paymentHash,
			paymentSecret: crypto.randomBytes(32),
			description: options.description,
			expiry: options.expirySeconds,
			minFinalCltvExpiry: options.minFinalCltvExpiry,
			privateKey: this.privkey
		});
		this.invoices.set(options.paymentHash.toString('hex'), {
			amountMsat: options.amountMsat,
			bolt11,
			minFinalCltvExpiry: options.minFinalCltvExpiry
		});
		return { bolt11 };
	}

	snapshot(paymentHash: Buffer): IHeldInvoiceSnapshot | null {
		const hashHex = paymentHash.toString('hex');
		const invoice = this.invoices.get(hashHex);
		if (!invoice) return null;
		const parts = this.parts.get(hashHex) ?? [];
		let committedMsat = 0n;
		let earliestExpiry: number | null = null;
		for (const p of parts) {
			if (!p.committed) continue;
			committedMsat += p.amountMsat;
			earliestExpiry =
				earliestExpiry === null
					? p.cltvExpiry
					: Math.min(earliestExpiry, p.cltvExpiry);
		}
		const state = this.settledHashes.has(hashHex)
			? 'SETTLED'
			: this.cancelledHashes.has(hashHex)
			? 'CANCELLED'
			: parts.length > 0
			? 'ACCEPTED'
			: 'OPEN';
		return {
			paymentHash,
			state,
			currentHeight: this.height(),
			parts,
			committedMsat,
			expectedAmountMsat: invoice.amountMsat,
			complete:
				parts.length > 0 &&
				parts.every((p) => p.committed) &&
				committedMsat === invoice.amountMsat,
			earliestExpiry,
			cancelMarginBlocks: HOLD_CANCEL_MARGIN,
			cancelHeight:
				earliestExpiry === null ? null : earliestExpiry - HOLD_CANCEL_MARGIN
		};
	}

	/** A payer's part arrives, committed; fires 'htlc:held'. */
	hold(
		paymentHash: Buffer,
		amountMsat: bigint,
		cltvExpiry: number,
		committed = true
	): void {
		const hashHex = paymentHash.toString('hex');
		const parts = this.parts.get(hashHex) ?? [];
		parts.push({
			id: `${'aa'.repeat(32)}:${parts.length}`,
			channelId: Buffer.alloc(32, 0xaa),
			htlcId: BigInt(parts.length),
			paymentHash,
			amountMsat,
			cltvExpiry,
			committed
		});
		this.parts.set(hashHex, parts);
		for (const cb of this.heldListeners) cb({ paymentHash });
	}

	settleHeld(paymentHash: Buffer, preimage: Buffer): boolean {
		const hashHex = paymentHash.toString('hex');
		if (this.settleThrows) throw new Error('settle refused');
		if (this.settleReturns !== undefined) return this.settleReturns;
		if (!this.parts.get(hashHex)?.length) return false;
		this.settled.push({ hash: hashHex, preimage: preimage.toString('hex') });
		this.parts.delete(hashHex);
		this.settledHashes.add(hashHex);
		return true;
	}

	cancelHold(paymentHash: Buffer): void {
		const hashHex = paymentHash.toString('hex');
		if (
			!this.invoices.has(hashHex) ||
			this.cancelledHashes.has(hashHex) ||
			this.settledHashes.has(hashHex)
		)
			return;
		this.cancelled.push(hashHex);
		this.parts.delete(hashHex);
		this.cancelledHashes.add(hashHex);
	}

	/** The node's own sweeper (or an operator) cancels: fires 'hold:cancelled'. */
	sweep(paymentHash: Buffer, reason = 'expiry-scan'): void {
		this.cancelHold(paymentHash);
		for (const cb of this.cancelListeners) cb({ paymentHash, reason });
	}
}

/** A wallet that builds a real 1-in-1-out transaction to the address. */
export class FakeWallet {
	readonly builds: string[] = [];
	readonly pledged: string[] = [];
	readonly released: string[] = [];
	failBuilds = 0;
	/** Build a wrong output on purpose. */
	shortBy = 0n;
	/** Awaited inside fundOutput: a wallet that signs slowly (tests). */
	gate: (() => Promise<void>) | null = null;
	/** Awaited inside pledge: a wallet whose selection lock is busy (tests). */
	pledgeGate: (() => Promise<void>) | null = null;

	async fundOutput(
		address: string,
		amountSat: bigint,
		_feeRate: number
	): Promise<{ txHex: string; txid: Buffer; vout: number }> {
		if (this.failBuilds > 0) {
			this.failBuilds--;
			throw new Error('wallet busy');
		}
		if (this.gate) await this.gate();
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(crypto.randomBytes(32), 0, 0xfffffffd);
		tx.addOutput(
			bitcoin.address.toOutputScript(address, bitcoin.networks.regtest),
			Number(amountSat - this.shortBy)
		);
		tx.addOutput(
			bitcoin.payments.p2wpkh({ pubkey: getPublicKey(crypto.randomBytes(32)) })
				.output!,
			5_000
		);
		const txHex = tx.toHex();
		this.builds.push(txHex);
		return { txHex, txid: Buffer.from(tx.getId(), 'hex'), vout: 0 };
	}
}

export interface ISwapHarness {
	net: FakeDfNetwork;
	provider: FakeDfPeer;
	client: FakeDfPeer;
	chain: FakeSwapChain;
	holds: FakeHolds;
	wallet: FakeWallet;
	ledger: SwapLedger;
	store: MemoryLedgerStore<ISwapRecord>;
	engine: ReverseSwapProvider;
	nodeKey: Buffer;
	events: Array<{ name: string; data: Record<string, unknown> }>;
	logs: Array<{ action: string; data: Record<string, unknown> }>;
	feeRate: number | null;
	destination: Buffer;
	/** Build the engine again over the same store, as after a restart. */
	restart(overrides?: { start?: boolean }): Promise<ISwapHarness>;
}

export async function harness(
	options: {
		config?: Partial<IReverseSwapProviderConfig>;
		store?: MemoryLedgerStore<ISwapRecord>;
		chain?: FakeSwapChain;
		holds?: FakeHolds;
		wallet?: FakeWallet;
		net?: FakeDfNetwork;
		nodeKey?: Buffer;
		feeRate?: number | null;
		start?: boolean;
		/** The refund destination the engine is handed (default a P2WPKH). */
		destination?: Buffer;
	} = {}
): Promise<ISwapHarness> {
	const net = options.net ?? new FakeDfNetwork();
	const provider = net.peers.get('provider-peer') ?? net.add('provider');
	const client = net.add(`client-${crypto.randomBytes(4).toString('hex')}`);
	net.connect(provider, client);
	const chain = options.chain ?? new FakeSwapChain();
	const nodeKey =
		options.nodeKey ??
		crypto.createHash('sha256').update('swap-provider-node').digest();
	const holds = options.holds ?? new FakeHolds(nodeKey, () => chain.height);
	const wallet = options.wallet ?? new FakeWallet();
	const store = options.store ?? new MemoryLedgerStore<ISwapRecord>();
	const ledger = new SwapLedger(store);
	ledger.rehydrate();
	const config: Partial<IReverseSwapProviderConfig> & {
		holdCancelSafetyBlocks: number;
	} = {
		refundDeltaBlocks: 60,
		minRefundDeltaBlocks: 30,
		maxRefundDeltaBlocks: 120,
		fundingSafetyBlocks: 6,
		resolutionSafetyBlocks: 6,
		fundingConfirmations: 1,
		resolutionConfirmations: 2,
		refundBumpIntervalBlocks: 2,
		maxFundingAttempts: 2,
		flatFeeSat: 100n,
		feePpm: 1_000,
		...options.config,
		holdCancelSafetyBlocks: HOLD_CANCEL_MARGIN
	};
	const events: ISwapHarness['events'] = [];
	const logs: ISwapHarness['logs'] = [];
	const state = {
		feeRate: options.feeRate === undefined ? 2 : options.feeRate
	};
	const destination =
		options.destination ??
		bitcoin.payments.p2wpkh({ pubkey: getPublicKey(nodeKey) }).output!;
	const deps: IReverseSwapProviderDeps = {
		peers: provider,
		ledger,
		resolver: new SwapChainResolver(
			chain,
			{
				fundingConfirmations: config.fundingConfirmations!,
				resolutionConfirmations: config.resolutionConfirmations!
			},
			bitcoin.networks.regtest
		),
		createHoldInvoice: (o) => holds.createHoldInvoice(o),
		heldSnapshot: (hash) => holds.snapshot(hash),
		hashInUse: (hash) => holds.inUse.has(hash.toString('hex')),
		settleHeld: (hash, preimage) => holds.settleHeld(hash, preimage),
		cancelHold: (hash) => holds.cancelHold(hash),
		onHeld: (cb) => {
			holds.heldListeners.add(cb);
			return () => holds.heldListeners.delete(cb);
		},
		onHoldCancelled: (cb) => {
			holds.cancelListeners.add(cb);
			return () => holds.cancelListeners.delete(cb);
		},
		fundOutput: (address, amount, rate) =>
			wallet.fundOutput(address, amount, rate),
		broadcast: (txHex) => chain.broadcastTransaction(txHex),
		pledge: async (txHex) => {
			if (wallet.pledgeGate) await wallet.pledgeGate();
			wallet.pledged.push(txHex);
		},
		releasePledges: (txHex) => {
			wallet.released.push(txHex);
		},
		estimateFee: async () => state.feeRate,
		currentHeight: () => chain.height,
		deriveRefundKey: (swapId) => deriveSwapKey(nodeKey, swapId, 'refund'),
		refundDestinationScript: () => destination,
		network: bitcoin.networks.regtest,
		networkName: 'regtest',
		log: (action, data) => logs.push({ action, data })
	};
	const engine = new ReverseSwapProvider(deps, config);
	for (const evt of [
		'swap:created',
		'swap:held',
		'swap:funding',
		'swap:funded',
		'swap:claimed',
		'swap:settled',
		'swap:refund-broadcast',
		'swap:refunded',
		'swap:hold-cancelled',
		'swap:exposed',
		'swap:failed'
	]) {
		engine.on(evt, (data) => events.push({ name: evt, data }));
	}
	if (options.start !== false) await engine.start();
	const h: ISwapHarness = {
		net,
		provider,
		client,
		chain,
		holds,
		wallet,
		ledger,
		store,
		engine,
		nodeKey,
		events,
		logs,
		get feeRate() {
			return state.feeRate;
		},
		set feeRate(v: number | null) {
			state.feeRate = v;
		},
		destination,
		restart: async (overrides = {}) => {
			engine.stop();
			return harness({
				...options,
				...overrides,
				store,
				chain,
				holds,
				wallet,
				net,
				nodeKey,
				feeRate: state.feeRate
			});
		}
	};
	return h;
}

/** Let the engine's serialized queue drain. */
export async function settle(): Promise<void> {
	for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r));
}

export interface IClientSwap {
	preimage: Buffer;
	paymentHash: Buffer;
	claimKey: Buffer;
	claimPubkey: Buffer;
}

export function clientSwap(): IClientSwap {
	const preimage = crypto.randomBytes(32);
	const claimKey = crypto.randomBytes(32);
	return {
		preimage,
		paymentHash: crypto.createHash('sha256').update(preimage).digest(),
		claimKey,
		claimPubkey: getPublicKey(claimKey)
	};
}

/** The client's claim of a funded swap, to a fresh P2WPKH. */
export function claimTxFor(
	record: ISwapRecord,
	swap: IClientSwap,
	feeSatoshis = 500n
): bitcoin.Transaction {
	return buildSwapClaimTx({
		htlc: {
			paymentHash: swap.paymentHash,
			claimPublicKey: swap.claimPubkey,
			refundPublicKey: Buffer.from(record.refundPubkeyHex, 'hex'),
			refundHeight: record.refundHeight
		},
		fundingTransaction: bitcoin.Transaction.fromHex(record.fundingTxHex!),
		outputIndex: record.fundingVout!,
		destinationScript: bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(crypto.randomBytes(32))
		}).output!,
		feeSatoshis,
		privateKey: swap.claimKey,
		preimage: swap.preimage
	});
}

// ─────────────── Submarine direction (issue #743) ───────────────

/**
 * The node's outgoing payment surface as the submarine engine sees it: a
 * scripted `payInvoice` (what the call does), the honest HTLC view the
 * engine reads afterwards, and the payment events. Records the ledger state
 * at the moment of each call so a test can prove persist-before-pay.
 */
export class FakeOutgoing {
	readonly calls: Array<{
		bolt11: string;
		paymentHashHex: string;
		maxCltvExpiryHeight: number;
		maxFeeMsat: bigint;
		ledgerStateAtCall: string | undefined;
	}> = [];
	readonly listeners = new Set<(paymentHash: Buffer) => void>();
	private readonly views = new Map<string, IOutgoingPaymentResolution>();
	/**
	 * What the next payInvoice does:
	 *  - 'pending': one HTLC offered, record PENDING (the ordinary case)
	 *  - 'complete': the loopback case, fulfilled synchronously
	 *  - 'throw-no-record': throws before any record (NO_ROUTE, CLTV_EXCEEDS_MAX)
	 *  - 'throw-with-htlc': throws after one HTLC left (a later MPP part refused)
	 *  - 'failed-live-htlc': record FAILED, one HTLC still offered
	 *  - 'failed': record FAILED, no HTLC
	 */
	script:
		| 'pending'
		| 'complete'
		| 'throw-no-record'
		| 'throw-with-htlc'
		| 'failed-live-htlc'
		| 'failed' = 'pending';
	/** The preimage a 'complete' script reveals; set per hash by the test. */
	readonly preimages = new Map<string, Buffer>();

	constructor(
		private readonly ledgerStateOf: (
			paymentHashHex: string
		) => string | undefined
	) {}

	private view(
		hashHex: string,
		patch: Partial<IOutgoingPaymentResolution>
	): void {
		const base: IOutgoingPaymentResolution = this.views.get(hashHex) ?? {
			paymentHash: Buffer.from(hashHex, 'hex'),
			status: null,
			htlcs: [],
			resolved: true,
			latestOutstandingExpiry: null
		};
		this.views.set(hashHex, { ...base, ...patch });
	}

	private htlc(
		state: 'offered' | 'fulfilled' | 'failed',
		cltvExpiry: number
	): IOutgoingPaymentResolution['htlcs'][number] {
		return {
			channelId: Buffer.alloc(32, 1),
			htlcId: 0n,
			amountMsat: 1_000n,
			cltvExpiry,
			state,
			terminal: state !== 'offered'
		};
	}

	payInvoice(
		bolt11: string,
		options: { maxCltvExpiryHeight: number; maxFeeMsat: bigint }
	): IPaymentInfo {
		const invoice = decodeInvoice(bolt11);
		const hashHex = invoice.paymentHash.toString('hex');
		this.calls.push({
			bolt11,
			paymentHashHex: hashHex,
			maxCltvExpiryHeight: options.maxCltvExpiryHeight,
			maxFeeMsat: options.maxFeeMsat,
			ledgerStateAtCall: this.ledgerStateOf(hashHex)
		});
		const expiry = options.maxCltvExpiryHeight - 10;
		const info = (status: PaymentStatus): IPaymentInfo => ({
			paymentHash: invoice.paymentHash,
			amountMsat: invoice.amountMsat ?? 0n,
			status,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now()
		});
		switch (this.script) {
			case 'throw-no-record':
				throw new Error('NO_ROUTE: no route found');
			case 'throw-with-htlc':
				this.view(hashHex, {
					status: PaymentStatus.PENDING,
					htlcs: [this.htlc('offered', expiry)],
					resolved: false,
					latestOutstandingExpiry: expiry
				});
				throw new Error('a later part was refused');
			case 'complete': {
				const preimage = this.preimages.get(hashHex);
				if (!preimage) throw new Error('test: no preimage for complete');
				this.view(hashHex, {
					status: PaymentStatus.COMPLETED,
					htlcs: [this.htlc('fulfilled', expiry)],
					resolved: true,
					latestOutstandingExpiry: null,
					preimage
				});
				return { ...info(PaymentStatus.COMPLETED), preimage };
			}
			case 'failed-live-htlc':
				this.view(hashHex, {
					status: PaymentStatus.FAILED,
					htlcs: [this.htlc('offered', expiry)],
					resolved: false,
					latestOutstandingExpiry: expiry
				});
				return info(PaymentStatus.FAILED);
			case 'failed':
				this.view(hashHex, {
					status: PaymentStatus.FAILED,
					htlcs: [],
					resolved: true,
					latestOutstandingExpiry: null
				});
				return info(PaymentStatus.FAILED);
			default:
				this.view(hashHex, {
					status: PaymentStatus.PENDING,
					htlcs: [this.htlc('offered', expiry)],
					resolved: false,
					latestOutstandingExpiry: expiry
				});
				return info(PaymentStatus.PENDING);
		}
	}

	outgoingHtlcs(paymentHash: Buffer): IOutgoingPaymentResolution {
		const hashHex = paymentHash.toString('hex');
		return (
			this.views.get(hashHex) ?? {
				paymentHash,
				status: null,
				htlcs: [],
				resolved: true,
				latestOutstandingExpiry: null
			}
		);
	}

	/** The peer fulfilled: every HTLC terminal, preimage known. */
	fulfil(paymentHash: Buffer, preimage: Buffer, notify = true): void {
		const hashHex = paymentHash.toString('hex');
		const current = this.outgoingHtlcs(paymentHash);
		this.view(hashHex, {
			status: PaymentStatus.COMPLETED,
			htlcs: current.htlcs.map((h) => ({
				...h,
				state: 'fulfilled',
				terminal: true
			})),
			resolved: true,
			latestOutstandingExpiry: null,
			preimage
		});
		if (notify) this.notify(paymentHash);
	}

	/** A preimage learned on chain, whatever the record says (a late success). */
	preimageOnChain(paymentHash: Buffer, preimage: Buffer): void {
		const hashHex = paymentHash.toString('hex');
		const current = this.outgoingHtlcs(paymentHash);
		this.view(hashHex, {
			status: PaymentStatus.COMPLETED,
			htlcs: current.htlcs.map((h) => ({
				...h,
				state: 'onchain-resolved',
				terminal: true
			})),
			resolved: true,
			latestOutstandingExpiry: null,
			preimage
		});
		this.notify(paymentHash);
	}

	/** Every HTLC failed back; the record is FAILED. */
	fail(paymentHash: Buffer, notify = true): void {
		const hashHex = paymentHash.toString('hex');
		const current = this.outgoingHtlcs(paymentHash);
		this.view(hashHex, {
			status: PaymentStatus.FAILED,
			htlcs: current.htlcs.map((h) => ({
				...h,
				state: 'failed',
				terminal: true
			})),
			resolved: true,
			latestOutstandingExpiry: null
		});
		if (notify) this.notify(paymentHash);
	}

	/** The record was failed by a wall clock while the HTLC is still out. */
	failRecordOnly(paymentHash: Buffer): void {
		const hashHex = paymentHash.toString('hex');
		this.view(hashHex, { status: PaymentStatus.FAILED, resolved: false });
		this.notify(paymentHash);
	}

	notify(paymentHash: Buffer): void {
		for (const cb of this.listeners) cb(paymentHash);
	}
}

export interface ISubmarineClient {
	preimage: Buffer;
	paymentHash: Buffer;
	refundKey: Buffer;
	refundPubkey: Buffer;
	/** The client's node key, which signs its invoice. */
	nodeKey: Buffer;
}

export function submarineClient(): ISubmarineClient {
	const preimage = crypto.randomBytes(32);
	const refundKey = crypto.randomBytes(32);
	return {
		preimage,
		paymentHash: crypto.createHash('sha256').update(preimage).digest(),
		refundKey,
		refundPubkey: getPublicKey(refundKey),
		nodeKey: crypto.randomBytes(32)
	};
}

/** The client's own invoice for a submarine swap. */
export function submarineInvoice(
	client: ISubmarineClient,
	amountMsat: bigint,
	options: {
		minFinalCltvExpiry?: number;
		expiry?: number;
		timestamp?: number;
		network?: Network;
		routingHints?: Array<{ pubkey: Buffer }>;
		privateKey?: Buffer;
		paymentSecret?: Buffer | null;
	} = {}
): string {
	return encodeInvoice({
		network: options.network ?? Network.REGTEST,
		amountMsat,
		timestamp: options.timestamp ?? Math.floor(Date.now() / 1000),
		paymentHash: client.paymentHash,
		...(options.paymentSecret === null
			? {}
			: { paymentSecret: options.paymentSecret ?? crypto.randomBytes(32) }),
		description: 'submarine swap',
		expiry: options.expiry ?? 7200,
		minFinalCltvExpiry: options.minFinalCltvExpiry ?? 40,
		privateKey: options.privateKey ?? client.nodeKey,
		...(options.routingHints
			? {
					routingHints: [
						options.routingHints.map((hop) => ({
							pubkey: hop.pubkey,
							shortChannelId: Buffer.alloc(8, 1),
							feeBaseMsat: 1000,
							feeProportionalMillionths: 1,
							cltvExpiryDelta: 80
						}))
					]
			  }
			: {})
	});
}

/** A transaction paying `valueSat` to the contract, placed on the fake chain. */
export function fundContract(
	chain: FakeSwapChain,
	outputScript: Buffer,
	valueSat: bigint,
	height: number
): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0, 0xfffffffd);
	tx.addOutput(outputScript, Number(valueSat));
	// A change output so the funding is never confused with a 1-in-1-out spend.
	tx.addOutput(
		bitcoin.payments.p2wpkh({ pubkey: getPublicKey(crypto.randomBytes(32)) })
			.output!,
		5_000
	);
	chain.place(tx, height);
	return tx;
}

/** The client's refund of its funding after the refund height. */
export function refundTxFor(
	record: ISwapRecord,
	client: ISubmarineClient,
	fundingTx: bitcoin.Transaction,
	feeSatoshis = 500n
): bitcoin.Transaction {
	return buildSwapRefundTx({
		htlc: {
			paymentHash: client.paymentHash,
			claimPublicKey: Buffer.from(record.claimPubkeyHex, 'hex'),
			refundPublicKey: client.refundPubkey,
			refundHeight: record.refundHeight
		},
		fundingTransaction: fundingTx,
		outputIndex: record.fundingVout!,
		destinationScript: bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(crypto.randomBytes(32))
		}).output!,
		feeSatoshis,
		privateKey: client.refundKey
	});
}

export interface ISubmarineHarness {
	net: FakeDfNetwork;
	provider: FakeDfPeer;
	client: FakeDfPeer;
	chain: FakeSwapChain;
	outgoing: FakeOutgoing;
	ledger: SwapLedger;
	store: MemoryLedgerStore<ISwapRecord>;
	engine: SubmarineSwapProvider;
	nodeKey: Buffer;
	ownNodeId: Buffer;
	events: Array<{ name: string; data: Record<string, unknown> }>;
	logs: Array<{ action: string; data: Record<string, unknown> }>;
	feeRate: number | null;
	spendableMsat: bigint;
	/** Hashes the node already holds a record for. */
	inUse: Set<string>;
	/** Node ids this provider has a usable channel with (hex). */
	channelPeers: Set<string>;
	destination: Buffer;
	/** The engine's wall clock, ms; settable to expire invoices. */
	clock: number | undefined;
	restart(overrides?: {
		start?: boolean;
		outgoing?: FakeOutgoing;
	}): Promise<ISubmarineHarness>;
}

export async function submarineHarness(
	options: {
		config?: Partial<ISubmarineSwapProviderConfig>;
		store?: MemoryLedgerStore<ISwapRecord>;
		chain?: FakeSwapChain;
		outgoing?: FakeOutgoing;
		net?: FakeDfNetwork;
		nodeKey?: Buffer;
		feeRate?: number | null;
		spendableMsat?: bigint;
		inUse?: Set<string>;
		start?: boolean;
		destination?: Buffer;
		clock?: number;
		/** Share the provider peer with another engine (the reverse harness). */
		provider?: FakeDfPeer;
		/** Share the ledger instance too, as the node does. */
		ledger?: SwapLedger;
		/** Node ids this provider has a usable channel with (hex). */
		channelPeers?: Set<string>;
	} = {}
): Promise<ISubmarineHarness> {
	const net = options.net ?? new FakeDfNetwork();
	const provider = options.provider ?? net.add('provider');
	const client = net.add(`client-${crypto.randomBytes(4).toString('hex')}`);
	net.connect(provider, client);
	const chain = options.chain ?? new FakeSwapChain();
	const nodeKey =
		options.nodeKey ??
		crypto.createHash('sha256').update('submarine-provider-node').digest();
	const store = options.store ?? new MemoryLedgerStore<ISwapRecord>();
	const ledger = options.ledger ?? new SwapLedger(store);
	if (!options.ledger) ledger.rehydrate();
	const outgoing =
		options.outgoing ??
		new FakeOutgoing((hashHex) => ledger.byPaymentHash(hashHex)[0]?.state);
	const config: Partial<ISubmarineSwapProviderConfig> = {
		refundDeltaBlocks: 200,
		minRefundDeltaBlocks: 100,
		maxRefundDeltaBlocks: 400,
		claimSafetyBlocks: 12,
		resolutionSafetyBlocks: 6,
		routeCltvBudgetBlocks: 20,
		fundingConfirmations: 1,
		resolutionConfirmations: 2,
		claimBumpIntervalBlocks: 2,
		unresolvedAfterBlocks: 3,
		minInvoiceExpirySeconds: 60,
		flatFeeSat: 100n,
		feePpm: 1_000,
		...options.config
	};
	const events: ISubmarineHarness['events'] = [];
	const logs: ISubmarineHarness['logs'] = [];
	const state = {
		feeRate: options.feeRate === undefined ? 2 : options.feeRate,
		spendableMsat: options.spendableMsat ?? 10_000_000_000n,
		clock: options.clock
	};
	const inUse = options.inUse ?? new Set<string>();
	const channelPeers = options.channelPeers ?? new Set<string>();
	const destination =
		options.destination ??
		bitcoin.payments.p2wpkh({ pubkey: getPublicKey(nodeKey) }).output!;
	const ownNodeId = getPublicKey(nodeKey);
	const deps: ISubmarineSwapProviderDeps = {
		peers: provider,
		ledger,
		resolver: new SwapChainResolver(
			chain,
			{
				fundingConfirmations: config.fundingConfirmations!,
				resolutionConfirmations: config.resolutionConfirmations!
			},
			bitcoin.networks.regtest
		),
		payInvoice: (bolt11, o) => outgoing.payInvoice(bolt11, o),
		outgoingHtlcs: (hash) => outgoing.outgoingHtlcs(hash),
		onPaymentEvent: (cb) => {
			outgoing.listeners.add(cb);
			return () => outgoing.listeners.delete(cb);
		},
		hashInUse: (hash) => inUse.has(hash.toString('hex')),
		spendableOutboundMsat: () => state.spendableMsat,
		ownNodeId,
		hasUsableChannelWith: (nodeId) => channelPeers.has(nodeId.toString('hex')),
		broadcast: (txHex) => chain.broadcastTransaction(txHex),
		estimateFee: async () => state.feeRate,
		currentHeight: () => chain.height,
		deriveClaimKey: (swapId) => deriveSwapKey(nodeKey, swapId, 'claim'),
		claimDestinationScript: () => destination,
		network: bitcoin.networks.regtest,
		networkName: 'regtest',
		now: () => state.clock ?? Date.now(),
		log: (action, data) => logs.push({ action, data })
	};
	const engine = new SubmarineSwapProvider(deps, config);
	for (const evt of SUBMARINE_SWAP_EVENTS) {
		engine.on(evt, (data) => events.push({ name: evt, data }));
	}
	if (options.start !== false) await engine.start();
	const h: ISubmarineHarness = {
		net,
		provider,
		client,
		chain,
		outgoing,
		ledger,
		store,
		engine,
		nodeKey,
		ownNodeId,
		events,
		logs,
		get feeRate() {
			return state.feeRate;
		},
		set feeRate(v: number | null) {
			state.feeRate = v;
		},
		get spendableMsat() {
			return state.spendableMsat;
		},
		set spendableMsat(v: bigint) {
			state.spendableMsat = v;
		},
		inUse,
		channelPeers,
		destination,
		get clock() {
			return state.clock;
		},
		set clock(v: number | undefined) {
			state.clock = v;
		},
		restart: async (overrides = {}) => {
			engine.stop();
			return submarineHarness({
				...options,
				...overrides,
				store,
				chain,
				outgoing: overrides.outgoing ?? outgoing,
				net,
				provider,
				nodeKey,
				feeRate: state.feeRate,
				spendableMsat: state.spendableMsat,
				inUse,
				channelPeers,
				clock: state.clock
			});
		}
	};
	return h;
}
