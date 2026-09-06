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
import {
	IHeldInvoicePart,
	IHeldInvoiceSnapshot
} from '../../../src/lightning/node/types';
import {
	IReverseSwapProviderConfig,
	IReverseSwapProviderDeps,
	ISwapChainSource,
	ISwapRecord,
	ReverseSwapProvider,
	SwapChainResolver,
	SwapLedger,
	buildSwapClaimTx,
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

	async fundOutput(
		address: string,
		amountSat: bigint,
		_feeRate: number
	): Promise<{ txHex: string; txid: Buffer; vout: number }> {
		if (this.failBuilds > 0) {
			this.failBuilds--;
			throw new Error('wallet busy');
		}
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
	restart(): Promise<ISwapHarness>;
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
		pledge: (txHex) => {
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
		restart: async () => {
			engine.stop();
			return harness({
				...options,
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
