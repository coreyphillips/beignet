/**
 * Regtest helpers for the reverse swap provider (issue #737): a chain source
 * over Bitcoin Core's RPC, a provider node built like the JIT interop node
 * with the swap role on, and a client node that opens a swap over TCP.
 *
 * Core has no address index, so the chain source is told which contract
 * scripts to watch and scans the mempool plus every block since the watch
 * began for outputs paying them and inputs spending those outputs. Regtest
 * mempools and blocks are tiny, and a scanned block is cached by hash.
 */

import crypto from 'crypto';
import * as net from 'net';
import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import { bitcoinRpc, mineBlocks, TEST_MNEMONIC } from './shared-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { REGTEST_CHAIN_HASH } from '../../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import { BeignetCustomSubtype } from '../../../src/lightning/message/custom';
import { INodeConfig, PaymentStatus } from '../../../src/lightning/node/types';
import { computeScriptHash } from '../../../src/lightning/chain/chain-watcher';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	ISwapChainSource,
	ISwapCreateAck,
	ISwapSubmarineCreateAck,
	SwapWireDirection,
	buildSwapClaimTx,
	buildSwapRefundTx,
	decodeSwapCreateAck,
	decodeSwapSubmarineCreateAck,
	encodeSwapCreate,
	encodeSwapSubmarineCreate,
	submarineSwapFee,
	SUBMARINE_SWAP_DEFAULTS,
	verifySubmarineSwapTerms
} from '../../../src/lightning/swaps';

interface ICoreTx {
	txid: string;
	hex: string;
	vin: Array<{ txid?: string; vout?: number; coinbase?: string }>;
	vout: Array<{ n: number; scriptPubKey: { hex: string } }>;
}

export class CoreSwapChainSource implements ISwapChainSource {
	height = 0;
	private readonly watched = new Map<string, { since: number }>();
	/** Funding outpoints found for a watched script: "txid:vout" -> scriptHash. */
	private readonly outpoints = new Map<string, string>();
	private readonly confirmed = new Map<string, Map<string, number>>();
	private readonly scannedBlocks = new Set<string>();
	private lastScanned = 0;

	async refresh(): Promise<number> {
		this.height = (await bitcoinRpc('getblockcount')) as number;
		return this.height;
	}

	currentHeight(): number {
		return this.height;
	}

	watch(outputScript: Buffer, since: number): void {
		const hash = computeScriptHash(outputScript);
		if (!this.watched.has(hash)) {
			this.watched.set(hash, { since });
			this.confirmed.set(hash, new Map());
			if (this.lastScanned === 0 || since - 1 < this.lastScanned) {
				this.lastScanned = Math.max(0, since - 1);
				this.scannedBlocks.clear();
				for (const m of this.confirmed.values()) m.clear();
			}
		}
	}

	async getTransaction(txid: string): Promise<Buffer> {
		const hex = (await bitcoinRpc('getrawtransaction', [txid])) as string;
		return Buffer.from(hex, 'hex');
	}

	async broadcastTransaction(rawTxHex: string): Promise<string> {
		return (await bitcoinRpc('sendrawtransaction', [rawTxHex])) as string;
	}

	async getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>> {
		if (!this.watched.has(scriptHash)) return [];
		await this.scanBlocks();
		const out: Array<{ txid: string; height: number }> = [];
		for (const [txid, height] of this.confirmed.get(scriptHash)!) {
			out.push({ txid, height });
		}
		const mempool = (await bitcoinRpc('getrawmempool')) as string[];
		for (const txid of mempool) {
			if (out.some((e) => e.txid === txid)) continue;
			let tx: ICoreTx;
			try {
				tx = (await bitcoinRpc('getrawtransaction', [txid, true])) as ICoreTx;
			} catch {
				continue;
			}
			if (this.touches(tx, scriptHash)) out.push({ txid, height: 0 });
		}
		return out;
	}

	private touches(tx: ICoreTx, scriptHash: string): boolean {
		let hit = false;
		for (const out of tx.vout) {
			const h = computeScriptHash(Buffer.from(out.scriptPubKey.hex, 'hex'));
			if (this.watched.has(h)) {
				this.outpoints.set(`${tx.txid}:${out.n}`, h);
				if (h === scriptHash) hit = true;
			}
		}
		for (const input of tx.vin) {
			if (!input.txid) continue;
			const h = this.outpoints.get(`${input.txid}:${input.vout}`);
			if (h === scriptHash) hit = true;
		}
		return hit;
	}

	private async scanBlocks(): Promise<void> {
		const tip = (await bitcoinRpc('getblockcount')) as number;
		for (let h = this.lastScanned + 1; h <= tip; h++) {
			const hash = (await bitcoinRpc('getblockhash', [h])) as string;
			if (this.scannedBlocks.has(hash)) continue;
			const block = (await bitcoinRpc('getblock', [hash, 2])) as {
				tx: ICoreTx[];
			};
			for (const tx of block.tx) {
				for (const scriptHash of this.watched.keys()) {
					if (this.touches(tx, scriptHash)) {
						this.confirmed.get(scriptHash)!.set(tx.txid, h);
					}
				}
			}
			this.scannedBlocks.add(hash);
		}
		this.lastScanned = Math.max(this.lastScanned, tip);
	}
}

function swapFeatures(): FeatureFlags {
	const f = FeatureFlags.empty();
	f.setOptional(Feature.DATA_LOSS_PROTECT);
	f.setOptional(Feature.STATIC_REMOTE_KEY);
	f.setOptional(Feature.PAYMENT_SECRET);
	f.setOptional(Feature.TLV_ONION);
	f.setOptional(Feature.CHANNEL_TYPE);
	f.setOptional(Feature.GOSSIP_QUERIES);
	f.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	f.setOptional(Feature.SCID_ALIAS);
	return f;
}

export function makeSwapNode(
	passphrase: string,
	extra: Partial<INodeConfig> = {}
): LightningNode {
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		passphrase,
		LnCoinType.REGTEST
	);
	const node = new LightningNode({
		nodePrivateKey: keys.nodePrivateKey,
		channelBasepoints: keys.channelBasepoints,
		perCommitmentSeed: keys.perCommitmentSeed,
		fundingPrivkey: keys.fundingPrivkey,
		htlcBasepointSecret: keys.htlcBasepointSecret,
		revocationBasepointSecret: keys.revocationBasepointSecret,
		paymentBasepointSecret: keys.paymentBasepointSecret,
		delayedPaymentBasepointSecret: keys.delayedPaymentBasepointSecret,
		network: Network.REGTEST,
		enableNetworking: true,
		localFeatures: swapFeatures(),
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true,
		...extra
	});
	node.on('node:error', () => undefined);
	node.on('error', () => undefined);
	return node;
}

export async function freePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const server = net.createServer();
		server.on('error', reject);
		server.listen(0, '127.0.0.1', () => {
			const port = (server.address() as net.AddressInfo).port;
			server.close(() => resolve(port));
		});
	});
}

export interface IClientSwapKeys {
	preimage: Buffer;
	paymentHash: Buffer;
	claimKey: Buffer;
	claimPubkey: Buffer;
}

export function clientSwapKeys(): IClientSwapKeys {
	const preimage = crypto.randomBytes(32);
	const claimKey = crypto.randomBytes(32);
	return {
		preimage,
		paymentHash: crypto.createHash('sha256').update(preimage).digest(),
		claimKey,
		claimPubkey: getPublicKey(claimKey)
	};
}

/** Send SWAP_CREATE from the client node and await the provider's ack. */
export async function createSwapOverTcp(
	client: LightningNode,
	providerId: string,
	keys: IClientSwapKeys,
	onchainAmountSat: bigint,
	maxTotalFeeSat = 20_000n
): Promise<ISwapCreateAck> {
	const requestId = crypto.randomBytes(8);
	const ack = new Promise<ISwapCreateAck>((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error('no swap ack')), 15_000);
		const handler = (m: {
			peerPubkey: string;
			subtype: number;
			payload: Buffer;
		}): void => {
			if (
				m.peerPubkey !== providerId ||
				m.subtype !== BeignetCustomSubtype.SWAP_CREATE_ACK
			)
				return;
			const decoded = decodeSwapCreateAck(m.payload);
			if (!decoded.requestId.equals(requestId)) return;
			clearTimeout(timer);
			client.removeListener('custom-message', handler);
			resolve(decoded);
		};
		client.on('custom-message', handler);
	});
	client.sendCustomMessage(
		providerId,
		BeignetCustomSubtype.SWAP_CREATE,
		encodeSwapCreate({
			requestId,
			direction: SwapWireDirection.REVERSE,
			paymentHash: keys.paymentHash,
			claimPubkey: keys.claimPubkey,
			onchainAmountSat,
			maxTotalFeeSat
		})
	);
	return ack;
}

/** Wait for a swap ledger state on the provider, polling. */
export async function waitForSwapState(
	provider: LightningNode,
	swapIdHex: string,
	states: string[],
	timeoutMs = 60_000
): Promise<string> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const row = provider.listSwaps().find((r) => r.id === swapIdHex);
		if (row && states.includes(row.state)) return row.state;
		await new Promise((r) => setTimeout(r, 300));
	}
	const row = provider.listSwaps().find((r) => r.id === swapIdHex);
	throw new Error(
		`swap ${swapIdHex} is ${row?.state ?? 'missing'}, wanted ${states.join(
			'|'
		)}` +
			(row?.failureReason ? ` (failureReason: ${row.failureReason})` : '') +
			(row?.lastError ? ` (lastError: ${row.lastError})` : '')
	);
}

export function p2wpkhScript(address: string): Buffer {
	return bitcoin.address.toOutputScript(address, bitcoin.networks.regtest);
}

// ─────────────── Shared scenarios for the LND and CLN suites ───────────────

/** What the paying Lightning node must offer the scenarios. */
export interface ISwapPayer {
	/** Fire the payment; resolves with the preimage hex once settled. Never awaited on the hot path. */
	pay(bolt11: string): Promise<{ preimageHex: string }>;
	/** 'pending' | 'complete' | 'failed' | 'unknown'. */
	status(paymentHashHex: string): Promise<string>;
	newAddress(): Promise<string>;
}

export interface ISwapScene {
	provider: LightningNode;
	client: LightningNode;
	chain: CoreSwapChainSource;
	payer: ISwapPayer;
}

export const SWAP_TIMEOUTS = {
	refundDeltaBlocks: 24,
	minRefundDeltaBlocks: 16,
	maxRefundDeltaBlocks: 48,
	fundingSafetyBlocks: 3,
	resolutionSafetyBlocks: 3
};

export const SWAP_PROVIDER_CONFIG: INodeConfig['swaps'] = {
	enabled: true,
	fee: { flatFeeSat: 100n, feePpm: 1_000 },
	confirmations: { fundingConfirmations: 1, resolutionConfirmations: 2 },
	timeouts: SWAP_TIMEOUTS
};

async function tick(scene: ISwapScene): Promise<number> {
	const tip = await scene.chain.refresh();
	scene.provider.handleNewBlock(tip);
	scene.client.handleNewBlock(tip);
	await scene.provider.getSwapProvider()!.onBlock(tip);
	return tip;
}

export async function mineAndTick(
	scene: ISwapScene,
	blocks: number
): Promise<number> {
	await mineBlocks(blocks);
	await new Promise((r) => setTimeout(r, 1_000));
	return tick(scene);
}

async function until(
	label: string,
	check: () => Promise<boolean>,
	timeoutMs = 60_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (await check()) return;
		await new Promise((r) => setTimeout(r, 500));
	}
	throw new Error(`timed out waiting for ${label}`);
}

/**
 * The client pays, the provider funds, the client claims to the paying
 * node's own wallet, the provider settles the hold, the payment completes
 * with the client's preimage.
 */
export async function runReverseSwapHappyPath(
	scene: ISwapScene,
	amountSat = 100_000n
): Promise<{ claimTxid: string; swapIdHex: string }> {
	const providerId = scene.provider.getNodeId();
	const tip = await tick(scene);
	const keys = clientSwapKeys();
	const ack = await createSwapOverTcp(
		scene.client,
		providerId,
		keys,
		amountSat
	);
	expect(ack.accepted, ack.reasonText).to.equal(true);
	const terms = ack.terms!;
	const swapIdHex = terms.swapId.toString('hex');
	expect(terms.refundHeight).to.equal(tip + SWAP_TIMEOUTS.refundDeltaBlocks);
	scene.chain.watch(terms.outputScript, tip);

	const paying = scene.payer.pay(terms.bolt11);
	paying.catch(() => undefined);
	await waitForSwapState(scene.provider, swapIdHex, [
		'FUNDING_BROADCAST',
		'FUNDED'
	]);
	await mineAndTick(scene, 1);
	await waitForSwapState(scene.provider, swapIdHex, ['FUNDED']);
	const record = scene.provider.listSwaps().find((r) => r.id === swapIdHex)!;
	expect(record.fundingHeight).to.be.a('number');

	const claim = buildSwapClaimTx({
		htlc: {
			paymentHash: keys.paymentHash,
			claimPublicKey: keys.claimPubkey,
			refundPublicKey: terms.refundPubkey,
			refundHeight: terms.refundHeight
		},
		fundingTransaction: bitcoin.Transaction.fromHex(record.fundingTxHex!),
		outputIndex: record.fundingVout!,
		destinationScript: p2wpkhScript(await scene.payer.newAddress()),
		feeSatoshis: 500n,
		privateKey: keys.claimKey,
		preimage: keys.preimage
	});
	const claimTxid = (await bitcoinRpc('sendrawtransaction', [
		claim.toHex()
	])) as string;
	expect(claimTxid).to.equal(claim.getId());
	// The claim is in the mempool: the provider settles without waiting for a block.
	await tick(scene);
	await waitForSwapState(scene.provider, swapIdHex, ['SETTLED']);
	const settled = scene.provider.listSwaps().find((r) => r.id === swapIdHex)!;
	expect(settled.preimageHex).to.equal(keys.preimage.toString('hex'));
	expect(settled.resolution!.kind).to.equal('claim');

	const paid = await paying;
	expect(paid.preimageHex).to.equal(keys.preimage.toString('hex'));
	await until(
		'payment complete',
		async () =>
			(await scene.payer.status(keys.paymentHash.toString('hex'))) ===
			'complete'
	);
	expect(
		scene.provider
			.listHoldInvoices()
			.find((i) => i.paymentHash === keys.paymentHash.toString('hex'))!.state
	).to.equal('SETTLED');

	await mineAndTick(scene, 1);
	const confirmed = (await bitcoinRpc('getrawtransaction', [
		claimTxid,
		true
	])) as { confirmations?: number };
	expect(confirmed.confirmations ?? 0).to.be.at.least(1);
	return { claimTxid, swapIdHex };
}

/**
 * Nobody claims: after the refund height the provider refunds itself, keeps
 * the hold through the first confirmation, and cancels it only at policy
 * depth, when the payment finally fails.
 */
export async function runReverseSwapRefundPath(
	scene: ISwapScene,
	amountSat = 80_000n
): Promise<{ swapIdHex: string }> {
	const providerId = scene.provider.getNodeId();
	const tip = await tick(scene);
	const keys = clientSwapKeys();
	const hashHex = keys.paymentHash.toString('hex');
	const ack = await createSwapOverTcp(
		scene.client,
		providerId,
		keys,
		amountSat
	);
	expect(ack.accepted, ack.reasonText).to.equal(true);
	const terms = ack.terms!;
	const swapIdHex = terms.swapId.toString('hex');
	scene.chain.watch(terms.outputScript, tip);

	scene.payer.pay(terms.bolt11).catch(() => undefined);
	await waitForSwapState(scene.provider, swapIdHex, [
		'FUNDING_BROADCAST',
		'FUNDED'
	]);
	await mineAndTick(scene, 1);
	await waitForSwapState(scene.provider, swapIdHex, ['FUNDED']);
	await until(
		'payment in flight',
		async () => (await scene.payer.status(hashHex)) === 'pending'
	);

	// To the first eligible refund block, one tick at a time so every height
	// is judged: nothing before refundHeight + 1.
	let height = await scene.chain.refresh();
	while (height < terms.refundHeight) {
		height = await mineAndTick(scene, Math.min(5, terms.refundHeight - height));
		expect(
			scene.provider.listSwaps().find((r) => r.id === swapIdHex)!.state
		).to.equal('FUNDED');
	}
	await mineAndTick(scene, 1);
	await waitForSwapState(scene.provider, swapIdHex, ['REFUND_PENDING']);
	const pending = scene.provider.listSwaps().find((r) => r.id === swapIdHex)!;
	expect(pending.refundTxid).to.be.a('string');
	expect(await scene.payer.status(hashHex)).to.equal('pending');
	expect(
		scene.provider.listHoldInvoices().find((i) => i.paymentHash === hashHex)!
			.state
	).to.equal('ACCEPTED');

	// One confirmation: still held.
	await mineAndTick(scene, 1);
	expect(
		scene.provider.listSwaps().find((r) => r.id === swapIdHex)!.state
	).to.equal('REFUND_PENDING');
	expect(await scene.payer.status(hashHex)).to.equal('pending');

	// Policy depth: refunded, hold cancelled, payment fails.
	await mineAndTick(scene, 1);
	await waitForSwapState(scene.provider, swapIdHex, ['REFUNDED']);
	expect(
		scene.provider.listHoldInvoices().find((i) => i.paymentHash === hashHex)!
			.state
	).to.equal('CANCELLED');
	await until(
		'payment failed',
		async () => (await scene.payer.status(hashHex)) === 'failed'
	);

	const refund = (await bitcoinRpc('getrawtransaction', [
		pending.refundTxid!,
		true
	])) as {
		confirmations?: number;
		vout: Array<{ scriptPubKey: { hex: string } }>;
	};
	expect(refund.confirmations ?? 0).to.be.at.least(2);
	expect(refund.vout[0].scriptPubKey.hex).to.equal(
		scene.provider.getSweepDestinationScript().toString('hex')
	);
	return { swapIdHex };
}

// ─────────────── Submarine direction (issue #743) ───────────────

/**
 * Margins sized for LND's 80-block final CLTV: the fit needs
 * fundingConfirmations + route budget + 80 + 3 + claim + resolution margins
 * under the refund delta.
 */
export const SUBMARINE_TIMEOUTS = {
	refundDeltaBlocks: 160,
	minRefundDeltaBlocks: 100,
	maxRefundDeltaBlocks: 300,
	claimSafetyBlocks: 6,
	resolutionSafetyBlocks: 6,
	routeCltvBudgetBlocks: 6,
	claimBumpIntervalBlocks: 2,
	minInvoiceExpirySeconds: 30
};

export const SUBMARINE_PROVIDER_CONFIG: INodeConfig['swaps'] = {
	...SWAP_PROVIDER_CONFIG,
	submarine: { enabled: true, ...SUBMARINE_TIMEOUTS }
};

/**
 * Open a channel FROM a beignet node TO a peer through the node's bitcoind
 * funding provider, so the node has outbound liquidity (the submarine
 * provider pays). `peerSeesChannel` waits until the remote lists it usable.
 */
export async function openBeignetFundedChannelTo(
	node: LightningNode,
	peerPubkey: string,
	host: string,
	port: number,
	amountSat: bigint,
	peerSeesChannel: () => Promise<unknown>
): Promise<Buffer> {
	await node.connectPeer(peerPubkey, host, port);
	await new Promise((r) => setTimeout(r, 2_000));
	node.openChannel(peerPubkey, amountSat);
	const manager = node.getChannelManager();
	const deadline = Date.now() + 30_000;
	let funded = manager.listChannels().find((c) => c.getChannelId() !== null);
	while (!funded && Date.now() < deadline) {
		await new Promise((r) => setTimeout(r, 500));
		funded = manager.listChannels().find((c) => c.getChannelId() !== null);
	}
	if (!funded)
		throw new Error('no funded channel after the beignet-funded open');
	const channelId = funded.getChannelId()!;
	await mineBlocks(6);
	await new Promise((r) => setTimeout(r, 3_000));
	node.handleFundingConfirmed(channelId);
	await peerSeesChannel();
	const normalDeadline = Date.now() + 30_000;
	while (Date.now() < normalDeadline) {
		const ch = manager.getChannel(channelId);
		if (ch && ch.getState() === 'NORMAL') break;
		await new Promise((r) => setTimeout(r, 500));
	}
	return channelId;
}

/** What the invoicing (client) Lightning node must offer the scenarios. */
export interface ISubmarineInvoicer {
	/**
	 * Mint an invoice for the amount. A `failable` one can later be failed
	 * while unpaid (LND: a hold invoice on a hash the test knows; CLN: a
	 * regular invoice deleted by label), so the provider's payment fails
	 * back with no preimage.
	 */
	createInvoice(
		amountMsat: bigint,
		options?: { failable?: boolean }
	): Promise<{ bolt11: string; paymentHashHex: string; handle: string }>;
	failUnpaid(handle: string, paymentHashHex: string): Promise<void>;
	/** 'open' | 'accepted' | 'settled' | 'cancelled' | 'unknown' */
	invoiceState(paymentHashHex: string): Promise<string>;
	newAddress(): Promise<string>;
}

export interface ISubmarineScene {
	provider: LightningNode;
	client: LightningNode;
	chain: CoreSwapChainSource;
	invoicer: ISubmarineInvoicer;
}

async function subTick(scene: ISubmarineScene): Promise<number> {
	const tip = await scene.chain.refresh();
	scene.provider.handleNewBlock(tip);
	scene.client.handleNewBlock(tip);
	await scene.provider.getSubmarineSwapProvider()!.onBlock(tip);
	return tip;
}

export async function mineAndTickSubmarine(
	scene: ISubmarineScene,
	blocks: number
): Promise<number> {
	await mineBlocks(blocks);
	await new Promise((r) => setTimeout(r, 1_000));
	return subTick(scene);
}

/** Send SWAP_SUBMARINE_CREATE from the client node and await the provider's ack. */
export async function createSubmarineSwapOverTcp(
	client: LightningNode,
	providerId: string,
	params: {
		paymentHash: Buffer;
		refundPubkey: Buffer;
		bolt11: string;
		onchainAmountSat: bigint;
		maxTotalFeeSat?: bigint;
	}
): Promise<ISwapSubmarineCreateAck> {
	const requestId = crypto.randomBytes(8);
	const ack = new Promise<ISwapSubmarineCreateAck>((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error('no swap ack')), 15_000);
		const handler = (m: {
			peerPubkey: string;
			subtype: number;
			payload: Buffer;
		}): void => {
			if (
				m.peerPubkey !== providerId ||
				m.subtype !== BeignetCustomSubtype.SWAP_SUBMARINE_CREATE_ACK
			)
				return;
			const decoded = decodeSwapSubmarineCreateAck(m.payload);
			if (!decoded.requestId.equals(requestId)) return;
			clearTimeout(timer);
			client.removeListener('custom-message', handler);
			resolve(decoded);
		};
		client.on('custom-message', handler);
	});
	client.sendCustomMessage(
		providerId,
		BeignetCustomSubtype.SWAP_SUBMARINE_CREATE,
		encodeSwapSubmarineCreate({
			requestId,
			direction: SwapWireDirection.SUBMARINE,
			paymentHash: params.paymentHash,
			refundPubkey: params.refundPubkey,
			bolt11: params.bolt11,
			onchainAmountSat: params.onchainAmountSat,
			maxTotalFeeSat: params.maxTotalFeeSat ?? 20_000n
		})
	);
	return ack;
}

/** Pay the contract address from Core's wallet; the txid in display order. */
export async function fundContractFromCore(
	address: string,
	amountSat: bigint
): Promise<string> {
	const btc = (Number(amountSat) / 1e8).toFixed(8);
	return (await bitcoinRpc('sendtoaddress', [address, btc])) as string;
}

/**
 * The provider's fee for the scenarios' config at 2 sat/vB (150 vB claim),
 * with the default routing budget (5000 ppm) charged on the net amount.
 */
export function submarineFeeFor(amountSat: bigint): bigint {
	return submarineSwapFee(amountSat, {
		flatFeeSat: 100n,
		feePpm: 1_000,
		minerFeeSat: 300n,
		routingFeePpm: SUBMARINE_SWAP_DEFAULTS.paymentMaxFeePpm
	});
}

/**
 * The client mints an invoice and funds the contract, the provider pays the
 * invoice over its channel to the client's node, learns the preimage from
 * the settle, claims to its sweep destination and confirms the claim.
 */
export async function runSubmarineSwapHappyPath(
	scene: ISubmarineScene,
	amountSat = 100_000n
): Promise<{ claimTxid: string; swapIdHex: string }> {
	const providerId = scene.provider.getNodeId();
	const tip = await subTick(scene);
	// Leave a little more than the floor so a fee estimate wobble cannot refuse.
	const feeSat = submarineFeeFor(amountSat) + 100n;
	const invoice = await scene.invoicer.createInvoice(
		(amountSat - feeSat) * 1000n
	);
	const paymentHash = Buffer.from(invoice.paymentHashHex, 'hex');
	const refundKey = crypto.randomBytes(32);
	const ack = await createSubmarineSwapOverTcp(scene.client, providerId, {
		paymentHash,
		refundPubkey: getPublicKey(refundKey),
		bolt11: invoice.bolt11,
		onchainAmountSat: amountSat
	});
	expect(ack.accepted, ack.reasonText).to.equal(true);
	const terms = ack.terms!;
	const swapIdHex = terms.swapId.toString('hex');
	expect(terms.refundHeight).to.equal(
		tip + SUBMARINE_TIMEOUTS.refundDeltaBlocks
	);
	expect(terms.totalFeeSat).to.equal(feeSat);
	const verdict = verifySubmarineSwapTerms({
		create: {
			requestId: ack.requestId,
			direction: SwapWireDirection.SUBMARINE,
			paymentHash,
			refundPubkey: getPublicKey(refundKey),
			bolt11: invoice.bolt11,
			onchainAmountSat: amountSat,
			maxTotalFeeSat: 20_000n
		},
		ack,
		currentHeight: tip,
		network: Network.REGTEST,
		minRefundDelta: 50,
		maxRefundDelta: 400,
		maxTotalFeeSat: 20_000n
	});
	expect(verdict.ok, verdict.ok ? '' : verdict.reason).to.equal(true);
	scene.chain.watch(terms.outputScript, tip);

	const fundingTxid = await fundContractFromCore(terms.address, amountSat);
	await subTick(scene);
	await waitForSwapState(scene.provider, swapIdHex, ['FUNDING_SEEN'], 30_000);
	expect(
		scene.provider.listSwaps().find((r) => r.id === swapIdHex)!.fundingTxid
	).to.equal(fundingTxid);
	expect(await scene.invoicer.invoiceState(invoice.paymentHashHex)).to.equal(
		'open'
	);

	// Confirmed: the provider pays, the client's node settles at once, the
	// preimage arrives through payment:preimage, the claim goes out.
	await mineAndTickSubmarine(scene, 1);
	await waitForSwapState(
		scene.provider,
		swapIdHex,
		['CLAIM_BROADCAST', 'CLAIM_CONFIRMED'],
		90_000
	);
	const claimed = scene.provider.listSwaps().find((r) => r.id === swapIdHex)!;
	expect(claimed.preimageHex).to.be.a('string');
	expect(claimed.paymentMaxCltvExpiryHeight).to.equal(
		terms.refundHeight -
			SUBMARINE_TIMEOUTS.claimSafetyBlocks -
			SUBMARINE_TIMEOUTS.resolutionSafetyBlocks
	);
	await until(
		'invoice settled',
		async () =>
			(await scene.invoicer.invoiceState(invoice.paymentHashHex)) === 'settled'
	);
	const payment = scene.provider.getPayment(paymentHash)!;
	expect(payment.preimage!.toString('hex')).to.equal(claimed.preimageHex);
	const claimTxid = claimed.claimTxid!;
	const inMempool = (await bitcoinRpc('getrawtransaction', [
		claimTxid,
		true
	])) as { vout: Array<{ scriptPubKey: { hex: string } }> };
	expect(inMempool.vout[0].scriptPubKey.hex).to.equal(
		scene.provider.getSweepDestinationScript().toString('hex')
	);

	await mineAndTickSubmarine(scene, 1);
	await mineAndTickSubmarine(scene, 1);
	await waitForSwapState(
		scene.provider,
		swapIdHex,
		['CLAIM_CONFIRMED'],
		30_000
	);
	const confirmed = (await bitcoinRpc('getrawtransaction', [
		claimTxid,
		true
	])) as { confirmations?: number };
	expect(confirmed.confirmations ?? 0).to.be.at.least(2);
	return { claimTxid, swapIdHex };
}

/**
 * The client's node fails the payment back (a hold invoice cancelled, or an
 * invoice deleted): every HTLC terminal, no preimage, the swap ends
 * PAYMENT_FAILED with no claim; after the refund height the client refunds
 * itself and the provider never pays again.
 */
export async function runSubmarineSwapRefundPath(
	scene: ISubmarineScene,
	amountSat = 80_000n
): Promise<{ swapIdHex: string; refundTxid: string }> {
	const providerId = scene.provider.getNodeId();
	const tip = await subTick(scene);
	const feeSat = submarineFeeFor(amountSat) + 100n;
	const invoice = await scene.invoicer.createInvoice(
		(amountSat - feeSat) * 1000n,
		{ failable: true }
	);
	const paymentHash = Buffer.from(invoice.paymentHashHex, 'hex');
	const refundKey = crypto.randomBytes(32);
	const ack = await createSubmarineSwapOverTcp(scene.client, providerId, {
		paymentHash,
		refundPubkey: getPublicKey(refundKey),
		bolt11: invoice.bolt11,
		onchainAmountSat: amountSat
	});
	expect(ack.accepted, ack.reasonText).to.equal(true);
	const terms = ack.terms!;
	const swapIdHex = terms.swapId.toString('hex');
	scene.chain.watch(terms.outputScript, tip);
	const fundingTxid = await fundContractFromCore(terms.address, amountSat);
	await subTick(scene);
	await waitForSwapState(scene.provider, swapIdHex, ['FUNDING_SEEN'], 30_000);

	// The payee will not settle: fail it while unpaid, before or as the
	// provider pays. A hold invoice parks first, so the failure may land
	// after PAYING; a deleted invoice fails the HTLC on arrival.
	await mineAndTickSubmarine(scene, 1);
	await waitForSwapState(
		scene.provider,
		swapIdHex,
		['PAYING', 'PAYMENT_UNRESOLVED', 'PAYMENT_FAILED'],
		60_000
	);
	await scene.invoicer.failUnpaid(invoice.handle, invoice.paymentHashHex);
	try {
		await waitForSwapState(
			scene.provider,
			swapIdHex,
			['PAYMENT_FAILED'],
			90_000
		);
	} catch (err) {
		const view = scene.provider.getOutgoingHtlcs(paymentHash);
		const payment = scene.provider.getPayment(paymentHash);
		// eslint-disable-next-line no-console
		console.log(
			'    [diag] outgoing view',
			JSON.stringify({
				status: view.status,
				resolved: view.resolved,
				latest: view.latestOutstandingExpiry,
				htlcs: view.htlcs.map((h) => ({
					id: h.htlcId.toString(),
					state: h.state,
					terminal: h.terminal,
					expiry: h.cltvExpiry
				})),
				payment: payment
					? {
							status: payment.status,
							failureReason: payment.failureReason,
							retryCount: payment.retryCount
					  }
					: null,
				invoice: await scene.invoicer.invoiceState(invoice.paymentHashHex),
				row: scene.provider.listSwaps().find((r) => r.id === swapIdHex)?.state
			})
		);
		throw err;
	}
	const failed = scene.provider.listSwaps().find((r) => r.id === swapIdHex)!;
	expect(failed.claimTxHex).to.equal(undefined);
	expect(failed.preimageHex).to.equal(undefined);
	const view = scene.provider.getOutgoingHtlcs(paymentHash);
	expect(view.resolved).to.equal(true);
	expect(view.preimage).to.equal(undefined);

	// To the refund height, in steps: the row stays terminal, nothing claims.
	let height = await scene.chain.refresh();
	while (height < terms.refundHeight) {
		height = await mineAndTickSubmarine(
			scene,
			Math.min(20, terms.refundHeight - height)
		);
		expect(
			scene.provider.listSwaps().find((r) => r.id === swapIdHex)!.state
		).to.equal('PAYMENT_FAILED');
	}
	const raw = (await bitcoinRpc('getrawtransaction', [fundingTxid])) as string;
	const fundingTx = bitcoin.Transaction.fromHex(raw);
	const vout = fundingTx.outs.findIndex((o) =>
		o.script.equals(terms.outputScript)
	);
	expect(vout).to.be.at.least(0);
	const refund = buildSwapRefundTx({
		htlc: {
			paymentHash,
			claimPublicKey: terms.claimPubkey,
			refundPublicKey: getPublicKey(refundKey),
			refundHeight: terms.refundHeight
		},
		fundingTransaction: fundingTx,
		outputIndex: vout,
		destinationScript: p2wpkhScript(await scene.invoicer.newAddress()),
		feeSatoshis: 500n,
		privateKey: refundKey
	});
	// nLockTime = refundHeight: valid in the block after it.
	await mineAndTickSubmarine(scene, 1);
	const refundTxid = (await bitcoinRpc('sendrawtransaction', [
		refund.toHex()
	])) as string;
	expect(refundTxid).to.equal(refund.getId());
	await mineAndTickSubmarine(scene, 1);
	const confirmed = (await bitcoinRpc('getrawtransaction', [
		refundTxid,
		true
	])) as { confirmations?: number };
	expect(confirmed.confirmations ?? 0).to.be.at.least(1);
	expect(
		scene.provider.listSwaps().find((r) => r.id === swapIdHex)!.state
	).to.equal('PAYMENT_FAILED');
	expect(scene.provider.getPayment(paymentHash)!.status).to.not.equal(
		PaymentStatus.COMPLETED
	);
	return { swapIdHex, refundTxid };
}
