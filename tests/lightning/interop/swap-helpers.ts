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
import { bitcoinRpc, TEST_MNEMONIC } from './shared-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { REGTEST_CHAIN_HASH } from '../../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import { BeignetCustomSubtype } from '../../../src/lightning/message/custom';
import { INodeConfig } from '../../../src/lightning/node/types';
import { computeScriptHash } from '../../../src/lightning/chain/chain-watcher';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	ISwapChainSource,
	ISwapCreateAck,
	SwapWireDirection,
	decodeSwapCreateAck,
	encodeSwapCreate
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
	const { mineBlocks } = await import('./shared-helpers');
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
	const { expect } = await import('chai');
	const { buildSwapClaimTx } = await import('../../../src/lightning/swaps');
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
	const { expect } = await import('chai');
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
