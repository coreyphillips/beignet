/**
 * Issue #2045 on a real chain: a block template whose coinbase pays a
 * channel's funding script, watched as a v1 fundee would watch it. No
 * confirmation (and so no channel_ready) may reach the channel manager
 * before the coinbase has 100 confirmations, while an ordinary funding still
 * confirms at minimum_depth. Auto-skips if regtest bitcoind is unreachable.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChainWatcher,
	IChainBackend,
	IChainWatcherChannelManager,
	computeScriptHash
} from '../../../src/lightning/chain/chain-watcher';
import type { Channel } from '../../../src/lightning/channel/channel';
import { createFundingScript } from '../../../src/lightning/script/funding';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	bitcoinRpc,
	ensureBitcoindFunds,
	mineBlocks,
	sleep
} from './shared-helpers';

bitcoin.initEccLib(ecc);
const NETWORK = bitcoin.networks.regtest;

async function bitcoindUp(): Promise<boolean> {
	try {
		await bitcoinRpc('getblockchaininfo');
		return true;
	} catch {
		return false;
	}
}

/** Chain backend read straight from bitcoind (txindex), polled. */
class BitcoindBackend implements IChainBackend {
	private headerCbs: Array<(height: number) => void> = [];
	private subs = new Map<string, Array<() => void>>();
	private history = new Map<string, Array<{ txid: string; height: number }>>();
	private scanned: number;
	private reportedTip = -1;
	private syncChain: Promise<Set<string>> = Promise.resolve(new Set());
	private timer: ReturnType<typeof setInterval> | null = null;

	constructor(fromHeight: number) {
		this.scanned = fromHeight - 1;
	}

	private sync(): Promise<Set<string>> {
		this.syncChain = this.syncChain.then(
			() => this.scan(),
			() => this.scan()
		);
		return this.syncChain;
	}

	private async scan(): Promise<Set<string>> {
		const changed = new Set<string>();
		const tip = (await bitcoinRpc('getblockcount')) as number;
		for (let h = this.scanned + 1; h <= tip; h++) {
			const hash = (await bitcoinRpc('getblockhash', [h])) as string;
			const block = (await bitcoinRpc('getblock', [hash, 2])) as {
				tx: Array<{
					txid: string;
					vout: Array<{ scriptPubKey: { hex: string } }>;
				}>;
			};
			for (const tx of block.tx) {
				for (const out of tx.vout) {
					const sh = computeScriptHash(
						Buffer.from(out.scriptPubKey.hex, 'hex')
					);
					const entries = this.history.get(sh) ?? [];
					if (entries.some((e) => e.txid === tx.txid)) continue;
					entries.push({ txid: tx.txid, height: h });
					this.history.set(sh, entries);
					changed.add(sh);
				}
			}
		}
		this.scanned = Math.max(this.scanned, tip);
		return changed;
	}

	private async poll(): Promise<void> {
		const changed = await this.sync();
		if (this.scanned > this.reportedTip) {
			this.reportedTip = this.scanned;
			for (const cb of this.headerCbs) cb(this.scanned);
		}
		for (const sh of changed) {
			for (const cb of this.subs.get(sh) ?? []) cb();
		}
	}

	stop(): void {
		if (this.timer) clearInterval(this.timer);
		this.timer = null;
	}

	async subscribeToHeaders(cb: (height: number) => void): Promise<void> {
		this.headerCbs.push(cb);
		await this.sync();
		this.reportedTip = this.scanned;
		cb(this.scanned);
		this.timer ??= setInterval(() => {
			this.poll().catch(() => {
				/* transient RPC error, retried next tick */
			});
		}, 250);
	}

	async subscribeToScriptHash(sh: string, cb: () => void): Promise<void> {
		this.subs.set(sh, [...(this.subs.get(sh) ?? []), cb]);
	}

	async getScriptHashHistory(
		sh: string
	): Promise<Array<{ txid: string; height: number }>> {
		await this.sync();
		return this.history.get(sh) ?? [];
	}

	async getTransaction(txid: string): Promise<Buffer> {
		return Buffer.from(
			(await bitcoinRpc('getrawtransaction', [txid])) as string,
			'hex'
		);
	}

	async broadcastTransaction(hex: string): Promise<string> {
		return (await bitcoinRpc('sendrawtransaction', [hex])) as string;
	}
}

/** A fresh 2-of-2 funding script and its regtest address. */
function newFundingScript(): { script: Buffer; address: string } {
	const script = createFundingScript(
		getPublicKey(crypto.randomBytes(32)),
		getPublicKey(crypto.randomBytes(32)),
		NETWORK
	).p2wshOutput;
	return {
		script,
		address: bitcoin.address.fromOutputScript(script, NETWORK)
	};
}

async function waitUntil(
	probe: () => boolean,
	what: string,
	timeoutMs = 30_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!probe()) {
		if (Date.now() > deadline) throw new Error(`Timed out waiting for ${what}`);
		await sleep(100);
	}
}

describe('Interop: coinbase funding waits 100 blocks (regtest, issue #2045)', function () {
	this.timeout(180_000);
	let skip = false;
	let backend: BitcoindBackend;
	let watcher: ChainWatcher;
	/** Depth each confirmation reached the channel manager at. */
	let confirmedAt: number[];
	let fundingHeight: number;
	const channelId = crypto.randomBytes(32);

	before(async function () {
		this.timeout(30_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds();
	});

	beforeEach(async function () {
		if (skip) this.skip();
		confirmedAt = [];
		fundingHeight = 0;
		backend = new BitcoindBackend(
			((await bitcoinRpc('getblockcount')) as number) + 1
		);
		// A v1 fundee's record: it knows the funding txid and nothing else.
		const channel = {
			getFullState: () => ({ channelId, temporaryChannelId: channelId })
		} as unknown as Channel;
		const manager: IChainWatcherChannelManager = {
			on: () => {},
			off: () => {},
			listChannels: () => [channel],
			handleNewBlock: () => {},
			handleFundingConfirmed: () => {
				confirmedAt.push(watcher.getCurrentBlockHeight() - fundingHeight + 1);
			},
			handleFundingSpent: () => {},
			handleFundingSpendAbsent: () => false,
			handleOutputSpent: () => {},
			handleOutputUnspent: () => {}
		};
		watcher = new ChainWatcher({ backend, channelManager: manager });
		watcher.on('error', () => {});
		await watcher.start();
	});

	afterEach(() => {
		watcher?.stop();
		backend?.stop();
	});

	it('holds a coinbase funding until it matures', async () => {
		const { script, address } = newFundingScript();
		// The block template: its coinbase pays the funding script.
		const { hash } = (await bitcoinRpc('generateblock', [address, []])) as {
			hash: string;
		};
		const block = (await bitcoinRpc('getblock', [hash, 1])) as {
			height: number;
			tx: string[];
		};
		fundingHeight = block.height;
		const coinbaseTxid = block.tx[0];
		const raw = (await bitcoinRpc('getrawtransaction', [
			coinbaseTxid
		])) as string;
		expect(bitcoin.Transaction.fromHex(raw).isCoinbase()).to.equal(true);

		await watcher.watchFundingOutput(channelId, coinbaseTxid, 0, 3, script);
		await mineBlocks(2);
		await waitUntil(
			() => watcher.getCurrentBlockHeight() >= fundingHeight + 2,
			'minimum_depth'
		);
		await sleep(1_000);
		expect(confirmedAt, 'at minimum_depth').to.deep.equal([]);

		// Another process may mine too, so mine to 99 deep from wherever the
		// tip is now.
		const tip = (await bitcoinRpc('getblockcount')) as number;
		const short = fundingHeight + 98 - tip;
		if (short > 0) await mineBlocks(short);
		await waitUntil(
			() => watcher.getCurrentBlockHeight() >= fundingHeight + 98,
			'99 confirmations'
		);
		await sleep(1_000);
		const below = confirmedAt.filter((depth) => depth < 100);
		expect(below, 'confirmed before maturity').to.deep.equal([]);

		await mineBlocks(1);
		await waitUntil(() => confirmedAt.length > 0, 'the maturing block');
		expect(confirmedAt[0]).to.be.at.least(100);
	});

	it('confirms an ordinary funding at minimum_depth', async () => {
		const { script, address } = newFundingScript();
		const txid = (await bitcoinRpc('sendtoaddress', [
			address,
			0.001
		])) as string;
		const [hash] = await mineBlocks(1);
		const block = (await bitcoinRpc('getblock', [hash, 1])) as {
			height: number;
			tx: string[];
		};
		expect(block.tx).to.include(txid);
		fundingHeight = block.height;
		const vout = (
			bitcoin.Transaction.fromHex(
				(await bitcoinRpc('getrawtransaction', [txid])) as string
			).outs as Array<{ script: Buffer }>
		).findIndex((out) => Buffer.from(out.script).equals(script));

		await watcher.watchFundingOutput(channelId, txid, vout, 3, script);
		await mineBlocks(2);
		await waitUntil(() => confirmedAt.length > 0, 'minimum_depth');
		expect(confirmedAt[0]).to.be.within(3, 99);
	});
});
