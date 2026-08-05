/**
 * Interop chaos: stale-DB-copy restart on a simple taproot channel against
 * live LND, proving the safe-DLP path all the way to on-chain funds
 * (regtest).
 *
 * Beignet funds a taproot channel to LND, pays advance the commitment, and a
 * copy of the DB is snapshotted. More payments advance the live state past
 * the snapshot, then the node restarts FROM THE STALE COPY. On reestablish
 * LND proves the restored state is stale (a valid future per-commitment
 * secret): the channel must go ERRORED with local_data_loss, broadcast
 * NOTHING, and ask the peer to close. LND force-closes with its commitment;
 * the restored node's chain watcher classifies the future commitment, holds
 * the taproot to_remote sweep for its 1-block CSV, broadcasts at maturity,
 * and the funds CONFIRM at the node's sweep destination.
 *
 * Requires the standalone `lnd-taproot` container (REST 8082, P2P 9736).
 * It shares host port 8082 with the compose `eclair` container; stop eclair
 * first (docker stop eclair && docker start lnd-taproot).
 * Run solo:
 *   npx mocha --exit --timeout 240000 -r ts-node/register tests/lightning/interop/chaos-lnd-taproot-dlp.test.ts
 * Auto-skips when the containers are down.
 */

import { expect } from 'chai';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { LndRestClient } from './lnd-client';
import {
	isLndTaprootAvailable,
	createLndTaprootClient,
	LND_TAPROOT_P2P_HOST,
	LND_TAPROOT_P2P_PORT
} from './lnd-taproot-helpers';
import {
	waitForLndSync,
	waitForLndChannels,
	cleanupLndState
} from './lnd-helpers';
import {
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	ensureBitcoindFunds,
	setupRoutingForChannel,
	sleep,
	BitcoindFundingProvider
} from './shared-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	ChannelState,
	REGTEST_CHAIN_HASH
} from '../../../src/lightning/channel/types';
import { ChannelRecoveryStatus } from '../../../src/lightning/recovery/channel-status';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import { OutputType, OutputStatus } from '../../../src/lightning/chain/types';
import {
	IChainBackend,
	computeScriptHash
} from '../../../src/lightning/chain/chain-watcher';
import type { IStorageBackend } from '../../../src/lightning/storage/types';

bitcoin.initEccLib(ecc);
const NETWORK = bitcoin.networks.regtest;

const SEED_PASSPHRASE = 'taproot-interop-306';

async function waitFor(
	probe: () => boolean | Promise<boolean>,
	what: string,
	timeoutMs: number,
	intervalMs = 500
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		if (await probe()) return;
		await sleep(intervalMs);
	}
	throw new Error(`timed out waiting for ${what}`);
}

// ── Bitcoind-backed IChainBackend (taproot-scb-recovery-regtest harness) ────

class BitcoindChainBackend implements IChainBackend {
	private history = new Map<string, Array<{ txid: string; height: number }>>();
	private outpointScript = new Map<string, string>();
	private subs = new Map<string, Array<() => void>>();
	private headerCallbacks: Array<(height: number) => void> = [];
	private lastScanned: number;
	private lastReportedTip = 0;
	private timer: ReturnType<typeof setInterval> | null = null;
	private syncChain: Promise<Set<string>> = Promise.resolve(new Set());

	constructor(scanFromHeight: number) {
		this.lastScanned = scanFromHeight - 1;
	}

	private sync(): Promise<Set<string>> {
		this.syncChain = this.syncChain.then(
			() => this.scanNewBlocks(),
			() => this.scanNewBlocks()
		);
		return this.syncChain;
	}

	private async scanNewBlocks(): Promise<Set<string>> {
		const changed = new Set<string>();
		const tip = (await bitcoinRpc('getblockcount')) as number;
		for (let h = this.lastScanned + 1; h <= tip; h++) {
			const hash = (await bitcoinRpc('getblockhash', [h])) as string;
			const block = (await bitcoinRpc('getblock', [hash, 2])) as {
				tx: Array<{
					txid: string;
					vin: Array<{ txid?: string; vout?: number }>;
					vout: Array<{ scriptPubKey: { hex: string } }>;
				}>;
			};
			for (const tx of block.tx) {
				for (let i = 0; i < tx.vout.length; i++) {
					const sh = computeScriptHash(
						Buffer.from(tx.vout[i].scriptPubKey.hex, 'hex')
					);
					this.outpointScript.set(`${tx.txid}:${i}`, sh);
					this.pushHistory(sh, tx.txid, h, changed);
				}
				for (const vin of tx.vin) {
					if (vin.txid === undefined || vin.vout === undefined) continue;
					const sh = this.outpointScript.get(`${vin.txid}:${vin.vout}`);
					if (sh) this.pushHistory(sh, tx.txid, h, changed);
				}
			}
		}
		this.lastScanned = tip;
		return changed;
	}

	private pushHistory(
		scriptHash: string,
		txid: string,
		height: number,
		changed: Set<string>
	): void {
		const entries = this.history.get(scriptHash) ?? [];
		if (!entries.some((e) => e.txid === txid)) {
			entries.push({ txid, height });
			this.history.set(scriptHash, entries);
			changed.add(scriptHash);
		}
	}

	private async pollOnce(): Promise<void> {
		const changed = await this.sync();
		const tip = this.lastScanned;
		if (tip > this.lastReportedTip) {
			this.lastReportedTip = tip;
			for (const cb of this.headerCallbacks) cb(tip);
		}
		for (const sh of changed) {
			for (const cb of this.subs.get(sh) ?? []) cb();
		}
	}

	stop(): void {
		if (this.timer) {
			clearInterval(this.timer);
			this.timer = null;
		}
	}

	async subscribeToHeaders(
		onNewBlock: (height: number) => void
	): Promise<void> {
		this.headerCallbacks.push(onNewBlock);
		await this.sync();
		this.lastReportedTip = this.lastScanned;
		onNewBlock(this.lastScanned);
		if (!this.timer) {
			this.timer = setInterval(() => {
				this.pollOnce().catch(() => {
					/* transient RPC error - retried next tick */
				});
			}, 250);
			if (this.timer.unref) this.timer.unref();
		}
	}

	async subscribeToScriptHash(
		scriptHash: string,
		onChange: () => void
	): Promise<void> {
		const cbs = this.subs.get(scriptHash) ?? [];
		cbs.push(onChange);
		this.subs.set(scriptHash, cbs);
	}

	async getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>> {
		await this.sync();
		return this.history.get(scriptHash) ?? [];
	}

	async getTransaction(txid: string): Promise<Buffer> {
		const hex = (await bitcoinRpc('getrawtransaction', [txid])) as string;
		return Buffer.from(hex, 'hex');
	}

	async broadcastTransaction(rawTxHex: string): Promise<string> {
		return (await bitcoinRpc('sendrawtransaction', [rawTxHex])) as string;
	}
}

describe('Interop chaos: LND taproot stale-copy DLP (regtest)', function () {
	this.timeout(240_000);

	let lnd: LndRestClient;
	let lndPubkey: string;
	let skipAll = false;
	let node: LightningNode | null = null;
	let storage: SqliteStorage | null = null;
	let backend: BitcoindChainBackend | null = null;

	before(async function () {
		this.timeout(60_000);
		if (!(await isLndTaprootAvailable())) {
			skipAll = true;
			console.log('    [skip] lnd-taproot container not reachable');
			this.skip();
			return;
		}
		const client = await createLndTaprootClient();
		if (!client) {
			skipAll = true;
			console.log('    [skip] lnd-taproot macaroon not loadable');
			this.skip();
			return;
		}
		lnd = client;
		await waitForLndSync(lnd);
		await cleanupLndState(lnd);
		lndPubkey = (await lnd.getInfo()).identity_pubkey;
	});

	beforeEach(function () {
		if (skipAll) this.skip();
	});

	afterEach(() => {
		backend?.stop();
		backend = null;
		if (node) {
			try {
				node.destroy();
			} catch {
				/* ignore */
			}
			node = null;
		}
		if (storage) {
			try {
				storage.close();
			} catch {
				/* ignore */
			}
			storage = null;
		}
	});

	const mkFeatures = (): FeatureFlags => {
		const f = FeatureFlags.empty();
		f.setOptional(Feature.DATA_LOSS_PROTECT);
		f.setOptional(Feature.STATIC_REMOTE_KEY);
		f.setOptional(Feature.PAYMENT_SECRET);
		f.setOptional(Feature.TLV_ONION);
		f.setOptional(Feature.CHANNEL_TYPE);
		f.setOptional(Feature.GOSSIP_QUERIES);
		f.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
		f.setOptional(Feature.OPTION_TAPROOT);
		return f;
	};

	const mkNode = (
		s: IStorageBackend,
		extras: {
			fundingProvider?: BitcoindFundingProvider;
			chainBackend?: IChainBackend;
			sweepDestinationScript?: Buffer;
		} = {}
	): LightningNode => {
		const keys = deriveLightningKeysFromMnemonic(
			TEST_MNEMONIC,
			SEED_PASSPHRASE,
			LnCoinType.REGTEST
		);
		const n = new LightningNode({
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
			localFeatures: mkFeatures(),
			chainHashes: [REGTEST_CHAIN_HASH],
			preferAnchors: true,
			preferTaproot: true,
			storage: s,
			...extras
		});
		n.on('node:error', () => {
			/* absorb */
		});
		n.on('error', () => {
			/* absorb */
		});
		return n;
	};

	// A dial right after the previous life's socket died can lose to LND's
	// teardown of that peer object ("Connection closed during handshake");
	// retry a couple of times with a settle gap.
	const connectWithRetry = async (n: LightningNode): Promise<void> => {
		for (let attempt = 0; ; attempt++) {
			try {
				await n.connectPeer(
					lndPubkey,
					LND_TAPROOT_P2P_HOST,
					LND_TAPROOT_P2P_PORT
				);
				return;
			} catch (err) {
				if (attempt >= 2) throw err;
				await sleep(2000);
			}
		}
	};

	const payBeignet = async (
		n: LightningNode,
		amountMsat: bigint,
		tag: string
	): Promise<void> => {
		const invoice = n.createInvoice({ amountMsat, description: tag });
		const pay = await lnd.sendPaymentSync(invoice.bolt11);
		expect(pay.payment_error || '', tag).to.equal('');
		expect(pay.payment_preimage, tag).to.be.a('string');
	};

	it('goes safe-DLP on a stale restart and sweeps the peer force-close', async function () {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chaos-taproot-dlp-'));
		const dbPath = path.join(dir, 'node.db');
		const stalePath = path.join(dir, 'stale.db');

		try {
			// ── Life 1: beignet-funded taproot channel, one payment ──
			await ensureBitcoindFunds(2.0);
			// The life 3 chain backend must scan from BEFORE the funding tx:
			// the monitor reads the funding outpoint's script history, and a
			// history that lacks the funding tx itself never yields the spend.
			const scanFrom = ((await bitcoinRpc('getblockcount')) as number) + 1;
			storage = new SqliteStorage(dbPath);
			storage.open();
			node = mkNode(storage, {
				fundingProvider: new BitcoindFundingProvider()
			});
			const nodeId = node.getNodeId();

			await node.connectPeer(
				lndPubkey,
				LND_TAPROOT_P2P_HOST,
				LND_TAPROOT_P2P_PORT
			);
			await sleep(2000);
			node.openChannel(lndPubkey, 200_000n, 100_000_000n);

			const cm = node.getChannelManager();
			await waitFor(
				() => cm.listChannels().some((c) => c.getChannelId() !== null),
				'taproot channel to be funded',
				30_000
			);
			const channelId = cm
				.listChannels()
				.find((c) => c.getChannelId() !== null)!
				.getChannelId()!;

			await mineBlocks(6);
			await sleep(3000);
			node.handleFundingConfirmed(channelId);
			const tip = (await bitcoinRpc('getblockcount')) as number;
			node.handleNewBlock(tip);
			await waitForLndChannels(lnd, 1, 60_000);
			const life1Cm = node.getChannelManager();
			await waitFor(
				() => life1Cm.getChannel(channelId)?.getState() === ChannelState.NORMAL,
				'channel_ready exchange to complete',
				30_000
			);
			// LND marks the channel active moments before it will actually
			// route through it; paying immediately loses to that race.
			await sleep(2000);
			setupRoutingForChannel(node, lndPubkey);

			await payBeignet(node, 5_000_000n, 'dlp payment 1');
			await sleep(3000);

			// ── Snapshot: clean shutdown, copy the DB ──
			node.destroy();
			node = null;
			storage.close();
			storage = null;
			fs.copyFileSync(dbPath, stalePath);
			await sleep(3000);

			// ── Life 2: advance the live state past the snapshot ──
			storage = new SqliteStorage(dbPath);
			storage.open();
			node = mkNode(storage);
			setupRoutingForChannel(node, lndPubkey);
			node.handleNewBlock(tip);
			await connectWithRetry(node);
			const life2Channel = node.getChannelManager().listChannels()[0];
			await waitFor(
				() => life2Channel.getState() === ChannelState.NORMAL,
				'life 2 reestablish',
				60_000
			);
			await payBeignet(node, 4_000_000n, 'dlp payment 2');
			await payBeignet(node, 3_000_000n, 'dlp payment 3');
			await sleep(3000);

			// Remember LND's channel point for the deterministic force-close.
			const lndChans = await lnd.listChannels();
			const ours = (lndChans.channels || []).find(
				(c) =>
					(c as unknown as { remote_pubkey?: string }).remote_pubkey === nodeId
			);
			expect(ours, 'LND lists our channel').to.not.equal(undefined);
			const [cpTxid, cpIndex] = ours!.channel_point.split(':');

			node.destroy();
			node = null;
			storage.close();
			storage = null;
			await sleep(3000);

			// ── Life 3: restart from the STALE copy with a real chain backend ──
			const destAddress = (await bitcoinRpc('getnewaddress', [
				'chaos-dlp-sweep',
				'bech32'
			])) as string;
			const destScript = bitcoin.address.toOutputScript(destAddress, NETWORK);
			backend = new BitcoindChainBackend(scanFrom);
			storage = new SqliteStorage(stalePath);
			storage.open();
			node = mkNode(storage, {
				chainBackend: backend,
				sweepDestinationScript: destScript
			});
			const broadcasts: unknown[] = [];
			node.on('broadcast:tx', (tx: unknown) => broadcasts.push(tx));
			await node.startChainWatcher();

			await connectWithRetry(node);

			// LND's reestablish proves our restored state is stale: safe-DLP.
			const staleNode = node;
			const staleChannel = staleNode.getChannelManager().listChannels()[0];
			await waitFor(
				() => staleChannel.getState() === ChannelState.ERRORED,
				'stale channel to go ERRORED (safe-DLP)',
				60_000
			);
			const status = staleNode
				.getRecoveryStatus()
				.channels.find(
					(c) =>
						c.channelId ===
						(staleChannel.getChannelId() ?? channelId).toString('hex')
				);
			expect(status?.status).to.equal(ChannelRecoveryStatus.LocalDataLoss);
			// The stale node must never broadcast its revoked commitment.
			expect(broadcasts.length).to.equal(0);

			// ── LND force-closes with ITS (current) commitment ──
			try {
				await lnd.forceCloseChannel(cpTxid, parseInt(cpIndex, 10));
			} catch {
				// LND may already be closing after our DLP error message.
			}
			// The broadcast is asynchronous: wait for LND to publish the close
			// and for bitcoind to hold it before mining the confirmation, or
			// the block races the broadcast and the commitment never confirms.
			let closingTxid: string | null = null;
			await waitFor(
				async () => {
					const pending = await lnd.pendingChannels();
					const pools = [
						(pending as unknown as { waiting_close_channels?: unknown[] })
							.waiting_close_channels || [],
						pending.pending_force_closing_channels || []
					];
					for (const pool of pools) {
						const entry = (
							pool as Array<{
								channel?: { channel_point?: string };
								closing_txid?: string;
							}>
						).find((e) => e.channel?.channel_point?.startsWith(cpTxid));
						if (entry?.closing_txid) {
							closingTxid = entry.closing_txid;
							return true;
						}
					}
					return false;
				},
				'LND to publish its force close',
				30_000,
				1000
			);
			await waitFor(
				async () => {
					try {
						await bitcoinRpc('getrawtransaction', [closingTxid!]);
						return true;
					} catch {
						return false;
					}
				},
				'the close tx to reach bitcoind',
				30_000,
				1000
			);
			await mineBlocks(1);

			// The chain watcher sees the future commitment, resolves ONLY the
			// to_remote output, and holds the sweep for the 1-block CSV.
			let sweepTxHex: string | undefined;
			await waitFor(
				() => {
					const monitor = staleNode
						.getChannelManager()
						.getMonitor(staleChannel.getChannelId() ?? channelId);
					const tracked = monitor
						?.getTrackedOutputs()
						.find((o) => o.outputType === OutputType.TO_REMOTE);
					if (
						tracked?.sweepTxHex &&
						tracked.status === OutputStatus.CONFIRMED
					) {
						sweepTxHex = tracked.sweepTxHex;
						return true;
					}
					return false;
				},
				'the held to_remote sweep',
				90_000
			);
			const sweepTx = bitcoin.Transaction.fromHex(sweepTxHex!);
			expect(sweepTx.outs[0].script.equals(destScript)).to.equal(true);

			// ── Mine to CSV maturity: the sweep broadcasts and confirms ──
			await mineBlocks(1);
			await waitFor(
				async () => {
					try {
						await bitcoinRpc('getmempoolentry', [sweepTx.getId()]);
						return true;
					} catch {
						return false;
					}
				},
				'the sweep in the mempool',
				60_000,
				1000
			);
			await mineBlocks(1);
			await waitFor(
				async () => {
					const res = (await bitcoinRpc('getrawtransaction', [
						sweepTx.getId(),
						true
					])) as { confirmations?: number };
					return (res.confirmations ?? 0) >= 1;
				},
				'the confirmed sweep',
				60_000,
				1000
			);

			// The funds ARRIVED at the sweep destination.
			const received = BigInt(
				Math.round(
					((await bitcoinRpc('getreceivedbyaddress', [
						destAddress,
						1
					])) as number) * 1e8
				)
			);
			expect(received).to.equal(BigInt(sweepTx.outs[0].value));
			expect(received > 0n).to.equal(true);
		} catch (err) {
			const msg = (err as Error).message || '';
			if (msg.includes('not available') || msg.includes('ECONNREFUSED')) {
				console.log(`    chaos-lnd-taproot-dlp skipped: ${msg}`);
				this.skip();
				return;
			}
			throw err;
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
