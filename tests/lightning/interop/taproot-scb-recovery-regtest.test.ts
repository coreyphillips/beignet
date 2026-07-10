/**
 * Interop (regtest bitcoind): taproot SCB-recovery sweep, end to end against a
 * REAL chain. Open a simple taproot channel between two LightningNodes on a
 * real MuSig2 P2TR funding output, export the static channel backup, WIPE the
 * opener, have the peer force-close on-chain, then restore a fresh node from
 * the SCB blob data with a bitcoind-backed chain backend and assert the
 * recovered node detects the force-close, holds the taproot to_remote sweep
 * for its 1-block CSV, broadcasts it at maturity, and the funds CONFIRM at the
 * node's sweep destination. Auto-skips if regtest bitcoind is unreachable.
 * Mirrors the harness of taproot-force-close-regtest.test.ts.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../../src/lightning/node/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../../src/lightning/channel/types';
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import { buildTaprootToRemoteOutput } from '../../../src/lightning/script/commitment-taproot';
import { OutputType, OutputStatus } from '../../../src/lightning/chain/types';
import {
	IChainBackend,
	computeScriptHash
} from '../../../src/lightning/chain/chain-watcher';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import {
	bitcoinRpc,
	mineBlocks,
	ensureBitcoindFunds,
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

// ── Deterministic node configs (scb-restore.test.ts harness) ────────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-scb-rt-seed-${id}-${process.pid}`))
		.digest();
}

function makePrivkeys(seed: Buffer): Buffer[] {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return keys;
}

function makeBasepoints(privkeys: Buffer[]): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(privkeys[0]),
		revocationBasepoint: getPublicKey(privkeys[1]),
		paymentBasepoint: getPublicKey(privkeys[2]),
		delayedPaymentBasepoint: getPublicKey(privkeys[3]),
		htlcBasepoint: getPublicKey(privkeys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	const privkeys = makePrivkeys(seed);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(privkeys),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: privkeys[0],
		revocationBasepointSecret: privkeys[1],
		paymentBasepointSecret: privkeys[2],
		delayedPaymentBasepointSecret: privkeys[3],
		htlcBasepointSecret: privkeys[4],
		preferTaproot: true
	};
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeB.getNodeId()) {
				nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
			}
		}
	);
	nodeB.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeA.getNodeId()) {
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		}
	);
}

// ── Bitcoind-backed IChainBackend ────────────────────────────────────────────

/**
 * Honest Electrum-style backend over regtest bitcoind: script-hash histories
 * are built by scanning REAL blocks (from a caller-supplied start height, so
 * the pre-existing chain is skipped), transactions come from getrawtransaction
 * and broadcasts go through sendrawtransaction. A short poll loop drives the
 * header callback and per-scripthash change notifications, mirroring how the
 * production ElectrumBackend pushes subscriptions.
 */
class BitcoindChainBackend implements IChainBackend {
	private history = new Map<string, Array<{ txid: string; height: number }>>();
	private outpointScript = new Map<string, string>(); // "txid:vout" -> scripthash
	private subs = new Map<string, Array<() => void>>();
	private headerCallbacks: Array<(height: number) => void> = [];
	private lastScanned: number;
	private lastReportedTip = 0;
	private timer: ReturnType<typeof setInterval> | null = null;
	private syncChain: Promise<Set<string>> = Promise.resolve(new Set());

	constructor(scanFromHeight: number) {
		this.lastScanned = scanFromHeight - 1;
	}

	/** Serialize scans; returns the scripthashes whose history changed. */
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

async function waitFor<T>(
	probe: () => Promise<T | undefined> | (T | undefined),
	what: string,
	timeoutMs = 30_000,
	intervalMs = 250
): Promise<T> {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const value = await probe();
		if (value !== undefined) return value;
		if (Date.now() > deadline) {
			throw new Error(`Timed out waiting for ${what}`);
		}
		await sleep(intervalMs);
	}
}

describe('Interop: taproot SCB-recovery sweep (regtest)', function () {
	this.timeout(180_000);
	let skip = false;
	before(async function () {
		this.timeout(30_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds();
	});

	it('restores from SCB, peer force-closes on-chain, to_remote confirms at the sweep destination after the 1-block CSV', async function () {
		if (skip) this.skip();

		// The recovery backend only needs to see blocks from here on.
		const scanFromHeight = ((await bitcoinRpc('getblockcount')) as number) + 1;

		// ── 1. Live taproot channel on a REAL MuSig2 P2TR funding output ──
		const aliceConfig = makeNodeConfig(1);
		const bobConfig = makeNodeConfig(2);
		const alice = new LightningNode(aliceConfig);
		const bob = new LightningNode(bobConfig);
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);

		const capacitySat = 1_000_000n;
		const funding = createTaprootFundingScript(
			aliceConfig.channelBasepoints.fundingPubkey,
			bobConfig.channelBasepoints.fundingPubkey,
			NETWORK
		);
		const fundTxid = (await bitcoinRpc('sendtoaddress', [
			funding.address,
			0.01
		])) as string;
		await mineBlocks(1);
		const fundTx = (await bitcoinRpc('getrawtransaction', [
			fundTxid,
			true
		])) as {
			vout: { value: number; n: number; scriptPubKey: { address?: string } }[];
		};
		const fout = fundTx.vout.find(
			(v) => v.scriptPubKey.address === funding.address
		)!;
		expect(fout, 'funding output present on-chain').to.not.be.undefined;

		const aliceChannel = alice.openChannel(bob.getNodeId(), capacitySat);
		const channelId = alice.createFunding(
			aliceChannel,
			Buffer.from(fundTxid, 'hex').reverse(),
			fout.n,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		expect(isTaprootChannel(aliceChannel.getFullState().channelType)).to.equal(
			true
		);
		expect(aliceChannel.getFullState().state).to.equal(ChannelState.NORMAL);

		// A commitment round at a relay-clearing feerate (mirrors the taproot
		// force-close regtest) so bob's broadcast commitment is accepted.
		expect(
			alice.getChannelManager().updateChannelFee(channelId, 2500).ok
		).to.equal(true);

		// ── 2. Export alice's SCB, then WIPE alice ──
		const entries = alice.buildStaticChannelBackupData().channels;
		expect(entries).to.have.length(1);
		expect(entries[0].isTaproot).to.equal(true);
		alice.destroy();
		// Alice is gone: stop routing bob's outbound messages at her.
		bob.removeAllListeners('message:outbound');

		// ── 3. The peer force-closes ON-CHAIN ──
		const bobChannel = bob.getChannelManager().getChannel(channelId)!;
		const fcActions = bobChannel.forceClose(bobChannel.getSigner()!);
		const fcBroadcast = fcActions.find(
			(a) => a.type === ChannelActionType.BROADCAST_TX
		) as { tx: Buffer } | undefined;
		expect(fcBroadcast, "bob's force-close BROADCAST_TX").to.not.be.undefined;
		const commitTx = bitcoin.Transaction.fromBuffer(fcBroadcast!.tx);
		await bitcoinRpc('sendrawtransaction', [commitTx.toHex()]);
		await mineBlocks(1);
		const commitHeight = (await bitcoinRpc('getblockcount')) as number;
		bob.destroy();

		// Alice's balance sits in the commitment's taproot to_remote (NUMS
		// internal key, 1-CSV leaf paying her STATIC payment basepoint).
		const expectedToRemoteSpk = buildTaprootToRemoteOutput(
			aliceConfig.channelBasepoints.paymentBasepoint,
			NETWORK
		).output;
		const toRemoteIndex = commitTx.outs.findIndex((o) =>
			o.script.equals(expectedToRemoteSpk)
		);
		expect(toRemoteIndex, 'taproot to_remote present on-chain').to.be.at.least(
			0
		);
		const toRemoteAmount = BigInt(commitTx.outs[toRemoteIndex].value);

		// ── 4. Fresh node, same seed: restore from the SCB entries ──
		const destAddress = (await bitcoinRpc('getnewaddress', [
			'scb-recovery-sweep',
			'bech32'
		])) as string;
		const destScript = bitcoin.address.toOutputScript(destAddress, NETWORK);
		const backend = new BitcoindChainBackend(scanFromHeight);
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const restored = new LightningNode({
			...makeNodeConfig(1),
			storage,
			chainBackend: backend,
			sweepDestinationScript: destScript
		});
		restored.on('node:error', () => {});
		try {
			await restored.startChainWatcher();
			const result = await restored.recoverFromStaticChannelBackup(entries);
			expect(result.recovering).to.deep.equal([entries[0].channelId]);
			expect(result.skipped).to.deep.equal([]);

			// The recovered node must detect bob's on-chain force-close and build
			// the to_remote sweep, HELD for the 1-block CSV (maturity = commit
			// confirmation height + 1, which is one past the current tip).
			const heldOutput = await waitFor(async () => {
				const monitor = restored.getChannelManager().getMonitor(channelId);
				const tracked = monitor
					?.getTrackedOutputs()
					.find((o) => o.outputType === OutputType.TO_REMOTE);
				return tracked?.sweepTxHex !== undefined ? tracked : undefined;
			}, 'the held to_remote sweep');
			expect(heldOutput.txid).to.equal(commitTx.getId());
			expect(heldOutput.outputIndex).to.equal(toRemoteIndex);
			expect(heldOutput.amount).to.equal(toRemoteAmount);
			expect(heldOutput.status).to.equal(OutputStatus.CONFIRMED);
			expect(heldOutput.maturityHeight).to.equal(commitHeight + 1);

			const sweepTx = bitcoin.Transaction.fromHex(heldOutput.sweepTxHex!);
			expect(sweepTx.ins[0].sequence, '1-block CSV sequence').to.equal(1);
			expect(sweepTx.outs[0].script.equals(destScript)).to.equal(true);

			// ── 5. Mine to CSV maturity: the sweep must broadcast and confirm ──
			await mineBlocks(1);
			await waitFor(async () => {
				try {
					await bitcoinRpc('getmempoolentry', [sweepTx.getId()]);
					return true;
				} catch {
					return undefined;
				}
			}, 'the sweep in the mempool');

			await mineBlocks(1);
			const mined = await waitFor(async () => {
				const res = (await bitcoinRpc('getrawtransaction', [
					sweepTx.getId(),
					true
				])) as { confirmations?: number };
				return (res.confirmations ?? 0) >= 1 ? res : undefined;
			}, 'the confirmed sweep');
			expect((mined.confirmations ?? 0) >= 1).to.equal(true);

			// The funds ARRIVED at the recovered node's wallet destination: the
			// confirmed sweep spends the commitment's to_remote outpoint and pays
			// the wallet address the to_remote amount minus a sane fee.
			expect(
				Buffer.from(sweepTx.ins[0].hash).reverse().toString('hex')
			).to.equal(commitTx.getId());
			expect(sweepTx.ins[0].index).to.equal(toRemoteIndex);
			const received = BigInt(
				Math.round(
					((await bitcoinRpc('getreceivedbyaddress', [
						destAddress,
						1
					])) as number) * 1e8
				)
			);
			expect(received).to.equal(BigInt(sweepTx.outs[0].value));
			const fee = toRemoteAmount - received;
			expect(fee > 0n && fee < 10_000n, `sane sweep fee (${fee})`).to.equal(
				true
			);
		} finally {
			backend.stop();
			restored.destroy();
			storage.close();
		}
	});
});
