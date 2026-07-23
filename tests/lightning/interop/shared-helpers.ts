/**
 * Implementation-agnostic interop test helpers.
 *
 * Shared utilities for all interop test suites (LND, CLN, Eclair).
 * Contains bitcoin RPC, mining, node factory, routing setup, and
 * general-purpose wait/sleep helpers.
 */

import os from 'os';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { IFundingProvider } from '../../../src/lightning/node/types';
import type { ISpliceWalletInput } from '../../../src/lightning/channel/channel';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { REGTEST_CHAIN_HASH } from '../../../src/lightning/channel/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';

// ── Constants ──────────────────────────────────────────────────

const BITCOIN_RPC_HOST = '127.0.0.1';
const BITCOIN_RPC_PORT = 43782;
const BITCOIN_RPC_USER = 'polaruser';
const BITCOIN_RPC_PASS = 'polarpass';
// The shared bitcoind container can have wallets loaded by OTHER projects;
// wallet-scoped RPCs sent to the root path then fail with code -19
// ("Multiple wallets are loaded"). Always target our wallet explicitly via
// the /wallet/<name> URI (the historical default wallet has the empty name).
const BITCOIN_RPC_WALLET = process.env.BITCOIN_RPC_WALLET ?? '';

/**
 * Deterministic test mnemonic for reproducible interop testing.
 * DO NOT use on mainnet!
 */
export const TEST_MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// ── Docker Host Detection ──────────────────────────────────────

/**
 * Get the host address that a Docker container can use to reach
 * the beignet node running on the host machine.
 * - macOS: host.docker.internal
 * - Linux: 172.17.0.1 (default docker0 bridge)
 */
export function getDockerHostAddress(): string {
	if (os.platform() === 'darwin') {
		return 'host.docker.internal';
	}
	return '172.17.0.1';
}

// ── Wait Helpers ───────────────────────────────────────────────

/**
 * Wait for a specific event on an EventEmitter.
 */
export function waitForEvent(
	emitter: NodeJS.EventEmitter,
	event: string,
	timeoutMs = 15_000
): Promise<unknown[]> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => {
			reject(new Error(`Timed out waiting for event '${event}'`));
		}, timeoutMs);

		emitter.once(event, (...args: unknown[]) => {
			clearTimeout(timer);
			resolve(args);
		});
	});
}

// ── Bitcoin RPC ────────────────────────────────────────────────

/**
 * Make a JSON-RPC call to the regtest bitcoind.
 */
export async function bitcoinRpc(
	method: string,
	params: unknown[] = []
): Promise<unknown> {
	return new Promise((resolve, reject) => {
		const body = JSON.stringify({
			jsonrpc: '2.0',
			id: Date.now(),
			method,
			params
		});

		const auth = Buffer.from(
			`${BITCOIN_RPC_USER}:${BITCOIN_RPC_PASS}`
		).toString('base64');

		const options = {
			hostname: BITCOIN_RPC_HOST,
			port: BITCOIN_RPC_PORT,
			// Wallet-scoped path: node-level RPCs work here too, and wallet RPCs
			// keep working when other projects load extra wallets on the node.
			path: `/wallet/${BITCOIN_RPC_WALLET}`,
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Basic ${auth}`,
				'Content-Length': Buffer.byteLength(body)
			}
		};

		// Use http (not https) for bitcoind RPC
		const http = require('http');
		const req = http.request(
			options,
			(res: {
				on: (event: string, cb: (data: Buffer | string) => void) => void;
			}) => {
				let data = '';
				res.on('data', (chunk: Buffer | string) => {
					data += chunk;
				});
				res.on('end', () => {
					try {
						const parsed = JSON.parse(data);
						if (parsed.error) {
							reject(
								new Error(`Bitcoin RPC error: ${JSON.stringify(parsed.error)}`)
							);
						} else {
							resolve(parsed.result);
						}
					} catch {
						reject(new Error(`Failed to parse Bitcoin RPC response: ${data}`));
					}
				});
			}
		);

		req.on('error', reject);
		req.write(body);
		req.end();
	});
}

// Cached mining address to avoid depleting the key pool
let _cachedMiningAddress: string | null = null;

/**
 * Get a reusable mining address. Avoids calling getnewaddress repeatedly
 * which depletes the legacy wallet key pool across many test runs.
 */
async function getMiningAddress(): Promise<string> {
	if (!_cachedMiningAddress) {
		try {
			// Refill key pool first in case it's depleted
			await bitcoinRpc('keypoolrefill', [100]);
		} catch {
			/* ignore — descriptor wallets don't need this */
		}
		_cachedMiningAddress = (await bitcoinRpc('getnewaddress', [
			'mining',
			'bech32'
		])) as string;
	}
	return _cachedMiningAddress;
}

/**
 * Mine blocks on regtest, sending the reward to a specified address.
 */
export async function mineBlocks(
	count: number,
	address?: string
): Promise<string[]> {
	if (!address) {
		address = await getMiningAddress();
	}
	return (await bitcoinRpc('generatetoaddress', [count, address])) as string[];
}

/**
 * Ensure the bitcoind wallet has enough spendable balance.
 * In regtest, coinbase outputs need 100 confirmations to mature.
 * If the wallet is underfunded (e.g. fresh Docker start with only 1 block),
 * mine 101 blocks so at least the first coinbase becomes spendable.
 */
export async function ensureBitcoindFunds(minBalance = 1.5): Promise<void> {
	const balance = (await bitcoinRpc('getbalance')) as number;
	if (balance < minBalance) {
		await mineBlocks(101);
	}
}

// ── Interop Node Factory ───────────────────────────────────────

/**
 * Create a beignet LightningNode configured for interop testing.
 * Uses deterministic keys from test mnemonic + unique derivation per seedId.
 */
export function createInteropNode(seedId = 42): LightningNode {
	// Derive unique keys for this seedId by using the mnemonic + a passphrase
	const passphrase = `interop-seed-${seedId}`;
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		passphrase,
		LnCoinType.REGTEST
	);

	const features = FeatureFlags.empty();
	features.setOptional(Feature.DATA_LOSS_PROTECT);
	features.setOptional(Feature.STATIC_REMOTE_KEY);
	features.setOptional(Feature.PAYMENT_SECRET);
	features.setOptional(Feature.TLV_ONION);
	features.setOptional(Feature.CHANNEL_TYPE);
	features.setOptional(Feature.GOSSIP_QUERIES);
	features.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	features.setOptional(Feature.QUIESCE);
	features.setOptional(Feature.SPLICE);
	features.setOptional(Feature.ROUTE_BLINDING);
	// option_simple_close (+ its BOLT 9 dependency). Odd bits — peers that
	// don't know them (CLN v24, stock LND) simply ignore them.
	features.setOptional(Feature.SHUTDOWN_ANY_SEGWIT);
	features.setOptional(Feature.SIMPLE_CLOSE);

	return new LightningNode({
		nodePrivateKey: keys.nodePrivateKey,
		channelBasepoints: keys.channelBasepoints,
		perCommitmentSeed: keys.perCommitmentSeed,
		fundingPrivkey: keys.fundingPrivkey,
		htlcBasepointSecret: keys.htlcBasepointSecret,
		network: Network.REGTEST,
		enableNetworking: true,
		localFeatures: features,
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true
	});
}

/**
 * Register a channel's SCIDs and add synthetic gossip graph entries
 * so beignet can route payments to a remote node via this channel.
 */
export function setupRoutingForChannel(
	node: LightningNode,
	remotePubkey: string
): void {
	const beignetNodeId = node.getNodeId();
	const channelManager = node.getChannelManager();
	const channels = channelManager.listChannels();

	if (channels.length === 0) return;

	const channelId = channels[0].getChannelId();
	if (!channelId) return;

	const fullState = channels[0].getFullState();
	if (fullState.scidAlias) {
		node.registerChannelScid(channelId, fullState.scidAlias);
	}
	if (fullState.remoteScidAlias) {
		node.registerChannelScid(channelId, fullState.remoteScidAlias);
	}

	// Add synthetic gossip entries
	const graph = node.getGraph();
	const remotePubBuf = Buffer.from(remotePubkey, 'hex');
	const nodePubBuf = Buffer.from(beignetNodeId, 'hex');
	const shortChannelId = fullState.shortChannelId || fullState.scidAlias;

	if (shortChannelId) {
		graph.addChannelAnnouncement({
			nodeSignature1: Buffer.alloc(64),
			nodeSignature2: Buffer.alloc(64),
			bitcoinSignature1: Buffer.alloc(64),
			bitcoinSignature2: Buffer.alloc(64),
			features: Buffer.alloc(0),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId,
			nodeId1:
				Buffer.compare(nodePubBuf, remotePubBuf) < 0
					? nodePubBuf
					: remotePubBuf,
			nodeId2:
				Buffer.compare(nodePubBuf, remotePubBuf) < 0
					? remotePubBuf
					: nodePubBuf,
			bitcoinKey1: Buffer.alloc(33),
			bitcoinKey2: Buffer.alloc(33)
		});

		const isNode1 = Buffer.compare(nodePubBuf, remotePubBuf) < 0;
		const ts = Math.floor(Date.now() / 1000);

		graph.applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId,
			timestamp: ts,
			messageFlags: 0x01,
			channelFlags: isNode1 ? 0 : 1,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 500_000_000n
		});

		graph.applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId,
			timestamp: ts,
			messageFlags: 0x01,
			channelFlags: isNode1 ? 1 : 0,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 500_000_000n
		});
	}
}

// ── Utilities ──────────────────────────────────────────────────

export function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Bitcoind Funding Provider ───────────────────────────────────

/**
 * IFundingProvider backed by bitcoind's wallet RPCs.
 * Implementation-agnostic — works with LND, CLN, and Eclair interop tests.
 */
export class BitcoindFundingProvider implements IFundingProvider {
	async buildFundingTransaction(
		address: string,
		amountSats: bigint
	): Promise<{ txHex: string; txid: Buffer; outputIndex: number }> {
		const amountBtc = Number(amountSats) / 1e8;

		const rawHex = (await bitcoinRpc('createrawtransaction', [
			[],
			[{ [address]: amountBtc }]
		])) as string;

		const funded = (await bitcoinRpc('fundrawtransaction', [rawHex])) as {
			hex: string;
			fee: number;
			changepos: number;
		};

		const signed = (await bitcoinRpc('signrawtransactionwithwallet', [
			funded.hex
		])) as {
			hex: string;
			complete: boolean;
		};

		if (!signed.complete) {
			throw new Error('bitcoind failed to fully sign funding transaction');
		}

		const tx = bitcoin.Transaction.fromHex(signed.hex);
		const targetScript = bitcoin.address.toOutputScript(
			address,
			bitcoin.networks.regtest
		);

		let outputIndex = -1;
		for (let i = 0; i < tx.outs.length; i++) {
			if (tx.outs[i].script.equals(targetScript)) {
				outputIndex = i;
				break;
			}
		}

		if (outputIndex < 0) {
			throw new Error(
				`Funding output not found in signed tx for address ${address}`
			);
		}

		const txid = Buffer.from(tx.getHash());
		return { txHex: signed.hex, txid, outputIndex };
	}

	async broadcastTransaction(txHex: string): Promise<string> {
		return (await bitcoinRpc('sendrawtransaction', [txHex])) as string;
	}

	// ── Anchor fee-bump support ──────────────────────────────────
	//
	// selectFeeBumpInputs needs to return inputs with a working signWitness
	// closure, so we hold our OWN P2WPKH keys (funded from bitcoind) rather than
	// trying to extract private keys from bitcoind's descriptor wallet. Call
	// prefundFeeInputs() before a force-close to stock the pool.

	private feeUtxos: Array<{
		priv: Buffer;
		pubkey: Buffer;
		prevTx: Buffer;
		vout: number;
		value: bigint;
		spent: boolean;
	}> = [];

	/** Fund `count` self-held P2WPKH UTXOs of `satsEach` from bitcoind's wallet. */
	async prefundFeeInputs(count: number, satsEach: number): Promise<void> {
		const ECPair = ECPairFactory(ecc);
		for (let i = 0; i < count; i++) {
			const priv = crypto.randomBytes(32);
			const keyPair = ECPair.fromPrivateKey(priv, {
				network: bitcoin.networks.regtest
			});
			const pubkey = Buffer.from(keyPair.publicKey);
			const address = bitcoin.payments.p2wpkh({
				pubkey,
				network: bitcoin.networks.regtest
			}).address!;
			const txid = (await bitcoinRpc('sendtoaddress', [
				address,
				satsEach / 1e8
			])) as string;
			await mineBlocks(1);
			const wtx = (await bitcoinRpc('gettransaction', [txid])) as {
				hex: string;
			};
			const tx = bitcoin.Transaction.fromHex(wtx.hex);
			const script = bitcoin.payments.p2wpkh({
				pubkey,
				network: bitcoin.networks.regtest
			}).output!;
			const vout = tx.outs.findIndex((o) => o.script.equals(script));
			if (vout < 0) throw new Error('prefundFeeInputs: funded vout not found');
			this.feeUtxos.push({
				priv,
				pubkey,
				prevTx: Buffer.from(tx.toBuffer()),
				vout,
				value: BigInt(tx.outs[vout].value),
				spent: false
			});
		}
	}

	async selectFeeBumpInputs(
		targetFeeSats: bigint,
		_feeratePerKw: number
	): Promise<{ inputs: ISpliceWalletInput[]; changeScript: Buffer }> {
		const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;
		const need = targetFeeSats + 10_000n; // generous buffer for input/change weight
		const chosen: typeof this.feeUtxos = [];
		let sum = 0n;
		for (const u of this.feeUtxos) {
			if (u.spent) continue;
			chosen.push(u);
			sum += u.value;
			if (sum >= need) break;
		}
		if (sum < need) {
			throw new Error(
				`selectFeeBumpInputs: insufficient prefunded inputs (have ${sum}, need ${need})`
			);
		}
		chosen.forEach((u) => {
			u.spent = true;
		});

		const inputs: ISpliceWalletInput[] = chosen.map((u) => {
			const scriptCode = bitcoin.payments.p2pkh({
				pubkey: u.pubkey,
				network: bitcoin.networks.regtest
			}).output!;
			return {
				prevTx: u.prevTx,
				prevOutputIndex: u.vout,
				value: u.value,
				sequence: 0xfffffffd,
				confirmed: true,
				signWitness: (
					tx: bitcoin.Transaction,
					inputIndex: number,
					value: bigint
				): Buffer[] => {
					const sighash = tx.hashForWitnessV0(
						inputIndex,
						scriptCode,
						Number(value),
						SIGHASH_ALL
					);
					const der = bitcoin.script.signature.encode(
						Buffer.from(ecc.sign(sighash, u.priv)),
						SIGHASH_ALL
					);
					return [der, u.pubkey];
				}
			};
		});

		const changeAddress = (await bitcoinRpc('getnewaddress', [
			'fee-bump-change',
			'bech32'
		])) as string;
		const changeScript = bitcoin.address.toOutputScript(
			changeAddress,
			bitcoin.networks.regtest
		);
		return { inputs, changeScript };
	}
}
