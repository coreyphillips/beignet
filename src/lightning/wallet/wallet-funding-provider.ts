/**
 * Wallet funding provider adapter.
 *
 * Wraps the beignet Wallet class to implement IFundingProvider,
 * enabling LightningNode to auto-fund channels from the on-chain wallet.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { IFundingProvider } from '../node/types';
import { ISpliceWalletInput } from '../channel/channel';
import {
	estimateSpliceTxWeight,
	spliceFeeSats,
	outputWeight,
	P2WPKH_INPUT_WEIGHT,
	P2WPKH_DUST_LIMIT
} from '../channel/splice-weight';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

/**
 * Minimal Result-like interface matching beignet's Result<T> union type.
 * Both Ok and Err satisfy this via structural typing.
 */
interface IResult {
	isErr(): boolean;
	isOk(): boolean;
}

interface IResultOk<T> extends IResult {
	value: T;
}

interface IResultErr extends IResult {
	error: { message: string };
}

/** A wallet UTXO, shaped like beignet's IUtxo (only the fields we need). */
export interface ISpliceUtxo {
	address: string;
	path: string;
	/** Txid in big-endian (display/electrum) hex. */
	tx_hash: string;
	tx_pos: number;
	/** Value in satoshis. */
	value: number;
	/** Confirmation height; 0 = unconfirmed. */
	height: number;
	publicKey: string;
}

/**
 * Minimal wallet interface — only the methods we need.
 * Structurally compatible with beignet's Wallet class without
 * requiring an import dependency on it.
 *
 * The splice-in members (listUtxos, getPrivateKey, getChangeAddress,
 * electrum.getTransactions) are optional: channel auto-funding works without
 * them, and selectSpliceInputs throws a descriptive error if they are missing.
 */
export interface IWalletLike {
	send(params: {
		address: string;
		amount: number;
		satsPerByte?: number;
		broadcast?: boolean;
		shuffleOutputs?: boolean;
	}): Promise<IResult>;
	/**
	 * Sweep the whole spendable balance to `address` (no change output). Used to
	 * fund a "max" channel: the funding output then equals inputs minus fee, which
	 * is exactly the amount the sweep quote computed, so it matches the committed
	 * funding_satoshis. Optional so minimal/legacy wallets can omit it; a max
	 * funding request against a wallet without it is rejected rather than guessed.
	 */
	sendMax?(params: {
		address: string;
		satsPerByte?: number;
		broadcast?: boolean;
	}): Promise<IResult>;
	electrum: {
		broadcastTransaction(params: {
			rawTx: string;
			subscribeToOutputAddress?: boolean;
		}): Promise<IResult>;
		getTransactions?(params: {
			txHashes: Array<{ tx_hash: string }>;
		}): Promise<IResult>;
	};
	listUtxos?(): ISpliceUtxo[];
	/** Returns the WIF-encoded private key for a derivation path. */
	getPrivateKey?(path: string): string;
	/** Returns Result<{ address: string }>. */
	getChangeAddress?(): Promise<IResult>;
	/** 'bitcoin' | 'testnet' | 'regtest' (beignet EAvailableNetworks). */
	network?: string;
}

/**
 * Adapts a beignet Wallet into an IFundingProvider for LightningNode.
 *
 * Usage:
 *   const wallet = (await Wallet.create({ mnemonic, electrumOptions })).value;
 *   const fundingProvider = new WalletFundingProvider(wallet);
 *   const node = LightningNode.fromMnemonic(mnemonic, { fundingProvider });
 *   node.openChannel(peerPubkey, 100_000n); // fully automatic
 */
export class WalletFundingProvider implements IFundingProvider {
	private wallet: IWalletLike;

	constructor(wallet: IWalletLike) {
		this.wallet = wallet;
	}

	async buildFundingTransaction(
		address: string,
		amountSats: bigint,
		satsPerByte?: number,
		max = false
	): Promise<{ txHex: string; txid: Buffer; outputIndex: number }> {
		let result: IResult;
		if (max) {
			// A max channel sweeps the whole balance into the funding output. Funding
			// it as a fixed-amount send instead adds a change output whose fee the
			// swept balance cannot cover, so the fixed path fails at the exact max
			// ("New total amount exceeds the available balance"). Sweeping produces a
			// no-change tx whose output is inputs minus fee, i.e. the amount the
			// caller already committed as funding_satoshis.
			if (!this.wallet.sendMax) {
				throw new Error(
					'Wallet does not support max funding (sendMax unavailable)'
				);
			}
			result = await this.wallet.sendMax({
				address,
				broadcast: false,
				...(satsPerByte !== undefined ? { satsPerByte } : {})
			});
		} else {
			const sendParams: {
				address: string;
				amount: number;
				broadcast: boolean;
				shuffleOutputs: boolean;
				satsPerByte?: number;
			} = {
				address,
				amount: Number(amountSats),
				broadcast: false,
				shuffleOutputs: true
			};
			if (satsPerByte !== undefined) {
				sendParams.satsPerByte = satsPerByte;
			}
			result = await this.wallet.send(sendParams);
		}
		if (result.isErr()) {
			throw new Error(
				`Wallet send failed: ${(result as IResultErr).error.message}`
			);
		}

		const txHex = (result as IResultOk<string>).value;
		const tx = bitcoin.Transaction.fromHex(txHex);

		// Find the output that pays to the P2WSH funding address
		const targetScript = bitcoin.address.toOutputScript(
			address,
			this.detectNetwork(address)
		);
		let outputIndex = -1;
		for (let i = 0; i < tx.outs.length; i++) {
			if (tx.outs[i].script.equals(targetScript)) {
				outputIndex = i;
				break;
			}
		}

		if (outputIndex === -1) {
			throw new Error('Funding output not found in transaction');
		}

		// The commitment is built against the committed funding_satoshis, so the
		// on-chain funding output must equal it exactly. A max sweep is priced from
		// the same balance and rate as the amount already committed, so they match;
		// guard the rare drift (a UTXO arriving or spent between quote and funding)
		// rather than sign a commitment against a mismatched output.
		if (max) {
			const fundedValue = tx.outs[outputIndex].value;
			if (fundedValue !== Number(amountSats)) {
				throw new Error(
					`Max funding output (${fundedValue} sats) does not match committed funding amount (${amountSats} sats); on-chain balance changed since the amount was quoted`
				);
			}
		}

		// getHash() returns txid in internal byte order (per BOLT 2)
		const txid = Buffer.from(tx.getHash());

		return { txHex, txid, outputIndex };
	}

	async broadcastTransaction(txHex: string): Promise<string> {
		const result = await this.wallet.electrum.broadcastTransaction({
			rawTx: txHex
		});
		if (result.isErr()) {
			throw new Error(
				`Broadcast failed: ${(result as IResultErr).error.message}`
			);
		}
		return (result as IResultOk<string>).value;
	}

	/**
	 * Source wallet inputs + a change script for a splice-in.
	 *
	 * Selects P2WPKH UTXOs (confirmed first, largest first) until they cover
	 * amount + the splice tx fee — computed with the SAME weight formula the
	 * channel uses (the channel derives change = walletTotal - amount - fee, so
	 * under-selection would produce an underfunded splice tx). Each input
	 * carries a signWitness closure so wallet keys never leave this method.
	 */
	async selectSpliceInputs(
		amountSats: bigint,
		feeratePerKw: number
	): Promise<{ inputs: ISpliceWalletInput[]; changeScript: Buffer }> {
		// Cover the splice amount plus the splice tx fee, recomputed per added
		// input using the SAME weight formula the channel uses to derive change.
		return this.gatherWalletInputs(
			'splice-in',
			(selectedCount) =>
				amountSats +
				spliceFeeSats(
					estimateSpliceTxWeight({
						walletInputCount: selectedCount,
						changeScriptLen: 22
					}),
					feeratePerKw
				)
		);
	}

	/**
	 * Source wallet inputs + a change script to fund an anchor fee bump.
	 *
	 * `targetFeeSats` is the fee the bumped tx must pay excluding the wallet's own
	 * inputs/change; we add the marginal fee of those inputs (and one P2WPKH
	 * change output) plus a dust buffer so the chain layer can finalise a
	 * non-dust change. Inputs reuse the same P2WPKH signWitness recipe as
	 * splice-in (SIGHASH_ALL; keys never leave the closure).
	 */
	async selectFeeBumpInputs(
		targetFeeSats: bigint,
		feeratePerKw: number
	): Promise<{ inputs: ISpliceWalletInput[]; changeScript: Buffer }> {
		return this.gatherWalletInputs(
			'fee-bump',
			(selectedCount) =>
				targetFeeSats +
				spliceFeeSats(
					selectedCount * P2WPKH_INPUT_WEIGHT + outputWeight(22),
					feeratePerKw
				) +
				P2WPKH_DUST_LIMIT
		);
	}

	/**
	 * The UTXOs a splice-in (or fee bump) may spend: P2WPKH only, since the
	 * signing recipe in gatherWalletInputs is P2WPKH-specific. Confirmed before
	 * unconfirmed, then largest first within each group.
	 */
	private spendableP2wpkhUtxos(): ISpliceUtxo[] {
		if (!this.wallet.listUtxos) return [];
		const network = this.bitcoinJsNetwork();
		const candidates = this.wallet.listUtxos().filter((u) => {
			try {
				return bitcoin.address.toOutputScript(u.address, network).length === 22;
			} catch {
				return false;
			}
		});
		candidates.sort((a, b) => {
			const aConf = a.height > 0 ? 0 : 1;
			const bConf = b.height > 0 ? 0 : 1;
			if (aConf !== bConf) return aConf - bConf;
			return b.value - a.value;
		});
		return candidates;
	}

	/**
	 * Price a splice-in without performing one: what the wallet could add to a
	 * channel at this feerate. Uses the SAME UTXO filter and weight formula as
	 * selectSpliceInputs, so the quoted maximum is an amount the selection will
	 * actually fund rather than a guess reconstructed in a UI. The maximum
	 * sweeps every spendable UTXO; the change output the weight includes is
	 * dropped as dust by the channel, a slight, safe overestimate of the fee.
	 */
	quoteSpliceIn(feeratePerKw: number): {
		spendableSats: bigint;
		feeSats: bigint;
		maxAmountSats: bigint;
		inputCount: number;
	} {
		const candidates = this.spendableP2wpkhUtxos();
		const spendableSats = candidates.reduce((s, u) => s + BigInt(u.value), 0n);
		const feeSats = spliceFeeSats(
			estimateSpliceTxWeight({
				walletInputCount: Math.max(1, candidates.length),
				changeScriptLen: 22
			}),
			feeratePerKw
		);
		const maxAmountSats =
			spendableSats > feeSats ? spendableSats - feeSats : 0n;
		return {
			spendableSats,
			feeSats,
			maxAmountSats,
			inputCount: candidates.length
		};
	}

	/**
	 * Shared P2WPKH UTXO selection used by splice-in and fee bumping.
	 *
	 * Selects confirmed-first, largest-first until the running total covers
	 * `computeTarget(selectedCount)` — recomputed per added input because each
	 * input grows the tx (and thus the fee). Each returned input carries a
	 * signWitness closure so wallet keys never leave this method.
	 */
	private async gatherWalletInputs(
		purpose: string,
		computeTarget: (selectedCount: number) => bigint
	): Promise<{ inputs: ISpliceWalletInput[]; changeScript: Buffer }> {
		const wallet = this.wallet;
		if (
			!wallet.listUtxos ||
			!wallet.getPrivateKey ||
			!wallet.getChangeAddress ||
			!wallet.electrum.getTransactions
		) {
			throw new Error(
				`wallet does not support ${purpose} (requires listUtxos, getPrivateKey, getChangeAddress and electrum.getTransactions)`
			);
		}

		const candidates = this.spendableP2wpkhUtxos();
		const network = this.bitcoinJsNetwork();

		const selected: ISpliceUtxo[] = [];
		let selectedSum = 0n;
		let target = 0n;
		for (const utxo of candidates) {
			selected.push(utxo);
			selectedSum += BigInt(utxo.value);
			// Each added input grows the tx (and thus the fee) — recompute.
			target = computeTarget(selected.length);
			if (selectedSum >= target) break;
		}
		if (selectedSum < target || selected.length === 0) {
			const have = candidates.reduce((s, u) => s + BigInt(u.value), 0n);
			throw new Error(
				`insufficient wallet funds for ${purpose}: need ${
					target > 0n ? target : 0n
				} sats (amount + fee), have ${have} sats in spendable P2WPKH UTXOs`
			);
		}

		// Fetch the raw previous transactions in one batch.
		const txResult = await wallet.electrum.getTransactions({
			txHashes: selected.map((u) => ({ tx_hash: u.tx_hash }))
		});
		if (txResult.isErr()) {
			throw new Error(
				`failed to fetch ${purpose} prev txs: ${
					(txResult as IResultErr).error.message
				}`
			);
		}
		const txData = (
			txResult as IResultOk<{
				data: Array<{
					data: { tx_hash: string };
					result: { hex?: string; txid?: string };
				}>;
			}>
		).value;
		const hexByTxid = new Map<string, string>();
		for (const entry of txData.data || []) {
			const txid = entry.result?.txid || entry.data?.tx_hash;
			if (txid && entry.result?.hex) hexByTxid.set(txid, entry.result.hex);
		}

		const inputs: ISpliceWalletInput[] = selected.map((utxo) => {
			const hex = hexByTxid.get(utxo.tx_hash);
			if (!hex) {
				throw new Error(`missing raw tx for ${purpose} input ${utxo.tx_hash}`);
			}
			const keyPair = ECPair.fromWIF(wallet.getPrivateKey!(utxo.path), network);
			const pubkey = Buffer.from(keyPair.publicKey);
			if (pubkey.toString('hex') !== utxo.publicKey) {
				throw new Error(
					`derived key mismatch for ${purpose} input ${utxo.tx_hash}:${utxo.tx_pos}`
				);
			}
			const privKey = Buffer.from(keyPair.privateKey!);
			const scriptCode = bitcoin.payments.p2pkh({ pubkey, network }).output!;

			return {
				prevTx: Buffer.from(hex, 'hex'),
				prevOutputIndex: utxo.tx_pos,
				value: BigInt(utxo.value),
				sequence: 0xfffffffd,
				confirmed: utxo.height > 0,
				signWitness: (
					tx: bitcoin.Transaction,
					inputIndex: number,
					value: bigint
				): Buffer[] => {
					const sighash = tx.hashForWitnessV0(
						inputIndex,
						scriptCode,
						Number(value),
						bitcoin.Transaction.SIGHASH_ALL
					);
					const sig64 = Buffer.from(ecc.sign(sighash, privKey));
					const der = bitcoin.script.signature.encode(
						sig64,
						bitcoin.Transaction.SIGHASH_ALL
					);
					return [der, pubkey];
				}
			};
		});

		const changeRes = await wallet.getChangeAddress();
		if (changeRes.isErr()) {
			throw new Error(
				`failed to get change address: ${
					(changeRes as IResultErr).error.message
				}`
			);
		}
		const changeAddress = (changeRes as IResultOk<{ address: string }>).value
			.address;
		const changeScript = bitcoin.address.toOutputScript(changeAddress, network);

		return { inputs, changeScript };
	}

	/**
	 * Map the wallet's network name to a bitcoinjs-lib network.
	 */
	private bitcoinJsNetwork(): bitcoin.Network {
		switch (this.wallet.network) {
			case 'bitcoin':
				return bitcoin.networks.bitcoin;
			case 'testnet':
				return bitcoin.networks.testnet;
			case 'regtest':
				return bitcoin.networks.regtest;
			default:
				return bitcoin.networks.regtest;
		}
	}

	/**
	 * Detect the bitcoin network from a bech32 address prefix.
	 */
	private detectNetwork(address: string): bitcoin.Network {
		if (address.startsWith('bc1')) return bitcoin.networks.bitcoin;
		if (address.startsWith('tb1')) return bitcoin.networks.testnet;
		if (address.startsWith('bcrt1')) return bitcoin.networks.regtest;
		return bitcoin.networks.regtest;
	}
}
