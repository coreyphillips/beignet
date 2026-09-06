/**
 * Swap chain resolver (issue #737, phase 2): what the chain says about one
 * swap contract, as facts. It finds the funding output, every spend of it,
 * classifies each spend (a claim with its extracted preimage, a refund, or
 * something else), tracks confirmations against the operator's policy, and
 * notices when a fact it was told last time is no longer on the chain.
 *
 * It never decides. The ledger records, the engine acts; this module only
 * answers `observe`, and every transaction it returns was fetched by txid
 * and checked to hash to that txid, so a backend answering with the wrong
 * bytes cannot plant a fact.
 *
 * Restart rule: `verifiedThisSession` is false for a contract until the
 * first observation completes after construction. An engine must not count
 * a recorded confirmation depth toward its policy until then; the recorded
 * fact might have been reorged away while the node was down.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { computeScriptHash } from '../chain/chain-watcher';
import { buildSwapHtlc, ISwapHtlc } from './htlc';
import { extractSwapPreimage } from './transactions';
import { SwapResolutionKind } from './ledger';

/** The narrow chain view a swap engine needs; IChainBackend satisfies it. */
export interface ISwapChainSource {
	currentHeight(): number;
	getTransaction(txid: string): Promise<Buffer>;
	/** Electrum shape: height 0 means the mempool. */
	getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>>;
	listUnspent?(scriptHash: string): Promise<
		Array<{
			txid: string;
			outputIndex: number;
			valueSat: number;
			height: number;
		}>
	>;
	broadcastTransaction(rawTxHex: string): Promise<string>;
}

export interface ISwapConfirmationPolicy {
	/** Depth a funding output needs before the provider relies on it. */
	fundingConfirmations: number;
	/** Depth a spend needs before the provider treats it as the outcome. */
	resolutionConfirmations: number;
}

export function validateSwapConfirmationPolicy(
	policy: ISwapConfirmationPolicy
): void {
	for (const [name, value] of [
		['fundingConfirmations', policy.fundingConfirmations],
		['resolutionConfirmations', policy.resolutionConfirmations]
	] as const) {
		if (!Number.isSafeInteger(value) || value < 1) {
			throw new Error(`${name} must be a positive integer`);
		}
	}
}

export type SwapFundingStatus =
	| { kind: 'absent' }
	| { kind: 'mempool'; tx: bitcoin.Transaction; valueSat: bigint }
	| {
			kind: 'confirmed';
			tx: bitcoin.Transaction;
			valueSat: bigint;
			height: number;
			confirmations: number;
			meetsPolicy: boolean;
	  }
	| { kind: 'reorged-out'; previousHeight: number; tx?: bitcoin.Transaction };

export interface ISwapSpendObservation {
	txid: string;
	tx: bitcoin.Transaction;
	/** 0 while in the mempool. */
	height: number;
	confirmations: number;
	kind: SwapResolutionKind;
	/** Only for a claim: the preimage extractSwapPreimage verified. */
	preimage?: Buffer;
	meetsPolicy: boolean;
}

/** An output paying the contract script, for a swap whose funding we await. */
export interface ISwapFundingCandidate {
	txid: string;
	vout: number;
	valueSat: bigint;
	height: number;
}

export interface ISwapChainObservation {
	height: number;
	funding: SwapFundingStatus;
	/** Every spend of the funding outpoint the history shows, any depth. */
	spends: ISwapSpendObservation[];
	/** The confirmed spend with the greatest depth, if any. */
	winning?: ISwapSpendObservation;
	/** A recorded resolution the chain no longer shows at its recorded height. */
	demoted?: { previousTxid: string; previousHeight?: number };
	/** Outputs paying the contract, when no funding outpoint was given. */
	candidates: ISwapFundingCandidate[];
	verifiedThisSession: boolean;
}

export interface ISwapObserveParams {
	htlc: ISwapHtlc;
	/** The funding outpoint once known; omitted to discover candidates. */
	funding?: { txid: string; vout: number };
	recorded?: {
		fundingHeight?: number;
		resolutionTxid?: string;
		resolutionHeight?: number;
	};
}

const TX_CACHE_LIMIT = 512;

export class SwapChainResolver {
	private readonly txCache = new Map<string, bitcoin.Transaction>();
	private readonly verified = new Set<string>();

	constructor(
		private readonly source: ISwapChainSource,
		private readonly policy: ISwapConfirmationPolicy,
		private readonly network: bitcoin.Network = bitcoin.networks.bitcoin
	) {
		validateSwapConfirmationPolicy(policy);
	}

	/** Broadcast and insist the backend acknowledged these exact bytes. */
	async broadcast(rawTxHex: string): Promise<string> {
		const expected = bitcoin.Transaction.fromHex(rawTxHex).getId();
		const reported = await this.source.broadcastTransaction(rawTxHex);
		if (reported !== expected) {
			throw new Error(
				`Broadcast returned txid ${reported}, expected ${expected}`
			);
		}
		return expected;
	}

	async observe(params: ISwapObserveParams): Promise<ISwapChainObservation> {
		const { witnessScript, outputScript } = buildSwapHtlc(
			params.htlc,
			this.network
		);
		const scriptHash = computeScriptHash(outputScript);
		const height = this.source.currentHeight();
		const history = await this.source.getScriptHashHistory(scriptHash);
		const key = params.funding
			? `${params.funding.txid}:${params.funding.vout}`
			: scriptHash;
		const verifiedThisSession = this.verified.has(key);

		const candidates: ISwapFundingCandidate[] = [];
		let funding: SwapFundingStatus = { kind: 'absent' };
		let fundingTx: bitcoin.Transaction | undefined;

		if (params.funding) {
			const entry = history.find((h) => h.txid === params.funding!.txid);
			if (entry) {
				fundingTx = await this.fetch(entry.txid);
				const out = fundingTx.outs[params.funding.vout];
				if (!out || !out.script.equals(outputScript)) {
					throw new Error(
						`Funding ${params.funding.txid}:${params.funding.vout} does not pay the swap contract`
					);
				}
				const valueSat = BigInt(out.value);
				if (entry.height > 0) {
					const confirmations = height - entry.height + 1;
					funding = {
						kind: 'confirmed',
						tx: fundingTx,
						valueSat,
						height: entry.height,
						confirmations,
						meetsPolicy: confirmations >= this.policy.fundingConfirmations
					};
				} else if (params.recorded?.fundingHeight) {
					funding = {
						kind: 'reorged-out',
						previousHeight: params.recorded.fundingHeight,
						tx: fundingTx
					};
				} else {
					funding = { kind: 'mempool', tx: fundingTx, valueSat };
				}
			} else if (params.recorded?.fundingHeight) {
				funding = {
					kind: 'reorged-out',
					previousHeight: params.recorded.fundingHeight
				};
			}
		} else {
			for (const entry of history) {
				const tx = await this.fetch(entry.txid);
				tx.outs.forEach((out, vout) => {
					if (out.script.equals(outputScript)) {
						candidates.push({
							txid: entry.txid,
							vout,
							valueSat: BigInt(out.value),
							height: entry.height
						});
					}
				});
			}
		}

		const spends: ISwapSpendObservation[] = [];
		if (params.funding && fundingTx) {
			const fundingHash = fundingTx.getHash();
			const outputIndex = params.funding.vout;
			for (const entry of history) {
				if (entry.txid === params.funding.txid) continue;
				const tx = await this.fetch(entry.txid);
				const inputIndex = tx.ins.findIndex(
					(input) =>
						input.hash.equals(fundingHash) && input.index === outputIndex
				);
				if (inputIndex < 0) continue;
				const preimage = extractSwapPreimage(tx, {
					htlc: params.htlc,
					fundingTransaction: fundingTx,
					outputIndex
				});
				let kind: SwapResolutionKind = 'unknown';
				if (preimage) {
					kind = 'claim';
				} else {
					const witness = tx.ins[inputIndex].witness;
					if (
						witness.length === 3 &&
						witness[1].length === 0 &&
						witness[2].equals(witnessScript)
					) {
						kind = 'refund';
					}
				}
				const confirmations = entry.height > 0 ? height - entry.height + 1 : 0;
				spends.push({
					txid: entry.txid,
					tx,
					height: entry.height,
					confirmations,
					kind,
					preimage,
					meetsPolicy: confirmations >= this.policy.resolutionConfirmations
				});
			}
		}

		let winning: ISwapSpendObservation | undefined;
		for (const spend of spends) {
			if (spend.height === 0) continue;
			if (!winning || spend.confirmations > winning.confirmations) {
				winning = spend;
			}
		}

		let demoted: ISwapChainObservation['demoted'];
		if (params.recorded?.resolutionTxid) {
			const seen = spends.find(
				(s) => s.txid === params.recorded!.resolutionTxid
			);
			const recordedHeight = params.recorded.resolutionHeight;
			if (
				!seen ||
				(recordedHeight !== undefined &&
					recordedHeight > 0 &&
					seen.height !== recordedHeight)
			) {
				demoted = {
					previousTxid: params.recorded.resolutionTxid,
					previousHeight: recordedHeight
				};
			}
		}

		this.verified.add(key);
		return {
			height,
			funding,
			spends,
			winning,
			demoted,
			candidates,
			verifiedThisSession
		};
	}

	/** Fetch by txid and refuse bytes that do not hash to it. */
	private async fetch(txid: string): Promise<bitcoin.Transaction> {
		const cached = this.txCache.get(txid);
		if (cached) return cached;
		const raw = await this.source.getTransaction(txid);
		const tx = bitcoin.Transaction.fromBuffer(raw);
		if (tx.getId() !== txid) {
			throw new Error(
				`Chain source returned transaction ${tx.getId()} for ${txid}`
			);
		}
		if (this.txCache.size >= TX_CACHE_LIMIT) {
			const oldest = this.txCache.keys().next().value;
			if (oldest !== undefined) this.txCache.delete(oldest);
		}
		this.txCache.set(txid, tx);
		return tx;
	}
}
