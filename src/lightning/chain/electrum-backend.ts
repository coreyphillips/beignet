/**
 * ElectrumBackend: Adapter wrapping beignet's Electrum class
 * to implement the IChainBackend interface for Lightning chain monitoring.
 */

import { IChainBackend } from './chain-watcher';
import { IFeeEstimator } from '../node/types';
import { Electrum } from '../../electrum';

/**
 * Wraps beignet's Electrum class to implement IChainBackend.
 *
 * This is a thin adapter — the underlying Electrum class handles
 * connection management, reconnection, and protocol details.
 */
export class ElectrumBackend implements IChainBackend, IFeeEstimator {
	private electrum: Electrum;
	private headerCallback: ((height: number) => void) | null = null;
	private subscribedScriptHashes: Map<string, () => void> = new Map();
	private _originalOnReceive: ((data: unknown) => void) | undefined = undefined;
	private _reconnectTimer: ReturnType<typeof setInterval> | null = null;
	/** Timeout in ms for individual Electrum RPC calls (default 30s) */
	readonly callTimeoutMs: number;
	/** Consecutive reconnect failures — used for failover signaling */
	private _consecutiveFailures = 0;
	/** Threshold of consecutive failures before emitting failover request */
	readonly failoverThreshold: number;
	/** Callback invoked when failover threshold is reached */
	onFailoverNeeded: ((consecutiveFailures: number) => void) | null = null;
	/** Callback invoked after subscriptions are (re)established on reconnect. */
	onResubscribed: (() => void) | null = null;

	constructor(
		electrum: Electrum,
		callTimeoutMs = 30_000,
		failoverThreshold = 3
	) {
		this.electrum = electrum;
		this.callTimeoutMs = callTimeoutMs;
		this.failoverThreshold = failoverThreshold;
	}

	/** Replace the underlying Electrum instance (used during failover) */
	setElectrum(electrum: Electrum): void {
		this.electrum = electrum;
		this._consecutiveFailures = 0;
		this._originalOnReceive = undefined;
	}

	getConsecutiveFailures(): number {
		return this._consecutiveFailures;
	}

	/**
	 * Race a promise against a timeout. Rejects with a descriptive error if timeout fires.
	 * The timeout timer is cleaned up in .finally() to prevent timer leaks.
	 */
	private withTimeout<T>(promise: Promise<T>, label: string): Promise<T> {
		let timer: ReturnType<typeof setTimeout>;
		const timeout = new Promise<never>((_, reject) => {
			timer = setTimeout(() => {
				reject(
					new Error(
						`Electrum call timed out after ${this.callTimeoutMs}ms: ${label}`
					)
				);
			}, this.callTimeoutMs);
		});
		return Promise.race([promise, timeout]).finally(() => {
			clearTimeout(timer);
		});
	}

	/**
	 * Re-subscribe all tracked script hashes and the header subscription.
	 * Call this after an Electrum reconnect to restore all subscriptions.
	 */
	async resubscribeAll(): Promise<void> {
		// Re-subscribe to headers
		if (this.headerCallback) {
			await this.subscribeToHeaders(this.headerCallback);
		}
		// Re-subscribe to all tracked script hashes
		for (const [scriptHash, onChange] of this.subscribedScriptHashes) {
			try {
				await this.withTimeout(
					this.electrum.subscribeToAddresses({
						scriptHashes: [scriptHash],
						onReceive: () => {
							onChange();
						}
					}),
					`resubscribe(${scriptHash.slice(0, 8)}...)`
				);
			} catch {
				// Swallow timeout errors — retry next interval
			}
		}

		// Subscriptions only fire on FUTURE changes, so a confirmation/spend that
		// landed while we were disconnected would be missed. Let the chain watcher
		// re-scan now that the connection is back.
		if (this.onResubscribed) {
			try {
				this.onResubscribed();
			} catch {
				/* best effort */
			}
		}
	}

	async subscribeToHeaders(
		onNewBlock: (height: number) => void
	): Promise<void> {
		this.headerCallback = onNewBlock;

		let result = await this.withTimeout(
			this.electrum.subscribeToHeader(),
			'subscribeToHeaders'
		);
		// Retry once after a short delay — the wallet's own header subscription
		// (fire-and-forget in connectToElectrum) may still be in-flight.
		if (result.isErr()) {
			await new Promise((r) => setTimeout(r, 1000));
			result = await this.withTimeout(
				this.electrum.subscribeToHeader(),
				'subscribeToHeaders(retry)'
			);
		}
		if (result.isErr()) {
			throw new Error(`Failed to subscribe to headers: ${result.error}`);
		}

		// Install stable delegate exactly once to prevent callback stacking on resubscribe
		if (!this._originalOnReceive) {
			this._originalOnReceive = this.electrum.onReceive;
			this.electrum.onReceive = (data: unknown) => {
				if (this._originalOnReceive) {
					this._originalOnReceive(data);
				}
				// Electrum header subscription data arrives as an array with { height, hex }
				if (
					Array.isArray(data) &&
					data.length > 0 &&
					typeof data[0]?.height === 'number'
				) {
					this.notifyNewBlock(data[0].height);
				}
			};
		}

		// Initial height from subscription result:
		const header = result.value;
		if (header && header.height) {
			onNewBlock(header.height);
		}

		// Auto-start reconnect monitor after successful header subscription
		if (!this._reconnectTimer) {
			this.startReconnectMonitor();
		}
	}

	/**
	 * Start a periodic reconnect monitor that pings the Electrum server.
	 * On failure, calls resubscribeAll() to restore all subscriptions.
	 */
	startReconnectMonitor(intervalMs = 30_000): void {
		this.stopReconnectMonitor();
		this._reconnectTimer = setInterval(async () => {
			try {
				// Lightweight ping: attempt to subscribe to header (no-op if already
				// subscribed). Wrapped in the call timeout — a hanging server (e.g.
				// Fulcrum mid-restart) must not stall the monitor itself.
				const result = await this.withTimeout(
					this.electrum.subscribeToHeader(),
					'reconnectMonitorPing'
				);
				if (result.isErr()) {
					this._consecutiveFailures++;
					if (
						this._consecutiveFailures >= this.failoverThreshold &&
						this.onFailoverNeeded
					) {
						this.onFailoverNeeded(this._consecutiveFailures);
					}
					await this.resubscribeAll();
				} else {
					this._consecutiveFailures = 0;
				}
			} catch {
				this._consecutiveFailures++;
				if (
					this._consecutiveFailures >= this.failoverThreshold &&
					this.onFailoverNeeded
				) {
					this.onFailoverNeeded(this._consecutiveFailures);
				}
				try {
					await this.resubscribeAll();
				} catch {
					// Resubscribe also failed — will retry next interval
				}
			}
		}, intervalMs);
		if (this._reconnectTimer.unref) {
			this._reconnectTimer.unref();
		}
	}

	/**
	 * Stop the reconnect monitor.
	 */
	stopReconnectMonitor(): void {
		if (this._reconnectTimer) {
			clearInterval(this._reconnectTimer);
			this._reconnectTimer = null;
		}
	}

	/**
	 * Forward a new block notification from the Electrum subscription.
	 * Call this from the Electrum onReceive callback when a new block arrives.
	 */
	notifyNewBlock(height: number): void {
		if (this.headerCallback) {
			this.headerCallback(height);
		}
	}

	/**
	 * Remove a script hash from the tracked set (memory cleanup).
	 * Does not unsubscribe at the Electrum protocol level (no such command),
	 * but prevents re-subscription on reconnect and frees the callback.
	 */
	unsubscribeScriptHash(scriptHash: string): boolean {
		return this.subscribedScriptHashes.delete(scriptHash);
	}

	async subscribeToScriptHash(
		scriptHash: string,
		onChange: () => void
	): Promise<void> {
		// Track for re-subscription on reconnect
		this.subscribedScriptHashes.set(scriptHash, onChange);
		const result = await this.withTimeout(
			this.electrum.subscribeToAddresses({
				scriptHashes: [scriptHash],
				onReceive: () => {
					onChange();
				}
			}),
			`subscribeToScriptHash(${scriptHash.slice(0, 8)}...)`
		);
		if (result.isErr()) {
			throw new Error(`Failed to subscribe to script hash: ${result.error}`);
		}
	}

	async getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>> {
		const result = await this.withTimeout(
			this.electrum.getAddressScriptHashesHistory([scriptHash]),
			`getScriptHashHistory(${scriptHash.slice(0, 8)}...)`
		);
		if (result.isErr()) {
			throw new Error(`Failed to get script hash history: ${result.error}`);
		}

		const response = result.value;
		const history: Array<{ txid: string; height: number }> = [];

		if (response.data && Array.isArray(response.data)) {
			for (const entry of response.data) {
				if (entry.result && Array.isArray(entry.result)) {
					for (const tx of entry.result) {
						history.push({
							txid: tx.tx_hash,
							height: tx.height ?? 0
						});
					}
				}
			}
		}

		return history;
	}

	/**
	 * List unspent outputs for a script hash (Electrum
	 * blockchain.scripthash.listunspent). Used to recover funds that landed at
	 * non-wallet scripts the node controls, e.g. force-close sweeps paid to the
	 * funding-key fallback address.
	 */
	async listUnspent(scriptHash: string): Promise<
		Array<{
			txid: string;
			outputIndex: number;
			valueSat: number;
			height: number;
		}>
	> {
		// Don't probe a not-yet-open / dropped socket. The underlying
		// rn-electrum-client helper logs the raw rejection (a "Connection to
		// server lost" stack trace) to the console before resolving an error
		// Result, which is alarming noise during the startup connect window.
		// Fail fast with a clean error instead; callers treat this as
		// "nothing to do for now" and retry once connected.
		if (!this.electrum.connectedToElectrum) {
			throw new Error('Electrum not connected');
		}
		const result = await this.withTimeout(
			this.electrum.listUnspentAddressScriptHashes({
				addresses: {
					[scriptHash]: {
						index: 0,
						path: '',
						address: '',
						scriptHash,
						publicKey: ''
					}
				}
			}),
			`listUnspent(${scriptHash.slice(0, 8)}...)`
		);
		if (result.isErr()) {
			throw new Error(`Failed to list unspent: ${result.error}`);
		}
		return (result.value.utxos || []).map((u) => ({
			txid: u.tx_hash,
			outputIndex: u.tx_pos,
			valueSat: u.value,
			height: u.height
		}));
	}

	async getTransaction(txid: string): Promise<Buffer> {
		const result = await this.withTimeout(
			this.electrum.getTransactions({
				txHashes: [{ tx_hash: txid }]
			}),
			`getTransaction(${txid.slice(0, 8)}...)`
		);
		if (result.isErr()) {
			throw new Error(`Failed to get transaction ${txid}: ${result.error}`);
		}

		const response = result.value;
		if (!response.data || response.data.length === 0) {
			throw new Error(`Transaction ${txid} not found`);
		}

		const txData = response.data[0];
		const hex = txData.result?.hex;
		if (!hex) {
			throw new Error(`No hex data for transaction ${txid}`);
		}

		return Buffer.from(hex, 'hex');
	}

	async getTransactionMerkleProof(
		txid: string,
		height: number
	): Promise<{ blockHeight: number; txIndex: number }> {
		const result = await this.withTimeout(
			this.electrum.getTransactionMerkle({ tx_hash: txid, height }),
			`getTransactionMerkleProof(${txid.slice(0, 8)}...)`
		);
		// rn-electrum-client wraps responses: { id, error, method, data: { pos, ... }, network }
		// The TypeScript declaration claims { merkle, block_height, pos } but runtime wraps it
		const res = result as any;
		const pos = res?.data?.pos ?? res?.pos ?? 0;
		return {
			blockHeight: height,
			txIndex: pos
		};
	}

	/**
	 * Estimate fee rate in sat/vByte for a given confirmation target.
	 * Uses the wallet's fee estimates (sourced from mempool.space or fallback).
	 * Returns -1 if unavailable.
	 */
	async estimateFee(targetBlocks: number): Promise<number> {
		try {
			const wallet = this.electrum.wallet;
			if (!wallet) return -1;
			const fees = wallet.feeEstimates;
			if (!fees) return -1;
			// Map target blocks to fee tier: <=2 = fast, <=6 = normal, >6 = slow
			if (targetBlocks <= 2) return fees.fast > 0 ? fees.fast : -1;
			if (targetBlocks <= 6) return fees.normal > 0 ? fees.normal : -1;
			return fees.slow > 0 ? fees.slow : -1;
		} catch {
			return -1;
		}
	}

	async broadcastTransaction(rawTxHex: string): Promise<string> {
		const result = await this.withTimeout(
			this.electrum.broadcastTransaction({
				rawTx: rawTxHex,
				subscribeToOutputAddress: false
			}),
			'broadcastTransaction'
		);
		if (result.isErr()) {
			throw new Error(`Failed to broadcast transaction: ${result.error}`);
		}

		return result.value;
	}
}
