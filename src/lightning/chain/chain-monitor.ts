/**
 * BOLT 5: Chain Monitor state machine.
 *
 * Receives blockchain events (funding spent, new block, output spent, reorg)
 * and returns ChainAction[] — never talks to a real blockchain directly.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';
import {
	ChainAction,
	ChainActionType,
	MonitorState,
	CommitmentType,
	OutputStatus,
	OutputType,
	ITrackedOutput,
	ICommitmentBroadcast,
	IRREVOCABLE_DEPTH
} from './types';
import {
	classifyCommitmentTx,
	classifyOutputs,
	resolveOurCommitmentOutputs,
	resolveTheirCurrentCommitmentOutputs,
	resolveRevokedCommitmentOutputs
} from './output-resolver';
import { estimateSweepVbytes } from './sweep';
import { IChannelState } from '../channel/channel-state';
import { isAnchorChannel } from '../channel/types';

/** Number of blocks before re-broadcasting unconfirmed sweeps */
const REBROADCAST_INTERVAL = 6;
/** Fee bump multiplier for re-broadcast */
const FEE_BUMP_FACTOR = 1.5;
/** Maximum fee bump multiplier relative to original rate */
const MAX_FEE_BUMP_MULTIPLIER = 10;

bitcoin.initEccLib(ecc);

/**
 * Serializable state for the ChainMonitor.
 */
export interface IChainMonitorState {
	monitorState: MonitorState;
	commitmentBroadcast: ICommitmentBroadcast | null;
	trackedOutputs: ITrackedOutput[];
	currentBlockHeight: number;
	/** Persisted preimages for HTLC claims (paymentHashHex → preimageHex) */
	knownPreimages?: Record<string, string>;
}

/**
 * Stateful component that tracks on-chain commitment lifecycle.
 * Receives blockchain events, produces ChainAction[].
 */
export class ChainMonitor {
	private _state: MonitorState = MonitorState.WATCHING;
	private _channelState: IChannelState;
	private _destinationScript: Buffer;
	private _feeRatePerVbyte: number;
	private _revocationBasepointSecret: Buffer;
	private _paymentPrivkey: Buffer;
	private _delayedPaymentBasepointSecret: Buffer | undefined;
	private _htlcBasepointSecret: Buffer | undefined;
	private _network: bitcoin.Network;

	private _commitmentBroadcast: ICommitmentBroadcast | null = null;
	private _trackedOutputs: ITrackedOutput[] = [];
	private _currentBlockHeight = 0;
	private _knownPreimages: Map<string, Buffer> = new Map();

	constructor(
		channelState: IChannelState,
		destinationScript: Buffer,
		feeRatePerVbyte: number,
		revocationBasepointSecret: Buffer,
		paymentPrivkey: Buffer,
		network: bitcoin.Network = bitcoin.networks.bitcoin,
		delayedPaymentBasepointSecret?: Buffer,
		htlcBasepointSecret?: Buffer
	) {
		this._channelState = channelState;
		this._destinationScript = destinationScript;
		this._feeRatePerVbyte = feeRatePerVbyte;
		this._revocationBasepointSecret = revocationBasepointSecret;
		this._paymentPrivkey = paymentPrivkey;
		this._delayedPaymentBasepointSecret = delayedPaymentBasepointSecret;
		this._htlcBasepointSecret = htlcBasepointSecret;
		this._network = network;
	}

	/**
	 * Update the destination script that sweeps pay into. Used when a
	 * wallet-owned address becomes available after construction (e.g. once
	 * Electrum connects), so recovered funds land in the tracked wallet rather
	 * than the funding-key fallback. Affects future sweeps AND rebuilds any
	 * already-built sweep still held for CSV/CLTV maturity (not yet broadcast),
	 * so held funds are also redirected to the new destination.
	 */
	setDestinationScript(destinationScript: Buffer): void {
		if (this._destinationScript.equals(destinationScript)) return;
		this._destinationScript = destinationScript;
		this._rebuildHeldSweeps();
	}

	/**
	 * Rebuild sweeps that are built but still held for timelock maturity
	 * (status CONFIRMED with a stored sweepTxHex) against the current
	 * destination script. Maturity is unchanged: the rebuilt sweep spends the
	 * same input with the same sequence/locktime — only the payout moves.
	 *
	 * Best-effort: on any failure the held output keeps its existing sweep
	 * (which still pays the previous destination and remains broadcastable) —
	 * a rebuild must never prevent restore/startup.
	 */
	private _rebuildHeldSweeps(): void {
		if (!this._commitmentBroadcast) return;
		const held = this._trackedOutputs.filter(
			(o) =>
				o.status === OutputStatus.CONFIRMED &&
				o.sweepTxHex !== undefined &&
				// Skip sweeps already paying the current destination.
				!this._sweepPaysDestination(o.sweepTxHex)
		);
		if (held.length === 0) return;

		try {
			let resolved: ReturnType<typeof resolveOurCommitmentOutputs> = [];
			switch (this._commitmentBroadcast.commitmentType) {
				case CommitmentType.OUR_COMMITMENT:
					resolved = resolveOurCommitmentOutputs(
						this._channelState,
						held,
						this._commitmentBroadcast.commitmentNumber,
						this._destinationScript,
						this._feeRatePerVbyte,
						this._knownPreimages,
						this._delayedPaymentBasepointSecret,
						this._htlcBasepointSecret,
						this._channelState.remoteHtlcSignatures
					);
					break;
				case CommitmentType.THEIR_CURRENT_COMMITMENT:
					resolved = resolveTheirCurrentCommitmentOutputs(
						this._channelState,
						held,
						this._destinationScript,
						this._feeRatePerVbyte,
						this._knownPreimages,
						this._paymentPrivkey
					);
					break;
				default:
					// Penalty sweeps broadcast immediately and are never held.
					return;
			}

			for (const r of resolved) {
				if (!r.spendTx) continue;
				// A to_local sweep is always self-signed (witness present). An HTLC
				// sweep without a witness is not yet spendable (missing remote htlc
				// signature) — don't persist an unsigned tx that would be rejected on
				// broadcast; it stays held and is rebuilt once the signature exists.
				if (!r.witness) continue;
				r.spendTx.setWitness(0, r.witness);
				r.trackedOutput.sweepTxHex = r.spendTx.toBuffer().toString('hex');
			}
		} catch {
			// Keep the existing held sweeps; they are still valid spends.
		}
	}

	/** Whether a stored sweep's first output already pays _destinationScript. */
	private _sweepPaysDestination(sweepTxHex: string): boolean {
		try {
			const tx = bitcoin.Transaction.fromHex(sweepTxHex);
			return (
				tx.outs.length > 0 && tx.outs[0].script.equals(this._destinationScript)
			);
		} catch {
			return false;
		}
	}

	/**
	 * Restore a ChainMonitor from persisted state.
	 */
	static restore(
		saved: IChainMonitorState,
		channelState: IChannelState,
		destinationScript: Buffer,
		feeRatePerVbyte: number,
		revocationBasepointSecret: Buffer,
		paymentPrivkey: Buffer,
		network: bitcoin.Network = bitcoin.networks.bitcoin,
		delayedPaymentBasepointSecret?: Buffer,
		htlcBasepointSecret?: Buffer
	): ChainMonitor {
		const monitor = new ChainMonitor(
			channelState,
			destinationScript,
			feeRatePerVbyte,
			revocationBasepointSecret,
			paymentPrivkey,
			network,
			delayedPaymentBasepointSecret,
			htlcBasepointSecret
		);
		monitor._state = saved.monitorState;
		monitor._commitmentBroadcast = saved.commitmentBroadcast;
		monitor._trackedOutputs = saved.trackedOutputs;
		monitor._currentBlockHeight = saved.currentBlockHeight;
		// Restore known preimages if present
		if (saved.knownPreimages) {
			for (const [hash, preimage] of Object.entries(saved.knownPreimages)) {
				monitor._knownPreimages.set(hash, Buffer.from(preimage, 'hex'));
			}
		}
		// Persisted held sweeps may have been built against a previous session's
		// destination (e.g. the funding-key fallback when the wallet was offline);
		// rebuild them against this session's destination before they release.
		monitor._rebuildHeldSweeps();
		return monitor;
	}

	getState(): MonitorState {
		return this._state;
	}

	getTrackedOutputs(): ITrackedOutput[] {
		return [...this._trackedOutputs];
	}

	isFullyResolved(): boolean {
		return this._state === MonitorState.FULLY_RESOLVED;
	}

	/**
	 * Update the fee rate used for sweep transactions.
	 * @param feeRatePerKw Fee rate in sat/kw — converted to sat/vbyte internally.
	 */
	updateFeeRate(feeRatePerKw: number): void {
		// Convert sat/kw to sat/vbyte: 1 kw = 4 kvb, so sat/vbyte = sat/kw * 4 / 1000
		this._feeRatePerVbyte = Math.max(1, Math.round((feeRatePerKw * 4) / 1000));
	}

	getFullState(): IChainMonitorState {
		const knownPreimages: Record<string, string> = {};
		for (const [hash, preimage] of this._knownPreimages) {
			knownPreimages[hash] = preimage.toString('hex');
		}
		return {
			monitorState: this._state,
			commitmentBroadcast: this._commitmentBroadcast,
			trackedOutputs: [...this._trackedOutputs],
			currentBlockHeight: this._currentBlockHeight,
			knownPreimages
		};
	}

	/**
	 * Called when the funding outpoint is spent on-chain.
	 * Classifies the spending transaction and begins output resolution.
	 */
	handleFundingSpent(
		spendingTx: bitcoin.Transaction,
		blockHeight: number
	): ChainAction[] {
		if (this._state !== MonitorState.WATCHING) {
			// The spend was already processed (restored monitor, mempool-first
			// sighting, or a duplicate scripthash notification). A spend first seen
			// unconfirmed recorded confirmationHeight 0 — adopt the real height now
			// so held BIP68 sweeps become schedulable.
			return this._adoptLateConfirmation(spendingTx, blockHeight);
		}

		this._currentBlockHeight = blockHeight;

		const classified = classifyCommitmentTx(spendingTx, this._channelState);
		const txid = spendingTx.getId();

		// Classify and track outputs
		const trackedOutputs = classifyOutputs(
			spendingTx,
			this._channelState,
			classified.type,
			classified.commitmentNumber
		);

		// Set confirmation heights on all tracked outputs
		for (const output of trackedOutputs) {
			output.confirmationHeight = blockHeight;
			output.status = OutputStatus.CONFIRMED;
		}

		this._trackedOutputs = trackedOutputs;
		this._commitmentBroadcast = {
			commitmentType: classified.type,
			txid,
			blockHeight,
			commitmentNumber: classified.commitmentNumber,
			trackedOutputs
		};

		this._state = MonitorState.COMMITMENT_DETECTED;

		const actions: ChainAction[] = [];

		// Defense-in-depth: scan the commitment spend itself for any revealed
		// preimages before we even set up per-output watches.
		actions.push(...this._scanForPreimages(spendingTx));

		// Watch all tracked outputs
		for (const output of trackedOutputs) {
			actions.push({
				type: ChainActionType.WATCH_OUTPUT,
				txid: output.txid,
				outputIndex: output.outputIndex
			});
		}

		// Process based on commitment type
		switch (classified.type) {
			case CommitmentType.COOPERATIVE_CLOSE:
				return this._handleCooperativeClose(actions);

			case CommitmentType.OUR_COMMITMENT:
				return this._handleOurCommitment(actions, classified.commitmentNumber);

			case CommitmentType.THEIR_CURRENT_COMMITMENT:
				return this._handleTheirCurrentCommitment(actions);

			case CommitmentType.THEIR_REVOKED_COMMITMENT:
				return this._handleRevokedCommitment(
					actions,
					spendingTx,
					classified.commitmentNumber
				);

			default:
				actions.push({
					type: ChainActionType.ERROR,
					message: `Unknown commitment type for tx ${txid}`
				});
				return actions;
		}
	}

	/**
	 * Called when a new block arrives. Checks CSV/CLTV delays and
	 * updates output statuses.
	 */
	handleNewBlock(blockHeight: number): ChainAction[] {
		if (
			this._state === MonitorState.WATCHING ||
			this._state === MonitorState.FULLY_RESOLVED
		) {
			this._currentBlockHeight = blockHeight;
			return [];
		}

		this._currentBlockHeight = blockHeight;
		const actions: ChainAction[] = [];

		// Check each tracked output for maturation
		let allResolved = true;
		for (const output of this._trackedOutputs) {
			if (output.status === OutputStatus.IRREVOCABLY_RESOLVED) {
				continue;
			}

			// Check if confirmed spend has reached irrevocable depth
			if (
				output.status === OutputStatus.SPEND_CONFIRMED &&
				output.resolutionTxid
			) {
				// The resolution was confirmed; check depth
				const depth = blockHeight - output.confirmationHeight;
				if (depth >= IRREVOCABLE_DEPTH) {
					output.status = OutputStatus.IRREVOCABLY_RESOLVED;
					actions.push({
						type: ChainActionType.OUTPUT_RESOLVED,
						txid: output.txid,
						outputIndex: output.outputIndex
					});
					continue;
				}
			}

			allResolved = false;
		}

		// Release held (timelocked) sweeps whose CSV/CLTV has now matured.
		for (const output of this._trackedOutputs) {
			if (
				output.status === OutputStatus.CONFIRMED &&
				output.sweepTxHex !== undefined &&
				output.maturityHeight !== undefined &&
				blockHeight >= output.maturityHeight
			) {
				actions.push(
					this._broadcastSweepAction(
						output,
						Buffer.from(output.sweepTxHex, 'hex'),
						`${output.outputType.toLowerCase()} sweep (matured)`
					)
				);
				output.status = OutputStatus.SPEND_BROADCAST;
				output.broadcastHeight = blockHeight;
			}
		}

		// Re-broadcast unconfirmed sweeps stuck in SPEND_BROADCAST
		for (const output of this._trackedOutputs) {
			// Second-level HTLC transactions (HTLC-timeout / HTLC-success) are
			// pre-signed by the counterparty at the channel's committed feerate.
			// Their fee cannot be changed without invalidating that signature, so
			// they must NOT be RBF-rebuilt. They are fee-bumped via CPFP on their
			// own (CSV-delayed) output sweep instead — or, for anchors, by attaching
			// a wallet input (see resolveOurCommitmentOutputs / fee attachment).
			if (
				output.outputType === OutputType.OFFERED_HTLC ||
				output.outputType === OutputType.RECEIVED_HTLC
			) {
				continue;
			}
			if (
				output.status === OutputStatus.SPEND_BROADCAST &&
				output.broadcastHeight !== undefined
			) {
				const blocksSinceBroadcast = blockHeight - output.broadcastHeight;
				if (blocksSinceBroadcast >= REBROADCAST_INTERVAL) {
					// Bump the fee rate, but never below the current network estimate
					// (the node feeds live rates via updateFeeRate). This lets a sweep
					// catch up to a fee spike instead of crawling 1.5x per interval.
					// Still capped at MAX_FEE_BUMP_MULTIPLIER × original.
					const originalRate = output.originalFeeRate || this._feeRatePerVbyte;
					const currentRate = output.currentFeeRate || originalRate;
					const bumpedRate = Math.min(
						Math.max(currentRate * FEE_BUMP_FACTOR, this._feeRatePerVbyte),
						originalRate * MAX_FEE_BUMP_MULTIPLIER
					);
					const vbytes = estimateSweepVbytes(output.outputType);
					const feeSatoshis = BigInt(Math.ceil(bumpedRate * vbytes));

					if (output.amount > feeSatoshis) {
						// Track per-output fee rate — do NOT mutate global _feeRatePerVbyte
						output.currentFeeRate = bumpedRate;
						output.broadcastHeight = blockHeight;

						// Emit REBUILD_SWEEP so the caller can re-resolve with new fee
						actions.push({
							type: ChainActionType.REBUILD_SWEEP,
							output,
							feeRatePerVbyte: bumpedRate
						});
					}
				}
			}
		}

		// Check if all outputs are irrevocably resolved
		if (allResolved && this._trackedOutputs.length > 0) {
			this._state = MonitorState.FULLY_RESOLVED;
			if (this._channelState.channelId) {
				actions.push({
					type: ChainActionType.CHANNEL_FULLY_RESOLVED,
					channelId: this._channelState.channelId
				});
			}
		}

		return actions;
	}

	/**
	 * Called when a tracked output is spent on-chain.
	 */
	handleOutputSpent(
		txid: string,
		outputIndex: number,
		spendingTx: bitcoin.Transaction,
		blockHeight: number
	): ChainAction[] {
		this._currentBlockHeight = blockHeight;
		const actions: ChainAction[] = [];

		const output = this._trackedOutputs.find(
			(o) => o.txid === txid && o.outputIndex === outputIndex
		);

		if (!output) {
			return [];
		}

		output.status = OutputStatus.SPEND_CONFIRMED;
		output.resolutionTxid = spendingTx.getId();
		output.confirmationHeight = blockHeight;

		// Scan the whole spending tx for any preimages it reveals — not just the
		// one matched output. A single counterparty tx can claim several HTLC
		// outputs at once, and we want every preimage we can learn.
		actions.push(...this._scanForPreimages(spendingTx));

		return actions;
	}

	/**
	 * Inspect every input witness of a transaction for payment preimages that
	 * match one of our HTLCs (tracked commitment outputs or in-flight channel
	 * HTLCs). Records newly-learned preimages and emits PREIMAGE_LEARNED so the
	 * node can settle the corresponding upstream HTLC.
	 *
	 * This is the defense-in-depth path: a forwarding node MUST learn a preimage
	 * the counterparty reveals on-chain to claim the matching upstream HTLC. It is
	 * called both when a watched output spend is observed and when a commitment
	 * spend (force-close) is first detected, so we don't depend solely on a
	 * per-output watch subscription firing.
	 */
	private _scanForPreimages(spendingTx: bitcoin.Transaction): ChainAction[] {
		const actions: ChainAction[] = [];

		// Collect the set of payment hashes we care about for this channel.
		const wantedHashes = new Map<string, Buffer>();
		for (const o of this._trackedOutputs) {
			if (o.paymentHash)
				wantedHashes.set(o.paymentHash.toString('hex'), o.paymentHash);
		}
		for (const htlc of this._channelState.htlcs.values()) {
			wantedHashes.set(htlc.paymentHash.toString('hex'), htlc.paymentHash);
		}
		if (wantedHashes.size === 0) return actions;

		// Scan every witness element rather than assuming a fixed position: a
		// preimage can appear in a 3-element direct offered-HTLC claim
		// (`<sig> <preimage>`) or a 5-element second-level HTLC-success witness.
		// Each 32-byte candidate is verified by hashing it against a wanted hash,
		// so scanning broadly cannot produce a false positive.
		for (const input of spendingTx.ins) {
			if (!input.witness) continue;
			for (const el of input.witness) {
				if (el.length !== 32) continue;
				const hash = crypto.createHash('sha256').update(el).digest();
				const hashHex = hash.toString('hex');
				if (!wantedHashes.has(hashHex)) continue;
				if (this._knownPreimages.has(hashHex)) continue;
				this._knownPreimages.set(hashHex, el);
				actions.push({
					type: ChainActionType.PREIMAGE_LEARNED,
					paymentHash: hash,
					preimage: el
				});
			}
		}

		return actions;
	}

	/**
	 * Called when a block is disconnected (reorg).
	 * Resets output states to avoid double-broadcasting.
	 */
	handleBlockDisconnected(blockHeight: number): ChainAction[] {
		if (this._state === MonitorState.FULLY_RESOLVED) {
			// Can't un-resolve
			return [];
		}

		// Reset any outputs that were confirmed at or after the disconnected height
		for (const output of this._trackedOutputs) {
			if (output.confirmationHeight >= blockHeight) {
				if (output.status === OutputStatus.SPEND_CONFIRMED) {
					output.status = OutputStatus.CONFIRMED;
					output.resolutionTxid = undefined;
				} else if (output.status === OutputStatus.IRREVOCABLY_RESOLVED) {
					output.status = OutputStatus.SPEND_CONFIRMED;
				}
			}
		}

		// If the commitment itself was in the disconnected block, reset to WATCHING
		if (
			this._commitmentBroadcast &&
			this._commitmentBroadcast.blockHeight >= blockHeight
		) {
			this._state = MonitorState.WATCHING;
			this._trackedOutputs = [];
			this._commitmentBroadcast = null;
		}

		return [];
	}

	/**
	 * Add a preimage for an HTLC, enabling resolution of previously
	 * unclaimable outputs.
	 */
	addPreimage(paymentHash: Buffer, preimage: Buffer): ChainAction[] {
		this._knownPreimages.set(paymentHash.toString('hex'), preimage);

		const actions: ChainAction[] = [];

		// Check if any tracked HTLC can now be resolved
		if (
			this._state === MonitorState.RESOLVING ||
			this._state === MonitorState.COMMITMENT_DETECTED
		) {
			// Re-resolve with new preimage information
			const commitmentType = this._commitmentBroadcast?.commitmentType;
			if (commitmentType === CommitmentType.OUR_COMMITMENT) {
				const htlcOutputs = this._trackedOutputs.filter(
					(o) =>
						o.outputType === OutputType.RECEIVED_HTLC &&
						o.status !== OutputStatus.IRREVOCABLY_RESOLVED &&
						o.status !== OutputStatus.SPEND_CONFIRMED
				);
				const resolved = resolveOurCommitmentOutputs(
					this._channelState,
					htlcOutputs,
					this._commitmentBroadcast!.commitmentNumber,
					this._destinationScript,
					this._feeRatePerVbyte,
					this._knownPreimages,
					this._delayedPaymentBasepointSecret,
					// HTLC-success on our own commitment is a second-level tx that
					// needs OUR htlc signature plus the peer's pre-supplied htlc
					// signature. Without these the witness cannot be built — pass
					// them so the broadcast below is actually spendable.
					this._htlcBasepointSecret,
					this._channelState.remoteHtlcSignatures
				);

				for (const r of resolved) {
					// Only broadcast a fully-witnessed spend. If the witness is
					// missing (e.g. the peer's htlc signature was never persisted),
					// broadcasting an unsigned HTLC-success tx would be rejected by
					// the network and waste the preimage; leave the output tracked
					// so it can be retried once the signature is available.
					if (r.spendTx && r.witness) {
						r.spendTx.setWitness(0, r.witness);
						const txBuf = r.spendTx.toBuffer();
						actions.push(
							this._broadcastSweepAction(
								r.trackedOutput,
								txBuf,
								'HTLC-success (preimage learned)'
							)
						);
						r.trackedOutput.status = OutputStatus.SPEND_BROADCAST;
						r.trackedOutput.broadcastHeight = this._currentBlockHeight;
						r.trackedOutput.originalFeeRate = this._feeRatePerVbyte;
						r.trackedOutput.sweepTxHex = txBuf.toString('hex');
					}
				}
			}
		}

		return actions;
	}

	// ─────────────── Private Handlers ───────────────

	/**
	 * Build the chain action to broadcast a sweep transaction.
	 *
	 * Zero-fee second-level HTLC txs on anchor channels cannot pay their own fee,
	 * so they are routed through FEE_BUMP_AND_BROADCAST to have a wallet fee input
	 * attached before broadcast. Every other sweep broadcasts directly.
	 */
	private _broadcastSweepAction(
		output: ITrackedOutput,
		txBuf: Buffer,
		description: string
	): ChainAction {
		// Only our OWN commitment's second-level HTLC txs are the pre-signed
		// zero-fee variant that needs a fee attached. HTLC claims on the remote's
		// commitment are direct spends that already deduct a fee, and penalty
		// sweeps on a revoked commitment likewise pay their own way.
		const ourCommitment =
			this._commitmentBroadcast?.commitmentType ===
			CommitmentType.OUR_COMMITMENT;
		if (
			ourCommitment &&
			isAnchorChannel(this._channelState.channelType) &&
			(output.outputType === OutputType.OFFERED_HTLC ||
				output.outputType === OutputType.RECEIVED_HTLC)
		) {
			return {
				type: ChainActionType.FEE_BUMP_AND_BROADCAST,
				kind: 'htlc-fee-attach',
				tx: txBuf,
				description,
				feeratePerVbyte: output.currentFeeRate || this._feeRatePerVbyte
			};
		}
		return { type: ChainActionType.BROADCAST_TX, tx: txBuf, description };
	}

	private _handleCooperativeClose(actions: ChainAction[]): ChainAction[] {
		// Cooperative close is immediately fully resolved (no pending outputs to sweep)
		// Mark all outputs as irrevocably resolved
		for (const output of this._trackedOutputs) {
			output.status = OutputStatus.IRREVOCABLY_RESOLVED;
		}

		this._state = MonitorState.FULLY_RESOLVED;

		if (this._channelState.channelId) {
			actions.push({
				type: ChainActionType.CHANNEL_FULLY_RESOLVED,
				channelId: this._channelState.channelId
			});
		}

		return actions;
	}

	/**
	 * Adopt the confirmation height of a commitment spend that was first seen
	 * in the mempool (recorded with height 0). Re-derives the maturity of every
	 * held sweep — a BIP68 (CSV) sweep is unschedulable until its parent's
	 * confirmation height is known — then releases anything already mature.
	 */
	private _adoptLateConfirmation(
		spendingTx: bitcoin.Transaction,
		blockHeight: number
	): ChainAction[] {
		if (
			blockHeight <= 0 ||
			!this._commitmentBroadcast ||
			this._commitmentBroadcast.txid !== spendingTx.getId() ||
			this._commitmentBroadcast.blockHeight > 0
		) {
			return [];
		}

		this._commitmentBroadcast.blockHeight = blockHeight;
		const tip = Math.max(this._currentBlockHeight, blockHeight);
		for (const output of this._trackedOutputs) {
			if (output.confirmationHeight <= 0) {
				output.confirmationHeight = blockHeight;
			}
			if (output.sweepTxHex === undefined) continue;
			if (
				output.status === OutputStatus.CONFIRMED ||
				output.status === OutputStatus.SPEND_BROADCAST
			) {
				const sweepTx = bitcoin.Transaction.fromHex(output.sweepTxHex);
				output.maturityHeight = this._computeMaturityHeight(
					sweepTx,
					output.confirmationHeight
				);
				// A "broadcast" sweep whose true maturity is still in the future was
				// necessarily rejected by the network (premature BIP68) — put it back
				// on hold so it releases exactly at maturity instead of fee-bumping
				// through the rebroadcast path until then.
				if (
					output.status === OutputStatus.SPEND_BROADCAST &&
					tip < output.maturityHeight
				) {
					output.status = OutputStatus.CONFIRMED;
					output.broadcastHeight = undefined;
				}
			}
		}

		// Release any sweep whose timelock already matured while we waited.
		return this.handleNewBlock(tip);
	}

	/**
	 * Derive the block height at which a sweep transaction becomes valid from
	 * its own timelock fields — exactly the rules the network enforces:
	 *   - nLockTime (BIP65, absolute block height) — e.g. HTLC-timeout cltv_expiry
	 *   - nSequence (BIP68, relative block delay) — e.g. to_local to_self_delay,
	 *     anchor to_remote 1-block CSV
	 * Returns the greater of the two constraints (and never earlier than the
	 * commitment's own confirmation height).
	 */
	private _computeMaturityHeight(
		tx: bitcoin.Transaction,
		confirmationHeight: number
	): number {
		let maturity = confirmationHeight;

		// Absolute timelock (nLockTime). Block-height-based values are < 500e6.
		if (tx.locktime > 0 && tx.locktime < 500_000_000) {
			maturity = Math.max(maturity, tx.locktime);
		}

		// Relative timelock (nSequence, BIP68) on the first input.
		const seq = tx.ins[0]?.sequence ?? 0xffffffff;
		const DISABLE_FLAG = 1 << 31; // relative locktime disabled when set
		const TYPE_FLAG = 1 << 22; // 0 = block-based, 1 = time-based
		if ((seq & DISABLE_FLAG) === 0 && (seq & TYPE_FLAG) === 0) {
			const relativeBlocks = seq & 0x0000ffff;
			if (confirmationHeight <= 0) {
				// A BIP68 relative lock counts from the PARENT's confirmation, which
				// is unknown while the commitment sits in the mempool (the watcher
				// reports such spends with height 0). Releasing against height 0
				// broadcasts immediately and the network rejects it as
				// non-BIP68-final. Hold until the confirmation height is adopted
				// (the funding watch re-fires once the spend confirms).
				return Number.MAX_SAFE_INTEGER;
			}
			maturity = Math.max(maturity, confirmationHeight + relativeBlocks);
		}

		return maturity;
	}

	/**
	 * Either broadcast a resolved sweep now (if its timelock has already
	 * matured) or hold it until maturity. Holding avoids broadcasting
	 * CSV/CLTV-locked transactions prematurely, which the network rejects as
	 * `non-BIP68-final` / `non-final` and which otherwise spams failed
	 * broadcasts. Held sweeps are released by handleNewBlock() once the chain
	 * reaches their maturity height.
	 */
	private _scheduleSweep(
		actions: ChainAction[],
		r: {
			trackedOutput: ITrackedOutput;
			spendTx?: bitcoin.Transaction;
			witness?: Buffer[];
		},
		description: string
	): void {
		if (!r.spendTx) {
			return;
		}
		if (r.witness) {
			r.spendTx.setWitness(0, r.witness);
		}

		const txBuf = r.spendTx.toBuffer();
		const maturityHeight = this._computeMaturityHeight(
			r.spendTx,
			r.trackedOutput.confirmationHeight
		);

		r.trackedOutput.sweepTxHex = txBuf.toString('hex');
		r.trackedOutput.originalFeeRate = this._feeRatePerVbyte;
		r.trackedOutput.maturityHeight = maturityHeight;

		if (this._currentBlockHeight >= maturityHeight) {
			// Already spendable — broadcast immediately.
			actions.push(
				this._broadcastSweepAction(r.trackedOutput, txBuf, description)
			);
			r.trackedOutput.status = OutputStatus.SPEND_BROADCAST;
			r.trackedOutput.broadcastHeight = this._currentBlockHeight;
		} else {
			// Timelock not yet matured — hold; handleNewBlock releases it.
			r.trackedOutput.status = OutputStatus.CONFIRMED;
		}
	}

	private _handleOurCommitment(
		actions: ChainAction[],
		commitmentNumber: bigint
	): ChainAction[] {
		this._state = MonitorState.RESOLVING;

		const resolved = resolveOurCommitmentOutputs(
			this._channelState,
			this._trackedOutputs,
			commitmentNumber,
			this._destinationScript,
			this._feeRatePerVbyte,
			this._knownPreimages,
			this._delayedPaymentBasepointSecret,
			this._htlcBasepointSecret,
			this._channelState.remoteHtlcSignatures
		);

		for (const r of resolved) {
			if (r.spendTx) {
				const desc =
					r.trackedOutput.outputType === OutputType.TO_LOCAL
						? 'to_local sweep (CSV delayed)'
						: r.trackedOutput.outputType === OutputType.OFFERED_HTLC
						? 'HTLC-timeout'
						: r.trackedOutput.outputType === OutputType.RECEIVED_HTLC
						? 'HTLC-success'
						: 'sweep';
				this._scheduleSweep(actions, r, desc);
			}
		}

		return actions;
	}

	private _handleTheirCurrentCommitment(actions: ChainAction[]): ChainAction[] {
		this._state = MonitorState.RESOLVING;

		const resolved = resolveTheirCurrentCommitmentOutputs(
			this._channelState,
			this._trackedOutputs,
			this._destinationScript,
			this._feeRatePerVbyte,
			this._knownPreimages,
			this._paymentPrivkey,
			this._htlcBasepointSecret,
			this._channelState.remoteCurrentPerCommitmentPoint ?? undefined
		);

		for (const r of resolved) {
			if (r.spendTx) {
				this._scheduleSweep(
					actions,
					r,
					r.trackedOutput.outputType === OutputType.TO_REMOTE
						? 'to_remote claim'
						: 'HTLC claim'
				);
			}
		}

		return actions;
	}

	private _handleRevokedCommitment(
		actions: ChainAction[],
		revokedTx: bitcoin.Transaction,
		commitmentNumber: bigint
	): ChainAction[] {
		this._state = MonitorState.RESOLVING;

		const resolved = resolveRevokedCommitmentOutputs(
			this._channelState,
			this._trackedOutputs,
			commitmentNumber,
			revokedTx,
			this._destinationScript,
			this._feeRatePerVbyte,
			this._revocationBasepointSecret,
			this._network
		);

		for (const r of resolved) {
			if (r.spendTx) {
				// Penalty tx already has witnesses set
				const txBuf = r.spendTx.toBuffer();
				actions.push({
					type: ChainActionType.BROADCAST_TX,
					tx: txBuf,
					description: 'penalty sweep (revoked commitment)'
				});
				r.trackedOutput.status = OutputStatus.SPEND_BROADCAST;
				r.trackedOutput.broadcastHeight = this._currentBlockHeight;
				r.trackedOutput.originalFeeRate = this._feeRatePerVbyte;
				r.trackedOutput.sweepTxHex = txBuf.toString('hex');
			}
		}

		return actions;
	}
}
