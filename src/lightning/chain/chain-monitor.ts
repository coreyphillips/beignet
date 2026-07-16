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
	resolveRevokedCommitmentOutputs,
	resolveSecondLevelHtlcOutput,
	resolveRevokedSecondLevelOutput
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
				case CommitmentType.THEIR_FUTURE_COMMITMENT:
					// Future commitment (data loss on our side): the only held sweep
					// possible is our to_remote (anchor CSV-1) claim.
					resolved = resolveTheirCurrentCommitmentOutputs(
						this._channelState,
						held.filter((o) => o.outputType === OutputType.TO_REMOTE),
						this._destinationScript,
						this._feeRatePerVbyte,
						this._knownPreimages,
						this._paymentPrivkey,
						this._htlcBasepointSecret,
						this._channelState.dlpRemotePerCommitmentPoint ??
							this._channelState.remoteCurrentPerCommitmentPoint ??
							undefined
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
	 * True once the force-close commitment tx has CONFIRMED on-chain (blockHeight > 0).
	 * While it is only mempool-detected the commitment is still unconfirmed and its
	 * CPFP package can be pinned by a fee spike — so re-CPFP must keep running. Note
	 * COMMITMENT_DETECTED alone does NOT imply confirmation (a mempool-first sighting
	 * leaves blockHeight 0 until _adoptLateConfirmation records the real height).
	 */
	isCommitmentConfirmed(): boolean {
		return (
			this._commitmentBroadcast !== null &&
			this._commitmentBroadcast.blockHeight > 0
		);
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
			// Commitment SWAP: a DIFFERENT tx now spends the funding output. The
			// funding outpoint can only be spent once per chain, so a confirmed
			// conflicting spend means the recorded commitment was reorged out or
			// lost a mempool race (e.g. we broadcast ours, the peer's revoked
			// commitment confirmed instead; or a mempool-seen coop close was
			// double-spent by a revoked commitment). Discarding it would leave
			// the real close — possibly a revoked commitment needing penalty —
			// entirely unresolved: our tracked outputs belong to a tx that no
			// longer exists. Reset and reclassify against the confirmed spend.
			// Only a CONFIRMED conflict swaps (mempool sightings of a competing
			// commitment must not thrash the tracking back and forth).
			//
			// The swap must NOT be gated on the recorded spend's apparent burial
			// depth. The funding outpoint can be spent exactly once per chain, so a
			// DIFFERENT tx confirming as its spender is itself definitive proof that
			// the previously recorded commitment was reorged out, no matter how
			// deeply buried its (now stale, never reset after the reorg) recorded
			// height made it look. Refusing the swap on that stale height (the old
			// recordedFinal >= IRREVOCABLE_DEPTH guard) let a later revoked
			// commitment escape THEIR_REVOKED_COMMITMENT classification and go
			// unpunished. Trust the confirmed conflict and reclassify against it.
			if (
				this._commitmentBroadcast &&
				this._commitmentBroadcast.txid !== spendingTx.getId() &&
				blockHeight > 0
			) {
				this._trackedOutputs = [];
				this._commitmentBroadcast = null;
				this._state = MonitorState.WATCHING;
				// fall through to normal classification below (preimages learned
				// so far are retained in _knownPreimages)
			} else {
				// The spend was already processed (restored monitor, mempool-first
				// sighting, or a duplicate scripthash notification). A spend first
				// seen unconfirmed recorded confirmationHeight 0 — adopt the real
				// height now so held BIP68 sweeps become schedulable.
				return this._adoptLateConfirmation(spendingTx, blockHeight);
			}
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

			case CommitmentType.THEIR_FUTURE_COMMITMENT:
				return this._handleTheirFutureCommitment(actions);

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
						outputIndex: output.outputIndex,
						channelId: this._channelState.channelId ?? undefined,
						outputType: output.outputType,
						paymentHash: output.paymentHash
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
			// HTLC output handling splits by WHOSE commitment confirmed:
			//
			// OUR commitment — HTLC resolution uses pre-signed second-level txs
			// (HTLC-timeout / HTLC-success). On NON-anchor channels the fee is baked
			// into the counterparty's signature and cannot be changed, so they must NOT
			// be RBF-rebuilt (they are CPFP-bumped via their own CSV-delayed output
			// sweep). On ANCHOR channels they are zero-fee (SIGHASH_SINGLE|ANYONECANPAY),
			// so the wallet fee attached at broadcast CAN be replaced with a larger one;
			// re-issue the fee-attach when stuck (M1). Either way, never fall through to
			// the generic REBUILD_SWEEP below.
			//
			// THEIR commitment (current or revoked) — our HTLC claim (preimage/timeout/
			// penalty) is a SINGLE tx we fully sign, so it can be freely RBF'd. Fall
			// through to the generic REBUILD_SWEEP path so a fee spike after broadcast
			// can't strand it and let the peer win the HTLC-timeout race (H2). The
			// blanket `continue` here previously pinned these claims at their initial
			// feerate forever.
			if (
				output.outputType === OutputType.OFFERED_HTLC ||
				output.outputType === OutputType.RECEIVED_HTLC
			) {
				const ourCommitment =
					this._commitmentBroadcast?.commitmentType ===
					CommitmentType.OUR_COMMITMENT;
				if (ourCommitment) {
					const ourAnchorHtlc = isAnchorChannel(this._channelState.channelType);
					if (
						ourAnchorHtlc &&
						output.status === OutputStatus.SPEND_BROADCAST &&
						output.broadcastHeight !== undefined &&
						output.sweepTxHex !== undefined &&
						blockHeight - output.broadcastHeight >= REBROADCAST_INTERVAL
					) {
						const originalRate =
							output.originalFeeRate || this._feeRatePerVbyte;
						const currentRate = output.currentFeeRate || originalRate;
						// Anti-runaway cap: 10x the build-time rate OR the live network
						// rate, whichever is larger. A sweep built at a stale low rate
						// (e.g. the 10 sat/vB restore default) must still be able to
						// reach the known live rate.
						const bumpedRate = Math.min(
							Math.max(currentRate * FEE_BUMP_FACTOR, this._feeRatePerVbyte),
							Math.max(
								originalRate * MAX_FEE_BUMP_MULTIPLIER,
								this._feeRatePerVbyte
							)
						);
						// _broadcastSweepAction reads output.currentFeeRate for the anchor
						// HTLC fee-attach target, so set it before re-issuing the broadcast.
						output.currentFeeRate = bumpedRate;
						output.broadcastHeight = blockHeight;
						actions.push(
							this._broadcastSweepAction(
								output,
								Buffer.from(output.sweepTxHex, 'hex'),
								`${output.outputType.toLowerCase()} re-fee-bump (stuck HTLC race)`
							)
						);
					} else if (
						!ourAnchorHtlc &&
						output.status === OutputStatus.SPEND_BROADCAST &&
						output.broadcastHeight !== undefined &&
						output.sweepTxHex !== undefined &&
						blockHeight - output.broadcastHeight >= REBROADCAST_INTERVAL
					) {
						// Non-anchor OUR-commitment HTLC-success/timeout: its fee is fixed
						// by the counterparty signature and cannot be RBF'd, but the SAME
						// pre-signed tx must still be periodically REBROADCAST. Otherwise an
						// HTLC-success marked SPEND_BROADCAST by preimage seeding on restore
						// (whose one-shot broadcast may never have reached the network) is
						// pinned forever and the inbound HTLC falls to the peer's timeout.
						output.broadcastHeight = blockHeight;
						actions.push(
							this._broadcastSweepAction(
								output,
								Buffer.from(output.sweepTxHex, 'hex'),
								`${output.outputType.toLowerCase()} rebroadcast (our-commitment HTLC)`
							)
						);
					}
					continue;
				}
				// THEIR commitment: fall through to generic RBF/REBUILD_SWEEP.
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
					// Anti-runaway cap: 10x the build-time rate OR the live rate,
					// whichever is larger — a sweep built at a stale low rate (e.g.
					// the 10 sat/vB restore default) must still reach the live rate.
					const originalRate = output.originalFeeRate || this._feeRatePerVbyte;
					const currentRate = output.currentFeeRate || originalRate;
					const bumpedRate = Math.min(
						Math.max(currentRate * FEE_BUMP_FACTOR, this._feeRatePerVbyte),
						Math.max(
							originalRate * MAX_FEE_BUMP_MULTIPLIER,
							this._feeRatePerVbyte
						)
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

		// Idempotent: the watch is retained after a spend (so a reorg can be detected),
		// which re-fires the subscription. If we already recorded THIS exact spend,
		// don't reprocess it (avoids duplicate second-level tracking / preimage scans).
		if (
			output.status === OutputStatus.SPEND_CONFIRMED &&
			output.resolutionTxid === spendingTx.getId()
		) {
			return [];
		}

		output.status = OutputStatus.SPEND_CONFIRMED;
		output.resolutionTxid = spendingTx.getId();
		output.confirmationHeight = blockHeight;

		// Scan the whole spending tx for any preimages it reveals — not just the
		// one matched output. A single counterparty tx can claim several HTLC
		// outputs at once, and we want every preimage we can learn.
		actions.push(...this._scanForPreimages(spendingTx));

		// M2: if WE swept one of our own HTLC outputs with a second-level
		// HTLC-timeout/success tx, that tx created a fresh CSV-delayed to_local
		// output. Track it and schedule its sweep to our destination — otherwise
		// the value sits unspent forever even though the channel reports fully
		// resolved.
		if (
			(output.outputType === OutputType.OFFERED_HTLC ||
				output.outputType === OutputType.RECEIVED_HTLC) &&
			this._commitmentBroadcast?.commitmentType ===
				CommitmentType.OUR_COMMITMENT &&
			output.sweepTxHex
		) {
			let isOurSecondLevel = false;
			try {
				const template = bitcoin.Transaction.fromHex(output.sweepTxHex);
				if (template.getId() === spendingTx.getId()) {
					isOurSecondLevel = true;
				} else {
					// Anchor channels: the broadcast second-level tx had wallet fee
					// inputs attached (htlc-fee-attach), which changes its txid. It is
					// still OURS if input 0 spends the same HTLC outpoint with the
					// identical pre-signed witness as the retained zero-fee template
					// (SIGHASH_SINGLE|ANYONECANPAY keeps that input/witness unchanged).
					// Without this match the fee-bumped HTLC tx's CSV output would
					// never be tracked or swept.
					const tIn = template.ins[0];
					const sIn = spendingTx.ins[0];
					// Output 0 must ALSO be the expected second-level CSV output:
					// byte-equal script and exact value versus the pre-signed
					// template. The SIGHASH_SINGLE|ANYONECANPAY witness already binds
					// output 0 cryptographically for any script-valid transaction,
					// but adoption should not depend on that sighash reasoning
					// holding across future code paths or unvalidated sightings —
					// explicit output validation makes it self-contained.
					const tOut = template.outs[0];
					const sOut = spendingTx.outs[0];
					isOurSecondLevel =
						!!tIn &&
						!!sIn &&
						Buffer.from(tIn.hash).equals(Buffer.from(sIn.hash)) &&
						tIn.index === sIn.index &&
						tIn.witness.length > 0 &&
						tIn.witness.length === sIn.witness.length &&
						tIn.witness.every((w, i) =>
							Buffer.from(w).equals(Buffer.from(sIn.witness[i]))
						) &&
						!!tOut &&
						!!sOut &&
						tOut.value === sOut.value &&
						Buffer.from(tOut.script).equals(Buffer.from(sOut.script));
				}
			} catch {
				isOurSecondLevel = false;
			}
			if (isOurSecondLevel) {
				const already = this._trackedOutputs.some(
					(o) => o.txid === spendingTx.getId() && o.outputIndex === 0
				);
				if (!already) {
					const r = resolveSecondLevelHtlcOutput(
						this._channelState,
						spendingTx,
						blockHeight,
						this._commitmentBroadcast.commitmentNumber,
						this._destinationScript,
						this._feeRatePerVbyte,
						this._delayedPaymentBasepointSecret,
						this._network
					);
					if (r) {
						this._trackedOutputs.push(r.trackedOutput);
						actions.push({
							type: ChainActionType.WATCH_OUTPUT,
							txid: r.trackedOutput.txid,
							outputIndex: r.trackedOutput.outputIndex
						});
						this._scheduleSweep(
							actions,
							r,
							'second-level HTLC sweep (CSV delayed)'
						);
					}
				}
			}
		}

		// #8: REVOKED commitment — the cheater confirmed their pre-signed
		// second-level HTLC tx (success with the preimage / timeout) before our
		// HTLC penalty. Its output is ALSO revocable by us with NO timelock
		// (BOLT 5: SHOULD spend the HTLC-timeout/HTLC-success output using the
		// revocation private key); without this claim the HTLC value is lost once
		// the cheater's to_self_delay matures.
		if (
			(output.outputType === OutputType.OFFERED_HTLC ||
				output.outputType === OutputType.RECEIVED_HTLC) &&
			this._commitmentBroadcast?.commitmentType ===
				CommitmentType.THEIR_REVOKED_COMMITMENT
		) {
			// Our own penalty confirming resolves the HTLC output — nothing to claim.
			let ourPenaltyTxid: string | null = null;
			if (output.sweepTxHex) {
				try {
					ourPenaltyTxid = bitcoin.Transaction.fromHex(
						output.sweepTxHex
					).getId();
				} catch {
					ourPenaltyTxid = null;
				}
			}
			if (ourPenaltyTxid !== spendingTx.getId()) {
				const resolved = resolveRevokedSecondLevelOutput(
					this._channelState,
					spendingTx,
					blockHeight,
					this._commitmentBroadcast.commitmentNumber,
					this._destinationScript,
					this._feeRatePerVbyte,
					this._revocationBasepointSecret,
					this._network
				);
				for (const r of resolved) {
					if (!r.spendTx) continue;
					const already = this._trackedOutputs.some(
						(o) =>
							o.txid === r.trackedOutput.txid &&
							o.outputIndex === r.trackedOutput.outputIndex
					);
					if (already) continue;
					// The revocation path has no timelock — broadcast immediately
					// (mirrors _handleRevokedCommitment; witness already set by the
					// resolver). The claim races the cheater's to_self_delay.
					const txBuf = r.spendTx.toBuffer();
					r.trackedOutput.status = OutputStatus.SPEND_BROADCAST;
					r.trackedOutput.broadcastHeight = blockHeight;
					r.trackedOutput.originalFeeRate = this._feeRatePerVbyte;
					r.trackedOutput.sweepTxHex = txBuf.toString('hex');
					// Retain the cheater's second-level tx so a stalled claim can be
					// re-resolved at a bumped feerate (rebuildSweep) rather than
					// stranded at its initial rate until the to_self_delay matures.
					r.trackedOutput.secondLevelTxHex = spendingTx
						.toBuffer()
						.toString('hex');
					this._trackedOutputs.push(r.trackedOutput);
					actions.push({
						type: ChainActionType.WATCH_OUTPUT,
						txid: r.trackedOutput.txid,
						outputIndex: r.trackedOutput.outputIndex
					});
					actions.push({
						type: ChainActionType.BROADCAST_TX,
						tx: txBuf,
						description: 'penalty sweep (revoked second-level HTLC)'
					});
				}
			}
		}

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
	 * Reorg recovery: a spend of this output that we previously saw confirmed (our
	 * own penalty / HTLC-success / to_local sweep, or a counterparty spend we were
	 * racing) has been evicted from the active chain by a reorg. Re-arm the output
	 * and re-broadcast our own sweep, so a breach stays punished and an HTLC we hold
	 * the preimage for stays claimed. Without this, a reorg that drops our penalty tx
	 * lets the cheater sweep the revoked output once their to_self_delay matures on
	 * the new chain — permanent loss of the breached balance.
	 */
	handleSpendUnconfirmed(txid: string, outputIndex: number): ChainAction[] {
		const output = this._trackedOutputs.find(
			(o) => o.txid === txid && o.outputIndex === outputIndex
		);
		if (!output) return [];
		if (
			output.status !== OutputStatus.SPEND_CONFIRMED &&
			output.status !== OutputStatus.IRREVOCABLY_RESOLVED &&
			output.status !== OutputStatus.SPEND_BROADCAST
		) {
			return [];
		}

		// The recorded spend is gone; forget it.
		output.resolutionTxid = undefined;
		// If the monitor had declared the channel fully resolved on the strength of
		// this spend, resume resolving so handleNewBlock keeps working the output.
		if (this._state === MonitorState.FULLY_RESOLVED) {
			this._state = MonitorState.RESOLVING;
		}

		// Re-broadcast our own sweep if we have one; otherwise just re-arm the watch
		// (a counterparty spend was reorged out and we had no competing sweep).
		if (output.sweepTxHex) {
			output.status = OutputStatus.SPEND_BROADCAST;
			output.broadcastHeight = this._currentBlockHeight;
			return [
				this._broadcastSweepAction(
					output,
					Buffer.from(output.sweepTxHex, 'hex'),
					`${output.outputType.toLowerCase()} re-broadcast (reorg recovery)`
				)
			];
		}
		output.status = OutputStatus.CONFIRMED;
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
			this._state !== MonitorState.RESOLVING &&
			this._state !== MonitorState.COMMITMENT_DETECTED
		) {
			return actions;
		}

		// Only inbound (received) HTLCs that are still unresolved become claimable
		// with a newly-learned preimage.
		const htlcOutputs = this._trackedOutputs.filter(
			(o) =>
				o.outputType === OutputType.RECEIVED_HTLC &&
				o.status !== OutputStatus.IRREVOCABLY_RESOLVED &&
				o.status !== OutputStatus.SPEND_CONFIRMED &&
				o.status !== OutputStatus.SPEND_BROADCAST
		);
		if (htlcOutputs.length === 0) return actions;

		const commitmentType = this._commitmentBroadcast?.commitmentType;
		if (commitmentType === CommitmentType.OUR_COMMITMENT) {
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
		} else if (commitmentType === CommitmentType.THEIR_CURRENT_COMMITMENT) {
			// C2 fund-safety: the peer force-closed with THEIR current commitment
			// before we knew the preimage, so our received HTLC was tracked with no
			// spend (output-resolver leaves it unswept). Now that the preimage has
			// arrived (e.g. learned on-chain or from the downstream leg we already
			// paid), build and broadcast the direct received-HTLC preimage claim —
			// otherwise the peer reclaims it via HTLC-timeout after cltv_expiry and we
			// lose the full forwarded amount. Symmetric to the OUR_COMMITMENT branch.
			const resolved = resolveTheirCurrentCommitmentOutputs(
				this._channelState,
				htlcOutputs,
				this._destinationScript,
				this._feeRatePerVbyte,
				this._knownPreimages,
				this._paymentPrivkey,
				this._htlcBasepointSecret,
				this._channelState.remoteCurrentPerCommitmentPoint ?? undefined
			);
			for (const r of resolved) {
				// _scheduleSweep sets the witness, computes maturity, broadcasts (or
				// holds), and marks the output SPEND_BROADCAST.
				if (r.spendTx) {
					this._scheduleSweep(actions, r, 'HTLC claim (preimage learned)');
				}
			}
		}
		// THEIR_REVOKED_COMMITMENT needs no preimage — a received HTLC on a revoked
		// commitment is swept via the revocation key at broadcast time, not by preimage.

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

	/**
	 * The peer broadcast a commitment NEWER than our recorded remote state
	 * (data loss on our side - the fell-behind reestablish path). We never saw
	 * its per-commitment point, so HTLC scripts are unknowable and its
	 * to_local is not ours: resolve ONLY our to_remote output. The classifier
	 * already tracks just to_remote for a future commitment; the filter here
	 * is defense in depth.
	 */
	private _handleTheirFutureCommitment(actions: ChainAction[]): ChainAction[] {
		this._state = MonitorState.RESOLVING;

		const toRemoteOutputs = this._trackedOutputs.filter(
			(o) => o.outputType === OutputType.TO_REMOTE
		);
		const resolved = resolveTheirCurrentCommitmentOutputs(
			this._channelState,
			toRemoteOutputs,
			this._destinationScript,
			this._feeRatePerVbyte,
			this._knownPreimages,
			this._paymentPrivkey,
			this._htlcBasepointSecret,
			// The reestablish-supplied point (kept for legacy completeness). The
			// to_remote spend itself derives from our static payment basepoint on
			// every channel type - static_remotekey P2WPKH, anchor CSV-1 P2WSH,
			// and the taproot 1-CSV leaf - so it also resolves on an SCB-recovery
			// state where no point was ever learned.
			this._channelState.dlpRemotePerCommitmentPoint ??
				this._channelState.remoteCurrentPerCommitmentPoint ??
				undefined
		);

		for (const r of resolved) {
			if (r.spendTx) {
				this._scheduleSweep(actions, r, 'to_remote claim (peer ahead)');
			}
		}

		return actions;
	}

	/**
	 * Re-resolve a single tracked output at a higher feerate and return the
	 * fee-bumped, fully-signed sweep transaction (or null if it can't be rebuilt).
	 * Handles the REBUILD_SWEEP action: without it, a sweep first broadcast at a
	 * fee too low to confirm would never be bumped — most dangerous for a penalty
	 * (justice) tx that must confirm before the cheater's to_self_delay matures.
	 */
	rebuildSweep(
		output: ITrackedOutput,
		feeRatePerVbyte: number
	): bitcoin.Transaction | null {
		if (!this._commitmentBroadcast) return null;
		let resolved: ReturnType<typeof resolveOurCommitmentOutputs> = [];
		try {
			switch (this._commitmentBroadcast.commitmentType) {
				case CommitmentType.OUR_COMMITMENT:
					resolved = resolveOurCommitmentOutputs(
						this._channelState,
						[output],
						this._commitmentBroadcast.commitmentNumber,
						this._destinationScript,
						feeRatePerVbyte,
						this._knownPreimages,
						this._delayedPaymentBasepointSecret,
						this._htlcBasepointSecret,
						this._channelState.remoteHtlcSignatures
					);
					break;
				case CommitmentType.THEIR_CURRENT_COMMITMENT:
					resolved = resolveTheirCurrentCommitmentOutputs(
						this._channelState,
						[output],
						this._destinationScript,
						feeRatePerVbyte,
						this._knownPreimages,
						this._paymentPrivkey,
						this._htlcBasepointSecret,
						this._channelState.remoteCurrentPerCommitmentPoint ?? undefined
					);
					break;
				case CommitmentType.THEIR_FUTURE_COMMITMENT:
					// Future commitment (data loss on our side): only our to_remote
					// is ever tracked/claimable; never rebuild anything else.
					if (output.outputType !== OutputType.TO_REMOTE) return null;
					resolved = resolveTheirCurrentCommitmentOutputs(
						this._channelState,
						[output],
						this._destinationScript,
						feeRatePerVbyte,
						this._knownPreimages,
						this._paymentPrivkey,
						this._htlcBasepointSecret,
						this._channelState.dlpRemotePerCommitmentPoint ??
							this._channelState.remoteCurrentPerCommitmentPoint ??
							undefined
					);
					break;
				case CommitmentType.THEIR_REVOKED_COMMITMENT: {
					// A revoked second-level justice claim (#8) spends the cheater's
					// HTLC tx, not the revoked commitment. Re-resolve it against the
					// retained second-level tx at the bumped rate so a stalled claim
					// can be RBF'd before the cheater's to_self_delay matures.
					if (output.secondLevelTxHex) {
						const secondLevelTx = bitcoin.Transaction.fromHex(
							output.secondLevelTxHex
						);
						resolved = resolveRevokedSecondLevelOutput(
							this._channelState,
							secondLevelTx,
							output.confirmationHeight,
							this._commitmentBroadcast.commitmentNumber,
							this._destinationScript,
							feeRatePerVbyte,
							this._revocationBasepointSecret,
							this._network
						);
						break;
					}
					if (!this._commitmentBroadcast.revokedTxHex) return null;
					const revokedTx = bitcoin.Transaction.fromHex(
						this._commitmentBroadcast.revokedTxHex
					);
					// Non-second-level output whose txid does not match the revoked
					// commitment cannot be rebuilt from it — signing would target the
					// wrong outpoint.
					if (output.txid !== revokedTx.getId()) return null;
					resolved = resolveRevokedCommitmentOutputs(
						this._channelState,
						[output],
						this._commitmentBroadcast.commitmentNumber,
						revokedTx,
						this._destinationScript,
						feeRatePerVbyte,
						this._revocationBasepointSecret,
						this._paymentPrivkey,
						this._network
					);
					break;
				}
				default:
					return null;
			}
		} catch {
			return null;
		}

		// Return the claim for the SPECIFIC tracked output that triggered this
		// rebuild. A batched second-level justice tx (SIGHASH_SINGLE|ANYONECANPAY
		// lets a cheater confirm multiple HTLC claims in one tx) resolves to one
		// entry per output, so returning resolved[0] unconditionally would re-bump
		// only the first claim and leave outputs 1..N-1 pinned at their stale
		// feerate until the cheater's to_self_delay matures. Match on the outpoint;
		// fall back to the sole entry only when resolution produced exactly one.
		const match =
			resolved.find(
				(r) =>
					r.trackedOutput.txid === output.txid &&
					r.trackedOutput.outputIndex === output.outputIndex
			) ?? (resolved.length === 1 ? resolved[0] : undefined);
		if (match?.spendTx) {
			// Penalty txs come back with witnesses already set; others carry a
			// separate witness to attach.
			if (match.witness) match.spendTx.setWitness(0, match.witness);
			return match.spendTx;
		}
		return null;
	}

	private _handleRevokedCommitment(
		actions: ChainAction[],
		revokedTx: bitcoin.Transaction,
		commitmentNumber: bigint
	): ChainAction[] {
		this._state = MonitorState.RESOLVING;

		// Retain the raw revoked tx so a stuck penalty sweep can be re-resolved
		// and fee-bumped later (rebuildSweep / REBUILD_SWEEP handling).
		if (this._commitmentBroadcast) {
			this._commitmentBroadcast.revokedTxHex = revokedTx
				.toBuffer()
				.toString('hex');
		}

		const resolved = resolveRevokedCommitmentOutputs(
			this._channelState,
			this._trackedOutputs,
			commitmentNumber,
			revokedTx,
			this._destinationScript,
			this._feeRatePerVbyte,
			this._revocationBasepointSecret,
			this._paymentPrivkey,
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
