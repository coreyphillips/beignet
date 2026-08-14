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
	matchRevokedHtlcSnapshotOutputs,
	resolveSecondLevelHtlcOutput,
	resolveRevokedSecondLevelOutput
} from './output-resolver';
import { csvFromToLocalScript } from '../script/commitment';
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
						this._paymentPrivkey,
						this._htlcBasepointSecret,
						this._channelState.remoteCurrentPerCommitmentPoint ?? undefined
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
		if (monitor._commitmentBroadcast) {
			// Serialized state contains this list in two places. Rejoin the references
			// so restored adoption and metadata repair persist consistently.
			monitor._commitmentBroadcast.trackedOutputs = monitor._trackedOutputs;
		}
		monitor._currentBlockHeight = saved.currentBlockHeight;
		if (
			monitor._commitmentBroadcast?.commitmentType ===
				CommitmentType.THEIR_REVOKED_COMMITMENT &&
			monitor._commitmentBroadcast.revokedTxHex
		) {
			try {
				const revokedTx = bitcoin.Transaction.fromHex(
					monitor._commitmentBroadcast.revokedTxHex
				);
				const snapshotOutputs = matchRevokedHtlcSnapshotOutputs(
					channelState,
					monitor._commitmentBroadcast.commitmentNumber,
					revokedTx,
					network
				);
				for (const [outputIndex, metadata] of snapshotOutputs) {
					const existing = monitor._trackedOutputs.find(
						(output) =>
							output.txid === monitor._commitmentBroadcast?.txid &&
							output.outputIndex === outputIndex
					);
					if (existing) {
						existing.outputType = metadata.outputType;
						existing.paymentHash = metadata.paymentHash;
						existing.cltvExpiry = metadata.cltvExpiry;
						existing.witnessScript = metadata.witnessScript;
						continue;
					}

					const claimCandidates = monitor._trackedOutputs.flatMap((output) => {
						if (!output.sweepTxHex) return [];
						try {
							const sweep = bitcoin.Transaction.fromHex(output.sweepTxHex);
							const spendsOutput = sweep.ins.some(
								(input) =>
									Buffer.from(input.hash).reverse().toString('hex') ===
										revokedTx.getId() && input.index === outputIndex
							);
							return spendsOutput ? [{ output, sweep }] : [];
						} catch {
							return [];
						}
					});
					// A sibling's stored batch proves this output is managed only while
					// the batch is live, held, or known to be the transaction that
					// confirmed. A competing spend can leave the old batch hex behind;
					// copying that sibling's terminal state would falsely resolve an
					// output the competitor never spent.
					const claimSource =
						claimCandidates.find(
							({ output, sweep }) =>
								(output.status === OutputStatus.SPEND_CONFIRMED ||
									output.status === OutputStatus.IRREVOCABLY_RESOLVED) &&
								output.resolutionTxid === sweep.getId()
						) ??
						claimCandidates.find(
							({ output }) =>
								output.status === OutputStatus.SPEND_BROADCAST &&
								output.resolutionTxid === undefined
						) ??
						claimCandidates.find(
							({ output }) =>
								output.status === OutputStatus.CONFIRMED &&
								output.maturityHeight !== undefined
						);
					const sourceOutput = claimSource?.output;
					const restoredStatus =
						sourceOutput?.status === OutputStatus.SPEND_CONFIRMED ||
						sourceOutput?.status === OutputStatus.IRREVOCABLY_RESOLVED
							? OutputStatus.SPEND_CONFIRMED
							: sourceOutput?.status ?? OutputStatus.CONFIRMED;
					const restoredOutput: ITrackedOutput = {
						txid: revokedTx.getId(),
						outputIndex,
						amount: BigInt(revokedTx.outs[outputIndex].value),
						outputType: metadata.outputType,
						// A newly inferred terminal member has never emitted its own
						// OUTPUT_RESOLVED action. Route it through SPEND_CONFIRMED so
						// block processing performs that per-output transition.
						status: restoredStatus,
						confirmationHeight:
							sourceOutput?.confirmationHeight ??
							monitor._commitmentBroadcast.blockHeight,
						witnessScript: metadata.witnessScript,
						paymentHash: metadata.paymentHash,
						cltvExpiry: metadata.cltvExpiry,
						sweepTxHex: sourceOutput?.sweepTxHex,
						broadcastHeight: sourceOutput?.broadcastHeight,
						originalFeeRate: sourceOutput?.originalFeeRate,
						currentFeeRate: sourceOutput?.currentFeeRate,
						resolutionTxid: sourceOutput?.resolutionTxid,
						maturityHeight: sourceOutput?.maturityHeight
					};
					monitor._trackedOutputs.push(restoredOutput);
					if (!sourceOutput) {
						// No stored transaction can manage this old claim. Allow the retry
						// pass to rebuild this output while preserving every other claim.
						monitor._commitmentBroadcast.claimedOutputIndices = (
							monitor._commitmentBroadcast.claimedOutputIndices ?? []
						).filter((claimedIndex) => claimedIndex !== outputIndex);
					}
				}
			} catch {
				// A malformed legacy transaction must not prevent monitor restore.
			}
		}
		if (
			monitor._state === MonitorState.FULLY_RESOLVED &&
			monitor._commitmentBroadcast?.commitmentType ===
				CommitmentType.THEIR_REVOKED_COMMITMENT &&
			!monitor._allTrackedOutputsResolved()
		) {
			monitor._state = MonitorState.RESOLVING;
		}
		// Pre-issue-338 state marked a cooperative close fully resolved at zero
		// confirmations. Unless the saved state itself proves the close reached
		// IRREVOCABLE_DEPTH, reopen resolution so the funding watch is re-armed
		// and handleNewBlock re-promotes at real depth. Legacy monitors stopped
		// receiving blocks at instant resolution, so their saved height sits at
		// the close height and they all demote once; the first deep block feed
		// re-resolves them. Only IRREVOCABLY_RESOLVED outputs are demoted:
		// a SPEND_CONFIRMED output keeps its resolutionTxid so the restart
		// re-arm can seed the recorded spend for reorg detection.
		if (
			monitor._state === MonitorState.FULLY_RESOLVED &&
			monitor._commitmentBroadcast?.commitmentType ===
				CommitmentType.COOPERATIVE_CLOSE &&
			(monitor._commitmentBroadcast.blockHeight <= 0 ||
				monitor._currentBlockHeight - monitor._commitmentBroadcast.blockHeight <
					IRREVOCABLE_DEPTH)
		) {
			monitor._state = MonitorState.RESOLVING;
			for (const output of monitor._trackedOutputs) {
				if (output.status === OutputStatus.IRREVOCABLY_RESOLVED) {
					output.status = OutputStatus.CONFIRMED;
				}
			}
		}
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

	private _allTrackedOutputsResolved(): boolean {
		return (
			this._trackedOutputs.length > 0 &&
			this._trackedOutputs.every(
				(output) =>
					output.status === OutputStatus.IRREVOCABLY_RESOLVED ||
					(this._commitmentBroadcast?.commitmentType ===
						CommitmentType.OUR_COMMITMENT &&
						output.outputType === OutputType.TO_REMOTE &&
						output.status === OutputStatus.CONFIRMED)
			)
		);
	}

	/**
	 * Update the fee rate used for sweep transactions.
	 *
	 * Returns any actions the new rate makes possible: a claim declined as
	 * uneconomic is retried as soon as the estimate that priced it out falls,
	 * rather than waiting for the next block. Callers that only want to set the
	 * rate can ignore the return value.
	 *
	 * @param feeRatePerKw Fee rate in sat/kw — converted to sat/vbyte internally.
	 */
	updateFeeRate(feeRatePerKw: number): ChainAction[] {
		// Convert sat/kw to sat/vbyte: 1 kw = 4 kvb, so sat/vbyte = sat/kw * 4 / 1000
		this._feeRatePerVbyte = Math.max(1, Math.round((feeRatePerKw * 4) / 1000));
		const actions: ChainAction[] = [];
		this._retryUnsweptRevokedSweeps(actions);
		this._retryUnsweptPeerCommitmentClaims(actions, true);
		return actions;
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

		// A cooperative close has no sweeps: its outputs pay each side's script
		// directly, so the only question is whether the close tx itself is buried
		// deep enough that a reorg can no longer evict it (issue 338: resolving at
		// zero confirmations tore down the funding watch, so a 1-block reorg
		// followed by a revoked commitment went unpunished). Depth is measured
		// from the close tx's own confirmation, never per-output heights: a
		// wallet spend of our close output must not restart the clock, and an
		// SCB-recovered state tracks zero outputs yet still needs to resolve.
		// A mempool-only sighting (blockHeight 0) never counts depth;
		// _adoptLateConfirmation starts the clock when the spend confirms.
		if (
			this._commitmentBroadcast?.commitmentType ===
			CommitmentType.COOPERATIVE_CLOSE
		) {
			const closeHeight = this._commitmentBroadcast.blockHeight;
			if (closeHeight > 0 && blockHeight - closeHeight >= IRREVOCABLE_DEPTH) {
				for (const output of this._trackedOutputs) {
					if (output.status === OutputStatus.IRREVOCABLY_RESOLVED) continue;
					output.status = OutputStatus.IRREVOCABLY_RESOLVED;
					actions.push({
						type: ChainActionType.OUTPUT_RESOLVED,
						txid: output.txid,
						outputIndex: output.outputIndex,
						channelId: this._channelState.channelId ?? undefined,
						outputType: output.outputType,
						paymentHash: output.paymentHash
					});
				}
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

		// Check each tracked output for maturation
		for (const output of this._trackedOutputs) {
			if (output.status === OutputStatus.IRREVOCABLY_RESOLVED) {
				continue;
			}

			// The PEER's to_remote on OUR commitment is tracked (classification
			// completeness) but only the peer can spend it. A vanished peer would
			// otherwise pin the monitor in RESOLVING forever, so an unspent one
			// does not block full resolution; once the peer does spend it, the
			// normal SPEND_CONFIRMED path below applies.
			if (
				this._commitmentBroadcast?.commitmentType ===
					CommitmentType.OUR_COMMITMENT &&
				output.outputType === OutputType.TO_REMOTE &&
				output.status === OutputStatus.CONFIRMED
			) {
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
		const handledSharedSweeps = new Set<string>();
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
				let rebuildOutputs = [output];
				const sharedPenaltyHex =
					this._commitmentBroadcast?.commitmentType ===
					CommitmentType.THEIR_REVOKED_COMMITMENT
						? output.sweepTxHex
						: undefined;
				if (sharedPenaltyHex) {
					if (handledSharedSweeps.has(sharedPenaltyHex)) continue;
					handledSharedSweeps.add(sharedPenaltyHex);
					rebuildOutputs = this._trackedOutputs.filter(
						(candidate) =>
							candidate.status === OutputStatus.SPEND_BROADCAST &&
							candidate.sweepTxHex === sharedPenaltyHex
					);
				}
				const blocksSinceBroadcast = blockHeight - output.broadcastHeight;
				if (blocksSinceBroadcast >= REBROADCAST_INTERVAL) {
					// Bump the fee rate, but never below the current network estimate
					// (the node feeds live rates via updateFeeRate). This lets a sweep
					// catch up to a fee spike instead of crawling 1.5x per interval.
					// Anti-runaway cap: 10x the build-time rate OR the live rate,
					// whichever is larger — a sweep built at a stale low rate (e.g.
					// the 10 sat/vB restore default) must still reach the live rate.
					const originalRate = Math.max(
						...rebuildOutputs.map(
							(candidate) => candidate.originalFeeRate || this._feeRatePerVbyte
						)
					);
					const currentRate = Math.max(
						...rebuildOutputs.map(
							(candidate) => candidate.currentFeeRate || originalRate
						)
					);
					const bumpedRate = Math.min(
						Math.max(currentRate * FEE_BUMP_FACTOR, this._feeRatePerVbyte),
						Math.max(
							originalRate * MAX_FEE_BUMP_MULTIPLIER,
							this._feeRatePerVbyte
						)
					);
					// Rebuild and fallback decisions use the actual resolver result. A
					// size estimate can disagree at the dust boundary, and a shared batch
					// can split as one of its HTLCs becomes urgent.
					actions.push({
						type: ChainActionType.REBUILD_SWEEP,
						output,
						feeRatePerVbyte: bumpedRate
					});
				}
			}
		}

		// Retry claims that were declined as uneconomic. The loops above only ever
		// rebuild a sweep that already reached SPEND_BROADCAST, so without this a
		// claim skipped during a fee spike is never revisited even after the spike
		// passes.
		this._retryUnsweptRevokedSweeps(actions);
		this._retryUnsweptPeerCommitmentClaims(actions);

		// A retry can adopt a snapshot-reconstructed output after the scan above.
		// Recompute from the current tracked set so a new in-flight claim cannot be
		// followed by CHANNEL_FULLY_RESOLVED in the same block.
		// Check if all outputs are irrevocably resolved
		if (this._allTrackedOutputsResolved()) {
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
		const spentIndices = new Set<number>();
		for (const input of spendingTx.ins) {
			if (Buffer.from(input.hash).reverse().toString('hex') === txid) {
				spentIndices.add(input.index);
			}
		}
		const spentTrackedOutputs = this._trackedOutputs.filter(
			(candidate) =>
				candidate.txid === txid && spentIndices.has(candidate.outputIndex)
		);

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
			spentTrackedOutputs.some(
				(candidate) =>
					candidate.outputType === OutputType.OFFERED_HTLC ||
					candidate.outputType === OutputType.RECEIVED_HTLC
			) &&
			this._commitmentBroadcast?.commitmentType ===
				CommitmentType.THEIR_REVOKED_COMMITMENT
		) {
			// Our own penalty confirming resolves the HTLC output — nothing to claim.
			let isOurPenalty = false;
			for (const spentTrackedOutput of spentTrackedOutputs) {
				if (!spentTrackedOutput.sweepTxHex) continue;
				try {
					if (
						bitcoin.Transaction.fromHex(
							spentTrackedOutput.sweepTxHex
						).getId() === spendingTx.getId()
					) {
						isOurPenalty = true;
						break;
					}
				} catch {
					// Ignore malformed retained sweep metadata and let the
					// second-level resolver inspect the external spend.
				}
			}
			if (!isOurPenalty) {
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

		// The transaction proves every matching watched input spent atomically.
		// Apply that shared fact only after the whole-transaction HTLC follow-up
		// paths above have run, so later per-output callbacks can be idempotent
		// without suppressing second-level handling.
		for (const spentTrackedOutput of spentTrackedOutputs) {
			spentTrackedOutput.status = OutputStatus.SPEND_CONFIRMED;
			spentTrackedOutput.resolutionTxid = spendingTx.getId();
			spentTrackedOutput.confirmationHeight = blockHeight;
		}

		this._repairRevokedSharedSweepAfterConflict(spendingTx, actions);
		return actions;
	}

	/**
	 * A competing spend of one shared penalty input invalidates the whole stored
	 * batch. Rebuild the surviving members immediately instead of waiting six
	 * blocks to discover that the old transaction can no longer confirm.
	 */
	private _repairRevokedSharedSweepAfterConflict(
		spendingTx: bitcoin.Transaction,
		actions: ChainAction[]
	): void {
		const broadcast = this._commitmentBroadcast;
		if (broadcast?.commitmentType !== CommitmentType.THEIR_REVOKED_COMMITMENT) {
			return;
		}
		const spentIndices = new Set<number>();
		for (const input of spendingTx.ins) {
			if (
				Buffer.from(input.hash).reverse().toString('hex') === broadcast.txid
			) {
				spentIndices.add(input.index);
			}
		}
		const affectedSweepHexes = new Set<string>();
		// A single competing transaction can invalidate more than one stored
		// shared cohort. Collect every affected sweep independently of which
		// output's watch delivered this callback first.
		for (const candidate of this._trackedOutputs) {
			if (
				candidate.txid === broadcast.txid &&
				spentIndices.has(candidate.outputIndex)
			) {
				if (candidate.sweepTxHex) {
					affectedSweepHexes.add(candidate.sweepTxHex);
				}
			}
		}
		const claimed = new Set(broadcast.claimedOutputIndices ?? []);
		let hasSurvivors = false;
		for (const sweepHex of affectedSweepHexes) {
			let oldSweep: bitcoin.Transaction;
			try {
				oldSweep = bitcoin.Transaction.fromHex(sweepHex);
			} catch {
				continue;
			}
			if (oldSweep.getId() === spendingTx.getId()) continue;
			const oldIndices = new Set<number>();
			for (const input of oldSweep.ins) {
				if (
					Buffer.from(input.hash).reverse().toString('hex') === broadcast.txid
				) {
					oldIndices.add(input.index);
				}
			}
			if (oldIndices.size <= 1) continue;
			const survivors = this._trackedOutputs.filter(
				(candidate) =>
					candidate.txid === broadcast.txid &&
					oldIndices.has(candidate.outputIndex) &&
					!spentIndices.has(candidate.outputIndex) &&
					candidate.status === OutputStatus.SPEND_BROADCAST &&
					candidate.sweepTxHex === sweepHex
			);
			if (survivors.length === 0) continue;
			hasSurvivors = true;
			for (const outputIndex of oldIndices) claimed.delete(outputIndex);
			for (const survivor of survivors) {
				survivor.status = OutputStatus.CONFIRMED;
				survivor.sweepTxHex = undefined;
				survivor.broadcastHeight = undefined;
				survivor.originalFeeRate = undefined;
				survivor.currentFeeRate = undefined;
				survivor.maturityHeight = undefined;
				survivor.resolutionTxid = undefined;
			}
		}
		if (hasSurvivors) {
			broadcast.claimedOutputIndices = [...claimed];
			this._retryUnsweptRevokedSweeps(actions);
		}
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
		const actions: ChainAction[] = [];
		if (
			output.status !== OutputStatus.SPEND_CONFIRMED &&
			output.status !== OutputStatus.IRREVOCABLY_RESOLVED &&
			output.status !== OutputStatus.SPEND_BROADCAST
		) {
			return [];
		}

		// A multi-input spend can be recorded atomically after only one watched
		// outpoint reports it. Reopen every output tied to that same transaction
		// when any one watch later reports the reorg.
		const previousResolutionTxid = output.resolutionTxid;
		const reorgedOutputs = previousResolutionTxid
			? this._trackedOutputs.filter(
					(candidate) =>
						candidate.txid === txid &&
						candidate.resolutionTxid === previousResolutionTxid
			  )
			: [output];
		for (const candidate of reorgedOutputs) {
			candidate.resolutionTxid = undefined;
		}
		// If the monitor had declared the channel fully resolved on the strength of
		// this spend, resume resolving so handleNewBlock keeps working the output.
		if (this._state === MonitorState.FULLY_RESOLVED) {
			this._state = MonitorState.RESOLVING;
		}

		const revokedBroadcast =
			this._commitmentBroadcast?.commitmentType ===
				CommitmentType.THEIR_REVOKED_COMMITMENT &&
			this._commitmentBroadcast.txid === txid
				? this._commitmentBroadcast
				: undefined;
		if (revokedBroadcast) {
			const rawRebroadcasts = new Map<
				string,
				{ output: ITrackedOutput; tx: bitcoin.Transaction }
			>();
			const claimed = new Set(revokedBroadcast.claimedOutputIndices ?? []);
			for (const reorgedOutput of reorgedOutputs) {
				let retainedSweep: bitcoin.Transaction | undefined;
				let retainedHex = reorgedOutput.sweepTxHex;
				try {
					if (retainedHex) {
						retainedSweep = bitcoin.Transaction.fromHex(retainedHex);
					}
				} catch {
					retainedSweep = undefined;
					retainedHex = undefined;
				}

				const oldIndices = new Set<number>();
				if (retainedSweep) {
					for (const input of retainedSweep.ins) {
						if (Buffer.from(input.hash).reverse().toString('hex') === txid) {
							oldIndices.add(input.index);
						}
					}
				}
				const oldSweepTxid = retainedSweep?.getId();
				const staleSharedSweep =
					retainedSweep !== undefined &&
					oldIndices.size > 1 &&
					previousResolutionTxid !== oldSweepTxid &&
					this._trackedOutputs.some(
						(candidate) =>
							candidate.txid === txid &&
							oldIndices.has(candidate.outputIndex) &&
							!reorgedOutputs.includes(candidate) &&
							(((candidate.status === OutputStatus.SPEND_CONFIRMED ||
								candidate.status === OutputStatus.IRREVOCABLY_RESOLVED) &&
								candidate.resolutionTxid !== oldSweepTxid) ||
								(candidate.status === OutputStatus.SPEND_BROADCAST &&
									candidate.sweepTxHex !== retainedHex))
					);

				if (!retainedSweep || staleSharedSweep) {
					reorgedOutput.status = OutputStatus.CONFIRMED;
					reorgedOutput.confirmationHeight = revokedBroadcast.blockHeight;
					reorgedOutput.sweepTxHex = undefined;
					reorgedOutput.broadcastHeight = undefined;
					reorgedOutput.originalFeeRate = undefined;
					reorgedOutput.currentFeeRate = undefined;
					reorgedOutput.maturityHeight = undefined;
					claimed.delete(reorgedOutput.outputIndex);
					continue;
				}

				for (const candidate of this._trackedOutputs) {
					if (
						candidate.txid === txid &&
						oldIndices.has(candidate.outputIndex) &&
						(candidate.resolutionTxid === undefined ||
							candidate.resolutionTxid === oldSweepTxid)
					) {
						candidate.status = OutputStatus.SPEND_BROADCAST;
						candidate.resolutionTxid = undefined;
						candidate.confirmationHeight = revokedBroadcast.blockHeight;
						candidate.sweepTxHex = retainedHex;
						candidate.originalFeeRate = reorgedOutput.originalFeeRate;
						candidate.currentFeeRate = reorgedOutput.currentFeeRate;
						candidate.maturityHeight = undefined;
						candidate.broadcastHeight = this._currentBlockHeight;
					}
				}
				for (const oldIndex of oldIndices) claimed.add(oldIndex);
				rawRebroadcasts.set(retainedSweep.getId(), {
					output: reorgedOutput,
					tx: retainedSweep
				});
			}
			revokedBroadcast.claimedOutputIndices = [...claimed];
			for (const { output: representative, tx } of rawRebroadcasts.values()) {
				actions.push(
					this._broadcastSweepAction(
						representative,
						tx.toBuffer(),
						`${representative.outputType.toLowerCase()} re-broadcast (reorg recovery)`
					)
				);
			}
			this._retryUnsweptRevokedSweeps(actions);
			return actions;
		}

		// Re-arm every output tied to the evicted transaction. This is normally
		// one output, but a backend can report a multi-input spend through only one
		// watch before it disappears. Deduplicate a shared raw sweep if present.
		const rawRebroadcasts = new Map<string, ITrackedOutput>();
		for (const reorgedOutput of reorgedOutputs) {
			// handleOutputSpent overwrote confirmationHeight with the SPEND's height.
			// Now that the spend is gone, put the commitment's own height back: every
			// timelock on this output (its CSV base, its contest height, the maturity
			// of a claim rebuilt below) counts from the transaction that CREATED it.
			if (
				this._commitmentBroadcast?.txid === reorgedOutput.txid &&
				this._commitmentBroadcast.blockHeight > 0
			) {
				reorgedOutput.confirmationHeight =
					this._commitmentBroadcast.blockHeight;
			}
			if (reorgedOutput.sweepTxHex) {
				let maturityHeight = reorgedOutput.maturityHeight;
				if (maturityHeight === undefined) {
					try {
						maturityHeight = this._computeMaturityHeight(
							bitcoin.Transaction.fromHex(reorgedOutput.sweepTxHex),
							reorgedOutput.confirmationHeight
						);
						reorgedOutput.maturityHeight = maturityHeight;
					} catch {
						maturityHeight = this._currentBlockHeight;
					}
				}
				if (this._currentBlockHeight < maturityHeight) {
					// A competing spend can disappear before our retained timeout or
					// CSV claim matures. Keep it held instead of broadcasting a
					// transaction the network must reject as non-final.
					reorgedOutput.status = OutputStatus.CONFIRMED;
					reorgedOutput.broadcastHeight = undefined;
					continue;
				}
				reorgedOutput.status = OutputStatus.SPEND_BROADCAST;
				reorgedOutput.broadcastHeight = this._currentBlockHeight;
				rawRebroadcasts.set(reorgedOutput.sweepTxHex, reorgedOutput);
			} else {
				reorgedOutput.status = OutputStatus.CONFIRMED;
			}
		}
		for (const [sweepHex, representative] of rawRebroadcasts) {
			actions.push(
				this._broadcastSweepAction(
					representative,
					Buffer.from(sweepHex, 'hex'),
					`${representative.outputType.toLowerCase()} re-broadcast (reorg recovery)`
				)
			);
		}
		this._retryUnsweptPeerCommitmentClaims(actions);
		return actions;
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
			this._reportDeclinedClaims(
				actions,
				resolved
					.filter((r) => r.declinedAsUneconomic)
					.map((r) => r.trackedOutput)
			);
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
		// A cooperative close has nothing to sweep, but it is NOT resolved until
		// the close tx is buried IRREVOCABLE_DEPTH deep (issue 338). Resolving
		// here, at as little as a mempool sighting, emitted CHANNEL_FULLY_RESOLVED
		// which tore down the funding watch and made restart skip re-arming it, so
		// a reorg that evicted the close followed by a revoked commitment on the
		// still-live funding output went undetected and unpunished. Stay in
		// RESOLVING so the funding watch and the commitment-swap reclassify path
		// in handleFundingSpent survive the window; handleNewBlock promotes the
		// outputs and the monitor once the close reaches depth.
		this._state = MonitorState.RESOLVING;
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

		this._reportDeclinedClaims(
			actions,
			resolved.filter((r) => r.declinedAsUneconomic).map((r) => r.trackedOutput)
		);

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

		// Reporting from the first pass keeps a decline visible even when the next
		// fee sample immediately recovers it.
		this._reportDeclinedClaims(
			actions,
			resolved.filter((r) => r.declinedAsUneconomic).map((r) => r.trackedOutput)
		);

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
		const rebuilt =
			this._commitmentBroadcast?.commitmentType ===
				CommitmentType.THEIR_REVOKED_COMMITMENT &&
			output.sweepTxHex &&
			!output.secondLevelTxHex
				? this._rebuildRevokedPenaltySweeps(output, feeRatePerVbyte, false)
				: [this._rebuildSingleSweep(output, feeRatePerVbyte)].filter(
						(tx): tx is bitcoin.Transaction => !!tx
				  );
		return (
			rebuilt.find((tx) =>
				tx.ins.some(
					(input) =>
						Buffer.from(input.hash).reverse().toString('hex') === output.txid &&
						input.index === output.outputIndex
				)
			) ??
			rebuilt[0] ??
			null
		);
	}

	/**
	 * Return the complete replacement set. A shared revoked penalty can split
	 * into several transactions when one of its HTLCs becomes urgent.
	 */
	rebuildSweeps(
		output: ITrackedOutput,
		feeRatePerVbyte: number
	): bitcoin.Transaction[] {
		if (
			this._commitmentBroadcast?.commitmentType ===
				CommitmentType.THEIR_REVOKED_COMMITMENT &&
			output.sweepTxHex &&
			!output.secondLevelTxHex
		) {
			return this._rebuildRevokedPenaltySweeps(output, feeRatePerVbyte, true);
		}
		const rebuilt = this._rebuildSingleSweep(output, feeRatePerVbyte);
		return rebuilt ? [rebuilt] : [];
	}

	private _rebuildSingleSweep(
		output: ITrackedOutput,
		feeRatePerVbyte: number,
		replacementAttempt = 0
	): bitcoin.Transaction | null {
		if (!this._commitmentBroadcast) return null;
		let previousSweep: bitcoin.Transaction | undefined;
		if (output.sweepTxHex) {
			try {
				const parsedSweep = bitcoin.Transaction.fromHex(output.sweepTxHex);
				const expectedInput =
					parsedSweep.ins.length === 1 && parsedSweep.ins[0];
				if (
					expectedInput &&
					Buffer.from(expectedInput.hash).reverse().toString('hex') ===
						output.txid &&
					expectedInput.index === output.outputIndex
				) {
					previousSweep = parsedSweep;
				}
				// A parseable transaction for another outpoint is stale metadata, not
				// a replacement baseline. Rebuild the intended claim from retained
				// commitment context instead of rebroadcasting the unrelated tx.
				if (!previousSweep)
					throw new Error('stored sweep spends another outpoint');
				if (!previousSweep.ins.some((input) => input.sequence < 0xfffffffe)) {
					// A legacy final-sequence claim cannot be replaced under
					// opt-in RBF. Keep rebroadcasting the transaction the backend
					// may already have instead of recording an unrelayable rebuild.
					output.broadcastHeight = this._currentBlockHeight;
					return previousSweep;
				}
			} catch {
				// Rebuild undecodable or mismatched metadata from retained context.
				previousSweep = undefined;
			}
		}
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
					const rebuildOutputs = [output];
					const claimedOutsideBatch = new Set<number>();
					for (let i = 0; i < revokedTx.outs.length; i++) {
						if (i !== output.outputIndex) claimedOutsideBatch.add(i);
					}
					resolved = resolveRevokedCommitmentOutputs(
						this._channelState,
						rebuildOutputs,
						this._commitmentBroadcast.commitmentNumber,
						revokedTx,
						this._destinationScript,
						feeRatePerVbyte,
						this._revocationBasepointSecret,
						this._paymentPrivkey,
						this._network,
						this._currentBlockHeight,
						claimedOutsideBatch
					);
					break;
				}
				default:
					return null;
			}
		} catch {
			if (previousSweep) {
				output.broadcastHeight = this._currentBlockHeight;
				return previousSweep;
			}
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
			if (previousSweep) {
				const feeForSingleInput = (
					tx: bitcoin.Transaction
				): number | undefined => {
					if (tx.ins.length !== 1) return undefined;
					const input = tx.ins[0];
					if (
						Buffer.from(input.hash).reverse().toString('hex') !== output.txid ||
						input.index !== output.outputIndex
					) {
						return undefined;
					}
					return (
						Number(output.amount) -
						tx.outs.reduce((sum, txOutput) => sum + txOutput.value, 0)
					);
				};
				const oldFee = feeForSingleInput(previousSweep);
				const replacementFee = feeForSingleInput(match.spendTx);
				const requiredFee =
					oldFee === undefined
						? undefined
						: oldFee + match.spendTx.virtualSize();
				if (
					oldFee === undefined ||
					replacementFee === undefined ||
					requiredFee === undefined ||
					replacementFee < requiredFee
				) {
					const maxRebuildRate = Math.max(
						(output.originalFeeRate ?? feeRatePerVbyte) *
							MAX_FEE_BUMP_MULTIPLIER,
						this._feeRatePerVbyte
					);
					const shortfall =
						replacementFee !== undefined && requiredFee !== undefined
							? requiredFee - replacementFee
							: 0;
					const nextRate = Math.min(
						maxRebuildRate,
						feeRatePerVbyte +
							Math.max(1, Math.ceil(shortfall / match.spendTx.virtualSize()))
					);
					if (
						replacementAttempt < 3 &&
						nextRate > feeRatePerVbyte &&
						oldFee !== undefined &&
						replacementFee !== undefined
					) {
						return this._rebuildSingleSweep(
							output,
							nextRate,
							replacementAttempt + 1
						);
					}
					output.broadcastHeight = this._currentBlockHeight;
					return previousSweep;
				}
			}
			const rebuiltHex = match.spendTx.toHex();
			const spentOutpoints = new Set(
				match.spendTx.ins.map(
					(input) =>
						`${Buffer.from(input.hash).reverse().toString('hex')}:${
							input.index
						}`
				)
			);
			for (const candidate of this._trackedOutputs) {
				if (spentOutpoints.has(`${candidate.txid}:${candidate.outputIndex}`)) {
					candidate.status = OutputStatus.SPEND_BROADCAST;
					candidate.sweepTxHex = rebuiltHex;
					candidate.currentFeeRate = feeRatePerVbyte;
					candidate.broadcastHeight = this._currentBlockHeight;
				}
			}
			return match.spendTx;
		}
		if (previousSweep) {
			output.broadcastHeight = this._currentBlockHeight;
			return previousSweep;
		}
		return null;
	}

	private _rebuildRevokedPenaltySweeps(
		output: ITrackedOutput,
		feeRatePerVbyte: number,
		allowDeadlineSplit: boolean
	): bitcoin.Transaction[] {
		const broadcast = this._commitmentBroadcast;
		if (
			!broadcast ||
			broadcast.commitmentType !== CommitmentType.THEIR_REVOKED_COMMITMENT ||
			!broadcast.revokedTxHex ||
			!output.sweepTxHex
		) {
			return [];
		}

		let revokedTx: bitcoin.Transaction;
		let oldSweep: bitcoin.Transaction;
		try {
			revokedTx = bitcoin.Transaction.fromHex(broadcast.revokedTxHex);
			oldSweep = bitcoin.Transaction.fromHex(output.sweepTxHex);
		} catch {
			return [];
		}
		if (output.txid !== revokedTx.getId()) return [];

		const liveGroup = this._trackedOutputs.filter(
			(candidate) =>
				candidate.txid === revokedTx.getId() &&
				candidate.status === OutputStatus.SPEND_BROADCAST &&
				candidate.sweepTxHex === output.sweepTxHex
		);
		if (liveGroup.length === 0) return [];

		const commitmentInputIndices = (tx: bitcoin.Transaction): Set<number> => {
			const indices = new Set<number>();
			for (const input of tx.ins) {
				if (
					Buffer.from(input.hash).reverse().toString('hex') ===
					revokedTx.getId()
				) {
					indices.add(input.index);
				}
			}
			return indices;
		};
		const oldIndices = commitmentInputIndices(oldSweep);
		const liveIndices = new Set(
			liveGroup.map((candidate) => candidate.outputIndex)
		);

		// If the old transaction itself confirmed, all of its inputs were spent
		// atomically even when only one output watch has fired so far.
		const confirmedOldSweep = this._trackedOutputs.find(
			(candidate) =>
				oldIndices.has(candidate.outputIndex) &&
				(candidate.status === OutputStatus.SPEND_CONFIRMED ||
					candidate.status === OutputStatus.IRREVOCABLY_RESOLVED) &&
				candidate.resolutionTxid === oldSweep.getId()
		);
		if (confirmedOldSweep) {
			for (const candidate of liveGroup) {
				// Even when the watched sibling already reached final depth, route
				// inferred members through SPEND_CONFIRMED so each one emits its own
				// OUTPUT_RESOLVED action on the next block.
				candidate.status = OutputStatus.SPEND_CONFIRMED;
				candidate.resolutionTxid = confirmedOldSweep.resolutionTxid;
				candidate.confirmationHeight = confirmedOldSweep.confirmationHeight;
			}
			return [];
		}
		const oldStillValid =
			oldIndices.size === liveIndices.size &&
			[...oldIndices].every((outputIndex) => liveIndices.has(outputIndex));
		if (
			oldStillValid &&
			!oldSweep.ins.some((input) => input.sequence < 0xfffffffe)
		) {
			// A legacy final-sequence transaction cannot be replaced under
			// opt-in RBF policy. Keep the only relayable claim under management.
			for (const candidate of liveGroup) {
				candidate.broadcastHeight = this._currentBlockHeight;
			}
			return [oldSweep];
		}

		// Exclude every output outside the old live cohort. The revoked resolver
		// also scans snapshot HTLCs, and an unrestricted rebuild could steal an
		// independently urgent output into this replacement.
		const claimedOutside = new Set<number>();
		for (let i = 0; i < revokedTx.outs.length; i++) {
			if (!liveIndices.has(i)) claimedOutside.add(i);
		}
		const resolveGroup = (
			currentHeight: number | undefined,
			targetFeeRate: number
		): ReturnType<typeof resolveRevokedCommitmentOutputs> => {
			try {
				return resolveRevokedCommitmentOutputs(
					this._channelState,
					liveGroup,
					broadcast.commitmentNumber,
					revokedTx,
					this._destinationScript,
					targetFeeRate,
					this._revocationBasepointSecret,
					this._paymentPrivkey,
					this._network,
					currentHeight,
					claimedOutside
				);
			} catch {
				return [];
			}
		};
		const collectTransactions = (
			resolved: ReturnType<typeof resolveRevokedCommitmentOutputs>
		): bitcoin.Transaction[] => {
			const unique = new Map<string, bitcoin.Transaction>();
			for (const entry of resolved) {
				if (!entry.spendTx) continue;
				if (entry.witness && entry.spendTx.ins[0]?.witness.length === 0) {
					entry.spendTx.setWitness(0, entry.witness);
				}
				const spent = commitmentInputIndices(entry.spendTx);
				if (
					spent.size === 0 ||
					[...spent].some((outputIndex) => !liveIndices.has(outputIndex))
				) {
					continue;
				}
				unique.set(entry.spendTx.getId(), entry.spendTx);
			}
			return [...unique.values()];
		};
		const transactionFee = (tx: bitcoin.Transaction): number | undefined => {
			let totalIn = 0;
			for (const input of tx.ins) {
				if (
					Buffer.from(input.hash).reverse().toString('hex') !==
					revokedTx.getId()
				) {
					return undefined;
				}
				const previousOutput = revokedTx.outs[input.index];
				if (!previousOutput) return undefined;
				totalIn += previousOutput.value;
			}
			return (
				totalIn - tx.outs.reduce((sum, txOutput) => sum + txOutput.value, 0)
			);
		};

		const oldFee = transactionFee(oldSweep);
		const orderByFee = (transactions: bitcoin.Transaction[]): void => {
			transactions.sort(
				(a, b) =>
					(transactionFee(b) ?? Number.MIN_SAFE_INTEGER) -
					(transactionFee(a) ?? Number.MIN_SAFE_INTEGER)
			);
		};
		const paysForEviction = (transactions: bitcoin.Transaction[]): boolean => {
			if (transactions.length === 0 || oldFee === undefined) return false;
			orderByFee(transactions);
			const firstFee = transactionFee(transactions[0]);
			return (
				firstFee !== undefined &&
				firstFee >= oldFee + transactions[0].virtualSize()
			);
		};
		const maxRebuildRate = Math.max(
			...liveGroup.map(
				(candidate) =>
					(candidate.originalFeeRate ?? feeRatePerVbyte) *
					MAX_FEE_BUMP_MULTIPLIER
			),
			this._feeRatePerVbyte
		);
		const buildPayingReplacement = (
			currentHeight: number | undefined
		): { transactions: bitcoin.Transaction[]; feeRate: number } => {
			let targetFeeRate = feeRatePerVbyte;
			for (let attempt = 0; attempt < 3; attempt++) {
				const transactions = collectTransactions(
					resolveGroup(currentHeight, targetFeeRate)
				);
				if (transactions.length === 0) {
					return { transactions: [], feeRate: targetFeeRate };
				}
				if (!oldStillValid || paysForEviction(transactions)) {
					return { transactions, feeRate: targetFeeRate };
				}
				orderByFee(transactions);
				const firstFee = transactionFee(transactions[0]);
				if (firstFee === undefined || oldFee === undefined) {
					return { transactions: [], feeRate: targetFeeRate };
				}
				const shortfall = oldFee + transactions[0].virtualSize() - firstFee;
				const nextRate = Math.min(
					maxRebuildRate,
					targetFeeRate +
						Math.max(1, Math.ceil(shortfall / transactions[0].virtualSize()))
				);
				if (nextRate <= targetFeeRate) {
					return { transactions: [], feeRate: targetFeeRate };
				}
				targetFeeRate = nextRate;
			}
			return { transactions: [], feeRate: targetFeeRate };
		};

		let replacementResult = buildPayingReplacement(
			allowDeadlineSplit ? this._currentBlockHeight : undefined
		);
		if (
			allowDeadlineSplit &&
			replacementResult.transactions.length === 0 &&
			oldStillValid
		) {
			// A deadline split may be unable to evict the larger old batch even
			// though a full-group replacement remains economical.
			replacementResult = buildPayingReplacement(undefined);
		}
		const replacements = replacementResult.transactions;
		const appliedFeeRate = replacementResult.feeRate;

		if (replacements.length === 0) {
			if (oldStillValid) {
				for (const candidate of liveGroup) {
					candidate.broadcastHeight = this._currentBlockHeight;
				}
				return [oldSweep];
			}
		}

		// Replace the old cohort atomically. Claimed indices describe only current
		// managed claims, not stale inputs from an invalidated batch.
		const claimed = new Set(broadcast.claimedOutputIndices ?? []);
		for (const outputIndex of oldIndices) claimed.delete(outputIndex);
		const replacementByIndex = new Map<number, bitcoin.Transaction>();
		for (const replacement of replacements) {
			for (const outputIndex of commitmentInputIndices(replacement)) {
				claimed.add(outputIndex);
				replacementByIndex.set(outputIndex, replacement);
			}
		}
		broadcast.claimedOutputIndices = [...claimed];

		for (const candidate of liveGroup) {
			const replacement = replacementByIndex.get(candidate.outputIndex);
			if (replacement) {
				candidate.status = OutputStatus.SPEND_BROADCAST;
				candidate.sweepTxHex = replacement.toHex();
				candidate.originalFeeRate ??= appliedFeeRate;
				candidate.currentFeeRate = appliedFeeRate;
				candidate.broadcastHeight = this._currentBlockHeight;
				candidate.resolutionTxid = undefined;
				continue;
			}
			// The old batch no longer manages this member. Return it to the retry
			// set instead of retaining a transaction that can no longer confirm.
			candidate.status = OutputStatus.CONFIRMED;
			candidate.sweepTxHex = undefined;
			candidate.broadcastHeight = undefined;
			candidate.originalFeeRate = undefined;
			candidate.currentFeeRate = undefined;
			candidate.maturityHeight = undefined;
			candidate.resolutionTxid = undefined;
		}

		return replacements;
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
			this._network,
			// Lets the resolver split a near-cltv-deadline HTLC input into its
			// own penalty tx (independent broadcast + fee-bump fate).
			this._currentBlockHeight
		);

		this._recordPenaltyBroadcasts(
			actions,
			resolved,
			'penalty sweep (revoked commitment)'
		);
		// Report anything this first pass declined. Waiting for the first retry to
		// report would lose the decline entirely whenever the very next fee
		// estimate recovers the claim.
		if (this._commitmentBroadcast) {
			this._reportDeclinedClaims(
				actions,
				this._revokedCommitmentOutputs(this._commitmentBroadcast)
			);
		}

		return actions;
	}

	/**
	 * Broadcast the spends a revoked-commitment resolution produced and record
	 * each against its output. A batched penalty produces one resolved entry PER
	 * INPUT sharing the same tx, and the deadline split can yield several distinct
	 * txs, so each distinct tx is broadcast exactly once.
	 */
	private _recordPenaltyBroadcasts(
		actions: ChainAction[],
		resolved: ReturnType<typeof resolveRevokedCommitmentOutputs>,
		description: string
	): void {
		const broadcastTxids = new Set<string>();
		for (const entry of resolved) {
			// Adopt before anything else: a settled-HTLC output rebuilt from the
			// snapshot is not in the tracked set, and writing this pass's bookkeeping
			// to a value that is then discarded is what left those claims unwatched,
			// never rebroadcast, and outside full-resolution accounting.
			const r = {
				...entry,
				trackedOutput: this._adoptPenaltyOutput(actions, entry.trackedOutput)
			};
			if (
				r.trackedOutput.status === OutputStatus.SPEND_CONFIRMED ||
				r.trackedOutput.status === OutputStatus.IRREVOCABLY_RESOLVED
			) {
				continue;
			}
			if (!r.spendTx) continue;
			// Penalty txs come back with every input's witness already attached; a
			// to_remote claim (our own balance on their revoked commitment) comes
			// back with its witness alongside the tx instead, and broadcasting it
			// unsigned strands the balance. Attach it ONLY while input 0 is still
			// unsigned, so a batched penalty, one entry per input, each carrying
			// its own witness, never has input 0 overwritten.
			if (r.witness && r.spendTx.ins[0]?.witness.length === 0) {
				r.spendTx.setWitness(0, r.witness);
			}
			const txBuf = r.spendTx.toBuffer();
			if (!broadcastTxids.has(r.spendTx.getId())) {
				broadcastTxids.add(r.spendTx.getId());
				this._recordClaimedOutpoints(r.spendTx);
				actions.push({
					type: ChainActionType.BROADCAST_TX,
					tx: txBuf,
					description
				});
			}
			r.trackedOutput.status = OutputStatus.SPEND_BROADCAST;
			r.trackedOutput.broadcastHeight = this._currentBlockHeight;
			r.trackedOutput.originalFeeRate = this._feeRatePerVbyte;
			r.trackedOutput.sweepTxHex = txBuf.toString('hex');
		}
	}

	/**
	 * Height at which a COMPETING spend path opens for a peer-commitment output,
	 * when one is bounded and known.
	 *
	 * This is urgency, never a stopping condition. None of these heights
	 * invalidates our revocation spend: it stays valid for as long as the outpoint
	 * is unspent, so a claim skipped as uneconomic is still worth building after
	 * the height passes. Only an actual spend ends the claim.
	 *
	 * - their to_local: their delayed branch opens at the CSV in the ON-CHAIN
	 *   script, which on a leased channel is the lease lock rather than the
	 *   to_self_delay we configured (update_blockheight moves it over the
	 *   channel's life, so current state can disagree with what they signed).
	 * - an HTLC WE receive: their pre-signed HTLC-timeout opens at cltv_expiry;
	 *   anchor-style claims also require one confirmation-relative block.
	 * - an HTLC WE offered: theirs to claim with the preimage at any moment, so
	 *   there is no height to name.
	 * - our to_remote: our own balance, which no one else can spend.
	 */
	private _contestHeight(output: ITrackedOutput): number | undefined {
		switch (output.outputType) {
			case OutputType.TO_LOCAL: {
				// A relative delay needs the height it counts from. A mempool-first
				// sighting has none yet, and treating that as 0 would name a height
				// already behind the tip and report a race that has not started.
				// _adoptLateConfirmation fills the height in once the commitment
				// confirms, and the real transition is reported from there.
				if (output.confirmationHeight <= 0) return undefined;
				const scriptCsv = output.witnessScript
					? csvFromToLocalScript(output.witnessScript)
					: undefined;
				return (
					output.confirmationHeight +
					(scriptCsv ?? this._channelState.localConfig.toSelfDelay)
				);
			}
			case OutputType.RECEIVED_HTLC:
				if (output.cltvExpiry === undefined) return undefined;
				if (!isAnchorChannel(this._channelState.channelType)) {
					return output.cltvExpiry;
				}
				// Anchor and Taproot HTLC-timeout inputs carry CSV-1. While the
				// commitment is only in the mempool there is no relative-lock base,
				// and after confirmation both the absolute and relative locks apply.
				if (output.confirmationHeight <= 0) return undefined;
				return Math.max(output.cltvExpiry, output.confirmationHeight + 1);
			default:
				return undefined;
		}
	}

	/**
	 * Return the tracked output a resolution entry refers to, adopting it into the
	 * tracked set first if it is not there yet.
	 *
	 * The revoked resolver rebuilds settled-HTLC outputs from revokedHtlcSnapshots
	 * (an HTLC that left state.htlcs, whose output the live classification never
	 * matched). Those arrive as stand-ins that belong to no tracked output, so
	 * without adoption nothing watches the outpoint, nothing rebroadcasts or
	 * fee-bumps the claim if it stalls, the second-level justice path can never
	 * fire for it, and full resolution is declared over a claim still in flight.
	 */
	private _adoptPenaltyOutput(
		actions: ChainAction[],
		candidate: ITrackedOutput
	): ITrackedOutput {
		const existing = this._trackedOutputs.find(
			(o) =>
				o.txid === candidate.txid && o.outputIndex === candidate.outputIndex
		);
		if (existing) return existing;
		// A fee update can discover a snapshot output on a monitor restored from
		// older state that already said it was fully resolved. The adopted output is
		// unresolved, so block processing must resume immediately.
		if (this._state === MonitorState.FULLY_RESOLVED) {
			this._state = MonitorState.RESOLVING;
		}
		if (candidate.confirmationHeight <= 0) {
			// A mempool-first breach has no height yet; _adoptLateConfirmation fills
			// it in for every tracked output once the commitment confirms.
			candidate.confirmationHeight =
				this._commitmentBroadcast?.blockHeight ?? 0;
		}
		this._trackedOutputs.push(candidate);
		actions.push({
			type: ChainActionType.WATCH_OUTPUT,
			txid: candidate.txid,
			outputIndex: candidate.outputIndex
		});
		return candidate;
	}

	/**
	 * Record which of the commitment's outputs a claim we are broadcasting spends,
	 * reading the transaction's own inputs. A batched penalty can also spend
	 * settled-HTLC outputs reconstructed from revokedHtlcSnapshots, which never
	 * become tracked outputs, so the tracked set alone cannot answer the question
	 * this set exists to answer.
	 */
	private _recordClaimedOutpoints(spendTx: bitcoin.Transaction): void {
		const broadcast = this._commitmentBroadcast;
		if (!broadcast) return;
		const claimed = new Set<number>(broadcast.claimedOutputIndices ?? []);
		for (const input of spendTx.ins) {
			// Transaction inputs hold the txid in internal byte order.
			const spentTxid = Buffer.from(input.hash).reverse().toString('hex');
			if (spentTxid === broadcast.txid) claimed.add(input.index);
		}
		broadcast.claimedOutputIndices = [...claimed];
	}

	/**
	 * Output indices of the revoked commitment that one of our claims already
	 * spends: what _recordClaimedOutpoints has seen, plus the inputs of every
	 * sweep still stored against a tracked output. The second half covers monitors
	 * restored from state persisted before the recorded set existed.
	 */
	private _claimedRevokedOutputIndices(commitmentTxid: string): Set<number> {
		const claimed = new Set<number>(
			this._commitmentBroadcast?.claimedOutputIndices ?? []
		);
		for (const output of this._trackedOutputs) {
			if (
				output.txid === commitmentTxid &&
				(output.status === OutputStatus.SPEND_CONFIRMED ||
					output.status === OutputStatus.IRREVOCABLY_RESOLVED)
			) {
				claimed.add(output.outputIndex);
			}
			if (!output.sweepTxHex) continue;
			try {
				const sweep = bitcoin.Transaction.fromHex(output.sweepTxHex);
				const managesLiveClaim =
					(output.status === OutputStatus.SPEND_BROADCAST &&
						output.resolutionTxid === undefined) ||
					(output.status === OutputStatus.CONFIRMED &&
						output.maturityHeight !== undefined) ||
					((output.status === OutputStatus.SPEND_CONFIRMED ||
						output.status === OutputStatus.IRREVOCABLY_RESOLVED) &&
						output.resolutionTxid === sweep.getId());
				if (!managesLiveClaim) continue;
				for (const input of sweep.ins) {
					const spentTxid = Buffer.from(input.hash).reverse().toString('hex');
					if (spentTxid === commitmentTxid) claimed.add(input.index);
				}
			} catch {
				// An undecodable sweep cannot say which outpoints it spends; fall
				// back to the one it is recorded against.
				claimed.add(output.outputIndex);
			}
		}
		return claimed;
	}

	private _uneconomicAction(
		output: ITrackedOutput,
		reason: 'skipped' | 'contested'
	): ChainAction {
		return {
			type: ChainActionType.SWEEP_UNECONOMIC,
			reason,
			txid: output.txid,
			outputIndex: output.outputIndex,
			outputType: output.outputType,
			amount: output.amount,
			feeRatePerVbyte: this._feeRatePerVbyte,
			contestHeight: this._contestHeight(output)
		};
	}

	/**
	 * Report every output left without a spend by a resolution pass, once each.
	 *
	 * Reported from the FIRST resolution as well as from retries: a claim declined
	 * at breach time and recovered by the very next fee estimate would otherwise
	 * be recorded and recovered without the decline ever being visible.
	 *
	 * A second report follows if a competing spend path opens while the claim is
	 * still unbuilt. That is urgency, not a stopping condition, and the retry
	 * carries on.
	 */
	private _reportDeclinedClaims(
		actions: ChainAction[],
		outputs: ITrackedOutput[]
	): void {
		const height = this._currentBlockHeight;
		for (const output of outputs) {
			if (output.sweepTxHex !== undefined) continue;
			if (output.uneconomicSinceHeight === undefined) {
				output.uneconomicSinceHeight = height;
				actions.push(this._uneconomicAction(output, 'skipped'));
			}
			const contestHeight = this._contestHeight(output);
			if (
				contestHeight !== undefined &&
				height >= contestHeight &&
				output.uneconomicContestedHeight === undefined
			) {
				output.uneconomicContestedHeight = height;
				actions.push(this._uneconomicAction(output, 'contested'));
			}
		}
	}

	/**
	 * Re-resolve revoked-commitment outputs that produced no spend, at the CURRENT
	 * feerate.
	 *
	 * A claim that cannot pay its own fee is skipped rather than built (#241), and
	 * nothing else revisits it: the rebroadcast/RBF loops only rebuild sweeps that
	 * already reached SPEND_BROADCAST, and an output with no sweepTxHex is not in
	 * that set. Fee spikes are transient and a breach remedy is not, so a skipped
	 * claim is retried for as long as its outpoint is unspent. A competing spend
	 * path opening (their CSV maturing, an HTLC expiring) does NOT stop the retry:
	 * it does not invalidate our revocation spend, it only starts a race, and a
	 * later fee drop can still win it. Only an actual spend, which moves the
	 * output off CONFIRMED through handleOutputSpent, ends the attempt.
	 *
	 * Runs on every new block and whenever a fresh fee estimate arrives.
	 */
	private _retryUnsweptRevokedSweeps(actions: ChainAction[]): void {
		const broadcast = this._commitmentBroadcast;
		if (
			!broadcast ||
			broadcast.commitmentType !== CommitmentType.THEIR_REVOKED_COMMITMENT ||
			!broadcast.revokedTxHex
		) {
			return;
		}

		let revokedTx: bitcoin.Transaction;
		try {
			revokedTx = bitcoin.Transaction.fromHex(broadcast.revokedTxHex);
		} catch {
			return;
		}

		const retryable = this._trackedOutputs.filter(
			(output) =>
				output.status === OutputStatus.CONFIRMED &&
				output.sweepTxHex === undefined &&
				!output.isSecondLevelHtlc &&
				// Second-level justice claims spend the cheater's HTLC tx rather than
				// this commitment, and are re-resolved through rebuildSweep.
				output.txid === broadcast.txid
		);
		const claimed = this._claimedRevokedOutputIndices(broadcast.txid);
		if (
			retryable.length === 0 &&
			!this._hasUnclaimedSnapshotOutputs(broadcast, revokedTx, claimed)
		) {
			return;
		}

		let resolved: ReturnType<typeof resolveRevokedCommitmentOutputs> = [];
		try {
			resolved = resolveRevokedCommitmentOutputs(
				this._channelState,
				retryable,
				broadcast.commitmentNumber,
				revokedTx,
				this._destinationScript,
				this._feeRatePerVbyte,
				this._revocationBasepointSecret,
				this._paymentPrivkey,
				this._network,
				this._currentBlockHeight,
				// Never re-batch an outpoint one of our live sweeps already spends:
				// the replacement would conflict with our own penalty.
				claimed
			);
		} catch {
			// A retry must never break block processing; the next one tries again.
			return;
		}

		this._recordPenaltyBroadcasts(
			actions,
			resolved,
			'penalty sweep (revoked commitment, retried after skip)'
		);
		// Over the tracked set rather than over `retryable`: the pass above adopts
		// snapshot-reconstructed outputs, and a claim declined for one of those is
		// otherwise the one decline nothing can report.
		this._reportDeclinedClaims(
			actions,
			this._revokedCommitmentOutputs(broadcast)
		);
	}

	/** Tracked outputs belonging to a given commitment broadcast. */
	private _revokedCommitmentOutputs(
		broadcast: ICommitmentBroadcast
	): ITrackedOutput[] {
		return this._trackedOutputs.filter((o) => o.txid === broadcast.txid);
	}

	/**
	 * Whether the revoked commitment still carries an output that no claim of ours
	 * spends and no tracked output covers, while a settled-HTLC snapshot exists
	 * that could reconstruct one.
	 *
	 * The retry set is otherwise seeded from _trackedOutputs alone, and outputs
	 * rebuilt from revokedHtlcSnapshots never become tracked outputs (#322). A
	 * skipped snapshot HTLC would then be the one thing the retry could never come
	 * back for, which is precisely the case it exists to cover. This is a coarse
	 * trigger on purpose: the resolver does the exact script matching and returns
	 * nothing when there is nothing to claim.
	 */
	private _hasUnclaimedSnapshotOutputs(
		broadcast: ICommitmentBroadcast,
		revokedTx: bitcoin.Transaction,
		claimed: ReadonlySet<number>
	): boolean {
		const snapshot = this._channelState.revokedHtlcSnapshots?.get(
			broadcast.commitmentNumber.toString()
		);
		if (!snapshot || snapshot.length === 0) return false;
		for (let i = 0; i < revokedTx.outs.length; i++) {
			if (claimed.has(i)) continue;
			if (
				this._trackedOutputs.some(
					(o) => o.txid === broadcast.txid && o.outputIndex === i
				)
			) {
				continue;
			}
			return true;
		}
		return false;
	}

	/**
	 * Retry economically declined claims on a non-revoked peer commitment.
	 *
	 * A current commitment can carry our to_remote balance, an offered HTLC we
	 * reclaim after CLTV, and a received HTLC we claim once its preimage is known.
	 * The resolver marks only claims that were fully constructible but priced out,
	 * so outputs waiting for a preimage or signing material are not reported as fee
	 * declines. A future commitment remains restricted to to_remote because its
	 * HTLC scripts and per-commitment point are unknown after data loss. A fresh
	 * fee estimate also refreshes a held CLTV or CSV claim before maturity, so it
	 * does not enter its spend race at a stale rate and wait another rebroadcast
	 * interval for its first bump.
	 */
	private _retryUnsweptPeerCommitmentClaims(
		actions: ChainAction[],
		refreshHeld = false
	): void {
		const broadcast = this._commitmentBroadcast;
		if (
			!broadcast ||
			(broadcast.commitmentType !== CommitmentType.THEIR_CURRENT_COMMITMENT &&
				broadcast.commitmentType !== CommitmentType.THEIR_FUTURE_COMMITMENT)
		) {
			return;
		}

		const currentCommitment =
			broadcast.commitmentType === CommitmentType.THEIR_CURRENT_COMMITMENT;
		const retryable = this._trackedOutputs.filter(
			(output) =>
				output.status === OutputStatus.CONFIRMED &&
				(output.sweepTxHex === undefined ||
					(refreshHeld && output.maturityHeight !== undefined)) &&
				output.txid === broadcast.txid &&
				(output.outputType === OutputType.TO_REMOTE ||
					(currentCommitment &&
						(output.outputType === OutputType.OFFERED_HTLC ||
							output.outputType === OutputType.RECEIVED_HTLC)))
		);
		if (retryable.length === 0) return;

		let resolved: ReturnType<typeof resolveTheirCurrentCommitmentOutputs>;
		try {
			resolved = resolveTheirCurrentCommitmentOutputs(
				this._channelState,
				retryable,
				this._destinationScript,
				this._feeRatePerVbyte,
				this._knownPreimages,
				this._paymentPrivkey,
				this._htlcBasepointSecret,
				currentCommitment
					? this._channelState.remoteCurrentPerCommitmentPoint ?? undefined
					: this._channelState.dlpRemotePerCommitmentPoint ??
							this._channelState.remoteCurrentPerCommitmentPoint ??
							undefined
			);
		} catch {
			// A malformed retained claim must not abort block or fee processing.
			return;
		}

		for (const entry of resolved) {
			if (!entry.spendTx) continue;
			const description =
				entry.trackedOutput.outputType === OutputType.TO_REMOTE
					? 'to_remote claim (retried after skip)'
					: entry.trackedOutput.outputType === OutputType.OFFERED_HTLC
					? 'HTLC-timeout claim (retried after skip)'
					: 'HTLC preimage claim (retried after skip)';
			this._scheduleSweep(actions, entry, description);
		}
		this._reportDeclinedClaims(
			actions,
			resolved
				.filter((entry) => entry.declinedAsUneconomic)
				.map((entry) => entry.trackedOutput)
		);
	}
}
