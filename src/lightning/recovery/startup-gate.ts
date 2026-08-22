/**
 * Startup quarantine (docs/RECOVERY-PROTOCOL.md 5.6, Phase 5).
 *
 * The rule this enforces, from the spec's "additional startup rule":
 *
 *   Channels may not leave quarantine, and the node may not even connect to
 *   channel peers, until current writer ownership is confirmed with the
 *   quorum (or the operator explicitly runs in a mode without guardians).
 *
 * A stale device therefore learns it was superseded BEFORE it can touch the
 * Lightning protocol. That ordering is the whole value: fencing at the
 * replication layer only helps a device that gets as far as writing, while
 * a restarted stale device would otherwise reconnect, exchange
 * channel_reestablish, and act on state it no longer owns.
 *
 * The gate is deliberately conservative in every uncertain case. Confirmed
 * is the ONLY state that permits peer traffic; a proven newer epoch freezes
 * permanently; and no quorum, a conflict, or evidence that only stale
 * guardians could supply all leave the node quarantined, which is safe
 * because a quarantined node simply does nothing.
 */

import { GuardianState } from './guardian-wire';
import { GuardianReplicator } from './guardian-replication';
import {
	IWriterLeaseKeys,
	markLeaseConfirmed,
	publicLease
} from './writer-lease';
import { IStorageBackend } from '../storage/types';

export type StartupGateState =
	/** Nothing may reach a channel peer. The starting state, and the safe one. */
	| 'quarantined'
	/** A quorum confirmed THIS lease; peer traffic is permitted. */
	| 'confirmed'
	/** A newer epoch was proven: this writer is superseded, permanently. */
	| 'fenced';

export interface IStartupGateEvent {
	type: 'gate:quarantined' | 'gate:confirmed' | 'gate:fenced' | 'gate:blocked';
	detail: string;
	/** The proven current state, on a fenced outcome. */
	currentState?: GuardianState;
}

export interface IStartupGateConfig {
	storage: IStorageBackend;
	replicator: GuardianReplicator;
	/** Distinct guardians whose confirmation releases the gate. */
	required: number;
	clock?: () => bigint;
	onEvent?: (event: IStartupGateEvent) => void;
}

export interface IConfirmationOutcome {
	state: StartupGateState;
	/** Distinct guardians that confirmed this exact (epoch, writer key). */
	confirming: number;
	/** On `fenced`: the newer state that superseded this lease. */
	supersededBy?: GuardianState;
}

/**
 * Ownership confirmation and the peer-traffic gate it releases.
 *
 * Construct it quarantined, call `confirm` with the lease this device
 * believes it holds, and consult `permitsPeerTraffic()` at every transport
 * boundary. Nothing here ever opens the gate optimistically: the only path
 * to `confirmed` is a quorum of guardians naming this exact epoch and
 * writer key, and once `fenced` the gate never reopens for that lease.
 */
export class GuardianStartupGate {
	private readonly config: IStartupGateConfig;
	private readonly clock: () => bigint;
	private state: StartupGateState = 'quarantined';
	private supersededBy?: GuardianState;
	private openListeners: Array<() => void> = [];
	private fencedListeners: Array<() => void> = [];

	constructor(config: IStartupGateConfig) {
		this.config = config;
		this.clock = config.clock ?? ((): bigint => BigInt(Date.now()));
	}

	/**
	 * Run `listener` when the gate opens. The node defers its startup
	 * networking (auto-reconnect dialing, held connections) behind this, so
	 * peer contact begins the moment ownership is proven and not before.
	 */
	onOpen(listener: () => void): void {
		this.openListeners.push(listener);
		if (this.state === 'confirmed') listener();
	}

	/**
	 * Run `listener` when the gate fences. Fencing is the spec 5.6
	 * hard-freeze: a superseded writer must not exchange another wire
	 * message, so the node uses this to drop every live connection and stop
	 * its listeners rather than trusting per-message suppression alone.
	 */
	onFenced(listener: () => void): void {
		this.fencedListeners.push(listener);
		if (this.state === 'fenced') listener();
	}

	private emit(event: IStartupGateEvent): void {
		this.config.onEvent?.(event);
	}

	getState(): StartupGateState {
		return this.state;
	}

	/** The single question every transport chokepoint asks. */
	permitsPeerTraffic(): boolean {
		return this.state === 'confirmed';
	}

	/** The newer state that fenced this device, once known. */
	getSupersedingState(): GuardianState | undefined {
		return this.supersededBy;
	}

	/**
	 * Record that something was refused. Called by the node at the transport
	 * boundary so an operator can see the gate doing its job rather than
	 * wondering why a node is silent.
	 */
	reportBlocked(detail: string): void {
		this.emit({ type: 'gate:blocked', detail });
	}

	/**
	 * Fencing is permanent: this writer lost the namespace, and no later
	 * answer can give it back. Only a restore can. Callers have already
	 * returned on every fenced-before path, so this is always a transition
	 * and the fenced listeners (the node's hard freeze) run exactly once.
	 */
	private fenceOn(
		lease: IWriterLeaseKeys,
		states: GuardianState[],
		confirming: number
	): IConfirmationOutcome {
		this.supersededBy = states.find(
			(state) => state.lease.epoch > lease.epoch
		);
		this.state = 'fenced';
		this.emit({
			type: 'gate:fenced',
			detail:
				`epoch ${lease.epoch} was superseded` +
				(this.supersededBy
					? ` by epoch ${this.supersededBy.lease.epoch}`
					: '') +
				'; channels are frozen and no peer traffic is permitted',
			currentState: this.supersededBy
		});
		for (const listener of this.fencedListeners) listener();
		return {
			state: 'fenced',
			confirming,
			supersededBy: this.supersededBy
		};
	}

	/**
	 * Re-ask the guardian set whether THIS lease is still current, for a
	 * gate that is already open (issue #455).
	 *
	 * An idle writer otherwise learns of a takeover only on its next commit
	 * (the barrier) or its next restart (confirm), which on a parked node
	 * can be days. This is the cheap periodic check in between, and it is
	 * deliberately asymmetric: a proven newer epoch fences exactly as
	 * confirm would (one bound guardian's receipt-covered state naming a
	 * higher epoch is the same evidence the barrier fences on), but nothing
	 * else touches the gate. Silence, a partial answer or a transport error
	 * is not evidence of anything, and unlike confirm this must never
	 * downgrade a confirmed gate to quarantined: that would freeze a
	 * healthy running node on every guardian outage. Errors propagate so
	 * the caller can log them; the gate state is unchanged on any throw.
	 */
	async recheck(lease: IWriterLeaseKeys): Promise<IConfirmationOutcome> {
		if (this.state !== 'confirmed') {
			return {
				state: this.state,
				confirming: 0,
				supersededBy: this.supersededBy
			};
		}
		const answer = await this.config.replicator.confirmOwnership(lease);
		if ((this.state as StartupGateState) === 'fenced') {
			// Fenced concurrently (a barrier pass, or a racing confirm).
			return {
				state: 'fenced',
				confirming: 0,
				supersededBy: this.supersededBy
			};
		}
		if (answer.superseded) {
			return this.fenceOn(lease, answer.states, answer.confirming);
		}
		return { state: 'confirmed', confirming: answer.confirming };
	}

	/**
	 * Ask the guardian set whether THIS lease is still the current writer.
	 *
	 * Confirmation requires `required` distinct guardians whose signed state
	 * names this exact epoch and writer key; the replicator already refuses
	 * to count uncertain stores or receipts that do not cover the state they
	 * accompany. A proven newer epoch fences permanently. Anything else
	 * leaves the node quarantined, including a bare timeout: silence is not
	 * evidence of ownership.
	 */
	async confirm(lease: IWriterLeaseKeys): Promise<IConfirmationOutcome> {
		if (this.state === 'fenced') {
			return {
				state: 'fenced',
				confirming: 0,
				supersededBy: this.supersededBy
			};
		}
		let confirming = 0;
		let superseded = false;
		let states: GuardianState[] = [];
		try {
			const answer = await this.config.replicator.confirmOwnership(lease);
			confirming = answer.confirming;
			superseded = answer.superseded;
			states = answer.states;
		} catch (error) {
			if ((this.state as StartupGateState) === 'fenced') {
				// Fenced concurrently while this attempt was failing; the
				// failure must not downgrade a permanent state.
				return {
					state: 'fenced',
					confirming: 0,
					supersededBy: this.supersededBy
				};
			}
			const message = error instanceof Error ? error.message : String(error);
			this.state = 'quarantined';
			this.emit({
				type: 'gate:quarantined',
				detail: `ownership could not be confirmed (${message}); channels stay quarantined`
			});
			return { state: 'quarantined', confirming: 0 };
		}

		if ((this.state as StartupGateState) === 'fenced') {
			// A concurrent confirmation proved a newer epoch while this one
			// was in flight. Fencing is permanent, so a slower answer that
			// still names this lease current must not reopen the gate.
			return {
				state: 'fenced',
				confirming: 0,
				supersededBy: this.supersededBy
			};
		}

		if (superseded) {
			return this.fenceOn(lease, states, confirming);
		}

		if (confirming < this.config.required) {
			this.state = 'quarantined';
			this.emit({
				type: 'gate:quarantined',
				detail: `only ${confirming} of ${this.config.required} guardians confirmed this lease; channels stay quarantined`
			});
			return { state: 'quarantined', confirming };
		}

		// The lease is current. Record the confirmation against THIS identity
		// (markLeaseConfirmed refuses any other), then open the gate.
		markLeaseConfirmed(
			this.config.storage,
			{ epoch: lease.epoch, writerPublicKey: lease.writerPublicKey },
			this.clock()
		);
		const opened = (this.state as StartupGateState) !== 'confirmed';
		this.state = 'confirmed';
		this.emit({
			type: 'gate:confirmed',
			detail: `${confirming} guardians confirmed epoch ${
				publicLease(lease).epoch
			}; peer traffic is permitted`
		});
		// Fire only on the closed-to-open TRANSITION: a re-confirmation of an
		// already-open gate must not re-run reestablish on live connections.
		if (opened) {
			for (const listener of this.openListeners) listener();
		}
		return { state: 'confirmed', confirming };
	}
}
