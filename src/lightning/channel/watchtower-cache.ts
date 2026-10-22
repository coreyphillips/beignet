/**
 * The watchtower side of revocation: each remote commitment we sign, cached
 * by its per-commitment point until the revoke_and_ack that reveals the
 * point's secret hands it to a tower, and the revoked commitments whose
 * hand-off failed. Both live on the channel state. Channel's methods of the
 * same names delegate here and carry the documentation.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { perCommitmentPointFromSecret } from '../keys/derivation';
import type { IChannelState } from './channel-state';
import { buildRemoteCommitment } from './commitment-builder';

// Bound on state.watchtowerRemoteCommitmentTxs; unrevoked states number at
// most a couple.
const REVOKED_TX_CACHE_MAX = 8;

/** What the cache reads from its channel. */
export interface IWatchtowerCacheHost {
	state(): IChannelState;
	isAwaitingRemoteRevocation(): boolean;
	splicedState(): IChannelState | null;
}

export class WatchtowerCache {
	private readonly _host: IWatchtowerCacheHost;

	constructor(host: IWatchtowerCacheHost) {
		this._host = host;
	}

	private get _state(): IChannelState {
		return this._host.state();
	}

	private isAwaitingRemoteRevocation(): boolean {
		return this._host.isAwaitingRemoteRevocation();
	}

	private _splicedState(): IChannelState | null {
		return this._host.splicedState();
	}

	/**
	 * Cache the remote commitment tx we signed at `commitmentNumber`, keyed by
	 * its per-commitment point, so the revoke_and_ack that later reveals that
	 * point's secret can hand the exact tx to a watchtower. Taproot commitments
	 * are cached too: they feed the version-1 (schnorr) justice kit. Never
	 * throws: a cache miss only forfeits a pre-emptive tower ship, it must not
	 * break commitment signing.
	 *
	 * `spliced` is the pending splice's view: its tx joins the one cached for
	 * the current funding under the same point.
	 */
	cacheRemoteCommitment(
		point: Buffer | null,
		commitmentNumber: bigint,
		spliced?: IChannelState
	): void {
		try {
			const view = spliced ?? this._state;
			if (!point || !view.remoteBasepoints || !view.fundingTxid) {
				return;
			}
			const built = buildRemoteCommitment(view, point, commitmentNumber);
			const cache = (this._state.watchtowerRemoteCommitmentTxs ??= new Map<
				string,
				Buffer[]
			>());
			const key = point.toString('hex');
			// Anything else under the point is a signature since replaced, or a
			// splice attempt that never locked, so only the current funding's tx
			// survives a splice-side write.
			const current = this._state.fundingTxid;
			const kept =
				spliced && current
					? (cache.get(key) ?? []).filter(
							(tx) =>
								bitcoin.Transaction.fromBuffer(tx).ins[0]?.hash.equals(current)
					  )
					: [];
			cache.set(key, [...kept, built.result.tx.toBuffer()]);
			// Bound the cache: only unrevoked states matter and there are few.
			while (cache.size > REVOKED_TX_CACHE_MAX) {
				const oldest = cache.keys().next().value;
				if (oldest === undefined) break;
				cache.delete(oldest);
			}
		} catch {
			// Best-effort cache; ignore.
		}
	}

	repairWatchtowerCommitmentCache(): void {
		if (this._state.needsCommitment) return;
		const point = this.isAwaitingRemoteRevocation()
			? this._state.remoteNextPerCommitmentPoint
			: this._state.remoteCurrentPerCommitmentPoint;
		if (!point) return;
		const key = point.toString('hex');
		if (!this._state.watchtowerRemoteCommitmentTxs?.has(key)) {
			this.cacheRemoteCommitment(point, this._state.remoteCommitmentNumber);
		}
		const spliced = this._state.spliceInFlight ? this._splicedState() : null;
		const spliceFunding = spliced?.fundingTxid;
		if (!spliced || !spliceFunding) return;
		const spliceCached = (
			this._state.watchtowerRemoteCommitmentTxs?.get(key) ?? []
		).some((tx) => {
			try {
				return bitcoin.Transaction.fromBuffer(tx).ins[0]?.hash.equals(
					spliceFunding
				);
			} catch {
				return false;
			}
		});
		if (!spliceCached) {
			this.cacheRemoteCommitment(
				point,
				this._state.remoteCommitmentNumber,
				spliced
			);
		}
	}

	takeRevokedCommitmentTxs(perCommitmentSecret: Buffer): Buffer[] {
		const pointHex =
			perCommitmentPointFromSecret(perCommitmentSecret).toString('hex');
		const cache = this._state.watchtowerRemoteCommitmentTxs;
		const txs = cache?.get(pointHex) ?? [];
		cache?.delete(pointHex);
		return txs;
	}

	oweWatchtowerBackup(perCommitmentSecret: Buffer, tx: Buffer): void {
		(this._state.watchtowerBackupsOwed ??= []).push({
			perCommitmentSecret,
			tx
		});
	}

	takeOwedWatchtowerBackups(): Array<{
		perCommitmentSecret: Buffer;
		tx: Buffer;
	}> {
		const owed = this._state.watchtowerBackupsOwed ?? [];
		this._state.watchtowerBackupsOwed = undefined;
		return owed;
	}
}
