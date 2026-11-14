/**
 * `beignet channel forceclose <id> --offline`: force close a channel while the
 * daemon is stopped (issue #2024), for the case where it cannot run at all.
 *
 * Its own module because cli.ts runs main() the moment it is imported, and
 * both halves here need tests: an option the mapping forgets fails silently,
 * and the close sequence has to tell "closed and on the network" from
 * "closed locally, never broadcast".
 */
import type { BeignetNodeOptions } from './beignet-node';
import type { ApiResponse, BeignetConfig, ChannelInfo } from './types';
import type { ILogger } from '../logger';

/**
 * The node options an offline force close boots with. The wallet, its data
 * directory and its Electrum settings come from the resolved config exactly as
 * the daemon reads them, so the instance lock, the database and the TLS choice
 * are the daemon's own. The recovery settings ride along because they decide
 * whether this device may still broadcast (a fenced or superseded writer is
 * refused the same way the daemon refuses it).
 *
 * Everything that talks to peers is left out or switched off. A unilateral
 * close needs no peer, and a one-shot run should not accept connections, dial
 * stored peers, or download gossip while it holds the wallet.
 */
export function offlineForceCloseOptions(
	config: BeignetConfig,
	logger: ILogger
): BeignetNodeOptions {
	return {
		mnemonic: config.mnemonic,
		network: config.network,
		dataDir: config.dataDir,
		electrumHost: config.electrumHost,
		electrumPort: config.electrumPort,
		electrumTls: config.electrumTls,
		electrumTlsVerify: config.electrumTlsVerify,
		electrumTlsFingerprints: config.electrumTlsFingerprints,
		electrumServers: config.electrumServers,
		feeEstimationSource: config.feeEstimationSource,
		// An onion guardian is reached through the proxy.
		torProxy: config.torProxy,
		torProxyOnionOnly: config.torProxyOnionOnly,
		recoveryMode: config.recoveryMode,
		recoveryGuardians: config.recoveryGuardians,
		recoveryProfile: config.recoveryProfile,
		recoveryLeaseCheckIntervalMs: config.recoveryLeaseCheckIntervalMs,
		recoveryReestablishHoldMs: config.recoveryReestablishHoldMs,
		autoReconnect: false,
		autoBootstrap: false,
		autoGossipSync: false,
		rapidGossipSync: false,
		logger
	};
}

/** The part of BeignetNode the close sequence uses. */
export interface IOfflineForceCloseNode {
	getHealth(): { electrumConnected: boolean };
	getChannel(channelId: string): ChannelInfo | null;
	forceCloseChannel(
		channelId: string,
		acceptStaleStateRisk?: boolean
	): { ok: boolean; error?: string; commitmentTxid?: string };
	rebroadcastClose(channelId: string): Promise<{
		ok: boolean;
		error?: string;
		txid?: string;
		broadcastOk?: boolean;
	}>;
}

export interface IOfflineForceCloseOptions {
	acceptStaleStateRisk: boolean;
	/** How long to wait for Electrum before giving up with nothing closed. */
	connectTimeoutMs: number;
	/** How long to wait for the commitment to reach the network. */
	broadcastTimeoutMs: number;
	/** Between checks of the connection and of the close status. */
	pollMs: number;
	/** Between rebroadcasts while the close is not known to be out. */
	rebroadcastMs: number;
	/** The last broadcast error the node reported, for the failure message. */
	lastBroadcastError?: () => string | undefined;
	sleep?: (ms: number) => Promise<void>;
	now?: () => number;
}

export const OFFLINE_FORCE_CLOSE_DEFAULTS = {
	connectTimeoutMs: 60_000,
	broadcastTimeoutMs: 60_000,
	pollMs: 500,
	rebroadcastMs: 10_000
} as const;

export interface IOfflineForceCloseResult {
	forceClosed: true;
	commitmentTxid?: string;
	broadcast: true;
	/** The channel was already FORCE_CLOSED; this run only rebroadcast it. */
	alreadyForceClosed?: true;
}

const fail = (code: string, message: string): ApiResponse<never> => ({
	ok: false,
	error: { code, message }
});

/**
 * Wait for Electrum, force close, and wait until the commitment is known to
 * have reached the network.
 *
 * Nothing is closed until Electrum answers: a close the node cannot broadcast
 * would leave the channel FORCE_CLOSED in the database with the commitment
 * sitting until the daemon next runs. A channel that is already FORCE_CLOSED
 * (a re-run after such a broadcast failed) is rebroadcast rather than refused.
 */
export async function runOfflineForceClose(
	node: IOfflineForceCloseNode,
	channelId: string,
	opts: IOfflineForceCloseOptions
): Promise<ApiResponse<IOfflineForceCloseResult>> {
	const sleep =
		opts.sleep ??
		((ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms)));
	const now = opts.now ?? Date.now;

	const connectDeadline = now() + opts.connectTimeoutMs;
	while (!node.getHealth().electrumConnected) {
		if (now() >= connectDeadline) {
			return fail(
				'ELECTRUM_UNAVAILABLE',
				`No Electrum connection after ${Math.round(
					opts.connectTimeoutMs / 1000
				)} s, so nothing was closed. Check electrumHost, electrumPort and electrumTls in the config.`
			);
		}
		await sleep(opts.pollMs);
	}

	const before = node.getChannel(channelId);
	if (!before) {
		return fail('CHANNEL_NOT_FOUND', `Channel not found: ${channelId}`);
	}
	let txid: string | undefined;
	const alreadyForceClosed = before.state === 'FORCE_CLOSED';
	if (alreadyForceClosed) {
		txid = before.closeStatus?.closingTxid;
	} else {
		const closed = node.forceCloseChannel(channelId, opts.acceptStaleStateRisk);
		if (!closed.ok) {
			return fail('FORCE_CLOSE_FAILED', closed.error || 'Force close failed');
		}
		txid = closed.commitmentTxid;
	}

	const done = (): ApiResponse<IOfflineForceCloseResult> => ({
		ok: true,
		result: {
			forceClosed: true,
			...(txid !== undefined ? { commitmentTxid: txid } : {}),
			broadcast: true,
			...(alreadyForceClosed ? { alreadyForceClosed: true as const } : {})
		}
	});

	// The close queues its own broadcast, so a fresh close is given one
	// interval before the first rebroadcast; a re-run has nothing queued.
	const deadline = now() + opts.broadcastTimeoutMs;
	let nextRebroadcast = alreadyForceClosed ? now() : now() + opts.rebroadcastMs;
	let rebroadcastError: string | undefined;
	for (;;) {
		const status = node.getChannel(channelId)?.closeStatus;
		// On a re-run, a stored sighting (of our commitment or the peer's) can
		// come from an earlier run and the tx may have left the mempool since,
		// so only a rebroadcast from this run counts. rebroadcastClose reports a
		// confirmed close by either side as broadcast.
		if (status?.broadcast === true && !alreadyForceClosed) {
			return done();
		}
		if (now() >= nextRebroadcast) {
			const again = await node.rebroadcastClose(channelId);
			if (again.ok) {
				txid = again.txid ?? txid;
				if (again.broadcastOk === true) return done();
			} else {
				rebroadcastError = again.error;
			}
			nextRebroadcast = now() + opts.rebroadcastMs;
		}
		if (now() >= deadline) break;
		await sleep(opts.pollMs);
	}

	const reason = opts.lastBroadcastError?.() ?? rebroadcastError;
	return fail(
		'BROADCAST_FAILED',
		`The channel is force closed and its commitment${
			txid !== undefined ? ` ${txid}` : ''
		} is stored, but it was not seen to reach the network within ${Math.round(
			opts.broadcastTimeoutMs / 1000
		)} s${
			reason ? ` (${reason})` : ''
		}. Run this command again, or start the daemon and run beignet channel rebroadcast-close ${channelId}.`
	);
}
