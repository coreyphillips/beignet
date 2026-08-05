/**
 * Recovery Phase 7 verdict oracle (docs/RECOVERY-PROTOCOL.md section 9).
 *
 * Every chaos cell ends here. `exact-resume` means the restored node holds
 * the channel it held before the kill, reaches Active through reestablish,
 * drains whatever the kill interrupted, and can move fresh money.
 * `safe-dlp` means the restored node knows it must not broadcast and keeps
 * refusing to however it is poked, while its peer remains free to close.
 * The absolute assertions (no broadcastable stale state, no lost forwarded
 * preimage, no nonce signing two sighashes) are their own helpers because
 * they apply across cells whatever the verdict.
 */

import crypto from 'crypto';
import { expect } from 'chai';
import { ChannelState } from '../../../src/lightning/channel/types';
import { ChannelRecoveryStatus } from '../../../src/lightning/recovery/channel-status';
import { IStorageBackend } from '../../../src/lightning/storage/types';
import { IChaosRunResult, settle } from './chaos-harness';

/**
 * Wait for the reestablish cascades to finish (the peer re-fulfilling an
 * interrupted HTLC, replayed batches completing their round). In the
 * synchronous modes this converges within a handful of macrotasks; in
 * quorum mode every gated re-send parks behind its own fresh frame and
 * waits on a real HTTP receipt, so the drain polls a condition up to a
 * deadline instead of counting setImmediates. The assertions after it
 * still run unconditionally: a drain that never converges fails on them
 * with the precise state it left behind.
 */
async function drain(
	converged?: () => boolean,
	timeoutMs = 8_000
): Promise<void> {
	for (let i = 0; i < 5; i++) await settle();
	if (!converged) return;
	const deadline = Date.now() + timeoutMs;
	while (!converged() && Date.now() < deadline) {
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
}

/**
 * Call AFTER the scenario's probe (the matrix runner does): ReplayRequired
 * legitimately persists until the next commitment activity, and the probe
 * is that activity, so asserting Active before it would reject a channel
 * that is converging exactly as specified.
 */
export async function assertExactResume(
	result: IChaosRunResult
): Promise<void> {
	const { restored } = result;
	await drain(() =>
		restored
			.getChannelManager()
			.listChannels()
			.every(
				(c) =>
					c.getState() === ChannelState.NORMAL &&
					c.getFullState().htlcs.size === 0
			)
	);
	const channels = restored.getChannelManager().listChannels();
	expect(channels.length, 'restored node lost its channel').to.be.greaterThan(
		0
	);
	for (const channel of channels) {
		expect(
			channel.getState(),
			'restored channel did not return to NORMAL'
		).to.equal(ChannelState.NORMAL);
		expect(
			channel.getFullState().htlcs.size,
			'HTLC left pending after reestablish drained'
		).to.equal(0);
	}
	const status = restored.getRecoveryStatus();
	for (const entry of status.channels) {
		expect(
			entry.status,
			`channel ${entry.channelId} status after resume`
		).to.equal(ChannelRecoveryStatus.Active);
	}
	// A resumed channel force-closed by nobody: the kill must not have cost
	// anyone a commitment broadcast, dead, alive or restored.
	expect(
		result.broadcasts.filter((b) => b.when !== 'alive'),
		'a commitment reached the wire around a resumable kill'
	).to.deep.equal([]);
}

export async function assertSafeDlp(result: IChaosRunResult): Promise<void> {
	await drain();
	const { restored } = result;
	const status = restored.getRecoveryStatus();
	expect(
		status.channels.length,
		'safe-dlp verdict with no channel to judge'
	).to.be.greaterThan(0);
	for (const entry of status.channels) {
		expect(
			[
				ChannelRecoveryStatus.LocalDataLoss,
				ChannelRecoveryStatus.StateUncertain
			],
			`channel ${entry.channelId} must know it cannot trust its state`
		).to.include(entry.status);
	}
	// The ban is behavioral, not a flag: poke the operator's own exit and
	// assert the stored commitment still never leaves.
	const destination = Buffer.concat([
		Buffer.from([0x00, 0x14]),
		crypto.randomBytes(20)
	]);
	for (const channel of restored.getChannelManager().listChannels()) {
		const id =
			channel.getChannelId() ?? channel.getFullState().temporaryChannelId;
		try {
			restored.getChannelManager().forceClose(id, destination);
		} catch {
			// A refusal by throw is as good as a refusal by return.
		}
	}
	await drain();
	expect(
		result.broadcasts.filter((b) => b.when !== 'alive'),
		'a possibly-stale commitment reached the wire'
	).to.deep.equal([]);
}

export async function assertChaosOutcome(
	result: IChaosRunResult,
	verdict: 'exact-resume' | 'safe-dlp'
): Promise<void> {
	if (verdict === 'exact-resume') {
		await assertExactResume(result);
	} else {
		await assertSafeDlp(result);
	}
}

/**
 * Never a lost preimage for a forwarded HTLC: once the downstream fulfill
 * was exposed to this node (on the wire or in a commit), the preimage must
 * be readable from the restart's storage.
 */
export function assertPreimageRetained(
	storage: IStorageBackend,
	paymentHashHex: string
): void {
	const rows = storage.loadAllPreimages();
	expect(
		rows.some((r) => r.paymentHash === paymentHashHex),
		`preimage for ${paymentHashHex} lost across the kill`
	).to.equal(true);
}

/**
 * Never a secret nonce signing two different sighashes across a restart.
 * Callers extract (public nonce, signed material) pairs from whatever
 * surface their scenario exposes (captured wire bytes, plan objects) and
 * this asserts no public nonce ever appears against two distinct
 * materials. Byte-identical retransmission passes (same material),
 * fresh-session restarts pass (fresh nonce), and deterministic re-derivation
 * passes exactly when it re-signs the same material, which is the rule.
 */
export function assertNoNonceReuse(
	pairs: Array<{ pubNonce: Buffer; material: Buffer }>
): void {
	const seen = new Map<string, string>();
	for (const { pubNonce, material } of pairs) {
		const nonceHex = pubNonce.toString('hex');
		const materialHex = material.toString('hex');
		const prior = seen.get(nonceHex);
		if (prior === undefined) {
			seen.set(nonceHex, materialHex);
		} else {
			expect(
				prior,
				`public nonce ${nonceHex.slice(0, 16)}... signed two materials`
			).to.equal(materialHex);
		}
	}
}
