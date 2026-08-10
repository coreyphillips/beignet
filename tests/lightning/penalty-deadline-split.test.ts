/**
 * Per-output penalty tx fallback near expiry.
 *
 * A batched penalty tx spends every claimable output of a revoked commitment
 * in one transaction. If the cheater's pre-signed HTLC-timeout wins the race
 * for ONE of those inputs (possible as soon as its cltv_expiry passes), the
 * whole batch becomes invalid and every other claim stalls until the
 * rebroadcast interval rebuilds them. The fallback: any HTLC input within
 * PENALTY_SPLIT_DEADLINE_BLOCKS of its cltv_expiry is claimed in its OWN
 * single-input penalty tx; the rest stay batched. Far from any deadline (or
 * when no height is known) the previous single-batch behavior is preserved.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { HtlcDirection } from '../../src/lightning/channel/types';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import { ChainActionType } from '../../src/lightning/chain/types';
import { MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	perCommitmentPointFromSecret,
	deriveRevocationPubkey,
	derivePublicKey
} from '../../src/lightning/keys/derivation';
import { buildReceivedHtlcScript } from '../../src/lightning/script/htlc';
import { resolveRevokedCommitmentOutputs } from '../../src/lightning/chain/output-resolver';
import { setupRevokedWithHtlcs } from './helpers/revoked-commitment-fixture';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;

describe('Per-output penalty fallback near expiry', function () {
	const HEIGHT = 750_000;

	it('isolates a near-deadline HTLC input into its own penalty tx', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);

		const resolved = resolveRevokedCommitmentOutputs(
			s.state,
			s.trackedOutputs,
			0n,
			s.revokedTx,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network,
			HEIGHT
		);

		const byIndex = new Map(
			resolved.map((r) => [r.trackedOutput.outputIndex, r])
		);
		expect(byIndex.size).to.equal(3);

		// The near-deadline HTLC (index 1) gets a single-input tx of its own.
		const near = byIndex.get(1)!;
		expect(near.spendTx!.ins.length).to.equal(1);
		expect(near.spendTx!.ins[0].index).to.equal(1);
		expect(
			Buffer.from(near.spendTx!.ins[0].hash).reverse().toString('hex')
		).to.equal(s.revokedTx.getId());

		// to_local + far HTLC stay batched in ONE shared tx.
		const toLocal = byIndex.get(0)!;
		const far = byIndex.get(2)!;
		expect(toLocal.spendTx).to.equal(far.spendTx);
		expect(toLocal.spendTx!.ins.length).to.equal(2);
		expect(toLocal.spendTx!.getId()).to.not.equal(near.spendTx!.getId());

		// Every input carries its witness (the batch signs per-input).
		for (const r of resolved) {
			expect(r.witness).to.exist;
			expect(r.witness![r.witness!.length - 1].length).to.be.greaterThan(0);
		}
	});

	it('keeps the single batched penalty when no height is known (previous behavior)', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);

		const resolved = resolveRevokedCommitmentOutputs(
			s.state,
			s.trackedOutputs,
			0n,
			s.revokedTx,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		expect(resolved.length).to.equal(3);
		const txids = new Set(resolved.map((r) => r.spendTx!.getId()));
		expect(txids.size).to.equal(1);
		expect(resolved[0].spendTx!.ins.length).to.equal(3);
	});

	it('keeps the single batched penalty when every deadline is far', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);

		// Far below both cltv_expiry values: nothing is urgent.
		const resolved = resolveRevokedCommitmentOutputs(
			s.state,
			s.trackedOutputs,
			0n,
			s.revokedTx,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network,
			HEIGHT - 10_000
		);

		const txids = new Set(resolved.map((r) => r.spendTx!.getId()));
		expect(txids.size).to.equal(1);
		expect(resolved[0].spendTx!.ins.length).to.equal(3);
	});

	it('splits a snapshot-reconstructed HTLC near its deadline (H2 path)', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);

		// Move the near HTLC out of live tracking and into the revoked snapshot
		// (settled since the revoked commitment; direction OFFERED from our
		// perspective maps to the received-HTLC script on their commitment).
		const remaining = [s.trackedOutputs[0], s.trackedOutputs[2]];
		s.state.revokedHtlcSnapshots = new Map([
			[
				'0',
				[
					{
						paymentHash: crypto.randomBytes(32),
						amountMsat: 120_000_000n,
						cltvExpiry: s.nearCltv,
						direction: HtlcDirection.OFFERED
					}
				]
			]
		]);
		// Rebuild the snapshot entry's script so it matches revokedTx output 1.
		const secret = s.state.shaChainStore.getSecret(MAX_INDEX - 0n)!;
		const revokedPoint = perCommitmentPointFromSecret(secret);
		const snapshotEntry = s.state.revokedHtlcSnapshots.get('0')![0];
		const script = buildReceivedHtlcScript(
			deriveRevocationPubkey(
				s.state.localBasepoints.revocationBasepoint,
				revokedPoint
			),
			derivePublicKey(s.state.remoteBasepoints!.htlcBasepoint, revokedPoint),
			derivePublicKey(s.state.localBasepoints.htlcBasepoint, revokedPoint),
			snapshotEntry.paymentHash,
			s.nearCltv,
			false
		);
		s.revokedTx.outs[1].script = bitcoin.payments.p2wsh({
			redeem: { output: script }
		}).output!;

		const resolved = resolveRevokedCommitmentOutputs(
			s.state,
			remaining,
			0n,
			s.revokedTx,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network,
			HEIGHT
		);

		expect(resolved.length).to.equal(3);
		const near = resolved.find((r) => r.trackedOutput.outputIndex === 1)!;
		expect(near).to.exist;
		expect(near.spendTx!.ins.length).to.equal(1);
		expect(near.trackedOutput.cltvExpiry).to.equal(s.nearCltv);
		// The other two share the batch.
		const others = resolved.filter((r) => r.trackedOutput.outputIndex !== 1);
		expect(others[0].spendTx).to.equal(others[1].spendTx);
		expect(others[0].spendTx!.getId()).to.not.equal(near.spendTx!.getId());
	});

	it('monitor broadcasts each distinct penalty tx exactly once (dedupe + split)', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);

		// Route both HTLCs through the snapshot (classification only matches
		// live HTLCs): the resolver's H2 fallback picks them up with their
		// deadlines, so the monitor's height plumbing drives the split.
		const secret = s.state.shaChainStore.getSecret(MAX_INDEX - 0n)!;
		const revokedPoint = perCommitmentPointFromSecret(secret);
		const revocationPubkey = deriveRevocationPubkey(
			s.state.localBasepoints.revocationBasepoint,
			revokedPoint
		);
		const theirHtlc = derivePublicKey(
			s.state.remoteBasepoints!.htlcBasepoint,
			revokedPoint
		);
		const ourHtlc = derivePublicKey(
			s.state.localBasepoints.htlcBasepoint,
			revokedPoint
		);
		const nearHash = crypto.randomBytes(32);
		const farHash = crypto.randomBytes(32);
		s.state.revokedHtlcSnapshots = new Map([
			[
				'0',
				[
					{
						paymentHash: nearHash,
						amountMsat: 120_000_000n,
						cltvExpiry: s.nearCltv,
						direction: HtlcDirection.OFFERED
					},
					{
						paymentHash: farHash,
						amountMsat: 130_000_000n,
						cltvExpiry: s.farCltv,
						direction: HtlcDirection.OFFERED
					}
				]
			]
		]);
		s.revokedTx.outs[1].script = bitcoin.payments.p2wsh({
			redeem: {
				output: buildReceivedHtlcScript(
					revocationPubkey,
					theirHtlc,
					ourHtlc,
					nearHash,
					s.nearCltv,
					false
				)
			}
		}).output!;
		s.revokedTx.outs[2].script = bitcoin.payments.p2wsh({
			redeem: {
				output: buildReceivedHtlcScript(
					revocationPubkey,
					theirHtlc,
					ourHtlc,
					farHash,
					s.farCltv,
					false
				)
			}
		}).output!;

		const monitor = new ChainMonitor(
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const actions = monitor.handleFundingSpent(s.revokedTx, HEIGHT);

		const penaltyBroadcasts = actions.filter(
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(a: any) =>
				a.type === ChainActionType.BROADCAST_TX &&
				a.description?.includes('penalty')
		);
		// Two distinct penalty txs (near-deadline single + batch), each once.
		const txs = penaltyBroadcasts.map(
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(a: any) => bitcoin.Transaction.fromBuffer(a.tx)
		);
		expect(txs.length).to.equal(2);
		expect(new Set(txs.map((t) => t.getId())).size).to.equal(2);

		// The single-input tx claims the near HTLC outpoint; the batch claims
		// the other two.
		const single = txs.find((t) => t.ins.length === 1)!;
		const batch = txs.find((t) => t.ins.length === 2)!;
		expect(single).to.exist;
		expect(batch).to.exist;
		expect(single.ins[0].index).to.equal(1);
		expect(batch.ins.map((i) => i.index).sort()).to.deep.equal([0, 2]);
	});
});

describe('Penalty batch affordability (witness-v0)', function () {
	const HEIGHT = 750_000;

	it('an unaffordable urgent HTLC no longer aborts the batched to_local penalty', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		// Starve ONLY the near-deadline HTLC, which the split isolates into its own
		// penalty tx. Their to_local (index 0) stays large and must still be claimed.
		s.revokedTx.outs[1].value = 500;
		s.trackedOutputs[1].amount = 500n;

		const resolved = resolveRevokedCommitmentOutputs(
			s.state,
			s.trackedOutputs,
			0n,
			s.revokedTx,
			s.destScript,
			50,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network,
			HEIGHT
		);

		const byIndex = new Map(
			resolved.map((r) => [r.trackedOutput.outputIndex, r])
		);
		expect(
			byIndex.get(0),
			'their to_local penalty survived the unaffordable HTLC'
		).to.exist;
		expect(byIndex.get(0)!.spendTx, 'and carries a real spend').to.exist;
		expect(byIndex.get(2), 'the far HTLC is still batched with it').to.exist;
		// Reported as declined (tracked, no spend) rather than dropped silently, so
		// the caller can retry it once fees fall.
		expect(
			byIndex.get(1)?.spendTx,
			'the starved HTLC produced no penalty of its own'
		).to.equal(undefined);
	});
});
