/**
 * Retrying revoked-commitment claims that were skipped as uneconomic (#242).
 *
 * A claim that cannot pay its own fee is skipped rather than built (#241), and
 * before this nothing revisited it: updateFeeRate only assigned a rate, and the
 * block loops only rebuild sweeps that already reached SPEND_BROADCAST. So a
 * breach during a fee spike could leave the cheater's to_local penalty unbuilt,
 * and once the spike passed nothing went back for it, even though the funds
 * stay claimable until their to_self_delay matures.
 *
 * The retry runs on every new block and on every fresh fee estimate, over every
 * output that still has no spend, for as long as its outpoint is unspent. A
 * competing spend path opening (their CSV maturing, an HTLC expiring) is
 * reported but does not stop it: it does not invalidate our own spend path.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	ChainAction,
	ChainActionType,
	CommitmentType,
	MonitorState,
	OutputStatus,
	OutputType,
	ITrackedOutput
} from '../../src/lightning/chain/types';
import {
	matchRevokedHtlcSnapshotOutputs,
	resolveRevokedCommitmentOutputs,
	resolveTheirCurrentCommitmentOutputs
} from '../../src/lightning/chain/output-resolver';
import { HtlcDirection, ChannelRole } from '../../src/lightning/channel/types';
import { MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	perCommitmentPointFromSecret,
	deriveRevocationPubkey,
	derivePublicKey
} from '../../src/lightning/keys/derivation';
import {
	buildOfferedHtlcScript,
	buildReceivedHtlcScript
} from '../../src/lightning/script/htlc';
import {
	buildToLocalScript,
	calculateObscuredCommitmentNumber
} from '../../src/lightning/script/commitment';
import {
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput
} from '../../src/lightning/script/commitment-taproot';
import {
	setupRevokedWithHtlcs,
	IRevokedSetup
} from './helpers/revoked-commitment-fixture';
import {
	NETWORK,
	privAt,
	revokedTaprootSetup,
	trackedFor,
	emptyRevokedTx
} from './helpers/taproot-revoked-fixture';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;

const HEIGHT = 750_000;
/** DEFAULT_CHANNEL_CONFIG.toSelfDelay: how long their to_local stays ours alone. */
const TO_SELF_DELAY = 144;
/** Prices every claim here out of its own fee. */
const SPIKE_SAT_PER_VBYTE = 50;
/** 1 sat/vByte, as updateFeeRate takes it (sat/kw = sat/vB * 250). */
const CALM_SAT_PER_KW = 250;
/** Small enough to be unaffordable at the spike, large enough to claim at 1 sat/vB. */
const STARVED_SATS = 2_000;

function monitorFor(s: IRevokedSetup, feeRatePerVbyte: number): ChainMonitor {
	return new ChainMonitor(
		s.state,
		s.destScript,
		feeRatePerVbyte,
		s.openerPrivkeys[1], // revocation basepoint secret
		s.openerPrivkeys[2], // payment privkey
		network
	);
}

function broadcastTxs(actions: ChainAction[]): bitcoin.Transaction[] {
	const txs: bitcoin.Transaction[] = [];
	for (const action of actions) {
		if (action.type === ChainActionType.BROADCAST_TX) {
			txs.push(bitcoin.Transaction.fromBuffer(action.tx));
		}
	}
	return txs;
}

function uneconomicActions(
	actions: ChainAction[]
): Array<{ reason: string; outputIndex: number; contestHeight?: number }> {
	const found: Array<{
		reason: string;
		outputIndex: number;
		contestHeight?: number;
	}> = [];
	for (const action of actions) {
		if (action.type === ChainActionType.SWEEP_UNECONOMIC) {
			found.push({
				reason: action.reason,
				outputIndex: action.outputIndex,
				contestHeight: action.contestHeight
			});
		}
	}
	return found;
}

function spentIndices(tx: bitcoin.Transaction): number[] {
	return tx.ins.map((i) => i.index).sort((a, b) => a - b);
}

function trackedAt(
	monitor: ChainMonitor,
	outputIndex: number
): ITrackedOutput | undefined {
	return monitor.getTrackedOutputs().find((o) => o.outputIndex === outputIndex);
}

interface ISnapshotHtlcSpec {
	outputIndex: number;
	direction: HtlcDirection;
	amountSats: number;
	cltvExpiry: number;
}

function installSnapshotHtlcs(
	s: IRevokedSetup,
	specs: ISnapshotHtlcSpec[]
): Buffer[] {
	const secret = s.state.shaChainStore.getSecret(MAX_INDEX)!;
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
	const entries = specs.map((spec) => ({
		paymentHash: crypto.randomBytes(32),
		amountMsat: BigInt(spec.amountSats) * 1000n,
		cltvExpiry: spec.cltvExpiry,
		direction: spec.direction
	}));
	s.state.revokedHtlcSnapshots = new Map([['0', entries]]);
	for (let i = 0; i < specs.length; i++) {
		const spec = specs[i];
		const entry = entries[i];
		const script =
			spec.direction === HtlcDirection.OFFERED
				? buildReceivedHtlcScript(
						revocationPubkey,
						theirHtlc,
						ourHtlc,
						entry.paymentHash,
						spec.cltvExpiry,
						false
				  )
				: buildOfferedHtlcScript(
						revocationPubkey,
						theirHtlc,
						ourHtlc,
						entry.paymentHash,
						false
				  );
		s.revokedTx.outs[spec.outputIndex].script = bitcoin.payments.p2wsh({
			redeem: { output: script }
		}).output!;
		s.revokedTx.outs[spec.outputIndex].value = spec.amountSats;
	}
	return entries.map((entry) => entry.paymentHash);
}

function installSnapshotHtlc(
	s: IRevokedSetup,
	direction: HtlcDirection,
	amountSats = STARVED_SATS
): Buffer {
	return installSnapshotHtlcs(s, [
		{
			outputIndex: 1,
			direction,
			amountSats,
			cltvExpiry: s.nearCltv
		}
	])[0];
}

/**
 * A breach whose to_local penalty was declined: their to_local is the only
 * claimable output (the fixture's HTLCs are not live, so they are not
 * classified) and it is far too small to pay for a penalty at the spike rate.
 */
function breachWithStarvedToLocal(): {
	s: IRevokedSetup;
	monitor: ChainMonitor;
} {
	const s = setupRevokedWithHtlcs(HEIGHT);
	expect(
		s.state.localConfig.toSelfDelay,
		'the deadline these tests assert tracks the channel config'
	).to.equal(TO_SELF_DELAY);
	s.revokedTx.outs[0].value = STARVED_SATS;
	const monitor = monitorFor(s, SPIKE_SAT_PER_VBYTE);
	const actions = monitor.handleFundingSpent(s.revokedTx, HEIGHT);

	expect(
		broadcastTxs(actions),
		'the starved to_local penalty is declined, not built'
	).to.have.length(0);
	const declined = uneconomicActions(actions);
	expect(
		declined.map((d) => d.reason),
		'and the very first decline is reported, not only later retries'
	).to.deep.equal(['skipped']);
	expect(declined[0].outputIndex).to.equal(0);
	const toLocal = trackedAt(monitor, 0)!;
	expect(toLocal.outputType).to.equal(OutputType.TO_LOCAL);
	expect(toLocal.status).to.equal(OutputStatus.CONFIRMED);
	expect(toLocal.sweepTxHex, 'and it holds no sweep').to.equal(undefined);

	return { s, monitor };
}

describe('Retrying uneconomic revoked sweeps', function () {
	it('retries a skipped penalty when a fresh fee estimate makes it affordable', function () {
		const { monitor } = breachWithStarvedToLocal();

		const actions = monitor.updateFeeRate(CALM_SAT_PER_KW);

		const txs = broadcastTxs(actions);
		expect(txs, 'the penalty is built once fees fall').to.have.length(1);
		expect(spentIndices(txs[0]), 'and it claims their to_local').to.deep.equal([
			0
		]);
		expect(txs[0].outs[0].value, 'paying out more than dust').to.be.greaterThan(
			294
		);

		const toLocal = trackedAt(monitor, 0)!;
		expect(toLocal.status).to.equal(OutputStatus.SPEND_BROADCAST);
		expect(toLocal.sweepTxHex, 'the sweep is recorded').to.not.equal(undefined);
	});

	it('retries a skipped penalty on a new block after a restart at a lower rate', function () {
		const { s, monitor } = breachWithStarvedToLocal();

		// A restart mid-breach, once the spike has passed.
		const restored = ChainMonitor.restore(
			monitor.getFullState(),
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		const txs = broadcastTxs(restored.handleNewBlock(HEIGHT + 1));
		expect(txs, 'the block-driven retry builds it').to.have.length(1);
		expect(spentIndices(txs[0])).to.deep.equal([0]);
		expect(trackedAt(restored, 0)!.status).to.equal(
			OutputStatus.SPEND_BROADCAST
		);
	});

	it('reports the decline once, not on every retry', function () {
		const { monitor } = breachWithStarvedToLocal();

		expect(
			uneconomicActions(monitor.handleNewBlock(HEIGHT + 1)),
			'the decline was already reported at breach time'
		).to.have.length(0);
		expect(
			uneconomicActions(monitor.handleNewBlock(HEIGHT + 2)),
			'and a still-unaffordable retry does not report again'
		).to.have.length(0);
	});

	it('keeps retrying after a competing spend path opens', function () {
		const { monitor } = breachWithStarvedToLocal();

		// Their delayed branch matures here. It does not invalidate our revocation
		// spend, so the claim is now a race rather than a lost cause.
		const contested = monitor.handleNewBlock(HEIGHT + TO_SELF_DELAY + 1);
		const reported = uneconomicActions(contested);
		expect(reported, 'the race is surfaced').to.have.length(1);
		expect(reported[0].reason).to.equal('contested');
		expect(
			reported[0].contestHeight,
			'at the CSV their to_local script actually carries'
		).to.equal(HEIGHT + TO_SELF_DELAY);

		const txs = broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW));
		expect(
			txs,
			'and a later fee drop still recovers the outpoint, which is unspent'
		).to.have.length(1);
		expect(spentIndices(txs[0])).to.deep.equal([0]);

		expect(
			uneconomicActions(monitor.handleNewBlock(HEIGHT + TO_SELF_DELAY + 2)),
			'the race is reported only once'
		).to.have.length(0);
	});

	it('uses the on-chain lease CSV, not the configured to_self_delay', function () {
		const { monitor } = breachWithStarvedToLocal();
		const toLocal = trackedAt(monitor, 0)!;
		// A leased to_local carries the lease lock in its script (CLN model: a pure
		// CSV), far beyond the 144 we configured.
		const leaseCsv = 4032;
		toLocal.witnessScript = buildToLocalScript(
			crypto.randomBytes(33),
			crypto.randomBytes(33),
			TO_SELF_DELAY,
			leaseCsv
		);

		expect(
			uneconomicActions(monitor.handleNewBlock(HEIGHT + TO_SELF_DELAY + 1)),
			'the configured delay is not the height their branch opens at'
		).to.have.length(0);

		const reported = uneconomicActions(
			monitor.handleNewBlock(HEIGHT + leaseCsv)
		);
		expect(reported, 'the lease CSV is').to.have.length(1);
		expect(reported[0].reason).to.equal('contested');
		expect(reported[0].contestHeight).to.equal(HEIGHT + leaseCsv);
	});

	it('names no competing height until the breach confirms', function () {
		// A relative delay counts from confirmation. A mempool-first sighting has
		// no height yet, and treating that as 0 would name a height already behind
		// the tip: a race reported before it starts, and then suppressed when it
		// really does.
		const s = setupRevokedWithHtlcs(HEIGHT);
		s.revokedTx.outs[0].value = STARVED_SATS;
		const monitor = monitorFor(s, SPIKE_SAT_PER_VBYTE);
		monitor.handleFundingSpent(s.revokedTx, 0);
		expect(trackedAt(monitor, 0)!.confirmationHeight).to.equal(0);

		expect(
			uneconomicActions(monitor.handleNewBlock(HEIGHT)),
			'no height is named while the commitment is unconfirmed'
		).to.have.length(0);

		// It confirms; the CSV counts from here.
		monitor.handleFundingSpent(s.revokedTx, HEIGHT);
		expect(
			uneconomicActions(monitor.handleNewBlock(HEIGHT + TO_SELF_DELAY - 1)),
			'and the race has still not started'
		).to.have.length(0);

		const reported = uneconomicActions(
			monitor.handleNewBlock(HEIGHT + TO_SELF_DELAY)
		);
		expect(
			reported.map((r) => r.reason),
			'the real transition is reported once it does'
		).to.deep.equal(['contested']);
		expect(reported[0].contestHeight).to.equal(HEIGHT + TO_SELF_DELAY);
	});

	it('names no competing height for an HTLC only a preimage can take', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		s.revokedTx.outs[0].value = STARVED_SATS;
		const monitor = monitorFor(s, SPIKE_SAT_PER_VBYTE);
		monitor.handleFundingSpent(s.revokedTx, HEIGHT);

		// An HTLC WE offered is theirs to claim with the preimage at any moment, so
		// no height bounds it. One we receive is bounded by their HTLC-timeout.
		const toLocal = trackedAt(monitor, 0)!;
		toLocal.outputType = OutputType.OFFERED_HTLC;
		toLocal.cltvExpiry = HEIGHT + 10;
		expect(
			uneconomicActions(monitor.handleNewBlock(HEIGHT + 500)),
			'an offered HTLC has no cltv boundary of ours to report'
		).to.have.length(0);

		toLocal.outputType = OutputType.RECEIVED_HTLC;
		const reported = uneconomicActions(monitor.handleNewBlock(HEIGHT + 501));
		expect(
			reported,
			'a received HTLC is bounded by its cltv_expiry'
		).to.have.length(1);
		expect(reported[0].contestHeight).to.equal(HEIGHT + 10);
	});

	it('stops retrying an outpoint the cheater has spent', function () {
		const { s, monitor } = breachWithStarvedToLocal();

		// Their delayed claim confirms: the outpoint is gone, affordable or not.
		const theirClaim = new bitcoin.Transaction();
		theirClaim.version = 2;
		theirClaim.addInput(
			Buffer.from(s.revokedTx.getId(), 'hex').reverse(),
			0,
			TO_SELF_DELAY
		);
		theirClaim.addOutput(
			Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
			1_000
		);
		monitor.handleOutputSpent(
			s.revokedTx.getId(),
			0,
			theirClaim,
			HEIGHT + TO_SELF_DELAY
		);

		expect(
			broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW)),
			'a spent outpoint is not re-claimed'
		).to.have.length(0);
	});

	it('does not re-broadcast a claim it already built', function () {
		const { monitor } = breachWithStarvedToLocal();

		expect(broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW))).to.have.length(
			1
		);
		expect(
			broadcastTxs(monitor.handleNewBlock(HEIGHT + 1)),
			'the next block has nothing left to retry'
		).to.have.length(0);
		expect(
			broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW)),
			'and neither does another fee estimate'
		).to.have.length(0);
	});

	it('never re-batches an outpoint a live claim of ours already spends', function () {
		// Both HTLCs reach the resolver through revokedHtlcSnapshots, the settled-
		// HTLC path: they are claimed by the initial penalty but never become
		// tracked outputs, so only the transactions themselves record that their
		// outpoints are taken. Our to_remote is starved and left for the retry.
		const s = setupRevokedWithHtlcs(HEIGHT, { toRemoteSats: STARVED_SATS });
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

		const monitor = monitorFor(s, SPIKE_SAT_PER_VBYTE);
		const opening = monitor.handleFundingSpent(s.revokedTx, HEIGHT);

		const claimedByOpening = new Set<number>();
		for (const tx of broadcastTxs(opening)) {
			for (const index of spentIndices(tx)) claimedByOpening.add(index);
		}
		expect(
			[...claimedByOpening].sort((a, b) => a - b),
			'their to_local and both snapshot HTLCs are claimed up front'
		).to.deep.equal([0, 1, 2]);
		const toRemote = trackedAt(monitor, s.toRemoteIndex!)!;
		expect(toRemote.outputType).to.equal(OutputType.TO_REMOTE);
		expect(
			toRemote.sweepTxHex,
			'our starved to_remote is left unclaimed'
		).to.equal(undefined);

		const retried = broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW));

		expect(
			retried,
			'the retry claims exactly the outpoint left over'
		).to.have.length(1);
		expect(spentIndices(retried[0])).to.deep.equal([s.toRemoteIndex!]);
		for (const tx of retried) {
			for (const index of spentIndices(tx)) {
				expect(
					claimedByOpening.has(index),
					`retry must not spend outpoint ${index}, which a live claim already spends`
				).to.equal(false);
			}
		}
		expect(
			retried[0].ins[0].witness.length,
			'and the claim is signed, not broadcast bare'
		).to.be.greaterThan(0);
	});

	it('adopts, reports and keeps managing a snapshot-reconstructed HTLC', function () {
		// The tracked to_local is affordable and claimed at the opening; the only
		// skipped claim is a settled HTLC rebuilt from revokedHtlcSnapshots, which
		// the live classification never matched. Left unadopted it would be outside
		// the retry set, unwatched, never rebroadcast, and outside full-resolution
		// accounting, so "retry until spent" would not hold for it.
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlc(s, HtlcDirection.RECEIVED);

		const monitor = monitorFor(s, SPIKE_SAT_PER_VBYTE);
		const openingActions = monitor.handleFundingSpent(s.revokedTx, HEIGHT);
		const claimedAtOpening = new Set<number>();
		for (const tx of broadcastTxs(openingActions)) {
			for (const index of spentIndices(tx)) claimedAtOpening.add(index);
		}
		expect(
			claimedAtOpening.has(0),
			'their to_local is affordable and claimed'
		).to.equal(true);
		expect(
			claimedAtOpening.has(1),
			'the starved snapshot HTLC is not'
		).to.equal(false);
		expect(
			trackedAt(monitor, 1),
			'but it is adopted, so something owns it from here on'
		).to.not.equal(undefined);
		expect(
			openingActions.some(
				(a) =>
					a.type === ChainActionType.WATCH_OUTPUT &&
					a.txid === s.revokedTx.getId() &&
					a.outputIndex === 1
			),
			'and its outpoint is watched, so a spend can end the claim'
		).to.equal(true);
		expect(
			uneconomicActions(openingActions).map((d) => d.outputIndex),
			'the decline of a snapshot claim is reported too'
		).to.deep.equal([1]);

		const retried = broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW));
		expect(retried, 'the retry reaches it').to.have.length(1);
		expect(spentIndices(retried[0])).to.deep.equal([1]);

		// Recovered, and still under management: it holds its sweep, so the
		// rebroadcast and RBF loops cover it, and full resolution waits for it.
		const adopted = trackedAt(monitor, 1)!;
		expect(adopted.status).to.equal(OutputStatus.SPEND_BROADCAST);
		expect(adopted.sweepTxHex).to.not.equal(undefined);
		monitor.handleNewBlock(HEIGHT + 1);
		expect(
			monitor.getState(),
			'a claim still in flight is not full resolution'
		).to.not.equal(MonitorState.FULLY_RESOLVED);
	});

	it('preserves metadata for a received snapshot HTLC', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		const paymentHash = installSnapshotHtlc(s, HtlcDirection.RECEIVED);
		const monitor = monitorFor(s, SPIKE_SAT_PER_VBYTE);
		const actions = monitor.handleFundingSpent(s.revokedTx, HEIGHT);

		const adopted = trackedAt(monitor, 1)!;
		expect(adopted.outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(adopted.paymentHash?.equals(paymentHash)).to.equal(true);
		const report = actions.find(
			(action) =>
				action.type === ChainActionType.SWEEP_UNECONOMIC &&
				action.outputIndex === 1
		);
		expect(report?.type).to.equal(ChainActionType.SWEEP_UNECONOMIC);
		if (report?.type === ChainActionType.SWEEP_UNECONOMIC) {
			expect(report.outputType).to.equal(OutputType.RECEIVED_HTLC);
			expect(report.contestHeight).to.equal(s.nearCltv);
		}
	});

	it('repairs received snapshot metadata from a legacy monitor state', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		const paymentHash = installSnapshotHtlc(s, HtlcDirection.RECEIVED);
		const active = monitorFor(s, SPIKE_SAT_PER_VBYTE);
		active.handleFundingSpent(s.revokedTx, HEIGHT);
		const legacySnapshot: ITrackedOutput = {
			...trackedAt(active, 1)!,
			outputType: OutputType.OFFERED_HTLC,
			paymentHash: undefined
		};
		const resolvedToLocal: ITrackedOutput = {
			...trackedAt(active, 0)!,
			status: OutputStatus.IRREVOCABLY_RESOLVED
		};
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [resolvedToLocal, legacySnapshot],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [resolvedToLocal, legacySnapshot],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			SPIKE_SAT_PER_VBYTE,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		const repaired = trackedAt(monitor, 1)!;
		expect(repaired.outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(repaired.paymentHash?.equals(paymentHash)).to.equal(true);
		const persisted = monitor
			.getFullState()
			.trackedOutputs.find((output) => output.outputIndex === 1)!;
		expect(persisted.outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(persisted.paymentHash?.equals(paymentHash)).to.equal(true);
		const contested = monitor.handleNewBlock(s.nearCltv);
		expect(
			uneconomicActions(contested).some(
				(action) => action.outputIndex === 1 && action.reason === 'contested'
			)
		).to.equal(true);
	});

	it('ignores a trimmed same-script snapshot when matching metadata', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		const secret = s.state.shaChainStore.getSecret(MAX_INDEX)!;
		const revokedPoint = perCommitmentPointFromSecret(secret);
		const paymentHash = crypto.randomBytes(32);
		const trimmedCltv = HEIGHT + 150_000;
		const liveCltv = HEIGHT + 10;
		const liveAmount = 20_000;
		const script = buildOfferedHtlcScript(
			deriveRevocationPubkey(
				s.state.localBasepoints.revocationBasepoint,
				revokedPoint
			),
			derivePublicKey(s.state.remoteBasepoints!.htlcBasepoint, revokedPoint),
			derivePublicKey(s.state.localBasepoints.htlcBasepoint, revokedPoint),
			paymentHash,
			false
		);
		s.revokedTx.outs[1].script = bitcoin.payments.p2wsh({
			redeem: { output: script }
		}).output!;
		s.revokedTx.outs[1].value = liveAmount;
		s.state.revokedHtlcSnapshots = new Map([
			[
				'0',
				[
					{
						paymentHash,
						amountMsat: 100_000n,
						cltvExpiry: trimmedCltv,
						direction: HtlcDirection.RECEIVED
					},
					{
						paymentHash,
						amountMsat: BigInt(liveAmount) * 1000n,
						cltvExpiry: liveCltv,
						direction: HtlcDirection.RECEIVED
					}
				]
			]
		]);

		const matched = matchRevokedHtlcSnapshotOutputs(
			s.state,
			0n,
			s.revokedTx,
			network
		);
		expect(matched.size).to.equal(1);
		expect(matched.get(1)?.cltvExpiry).to.equal(liveCltv);
		expect(matched.get(1)?.outputType).to.equal(OutputType.RECEIVED_HTLC);
	});

	it('matches duplicate offered scripts in BOLT CLTV order', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		const secret = s.state.shaChainStore.getSecret(MAX_INDEX)!;
		const revokedPoint = perCommitmentPointFromSecret(secret);
		const paymentHash = crypto.randomBytes(32);
		const lowCltv = HEIGHT + 10;
		const highCltv = HEIGHT + 100;
		const amountSats = 20_000;
		const script = buildOfferedHtlcScript(
			deriveRevocationPubkey(
				s.state.localBasepoints.revocationBasepoint,
				revokedPoint
			),
			derivePublicKey(s.state.remoteBasepoints!.htlcBasepoint, revokedPoint),
			derivePublicKey(s.state.localBasepoints.htlcBasepoint, revokedPoint),
			paymentHash,
			false
		);
		const scriptPubkey = bitcoin.payments.p2wsh({
			redeem: { output: script }
		}).output!;
		for (const outputIndex of [1, 2]) {
			s.revokedTx.outs[outputIndex].script = scriptPubkey;
			s.revokedTx.outs[outputIndex].value = amountSats;
		}
		// Deliberately reverse snapshot insertion order. The commitment indices
		// still follow the BOLT 3 CLTV tie-break.
		s.state.revokedHtlcSnapshots = new Map([
			[
				'0',
				[
					{
						paymentHash,
						amountMsat: BigInt(amountSats) * 1000n,
						cltvExpiry: highCltv,
						direction: HtlcDirection.RECEIVED
					},
					{
						paymentHash,
						amountMsat: BigInt(amountSats) * 1000n,
						cltvExpiry: lowCltv,
						direction: HtlcDirection.RECEIVED
					}
				]
			]
		]);

		const matched = matchRevokedHtlcSnapshotOutputs(
			s.state,
			0n,
			s.revokedTx,
			network
		);
		expect(matched.get(1)?.cltvExpiry).to.equal(lowCltv);
		expect(matched.get(2)?.cltvExpiry).to.equal(highCltv);
	});

	it('does not resolve a monitor when a block retry adopts a claim', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlc(s, HtlcDirection.OFFERED);
		const resolvedToLocal: ITrackedOutput = {
			...s.trackedOutputs[0],
			status: OutputStatus.IRREVOCABLY_RESOLVED
		};
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [resolvedToLocal],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [resolvedToLocal],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		const actions = monitor.handleNewBlock(HEIGHT + 1);
		expect(broadcastTxs(actions)).to.have.length(1);
		expect(trackedAt(monitor, 1)?.status).to.equal(
			OutputStatus.SPEND_BROADCAST
		);
		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
		expect(
			actions.some(
				(action) => action.type === ChainActionType.CHANNEL_FULLY_RESOLVED
			)
		).to.equal(false);
	});

	it('reopens a fully resolved monitor before a block retry adopts a claim', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlc(s, HtlcDirection.OFFERED);
		const resolvedToLocal: ITrackedOutput = {
			...s.trackedOutputs[0],
			status: OutputStatus.IRREVOCABLY_RESOLVED
		};
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.FULLY_RESOLVED,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [resolvedToLocal],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [resolvedToLocal],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
		const actions = monitor.handleNewBlock(HEIGHT + 1);
		expect(broadcastTxs(actions)).to.have.length(1);
		expect(trackedAt(monitor, 1)?.status).to.equal(
			OutputStatus.SPEND_BROADCAST
		);
		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
	});

	it('rebuilds a legacy claimed snapshot output with no stored sweep', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlc(s, HtlcDirection.OFFERED);
		const resolvedToLocal: ITrackedOutput = {
			...s.trackedOutputs[0],
			status: OutputStatus.IRREVOCABLY_RESOLVED
		};
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.FULLY_RESOLVED,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [resolvedToLocal],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0, 1]
				},
				trackedOutputs: [resolvedToLocal],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
		expect(trackedAt(monitor, 1)?.status).to.equal(OutputStatus.CONFIRMED);
		expect(
			monitor.getFullState().commitmentBroadcast?.claimedOutputIndices
		).to.deep.equal([0]);
		const actions = monitor.handleNewBlock(HEIGHT + 1);
		expect(broadcastTxs(actions)).to.have.length(1);
		expect(trackedAt(monitor, 1)?.status).to.equal(
			OutputStatus.SPEND_BROADCAST
		);
		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
	});

	it('restores a missing snapshot output from its shared penalty sweep', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 1_000
			}
		]);
		const active = monitorFor(s, 1);
		const opening = broadcastTxs(
			active.handleFundingSpent(s.revokedTx, HEIGHT)
		);
		const shared = opening.find((tx) => {
			const indices = spentIndices(tx);
			return indices.length === 2 && indices[0] === 0 && indices[1] === 1;
		})!;
		expect(spentIndices(shared)).to.deep.equal([0, 1]);
		const trackedToLocal = trackedAt(active, 0)!;
		expect(trackedToLocal.sweepTxHex).to.equal(shared.toHex());
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.FULLY_RESOLVED,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [trackedToLocal],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0, 1]
				},
				trackedOutputs: [trackedToLocal],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		const restoredSnapshot = trackedAt(monitor, 1)!;
		expect(restoredSnapshot.status).to.equal(OutputStatus.SPEND_BROADCAST);
		expect(restoredSnapshot.sweepTxHex).to.equal(shared.toHex());
		expect(
			monitor.getFullState().commitmentBroadcast?.claimedOutputIndices
		).to.deep.equal([0, 1]);
		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
	});

	it('emits resolution for a hidden member of a confirmed shared penalty', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 1_000
			}
		]);
		const active = monitorFor(s, 1);
		const shared = broadcastTxs(
			active.handleFundingSpent(s.revokedTx, HEIGHT)
		).find((tx) => spentIndices(tx).join(',') === '0,1')!;
		expect(shared).to.exist;
		const terminalSource: ITrackedOutput = {
			...trackedAt(active, 0)!,
			status: OutputStatus.IRREVOCABLY_RESOLVED,
			confirmationHeight: HEIGHT + 1,
			resolutionTxid: shared.getId(),
			sweepTxHex: shared.toHex()
		};
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.FULLY_RESOLVED,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [terminalSource],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0, 1]
				},
				trackedOutputs: [terminalSource],
				currentBlockHeight: HEIGHT + 100
			},
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		expect(trackedAt(monitor, 1)?.status).to.equal(
			OutputStatus.SPEND_CONFIRMED
		);
		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
		const actions = monitor.handleNewBlock(HEIGHT + 101);
		expect(
			actions.some(
				(action) =>
					action.type === ChainActionType.OUTPUT_RESOLVED &&
					action.outputIndex === 1
			)
		).to.equal(true);
		expect(trackedAt(monitor, 1)?.status).to.equal(
			OutputStatus.IRREVOCABLY_RESOLVED
		);
	});

	it('emits resolution for a late-inferred member of a buried penalty', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 1_000
			}
		]);
		const monitor = monitorFor(s, 1);
		const shared = broadcastTxs(
			monitor.handleFundingSpent(s.revokedTx, HEIGHT)
		).find((tx) => spentIndices(tx).join(',') === '0,1')!;
		expect(shared).to.exist;
		const source = trackedAt(monitor, 0)!;
		const inferred = trackedAt(monitor, 1)!;
		source.status = OutputStatus.IRREVOCABLY_RESOLVED;
		source.resolutionTxid = shared.getId();
		source.confirmationHeight = HEIGHT + 1;

		const replacements = monitor.rebuildSweeps(inferred, 2);
		expect(replacements).to.deep.equal([]);
		expect(inferred.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		expect(inferred.resolutionTxid).to.equal(shared.getId());
		const actions = monitor.handleNewBlock(HEIGHT + 101);
		expect(
			actions.some(
				(action) =>
					action.type === ChainActionType.OUTPUT_RESOLVED &&
					action.outputIndex === 1
			)
		).to.equal(true);
	});

	it('rebuilds a hidden batch member after its sibling loses a spend race', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 1_000
			}
		]);
		const active = monitorFor(s, 1);
		const shared = broadcastTxs(
			active.handleFundingSpent(s.revokedTx, HEIGHT)
		).find((tx) => spentIndices(tx).join(',') === '0,1')!;
		expect(shared).to.exist;

		const competitor = new bitcoin.Transaction();
		competitor.version = 2;
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 0);
		competitor.addOutput(s.destScript, 500_000);
		const staleSource: ITrackedOutput = {
			...trackedAt(active, 0)!,
			status: OutputStatus.IRREVOCABLY_RESOLVED,
			confirmationHeight: HEIGHT + 1,
			resolutionTxid: competitor.getId(),
			sweepTxHex: shared.toHex()
		};
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.FULLY_RESOLVED,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [staleSource],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0, 1]
				},
				trackedOutputs: [staleSource],
				currentBlockHeight: HEIGHT + 100
			},
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		const hidden = trackedAt(monitor, 1)!;
		expect(hidden.status).to.equal(OutputStatus.CONFIRMED);
		expect(hidden.sweepTxHex).to.equal(undefined);
		expect(hidden.resolutionTxid).to.equal(undefined);
		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
		expect(
			monitor.getFullState().commitmentBroadcast?.claimedOutputIndices
		).to.deep.equal([0]);

		const retried = broadcastTxs(monitor.handleNewBlock(HEIGHT + 101));
		expect(retried).to.have.length(1);
		expect(spentIndices(retried[0])).to.deep.equal([1]);
	});

	it('reopens a legacy fully resolved monitor with an in-flight claim', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlc(s, HtlcDirection.OFFERED);
		const active = monitorFor(s, SPIKE_SAT_PER_VBYTE);
		active.handleFundingSpent(s.revokedTx, HEIGHT);
		active.updateFeeRate(CALM_SAT_PER_KW);
		const inFlight = trackedAt(active, 1)!;
		expect(inFlight.status).to.equal(OutputStatus.SPEND_BROADCAST);
		const resolvedToLocal: ITrackedOutput = {
			...trackedAt(active, 0)!,
			status: OutputStatus.IRREVOCABLY_RESOLVED
		};
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.FULLY_RESOLVED,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [resolvedToLocal, inFlight],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0, 1]
				},
				trackedOutputs: [resolvedToLocal, inFlight],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
		const actions = monitor.handleNewBlock(HEIGHT + 6);
		expect(
			actions.some(
				(action) =>
					action.type === ChainActionType.REBUILD_SWEEP ||
					action.type === ChainActionType.BROADCAST_TX
			)
		).to.equal(true);
	});

	it('fee-bumps a jointly economical snapshot penalty as one batch', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_100,
				cltvExpiry: HEIGHT + 1_000
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_100,
				cltvExpiry: HEIGHT + 1_100
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		expect(spentIndices(opening[0])).to.deep.equal([1, 2]);
		expect(
			opening[0].ins.some((input) => input.sequence < 0xfffffffe)
		).to.equal(true);
		const originalHex = opening[0].toHex();
		expect(trackedAt(monitor, 1)?.sweepTxHex).to.equal(originalHex);
		expect(trackedAt(monitor, 2)?.sweepTxHex).to.equal(originalHex);

		const bumpActions = monitor.handleNewBlock(HEIGHT + 7);
		const rebuilds = bumpActions.filter(
			(action) => action.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuilds).to.have.length(1);
		const rebuild = rebuilds[0];
		if (rebuild.type !== ChainActionType.REBUILD_SWEEP) {
			throw new Error('expected one grouped sweep rebuild');
		}
		const replacements = monitor.rebuildSweeps(
			rebuild.output,
			rebuild.feeRatePerVbyte
		);
		expect(replacements).to.have.length(1);
		const replacement = replacements[0];
		expect(spentIndices(replacement)).to.deep.equal([1, 2]);
		expect(replacement.toHex()).to.not.equal(originalHex);
		expect(
			replacement.ins.some((input) => input.sequence < 0xfffffffe)
		).to.equal(true);
		expect(replacement.outs[0].value).to.equal(480);
		const replacementHex = replacement.toHex();
		for (const outputIndex of [1, 2]) {
			const output = trackedAt(monitor, outputIndex)!;
			expect(output.sweepTxHex).to.equal(replacementHex);
			expect(output.currentFeeRate).to.equal(15);
			expect(output.broadcastHeight).to.equal(HEIGHT + 7);
		}

		const restored = ChainMonitor.restore(
			monitor.getFullState(),
			s.state,
			s.destScript,
			15,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		expect(trackedAt(restored, 1)?.sweepTxHex).to.equal(replacementHex);
		expect(trackedAt(restored, 2)?.sweepTxHex).to.equal(replacementHex);
	});

	it('raises a low-rate replacement enough to evict its old batch', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 1_000
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 1_100
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		const actions = monitor.handleNewBlock(HEIGHT + 7);
		const rebuild = actions.find(
			(action) => action.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuild?.type).to.equal(ChainActionType.REBUILD_SWEEP);
		if (rebuild?.type !== ChainActionType.REBUILD_SWEEP) {
			throw new Error('expected low-rate group rebuild');
		}
		expect(rebuild.feeRatePerVbyte).to.equal(1.5);
		const replacements = monitor.rebuildSweeps(
			rebuild.output,
			rebuild.feeRatePerVbyte
		);
		expect(replacements).to.have.length(1);
		expect(spentIndices(replacements[0])).to.deep.equal([1, 2]);
		expect(replacements[0].toHex()).to.not.equal(opening[0].toHex());
		expect(trackedAt(monitor, 1)?.currentFeeRate).to.be.greaterThan(1.5);
		expect(trackedAt(monitor, 2)?.currentFeeRate).to.equal(
			trackedAt(monitor, 1)?.currentFeeRate
		);
	});

	it('rebroadcasts a shared penalty when its group bump is uneconomic', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 1_500,
				cltvExpiry: HEIGHT + 1_000
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 1_500,
				cltvExpiry: HEIGHT + 1_100
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		expect(spentIndices(opening[0])).to.deep.equal([1, 2]);
		const rebroadcast = monitor.handleNewBlock(HEIGHT + 7);
		const rebuilds = rebroadcast.filter(
			(action) => action.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuilds).to.have.length(1);
		const rebuild = rebuilds[0];
		if (rebuild.type !== ChainActionType.REBUILD_SWEEP) {
			throw new Error('expected one grouped sweep rebuild');
		}
		const rebroadcastTxs = monitor.rebuildSweeps(
			rebuild.output,
			rebuild.feeRatePerVbyte
		);
		expect(rebroadcastTxs).to.have.length(1);
		expect(rebroadcastTxs[0].toHex()).to.equal(opening[0].toHex());
		expect(spentIndices(rebroadcastTxs[0])).to.deep.equal([1, 2]);
		for (const outputIndex of [1, 2]) {
			expect(trackedAt(monitor, outputIndex)?.currentFeeRate).to.equal(
				undefined
			);
			expect(trackedAt(monitor, outputIndex)?.broadcastHeight).to.equal(
				HEIGHT + 7
			);
		}
	});

	it('retains a legacy shared penalty that did not signal replacement', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_100,
				cltvExpiry: HEIGHT + 1_000
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_100,
				cltvExpiry: HEIGHT + 1_100
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		const legacy = bitcoin.Transaction.fromHex(opening[0].toHex());
		for (const input of legacy.ins) input.sequence = 0xffffffff;
		const legacyHex = legacy.toHex();
		for (const outputIndex of [1, 2]) {
			const tracked = trackedAt(monitor, outputIndex)!;
			tracked.sweepTxHex = legacyHex;
			tracked.currentFeeRate = undefined;
		}

		const actions = monitor.handleNewBlock(HEIGHT + 7);
		const rebuild = actions.find(
			(action) => action.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuild?.type).to.equal(ChainActionType.REBUILD_SWEEP);
		if (rebuild?.type !== ChainActionType.REBUILD_SWEEP) {
			throw new Error('expected legacy group rebuild');
		}
		const transactions = monitor.rebuildSweeps(
			rebuild.output,
			rebuild.feeRatePerVbyte
		);
		expect(transactions).to.have.length(1);
		expect(transactions[0].toHex()).to.equal(legacyHex);
		for (const outputIndex of [1, 2]) {
			expect(trackedAt(monitor, outputIndex)?.sweepTxHex).to.equal(legacyHex);
			expect(trackedAt(monitor, outputIndex)?.currentFeeRate).to.equal(
				undefined
			);
			expect(trackedAt(monitor, outputIndex)?.broadcastHeight).to.equal(
				HEIGHT + 7
			);
		}
	});

	it('rebuilds the surviving member after a shared penalty is conflicted', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 500,
				cltvExpiry: HEIGHT + 1_000
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_500,
				cltvExpiry: HEIGHT + 1_100
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		expect(spentIndices(opening[0])).to.deep.equal([1, 2]);

		const competitor = new bitcoin.Transaction();
		competitor.version = 2;
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 1);
		competitor.addOutput(s.destScript, 400);
		const conflictActions = monitor.handleOutputSpent(
			s.revokedTx.getId(),
			1,
			competitor,
			HEIGHT + 2
		);
		const replacements = broadcastTxs(conflictActions);
		expect(replacements).to.have.length(1);
		expect(spentIndices(replacements[0])).to.deep.equal([2]);
		expect(replacements[0].toHex()).to.not.equal(opening[0].toHex());
		expect(trackedAt(monitor, 2)?.sweepTxHex).to.equal(replacements[0].toHex());
		expect(
			monitor
				.getFullState()
				.commitmentBroadcast?.claimedOutputIndices?.sort((a, b) => a - b)
		).to.deep.equal([0, 2]);
	});

	it('excludes a spent member when a survivor becomes affordable later', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 500,
				cltvExpiry: HEIGHT + 1_000
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 1_500,
				cltvExpiry: HEIGHT + 1_100
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		expect(spentIndices(opening[0])).to.deep.equal([1, 2]);
		monitor.updateFeeRate(12_500);

		const competitor = new bitcoin.Transaction();
		competitor.version = 2;
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 1);
		competitor.addOutput(s.destScript, 400);
		const conflictActions = monitor.handleOutputSpent(
			s.revokedTx.getId(),
			1,
			competitor,
			HEIGHT + 2
		);
		expect(broadcastTxs(conflictActions)).to.have.length(0);
		expect(trackedAt(monitor, 2)?.status).to.equal(OutputStatus.CONFIRMED);
		expect(trackedAt(monitor, 2)?.sweepTxHex).to.equal(undefined);

		const recovered = broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW));
		expect(recovered).to.have.length(1);
		expect(spentIndices(recovered[0])).to.deep.equal([2]);
		expect(trackedAt(monitor, 1)?.status).to.equal(
			OutputStatus.SPEND_CONFIRMED
		);
		expect(trackedAt(monitor, 1)?.resolutionTxid).to.equal(competitor.getId());
	});

	it('does not rebuild any member spent by one competing transaction', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_500,
				cltvExpiry: HEIGHT + 1_000
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_500,
				cltvExpiry: HEIGHT + 1_100
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		expect(broadcastTxs(monitor.handleNewBlock(HEIGHT + 1))).to.have.length(1);

		const competitor = new bitcoin.Transaction();
		competitor.version = 2;
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 1);
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 2);
		competitor.addOutput(s.destScript, 4_000);
		const actions = monitor.handleOutputSpent(
			s.revokedTx.getId(),
			1,
			competitor,
			HEIGHT + 2
		);
		expect(broadcastTxs(actions)).to.have.length(0);
		for (const outputIndex of [1, 2]) {
			expect(trackedAt(monitor, outputIndex)?.status).to.equal(
				OutputStatus.SPEND_CONFIRMED
			);
			expect(trackedAt(monitor, outputIndex)?.resolutionTxid).to.equal(
				competitor.getId()
			);
		}
		expect(
			monitor.handleOutputSpent(s.revokedTx.getId(), 2, competitor, HEIGHT + 2)
		).to.deep.equal([]);
	});

	it('repairs a shared cohort when the first callback names another claim', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.RECEIVED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 10
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 1_000
			}
		]);
		const toLocal = {
			...s.trackedOutputs[0],
			txid: s.revokedTx.getId(),
			confirmationHeight: HEIGHT
		};
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [toLocal],
					revokedTxHex: s.revokedTx.toHex()
				},
				trackedOutputs: [toLocal],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening.map(spentIndices)).to.deep.include.members([[1], [0, 2]]);
		const oldShared = opening.find(
			(tx) => spentIndices(tx).join(',') === '0,2'
		)!;

		const competitor = new bitcoin.Transaction();
		competitor.version = 2;
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 1);
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 2);
		competitor.addOutput(s.destScript, 90_000);
		const repaired = broadcastTxs(
			monitor.handleOutputSpent(s.revokedTx.getId(), 1, competitor, HEIGHT + 2)
		);
		expect(repaired).to.have.length(1);
		expect(spentIndices(repaired[0])).to.deep.equal([0]);
		expect(repaired[0].toHex()).to.not.equal(oldShared.toHex());
		expect(trackedAt(monitor, 2)?.status).to.equal(
			OutputStatus.SPEND_CONFIRMED
		);
	});

	it('rearms every member when one watch reports a multi-input reorg', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_500,
				cltvExpiry: HEIGHT + 1_000
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_500,
				cltvExpiry: HEIGHT + 1_100
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		expect(spentIndices(opening[0])).to.deep.equal([1, 2]);

		const competitor = new bitcoin.Transaction();
		competitor.version = 2;
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 1);
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 2);
		competitor.addOutput(s.destScript, 4_000);
		monitor.handleOutputSpent(s.revokedTx.getId(), 1, competitor, HEIGHT + 2);

		const recovery = broadcastTxs(
			monitor.handleSpendUnconfirmed(s.revokedTx.getId(), 1)
		);
		expect(recovery).to.have.length(1);
		expect(recovery[0].toHex()).to.equal(opening[0].toHex());
		expect(spentIndices(recovery[0])).to.deep.equal([1, 2]);
		for (const outputIndex of [1, 2]) {
			expect(trackedAt(monitor, outputIndex)?.status).to.equal(
				OutputStatus.SPEND_BROADCAST
			);
			expect(trackedAt(monitor, outputIndex)?.resolutionTxid).to.equal(
				undefined
			);
		}
	});

	it('keeps a survivor claim when its competing sibling spend reorgs', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_500,
				cltvExpiry: HEIGHT + 1_000
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 2_500,
				cltvExpiry: HEIGHT + 1_100
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);

		const competitor = new bitcoin.Transaction();
		competitor.version = 2;
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 1);
		competitor.addOutput(s.destScript, 2_000);
		const survivor = broadcastTxs(
			monitor.handleOutputSpent(s.revokedTx.getId(), 1, competitor, HEIGHT + 2)
		);
		expect(survivor).to.have.length(1);
		expect(spentIndices(survivor[0])).to.deep.equal([2]);
		const survivorHex = survivor[0].toHex();

		const recovery = broadcastTxs(
			monitor.handleSpendUnconfirmed(s.revokedTx.getId(), 1)
		);
		expect(recovery).to.have.length(1);
		expect(spentIndices(recovery[0])).to.deep.equal([1]);
		expect(trackedAt(monitor, 1)?.sweepTxHex).to.equal(recovery[0].toHex());
		expect(trackedAt(monitor, 2)?.sweepTxHex).to.equal(survivorHex);
	});

	it('restores shared bookkeeping when an uneconomic conflict reorgs', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.OFFERED,
				amountSats: 500,
				cltvExpiry: HEIGHT + 1_000
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 1_500,
				cltvExpiry: HEIGHT + 1_100
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		expect(spentIndices(opening[0])).to.deep.equal([1, 2]);
		monitor.updateFeeRate(12_500);

		const competitor = new bitcoin.Transaction();
		competitor.version = 2;
		competitor.addInput(Buffer.from(s.revokedTx.getId(), 'hex').reverse(), 1);
		competitor.addOutput(s.destScript, 400);
		expect(
			broadcastTxs(
				monitor.handleOutputSpent(
					s.revokedTx.getId(),
					1,
					competitor,
					HEIGHT + 2
				)
			)
		).to.have.length(0);
		expect(trackedAt(monitor, 2)?.sweepTxHex).to.equal(undefined);

		const recovery = broadcastTxs(
			monitor.handleSpendUnconfirmed(s.revokedTx.getId(), 1)
		);
		expect(recovery).to.have.length(1);
		expect(recovery[0].toHex()).to.equal(opening[0].toHex());
		for (const outputIndex of [1, 2]) {
			expect(trackedAt(monitor, outputIndex)?.status).to.equal(
				OutputStatus.SPEND_BROADCAST
			);
			expect(trackedAt(monitor, outputIndex)?.sweepTxHex).to.equal(
				opening[0].toHex()
			);
		}
		expect(
			monitor
				.getFullState()
				.commitmentBroadcast?.claimedOutputIndices?.sort((a, b) => a - b)
		).to.deep.equal([0, 1, 2]);
	});

	it('does not pull an unclaimed urgent snapshot into a safe group rebuild', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.RECEIVED,
				amountSats: 1_200,
				cltvExpiry: HEIGHT + 10
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 1_000
			}
		]);
		const toLocal = {
			...s.trackedOutputs[0],
			txid: s.revokedTx.getId(),
			confirmationHeight: HEIGHT
		};
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [toLocal],
					revokedTxHex: s.revokedTx.toHex()
				},
				trackedOutputs: [toLocal],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		expect(spentIndices(opening[0])).to.deep.equal([0, 2]);
		expect(trackedAt(monitor, 1)?.sweepTxHex).to.equal(undefined);

		const actions = monitor.handleNewBlock(HEIGHT + 7);
		const rebuild = actions.find(
			(action) =>
				action.type === ChainActionType.REBUILD_SWEEP &&
				action.output.sweepTxHex === opening[0].toHex()
		);
		expect(rebuild?.type).to.equal(ChainActionType.REBUILD_SWEEP);
		if (rebuild?.type !== ChainActionType.REBUILD_SWEEP) {
			throw new Error('expected safe group rebuild');
		}
		const replacements = monitor.rebuildSweeps(
			rebuild.output,
			rebuild.feeRatePerVbyte
		);
		expect(replacements).to.have.length(1);
		expect(spentIndices(replacements[0])).to.deep.equal([0, 2]);
		expect(trackedAt(monitor, 1)?.status).to.equal(OutputStatus.CONFIRMED);
		expect(trackedAt(monitor, 1)?.sweepTxHex).to.equal(undefined);
	});

	it('splits a newly urgent member and leaves the remainder retryable', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.RECEIVED,
				amountSats: 4_000,
				cltvExpiry: HEIGHT + 20
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 500,
				cltvExpiry: HEIGHT + 1_000
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		expect(spentIndices(opening[0])).to.deep.equal([1, 2]);

		monitor.updateFeeRate(5_000);
		const actions = monitor.handleNewBlock(HEIGHT + 7);
		const rebuild = actions.find(
			(action) => action.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuild?.type).to.equal(ChainActionType.REBUILD_SWEEP);
		if (rebuild?.type !== ChainActionType.REBUILD_SWEEP) {
			throw new Error('expected urgent group rebuild');
		}
		const replacements = monitor.rebuildSweeps(
			rebuild.output,
			rebuild.feeRatePerVbyte
		);
		expect(replacements).to.have.length(1);
		expect(spentIndices(replacements[0])).to.deep.equal([1]);
		expect(trackedAt(monitor, 1)?.sweepTxHex).to.equal(replacements[0].toHex());
		expect(trackedAt(monitor, 2)?.status).to.equal(OutputStatus.CONFIRMED);
		expect(trackedAt(monitor, 2)?.sweepTxHex).to.equal(undefined);
		expect(
			monitor
				.getFullState()
				.commitmentBroadcast?.claimedOutputIndices?.sort((a, b) => a - b)
		).to.deep.equal([0, 1]);

		const retry = broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW));
		expect(retry).to.have.length(1);
		expect(spentIndices(retry[0])).to.deep.equal([2]);
	});

	it('keeps the singular rebuild API on one complete replacement', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);
		installSnapshotHtlcs(s, [
			{
				outputIndex: 1,
				direction: HtlcDirection.RECEIVED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 20
			},
			{
				outputIndex: 2,
				direction: HtlcDirection.OFFERED,
				amountSats: 50_000,
				cltvExpiry: HEIGHT + 1_000
			}
		]);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: s.revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 0n,
					trackedOutputs: [],
					revokedTxHex: s.revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const opening = broadcastTxs(monitor.handleNewBlock(HEIGHT + 1));
		expect(opening).to.have.length(1);
		expect(spentIndices(opening[0])).to.deep.equal([1, 2]);

		const actions = monitor.handleNewBlock(HEIGHT + 7);
		const rebuild = actions.find(
			(action) => action.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuild?.type).to.equal(ChainActionType.REBUILD_SWEEP);
		if (rebuild?.type !== ChainActionType.REBUILD_SWEEP) {
			throw new Error('expected singular compatibility rebuild');
		}
		const replacement = monitor.rebuildSweep(
			rebuild.output,
			rebuild.feeRatePerVbyte
		);
		expect(replacement).to.not.equal(null);
		expect(spentIndices(replacement!)).to.deep.equal([1, 2]);
		for (const outputIndex of [1, 2]) {
			expect(trackedAt(monitor, outputIndex)?.sweepTxHex).to.equal(
				replacement!.toHex()
			);
		}
	});

	it('retries a skipped taproot penalty', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();
		const revokedTx = emptyRevokedTx();
		revokedTx.addOutput(Buffer.from([0x51]), 50_000);
		revokedTx.addOutput(Buffer.from([0x51]), 20_000);
		const txid = revokedTx.getId();
		const tracked = trackedFor(50_000n, 20_000n, HEIGHT + 500).map((o) => ({
			...o,
			txid,
			confirmationHeight: HEIGHT
		}));

		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid,
					blockHeight: HEIGHT,
					commitmentNumber: 1n,
					trackedOutputs: tracked,
					revokedTxHex: revokedTx.toHex()
				},
				trackedOutputs: tracked,
				currentBlockHeight: HEIGHT
			},
			state,
			destScript,
			500, // a spike no taproot penalty over 70k sats can pay for
			privAt(aliceSeed, 1),
			privAt(aliceSeed, 2),
			NETWORK
		);

		expect(
			broadcastTxs(monitor.handleNewBlock(HEIGHT + 1)),
			'unaffordable at the spike rate'
		).to.have.length(0);

		const txs = broadcastTxs(monitor.updateFeeRate(5 * 250));
		expect(txs, 'and built once the spike passes').to.have.length(1);
		expect(spentIndices(txs[0]), 'claiming both penalty inputs').to.deep.equal([
			0, 1
		]);
		expect(txs[0].ins.some((input) => input.sequence < 0xfffffffe)).to.equal(
			true
		);

		const actions = monitor.handleNewBlock(HEIGHT + 7);
		const rebuild = actions.find(
			(action) => action.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuild?.type).to.equal(ChainActionType.REBUILD_SWEEP);
		if (rebuild?.type !== ChainActionType.REBUILD_SWEEP) {
			throw new Error('expected taproot penalty rebuild');
		}
		const replacements = monitor.rebuildSweeps(
			rebuild.output,
			rebuild.feeRatePerVbyte
		);
		expect(replacements).to.have.length(1);
		expect(replacements[0].toHex()).to.not.equal(txs[0].toHex());
		expect(
			replacements[0].ins.some((input) => input.sequence < 0xfffffffe)
		).to.equal(true);
	});

	it('adopts an untracked claimed taproot snapshot during restore', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();
		const secret = state.shaChainStore.getSecret(MAX_INDEX - 1n)!;
		const point = perCommitmentPointFromSecret(secret);
		const paymentHash = crypto.randomBytes(32);
		const cltvExpiry = HEIGHT + 1_000;
		const amountSats = 50_000;
		state.revokedHtlcSnapshots = new Map([
			[
				'1',
				[
					{
						paymentHash,
						amountMsat: BigInt(amountSats) * 1000n,
						cltvExpiry,
						direction: HtlcDirection.OFFERED
					}
				]
			]
		]);
		const htlcOutput = buildTaprootReceivedHtlcOutput(
			deriveRevocationPubkey(state.localBasepoints.revocationBasepoint, point),
			derivePublicKey(state.remoteBasepoints!.htlcBasepoint, point),
			derivePublicKey(state.localBasepoints.htlcBasepoint, point),
			paymentHash,
			cltvExpiry,
			NETWORK
		).output;
		const revokedTx = emptyRevokedTx();
		revokedTx.addOutput(htlcOutput, amountSats);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.FULLY_RESOLVED,
				commitmentBroadcast: {
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
					txid: revokedTx.getId(),
					blockHeight: HEIGHT,
					commitmentNumber: 1n,
					trackedOutputs: [],
					revokedTxHex: revokedTx.toHex(),
					claimedOutputIndices: [0]
				},
				trackedOutputs: [],
				currentBlockHeight: HEIGHT
			},
			state,
			destScript,
			1,
			privAt(aliceSeed, 1),
			privAt(aliceSeed, 2),
			NETWORK
		);

		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
		const adopted = trackedAt(monitor, 0)!;
		expect(adopted.outputType).to.equal(OutputType.OFFERED_HTLC);
		expect(adopted.paymentHash?.equals(paymentHash)).to.equal(true);
		expect(
			monitor.getFullState().commitmentBroadcast?.claimedOutputIndices
		).to.deep.equal([]);
		const actions = monitor.handleNewBlock(HEIGHT + 1);
		expect(broadcastTxs(actions)).to.have.length(1);
		expect(trackedAt(monitor, 0)?.status).to.equal(
			OutputStatus.SPEND_BROADCAST
		);
	});

	it('matches duplicate taproot offered outputs in BOLT CLTV order', function () {
		const { state } = revokedTaprootSetup();
		const secret = state.shaChainStore.getSecret(MAX_INDEX - 1n)!;
		const point = perCommitmentPointFromSecret(secret);
		const paymentHash = crypto.randomBytes(32);
		const amountSats = 50_000;
		const lowCltv = HEIGHT + 10;
		const highCltv = HEIGHT + 100;
		state.revokedHtlcSnapshots = new Map([
			[
				'1',
				[
					{
						paymentHash,
						amountMsat: BigInt(amountSats) * 1000n,
						cltvExpiry: highCltv,
						direction: HtlcDirection.RECEIVED
					},
					{
						paymentHash,
						amountMsat: BigInt(amountSats) * 1000n,
						cltvExpiry: lowCltv,
						direction: HtlcDirection.RECEIVED
					}
				]
			]
		]);
		const output = buildTaprootOfferedHtlcOutput(
			deriveRevocationPubkey(state.localBasepoints.revocationBasepoint, point),
			derivePublicKey(state.remoteBasepoints!.htlcBasepoint, point),
			derivePublicKey(state.localBasepoints.htlcBasepoint, point),
			paymentHash,
			NETWORK
		).output;
		const revokedTx = emptyRevokedTx();
		revokedTx.addOutput(output, amountSats);
		revokedTx.addOutput(output, amountSats);

		const matched = matchRevokedHtlcSnapshotOutputs(
			state,
			1n,
			revokedTx,
			NETWORK
		);
		expect(matched.get(0)?.cltvExpiry).to.equal(lowCltv);
		expect(matched.get(1)?.cltvExpiry).to.equal(highCltv);
	});
});

describe('Uneconomic to_remote no longer aborts the resolution', function () {
	it('keeps the breach remedy when our to_remote cannot pay its own fee', function () {
		const s = setupRevokedWithHtlcs(HEIGHT, { toRemoteSats: STARVED_SATS });

		let resolved: ReturnType<typeof resolveRevokedCommitmentOutputs> = [];
		expect(() => {
			resolved = resolveRevokedCommitmentOutputs(
				s.state,
				s.trackedOutputs,
				0n,
				s.revokedTx,
				s.destScript,
				SPIKE_SAT_PER_VBYTE,
				s.openerPrivkeys[1],
				s.openerPrivkeys[2],
				network,
				HEIGHT
			);
		}, 'an unaffordable to_remote must not throw out of the resolver').to.not.throw();

		const byIndex = new Map(
			resolved.map((r) => [r.trackedOutput.outputIndex, r])
		);
		expect(byIndex.get(0)?.spendTx, 'their to_local is still penalized').to
			.exist;
		expect(
			byIndex.get(s.toRemoteIndex!)?.spendTx,
			'and the starved to_remote is tracked without a spend'
		).to.equal(undefined);
	});

	it('claims that same to_remote at an affordable feerate', function () {
		const s = setupRevokedWithHtlcs(HEIGHT, { toRemoteSats: STARVED_SATS });

		const resolved = resolveRevokedCommitmentOutputs(
			s.state,
			s.trackedOutputs,
			0n,
			s.revokedTx,
			s.destScript,
			1,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network,
			HEIGHT
		);

		const claim = resolved.find(
			(r) => r.trackedOutput.outputIndex === s.toRemoteIndex
		);
		expect(claim?.spendTx, 'the guard does not decline an affordable claim').to
			.exist;
	});

	it('retries the skipped to_remote on a current peer commitment', function () {
		// The guard above leaves the balance tracked without a spend. The penalty
		// retry only covers revoked commitments, so without a path of its own this
		// output would trade a throw for a balance nobody comes back for.
		for (const commitmentType of [
			CommitmentType.THEIR_CURRENT_COMMITMENT,
			CommitmentType.THEIR_FUTURE_COMMITMENT
		]) {
			const s = setupRevokedWithHtlcs(HEIGHT);
			const txid = crypto.randomBytes(32).toString('hex');
			const toRemote: ITrackedOutput = {
				txid,
				outputIndex: 0,
				amount: BigInt(STARVED_SATS),
				outputType: OutputType.TO_REMOTE,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: HEIGHT
			};

			const monitor = ChainMonitor.restore(
				{
					monitorState: MonitorState.RESOLVING,
					commitmentBroadcast: {
						commitmentType,
						txid,
						blockHeight: HEIGHT,
						commitmentNumber: 0n,
						trackedOutputs: [toRemote]
					},
					trackedOutputs: [toRemote],
					currentBlockHeight: HEIGHT
				},
				s.state,
				s.destScript,
				SPIKE_SAT_PER_VBYTE,
				s.openerPrivkeys[1],
				s.openerPrivkeys[2],
				network
			);

			expect(
				broadcastTxs(monitor.handleNewBlock(HEIGHT + 1)),
				`${commitmentType}: unaffordable at the spike rate`
			).to.have.length(0);

			const txs = broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW));
			expect(
				txs,
				`${commitmentType}: claimed once the spike passes`
			).to.have.length(1);
			expect(spentIndices(txs[0])).to.deep.equal([0]);
			expect(txs[0].ins[0].witness.length, 'signed').to.be.greaterThan(0);
			expect(trackedAt(monitor, 0)!.status).to.equal(
				OutputStatus.SPEND_BROADCAST
			);
		}
	});

	it('reports the declined to_remote on a future peer commitment', function () {
		// The peer advanced past us (data loss on our side), so our to_remote is the
		// only thing we can claim from their commitment. Reporting the decline only
		// from a later retry loses it whenever the next fee sample recovers it.
		const s = setupRevokedWithHtlcs(HEIGHT);
		const isOpener = s.state.role === ChannelRole.OPENER;
		const openPBP = isOpener
			? s.state.localBasepoints.paymentBasepoint
			: s.state.remoteBasepoints!.paymentBasepoint;
		const acceptPBP = isOpener
			? s.state.remoteBasepoints!.paymentBasepoint
			: s.state.localBasepoints.paymentBasepoint;
		const obscured = calculateObscuredCommitmentNumber(
			openPBP,
			acceptPBP,
			s.state.remoteCommitmentNumber + 50n
		);

		const futureTx = new bitcoin.Transaction();
		futureTx.version = 2;
		futureTx.locktime = 0x20000000 | Number(obscured & 0xffffffn);
		futureTx.addInput(
			Buffer.from(s.state.fundingTxid!.toString('hex'), 'hex').reverse(),
			s.state.fundingOutputIndex,
			(0x80000000 | Number((obscured >> 24n) & 0xffffffn)) >>> 0
		);
		futureTx.addOutput(
			bitcoin.payments.p2wpkh({
				pubkey: s.state.localBasepoints.paymentBasepoint
			}).output!,
			STARVED_SATS
		);

		const monitor = monitorFor(s, SPIKE_SAT_PER_VBYTE);
		const actions = monitor.handleFundingSpent(futureTx, HEIGHT);

		expect(
			broadcastTxs(actions),
			'unaffordable at the spike rate, so nothing is built'
		).to.have.length(0);
		expect(
			uneconomicActions(actions).map((d) => d.reason),
			'and the decline is reported where it happens'
		).to.deep.equal(['skipped']);

		expect(
			broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW)),
			'the next fee sample still recovers it'
		).to.have.length(1);
	});

	it('keeps their-current-commitment claims when to_remote is unaffordable', function () {
		const s = setupRevokedWithHtlcs(HEIGHT, { toRemoteSats: STARVED_SATS });
		const toRemote: ITrackedOutput = {
			txid: s.revokedTx.getId(),
			outputIndex: s.toRemoteIndex!,
			amount: BigInt(STARVED_SATS),
			outputType: OutputType.TO_REMOTE,
			status: OutputStatus.CONFIRMED,
			confirmationHeight: HEIGHT
		};

		let resolved: ReturnType<typeof resolveTheirCurrentCommitmentOutputs> = [];
		expect(() => {
			resolved = resolveTheirCurrentCommitmentOutputs(
				s.state,
				[toRemote],
				s.destScript,
				SPIKE_SAT_PER_VBYTE,
				new Map(),
				s.openerPrivkeys[2]
			);
		}, 'the same unguarded builder throws on their current commitment too').to.not.throw();

		expect(resolved, 'the output is still tracked').to.have.length(1);
		expect(resolved[0].spendTx, 'without a spend').to.equal(undefined);
	});
});
