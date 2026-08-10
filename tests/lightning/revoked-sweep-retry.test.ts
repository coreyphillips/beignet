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

function installSnapshotHtlc(
	s: IRevokedSetup,
	direction: HtlcDirection,
	amountSats = STARVED_SATS
): Buffer {
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
	const paymentHash = crypto.randomBytes(32);
	s.state.revokedHtlcSnapshots = new Map([
		[
			'0',
			[
				{
					paymentHash,
					amountMsat: BigInt(amountSats) * 1000n,
					cltvExpiry: s.nearCltv,
					direction
				}
			]
		]
	]);
	const script =
		direction === HtlcDirection.OFFERED
			? buildReceivedHtlcScript(
					revocationPubkey,
					theirHtlc,
					ourHtlc,
					paymentHash,
					s.nearCltv,
					false
			  )
			: buildOfferedHtlcScript(
					revocationPubkey,
					theirHtlc,
					ourHtlc,
					paymentHash,
					false
			  );
	s.revokedTx.outs[1].script = bitcoin.payments.p2wsh({
		redeem: { output: script }
	}).output!;
	s.revokedTx.outs[1].value = amountSats;
	return paymentHash;
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
		installSnapshotHtlc(s, HtlcDirection.OFFERED);

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

	it('reopens a fully resolved monitor when a fee retry adopts a claim', function () {
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

		const actions = monitor.updateFeeRate(CALM_SAT_PER_KW);
		expect(broadcastTxs(actions)).to.have.length(1);
		expect(trackedAt(monitor, 1)?.status).to.equal(
			OutputStatus.SPEND_BROADCAST
		);
		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
	});

	it('retries a skipped taproot penalty', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();
		const revokedTx = emptyRevokedTx();
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
