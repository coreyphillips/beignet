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
 * The retry runs on every new block and on every fresh fee estimate, over the
 * outputs of a revoked commitment that still have no spend, while the outpoint
 * is unspent and the deadline that bounds the claim is still ahead.
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
import { HtlcDirection } from '../../src/lightning/channel/types';
import { MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	perCommitmentPointFromSecret,
	deriveRevocationPubkey,
	derivePublicKey
} from '../../src/lightning/keys/derivation';
import { buildReceivedHtlcScript } from '../../src/lightning/script/htlc';
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
): Array<{ reason: string; outputIndex: number; deadlineHeight?: number }> {
	const found: Array<{
		reason: string;
		outputIndex: number;
		deadlineHeight?: number;
	}> = [];
	for (const action of actions) {
		if (action.type === ChainActionType.SWEEP_UNECONOMIC) {
			found.push({
				reason: action.reason,
				outputIndex: action.outputIndex,
				deadlineHeight: action.deadlineHeight
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

		const first = uneconomicActions(monitor.handleNewBlock(HEIGHT + 1));
		expect(first, 'the skip is surfaced').to.have.length(1);
		expect(first[0].reason).to.equal('skipped');
		expect(first[0].outputIndex).to.equal(0);
		expect(
			first[0].deadlineHeight,
			'bounded by the to_self_delay we demanded of them'
		).to.equal(HEIGHT + TO_SELF_DELAY);

		expect(
			uneconomicActions(monitor.handleNewBlock(HEIGHT + 2)),
			'a still-unaffordable retry does not report again'
		).to.have.length(0);
	});

	it('gives up once the deadline that bounds the claim has passed', function () {
		const { monitor } = breachWithStarvedToLocal();

		const past = monitor.handleNewBlock(HEIGHT + TO_SELF_DELAY + 1);
		const reported = uneconomicActions(past);
		expect(reported, 'the abandonment is surfaced').to.have.length(1);
		expect(reported[0].reason).to.equal('abandoned');
		expect(broadcastTxs(past), 'and nothing is broadcast').to.have.length(0);

		expect(
			broadcastTxs(monitor.updateFeeRate(CALM_SAT_PER_KW)),
			'a later fee drop does not revive an abandoned claim'
		).to.have.length(0);
		expect(
			uneconomicActions(monitor.handleNewBlock(HEIGHT + TO_SELF_DELAY + 2)),
			'and the abandonment is reported only once'
		).to.have.length(0);
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
