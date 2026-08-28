/**
 * A recorded spend height only counts toward finality once this session has
 * verified it against the chain (issues #576 and #577).
 *
 * A commitment close resolves through individual sweeps whose spends carry
 * their own heights, and those heights were trusted verbatim across a
 * restart. The session's first header reaches the monitors BEFORE
 * restoreChainWatches can re-arm the per-output watches, so a restored breach
 * monitor promoted a penalty sweep to irrevocably resolved off a height
 * nothing could contradict. A penalty reorged out while the node was offline
 * then counted as resolved, the channel as fully swept, and nothing ever
 * rebroadcast it: the breach went unpunished (#576).
 *
 * The same clock ran on during a commitment-evicting reorg, and the watch
 * that would have corrected it could be permanently un-armed, because the
 * commitment fetch that arms it fails for exactly as long as the eviction
 * lasts and its failure was swallowed with no retry (#577).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	CommitmentType,
	MonitorState,
	OutputStatus,
	OutputType,
	ChainActionType,
	ITrackedOutput,
	IRREVOCABLE_DEPTH
} from '../../src/lightning/chain/types';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const network = bitcoin.networks.regtest;

// ─── Helpers ───

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeP2wpkhScript(pubkey: Buffer): Buffer {
	return bitcoin.payments.p2wpkh({ pubkey, network }).output!;
}

const COMMITMENT_TXID = 'bb'.repeat(32);
const COMMITMENT_HEIGHT = 95;
const SPEND_HEIGHT = 100;

interface IFixture {
	monitor: ChainMonitor;
	channelState: IChannelState;
	destScript: Buffer;
	privkeys: Buffer[];
	penalty: bitcoin.Transaction;
}

/**
 * A revoked-commitment monitor whose penalty sweep is SPEND_CONFIRMED at a
 * recorded height: the shape a restart inherits.
 */
function monitorWithConfirmedPenalty(seedId = 1): IFixture {
	const seed = crypto
		.createHash('sha256')
		.update(Buffer.from(`reverify-${seedId}`))
		.digest();
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		privkeys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([100 + i]))
				.digest()
		);
	}
	const channelState = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: seed
	});
	channelState.channelId = crypto.randomBytes(32);
	channelState.state = ChannelState.FORCE_CLOSED;
	channelState.fundingTxid = crypto.randomBytes(32);
	// A real Channel is not needed; the monitor reads state only.
	void Channel;

	const destScript = makeP2wpkhScript(getPublicKey(privkeys[0]));
	const monitor = new ChainMonitor(
		channelState,
		destScript,
		5,
		privkeys[1],
		privkeys[2],
		network,
		privkeys[3],
		privkeys[4]
	);
	const penalty = new bitcoin.Transaction();
	penalty.version = 2;
	penalty.addInput(
		Buffer.from(COMMITMENT_TXID, 'hex').reverse(),
		0,
		0xfffffffd
	);
	penalty.addOutput(destScript, 90_000);

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const m = monitor as any;
	m._state = MonitorState.RESOLVING;
	m._commitmentBroadcast = {
		commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
		txid: COMMITMENT_TXID,
		blockHeight: COMMITMENT_HEIGHT,
		commitmentNumber: 0n
	};
	m._currentBlockHeight = SPEND_HEIGHT + 5;
	const tracked: ITrackedOutput = {
		txid: COMMITMENT_TXID,
		outputIndex: 0,
		amount: 100_000n,
		outputType: OutputType.TO_LOCAL,
		status: OutputStatus.SPEND_CONFIRMED,
		resolutionTxid: penalty.getId(),
		confirmationHeight: SPEND_HEIGHT,
		sweepTxHex: penalty.toHex()
	};
	m._trackedOutputs = [tracked];
	m._commitmentBroadcast.trackedOutputs = m._trackedOutputs;

	return { monitor, channelState, destScript, privkeys, penalty };
}

function restoreFrom(f: IFixture): ChainMonitor {
	return ChainMonitor.restore(
		f.monitor.getFullState(),
		f.channelState,
		f.destScript,
		5,
		f.privkeys[1],
		f.privkeys[2],
		network,
		f.privkeys[3],
		f.privkeys[4]
	);
}

const trackedOutput = (m: ChainMonitor): ITrackedOutput =>
	m.getTrackedOutputs()[0];

const resolvedActions = (m: ChainMonitor, height: number): unknown[] =>
	m
		.handleNewBlock(height)
		.filter((a) => a.type === ChainActionType.OUTPUT_RESOLVED);

// ─── Tests ───

describe('Spend finality waits for live re-verification (issues #576/#577)', function () {
	this.timeout(10_000);

	it('a live monitor still resolves at depth: the rule costs nothing in-session', function () {
		const f = monitorWithConfirmedPenalty(1);
		// No restart: the spend was observed by THIS session, so its height is
		// already verified and the clock runs untouched.
		expect(trackedOutput(f.monitor).spendReverifyPending).to.equal(undefined);
		expect(
			resolvedActions(f.monitor, SPEND_HEIGHT + IRREVOCABLE_DEPTH),
			'resolves at depth as before'
		).to.have.length(1);
		expect(trackedOutput(f.monitor).status).to.equal(
			OutputStatus.IRREVOCABLY_RESOLVED
		);
	});

	it('a restored monitor does not resolve off the stale height (#576)', function () {
		const f = monitorWithConfirmedPenalty(2);
		const restored = restoreFrom(f);

		expect(
			trackedOutput(restored).spendReverifyPending,
			'restore parks the clock'
		).to.equal(true);
		// The height is KEPT: it seeds the re-armed watch and a re-report of
		// the same height must lose no progress.
		expect(trackedOutput(restored).confirmationHeight).to.equal(SPEND_HEIGHT);

		// The session's first header, well past depth, must NOT promote: no
		// watch has re-armed yet, so nothing could have contradicted it.
		expect(
			resolvedActions(restored, SPEND_HEIGHT + IRREVOCABLE_DEPTH),
			'no resolution off unverified evidence'
		).to.have.length(0);
		expect(trackedOutput(restored).status).to.equal(
			OutputStatus.SPEND_CONFIRMED
		);
		expect(restored.getState()).to.equal(MonitorState.RESOLVING);
	});

	it('a live report of the same spend releases the parked clock', function () {
		// The re-armed watch reports the spend it finds. Whether the height is
		// unchanged or moved, that report is the positive evidence the clock
		// was waiting for, and depth counts from it.
		const f = monitorWithConfirmedPenalty(3);
		const restored = restoreFrom(f);
		restored.handleOutputSpent(COMMITMENT_TXID, 0, f.penalty, SPEND_HEIGHT);

		expect(trackedOutput(restored).spendReverifyPending).to.equal(undefined);
		expect(trackedOutput(restored).confirmationHeight).to.equal(SPEND_HEIGHT);
		expect(
			resolvedActions(restored, SPEND_HEIGHT + IRREVOCABLE_DEPTH - 1),
			'still short of depth'
		).to.have.length(0);
		expect(
			resolvedActions(restored, SPEND_HEIGHT + IRREVOCABLE_DEPTH)
		).to.have.length(1);
	});

	it('a re-mined spend recounts depth from where it actually sits', function () {
		const f = monitorWithConfirmedPenalty(4);
		const restored = restoreFrom(f);
		// Reorged and re-mined 40 blocks later.
		const reminedAt = SPEND_HEIGHT + 40;
		restored.handleOutputSpent(COMMITMENT_TXID, 0, f.penalty, reminedAt);

		expect(trackedOutput(restored).confirmationHeight).to.equal(reminedAt);
		expect(
			resolvedActions(restored, SPEND_HEIGHT + IRREVOCABLE_DEPTH),
			'the old height no longer buys depth'
		).to.have.length(0);
		expect(
			resolvedActions(restored, reminedAt + IRREVOCABLE_DEPTH)
		).to.have.length(1);
	});

	it('an eviction after restore still rebroadcasts the penalty', function () {
		// The parked clock must not disturb the reorg path that repairs it.
		const f = monitorWithConfirmedPenalty(5);
		const restored = restoreFrom(f);
		const actions = restored.handleSpendUnconfirmed(COMMITMENT_TXID, 0);

		expect(
			actions.some((a) => a.type === ChainActionType.BROADCAST_TX),
			'penalty rebroadcast'
		).to.equal(true);
		expect(trackedOutput(restored).resolutionTxid).to.equal(undefined);
	});

	it('demoting the commitment parks its sweeps too (#577)', function () {
		// When the funding watch proves the commitment absent, the sweeps that
		// spend its outputs cannot be confirmed either.
		const f = monitorWithConfirmedPenalty(6);
		expect(trackedOutput(f.monitor).spendReverifyPending).to.equal(undefined);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.monitor as any)._rebindCommitmentConfirmation(0);

		expect(trackedOutput(f.monitor).spendReverifyPending).to.equal(true);
		expect(
			resolvedActions(f.monitor, SPEND_HEIGHT + IRREVOCABLE_DEPTH),
			'no finality while the commitment itself is unconfirmed'
		).to.have.length(0);
	});

	it('a re-confirmation of the commitment does not itself release the clock', function () {
		// Only per-output evidence releases a per-output clock: the commitment
		// re-confirming says nothing about whether our sweep is still mined.
		const f = monitorWithConfirmedPenalty(7);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const m = f.monitor as any;
		m._rebindCommitmentConfirmation(0);
		m._rebindCommitmentConfirmation(COMMITMENT_HEIGHT + 10);

		expect(trackedOutput(f.monitor).spendReverifyPending).to.equal(true);
		expect(
			resolvedActions(f.monitor, SPEND_HEIGHT + IRREVOCABLE_DEPTH)
		).to.have.length(0);
	});
});
