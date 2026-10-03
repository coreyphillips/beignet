/**
 * Balance visibility — pending-close vs errored channel funds.
 *
 * - pendingCloseBalanceSats counts only channels still resolving a close
 *   (FORCE_CLOSED / SHUTTING_DOWN / NEGOTIATING_CLOSING) — never CLOSED.
 * - erroredBalanceSats surfaces local balance stuck in ERRORED channels,
 *   which is counted in no other figure.
 * - recoverFallbackFunds is exposed on BeignetNode.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { BeignetNode } from '../../src/cli/beignet-node';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	CommitmentType,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';

type FakeTrackedOutput = {
	txid: string;
	outputType: OutputType;
	status: OutputStatus;
	isSecondLevelHtlc?: boolean;
	resolutionTxid?: string;
	sweepTxHex?: string;
};

/** What getPendingCloseBalanceSats reads from a channel's chain monitor. */
type FakeMonitor = {
	commitmentType: CommitmentType;
	commitmentTxid: string;
	outputs: FakeTrackedOutput[];
};

type FakeChannel = {
	channelId?: Buffer;
	state: ChannelState;
	localBalanceMsat: bigint;
	pendingSpliceLocalBalanceMsat?: bigint;
	htlcUsable?: boolean;
	payThroughSplice?: boolean;
	monitor?: FakeMonitor;
};

type FakeWalletTx = { txid: string; exists?: boolean };

function fakeNode(
	channels: FakeChannel[],
	walletTxs: FakeWalletTx[] = []
): {
	node: {
		listChannels: () => FakeChannel[];
		getChannelManager: () => { getMonitor: (id?: Buffer) => unknown };
	};
	wallet: { transactions: Record<string, FakeWalletTx> };
} {
	const monitors = new Map<string, FakeMonitor>();
	for (const ch of channels) {
		if (ch.channelId && ch.monitor) {
			monitors.set(ch.channelId.toString('hex'), ch.monitor);
		}
	}
	const transactions: Record<string, FakeWalletTx> = {};
	for (const tx of walletTxs) transactions[tx.txid] = tx;
	// Built on the prototype so the private helpers a bucket calls through
	// `this` (isForceCloseBalanceInWallet) resolve.
	return Object.assign(Object.create(BeignetNode.prototype), {
		node: {
			listChannels: () => channels,
			getChannelManager: () => ({
				// A fake channel row without a channelId (the older cases) has
				// no monitor, like a FORCE_CLOSED channel nothing has classified.
				getMonitor: (id?: Buffer) => {
					const monitor = id && monitors.get(id.toString('hex'));
					if (!monitor) return undefined;
					return {
						getFullState: () => ({
							commitmentBroadcast: {
								commitmentType: monitor.commitmentType,
								txid: monitor.commitmentTxid
							}
						}),
						getTrackedOutputs: () => monitor.outputs
					};
				}
			})
		},
		wallet: { transactions }
	});
}

function pendingCloseSats(
	channels: FakeChannel[],
	walletTxs: FakeWalletTx[] = []
): number {
	return (BeignetNode.prototype as any).getPendingCloseBalanceSats.call(
		fakeNode(channels, walletTxs)
	);
}

function erroredSats(channels: FakeChannel[]): number {
	return (BeignetNode.prototype as any).getErroredBalanceSats.call(
		fakeNode(channels)
	);
}

function splicingSats(channels: FakeChannel[]): number {
	return (BeignetNode.prototype as any).getSplicingBalanceSats.call(
		fakeNode(channels)
	);
}

describe('LightningNode.getBalance mid-splice accounting', () => {
	type FakeNodeChannel = {
		state: ChannelState;
		preReestablishState?: ChannelState | null;
		localBalanceMsat: bigint;
		remoteBalanceMsat: bigint;
		pending?: bigint | null;
		usableThrough?: boolean;
	};
	function balanceOf(channels: FakeNodeChannel[]): bigint {
		const fakes = channels.map((c) => ({
			getFullState: () => ({
				state: c.state,
				preReestablishState: c.preReestablishState ?? null,
				localBalanceMsat: c.localBalanceMsat,
				remoteBalanceMsat: c.remoteBalanceMsat,
				htlcs: new Map()
			}),
			isHtlcUsable: (lookThrough?: boolean) =>
				c.state === ChannelState.NORMAL ||
				(!!lookThrough && c.usableThrough === true),
			getPendingSpliceLocalBalanceMsat: () => c.pending ?? null
		}));
		const result = (LightningNode.prototype as any).getBalance.call({
			channelManager: { listChannels: () => fakes }
		});
		return result.localBalanceMsat;
	}

	it('counts a pay-through splice-out at its settle-to side, connected or not', () => {
		const connected: FakeNodeChannel = {
			state: ChannelState.SPLICING,
			localBalanceMsat: 120_000_000n,
			remoteBalanceMsat: 0n,
			pending: 20_000_000n,
			usableThrough: true
		};
		expect(balanceOf([connected])).to.equal(20_000_000n);
		// The review's blocker: a disconnect must NOT bounce the balance back
		// to the full pre-splice 120k while 100k is also on its way on-chain.
		const disconnected: FakeNodeChannel = {
			...connected,
			state: ChannelState.AWAITING_REESTABLISH,
			preReestablishState: ChannelState.SPLICING
		};
		expect(balanceOf([disconnected])).to.equal(20_000_000n);
	});

	it('counts a pay-through splice-in at its live side, connected or not', () => {
		const connected: FakeNodeChannel = {
			state: ChannelState.SPLICING,
			localBalanceMsat: 132_295_000n,
			remoteBalanceMsat: 5_000_000n,
			pending: 211_746_000n,
			usableThrough: true
		};
		expect(balanceOf([connected])).to.equal(132_295_000n);
		expect(
			balanceOf([
				{
					...connected,
					state: ChannelState.AWAITING_REESTABLISH,
					preReestablishState: ChannelState.SPLICING
				}
			])
		).to.equal(132_295_000n);
	});

	it('excludes parked splices and ordinary non-live channels', () => {
		expect(
			balanceOf([
				{
					state: ChannelState.SPLICING,
					localBalanceMsat: 50_000_000n,
					remoteBalanceMsat: 0n,
					pending: 60_000_000n,
					usableThrough: false
				},
				{
					state: ChannelState.FORCE_CLOSED,
					localBalanceMsat: 9_000_000n,
					remoteBalanceMsat: 0n
				},
				{
					state: ChannelState.NORMAL,
					localBalanceMsat: 40_000_000n,
					remoteBalanceMsat: 0n
				}
			])
		).to.equal(40_000_000n);
	});
});

describe('Channel listing wire fields (GET /channels JSON)', () => {
	// Regression: htlcUsable/payThroughSplice existed on the node-layer channel
	// info but the CLI serializer dropped them, so the dashboard re-parked
	// every mid-splice channel while the daemon happily paid through the
	// window (observed live on umbrel 0.8.1 / beignet 0.6.1).
	it('toChannelInfo passes htlcUsable and payThroughSplice through', () => {
		const info = (BeignetNode.prototype as any).toChannelInfo.call(
			{
				node: {
					getFforEpoch: () => undefined,
					getChannelManager: () => ({ getPeerForChannel: () => 'peerpk' }),
					peerSupportsSplicing: () => null
				}
			},
			{
				channelId: Buffer.alloc(32, 1),
				peerPubkey: 'peerpk',
				state: 'SPLICING',
				localBalanceMsat: 132_295_000n,
				remoteBalanceMsat: 5_000_000n,
				fundingSatoshis: 137_295n,
				channelType: null,
				htlcUsable: true,
				payThroughSplice: true,
				pendingSpliceLocalBalanceMsat: 211_746_000n
			}
		);
		expect(info.htlcUsable).to.equal(true);
		expect(info.payThroughSplice).to.equal(true);
		expect(info.pendingSpliceLocalBalanceSats).to.equal(211_746);
	});

	it('omits the flags when the node layer does not provide them', () => {
		const info = (BeignetNode.prototype as any).toChannelInfo.call(
			{
				node: {
					getFforEpoch: () => undefined,
					getChannelManager: () => ({ getPeerForChannel: () => 'peerpk' }),
					peerSupportsSplicing: () => null
				}
			},
			{
				channelId: Buffer.alloc(32, 2),
				peerPubkey: 'peerpk',
				state: 'NORMAL',
				localBalanceMsat: 1_000_000n,
				remoteBalanceMsat: 0n,
				fundingSatoshis: 1_000n,
				channelType: null
			}
		);
		expect(info.htlcUsable).to.equal(undefined);
		expect(info.payThroughSplice).to.equal(undefined);
	});

	// Issue #1060: a wallet matches its own deposits against the channel's
	// fundings, so the in-flight splice txid has to ride with the pending
	// balance (same presence rule) and the retired fundings have to survive
	// the adoption that moves fundingTxid on.
	it('toChannelInfo passes pendingSpliceTxid through, present exactly with the pending balance', () => {
		const call = (ch: Record<string, unknown>): Record<string, unknown> =>
			(BeignetNode.prototype as any).toChannelInfo.call(
				{
					node: {
						getFforEpoch: () => undefined,
						getChannelManager: () => ({ getPeerForChannel: () => 'peerpk' }),
						peerSupportsSplicing: () => null
					}
				},
				ch
			);
		const base = {
			channelId: Buffer.alloc(32, 4),
			peerPubkey: 'peerpk',
			state: 'NORMAL',
			localBalanceMsat: 132_295_000n,
			remoteBalanceMsat: 5_000_000n,
			fundingSatoshis: 137_295n,
			channelType: null
		};
		const spliceTxid = 'ab'.repeat(32);
		const mid = call({
			...base,
			state: 'SPLICING',
			pendingSpliceLocalBalanceMsat: 211_746_000n,
			pendingSpliceTxid: spliceTxid
		});
		expect(mid.pendingSpliceLocalBalanceSats).to.equal(211_746);
		expect(mid.pendingSpliceTxid).to.equal(spliceTxid);
		const idle = call(base);
		expect(idle.pendingSpliceLocalBalanceSats).to.equal(undefined);
		expect(idle).to.not.have.property('pendingSpliceTxid');
	});

	it('toChannelInfo passes previousFundingTxids through in display order, oldest first', () => {
		const call = (ch: Record<string, unknown>): Record<string, unknown> =>
			(BeignetNode.prototype as any).toChannelInfo.call(
				{
					node: {
						getFforEpoch: () => undefined,
						getChannelManager: () => ({ getPeerForChannel: () => 'peerpk' }),
						peerSupportsSplicing: () => null
					}
				},
				ch
			);
		const base = {
			channelId: Buffer.alloc(32, 5),
			peerPubkey: 'peerpk',
			state: 'NORMAL',
			localBalanceMsat: 1_000_000n,
			remoteBalanceMsat: 0n,
			fundingSatoshis: 1_000n,
			channelType: null,
			fundingTxid: 'cc'.repeat(32)
		};
		// The node layer already reversed these; the serializer must pass
		// them through untouched and in order.
		const previous = ['aa'.repeat(32), 'bb'.repeat(32)];
		const spliced = call({ ...base, previousFundingTxids: previous });
		expect(spliced.previousFundingTxids).to.deep.equal(previous);
		expect(spliced.fundingTxid).to.equal('cc'.repeat(32));
		const never = call(base);
		expect(never).to.not.have.property('previousFundingTxids');
		const empty = call({ ...base, previousFundingTxids: [] });
		expect(empty).to.not.have.property('previousFundingTxids');
	});

	// The dashboard hides its splice buttons on `false` alone, so the
	// distinction between false and absent is load-bearing: absent means the
	// peer is disconnected and support is unknowable, and hiding on unknown
	// would strip the buttons from every channel whose peer blinked.
	it('toChannelInfo carries the peer splice support the node read', () => {
		const base = {
			channelId: Buffer.alloc(32, 3),
			peerPubkey: 'peerpk',
			state: 'NORMAL',
			localBalanceMsat: 1_000_000n,
			remoteBalanceMsat: 0n,
			fundingSatoshis: 1_000n,
			channelType: null
		};
		const withSupport = (answer: boolean | null) => ({
			node: {
				getFforEpoch: () => undefined,
				getChannelManager: () => ({ getPeerForChannel: () => 'peerpk' }),
				peerSupportsSplicing: () => answer
			}
		});
		const yes = (BeignetNode.prototype as any).toChannelInfo.call(
			withSupport(true),
			{ ...base }
		);
		expect(yes.peerSupportsSplicing).to.equal(true);
		const no = (BeignetNode.prototype as any).toChannelInfo.call(
			withSupport(false),
			{ ...base }
		);
		expect(no.peerSupportsSplicing).to.equal(false);
		const unknown = (BeignetNode.prototype as any).toChannelInfo.call(
			withSupport(null),
			{ ...base }
		);
		expect(unknown.peerSupportsSplicing).to.equal(undefined);
	});
});

describe('Balance visibility (pending close / errored)', () => {
	it('pendingCloseBalanceSats sums closing-state channels only', () => {
		const sats = pendingCloseSats([
			{ state: ChannelState.FORCE_CLOSED, localBalanceMsat: 20_000_000n },
			{ state: ChannelState.SHUTTING_DOWN, localBalanceMsat: 5_000_000n },
			{ state: ChannelState.NEGOTIATING_CLOSING, localBalanceMsat: 3_000_000n },
			{ state: ChannelState.NORMAL, localBalanceMsat: 100_000_000n }
		]);
		expect(sats).to.equal(28_000);
	});

	it('pendingCloseBalanceSats excludes CLOSED (resolved) channels', () => {
		const sats = pendingCloseSats([
			{ state: ChannelState.CLOSED, localBalanceMsat: 20_000_000n },
			{ state: ChannelState.FORCE_CLOSED, localBalanceMsat: 7_000_000n }
		]);
		expect(sats).to.equal(7_000);
	});

	it('pendingCloseBalanceSats excludes ERRORED channels', () => {
		const sats = pendingCloseSats([
			{ state: ChannelState.ERRORED, localBalanceMsat: 22_000_000n }
		]);
		expect(sats).to.equal(0);
	});

	it('erroredBalanceSats sums only ERRORED channels', () => {
		const sats = erroredSats([
			{ state: ChannelState.ERRORED, localBalanceMsat: 22_000_000n },
			{ state: ChannelState.ERRORED, localBalanceMsat: 1_500_000n },
			{ state: ChannelState.FORCE_CLOSED, localBalanceMsat: 9_000_000n },
			{ state: ChannelState.NORMAL, localBalanceMsat: 50_000_000n }
		]);
		expect(sats).to.equal(23_500);
	});

	it('splicingBalanceSats reports the POST-splice balance for a splice-in', () => {
		// The scare this guards against, observed on mainnet: a max splice-in
		// sweeps the on-chain balance into the splice, the canonical lightning
		// balance excludes the SPLICING channel, and the live localBalanceMsat
		// stays PRE-splice until splice_locked — so the newly spliced-in sats
		// appeared in no reported figure at all. The bucket must use the
		// pending post-splice balance (old local 132,295 + spliced ~79,451).
		const sats = splicingSats([
			{
				state: ChannelState.SPLICING,
				localBalanceMsat: 132_295_000n,
				pendingSpliceLocalBalanceMsat: 211_746_000n,
				payThroughSplice: false
			},
			{ state: ChannelState.NORMAL, localBalanceMsat: 50_000_000n },
			{ state: ChannelState.FORCE_CLOSED, localBalanceMsat: 9_000_000n }
		]);
		expect(sats).to.equal(211_746);
	});

	it('splicingBalanceSats reports the POST-splice balance for a splice-out', () => {
		// The inverse error: a splice-out's live balance is still the old
		// 120k, but only ~20k rejoins Lightning at splice_locked; the rest is
		// on its way on-chain and must not be promised back to Lightning.
		const sats = splicingSats([
			{
				state: ChannelState.SPLICING,
				localBalanceMsat: 120_000_000n,
				pendingSpliceLocalBalanceMsat: 20_000_000n,
				payThroughSplice: false
			}
		]);
		expect(sats).to.equal(20_000);
	});

	it('splicingBalanceSats falls back to the live balance pre point-of-no-return', () => {
		// A channel still negotiating its splice has no pending figure yet; the
		// wallet inputs are still visible on-chain, so the live balance is the
		// double-count-free number.
		const sats = splicingSats([
			{
				state: ChannelState.SPLICING,
				localBalanceMsat: 132_295_000n,
				payThroughSplice: false
			}
		]);
		expect(sats).to.equal(132_295);
	});

	it('splicingBalanceSats holds only the arriving delta for a channel paying through its splice-in', () => {
		// Pay-during-splice: the canonical balance counts a usable mid-splice
		// channel at min(live, settle-to), so the bucket keeps only what is
		// still in transit — here the ~79,451 sats arriving with the splice.
		const sats = splicingSats([
			{
				state: ChannelState.SPLICING,
				localBalanceMsat: 132_295_000n,
				pendingSpliceLocalBalanceMsat: 211_746_000n,
				payThroughSplice: true
			}
		]);
		expect(sats).to.equal(79_451);
	});

	it('splicingBalanceSats is 0 for a channel paying through its splice-out', () => {
		// The canonical balance already counts the settle-to side (20k); the
		// departing 100k surfaces on-chain once the splice tx is seen.
		const sats = splicingSats([
			{
				state: ChannelState.SPLICING,
				localBalanceMsat: 120_000_000n,
				pendingSpliceLocalBalanceMsat: 20_000_000n,
				payThroughSplice: true
			}
		]);
		expect(sats).to.equal(0);
	});

	it('splicingBalanceSats keeps the in-transit delta while the peer is disconnected', () => {
		// The review case: a disconnect wraps the splice in AWAITING_REESTABLISH.
		// The accounting phase looks through it — the arriving sats must not
		// vanish from the bucket (splice-in) or reappear twice (splice-out).
		expect(
			splicingSats([
				{
					state: ChannelState.AWAITING_REESTABLISH,
					localBalanceMsat: 132_295_000n,
					pendingSpliceLocalBalanceMsat: 211_746_000n,
					payThroughSplice: true
				}
			])
		).to.equal(79_451);
		expect(
			splicingSats([
				{
					state: ChannelState.AWAITING_REESTABLISH,
					localBalanceMsat: 120_000_000n,
					pendingSpliceLocalBalanceMsat: 20_000_000n,
					payThroughSplice: true
				}
			])
		).to.equal(0);
	});

	it('splicingBalanceSats is 0 with no splice in flight', () => {
		expect(
			splicingSats([
				{ state: ChannelState.NORMAL, localBalanceMsat: 50_000_000n }
			])
		).to.equal(0);
	});

	it('erroredBalanceSats is 0 with no errored channels', () => {
		expect(
			erroredSats([
				{ state: ChannelState.NORMAL, localBalanceMsat: 50_000_000n },
				{ state: ChannelState.CLOSED, localBalanceMsat: 10_000_000n }
			])
		).to.equal(0);
	});

	it('BeignetNode exposes recoverFallbackFunds()', () => {
		expect(typeof BeignetNode.prototype.recoverFallbackFunds).to.equal(
			'function'
		);
	});
});

describe('pendingCloseBalanceSats hands off to the wallet at the sweep (#1065)', () => {
	// The regtest numbers from the issue: a 200,000-sat channel in which we
	// held 10,628 sats, force-closed by the peer; our to_remote sweep pays
	// 10,298 after a 330-sat fee.
	const LOCAL_MSAT = 10_628_000n;
	const channelId = Buffer.alloc(32, 7);
	const commitmentTxid = 'aa'.repeat(32);
	const spendTxid = 'bb'.repeat(32);

	/** A real sweep tx so the txid derived from sweepTxHex is the wallet's. */
	function sweepTx(): { hex: string; txid: string } {
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(Buffer.from(commitmentTxid, 'hex').reverse(), 0);
		tx.addOutput(Buffer.from('0014' + '11'.repeat(20), 'hex'), 10_298);
		return { hex: tx.toHex(), txid: tx.getId() };
	}

	function theirCurrent(
		balanceOutput: Partial<FakeTrackedOutput>,
		extra: FakeTrackedOutput[] = []
	): FakeChannel {
		return {
			channelId,
			state: ChannelState.FORCE_CLOSED,
			localBalanceMsat: LOCAL_MSAT,
			monitor: {
				commitmentType: CommitmentType.THEIR_CURRENT_COMMITMENT,
				commitmentTxid,
				outputs: [
					{
						txid: commitmentTxid,
						outputType: OutputType.TO_REMOTE,
						status: OutputStatus.CONFIRMED,
						...balanceOutput
					},
					// The peer's own to_local: never ours, never swept by us.
					{
						txid: commitmentTxid,
						outputType: OutputType.TO_LOCAL,
						status: OutputStatus.CONFIRMED
					},
					...extra
				]
			}
		};
	}

	it('counts a FORCE_CLOSED channel whose balance output is not swept yet', () => {
		// Timelocked or declined: no sweep exists, the funds are pending close.
		expect(pendingCloseSats([theirCurrent({})])).to.equal(10_628);
		// A sweep exists but the wallet has not seen it: still pending close.
		const sweep = sweepTx();
		expect(
			pendingCloseSats([
				theirCurrent({
					status: OutputStatus.SPEND_BROADCAST,
					sweepTxHex: sweep.hex
				})
			])
		).to.equal(10_628);
	});

	it('drops the channel once the wallet history holds the spend the monitor saw', () => {
		const channel = theirCurrent({
			status: OutputStatus.SPEND_CONFIRMED,
			resolutionTxid: spendTxid
		});
		expect(pendingCloseSats([channel], [{ txid: spendTxid }])).to.equal(0);
	});

	it('drops the channel once the wallet history holds the sweep it built (mempool sighting)', () => {
		const sweep = sweepTx();
		const channel = theirCurrent({
			status: OutputStatus.SPEND_BROADCAST,
			sweepTxHex: sweep.hex
		});
		expect(pendingCloseSats([channel], [{ txid: sweep.txid }])).to.equal(0);
		// An unrelated wallet transaction is not the sweep.
		expect(pendingCloseSats([channel], [{ txid: spendTxid }])).to.equal(10_628);
	});

	it('counts the channel again when the wallet drops the sweep (evicted or ghosted)', () => {
		const sweep = sweepTx();
		const channel = theirCurrent({
			status: OutputStatus.SPEND_BROADCAST,
			sweepTxHex: sweep.hex
		});
		expect(pendingCloseSats([channel], [{ txid: sweep.txid }])).to.equal(0);
		// Evicted: the entry is gone from the history.
		expect(pendingCloseSats([channel], [])).to.equal(10_628);
		// Ghosted: the entry is kept but marked no longer observed.
		expect(
			pendingCloseSats([channel], [{ txid: sweep.txid, exists: false }])
		).to.equal(10_628);
	});

	it('uses the recorded spend over the built sweep when both exist', () => {
		// An RBF replacement the monitor did not build (or a re-report) is the
		// authoritative spend; the retained template is stale.
		const sweep = sweepTx();
		const channel = theirCurrent({
			status: OutputStatus.SPEND_CONFIRMED,
			sweepTxHex: sweep.hex,
			resolutionTxid: spendTxid
		});
		expect(pendingCloseSats([channel], [{ txid: spendTxid }])).to.equal(0);
		expect(pendingCloseSats([channel], [{ txid: sweep.txid }])).to.equal(
			10_628
		);
	});

	it('an HTLC sweep in the wallet does not stand in for the balance sweep', () => {
		const htlcSpend = 'cc'.repeat(32);
		const channel = theirCurrent({}, [
			{
				txid: commitmentTxid,
				outputType: OutputType.RECEIVED_HTLC,
				status: OutputStatus.SPEND_CONFIRMED,
				resolutionTxid: htlcSpend
			}
		]);
		expect(pendingCloseSats([channel], [{ txid: htlcSpend }])).to.equal(10_628);
	});

	it('on OUR commitment the balance output is the commitment to_local, not a second-level one', () => {
		const secondLevelTxid = 'dd'.repeat(32);
		const secondLevelSpend = 'ee'.repeat(32);
		const ours = (toLocal: Partial<FakeTrackedOutput>): FakeChannel => ({
			channelId,
			state: ChannelState.FORCE_CLOSED,
			localBalanceMsat: LOCAL_MSAT,
			monitor: {
				commitmentType: CommitmentType.OUR_COMMITMENT,
				commitmentTxid,
				outputs: [
					{
						txid: commitmentTxid,
						outputType: OutputType.TO_LOCAL,
						status: OutputStatus.CONFIRMED,
						...toLocal
					},
					// The peer's to_remote on our commitment: never ours.
					{
						txid: commitmentTxid,
						outputType: OutputType.TO_REMOTE,
						status: OutputStatus.CONFIRMED
					},
					// The CSV output of our own HTLC-success tx: an HTLC resolution.
					{
						txid: secondLevelTxid,
						outputType: OutputType.TO_LOCAL,
						status: OutputStatus.SPEND_CONFIRMED,
						isSecondLevelHtlc: true,
						resolutionTxid: secondLevelSpend
					}
				]
			}
		});
		// Timelocked to_local, no sweep yet: pending close, even though the
		// second-level sweep is already in the wallet.
		expect(pendingCloseSats([ours({})], [{ txid: secondLevelSpend }])).to.equal(
			10_628
		);
		// The matured to_local sweep is in the wallet: handed off.
		expect(
			pendingCloseSats(
				[
					ours({
						status: OutputStatus.SPEND_CONFIRMED,
						resolutionTxid: spendTxid
					})
				],
				[{ txid: spendTxid }]
			)
		).to.equal(0);
	});

	it('leaves SHUTTING_DOWN and NEGOTIATING_CLOSING counted whole, and a channel with no monitor', () => {
		const coopId = Buffer.alloc(32, 8);
		expect(
			pendingCloseSats(
				[
					{
						channelId: coopId,
						state: ChannelState.SHUTTING_DOWN,
						localBalanceMsat: 5_000_000n,
						monitor: {
							commitmentType: CommitmentType.COOPERATIVE_CLOSE,
							commitmentTxid,
							outputs: [
								{
									txid: commitmentTxid,
									outputType: OutputType.TO_LOCAL,
									status: OutputStatus.SPEND_CONFIRMED,
									resolutionTxid: spendTxid
								}
							]
						}
					},
					{
						state: ChannelState.NEGOTIATING_CLOSING,
						localBalanceMsat: 3_000_000n
					},
					// FORCE_CLOSED with no monitor at all (nothing classified yet).
					{
						channelId: Buffer.alloc(32, 9),
						state: ChannelState.FORCE_CLOSED,
						localBalanceMsat: 2_000_000n
					}
				],
				[{ txid: spendTxid }]
			)
		).to.equal(10_000);
	});

	it('sums per channel: only the channel whose sweep the wallet holds leaves the figure', () => {
		const otherId = Buffer.alloc(32, 10);
		const otherCommitment = 'ff'.repeat(32);
		const swept = theirCurrent({
			status: OutputStatus.SPEND_CONFIRMED,
			resolutionTxid: spendTxid
		});
		const unswept: FakeChannel = {
			channelId: otherId,
			state: ChannelState.FORCE_CLOSED,
			localBalanceMsat: 4_000_000n,
			monitor: {
				commitmentType: CommitmentType.THEIR_CURRENT_COMMITMENT,
				commitmentTxid: otherCommitment,
				outputs: [
					{
						txid: otherCommitment,
						outputType: OutputType.TO_REMOTE,
						status: OutputStatus.CONFIRMED
					}
				]
			}
		};
		expect(pendingCloseSats([swept, unswept], [{ txid: spendTxid }])).to.equal(
			4_000
		);
	});

	it('getInfo: after the sweep reaches the wallet the total equals the on-chain balance', () => {
		// The issue's regtest read: height 96828, the to_remote sweep is in the
		// mempool and the wallet already counts it (10,298). Before the fix
		// getInfo reported pending close 10,628 next to it, a total of 20,926
		// against a true 10,298.
		const sweep = sweepTx();
		const channel = theirCurrent({
			status: OutputStatus.SPEND_BROADCAST,
			sweepTxHex: sweep.hex
		});
		const info = (walletTxs: FakeWalletTx[], onchain: number) => {
			const fake = Object.assign(Object.create(BeignetNode.prototype), {
				...fakeNode([channel], walletTxs),
				networkName: 'regtest'
			});
			fake.node.getNodeInfo = () => ({
				nodeId: '02' + '00'.repeat(32),
				channelCount: 1,
				openChannelCount: 0,
				peerCount: 0
			});
			fake.node.getCurrentBlockHeight = () => 96_828;
			fake.node.isListening = () => false;
			fake.node.getIrohConnectionString = () => undefined;
			fake.node.getBalance = () => ({ localBalanceMsat: 0n });
			fake.wallet.getBalance = () => onchain;
			return fake.getInfo();
		};
		const before = info([], 0);
		expect(before.pendingCloseBalanceSats).to.equal(10_628);
		expect(before.onchainBalanceSats).to.equal(0);
		const after = info([{ txid: sweep.txid }], 10_298);
		expect(after.pendingCloseBalanceSats).to.equal(0);
		expect(after.onchainBalanceSats).to.equal(10_298);
		expect(
			after.onchainBalanceSats +
				after.lightningBalanceSats +
				after.pendingCloseBalanceSats
		).to.equal(10_298);
	});
});
