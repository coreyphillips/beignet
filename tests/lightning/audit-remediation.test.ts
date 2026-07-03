/**
 * Pre-custody fund-safety audit remediation regression tests.
 *
 * Each describe block reproduces a distinct loss-of-funds / stranding scenario
 * flagged by the adversarial fund-safety audit and asserts the fix. Every test
 * here was verified to FAIL against the pre-fix tree.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChainWatcher,
	IChainBackend
} from '../../src/lightning/chain/chain-watcher';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import { ChainActionType } from '../../src/lightning/chain/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, IFeeEstimator } from '../../src/lightning/node/types';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	HtlcDirection,
	HtlcState,
	IHtlcEntry,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`audit-seed-${id}`))
		.digest();
}

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

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	return node;
}

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId())
			b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId())
			a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

function openReadyChannel(alice: LightningNode, bob: LightningNode): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

// ═══════════════════════════════════════════════════════════════════════
// HIGH-1: coop-close CLOSED channels re-watched + rebroadcast on restart
// ═══════════════════════════════════════════════════════════════════════

describe('Audit HIGH-1: coop-close CLOSED channel re-armed on restart', function () {
	this.timeout(10_000);

	it('re-arms the funding watch and rebroadcasts the stored mutual close', async () => {
		const alice = createNode(1);
		const bob = createNode(2);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);

		// Put the channel into the coop-close pre-confirmation window: CLOSED at
		// fee/sig agreement with the signed mutual close persisted, but the tx not
		// yet confirmed (no ChainMonitor exists for it).
		const chan = (alice as any).channelManager.getChannel(channelId);
		const st = chan.getFullState();
		st.state = ChannelState.CLOSED;
		st.lastCooperativeCloseTxHex = 'deadbeefcafe';

		// Inject a spy chain watcher + backend (restoreChainWatches only needs the
		// watcher to be present and the backend for rebroadcast).
		const fundingWatches: unknown[][] = [];
		const rebroadcasts: string[] = [];
		(alice as any).chainWatcher = {
			watchFundingOutput: async (...args: unknown[]): Promise<void> => {
				fundingWatches.push(args);
			},
			watchOutputByTxid: async (): Promise<void> => {},
			stop: (): void => {}
		};
		(alice as any)._chainBackend = {
			broadcastTransaction: async (hex: string): Promise<void> => {
				rebroadcasts.push(hex);
			}
		};

		await alice.restoreChainWatches();

		// Before the fix restoreChainWatches unconditionally `continue`d on CLOSED,
		// so the funding output was never re-watched and the close never rebroadcast.
		expect(fundingWatches.length).to.equal(1);
		expect(rebroadcasts).to.include('deadbeefcafe');

		alice.destroy();
		bob.destroy();
	});
});

// ═══════════════════════════════════════════════════════════════════════
// HIGH-2: reorg eviction of a recorded spend detectable after restart
// ═══════════════════════════════════════════════════════════════════════

describe('Audit HIGH-2: restored watch stays reorg-eviction aware', function () {
	this.timeout(10_000);

	function buildOneOutputTx(): { rawTx: Buffer; txid: string } {
		const tx = new bitcoin.Transaction();
		tx.addInput(crypto.randomBytes(32), 0);
		tx.addOutput(Buffer.from('0014' + '00'.repeat(20), 'hex'), 1000);
		return { rawTx: tx.toBuffer(), txid: tx.getId() };
	}

	it('detects an evicted spend on a restored (seeded) output watch', async () => {
		const { rawTx, txid } = buildOneOutputTx();

		// Backend history reports only the output's own tx, i.e. the previously
		// recorded spend has been reorged out of the active chain.
		const backend: IChainBackend = {
			subscribeToHeaders: async (): Promise<void> => {},
			subscribeToScriptHash: async (): Promise<void> => {},
			getScriptHashHistory: async (): Promise<
				Array<{ txid: string; height: number }>
			> => [{ txid, height: 90 }],
			getTransaction: async (): Promise<Buffer> => rawTx,
			broadcastTransaction: async (): Promise<string> => 'sent'
		};

		let unspentCalls = 0;
		const channelManager = {
			on: (): void => {},
			handleOutputSpent: (): void => {},
			handleOutputUnspent: (): void => {
				unspentCalls++;
			}
		} as unknown as ChannelManager;

		const watcher = new ChainWatcher({ backend, channelManager });
		(watcher as any).currentBlockHeight = 95;

		// Simulate restoreChainWatches re-arming a SPEND_CONFIRMED output: seed the
		// recorded resolution txid + height so the eviction branch can fire.
		const resolutionTxid = crypto.randomBytes(32).toString('hex');
		await watcher.watchOutputByTxid(txid, 0, resolutionTxid, 91);

		// A subscription re-fire re-checks the output; the seeded spend is gone.
		await (watcher as any).checkOutputSpend(`${txid}:0`);

		// Before the fix the restored watch had spendTxid undefined, so the eviction
		// branch never fired and the reorg-then-theft went undetected.
		expect(unspentCalls).to.equal(1);
	});
});

// ═══════════════════════════════════════════════════════════════════════
// HIGH-6: direction-aware failHtlc (no same-id RECEIVED corruption)
// ═══════════════════════════════════════════════════════════════════════

describe('Audit HIGH-6: failHtlc is direction-aware', function () {
	this.timeout(10_000);

	function makeChannelWithBothLegs(seedId: number): Channel {
		const seed = makeSeed(seedId);
		const state = createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 0xcc),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(seed),
			localPerCommitmentSeed: makeSeed(seedId + 100)
		});
		state.state = ChannelState.NORMAL;
		state.channelId = crypto.randomBytes(32);
		state.remoteBasepoints = makeBasepoints(makeSeed(seedId + 50));
		state.remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
		state.fundingTxid = crypto.randomBytes(32);
		state.fundingOutputIndex = 0;
		state.localBalanceMsat = 500_000_000n;
		state.remoteBalanceMsat = 500_000_000n;

		// A live inbound HTLC and a live outbound HTLC sharing numeric id 5.
		const received: IHtlcEntry = {
			id: 5n,
			amountMsat: 20_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 800_100,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.COMMITTED
		};
		const offered: IHtlcEntry = {
			id: 5n,
			amountMsat: 15_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 800_060,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.OFFERED,
			state: HtlcState.COMMITTED
		};
		state.htlcs.set('received-5', received);
		state.htlcs.set('offered-5', offered);
		return new Channel(state);
	}

	it('refuses to fail an offered HTLC and leaves the same-id received HTLC intact', () => {
		const channel = makeChannelWithBothLegs(6);

		const actions = channel.failHtlc(
			5n,
			Buffer.alloc(290),
			HtlcDirection.OFFERED
		);

		// The offered-direction fail is refused (cannot cancel our own offered HTLC).
		expect(actions).to.have.lengthOf(1);
		expect(actions[0].type).to.equal(ChannelActionType.ERROR);

		// Critically, the unrelated received-5 HTLC is NOT corrupted. Before the fix
		// the direction-blind lookup marked it FAILED and refunded upstream.
		const received = channel.getFullState().htlcs.get('received-5');
		expect(received!.state).to.equal(HtlcState.COMMITTED);
	});

	it('still fails a received HTLC by default (existing callers unchanged)', () => {
		const channel = makeChannelWithBothLegs(7);
		const actions = channel.failHtlc(5n, Buffer.alloc(290));
		// Default direction RECEIVED: the inbound HTLC is failed as before.
		expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.equal(
			false
		);
		const received = channel.getFullState().htlcs.get('received-5');
		expect(received!.state).to.equal(HtlcState.FAILED);
	});
});

// ═══════════════════════════════════════════════════════════════════════
// HIGH-4: force-close backstop for an inbound HTLC whose preimage we hold
// ═══════════════════════════════════════════════════════════════════════

describe('Audit HIGH-4: preimage-held inbound HTLC forces a claim close', function () {
	this.timeout(10_000);

	it('force-closes when a FULFILLED inbound HTLC nears expiry unacked', () => {
		const alice = createNode(11);
		const bob = createNode(12);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);

		const chan = (alice as any).channelManager.getChannel(channelId);
		const st = chan.getFullState();

		const currentHeight = 800_000;
		(alice as any).currentBlockHeight = currentHeight;

		// An inbound HTLC we already fulfilled off-chain, but the peer never acked
		// its removal, so it lingers FULFILLED and nears its cltv_expiry.
		const received: IHtlcEntry = {
			id: 3n,
			amountMsat: 40_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: currentHeight + 5, // within the claim buffer
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.FULFILLED
		};
		st.htlcs.set('received-3', received);

		let forceCloseEvent = false;
		alice.on('node:error', (err: any) => {
			if (err.code === 'HTLC_CLAIM_FORCE_CLOSE') forceCloseEvent = true;
		});

		(alice as any).scanExpiringHtlcs(currentHeight);

		// Before the fix scanExpiringHtlcs skipped FULFILLED received HTLCs entirely,
		// so nothing force-closed and the on-chain claim became a mempool race.
		expect(forceCloseEvent).to.equal(true);

		alice.destroy();
		bob.destroy();
	});
});

// ═══════════════════════════════════════════════════════════════════════
// HIGH-5: forwarder does not fail inbound on time while outbound unresolved
// ═══════════════════════════════════════════════════════════════════════

describe('Audit HIGH-5: forward timeout gates on outbound resolution', function () {
	this.timeout(10_000);

	it('force-closes inbound (not off-chain fail) when outbound leg is unresolved', () => {
		const alice = createNode(21); // forwarder
		const bob = createNode(22); // upstream (inbound)
		const carol = createNode(23); // downstream (outbound)
		connectNodes(alice, bob);
		connectNodes(alice, carol);
		const inChannelId = openReadyChannel(alice, bob);
		const outChannelId = openReadyChannel(alice, carol);

		const height = 800_000;
		(alice as any).currentBlockHeight = height;

		// Inbound leg: a received HTLC nearing its cltv_expiry.
		const inChan = (alice as any).channelManager.getChannel(inChannelId);
		const inSt = inChan.getFullState();
		const inbound: IHtlcEntry = {
			id: 7n,
			amountMsat: 50_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: height + 5, // within doubleMargin
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.COMMITTED
		};
		inSt.htlcs.set('received-7', inbound);

		// Outbound leg: the offered HTLC we forwarded is still UNRESOLVED.
		const outChan = (alice as any).channelManager.getChannel(outChannelId);
		const outSt = outChan.getFullState();
		const outbound: IHtlcEntry = {
			id: 7n,
			amountMsat: 49_000n,
			paymentHash: inbound.paymentHash,
			cltvExpiry: height - 35,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.OFFERED,
			state: HtlcState.COMMITTED
		};
		outSt.htlcs.set('offered-7', outbound);

		// Link the two legs.
		const outKey = `${outChannelId.toString('hex')}:offered-7`;
		(alice as any).forwardedHtlcs.set(outKey, {
			inChannelId,
			inHtlcId: 7n
		});

		let forceClose = false;
		alice.on('node:error', (err: any) => {
			if (err.code === 'FORWARD_TIMEOUT_FORCE_CLOSE') forceClose = true;
		});

		(alice as any).scanForwardTimeouts(height);

		// Before the fix the inbound leg was failed off-chain on time alone and the
		// mapping deleted, so a late downstream settlement would double-pay.
		expect(forceClose).to.equal(true);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(true);
		expect(inSt.htlcs.get('received-7')!.state).to.not.equal(HtlcState.FAILED);

		alice.destroy();
		bob.destroy();
		carol.destroy();
	});
});

// ═══════════════════════════════════════════════════════════════════════
// MEDIUM-2: seeded HTLC-success broadcast actions are processed on restore
// ═══════════════════════════════════════════════════════════════════════

describe('Audit MEDIUM-2: _seedMonitorPreimages processes broadcast actions', function () {
	this.timeout(10_000);

	it('emits the HTLC-success broadcast when restoring a monitor', () => {
		const cfg: IChannelManagerConfig = {
			localBasepoints: makeBasepoints(makeSeed(31)),
			localPerCommitmentSeed: makeSeed(131),
			localFundingPrivkey: makeSeed(231)
		};
		const cm = new ChannelManager(cfg);
		cm.on('error', () => {});

		// A preimage learned before the monitor exists (the restore ordering the
		// finding describes: preimages re-recorded, then monitors restored).
		const preimage = crypto.randomBytes(32);
		const hash = crypto.createHash('sha256').update(preimage).digest();
		cm.recordPreimage(hash, preimage);

		// A restored monitor whose addPreimage yields an HTLC-success broadcast and
		// marks its output SPEND_BROADCAST (as the real ChainMonitor does).
		const fakeTx = Buffer.from('deadbeef', 'hex');
		let addPreimageCalled = false;
		const stubMonitor = {
			addPreimage: (): unknown[] => {
				addPreimageCalled = true;
				return [{ type: ChainActionType.BROADCAST_TX, tx: fakeTx }];
			}
		} as unknown as ChainMonitor;

		let broadcast: Buffer | null = null;
		cm.on('broadcast:tx', (tx: Buffer) => {
			broadcast = tx;
		});

		cm.restoreMonitor('aa'.repeat(32), stubMonitor);

		expect(addPreimageCalled).to.equal(true);
		// Before the fix _seedMonitorPreimages discarded the action, so the output
		// was marked SPEND_BROADCAST but the HTLC-success never reached the network.
		expect(broadcast).to.equal(fakeTx);
	});
});

// ═══════════════════════════════════════════════════════════════════════
// MEDIUM-3: re-CPFP re-broadcasts the parent commitment, not just the child
// ═══════════════════════════════════════════════════════════════════════

describe('Audit MEDIUM-3: reCpfpStuckCommitments re-broadcasts the parent', function () {
	this.timeout(10_000);

	it('emits the parent commitment tx when re-bumping a stuck package', () => {
		const cfg: IChannelManagerConfig = {
			localBasepoints: makeBasepoints(makeSeed(41)),
			localPerCommitmentSeed: makeSeed(141),
			localFundingPrivkey: makeSeed(241)
		};
		const cm = new ChannelManager(cfg);
		cm.on('error', () => {});
		// A funding provider is present, so the "no provider" fallback (which would
		// also emit the parent) is NOT taken; the child build fails on the stub
		// action instead, isolating the parent re-broadcast as the fix under test.
		(cm as any).fundingProvider = {
			selectFeeBumpInputs: async (): Promise<unknown> => ({
				inputs: [],
				changeScript: Buffer.alloc(22)
			})
		};

		const parentBuf = Buffer.from('aabbccddeeff', 'hex');
		const channelIdHex = 'cc'.repeat(32);
		(cm as any)._pendingCommitmentCpfp.set(channelIdHex, {
			action: {
				type: ChainActionType.FEE_BUMP_AND_BROADCAST,
				kind: 'anchor-cpfp',
				tx: parentBuf,
				description: 'anchor commitment CPFP',
				feeratePerVbyte: 5
			},
			broadcastHeight: 100,
			lastFeeRate: 5
		});
		(cm as any).monitors.set(channelIdHex, {
			isFullyResolved: (): boolean => false,
			isCommitmentConfirmed: (): boolean => false
		});

		const broadcasts: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		// Advance well past the re-bump interval with a strictly higher feerate.
		cm.reCpfpStuckCommitments(100 + 1000, 50);

		// Before the fix only the (orphan) child was emitted, so the evicted parent
		// commitment never re-entered the mempool.
		expect(broadcasts.some((b) => b.equals(parentBuf))).to.equal(true);
	});
});

// ═══════════════════════════════════════════════════════════════════════
// MEDIUM-4: failed anchor-CPFP attempts are retried, not recorded as paid
// ═══════════════════════════════════════════════════════════════════════

describe('Audit MEDIUM-4: failed CPFP attempt is retried at unchanged feerate', function () {
	this.timeout(10_000);

	it('retries when the previous attempt failed even if the feerate is unchanged', () => {
		const cfg: IChannelManagerConfig = {
			localBasepoints: makeBasepoints(makeSeed(51)),
			localPerCommitmentSeed: makeSeed(151),
			localFundingPrivkey: makeSeed(251)
		};
		const cm = new ChannelManager(cfg);
		cm.on('error', () => {});
		(cm as any).fundingProvider = {
			selectFeeBumpInputs: async (): Promise<unknown> => {
				throw new Error('no confirmed UTXOs');
			}
		};

		const parentBuf = Buffer.from('a1b2c3d4', 'hex');
		const channelIdHex = 'dd'.repeat(32);
		// A prior attempt failed: lastAttemptFailed is set, and lastFeeRate is the
		// live*1.5 value that a failed attempt would previously have recorded as paid.
		(cm as any)._pendingCommitmentCpfp.set(channelIdHex, {
			action: {
				type: ChainActionType.FEE_BUMP_AND_BROADCAST,
				kind: 'anchor-cpfp',
				tx: parentBuf,
				description: 'anchor commitment CPFP',
				feeratePerVbyte: 50
			},
			broadcastHeight: 100,
			lastFeeRate: 50,
			lastAttemptFailed: true
		});
		(cm as any).monitors.set(channelIdHex, {
			isFullyResolved: (): boolean => false,
			isCommitmentConfirmed: (): boolean => false
		});

		const broadcasts: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		// Feerate is UNCHANGED (equal to lastFeeRate). Before the fix the
		// `feeRatePerVbyte <= entry.lastFeeRate` gate blocked the retry forever.
		cm.reCpfpStuckCommitments(100 + 1000, 50);

		expect(broadcasts.some((b) => b.equals(parentBuf))).to.equal(true);
	});
});

// ═══════════════════════════════════════════════════════════════════════
// MEDIUM-5: restore re-arms commitment CPFP even when the estimator errors
// ═══════════════════════════════════════════════════════════════════════

describe('Audit MEDIUM-5: restore re-arms CPFP on estimator failure', function () {
	this.timeout(10_000);

	// Minimal storage: reports one persisted chain monitor so the restore
	// fee-handling block runs; everything else is empty.
	function stubStorage(monitorEntries: unknown[]): IStorageBackend {
		return new Proxy(
			{},
			{
				get(_t, prop: string) {
					if (prop === 'loadAllChainMonitors') return () => monitorEntries;
					if (typeof prop === 'string' && prop.startsWith('loadAll'))
						return () => [];
					return (): unknown =>
						typeof prop === 'string' && prop.startsWith('load')
							? null
							: undefined;
				}
			}
		) as unknown as IStorageBackend;
	}

	it('calls rearmCommitmentCpfp for restored monitors when estimateFee rejects', async () => {
		const origRearm = ChannelManager.prototype.rearmCommitmentCpfp;
		let rearmCalls = 0;
		ChannelManager.prototype.rearmCommitmentCpfp = function (
			...args: unknown[]
		): void {
			rearmCalls++;
			return (origRearm as (...a: unknown[]) => void).apply(this, args);
		};

		try {
			const feeEstimator: IFeeEstimator = {
				estimateFee: async (): Promise<number> => {
					throw new Error('estimator offline');
				}
			};
			const cfg = makeNodeConfig(61);
			cfg.storage = stubStorage([{ channelId: 'aa'.repeat(32), state: {} }]);
			cfg.feeEstimator = feeEstimator;

			const node = new LightningNode(cfg);
			node.on('error', () => {});
			node.on('node:error', () => {});

			// Let the estimateFee().catch microtask run.
			await new Promise((r) => setTimeout(r, 30));

			// Before the fix the .catch only logged, so a transient estimator error
			// left the force-close commitment package unbumped for the whole session.
			expect(rearmCalls).to.be.greaterThan(0);

			node.destroy();
		} finally {
			ChannelManager.prototype.rearmCommitmentCpfp = origRearm;
		}
	});
});
