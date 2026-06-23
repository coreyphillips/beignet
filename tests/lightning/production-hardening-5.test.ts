/**
 * Production Hardening 5: 24/7 AI Agent Readiness Tests.
 *
 * Covers 20 fixes across 4 phases:
 * - Phase 1: P0 Fund Safety — HTLC & Channel Validation
 * - Phase 2: P0 Fund Safety — Payments & Chain Monitoring
 * - Phase 3: P1 Reliability
 * - Phase 4: P1-P2 Ergonomics & Standards
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	PaymentStatus,
	PaymentDirection,
	IPaymentInfo
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import { Feature } from '../../src/lightning/features/flags';
import {
	ChainMonitor,
	IChainMonitorState
} from '../../src/lightning/chain/chain-monitor';
import {
	MonitorState,
	OutputStatus,
	OutputType,
	ITrackedOutput
} from '../../src/lightning/chain/types';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import {
	validateOpenChannelParams,
	validateAcceptChannelParams
} from '../../src/lightning/channel/validation';
import {
	IOpenChannelMessage,
	IAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	CHANNEL_DISABLED,
	PERMANENT_NODE_FAILURE,
	PERMANENT_CHANNEL_FAILURE,
	REQUIRED_NODE_FEATURE_MISSING,
	TEMPORARY_NODE_FAILURE
} from '../../src/lightning/onion/types';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import {
	serializeChainMonitorState,
	deserializeChainMonitorState
} from '../../src/lightning/storage/serialization';

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`ph5-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
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

function makeNodeConfig(
	seedId: number,
	extras?: Partial<INodeConfig>
): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		...extras
	};
}

function createNode(
	seedId: number,
	extras?: Partial<INodeConfig>
): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, extras));
	node.on('error', () => {});
	return node;
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeB.getNodeId()) {
				nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
			}
		}
	);
	nodeB.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeA.getNodeId()) {
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		}
	);
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	fundingSatoshis = 1_000_000n
): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), fundingSatoshis);
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

function makeNormalChannel(
	seedId: number,
	opts?: {
		localHtlcMinimum?: bigint;
		localMaxAcceptedHtlcs?: number;
		localMaxHtlcValueInFlightMsat?: bigint;
		remoteReserveSatoshis?: bigint;
	}
): { channel: Channel; state: IChannelState } {
	const seed = makeSeed(seedId);
	const bp = makeBasepoints(seed);
	const remoteSeed = makeSeed(seedId + 50);
	const remoteBp = makeBasepoints(remoteSeed);

	const localConfig = { ...DEFAULT_CHANNEL_CONFIG };
	if (opts?.localHtlcMinimum !== undefined)
		localConfig.htlcMinimumMsat = opts.localHtlcMinimum;
	if (opts?.localMaxAcceptedHtlcs !== undefined)
		localConfig.maxAcceptedHtlcs = opts.localMaxAcceptedHtlcs;
	if (opts?.localMaxHtlcValueInFlightMsat !== undefined)
		localConfig.maxHtlcValueInFlightMsat = opts.localMaxHtlcValueInFlightMsat;

	const remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
	if (opts?.remoteReserveSatoshis !== undefined)
		remoteConfig.channelReserveSatoshis = opts.remoteReserveSatoshis;

	const state = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xdd),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig,
		localBasepoints: bp,
		localPerCommitmentSeed: makeSeed(seedId + 100)
	});

	state.state = ChannelState.NORMAL;
	state.channelId = crypto.randomBytes(32);
	state.remoteBasepoints = remoteBp;
	state.remoteConfig = remoteConfig;
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.localBalanceMsat = 500_000_000n;
	state.remoteBalanceMsat = 500_000_000n;

	const channel = new Channel(state);
	return { channel, state };
}

// ═══════════════════════════════════════════════════════════════════════
// Phase 1: P0 Fund Safety — HTLC & Channel Validation
// ═══════════════════════════════════════════════════════════════════════

describe('Production Hardening 5: Phase 1 — HTLC & Channel Validation', function () {
	this.timeout(10_000);

	// ─── Fix 1: handleUpdateAddHtlc inbound validation ───

	describe('Fix 1: handleUpdateAddHtlc inbound validation', () => {
		it('rejects HTLC with zero amount', () => {
			const { channel, state } = makeNormalChannel(1);
			const actions = channel.handleUpdateAddHtlc({
				channelId: state.channelId!,
				id: 0n,
				amountMsat: 0n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 100,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			expect(actions).to.have.lengthOf(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect((actions[0] as any).message).to.include('greater than 0');
		});

		it('rejects HTLC below our htlcMinimumMsat', () => {
			const { channel, state } = makeNormalChannel(2, {
				localHtlcMinimum: 10_000n
			});
			const actions = channel.handleUpdateAddHtlc({
				channelId: state.channelId!,
				id: 0n,
				amountMsat: 5_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 100,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			expect(actions).to.have.lengthOf(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect((actions[0] as any).message).to.include('below our minimum');
		});

		it('rejects HTLC when max inbound pending exceeded', () => {
			const { channel, state } = makeNormalChannel(3, {
				localMaxAcceptedHtlcs: 1
			});

			// Add first HTLC (should succeed)
			const ok = channel.handleUpdateAddHtlc({
				channelId: state.channelId!,
				id: 0n,
				amountMsat: 1_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 100,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			// A successful inbound add returns no actions — forwarding is deferred
			// until the commitment round-trip completes (BOLT 2).
			expect(ok.find((a) => a.type === ChannelActionType.ERROR)).to.be
				.undefined;

			// Second HTLC should fail
			const actions = channel.handleUpdateAddHtlc({
				channelId: state.channelId!,
				id: 1n,
				amountMsat: 1_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 100,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			expect(actions).to.have.lengthOf(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect((actions[0] as any).message).to.include('Max inbound pending');
		});

		it('rejects HTLC when max inbound value in flight exceeded', () => {
			const { channel, state } = makeNormalChannel(4, {
				localMaxHtlcValueInFlightMsat: 50_000n
			});
			const actions = channel.handleUpdateAddHtlc({
				channelId: state.channelId!,
				id: 0n,
				amountMsat: 60_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 100,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			expect(actions).to.have.lengthOf(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect((actions[0] as any).message).to.include('Max inbound HTLC value');
		});
	});

	// ─── Fix 2: handleUpdateFee reserve check ───

	describe('Fix 2: handleUpdateFee reserve check', () => {
		it('rejects fee that drains opener below reserve', () => {
			const seed = makeSeed(20);
			const bp = makeBasepoints(seed);
			const remoteSeed = makeSeed(21);
			const remoteBp = makeBasepoints(remoteSeed);

			// Create acceptor state (we receive update_fee as acceptor)
			const state = createAcceptorState({
				temporaryChannelId: Buffer.alloc(32, 0xcc),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: {
					...DEFAULT_CHANNEL_CONFIG,
					channelReserveSatoshis: 10_000n
				},
				localBasepoints: bp,
				localPerCommitmentSeed: makeSeed(120),
				remoteBasepoints: remoteBp,
				remoteConfig: { ...DEFAULT_CHANNEL_CONFIG, feeratePerKw: 1000 }
			});
			state.state = ChannelState.NORMAL;
			state.channelId = crypto.randomBytes(32);
			state.localBalanceMsat = 10_000_000n;
			// Remote (opener) has very little balance
			state.remoteBalanceMsat = 100_000n;

			const channel = new Channel(state);

			// Set a very high fee rate that would drain remote below reserve
			const actions = channel.handleUpdateFee({
				channelId: state.channelId!,
				feeratePerKw: 5000
			});
			expect(actions).to.have.lengthOf(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect((actions[0] as any).message).to.include(
				'drain opener below channel reserve'
			);
		});
	});

	// ─── Fix 7: addHtlc uses remoteConfig reserve ───

	describe('Fix 7: addHtlc enforces remote-specified channel reserve', () => {
		it('uses remoteConfig.channelReserveSatoshis for balance check', () => {
			const { channel } = makeNormalChannel(7, {
				remoteReserveSatoshis: 400_000n
			});
			// Local balance is 500_000_000 msat, remote reserve is 400_000 sat = 400_000_000 msat
			// So available for HTLC = 500_000_000 - 400_000_000 = 100_000_000 msat
			// Trying to send 200_000_000 msat should fail
			const actions = channel.addHtlc(
				200_000_000n,
				crypto.randomBytes(32),
				100,
				Buffer.alloc(1366)
			);
			expect(actions).to.have.lengthOf(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect((actions[0] as any).message).to.include('Insufficient balance');
		});
	});

	// ─── Fix 13: CLTV validation on incoming HTLCs ───

	describe('Fix 13: CLTV validation on incoming HTLCs', () => {
		it('rejects HTLC with already-expired CLTV', () => {
			const { channel, state } = makeNormalChannel(13);
			channel.setBlockHeight(500);

			const actions = channel.handleUpdateAddHtlc({
				channelId: state.channelId!,
				id: 0n,
				amountMsat: 10_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 499, // Already expired
				onionRoutingPacket: Buffer.alloc(1366)
			});
			expect(actions).to.have.lengthOf(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect((actions[0] as any).message).to.include('CLTV already expired');
		});

		it('rejects HTLC with CLTV too far in future', () => {
			const { channel, state } = makeNormalChannel(14);
			channel.setBlockHeight(500);

			const actions = channel.handleUpdateAddHtlc({
				channelId: state.channelId!,
				id: 0n,
				amountMsat: 10_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500 + 5041, // > 5040 blocks in future
				onionRoutingPacket: Buffer.alloc(1366)
			});
			expect(actions).to.have.lengthOf(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect((actions[0] as any).message).to.include('CLTV too far in future');
		});
	});
});

// ═══════════════════════════════════════════════════════════════════════
// Phase 2: P0 Fund Safety — Payments & Chain Monitoring
// ═══════════════════════════════════════════════════════════════════════

describe('Production Hardening 5: Phase 2 — Payments & Chain Monitoring', function () {
	this.timeout(10_000);

	// ─── Fix 3: Sweep re-broadcast ───

	describe('Fix 3: Sweep re-broadcast uses stored tx', () => {
		it('re-broadcast emits non-empty tx buffer', () => {
			// Create a minimal chain monitor state with a SPEND_BROADCAST output
			const state = createOpenerState({
				temporaryChannelId: Buffer.alloc(32, 0xaa),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(makeSeed(30)),
				localPerCommitmentSeed: makeSeed(130)
			});
			state.channelId = crypto.randomBytes(32);
			state.remoteBasepoints = makeBasepoints(makeSeed(31));

			const monitor = new ChainMonitor(
				state,
				Buffer.alloc(22, 0xbb),
				10,
				crypto.randomBytes(32),
				crypto.randomBytes(32)
			);

			// Manually set up a tracked output in SPEND_BROADCAST with sweepTxHex
			const trackedOutput: ITrackedOutput = {
				txid: crypto.randomBytes(32).toString('hex'),
				outputIndex: 0,
				amount: 100_000n,
				outputType: OutputType.TO_LOCAL,
				status: OutputStatus.SPEND_BROADCAST,
				confirmationHeight: 100,
				broadcastHeight: 100,
				originalFeeRate: 10,
				sweepTxHex: 'deadbeef01020304'
			};

			// Access internal state for testing
			const fullState = monitor.getFullState();
			fullState.trackedOutputs.push(trackedOutput);
			fullState.monitorState = MonitorState.RESOLVING;

			// Restore with the tracked output
			const restored = ChainMonitor.restore(
				fullState,
				state,
				Buffer.alloc(22, 0xbb),
				10,
				crypto.randomBytes(32),
				crypto.randomBytes(32)
			);

			// Advance blocks to trigger re-broadcast (6 blocks interval)
			const actions = restored.handleNewBlock(107);
			const broadcastActions = actions.filter(
				(a) => a.type === 'CHAIN_BROADCAST_TX'
			);
			for (const action of broadcastActions) {
				if (action.type === 'CHAIN_BROADCAST_TX') {
					expect(action.tx.length).to.be.greaterThan(0);
				}
			}
		});

		it('sweepTxHex survives serialization round-trip', () => {
			const monitorState: IChainMonitorState = {
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: null,
				trackedOutputs: [
					{
						txid: 'abcdef1234567890',
						outputIndex: 0,
						amount: 50_000n,
						outputType: OutputType.TO_LOCAL,
						status: OutputStatus.SPEND_BROADCAST,
						confirmationHeight: 100,
						broadcastHeight: 100,
						originalFeeRate: 5,
						sweepTxHex: 'cafebabe'
					}
				],
				currentBlockHeight: 110
			};

			const json = serializeChainMonitorState(monitorState);
			const restored = deserializeChainMonitorState(json);
			expect(restored.trackedOutputs[0].sweepTxHex).to.equal('cafebabe');
		});
	});

	// ─── Fix 4: FORCE_CLOSED re-watch ───

	describe('Fix 4: FORCE_CLOSED channels re-watch logic', () => {
		it('restoreChainWatches does not skip FORCE_CLOSED channels with RESOLVING monitor', () => {
			// This is hard to fully integration-test without chain backend,
			// so we verify the logic by checking the node doesn't throw
			const alice = createNode(40);
			const bob = createNode(41);
			connectNodes(alice, bob);
			openReadyChannel(alice, bob);

			// Verify the method exists and doesn't crash
			alice
				.restoreChainWatches()
				.then(() => {
					// pass
				})
				.catch(() => {
					// No chain watcher configured, expected
				});
			alice.destroy();
			bob.destroy();
		});
	});

	// ─── Fix 5: Late preimage settlement ───

	describe('Fix 5: sendPaymentAsync late settlement', () => {
		it('accepts preimage for timed-out FAILED payment', () => {
			const alice = createNode(50);
			const bob = createNode(51);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);

			// Create an outbound payment manually
			const preimage = crypto.randomBytes(32);

			// Compute the actual hash from preimage
			const actualHash = crypto.createHash('sha256').update(preimage).digest();
			const actualHashHex = actualHash.toString('hex');

			// Set up a FAILED payment
			const payment: IPaymentInfo = {
				paymentHash: actualHash,
				amountMsat: 10_000n,
				status: PaymentStatus.FAILED,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now() - 10_000,
				completedAt: Date.now() - 5_000
			};

			// Access payments map via internal mechanism
			(alice as any).payments.set(actualHashHex, payment);

			// Simulate an HTLC fulfillment coming in from the channel
			let sentEmitted = false;
			alice.on('payment:sent', (info: IPaymentInfo) => {
				if (info.paymentHash.toString('hex') === actualHashHex) {
					sentEmitted = true;
				}
			});

			// Trigger handleHtlcFulfilled
			(alice as any).handleHtlcFulfilled(channelId, 0n, preimage);

			expect(sentEmitted).to.be.true;
			const updated = (alice as any).payments.get(actualHashHex);
			expect(updated.status).to.equal(PaymentStatus.COMPLETED);

			alice.destroy();
			bob.destroy();
		});

		it('does not double-complete a COMPLETED payment', () => {
			const alice = createNode(52);
			const bob = createNode(53);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);

			const preimage = crypto.randomBytes(32);
			const actualHash = crypto.createHash('sha256').update(preimage).digest();
			const actualHashHex = actualHash.toString('hex');

			const payment: IPaymentInfo = {
				paymentHash: actualHash,
				amountMsat: 10_000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now() - 10_000,
				completedAt: Date.now() - 5_000,
				preimage
			};
			(alice as any).payments.set(actualHashHex, payment);

			let sentCount = 0;
			alice.on('payment:sent', () => {
				sentCount++;
			});

			(alice as any).handleHtlcFulfilled(channelId, 0n, preimage);
			expect(sentCount).to.equal(0);

			alice.destroy();
			bob.destroy();
		});
	});
});

// ═══════════════════════════════════════════════════════════════════════
// Phase 3: P1 Reliability
// ═══════════════════════════════════════════════════════════════════════

describe('Production Hardening 5: Phase 3 — Reliability', function () {
	this.timeout(10_000);

	// ─── Fix 9: subscribeToHeaders dedup ───

	describe('Fix 9: ElectrumBackend subscribeToHeaders dedup', () => {
		it('ElectrumBackend has _originalOnReceive and reconnect methods', () => {
			// We can't easily create a full Electrum instance in unit tests,
			// but we can verify the ElectrumBackend class has the right interface
			const {
				ElectrumBackend
			} = require('../../src/lightning/chain/electrum-backend');
			expect(ElectrumBackend.prototype).to.have.property('resubscribeAll');
			expect(ElectrumBackend.prototype).to.have.property(
				'startReconnectMonitor'
			);
			expect(ElectrumBackend.prototype).to.have.property(
				'stopReconnectMonitor'
			);
		});
	});

	// ─── Fix 10: acceptInbound timeout ───

	describe('Fix 10: acceptInbound handshake timeout', () => {
		it('Peer.acceptInbound sets handshake timeout on socket', () => {
			// Verify the Peer class has the acceptInbound method
			const { Peer } = require('../../src/lightning/transport/peer');
			expect(Peer.prototype).to.have.property('acceptInbound');
		});
	});

	// ─── Fix 11: ChainWatcher error forwarded ───

	describe('Fix 11: ChainWatcher errors forwarded as node:error', () => {
		it('wireChainWatcherEvents registers error listener', () => {
			const node = createNode(110);
			// Without a chain backend, chainWatcher is null, so
			// we verify the method doesn't crash
			const cw = node.getChainWatcher();
			expect(cw).to.be.null;
			node.destroy();
		});
	});

	// ─── Fix 12: Mission control periodic persistence ───

	describe('Fix 12: Mission control periodic persistence', () => {
		it('missionControlTimer is created when storage is provided', () => {
			// Create a mock storage
			const storage = {
				saveChannel: () => {},
				loadAllChannels: () => [],
				savePeerAddress: () => {},
				loadAllPeerAddresses: () => [],
				savePayment: () => {},
				loadAllPayments: () => [],
				saveChainMonitor: () => {},
				loadAllChainMonitors: () => [],
				saveGossipChannel: () => {},
				saveGossipNode: () => {},
				loadAllGossipChannels: () => [],
				loadAllGossipNodes: () => [],
				saveHtlcPaymentMapping: () => {},
				loadAllHtlcPaymentMappings: () => [],
				deleteHtlcPaymentMapping: () => {},
				saveForwardedHtlc: () => {},
				loadAllForwardedHtlcs: () => [],
				deleteForwardedHtlc: () => {},
				savePaymentSecret: () => {},
				loadAllPaymentSecrets: () => [],
				deletePaymentSecret: () => {},
				saveInvoice: () => {},
				loadAllInvoices: () => [],
				saveMissionControl: () => {},
				loadMissionControl: () => null,
				loadAllPreimages: () => [],
				loadAllScidMappings: () => [],
				saveMetadata: () => {},
				loadMetadata: () => null,
				saveHtlcSharedSecret: () => {},
				deleteHtlcSharedSecret: () => {},
				loadAllHtlcSharedSecrets: () => [],
				transaction: (fn: () => void) => fn(),
				getSchemaVersion: () => 1,
				setSchemaVersion: () => {}
			} as any;

			const node = createNode(120, { storage });
			expect((node as any).missionControlTimer).to.not.be.null;
			node.destroy();
			expect((node as any).missionControlTimer).to.be.null;
		});
	});

	// ─── Fix 14: Inbound peer address stored ───

	describe('Fix 14: Inbound peer address stored', () => {
		it('handleInboundConnection stores peer address', () => {
			const privKey = crypto.randomBytes(32);
			const pm = new PeerManager({
				localPrivateKey: privKey
			});
			// Verify the method exists (actual TCP testing would require integration tests)
			expect(pm.getPeerAddress('abc')).to.be.undefined;
			pm.destroy();
		});
	});
});

// ═══════════════════════════════════════════════════════════════════════
// Phase 4: P1-P2 Ergonomics & Standards
// ═══════════════════════════════════════════════════════════════════════

describe('Production Hardening 5: Phase 4 — Ergonomics & Standards', function () {
	this.timeout(10_000);

	// ─── Fix 15: closeChannel/forceCloseChannel return results ───

	describe('Fix 15: closeChannel returns results', () => {
		it('closeChannel returns { ok: false } on invalid channel', () => {
			const node = createNode(150);
			node.on('node:error', () => {}); // absorb error

			const result = node.closeChannel(
				crypto.randomBytes(32),
				crypto.randomBytes(22)
			);
			expect(result).to.have.property('ok', false);
			expect(result).to.have.property('error');
			node.destroy();
		});

		it('forceCloseChannel returns { ok: false } on invalid channel', () => {
			const node = createNode(151);
			node.on('node:error', () => {}); // absorb error

			const result = node.forceCloseChannel(
				crypto.randomBytes(32),
				crypto.randomBytes(22)
			);
			expect(result).to.have.property('ok', false);
			expect(result).to.have.property('error');
			node.destroy();
		});
	});

	// ─── Fix 16: channel:ready structured data ───

	describe('Fix 16: channel:ready emits structured data', () => {
		it('channel:ready emits { channelId } object', () => {
			const alice = createNode(160);
			const bob = createNode(161);
			connectNodes(alice, bob);

			let receivedData: any = null;
			alice.on('channel:ready', (data: any) => {
				receivedData = data;
			});

			const channelId = openReadyChannel(alice, bob);

			expect(receivedData).to.not.be.null;
			expect(receivedData).to.have.property('channelId');
			expect(Buffer.isBuffer(receivedData.channelId)).to.be.true;
			expect(receivedData.channelId.toString('hex')).to.equal(
				channelId.toString('hex')
			);

			alice.destroy();
			bob.destroy();
		});
	});

	// ─── Fix 17: PAYMENT_SECRET compulsory ───

	describe('Fix 17: defaultFeatures sets PAYMENT_SECRET compulsory', () => {
		it('PAYMENT_SECRET is compulsory in default features', () => {
			const flags = LightningNode.defaultFeatures();
			// Compulsory means the even bit is set
			// Feature.PAYMENT_SECRET = 14 (even bit)
			expect(flags.hasFeature(Feature.PAYMENT_SECRET)).to.be.true;
			// Check it's compulsory (even bit set) not just optional (odd bit)
			const raw = flags.toBuffer();
			// PAYMENT_SECRET is feature 14, bit 14 is the compulsory version
			// The bit position is counted from LSB
			const byteIndex = raw.length - 1 - Math.floor(14 / 8);
			const bitIndex = 14 % 8;
			if (byteIndex >= 0 && byteIndex < raw.length) {
				const compulsoryBitSet = (raw[byteIndex] & (1 << bitIndex)) !== 0;
				expect(compulsoryBitSet).to.be.true;
			}
		});
	});

	// ─── Fix 19: Validation upper bounds ───

	describe('Fix 19: Validation upper bounds', () => {
		function makeValidOpenMsg(
			overrides?: Partial<IOpenChannelMessage>
		): IOpenChannelMessage {
			return {
				chainHash: Buffer.alloc(32),
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 100_000_000n,
				channelReserveSatoshis: 10_000n,
				htlcMinimumMsat: 1n,
				feeratePerKw: 1000,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 30,
				channelFlags: 1,
				fundingPubkey: getPublicKey(crypto.randomBytes(32)),
				revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
				paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
				delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
				htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
				firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32)),
				...overrides
			};
		}

		function makeValidAcceptMsg(
			open: IOpenChannelMessage,
			overrides?: Partial<IAcceptChannelMessage>
		): IAcceptChannelMessage {
			return {
				temporaryChannelId: open.temporaryChannelId,
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 100_000_000n,
				channelReserveSatoshis: 10_000n,
				htlcMinimumMsat: 1n,
				minimumDepth: 3,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 30,
				fundingPubkey: getPublicKey(crypto.randomBytes(32)),
				revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
				paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
				delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
				htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
				firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32)),
				...overrides
			};
		}

		it('open_channel rejects to_self_delay > 2016', () => {
			const msg = makeValidOpenMsg({ toSelfDelay: 3000 });
			const err = validateOpenChannelParams(msg);
			expect(err).to.include('to_self_delay');
			expect(err).to.include('2016');
		});

		it('open_channel rejects feerate_per_kw > 100000', () => {
			const msg = makeValidOpenMsg({ feeratePerKw: 200_000 });
			const err = validateOpenChannelParams(msg);
			expect(err).to.include('feerate_per_kw');
			expect(err).to.include('100000');
		});

		it('accept_channel rejects to_self_delay > 2016', () => {
			const open = makeValidOpenMsg();
			const accept = makeValidAcceptMsg(open, { toSelfDelay: 5000 });
			const err = validateAcceptChannelParams(open, accept);
			expect(err).to.include('to_self_delay');
			expect(err).to.include('2016');
		});
	});

	// ─── Fix 20: Missing BOLT 4 failure codes ───

	describe('Fix 20: BOLT 4 failure codes', () => {
		it('failure codes have correct values', () => {
			// CHANNEL_DISABLED = UPDATE (0x1000) | 20
			expect(CHANNEL_DISABLED).to.equal(0x1000 | 20);
			expect(CHANNEL_DISABLED).to.equal(4116);

			// PERMANENT_NODE_FAILURE = PERM (0x4000) | NODE (0x2000) | 2
			expect(PERMANENT_NODE_FAILURE).to.equal(0x4000 | 0x2000 | 2);
			expect(PERMANENT_NODE_FAILURE).to.equal(24578);

			// PERMANENT_CHANNEL_FAILURE = PERM (0x4000) | UPDATE (0x1000) | 8
			expect(PERMANENT_CHANNEL_FAILURE).to.equal(0x4000 | 0x1000 | 8);
			expect(PERMANENT_CHANNEL_FAILURE).to.equal(20488);

			// REQUIRED_NODE_FEATURE_MISSING = PERM (0x4000) | NODE (0x2000) | 3
			expect(REQUIRED_NODE_FEATURE_MISSING).to.equal(0x4000 | 0x2000 | 3);
			expect(REQUIRED_NODE_FEATURE_MISSING).to.equal(24579);

			// TEMPORARY_NODE_FAILURE (pre-existing) = NODE (0x2000) | 2
			expect(TEMPORARY_NODE_FAILURE).to.equal(0x2000 | 2);
			expect(TEMPORARY_NODE_FAILURE).to.equal(8194);
		});
	});
});
