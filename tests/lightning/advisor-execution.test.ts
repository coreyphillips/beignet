/**
 * Advisor execution (M3 phases 1+2).
 *
 * Phase 1 -- circular rebalancing: rebalanceChannel over a 3-node loop
 * (A->B->C->A) and a 2-node loop (two channels to the same peer), strict
 * maxFeeSats abort before anything is sent, executeRebalanceRecommendations
 * under a per-UTC-day fee budget with persisted spend, and the pure planner.
 *
 * Phase 2 -- routing-fee auto-tuning: runFeeTuneOnce with a seeded forwarding
 * ledger and an injected clock (nudge up on depletion, down on idle, clamps),
 * plus the pure tuner.
 *
 * Both features are asserted OFF by default (no timers unless enabled: true).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	planRebalances,
	MIN_REBALANCE_SATS
} from '../../src/lightning/advisor/rebalance-planner';
import { computeFeeTuneAdjustments } from '../../src/lightning/advisor/fee-tuner';
import { IChannelSnapshot } from '../../src/lightning/advisor/liquidity-advisor';

// ─────────────── Helpers (mirrors tests/lightning/channel-policy.test.ts) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`advisor-exec-seed-${id}`))
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

function makeNodeConfig(seedId: number): INodeConfig {
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
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret
	};
}

function createNode(
	seedId: number,
	extra?: Partial<INodeConfig>
): LightningNode {
	const node = new LightningNode({ ...makeNodeConfig(seedId), ...extra });
	node.on('node:error', () => {});
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
	opener: LightningNode,
	acceptor: LightningNode,
	fundingSatoshis = 1_000_000n
): Buffer {
	const channel = opener.openChannel(acceptor.getNodeId(), fundingSatoshis);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = opener.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	return channelId;
}

/** Add an announced channel + both-direction updates to a node's graph. */
function addGraphChannel(
	node: LightningNode,
	scid: Buffer,
	pubA: Buffer,
	pubB: Buffer
): void {
	const aIs1 = Buffer.compare(pubA, pubB) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: REGTEST_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aIs1 ? pubA : pubB,
		nodeId2: aIs1 ? pubB : pubA,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const dir of [0, 1]) {
		node.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: dir,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		});
	}
}

function nodePubkey(seedId: number): Buffer {
	return getPublicKey(makeNodeConfig(seedId).nodePrivateKey);
}

function setScidAlias(
	node: LightningNode,
	channelId: Buffer,
	scid: Buffer
): void {
	node.getChannelManager().getChannel(channelId)!.getFullState().scidAlias =
		scid;
}

function localMsat(node: LightningNode, channelId: Buffer): bigint {
	return node.getChannelManager().getChannel(channelId)!.getFullState()
		.localBalanceMsat;
}

interface ICircularSetup {
	alice: LightningNode;
	bob: LightningNode;
	charlie: LightningNode;
	abChannelId: Buffer;
	caChannelId: Buffer;
	destroy: () => void;
}

/**
 * A->B->C->A loop from alice's perspective: alice funds AB (all local), bob
 * funds BC (can forward), charlie funds CA (alice has pure inbound there).
 */
function setupCircular(storage?: SqliteStorage): ICircularSetup {
	const alice = createNode(1, storage ? { storage } : undefined);
	const bob = createNode(2);
	const charlie = createNode(3);
	connectNodes(alice, bob);
	connectNodes(bob, charlie);
	connectNodes(charlie, alice);

	const abChannelId = openReadyChannel(alice, bob);
	const bcChannelId = openReadyChannel(bob, charlie);
	const caChannelId = openReadyChannel(charlie, alice);

	const scidAB = encodeShortChannelId({
		block: 900,
		txIndex: 1,
		outputIndex: 0
	});
	const scidBC = encodeShortChannelId({
		block: 900,
		txIndex: 2,
		outputIndex: 0
	});
	const scidCA = encodeShortChannelId({
		block: 900,
		txIndex: 3,
		outputIndex: 0
	});

	// Alice needs SCIDs on her channel states (first-hop pin + inbound hint),
	// forwarders need the onion SCID -> channel mapping.
	setScidAlias(alice, abChannelId, scidAB);
	setScidAlias(alice, caChannelId, scidCA);
	bob.registerChannelScid(abChannelId, scidAB);
	bob.registerChannelScid(bcChannelId, scidBC);
	charlie.registerChannelScid(bcChannelId, scidBC);
	charlie.registerChannelScid(caChannelId, scidCA);

	// Alice's graph only needs the B->C leg; AB is her own local edge and the
	// C->A hop comes from her own routing hint for the CA channel.
	addGraphChannel(alice, scidBC, nodePubkey(2), nodePubkey(3));

	return {
		alice,
		bob,
		charlie,
		abChannelId,
		caChannelId,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
			charlie.destroy();
		}
	};
}

// ─────────────── Tests ───────────────

describe('Advisor Execution (M3 phases 1+2)', function () {
	this.timeout(30_000);

	describe('planRebalances (pure planner)', function () {
		function snap(
			id: string,
			localSats: number,
			capacitySats = 1_000_000,
			state = 'NORMAL'
		): IChannelSnapshot {
			return {
				channelId: id,
				state,
				localBalanceMsat: BigInt(localSats) * 1000n,
				remoteBalanceMsat: BigInt(capacitySats - localSats) * 1000n,
				capacitySats,
				peerPubkey: '02'.repeat(33 / 3)
			};
		}

		it('pairs a saturated channel with a depleted one toward 50/50', function () {
			const plans = planRebalances([snap('aa', 950_000), snap('bb', 50_000)]);
			expect(plans).to.have.length(1);
			expect(plans[0].fromChannelId).to.equal('aa');
			expect(plans[0].toChannelId).to.equal('bb');
			// min(donor excess 450k, receiver deficit 450k)
			expect(plans[0].amountSats).to.equal(450_000n);
		});

		it('ignores balanced and non-NORMAL channels', function () {
			expect(
				planRebalances([
					snap('aa', 500_000),
					snap('bb', 950_000, 1_000_000, 'CLOSED'),
					snap('cc', 40_000, 1_000_000, 'AWAITING_REESTABLISH')
				])
			).to.deep.equal([]);
		});

		it('is deterministic: most-saturated donor pairs with most-depleted receiver', function () {
			const plans = planRebalances([
				snap('d2', 850_000),
				snap('d1', 990_000),
				snap('r2', 150_000),
				snap('r1', 10_000)
			]);
			expect(plans[0].fromChannelId).to.equal('d1');
			expect(plans[0].toChannelId).to.equal('r1');
		});

		it('skips moves below MIN_REBALANCE_SATS', function () {
			// 80.05% local: technically a donor at the 20% threshold, but the
			// excess over 50% of a tiny channel is under the minimum move size.
			const tiny = snap('aa', 1_610, 2_000);
			const receiver = snap('bb', 100, 2_000);
			const plans = planRebalances([tiny, receiver]);
			expect(plans).to.deep.equal([]);
			expect(MIN_REBALANCE_SATS).to.equal(1_000n);
		});
	});

	describe('computeFeeTuneAdjustments (pure tuner)', function () {
		const opts = { floorPpm: 1, ceilPpm: 10_000 };

		it('nudges up 25% when depleted and forwarding, capped at ceilPpm', function () {
			const adjustments = computeFeeTuneAdjustments(
				[
					{
						channelId: 'aa',
						currentPpm: 1000,
						localBalanceFraction: 0.1,
						outboundForwards: 3,
						totalForwards: 3
					},
					{
						channelId: 'bb',
						currentPpm: 9000,
						localBalanceFraction: 0.05,
						outboundForwards: 1,
						totalForwards: 1
					}
				],
				opts
			);
			expect(adjustments).to.deep.equal([
				{
					channelId: 'aa',
					oldPpm: 1000,
					newPpm: 1250,
					reason: 'DEPLETED_OUTBOUND'
				},
				{
					channelId: 'bb',
					oldPpm: 9000,
					newPpm: 10_000,
					reason: 'DEPLETED_OUTBOUND'
				}
			]);
		});

		it('nudges down 25% when idle, floored at floorPpm', function () {
			const adjustments = computeFeeTuneAdjustments(
				[
					{
						channelId: 'aa',
						currentPpm: 1000,
						localBalanceFraction: 0.5,
						outboundForwards: 0,
						totalForwards: 0
					},
					{
						channelId: 'bb',
						currentPpm: 2,
						localBalanceFraction: 0.5,
						outboundForwards: 0,
						totalForwards: 0
					}
				],
				{ floorPpm: 800, ceilPpm: 10_000 }
			);
			expect(adjustments).to.deep.equal([
				{ channelId: 'aa', oldPpm: 1000, newPpm: 800, reason: 'IDLE' },
				{ channelId: 'bb', oldPpm: 2, newPpm: 800, reason: 'IDLE' }
			]);
		});

		it('leaves healthy active channels and already-clamped values alone', function () {
			const adjustments = computeFeeTuneAdjustments(
				[
					// Active with plenty of outbound: no change
					{
						channelId: 'aa',
						currentPpm: 1000,
						localBalanceFraction: 0.6,
						outboundForwards: 5,
						totalForwards: 5
					},
					// Idle but already at the floor: no change emitted
					{
						channelId: 'bb',
						currentPpm: 1,
						localBalanceFraction: 0.5,
						outboundForwards: 0,
						totalForwards: 0
					},
					// Depleted at the ceiling: no change emitted
					{
						channelId: 'cc',
						currentPpm: 10_000,
						localBalanceFraction: 0.1,
						outboundForwards: 2,
						totalForwards: 2
					}
				],
				opts
			);
			expect(adjustments).to.deep.equal([]);
		});

		it('guarantees a minimum step of 1 ppm upward from tiny values', function () {
			const adjustments = computeFeeTuneAdjustments(
				[
					{
						channelId: 'aa',
						currentPpm: 0,
						localBalanceFraction: 0.05,
						outboundForwards: 1,
						totalForwards: 1
					}
				],
				opts
			);
			expect(adjustments[0].newPpm).to.equal(1);
		});
	});

	describe('rebalanceChannel (phase 1)', function () {
		it('3-node circular rebalance: A->B->C->A moves balance within the fee cap', async function () {
			const setup = setupCircular();
			const { alice, abChannelId, caChannelId } = setup;
			try {
				const abBefore = localMsat(alice, abChannelId);
				const caBefore = localMsat(alice, caChannelId);
				expect(caBefore).to.equal(0n);

				const result = await alice.rebalanceChannel({
					fromChannelId: abChannelId,
					toChannelId: caChannelId,
					amountSats: 100_000n,
					maxFeeSats: 10n
				});

				expect(result.amountMsat).to.equal(100_000_000n);
				expect(result.feeMsat > 0n, 'fee was paid').to.be.true;
				expect(result.feeMsat <= 10_000n, 'fee within cap').to.be.true;
				expect(result.hops).to.equal(3);

				const payment = alice.getPayment(result.paymentHash);
				expect(payment?.status).to.equal('COMPLETED');

				// The full loop settled: amount arrived on CA, amount+fee left AB.
				expect(localMsat(alice, caChannelId)).to.equal(caBefore + 100_000_000n);
				expect(localMsat(alice, abChannelId)).to.equal(
					abBefore - 100_000_000n - result.feeMsat
				);
			} finally {
				setup.destroy();
			}
		});

		it('2-node circular rebalance over two channels to the same peer', async function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);
			try {
				const ch1 = openReadyChannel(alice, bob); // alice all-local
				const ch2 = openReadyChannel(bob, alice); // alice all-remote
				const scid1 = encodeShortChannelId({
					block: 910,
					txIndex: 1,
					outputIndex: 0
				});
				const scid2 = encodeShortChannelId({
					block: 910,
					txIndex: 2,
					outputIndex: 0
				});
				setScidAlias(alice, ch1, scid1);
				setScidAlias(alice, ch2, scid2);
				bob.registerChannelScid(ch1, scid1);
				bob.registerChannelScid(ch2, scid2);

				const ch1Before = localMsat(alice, ch1);
				const result = await alice.rebalanceChannel({
					fromChannelId: ch1,
					toChannelId: ch2,
					amountSats: 50_000n,
					maxFeeSats: 5n
				});

				expect(result.hops).to.equal(2);
				// First hop was pinned to ch1 and the loop landed on ch2.
				expect(localMsat(alice, ch2)).to.equal(50_000_000n);
				expect(localMsat(alice, ch1)).to.equal(
					ch1Before - 50_000_000n - result.feeMsat
				);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});

		it('aborts on maxFeeSats BEFORE sending anything', async function () {
			const setup = setupCircular();
			const { alice, abChannelId, caChannelId } = setup;
			try {
				const abBefore = localMsat(alice, abChannelId);
				let error: Error | null = null;
				try {
					await alice.rebalanceChannel({
						fromChannelId: abChannelId,
						toChannelId: caChannelId,
						amountSats: 100_000n,
						maxFeeSats: 0n // route needs ~2 sats of fees
					});
				} catch (err) {
					error = err as Error;
				}
				expect(error, 'rebalance must throw').to.not.be.null;
				expect(error!.message).to.include('exceeds cap');
				// Nothing left the channel and no payment was even created.
				expect(localMsat(alice, abChannelId)).to.equal(abBefore);
				expect(localMsat(alice, caChannelId)).to.equal(0n);
				expect(
					alice.listPayments().filter((p) => p.status === 'PENDING')
				).to.deep.equal([]);
			} finally {
				setup.destroy();
			}
		});

		it('rejects unusable inputs', async function () {
			const setup = setupCircular();
			const { alice, abChannelId, caChannelId } = setup;
			try {
				const cases: Array<{
					opts: Parameters<LightningNode['rebalanceChannel']>[0];
					msg: string;
				}> = [
					{
						opts: {
							fromChannelId: abChannelId,
							toChannelId: abChannelId,
							amountSats: 1000n,
							maxFeeSats: 1n
						},
						msg: 'must differ'
					},
					{
						opts: {
							fromChannelId: abChannelId,
							toChannelId: caChannelId,
							amountSats: 0n,
							maxFeeSats: 1n
						},
						msg: 'amountSats'
					},
					{
						opts: {
							fromChannelId: crypto.randomBytes(32),
							toChannelId: caChannelId,
							amountSats: 1000n,
							maxFeeSats: 1n
						},
						msg: 'not found'
					},
					{
						opts: {
							fromChannelId: abChannelId,
							toChannelId: caChannelId,
							amountSats: 2_000_000n, // above channel balance
							maxFeeSats: 1n
						},
						msg: 'insufficient local balance'
					}
				];
				for (const { opts, msg } of cases) {
					let error: Error | null = null;
					try {
						await alice.rebalanceChannel(opts);
					} catch (err) {
						error = err as Error;
					}
					expect(error, `expected throw containing "${msg}"`).to.not.be.null;
					expect(error!.message).to.include(msg);
				}
			} finally {
				setup.destroy();
			}
		});
	});

	describe('executeRebalanceRecommendations (phase 1 budget)', function () {
		it('executes the advisor plan and persists the daily fee spend', async function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const setup = setupCircular(storage);
			const { alice, abChannelId, caChannelId } = setup;
			try {
				// AB is 100% local (donor), CA is 0% local (receiver).
				const plans = alice.planRebalanceRecommendations();
				expect(plans).to.have.length(1);
				expect(plans[0].fromChannelId).to.equal(abChannelId.toString('hex'));
				expect(plans[0].toChannelId).to.equal(caChannelId.toString('hex'));
				// Half the capacity (500k) clamped to one HTLC's carrying capacity:
				// 99% of the 500M msat max_htlc_value_in_flight (fee headroom).
				expect(plans[0].amountSats).to.equal(495_000n);

				const summary = await alice.executeRebalanceRecommendations({
					budgetSatsPerDay: 10
				});
				expect(summary.succeeded).to.equal(1);
				expect(summary.failed).to.equal(0);
				expect(summary.skippedBudget).to.equal(0);
				expect(summary.feeSpentMsat > 0n).to.be.true;
				expect(summary.budgetRemainingMsat).to.equal(
					10_000n - summary.feeSpentMsat
				);
				expect(localMsat(alice, caChannelId)).to.equal(495_000_000n);

				// Budget spend persisted (survives restart within the same day).
				const raw = storage.loadMetadata('advisor:rebalance-budget');
				expect(raw, 'metadata written').to.not.be.null;
				const parsed = JSON.parse(raw!) as {
					day: string;
					spentFeeMsat: string;
				};
				expect(parsed.day).to.equal(new Date().toISOString().slice(0, 10));
				expect(BigInt(parsed.spentFeeMsat)).to.equal(summary.feeSpentMsat);
			} finally {
				setup.destroy();
				storage.close();
			}
		});

		it('an exhausted budget stops execution without sending', async function () {
			const setup = setupCircular();
			const { alice, abChannelId, caChannelId } = setup;
			try {
				const abBefore = localMsat(alice, abChannelId);
				const summary = await alice.executeRebalanceRecommendations({
					budgetSatsPerDay: 0
				});
				expect(summary.succeeded).to.equal(0);
				expect(summary.skippedBudget).to.equal(1);
				expect(summary.attempts[0].status).to.equal('SKIPPED_BUDGET');
				expect(summary.feeSpentMsat).to.equal(0n);
				expect(summary.budgetRemainingMsat).to.equal(0n);
				expect(localMsat(alice, abChannelId)).to.equal(abBefore);
				expect(localMsat(alice, caChannelId)).to.equal(0n);
			} finally {
				setup.destroy();
			}
		});

		it('respects spend already persisted for the current UTC day', async function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const setup = setupCircular(storage);
			const { alice, abChannelId } = setup;
			try {
				// Simulate an earlier run today that consumed the whole budget.
				storage.saveMetadata(
					'advisor:rebalance-budget',
					JSON.stringify({
						day: new Date().toISOString().slice(0, 10),
						spentFeeMsat: '10000'
					})
				);
				const abBefore = localMsat(alice, abChannelId);
				const summary = await alice.executeRebalanceRecommendations({
					budgetSatsPerDay: 10
				});
				expect(summary.succeeded).to.equal(0);
				expect(summary.skippedBudget).to.equal(1);
				expect(summary.budgetRemainingMsat).to.equal(0n);
				expect(localMsat(alice, abChannelId)).to.equal(abBefore);
			} finally {
				setup.destroy();
				storage.close();
			}
		});
	});

	describe('runFeeTuneOnce (phase 2)', function () {
		const NOW = 1_800_000_000_000; // injected fake clock
		const WINDOW = 21_600_000; // default 6h interval = observation window

		interface ITuneSetup {
			alice: LightningNode;
			bob: LightningNode;
			storage: SqliteStorage;
			drained: Buffer; // alice local 0% (bob funded)
			full: Buffer; // alice local 100% (alice funded)
			destroy: () => void;
		}

		function setupTune(tuneConfig?: INodeConfig['autoTuneFees']): ITuneSetup {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const alice = createNode(1, { storage, autoTuneFees: tuneConfig });
			const bob = createNode(2);
			connectNodes(alice, bob);
			const full = openReadyChannel(alice, bob);
			const drained = openReadyChannel(bob, alice);
			return {
				alice,
				bob,
				storage,
				drained,
				full,
				destroy: (): void => {
					alice.destroy();
					bob.destroy();
					storage.close();
				}
			};
		}

		function seedForward(
			storage: SqliteStorage,
			inId: Buffer,
			outId: Buffer,
			settledAt: number
		): void {
			storage.saveForwardingEvent!({
				settledAt,
				inChannelId: inId.toString('hex'),
				outChannelId: outId.toString('hex'),
				amountInMsat: 1_001_000n,
				amountOutMsat: 1_000_000n,
				feeMsat: 1_000n
			});
		}

		it('nudges a depleted forwarding channel up 25% and applies the policy', function () {
			const setup = setupTune();
			const { alice, storage, drained, full } = setup;
			try {
				alice.setChannelPolicy(drained, { feeProportionalMillionths: 1000 });
				alice.setChannelPolicy(full, { feeProportionalMillionths: 1000 });
				// A forward went OUT over the drained channel inside the window;
				// its inbound leg keeps the full channel from counting as idle.
				seedForward(storage, full, drained, NOW - 1000);

				const adjustments = alice.runFeeTuneOnce(NOW);
				expect(adjustments).to.have.length(1);
				expect(adjustments[0]).to.deep.equal({
					channelId: drained.toString('hex'),
					oldPpm: 1000,
					newPpm: 1250,
					reason: 'DEPLETED_OUTBOUND'
				});
				expect(
					alice.getChannelPolicy(drained)!.feeProportionalMillionths
				).to.equal(1250);
				// The saturated channel forwarded too, so it is left alone.
				expect(
					alice.getChannelPolicy(full)!.feeProportionalMillionths
				).to.equal(1000);
			} finally {
				setup.destroy();
			}
		});

		it('nudges idle channels down 25%, ignoring forwards outside the window', function () {
			const setup = setupTune();
			const { alice, storage, drained, full } = setup;
			try {
				alice.setChannelPolicy('all', { feeProportionalMillionths: 1000 });
				// Only STALE activity (outside the 6h window) -- both count as idle.
				seedForward(storage, full, drained, NOW - WINDOW - 60_000);

				const adjustments = alice.runFeeTuneOnce(NOW);
				expect(adjustments).to.have.length(2);
				for (const adj of adjustments) {
					expect(adj.reason).to.equal('IDLE');
					expect(adj.oldPpm).to.equal(1000);
					expect(adj.newPpm).to.equal(750);
				}
			} finally {
				setup.destroy();
			}
		});

		it('clamps to configured floorPpm/ceilPpm', function () {
			const setup = setupTune({ enabled: false, floorPpm: 800, ceilPpm: 1100 });
			const { alice, storage, drained, full } = setup;
			try {
				alice.setChannelPolicy('all', { feeProportionalMillionths: 1000 });
				seedForward(storage, full, drained, NOW - 1000);

				const adjustments = alice.runFeeTuneOnce(NOW);
				const byId = new Map(adjustments.map((a) => [a.channelId, a]));
				// Up nudge 1000 -> 1250 clamps at ceil 1100.
				expect(byId.get(drained.toString('hex'))!.newPpm).to.equal(1100);
				// The full channel forwarded (inbound leg), so no down nudge here;
				// run again with no in-window forwards to exercise the floor.
				const later = alice.runFeeTuneOnce(NOW + WINDOW + 120_000);
				const laterById = new Map(later.map((a) => [a.channelId, a]));
				// Down nudge 1100 * 0.75 = 825 stays above floor; next pass clamps.
				expect(laterById.get(drained.toString('hex'))!.newPpm).to.equal(825);
				expect(laterById.get(full.toString('hex'))!.newPpm).to.equal(800);

				const final = alice.runFeeTuneOnce(NOW + 2 * (WINDOW + 120_000));
				const finalById = new Map(final.map((a) => [a.channelId, a]));
				expect(finalById.get(drained.toString('hex'))!.newPpm).to.equal(800);
				// Already at the floor: no adjustment emitted for the full channel.
				expect(finalById.has(full.toString('hex'))).to.be.false;
			} finally {
				setup.destroy();
			}
		});

		it('emits at most one adjustment per channel per pass', function () {
			const setup = setupTune();
			const { alice, storage, drained, full } = setup;
			try {
				alice.setChannelPolicy('all', { feeProportionalMillionths: 1000 });
				// Multiple forwards over the same drained channel in the window.
				seedForward(storage, full, drained, NOW - 1000);
				seedForward(storage, full, drained, NOW - 2000);
				seedForward(storage, full, drained, NOW - 3000);

				const adjustments = alice.runFeeTuneOnce(NOW);
				const ids = adjustments.map((a) => a.channelId);
				expect(new Set(ids).size).to.equal(ids.length);
				expect(
					alice.getChannelPolicy(drained)!.feeProportionalMillionths
				).to.equal(1250); // exactly one 25% step, not compounded
			} finally {
				setup.destroy();
			}
		});
	});

	describe('disabled by default', function () {
		interface ITimerPeek {
			autoRebalanceTimer: unknown;
			autoTuneFeesTimer: unknown;
		}

		it('starts NO advisor-execution timers unless explicitly enabled', function () {
			const node = createNode(7);
			try {
				const peek = node as unknown as ITimerPeek;
				expect(peek.autoRebalanceTimer).to.be.null;
				expect(peek.autoTuneFeesTimer).to.be.null;
			} finally {
				node.destroy();
			}
		});

		it('enabled: false explicitly also starts no timers', function () {
			const node = createNode(7, {
				autoRebalance: { enabled: false, budgetSatsPerDay: 100 },
				autoTuneFees: { enabled: false }
			});
			try {
				const peek = node as unknown as ITimerPeek;
				expect(peek.autoRebalanceTimer).to.be.null;
				expect(peek.autoTuneFeesTimer).to.be.null;
			} finally {
				node.destroy();
			}
		});

		it('enabled: true starts the timers and destroy() clears them', function () {
			const node = createNode(7, {
				autoRebalance: { enabled: true, budgetSatsPerDay: 100 },
				autoTuneFees: { enabled: true }
			});
			const peek = node as unknown as ITimerPeek;
			expect(peek.autoRebalanceTimer).to.not.be.null;
			expect(peek.autoTuneFeesTimer).to.not.be.null;
			node.destroy();
			expect(peek.autoRebalanceTimer).to.be.null;
			expect(peek.autoTuneFeesTimer).to.be.null;
		});
	});
});
