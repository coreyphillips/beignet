/**
 * Issue #2098, step 5: a forward with an asset leg whose channel goes to the
 * chain.
 *
 * Alice pays an invoice of Carol's through Bob, and Carol holds the HTLC.
 * Bob's channel with Alice is the incoming side of the forward and his
 * channel with Carol the outgoing side; either is an asset channel or an
 * ordinary one, which makes the three directions: bitcoin in and asset out,
 * asset in and bitcoin out, asset in and asset out. Every node follows one
 * test chain through its own watcher, and every spend is judged by it.
 */

import { expect } from 'chai';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import type {
	IAuxiliaryForwardLegResolution,
	IAuxiliaryForwardRequest,
	IAuxiliaryForwardTerms
} from '../../src/lightning/channel/auxiliary-forward';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import {
	ChannelState,
	HtlcState,
	isFixedAssetHtlcChannel,
	type IHtlcEntry
} from '../../src/lightning/channel/types';
import {
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import type { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	ASSET_FORWARD_FAIL_BACK_DEPTH,
	ASSET_FORWARD_MIN_CLTV_DELTA
} from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	FORWARD_CARRIER_MSAT,
	forwardChainWorld,
	forwardHeld,
	type ForwardChannelKind,
	type IForwardPayment,
	type IForwardWorld
} from './helpers/auxiliary-forward-world';
import { withAssetForwards, withAssetOpens } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	errorsOf,
	settle,
	trackedOutputs
} from './helpers/auxiliary-on-chain';
import { amountRecord } from './helpers/auxiliary-pair';
import type { IFixedOutputFeePolicy } from '../../src/lightning/wallet/fixed-output-fees';

/** What Alice sends Bob over an asset channel, and what Bob's host values each unit at. */
const INCOMING_UNITS = 5010n;
const MSAT_PER_UNIT = 1000n;
/** What Alice sends Bob over an ordinary channel. */
const INCOMING_MSAT = 5_100_000n;
/** The units Bob's host makes the outgoing asset HTLC carry, and what the onion asks Bob to forward. */
const OUTGOING_UNITS = 5000n;
const FORWARD_MSAT = 5_000_000n;
/** The delta of the quotes' hints, and the node's default policy. */
const CLTV_DELTA = 40;
/** How many blocks above the tip Bob's outgoing HTLC expires. */
const OUTGOING_DELTA = 60;
/** Where an asset leg's channel goes to the chain before its incoming expiry. */
const ASSET_INCOMING_MARGIN = 18;

type Shape = [ForwardChannelKind, ForwardChannelKind];
const SHAPES: Shape[] = [
	['ordinary', 'asset'],
	['asset', 'ordinary'],
	['asset', 'asset']
];
const ASSET_OUT: Shape[] = SHAPES.filter(([, out]) => out === 'asset');
const ASSET_IN: Shape[] = SHAPES.filter(([inKind]) => inKind === 'asset');
const named = ([inKind, outKind]: Shape): string =>
	inKind === 'ordinary'
		? 'bitcoin in, asset out'
		: outKind === 'ordinary'
		? 'asset in, bitcoin out'
		: 'asset in, asset out';

type Who = 'alice' | 'bob' | 'carol';

interface IScene {
	w: IForwardWorld;
	held: IForwardPayment;
	asked: IAuxiliaryForwardRequest[];
	told: IAuxiliaryForwardLegResolution[];
	/** Every channel a node took to the chain itself, as `who:channel`. */
	closed: string[];
	/** Bob's structured log, as `action: reason`. */
	logs: string[];
}

describe('a forward with an asset leg on the chain (issue #2098, step 5)', function () {
	this.timeout(240000);
	withAssetOpens();
	withAssetForwards();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	/** The terms of a host that values each incoming unit at MSAT_PER_UNIT and pays OUTGOING_UNITS out. */
	const termsOf =
		([inKind, outKind]: Shape) =>
		(request: IAuxiliaryForwardRequest): IAuxiliaryForwardTerms => ({
			...(inKind === 'asset'
				? {
						incomingValueMsat: request.incoming.auxiliaryAmount! * MSAT_PER_UNIT
				  }
				: {}),
			...(outKind === 'asset'
				? {
						outgoingHtlc: {
							customRecords: amountRecord(OUTGOING_UNITS),
							wireAmountMsat: FORWARD_CARRIER_MSAT
						}
				  }
				: {})
		});

	const valued = (incoming: {
		auxiliaryAmount?: bigint;
	}): bigint | undefined =>
		incoming.auxiliaryAmount === undefined
			? undefined
			: incoming.auxiliaryAmount * MSAT_PER_UNIT;

	const listen = (s: IScene): void => {
		const { w, closed, logs } = s;
		for (const name of ['alice', 'bob', 'carol'] as const) {
			w.hosts[name].node.removeAllListeners('channel:force-closing');
			w.hosts[name].node.on(
				'channel:force-closing',
				(event: { channelId: Buffer; initiator: 'local' | 'remote' }) => {
					if (event.initiator === 'local') {
						closed.push(`${name}:${event.channelId.toString('hex')}`);
					}
				}
			);
		}
		w.hosts.bob.node.on(
			'log',
			(log: { action: string; data: Record<string, unknown> }) => {
				logs.push(`${log.action}: ${String(log.data.reason ?? '')}`);
			}
		);
	};

	async function scene(
		tag: string,
		shape: Shape,
		options: {
			bob?: Partial<IAuxiliaryChannelConfig>;
			wrapBob?: (
				provider: IChannelAuxiliaryProvider
			) => IChannelAuxiliaryProvider;
			cltvDelta?: number;
			/** Bob's policy on the outgoing channel. */
			policyDelta?: number;
			/** Runs before Alice pays. */
			beforeSend?: (w: IForwardWorld) => void;
			/** Carol holds the HTLC; false when it is not to reach her. */
			held?: boolean;
			/** How many times Bob is asked; once unless said. */
			asked?: number;
		} = {}
	): Promise<IScene> {
		const asked: IAuxiliaryForwardRequest[] = [];
		const told: IAuxiliaryForwardLegResolution[] = [];
		const terms = termsOf(shape);
		const w = await world.open(tag, {
			kinds: { in: shape[0], out: shape[1] },
			feeWallet: { alice: true, bob: true, carol: true },
			...(options.wrapBob ? { wrapProvider: { bob: options.wrapBob } } : {}),
			hooks: {
				alice: { valueIncomingHtlc: valued },
				bob: {
					prepareForward: (request): IAuxiliaryForwardTerms => {
						asked.push(request);
						return terms(request);
					},
					onForwardLegResolved: (resolution): void => {
						told.push(resolution);
					},
					...options.bob
				},
				carol: { valueIncomingHtlc: valued }
			}
		});
		// Two coins each: a commitment's child takes one, an HTLC spend another.
		for (const name of ['alice', 'bob', 'carol'] as const) {
			w.wallets[name]!.fund(100_000);
			w.wallets[name]!.fund(100_000);
		}
		await world.mine(w, 1);
		if (options.policyDelta !== undefined) {
			w.hosts.bob.node.setChannelPolicy(w.outChannel, {
				cltvExpiryDelta: options.policyDelta
			});
		}
		const s: IScene = {
			w,
			held: undefined as unknown as IForwardPayment,
			asked,
			told,
			closed: [],
			logs: []
		};
		listen(s);
		options.beforeSend?.(w);
		const next = w.hosts.bob.node
			.getChannelManager()
			.getChannel(w.outChannel)!
			.getFullState().scidAlias!;
		s.held = await forwardHeld(w, tag, {
			next,
			forwardMsat: FORWARD_MSAT,
			outgoingDelta: OUTGOING_DELTA,
			cltvDelta: options.cltvDelta ?? CLTV_DELTA,
			units: INCOMING_UNITS,
			incomingMsat: INCOMING_MSAT,
			held: options.held
		});
		expect(asked.length, 'how often Bob is asked').to.equal(options.asked ?? 1);
		return s;
	}

	const describeOutputs = (
		w: IForwardWorld,
		who: Who,
		channelId: Buffer
	): string =>
		trackedOutputs(w.hosts[who], channelId)
			.map(
				(output) =>
					`${output.outputType}${output.isSecondLevelHtlc ? '/2nd' : ''}:${
						output.status
					}@${output.confirmationHeight}${
						output.auxiliaryFeeWait
							? `(wait ${output.auxiliaryFeeWait.code})`
							: ''
					}${output.spendReverifyPending ? '(reverify)' : ''}`
			)
			.join(',');

	const until = async (
		w: IForwardWorld,
		what: string,
		reached: () => boolean,
		most = 80
	): Promise<void> => {
		for (let i = 0; i < most && !reached(); i++) await world.mine(w, 1);
		if (!reached()) {
			throw new Error(
				`never reached: ${what} at ${
					w.chain.height
				}; bob out [${describeOutputs(
					w,
					'bob',
					w.outChannel
				)}] bob in [${describeOutputs(
					w,
					'bob',
					w.inChannel
				)}]; alice: ${errorsOf(w.hosts.alice).join(' | ')}; bob: ${errorsOf(
					w.hosts.bob
				).join(' | ')}; carol: ${errorsOf(w.hosts.carol).join(' | ')}`
			);
		}
	};

	const stateOf = (
		w: IForwardWorld,
		who: Who,
		channelId: Buffer
	): ChannelState | undefined =>
		w.hosts[who].node.getChannelManager().getChannel(channelId)?.getState();

	const paymentOf = (s: IScene): PaymentStatus | undefined =>
		s.w.hosts.alice.node.getPayment(s.held.paymentHash)?.status;

	/** Bob's first-level output of the forward's outgoing HTLC. */
	const offeredOf = (w: IForwardWorld): ITrackedOutput | undefined =>
		trackedOutputs(w.hosts.bob, w.outChannel).find(
			(output) =>
				output.outputType === OutputType.OFFERED_HTLC &&
				!output.isSecondLevelHtlc
		);
	/** Bob's first-level output of the forward's incoming HTLC. */
	const receivedOf = (w: IForwardWorld): ITrackedOutput | undefined =>
		trackedOutputs(w.hosts.bob, w.inChannel).find(
			(output) =>
				output.outputType === OutputType.RECEIVED_HTLC &&
				!output.isSecondLevelHtlc
		);
	const spentAt = (
		output: { status: OutputStatus; confirmationHeight: number } | undefined
	): number | undefined =>
		output &&
		(output.status === OutputStatus.SPEND_CONFIRMED ||
			output.status === OutputStatus.IRREVOCABLY_RESOLVED)
			? output.confirmationHeight
			: undefined;

	/** Bob's entries of the forward's incoming HTLC, as his row of the incoming channel has them. */
	const incomingEntries = (s: IScene): IHtlcEntry[] =>
		[
			...s.w.hosts.bob.node
				.getChannelManager()
				.getChannel(s.w.inChannel)!
				.getFullState()
				.htlcs.values()
		].filter((entry) => entry.paymentHash.equals(s.held.paymentHash));

	const bobClosed = (s: IScene, channelId: Buffer): boolean =>
		s.closed.includes(`bob:${channelId.toString('hex')}`);

	/**
	 * After the outgoing leg failed on the chain: the incoming leg is failed
	 * back in its channel within a block or two of the fail back depth, long
	 * before its own deadline, and that channel stays open.
	 */
	const expectFailedBackInChannel = async (
		s: IScene,
		failedAt: number
	): Promise<void> => {
		const { w } = s;
		await until(
			w,
			"Alice's payment failed",
			() => paymentOf(s) === PaymentStatus.FAILED,
			ASSET_FORWARD_FAIL_BACK_DEPTH + 6
		);
		expect(w.chain.height - failedAt).to.be.at.least(
			ASSET_FORWARD_FAIL_BACK_DEPTH
		);
		expect(w.chain.height - failedAt).to.be.at.most(
			ASSET_FORWARD_FAIL_BACK_DEPTH + 2
		);
		expect(w.chain.height).to.be.lessThan(
			s.held.incomingExpiry - ASSET_INCOMING_MARGIN
		);
		await world.mine(w, 2);
		expect(stateOf(w, 'bob', w.inChannel)).to.equal(ChannelState.NORMAL);
		expect(stateOf(w, 'alice', w.inChannel)).to.equal(ChannelState.NORMAL);
		expect(bobClosed(s, w.inChannel)).to.equal(false);
		expect(incomingEntries(s)).to.deep.equal([]);
	};

	describe('the outgoing leg times out on the chain', () => {
		for (const shape of SHAPES) {
			it(`${named(
				shape
			)}: Bob takes the outgoing channel to the chain, and once his timeout spend is ${ASSET_FORWARD_FAIL_BACK_DEPTH} blocks deep with no preimage the incoming leg is failed back in its channel, which stays open`, async () => {
				const s = await scene(`fwd-timeout-bob-${shape.join('-')}`, shape);
				const { w, held } = s;
				const closedOut = w.hosts.bob.node.forceCloseChannel(
					w.outChannel,
					SWEEP_DESTINATION
				);
				expect(closedOut.ok, closedOut.error).to.equal(true);
				await world.mine(w, 1);
				await world.passTo(w, held.outgoingExpiry - 1);
				await until(
					w,
					"Bob's timeout spend in a block",
					() => spentAt(offeredOf(w)) !== undefined
				);
				const timedOutAt = spentAt(offeredOf(w))!;
				expect(timedOutAt).to.be.at.least(held.outgoingExpiry);
				await expectFailedBackInChannel(s, timedOutAt);
			});

			it(`${named(
				shape
			)}: Carol takes the outgoing channel to the chain, Bob times the HTLC out on her commitment, and ${ASSET_FORWARD_FAIL_BACK_DEPTH} blocks on the incoming leg is failed back`, async () => {
				const s = await scene(`fwd-timeout-carol-${shape.join('-')}`, shape);
				const { w, held } = s;
				const closedOut = w.hosts.carol.node.forceCloseChannel(
					w.outChannel,
					SWEEP_DESTINATION
				);
				expect(closedOut.ok, closedOut.error).to.equal(true);
				await world.mine(w, 1);
				await world.passTo(w, held.outgoingExpiry - 1);
				await until(
					w,
					"Bob's timeout of the HTLC on Carol's commitment",
					() => spentAt(offeredOf(w)) !== undefined
				);
				await expectFailedBackInChannel(s, spentAt(offeredOf(w))!);
			});
		}

		for (const shape of ASSET_OUT) {
			it(`${named(
				shape
			)}: the outgoing HTLC never reached Carol, and once Bob's commitment without it is ${ASSET_FORWARD_FAIL_BACK_DEPTH} blocks deep the incoming leg is failed back`, async () => {
				const s = await scene(`fwd-absent-${shape.join('-')}`, shape, {
					beforeSend: (w) => world.silence(w, 'out'),
					held: false
				});
				const { w } = s;
				const offered = [
					...w.hosts.bob.node
						.getChannelManager()
						.getChannel(w.outChannel)!
						.getFullState()
						.htlcs.values()
				].filter((entry) => entry.paymentHash.equals(s.held.paymentHash));
				expect(offered.length, 'Bob offered the HTLC').to.equal(1);
				const closedOut = w.hosts.bob.node.forceCloseChannel(
					w.outChannel,
					SWEEP_DESTINATION
				);
				expect(closedOut.ok, closedOut.error).to.equal(true);
				await world.mine(w, 1);
				const commitment = trackedOutputs(w.hosts.bob, w.outChannel)[0];
				expect(commitment, 'the commitment is in a block').to.not.equal(
					undefined
				);
				expect(offeredOf(w), 'no output carries the HTLC').to.equal(undefined);
				await expectFailedBackInChannel(s, commitment.confirmationHeight);
			});
		}

		it(`asset in, asset out: Bob is restarted while his timeout spend is 2 blocks deep, and the incoming leg is failed back only once his watch has reported the spend again in this session, however deep its stored height`, async () => {
			const shape: Shape = ['asset', 'asset'];
			const s = await scene('fwd-timeout-restart', shape);
			const { w, held } = s;
			const closedOut = w.hosts.bob.node.forceCloseChannel(
				w.outChannel,
				SWEEP_DESTINATION
			);
			expect(closedOut.ok, closedOut.error).to.equal(true);
			await world.mine(w, 1);
			await world.passTo(w, held.outgoingExpiry - 1);
			await until(
				w,
				"Bob's timeout spend in a block",
				() => spentAt(offeredOf(w)) !== undefined
			);
			const timedOutAt = spentAt(offeredOf(w))!;
			await world.mine(w, 2);
			await world.restartBob(w, 'fwd-timeout-restart');
			listen(s);
			// The stored height of the spend is not taken as depth until this
			// session's watch reports the spend again, which its recheck does
			// (every minute, and on any block that touches the output).
			await world.passTo(w, timedOutAt + ASSET_FORWARD_FAIL_BACK_DEPTH + 2);
			await world.mine(w, 1);
			expect(paymentOf(s)).to.equal(PaymentStatus.PENDING);
			expect(offeredOf(w)!.spendReverifyPending).to.equal(true);
			w.hosts.bob.node.getChainWatcher()!.recheckAllWatches();
			await settle();
			expect(offeredOf(w)!.spendReverifyPending).to.equal(undefined);
			await until(
				w,
				"Alice's payment failed",
				() => paymentOf(s) === PaymentStatus.FAILED,
				2
			);
			expect(w.chain.height).to.be.lessThan(
				held.incomingExpiry - ASSET_INCOMING_MARGIN
			);
			await world.mine(w, 2);
			expect(stateOf(w, 'bob', w.inChannel)).to.equal(ChannelState.NORMAL);
			expect(bobClosed(s, w.inChannel)).to.equal(false);
			expect(incomingEntries(s)).to.deep.equal([]);
		});
	});

	describe('the preimage learned downstream', () => {
		for (const shape of SHAPES) {
			for (const closer of ['bob', 'carol'] as const) {
				it(`${named(shape)}: ${
					closer === 'bob' ? 'Bob' : 'Carol'
				} takes the outgoing channel to the chain after Carol settled out of Bob's hearing, Carol claims the HTLC there with the preimage, and Bob settles the incoming leg in its channel`, async () => {
					const s = await scene(
						`fwd-claimed-${closer}-${shape.join('-')}`,
						shape
					);
					const { w, held } = s;
					// Carol settles, and her fulfil never reaches Bob: the channel
					// then goes to the chain, where she claims with the preimage.
					world.silence(w, 'out');
					expect(
						w.hosts.carol.node.settleHeldHtlc(held.paymentHash, held.preimage)
					).to.equal(true);
					await settle();
					const closedOut = w.hosts[closer].node.forceCloseChannel(
						w.outChannel,
						SWEEP_DESTINATION
					);
					expect(closedOut.ok, closedOut.error).to.equal(true);
					await world.mine(w, 1);
					await until(
						w,
						"Alice's payment completed",
						() => paymentOf(s) === PaymentStatus.COMPLETED,
						30
					);
					expect(w.chain.height).to.be.lessThan(held.outgoingExpiry);
					expect(stateOf(w, 'bob', w.inChannel)).to.equal(ChannelState.NORMAL);
					expect(bobClosed(s, w.inChannel)).to.equal(false);
					expect(incomingEntries(s)).to.deep.equal([]);
				});
			}
		}
	});

	describe('the incoming channel on the chain', () => {
		for (const shape of SHAPES) {
			for (const closer of ['alice', 'bob'] as const) {
				it(`${named(shape)}: ${
					closer === 'alice' ? 'Alice' : 'Bob'
				} takes the incoming channel to the chain with the forward in flight, Carol settles, and Bob claims the incoming HTLC there with the preimage`, async () => {
					const s = await scene(
						`fwd-in-chain-${closer}-${shape.join('-')}`,
						shape
					);
					const { w, held } = s;
					const closedIn = w.hosts[closer].node.forceCloseChannel(
						w.inChannel,
						SWEEP_DESTINATION
					);
					expect(closedIn.ok, closedIn.error).to.equal(true);
					await world.mine(w, 2);
					expect(
						w.hosts.carol.node.settleHeldHtlc(held.paymentHash, held.preimage)
					).to.equal(true);
					await settle();
					await until(
						w,
						"Bob's claim of the incoming HTLC in a block",
						() => spentAt(receivedOf(w)) !== undefined
					);
					expect(spentAt(receivedOf(w))!).to.be.lessThan(held.incomingExpiry);
					await until(
						w,
						"Alice's payment completed",
						() => paymentOf(s) === PaymentStatus.COMPLETED,
						20
					);
					// Carol was paid in her channel, which stays open.
					expect(stateOf(w, 'carol', w.outChannel)).to.equal(
						ChannelState.NORMAL
					);
				});
			}
		}
	});

	describe('the incoming deadline of an asset leg', () => {
		for (const shape of ASSET_IN) {
			it(`${named(
				shape
			)}: Alice is away and the outgoing leg unresolved, so Bob takes the incoming channel to the chain ${ASSET_INCOMING_MARGIN} blocks before its expiry`, async () => {
				const s = await scene(`fwd-away-${shape.join('-')}`, shape);
				const { w, held } = s;
				world.cut(w, 'in');
				await world.passTo(w, held.incomingExpiry - ASSET_INCOMING_MARGIN - 2);
				expect(bobClosed(s, w.inChannel)).to.equal(false);
				await until(w, 'Bob closes the incoming channel', () =>
					bobClosed(s, w.inChannel)
				);
				expect(w.chain.height).to.equal(
					held.incomingExpiry - ASSET_INCOMING_MARGIN
				);
			});

			it(`${named(
				shape
			)}: a shutdown of the incoming channel is under way with the outgoing leg unresolved, so Bob takes it to the chain ${ASSET_INCOMING_MARGIN} blocks before the expiry`, async () => {
				const s = await scene(`fwd-shutdown-${shape.join('-')}`, shape);
				const { w, held } = s;
				w.hosts.alice.node.closeChannel(w.inChannel, SWEEP_DESTINATION);
				for (let i = 0; i < 3; i++) await settle();
				expect(stateOf(w, 'bob', w.inChannel)).to.equal(
					ChannelState.SHUTTING_DOWN
				);
				await world.passTo(w, held.incomingExpiry - ASSET_INCOMING_MARGIN - 2);
				expect(bobClosed(s, w.inChannel)).to.equal(false);
				await until(w, 'Bob closes the incoming channel', () =>
					bobClosed(s, w.inChannel)
				);
				expect(w.chain.height).to.equal(
					held.incomingExpiry - ASSET_INCOMING_MARGIN
				);
			});

			it(`${named(
				shape
			)}: Bob's provider refuses the fulfil upstream after Carol settled, so Bob takes the incoming channel to the chain ${ASSET_INCOMING_MARGIN} blocks before its expiry and claims the HTLC there`, async () => {
				const arm = { down: false };
				const s = await scene(`fwd-refused-${shape.join('-')}`, shape, {
					wrapBob: (provider) =>
						({
							...provider,
							buildCommitment: (...args: unknown[]): unknown => {
								if (arm.down)
									throw new Error('provider down in buildCommitment');
								return (
									provider.buildCommitment as (...a: unknown[]) => unknown
								)(...args);
							}
						}) as IChannelAuxiliaryProvider
				});
				const { w, held } = s;
				// Carol's fulfil reaches Bob, who learns the preimage from it; his
				// provider cannot build the commitment that would carry the
				// settlement to Alice.
				arm.down = true;
				expect(
					w.hosts.carol.node.settleHeldHtlc(held.paymentHash, held.preimage)
				).to.equal(true);
				for (let i = 0; i < 4; i++) await settle();
				expect(
					incomingEntries(s).map((entry) => entry.state),
					'the incoming HTLC is not settled'
				).to.deep.equal([HtlcState.COMMITTED]);
				await world.passTo(w, held.incomingExpiry - ASSET_INCOMING_MARGIN - 2);
				expect(bobClosed(s, w.inChannel)).to.equal(false);
				await until(w, 'Bob closes the incoming channel', () =>
					bobClosed(s, w.inChannel)
				);
				expect(w.chain.height).to.equal(
					held.incomingExpiry - ASSET_INCOMING_MARGIN
				);
				arm.down = false;
				await until(
					w,
					"Bob's claim of the incoming HTLC in a block",
					() => spentAt(receivedOf(w)) !== undefined
				);
				expect(spentAt(receivedOf(w))!).to.be.lessThan(held.incomingExpiry);
			});
		}
	});

	describe('the expiry delta of a forward with an asset leg', () => {
		for (const shape of SHAPES) {
			it(`${named(shape)}: with Bob's policy at 20 blocks, a forward with ${
				ASSET_FORWARD_MIN_CLTV_DELTA - 10
			} blocks between its expiries is refused with incorrect_cltv_expiry before Bob's host is asked`, async () => {
				const s = await scene(`fwd-delta-${shape.join('-')}`, shape, {
					policyDelta: 20,
					cltvDelta: ASSET_FORWARD_MIN_CLTV_DELTA - 10,
					held: false,
					asked: 0
				});
				expect(paymentOf(s)).to.equal(PaymentStatus.FAILED);
				expect(s.logs).to.include(
					`asset_forward_declined: the expiry delta ${
						ASSET_FORWARD_MIN_CLTV_DELTA - 10
					} is under ${ASSET_FORWARD_MIN_CLTV_DELTA}`
				);
			});
		}
	});

	describe('the fail back at depth, read off the monitor', () => {
		/**
		 * A forward whose outgoing leg Bob has timed out on the chain, the spend
		 * as deep as it is, and the predicate asked directly with the monitor's
		 * records as a test sets them.
		 */
		const timedOut = async (
			tag: string
		): Promise<{
			s: IScene;
			outKey: string;
			failed: () => boolean;
			monitor: ChainMonitor;
		}> => {
			const s = await scene(tag, ['asset', 'asset']);
			const { w, held } = s;
			// Bob does not drive the fail back himself: the test asks.
			const node = w.hosts.bob.node as unknown as {
				settleForwardsOwedUpstream: (id: Buffer) => void;
				isOutgoingLegTerminallyFailed: (
					outKey: string,
					hash: Buffer
				) => boolean;
				forwardedHtlcs: Map<string, unknown>;
			};
			node.settleForwardsOwedUpstream = (): void => undefined;
			const closedOut = w.hosts.bob.node.forceCloseChannel(
				w.outChannel,
				SWEEP_DESTINATION
			);
			expect(closedOut.ok, closedOut.error).to.equal(true);
			await world.mine(w, 1);
			await world.passTo(w, held.outgoingExpiry - 1);
			await until(
				w,
				"Bob's timeout spend in a block",
				() => spentAt(offeredOf(w)) !== undefined
			);
			const outKey = [...node.forwardedHtlcs.keys()][0];
			return {
				s,
				outKey,
				failed: () =>
					node.isOutgoingLegTerminallyFailed(outKey, held.paymentHash),
				monitor: w.hosts.bob.node.getChannelManager().getMonitor(w.outChannel)!
			};
		};
		const ownOutput = (
			monitor: ChainMonitor
		): {
			outputType: OutputType;
			isSecondLevelHtlc?: boolean;
			spendReverifyPending?: boolean;
			resolutionTxHex?: string;
		} =>
			(
				monitor as unknown as {
					_trackedOutputs: Array<{
						outputType: OutputType;
						isSecondLevelHtlc?: boolean;
						spendReverifyPending?: boolean;
						resolutionTxHex?: string;
					}>;
				}
			)._trackedOutputs.find(
				(output) =>
					output.outputType === OutputType.OFFERED_HTLC &&
					!output.isSecondLevelHtlc
			)!;

		it(`answers no at ${
			ASSET_FORWARD_FAIL_BACK_DEPTH - 1
		} blocks and yes at ${ASSET_FORWARD_FAIL_BACK_DEPTH}`, async () => {
			const { s, failed } = await timedOut('fwd-depth');
			const at = spentAt(offeredOf(s.w))!;
			await world.passTo(s.w, at + ASSET_FORWARD_FAIL_BACK_DEPTH - 1);
			expect(failed()).to.equal(false);
			await world.mine(s.w, 1);
			expect(failed()).to.equal(true);
		});

		it('answers no while the spend has not been reported again in this session (a restart), however deep its stored height', async () => {
			const { s, failed, monitor } = await timedOut('fwd-reverify');
			const at = spentAt(offeredOf(s.w))!;
			await world.passTo(s.w, at + ASSET_FORWARD_FAIL_BACK_DEPTH + 2);
			expect(failed()).to.equal(true);
			ownOutput(monitor).spendReverifyPending = true;
			expect(failed()).to.equal(false);
		});

		it('answers no for a spend whose witness shows the preimage, and for one the monitor no longer holds the transaction of', async () => {
			const { s, failed, monitor } = await timedOut('fwd-shows');
			const at = spentAt(offeredOf(s.w))!;
			await world.passTo(s.w, at + ASSET_FORWARD_FAIL_BACK_DEPTH + 2);
			expect(failed()).to.equal(true);
			const output = ownOutput(monitor);
			const kept = output.resolutionTxHex;
			delete output.resolutionTxHex;
			expect(failed(), 'a spend not held proves nothing').to.equal(false);
			output.resolutionTxHex = kept;
			(
				monitor as unknown as {
					_spendShowsPreimage: () => boolean;
				}
			)._spendShowsPreimage = (): boolean => true;
			expect(failed(), 'a spend that shows the preimage').to.equal(false);
		});

		it('answers no for a commitment without the HTLC whose height this session has not seen reported again', async () => {
			const s = await scene('fwd-absent-restored', ['asset', 'asset'], {
				beforeSend: (w) => world.silence(w, 'out'),
				held: false
			});
			const { w, held } = s;
			const node = w.hosts.bob.node as unknown as {
				isOutgoingLegTerminallyFailed: (
					outKey: string,
					hash: Buffer
				) => boolean;
				forwardedHtlcs: Map<string, unknown>;
				settleForwardsOwedUpstream: (id: Buffer) => void;
			};
			node.settleForwardsOwedUpstream = (): void => undefined;
			const closedOut = w.hosts.bob.node.forceCloseChannel(
				w.outChannel,
				SWEEP_DESTINATION
			);
			expect(closedOut.ok, closedOut.error).to.equal(true);
			await world.mine(w, ASSET_FORWARD_FAIL_BACK_DEPTH + 2);
			const outKey = [...node.forwardedHtlcs.keys()][0];
			expect(
				node.isOutgoingLegTerminallyFailed(outKey, held.paymentHash)
			).to.equal(true);
			const monitor = w.hosts.bob.node
				.getChannelManager()
				.getMonitor(w.outChannel)!;
			(
				monitor as unknown as { _commitmentDepthUnverified: boolean }
			)._commitmentDepthUnverified = true;
			expect(
				node.isOutgoingLegTerminallyFailed(outKey, held.paymentHash)
			).to.equal(false);
		});
	});

	describe("each leg's end, told to the host", () => {
		/** The ends Bob's host was told, as `leg:outcome`, with `:chain` for one that ended there. */
		const endsOf = (s: IScene): string[] =>
			s.told
				.map((end) => `${end.leg}:${end.outcome}${end.onChain ? ':chain' : ''}`)
				.sort();
		const linksOf = (w: IForwardWorld): number =>
			w.hosts.bob.storage!.loadAllForwardedHtlcs().length;

		for (const shape of SHAPES) {
			it(`${named(
				shape
			)}: the outgoing leg timed out on the chain is told failed there once its spend is irrevocable, and the incoming leg failed in its channel, each once`, async () => {
				const s = await scene(`fwd-ends-timeout-${shape.join('-')}`, shape);
				const { w, held } = s;
				const closedOut = w.hosts.bob.node.forceCloseChannel(
					w.outChannel,
					SWEEP_DESTINATION
				);
				expect(closedOut.ok, closedOut.error).to.equal(true);
				await world.mine(w, 1);
				await world.passTo(w, held.outgoingExpiry - 1);
				await until(
					w,
					"Bob's timeout spend in a block",
					() => spentAt(offeredOf(w)) !== undefined
				);
				const timedOutAt = spentAt(offeredOf(w))!;
				await until(
					w,
					"Alice's payment failed",
					() => paymentOf(s) === PaymentStatus.FAILED,
					ASSET_FORWARD_FAIL_BACK_DEPTH + 6
				);
				await world.mine(w, 2);
				expect(endsOf(s)).to.deep.equal(['incoming:failed']);
				await world.passTo(w, timedOutAt + IRREVOCABLE_DEPTH - 1);
				await until(w, "the outgoing leg's end", () => s.told.length === 2, 6);
				expect(endsOf(s)).to.deep.equal([
					'incoming:failed',
					'outgoing:failed:chain'
				]);
				const outgoing = s.told.find((end) => end.leg === 'outgoing')!;
				expect(outgoing.channelId?.equals(w.outChannel)).to.equal(true);
				expect(outgoing.incomingChannelId.equals(w.inChannel)).to.equal(true);
				expect(outgoing.auxiliaryAmount).to.equal(
					shape[1] === 'asset' ? OUTGOING_UNITS : undefined
				);
				await world.mine(w, 3);
				expect(s.told).to.have.length(2);
			});

			it(`${named(
				shape
			)}: the incoming leg Bob claimed on the chain is told fulfilled there once his claim is irrevocable, the outgoing leg fulfilled in its channel, and the link goes`, async () => {
				const s = await scene(`fwd-ends-claim-${shape.join('-')}`, shape);
				const { w, held } = s;
				const closedIn = w.hosts.alice.node.forceCloseChannel(
					w.inChannel,
					SWEEP_DESTINATION
				);
				expect(closedIn.ok, closedIn.error).to.equal(true);
				await world.mine(w, 2);
				expect(
					w.hosts.carol.node.settleHeldHtlc(held.paymentHash, held.preimage)
				).to.equal(true);
				await settle();
				await until(
					w,
					"Bob's claim of the incoming HTLC in a block",
					() => spentAt(receivedOf(w)) !== undefined
				);
				const claimedAt = spentAt(receivedOf(w))!;
				expect(endsOf(s)).to.deep.equal(['outgoing:fulfilled']);
				await world.passTo(w, claimedAt + IRREVOCABLE_DEPTH - 1);
				await until(w, "the incoming leg's end", () => s.told.length === 2, 6);
				expect(endsOf(s)).to.deep.equal([
					'incoming:fulfilled:chain',
					'outgoing:fulfilled'
				]);
				const incoming = s.told.find((end) => end.leg === 'incoming')!;
				expect(incoming.auxiliaryAmount).to.equal(
					shape[0] === 'asset' ? INCOMING_UNITS : undefined
				);
				await world.mine(w, 2);
				expect(linksOf(w)).to.equal(0);
				expect(s.told).to.have.length(2);
			});

			it(`${named(
				shape
			)}: the outgoing leg Carol claimed on the chain is told fulfilled there once her claim is irrevocable, and the incoming leg fulfilled in its channel`, async () => {
				const s = await scene(`fwd-ends-carol-${shape.join('-')}`, shape);
				const { w, held } = s;
				world.silence(w, 'out');
				expect(
					w.hosts.carol.node.settleHeldHtlc(held.paymentHash, held.preimage)
				).to.equal(true);
				await settle();
				const closedOut = w.hosts.carol.node.forceCloseChannel(
					w.outChannel,
					SWEEP_DESTINATION
				);
				expect(closedOut.ok, closedOut.error).to.equal(true);
				await until(
					w,
					"Alice's payment completed",
					() => paymentOf(s) === PaymentStatus.COMPLETED,
					30
				);
				await until(
					w,
					"Carol's claim in a block",
					() => spentAt(offeredOf(w)) !== undefined
				);
				const claimedAt = spentAt(offeredOf(w))!;
				expect(endsOf(s)).to.deep.equal(['incoming:fulfilled']);
				await world.passTo(w, claimedAt + IRREVOCABLE_DEPTH - 1);
				await until(w, "the outgoing leg's end", () => s.told.length === 2, 6);
				expect(endsOf(s)).to.deep.equal([
					'incoming:fulfilled',
					'outgoing:fulfilled:chain'
				]);
			});
		}

		it('a host whose call throws is told again on the next block and after a restart, until a call returns, and each end once', async () => {
			let refuse = 3;
			const taken: IAuxiliaryForwardLegResolution[] = [];
			const s = await scene('fwd-ends-throws', ['asset', 'asset'], {
				bob: {
					onForwardLegResolved: (resolution): void => {
						if (refuse > 0) {
							refuse--;
							throw new Error('host busy');
						}
						taken.push(resolution);
					}
				}
			});
			const { w, held } = s;
			expect(
				w.hosts.carol.node.settleHeldHtlc(held.paymentHash, held.preimage)
			).to.equal(true);
			for (let i = 0; i < 4; i++) await settle();
			expect(paymentOf(s)).to.equal(PaymentStatus.COMPLETED);
			expect(taken).to.deep.equal([]);
			const held1 = (channelId: Buffer): number =>
				w.hosts.bob.node
					.getChannelManager()
					.getChannel(channelId)!
					.getFullState().forwardLegEnds?.size ?? 0;
			expect(held1(w.inChannel) + held1(w.outChannel)).to.be.greaterThan(0);
			// One more refusal is left for the restarted node to meet.
			await world.mine(w, 1);
			await world.restartBob(w, 'fwd-ends-throws', {
				hooks: {
					prepareForward: (): undefined => undefined,
					onForwardLegResolved: (
						resolution: IAuxiliaryForwardLegResolution
					): void => {
						if (refuse > 0) {
							refuse--;
							throw new Error('host busy');
						}
						taken.push(resolution);
					}
				}
			});
			for (let i = 0; i < 3; i++) await world.mine(w, 1);
			expect(
				taken.map((end) => `${end.leg}:${end.outcome}`).sort()
			).to.deep.equal(['incoming:fulfilled', 'outgoing:fulfilled']);
			const rows = (channelId: Buffer): number =>
				w.hosts.bob.storage!.loadChannel(channelId.toString('hex'))?.state
					.forwardLegEnds?.size ?? 0;
			expect(rows(w.inChannel) + rows(w.outChannel)).to.equal(0);
		});

		it('a host without onForwardLegResolved is kept nothing: no mark on the HTLCs and no end in any row', async () => {
			const s = await scene('fwd-ends-no-hook', ['asset', 'asset'], {
				bob: { onForwardLegResolved: undefined }
			});
			const { w, held } = s;
			const marks = (): string[] =>
				[w.inChannel, w.outChannel].flatMap((channelId) =>
					[
						...w.hosts.bob.node
							.getChannelManager()
							.getChannel(channelId)!
							.getFullState()
							.htlcs.values()
					].flatMap((entry) => [
						...(entry.forwardTaken ? ['taken'] : []),
						...(entry.forwardOf ? ['of'] : [])
					])
				);
			expect(marks()).to.deep.equal([]);
			expect(
				w.hosts.carol.node.settleHeldHtlc(held.paymentHash, held.preimage)
			).to.equal(true);
			for (let i = 0; i < 4; i++) await settle();
			expect(paymentOf(s)).to.equal(PaymentStatus.COMPLETED);
			for (const channelId of [w.inChannel, w.outChannel]) {
				expect(
					w.hosts.bob.storage!.loadChannel(channelId.toString('hex'))?.state
						.forwardLegEnds
				).to.equal(undefined);
			}
			expect(s.told).to.deep.equal([]);
		});

		it('a channel holding as many ends its host has not taken as the node keeps for one takes no forward with an asset leg, and its host is not asked', async () => {
			const asked: IAuxiliaryForwardRequest[] = [];
			const w = await world.open('fwd-ends-bound', {
				kinds: { in: 'asset', out: 'asset' },
				hooks: {
					bob: {
						prepareForward: (request): IAuxiliaryForwardTerms => {
							asked.push(request);
							return termsOf(['asset', 'asset'])(request);
						},
						onForwardLegResolved: (): void => {
							throw new Error('host down');
						}
					},
					carol: { valueIncomingHtlc: valued }
				}
			});
			const state = w.hosts.bob.node
				.getChannelManager()
				.getChannel(w.inChannel)!
				.getFullState();
			const ends = new Map<string, IAuxiliaryForwardLegResolution>();
			(
				state as {
					forwardLegEnds?: Map<string, IAuxiliaryForwardLegResolution>;
				}
			).forwardLegEnds = ends;
			for (let i = 0; i < 1000; i++) {
				ends.set(`never-offered:${1000 + i}`, {
					paymentHash: Buffer.alloc(32, 1),
					incomingChannelId: Buffer.from(w.inChannel),
					incomingHtlcId: BigInt(1000 + i),
					leg: 'outgoing',
					outcome: 'never-offered',
					onChain: false,
					customRecords: new Map()
				});
			}
			const next = w.hosts.bob.node
				.getChannelManager()
				.getChannel(w.outChannel)!
				.getFullState().scidAlias!;
			const held = await forwardHeld(w, 'fwd-ends-bound', {
				next,
				forwardMsat: FORWARD_MSAT,
				outgoingDelta: OUTGOING_DELTA,
				cltvDelta: CLTV_DELTA,
				units: INCOMING_UNITS,
				held: false
			});
			expect(asked).to.deep.equal([]);
			expect(w.hosts.alice.node.getPayment(held.paymentHash)?.status).to.equal(
				PaymentStatus.FAILED
			);
		});
	});

	describe('a look at the fee coin pool before a forward pays out', () => {
		/**
		 * The three in channels of the fixed mode: each node reads the features
		 * the others advertise and none allows the older HTLC signatures. Bob's
		 * wallet holds `bobCoins`, under `policy`.
		 */
		async function feeScene(
			tag: string,
			shape: Shape,
			options: {
				bobCoins: number[];
				policy?: Partial<IFixedOutputFeePolicy>;
				held?: boolean;
				asked?: number;
			}
		): Promise<IScene> {
			const asked: IAuxiliaryForwardRequest[] = [];
			const told: IAuxiliaryForwardLegResolution[] = [];
			const terms = termsOf(shape);
			const w = await world.open(tag, {
				kinds: { in: shape[0], out: shape[1] },
				realInit: true,
				feeWallet: {
					alice: true,
					bob: options.policy ?? true,
					carol: true
				},
				hooks: {
					alice: {
						valueIncomingHtlc: valued,
						allowLegacyHtlcSignatures: undefined
					},
					bob: {
						prepareForward: (request): IAuxiliaryForwardTerms => {
							asked.push(request);
							return terms(request);
						},
						onForwardLegResolved: (resolution): void => {
							told.push(resolution);
						},
						allowLegacyHtlcSignatures: undefined
					},
					carol: {
						valueIncomingHtlc: valued,
						allowLegacyHtlcSignatures: undefined
					}
				}
			});
			for (const [which, channelId] of [
				['in', w.inChannel],
				['out', w.outChannel]
			] as const) {
				if (w.kinds[which] !== 'asset') continue;
				expect(
					isFixedAssetHtlcChannel(
						w.hosts.bob.node
							.getChannelManager()
							.getChannel(channelId)!
							.getFullState().channelType
					),
					`the ${which} channel is of the fixed mode`
				).to.equal(true);
			}
			for (const value of options.bobCoins) w.wallets.bob!.fund(value);
			await world.mine(w, 1);
			const s: IScene = {
				w,
				held: undefined as unknown as IForwardPayment,
				asked,
				told,
				closed: [],
				logs: []
			};
			listen(s);
			return s;
		}

		const send = async (
			s: IScene,
			tag: string,
			held = true
		): Promise<IForwardPayment> =>
			forwardHeld(s.w, tag, {
				next: s.w.hosts.bob.node
					.getChannelManager()
					.getChannel(s.w.outChannel)!
					.getFullState().scidAlias!,
				forwardMsat: FORWARD_MSAT,
				outgoingDelta: OUTGOING_DELTA,
				cltvDelta: CLTV_DELTA,
				units: INCOMING_UNITS,
				incomingMsat: INCOMING_MSAT,
				held
			});

		for (const shape of SHAPES) {
			it(`${named(
				shape
			)}: with a wallet coin a split makes four fee coins of, the forward goes on`, async () => {
				const s = await feeScene(`fwd-fee-ok-${shape.join('-')}`, shape, {
					bobCoins: [100_000]
				});
				s.held = await send(s, 'fwd-fee-ok');
				expect(s.asked).to.have.length(1);
			});

			it(`${named(
				shape
			)}: with no fee coin ready and none a split could make, the forward is refused with temporary_channel_failure before the host is asked`, async () => {
				const s = await feeScene(`fwd-fee-none-${shape.join('-')}`, shape, {
					bobCoins: []
				});
				s.held = await send(s, 'fwd-fee-none', false);
				expect(s.asked).to.deep.equal([]);
				expect(paymentOf(s)).to.equal(PaymentStatus.FAILED);
				expect(
					s.logs.some(
						(line) =>
							line.startsWith('asset_forward_declined') &&
							line.includes('the fee coin pool can pay for 0 spends')
					),
					s.logs.join(' | ')
				).to.equal(true);
			});
		}

		it('bitcoin in, asset out: with a wallet coin one split makes one fee coin of, the first forward goes on and a second one while it is in flight is refused before the host is asked', async () => {
			const s = await feeScene('fwd-fee-one', ['ordinary', 'asset'], {
				bobCoins: [30_000]
			});
			s.held = await send(s, 'fwd-fee-one-a');
			expect(s.asked).to.have.length(1);
			const second = await send(s, 'fwd-fee-one-b', false);
			expect(s.asked).to.have.length(1);
			expect(
				s.w.hosts.alice.node.getPayment(second.paymentHash)?.status
			).to.equal(PaymentStatus.FAILED);
		});

		it('asset in, asset out: a forward takes a fee coin for each of its asset HTLCs, so one coin refuses it and two let the first through and refuse a second while it is in flight', async () => {
			const one = await feeScene('fwd-fee-two-of-one', ['asset', 'asset'], {
				bobCoins: [30_000]
			});
			one.held = await send(one, 'fwd-fee-two-of-one', false);
			expect(one.asked).to.deep.equal([]);
			expect(paymentOf(one)).to.equal(PaymentStatus.FAILED);
			world.dispose();
			const two = await feeScene('fwd-fee-two', ['asset', 'asset'], {
				bobCoins: [50_000]
			});
			two.held = await send(two, 'fwd-fee-two-a');
			expect(two.asked).to.have.length(1);
			const second = await send(two, 'fwd-fee-two-b', false);
			expect(two.asked).to.have.length(1);
			expect(
				two.w.hosts.alice.node.getPayment(second.paymentHash)?.status
			).to.equal(PaymentStatus.FAILED);
		});

		it('asset in, asset out: a fee budget without room for two spends at the cap refuses the forward before the host is asked', async () => {
			const s = await feeScene('fwd-fee-budget', ['asset', 'asset'], {
				bobCoins: [100_000],
				policy: { maxTotalFeeSatoshis: 40_000n }
			});
			s.held = await send(s, 'fwd-fee-budget', false);
			expect(s.asked).to.deep.equal([]);
			expect(paymentOf(s)).to.equal(PaymentStatus.FAILED);
			expect(
				s.logs.some((line) => line.includes('the fee budget has')),
				s.logs.join(' | ')
			).to.equal(true);
		});
	});
});
