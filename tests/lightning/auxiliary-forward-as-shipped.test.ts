/**
 * Issue #2098, step 5: forwards with an asset leg as the build ships them.
 *
 * No test here turns the switch for asset forwards on or off: the build has
 * it on, and the API names the part among its surfaces. A node whose host
 * supplies no prepareForward refuses a forward with an asset leg before
 * anything is offered, as builds before did. Nodes that read the features
 * the others really advertise, with no hook for the older HTLC signatures,
 * hold their asset channels in the fixed mode and pay the fees of their
 * spends on the chain from the real fee pool; a forward over them in each
 * direction is defended there when its outgoing channel is closed.
 */

import { expect } from 'chai';
import type {
	IAuxiliaryForwardRequest,
	IAuxiliaryForwardTerms
} from '../../src/lightning/channel/auxiliary-forward';
import { AUXILIARY_CHANNELS_API } from '../../src/lightning/channel/auxiliary-api';
import { auxiliaryForwards } from '../../src/lightning/channel/auxiliary-switch';
import {
	ChannelState,
	isFixedAssetHtlcChannel
} from '../../src/lightning/channel/types';
import { OutputStatus, OutputType } from '../../src/lightning/chain/types';
import { ASSET_FORWARD_FAIL_BACK_DEPTH } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	FORWARD_CARRIER_MSAT,
	forwardChainWorld,
	forwardHeld,
	type ForwardChannelKind,
	type IForwardWorld
} from './helpers/auxiliary-forward-world';
import { withAssetOpens } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	errorsOf,
	trackedOutputs
} from './helpers/auxiliary-on-chain';
import { amountRecord } from './helpers/auxiliary-pair';

type Shape = [ForwardChannelKind, ForwardChannelKind];
const SHAPES: Shape[] = [
	['ordinary', 'asset'],
	['asset', 'ordinary'],
	['asset', 'asset']
];
const named = ([inKind, outKind]: Shape): string =>
	inKind === 'ordinary'
		? 'bitcoin in, asset out'
		: outKind === 'ordinary'
		? 'asset in, bitcoin out'
		: 'asset in, asset out';

const valued = (incoming: { auxiliaryAmount?: bigint }): bigint | undefined =>
	incoming.auxiliaryAmount === undefined
		? undefined
		: incoming.auxiliaryAmount * 1000n;

describe('forwards with an asset leg as the build ships them (issue #2098, step 5)', function () {
	this.timeout(240000);
	withAssetOpens();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	const until = async (
		w: IForwardWorld,
		what: string,
		reached: () => boolean,
		most = 80
	): Promise<void> => {
		for (let i = 0; i < most && !reached(); i++) await world.mine(w, 1);
		if (!reached()) {
			throw new Error(
				`never reached: ${what} at ${w.chain.height}; bob: ${errorsOf(
					w.hosts.bob
				).join(' | ')}`
			);
		}
	};

	it('says so itself: the switch is on, and the API names the part among its surfaces with nothing declared', () => {
		expect(auxiliaryForwards.enabled).to.equal(true);
		expect(AUXILIARY_CHANNELS_API.surfaces).to.include('prepareForward');
		expect(AUXILIARY_CHANNELS_API.surfaces).to.include(
			'getFixedOutputFeeStatus:splitCoins'
		);
		expect([...AUXILIARY_CHANNELS_API.declared]).to.deep.equal([]);
	});

	for (const shape of SHAPES) {
		it(`${named(
			shape
		)}: a node whose host supplies no prepareForward refuses the forward before anything is offered`, async () => {
			const w = await world.open(`as-shipped-no-hook-${shape.join('-')}`, {
				kinds: { in: shape[0], out: shape[1] },
				hooks: { carol: { valueIncomingHtlc: valued } }
			});
			const held = await forwardHeld(w, 'as-shipped-no-hook', {
				next: w.hosts.bob.node
					.getChannelManager()
					.getChannel(w.outChannel)!
					.getFullState().scidAlias!,
				forwardMsat: 5_000_000n,
				outgoingDelta: 60,
				cltvDelta: 40,
				units: 5010n,
				incomingMsat: 5_100_000n,
				held: false
			});
			expect(w.hosts.alice.node.getPayment(held.paymentHash)?.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(
				w.hosts.bob.node
					.getChannelManager()
					.getChannel(w.outChannel)!
					.getFullState().localHtlcCounter
			).to.equal(0n);
		});

		it(`${named(
			shape
		)}: over channels of the fixed mode and the real fee pool, the forward goes on, and when Bob closes its outgoing channel it is timed out there and failed back ${ASSET_FORWARD_FAIL_BACK_DEPTH} blocks on`, async () => {
			const asked: IAuxiliaryForwardRequest[] = [];
			const w = await world.open(`as-shipped-${shape.join('-')}`, {
				kinds: { in: shape[0], out: shape[1] },
				realInit: true,
				feeWallet: { alice: true, bob: true, carol: true },
				hooks: {
					alice: {
						valueIncomingHtlc: valued,
						allowLegacyHtlcSignatures: undefined
					},
					bob: {
						allowLegacyHtlcSignatures: undefined,
						prepareForward: (request): IAuxiliaryForwardTerms => {
							asked.push(request);
							return {
								...(shape[0] === 'asset'
									? {
											incomingValueMsat:
												request.incoming.auxiliaryAmount! * 1000n
									  }
									: {}),
								...(shape[1] === 'asset'
									? {
											outgoingHtlc: {
												customRecords: amountRecord(5000n),
												wireAmountMsat: FORWARD_CARRIER_MSAT
											}
									  }
									: {})
							};
						}
					},
					carol: {
						valueIncomingHtlc: valued,
						allowLegacyHtlcSignatures: undefined
					}
				}
			});
			for (const [kind, channelId] of [
				[shape[0], w.inChannel],
				[shape[1], w.outChannel]
			] as const) {
				if (kind !== 'asset') continue;
				expect(
					isFixedAssetHtlcChannel(
						w.hosts.bob.node
							.getChannelManager()
							.getChannel(channelId)!
							.getFullState().channelType
					)
				).to.equal(true);
			}
			for (const name of ['alice', 'bob', 'carol'] as const) {
				w.wallets[name]!.fund(100_000);
				w.wallets[name]!.fund(100_000);
			}
			// A block in which Bob splits a coin into the fee coins he keeps for
			// his spends with a deadline, and one in which they confirm (#2098
			// step 6): a forward goes on only once they are ready.
			await world.mine(w, 3);
			const held = await forwardHeld(w, `as-shipped-${shape.join('-')}`, {
				next: w.hosts.bob.node
					.getChannelManager()
					.getChannel(w.outChannel)!
					.getFullState().scidAlias!,
				forwardMsat: 5_000_000n,
				outgoingDelta: 60,
				cltvDelta: 40,
				units: 5010n,
				incomingMsat: 5_100_000n
			});
			expect(asked).to.have.length(1);
			const closed = w.hosts.bob.node.forceCloseChannel(
				w.outChannel,
				SWEEP_DESTINATION
			);
			expect(closed.ok, closed.error).to.equal(true);
			await world.mine(w, 2);
			await world.passTo(w, held.outgoingExpiry - 1);
			const offered = ():
				| { status: OutputStatus; confirmationHeight: number }
				| undefined =>
				trackedOutputs(w.hosts.bob, w.outChannel).find(
					(output) =>
						output.outputType === OutputType.OFFERED_HTLC &&
						!output.isSecondLevelHtlc
				);
			await until(w, "Bob's timeout spend in a block", () =>
				[
					OutputStatus.SPEND_CONFIRMED,
					OutputStatus.IRREVOCABLY_RESOLVED
				].includes(offered()?.status as OutputStatus)
			);
			const timedOutAt = offered()!.confirmationHeight;
			await until(
				w,
				"Alice's payment failed",
				() =>
					w.hosts.alice.node.getPayment(held.paymentHash)?.status ===
					PaymentStatus.FAILED,
				ASSET_FORWARD_FAIL_BACK_DEPTH + 6
			);
			expect(w.chain.height - timedOutAt).to.be.at.least(
				ASSET_FORWARD_FAIL_BACK_DEPTH
			);
			expect(w.chain.height).to.be.lessThan(held.incomingExpiry - 18);
			await world.mine(w, 2);
			expect(
				w.hosts.bob.node.getChannelManager().getChannel(w.inChannel)!.getState()
			).to.equal(ChannelState.NORMAL);
		});
	}
});
