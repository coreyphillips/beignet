import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelAction,
	ChannelActionType
} from '../../src/lightning/channel/channel-actions';
import {
	createAcceptorState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	buildLocalCommitment,
	funderCommitmentCostSats
} from '../../src/lightning/channel/commitment-builder';
import {
	ChannelRole,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { IUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { expectWireFailure } from './helpers/open-refusal';
import {
	connectNodes,
	createNode,
	openReadyChannel
} from './helpers/loopback-nodes';

/**
 * Issue #1020: as the channel funder, an inbound update_add_htlc was never
 * checked against OUR commitment fee. The receive-side affordability arm
 * priced the fee only when the peer funds, so a peer could stack adds until
 * the fee consumed our whole balance: the builder saturates the funder's
 * output at zero and drops it, and a broadcast of either commitment then paid
 * our balance to miners.
 *
 * Fix under test: after admitting an inbound add, our settled balance must
 * still keep the reserve the peer requires of us plus the funder's cost
 * (funderCommitmentCostSats) of the dearer of the two commitments carrying
 * it, with the untrimmed HTLC count the builder actually fees. A breach fails
 * the channel on the wire, the answer eclair, LND and CLN give. The send-side
 * mirror refuses locally, one slot early, when the PEER funds, so two honest
 * beignet nodes never reach the wire refusal.
 */

const WIRE =
	/Cannot afford commitment fee for inbound HTLC above channel reserve/;
const MIRROR = 'Remote funder cannot afford commitment fee for HTLC';

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
		firstPerCommitmentPoint: getPublicKey(keys[1])
	};
}

function taprootType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT);
	return flags.toBuffer();
}

function anchorType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	return flags.toBuffer();
}

interface IFixtureOpts {
	channelType?: Buffer | null;
	role?: ChannelRole;
	/** localConfig.feeratePerKw: the committed rate when WE are the opener. */
	localFeeratePerKw?: number;
	/** remoteConfig.feeratePerKw: the committed rate when the PEER is opener. */
	remoteFeeratePerKw?: number;
	/** A staged update_fee rate, as the state carries it mid fee round. */
	pendingFeeratePerKw?: number;
	/** localConfig.channelReserveSatoshis: what we require of the peer. */
	enforceReserve?: bigint;
	/** remoteConfig.channelReserveSatoshis: what the peer requires of us. */
	keepReserve?: bigint;
	localDustLimit?: bigint;
	remoteDustLimit?: bigint;
	localMsat?: bigint;
	remoteMsat?: bigint;
	htlcs?: {
		amountMsat: bigint;
		direction: HtlcDirection;
		state?: HtlcState;
	}[];
}

/**
 * A NORMAL channel with default 354-sat dust limits and a 10,000-sat reserve
 * on both sides unless overridden. The reserve stays at or above our dust
 * limit, so _localCommitmentEmptyRefusal short-circuits and only the fee
 * arithmetic under test decides.
 */
function makeChannel(opts: IFixtureOpts = {}): Channel {
	const state: IChannelState = createAcceptorState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			channelReserveSatoshis: opts.enforceReserve ?? 10_000n,
			dustLimitSatoshis: opts.localDustLimit ?? 354n,
			feeratePerKw: opts.localFeeratePerKw ?? 2_500
		},
		localBasepoints: makeBasepoints(
			crypto.createHash('sha256').update('local').digest()
		),
		localPerCommitmentSeed: crypto
			.createHash('sha256')
			.update('commit')
			.digest(),
		remoteBasepoints: makeBasepoints(
			crypto.createHash('sha256').update('remote').digest()
		),
		remoteConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			channelReserveSatoshis: opts.keepReserve ?? 10_000n,
			dustLimitSatoshis: opts.remoteDustLimit ?? 354n,
			feeratePerKw: opts.remoteFeeratePerKw ?? 2_500
		}
	});

	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.state = ChannelState.NORMAL;
	state.role = opts.role ?? ChannelRole.OPENER;
	state.channelType = opts.channelType ?? null;
	state.localBalanceMsat = opts.localMsat ?? 500_000_000n;
	state.remoteBalanceMsat = opts.remoteMsat ?? 500_000_000n;
	state.remoteCurrentPerCommitmentPoint =
		state.remoteBasepoints!.firstPerCommitmentPoint;
	state.remoteNextPerCommitmentPoint =
		state.remoteBasepoints!.firstPerCommitmentPoint;
	if (opts.pendingFeeratePerKw !== undefined) {
		state.pendingFeeratePerKw = opts.pendingFeeratePerKw;
	}

	(opts.htlcs ?? []).forEach((h, i) => {
		const key = `${
			h.direction === HtlcDirection.OFFERED ? 'offered' : 'received'
		}-${i}`;
		state.htlcs.set(key, {
			id: BigInt(i),
			amountMsat: h.amountMsat,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 600,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: h.direction,
			state: h.state ?? HtlcState.COMMITTED
		});
	});

	return new Channel(state);
}

function addHtlcMsg(
	channel: Channel,
	amountMsat: bigint,
	id = 99n
): IUpdateAddHtlcMessage {
	return {
		channelId: channel.getChannelId()!,
		id,
		amountMsat,
		paymentHash: crypto.randomBytes(32),
		cltvExpiry: 500,
		onionRoutingPacket: Buffer.alloc(1366)
	};
}

const errorOf = (actions: ChannelAction[]): string | null => {
	for (const a of actions) {
		if (a.type === ChannelActionType.ERROR) {
			return (a as unknown as { message: string }).message;
		}
	}
	return null;
};

const RESERVE_MSAT = 10_000_000n;
const RATE = 2_500;
/**
 * The non-anchor trim thresholds at 2,500 sat/kw: the 354-sat dust limit plus
 * the second-level fee, floor(703 * 2500 / 1000) = 1,757 sats of HTLC-success
 * fee for a RECEIVED HTLC (2,111 sats) and floor(663 * 2500 / 1000) = 1,657
 * sats of HTLC-timeout fee for an OFFERED one (2,011 sats). One msat under
 * the threshold is dust to the builder.
 */
const RECEIVED_TRIM_SATS = 354n + 1_757n;
const OFFERED_TRIM_SATS = 354n + 1_657n;

describe('Funder commitment fee on an inbound add (issue #1020)', function () {
	describe('handleUpdateAddHtlc: the fee WE pay as funder', function () {
		const types: [string, Buffer | null][] = [
			['legacy', null],
			['anchor', anchorType()],
			['taproot', taprootType()]
		];

		for (const [name, channelType] of types) {
			it(`${name}: admits an add exactly at reserve + funderCommitmentCostSats(n+1)`, function () {
				// One untrimmed HTLC after the add: (base + 172) * 2.5 sats, plus 660
				// sats of anchors where the builder deducts them.
				const requiredMsat =
					funderCommitmentCostSats(RATE, 1, channelType) * 1000n;
				const channel = makeChannel({
					channelType,
					localMsat: RESERVE_MSAT + requiredMsat
				});
				const actions = channel.handleUpdateAddHtlc(
					addHtlcMsg(channel, 5_000_000n)
				);
				expect(errorOf(actions)).to.equal(null);
				const state = channel.getFullState();
				expect(state.state).to.equal(ChannelState.NORMAL);
				expect(state.htlcs.size).to.equal(1);
				expect(state.remoteBalanceMsat).to.equal(495_000_000n);
			});

			it(`${name}: fails the channel on the wire one msat inside the boundary`, function () {
				const requiredMsat =
					funderCommitmentCostSats(RATE, 1, channelType) * 1000n;
				const channel = makeChannel({
					channelType,
					localMsat: RESERVE_MSAT + requiredMsat - 1n
				});
				const actions = channel.handleUpdateAddHtlc(
					addHtlcMsg(channel, 5_000_000n)
				);
				expectWireFailure(actions, channel.getChannelId()!, WIRE);
				const state = channel.getFullState();
				expect(state.state).to.equal(ChannelState.ERRORED);
				expect(state.htlcs.size, 'the add never enters the log').to.equal(0);
				expect(state.remoteBalanceMsat).to.equal(500_000_000n);
			});
		}

		it('the local error carries the figures the wire text leaves out', function () {
			const requiredMsat = funderCommitmentCostSats(RATE, 1, null) * 1000n;
			const channel = makeChannel({
				localMsat: RESERVE_MSAT + requiredMsat - 1n
			});
			const local = errorOf(
				channel.handleUpdateAddHtlc(addHtlcMsg(channel, 5_000_000n))
			)!;
			expect(local).to.match(WIRE);
			expect(local).to.match(
				new RegExp(`localBalanceMsat=${RESERVE_MSAT + requiredMsat - 1n}`)
			);
			expect(local).to.match(/reserveSats=10000/);
			expect(local).to.match(/feeratePerKw=2500/);
			expect(local).to.match(/untrimmedHtlcs=1/);
			expect(local).to.match(new RegExp(`requiredMsat=${requiredMsat}`));
			expect(local).to.match(/htlcAmountMsat=5000000/);
		});

		it('charges the 172-weight term for every untrimmed HTLC already in flight', function () {
			// One committed untrimmed HTLC plus the add: cost(2) = 2,670 sats.
			const requiredMsat = funderCommitmentCostSats(RATE, 2, null) * 1000n;
			expect(requiredMsat).to.equal(2_670_000n);
			const admitted = makeChannel({
				localMsat: RESERVE_MSAT + requiredMsat,
				htlcs: [{ amountMsat: 5_000_000n, direction: HtlcDirection.OFFERED }]
			});
			expect(
				errorOf(admitted.handleUpdateAddHtlc(addHtlcMsg(admitted, 5_000_000n)))
			).to.equal(null);
			const refused = makeChannel({
				localMsat: RESERVE_MSAT + requiredMsat - 1n,
				htlcs: [{ amountMsat: 5_000_000n, direction: HtlcDirection.OFFERED }]
			});
			expect(
				errorOf(refused.handleUpdateAddHtlc(addHtlcMsg(refused, 5_000_000n)))
			).to.match(WIRE);
		});

		it('a trimmed add does not raise the fee, so it is admitted at the boundary', function () {
			// Room for exactly one untrimmed HTLC, already taken by the committed
			// one. An add under the 2,111-sat trim threshold gets no output and
			// no fee weight, so it passes; one at the threshold does not.
			const requiredMsat = funderCommitmentCostSats(RATE, 1, null) * 1000n;
			const fixture = (): Channel =>
				makeChannel({
					localMsat: RESERVE_MSAT + requiredMsat,
					htlcs: [{ amountMsat: 5_000_000n, direction: HtlcDirection.RECEIVED }]
				});
			const dust = fixture();
			expect(
				errorOf(
					dust.handleUpdateAddHtlc(
						addHtlcMsg(dust, RECEIVED_TRIM_SATS * 1000n - 1n)
					)
				)
			).to.equal(null);
			expect(dust.getFullState().htlcs.size).to.equal(2);
			const untrimmed = fixture();
			expect(
				errorOf(
					untrimmed.handleUpdateAddHtlc(
						addHtlcMsg(untrimmed, RECEIVED_TRIM_SATS * 1000n)
					)
				)
			).to.match(WIRE);
		});

		it('trimmed HTLCs already in flight are not counted either', function () {
			// Two committed dust HTLCs: the builder gives them no output and fees
			// none of them, so an untrimmed add needs cost(1), not cost(3). A count
			// of every active entry (_countActiveHtlcs + 1) would refuse this.
			const requiredMsat = funderCommitmentCostSats(RATE, 1, null) * 1000n;
			const channel = makeChannel({
				localMsat: RESERVE_MSAT + requiredMsat,
				htlcs: [
					{ amountMsat: 1_000_000n, direction: HtlcDirection.RECEIVED },
					{ amountMsat: 1_000_000n, direction: HtlcDirection.OFFERED }
				]
			});
			expect(
				errorOf(channel.handleUpdateAddHtlc(addHtlcMsg(channel, 5_000_000n)))
			).to.equal(null);
			expect(channel.getFullState().htlcs.size).to.equal(3);
		});

		it("an HTLC trimmed on our commitment but not on the peer's still counts", function () {
			// Our dust limit is 1,000 sats (threshold 2,757), the peer's 354
			// (threshold 2,111). A 2,500-sat add gets no output on the commitment
			// we hold but does on the one the peer holds, where the fee comes off
			// our to_remote just the same: the dearer commitment binds.
			const zeroHtlcMsat = funderCommitmentCostSats(RATE, 0, null) * 1000n;
			const channel = makeChannel({
				localDustLimit: 1_000n,
				localMsat: RESERVE_MSAT + zeroHtlcMsat
			});
			expect(
				errorOf(channel.handleUpdateAddHtlc(addHtlcMsg(channel, 2_500_000n)))
			).to.match(WIRE);
			// The same add on a channel where both limits are 1,000 is dust on
			// both commitments and passes at the zero-HTLC cost.
			const symmetric = makeChannel({
				localDustLimit: 1_000n,
				remoteDustLimit: 1_000n,
				localMsat: RESERVE_MSAT + zeroHtlcMsat
			});
			expect(
				errorOf(
					symmetric.handleUpdateAddHtlc(addHtlcMsg(symmetric, 2_500_000n))
				)
			).to.equal(null);
		});

		it('mid fee round, prices the dearer of the two commitments', function () {
			// Our own staged update_fee applies to the commitment we sign for the
			// peer immediately and to ours only after the peer revokes for it, so
			// the two build at 2,500 and 5,000 until then. Both are signed; the
			// 5,000 one costs more and binds.
			const requiredMsat = funderCommitmentCostSats(5_000, 1, null) * 1000n;
			const admitted = makeChannel({
				pendingFeeratePerKw: 5_000,
				localMsat: RESERVE_MSAT + requiredMsat
			});
			expect(
				errorOf(admitted.handleUpdateAddHtlc(addHtlcMsg(admitted, 5_000_000n)))
			).to.equal(null);
			const refused = makeChannel({
				pendingFeeratePerKw: 5_000,
				localMsat: RESERVE_MSAT + requiredMsat - 1n
			});
			const local = errorOf(
				refused.handleUpdateAddHtlc(addHtlcMsg(refused, 5_000_000n))
			)!;
			expect(local).to.match(WIRE);
			expect(local).to.match(/feeratePerKw=5000/);
		});

		it('credits a settlement still awaiting its round, as the builder does', function () {
			// A received HTLC we fulfilled whose credit handleRevokeAndAck has not
			// finalized yet: the live balance is 5,000 sats short of the boundary
			// and the credit covers exactly that. The builder credits it into the
			// next commitment and the peer's arithmetic already counts it, so a
			// refusal here would fail a channel over an add both sides afford.
			const requiredMsat = funderCommitmentCostSats(RATE, 1, null) * 1000n;
			const fulfilled = makeChannel({
				localMsat: RESERVE_MSAT + requiredMsat - 5_000_000n,
				htlcs: [
					{
						amountMsat: 5_000_000n,
						direction: HtlcDirection.RECEIVED,
						state: HtlcState.FULFILLED
					}
				]
			});
			expect(
				errorOf(
					fulfilled.handleUpdateAddHtlc(addHtlcMsg(fulfilled, 5_000_000n))
				)
			).to.equal(null);
			// The same for an offered HTLC the peer failed (our refund).
			const failed = makeChannel({
				localMsat: RESERVE_MSAT + requiredMsat - 5_000_000n,
				htlcs: [
					{
						amountMsat: 5_000_000n,
						direction: HtlcDirection.OFFERED,
						state: HtlcState.FAILED
					}
				]
			});
			expect(
				errorOf(failed.handleUpdateAddHtlc(addHtlcMsg(failed, 5_000_000n)))
			).to.equal(null);
			// And without the settlement the same live balance is refused.
			const bare = makeChannel({
				localMsat: RESERVE_MSAT + requiredMsat - 5_000_000n
			});
			expect(
				errorOf(bare.handleUpdateAddHtlc(addHtlcMsg(bare, 5_000_000n)))
			).to.match(WIRE);
		});

		it('the reproduction from the issue: 5,000-sat adds into a 30,000-sat funder', function () {
			// Non-anchor channel we opened at 2,500 sat/kw, our balance 30,000
			// sats, reserve 10,000: 20,000 sats of headroom. cost(n) is
			// floor((724 + 172n) * 2.5) = 1,810 + 430n sats, so the 42nd untrimmed
			// HTLC still fits (19,870) and the 43rd does not (20,300). On master
			// every one of the 80 adds was admitted, and past the 65th our output
			// was gone entirely: the fee equalled our whole balance.
			expect(funderCommitmentCostSats(RATE, 42, null)).to.equal(19_870n);
			expect(funderCommitmentCostSats(RATE, 43, null)).to.equal(20_300n);
			const channel = makeChannel({ localMsat: 30_000_000n });
			let refusedAt: number | null = null;
			for (let i = 1; i <= 80; i++) {
				const actions = channel.handleUpdateAddHtlc(
					addHtlcMsg(channel, 5_000_000n, BigInt(i))
				);
				const err = errorOf(actions);
				if (err) {
					expect(err).to.match(WIRE);
					refusedAt = i;
					break;
				}
			}
			expect(refusedAt, 'refused at the first unaffordable add').to.equal(43);
			const state = channel.getFullState();
			expect(state.state).to.equal(ChannelState.ERRORED);
			expect(state.htlcs.size).to.equal(42);

			// The commitment we hold still carries our to_local output, at the
			// reserve or above: 30,000 - 19,870 = 10,130 sats.
			const built = buildLocalCommitment(
				state,
				state.remoteBasepoints!.firstPerCommitmentPoint,
				state.localCommitmentNumber
			);
			const toLocal = built.result.outputMap.toLocal;
			expect(toLocal, 'to_local present').to.not.equal(undefined);
			expect(built.result.tx.outs[toLocal!].value).to.equal(10_130);
			expect(built.result.outputMap.htlcs.length).to.equal(42);
		});

		it('leaves the acceptor arm alone: a drained acceptor still takes the add', function () {
			// When the PEER funds, the fee is the peer's problem and our balance
			// can sit at our reserve. The peer keeps its reserve plus cost(1)
			// with room to spare.
			const channel = makeChannel({
				role: ChannelRole.ACCEPTOR,
				localMsat: RESERVE_MSAT
			});
			expect(
				errorOf(channel.handleUpdateAddHtlc(addHtlcMsg(channel, 5_000_000n)))
			).to.equal(null);
			expect(channel.getFullState().htlcs.size).to.equal(1);
		});
	});

	describe('addHtlc: the send-side mirror when the peer funds', function () {
		// We are the acceptor; the peer keeps a 10,000-sat reserve plus cost(2):
		// the add and the one extra slot the mirror keeps. cost(2) = 2,670 sats.
		const fixture = (remoteMsat: bigint): Channel =>
			makeChannel({ role: ChannelRole.ACCEPTOR, remoteMsat });
		const mirrorMsat = funderCommitmentCostSats(RATE, 2, null) * 1000n;

		it('admits an add the funder can still pay the fee for, one slot to spare', function () {
			const channel = fixture(RESERVE_MSAT + mirrorMsat);
			expect(channel.canOfferHtlcSet([5_000_000n])).to.equal(true);
			const actions = channel.addHtlc(
				5_000_000n,
				crypto.randomBytes(32),
				500,
				Buffer.alloc(1366)
			);
			expect(errorOf(actions)).to.equal(null);
			expect(channel.getFullState().htlcs.size).to.equal(1);
			// The slot it kept is now the one this add took: a second untrimmed
			// add would need cost(3) of the funder, which it no longer has.
			expect(channel.canOfferHtlcSet([5_000_000n])).to.equal(false);
		});

		it('refuses locally, without touching the channel, one msat inside', function () {
			const channel = fixture(RESERVE_MSAT + mirrorMsat - 1n);
			expect(channel.canOfferHtlcSet([5_000_000n])).to.equal(false);
			const actions = channel.addHtlc(
				5_000_000n,
				crypto.randomBytes(32),
				500,
				Buffer.alloc(1366)
			);
			expect(errorOf(actions)).to.equal(MIRROR);
			expect(actions.length, 'a bare local error').to.equal(1);
			const state = channel.getFullState();
			expect(state.state).to.equal(ChannelState.NORMAL);
			expect(state.htlcs.size).to.equal(0);
			expect(state.localBalanceMsat).to.equal(500_000_000n);
		});

		it('a dust add asks nothing of the funder beyond the slot buffer', function () {
			// cost(1): room for the buffer slot only, and a trimmed add adds no
			// fee weight of its own.
			const channel = fixture(
				RESERVE_MSAT + funderCommitmentCostSats(RATE, 1, null) * 1000n
			);
			// Offered by us, so the timeout weight sets its threshold.
			expect(
				channel.canOfferHtlcSet([OFFERED_TRIM_SATS * 1000n - 1n])
			).to.equal(true);
			expect(channel.canOfferHtlcSet([OFFERED_TRIM_SATS * 1000n])).to.equal(
				false
			);
		});

		it('is not asked when we fund: our own ceiling already retains the fee', function () {
			const channel = makeChannel({
				role: ChannelRole.OPENER,
				localMsat: 100_000_000n,
				remoteMsat: RESERVE_MSAT
			});
			const ceiling = channel.getSpendableOutboundMsat();
			expect(channel.canOfferHtlcSet([ceiling])).to.equal(true);
			expect(
				errorOf(
					channel.addHtlc(
						ceiling,
						crypto.randomBytes(32),
						500,
						Buffer.alloc(1366)
					)
				)
			).to.equal(null);
		});
	});

	describe('two honest beignet nodes over a loopback wire', function () {
		this.timeout(20_000);

		let alice: LightningNode;
		let bob: LightningNode;
		let errors: string[];

		function node(seed: number): LightningNode {
			const n = createNode('funder-fee-1020', seed);
			n.on('node:error', (e: { message?: string }) => {
				errors.push(e.message ?? '');
			});
			return n;
		}

		function payCeiling(
			from: LightningNode,
			to: LightningNode,
			channelId: Buffer
		): PaymentStatus | undefined {
			const ceiling = from
				.getChannelManager()
				.getChannel(channelId)!
				.getSpendableOutboundMsat();
			expect(ceiling > 0n, 'ceiling positive').to.equal(true);
			const invoice = to.createInvoice({
				amountMsat: ceiling,
				description: 'exact ceiling'
			});
			const sent = from.sendPayment(invoice.bolt11);
			return from
				.listPayments()
				.find((p) => p.paymentHash.equals(sent.paymentHash))?.status;
		}

		beforeEach(function () {
			errors = [];
			alice = node(1);
			bob = node(2);
			connectNodes(alice, bob);
		});

		afterEach(function () {
			alice.destroy();
			bob.destroy();
		});

		it('a peer paying at ITS ceiling into a channel WE opened is not refused', function () {
			// Alice funds, pays Bob down to her own floor (reserve plus the
			// fee-spike buffer), then Bob pays everything he can back. Alice's
			// floor keeps cost(2 slots at twice the rate), which covers cost(1)
			// at the live rate with room to spare.
			const channelId = openReadyChannel(alice, bob);
			expect(payCeiling(alice, bob, channelId)).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(payCeiling(bob, alice, channelId)).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(errors.filter((m) => /cannot afford/i.test(m))).to.deep.equal([]);
			for (const n of [alice, bob]) {
				expect(
					n.getChannelManager().getChannel(channelId)!.getState()
				).to.equal(ChannelState.NORMAL);
			}
		});

		it('stacked hold invoices stop at the sender, one slot before the funder would refuse', function () {
			// Alice at her floor holds cost(2 slots at twice the rate) of
			// headroom (the fee-spike buffer getSpendableOutboundMsat retains):
			// on the harness's anchor channel at 253 sat/kw that is 1,402 sats,
			// and cost(k) at 253 is floor((1124 + 172k) * 0.253) + 660, so 10
			// parked HTLCs cost 1,378 and an 11th 1,421. Alice would fail the
			// channel on the 11th add; Bob keeps one slot in hand and refuses
			// the 10th locally instead, and the channel never sees a wire
			// refusal. Derived from the live figures so a change of default
			// channel type or rate moves the expectation with it.
			const channelId = openReadyChannel(alice, bob);
			expect(payCeiling(alice, bob, channelId)).to.equal(
				PaymentStatus.COMPLETED
			);
			const aliceChannel = alice.getChannelManager().getChannel(channelId)!;
			const aliceState = aliceChannel.getFullState();
			const headroomSats =
				(aliceState.localBalanceMsat -
					aliceState.remoteConfig.channelReserveSatoshis * 1000n) /
				1000n;
			const cost = (k: number): bigint =>
				funderCommitmentCostSats(
					aliceState.localConfig.feeratePerKw,
					k,
					aliceState.channelType
				);
			// Bob admits the k-th add while cost(k + 1) fits; Alice's own arm
			// would only refuse once cost(k) does not.
			let expectedParked = 0;
			while (cost(expectedParked + 2) <= headroomSats) expectedParked++;
			expect(expectedParked >= 2, 'a stack worth the name').to.equal(true);
			expect(
				cost(expectedParked + 1) <= headroomSats,
				'the funder would still have admitted the add the sender refused'
			).to.equal(true);

			const outcomes: PaymentStatus[] = [];
			for (let i = 0; i < expectedParked + 3; i++) {
				const invoice = alice.createInvoice({
					amountMsat: 10_000_000n,
					description: `hold ${i}`,
					hold: true
				});
				const sent = bob.sendPayment(invoice.bolt11);
				const status = bob
					.listPayments()
					.find((p) => p.paymentHash.equals(sent.paymentHash))!.status;
				outcomes.push(status);
				if (status === PaymentStatus.FAILED) break;
			}
			const parked = alice
				.listHoldInvoices()
				.filter((h) => h.state === 'ACCEPTED').length;
			expect(parked, 'HTLCs parked at Alice').to.equal(expectedParked);
			expect(outcomes.length, 'the next one was refused').to.equal(
				expectedParked + 1
			);
			expect(outcomes[expectedParked]).to.equal(PaymentStatus.FAILED);
			expect(
				errors.some((m) => /inbound HTLC/.test(m)),
				'no wire refusal at the funder'
			).to.equal(false);
			for (const n of [alice, bob]) {
				expect(
					n.getChannelManager().getChannel(channelId)!.getState()
				).to.equal(ChannelState.NORMAL);
			}
		});
	});
});
