import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelAction,
	ChannelActionType
} from '../../src/lightning/channel/channel-actions';
import {
	createAcceptorState,
	IChannelState,
	ISpliceInFlight
} from '../../src/lightning/channel/channel-state';
import {
	buildLocalCommitment,
	funderCommitmentCostSats,
	HTLC_SUCCESS_WEIGHT,
	HTLC_TIMEOUT_WEIGHT
} from '../../src/lightning/channel/commitment-builder';
import {
	ChannelRole,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry,
	isAnchorChannel
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { IUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS } from '../../src/lightning/onion/types';
import {
	deserializeHtlcEntry,
	serializeHtlcEntry
} from '../../src/lightning/storage/serialization';
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
 * Fix under test, three thresholds on the funder's side:
 *  1. the SENDER's view of our commitment (what eclair's canSendAdd, LND and
 *     CLN price before offering): reserve plus the fee at the rate the peer
 *     has revoked for, over the outputs it has revoked for, trimmed at OUR
 *     dust limit. Met: admitted outright. Every conforming sender stops here.
 *  2. short of that, the CONSERVATIVE floor (dearer rate, lower dust limit,
 *     everything in flight, live balance): while our output survives, the add
 *     is admitted and stamped funderFeeFailback, and the node fails it back
 *     once committed (the dustExposureFailback mechanism).
 *  3. past the floor our output would be trimmed: the channel fails on the
 *     wire.
 * The send-side mirror, when the PEER funds, prices the funder's own view
 * from our book one slot early and refuses locally, and folds into the
 * outbound ceiling so the router never offers what the mirror refuses.
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

interface IFixtureHtlc {
	amountMsat: bigint;
	direction: HtlcDirection;
	state?: HtlcState;
	addRemoteCommitted?: boolean;
	addLocallyRevoked?: boolean;
	removalRemoteCommitted?: boolean;
	removalLocallyRevoked?: boolean;
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
	pendingFeerateSignable?: boolean;
	/** localConfig.channelReserveSatoshis: what we require of the peer. */
	enforceReserve?: bigint;
	/** remoteConfig.channelReserveSatoshis: what the peer requires of us. */
	keepReserve?: bigint;
	localDustLimit?: bigint;
	remoteDustLimit?: bigint;
	localMsat?: bigint;
	remoteMsat?: bigint;
	htlcs?: IFixtureHtlc[];
	spliceInFlight?: Partial<ISpliceInFlight>;
}

/**
 * A NORMAL channel with default 354-sat dust limits and a 10,000-sat reserve
 * on both sides unless overridden, at 2,500 sat/kw. The reserve stays at or
 * above our dust limit, so _localCommitmentEmptyRefusal short-circuits and
 * only the fee arithmetic under test decides. Fixture HTLCs are COMMITTED
 * with no two-phase flags unless the case sets them.
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
	if (opts.pendingFeerateSignable !== undefined) {
		state.pendingFeerateSignable = opts.pendingFeerateSignable;
	}
	if (opts.spliceInFlight) {
		state.spliceInFlight = opts.spliceInFlight as ISpliceInFlight;
	}

	(opts.htlcs ?? []).forEach((h, i) => {
		const key = `${
			h.direction === HtlcDirection.OFFERED ? 'offered' : 'received'
		}-${i}`;
		const entry: IHtlcEntry = {
			id: BigInt(i),
			amountMsat: h.amountMsat,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 600,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: h.direction,
			state: h.state ?? HtlcState.COMMITTED
		};
		for (const flag of [
			'addRemoteCommitted',
			'addLocallyRevoked',
			'removalRemoteCommitted',
			'removalLocallyRevoked'
		] as const) {
			if (h[flag] !== undefined) entry[flag] = h[flag];
		}
		state.htlcs.set(key, entry);
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

type Outcome = 'clean' | 'stamped' | 'wire';

/** Feed one inbound add and classify the channel's answer. */
function outcomeOf(channel: Channel, amountMsat: bigint, id = 99n): Outcome {
	const before = channel.getFullState().remoteBalanceMsat;
	const actions = channel.handleUpdateAddHtlc(
		addHtlcMsg(channel, amountMsat, id)
	);
	const err = errorOf(actions);
	const state = channel.getFullState();
	if (err) {
		expect(err).to.match(WIRE);
		expect(state.state).to.equal(ChannelState.ERRORED);
		expect(state.htlcs.has(`received-${id}`), 'never enters the log').to.equal(
			false
		);
		expect(state.remoteBalanceMsat).to.equal(before);
		return 'wire';
	}
	expect(state.state).to.equal(ChannelState.NORMAL);
	expect(state.htlcs.has(`received-${id}`), 'in the log').to.equal(true);
	expect(state.remoteBalanceMsat).to.equal(before - amountMsat);
	return channel.receivedHtlcExceedsFunderFee(id) ? 'stamped' : 'clean';
}

/** Outputs of the commitment WE hold, as the builder would produce it now. */
function heldCommitment(channel: Channel): {
	toLocalSats: number | null;
	htlcOutputs: number;
} {
	const state = channel.getFullState();
	const built = buildLocalCommitment(
		state,
		state.remoteBasepoints!.firstPerCommitmentPoint,
		state.localCommitmentNumber
	).result;
	const idx = built.outputMap.toLocal;
	return {
		toLocalSats: idx === undefined ? null : built.tx.outs[idx].value,
		htlcOutputs: built.outputMap.htlcs.length
	};
}

const RESERVE_MSAT = 10_000_000n;
const RATE = 2_500;
const DUST_MSAT = 354_000n;
/**
 * The non-anchor trim thresholds at 2,500 sat/kw: the 354-sat dust limit plus
 * the second-level fee, floor(703 * 2500 / 1000) = 1,757 sats of HTLC-success
 * fee for a RECEIVED output (2,111 sats). One msat under the threshold is
 * dust to the builder. An add we offer is a received output on the funder's
 * commitment, so the mirror trims it at this same threshold.
 */
const RECEIVED_TRIM_SATS = 354n + 1_757n;

const cost = (n: number, type: Buffer | null = null, rate = RATE): bigint =>
	funderCommitmentCostSats(rate, n, type) * 1000n;

/**
 * What eclair's Commitments.canSendAdd computes on the PEER's side before it
 * offers an add into a channel WE fund, restricted to the arm that concerns
 * the receiver-is-initiator case (its own balance being ample):
 *
 *   reduced = reduce(remoteCommit.spec, remoteChanges.acked, localChanges.proposed)
 *   fees    = commitTxTotalCost(remoteCommitParams.dustLimit, reduced, format)
 *   missingForReceiver = reduced.toLocal - remoteParams.channelReserve - fees
 *   offer iff missingForReceiver >= 0
 *
 * In the peer's vocabulary "remote" is us. remoteCommit.spec plus
 * remoteChanges.acked is our commitment as the peer has revoked for it: our
 * adds it has not revoked for are not in it (not debited, no output), our
 * removals it has not revoked for are not applied (output still there, no
 * credit). localChanges.proposed are the peer's own adds and its removals of
 * our offered HTLCs, applied from the moment it sends them. The feerate is
 * the spec's, the one the peer has revoked for.
 */
function eclairPeerWouldOffer(channel: Channel, amountMsat: bigint): boolean {
	const s = channel.getFullState();
	const inFlight = (e: IHtlcEntry): boolean =>
		e.state === HtlcState.PENDING || e.state === HtlcState.COMMITTED;
	let toLocalMsat = s.localBalanceMsat;
	const outputs: { amountSats: bigint; offeredByUs: boolean }[] = [];
	for (const e of s.htlcs.values()) {
		if (e.direction === HtlcDirection.OFFERED) {
			if (inFlight(e) && e.addRemoteCommitted === false) {
				// Not in remoteChanges.acked yet.
				toLocalMsat += e.amountMsat;
			} else if (inFlight(e)) {
				outputs.push({ amountSats: e.amountMsat / 1000n, offeredByUs: true });
			} else if (e.state === HtlcState.FAILED) {
				// The peer's own update_fail_htlc: localChanges.proposed.
				toLocalMsat += e.amountMsat;
			}
			// FULFILLED: the peer's own fulfill, output gone, value to the peer.
		} else if (inFlight(e) || e.removalRemoteCommitted === false) {
			// The peer's own add, or our removal it has not revoked for.
			outputs.push({ amountSats: e.amountMsat / 1000n, offeredByUs: false });
		}
	}
	outputs.push({ amountSats: amountMsat / 1000n, offeredByUs: false });
	// commitTxTotalCost at OUR dust limit: the owner's offered outputs trim
	// with the timeout fee, its received outputs with the success fee.
	const rate = s.localConfig.feeratePerKw;
	const anchor = isAnchorChannel(s.channelType);
	let untrimmed = 0;
	for (const o of outputs) {
		const weight = o.offeredByUs ? HTLC_TIMEOUT_WEIGHT : HTLC_SUCCESS_WEIGHT;
		const secondLevel = anchor
			? 0n
			: BigInt(Math.floor((weight * rate) / 1000));
		if (o.amountSats >= s.localConfig.dustLimitSatoshis + secondLevel) {
			untrimmed++;
		}
	}
	const feesMsat =
		funderCommitmentCostSats(rate, untrimmed, s.channelType) * 1000n;
	const missingForReceiver =
		toLocalMsat - s.remoteConfig.channelReserveSatoshis * 1000n - feesMsat;
	return missingForReceiver >= 0n;
}

describe('Funder commitment fee on an inbound add (issue #1020)', function () {
	describe('handleUpdateAddHtlc: the three thresholds when WE fund', function () {
		const types: [string, Buffer | null][] = [
			['legacy', null],
			['anchor', anchorType()],
			['taproot', taprootType()]
		];

		for (const [name, channelType] of types) {
			it(`${name}: admits outright at reserve + funderCommitmentCostSats(1)`, function () {
				// One untrimmed HTLC after the add: (base + 172) * 2.5 sats, plus 660
				// sats of anchors where the builder deducts them.
				const channel = makeChannel({
					channelType,
					localMsat: RESERVE_MSAT + cost(1, channelType)
				});
				expect(outcomeOf(channel, 5_000_000n)).to.equal('clean');
			});

			it(`${name}: one msat short of the sender's view lands in the band, stamped`, function () {
				const channel = makeChannel({
					channelType,
					localMsat: RESERVE_MSAT + cost(1, channelType) - 1n
				});
				expect(outcomeOf(channel, 5_000_000n)).to.equal('stamped');
			});

			it(`${name}: stamped while our output lands on the dust limit, wire failure one msat under`, function () {
				const onFloor = makeChannel({
					channelType,
					localMsat: DUST_MSAT + cost(1, channelType)
				});
				expect(outcomeOf(onFloor, 5_000_000n)).to.equal('stamped');
				expect(heldCommitment(onFloor).toLocalSats).to.equal(354);
				const trimmed = makeChannel({
					channelType,
					localMsat: DUST_MSAT + cost(1, channelType) - 1n
				});
				const actions = trimmed.handleUpdateAddHtlc(
					addHtlcMsg(trimmed, 5_000_000n)
				);
				expectWireFailure(actions, trimmed.getChannelId()!, WIRE);
				expect(trimmed.getFullState().htlcs.size).to.equal(0);
			});
		}

		it('the local error carries the figures the wire text leaves out', function () {
			const channel = makeChannel({ localMsat: DUST_MSAT + cost(1) - 1n });
			const local = errorOf(
				channel.handleUpdateAddHtlc(addHtlcMsg(channel, 5_000_000n))
			)!;
			expect(local).to.match(WIRE);
			expect(local).to.match(
				new RegExp(`localBalanceMsat=${DUST_MSAT + cost(1) - 1n}`)
			);
			expect(local).to.match(/reserveSats=10000/);
			expect(local).to.match(/senderViewFeeratePerKw=2500/);
			expect(local).to.match(/senderViewUntrimmedHtlcs=1/);
			expect(local).to.match(new RegExp(`senderViewRequiredMsat=${cost(1)}`));
			expect(local).to.match(/floorUntrimmedHtlcs=1/);
			expect(local).to.match(new RegExp(`floorRequiredMsat=${cost(1)}`));
			expect(local).to.match(new RegExp(`outputMsat=${DUST_MSAT - 1n}`));
			expect(local).to.match(new RegExp(`outputFloorMsat=${DUST_MSAT}`));
			expect(local).to.match(/htlcAmountMsat=5000000/);
		});

		it('charges the 172-weight term for every untrimmed HTLC the peer has revoked for', function () {
			// One committed offered HTLC (revoked for: no two-phase flag) plus
			// the add: cost(2) = 2,670 sats.
			expect(cost(2)).to.equal(2_670_000n);
			const revoked: IFixtureHtlc[] = [
				{ amountMsat: 5_000_000n, direction: HtlcDirection.OFFERED }
			];
			const clean = makeChannel({
				localMsat: RESERVE_MSAT + cost(2),
				htlcs: revoked
			});
			expect(outcomeOf(clean, 5_000_000n)).to.equal('clean');
			const short = makeChannel({
				localMsat: RESERVE_MSAT + cost(2) - 1n,
				htlcs: revoked
			});
			expect(outcomeOf(short, 5_000_000n)).to.equal('stamped');
		});

		it('a trimmed add raises no fee, so it passes where an untrimmed one is stamped', function () {
			const fixture = (): Channel =>
				makeChannel({
					localMsat: RESERVE_MSAT + cost(1),
					htlcs: [{ amountMsat: 5_000_000n, direction: HtlcDirection.RECEIVED }]
				});
			expect(outcomeOf(fixture(), RECEIVED_TRIM_SATS * 1000n - 1n)).to.equal(
				'clean'
			);
			expect(outcomeOf(fixture(), RECEIVED_TRIM_SATS * 1000n)).to.equal(
				'stamped'
			);
		});

		it('trimmed HTLCs already in flight are not counted', function () {
			// Two committed dust HTLCs get no output and no fee weight: an
			// untrimmed add needs cost(1), not cost(3).
			const channel = makeChannel({
				localMsat: RESERVE_MSAT + cost(1),
				htlcs: [
					{ amountMsat: 1_000_000n, direction: HtlcDirection.RECEIVED },
					{ amountMsat: 1_000_000n, direction: HtlcDirection.OFFERED }
				]
			});
			expect(outcomeOf(channel, 5_000_000n)).to.equal('clean');
		});

		it('an add trimmed at OUR dust limit is not counted, whatever the peer trims at (scratch D)', function () {
			// Our dust limit 1,000 sats (threshold 2,757), the peer's 354
			// (2,111). eclair and CLN price the sender's view at the receiver's
			// own dust limit, so a 2,500-sat add costs 0 untrimmed outputs and
			// the peer offers it at cost(0). Refusing it force closed an honest
			// peer (review round 1).
			const channel = makeChannel({
				localDustLimit: 1_000n,
				localMsat: RESERVE_MSAT + cost(0)
			});
			expect(eclairPeerWouldOffer(channel, 2_500_000n)).to.equal(true);
			expect(outcomeOf(channel, 2_500_000n)).to.equal('clean');
		});

		it('the conservative floor still counts it at the lower dust limit', function () {
			// Same limits. Past the sender's view, the floor prices the peer's
			// commitment, where the 2,500-sat output survives and is feed, and
			// our output must clear the HIGHER limit (our 1,000): balance
			// cost(1) + 1,000 sats is stamped, one msat under fails the channel.
			// Pricing the floor at our own limit (cost(0)) would have left the
			// peer's commitment paying a fee our to_remote could not cover.
			const onFloor = makeChannel({
				localDustLimit: 1_000n,
				localMsat: 1_000_000n + cost(1)
			});
			expect(outcomeOf(onFloor, 2_500_000n)).to.equal('stamped');
			const trimmed = makeChannel({
				localDustLimit: 1_000n,
				localMsat: 1_000_000n + cost(1) - 1n
			});
			expect(outcomeOf(trimmed, 2_500_000n)).to.equal('wire');
		});

		it('prices the sender view at the rate the peer has revoked for, mid fee round (scratch A)', function () {
			// Our own staged raise to 5,000 applies to the commitment we hold
			// only once the peer's revoke_and_ack promotes it. Until then every
			// conforming sender prices our commitment at 2,500 and offers at
			// reserve + cost(2,500, 1); refusing that force closed an honest peer
			// right after our own updateFee (review round 1).
			const channel = makeChannel({
				pendingFeeratePerKw: 5_000,
				localMsat: RESERVE_MSAT + cost(1)
			});
			expect(eclairPeerWouldOffer(channel, 5_000_000n)).to.equal(true);
			expect(outcomeOf(channel, 5_000_000n)).to.equal('clean');
		});

		it('but the floor prices the dearer of the two commitments', function () {
			// The commitment we sign for the peer already builds at 5,000. Our
			// output must survive there too: cost(5,000, 1) + 354 sats is
			// stamped, one msat under fails the channel.
			const onFloor = makeChannel({
				pendingFeeratePerKw: 5_000,
				localMsat: DUST_MSAT + cost(1, null, 5_000)
			});
			expect(outcomeOf(onFloor, 5_000_000n)).to.equal('stamped');
			const trimmed = makeChannel({
				pendingFeeratePerKw: 5_000,
				localMsat: DUST_MSAT + cost(1, null, 5_000) - 1n
			});
			const local = errorOf(
				trimmed.handleUpdateAddHtlc(addHtlcMsg(trimmed, 5_000_000n))
			)!;
			expect(local).to.match(WIRE);
			expect(local).to.match(/floorFeeratePerKw=5000/);
			expect(local).to.match(/senderViewFeeratePerKw=2500/);
		});

		it('our own add the peer has not revoked for is neither debited nor counted (scratch B)', function () {
			// addHtlc debits localBalanceMsat at send; the peer debits us only
			// on its revoke_and_ack and prices cost(1) against balance + 50,000
			// until then. A 50,000-sat PENDING add of ours with the balance at
			// reserve + cost(2) - 1 msat is offered by every honest peer.
			const pending: IFixtureHtlc[] = [
				{
					amountMsat: 50_000_000n,
					direction: HtlcDirection.OFFERED,
					state: HtlcState.PENDING,
					addRemoteCommitted: false
				}
			];
			const channel = makeChannel({
				localMsat: RESERVE_MSAT + cost(2) - 1n,
				htlcs: pending
			});
			expect(eclairPeerWouldOffer(channel, 5_000_000n)).to.equal(true);
			expect(outcomeOf(channel, 5_000_000n)).to.equal('clean');
			// Once the peer has revoked for it, it is debited and counted.
			const revoked = makeChannel({
				localMsat: RESERVE_MSAT + cost(2) - 1n,
				htlcs: [{ ...pending[0], addRemoteCommitted: true }]
			});
			expect(eclairPeerWouldOffer(revoked, 5_000_000n)).to.equal(false);
			expect(outcomeOf(revoked, 5_000_000n)).to.equal('stamped');
		});

		it('a received HTLC we fulfilled is not credited while the peer has not revoked for its removal', function () {
			// handleRevokeAndAck credits and deletes the entry on the peer's
			// revoke_and_ack; until then the output stands and the value is in
			// neither balance. Crediting it here let a peer stack 98 adds and
			// build a held commitment with no to_local (review round 1). The
			// live balance is 5,000 sats short of the sender's view, and the
			// unapplied fulfill does not make it up: stamped, not clean.
			const fulfilled = makeChannel({
				localMsat: RESERVE_MSAT + cost(1) - 5_000_000n,
				htlcs: [
					{
						amountMsat: 5_000_000n,
						direction: HtlcDirection.RECEIVED,
						state: HtlcState.FULFILLED,
						removalRemoteCommitted: false
					}
				]
			});
			expect(eclairPeerWouldOffer(fulfilled, 5_000_000n)).to.equal(false);
			expect(outcomeOf(fulfilled, 5_000_000n)).to.equal('stamped');
			// An offered HTLC the peer failed IS credited: the peer's own
			// proposal, in its view from the moment it sent it.
			const failed = makeChannel({
				localMsat: RESERVE_MSAT + cost(1) - 5_000_000n,
				htlcs: [
					{
						amountMsat: 5_000_000n,
						direction: HtlcDirection.OFFERED,
						state: HtlcState.FAILED,
						removalLocallyRevoked: false
					}
				]
			});
			expect(eclairPeerWouldOffer(failed, 5_000_000n)).to.equal(true);
			expect(outcomeOf(failed, 5_000_000n)).to.equal('clean');
		});

		it('the credit exploit (scratch C): unapplied fulfills cannot buy adds past our dust limit', function () {
			// Live 20,410 sats, 20 fulfilled 3,000-sat HTLCs awaiting the peer's
			// revoke_and_ack, so 20 outputs still stand in the commitment we
			// hold. cost(20 + k) = 1,810 + 430 (20 + k): the sender's view is
			// short from the first add (10,410 < cost(21)), the floor admits
			// 22 stamped adds (20,410 - cost(42) = 540 >= 354) and fails the
			// channel on the 23rd (cost(43) = 20,300 leaves 110). Round 1's
			// arithmetic admitted 98 and held a commitment with no to_local.
			const held: IFixtureHtlc[] = [];
			for (let i = 0; i < 20; i++) {
				held.push({
					amountMsat: 3_000_000n,
					direction: HtlcDirection.RECEIVED,
					state: HtlcState.FULFILLED,
					removalRemoteCommitted: false
				});
			}
			const channel = makeChannel({ localMsat: 20_410_000n, htlcs: held });
			expect(eclairPeerWouldOffer(channel, 5_000_000n)).to.equal(false);
			const outcomes: Outcome[] = [];
			for (let i = 1; i <= 30; i++) {
				const o = outcomeOf(channel, 5_000_000n, BigInt(100 + i));
				outcomes.push(o);
				if (o === 'wire') break;
			}
			expect(outcomes.filter((o) => o === 'clean')).to.have.length(0);
			expect(outcomes.filter((o) => o === 'stamped')).to.have.length(22);
			expect(outcomes[22]).to.equal('wire');
			const commitment = heldCommitment(channel);
			expect(commitment.htlcOutputs).to.equal(42);
			expect(commitment.toLocalSats).to.equal(540);
		});

		it('the reproduction from the issue: 5,000-sat adds into a 30,000-sat funder', function () {
			// Non-anchor channel we opened at 2,500 sat/kw, our balance 30,000
			// sats, reserve 10,000: cost(n) = 1,810 + 430n. The sender's view
			// admits 42 (cost(42) = 19,870 <= 20,000), the band takes adds 43
			// to 64 stamped (30,000 - cost(64) = 670 >= 354) and the 65th fails
			// the channel (cost(65) = 29,760 leaves 240). On master every one
			// of the 80 was admitted and past the 65th our output was gone.
			expect(funderCommitmentCostSats(RATE, 42, null)).to.equal(19_870n);
			expect(funderCommitmentCostSats(RATE, 43, null)).to.equal(20_300n);
			expect(funderCommitmentCostSats(RATE, 64, null)).to.equal(29_330n);
			expect(funderCommitmentCostSats(RATE, 65, null)).to.equal(29_760n);
			const channel = makeChannel({ localMsat: 30_000_000n });
			const outcomes: Outcome[] = [];
			for (let i = 1; i <= 80; i++) {
				const o = outcomeOf(channel, 5_000_000n, BigInt(i));
				outcomes.push(o);
				if (o === 'wire') break;
			}
			expect(outcomes.filter((o) => o === 'clean')).to.have.length(42);
			expect(outcomes.filter((o) => o === 'stamped')).to.have.length(22);
			expect(outcomes.length, 'the 65th fails the channel').to.equal(65);
			expect(outcomes[64]).to.equal('wire');
			// The commitment we hold still carries our to_local output, above
			// our dust limit, with every admitted HTLC in it.
			const commitment = heldCommitment(channel);
			expect(commitment.htlcOutputs).to.equal(64);
			expect(commitment.toLocalSats).to.equal(670);
		});

		it('leaves the acceptor arm alone: a drained acceptor still takes the add', function () {
			const channel = makeChannel({
				role: ChannelRole.ACCEPTOR,
				localMsat: RESERVE_MSAT
			});
			expect(outcomeOf(channel, 5_000_000n)).to.equal('clean');
		});

		it('the stamp survives serialization', function () {
			const channel = makeChannel({ localMsat: RESERVE_MSAT + cost(1) - 1n });
			expect(outcomeOf(channel, 5_000_000n)).to.equal('stamped');
			const entry = channel.getFullState().htlcs.get('received-99')!;
			expect(entry.funderFeeFailback).to.equal(true);
			const round = deserializeHtlcEntry(
				serializeHtlcEntry('received-99', entry)
			);
			expect(round.entry.funderFeeFailback).to.equal(true);
			const clean = makeChannel({ localMsat: RESERVE_MSAT + cost(1) });
			expect(outcomeOf(clean, 5_000_000n)).to.equal('clean');
			const cleanEntry = clean.getFullState().htlcs.get('received-99')!;
			expect(cleanEntry.funderFeeFailback).to.equal(undefined);
			expect(
				deserializeHtlcEntry(serializeHtlcEntry('received-99', cleanEntry))
					.entry.funderFeeFailback
			).to.equal(undefined);
		});
	});

	describe("the sender's view is eclair's canSendAdd, to the msat", function () {
		// Across every fixture state above, at and around each boundary: an add
		// eclair's peer would offer is admitted outright, and an add it would
		// not offer is never admitted outright (it lands in the band or on
		// the wire). Equivalence, not one direction, so the view can neither
		// refuse an honest peer nor wave through what it would not send.
		const fixtures: { name: string; make: (delta: bigint) => Channel }[] = [
			{
				name: 'plain boundary',
				make: (d) => makeChannel({ localMsat: RESERVE_MSAT + cost(1) + d })
			},
			{
				name: 'anchor boundary',
				make: (d) =>
					makeChannel({
						channelType: anchorType(),
						localMsat: RESERVE_MSAT + cost(1, anchorType()) + d
					})
			},
			{
				name: 'A: our staged raise',
				make: (d) =>
					makeChannel({
						pendingFeeratePerKw: 5_000,
						localMsat: RESERVE_MSAT + cost(1) + d
					})
			},
			{
				name: 'B: our un-revoked add',
				make: (d) =>
					makeChannel({
						localMsat: RESERVE_MSAT + cost(2) - 50_000_000n + d,
						htlcs: [
							{
								amountMsat: 50_000_000n,
								direction: HtlcDirection.OFFERED,
								state: HtlcState.PENDING,
								addRemoteCommitted: false
							}
						]
					})
			},
			{
				name: 'B revoked: our committed add',
				make: (d) =>
					makeChannel({
						localMsat: RESERVE_MSAT + cost(2) + d,
						htlcs: [
							{
								amountMsat: 50_000_000n,
								direction: HtlcDirection.OFFERED,
								addRemoteCommitted: true
							}
						]
					})
			},
			{
				name: 'C: unapplied fulfill',
				make: (d) =>
					makeChannel({
						localMsat: RESERVE_MSAT + cost(2) + d,
						htlcs: [
							{
								amountMsat: 5_000_000n,
								direction: HtlcDirection.RECEIVED,
								state: HtlcState.FULFILLED,
								removalRemoteCommitted: false
							}
						]
					})
			},
			{
				name: 'D: asymmetric dust',
				make: (d) =>
					makeChannel({
						localDustLimit: 1_000n,
						localMsat: RESERVE_MSAT + cost(0) + d
					})
			},
			{
				name: 'peer-failed offered HTLC',
				make: (d) =>
					makeChannel({
						localMsat: RESERVE_MSAT + cost(1) - 5_000_000n + d,
						htlcs: [
							{
								amountMsat: 5_000_000n,
								direction: HtlcDirection.OFFERED,
								state: HtlcState.FAILED,
								removalLocallyRevoked: false
							}
						]
					})
			}
		];

		for (const f of fixtures) {
			it(`${f.name}: agrees one msat either side of the boundary`, function () {
				const amount = f.name.startsWith('D') ? 2_500_000n : 5_000_000n;
				for (const delta of [-1n, 0n, 1n]) {
					const channel = f.make(delta);
					const eclair = eclairPeerWouldOffer(channel, amount);
					const outcome = outcomeOf(channel, amount);
					expect(outcome === 'clean', `${f.name} delta ${delta}`).to.equal(
						eclair
					);
				}
			});
		}
	});

	describe('addHtlc: the send-side mirror when the peer funds', function () {
		// We are the acceptor at 2,500 sat/kw; the funder keeps a 10,000-sat
		// reserve. The mirror asks for cost(adds + 1 slot), so a single
		// untrimmed add needs the funder to hold reserve + cost(2) = 2,670.
		const fixture = (remoteMsat: bigint, extra: IFixtureOpts = {}): Channel =>
			makeChannel({ role: ChannelRole.ACCEPTOR, remoteMsat, ...extra });
		const send = (channel: Channel, amountMsat = 5_000_000n): string | null =>
			errorOf(
				channel.addHtlc(
					amountMsat,
					crypto.randomBytes(32),
					500,
					Buffer.alloc(1366)
				)
			);

		it('admits an add the funder can pay the fee for, one slot to spare', function () {
			const channel = fixture(RESERVE_MSAT + cost(2));
			expect(channel.canOfferHtlcSet([5_000_000n])).to.equal(true);
			expect(send(channel)).to.equal(null);
			expect(channel.getFullState().htlcs.size).to.equal(1);
			// The slot it kept is the one this add took: a second untrimmed
			// add would need cost(3) of the funder.
			expect(channel.canOfferHtlcSet([5_000_000n])).to.equal(false);
		});

		it('refuses locally, without touching the channel, one msat inside', function () {
			// The folded ceiling answers first for a single add (the router's
			// figure and the mirror agree); with the fold bypassed the mirror
			// itself answers. Either way: one bare local error, no state moved.
			const refused = (channel: Channel, message: string): void => {
				expect(channel.canOfferHtlcSet([5_000_000n])).to.equal(false);
				const actions = channel.addHtlc(
					5_000_000n,
					crypto.randomBytes(32),
					500,
					Buffer.alloc(1366)
				);
				expect(errorOf(actions)).to.equal(message);
				expect(actions.length, 'a bare local error').to.equal(1);
				const state = channel.getFullState();
				expect(state.state).to.equal(ChannelState.NORMAL);
				expect(state.htlcs.size).to.equal(0);
				expect(state.localBalanceMsat).to.equal(500_000_000n);
			};
			refused(
				fixture(RESERVE_MSAT + cost(2) - 1n),
				'Insufficient balance for HTLC'
			);
			const unfolded = fixture(RESERVE_MSAT + cost(2) - 1n);
			(
				unfolded as unknown as {
					_remoteFunderCeilingMsat: (s: bigint) => bigint;
				}
			)._remoteFunderCeilingMsat = (s: bigint): bigint => s;
			refused(unfolded, MIRROR);
		});

		it('prices the rate the funder has acked: a staged raise counts only once signable', function () {
			const staged = fixture(RESERVE_MSAT + cost(2), {
				pendingFeeratePerKw: 5_000
			});
			expect(staged.canOfferHtlcSet([5_000_000n])).to.equal(true);
			const signable = fixture(RESERVE_MSAT + cost(2), {
				pendingFeeratePerKw: 5_000,
				pendingFeerateSignable: true
			});
			expect(signable.canOfferHtlcSet([5_000_000n])).to.equal(false);
			expect(
				fixture(RESERVE_MSAT + cost(2, null, 5_000), {
					pendingFeeratePerKw: 5_000,
					pendingFeerateSignable: true
				}).canOfferHtlcSet([5_000_000n])
			).to.equal(true);
		});

		it("an add of the funder's we have not revoked for is neither debited nor counted", function () {
			// handleUpdateAddHtlc debited it at receipt; the funder's own view
			// debits it only on our revoke_and_ack and does not count it yet.
			const unrevoked = fixture(RESERVE_MSAT + cost(2) - 50_000_000n, {
				htlcs: [
					{
						amountMsat: 50_000_000n,
						direction: HtlcDirection.RECEIVED,
						state: HtlcState.PENDING,
						addLocallyRevoked: false
					}
				]
			});
			expect(unrevoked.canOfferHtlcSet([5_000_000n])).to.equal(true);
			const revoked = fixture(RESERVE_MSAT + cost(3) - 1n, {
				htlcs: [
					{
						amountMsat: 50_000_000n,
						direction: HtlcDirection.RECEIVED,
						addLocallyRevoked: true
					}
				]
			});
			expect(revoked.canOfferHtlcSet([5_000_000n])).to.equal(false);
		});

		it('credits a fulfill of ours only once we revoked for its removal, and counts it until then', function () {
			const base = RESERVE_MSAT + cost(2) - 5_000_000n;
			const credited = fixture(base, {
				htlcs: [
					{
						amountMsat: 5_000_000n,
						direction: HtlcDirection.OFFERED,
						state: HtlcState.FULFILLED,
						removalLocallyRevoked: true
					}
				]
			});
			expect(credited.canOfferHtlcSet([5_000_000n])).to.equal(true);
			// Not yet revoked for: no credit, and the output still counts, so
			// even reserve + cost(2) is short (the funder needs cost(3)).
			const standing = fixture(RESERVE_MSAT + cost(2), {
				htlcs: [
					{
						amountMsat: 5_000_000n,
						direction: HtlcDirection.OFFERED,
						state: HtlcState.FULFILLED,
						removalLocallyRevoked: false
					}
				]
			});
			expect(standing.canOfferHtlcSet([5_000_000n])).to.equal(false);
			expect(
				fixture(RESERVE_MSAT + cost(3), {
					htlcs: [
						{
							amountMsat: 5_000_000n,
							direction: HtlcDirection.OFFERED,
							state: HtlcState.FULFILLED,
							removalLocallyRevoked: false
						}
					]
				}).canOfferHtlcSet([5_000_000n])
			).to.equal(true);
			// Our own fail of the funder's HTLC refunds it at once (our
			// proposal, credited by every sender).
			const refunded = fixture(base, {
				htlcs: [
					{
						amountMsat: 5_000_000n,
						direction: HtlcDirection.RECEIVED,
						state: HtlcState.FAILED,
						removalRemoteCommitted: false
					}
				]
			});
			expect(refunded.canOfferHtlcSet([5_000_000n])).to.equal(true);
		});

		it("a trimmed add asks only the slot: it is a received output on the funder's commitment", function () {
			// Our offered add is a RECEIVED output there, so the HTLC-success
			// fee sets its threshold at the funder's dust limit.
			const channel = fixture(RESERVE_MSAT + cost(1));
			expect(
				channel.canOfferHtlcSet([RECEIVED_TRIM_SATS * 1000n - 1n])
			).to.equal(true);
			expect(channel.canOfferHtlcSet([RECEIVED_TRIM_SATS * 1000n])).to.equal(
				false
			);
		});

		it('folds into the outbound ceiling: unchanged, trimmed-only, or zero', function () {
			const own = fixture(RESERVE_MSAT + cost(2));
			const unchanged = own.getSpendableOutboundMsat();
			expect(unchanged > RECEIVED_TRIM_SATS * 1000n).to.equal(true);
			expect(
				fixture(RESERVE_MSAT + cost(2) - 1n).getSpendableOutboundMsat()
			).to.equal(RECEIVED_TRIM_SATS * 1000n - 1n);
			expect(
				fixture(RESERVE_MSAT + cost(1)).getSpendableOutboundMsat()
			).to.equal(RECEIVED_TRIM_SATS * 1000n - 1n);
			expect(
				fixture(RESERVE_MSAT + cost(1) - 1n).getSpendableOutboundMsat()
			).to.equal(0n);
		});

		it('binds on the pending-splice view from the persisted record after a restart', function () {
			// The funder spliced 490,000 sats out; no in-memory session (a
			// restart), only the record. Its pending balance is the remainder
			// of the new capacity after ours and the in-flight value, 10,000
			// sats, which is exactly its reserve: cost(2) short.
			const record: Partial<ISpliceInFlight> = {
				newFundingSatoshis: 510_000n,
				localRelativeSatoshis: 0n,
				remoteRelativeSatoshis: -490_000n,
				isInitiator: false
			};
			const live = fixture(RESERVE_MSAT + cost(2));
			expect(live.canOfferHtlcSet([5_000_000n])).to.equal(true);
			const spliced = fixture(RESERVE_MSAT + cost(2), {
				spliceInFlight: record
			});
			expect(spliced.canOfferHtlcSet([5_000_000n])).to.equal(false);
			expect(spliced.getSpendableOutboundMsat()).to.equal(0n);
		});

		it('is not asked when we fund: our own ceiling already retains the fee', function () {
			const channel = makeChannel({
				role: ChannelRole.OPENER,
				localMsat: 100_000_000n,
				remoteMsat: RESERVE_MSAT
			});
			const ceiling = channel.getSpendableOutboundMsat();
			expect(channel.canOfferHtlcSet([ceiling])).to.equal(true);
			expect(send(channel, ceiling)).to.equal(null);
		});
	});

	describe('two honest beignet nodes over a loopback wire', function () {
		this.timeout(30_000);

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
			return from.getPayment(sent.paymentHash)?.status;
		}

		/** Pay a hold invoice and report the payer's record. */
		function payHold(
			from: LightningNode,
			to: LightningNode,
			amountMsat: bigint,
			tag: string
		): {
			status: PaymentStatus | undefined;
			failureCode?: number;
			noRoute?: boolean;
		} {
			const invoice = to.createInvoice({
				amountMsat,
				description: tag,
				hold: true
			});
			let sent: { paymentHash: Buffer };
			try {
				sent = from.sendPayment(invoice.bolt11);
			} catch (err) {
				// The folded ceiling took the channel out of the router's view:
				// the sender's own refusal, before any add left.
				expect((err as Error).message).to.match(/No route found/);
				return { status: PaymentStatus.FAILED, noRoute: true };
			}
			const record = from.getPayment(sent.paymentHash);
			return { status: record?.status, failureCode: record?.failureCode };
		}

		function bothNormal(channelId: Buffer): void {
			for (const n of [alice, bob]) {
				expect(
					n.getChannelManager().getChannel(channelId)!.getState()
				).to.equal(ChannelState.NORMAL);
			}
		}

		/** Alice at her floor: reserve plus the fee-spike buffer her ceiling keeps. */
		function drainAlice(channelId: Buffer): {
			headroomSats: bigint;
			cost: (k: number) => bigint;
		} {
			expect(payCeiling(alice, bob, channelId)).to.equal(
				PaymentStatus.COMPLETED
			);
			const state = alice
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			const headroomSats =
				(state.localBalanceMsat -
					state.remoteConfig.channelReserveSatoshis * 1000n) /
				1000n;
			return {
				headroomSats,
				cost: (k: number): bigint =>
					funderCommitmentCostSats(
						state.localConfig.feeratePerKw,
						k,
						state.channelType
					)
			};
		}

		beforeEach(function () {
			errors = [];
			alice = node(1);
			bob = node(2);
		});

		afterEach(function () {
			alice.destroy();
			bob.destroy();
		});

		it('a peer paying at ITS ceiling into a channel WE opened is not refused', function () {
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			expect(payCeiling(alice, bob, channelId)).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(payCeiling(bob, alice, channelId)).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(errors.filter((m) => /cannot afford/i.test(m))).to.deep.equal([]);
			bothNormal(channelId);
		});

		it('stacked hold invoices stop at the sender, one slot before the funder would refuse', function () {
			// Bob admits the k-th add while cost(k + 1) fits Alice's headroom;
			// Alice's own view would only refuse once cost(k) does not. Derived
			// from the live channel type and rate.
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			const { headroomSats, cost: c } = drainAlice(channelId);
			let expectedParked = 0;
			while (c(expectedParked + 2) <= headroomSats) expectedParked++;
			expect(expectedParked >= 2, 'a stack worth the name').to.equal(true);
			expect(
				c(expectedParked + 1) <= headroomSats,
				'the funder would still have admitted the add the sender refused'
			).to.equal(true);

			const outcomes: (PaymentStatus | undefined)[] = [];
			let refusedByRouter = false;
			for (let i = 0; i < expectedParked + 3; i++) {
				const { status, noRoute } = payHold(
					bob,
					alice,
					10_000_000n,
					`hold ${i}`
				);
				outcomes.push(status);
				if (status === PaymentStatus.FAILED) {
					refusedByRouter = noRoute === true;
					break;
				}
			}
			const parked = alice
				.listHoldInvoices()
				.filter((h) => h.state === 'ACCEPTED').length;
			expect(parked, 'HTLCs parked at Alice').to.equal(expectedParked);
			expect(outcomes.length).to.equal(expectedParked + 1);
			expect(outcomes[expectedParked]).to.equal(PaymentStatus.FAILED);
			expect(
				refusedByRouter,
				'the folded ceiling kept the router off'
			).to.equal(true);
			expect(
				errors.some((m) => /inbound HTLC/.test(m)),
				'no wire refusal at the funder'
			).to.equal(false);
			bothNormal(channelId);
		});

		it('a peer without the mirror lands in the band: failed back after commit, channel kept', function () {
			// Simulate a sender that does not share the mirror (disable Bob's).
			// Alice admits while cost(k) fits her headroom, then stamps the
			// next adds and fails them back once committed with the final-hop
			// answer; the channel survives and the parked stack is untouched.
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			const { headroomSats, cost: c } = drainAlice(channelId);
			const bobChannel = bob.getChannelManager().getChannel(channelId)!;
			const unmirrored = bobChannel as unknown as {
				_remoteFunderFeeRefusal: () => string | null;
				_remoteFunderCeilingMsat: (s: bigint) => bigint;
			};
			unmirrored._remoteFunderFeeRefusal = (): string | null => null;
			unmirrored._remoteFunderCeilingMsat = (s: bigint): bigint => s;

			let expectedParked = 0;
			while (c(expectedParked + 1) <= headroomSats) expectedParked++;
			for (let i = 0; i < expectedParked; i++) {
				expect(
					payHold(bob, alice, 10_000_000n, `parked ${i}`).status,
					`hold ${i} parks`
				).to.equal(PaymentStatus.PENDING);
			}
			for (let i = 0; i < 2; i++) {
				const { status, failureCode } = payHold(
					bob,
					alice,
					10_000_000n,
					`band ${i}`
				);
				expect(status, `band add ${i} failed back`).to.equal(
					PaymentStatus.FAILED
				);
				expect(failureCode).to.equal(INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS);
			}
			expect(
				alice.listHoldInvoices().filter((h) => h.state === 'ACCEPTED').length
			).to.equal(expectedParked);
			expect(
				errors.some((m) => /inbound HTLC/.test(m)),
				'no wire refusal'
			).to.equal(false);
			bothNormal(channelId);
			// The commitment Alice holds keeps her output above the reserve
			// once the band adds are gone.
			const aliceState = alice
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			expect(
				aliceState.localBalanceMsat >=
					aliceState.remoteConfig.channelReserveSatoshis * 1000n
			).to.equal(true);
		});

		it('an add that crosses our own update_fee raise at the old-rate boundary is admitted', function () {
			// Alice raises the rate; Bob's add leaves before he has seen her
			// commitment_signed for it (her outbound direction is held). Alice
			// prices the add at the rate Bob has revoked for and takes it
			// outright; the rate then promotes with the add in the commitment.
			let held = false;
			const queue: { type: number; payload: Buffer }[] = [];
			alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
				if (pk !== bob.getNodeId()) return;
				if (held && t !== MessageType.UPDATE_FEE) {
					queue.push({ type: t, payload: Buffer.from(p) });
					return;
				}
				bob.handlePeerMessage(alice.getNodeId(), t, p);
			});
			bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
				if (pk === alice.getNodeId())
					alice.handlePeerMessage(bob.getNodeId(), t, p);
			});
			const channelId = openReadyChannel(alice, bob);
			const { headroomSats, cost: c } = drainAlice(channelId);
			const aliceState = alice
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			// A raise Alice can afford with no HTLC, but not with one, while
			// one still fits at the old rate.
			let raised = aliceState.localConfig.feeratePerKw + 1;
			while (c(1) <= headroomSats) {
				const costAt = (k: number): bigint =>
					funderCommitmentCostSats(raised, k, aliceState.channelType);
				if (costAt(0) <= headroomSats && costAt(1) > headroomSats) break;
				raised++;
				if (raised > 5_000) throw new Error('no boundary rate found');
			}
			held = true;
			expect(alice.updateChannelFee(channelId, raised).ok).to.equal(true);
			expect(queue.length, 'the covering commitment_signed is held').to.equal(
				1
			);
			expect(queue[0].type).to.equal(MessageType.COMMITMENT_SIGNED);

			const { status } = payHold(bob, alice, 10_000_000n, 'crossing');
			expect(status).to.equal(PaymentStatus.PENDING);
			const aliceChannel = alice.getChannelManager().getChannel(channelId)!;
			const parkedId = [...aliceChannel.getFullState().htlcs.entries()].find(
				([k]) => k.startsWith('received-')
			)![1].id;
			expect(
				aliceChannel.receivedHtlcExceedsFunderFee(parkedId),
				'admitted outright, not in the band'
			).to.equal(false);

			// Release in Alice's send order. Her replies to what Bob answers
			// during the release are queued behind what is still held, so Bob
			// never sees her second commitment_signed ahead of the
			// revoke_and_ack she sent first.
			while (queue.length > 0) {
				const m = queue.shift()!;
				bob.handlePeerMessage(alice.getNodeId(), m.type, m.payload);
			}
			held = false;
			bothNormal(channelId);
			expect(aliceChannel.getFullState().localConfig.feeratePerKw).to.equal(
				raised
			);
			expect(aliceChannel.getFullState().pendingFeeratePerKw).to.equal(
				undefined
			);
			expect(
				alice.listHoldInvoices().filter((h) => h.state === 'ACCEPTED').length
			).to.equal(1);
			expect(errors.filter((m) => /cannot afford/i.test(m))).to.deep.equal([]);
		});
	});
});
