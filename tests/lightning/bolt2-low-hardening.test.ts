/**
 * BOLT 2 LOW-severity hardening batch (2026-07-15 review):
 *  - funding cap is 2^24 - 1 (funding_satoshis MUST be < 2^24);
 *  - off-curve basepoints rejected on open_channel / accept_channel;
 *  - accept_channel omitting channel_type after open_channel set it fails;
 *  - accept_channel WE build couples reserve/dust to the opener's values;
 *  - cltv_expiry >= 500000000 rejected on send and receive;
 *  - channel_reestablish next_commitment_number == 0 fails the channel;
 *  - channel_ready retransmitted when peer's next_commitment_number == 1;
 *  - tx_abort echoed from active dual-funding/splice sessions;
 *  - RBF feerate floor is 25/24 of the previous feerate;
 *  - splice-out destination script must be a standard output form.
 * (Splice tx_init_rbf tx_abort reply is covered in splice.test.ts context;
 * per-output penalty splitting near expiry is tracked as its own follow-up.)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	Channel,
	createOpenerChannel
} from '../../src/lightning/channel/channel';
import { createAcceptorState } from '../../src/lightning/channel/channel-state';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { expectWireRefusal, wireRefusalOf } from './helpers/open-refusal';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	MAX_DUST_LIMIT_SATOSHIS,
	MAX_FUNDING_SATOSHIS
} from '../../src/lightning/channel/types';
import {
	validateOpenChannelParams,
	validateAcceptChannelParams
} from '../../src/lightning/channel/validation';
import { rbfFeerateFloor } from '../../src/lightning/channel/dual-funding';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage,
	IOpenChannelMessage,
	IAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import { IUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';
import {
	seedKey,
	signerFromSeed,
	realInitialCommitmentSig,
	realCommitmentSigs
} from './helpers/real-signing';
import { decodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';

function realBasepoints(seed?: Buffer): IChannelBasepoints {
	// With a seed, derive with the seedKey convention so signerFromSeed(seed)
	// matches the basepoints; without one the keys are throwaway randoms.
	const s = seed ?? crypto.randomBytes(32);
	return {
		fundingPubkey: getPublicKey(seedKey(s, 0)),
		revocationBasepoint: getPublicKey(seedKey(s, 1)),
		paymentBasepoint: getPublicKey(seedKey(s, 2)),
		delayedPaymentBasepoint: getPublicKey(seedKey(s, 3)),
		htlcBasepoint: getPublicKey(seedKey(s, 4)),
		firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
	};
}

/** A 33-byte buffer that is definitely NOT a secp256k1 point (bad prefix). */
function offCurvePoint(): Buffer {
	return Buffer.alloc(33, 0xff);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSend(actions: any[], type: MessageType): Buffer | null {
	for (const a of actions) {
		if (a.type === ChannelActionType.SEND_MESSAGE && a.messageType === type) {
			return a.payload;
		}
	}
	return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function errorOf(actions: any[]): string | null {
	const e = actions.find(
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(a: any) => a.type === ChannelActionType.ERROR
	);
	return e ? e.message : null;
}

function makeValidOpenMsg(): IOpenChannelMessage {
	const bp = realBasepoints();
	return {
		chainHash: BITCOIN_CHAIN_HASH,
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		channelReserveSatoshis: 10_000n,
		htlcMinimumMsat: 1_000n,
		feeratePerKw: 253,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		fundingPubkey: bp.fundingPubkey,
		revocationBasepoint: bp.revocationBasepoint,
		paymentBasepoint: bp.paymentBasepoint,
		delayedPaymentBasepoint: bp.delayedPaymentBasepoint,
		htlcBasepoint: bp.htlcBasepoint,
		firstPerCommitmentPoint: bp.firstPerCommitmentPoint,
		channelFlags: 0x01
	};
}

/**
 * Drive a real opener + acceptor to the accept_channel message.
 *
 * fundingSatoshis/pushMsat are parameters rather than something mutateOpen can
 * set, because handleOpenChannel re-reads the capacity from the message while
 * the opener keeps the one it was constructed with: mutating it in place moves
 * only the acceptor, and leaves the opener at 1,000,000, the single capacity
 * where computeChannelReserve returns exactly DEFAULT_CHANNEL_CONFIG's static
 * 10,000 and a reserve derivation bug is invisible.
 */
function openerAndAccept(
	mutateOpen?: (msg: IOpenChannelMessage) => void,
	acceptorDustLimit?: bigint,
	fundingSatoshis = 1_000_000n,
	pushMsat = 0n
): {
	opener: Channel;
	acceptor: Channel;
	openMsg: IOpenChannelMessage;
	acceptActions: ReturnType<Channel['handleOpenChannel']>;
	accept: IAcceptChannelMessage | null;
} {
	const openerSeed = crypto.randomBytes(32);
	const acceptorSeed = crypto.randomBytes(32);
	const opener = createOpenerChannel({
		fundingSatoshis,
		pushMsat,
		localBasepoints: realBasepoints(openerSeed),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	opener.setSigner(signerFromSeed(openerSeed));
	const openActions = opener.initiateOpen();
	const openMsg = decodeOpenChannelMessage(
		findSend(openActions, MessageType.OPEN_CHANNEL)!
	);
	if (mutateOpen) mutateOpen(openMsg);

	const acceptorState = createAcceptorState({
		temporaryChannelId: openMsg.temporaryChannelId,
		fundingSatoshis: openMsg.fundingSatoshis,
		pushMsat: openMsg.pushMsat,
		localConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			...(acceptorDustLimit !== undefined
				? { dustLimitSatoshis: acceptorDustLimit }
				: {})
		},
		localBasepoints: realBasepoints(acceptorSeed),
		localPerCommitmentSeed: crypto.randomBytes(32),
		remoteBasepoints: {
			fundingPubkey: openMsg.fundingPubkey,
			revocationBasepoint: openMsg.revocationBasepoint,
			paymentBasepoint: openMsg.paymentBasepoint,
			delayedPaymentBasepoint: openMsg.delayedPaymentBasepoint,
			htlcBasepoint: openMsg.htlcBasepoint,
			firstPerCommitmentPoint: openMsg.firstPerCommitmentPoint
		},
		remoteConfig: {
			dustLimitSatoshis: openMsg.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: openMsg.maxHtlcValueInFlightMsat,
			channelReserveSatoshis: openMsg.channelReserveSatoshis,
			htlcMinimumMsat: openMsg.htlcMinimumMsat,
			toSelfDelay: openMsg.toSelfDelay,
			maxAcceptedHtlcs: openMsg.maxAcceptedHtlcs,
			feeratePerKw: openMsg.feeratePerKw
		}
	});
	const acceptor = new Channel(acceptorState);
	acceptor.setSigner(signerFromSeed(acceptorSeed));
	const acceptActions = acceptor.handleOpenChannel(openMsg);
	const payload = findSend(acceptActions, MessageType.ACCEPT_CHANNEL);
	const accept = payload ? decodeAcceptChannelMessage(payload) : null;
	return { opener, acceptor, openMsg, acceptActions, accept };
}

/** An update_add_htlc as it arrives at `side`. A refused add burns no id. */
function inboundHtlc(
	side: Channel,
	amountMsat: bigint,
	id = 0n
): IUpdateAddHtlcMessage {
	return {
		channelId: side.getChannelId()!,
		id,
		amountMsat,
		paymentHash: crypto.randomBytes(32),
		cltvExpiry: 800_000,
		onionRoutingPacket: Buffer.alloc(1366)
	};
}

/** Drive a pair all the way to NORMAL (real sigs; no commitment exchange). */
function normalPair(
	fundingSatoshis = 1_000_000n,
	pushMsat = 0n,
	mutateOpen?: (msg: IOpenChannelMessage) => void
): { opener: Channel; acceptor: Channel } {
	const { opener, acceptor, accept } = openerAndAccept(
		mutateOpen,
		undefined,
		fundingSatoshis,
		pushMsat
	);
	opener.handleAcceptChannel(accept!);
	const fundingTxid = crypto.randomBytes(32);
	const sig = realInitialCommitmentSig(opener, fundingTxid, 0);
	opener.createFundingCreated(fundingTxid, 0, sig);
	const channelId = opener.getChannelId()!;
	const acceptorSig = realInitialCommitmentSig(acceptor, fundingTxid, 0);
	acceptor.handleFundingCreated(
		{
			temporaryChannelId: opener.getTemporaryChannelId(),
			fundingTxid,
			fundingOutputIndex: 0,
			signature: sig
		},
		acceptorSig
	);
	opener.handleFundingSigned({ channelId, signature: acceptorSig });
	opener.fundingConfirmed();
	acceptor.fundingConfirmed();
	opener.handleChannelReady({
		channelId,
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
	});
	acceptor.handleChannelReady({
		channelId: acceptor.getChannelId()!,
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
	});
	return { opener, acceptor };
}

describe('BOLT 2 LOW hardening batch', function () {
	describe('funding cap (funding_satoshis < 2^24)', function () {
		it('the cap constant is 2^24 - 1', function () {
			expect(MAX_FUNDING_SATOSHIS).to.equal(16_777_215n);
		});

		it('rejects funding of exactly 2^24 and accepts 2^24 - 1', function () {
			const at = makeValidOpenMsg();
			at.fundingSatoshis = 16_777_216n;
			expect(validateOpenChannelParams(at)).to.match(/exceeds maximum/);

			const under = makeValidOpenMsg();
			under.fundingSatoshis = 16_777_215n;
			expect(validateOpenChannelParams(under)).to.equal(null);
		});
	});

	describe('secp256k1 point validation on open/accept', function () {
		it('rejects an open_channel with an off-curve basepoint', function () {
			const msg = makeValidOpenMsg();
			msg.htlcBasepoint = offCurvePoint();
			expect(validateOpenChannelParams(msg)).to.match(
				/htlc_basepoint.*not a valid/
			);
		});

		it('rejects an off-curve first_per_commitment_point', function () {
			const msg = makeValidOpenMsg();
			msg.firstPerCommitmentPoint = offCurvePoint();
			expect(validateOpenChannelParams(msg)).to.match(
				/first_per_commitment_point.*not a valid/
			);
		});

		it('rejects an accept_channel with an off-curve basepoint', function () {
			const { openMsg, accept } = openerAndAccept();
			accept!.revocationBasepoint = offCurvePoint();
			expect(validateAcceptChannelParams(openMsg, accept!)).to.match(
				/revocation_basepoint.*not a valid/
			);
		});

		it('accepts real points end-to-end', function () {
			const { openMsg, accept } = openerAndAccept();
			expect(validateAcceptChannelParams(openMsg, accept!)).to.equal(null);
		});
	});

	describe('channel_type mirroring in accept_channel', function () {
		it('fails when accept_channel omits the channel_type open_channel set', function () {
			const { opener, accept } = openerAndAccept();
			expect(accept!.channelType, 'harness sanity: opener set a type').to.not.be
				.undefined;
			delete accept!.channelType;
			const actions = opener.handleAcceptChannel(accept!);
			expect(errorOf(actions)).to.match(/omitted channel_type/);
			expect(opener.getState()).to.equal(ChannelState.SENT_OPEN);
		});
	});

	describe('accept_channel build-side reserve/dust coupling', function () {
		it('raises our channel_reserve to at least the opener dust_limit', function () {
			// A 50,000-sat channel with a 1,000-sat opener dust limit: values
			// chosen to stay inside the MAX_DUST_LIMIT_SATOSHIS bound the
			// acceptor now applies to a peer's open_channel (issue 381), which
			// the former 20,000-sat dust limit no longer clears.
			const { accept, acceptActions } = openerAndAccept(
				(open) => {
					open.dustLimitSatoshis = 1_000n;
					open.channelReserveSatoshis = 1_000n;
				},
				undefined,
				50_000n
			);
			expect(errorOf(acceptActions)).to.equal(null);
			// Our 1% formula would give 546; the opener's dust forces >= 1,000.
			expect(accept!.channelReserveSatoshis).to.equal(1_000n);
		});

		it('rejects an open whose channel_reserve is below our dust_limit', function () {
			// Acceptor configured with a 600-sat dust floor; the opener's reserve
			// (400) cannot cover it, so emitting accept_channel would violate
			// BOLT 2 — reject the open instead.
			const { acceptActions, accept, acceptor } = openerAndAccept((open) => {
				open.dustLimitSatoshis = 354n;
				open.channelReserveSatoshis = 400n;
			}, 600n);
			expect(accept).to.equal(null);
			expect(errorOf(acceptActions)).to.match(/dust_limit.*channel_reserve/);
			// A refused open must leave enforcement untouched: the reserve is
			// recorded only past the last refusal arm.
			expect(
				acceptor.getFullState().localConfig.channelReserveSatoshis
			).to.equal(DEFAULT_CHANNEL_CONFIG.channelReserveSatoshis);
		});
	});

	describe('v1 channel_reserve: advertised == enforced (issue 381)', function () {
		it('opener enforces the reserve its open_channel advertised (issue 381)', function () {
			// localConfig.channelReserveSatoshis is what handleUpdateAddHtlc
			// requires the peer to keep. Left at the config default it is a flat
			// 10,000 while the wire carries 1% of capacity, so the peer spends
			// down to what we told it and we refuse the HTLC.
			const { openMsg, opener } = openerAndAccept(
				undefined,
				undefined,
				150_000n
			);
			expect(openMsg.channelReserveSatoshis).to.equal(1_500n);
			expect(opener.getFullState().localConfig.channelReserveSatoshis).to.equal(
				1_500n
			);
		});

		it('opener enforces the advertised reserve above 1,000,000 sat too (issue 381)', function () {
			// The other side of the static value, where it under-enforces.
			const { openMsg, opener } = openerAndAccept(
				undefined,
				undefined,
				5_000_000n
			);
			expect(openMsg.channelReserveSatoshis).to.equal(50_000n);
			expect(opener.getFullState().localConfig.channelReserveSatoshis).to.equal(
				50_000n
			);
		});

		it('acceptor enforces the reserve its accept_channel advertised (issue 381)', function () {
			const { accept, acceptor } = openerAndAccept(
				undefined,
				undefined,
				150_000n
			);
			expect(accept!.channelReserveSatoshis).to.equal(1_500n);
			expect(
				acceptor.getFullState().localConfig.channelReserveSatoshis
			).to.equal(1_500n);
		});

		it('acceptor enforces the advertised reserve above 1,000,000 sat too (issue 381)', function () {
			const { accept, acceptor } = openerAndAccept(
				undefined,
				undefined,
				5_000_000n
			);
			expect(accept!.channelReserveSatoshis).to.equal(50_000n);
			expect(
				acceptor.getFullState().localConfig.channelReserveSatoshis
			).to.equal(50_000n);
		});

		it('acceptor enforces the opener-dust floor it advertised (issue 381)', function () {
			// The only case that separates the advertised value from the bare
			// computeChannelReserve: 1% of 50,000 is 546, raised to the opener's
			// 1,000-sat dust limit. Recording the unraised value would enforce
			// less than we put on the wire.
			const { accept, acceptor } = openerAndAccept(
				(open) => {
					open.dustLimitSatoshis = 1_000n;
					open.channelReserveSatoshis = 1_000n;
				},
				undefined,
				50_000n
			);
			expect(accept!.channelReserveSatoshis).to.equal(1_000n);
			expect(
				acceptor.getFullState().localConfig.channelReserveSatoshis
			).to.equal(1_000n);
		});

		it('acceptor never advertises a reserve under its own dust limit (issue 381)', function () {
			// computeChannelReserve applies its 20% cap last, so a capacity under
			// 5x our dust limit lands beneath the floor it started from: 2,500/5
			// is 500 against a 600-sat local dust limit. Advertising that pairs a
			// reserve with a dust limit that trims it, and LND refuses such an
			// accept_channel.
			const { accept, acceptor } = openerAndAccept(
				(open) => {
					open.dustLimitSatoshis = 354n;
					open.channelReserveSatoshis = 600n;
				},
				600n,
				2_500n
			);
			expect(accept!.channelReserveSatoshis).to.equal(600n);
			expect(
				acceptor.getFullState().localConfig.channelReserveSatoshis
			).to.equal(600n);
		});

		it('a refused open records no reserve, opener side (issue 381)', function () {
			// 1,000 sat: computeChannelReserve caps at 200, under our 354-sat
			// dust limit, so validateOpenChannelParams refuses our own message.
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000n,
				localBasepoints: realBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			const actions = opener.initiateOpen();
			expect(errorOf(actions)).to.match(
				/channel_reserve_satoshis must be >= dust_limit_satoshis/
			);
			expect(opener.getFullState().localConfig.channelReserveSatoshis).to.equal(
				DEFAULT_CHANNEL_CONFIG.channelReserveSatoshis
			);
			// And no provenance stamp either: the field still holds the node's
			// static configuration, which is exactly the row the load-time repair
			// is allowed to re-derive.
			expect(opener.getFullState().channelReserveVersion).to.equal(undefined);
		});

		it('both roles stamp the reserve they recorded (issue 381)', function () {
			// The stamp is what tells a negotiated reserve apart from an inherited
			// static one on the next load, so an open site that records the value
			// without it would hand the repair a row it must not touch.
			const { opener, acceptor } = openerAndAccept(
				undefined,
				undefined,
				150_000n
			);
			expect(
				opener.getFullState().channelReserveVersion,
				'opener stamped'
			).to.be.a('number');
			expect(
				acceptor.getFullState().channelReserveVersion,
				'acceptor stamped'
			).to.be.a('number');
		});

		it('admits an inbound HTLC down to the reserve we advertised (issue 381)', function () {
			// Opener role, so no commitment-fee term rides on the peer's side:
			// the boundary is the bare 1,500-sat reserve. 147,000,000 msat pushed
			// leaves the acceptor holding everything but 3,000 sat.
			// One pristine channel per side of the boundary: since issue 404 the
			// refusal FAILS the channel, so the admitted case has to be measured on a
			// channel the refused case never touched.
			const { opener: refuses } = normalPair(150_000n, 147_000_000n);
			const { opener: admits } = normalPair(150_000n, 147_000_000n);
			expect(
				refuses.getFullState().localConfig.channelReserveSatoshis
			).to.equal(1_500n);
			expect(
				errorOf(refuses.handleUpdateAddHtlc(inboundHtlc(refuses, 145_500_001n)))
			).to.match(/cannot afford HTLC above channel reserve/);
			expect(
				errorOf(admits.handleUpdateAddHtlc(inboundHtlc(admits, 145_500_000n)))
			).to.equal(null);
			expect(admits.getFullState().remoteBalanceMsat).to.equal(1_500_000n);
		});

		it('admits an inbound HTLC above the reserve as acceptor, fee included (issue 381)', function () {
			// Acceptor role: the peer is the funder, so it must also cover the
			// commitment fee above its reserve. floor(896 * 253 / 1000) = 226 sat
			// on top of 1,500, against the opener's 3,000,000 msat. With the
			// static 10,000 the requirement exceeds the whole balance, so every
			// inbound HTLC on this channel is refused today.
			// One pristine channel per side of the boundary (see above).
			const { acceptor: refuses } = normalPair(150_000n, 147_000_000n);
			const { acceptor: admits } = normalPair(150_000n, 147_000_000n);
			expect(
				refuses.getFullState().localConfig.channelReserveSatoshis
			).to.equal(1_500n);
			expect(
				errorOf(refuses.handleUpdateAddHtlc(inboundHtlc(refuses, 1_274_001n)))
			).to.match(/cannot afford HTLC above channel reserve/);
			expect(
				errorOf(admits.handleUpdateAddHtlc(inboundHtlc(admits, 1_274_000n)))
			).to.equal(null);
			expect(admits.getFullState().remoteBalanceMsat).to.equal(1_726_000n);
		});

		it('admits an update_fee down to the reserve we advertised (issue 381)', function () {
			// The opener's balance must cover the new commitment fee above the
			// reserve we require of it: 3,000,000 - 1,500,000 = 1,500,000 msat of
			// headroom over a 724-weight commitment. Accepted case first, since
			// handleUpdateFee mutates on success.
			const { acceptor } = normalPair(150_000n, 147_000_000n);
			const channelId = acceptor.getChannelId()!;
			// floor(724 * 2000 / 1000) = 1,448 sat, inside the headroom.
			expect(
				errorOf(acceptor.handleUpdateFee({ channelId, feeratePerKw: 2000 }))
			).to.equal(null);
			// floor(724 * 2100 / 1000) = 1,520 sat, past it.
			expect(
				errorOf(acceptor.handleUpdateFee({ channelId, feeratePerKw: 2100 }))
			).to.match(/drain opener below channel reserve/);
		});

		it('fails an accept_channel whose dust_limit exceeds the reserve we proposed (issue 381)', function () {
			// BOLT 2 MUST for the receiver of accept_channel. Against the static
			// 10,000 it could never fire, since a peer dust limit is already
			// bounded at 1,062. No conforming peer is affected: our proposed
			// reserve is at least 546 for any capacity at or above 2,730, and
			// LND advertises 354 while CLN and eclair advertise 546.
			const { opener, accept } = openerAndAccept(undefined, undefined, 50_000n);
			expect(accept!.channelReserveSatoshis).to.equal(546n);
			accept!.dustLimitSatoshis = 1_000n;
			expect(errorOf(opener.handleAcceptChannel(accept!))).to.match(
				/opener channel_reserve must be >= acceptor dust_limit/
			);
		});

		it('completes a small open the static reserve blocked (issue 381)', function () {
			// 546 + 10,000 exceeds a 5,000-sat funding, so our own combined-reserve
			// check killed every v1 open in roughly [1,770, 10,546] after the peer
			// had already sent a legal accept_channel.
			const { opener, accept } = openerAndAccept(undefined, undefined, 5_000n);
			expect(accept!.channelReserveSatoshis).to.equal(546n);
			expect(errorOf(opener.handleAcceptChannel(accept!))).to.equal(null);
		});

		it('refuses a peer open_channel whose dust_limit exceeds the maximum (issue 381)', function () {
			// FS-1 from the acceptor role: buildRemoteCommitment trims at the
			// peer's dust limit, so an opener that sets it near the whole capacity
			// takes our to_remote output out of every commitment we sign.
			const refused = openerAndAccept(
				(open) => {
					open.dustLimitSatoshis = 3_000_000n;
					open.channelReserveSatoshis = 3_000_000n;
				},
				undefined,
				16_777_215n
			);
			expect(refused.accept).to.equal(null);
			expect(errorOf(refused.acceptActions)).to.match(
				/dust_limit_satoshis 3000000 exceeds maximum 1062/
			);
			// remoteConfig already holds the hostile limit at this point: the
			// state was seeded from the message before handleOpenChannel ran,
			// exactly as ChannelManager.handleOpenChannel seeds it. What makes
			// that harmless is that the channel never advances, so it signs
			// nothing, and the manager drops it on the ERROR (covered by
			// 'discards a channel whose open_channel names a hostile dust limit'
			// in channel-manager.test.ts).
			expect(refused.acceptor.getState()).to.equal(ChannelState.NONE);

			const atBound = openerAndAccept((open) => {
				open.dustLimitSatoshis = MAX_DUST_LIMIT_SATOSHIS;
				open.channelReserveSatoshis = 10_000n;
			});
			expect(errorOf(atBound.acceptActions)).to.equal(null);
		});
	});

	it('a restart does not widen what an acceptor admits (issue 381)', function () {
		// End to end for the reserve provenance stamp. The acceptor negotiated
		// max(1% of 50,000, both dust limits) = 1,000 against a 1,000-sat opener
		// dust limit, and that is the number BOLT 2 makes it responsible for
		// refusing below. Re-deriving on load would land at 546, and the 454-sat
		// difference is HTLCs this channel promised to reject and would start
		// accepting on the first restart, against a peer that is under no
		// obligation to be honest about its own reserve.
		const { acceptor } = normalPair(50_000n, 0n, (open) => {
			open.dustLimitSatoshis = 1_000n;
			open.channelReserveSatoshis = 1_000n;
		});
		expect(acceptor.getFullState().localConfig.channelReserveSatoshis).to.equal(
			1_000n
		);
		// Captured BEFORE any probe: since issue 404 a refusal fails the channel,
		// and a row serialized after one carries ERRORED to the restore.
		const row = JSON.parse(
			JSON.stringify(serializeChannelState(acceptor.getFullState()))
		);
		// A fresh restore per probe, for the same reason.
		const restore = (): Channel => {
			const restored = new Channel(
				deserializeChannelState(JSON.parse(JSON.stringify(row)))
			);
			restored.repairEnforcedChannelReserve();
			return restored;
		};

		// 49,100,000 msat sits in the band the two values disagree about: the
		// funder must keep 1,000,000 msat of reserve plus its commitment fee out
		// of 50,000,000, and at 546 it would only have to keep 546,000.
		expect(
			errorOf(acceptor.handleUpdateAddHtlc(inboundHtlc(acceptor, 49_100_000n)))
		).to.match(/cannot afford HTLC above channel reserve/);

		// Round-trip the row through disk and run the load-time repair over it.
		expect(
			restore().getFullState().localConfig.channelReserveSatoshis,
			'the negotiated reserve survived the restart'
		).to.equal(1_000n);
		const refuses = restore();
		expect(
			errorOf(refuses.handleUpdateAddHtlc(inboundHtlc(refuses, 49_100_000n)))
		).to.match(/cannot afford HTLC above channel reserve/);
		// And the refusal is the reserve boundary, not a channel that rejects
		// everything: comfortably under it still goes through.
		const admits = restore();
		expect(
			errorOf(admits.handleUpdateAddHtlc(inboundHtlc(admits, 48_000_000n)))
		).to.equal(null);
	});

	describe('a refused v1 open reaches the opener (issue 381)', function () {
		// A bare ERROR action is never put on the wire, so a refusal the opener
		// cannot see deletes our half of the negotiation while it stays in
		// SENT_OPEN retrying an open that can never be accepted. Every arm that
		// refuses a FRESH open is wire-visible, exactly as handleOpenChannel2 has
		// been since #383.

		it('a peer dust_limit above the maximum', function () {
			const { acceptActions, openMsg } = openerAndAccept(
				(open) => {
					open.dustLimitSatoshis = 3_000_000n;
					open.channelReserveSatoshis = 3_000_000n;
				},
				undefined,
				16_777_215n
			);
			expectWireRefusal(
				acceptActions,
				openMsg.temporaryChannelId,
				/dust_limit_satoshis 3000000 exceeds maximum 1062/
			);
		});

		it('an opener channel_reserve under our dust_limit', function () {
			const { acceptActions, openMsg } = openerAndAccept((open) => {
				open.dustLimitSatoshis = 354n;
				open.channelReserveSatoshis = 400n;
			}, 600n);
			expectWireRefusal(
				acceptActions,
				openMsg.temporaryChannelId,
				/exceeds opener channel_reserve/
			);
		});

		it('our own out-of-range max_htlc_value_in_flight_msat', function () {
			// The one arm that is OUR fault rather than the peer's, and told
			// anyway: blame does not change the opener's problem, and its twin on
			// the v2 path is wire-visible for the same reason.
			const openMsg = makeValidOpenMsg();
			const acceptor = new Channel(
				createAcceptorState({
					temporaryChannelId: openMsg.temporaryChannelId,
					fundingSatoshis: openMsg.fundingSatoshis,
					pushMsat: openMsg.pushMsat,
					localConfig: {
						...DEFAULT_CHANNEL_CONFIG,
						maxHtlcValueInFlightMsat: 2n ** 64n
					},
					localBasepoints: realBasepoints(),
					localPerCommitmentSeed: crypto.randomBytes(32),
					remoteBasepoints: realBasepoints(),
					remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
				})
			);
			expectWireRefusal(
				acceptor.handleOpenChannel(openMsg),
				openMsg.temporaryChannelId,
				/max_htlc_value_in_flight_msat/
			);
		});

		it('but an open under the all-zero id stays local, at the Channel layer', function () {
			// ChannelManager drops such an open before it builds a Channel, so this
			// covers anyone driving the Channel directly. It is what makes the
			// closure's "scoped to the id the opener used" unconditionally true:
			// BOLT 1 reserves the all-zero id for every channel with the peer, so
			// a wire error under it would cancel far more than this open.
			const { acceptor, openMsg } = openerAndAccept();
			const zeroed = { ...openMsg, temporaryChannelId: Buffer.alloc(32, 0) };
			const fresh = new Channel(
				createAcceptorState({
					temporaryChannelId: zeroed.temporaryChannelId,
					fundingSatoshis: zeroed.fundingSatoshis,
					pushMsat: zeroed.pushMsat,
					localConfig: { ...DEFAULT_CHANNEL_CONFIG },
					localBasepoints: realBasepoints(),
					localPerCommitmentSeed: crypto.randomBytes(32),
					remoteBasepoints: realBasepoints(),
					remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
				})
			);
			const actions = fresh.handleOpenChannel(zeroed);
			expect(errorOf(actions)).to.match(/reserved all-zero id/);
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
			expect(acceptor.getState()).to.equal(ChannelState.SENT_ACCEPT);
		});

		it('but an open against a channel that already has a life stays local', function () {
			// The one deliberate carve-out, shared with handleOpenChannel2: this
			// arm can only fire on a replayed or misrouted open, and a wire error
			// scoped to that id would cancel whatever the peer still considers
			// live.
			const { acceptor, openMsg } = openerAndAccept();
			const replayed = acceptor.handleOpenChannel(openMsg);
			expect(errorOf(replayed)).to.match(/Unexpected open_channel/);
			expect(wireRefusalOf(replayed)).to.equal(null);
		});
	});

	describe('cltv_expiry >= 500000000', function () {
		it('send side: addHtlc refuses a timestamp-range cltv_expiry', function () {
			const { opener } = normalPair();
			const actions = opener.addHtlc(
				10_000n,
				crypto.randomBytes(32),
				500_000_000,
				Buffer.alloc(1366)
			);
			expect(errorOf(actions)).to.match(/not a block height/);
		});

		it('receive side: update_add_htlc with a timestamp-range cltv_expiry is rejected even with no block height', function () {
			const { acceptor } = normalPair();
			const actions = acceptor.handleUpdateAddHtlc({
				channelId: acceptor.getChannelId()!,
				id: 0n,
				amountMsat: 10_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500_000_000,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			expect(errorOf(actions)).to.match(/not a block height/);
		});
	});

	describe('channel_reestablish next_commitment_number == 0', function () {
		it('fails the channel with a wire error', function () {
			const { opener } = normalPair();
			const actions = opener.handleReestablish({
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: 0n,
				nextRevocationNumber: 0n,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
			});
			expect(errorOf(actions)).to.match(/next_commitment_number is 0/);
			const wireError = findSend(actions, MessageType.ERROR);
			expect(wireError, 'wire error sent').to.not.equal(null);
		});
	});

	describe('channel_ready retransmission trigger', function () {
		it('retransmits channel_ready when the peer expects commitment 1, even from NORMAL', function () {
			const { opener } = normalPair();
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			const actions = opener.handleReestablish({
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: 1n,
				nextRevocationNumber: 0n,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
			});
			const ready = findSend(actions, MessageType.CHANNEL_READY);
			expect(ready, 'channel_ready retransmitted').to.not.equal(null);
		});
	});

	describe('RBF feerate floor (25/24, +25)', function () {
		it('computes the spec floor as max of the ratio and the additive arm', function () {
			// BOLT 2: max(floor(old * 25 / 24), old + 25).
			expect(rbfFeerateFloor(2400)).to.equal(2500);
			// At small rates the ratio arm loses to the additive +25.
			expect(rbfFeerateFloor(253)).to.equal(278);
			expect(rbfFeerateFloor(10)).to.equal(35);
			expect(rbfFeerateFloor(0)).to.equal(25);
			// The crossover: from 600 the ratio arm meets the additive arm.
			expect(rbfFeerateFloor(600)).to.equal(625);
		});
	});

	describe('splice-out destination script validation', function () {
		it('rejects an OP_RETURN destination that would burn the funds', function () {
			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				perCommitmentSeed: crypto.randomBytes(32),
				channelBasepoints: realBasepoints(),
				fundingPrivkey: crypto.randomBytes(32)
			});
			const opReturn = Buffer.concat([
				Buffer.from([0x6a, 0x20]),
				crypto.randomBytes(32)
			]);
			expect(() =>
				node.spliceOut(crypto.randomBytes(32), 10_000n, 253, opReturn)
			).to.throw(/not a standard output script/);
			node.destroy();
		});

		it('accepts a standard P2WPKH destination script', function () {
			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				perCommitmentSeed: crypto.randomBytes(32),
				channelBasepoints: realBasepoints(),
				fundingPrivkey: crypto.randomBytes(32)
			});
			const p2wpkh = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			// Passes the script gate; fails later only because the channel
			// does not exist (returned, not thrown).
			const res = node.spliceOut(crypto.randomBytes(32), 10_000n, 253, p2wpkh);
			expect(res.ok).to.equal(false);
			expect(res.error).to.match(/Channel not found/);
			node.destroy();
		});
	});

	describe('an add that crossed our own shutdown (issue 404)', function () {
		// BOLT 2 forbids update_add_htlc only AFTER the peer has received our
		// shutdown. Until it sends its own we have no evidence it has, so an add
		// that left before ours arrived is conformant and MUST be recorded.
		// Dropping it does not spare the channel; it only mislabels its death.

		/**
		 * normalPair hands each side a RANDOM secondPerCommitmentPoint for the
		 * peer, which is fine for tests that never run a commitment round but makes
		 * one impossible: the two sides then build different scripts and every
		 * signature mismatches. Replace both with the point the peer's own seed
		 * derives so a real round can be exchanged.
		 */
		function pairNextPoints(opener: Channel, acceptor: Channel): void {
			const pointAt = (side: Channel, n: bigint): Buffer =>
				perCommitmentPointFromSecret(
					generateFromSeed(
						side.getFullState().localPerCommitmentSeed,
						MAX_INDEX - n
					)
				);
			opener.getFullState().remoteNextPerCommitmentPoint = pointAt(
				acceptor,
				1n
			);
			acceptor.getFullState().remoteNextPerCommitmentPoint = pointAt(
				opener,
				1n
			);
		}

		function shutDownLocally(side: Channel): void {
			const actions = side.initiateShutdown(
				Buffer.from('0014' + '00'.repeat(20), 'hex')
			);
			expect(errorOf(actions), 'shutdown accepted').to.equal(null);
			expect(side.getState()).to.equal(ChannelState.SHUTTING_DOWN);
			expect(
				side.getFullState().remoteShutdownScript,
				'the peer has not shut down'
			).to.equal(null);
		}

		it('admits the add, and the covering commitment_signed then verifies', function () {
			const { opener, acceptor } = normalPair(1_000_000n, 400_000_000n);
			pairNextPoints(opener, acceptor);
			shutDownLocally(acceptor);

			// The opener, which has not seen our shutdown, adds an HTLC.
			const add = opener.addHtlc(
				1_000_000n,
				crypto.randomBytes(32),
				800_000,
				Buffer.alloc(1366)
			);
			expect(errorOf(add), 'the opener may still add').to.equal(null);
			const addMsg = decodeUpdateAddHtlcMessage(
				findSend(add, MessageType.UPDATE_ADD_HTLC)!
			);

			expect(
				acceptor.handleUpdateAddHtlc(addMsg),
				'admitted, not refused'
			).to.have.length(0);
			expect(
				acceptor.getFullState().htlcs.get(`received-${addMsg.id}`),
				'and recorded'
			).to.not.equal(undefined);

			// The whole point: the peer's covering commitment_signed is built over
			// the same commitment we now hold, so it verifies. While the add was
			// dropped this failed, and handleCommitmentSigned killed the channel
			// with an "invalid signature" that was never invalid.
			const sigs = realCommitmentSigs(opener);
			const actions = acceptor.handleCommitmentSigned({
				channelId: acceptor.getChannelId()!,
				signature: sigs.signature,
				htlcSignatures: sigs.htlcSignatures
			});
			expect(errorOf(actions), 'the covering commitment verifies').to.equal(
				null
			);
			expect(acceptor.getState()).to.not.equal(ChannelState.ERRORED);
		});

		it('and once the PEER has shut down the add is refused, but LOCALLY', function () {
			const { opener, acceptor } = normalPair(1_000_000n, 400_000_000n);
			shutDownLocally(acceptor);
			acceptor.handleShutdown({
				channelId: acceptor.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '11'.repeat(20), 'hex')
			});
			expect(acceptor.getFullState().remoteShutdownScript).to.not.equal(null);

			// The peer is bound now, and is still not condemned: handleReestablish
			// replays every queued update_add_htlc after a reconnect, so an add
			// arriving here can be a peer doing exactly what BOLT 2 requires.
			const actions = acceptor.handleUpdateAddHtlc(
				inboundHtlc(acceptor, 1_000_000n)
			);
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
			expect(errorOf(actions)).to.match(/Unexpected update_add_htlc/);
			expect(acceptor.getState()).to.not.equal(ChannelState.ERRORED);
			void opener;
		});
	});
});
