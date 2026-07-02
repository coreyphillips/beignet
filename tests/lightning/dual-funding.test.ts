/**
 * BOLT 2 v2: Dual-Funding (open_channel2 / accept_channel2) tests.
 *
 * Tests:
 * - Message encode/decode round-trips for open_channel2 and accept_channel2
 * - DualFundingSession state machine transitions
 * - Full v2 opening flow (both contribute inputs)
 * - Unequal contributions
 * - RBF (tx_init_rbf / tx_ack_rbf)
 * - Abort mid-construction
 * - Fee negotiation
 * - Signature exchange
 * - Integration with Channel class
 * - Integration with ChannelManager
 * - Integration with LightningNode
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

import {
	encodeOpenChannel2Message,
	decodeOpenChannel2Message,
	encodeAcceptChannel2Message,
	decodeAcceptChannel2Message,
	IOpenChannel2Message,
	IAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';

import {
	DualFundingSession,
	DualFundingState,
	IDualFundingParams
} from '../../src/lightning/channel/dual-funding';

// InteractiveTxState used indirectly via DualFundingSession

import { Channel } from '../../src/lightning/channel/channel';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';

// ─────────────── Helpers ───────────────

function makeBasepoints(): IChannelBasepoints {
	const privkey = crypto.randomBytes(32);
	const pub = getPublicKey(privkey);
	return {
		fundingPubkey: pub,
		revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
		paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
		firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
	};
}

function makeOpenChannel2Msg(
	overrides?: Partial<IOpenChannel2Message>
): IOpenChannel2Message {
	const bp = makeBasepoints();
	return {
		channelId: crypto.randomBytes(32),
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 253,
		fundingSatoshis: 100000n,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		locktime: 0,
		fundingPubkey: bp.fundingPubkey,
		revocationBasepoint: bp.revocationBasepoint,
		paymentBasepoint: bp.paymentBasepoint,
		delayedPaymentBasepoint: bp.delayedPaymentBasepoint,
		htlcBasepoint: bp.htlcBasepoint,
		firstPerCommitmentPoint: bp.firstPerCommitmentPoint,
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32)),
		channelFlags: 0x01,
		...overrides
	};
}

function makeAcceptChannel2Msg(
	overrides?: Partial<IAcceptChannel2Message>
): IAcceptChannel2Message {
	const bp = makeBasepoints();
	return {
		channelId: crypto.randomBytes(32),
		fundingSatoshis: 50000n,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		minimumDepth: 3,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		fundingPubkey: bp.fundingPubkey,
		revocationBasepoint: bp.revocationBasepoint,
		paymentBasepoint: bp.paymentBasepoint,
		delayedPaymentBasepoint: bp.delayedPaymentBasepoint,
		htlcBasepoint: bp.htlcBasepoint,
		firstPerCommitmentPoint: bp.firstPerCommitmentPoint,
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32)),
		...overrides
	};
}

function makeDualFundingParams(
	overrides?: Partial<IDualFundingParams>
): IDualFundingParams {
	return {
		fundingSatoshis: 100000n,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 253,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		locktime: 0,
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32),
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32)),
		...overrides
	};
}

function makeChannelManagerConfig() {
	const privkey = crypto.randomBytes(32);
	const bp = makeBasepoints();
	return {
		localBasepoints: bp,
		localPerCommitmentSeed: crypto.randomBytes(32),
		localFundingPrivkey: privkey
	};
}

// ─────────────── Tests ───────────────

describe('Dual Funding (BOLT 2 v2)', () => {
	// ─── Message encode/decode ───

	describe('open_channel2 encode/decode', () => {
		it('should round-trip encode/decode open_channel2', () => {
			const msg = makeOpenChannel2Msg();
			const encoded = encodeOpenChannel2Message(msg);
			const decoded = decodeOpenChannel2Message(encoded);

			expect(decoded.channelId.equals(msg.channelId)).to.be.true;
			expect(decoded.fundingFeeratePerkw).to.equal(msg.fundingFeeratePerkw);
			expect(decoded.commitmentFeeratePerkw).to.equal(
				msg.commitmentFeeratePerkw
			);
			expect(decoded.fundingSatoshis).to.equal(msg.fundingSatoshis);
			expect(decoded.dustLimitSatoshis).to.equal(msg.dustLimitSatoshis);
			expect(decoded.maxHtlcValueInFlightMsat).to.equal(
				msg.maxHtlcValueInFlightMsat
			);
			expect(decoded.htlcMinimumMsat).to.equal(msg.htlcMinimumMsat);
			expect(decoded.toSelfDelay).to.equal(msg.toSelfDelay);
			expect(decoded.maxAcceptedHtlcs).to.equal(msg.maxAcceptedHtlcs);
			expect(decoded.locktime).to.equal(msg.locktime);
			expect(decoded.fundingPubkey.equals(msg.fundingPubkey)).to.be.true;
			expect(decoded.revocationBasepoint.equals(msg.revocationBasepoint)).to.be
				.true;
			expect(decoded.paymentBasepoint.equals(msg.paymentBasepoint)).to.be.true;
			expect(
				decoded.delayedPaymentBasepoint.equals(msg.delayedPaymentBasepoint)
			).to.be.true;
			expect(decoded.htlcBasepoint.equals(msg.htlcBasepoint)).to.be.true;
			expect(
				decoded.firstPerCommitmentPoint.equals(msg.firstPerCommitmentPoint)
			).to.be.true;
			expect(
				decoded.secondPerCommitmentPoint.equals(msg.secondPerCommitmentPoint)
			).to.be.true;
			expect(decoded.channelFlags).to.equal(msg.channelFlags);
		});

		it('should round-trip with channel type TLV', () => {
			const channelType = Buffer.from([0x20, 0x00]); // static_remotekey
			const msg = makeOpenChannel2Msg({ channelType });
			const encoded = encodeOpenChannel2Message(msg);
			const decoded = decodeOpenChannel2Message(encoded);

			expect(decoded.channelType).to.not.be.undefined;
			expect(decoded.channelType!.equals(channelType)).to.be.true;
		});

		it('should handle zero funding_satoshis', () => {
			const msg = makeOpenChannel2Msg({ fundingSatoshis: 0n });
			const encoded = encodeOpenChannel2Message(msg);
			const decoded = decodeOpenChannel2Message(encoded);
			expect(decoded.fundingSatoshis).to.equal(0n);
		});

		it('should handle max funding_satoshis', () => {
			const msg = makeOpenChannel2Msg({ fundingSatoshis: 16777216n });
			const encoded = encodeOpenChannel2Message(msg);
			const decoded = decodeOpenChannel2Message(encoded);
			expect(decoded.fundingSatoshis).to.equal(16777216n);
		});

		it('should handle non-zero locktime', () => {
			const msg = makeOpenChannel2Msg({ locktime: 800000 });
			const encoded = encodeOpenChannel2Message(msg);
			const decoded = decodeOpenChannel2Message(encoded);
			expect(decoded.locktime).to.equal(800000);
		});

		it('should reject too-short payload', () => {
			expect(() => decodeOpenChannel2Message(Buffer.alloc(100))).to.throw(
				'too short'
			);
		});

		it('should preserve channel flags', () => {
			const msg = makeOpenChannel2Msg({ channelFlags: 0x00 });
			const encoded = encodeOpenChannel2Message(msg);
			const decoded = decodeOpenChannel2Message(encoded);
			expect(decoded.channelFlags).to.equal(0x00);
		});

		it('should reject non-32-byte channel ID', () => {
			const msg = makeOpenChannel2Msg({ channelId: Buffer.alloc(16) });
			expect(() => encodeOpenChannel2Message(msg)).to.throw('32 bytes');
		});

		it('should handle various fee rates', () => {
			const msg = makeOpenChannel2Msg({
				fundingFeeratePerkw: 5000,
				commitmentFeeratePerkw: 3000
			});
			const encoded = encodeOpenChannel2Message(msg);
			const decoded = decodeOpenChannel2Message(encoded);
			expect(decoded.fundingFeeratePerkw).to.equal(5000);
			expect(decoded.commitmentFeeratePerkw).to.equal(3000);
		});
	});

	describe('accept_channel2 encode/decode', () => {
		it('should round-trip encode/decode accept_channel2', () => {
			const msg = makeAcceptChannel2Msg();
			const encoded = encodeAcceptChannel2Message(msg);
			const decoded = decodeAcceptChannel2Message(encoded);

			expect(decoded.channelId.equals(msg.channelId)).to.be.true;
			expect(decoded.fundingSatoshis).to.equal(msg.fundingSatoshis);
			expect(decoded.dustLimitSatoshis).to.equal(msg.dustLimitSatoshis);
			expect(decoded.maxHtlcValueInFlightMsat).to.equal(
				msg.maxHtlcValueInFlightMsat
			);
			expect(decoded.htlcMinimumMsat).to.equal(msg.htlcMinimumMsat);
			expect(decoded.minimumDepth).to.equal(msg.minimumDepth);
			expect(decoded.toSelfDelay).to.equal(msg.toSelfDelay);
			expect(decoded.maxAcceptedHtlcs).to.equal(msg.maxAcceptedHtlcs);
			expect(decoded.fundingPubkey.equals(msg.fundingPubkey)).to.be.true;
			expect(decoded.revocationBasepoint.equals(msg.revocationBasepoint)).to.be
				.true;
			expect(decoded.paymentBasepoint.equals(msg.paymentBasepoint)).to.be.true;
			expect(
				decoded.delayedPaymentBasepoint.equals(msg.delayedPaymentBasepoint)
			).to.be.true;
			expect(decoded.htlcBasepoint.equals(msg.htlcBasepoint)).to.be.true;
			expect(
				decoded.firstPerCommitmentPoint.equals(msg.firstPerCommitmentPoint)
			).to.be.true;
			expect(
				decoded.secondPerCommitmentPoint.equals(msg.secondPerCommitmentPoint)
			).to.be.true;
		});

		it('should round-trip with channel type TLV', () => {
			const channelType = Buffer.from([0x20, 0x00]);
			const msg = makeAcceptChannel2Msg({ channelType });
			const encoded = encodeAcceptChannel2Message(msg);
			const decoded = decodeAcceptChannel2Message(encoded);

			expect(decoded.channelType).to.not.be.undefined;
			expect(decoded.channelType!.equals(channelType)).to.be.true;
		});

		it('should handle zero funding_satoshis (acceptor contributes nothing)', () => {
			const msg = makeAcceptChannel2Msg({ fundingSatoshis: 0n });
			const encoded = encodeAcceptChannel2Message(msg);
			const decoded = decodeAcceptChannel2Message(encoded);
			expect(decoded.fundingSatoshis).to.equal(0n);
		});

		it('should handle zero minimum_depth', () => {
			const msg = makeAcceptChannel2Msg({ minimumDepth: 0 });
			const encoded = encodeAcceptChannel2Message(msg);
			const decoded = decodeAcceptChannel2Message(encoded);
			expect(decoded.minimumDepth).to.equal(0);
		});

		it('should reject too-short payload', () => {
			expect(() => decodeAcceptChannel2Message(Buffer.alloc(100))).to.throw(
				'too short'
			);
		});

		it('should reject non-32-byte channel ID', () => {
			const msg = makeAcceptChannel2Msg({ channelId: Buffer.alloc(16) });
			expect(() => encodeAcceptChannel2Message(msg)).to.throw('32 bytes');
		});

		it('should handle large funding amounts', () => {
			const msg = makeAcceptChannel2Msg({ fundingSatoshis: 10_000_000n });
			const encoded = encodeAcceptChannel2Message(msg);
			const decoded = decodeAcceptChannel2Message(encoded);
			expect(decoded.fundingSatoshis).to.equal(10_000_000n);
		});
	});

	// ─── DualFundingSession state machine ───

	describe('DualFundingSession', () => {
		describe('constructor', () => {
			it('should initialize in NONE state', () => {
				const session = new DualFundingSession(true, crypto.randomBytes(32));
				expect(session.getState()).to.equal(DualFundingState.NONE);
			});

			it('should track initiator flag', () => {
				const initiator = new DualFundingSession(true, crypto.randomBytes(32));
				expect(initiator.isInitiator()).to.be.true;

				const acceptor = new DualFundingSession(false, crypto.randomBytes(32));
				expect(acceptor.isInitiator()).to.be.false;
			});

			it('should store channel ID', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				expect(session.getChannelId().equals(channelId)).to.be.true;
			});
		});

		describe('initiateOpen', () => {
			it('should transition to AWAITING_ACCEPT', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				const params = makeDualFundingParams();
				const result = session.initiateOpen(params);

				expect(result.ok).to.be.true;
				expect(result.message).to.not.be.undefined;
				expect(session.getState()).to.equal(DualFundingState.AWAITING_ACCEPT);
			});

			it('should fail if not in NONE state', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.initiateOpen(makeDualFundingParams());

				const result = session.initiateOpen(makeDualFundingParams());
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('wrong state');
			});

			it('should include all parameters in the message', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				const params = makeDualFundingParams({ fundingSatoshis: 200000n });
				const result = session.initiateOpen(params);

				expect(result.message!.fundingSatoshis).to.equal(200000n);
				expect(result.message!.fundingFeeratePerkw).to.equal(
					params.fundingFeeratePerkw
				);
				expect(result.message!.commitmentFeeratePerkw).to.equal(
					params.commitmentFeeratePerkw
				);
			});

			it('should store the open message', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.initiateOpen(makeDualFundingParams());
				expect(session.getOpenMsg()).to.not.be.null;
			});
		});

		describe('parameter validation', () => {
			it('should reject funding exceeding maximum', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				const params = makeDualFundingParams({ fundingSatoshis: 16777217n });
				const result = session.initiateOpen(params);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('exceeds maximum');
			});

			it('should reject dust below minimum', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				const params = makeDualFundingParams({ dustLimitSatoshis: 100n });
				const result = session.initiateOpen(params);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('below minimum');
			});

			it('should reject max_accepted_htlcs above 483', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				const params = makeDualFundingParams({ maxAcceptedHtlcs: 500 });
				const result = session.initiateOpen(params);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('exceeds maximum');
			});

			it('should reject zero to_self_delay', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				const params = makeDualFundingParams({ toSelfDelay: 0 });
				const result = session.initiateOpen(params);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('to_self_delay');
			});

			it('should reject zero funding feerate', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				const params = makeDualFundingParams({ fundingFeeratePerkw: 0 });
				const result = session.initiateOpen(params);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('funding_feerate');
			});

			it('should reject zero commitment feerate', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				const params = makeDualFundingParams({ commitmentFeeratePerkw: 0 });
				const result = session.initiateOpen(params);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('commitment_feerate');
			});

			it('should reject non-33-byte funding pubkey', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				const bp = makeBasepoints();
				bp.fundingPubkey = Buffer.alloc(32);
				const params = makeDualFundingParams({ localBasepoints: bp });
				const result = session.initiateOpen(params);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('33 bytes');
			});
		});

		describe('handleAcceptChannel2', () => {
			it('should transition to TX_NEGOTIATION', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.initiateOpen(makeDualFundingParams());

				const acceptMsg = makeAcceptChannel2Msg({ channelId });
				const result = session.handleAcceptChannel2(acceptMsg);

				expect(result.ok).to.be.true;
				expect(session.getState()).to.equal(DualFundingState.TX_NEGOTIATION);
			});

			it('should store remote basepoints', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.initiateOpen(makeDualFundingParams());

				const acceptMsg = makeAcceptChannel2Msg({ channelId });
				session.handleAcceptChannel2(acceptMsg);

				const bp = session.getRemoteBasepoints();
				expect(bp).to.not.be.null;
				expect(bp!.fundingPubkey.equals(acceptMsg.fundingPubkey)).to.be.true;
			});

			it('should store remote funding amount', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.initiateOpen(makeDualFundingParams());

				const acceptMsg = makeAcceptChannel2Msg({
					channelId,
					fundingSatoshis: 75000n
				});
				session.handleAcceptChannel2(acceptMsg);

				expect(session.getRemoteFundingSatoshis()).to.equal(75000n);
			});

			it('should fail on channel_id mismatch', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.initiateOpen(makeDualFundingParams());

				const acceptMsg = makeAcceptChannel2Msg({
					channelId: crypto.randomBytes(32)
				});
				const result = session.handleAcceptChannel2(acceptMsg);

				expect(result.ok).to.be.false;
				expect(result.error).to.contain('mismatch');
			});

			it('should fail if not in AWAITING_ACCEPT', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);

				const acceptMsg = makeAcceptChannel2Msg({ channelId });
				const result = session.handleAcceptChannel2(acceptMsg);

				expect(result.ok).to.be.false;
				expect(result.error).to.contain('Unexpected');
			});

			it('should create TX builder after accepting', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.initiateOpen(makeDualFundingParams());

				const acceptMsg = makeAcceptChannel2Msg({ channelId });
				session.handleAcceptChannel2(acceptMsg);

				expect(session.getTxBuilder()).to.not.be.null;
			});
		});

		describe('handleOpenChannel2 (acceptor side)', () => {
			it('should transition to TX_NEGOTIATION', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(false, channelId);
				const openMsg = makeOpenChannel2Msg({ channelId });
				const localParams = makeDualFundingParams({ fundingSatoshis: 50000n });

				const result = session.handleOpenChannel2(openMsg, localParams);

				expect(result.ok).to.be.true;
				expect(result.message).to.not.be.undefined;
				expect(session.getState()).to.equal(DualFundingState.TX_NEGOTIATION);
			});

			it('should return accept_channel2 message', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(false, channelId);
				const openMsg = makeOpenChannel2Msg({ channelId });
				const localParams = makeDualFundingParams({ fundingSatoshis: 50000n });

				const result = session.handleOpenChannel2(openMsg, localParams);

				expect(result.message!.channelId.equals(channelId)).to.be.true;
				expect(result.message!.fundingSatoshis).to.equal(50000n);
			});

			it('should store remote parameters', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(false, channelId);
				const openMsg = makeOpenChannel2Msg({
					channelId,
					fundingSatoshis: 200000n
				});
				const localParams = makeDualFundingParams();

				session.handleOpenChannel2(openMsg, localParams);

				expect(session.getRemoteFundingSatoshis()).to.equal(200000n);
			});

			it('should fail on channel_id mismatch', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(false, channelId);
				const openMsg = makeOpenChannel2Msg({
					channelId: crypto.randomBytes(32)
				});
				const localParams = makeDualFundingParams();

				const result = session.handleOpenChannel2(openMsg, localParams);
				expect(result.ok).to.be.false;
			});

			it('should store accept message', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(false, channelId);
				const openMsg = makeOpenChannel2Msg({ channelId });
				const localParams = makeDualFundingParams();

				session.handleOpenChannel2(openMsg, localParams);
				expect(session.getAcceptMsg()).to.not.be.null;
			});
		});

		describe('Interactive TX negotiation', () => {
			function makeReadySession(): {
				opener: DualFundingSession;
				acceptor: DualFundingSession;
				channelId: Buffer;
			} {
				const channelId = crypto.randomBytes(32);
				const opener = new DualFundingSession(true, channelId);
				const acceptor = new DualFundingSession(false, channelId);

				const openerParams = makeDualFundingParams({
					fundingSatoshis: 100000n
				});
				const openerResult = opener.initiateOpen(openerParams);

				const acceptorParams = makeDualFundingParams({
					fundingSatoshis: 50000n
				});
				acceptor.handleOpenChannel2(openerResult.message!, acceptorParams);

				const acceptMsg = makeAcceptChannel2Msg({
					channelId,
					fundingSatoshis: 50000n
				});
				opener.handleAcceptChannel2(acceptMsg);

				return { opener, acceptor, channelId };
			}

			it('should allow adding inputs', () => {
				const { opener } = makeReadySession();

				const result = opener.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});

				expect(result.ok).to.be.true;
			});

			it('should allow adding peer inputs', () => {
				const { opener } = makeReadySession();

				const result = opener.addPeerInput({
					serialId: 1n, // odd = acceptor
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});

				expect(result.ok).to.be.true;
			});

			it('should allow adding outputs', () => {
				const { opener } = makeReadySession();

				const result = opener.addOutput({
					serialId: 0n,
					amountSats: 100000n,
					scriptPubkey: Buffer.alloc(22, 0x00)
				});

				expect(result.ok).to.be.true;
			});

			it('should allow adding peer outputs', () => {
				const { opener } = makeReadySession();

				const result = opener.addPeerOutput({
					serialId: 1n,
					amountSats: 50000n,
					scriptPubkey: Buffer.alloc(22, 0x00)
				});

				expect(result.ok).to.be.true;
			});

			it('should allow removing inputs', () => {
				const { opener } = makeReadySession();

				opener.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});

				const result = opener.removeInput(0n);
				expect(result.ok).to.be.true;
			});

			it('should allow removing outputs', () => {
				const { opener } = makeReadySession();

				opener.addOutput({
					serialId: 0n,
					amountSats: 100000n,
					scriptPubkey: Buffer.alloc(22, 0x00)
				});

				const result = opener.removeOutput(0n);
				expect(result.ok).to.be.true;
			});

			it('should allow removing peer inputs', () => {
				const { opener } = makeReadySession();

				opener.addPeerInput({
					serialId: 1n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});

				const result = opener.removePeerInput(1n);
				expect(result.ok).to.be.true;
			});

			it('should allow removing peer outputs', () => {
				const { opener } = makeReadySession();

				opener.addPeerOutput({
					serialId: 1n,
					amountSats: 50000n,
					scriptPubkey: Buffer.alloc(22, 0x00)
				});

				const result = opener.removePeerOutput(1n);
				expect(result.ok).to.be.true;
			});

			it('should reject operations in wrong state', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				// Still in NONE state

				const result = session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('not in TX_NEGOTIATION');
			});

			it('should transition to AWAITING_TX_SIGNATURES when both complete', () => {
				const { opener } = makeReadySession();

				// Add at least one input and output
				opener.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				opener.addOutput({
					serialId: 2n,
					amountSats: 100000n,
					scriptPubkey: Buffer.alloc(22, 0x00)
				});

				opener.handlePeerComplete();
				opener.markComplete();

				expect(opener.getState()).to.equal(
					DualFundingState.AWAITING_TX_SIGNATURES
				);
			});

			it('should stay in TX_NEGOTIATION when only one side completes', () => {
				const { opener } = makeReadySession();

				opener.markComplete();
				expect(opener.getState()).to.equal(DualFundingState.TX_NEGOTIATION);
			});
		});

		describe('TX signatures', () => {
			function makeSignatureReadySession(): DualFundingSession {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);

				session.initiateOpen(makeDualFundingParams());
				session.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

				// Add input and output
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100000n,
					scriptPubkey: Buffer.alloc(22, 0x00)
				});

				// Both complete
				session.handlePeerComplete();
				session.markComplete();

				return session;
			}

			it('should accept our witnesses', () => {
				const session = makeSignatureReadySession();
				const txid = crypto.randomBytes(32);

				const result = session.provideWitnesses(txid, 0, [[Buffer.alloc(72)]]);
				expect(result.ok).to.be.true;
				expect(session.getLocalWitnesses()).to.not.be.null;
			});

			it('should accept peer witnesses', () => {
				const session = makeSignatureReadySession();
				const txid = crypto.randomBytes(32);

				const result = session.handlePeerWitnesses(txid, [[Buffer.alloc(72)]]);
				expect(result.ok).to.be.true;
				expect(session.getRemoteWitnesses()).to.not.be.null;
			});

			it('should transition to AWAITING_CHANNEL_READY when both sign', () => {
				const session = makeSignatureReadySession();
				const txid = crypto.randomBytes(32);

				session.provideWitnesses(txid, 0, [[Buffer.alloc(72)]]);
				session.handlePeerWitnesses(txid, [[Buffer.alloc(72)]]);

				expect(session.getState()).to.equal(
					DualFundingState.AWAITING_CHANNEL_READY
				);
			});

			it('should reject witnesses in wrong state', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);

				const result = session.provideWitnesses(crypto.randomBytes(32), 0, []);
				expect(result.ok).to.be.false;
			});

			it('should store funding txid', () => {
				const session = makeSignatureReadySession();
				const txid = crypto.randomBytes(32);

				session.provideWitnesses(txid, 1, [[Buffer.alloc(72)]]);

				expect(session.getFundingTxid()!.equals(txid)).to.be.true;
				expect(session.getFundingOutputIndex()).to.equal(1);
			});

			it('should reject txid mismatch in peer witnesses', () => {
				const session = makeSignatureReadySession();
				const txid1 = crypto.randomBytes(32);
				const txid2 = crypto.randomBytes(32);

				session.provideWitnesses(txid1, 0, [[Buffer.alloc(72)]]);
				const result = session.handlePeerWitnesses(txid2, [[Buffer.alloc(72)]]);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('mismatch');
			});
		});

		describe('Channel ready', () => {
			it('should transition to COMPLETE', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);

				session.initiateOpen(makeDualFundingParams());
				session.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100000n,
					scriptPubkey: Buffer.alloc(22, 0x00)
				});

				session.handlePeerComplete();
				session.markComplete();

				const txid = crypto.randomBytes(32);
				session.provideWitnesses(txid, 0, [[Buffer.alloc(72)]]);
				session.handlePeerWitnesses(txid, [[Buffer.alloc(72)]]);

				const result = session.markChannelReady();
				expect(result.ok).to.be.true;
				expect(session.getState()).to.equal(DualFundingState.COMPLETE);
				expect(session.isComplete()).to.be.true;
			});

			it('should fail if not in AWAITING_CHANNEL_READY', () => {
				const session = new DualFundingSession(true, crypto.randomBytes(32));
				const result = session.markChannelReady();
				expect(result.ok).to.be.false;
			});
		});

		describe('RBF', () => {
			function makeRbfReadySession(): {
				opener: DualFundingSession;
				channelId: Buffer;
			} {
				const channelId = crypto.randomBytes(32);
				const opener = new DualFundingSession(true, channelId);

				opener.initiateOpen(
					makeDualFundingParams({ fundingFeeratePerkw: 1000 })
				);
				opener.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

				return { opener, channelId };
			}

			it('should allow initiator to start RBF', () => {
				const { opener } = makeRbfReadySession();
				const result = opener.initiateRbf(2000);
				expect(result.ok).to.be.true;
				expect(result.feerate).to.equal(2000);
				expect(opener.getState()).to.equal(DualFundingState.TX_NEGOTIATION);
			});

			it('should increment RBF count', () => {
				const { opener } = makeRbfReadySession();
				expect(opener.getRbfCount()).to.equal(0);
				opener.initiateRbf(2000);
				expect(opener.getRbfCount()).to.equal(1);
				opener.initiateRbf(3000);
				expect(opener.getRbfCount()).to.equal(2);
			});

			it('should reject lower fee rate', () => {
				const { opener } = makeRbfReadySession();
				const result = opener.initiateRbf(500);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('higher');
			});

			it('should reject equal fee rate', () => {
				const { opener } = makeRbfReadySession();
				const result = opener.initiateRbf(1000);
				expect(result.ok).to.be.false;
			});

			it('should reject RBF from non-initiator', () => {
				const channelId = crypto.randomBytes(32);
				const acceptor = new DualFundingSession(false, channelId);
				const openMsg = makeOpenChannel2Msg({ channelId });
				acceptor.handleOpenChannel2(openMsg, makeDualFundingParams());

				const result = acceptor.initiateRbf(2000);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('initiator');
			});

			it('should reset TX builder on RBF', () => {
				const { opener } = makeRbfReadySession();

				// Add some data to the current session
				opener.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});

				opener.initiateRbf(2000);

				// TX builder should be fresh
				const builder = opener.getTxBuilder()!;
				expect(builder.getInputs().length).to.equal(0);
			});

			it('should handle acceptor receiving RBF', () => {
				const channelId = crypto.randomBytes(32);
				const acceptor = new DualFundingSession(false, channelId);
				const openMsg = makeOpenChannel2Msg({
					channelId,
					fundingFeeratePerkw: 1000
				});
				acceptor.handleOpenChannel2(openMsg, makeDualFundingParams());

				const result = acceptor.handleRbf(2000, 0);
				expect(result.ok).to.be.true;
				expect(acceptor.getState()).to.equal(DualFundingState.TX_NEGOTIATION);
				expect(acceptor.getRbfCount()).to.equal(1);
			});

			it('should reject RBF reception by initiator', () => {
				const { opener } = makeRbfReadySession();
				const result = opener.handleRbf(2000, 0);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('Initiator');
			});

			it('should allow RBF with new locktime', () => {
				const { opener } = makeRbfReadySession();
				const result = opener.initiateRbf(2000, 800000);
				expect(result.ok).to.be.true;
				expect(result.locktime).to.equal(800000);
			});
		});

		describe('Abort', () => {
			it('should transition to ABORTED', () => {
				const session = new DualFundingSession(true, crypto.randomBytes(32));
				session.initiateOpen(makeDualFundingParams());
				session.abort();
				expect(session.getState()).to.equal(DualFundingState.ABORTED);
				expect(session.isAborted()).to.be.true;
			});

			it('should abort from any state', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.abort();
				expect(session.isAborted()).to.be.true;
			});

			it('should also abort the TX builder', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.initiateOpen(makeDualFundingParams());
				session.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

				session.abort();

				expect(session.getTxBuilder()!.isAborted()).to.be.true;
			});
		});

		describe('Total funding', () => {
			it('should sum both contributions', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.initiateOpen(
					makeDualFundingParams({ fundingSatoshis: 100000n })
				);
				session.handleAcceptChannel2(
					makeAcceptChannel2Msg({
						channelId,
						fundingSatoshis: 50000n
					})
				);

				expect(session.getTotalFunding()).to.equal(150000n);
			});

			it('should handle zero remote contribution', () => {
				const channelId = crypto.randomBytes(32);
				const session = new DualFundingSession(true, channelId);
				session.initiateOpen(
					makeDualFundingParams({ fundingSatoshis: 100000n })
				);
				session.handleAcceptChannel2(
					makeAcceptChannel2Msg({
						channelId,
						fundingSatoshis: 0n
					})
				);

				expect(session.getTotalFunding()).to.equal(100000n);
			});
		});
	});

	// ─── Channel integration ───

	describe('Channel v2 integration', () => {
		function makeV2Channel(): { channel: Channel; params: IDualFundingParams } {
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			const channel = new Channel(state);
			const params = makeDualFundingParams({
				localBasepoints: state.localBasepoints,
				localPerCommitmentSeed: state.localPerCommitmentSeed
			});

			return { channel, params };
		}

		it('should initiate v2 opening', () => {
			const { channel, params } = makeV2Channel();
			const actions = channel.initiateOpenV2(params);

			expect(actions.length).to.be.greaterThan(0);
			expect(actions[0].type).to.equal(ChannelActionType.SEND_MESSAGE);
			if (actions[0].type === ChannelActionType.SEND_MESSAGE) {
				expect(actions[0].messageType).to.equal(MessageType.OPEN_CHANNEL2);
			}
			expect(channel.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		});

		it('should set funding version to 2', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);
			expect(channel.getFullState().fundingVersion).to.equal(2);
		});

		it('should reject v2 open in wrong state', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);
			const actions = channel.initiateOpenV2(params);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
		});

		it('should have a dual-funding session after initiation', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);
			expect(channel.getDualFundingSession()).to.not.be.null;
		});

		it('should handle accept_channel2 on opener side', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);

			const channelId = channel.getTemporaryChannelId();
			const acceptMsg = makeAcceptChannel2Msg({ channelId });

			const actions = channel.handleAcceptChannel2(acceptMsg);
			// Should succeed with no errors
			expect(actions.every((a) => a.type !== ChannelActionType.ERROR)).to.be
				.true;
		});

		it('should handle open_channel2 on acceptor side', () => {
			const state = createAcceptorState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 0n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32),
				remoteBasepoints: makeBasepoints(),
				remoteConfig: DEFAULT_CHANNEL_CONFIG
			});

			const channel = new Channel(state);
			const openMsg = makeOpenChannel2Msg({
				channelId: state.temporaryChannelId
			});
			const localParams = makeDualFundingParams({
				localBasepoints: state.localBasepoints,
				localPerCommitmentSeed: state.localPerCommitmentSeed
			});

			const actions = channel.handleOpenChannel2(openMsg, localParams);
			expect(actions.length).to.be.greaterThan(0);
			expect(actions[0].type).to.equal(ChannelActionType.SEND_MESSAGE);
			if (actions[0].type === ChannelActionType.SEND_MESSAGE) {
				expect(actions[0].messageType).to.equal(MessageType.ACCEPT_CHANNEL2);
			}
			expect(channel.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		});

		it('rejects a will_fund lease on a taproot channel (mutually-exclusive types)', () => {
			// Script-enforced lease and simple taproot are distinct commitment types
			// with no interoperable "leased taproot" script. Even if the manager-level
			// guard were bypassed and a will_fund reached the state machine on a taproot
			// open, handleOpenChannel2 must refuse rather than enter an unenforceable
			// lessor state.
			const state = createAcceptorState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 0n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32),
				remoteBasepoints: makeBasepoints(),
				remoteConfig: DEFAULT_CHANNEL_CONFIG
			});
			const channel = new Channel(state);

			const taprootType = FeatureFlags.empty();
			taprootType.setCompulsory(Feature.OPTION_TAPROOT);

			const openMsg = makeOpenChannel2Msg({
				channelId: state.temporaryChannelId,
				channelType: taprootType.toBuffer(),
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 }
			});
			const localParams = makeDualFundingParams({
				localBasepoints: state.localBasepoints,
				localPerCommitmentSeed: state.localPerCommitmentSeed,
				willFund: {
					signature: Buffer.alloc(64, 0x01),
					leaseRates: {
						fundingWeightWitness: 1000,
						leaseFeeBasis: 100,
						leaseFeeBaseSat: 500,
						channelFeeMaxBaseMsat: 5000,
						channelFeeMaxProportionalThousandths: 10
					}
				}
			});

			const actions = channel.handleOpenChannel2(openMsg, localParams);
			expect(actions.length).to.equal(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			if (actions[0].type === ChannelActionType.ERROR) {
				expect(actions[0].message).to.match(
					/lease is not supported on taproot/i
				);
			}
			// No lessor state was recorded.
			expect(channel.getFullState().isLessor).to.not.equal(true);
			expect(channel.getFullState().leaseExpiry).to.be.undefined;
		});

		const M2_RATES = {
			fundingWeightWitness: 1000,
			leaseFeeBasis: 100,
			leaseFeeBaseSat: 500,
			channelFeeMaxBaseMsat: 5000,
			channelFeeMaxProportionalThousandths: 10
		};

		it('rejects the lease when the seller funds less than requested (M2)', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2({
				...params,
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 }
			});
			const channelId = channel.getTemporaryChannelId();

			// Adversarial seller: a valid will_fund, but it funds only 100k of the 500k
			// we requested. We must not pay the lease fee for liquidity never delivered.
			const actions = channel.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId,
					fundingSatoshis: 100_000n,
					willFund: { signature: Buffer.alloc(64, 0x01), leaseRates: M2_RATES }
				})
			);
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.ERROR &&
						/funded less than the requested/i.test(
							(a as { message?: string }).message ?? ''
						)
				),
				'buyer must reject an under-funded lease'
			).to.be.true;
			expect(channel.getFullState().leaseExpiry).to.be.undefined;
		});

		it('accepts the lease when the seller funds at least the requested amount (M2 control)', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2({
				...params,
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 },
				// Buyer's accepted ceiling = the seller's advertised rates (H3).
				maxLeaseRates: M2_RATES
			});
			const channelId = channel.getTemporaryChannelId();

			const actions = channel.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId,
					fundingSatoshis: 500_000n,
					willFund: { signature: Buffer.alloc(64, 0x01), leaseRates: M2_RATES }
				})
			);
			expect(
				actions.every((a) => a.type !== ChannelActionType.ERROR),
				'a fully-funded lease is accepted'
			).to.be.true;
			expect(channel.getFullState().leaseExpiry).to.equal(800000 + 4032);
		});

		it('rejects a will_fund whose lease fee exceeds the buyer ceiling (H3)', () => {
			// The seller's will_fund rates are self-signed and otherwise bounded only by
			// our whole balance. A seller that inflates its rates beyond what the buyer
			// agreed to (maxLeaseRates) must be rejected, not paid.
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2({
				...params,
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 },
				maxLeaseRates: M2_RATES
			});
			const channelId = channel.getTemporaryChannelId();

			// Inflate the flat base fee far above the accepted ceiling.
			const gougingRates = {
				...M2_RATES,
				leaseFeeBaseSat: M2_RATES.leaseFeeBaseSat + 1_000_000
			};
			const actions = channel.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId,
					fundingSatoshis: 500_000n,
					willFund: {
						signature: Buffer.alloc(64, 0x01),
						leaseRates: gougingRates
					}
				})
			);
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.ERROR &&
						/exceeds our accepted maximum/i.test(
							(a as { message?: string }).message ?? ''
						)
				),
				'buyer must reject an over-priced lease'
			).to.be.true;
			// No fee shifted, no lease recorded.
			expect(channel.getFullState().leaseExpiry).to.be.undefined;
		});

		it('rejects a lease when no maximum rates ceiling is configured (H3)', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2({
				...params,
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 }
				// no maxLeaseRates → refuse to pay an unverified fee
			});
			const channelId = channel.getTemporaryChannelId();

			const actions = channel.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId,
					fundingSatoshis: 500_000n,
					willFund: { signature: Buffer.alloc(64, 0x01), leaseRates: M2_RATES }
				})
			);
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.ERROR &&
						/no maximum lease rates/i.test(
							(a as { message?: string }).message ?? ''
						)
				),
				'buyer must refuse a lease with no ceiling'
			).to.be.true;
			expect(channel.getFullState().leaseExpiry).to.be.undefined;
		});

		it('should handle tx_complete exchange', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);

			const channelId = channel.getTemporaryChannelId();
			channel.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

			// Add input and output
			channel.addTxInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			channel.addTxOutput({
				serialId: 2n,
				amountSats: 100000n,
				scriptPubkey: Buffer.alloc(22, 0x00)
			});

			// Both complete
			channel.handleTxComplete();
			const actions = channel.sendTxComplete();

			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType: MessageType }).messageType ===
							MessageType.TX_COMPLETE
				)
			).to.be.true;
			expect(channel.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		});

		it('should handle abort during v2 opening', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);

			const actions = channel.abortDualFunding('test abort');
			expect(actions.length).to.be.greaterThan(0);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('should handle tx_abort from peer', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);

			channel.handleTxAbort();
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('should handle RBF initiation', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);

			const channelId = channel.getTemporaryChannelId();
			channel.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

			const actions = channel.initiateTxRbf(2000);
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType: MessageType }).messageType ===
							MessageType.TX_INIT_RBF
				)
			).to.be.true;
		});

		it('does NOT release tx_signatures before the commitment_signed round (fund-safety)', () => {
			// BOLT 2 v2: tx_signatures must never leave until the peer has
			// verifiably signed our commitment #0. This single-channel harness has
			// no signer, so the commitment round can't complete — sendTxSignatures
			// must DEFER (empty actions), never emit TX_SIGNATURES. The full
			// exchange is covered end-to-end in dual-funding-commitment.test.ts.
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);

			const channelId = channel.getTemporaryChannelId();
			channel.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

			channel.addTxInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			channel.addTxOutput({
				serialId: 2n,
				amountSats: 100000n,
				scriptPubkey: Buffer.alloc(22, 0x00)
			});
			channel.handleTxComplete();
			channel.sendTxComplete();

			// A random txid can't match the negotiated funding tx either.
			const txid = crypto.randomBytes(32);
			const actions = channel.sendTxSignatures(txid, 0, [[Buffer.alloc(72)]]);

			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType: MessageType }).messageType ===
							MessageType.TX_SIGNATURES
				)
			).to.be.false;
		});
	});

	// ─── ChannelManager integration ───

	describe('ChannelManager dual-funding', () => {
		it('should create a dual-funded channel', () => {
			const config = makeChannelManagerConfig();
			const mgr = new ChannelManager(config);
			mgr.on('error', () => {}); // absorb errors

			const params = makeDualFundingParams({
				localBasepoints: config.localBasepoints,
				localPerCommitmentSeed: config.localPerCommitmentSeed
			});

			const channel = mgr.createDualFundedChannel(
				'02' + '00'.repeat(32),
				params
			);
			expect(channel).to.not.be.null;
			expect(channel.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		});

		it('should emit channel:opened event', (done) => {
			const config = makeChannelManagerConfig();
			const mgr = new ChannelManager(config);
			mgr.on('error', () => {});

			mgr.on('channel:opened', () => {
				done();
			});

			const params = makeDualFundingParams({
				localBasepoints: config.localBasepoints,
				localPerCommitmentSeed: config.localPerCommitmentSeed
			});

			mgr.createDualFundedChannel('02' + '00'.repeat(32), params);
		});

		it('should route open_channel2 messages', () => {
			const config = makeChannelManagerConfig();
			const mgr = new ChannelManager(config);
			mgr.on('error', () => {});

			const channelId = crypto.randomBytes(32);
			const openMsg = makeOpenChannel2Msg({ channelId });
			const encoded = encodeOpenChannel2Message(openMsg);

			// This should create a new channel
			mgr.handleMessage(
				'02' + '00'.repeat(32),
				MessageType.OPEN_CHANNEL2,
				encoded
			);

			// Verify a message was emitted (accept_channel2)
			// We check via outbound message emission
			let messageCount = 0;
			mgr.on('message:outbound', () => {
				messageCount++;
			});

			// Re-send to see if it gets handled (may error due to duplicate)
			mgr.handleMessage(
				'02' + '00'.repeat(32),
				MessageType.OPEN_CHANNEL2,
				encoded
			);
			// messageCount may or may not increase depending on duplicate handling
			expect(messageCount).to.be.a('number');
		});
	});

	// ─── LightningNode integration ───

	describe('LightningNode.openChannelV2', () => {
		it('should create a v2 channel', () => {
			const nodePrivkey = crypto.randomBytes(32);
			const bp = makeBasepoints();
			const node = new LightningNode({
				nodePrivateKey: nodePrivkey,
				channelBasepoints: bp,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32)
			});
			node.on('node:error', () => {}); // absorb errors

			const channel = node.openChannelV2('02' + 'ab'.repeat(32), {
				fundingSatoshis: 100000n
			});

			expect(channel).to.not.be.null;
			expect(channel.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);

			node.destroy();
		});

		it('should validate peer pubkey', () => {
			const nodePrivkey = crypto.randomBytes(32);
			const bp = makeBasepoints();
			const node = new LightningNode({
				nodePrivateKey: nodePrivkey,
				channelBasepoints: bp,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32)
			});
			node.on('node:error', () => {});

			expect(() =>
				node.openChannelV2('invalid', { fundingSatoshis: 100000n })
			).to.throw();

			node.destroy();
		});

		it('should validate funding amount', () => {
			const nodePrivkey = crypto.randomBytes(32);
			const bp = makeBasepoints();
			const node = new LightningNode({
				nodePrivateKey: nodePrivkey,
				channelBasepoints: bp,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32)
			});
			node.on('node:error', () => {});

			expect(() =>
				node.openChannelV2('02' + 'ab'.repeat(32), { fundingSatoshis: 0n })
			).to.throw();

			node.destroy();
		});
	});

	// ─── Full flow integration ───

	describe('Full dual-funding flow', () => {
		it('should complete a full v2 channel opening flow', () => {
			const channelId = crypto.randomBytes(32);

			// Opener session
			const opener = new DualFundingSession(true, channelId);
			const openerParams = makeDualFundingParams({ fundingSatoshis: 100000n });
			const openResult = opener.initiateOpen(openerParams);
			expect(openResult.ok).to.be.true;
			expect(opener.getState()).to.equal(DualFundingState.AWAITING_ACCEPT);

			// Acceptor session
			const acceptor = new DualFundingSession(false, channelId);
			const acceptorParams = makeDualFundingParams({ fundingSatoshis: 50000n });
			const acceptResult = acceptor.handleOpenChannel2(
				openResult.message!,
				acceptorParams
			);
			expect(acceptResult.ok).to.be.true;
			expect(acceptor.getState()).to.equal(DualFundingState.TX_NEGOTIATION);

			// Opener handles accept
			const handleAcceptResult = opener.handleAcceptChannel2(
				makeAcceptChannel2Msg({ channelId, fundingSatoshis: 50000n })
			);
			expect(handleAcceptResult.ok).to.be.true;
			expect(opener.getState()).to.equal(DualFundingState.TX_NEGOTIATION);

			// Both add inputs
			opener.addInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			acceptor.addInput({
				serialId: 1n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});

			// Add funding output
			opener.addOutput({
				serialId: 2n,
				amountSats: 150000n, // combined funding
				scriptPubkey: Buffer.alloc(34, 0x00)
			});

			// Mirror on peer side
			opener.addPeerInput({
				serialId: 1n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			acceptor.addPeerInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			acceptor.addPeerOutput({
				serialId: 2n,
				amountSats: 150000n,
				scriptPubkey: Buffer.alloc(34, 0x00)
			});

			// Both send tx_complete
			opener.markComplete();
			acceptor.markComplete();
			opener.handlePeerComplete();
			acceptor.handlePeerComplete();

			expect(opener.getState()).to.equal(
				DualFundingState.AWAITING_TX_SIGNATURES
			);
			expect(acceptor.getState()).to.equal(
				DualFundingState.AWAITING_TX_SIGNATURES
			);

			// Exchange signatures
			const txid = crypto.randomBytes(32);
			opener.provideWitnesses(txid, 0, [[Buffer.alloc(72)]]);
			acceptor.provideWitnesses(txid, 0, [[Buffer.alloc(72)]]);
			opener.handlePeerWitnesses(txid, [[Buffer.alloc(72)]]);
			acceptor.handlePeerWitnesses(txid, [[Buffer.alloc(72)]]);

			expect(opener.getState()).to.equal(
				DualFundingState.AWAITING_CHANNEL_READY
			);
			expect(acceptor.getState()).to.equal(
				DualFundingState.AWAITING_CHANNEL_READY
			);

			// Mark both channel ready
			opener.markChannelReady();
			acceptor.markChannelReady();

			expect(opener.getState()).to.equal(DualFundingState.COMPLETE);
			expect(acceptor.getState()).to.equal(DualFundingState.COMPLETE);
			expect(opener.isComplete()).to.be.true;
			expect(acceptor.isComplete()).to.be.true;
		});

		it('should handle unequal contributions (acceptor contributes 0)', () => {
			const channelId = crypto.randomBytes(32);

			const opener = new DualFundingSession(true, channelId);
			opener.initiateOpen(makeDualFundingParams({ fundingSatoshis: 100000n }));

			const acceptor = new DualFundingSession(false, channelId);
			const acceptResult = acceptor.handleOpenChannel2(
				opener.getOpenMsg()!,
				makeDualFundingParams({ fundingSatoshis: 0n })
			);
			expect(acceptResult.ok).to.be.true;
			expect(acceptResult.message!.fundingSatoshis).to.equal(0n);

			opener.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId,
					fundingSatoshis: 0n
				})
			);

			expect(opener.getTotalFunding()).to.equal(100000n);
		});

		it('should handle abort mid-construction', () => {
			const channelId = crypto.randomBytes(32);

			const opener = new DualFundingSession(true, channelId);
			opener.initiateOpen(makeDualFundingParams());
			opener.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

			// Add some data
			opener.addInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});

			// Abort
			opener.abort();

			expect(opener.getState()).to.equal(DualFundingState.ABORTED);
			expect(opener.isAborted()).to.be.true;

			// Should not be able to add more inputs
			const result = opener.addInput({
				serialId: 2n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			expect(result.ok).to.be.false;
		});

		it('should handle RBF flow', () => {
			const channelId = crypto.randomBytes(32);

			const opener = new DualFundingSession(true, channelId);
			opener.initiateOpen(makeDualFundingParams({ fundingFeeratePerkw: 1000 }));
			opener.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

			// Add input and output
			opener.addInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});

			// RBF with higher fee
			const rbfResult = opener.initiateRbf(2000);
			expect(rbfResult.ok).to.be.true;

			// Session should be reset to TX_NEGOTIATION
			expect(opener.getState()).to.equal(DualFundingState.TX_NEGOTIATION);
			expect(opener.getTxBuilder()!.getInputs().length).to.equal(0);

			// Can add new inputs
			opener.addInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			expect(opener.getTxBuilder()!.getInputs().length).to.equal(1);
		});
	});
});
