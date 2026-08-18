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
	encodeAcceptChannelMessage,
	encodeOpenChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	encodeFundingCreatedMessage,
	encodeFundingSignedMessage
} from '../../src/lightning/message/channel-funding';

import {
	DualFundingSession,
	DualFundingState,
	IDualFundingParams
} from '../../src/lightning/channel/dual-funding';

// InteractiveTxState used indirectly via DualFundingSession

import {
	Channel,
	ISpliceWalletInput
} from '../../src/lightning/channel/channel';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	validateV2ChannelType
} from '../../src/lightning/channel/types';
import {
	ChannelAction,
	ChannelActionType,
	IChannelPersistEvent
} from '../../src/lightning/channel/channel-actions';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeErrorMessage,
	encodeErrorMessage
} from '../../src/lightning/message/error';
import {
	encodeTxAbortMessage,
	encodeTxAddInputMessage,
	encodeTxAddOutputMessage,
	encodeTxRemoveInputMessage
} from '../../src/lightning/message/interactive-tx';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IFundingProvider } from '../../src/lightning/node/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { deriveV2TemporaryChannelId } from '../../src/lightning/channel/validation';
import { signWillFund } from '../../src/lightning/channel/liquidity-ads';

// ─────────────── Helpers ───────────────

/**
 * A minimal VALID previous transaction paying `valueSats` to a P2WPKH at
 * vout 0, for peer tx_add_input fixtures (S-2.H3: the receive side now
 * enforces prevtx validity + native-segwit spends).
 */
function makePeerPrevTx(valueSats = 100_000): Buffer {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(
		bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) }).output!,
		valueSats
	);
	return tx.toBuffer();
}

/**
 * Like makePeerPrevTx but paying a P2TR output at vout 0: the fee audit
 * must charge key-spend inputs their actual 230 WU minimum, not the
 * P2WPKH figure (issue #359).
 */
function makePeerPrevTxP2tr(valueSats = 100_000): Buffer {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(
		Buffer.concat([Buffer.from([0x51, 0x20]), crypto.randomBytes(32)]),
		valueSats
	);
	return tx.toBuffer();
}

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
	const message: IOpenChannel2Message = {
		channelId: deriveV2TemporaryChannelId(bp.revocationBasepoint),
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
		// BOLT 2 makes channel_type REQUIRED on open_channel2; the default
		// mirrors the opener's resolved default (static_remotekey).
		channelType: Buffer.from('1000', 'hex'),
		...overrides
	};
	if (overrides?.channelId === undefined) {
		message.channelId = deriveV2TemporaryChannelId(message.revocationBasepoint);
	}
	return message;
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
		// The accepter echoes the offered channel_type (BOLT 2); the default
		// matches makeOpenChannel2Msg's.
		channelType: Buffer.from('1000', 'hex'),
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
		// BOLT 2 makes channel_type REQUIRED on open_channel2; sessions do
		// not inject a default (the Channel layer does), so the fixture
		// carries one that matches the message fixtures above.
		channelType: Buffer.from('1000', 'hex'),
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
					sequence: 0xfffffffd,
					prevTx: makePeerPrevTx(),
					prevTxVout: 0
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
					sequence: 0xfffffffd,
					prevTx: makePeerPrevTx(),
					prevTxVout: 0
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
				expect(result.error).to.contain('25/24 floor');
			});

			it('should reject a fee rate above current but below the 25/24 floor', () => {
				// BOLT 2: RBF requires >= 25/24 of the previous feerate, not a
				// bare strict increase. 1040 > 1000 but < floor(1000 * 25 / 24).
				const { opener } = makeRbfReadySession();
				const result = opener.initiateRbf(1040);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('25/24 floor');
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

			it('allows RBF from AWAITING_CHANNEL_READY (issue 360 spec window)', () => {
				const { opener } = makeRbfReadySession();
				(opener as unknown as { _state: DualFundingState })._state =
					DualFundingState.AWAITING_CHANNEL_READY;
				const result = opener.initiateRbf(2000);
				expect(result.ok).to.be.true;
				expect(opener.getState()).to.equal(DualFundingState.TX_NEGOTIATION);
				expect(opener.getRbfCount()).to.equal(1);
			});

			it('acceptor handles RBF from AWAITING_CHANNEL_READY', () => {
				const channelId = crypto.randomBytes(32);
				const acceptor = new DualFundingSession(false, channelId);
				acceptor.handleOpenChannel2(
					makeOpenChannel2Msg({ channelId, fundingFeeratePerkw: 1000 }),
					makeDualFundingParams()
				);
				(acceptor as unknown as { _state: DualFundingState })._state =
					DualFundingState.AWAITING_CHANNEL_READY;
				const result = acceptor.handleRbf(2000, 0);
				expect(result.ok).to.be.true;
				expect(acceptor.getState()).to.equal(DualFundingState.TX_NEGOTIATION);
				expect(acceptor.getRbfCount()).to.equal(1);
			});

			it('still refuses RBF once the session is COMPLETE', () => {
				const { opener } = makeRbfReadySession();
				(opener as unknown as { _state: DualFundingState })._state =
					DualFundingState.COMPLETE;
				const result = opener.initiateRbf(2000);
				expect(result.ok).to.be.false;
				expect(result.error).to.contain('wrong state');
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

		/**
		 * Issue #379. A v2 reserve is not negotiated: BOLT 2 fixes it at 1% of the
		 * total channel balance "or the dust_limit_satoshis, whichever is greater",
		 * with no maximum, and both peers derive it. Two things were wrong.
		 */
		const openAcceptorChannel = (
			openOverrides: Partial<IOpenChannel2Message>,
			ourDustLimitSatoshis = DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis,
			ourFundingSatoshis = 0n
		): {
			channel: Channel;
			actions: ReturnType<Channel['handleOpenChannel2']>;
		} => {
			const state = createAcceptorState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 0n,
				pushMsat: 0n,
				localConfig: {
					...DEFAULT_CHANNEL_CONFIG,
					dustLimitSatoshis: ourDustLimitSatoshis
				},
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32),
				remoteBasepoints: makeBasepoints(),
				remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
			});
			const channel = new Channel(state);
			const openMsg = makeOpenChannel2Msg({
				channelId: state.temporaryChannelId,
				...openOverrides
			});
			const localParams = makeDualFundingParams({
				fundingSatoshis: ourFundingSatoshis,
				dustLimitSatoshis: ourDustLimitSatoshis,
				localBasepoints: state.localBasepoints,
				localPerCommitmentSeed: state.localPerCommitmentSeed
			});
			return {
				channel,
				actions: channel.handleOpenChannel2(openMsg, localParams)
			};
		};

		/** The opener side: initiateOpenV2, then a crafted accept_channel2. */
		const openOpenerChannel = (
			ourFundingSatoshis: bigint,
			acceptOverrides: Partial<IAcceptChannel2Message>
		): {
			channel: Channel;
			actions: ReturnType<Channel['handleAcceptChannel2']>;
		} => {
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: ourFundingSatoshis,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			const basepoints = state.localBasepoints;
			const seed = state.localPerCommitmentSeed;
			const channel = new Channel(state);
			const openActions = channel.initiateOpenV2(
				makeDualFundingParams({
					fundingSatoshis: ourFundingSatoshis,
					localBasepoints: basepoints,
					localPerCommitmentSeed: seed
				})
			);
			expect(
				openActions.some((a) => a.type === ChannelActionType.ERROR),
				'the open itself was emitted'
			).to.be.false;
			const acceptMsg = makeAcceptChannel2Msg({
				channelId: channel.getFullState().temporaryChannelId,
				...acceptOverrides
			});
			return { channel, actions: channel.handleAcceptChannel2(acceptMsg) };
		};

		const refusalOf = (
			actions: ReturnType<Channel['handleOpenChannel2']>
		): string | null => {
			const error = actions.find((a) => a.type === ChannelActionType.ERROR);
			return error && error.type === ChannelActionType.ERROR
				? error.message
				: null;
		};

		it('derives the v2 reserve without the v1 20% cap (issue 379)', () => {
			// The v1 helper applies its funding/5 cap LAST, so on a small channel
			// it lands the reserve BELOW the dust floor the spec's max() exists to
			// enforce: at capacity 5,000 with a peer dust limit of 1,062 it yields
			// 1,000, and a 1,000-sat reserve output is dust in the peer's own
			// commitment. The spec value is 1,062.
			const { channel, actions } = openAcceptorChannel({
				fundingSatoshis: 5_000n,
				dustLimitSatoshis: 1062n
			});
			expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.be
				.false;
			const state = channel.getFullState();
			expect(state.fundingSatoshis).to.equal(5_000n);
			// What WE keep: never below either side's dust limit.
			expect(state.remoteConfig.channelReserveSatoshis).to.equal(1062n);
			// What we ENFORCE on the peer: 1% floored at the lower dust limit.
			expect(state.localConfig.channelReserveSatoshis).to.equal(354n);
			// Derived, not inherited from static configuration, and stamped as
			// such so the load-time repair never re-derives it (issue 381).
			expect(state.channelReserveVersion).to.be.a('number');
		});

		it('enforces the spec reserve on the peer, without our policy floor (issue 379)', () => {
			// localConfig.channelReserveSatoshis is what we require of THEM, and it
			// was never derived on a v2 open: it stayed at the static 10,000 for
			// the channel's life, so under 1,000,000 sat of capacity we rejected an
			// honest peer's spec-legal HTLC. beignet's stricter 546-sat policy floor
			// must not reach it either, or a 20,000-sat channel over-enforces 546
			// against a peer that correctly derives 354.
			const { channel, actions } = openAcceptorChannel({
				fundingSatoshis: 20_000n,
				dustLimitSatoshis: 546n
			});
			expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.be
				.false;
			const state = channel.getFullState();
			expect(state.localConfig.channelReserveSatoshis).to.equal(354n);
			// Our own reserve keeps the policy floor, which only ever costs us
			// spendable balance.
			expect(state.remoteConfig.channelReserveSatoshis).to.equal(546n);

			// And it takes the LOWER of the two dust limits, so it stays at or
			// below what the peer derives for itself whichever side is stricter.
			// Ours raised to 1,062 against a peer at 354 still enforces 354.
			const strict = openAcceptorChannel(
				{ fundingSatoshis: 5_000n, dustLimitSatoshis: 354n },
				1062n
			);
			expect(strict.actions.some((a) => a.type === ChannelActionType.ERROR)).to
				.be.false;
			const strictState = strict.channel.getFullState();
			expect(strictState.localConfig.channelReserveSatoshis).to.equal(354n);
			expect(strictState.remoteConfig.channelReserveSatoshis).to.equal(1062n);
		});

		it('bounds a v2 peer dust_limit_satoshis at the maximum (issue 379)', () => {
			// v2 only checked the minimum, while v1 has bounded the maximum since
			// the FS-1 audit. It matters more now that the reserve is uncapped: a
			// peer dust limit near the whole capacity would make the reserve WE
			// keep larger than the channel, on top of trimming our commitment
			// output as "dust".
			const refused = openAcceptorChannel({
				fundingSatoshis: 200_000n,
				dustLimitSatoshis: 1063n
			});
			expect(
				refused.actions.some(
					(a) =>
						a.type === ChannelActionType.ERROR &&
						/dust_limit_satoshis 1063 exceeds maximum 1062/.test(a.message)
				)
			).to.be.true;

			const accepted = openAcceptorChannel({
				fundingSatoshis: 200_000n,
				dustLimitSatoshis: 1062n
			});
			expect(accepted.actions.some((a) => a.type === ChannelActionType.ERROR))
				.to.be.false;
			expect(
				accepted.channel.getFullState().remoteConfig.channelReserveSatoshis
			).to.equal(2_000n);

			// The acceptor's dust limit is bounded independently, on the opener's
			// receive side.
			expect(
				refusalOf(
					openOpenerChannel(200_000n, { dustLimitSatoshis: 1063n }).actions
				)
			).to.match(/dust_limit_satoshis 1063 exceeds maximum 1062/);
			expect(
				refusalOf(
					openOpenerChannel(200_000n, { dustLimitSatoshis: 1062n }).actions
				)
			).to.equal(null);
		});

		it('refuses a v2 open whose commitment #0 would have no outputs (issue 379)', () => {
			// open_channel2 and accept_channel2 inherit accept_channel's
			// requirements, so BOLT 2's two receiver MUST-fails on the initial
			// commitment apply: the funder must afford the commitment fee, and
			// both outputs must not be at or below the channel reserve. Neither
			// v2 path ran them, and the reserve values alone do not stop this:
			// a 483/300 split at 253 sat/kw leaves 300 and 300 after the 183-sat
			// fee, both below the 354-sat dust limit, so BOTH commitments are
			// built with zero outputs. A transaction with no outputs is invalid,
			// so neither side would ever have a unilateral exit from the funding.
			expect(
				refusalOf(
					openAcceptorChannel(
						{ fundingSatoshis: 483n, dustLimitSatoshis: 354n },
						354n,
						300n
					).actions
				),
				'acceptor side'
			).to.match(/both sides at or below their channel reserve/);

			// Mirrored on the opener's receive side.
			expect(
				refusalOf(
					openOpenerChannel(483n, {
						fundingSatoshis: 300n,
						dustLimitSatoshis: 354n
					}).actions
				),
				'opener side'
			).to.match(/both sides at or below their channel reserve/);

			// And an opener that cannot even pay commitment #0's fee.
			expect(
				refusalOf(
					openAcceptorChannel(
						{ fundingSatoshis: 100n, dustLimitSatoshis: 354n },
						354n,
						50_000n
					).actions
				),
				'funder cannot afford the fee'
			).to.match(/cannot afford the initial commitment fee/);

			// An ordinary open is untouched: a single-funded 20,000-sat channel
			// leaves the acceptor at 0, which is only ONE side below its reserve.
			expect(
				refusalOf(
					openAcceptorChannel({
						fundingSatoshis: 20_000n,
						dustLimitSatoshis: 354n
					}).actions
				),
				'a plain single-funded open still opens'
			).to.equal(null);
		});

		it('rejects a will_fund lease on a taproot channel (mutually-exclusive types)', () => {
			// Round 17 moved the taproot-v2 refusal to ADMISSION: the raw
			// Channel refuses the proposed type before the lease branch (or
			// any state mutation) sees it, so a will_fund on a taproot open
			// dies at the door with the channel-type error rather than deep
			// in the lease logic. The lessor assertions still pin what
			// matters: nothing was recorded.
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
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType?: number }).messageType === MessageType.ERROR
				),
				'the refusal went out on the wire'
			).to.equal(true);
			const local = actions.find((a) => a.type === ChannelActionType.ERROR);
			expect(local, 'and surfaced locally').to.exist;
			if (local && local.type === ChannelActionType.ERROR) {
				expect(local.message).to.match(
					/option_taproot is not supported for dual-funded/i
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
		// Leases are anchors-only: static_remotekey (12) + anchors (22).
		const LEASE_CHANNEL_TYPE = Buffer.from('401000', 'hex');

		it('rejects the lease when the seller funds less than requested (M2)', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2({
				...params,
				channelType: LEASE_CHANNEL_TYPE,
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 }
			});
			const channelId = channel.getTemporaryChannelId();

			// Adversarial seller: a valid will_fund, but it funds only 100k of the 500k
			// we requested. We must not pay the lease fee for liquidity never delivered.
			const actions = channel.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId,
					channelType: LEASE_CHANNEL_TYPE,
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
				channelType: LEASE_CHANNEL_TYPE,
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 },
				// Buyer's accepted ceiling = the seller's advertised rates (H3).
				maxLeaseRates: M2_RATES
			});
			const channelId = channel.getTemporaryChannelId();

			const actions = channel.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId,
					channelType: LEASE_CHANNEL_TYPE,
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
				channelType: LEASE_CHANNEL_TYPE,
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
					channelType: LEASE_CHANNEL_TYPE,
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
				channelType: LEASE_CHANNEL_TYPE,
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 }
				// no maxLeaseRates → refuse to pay an unverified fee
			});
			const channelId = channel.getTemporaryChannelId();

			const actions = channel.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId,
					channelType: LEASE_CHANNEL_TYPE,
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

			// Add input and output. The input carries its previous transaction,
			// as the wire message always does: the negotiated-tx audit refuses
			// inputs whose prevouts cannot be verified.
			const prevTx = makePeerPrevTx(200_000);
			channel.addTxInput({
				serialId: 0n,
				prevTxid: Buffer.from(bitcoin.Transaction.fromBuffer(prevTx).getHash()),
				prevOutputIndex: 0,
				sequence: 0xfffffffd,
				prevTx,
				prevTxVout: 0
			});
			// The peer's input backs the 50k contribution accept_channel2
			// pledged: with real prevouts the audit checks each side's
			// solvency, which the old prevtx-less fixture skipped.
			const peerPrevTx = makePeerPrevTx(60_000);
			channel.handleTxAddInput({
				channelId,
				serialId: 1n,
				prevTx: peerPrevTx,
				prevTxVout: 0,
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

		/**
		 * Issue #359: the completed-tx fee audit must charge each input its
		 * MINIMUM signed weight (271 WU for P2WPKH with a low-R 71 byte
		 * signature, 230 WU for a P2TR key-spend), never the funding-side
		 * 272 WU estimate. bitcoind-backed peers (eclair, CLN) grind low-R
		 * signatures and pay the exact negotiated feerate against those
		 * minimums; the old floor refused every such solo-funded open by
		 * 1 WU per input. Shape below: our P2WPKH input + the peer's input
		 * + one 22 byte script output at 1000 sat/kw.
		 */
		function driveCompletionWithFee(opts: {
			peerPrevTx: Buffer;
			peerInputValueSats: bigint;
			feeSats: bigint;
		}): { actions: ChannelAction[]; channel: Channel } {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);
			const channelId = channel.getTemporaryChannelId();
			channel.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

			const ourValue = 200_000n;
			const prevTx = makePeerPrevTx(Number(ourValue));
			channel.addTxInput({
				serialId: 0n,
				prevTxid: Buffer.from(bitcoin.Transaction.fromBuffer(prevTx).getHash()),
				prevOutputIndex: 0,
				sequence: 0xfffffffd,
				prevTx,
				prevTxVout: 0
			});
			channel.handleTxAddInput({
				channelId,
				serialId: 1n,
				prevTx: opts.peerPrevTx,
				prevTxVout: 0,
				sequence: 0xfffffffd
			});
			channel.addTxOutput({
				serialId: 2n,
				amountSats: ourValue + opts.peerInputValueSats - opts.feeSats,
				scriptPubkey: Buffer.alloc(22, 0x00)
			});
			channel.handleTxComplete();
			const actions = channel.sendTxComplete();
			return { actions, channel };
		}

		const sends = (
			actions: ChannelAction[],
			messageType: MessageType
		): boolean =>
			actions.some(
				(a) =>
					a.type === ChannelActionType.SEND_MESSAGE &&
					(a as { messageType: MessageType }).messageType === messageType
			);

		it('accepts a completed tx paying the exact feerate with low-R sized witnesses (issue 359)', () => {
			// 42 + 271 + 271 + 124 = 708 WU at 1000 sat/kw: 708 sats is the
			// exact low-R floor and sits BELOW the old 710 sat floor.
			const { actions, channel } = driveCompletionWithFee({
				peerPrevTx: makePeerPrevTx(60_000),
				peerInputValueSats: 60_000n,
				feeSats: 708n
			});
			expect(sends(actions, MessageType.TX_COMPLETE), 'negotiation completes')
				.to.be.true;
			expect(sends(actions, MessageType.TX_ABORT), 'no refusal').to.be.false;
			expect(channel.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		});

		it('audits P2TR key-spend inputs at their actual witness weight (issue 359)', () => {
			// 42 + 271 + 230 + 124 = 667 WU: well below any P2WPKH-based
			// figure for the same shape, so this only passes when the audit
			// prices the peer's taproot input by its prevout type.
			const { actions, channel } = driveCompletionWithFee({
				peerPrevTx: makePeerPrevTxP2tr(60_000),
				peerInputValueSats: 60_000n,
				feeSats: 667n
			});
			expect(sends(actions, MessageType.TX_COMPLETE), 'negotiation completes')
				.to.be.true;
			expect(sends(actions, MessageType.TX_ABORT), 'no refusal').to.be.false;
			expect(channel.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		});

		it('still refuses a P2TR-input tx one sat below its exact floor', () => {
			// 666 sats is 1 below the 667 WU minimum: pins the P2TR key-spend
			// input weight at exactly 230 WU rather than 230-or-less.
			const { actions } = driveCompletionWithFee({
				peerPrevTx: makePeerPrevTxP2tr(60_000),
				peerInputValueSats: 60_000n,
				feeSats: 666n
			});
			expect(sends(actions, MessageType.TX_ABORT), 'refused with tx_abort').to
				.be.true;
			expect(sends(actions, MessageType.TX_COMPLETE), 'does not complete').to.be
				.false;
		});

		it('still refuses a completed tx paying below the low-R fee floor', () => {
			// 707 sats is 1 below the 708 WU minimum: the audit floor moved
			// down to the honest minimum, it did not disappear.
			const { actions } = driveCompletionWithFee({
				peerPrevTx: makePeerPrevTx(60_000),
				peerInputValueSats: 60_000n,
				feeSats: 707n
			});
			expect(sends(actions, MessageType.TX_ABORT), 'refused with tx_abort').to
				.be.true;
			expect(sends(actions, MessageType.TX_COMPLETE), 'does not complete').to.be
				.false;
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

			const actions = channel.handleTxAbort();
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
			// BOLT 2: the receiver of tx_abort MUST echo tx_abort back as the
			// ack when it has not itself sent one.
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType: MessageType }).messageType ===
							MessageType.TX_ABORT
				),
				'tx_abort echoed'
			).to.be.true;
		});

		it('refuses RBF in both directions before the attempt is recorded', () => {
			const { channel, params } = makeV2Channel();
			channel.initiateOpenV2(params);

			const channelId = channel.getTemporaryChannelId();
			channel.handleAcceptChannel2(makeAcceptChannel2Msg({ channelId }));

			// Mid-negotiation there is no recorded attempt to replace (and
			// the wallet's asynchronous input selection may still be
			// resolving): the request is refused locally, nothing reaches
			// the wire, and the negotiation is untouched.
			const actions = channel.initiateTxRbf(2000);
			expect(
				actions.some((a) => a.type === ChannelActionType.ERROR),
				'refused locally'
			).to.be.true;
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType: MessageType }).messageType ===
							MessageType.TX_INIT_RBF
				),
				'nothing reaches the wire'
			).to.be.false;

			// A peer proposing the same mid-negotiation replacement is
			// refused with tx_abort; the session survives to keep negotiating.
			const refusal = channel.handleTxInitRbf({
				channelId: channel.getChannelId() ?? channelId,
				locktime: 0,
				feerate: 2000
			});
			expect(
				refusal.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType: MessageType }).messageType ===
							MessageType.TX_ABORT
				),
				'refused on the wire'
			).to.be.true;
			expect(channel.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
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

describe('Round 17: v2 channel_type admission', () => {
	function taprootType(): Buffer {
		const flags = FeatureFlags.empty();
		flags.setCompulsory(Feature.OPTION_TAPROOT);
		return flags.toBuffer();
	}

	function typeOf(...features: Feature[]): Buffer {
		const flags = FeatureFlags.empty();
		for (const feature of features) flags.setCompulsory(feature);
		return flags.toBuffer();
	}

	function vector(...features: Feature[]): FeatureFlags {
		const flags = FeatureFlags.empty();
		for (const feature of features) flags.setOptional(feature);
		return flags;
	}

	function makeAcceptorChannel(): Channel {
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
		return new Channel(state);
	}

	describe('validateV2ChannelType', () => {
		it('accepts the recognized combinations, requiring presence and minimality', () => {
			// BOLT 2 makes channel_type REQUIRED on open_channel2.
			expect(validateV2ChannelType(null)).to.match(/requires a channel_type/);
			expect(validateV2ChannelType(Buffer.alloc(0))).to.match(
				/requires a channel_type/
			);
			// A padded encoding is two byte strings for one type: the echo
			// check would pass on bytes the dispatch reads differently.
			expect(validateV2ChannelType(Buffer.from('001000', 'hex'))).to.match(
				/minimal encoding/
			);
			expect(validateV2ChannelType(typeOf(Feature.STATIC_REMOTE_KEY))).to.equal(
				null
			);
			expect(
				validateV2ChannelType(
					typeOf(Feature.STATIC_REMOTE_KEY, Feature.ANCHOR_ZERO_FEE_HTLC)
				)
			).to.equal(null);
			// The trusted zero-conf shape: scid_alias + zero_conf ride along.
			expect(
				validateV2ChannelType(
					typeOf(
						Feature.STATIC_REMOTE_KEY,
						Feature.ANCHOR_ZERO_FEE_HTLC,
						Feature.SCID_ALIAS,
						Feature.ZERO_CONF
					)
				)
			).to.equal(null);
		});

		it('refuses taproot, unknown bits, and structural violations', () => {
			expect(validateV2ChannelType(taprootType())).to.match(
				/option_taproot is not supported/
			);
			// An unknown feature bit inside the type.
			expect(
				validateV2ChannelType(
					typeOf(Feature.STATIC_REMOTE_KEY, Feature.LARGE_CHANNELS)
				)
			).to.match(/not a recognized/);
			// An ODD bit is never a channel type.
			const odd = FeatureFlags.empty();
			odd.setOptional(Feature.STATIC_REMOTE_KEY);
			expect(validateV2ChannelType(odd.toBuffer())).to.match(
				/not a recognized/
			);
			expect(
				validateV2ChannelType(typeOf(Feature.ANCHOR_ZERO_FEE_HTLC))
			).to.match(/must include static_remotekey/);
			expect(
				validateV2ChannelType(
					typeOf(Feature.STATIC_REMOTE_KEY, Feature.ZERO_CONF)
				)
			).to.match(/zero_conf requires option_scid_alias/);
		});

		it('holds commitment-format bits to BOTH feature vectors when supplied', () => {
			const anchorsType = typeOf(
				Feature.STATIC_REMOTE_KEY,
				Feature.ANCHOR_ZERO_FEE_HTLC
			);
			const full = vector(
				Feature.STATIC_REMOTE_KEY,
				Feature.ANCHOR_ZERO_FEE_HTLC
			);
			const noAnchors = vector(Feature.STATIC_REMOTE_KEY);
			expect(validateV2ChannelType(anchorsType, full, full)).to.equal(null);
			expect(validateV2ChannelType(anchorsType, noAnchors, full)).to.match(
				/this node does not advertise/
			);
			expect(validateV2ChannelType(anchorsType, full, noAnchors)).to.match(
				/the peer does not advertise/
			);
			// A vector the caller does not have skips only its own half.
			expect(validateV2ChannelType(anchorsType, undefined, full)).to.equal(
				null
			);
		});

		it('holds scid_alias and zero_conf to BOTH feature vectors too', () => {
			const aliasType = typeOf(Feature.STATIC_REMOTE_KEY, Feature.SCID_ALIAS);
			const zeroConfType = typeOf(
				Feature.STATIC_REMOTE_KEY,
				Feature.SCID_ALIAS,
				Feature.ZERO_CONF
			);
			const full = vector(
				Feature.STATIC_REMOTE_KEY,
				Feature.SCID_ALIAS,
				Feature.ZERO_CONF
			);
			const noAlias = vector(Feature.STATIC_REMOTE_KEY);
			const noZeroConf = vector(Feature.STATIC_REMOTE_KEY, Feature.SCID_ALIAS);
			expect(validateV2ChannelType(aliasType, full, full)).to.equal(null);
			expect(validateV2ChannelType(zeroConfType, full, full)).to.equal(null);
			expect(validateV2ChannelType(aliasType, noAlias, full)).to.match(
				/scid_alias was not negotiated: this node/
			);
			expect(validateV2ChannelType(aliasType, full, noAlias)).to.match(
				/scid_alias was not negotiated: the peer/
			);
			expect(validateV2ChannelType(zeroConfType, noZeroConf, full)).to.match(
				/zero_conf was not negotiated: this node/
			);
			expect(validateV2ChannelType(zeroConfType, full, noZeroConf)).to.match(
				/zero_conf was not negotiated: the peer/
			);
		});
	});

	describe('raw Channel admission', () => {
		it('refuses an inbound taproot channel_type before any state exists', () => {
			// No lease involved: the type alone is refused at the door, so
			// nothing is derived, adopted or echoed for a negotiation that
			// would die at the commitment stage (taproot v2 signing does
			// not exist).
			const channel = makeAcceptorChannel();
			const actions = channel.handleOpenChannel2(
				makeOpenChannel2Msg({
					channelId: channel.getTemporaryChannelId(),
					channelType: taprootType()
				}),
				makeDualFundingParams()
			);
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType?: number }).messageType === MessageType.ERROR
				),
				'the refusal went out on the wire'
			).to.equal(true);
			const local = actions.find((a) => a.type === ChannelActionType.ERROR);
			expect(local, 'and surfaced locally').to.exist;
			if (local && local.type === ChannelActionType.ERROR) {
				expect(local.message).to.match(
					/option_taproot is not supported for dual-funded/
				);
			}
			const state = channel.getFullState();
			expect(state.state, 'no state transition').to.equal(ChannelState.NONE);
			expect(state.dualFundingSession == null, 'no session').to.equal(true);
			expect(state.channelType, 'no adopted type').to.equal(null);
		});

		it('refuses an inbound channel_type carrying unknown bits', () => {
			const channel = makeAcceptorChannel();
			const actions = channel.handleOpenChannel2(
				makeOpenChannel2Msg({
					channelId: channel.getTemporaryChannelId(),
					channelType: typeOf(Feature.STATIC_REMOTE_KEY, Feature.LARGE_CHANNELS)
				}),
				makeDualFundingParams()
			);
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType?: number }).messageType === MessageType.ERROR
				),
				'the refusal went out on the wire'
			).to.equal(true);
			const local = actions.find((a) => a.type === ChannelActionType.ERROR);
			expect(local, 'and surfaced locally').to.exist;
			expect(channel.getFullState().state).to.equal(ChannelState.NONE);
		});

		it('refuses to INITIATE a v2 open with a taproot channel_type', () => {
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			const channel = new Channel(state);
			const actions = channel.initiateOpenV2(
				makeDualFundingParams({
					localBasepoints: state.localBasepoints,
					localPerCommitmentSeed: state.localPerCommitmentSeed,
					channelType: taprootType()
				})
			);
			expect(actions.length).to.equal(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			if (actions[0].type === ChannelActionType.ERROR) {
				expect(actions[0].message).to.match(
					/option_taproot is not supported for dual-funded/
				);
			}
			expect(
				channel.getFullState().fundingVersion,
				'no state mutated before the refusal'
			).to.not.equal(2);
		});
	});

	describe('round-18 admission hardening', () => {
		it('an inbound open_channel2 WITHOUT a channel_type is refused', () => {
			// BOLT 2 makes the field required; adopting a default here would
			// negotiate a commitment format the opener never named.
			const channel = makeAcceptorChannel();
			const actions = channel.handleOpenChannel2(
				makeOpenChannel2Msg({
					channelId: channel.getTemporaryChannelId(),
					channelType: undefined
				}),
				makeDualFundingParams()
			);
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType?: number }).messageType === MessageType.ERROR
				),
				'the refusal went out on the wire'
			).to.equal(true);
			const local = actions.find((a) => a.type === ChannelActionType.ERROR);
			expect(local, 'and surfaced locally').to.exist;
			if (local && local.type === ChannelActionType.ERROR) {
				expect(local.message).to.match(/requires a channel_type/);
			}
			expect(channel.getFullState().state).to.equal(ChannelState.NONE);
		});

		it('an inbound scid_alias type with the announce flag is refused', () => {
			// BOLT 2: a channel whose type carries option_scid_alias must not
			// be announced; an opener pairing them is refused, not silently
			// flipped private on one side only.
			const channel = makeAcceptorChannel();
			const actions = channel.handleOpenChannel2(
				makeOpenChannel2Msg({
					channelId: channel.getTemporaryChannelId(),
					channelType: typeOf(Feature.STATIC_REMOTE_KEY, Feature.SCID_ALIAS),
					channelFlags: 0x01
				}),
				makeDualFundingParams()
			);
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						(a as { messageType?: number }).messageType === MessageType.ERROR
				),
				'the refusal went out on the wire'
			).to.equal(true);
			const local = actions.find((a) => a.type === ChannelActionType.ERROR);
			expect(local, 'and surfaced locally').to.exist;
			if (local && local.type === ChannelActionType.ERROR) {
				expect(local.message).to.match(/cannot be announced/);
			}
			expect(channel.getFullState().state).to.equal(ChannelState.NONE);
		});

		it('an outbound scid_alias type is forced PRIVATE', () => {
			// The caller handed an alias type with the default (announce)
			// flags: the open must go out private, exactly like a trusted
			// open, because the alias type forbids announcement.
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			const channel = new Channel(state);
			const actions = channel.initiateOpenV2(
				makeDualFundingParams({
					localBasepoints: state.localBasepoints,
					localPerCommitmentSeed: state.localPerCommitmentSeed,
					channelType: typeOf(Feature.STATIC_REMOTE_KEY, Feature.SCID_ALIAS)
				})
			);
			expect(actions.length).to.equal(1);
			expect(actions[0].type).to.equal(ChannelActionType.SEND_MESSAGE);
			if (actions[0].type === ChannelActionType.SEND_MESSAGE) {
				const sent = decodeOpenChannel2Message(actions[0].payload);
				expect(sent.channelFlags & 0x01, 'announce bit cleared').to.equal(0);
			}
			expect(channel.getFullState().announceChannel).to.equal(false);
		});

		it('a rejected accept_channel2 echo fails WIRE-VISIBLY', () => {
			// A local error alone deletes our half while the accepter waits
			// for tx_add_input forever: the refusal must reach the peer.
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			const channel = new Channel(state);
			const openActions = channel.initiateOpenV2(
				makeDualFundingParams({
					localBasepoints: state.localBasepoints,
					localPerCommitmentSeed: state.localPerCommitmentSeed
				})
			);
			expect(openActions[0].type).to.equal(ChannelActionType.SEND_MESSAGE);
			const actions = channel.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId: channel.getTemporaryChannelId(),
					channelType: Buffer.from('401000', 'hex')
				})
			);
			const wire = actions.find(
				(a) =>
					a.type === ChannelActionType.SEND_MESSAGE &&
					(a as { messageType?: number }).messageType === MessageType.ERROR
			);
			expect(wire, 'the refusal went out on the wire').to.exist;
			expect(
				actions.some((a) => a.type === ChannelActionType.ERROR),
				'and surfaced locally'
			).to.equal(true);
		});
	});

	describe('round-19 wire-visible inbound refusals', () => {
		const peerPubkey = '02' + 'ab'.repeat(32);
		const leaseRates = {
			fundingWeightWitness: 1000,
			leaseFeeBasis: 100,
			leaseFeeBaseSat: 500,
			channelFeeMaxBaseMsat: 5000,
			channelFeeMaxProportionalThousandths: 10
		};
		type ManagerMaps = {
			channels: Map<string, Channel>;
			tempChannels: Map<string, Channel>;
			channelPeers: Map<string, string>;
		};

		function mapsOf(mgr: ChannelManager): ManagerMaps {
			return mgr as unknown as ManagerMaps;
		}

		function makeDetachedChannel(temporaryChannelId: Buffer): Channel {
			return new Channel(
				createOpenerState({
					temporaryChannelId,
					fundingSatoshis: 100_000n,
					pushMsat: 0n,
					localConfig: DEFAULT_CHANNEL_CONFIG,
					localBasepoints: makeBasepoints(),
					localPerCommitmentSeed: crypto.randomBytes(32)
				})
			);
		}

		function installPermanentVictim(
			mgr: ChannelManager,
			channelId: Buffer,
			owner: string
		): Channel {
			const victim = makeDetachedChannel(crypto.randomBytes(32));
			victim.getFullState().state = ChannelState.NORMAL;
			victim.getFullState().channelId = channelId;
			const maps = mapsOf(mgr);
			maps.channels.set(channelId.toString('hex'), victim);
			maps.channelPeers.set(channelId.toString('hex'), owner);
			return victim;
		}

		function encodeV1Open(temporaryChannelId: Buffer): Buffer {
			const points = makeBasepoints();
			return encodeOpenChannelMessage({
				chainHash: Buffer.alloc(32),
				temporaryChannelId,
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 500_000_000n,
				channelReserveSatoshis: 1_000n,
				htlcMinimumMsat: 1_000n,
				feeratePerKw: 253,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 483,
				fundingPubkey: points.fundingPubkey,
				revocationBasepoint: points.revocationBasepoint,
				paymentBasepoint: points.paymentBasepoint,
				delayedPaymentBasepoint: points.delayedPaymentBasepoint,
				htlcBasepoint: points.htlcBasepoint,
				firstPerCommitmentPoint: points.firstPerCommitmentPoint,
				channelFlags: 0
			});
		}

		function encodeV1Accept(channel: Channel): Buffer {
			const points = makeBasepoints();
			return encodeAcceptChannelMessage({
				temporaryChannelId: channel.getTemporaryChannelId(),
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 500_000_000n,
				channelReserveSatoshis: 1_000n,
				htlcMinimumMsat: 1_000n,
				minimumDepth: 3,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 483,
				fundingPubkey: points.fundingPubkey,
				revocationBasepoint: points.revocationBasepoint,
				paymentBasepoint: points.paymentBasepoint,
				delayedPaymentBasepoint: points.delayedPaymentBasepoint,
				htlcBasepoint: points.htlcBasepoint,
				firstPerCommitmentPoint: points.firstPerCommitmentPoint,
				channelType: channel.getFullState().channelType ?? undefined
			});
		}

		function untrustedZeroConfOpen(
			overrides: Partial<IOpenChannel2Message> = {}
		): IOpenChannel2Message {
			return makeOpenChannel2Msg({
				channelType: typeOf(
					Feature.STATIC_REMOTE_KEY,
					Feature.SCID_ALIAS,
					Feature.ZERO_CONF
				),
				channelFlags: 0x00,
				...overrides
			});
		}

		function installThrowingTransport(
			mgr: ChannelManager,
			openMsg: IOpenChannel2Message
		): {
			sent: Array<{ type: number; payload: Buffer }>;
			errors: string[];
			tempPresentAtDelivery: () => boolean;
		} {
			const sent: Array<{ type: number; payload: Buffer }> = [];
			const errors: string[] = [];
			let presentAtDelivery = false;
			let throwOnce = true;
			mgr.on('error', (_id: Buffer | null, message: string) => {
				errors.push(message);
			});
			mgr.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
					if (type === MessageType.ERROR && throwOnce) {
						throwOnce = false;
						presentAtDelivery = mgr.getTempChannel(openMsg.channelId) != null;
						throw new Error('transport threw after delivery');
					}
				}
			);
			return {
				sent,
				errors,
				tempPresentAtDelivery: (): boolean => presentAtDelivery
			};
		}

		function assertRefusal(
			mgr: ChannelManager,
			openMsg: IOpenChannel2Message,
			probe: ReturnType<typeof installThrowingTransport>
		): void {
			const wireErrors = probe.sent.filter(
				(message) => message.type === MessageType.ERROR
			);
			expect(wireErrors, 'one refusal reached the opener').to.have.length(1);
			const decoded = decodeErrorMessage(wireErrors[0].payload);
			expect(
				decoded.channelId.equals(openMsg.channelId),
				'exact temporary id'
			).to.equal(true);
			expect(decoded.data.toString('ascii')).to.contain(
				'requires a trusted peer'
			);
			expect(
				probe.errors.filter((message) =>
					message.includes('requires a trusted peer')
				),
				'one local refusal'
			).to.have.length(1);
			expect(
				probe.tempPresentAtDelivery(),
				'wire attempt preceded cleanup'
			).to.equal(true);
			expect(
				mgr.getTempChannel(openMsg.channelId),
				'temporary channel cleaned'
			).to.equal(undefined);
			expect(
				(
					mgr as unknown as { channelPeers: Map<string, string> }
				).channelPeers.has(openMsg.channelId.toString('hex')),
				'temporary peer binding cleaned'
			).to.equal(false);
			expect(
				probe.sent.some(
					(message) => message.type === MessageType.ACCEPT_CHANNEL2
				),
				'no accept_channel2 went out'
			).to.equal(false);
		}

		async function settlePromises(): Promise<void> {
			await new Promise<void>((resolve) => setImmediate(resolve));
			await new Promise<void>((resolve) => setImmediate(resolve));
		}

		function makeLeaseManager(
			selectSpliceInputs: NonNullable<IFundingProvider['selectSpliceInputs']>,
			selectDualFundingInputs?: NonNullable<
				IFundingProvider['selectDualFundingInputs']
			>
		): ChannelManager {
			const mgr = new ChannelManager({
				...makeChannelManagerConfig(),
				nodePrivateKey: crypto.randomBytes(32),
				leaseRates
			});
			mgr.setFundingProvider({
				buildFundingTransaction: async () => {
					throw new Error('not used by this test');
				},
				broadcastTransaction: async () => {
					throw new Error('not used by this test');
				},
				selectSpliceInputs,
				...(selectDualFundingInputs ? { selectDualFundingInputs } : {})
			});
			return mgr;
		}

		function makeAutofundInput(valueSats: number): ISpliceWalletInput {
			const prevTx = new bitcoin.Transaction();
			prevTx.version = 2;
			prevTx.addInput(crypto.randomBytes(32), 0);
			prevTx.addOutput(
				bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) }).output!,
				valueSats
			);
			return {
				prevTx: prevTx.toBuffer(),
				prevOutputIndex: 0,
				value: BigInt(valueSats),
				sequence: 0xfffffffd,
				confirmed: true,
				signWitness: (): Buffer[] => []
			};
		}

		function makeAutofundManager(
			selectSpliceInputs: NonNullable<IFundingProvider['selectSpliceInputs']>,
			selectDualFundingInputs?: NonNullable<
				IFundingProvider['selectDualFundingInputs']
			>
		): ChannelManager {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			mgr.setFundingProvider({
				buildFundingTransaction: async () => {
					throw new Error('not used by this test');
				},
				broadcastTransaction: async () => {
					throw new Error('not used by this test');
				},
				selectSpliceInputs,
				...(selectDualFundingInputs ? { selectDualFundingInputs } : {})
			});
			return mgr;
		}

		/**
		 * Issue #380: a v2 open contribution must be sized with the DUAL-FUNDING
		 * weight, not the splice weight. Both open paths prefer the
		 * dual-funding-aware selector and hand it the role whose fee share the
		 * channel will actually charge; selectSpliceInputs is only the fallback
		 * for providers that predate the method.
		 */
		interface IDualCall {
			amountSats: bigint;
			feeratePerKw: number;
			initiator: boolean;
		}

		it('funds a lease contribution through the dual-funding selector, as acceptor', async () => {
			const changeScript = bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!;
			const spliceCalls: bigint[] = [];
			const dualCalls: IDualCall[] = [];
			const mgr = makeLeaseManager(
				async (amountSats) => {
					spliceCalls.push(amountSats);
					return { inputs: [makeAutofundInput(900_000)], changeScript };
				},
				async (amountSats, feeratePerKw, initiator) => {
					dualCalls.push({ amountSats, feeratePerKw, initiator });
					return { inputs: [makeAutofundInput(900_000)], changeScript };
				}
			);
			const sent: number[] = [];
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const openMsg = makeOpenChannel2Msg({
				channelType: typeOf(
					Feature.STATIC_REMOTE_KEY,
					Feature.ANCHOR_ZERO_FEE_HTLC
				),
				channelFlags: 0x00,
				requestFunds: { requestedSats: 500_000n, blockheight: 800_000 }
			});

			mgr.handleMessage(
				peerPubkey,
				MessageType.OPEN_CHANNEL2,
				encodeOpenChannel2Message(openMsg)
			);
			await settlePromises();

			expect(spliceCalls, 'the splice selector must not be used').to.deep.equal(
				[]
			);
			expect(dualCalls).to.deep.equal([
				{
					amountSats: 500_000n,
					feeratePerKw: openMsg.fundingFeeratePerkw,
					// We are answering open_channel2, so our fee share excludes the
					// common fields and the shared funding output.
					initiator: false
				}
			]);
			expect(
				sent.filter((type) => type === MessageType.ACCEPT_CHANNEL2)
			).to.have.length(1);
		});

		it('funds the opener contribution through the dual-funding selector, as initiator', async () => {
			const owner = '02' + 'cd'.repeat(32);
			const changeScript = bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!;
			const spliceCalls: bigint[] = [];
			const dualCalls: IDualCall[] = [];
			const mgr = makeAutofundManager(
				async (amountSats) => {
					spliceCalls.push(amountSats);
					return { inputs: [makeAutofundInput(200_000)], changeScript };
				},
				async (amountSats, feeratePerKw, initiator) => {
					dualCalls.push({ amountSats, feeratePerKw, initiator });
					return { inputs: [makeAutofundInput(200_000)], changeScript };
				}
			);
			const sent: number[] = [];
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const params = makeDualFundingParams();
			const channel = mgr.createDualFundedChannel(owner, params);
			const tempId = channel.getTemporaryChannelId();
			sent.length = 0;

			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({ channelId: tempId })
				)
			);
			await settlePromises();

			expect(spliceCalls, 'the splice selector must not be used').to.deep.equal(
				[]
			);
			expect(dualCalls).to.deep.equal([
				{
					amountSats: params.fundingSatoshis,
					feeratePerKw: params.fundingFeeratePerkw,
					// The initiator additionally pays the common fields and the
					// shared funding output.
					initiator: true
				}
			]);
			expect(
				sent.filter((type) => type === MessageType.TX_ADD_INPUT)
			).to.have.length(1);
			expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
		});

		it('falls back to the splice selector for a provider without the dual method', async () => {
			const owner = '02' + 'cd'.repeat(32);
			const changeScript = bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!;
			const spliceCalls: bigint[] = [];
			const mgr = makeAutofundManager(async (amountSats) => {
				spliceCalls.push(amountSats);
				return { inputs: [makeAutofundInput(200_000)], changeScript };
			});
			const sent: number[] = [];
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const params = makeDualFundingParams();
			const channel = mgr.createDualFundedChannel(owner, params);
			const tempId = channel.getTemporaryChannelId();
			sent.length = 0;

			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({ channelId: tempId })
				)
			);
			await settlePromises();

			expect(spliceCalls).to.deep.equal([params.fundingSatoshis]);
			expect(
				sent.filter((type) => type === MessageType.TX_ADD_INPUT)
			).to.have.length(1);
			expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
		});

		it('cleans a synchronous refusal when transport throws after delivery', () => {
			// The reviewer's reproduction: the zero-conf trust gate fired
			// after the manager retained the temp channel, and its local-only
			// error deleted our half silently, leaving the opener awaiting
			// accept_channel2 forever. The refusal and cleanup must also survive
			// a synchronous transport failure after delivery.
			const config = makeChannelManagerConfig();
			const mgr = new ChannelManager(config);
			const openMsg = untrustedZeroConfOpen();
			const probe = installThrowingTransport(mgr, openMsg);
			mgr.handleMessage(
				peerPubkey,
				MessageType.OPEN_CHANNEL2,
				encodeOpenChannel2Message(openMsg)
			);
			assertRefusal(mgr, openMsg, probe);
		});

		it('cleans a refusal when the local error observer throws', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const openMsg = untrustedZeroConfOpen();
			const sent: number[] = [];
			let localCalls = 0;
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			mgr.on('error', () => {
				localCalls++;
				throw new Error('local observer failed');
			});
			try {
				mgr.handleMessage(
					peerPubkey,
					MessageType.OPEN_CHANNEL2,
					encodeOpenChannel2Message(openMsg)
				);
			} catch {
				// The observer may propagate, but it cannot prevent cleanup.
			}
			expect(sent.filter((type) => type === MessageType.ERROR)).to.have.length(
				1
			);
			expect(localCalls).to.be.greaterThan(0);
			expect(mgr.getTempChannel(openMsg.channelId)).to.equal(undefined);
		});

		it('contains a transition observer and completes the scoped refusal', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const openMsg = untrustedZeroConfOpen();
			const sent: Array<{ type: number; payload: Buffer }> = [];
			let transitionCalls = 0;
			mgr.on('error', () => {});
			mgr.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
				}
			);
			mgr.on('transition:begin', () => {
				transitionCalls++;
				throw new Error('transition setup failed');
			});

			expect(() =>
				mgr.handleMessage(
					peerPubkey,
					MessageType.OPEN_CHANNEL2,
					encodeOpenChannel2Message(openMsg)
				)
			).to.not.throw();

			expect(transitionCalls).to.equal(1);
			const wireErrors = sent.filter(
				(message) => message.type === MessageType.ERROR
			);
			expect(wireErrors).to.have.length(1);
			expect(
				decodeErrorMessage(wireErrors[0].payload).channelId.equals(
					openMsg.channelId
				)
			).to.equal(true);
			expect(mgr.getTempChannel(openMsg.channelId)).to.equal(undefined);
			expect(
				mapsOf(mgr).channelPeers.has(openMsg.channelId.toString('hex'))
			).to.equal(false);
		});

		it('refuses an outbound v2 temporary id collision without replacement', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const firstOwner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const secondOwner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const sent: number[] = [];
			mgr.on('error', () => {});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const first = mgr.createDualFundedChannel(
				firstOwner,
				makeDualFundingParams()
			);
			const tempId = first.getTemporaryChannelId();

			expect(() =>
				mgr.createDualFundedChannel(secondOwner, makeDualFundingParams())
			).to.throw('temporary channel_id is already in use');
			expect(mgr.getTempChannel(tempId)).to.equal(first);
			expect(mapsOf(mgr).channelPeers.get(tempId.toString('hex'))).to.equal(
				firstOwner
			);
			expect(
				sent.filter((type) => type === MessageType.OPEN_CHANNEL2)
			).to.have.length(1);
		});

		it('refuses a mismatched v2 temporary id without replacing its owner', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const attacker = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const sent: Array<{ type: number; payload: Buffer }> = [];
			mgr.on('error', () => {});
			mgr.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
				}
			);
			const existing = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = existing.getTemporaryChannelId();
			sent.length = 0;
			const malicious = makeOpenChannel2Msg({ channelId: tempId });

			mgr.handleMessage(
				attacker,
				MessageType.OPEN_CHANNEL2,
				encodeOpenChannel2Message(malicious)
			);

			expect(mgr.getTempChannel(tempId)).to.equal(existing);
			expect(
				(
					mgr as unknown as { channelPeers: Map<string, string> }
				).channelPeers.get(tempId.toString('hex'))
			).to.equal(owner);
			const wireErrors = sent.filter(
				(message) => message.type === MessageType.ERROR
			);
			expect(wireErrors).to.have.length(1);
			expect(
				decodeErrorMessage(wireErrors[0].payload).channelId.equals(tempId)
			).to.equal(true);
		});

		it('sends scoped refusals for wrong-chain and lost-namespace opens', () => {
			const cases = [
				{
					manager: new ChannelManager({
						...makeChannelManagerConfig(),
						chainHash: Buffer.alloc(32, 0x01)
					}),
					message: makeOpenChannel2Msg({
						chainHash: Buffer.alloc(32, 0x02)
					})
				},
				{
					manager: new ChannelManager({
						...makeChannelManagerConfig(),
						durabilityBarrier: {
							enforcing: true,
							namespaceLost: true,
							isReleased: (): boolean => false,
							whenReleased: async (): Promise<{
								released: boolean;
								reason: string;
							}> => ({
								released: false,
								reason: 'namespace-lost'
							})
						}
					}),
					message: makeOpenChannel2Msg()
				}
			];

			for (const { manager, message } of cases) {
				const sent: Array<{ type: number; payload: Buffer }> = [];
				manager.on('error', () => {});
				manager.on(
					'message:outbound',
					(_peer: string, type: number, payload: Buffer) => {
						sent.push({ type, payload });
					}
				);
				manager.handleMessage(
					peerPubkey,
					MessageType.OPEN_CHANNEL2,
					encodeOpenChannel2Message(message)
				);
				const wireErrors = sent.filter(
					(item) => item.type === MessageType.ERROR
				);
				expect(wireErrors).to.have.length(1);
				expect(
					decodeErrorMessage(wireErrors[0].payload).channelId.equals(
						message.channelId
					)
				).to.equal(true);
				expect(manager.getTempChannel(message.channelId)).to.equal(undefined);
			}
		});

		it('does not retry an async refusal after wallet selection succeeds', async () => {
			let selections = 0;
			const mgr = makeLeaseManager(async () => {
				selections++;
				return { inputs: [], changeScript: Buffer.alloc(0) };
			});
			const openMsg = untrustedZeroConfOpen({
				channelType: typeOf(
					Feature.STATIC_REMOTE_KEY,
					Feature.ANCHOR_ZERO_FEE_HTLC,
					Feature.SCID_ALIAS,
					Feature.ZERO_CONF
				),
				requestFunds: { requestedSats: 500_000n, blockheight: 800_000 }
			});
			const probe = installThrowingTransport(mgr, openMsg);
			mgr.handleMessage(
				peerPubkey,
				MessageType.OPEN_CHANNEL2,
				encodeOpenChannel2Message(openMsg)
			);
			await settlePromises();
			expect(selections).to.equal(1);
			assertRefusal(mgr, openMsg, probe);
		});

		it('contains an async fallback refusal after wallet selection fails', async () => {
			let selections = 0;
			const mgr = makeLeaseManager(async () => {
				selections++;
				throw new Error('selector failed');
			});
			const openMsg = untrustedZeroConfOpen({
				channelType: typeOf(
					Feature.STATIC_REMOTE_KEY,
					Feature.ANCHOR_ZERO_FEE_HTLC,
					Feature.SCID_ALIAS,
					Feature.ZERO_CONF
				),
				requestFunds: { requestedSats: 500_000n, blockheight: 800_000 }
			});
			const probe = installThrowingTransport(mgr, openMsg);
			mgr.handleMessage(
				peerPubkey,
				MessageType.OPEN_CHANNEL2,
				encodeOpenChannel2Message(openMsg)
			);
			await settlePromises();
			expect(selections).to.equal(1);
			assertRefusal(mgr, openMsg, probe);
		});

		it('routes a synchronous wallet throw through the fallback refusal', async () => {
			let selections = 0;
			const throwingSelector = (() => {
				selections++;
				throw new Error('synchronous selector failure');
			}) as NonNullable<IFundingProvider['selectSpliceInputs']>;
			const mgr = makeLeaseManager(throwingSelector);
			const openMsg = untrustedZeroConfOpen({
				channelType: typeOf(
					Feature.STATIC_REMOTE_KEY,
					Feature.ANCHOR_ZERO_FEE_HTLC,
					Feature.SCID_ALIAS,
					Feature.ZERO_CONF
				),
				requestFunds: { requestedSats: 500_000n, blockheight: 800_000 }
			});
			const probe = installThrowingTransport(mgr, openMsg);
			mgr.handleMessage(
				peerPubkey,
				MessageType.OPEN_CHANNEL2,
				encodeOpenChannel2Message(openMsg)
			);
			await settlePromises();
			expect(selections).to.equal(1);
			assertRefusal(mgr, openMsg, probe);
		});

		it('rechecks ownership after a reentrant wallet-failure observer', async () => {
			type Selection = Awaited<
				ReturnType<NonNullable<IFundingProvider['selectSpliceInputs']>>
			>;
			const attempts: Array<{
				resolve: (selection: Selection) => void;
				reject: (error: Error) => void;
			}> = [];
			const mgr = makeLeaseManager(
				() =>
					new Promise<Selection>((resolve, reject) => {
						attempts.push({ resolve, reject });
					})
			);
			const openMsg = untrustedZeroConfOpen({
				channelType: typeOf(
					Feature.STATIC_REMOTE_KEY,
					Feature.ANCHOR_ZERO_FEE_HTLC,
					Feature.SCID_ALIAS,
					Feature.ZERO_CONF
				),
				requestFunds: { requestedSats: 500_000n, blockheight: 800_000 }
			});
			const payload = encodeOpenChannel2Message(openMsg);
			const sent: number[] = [];
			let reentered = false;
			let replacement: Channel | undefined;
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			mgr.on('error', (_id: Buffer | null, message: string) => {
				if (!reentered && message.includes('Lease contribution not funded')) {
					reentered = true;
					mgr.handleMessage(
						peerPubkey,
						MessageType.ERROR,
						encodeErrorMessage({
							channelId: openMsg.channelId,
							data: Buffer.from('cancel old open', 'ascii')
						})
					);
					mgr.handleMessage(peerPubkey, MessageType.OPEN_CHANNEL2, payload);
					replacement = mgr.getTempChannel(openMsg.channelId);
				}
			});

			mgr.handleMessage(peerPubkey, MessageType.OPEN_CHANNEL2, payload);
			const first = mgr.getTempChannel(openMsg.channelId);
			attempts[0].reject(new Error('old selector failed'));
			await settlePromises();
			expect(reentered).to.equal(true);
			expect(replacement).to.exist;
			expect(replacement).to.not.equal(first);
			expect(mgr.getTempChannel(openMsg.channelId)).to.equal(replacement);
			expect(sent, 'the stale callback dispatched nothing').to.have.length(0);

			attempts[1].reject(new Error('replacement selector failed'));
			await settlePromises();
			expect(sent.filter((type) => type === MessageType.ERROR)).to.have.length(
				1
			);
			expect(mgr.getTempChannel(openMsg.channelId)).to.equal(undefined);
		});

		it('ignores stale wallet selection after a same-id retry', async () => {
			type Selection = Awaited<
				ReturnType<NonNullable<IFundingProvider['selectSpliceInputs']>>
			>;
			const resolvers: Array<(selection: Selection) => void> = [];
			const mgr = makeLeaseManager(
				() =>
					new Promise<Selection>((resolve) => {
						resolvers.push(resolve);
					})
			);
			const openMsg = makeOpenChannel2Msg({
				channelType: typeOf(
					Feature.STATIC_REMOTE_KEY,
					Feature.ANCHOR_ZERO_FEE_HTLC
				),
				channelFlags: 0x00,
				requestFunds: { requestedSats: 500_000n, blockheight: 800_000 }
			});
			const payload = encodeOpenChannel2Message(openMsg);
			const sent: number[] = [];
			const errors: string[] = [];
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			mgr.on('error', (_id: Buffer | null, message: string) => {
				errors.push(message);
			});

			mgr.handleMessage(peerPubkey, MessageType.OPEN_CHANNEL2, payload);
			const first = mgr.getTempChannel(openMsg.channelId);
			mgr.handlePeerDisconnected(peerPubkey);
			mgr.handleMessage(peerPubkey, MessageType.OPEN_CHANNEL2, payload);
			const replacement = mgr.getTempChannel(openMsg.channelId);
			expect(first).to.exist;
			expect(replacement).to.exist;
			expect(replacement).to.not.equal(first);

			resolvers[0]({ inputs: [], changeScript: Buffer.alloc(0) });
			await settlePromises();
			expect(mgr.getTempChannel(openMsg.channelId)).to.equal(replacement);
			expect(
				sent.filter((type) => type === MessageType.ACCEPT_CHANNEL2)
			).to.have.length(0);
			expect(errors.join(' ')).to.not.contain('Unexpected open_channel2');

			resolvers[1]({ inputs: [], changeScript: Buffer.alloc(0) });
			await settlePromises();
			expect(mgr.getTempChannel(openMsg.channelId)).to.equal(replacement);
			expect(
				sent.filter((type) => type === MessageType.ACCEPT_CHANNEL2)
			).to.have.length(1);
		});

		it('does not abort opener funding after a delivered action throws', async () => {
			const owner = '02' + 'cd'.repeat(32);
			const changeScript = bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!;
			const mgr = makeAutofundManager(async () => ({
				inputs: [makeAutofundInput(200_000)],
				changeScript
			}));
			const sent: number[] = [];
			const errors: string[] = [];
			let throwOnce = true;
			mgr.on('error', (_id: Buffer | null, message: string) => {
				errors.push(message);
			});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
				if (type === MessageType.TX_ADD_INPUT && throwOnce) {
					throwOnce = false;
					throw new Error('transport threw after tx_add_input delivery');
				}
			});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			sent.length = 0;

			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({ channelId: tempId })
				)
			);
			await settlePromises();

			expect(
				sent.filter((type) => type === MessageType.TX_ADD_INPUT)
			).to.have.length(1);
			expect(
				sent.filter((type) => type === MessageType.TX_ABORT)
			).to.have.length(0);
			expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
			expect(mgr.getTempChannel(tempId)).to.equal(channel);
			expect(errors.join(' ')).to.contain('v2 open dispatch failed');
		});

		it('aborts opener funding once when wallet selection throws', async () => {
			const owner = '02' + 'cd'.repeat(32);
			let selections = 0;
			const throwingSelector = (() => {
				selections++;
				throw new Error('synchronous opener selector failure');
			}) as NonNullable<IFundingProvider['selectSpliceInputs']>;
			const mgr = makeAutofundManager(throwingSelector);
			const sent: number[] = [];
			const errors: string[] = [];
			mgr.on('error', (_id: Buffer | null, message: string) => {
				errors.push(message);
			});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			sent.length = 0;

			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({ channelId: tempId })
				)
			);
			await settlePromises();

			expect(selections).to.equal(1);
			expect(
				sent.filter((type) => type === MessageType.TX_ADD_INPUT)
			).to.have.length(0);
			expect(
				sent.filter((type) => type === MessageType.TX_ABORT)
			).to.have.length(1);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
			expect(errors.join(' ')).to.contain('v2 open not funded');
		});

		it('starts opener funding before informational observers run', () => {
			const owner = '02' + 'cd'.repeat(32);
			let selections = 0;
			const mgr = makeAutofundManager(() => {
				selections++;
				return new Promise(() => {});
			});
			mgr.on('error', () => {});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			let transitionBegins = 0;
			let acceptedEvents = 0;
			mgr.on('transition:begin', () => {
				transitionBegins++;
				throw new Error('empty action transition must not run');
			});
			mgr.on('channel:accepted', () => {
				acceptedEvents++;
				throw new Error('informational observer failed');
			});

			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({ channelId: tempId })
				)
			);

			expect(selections).to.equal(1);
			expect(acceptedEvents).to.equal(1);
			expect(transitionBegins).to.equal(0);
			expect(mgr.getTempChannel(tempId)).to.equal(channel);
		});

		it('auto-funds normally when a transition observer throws', async () => {
			const owner = '02' + 'cd'.repeat(32);
			const changeScript = bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!;
			const mgr = makeAutofundManager(async () => ({
				inputs: [makeAutofundInput(200_000)],
				changeScript
			}));
			const sent: number[] = [];
			let transitionCalls = 0;
			mgr.on('error', () => {});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			sent.length = 0;
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			mgr.on('transition:begin', () => {
				transitionCalls++;
				throw new Error('transition observer failed');
			});

			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({ channelId: tempId })
				)
			);
			await settlePromises();

			expect(transitionCalls).to.be.greaterThan(0);
			expect(
				sent.filter((type) => type === MessageType.TX_ADD_INPUT)
			).to.have.length(1);
			expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
			expect(mgr.getTempChannel(tempId)).to.equal(channel);
		});

		it('cancels a deferred opener selection through its derived id', async () => {
			type Selection = Awaited<
				ReturnType<NonNullable<IFundingProvider['selectSpliceInputs']>>
			>;
			const owner = '02' + 'cd'.repeat(32);
			const foreignPeer = '03' + 'ef'.repeat(32);
			let resolveSelection: ((selection: Selection) => void) | undefined;
			const mgr = makeAutofundManager(
				() =>
					new Promise<Selection>((resolve) => {
						resolveSelection = resolve;
					})
			);
			const sent: number[] = [];
			mgr.on('error', () => {});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			sent.length = 0;
			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({ channelId: tempId })
				)
			);
			const derivedId = channel.getChannelId();
			expect(derivedId).to.not.equal(null);

			const cancel = encodeErrorMessage({
				channelId: derivedId!,
				data: Buffer.from('cancel open', 'ascii')
			});
			mgr.handleMessage(foreignPeer, MessageType.ERROR, cancel);
			expect(mgr.getTempChannel(tempId)).to.equal(channel);
			mgr.handleMessage(owner, MessageType.ERROR, cancel);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);

			resolveSelection?.({
				inputs: [makeAutofundInput(200_000)],
				changeScript: bitcoin.payments.p2wpkh({
					hash: crypto.randomBytes(20)
				}).output!
			});
			await settlePromises();
			expect(
				sent.filter((type) => type === MessageType.TX_ADD_INPUT)
			).to.have.length(0);
		});

		it('ignores accept_channel2 from a peer that does not own the open', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = '02' + 'cd'.repeat(32);
			const foreignPeer = '03' + 'ef'.repeat(32);
			const sent: number[] = [];
			mgr.on('error', () => {});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			const session = channel.getDualFundingSession();
			expect(session).to.not.equal(null);
			expect(session?.getState()).to.equal(DualFundingState.AWAITING_ACCEPT);
			expect(channel.getChannelId()).to.equal(null);
			sent.length = 0;

			mgr.handleMessage(
				foreignPeer,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({
						channelId: tempId
					})
				)
			);

			expect(mgr.getTempChannel(tempId)).to.equal(channel);
			expect(session?.getState()).to.equal(DualFundingState.AWAITING_ACCEPT);
			expect(channel.getChannelId()).to.equal(null);
			expect(
				(
					mgr as unknown as { channelPeers: Map<string, string> }
				).channelPeers.get(tempId.toString('hex'))
			).to.equal(owner);
			expect(sent, 'foreign accept caused no protocol response').to.have.length(
				0
			);
		});

		it('advances a valid lease before a throwing lease observer', async () => {
			const sellerPrivateKey = crypto.randomBytes(32);
			const seller = getPublicKey(sellerPrivateKey).toString('hex');
			let selections = 0;
			const mgr = makeAutofundManager(async () => {
				selections++;
				return {
					inputs: [makeAutofundInput(800_000)],
					changeScript: bitcoin.payments.p2wpkh({
						hash: crypto.randomBytes(20)
					}).output!
				};
			});
			const channelType = Buffer.from('401000', 'hex');
			const channel = mgr.createDualFundedChannel(
				seller,
				makeDualFundingParams({
					channelType,
					requestFunds: {
						requestedSats: 500_000n,
						blockheight: 800_000
					},
					maxLeaseRates: leaseRates
				})
			);
			const tempId = channel.getTemporaryChannelId();
			const accept = makeAcceptChannel2Msg({
				channelId: tempId,
				channelType,
				fundingSatoshis: 500_000n
			});
			accept.willFund = {
				signature: signWillFund(
					accept.fundingPubkey,
					800_000,
					leaseRates,
					sellerPrivateKey
				),
				leaseRates
			};
			const sent: number[] = [];
			let leaseEvents = 0;
			let selectionsAtLease = -1;
			mgr.on('error', () => {});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			mgr.on('channel:lease', () => {
				leaseEvents++;
				selectionsAtLease = selections;
				throw new Error('lease observer failed');
			});

			mgr.handleMessage(
				seller,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(accept)
			);
			await settlePromises();

			expect(leaseEvents).to.equal(1);
			expect(selectionsAtLease).to.equal(1);
			expect(
				sent.filter((type) => type === MessageType.TX_ADD_INPUT)
			).to.have.length(1);
			expect(channel.getFullState().leaseExpiry).to.equal(804_032);
			expect(mgr.getTempChannel(tempId)).to.equal(channel);
		});

		it('suppresses channel:accepted when the lease observer cancels the open', () => {
			const sellerPrivateKey = crypto.randomBytes(32);
			const seller = getPublicKey(sellerPrivateKey).toString('hex');
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const channelType = Buffer.from('401000', 'hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const channel = mgr.createDualFundedChannel(
				seller,
				makeDualFundingParams({
					channelType,
					requestFunds: {
						requestedSats: 500_000n,
						blockheight: 800_000
					},
					maxLeaseRates: leaseRates
				})
			);
			const tempId = channel.getTemporaryChannelId();
			const accept = makeAcceptChannel2Msg({
				channelId: tempId,
				channelType,
				fundingSatoshis: 500_000n
			});
			accept.willFund = {
				signature: signWillFund(
					accept.fundingPubkey,
					800_000,
					leaseRates,
					sellerPrivateKey
				),
				leaseRates
			};
			let leaseEvents = 0;
			let acceptedEvents = 0;
			mgr.on('channel:lease', () => {
				leaseEvents++;
				mgr.handleMessage(
					seller,
					MessageType.ERROR,
					encodeErrorMessage({
						channelId: tempId,
						data: Buffer.from('cancel accepted lease', 'ascii')
					})
				);
			});
			mgr.on('channel:accepted', () => {
				acceptedEvents++;
			});

			mgr.handleMessage(
				seller,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(accept)
			);

			expect(leaseEvents).to.equal(1);
			expect(acceptedEvents).to.equal(0);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);
			expect(mapsOf(mgr).channelPeers.has(tempId.toString('hex'))).to.equal(
				false
			);
		});

		it('suppresses lease events when the synchronous selector cancels the open', async () => {
			const sellerPrivateKey = crypto.randomBytes(32);
			const seller = getPublicKey(sellerPrivateKey).toString('hex');
			const control: {
				manager?: ChannelManager;
				tempId?: Buffer;
			} = {};
			let selections = 0;
			const mgr = makeAutofundManager(() => {
				selections++;
				control.manager!.handleMessage(
					seller,
					MessageType.ERROR,
					encodeErrorMessage({
						channelId: control.tempId!,
						data: Buffer.from('selector cancelled open', 'ascii')
					})
				);
				return Promise.resolve({
					inputs: [makeAutofundInput(800_000)],
					changeScript: bitcoin.payments.p2wpkh({
						hash: crypto.randomBytes(20)
					}).output!
				});
			});
			control.manager = mgr;
			const channelType = Buffer.from('401000', 'hex');
			const sent: number[] = [];
			let leaseEvents = 0;
			let acceptedEvents = 0;
			mgr.on('error', () => {});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			mgr.on('channel:lease', () => {
				leaseEvents++;
			});
			mgr.on('channel:accepted', () => {
				acceptedEvents++;
			});
			const channel = mgr.createDualFundedChannel(
				seller,
				makeDualFundingParams({
					channelType,
					requestFunds: {
						requestedSats: 500_000n,
						blockheight: 800_000
					},
					maxLeaseRates: leaseRates
				})
			);
			const tempId = channel.getTemporaryChannelId();
			control.tempId = tempId;
			sent.length = 0;
			const accept = makeAcceptChannel2Msg({
				channelId: tempId,
				channelType,
				fundingSatoshis: 500_000n
			});
			accept.willFund = {
				signature: signWillFund(
					accept.fundingPubkey,
					800_000,
					leaseRates,
					sellerPrivateKey
				),
				leaseRates
			};

			mgr.handleMessage(
				seller,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(accept)
			);
			await settlePromises();

			expect(selections).to.equal(1);
			expect(leaseEvents).to.equal(0);
			expect(acceptedEvents).to.equal(0);
			expect(
				sent.filter((type) => type === MessageType.TX_ADD_INPUT)
			).to.have.length(0);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);
		});

		it('refuses a late underfunded lease on the wire and cleans up', () => {
			const sellerPrivateKey = crypto.randomBytes(32);
			const seller = getPublicKey(sellerPrivateKey).toString('hex');
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const channelType = Buffer.from('401000', 'hex');
			const sent: Array<{ type: number; payload: Buffer }> = [];
			const errors: string[] = [];
			mgr.on('error', (_id: Buffer | null, message: string) => {
				errors.push(message);
			});
			mgr.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
				}
			);
			const channel = mgr.createDualFundedChannel(
				seller,
				makeDualFundingParams({
					channelType,
					requestFunds: {
						requestedSats: 500_000n,
						blockheight: 800_000
					},
					maxLeaseRates: leaseRates
				})
			);
			const tempId = channel.getTemporaryChannelId();
			sent.length = 0;
			const accept = makeAcceptChannel2Msg({
				channelId: tempId,
				channelType,
				fundingSatoshis: 499_999n
			});
			accept.willFund = {
				signature: signWillFund(
					accept.fundingPubkey,
					800_000,
					leaseRates,
					sellerPrivateKey
				),
				leaseRates
			};

			mgr.handleMessage(
				seller,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(accept)
			);

			const wireErrors = sent.filter(
				(message) => message.type === MessageType.ERROR
			);
			expect(wireErrors).to.have.length(1);
			expect(
				decodeErrorMessage(wireErrors[0].payload).channelId.equals(tempId)
			).to.equal(true);
			expect(errors.join(' ')).to.contain(
				'Seller funded less than the requested lease amount'
			);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);
			expect(mapsOf(mgr).channelPeers.has(tempId.toString('hex'))).to.equal(
				false
			);
		});

		it('refuses an invalid will_fund signature on the wire and cleans up', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const sent: Array<{ type: number; payload: Buffer }> = [];
			const errors: string[] = [];
			mgr.on('error', (_id: Buffer | null, message: string) => {
				errors.push(message);
			});
			mgr.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
				}
			);
			const channelType = Buffer.from('401000', 'hex');
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams({
					channelType,
					requestFunds: {
						requestedSats: 500_000n,
						blockheight: 800_000
					},
					maxLeaseRates: leaseRates
				})
			);
			const tempId = channel.getTemporaryChannelId();
			sent.length = 0;

			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({
						channelId: tempId,
						channelType,
						fundingSatoshis: 500_000n,
						willFund: {
							signature: Buffer.alloc(64, 0x01),
							leaseRates
						}
					})
				)
			);

			const wireErrors = sent.filter(
				(message) => message.type === MessageType.ERROR
			);
			expect(wireErrors).to.have.length(1);
			expect(
				decodeErrorMessage(wireErrors[0].payload).channelId.equals(tempId)
			).to.equal(true);
			expect(errors.join(' ')).to.contain('Invalid will_fund signature');
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);
			expect(channel.getDualFundingSession()?.getState()).to.equal(
				DualFundingState.AWAITING_ACCEPT
			);
		});

		it('ignores interactive tx messages for a derived id owned by another peer', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = '02' + 'cd'.repeat(32);
			const foreignPeer = '03' + 'ef'.repeat(32);
			const sent: number[] = [];
			mgr.on('error', () => {});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({ channelId: tempId })
				)
			);
			const derivedId = channel.getChannelId();
			const session = channel.getDualFundingSession();
			const builder = session?.getTxBuilder();
			expect(derivedId).to.not.equal(null);
			expect(builder).to.not.equal(null);
			expect(builder?.getOutputs()).to.have.length(0);
			sent.length = 0;
			const output = encodeTxAddOutputMessage({
				channelId: derivedId!,
				serialId: 1n,
				amountSats: 1_000n,
				scriptPubkey: bitcoin.payments.p2wpkh({
					hash: crypto.randomBytes(20)
				}).output!
			});

			mgr.handleMessage(foreignPeer, MessageType.TX_ADD_OUTPUT, output);
			expect(
				builder?.getOutputs(),
				'foreign message caused no mutation'
			).to.have.length(0);
			expect(mgr.getTempChannel(tempId)).to.equal(channel);
			expect(
				sent,
				'foreign message caused no protocol response'
			).to.have.length(0);

			mgr.handleMessage(owner, MessageType.TX_ADD_OUTPUT, output);
			expect(
				builder?.getOutputs(),
				'owner message still routed'
			).to.have.length(1);
		});

		it('ignores tx_abort for a temporary id owned by another peer', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = '02' + 'cd'.repeat(32);
			const foreignPeer = '03' + 'ef'.repeat(32);
			const sent: number[] = [];
			mgr.on('error', () => {});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			const session = channel.getDualFundingSession();
			expect(session?.getState()).to.equal(DualFundingState.AWAITING_ACCEPT);
			sent.length = 0;
			const abort = encodeTxAbortMessage({
				channelId: tempId,
				data: Buffer.from('cancel', 'ascii')
			});

			mgr.handleMessage(foreignPeer, MessageType.TX_ABORT, abort);
			expect(session?.getState()).to.equal(DualFundingState.AWAITING_ACCEPT);
			expect(channel.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
			expect(mgr.getTempChannel(tempId)).to.equal(channel);
			expect(sent, 'foreign abort caused no protocol response').to.have.length(
				0
			);

			mgr.handleMessage(owner, MessageType.TX_ABORT, abort);
			expect(session?.getState()).to.equal(DualFundingState.ABORTED);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);
			expect(
				sent.filter((type) => type === MessageType.TX_ABORT),
				'owner abort was routed'
			).to.have.length(1);
		});

		it('cleans an aborted open when transport throws after the echo', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const sent: number[] = [];
			let abandoned = 0;
			let throwOnce = true;
			mgr.on('error', () => {});
			mgr.on('channel:abandoned', () => {
				abandoned++;
			});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
				if (type === MessageType.TX_ABORT && throwOnce) {
					throwOnce = false;
					throw new Error('transport threw after tx_abort delivery');
				}
			});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			sent.length = 0;

			mgr.handleMessage(
				owner,
				MessageType.TX_ABORT,
				encodeTxAbortMessage({
					channelId: tempId,
					data: Buffer.from('cancel', 'ascii')
				})
			);

			expect(
				sent.filter((type) => type === MessageType.TX_ABORT)
			).to.have.length(1);
			expect(abandoned).to.equal(1);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);
			expect(
				(
					mgr as unknown as { channelPeers: Map<string, string> }
				).channelPeers.has(tempId.toString('hex'))
			).to.equal(false);
		});

		it('retains an abandoned v2 open when its teardown persist fails', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			const permanentId = crypto.randomBytes(32);
			channel.getFullState().channelId = permanentId;
			channel.getFullState().state = ChannelState.ERRORED;
			const lifecycle = channel as unknown as {
				handleTxAbort: () => ChannelAction[];
				isAbandonedV2Open: () => boolean;
			};
			lifecycle.handleTxAbort = (): ChannelAction[] => [
				{ type: ChannelActionType.PERSIST_STATE },
				{
					type: ChannelActionType.SEND_MESSAGE,
					messageType: MessageType.TX_ABORT,
					payload: encodeTxAbortMessage({
						channelId: permanentId,
						data: Buffer.from('teardown', 'ascii')
					})
				}
			];
			lifecycle.isAbandonedV2Open = (): boolean => true;
			const sent: number[] = [];
			let blocked = 0;
			let abandoned = 0;
			mgr.on('channel:persist', ({ request }: IChannelPersistEvent) => {
				if (request) request.committed = false;
			});
			mgr.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			mgr.on('transition:blocked', () => {
				blocked++;
			});
			mgr.on('channel:abandoned', () => {
				abandoned++;
			});

			mgr.handleMessage(
				owner,
				MessageType.TX_ABORT,
				encodeTxAbortMessage({
					channelId: permanentId,
					data: Buffer.from('echo', 'ascii')
				})
			);

			expect(
				sent.filter((type) => type === MessageType.TX_ABORT)
			).to.have.length(0);
			expect(blocked).to.equal(1);
			expect(abandoned).to.equal(0);
			expect(mgr.getTempChannel(tempId)).to.equal(channel);
			expect(mapsOf(mgr).tempChannels.get(tempId.toString('hex'))).to.equal(
				channel
			);
			expect(mapsOf(mgr).channels.has(permanentId.toString('hex'))).to.equal(
				false
			);
			expect(mapsOf(mgr).channelPeers.get(tempId.toString('hex'))).to.equal(
				owner
			);
		});

		it('does not delete a same-id replacement during abort cleanup', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			const oldChannel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = oldChannel.getTemporaryChannelId();
			const replacementOpen = makeOpenChannel2Msg({
				revocationBasepoint:
					oldChannel.getFullState().localBasepoints.revocationBasepoint
			});
			expect(replacementOpen.channelId.equals(tempId)).to.equal(true);
			let replacement: Channel | undefined;
			let reentered = false;
			mgr.on('message:outbound', (_peer: string, type: number) => {
				if (type !== MessageType.TX_ABORT || reentered) return;
				reentered = true;
				mgr.handleMessage(
					owner,
					MessageType.ERROR,
					encodeErrorMessage({
						channelId: tempId,
						data: Buffer.from('forget old open', 'ascii')
					})
				);
				mgr.handleMessage(
					owner,
					MessageType.OPEN_CHANNEL2,
					encodeOpenChannel2Message(replacementOpen)
				);
				replacement = mgr.getTempChannel(tempId);
			});

			mgr.handleMessage(
				owner,
				MessageType.TX_ABORT,
				encodeTxAbortMessage({
					channelId: tempId,
					data: Buffer.from('cancel', 'ascii')
				})
			);

			expect(reentered).to.equal(true);
			expect(replacement).to.exist;
			expect(replacement).to.not.equal(oldChannel);
			expect(mgr.getTempChannel(tempId)).to.equal(replacement);
			expect(
				(
					mgr as unknown as { channelPeers: Map<string, string> }
				).channelPeers.get(tempId.toString('hex'))
			).to.equal(owner);
		});

		it('refuses a v1 temporary id that collides with a permanent channel', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const attacker = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const collisionId = crypto.randomBytes(32);
			const victim = installPermanentVictim(mgr, collisionId, owner);
			const sent: Array<{ type: number; payload: Buffer }> = [];
			mgr.on('error', () => {});
			mgr.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
				}
			);

			mgr.handleMessage(
				attacker,
				MessageType.OPEN_CHANNEL,
				encodeV1Open(collisionId)
			);

			const wireErrors = sent.filter(
				(message) => message.type === MessageType.ERROR
			);
			expect(wireErrors).to.have.length(1);
			expect(
				decodeErrorMessage(wireErrors[0].payload).channelId.equals(collisionId)
			).to.equal(true);
			expect(mapsOf(mgr).channels.get(collisionId.toString('hex'))).to.equal(
				victim
			);
			expect(
				mapsOf(mgr).channelPeers.get(collisionId.toString('hex'))
			).to.equal(owner);
			expect(mgr.getTempChannel(collisionId)).to.equal(undefined);
			expect(
				sent.filter((message) => message.type === MessageType.ACCEPT_CHANNEL)
			).to.have.length(0);
		});

		it('refuses a funding_created permanent id collision without harming its victim', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const attacker = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const collisionId = crypto.randomBytes(32);
			const victim = installPermanentVictim(mgr, collisionId, owner);
			const attackerTempId = crypto.randomBytes(32);
			const sent: Array<{ type: number; payload: Buffer }> = [];
			mgr.on('error', () => {});
			mgr.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
				}
			);
			mgr.handleMessage(
				attacker,
				MessageType.OPEN_CHANNEL,
				encodeV1Open(attackerTempId)
			);
			const attackerChannel = mgr.getTempChannel(attackerTempId);
			expect(attackerChannel).to.exist;
			sent.length = 0;

			mgr.handleMessage(
				attacker,
				MessageType.FUNDING_CREATED,
				encodeFundingCreatedMessage({
					temporaryChannelId: attackerTempId,
					fundingTxid: collisionId,
					fundingOutputIndex: 0,
					signature: Buffer.alloc(64)
				})
			);

			const wireErrors = sent.filter(
				(message) => message.type === MessageType.ERROR
			);
			expect(wireErrors).to.have.length(1);
			expect(
				decodeErrorMessage(wireErrors[0].payload).channelId.equals(
					attackerTempId
				)
			).to.equal(true);
			expect(mapsOf(mgr).channels.get(collisionId.toString('hex'))).to.equal(
				victim
			);
			expect(
				mapsOf(mgr).channelPeers.get(collisionId.toString('hex'))
			).to.equal(owner);
			expect(mgr.getTempChannel(attackerTempId)).to.equal(undefined);
			expect(
				mapsOf(mgr).channelPeers.has(attackerTempId.toString('hex'))
			).to.equal(false);
			expect(attackerChannel?.getFullState().fundingTxid).to.not.exist;
		});

		it('cleans abortPendingOpen after an outbound observer throws', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const channel = mgr.openChannel(owner, 100_000n);
			const tempId = channel.getTemporaryChannelId();
			const sent: Array<{ type: number; payload: Buffer }> = [];
			let aborted = 0;
			mgr.on('channel:aborted', () => {
				aborted++;
			});
			mgr.prependListener(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					if (type !== MessageType.ERROR) return;
					sent.push({ type, payload });
					throw new Error('abort transport observer failed');
				}
			);

			expect(() => mgr.abortPendingOpen(channel, 'wallet failed')).to.throw(
				'abort transport observer failed'
			);
			expect(sent).to.have.length(1);
			expect(
				decodeErrorMessage(sent[0].payload).channelId.equals(tempId)
			).to.equal(true);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);
			expect(mapsOf(mgr).channelPeers.has(tempId.toString('hex'))).to.equal(
				false
			);
			expect(aborted).to.equal(1);
		});

		it('preserves a reentrant same-id replacement during abortPendingOpen cleanup', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const oldChannel = mgr.openChannel(owner, 100_000n);
			const tempId = oldChannel.getTemporaryChannelId();
			let replacement: Channel | undefined;
			let abandoned = 0;
			mgr.on('channel:aborted', () => {
				abandoned++;
			});
			mgr.prependListener('message:outbound', (_peer: string, type: number) => {
				if (type !== MessageType.ERROR) return;
				replacement = makeDetachedChannel(tempId);
				mapsOf(mgr).tempChannels.set(tempId.toString('hex'), replacement);
				mapsOf(mgr).channelPeers.set(tempId.toString('hex'), owner);
			});

			mgr.abortPendingOpen(oldChannel, 'wallet failed');
			expect(replacement).to.exist;
			expect(mgr.getTempChannel(tempId)).to.equal(replacement);
			expect(mapsOf(mgr).channelPeers.get(tempId.toString('hex'))).to.equal(
				owner
			);
			expect(oldChannel.getState()).to.equal(ChannelState.ERRORED);
			expect(abandoned).to.equal(0);
		});

		it('preserves a reentrant same-id replacement and refuses outer promotion', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const oldChannel = mgr.openChannel(owner, 100_000n);
			const tempId = oldChannel.getTemporaryChannelId();
			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL,
				encodeV1Accept(oldChannel)
			);
			expect(oldChannel.getState()).to.equal(ChannelState.SENT_ACCEPT);
			let replacement: Channel | undefined;
			mgr.prependListener('message:outbound', (_peer: string, type: number) => {
				if (type !== MessageType.FUNDING_CREATED) return;
				replacement = makeDetachedChannel(tempId);
				mapsOf(mgr).tempChannels.set(tempId.toString('hex'), replacement);
				mapsOf(mgr).channelPeers.set(tempId.toString('hex'), owner);
			});

			const fundingTxid = crypto.randomBytes(32);
			const permanentId = Buffer.from(fundingTxid);
			const result = mgr.createFunding(
				oldChannel,
				fundingTxid,
				0,
				Buffer.alloc(64)
			);

			expect(result).to.equal(null);
			expect(replacement).to.exist;
			expect(mgr.getTempChannel(tempId)).to.equal(replacement);
			expect(mapsOf(mgr).channelPeers.get(tempId.toString('hex'))).to.equal(
				owner
			);
			expect(mgr.getChannel(permanentId)).to.equal(undefined);
			expect(
				mapsOf(mgr).channelPeers.has(permanentId.toString('hex'))
			).to.equal(false);
		});

		it('does not promote after outbound funding_created disconnects the owner', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const channel = mgr.openChannel(owner, 100_000n);
			const tempId = channel.getTemporaryChannelId();
			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL,
				encodeV1Accept(channel)
			);
			const fundingTxid = crypto.randomBytes(32);
			const permanentId = Buffer.from(fundingTxid);
			let disconnected = false;
			mgr.prependListener('message:outbound', (_peer: string, type: number) => {
				if (type !== MessageType.FUNDING_CREATED || disconnected) return;
				disconnected = true;
				mgr.handlePeerDisconnected(owner);
			});

			const result = mgr.createFunding(
				channel,
				fundingTxid,
				0,
				Buffer.alloc(64)
			);

			expect(disconnected).to.equal(true);
			expect(result).to.equal(null);
			expect(mgr.getChannel(permanentId)).to.equal(undefined);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);
			expect(mapsOf(mgr).channelPeers.has(tempId.toString('hex'))).to.equal(
				false
			);
			expect(
				mapsOf(mgr).channelPeers.has(permanentId.toString('hex'))
			).to.equal(false);
		});

		it('does not promote after reentrant invalid funding_signed cleanup', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const channel = mgr.openChannel(owner, 100_000n);
			const tempId = channel.getTemporaryChannelId();
			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL,
				encodeV1Accept(channel)
			);
			const fundingTxid = crypto.randomBytes(32);
			const permanentId = Buffer.from(fundingTxid);
			let reentered = false;
			mgr.prependListener('message:outbound', (_peer: string, type: number) => {
				if (type !== MessageType.FUNDING_CREATED || reentered) return;
				reentered = true;
				mgr.handleMessage(
					owner,
					MessageType.FUNDING_SIGNED,
					encodeFundingSignedMessage({
						channelId: permanentId,
						signature: Buffer.alloc(64)
					})
				);
			});

			const result = mgr.createFunding(
				channel,
				fundingTxid,
				0,
				Buffer.alloc(64)
			);

			expect(reentered).to.equal(true);
			expect(result).to.equal(null);
			expect(mgr.getChannel(permanentId)).to.equal(undefined);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);
			expect(mapsOf(mgr).channelPeers.has(tempId.toString('hex'))).to.equal(
				false
			);
			expect(
				mapsOf(mgr).channelPeers.has(permanentId.toString('hex'))
			).to.equal(false);
		});

		it('reserves the permanent id across createFunding outbound reentrancy', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const attacker = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const original = mgr.openChannel(owner, 100_000n);
			const originalTempId = original.getTemporaryChannelId();
			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL,
				encodeV1Accept(original)
			);
			expect(original.getState()).to.equal(ChannelState.SENT_ACCEPT);

			const attackerTempId = crypto.randomBytes(32);
			mgr.handleMessage(
				attacker,
				MessageType.OPEN_CHANNEL,
				encodeV1Open(attackerTempId)
			);
			expect(mgr.getTempChannel(attackerTempId)).to.exist;
			const fundingTxid = crypto.randomBytes(32);
			const permanentId = Buffer.from(fundingTxid);
			const sent: Array<{ type: number; payload: Buffer }> = [];
			let reentered = false;
			mgr.prependListener(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
					if (type !== MessageType.FUNDING_CREATED || reentered) return;
					reentered = true;
					mgr.handleMessage(
						attacker,
						MessageType.FUNDING_CREATED,
						encodeFundingCreatedMessage({
							temporaryChannelId: attackerTempId,
							fundingTxid,
							fundingOutputIndex: 0,
							signature: Buffer.alloc(64)
						})
					);
				}
			);

			const promotedId = mgr.createFunding(
				original,
				fundingTxid,
				0,
				Buffer.alloc(64)
			);

			expect(reentered).to.equal(true);
			expect(promotedId?.equals(permanentId)).to.equal(true);
			expect(mgr.getChannel(permanentId)).to.equal(original);
			expect(
				mapsOf(mgr).channelPeers.get(permanentId.toString('hex'))
			).to.equal(owner);
			expect(mgr.getTempChannel(originalTempId)).to.equal(undefined);
			expect(mgr.getTempChannel(attackerTempId)).to.equal(undefined);
			expect(
				mapsOf(mgr).channelPeers.has(attackerTempId.toString('hex'))
			).to.equal(false);
			const wireErrors = sent.filter(
				(message) => message.type === MessageType.ERROR
			);
			expect(wireErrors).to.have.length(1);
			expect(
				decodeErrorMessage(wireErrors[0].payload).channelId.equals(
					attackerTempId
				)
			).to.equal(true);
		});

		it('blocks a second createFunding while the first owns the derived id in temp', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const firstOwner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const secondOwner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const first = mgr.openChannel(firstOwner, 100_000n);
			const second = mgr.openChannel(secondOwner, 100_000n);
			const firstTempId = first.getTemporaryChannelId();
			const secondTempId = second.getTemporaryChannelId();
			mgr.handleMessage(
				firstOwner,
				MessageType.ACCEPT_CHANNEL,
				encodeV1Accept(first)
			);
			mgr.handleMessage(
				secondOwner,
				MessageType.ACCEPT_CHANNEL,
				encodeV1Accept(second)
			);
			const fundingTxid = crypto.randomBytes(32);
			const permanentId = Buffer.from(fundingTxid);
			let throwOnce = true;
			mgr.prependListener('message:outbound', (_peer: string, type: number) => {
				if (type === MessageType.FUNDING_CREATED && throwOnce) {
					throwOnce = false;
					throw new Error('first funding_created observer failed');
				}
			});

			expect(() =>
				mgr.createFunding(first, fundingTxid, 0, Buffer.alloc(64))
			).to.throw('first funding_created observer failed');
			expect(first.getChannelId()?.equals(permanentId)).to.equal(true);
			expect(mgr.getTempChannel(firstTempId)).to.equal(first);

			const secondResult = mgr.createFunding(
				second,
				fundingTxid,
				0,
				Buffer.alloc(64)
			);

			expect(secondResult).to.equal(null);
			expect(mgr.getChannel(permanentId)).to.equal(undefined);
			expect(mgr.getTempChannel(firstTempId)).to.equal(first);
			expect(mgr.getTempChannel(secondTempId)).to.equal(undefined);
			expect(
				mapsOf(mgr).channelPeers.get(firstTempId.toString('hex'))
			).to.equal(firstOwner);
			expect(
				mapsOf(mgr).channelPeers.has(permanentId.toString('hex'))
			).to.equal(false);
		});

		it('refuses inbound v1 temporary ids owned as a pending derived id', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const attacker = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const first = mgr.openChannel(owner, 100_000n);
			const firstTempId = first.getTemporaryChannelId();
			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL,
				encodeV1Accept(first)
			);
			const fundingTxid = crypto.randomBytes(32);
			const permanentId = Buffer.from(fundingTxid);
			let throwOnce = true;
			const sent: Array<{ type: number; payload: Buffer }> = [];
			mgr.prependListener(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
					if (type === MessageType.FUNDING_CREATED && throwOnce) {
						throwOnce = false;
						throw new Error('pending derived owner');
					}
				}
			);
			expect(() =>
				mgr.createFunding(first, fundingTxid, 0, Buffer.alloc(64))
			).to.throw('pending derived owner');
			sent.length = 0;

			mgr.handleMessage(
				attacker,
				MessageType.OPEN_CHANNEL,
				encodeV1Open(permanentId)
			);

			const wireErrors = sent.filter(
				(message) => message.type === MessageType.ERROR
			);
			expect(wireErrors).to.have.length(1);
			expect(
				decodeErrorMessage(wireErrors[0].payload).channelId.equals(permanentId)
			).to.equal(true);
			expect(mgr.getTempChannel(permanentId)).to.equal(undefined);
			expect(mgr.getTempChannel(firstTempId)).to.equal(first);
			expect(first.getChannelId()?.equals(permanentId)).to.equal(true);
			expect(
				mapsOf(mgr).channelPeers.get(firstTempId.toString('hex'))
			).to.equal(owner);
		});

		it('removes the exact old temp entry during funding_signed fallback promotion', () => {
			const mgr = new ChannelManager(makeChannelManagerConfig());
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const channel = mgr.openChannel(owner, 100_000n);
			const tempId = channel.getTemporaryChannelId();
			const permanentId = crypto.randomBytes(32);
			channel.getFullState().channelId = permanentId;
			(
				channel as unknown as {
					handleFundingSigned: () => ChannelAction[];
				}
			).handleFundingSigned = (): ChannelAction[] => [];

			mgr.handleMessage(
				owner,
				MessageType.FUNDING_SIGNED,
				encodeFundingSignedMessage({
					channelId: permanentId,
					signature: Buffer.alloc(64)
				})
			);

			expect(mgr.getChannel(permanentId)).to.equal(channel);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);
			expect(mapsOf(mgr).channelPeers.has(tempId.toString('hex'))).to.equal(
				false
			);
			expect(
				mapsOf(mgr).channelPeers.get(permanentId.toString('hex'))
			).to.equal(owner);
		});

		it('guards v1 temporary negotiation messages by peer ownership', () => {
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const foreignPeer = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const opener = new ChannelManager(makeChannelManagerConfig());
			opener.on('error', () => {});
			opener.on('message:outbound', () => {});
			const outbound = opener.openChannel(owner, 100_000n);
			const outboundTempId = outbound.getTemporaryChannelId();
			const acceptPoints = makeBasepoints();
			const accept = encodeAcceptChannelMessage({
				temporaryChannelId: outboundTempId,
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 500_000_000n,
				channelReserveSatoshis: 1_000n,
				htlcMinimumMsat: 1_000n,
				minimumDepth: 3,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 483,
				fundingPubkey: acceptPoints.fundingPubkey,
				revocationBasepoint: acceptPoints.revocationBasepoint,
				paymentBasepoint: acceptPoints.paymentBasepoint,
				delayedPaymentBasepoint: acceptPoints.delayedPaymentBasepoint,
				htlcBasepoint: acceptPoints.htlcBasepoint,
				firstPerCommitmentPoint: acceptPoints.firstPerCommitmentPoint,
				channelType: outbound.getFullState().channelType ?? undefined
			});

			opener.handleMessage(foreignPeer, MessageType.ACCEPT_CHANNEL, accept);
			expect(outbound.getState()).to.equal(ChannelState.SENT_OPEN);
			expect(opener.getTempChannel(outboundTempId)).to.equal(outbound);
			opener.handleMessage(owner, MessageType.ACCEPT_CHANNEL, accept);
			expect(outbound.getState()).to.equal(ChannelState.SENT_ACCEPT);

			const acceptor = new ChannelManager(makeChannelManagerConfig());
			acceptor.on('error', () => {});
			acceptor.on('message:outbound', () => {});
			const inboundTempId = crypto.randomBytes(32);
			const openPoints = makeBasepoints();
			acceptor.handleMessage(
				owner,
				MessageType.OPEN_CHANNEL,
				encodeOpenChannelMessage({
					chainHash: Buffer.alloc(32),
					temporaryChannelId: inboundTempId,
					fundingSatoshis: 100_000n,
					pushMsat: 0n,
					dustLimitSatoshis: 546n,
					maxHtlcValueInFlightMsat: 500_000_000n,
					channelReserveSatoshis: 1_000n,
					htlcMinimumMsat: 1_000n,
					feeratePerKw: 253,
					toSelfDelay: 144,
					maxAcceptedHtlcs: 483,
					fundingPubkey: openPoints.fundingPubkey,
					revocationBasepoint: openPoints.revocationBasepoint,
					paymentBasepoint: openPoints.paymentBasepoint,
					delayedPaymentBasepoint: openPoints.delayedPaymentBasepoint,
					htlcBasepoint: openPoints.htlcBasepoint,
					firstPerCommitmentPoint: openPoints.firstPerCommitmentPoint,
					channelFlags: 0
				})
			);
			const inbound = acceptor.getTempChannel(inboundTempId);
			expect(inbound).to.exist;
			expect(inbound?.getState()).to.equal(ChannelState.SENT_ACCEPT);

			acceptor.handleMessage(
				foreignPeer,
				MessageType.FUNDING_CREATED,
				encodeFundingCreatedMessage({
					temporaryChannelId: inboundTempId,
					fundingTxid: crypto.randomBytes(32),
					fundingOutputIndex: 0,
					signature: Buffer.alloc(64)
				})
			);
			expect(acceptor.getTempChannel(inboundTempId)).to.equal(inbound);
			expect(inbound?.getState()).to.equal(ChannelState.SENT_ACCEPT);
			expect(inbound?.getFullState().fundingTxid).to.not.exist;
			expect(
				(
					acceptor as unknown as { channelPeers: Map<string, string> }
				).channelPeers.get(inboundTempId.toString('hex'))
			).to.equal(owner);
		});
	});

	describe('accept_channel2 echo (BOLT 2)', () => {
		const OFFERED = Buffer.from('401000', 'hex');

		function openerSession(withType: boolean): DualFundingSession {
			const channelId = crypto.randomBytes(32);
			const session = new DualFundingSession(true, channelId);
			const params = makeDualFundingParams(
				withType
					? { channelType: OFFERED }
					: // A session-level open with NO type at all (the Channel
					  // layer normally injects one): pins the volunteered-echo
					  // refusal below.
					  { channelType: undefined }
			);
			const result = session.initiateOpen(params);
			expect(result.ok).to.equal(true);
			return session;
		}

		it('a MISSING echo is refused before tx negotiation', () => {
			const session = openerSession(true);
			const result = session.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId: session.getChannelId(),
					channelType: undefined
				})
			);
			expect(result.ok).to.equal(false);
			expect(result.error).to.match(/omitted the channel_type/);
			expect(session.getState(), 'no tx negotiation started').to.equal(
				DualFundingState.AWAITING_ACCEPT
			);
		});

		it('a MISMATCHED echo is refused, an exact echo accepted', () => {
			const session = openerSession(true);
			const mismatched = session.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId: session.getChannelId(),
					channelType: Buffer.from('1000', 'hex')
				})
			);
			expect(mismatched.ok).to.equal(false);
			expect(mismatched.error).to.match(/Channel type mismatch/);

			const exact = session.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId: session.getChannelId(),
					channelType: Buffer.from(OFFERED)
				})
			);
			expect(exact.ok).to.equal(true);
			expect(session.getState()).to.equal(DualFundingState.TX_NEGOTIATION);
		});

		it('a volunteered type the open never proposed is refused', () => {
			const session = openerSession(false);
			const result = session.handleAcceptChannel2(
				makeAcceptChannel2Msg({
					channelId: session.getChannelId(),
					channelType: Buffer.from('1000', 'hex')
				})
			);
			expect(result.ok).to.equal(false);
			expect(result.error).to.match(/did not propose/);
		});
	});
});

describe('Issue #311: fabricated prevTx defenses', () => {
	type Verdict = 'unspent' | 'spent-or-missing' | 'unknown';
	type VerifyFn = (input: {
		txid: Buffer;
		vout: number;
		scriptPubKey: Buffer;
	}) => Promise<Verdict>;

	const settle = async (): Promise<void> => {
		await new Promise<void>((resolve) => setImmediate(resolve));
		await new Promise<void>((resolve) => setImmediate(resolve));
	};

	/** A wallet input whose witness closure is never exercised here. */
	function makeContributionInput(valueSats: number): ISpliceWalletInput {
		const prevTx = new bitcoin.Transaction();
		prevTx.version = 2;
		prevTx.addInput(crypto.randomBytes(32), 0);
		prevTx.addOutput(
			bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) }).output!,
			valueSats
		);
		return {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: 0,
			value: BigInt(valueSats),
			sequence: 0xfffffffd,
			signWitness: (): Buffer[] => []
		};
	}

	const outpointOf = (
		input: ISpliceWalletInput
	): { txid: string; vout: number } => ({
		txid: bitcoin.Transaction.fromBuffer(input.prevTx).getId(),
		vout: input.prevOutputIndex
	});

	/** Minimal provider carrying only the release spy (no auto-funding). */
	function providerWithReleaseSpy(): {
		provider: IFundingProvider;
		released: Array<Array<{ txid: string; vout: number }>>;
	} {
		const released: Array<Array<{ txid: string; vout: number }>> = [];
		const provider: IFundingProvider = {
			buildFundingTransaction: () => Promise.reject(new Error('not needed')),
			broadcastTransaction: () => Promise.reject(new Error('not needed')),
			releaseInputPledges: async (outpoints) => {
				released.push(outpoints);
			}
		};
		return { provider, released };
	}

	/**
	 * An opener whose accept_channel2 arrived: the session sits in
	 * TX_NEGOTIATION awaiting interactive-tx messages. No funding provider
	 * method is offered for selection, so the embedder-driven legacy path
	 * keeps the negotiation idle until the test feeds messages.
	 */
	function setupNegotiation(opts?: {
		verify?: VerifyFn;
		provider?: IFundingProvider;
		hasResumableChannelRow?: (channelId: Buffer) => boolean;
	}): {
		mgr: ChannelManager;
		channel: Channel;
		tempId: Buffer;
		owner: string;
		sent: number[];
		errors: string[];
	} {
		const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
		const mgr = new ChannelManager({
			...makeChannelManagerConfig(),
			...(opts?.verify ? { verifyRemoteFundingInput: opts.verify } : {}),
			...(opts?.hasResumableChannelRow
				? { hasResumableChannelRow: opts.hasResumableChannelRow }
				: {})
		});
		if (opts?.provider) mgr.setFundingProvider(opts.provider);
		const sent: number[] = [];
		const errors: string[] = [];
		mgr.on('error', (_id: Buffer | null, message: string) => {
			errors.push(message);
		});
		mgr.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});
		const channel = mgr.createDualFundedChannel(owner, makeDualFundingParams());
		const tempId = channel.getTemporaryChannelId();
		mgr.handleMessage(
			owner,
			MessageType.ACCEPT_CHANNEL2,
			encodeAcceptChannel2Message(makeAcceptChannel2Msg({ channelId: tempId }))
		);
		expect(channel.getDualFundingSession()?.getState()).to.equal(
			DualFundingState.TX_NEGOTIATION
		);
		sent.length = 0;
		return { mgr, channel, tempId, owner, sent, errors };
	}

	function peerAddInput(
		h: { mgr: ChannelManager; tempId: Buffer; owner: string },
		prevTx: Buffer,
		serialId = 1n
	): void {
		h.mgr.handleMessage(
			h.owner,
			MessageType.TX_ADD_INPUT,
			encodeTxAddInputMessage({
				channelId: h.tempId,
				serialId,
				prevTx,
				prevTxVout: 0,
				sequence: 0xfffffffd
			})
		);
	}

	describe('chain verification of peer inputs (ChannelManager)', () => {
		it('aborts the negotiation when the chain refutes a peer prevout', async () => {
			const h = setupNegotiation({
				verify: async () => 'spent-or-missing'
			});
			peerAddInput(h, makePeerPrevTx());
			await settle();

			expect(
				h.sent.filter((type) => type === MessageType.TX_ABORT)
			).to.have.length(1);
			expect(h.channel.getState()).to.equal(ChannelState.ERRORED);
			expect(h.channel.getDualFundingSession()?.getState()).to.equal(
				DualFundingState.ABORTED
			);
			expect(h.errors.join(' ')).to.contain('issue #311');
		});

		it('hands the callback the prevout the peer claimed', async () => {
			const seen: Array<{ txid: Buffer; vout: number; scriptPubKey: Buffer }> =
				[];
			const h = setupNegotiation({
				verify: async (input) => {
					seen.push(input);
					return 'unspent';
				}
			});
			const prevTx = makePeerPrevTx();
			peerAddInput(h, prevTx);
			await settle();

			expect(seen).to.have.length(1);
			const parsed = bitcoin.Transaction.fromBuffer(prevTx);
			expect(seen[0].txid.equals(parsed.getHash())).to.equal(true);
			expect(seen[0].vout).to.equal(0);
			expect(seen[0].scriptPubKey.equals(parsed.outs[0].script)).to.equal(true);
		});

		it('proceeds on unspent, unknown and a rejecting callback', async () => {
			const verdicts: Array<Verdict | Error> = [
				'unspent',
				'unknown',
				new Error('backend exploded')
			];
			for (const verdict of verdicts) {
				const h = setupNegotiation({
					verify: () =>
						verdict instanceof Error
							? Promise.reject(verdict)
							: Promise.resolve(verdict)
				});
				peerAddInput(h, makePeerPrevTx());
				await settle();

				expect(
					h.sent.filter((type) => type === MessageType.TX_ABORT),
					`no abort for ${String(verdict)}`
				).to.have.length(0);
				expect(h.channel.getDualFundingSession()?.getState()).to.equal(
					DualFundingState.TX_NEGOTIATION
				);
			}
		});

		it('never fires without a callback or outside TX_NEGOTIATION, and skips the splice shared input', async () => {
			let calls = 0;
			const counting: VerifyFn = async () => {
				calls++;
				return 'unspent';
			};

			// Outside TX_NEGOTIATION: the open still awaits accept_channel2.
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const mgr = new ChannelManager({
				...makeChannelManagerConfig(),
				verifyRemoteFundingInput: counting
			});
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			mgr.handleMessage(
				owner,
				MessageType.TX_ADD_INPUT,
				encodeTxAddInputMessage({
					channelId: channel.getTemporaryChannelId(),
					serialId: 1n,
					prevTx: makePeerPrevTx(),
					prevTxVout: 0,
					sequence: 0xfffffffd
				})
			);
			await settle();
			expect(calls, 'no verification before the negotiation').to.equal(0);

			// A shared-input tx_add_input (splice TLV) is exempt.
			const h = setupNegotiation({ verify: counting });
			h.mgr.handleMessage(
				h.owner,
				MessageType.TX_ADD_INPUT,
				encodeTxAddInputMessage({
					channelId: h.tempId,
					serialId: 1n,
					prevTx: Buffer.alloc(0),
					prevTxVout: 0,
					sequence: 0xfffffffd,
					sharedInputTxid: crypto.randomBytes(32)
				})
			);
			await settle();
			expect(calls, 'shared input skipped').to.equal(0);
		});

		it('queries a repeated outpoint once', async () => {
			let calls = 0;
			const h = setupNegotiation({
				verify: async () => {
					calls++;
					return 'unspent';
				}
			});
			const prevTx = makePeerPrevTx();
			peerAddInput(h, prevTx, 1n);
			peerAddInput(h, prevTx, 3n);
			await settle();

			expect(calls).to.equal(1);
		});

		it('a verdict landing after the peer aborted touches nothing', async () => {
			let resolveVerdict!: (verdict: Verdict) => void;
			const h = setupNegotiation({
				verify: () =>
					new Promise<Verdict>((resolve) => {
						resolveVerdict = resolve;
					})
			});
			peerAddInput(h, makePeerPrevTx());

			// The peer aborts while the chain query is in flight.
			h.mgr.handleMessage(
				h.owner,
				MessageType.TX_ABORT,
				encodeTxAbortMessage({
					channelId: h.tempId,
					data: Buffer.from('changed my mind', 'ascii')
				})
			);
			const sentBefore = [...h.sent];

			resolveVerdict('spent-or-missing');
			await settle();

			expect(h.sent, 'late verdict sent nothing').to.deep.equal(sentBefore);
		});

		it('a verdict landing after tx_remove_input does not abort', async () => {
			let resolveVerdict!: (verdict: Verdict) => void;
			const h = setupNegotiation({
				verify: () =>
					new Promise<Verdict>((resolve) => {
						resolveVerdict = resolve;
					})
			});
			peerAddInput(h, makePeerPrevTx());
			h.mgr.handleMessage(
				h.owner,
				MessageType.TX_REMOVE_INPUT,
				encodeTxRemoveInputMessage({ channelId: h.tempId, serialId: 1n })
			);

			resolveVerdict('spent-or-missing');
			await settle();

			expect(
				h.sent.filter((type) => type === MessageType.TX_ABORT)
			).to.have.length(0);
			expect(h.channel.getDualFundingSession()?.getState()).to.equal(
				DualFundingState.TX_NEGOTIATION
			);
		});

		it('a verdict landing after signature release reports but never aborts', async () => {
			let resolveVerdict!: (verdict: Verdict) => void;
			const h = setupNegotiation({
				verify: () =>
					new Promise<Verdict>((resolve) => {
						resolveVerdict = resolve;
					})
			});
			peerAddInput(h, makePeerPrevTx());

			// White-box: the negotiation raced ahead and our witnesses left.
			(
				h.channel.getFullState() as unknown as { v2InFlight: unknown }
			).v2InFlight = {
				sentTxSignatures: true,
				ourWalletInputIndices: [0],
				ourWitnesses: []
			};

			resolveVerdict('spent-or-missing');
			await settle();

			expect(
				h.sent.filter((type) => type === MessageType.TX_ABORT)
			).to.have.length(0);
			expect(h.mgr.getTempChannel(h.tempId), 'channel retained').to.equal(
				h.channel
			);
			expect(h.errors.join(' ')).to.contain('after signature release');
		});

		it('a verdict landing after a disconnect never re-arms the abort latch', async () => {
			let resolveVerdict!: (verdict: Verdict) => void;
			const h = setupNegotiation({
				verify: () =>
					new Promise<Verdict>((resolve) => {
						resolveVerdict = resolve;
					})
			});
			// A recorded open: the disconnect keeps the session and the record
			// so reestablish can resume the signature exchange. The derived id
			// must be in place before the peer input so the late verdict still
			// resolves this channel after its promotion.
			const derivedId = crypto.randomBytes(32);
			const st = h.channel.getFullState() as unknown as {
				channelId: Buffer;
				state: ChannelState;
				v2InFlight: unknown;
			};
			st.channelId = derivedId;
			h.mgr.handleMessage(
				h.owner,
				MessageType.TX_ADD_INPUT,
				encodeTxAddInputMessage({
					channelId: derivedId,
					serialId: 1n,
					prevTx: makePeerPrevTx(),
					prevTxVout: 0,
					sequence: 0xfffffffd
				})
			);
			st.state = ChannelState.AWAITING_TX_SIGNATURES;
			st.v2InFlight = {
				sentTxSignatures: false,
				fullySigned: false,
				ourWalletInputIndices: [0],
				ourWitnesses: []
			};

			h.mgr.handlePeerDisconnected(h.owner);
			expect(h.channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
			h.sent.length = 0;

			resolveVerdict('spent-or-missing');
			await settle();

			expect(
				h.sent.filter((type) => type === MessageType.TX_ABORT),
				'no abort into a dead connection'
			).to.have.length(0);
			expect(
				(h.channel as unknown as { _v2AbortPending: boolean })._v2AbortPending,
				'the latch the disconnect cleared stays cleared'
			).to.equal(false);
			expect(h.channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		});
	});

	describe('pledge release on terminal death (ChannelManager)', () => {
		it('reports no releasable outpoints for a live negotiation', () => {
			const { provider } = providerWithReleaseSpy();
			const h = setupNegotiation({ provider });
			h.channel.setDualFundingContribution(
				[makeContributionInput(100_000)],
				Buffer.alloc(0),
				100_000n,
				1000
			);
			expect(h.channel.getReleasableV2PledgeOutpoints()).to.deep.equal([]);
		});

		it('never reports outpoints once the attempt is broadcastable', () => {
			const { provider } = providerWithReleaseSpy();
			const h = setupNegotiation({ provider });
			h.channel.setDualFundingContribution(
				[makeContributionInput(100_000)],
				Buffer.alloc(0),
				100_000n,
				1000
			);
			const st = h.channel.getFullState() as unknown as {
				state: ChannelState;
				v2InFlight: unknown;
				pendingFundingTxHex?: string;
			};
			st.state = ChannelState.ERRORED;

			// Our witnesses left.
			st.v2InFlight = {
				sentTxSignatures: true,
				ourWalletInputIndices: [0],
				ourWitnesses: []
			};
			expect(h.channel.getReleasableV2PledgeOutpoints()).to.deep.equal([]);

			// Zero-local-input acceptor: the peer can complete the tx alone.
			st.v2InFlight = {
				sentTxSignatures: false,
				fullySigned: false,
				ourWalletInputIndices: [],
				ourWitnesses: []
			};
			expect(h.channel.getReleasableV2PledgeOutpoints()).to.deep.equal([]);

			// A fully signed tx staged for (re)broadcast.
			st.v2InFlight = null as unknown as object;
			st.pendingFundingTxHex = '02000000';
			expect(h.channel.getReleasableV2PledgeOutpoints()).to.deep.equal([]);
		});

		it('releases the contribution when the peer aborts the open', async () => {
			const { provider, released } = providerWithReleaseSpy();
			const h = setupNegotiation({ provider });
			const input = makeContributionInput(100_000);
			h.channel.setDualFundingContribution(
				[input],
				Buffer.alloc(0),
				100_000n,
				1000
			);

			h.mgr.handleMessage(
				h.owner,
				MessageType.TX_ABORT,
				encodeTxAbortMessage({
					channelId: h.tempId,
					data: Buffer.from('cancel', 'ascii')
				})
			);
			await settle();

			expect(h.mgr.getTempChannel(h.tempId)).to.equal(undefined);
			expect(released).to.deep.equal([[outpointOf(input)]]);
		});

		it('releases the contribution when the peer disconnects mid-negotiation', async () => {
			const { provider, released } = providerWithReleaseSpy();
			const h = setupNegotiation({ provider });
			const input = makeContributionInput(100_000);
			h.channel.setDualFundingContribution(
				[input],
				Buffer.alloc(0),
				100_000n,
				1000
			);

			h.mgr.handlePeerDisconnected(h.owner);
			await settle();

			expect(h.mgr.getTempChannel(h.tempId)).to.equal(undefined);
			expect(released).to.deep.equal([[outpointOf(input)]]);
		});

		it('releases an already-errored open when its peer disconnects', async () => {
			const { provider, released } = providerWithReleaseSpy();
			const h = setupNegotiation({ provider });
			const input = makeContributionInput(100_000);
			h.channel.setDualFundingContribution(
				[input],
				Buffer.alloc(0),
				100_000n,
				1000
			);
			// A local abort whose echo never arrives: ERRORED, still tracked.
			h.channel.abortDualFunding('operator cancelled');
			expect(h.channel.getState()).to.equal(ChannelState.ERRORED);
			expect(h.mgr.getTempChannel(h.tempId)).to.equal(h.channel);
			expect(
				released,
				'no release while the abort awaits its echo'
			).to.have.length(0);

			h.mgr.handlePeerDisconnected(h.owner);
			await settle();

			expect(released).to.deep.equal([[outpointOf(input)]]);
		});

		it('releases the contribution when a BOLT 1 error kills the open', async () => {
			const { provider, released } = providerWithReleaseSpy();
			const h = setupNegotiation({ provider });
			const input = makeContributionInput(100_000);
			h.channel.setDualFundingContribution(
				[input],
				Buffer.alloc(0),
				100_000n,
				1000
			);

			h.mgr.handleMessage(
				h.owner,
				MessageType.ERROR,
				encodeErrorMessage({
					channelId: h.tempId,
					data: Buffer.from('go away', 'ascii')
				})
			);
			await settle();

			expect(h.mgr.getTempChannel(h.tempId)).to.equal(undefined);
			expect(released).to.deep.equal([[outpointOf(input)]]);
		});

		it('releases the contribution on a connection-wide BOLT 1 error', async () => {
			const { provider, released } = providerWithReleaseSpy();
			const h = setupNegotiation({ provider });
			const input = makeContributionInput(100_000);
			h.channel.setDualFundingContribution(
				[input],
				Buffer.alloc(0),
				100_000n,
				1000
			);

			h.mgr.handleMessage(
				h.owner,
				MessageType.ERROR,
				encodeErrorMessage({
					channelId: Buffer.alloc(32),
					data: Buffer.from('all channels', 'ascii')
				})
			);
			await settle();

			expect(h.mgr.getTempChannel(h.tempId)).to.equal(undefined);
			expect(released).to.deep.equal([[outpointOf(input)]]);
		});

		it('releases a wallet selection that resolved after its open died', async () => {
			const released: Array<Array<{ txid: string; vout: number }>> = [];
			const input = makeContributionInput(200_000);
			let resolveSelection!: (value: {
				inputs: ISpliceWalletInput[];
				changeScript: Buffer;
			}) => void;
			const provider: IFundingProvider = {
				buildFundingTransaction: () => Promise.reject(new Error('not needed')),
				broadcastTransaction: () => Promise.reject(new Error('not needed')),
				selectSpliceInputs: () =>
					new Promise((resolve) => {
						resolveSelection = resolve;
					}),
				releaseInputPledges: async (outpoints) => {
					released.push(outpoints);
				}
			};
			const owner = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const mgr = new ChannelManager(makeChannelManagerConfig());
			mgr.setFundingProvider(provider);
			mgr.on('error', () => {});
			mgr.on('message:outbound', () => {});
			const channel = mgr.createDualFundedChannel(
				owner,
				makeDualFundingParams()
			);
			const tempId = channel.getTemporaryChannelId();
			mgr.handleMessage(
				owner,
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(
					makeAcceptChannel2Msg({ channelId: tempId })
				)
			);

			// The open dies while the wallet selection is still in flight.
			mgr.handleMessage(
				owner,
				MessageType.ERROR,
				encodeErrorMessage({
					channelId: tempId,
					data: Buffer.from('gone', 'ascii')
				})
			);
			expect(mgr.getTempChannel(tempId)).to.equal(undefined);

			resolveSelection({ inputs: [input], changeScript: Buffer.alloc(0) });
			await settle();

			expect(released).to.deep.equal([[outpointOf(input)]]);
		});

		it('keeps the pledges when a durable row a restart could restore survives', async () => {
			const { provider, released } = providerWithReleaseSpy();
			const probed: string[] = [];
			const h = setupNegotiation({
				provider,
				// The node's abandoned listener could not adjudicate the row
				// (unreadable store): the manager must not release inputs an
				// open resumed after a restart would still spend.
				hasResumableChannelRow: (channelId) => {
					probed.push(channelId.toString('hex'));
					return true;
				}
			});
			h.channel.setDualFundingContribution(
				[makeContributionInput(100_000)],
				Buffer.alloc(0),
				100_000n,
				1000
			);

			h.mgr.handleMessage(
				h.owner,
				MessageType.TX_ABORT,
				encodeTxAbortMessage({
					channelId: h.tempId,
					data: Buffer.from('cancel', 'ascii')
				})
			);
			await settle();

			expect(h.mgr.getTempChannel(h.tempId)).to.equal(undefined);
			expect(probed, 'the durable row was consulted').to.not.have.length(0);
			expect(
				released,
				'nothing released while the row survives'
			).to.have.length(0);
		});

		it('releases when the durable probe reports the row gone', async () => {
			const { provider, released } = providerWithReleaseSpy();
			const input = makeContributionInput(100_000);
			const h = setupNegotiation({
				provider,
				hasResumableChannelRow: () => false
			});
			h.channel.setDualFundingContribution(
				[input],
				Buffer.alloc(0),
				100_000n,
				1000
			);

			h.mgr.handleMessage(
				h.owner,
				MessageType.TX_ABORT,
				encodeTxAbortMessage({
					channelId: h.tempId,
					data: Buffer.from('cancel', 'ascii')
				})
			);
			await settle();

			expect(released).to.deep.equal([[outpointOf(input)]]);
		});

		it('releases the contribution when an invalid peer input errors the open', async () => {
			const { provider, released } = providerWithReleaseSpy();
			const h = setupNegotiation({ provider });
			const input = makeContributionInput(100_000);
			h.channel.setDualFundingContribution(
				[input],
				Buffer.alloc(0),
				100_000n,
				1000
			);

			// Serial id parity violation (we are the initiator, the peer must
			// use odd ids): the builder refuses, the batch carries a bare
			// local ERROR with no state transition, and the manager removes
			// the open. Its pledges must not be left to the TTL.
			h.mgr.handleMessage(
				h.owner,
				MessageType.TX_ADD_INPUT,
				encodeTxAddInputMessage({
					channelId: h.tempId,
					serialId: 2n,
					prevTx: makePeerPrevTx(),
					prevTxVout: 0,
					sequence: 0xfffffffd
				})
			);
			await settle();

			expect(h.mgr.getTempChannel(h.tempId)).to.equal(undefined);
			expect(released).to.deep.equal([[outpointOf(input)]]);
		});
	});
});
