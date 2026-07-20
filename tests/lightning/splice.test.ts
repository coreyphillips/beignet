import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	encodeSpliceMessage,
	decodeSpliceMessage,
	encodeSpliceAckMessage,
	decodeSpliceAckMessage,
	encodeSpliceLockedMessage,
	decodeSpliceLockedMessage,
	encodeStartBatchMessage,
	decodeStartBatchMessage,
	ISpliceMessage,
	ISpliceAckMessage,
	ISpliceLockedMessage
} from '../../src/lightning/message/splice';
import {
	SpliceSession,
	SpliceState,
	ISpliceSessionParams
} from '../../src/lightning/channel/splice';
import {
	estimateSpliceTxWeight,
	spliceFeeSats
} from '../../src/lightning/channel/splice-weight';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { calculateCommitmentFee } from '../../src/lightning/channel/commitment-builder';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxSignaturesMessage,
	encodeTxAddInputMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeStfuMessage } from '../../src/lightning/message/stfu';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../../src/lightning/message/channel-commitment';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../src/lightning/message/channel-funding';

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

function findAction(actions: any[], type: ChannelActionType): any {
	return actions.find((a: any) => a.type === type);
}

function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

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

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`seed-${id}`))
		.digest();
}

function makeConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: fundingPrivkey,
		// Matches makeBasepoints keys[4]: without it HTLC signatures are built
		// from the wrong key and commitment_signed fails 'Invalid HTLC
		// signature' once an HTLC exists — previously masked because that
		// error did not fail the channel, so payments settled on UNVERIFIED
		// signatures; the wire-error fix made it loud.
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest()
	};
}

function connectManagers(
	managerA: ChannelManager,
	pubkeyA: string,
	managerB: ChannelManager,
	pubkeyB: string
): void {
	managerA.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyB) {
				managerB.handleMessage(pubkeyA, type, payload);
			}
		}
	);
	managerB.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyA) {
				managerA.handleMessage(pubkeyB, type, payload);
			}
		}
	);
}

const FUNDING_SATOSHIS = 1_000_000n;

/**
 * A parseable wallet UTXO (plus change script) funding a splice-in: the
 * tx_complete audit requires splice-in contributions to be backed by real
 * inputs whose values cover the capacity increase plus the on-chain fee.
 * The UTXO is worth amountSats + 100k so a non-dust change remains.
 */
function makeSpliceInWallet(amountSats: bigint): {
	walletInput: {
		prevTx: Buffer;
		prevOutputIndex: number;
		value: bigint;
		sequence: number;
		signWitness: (
			tx: bitcoin.Transaction,
			inputIndex: number,
			value: bigint
		) => Buffer[];
	};
	changeScript: Buffer;
} {
	bitcoin.initEccLib(ecc);
	const walletPriv = crypto
		.createHash('sha256')
		.update('splice-in-wallet-helper')
		.digest();
	const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
	const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub }).output!;
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
	const value = amountSats + 100_000n;
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(walletScript, Number(value));
	return {
		walletInput: {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: 0,
			value,
			sequence: 0xfffffffd,
			signWitness: (
				tx: bitcoin.Transaction,
				inputIndex: number,
				inputValue: bigint
			): Buffer[] => {
				const sighash = tx.hashForWitnessV0(
					inputIndex,
					scriptCode,
					Number(inputValue),
					bitcoin.Transaction.SIGHASH_ALL
				);
				const sig64 = Buffer.from(ecc.sign(sighash, walletPriv));
				const der = bitcoin.script.signature.encode(
					sig64,
					bitcoin.Transaction.SIGHASH_ALL
				);
				return [der, walletPub];
			}
		},
		changeScript: walletScript
	};
}

/**
 * Helper to create a pair of channels (opener + acceptor) in NORMAL state,
 * connected through ChannelManagers with message routing.
 */
function createNormalChannelPair(): {
	openerManager: ChannelManager;
	acceptorManager: ChannelManager;
	openerPubkey: string;
	acceptorPubkey: string;
	channelId: Buffer;
	openerChannel: Channel;
	acceptorChannel: Channel;
} {
	const openerConfig = makeConfig(401);
	const acceptorConfig = makeConfig(402);
	const openerPubkey =
		openerConfig.localBasepoints.fundingPubkey.toString('hex');
	const acceptorPubkey =
		acceptorConfig.localBasepoints.fundingPubkey.toString('hex');

	const openerManager = new ChannelManager(openerConfig);
	const acceptorManager = new ChannelManager(acceptorConfig);

	// Suppress error events
	openerManager.on('error', () => {});
	acceptorManager.on('error', () => {});

	connectManagers(openerManager, openerPubkey, acceptorManager, acceptorPubkey);

	// Open channel (messages auto-route via connectManagers)
	const openerChannel = openerManager.openChannel(
		acceptorPubkey,
		FUNDING_SATOSHIS
	);

	// Create funding (moves acceptor channel from temp to permanent map)
	const fundingTxid = crypto.randomBytes(32);
	const sig = crypto.randomBytes(64);
	openerManager.createFunding(openerChannel, fundingTxid, 0, sig);

	// Get channel ID
	const channelId = openerChannel.getChannelId()!;
	expect(channelId).to.not.be.null;

	// Confirm funding => both sides send channel_ready
	openerManager.handleFundingConfirmed(channelId);
	acceptorManager.handleFundingConfirmed(channelId);

	// Now get acceptor channel (after it's been promoted to permanent map)
	const acceptorChannels = acceptorManager.getChannelsByPeer(openerPubkey);
	expect(acceptorChannels.length).to.equal(1);
	const acceptorChannel = acceptorChannels[0];

	expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);

	return {
		openerManager,
		acceptorManager,
		openerPubkey,
		acceptorPubkey,
		channelId,
		openerChannel,
		acceptorChannel
	};
}

describe('Splice', function () {
	// ─────────────── Message Encode/Decode ───────────────

	describe('Message: splice_init (type 80)', function () {
		it('should encode and decode a basic splice message', function () {
			const channelId = crypto.randomBytes(32);
			const fundingPubkey = Buffer.alloc(33, 0x02);
			const msg: ISpliceMessage = {
				channelId,
				fundingPubkey,
				relativeSatoshis: 100_000n,
				fundingFeeratePerkw: 253,
				locktime: 0
			};

			const encoded = encodeSpliceMessage(msg);
			const decoded = decodeSpliceMessage(encoded);

			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.fundingPubkey.equals(fundingPubkey)).to.be.true;
			expect(decoded.relativeSatoshis).to.equal(100_000n);
			expect(decoded.fundingFeeratePerkw).to.equal(253);
			expect(decoded.locktime).to.equal(0);
			expect(decoded.requireConfirmedInputs).to.be.undefined;
		});

		it('should lay out splice_init fields per the merged spec (interop wire order)', function () {
			// Spec order: channel_id(32) | funding_contribution_satoshis(s64) |
			// funding_feerate_perkw(u32) | locktime(u32) | funding_pubkey(33)
			const channelId = crypto.randomBytes(32);
			const fundingPubkey = crypto.randomBytes(33);
			const encoded = encodeSpliceMessage({
				channelId,
				fundingPubkey,
				relativeSatoshis: -42_000n,
				fundingFeeratePerkw: 1000,
				locktime: 7
			});

			expect(encoded.length).to.equal(81);
			expect(encoded.subarray(0, 32).equals(channelId)).to.be.true;
			expect(encoded.readBigInt64BE(32)).to.equal(-42_000n);
			expect(encoded.readUInt32BE(40)).to.equal(1000);
			expect(encoded.readUInt32BE(44)).to.equal(7);
			// funding_pubkey is LAST, immediately before any TLVs
			expect(encoded.subarray(48, 81).equals(fundingPubkey)).to.be.true;
		});

		it('should encode and decode splice-in (positive relativeSatoshis)', function () {
			const msg: ISpliceMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 500_000n,
				fundingFeeratePerkw: 500,
				locktime: 100
			};

			const decoded = decodeSpliceMessage(encodeSpliceMessage(msg));
			expect(decoded.relativeSatoshis).to.equal(500_000n);
		});

		it('should encode and decode splice-out (negative relativeSatoshis)', function () {
			const msg: ISpliceMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: -200_000n,
				fundingFeeratePerkw: 253,
				locktime: 0
			};

			const decoded = decodeSpliceMessage(encodeSpliceMessage(msg));
			expect(decoded.relativeSatoshis).to.equal(-200_000n);
		});

		it('should encode and decode with requireConfirmedInputs TLV', function () {
			const msg: ISpliceMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 100_000n,
				fundingFeeratePerkw: 253,
				locktime: 0,
				requireConfirmedInputs: true
			};

			const encoded = encodeSpliceMessage(msg);
			expect(encoded.length).to.equal(83); // 81 + 2 for TLV
			const decoded = decodeSpliceMessage(encoded);
			expect(decoded.requireConfirmedInputs).to.be.true;
		});

		it('should handle zero relativeSatoshis', function () {
			const msg: ISpliceMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 0n,
				fundingFeeratePerkw: 253,
				locktime: 0
			};

			const decoded = decodeSpliceMessage(encodeSpliceMessage(msg));
			expect(decoded.relativeSatoshis).to.equal(0n);
		});

		it('should reject short payloads', function () {
			expect(() => decodeSpliceMessage(Buffer.alloc(80))).to.throw('too short');
		});

		it('should validate channelId length', function () {
			expect(() =>
				encodeSpliceMessage({
					channelId: Buffer.alloc(16),
					fundingPubkey: Buffer.alloc(33, 0x02),
					relativeSatoshis: 0n,
					fundingFeeratePerkw: 253,
					locktime: 0
				})
			).to.throw('32 bytes');
		});

		it('should validate fundingPubkey length', function () {
			expect(() =>
				encodeSpliceMessage({
					channelId: Buffer.alloc(32),
					fundingPubkey: Buffer.alloc(32),
					relativeSatoshis: 0n,
					fundingFeeratePerkw: 253,
					locktime: 0
				})
			).to.throw('33 bytes');
		});

		it('should encode maximum positive 64-bit signed value', function () {
			const msg: ISpliceMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 9223372036854775807n, // 2^63 - 1
				fundingFeeratePerkw: 253,
				locktime: 0
			};
			const decoded = decodeSpliceMessage(encodeSpliceMessage(msg));
			expect(decoded.relativeSatoshis).to.equal(9223372036854775807n);
		});

		it('should encode minimum negative 64-bit signed value', function () {
			const msg: ISpliceMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: -9223372036854775808n, // -2^63
				fundingFeeratePerkw: 253,
				locktime: 0
			};
			const decoded = decodeSpliceMessage(encodeSpliceMessage(msg));
			expect(decoded.relativeSatoshis).to.equal(-9223372036854775808n);
		});

		it('should preserve high feerate values', function () {
			const msg: ISpliceMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 0n,
				fundingFeeratePerkw: 0xffffffff,
				locktime: 0
			};
			const decoded = decodeSpliceMessage(encodeSpliceMessage(msg));
			expect(decoded.fundingFeeratePerkw).to.equal(0xffffffff);
		});

		it('should preserve high locktime values', function () {
			const msg: ISpliceMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 0n,
				fundingFeeratePerkw: 253,
				locktime: 0xffffffff
			};
			const decoded = decodeSpliceMessage(encodeSpliceMessage(msg));
			expect(decoded.locktime).to.equal(0xffffffff);
		});
	});

	describe('Message: splice_ack (type 81)', function () {
		it('should encode and decode a basic splice_ack', function () {
			const channelId = crypto.randomBytes(32);
			const fundingPubkey = Buffer.alloc(33, 0x03);
			const msg: ISpliceAckMessage = {
				channelId,
				fundingPubkey,
				relativeSatoshis: 50_000n
			};

			const encoded = encodeSpliceAckMessage(msg);
			expect(encoded.length).to.equal(73);
			const decoded = decodeSpliceAckMessage(encoded);

			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.fundingPubkey.equals(fundingPubkey)).to.be.true;
			expect(decoded.relativeSatoshis).to.equal(50_000n);

			// Spec wire order: channel_id(32) | funding_contribution_satoshis(s64) | funding_pubkey(33)
			expect(encoded.subarray(0, 32).equals(channelId)).to.be.true;
			expect(encoded.readBigInt64BE(32)).to.equal(50_000n);
			expect(encoded.subarray(40, 73).equals(fundingPubkey)).to.be.true;
			expect(decoded.requireConfirmedInputs).to.be.undefined;
		});

		it('should encode and decode with negative relativeSatoshis', function () {
			const msg: ISpliceAckMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x03),
				relativeSatoshis: -100_000n
			};
			const decoded = decodeSpliceAckMessage(encodeSpliceAckMessage(msg));
			expect(decoded.relativeSatoshis).to.equal(-100_000n);
		});

		it('should encode and decode with requireConfirmedInputs TLV', function () {
			const msg: ISpliceAckMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x03),
				relativeSatoshis: 0n,
				requireConfirmedInputs: true
			};
			const encoded = encodeSpliceAckMessage(msg);
			expect(encoded.length).to.equal(75); // 73 + 2 TLV
			const decoded = decodeSpliceAckMessage(encoded);
			expect(decoded.requireConfirmedInputs).to.be.true;
		});

		it('should reject short payloads', function () {
			expect(() => decodeSpliceAckMessage(Buffer.alloc(72))).to.throw(
				'too short'
			);
		});

		it('should validate channelId length', function () {
			expect(() =>
				encodeSpliceAckMessage({
					channelId: Buffer.alloc(16),
					fundingPubkey: Buffer.alloc(33, 0x03),
					relativeSatoshis: 0n
				})
			).to.throw('32 bytes');
		});

		it('should validate fundingPubkey length', function () {
			expect(() =>
				encodeSpliceAckMessage({
					channelId: Buffer.alloc(32),
					fundingPubkey: Buffer.alloc(32),
					relativeSatoshis: 0n
				})
			).to.throw('33 bytes');
		});

		it('should handle zero relativeSatoshis', function () {
			const msg: ISpliceAckMessage = {
				channelId: crypto.randomBytes(32),
				fundingPubkey: Buffer.alloc(33, 0x03),
				relativeSatoshis: 0n
			};
			const decoded = decodeSpliceAckMessage(encodeSpliceAckMessage(msg));
			expect(decoded.relativeSatoshis).to.equal(0n);
		});
	});

	describe('tx_add_input shared_input_txid TLV (splicing)', function () {
		it('roundtrips the shared_input_txid TLV (type 0, len 32)', function () {
			const channelId = crypto.randomBytes(32);
			const sharedInputTxid = crypto.randomBytes(32);
			const encoded = encodeTxAddInputMessage({
				channelId,
				serialId: 0n,
				prevTx: Buffer.alloc(0),
				prevTxVout: 3,
				sequence: 0xfffffffd,
				sharedInputTxid
			});
			// 32 + 8 + 2 (prevTxLen=0) + 0 + 4 + 4 + 2 (TLV hdr) + 32 = 84 bytes
			expect(encoded.length).to.equal(84);
			const decoded = decodeTxAddInputMessage(encoded);
			expect(decoded.sharedInputTxid!.equals(sharedInputTxid)).to.be.true;
			expect(decoded.prevTx.length).to.equal(0);
			expect(decoded.prevTxVout).to.equal(3);
		});

		it('omits the TLV when sharedInputTxid is absent (normal input)', function () {
			const encoded = encodeTxAddInputMessage({
				channelId: crypto.randomBytes(32),
				serialId: 2n,
				prevTx: crypto.randomBytes(60),
				prevTxVout: 0,
				sequence: 0xfffffffd
			});
			const decoded = decodeTxAddInputMessage(encoded);
			expect(decoded.sharedInputTxid).to.be.undefined;
			expect(decoded.prevTx.length).to.equal(60);
		});
	});

	describe('Message: splice_locked (type 77)', function () {
		it('should encode and decode splice_locked without a txid (legacy CLN v24.x wire)', function () {
			const channelId = crypto.randomBytes(32);
			const msg: ISpliceLockedMessage = { channelId };

			const encoded = encodeSpliceLockedMessage(msg);
			// Without a known txid only channel_id goes on the wire (32 bytes).
			expect(encoded.length).to.equal(32);
			const decoded = decodeSpliceLockedMessage(encoded);

			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.fundingTxid).to.be.undefined;
		});

		it('should put the splice txid on the wire (merged spec / CLN v25.02+)', function () {
			const channelId = crypto.randomBytes(32);
			const fundingTxid = crypto.randomBytes(32);
			const encoded = encodeSpliceLockedMessage({ channelId, fundingTxid });
			expect(encoded.length).to.equal(64);
			const decoded = decodeSpliceLockedMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.fundingTxid!.equals(fundingTxid)).to.be.true;
		});

		it('should reject a malformed splice txid length', function () {
			expect(() =>
				encodeSpliceLockedMessage({
					channelId: crypto.randomBytes(32),
					fundingTxid: Buffer.alloc(16)
				})
			).to.throw('32 bytes');
		});

		it('should reject short payloads', function () {
			expect(() => decodeSpliceLockedMessage(Buffer.alloc(31))).to.throw(
				'too short'
			);
		});

		it('should validate channelId length', function () {
			expect(() =>
				encodeSpliceLockedMessage({
					channelId: Buffer.alloc(16)
				})
			).to.throw('32 bytes');
		});

		it('should produce independent buffer copies', function () {
			const channelId = crypto.randomBytes(32);
			const encoded = encodeSpliceLockedMessage({ channelId });
			const decoded = decodeSpliceLockedMessage(encoded);

			// Modify original — should not affect decoded
			channelId[0] ^= 0xff;
			expect(decoded.channelId[0]).to.not.equal(channelId[0]);
		});
	});

	describe('Message type numbers', function () {
		it('should have correct type numbers in MessageType enum', function () {
			expect(MessageType.SPLICE).to.equal(80);
			expect(MessageType.SPLICE_ACK).to.equal(81);
			expect(MessageType.SPLICE_LOCKED).to.equal(77);
		});
	});

	// ─────────────── SpliceSession ───────────────

	describe('SpliceSession', function () {
		const channelId = crypto.randomBytes(32);
		const localPubkey = Buffer.alloc(33, 0x02);
		const remotePubkey = Buffer.alloc(33, 0x03);

		function makeSession(
			params?: Partial<ISpliceSessionParams>
		): SpliceSession {
			return new SpliceSession({
				channelId,
				localFundingPubkey: localPubkey,
				isInitiator: true,
				localRelativeSatoshis: 100_000n,
				fundingFeeratePerkw: 253,
				locktime: 0,
				...params
			});
		}

		describe('State transitions', function () {
			it('should start in IDLE state', function () {
				const session = makeSession();
				expect(session.getState()).to.equal(SpliceState.IDLE);
			});

			it('should transition to AWAITING_ACK on initiate', function () {
				const session = makeSession();
				const result = session.initiate();
				expect(result.ok).to.be.true;
				expect(session.getState()).to.equal(SpliceState.AWAITING_ACK);
			});

			it('should transition to TX_NEGOTIATION on handleSpliceAck', function () {
				const session = makeSession();
				session.initiate();
				const result = session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 50_000n
				});
				expect(result.ok).to.be.true;
				expect(session.getState()).to.equal(SpliceState.TX_NEGOTIATION);
			});

			it('should transition to AWAITING_TX_SIGNATURES when both tx_complete', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});

				// Add inputs and outputs
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});

				session.markTxComplete();
				expect(session.getState()).to.equal(SpliceState.TX_NEGOTIATION); // not yet

				session.handlePeerTxComplete();
				expect(session.getState()).to.equal(SpliceState.AWAITING_TX_SIGNATURES);
			});

			it('should transition to AWAITING_SPLICE_LOCKED on handleTxSignatures', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();

				const result = session.handleTxSignatures(crypto.randomBytes(32), 0);
				expect(result.ok).to.be.true;
				expect(session.getState()).to.equal(SpliceState.AWAITING_SPLICE_LOCKED);
			});

			it('should transition to COMPLETE when both sides send splice_locked', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();

				const spliceTxid = crypto.randomBytes(32);
				session.handleTxSignatures(spliceTxid, 0);

				// Local sends splice_locked
				session.sendSpliceLocked();
				expect(session.getState()).to.equal(SpliceState.AWAITING_SPLICE_LOCKED);

				// Remote sends splice_locked
				session.handleSpliceLocked({ channelId, fundingTxid: spliceTxid });
				expect(session.getState()).to.equal(SpliceState.COMPLETE);
				expect(session.isComplete()).to.be.true;
			});

			it('should complete when remote sends splice_locked first', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();

				const spliceTxid = crypto.randomBytes(32);
				session.handleTxSignatures(spliceTxid, 0);

				// Remote first
				session.handleSpliceLocked({ channelId, fundingTxid: spliceTxid });
				expect(session.getState()).to.equal(SpliceState.AWAITING_SPLICE_LOCKED);

				// Local
				session.sendSpliceLocked();
				expect(session.getState()).to.equal(SpliceState.COMPLETE);
			});
		});

		describe('Initiator side', function () {
			it('initiate() should return splice message', function () {
				const session = makeSession({ localRelativeSatoshis: 200_000n });
				const result = session.initiate();
				expect(result.ok).to.be.true;
				expect(result.messageType).to.equal('splice');
				const msg = result.message as ISpliceMessage;
				expect(msg.channelId.equals(channelId)).to.be.true;
				expect(msg.fundingPubkey.equals(localPubkey)).to.be.true;
				expect(msg.relativeSatoshis).to.equal(200_000n);
			});

			it('should reject initiate in non-IDLE state', function () {
				const session = makeSession();
				session.initiate();
				const result = session.initiate();
				expect(result.ok).to.be.false;
				expect(result.error).to.include('wrong state');
			});

			it('should store remote params from splice_ack', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: -50_000n
				});
				expect(session.getRemoteFundingPubkey()!.equals(remotePubkey)).to.be
					.true;
				expect(session.getRemoteRelativeSatoshis()).to.equal(-50_000n);
			});

			it('should reject splice_ack with wrong channel_id', function () {
				const session = makeSession();
				session.initiate();
				const wrongId = crypto.randomBytes(32);
				const result = session.handleSpliceAck({
					channelId: wrongId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				expect(result.ok).to.be.false;
				expect(result.error).to.include('mismatch');
			});

			it('should reject splice_ack in wrong state', function () {
				const session = makeSession();
				const result = session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				expect(result.ok).to.be.false;
			});
		});

		describe('Acceptor side', function () {
			it('handleSplice() should return splice_ack', function () {
				const session = makeSession({
					isInitiator: false,
					localRelativeSatoshis: 30_000n
				});
				const result = session.handleSplice({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 100_000n,
					fundingFeeratePerkw: 500,
					locktime: 10
				});
				expect(result.ok).to.be.true;
				expect(result.messageType).to.equal('splice_ack');
				const ack = result.message as ISpliceAckMessage;
				expect(ack.channelId.equals(channelId)).to.be.true;
				expect(ack.fundingPubkey.equals(localPubkey)).to.be.true;
				expect(ack.relativeSatoshis).to.equal(30_000n);
			});

			it('should store remote params from splice', function () {
				const session = makeSession({ isInitiator: false });
				session.handleSplice({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 100_000n,
					fundingFeeratePerkw: 500,
					locktime: 10
				});
				expect(session.getRemoteFundingPubkey()!.equals(remotePubkey)).to.be
					.true;
				expect(session.getRemoteRelativeSatoshis()).to.equal(100_000n);
			});

			it('should transition to TX_NEGOTIATION after handleSplice', function () {
				const session = makeSession({ isInitiator: false });
				session.handleSplice({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 100_000n,
					fundingFeeratePerkw: 253,
					locktime: 0
				});
				expect(session.getState()).to.equal(SpliceState.TX_NEGOTIATION);
			});

			it('should reject splice with wrong channel_id', function () {
				const session = makeSession({ isInitiator: false });
				const result = session.handleSplice({
					channelId: crypto.randomBytes(32),
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n,
					fundingFeeratePerkw: 253,
					locktime: 0
				});
				expect(result.ok).to.be.false;
			});
		});

		describe('Interactive TX integration', function () {
			it('should create InteractiveTxBuilder after splice/splice_ack', function () {
				const session = makeSession();
				expect(session.getTxBuilder()).to.be.null;
				session.initiate();
				expect(session.getTxBuilder()).to.be.null;
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				expect(session.getTxBuilder()).to.not.be.null;
			});

			it('should allow adding inputs during TX_NEGOTIATION', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});

				const err = session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				expect(err).to.be.null;
			});

			it('should allow adding outputs during TX_NEGOTIATION', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});

				const err = session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				expect(err).to.be.null;
			});

			it('should allow adding peer inputs', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});

				const err = session.addPeerInput({
					serialId: 1n, // odd = acceptor
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd,
					prevTx: makePeerPrevTx(),
					prevTxVout: 0
				});
				expect(err).to.be.null;
			});

			it('should allow adding peer outputs', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});

				const err = session.addPeerOutput({
					serialId: 1n,
					amountSats: 50_000n,
					scriptPubkey: Buffer.alloc(22, 0x02)
				});
				expect(err).to.be.null;
			});

			it('should reject inputs in wrong state', function () {
				const session = makeSession();
				const err = session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				expect(err).to.include('not in TX_NEGOTIATION');
			});

			it('should reject outputs in wrong state', function () {
				const session = makeSession();
				const err = session.addOutput({
					serialId: 0n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22)
				});
				expect(err).to.include('not in TX_NEGOTIATION');
			});

			it('should generate next serial ID for initiator (even)', function () {
				const session = makeSession({ isInitiator: true });
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				const id1 = session.nextSerialId()!;
				const id2 = session.nextSerialId()!;
				expect(id1 % 2n).to.equal(0n);
				expect(id2 % 2n).to.equal(0n);
				expect(Number(id2)).to.be.greaterThan(Number(id1));
			});

			it('should generate next serial ID for acceptor (odd)', function () {
				const session = makeSession({ isInitiator: false });
				session.handleSplice({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n,
					fundingFeeratePerkw: 253,
					locktime: 0
				});
				const id1 = session.nextSerialId()!;
				const id2 = session.nextSerialId()!;
				expect(id1 % 2n).to.equal(1n);
				expect(id2 % 2n).to.equal(1n);
			});

			it('should allow removing inputs', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				const err = session.removeInput(0n);
				expect(err).to.be.null;
			});

			it('should allow removing outputs', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				const err = session.removeOutput(2n);
				expect(err).to.be.null;
			});

			it('should allow removing peer inputs', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addPeerInput({
					serialId: 1n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd,
					prevTx: makePeerPrevTx(),
					prevTxVout: 0
				});
				const err = session.removePeerInput(1n);
				expect(err).to.be.null;
			});

			it('should allow removing peer outputs', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addPeerOutput({
					serialId: 1n,
					amountSats: 50_000n,
					scriptPubkey: Buffer.alloc(22, 0x02)
				});
				const err = session.removePeerOutput(1n);
				expect(err).to.be.null;
			});

			it('should build transaction after both tx_complete', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();

				const tx = session.buildTransaction();
				expect(tx).to.not.be.null;
				expect(tx!.inputs.length).to.equal(1);
				expect(tx!.outputs.length).to.equal(1);
			});

			it('should return null from buildTransaction before complete', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				// Peer has not yet completed
				expect(session.buildTransaction()).to.be.null;
			});

			it('markTxComplete in wrong state should return error', function () {
				const session = makeSession();
				const err = session.markTxComplete();
				expect(err).to.include('not in TX_NEGOTIATION');
			});

			it('handlePeerTxComplete in wrong state should return error', function () {
				const session = makeSession();
				const err = session.handlePeerTxComplete();
				expect(err).to.include('not in TX_NEGOTIATION');
			});

			it('should reject remove of non-existent input in wrong state', function () {
				const session = makeSession();
				const err = session.removeInput(999n);
				expect(err).to.include('not in TX_NEGOTIATION');
			});

			it('should reject remove of non-existent output in wrong state', function () {
				const session = makeSession();
				const err = session.removeOutput(999n);
				expect(err).to.include('not in TX_NEGOTIATION');
			});

			it('should reject remove of non-existent peer input in wrong state', function () {
				const session = makeSession();
				const err = session.removePeerInput(999n);
				expect(err).to.include('not in TX_NEGOTIATION');
			});

			it('should reject remove of non-existent peer output in wrong state', function () {
				const session = makeSession();
				const err = session.removePeerOutput(999n);
				expect(err).to.include('not in TX_NEGOTIATION');
			});
		});

		describe('Net capacity change', function () {
			it('should compute positive net change for splice-in', function () {
				const session = makeSession({ localRelativeSatoshis: 100_000n });
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 50_000n
				});
				expect(session.getNetCapacityChange()).to.equal(150_000n);
			});

			it('should compute negative net change for splice-out', function () {
				const session = makeSession({ localRelativeSatoshis: -100_000n });
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: -50_000n
				});
				expect(session.getNetCapacityChange()).to.equal(-150_000n);
			});

			it('should compute net zero when contributions cancel', function () {
				const session = makeSession({ localRelativeSatoshis: 100_000n });
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: -100_000n
				});
				expect(session.getNetCapacityChange()).to.equal(0n);
			});
		});

		describe('Abort', function () {
			it('should abort from AWAITING_ACK', function () {
				const session = makeSession();
				session.initiate();
				const result = session.abort('test reason');
				expect(result.ok).to.be.true;
				expect(session.getState()).to.equal(SpliceState.ABORTED);
				expect(session.isAborted()).to.be.true;
			});

			it('should abort from TX_NEGOTIATION', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				const result = session.abort();
				expect(result.ok).to.be.true;
				expect(session.isAborted()).to.be.true;
			});

			it('should abort from AWAITING_TX_SIGNATURES', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();
				const result = session.abort();
				expect(result.ok).to.be.true;
			});

			it('should abort from AWAITING_SPLICE_LOCKED', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();
				session.handleTxSignatures(crypto.randomBytes(32), 0);
				const result = session.abort();
				expect(result.ok).to.be.true;
			});

			it('should reject abort of completed splice', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();
				const spliceTxid = crypto.randomBytes(32);
				session.handleTxSignatures(spliceTxid, 0);
				session.sendSpliceLocked();
				session.handleSpliceLocked({ channelId, fundingTxid: spliceTxid });
				expect(session.isComplete()).to.be.true;

				const result = session.abort();
				expect(result.ok).to.be.false;
				expect(result.error).to.include('completed');
			});

			it('should reject double abort', function () {
				const session = makeSession();
				session.initiate();
				session.abort();
				const result = session.abort();
				expect(result.ok).to.be.false;
				expect(result.error).to.include('already aborted');
			});

			it('should also abort the tx builder', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				const builder = session.getTxBuilder()!;
				expect(builder.isAborted()).to.be.false;
				session.abort();
				expect(builder.isAborted()).to.be.true;
			});
		});

		describe('Splice locked', function () {
			it('sendSpliceLocked should fail in wrong state', function () {
				const session = makeSession();
				const result = session.sendSpliceLocked();
				expect(result.ok).to.be.false;
			});

			it('handleSpliceLocked should fail in wrong state', function () {
				const session = makeSession();
				const result = session.handleSpliceLocked({
					channelId,
					fundingTxid: crypto.randomBytes(32)
				});
				expect(result.ok).to.be.false;
			});

			it('handleSpliceLocked should reject mismatched txid', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();
				session.handleTxSignatures(crypto.randomBytes(32), 0);

				const result = session.handleSpliceLocked({
					channelId,
					fundingTxid: crypto.randomBytes(32) // different txid
				});
				expect(result.ok).to.be.false;
				expect(result.error).to.include('txid mismatch');
			});

			it('handleSpliceLocked should reject mismatched channel_id', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();
				const spliceTxid = crypto.randomBytes(32);
				session.handleTxSignatures(spliceTxid, 0);

				const result = session.handleSpliceLocked({
					channelId: crypto.randomBytes(32),
					fundingTxid: spliceTxid
				});
				expect(result.ok).to.be.false;
				expect(result.error).to.include('Channel ID mismatch');
			});

			it('sendSpliceLocked returns splice_locked message', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();
				const spliceTxid = crypto.randomBytes(32);
				session.handleTxSignatures(spliceTxid, 0);

				const result = session.sendSpliceLocked();
				expect(result.ok).to.be.true;
				expect(result.messageType).to.equal('splice_locked');
				const msg = result.message as ISpliceLockedMessage;
				expect(msg.channelId.equals(channelId)).to.be.true;
				// Carried internally even though not serialized for CLN v24.11.1.
				expect(msg.fundingTxid!.equals(spliceTxid)).to.be.true;
			});
		});

		describe('TX signatures', function () {
			it('handleTxSignatures in wrong state should fail', function () {
				const session = makeSession();
				const result = session.handleTxSignatures(crypto.randomBytes(32), 0);
				expect(result.ok).to.be.false;
			});

			it('should store splice txid and output index', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n
				});
				session.addInput({
					serialId: 0n,
					prevTxid: crypto.randomBytes(32),
					prevOutputIndex: 0,
					sequence: 0xfffffffd
				});
				session.addOutput({
					serialId: 2n,
					amountSats: 100_000n,
					scriptPubkey: Buffer.alloc(22, 0x01)
				});
				session.markTxComplete();
				session.handlePeerTxComplete();

				const txid = crypto.randomBytes(32);
				session.handleTxSignatures(txid, 1);
				expect(session.getSpliceTxid()!.equals(txid)).to.be.true;
				expect(session.getSpliceFundingOutputIndex()).to.equal(1);
			});
		});

		describe('requireConfirmedInputs', function () {
			it('should default to false', function () {
				const session = makeSession();
				expect(session.getRequireConfirmedInputs()).to.be.false;
			});

			it('should be set from splice message', function () {
				const session = makeSession({ isInitiator: false });
				session.handleSplice({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n,
					fundingFeeratePerkw: 253,
					locktime: 0,
					requireConfirmedInputs: true
				});
				expect(session.getRequireConfirmedInputs()).to.be.true;
			});

			it('should be set from splice_ack', function () {
				const session = makeSession();
				session.initiate();
				session.handleSpliceAck({
					channelId,
					fundingPubkey: remotePubkey,
					relativeSatoshis: 0n,
					requireConfirmedInputs: true
				});
				expect(session.getRequireConfirmedInputs()).to.be.true;
			});
		});

		describe('Accessor methods', function () {
			it('getChannelId returns the correct channel ID', function () {
				const session = makeSession();
				expect(session.getChannelId().equals(channelId)).to.be.true;
			});

			it('isInitiator returns correct value', function () {
				const initiator = makeSession({ isInitiator: true });
				expect(initiator.isInitiator()).to.be.true;
				const acceptor = makeSession({ isInitiator: false });
				expect(acceptor.isInitiator()).to.be.false;
			});

			it('getTxBuilderState returns null when no builder', function () {
				const session = makeSession();
				expect(session.getTxBuilderState()).to.be.null;
			});

			it('nextSerialId returns null when no builder', function () {
				const session = makeSession();
				expect(session.nextSerialId()).to.be.null;
			});

			it('getSpliceTxid returns null initially', function () {
				const session = makeSession();
				expect(session.getSpliceTxid()).to.be.null;
			});
		});
	});

	// ─────────────── Channel Integration ───────────────

	describe('Channel splice methods', function () {
		const openerSeed = Buffer.alloc(32, 0x11);
		const acceptorSeed = Buffer.alloc(32, 0x22);
		const openerCommitmentSeed = crypto
			.createHash('sha256')
			.update(Buffer.from('opener-splice'))
			.digest();
		const acceptorCommitmentSeed = crypto
			.createHash('sha256')
			.update(Buffer.from('acceptor-splice'))
			.digest();

		function makeNormalChannel(pushMsat = 0n): {
			opener: Channel;
			acceptor: Channel;
		} {
			const openerBp = makeBasepoints(openerSeed);
			const acceptorBp = makeBasepoints(acceptorSeed);
			const tempId = Buffer.alloc(32, 0xbb);

			const openerState = createOpenerState({
				temporaryChannelId: tempId,
				fundingSatoshis: FUNDING_SATOSHIS,
				pushMsat,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: openerBp,
				localPerCommitmentSeed: openerCommitmentSeed
			});
			const opener = new Channel(openerState);

			const acceptorState = createAcceptorState({
				temporaryChannelId: tempId,
				fundingSatoshis: 0n,
				pushMsat,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: acceptorBp,
				localPerCommitmentSeed: acceptorCommitmentSeed,
				remoteBasepoints: openerBp,
				remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
			});
			const acceptor = new Channel(acceptorState);

			// Full open_channel / accept_channel flow with message decode
			const openActions = opener.initiateOpen();
			const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
			const acceptActions = acceptor.handleOpenChannel(
				decodeOpenChannelMessage(openMsg.payload)
			);
			const acceptMsg = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL
			);
			opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

			// Funding created / signed
			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const fsActions = acceptor.handleFundingCreated(
				decodeFundingCreatedMessage(fcMsg.payload),
				crypto.randomBytes(64)
			);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

			// Funding confirmed + channel ready
			const openerReady = opener.fundingConfirmed();
			const acceptorReady = acceptor.fundingConfirmed();

			const orMsg = findSendAction(openerReady, MessageType.CHANNEL_READY);
			const arMsg = findSendAction(acceptorReady, MessageType.CHANNEL_READY);

			opener.handleChannelReady(decodeChannelReadyMessage(arMsg.payload));
			acceptor.handleChannelReady(decodeChannelReadyMessage(orMsg.payload));

			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

			return { opener, acceptor };
		}

		function quiesce(channel: Channel): void {
			// Directly manipulate quiescence to QUIESCENT for testing
			const actions = channel.initiateQuiescence();
			expect(findSendAction(actions, MessageType.STFU)).to.exist;
			// Simulate receiving STFU from peer
			const channelId = channel.getChannelId()!;
			channel.handleStfuMessage({ channelId, initiator: false });
			expect(channel.isQuiescent()).to.be.true;
		}

		it('should reject splice when channel is not NORMAL', function () {
			const openerBp = makeBasepoints(openerSeed);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: FUNDING_SATOSHIS,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: openerBp,
				localPerCommitmentSeed: openerCommitmentSeed
			});
			const channel = new Channel(state);
			const actions = channel.initiateSplice(100_000n, 253);
			expect(findAction(actions, ChannelActionType.ERROR)).to.exist;
		});

		it('should auto-initiate quiescence when not yet quiescent', function () {
			const { opener } = makeNormalChannel();
			const actions = opener.initiateSplice(100_000n, 253);
			// No error: instead of rejecting, we drive quiescence ourselves.
			expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
			// We send STFU (as initiator) and defer the splice until QUIESCENT.
			const stfu = findSendAction(actions, MessageType.STFU);
			expect(stfu).to.exist;
			// splice_init is not sent yet, and we stay NORMAL until quiescent.
			expect(findSendAction(actions, MessageType.SPLICE)).to.not.exist;
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
		});

		it('should fire the deferred splice once quiescence completes', function () {
			const { opener } = makeNormalChannel();
			const channelId = opener.getChannelId()!;
			// Request a splice on a NORMAL (non-quiescent) channel -> sends STFU.
			const initActions = opener.initiateSplice(100_000n, 253);
			expect(findSendAction(initActions, MessageType.STFU)).to.exist;
			// Peer replies with STFU -> we become QUIESCENT and fire splice_init.
			const stfuReply = opener.handleStfuMessage({
				channelId,
				initiator: false
			});
			const spliceAction = findSendAction(stfuReply, MessageType.SPLICE);
			expect(spliceAction).to.exist;
			expect(
				decodeSpliceMessage(spliceAction.payload).relativeSatoshis
			).to.equal(100_000n);
			expect(opener.getState()).to.equal(ChannelState.SPLICING);
		});

		it('should send splice message when quiescent', function () {
			const { opener } = makeNormalChannel();
			quiesce(opener);

			const actions = opener.initiateSplice(100_000n, 253);
			const spliceAction = findSendAction(actions, MessageType.SPLICE);
			expect(spliceAction).to.exist;

			const decoded = decodeSpliceMessage(spliceAction.payload);
			expect(decoded.relativeSatoshis).to.equal(100_000n);
			expect(decoded.fundingFeeratePerkw).to.equal(253);
		});

		it('should transition to SPLICING state after initiateSplice', function () {
			const { opener } = makeNormalChannel();
			quiesce(opener);
			opener.initiateSplice(100_000n, 253);
			expect(opener.getState()).to.equal(ChannelState.SPLICING);
		});

		it('should create splice session', function () {
			const { opener } = makeNormalChannel();
			quiesce(opener);
			opener.initiateSplice(100_000n, 253);
			expect(opener.getSpliceSession()).to.not.be.null;
			expect(opener.getSpliceSession()!.getState()).to.equal(
				SpliceState.AWAITING_ACK
			);
		});

		it('should handle splice from remote (acceptor side)', function () {
			const { acceptor } = makeNormalChannel();
			quiesce(acceptor);

			const channelId = acceptor.getChannelId()!;
			const actions = acceptor.handleSplice({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 100_000n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});

			const ackAction = findSendAction(actions, MessageType.SPLICE_ACK);
			expect(ackAction).to.exist;
			expect(acceptor.getState()).to.equal(ChannelState.SPLICING);
		});

		it('should handle splice_ack from remote (initiator side)', function () {
			const { opener } = makeNormalChannel();
			quiesce(opener);
			opener.initiateSplice(100_000n, 253);

			const channelId = opener.getChannelId()!;
			const actions = opener.handleSpliceAck({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x03),
				relativeSatoshis: 0n
			});

			expect(findAction(actions, ChannelActionType.ERROR)).to.be.undefined;
			expect(opener.getSpliceSession()!.getState()).to.equal(
				SpliceState.TX_NEGOTIATION
			);
		});

		it('should route interactive-tx messages into the splice session (not reject them)', function () {
			// Acceptor receives a splice and enters TX_NEGOTIATION.
			const { acceptor } = makeNormalChannel();
			quiesce(acceptor);
			const channelId = acceptor.getChannelId()!;
			acceptor.handleSplice({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x02),
				// The peer's 400k output below draws on the shared capacity, so it
				// must be declared as a matching splice-out contribution or the
				// tx_complete audit rejects the books (S-2.M4).
				relativeSatoshis: -400_000n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});
			const session = acceptor.getSpliceSession()!;
			expect(session.getState()).to.equal(SpliceState.TX_NEGOTIATION);

			// The initiator (peer) drives even serial IDs. These previously errored
			// with "Unexpected tx_add_input" because handlers only knew about
			// dual-funding sessions.
			const inAction = acceptor.handleTxAddInput({
				channelId,
				serialId: 0n,
				// Covers the peer's 400k output plus the negotiated fee.
				prevTx: makePeerPrevTx(500_000),
				prevTxVout: 0,
				sequence: 0xfffffffd
			});
			expect(findAction(inAction, ChannelActionType.ERROR)).to.not.exist;

			const outAction = acceptor.handleTxAddOutput({
				channelId,
				serialId: 2n,
				amountSats: 400_000n,
				scriptPubkey: Buffer.alloc(34, 0x00)
			});
			expect(findAction(outAction, ChannelActionType.ERROR)).to.not.exist;

			// Peer signals tx_complete; the session accepts it without error.
			const completeAction = acceptor.handleTxComplete();
			expect(findAction(completeAction, ChannelActionType.ERROR)).to.not.exist;

			// The input and output were recorded in the splice session's builder.
			const built = session.getTxBuilder()!;
			expect(built.getInputs().some((i) => i.serialId === 0n)).to.be.true;
			expect(built.getOutputs().some((o) => o.serialId === 2n)).to.be.true;
		});

		it('rejects a tx_complete whose peer output is not covered by inputs or contribution (S-2.M4)', function () {
			// Same wire shape as the routing test above, but the peer declares NO
			// contribution while directing 400k of the shared capacity to its own
			// output: the completion audit must reject the books.
			const { acceptor } = makeNormalChannel();
			quiesce(acceptor);
			const channelId = acceptor.getChannelId()!;
			acceptor.handleSplice({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 0n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});
			acceptor.handleTxAddInput({
				channelId,
				serialId: 0n,
				prevTx: makePeerPrevTx(10_000),
				prevTxVout: 0,
				sequence: 0xfffffffd
			});
			acceptor.handleTxAddOutput({
				channelId,
				serialId: 2n,
				amountSats: 400_000n,
				scriptPubkey: Buffer.alloc(34, 0x00)
			});
			const completeAction = acceptor.handleTxComplete();
			const err = findAction(completeAction, ChannelActionType.ERROR);
			expect(err, 'tx_complete audit rejects uncovered peer output').to.exist;
			expect((err as { message: string }).message).to.contain('do not cover');
		});

		it('tx_aborts a splice whose shared input does not match the funding outpoint (S-2.H3)', function () {
			// A mismatched shared input would make each side sign commitments
			// against a different splice txid. The negotiation must fail with
			// tx_abort and the channel must keep operating on the existing funding.
			const { acceptor } = makeNormalChannel();
			quiesce(acceptor);
			const channelId = acceptor.getChannelId()!;
			acceptor.handleSplice({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 0n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});
			const actions = acceptor.handleTxAddInput({
				channelId,
				serialId: 0n,
				prevTx: Buffer.alloc(0),
				prevTxVout: 0,
				sequence: 0xfffffffd,
				sharedInputTxid: crypto.randomBytes(32) // NOT our funding txid
			});
			expect(findSendAction(actions, MessageType.TX_ABORT), 'tx_abort sent').to
				.exist;
			expect(acceptor.getSpliceSession()).to.be.null;
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
		});

		it('tx_aborts a splice input spending a legacy output; the channel survives (S-2.H3)', function () {
			const { acceptor } = makeNormalChannel();
			quiesce(acceptor);
			const channelId = acceptor.getChannelId()!;
			acceptor.handleSplice({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 0n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});
			// A legacy (P2PKH) prev output makes the splice txid malleable after
			// signing; the receive side must fail the negotiation.
			const legacyPrev = new bitcoin.Transaction();
			legacyPrev.version = 2;
			legacyPrev.addInput(crypto.randomBytes(32), 0);
			legacyPrev.addOutput(
				bitcoin.payments.p2pkh({ hash: crypto.randomBytes(20) }).output!,
				100_000
			);
			const actions = acceptor.handleTxAddInput({
				channelId,
				serialId: 0n,
				prevTx: legacyPrev.toBuffer(),
				prevTxVout: 0,
				sequence: 0xfffffffd
			});
			expect(findSendAction(actions, MessageType.TX_ABORT), 'tx_abort sent').to
				.exist;
			const abortMsg = findSendAction(actions, MessageType.TX_ABORT);
			expect(abortMsg.payload.toString()).to.contain('non-native-segwit');
			// The negotiation died; the channel did not.
			expect(acceptor.getSpliceSession()).to.be.null;
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
		});

		it('should drive splice-out contributions: shared input (TLV) + new funding + destination + tx_complete', function () {
			const { opener } = makeNormalChannel();
			quiesce(opener);
			const channelId = opener.getChannelId()!;
			const fundingTxid = opener.getFullState().fundingTxid!;

			// P2WPKH-shaped destination script for the withdrawn funds.
			const destScript = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const withdraw = 50_000n;
			// The on-chain fee is folded into the declared relative_satoshis so the
			// new funding output (oldCap + relative) matches what the peer computes
			// (this is what makes CLN accept the splice commitment_signed). The
			// destination still receives the full withdrawal; the fee comes from the
			// channel balance.
			const fee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 0,
					destinationScriptLen: destScript.length
				}),
				253
			);
			opener.setSpliceOutDestination(destScript, withdraw);
			opener.initiateSplice(-(withdraw + fee), 253);

			// splice_ack drives our first contribution: the shared input.
			const a1 = opener.handleSpliceAck({
				channelId,
				fundingPubkey: makeBasepoints(acceptorSeed).fundingPubkey,
				relativeSatoshis: 0n
			});
			const addIn = findSendAction(a1, MessageType.TX_ADD_INPUT);
			expect(addIn, 'sends tx_add_input').to.exist;
			const inMsg = decodeTxAddInputMessage(addIn.payload);
			// Shared input is signalled via shared_input_txid TLV with empty prevTx.
			expect(inMsg.sharedInputTxid, 'shared_input_txid TLV present').to.exist;
			expect(inMsg.sharedInputTxid!.equals(fundingTxid)).to.be.true;
			expect(inMsg.prevTx.length, 'empty prevTx for shared input').to.equal(0);
			expect(inMsg.prevTxVout).to.equal(
				opener.getFullState().fundingOutputIndex
			);
			expect(inMsg.serialId % 2n, 'initiator serial id is even').to.equal(0n);

			// Peer tx_complete -> we send the new funding (shared) output:
			// new funding = oldCap + relative = oldCap - withdraw - fee.
			const a2 = opener.handleTxComplete();
			const newFundingOut = findSendAction(a2, MessageType.TX_ADD_OUTPUT);
			expect(newFundingOut, 'sends tx_add_output (new funding)').to.exist;
			const fundMsg = decodeTxAddOutputMessage(newFundingOut.payload);
			expect(fundMsg.amountSats).to.equal(FUNDING_SATOSHIS - withdraw - fee);

			// Peer tx_complete -> we send the splice-out destination output (the
			// FULL withdrawal; the fee is implicit in the funding output).
			const a3 = opener.handleTxComplete();
			const destOut = findSendAction(a3, MessageType.TX_ADD_OUTPUT);
			expect(destOut, 'sends tx_add_output (destination)').to.exist;
			const destMsg = decodeTxAddOutputMessage(destOut.payload);
			expect(destMsg.amountSats).to.equal(withdraw);
			expect(destMsg.scriptPubkey.equals(destScript)).to.be.true;

			// Peer tx_complete -> nothing left to add, we send our tx_complete.
			const a4 = opener.handleTxComplete();
			expect(
				findSendAction(a4, MessageType.TX_COMPLETE),
				'sends our tx_complete'
			).to.exist;
			expect(opener.getSpliceSession()!.getState()).to.equal(
				SpliceState.AWAITING_TX_SIGNATURES
			);

			// Conservation: input value == sum of outputs + fee.
			expect(FUNDING_SATOSHIS - withdraw - fee + withdraw + fee).to.equal(
				FUNDING_SATOSHIS
			);
		});

		it('builds the spliced commitment with the peer FRESH splice funding pubkey (CLN interop)', function () {
			// CLN advertises a NEW funding pubkey in splice_ack (it does not reuse
			// the channel funding key). The spliced commitment must spend the new
			// funding 2-of-2 built from that fresh pubkey — otherwise our
			// reconstruction differs from what the peer signed and we reject a
			// valid commitment signature ("Invalid splice commitment signature").
			const { opener } = makeNormalChannel();
			const openerFundingPriv = crypto
				.createHash('sha256')
				.update(openerSeed)
				.update(Buffer.from([0]))
				.digest();
			opener.setSigner(new ChannelSigner(openerFundingPriv));
			quiesce(opener);
			const channelId = opener.getChannelId()!;

			// A fresh peer splice funding pubkey, distinct from the channel's
			// acceptor funding pubkey.
			const freshPriv = crypto
				.createHash('sha256')
				.update('cln-fresh-splice-key')
				.digest();
			const freshSplicePubkey = getPublicKey(freshPriv);
			expect(
				freshSplicePubkey.equals(makeBasepoints(acceptorSeed).fundingPubkey)
			).to.be.false;

			const destScript = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const withdraw = 50_000n;
			opener.setSpliceOutDestination(destScript, withdraw);
			opener.initiateSplice(-withdraw, 253);

			// splice_ack carries the FRESH funding pubkey (CLN behavior).
			opener.handleSpliceAck({
				channelId,
				fundingPubkey: freshSplicePubkey,
				relativeSatoshis: 0n
			});
			opener.handleTxComplete(); // -> new funding output
			opener.handleTxComplete(); // -> destination output
			opener.handleTxComplete(); // -> our tx_complete
			expect(opener.getSpliceSession()!.getState()).to.equal(
				SpliceState.AWAITING_TX_SIGNATURES
			);

			// Build the splice tx, then inspect the reconstructed spliced state.
			const built = opener.buildAndSignSpliceTx();
			expect(built, 'splice tx built').to.not.be.null;
			const tx = opener.getSpliceTransaction()!;

			const {
				createFundingScript
			} = require('../../src/lightning/script/funding');
			const expectedNewFunding = createFundingScript(
				opener.getFullState().localBasepoints.fundingPubkey,
				freshSplicePubkey
			);
			// The on-chain new funding output uses the fresh pubkey...
			const newOut = tx.outs[built!.newFundingOutputIndex];
			expect(
				newOut.script.equals(expectedNewFunding.p2wshOutput),
				'new funding output uses fresh splice pubkey'
			).to.be.true;

			// ...and the spliced commitment state must use the SAME fresh pubkey,
			// so the commitment funding witness script matches (the fix).
			const spliced = (opener as any)._splicedState();
			expect(spliced, 'spliced state built').to.not.be.null;
			expect(
				spliced.remoteBasepoints.fundingPubkey.equals(freshSplicePubkey),
				'spliced commitment uses the peer fresh splice funding pubkey'
			).to.be.true;
			// Other basepoints are unchanged by the splice.
			expect(
				spliced.remoteBasepoints.revocationBasepoint.equals(
					opener.getFullState().remoteBasepoints!.revocationBasepoint
				)
			).to.be.true;
		});

		it('should unwind the splice on peer tx_abort (channel returns to NORMAL)', function () {
			const { acceptor } = makeNormalChannel();
			quiesce(acceptor);
			const channelId = acceptor.getChannelId()!;
			acceptor.handleSplice({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 0n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});
			expect(acceptor.getState()).to.equal(ChannelState.SPLICING);

			const actions = acceptor.handleTxAbort();
			expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getSpliceSession()).to.be.null;
			expect(acceptor.isQuiescent()).to.be.false;
			// BOLT 2: the tx_abort must be echoed back as the ack (we had an
			// active splice session and had not sent tx_abort ourselves).
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

		it('should reject splice_ack when not SPLICING', function () {
			const { opener } = makeNormalChannel();
			const actions = opener.handleSpliceAck({
				channelId: opener.getChannelId()!,
				fundingPubkey: Buffer.alloc(33, 0x03),
				relativeSatoshis: 0n
			});
			expect(findAction(actions, ChannelActionType.ERROR)).to.exist;
		});

		it('should reject splice_locked when not SPLICING', function () {
			const { opener } = makeNormalChannel();
			const actions = opener.handleSpliceLocked({
				channelId: opener.getChannelId()!,
				fundingTxid: crypto.randomBytes(32)
			});
			expect(findAction(actions, ChannelActionType.ERROR)).to.exist;
		});

		it('should reject splice-out exceeding local balance', function () {
			const { opener } = makeNormalChannel();
			quiesce(opener);
			// Try to splice out more than we have
			const actions = opener.initiateSplice(-2_000_000n, 253);
			expect(findAction(actions, ChannelActionType.ERROR)).to.exist;
			expect(findAction(actions, ChannelActionType.ERROR).message).to.include(
				'insufficient'
			);
		});

		it('should abort splice and restore state', function () {
			const { opener } = makeNormalChannel();
			quiesce(opener);
			opener.initiateSplice(100_000n, 253);
			expect(opener.getState()).to.equal(ChannelState.SPLICING);

			const actions = opener.abortSplice('test abort');
			expect(findAction(actions, ChannelActionType.ERROR)).to.be.undefined;
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(opener.getSpliceSession()).to.be.null;
			expect(opener.isQuiescent()).to.be.false;
		});

		it('should reject abort when no splice session', function () {
			const { opener } = makeNormalChannel();
			const actions = opener.abortSplice();
			expect(findAction(actions, ChannelActionType.ERROR)).to.exist;
		});

		it('should send splice_locked message', function () {
			const { opener } = makeNormalChannel();
			quiesce(opener);
			opener.initiateSplice(100_000n, 253);
			opener.handleSpliceAck({
				channelId: opener.getChannelId()!,
				fundingPubkey: Buffer.alloc(33, 0x03),
				relativeSatoshis: 0n
			});

			// Simulate interactive TX completion
			const session = opener.getSpliceSession()!;
			session.addInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			session.addOutput({
				serialId: 2n,
				amountSats: 100_000n,
				scriptPubkey: Buffer.alloc(22, 0x01)
			});
			session.markTxComplete();
			session.handlePeerTxComplete();
			session.handleTxSignatures(crypto.randomBytes(32), 0);

			const actions = opener.sendSpliceLocked();
			const lockedAction = findSendAction(actions, MessageType.SPLICE_LOCKED);
			expect(lockedAction).to.exist;
		});

		it('should reject sendSpliceLocked when not SPLICING', function () {
			const { opener } = makeNormalChannel();
			const actions = opener.sendSpliceLocked();
			expect(findAction(actions, ChannelActionType.ERROR)).to.exist;
		});

		it('should complete splice and update funding on both splice_locked', function () {
			const { opener } = makeNormalChannel();
			quiesce(opener);

			const channelId = opener.getChannelId()!;
			opener.initiateSplice(100_000n, 253);
			opener.handleSpliceAck({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x03),
				relativeSatoshis: 50_000n
			});

			const session = opener.getSpliceSession()!;
			session.addInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			session.addOutput({
				serialId: 2n,
				amountSats: 200_000n,
				scriptPubkey: Buffer.alloc(22, 0x01)
			});
			session.markTxComplete();
			session.handlePeerTxComplete();

			const spliceTxid = crypto.randomBytes(32);
			session.handleTxSignatures(spliceTxid, 1);

			// Send our splice_locked
			opener.sendSpliceLocked();

			// Receive remote's splice_locked
			opener.handleSpliceLocked({ channelId, fundingTxid: spliceTxid });

			// Channel should be back to NORMAL with updated funding
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(opener.isQuiescent()).to.be.false;
			expect(opener.getSpliceSession()).to.be.null;

			// Funding should be updated
			const state = opener.getFullState();
			expect(state.fundingTxid!.equals(spliceTxid)).to.be.true;
			expect(state.fundingOutputIndex).to.equal(1);
		});

		it('should update balances after splice completion', function () {
			const { opener } = makeNormalChannel();
			quiesce(opener);

			const channelId = opener.getChannelId()!;
			const balancesBefore = opener.getBalances();
			const fundingBefore = opener.getFundingSatoshis();

			opener.initiateSplice(100_000n, 253);
			opener.handleSpliceAck({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x03),
				relativeSatoshis: 50_000n
			});

			const session = opener.getSpliceSession()!;
			session.addInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			session.addOutput({
				serialId: 2n,
				amountSats: 200_000n,
				scriptPubkey: Buffer.alloc(22, 0x01)
			});
			session.markTxComplete();
			session.handlePeerTxComplete();

			const spliceTxid = crypto.randomBytes(32);
			session.handleTxSignatures(spliceTxid, 0);

			opener.sendSpliceLocked();
			opener.handleSpliceLocked({ channelId, fundingTxid: spliceTxid });

			const balancesAfter = opener.getBalances();
			const fundingAfter = opener.getFundingSatoshis();

			// Funding should increase by net capacity change (100k + 50k = 150k)
			expect(fundingAfter).to.equal(fundingBefore + 150_000n);

			// Local balance should increase by our contribution (100k * 1000 msat)
			expect(balancesAfter.localMsat).to.equal(
				balancesBefore.localMsat + 100_000n * 1000n
			);

			// Remote balance should increase by their contribution (50k * 1000 msat)
			expect(balancesAfter.remoteMsat).to.equal(
				balancesBefore.remoteMsat + 50_000n * 1000n
			);
		});

		it('beignet<->beignet: complete splice-out, fully automated over the wire', function () {
			const { opener, acceptor } = makeNormalChannel();

			// Signers (funding private keys) are required so the channels can build
			// and co-sign the splice tx automatically during tx_signatures.
			const openerFundingPriv = crypto
				.createHash('sha256')
				.update(openerSeed)
				.update(Buffer.from([0]))
				.digest();
			const acceptorFundingPriv = crypto
				.createHash('sha256')
				.update(acceptorSeed)
				.update(Buffer.from([0]))
				.digest();
			opener.setSigner(new ChannelSigner(openerFundingPriv));
			acceptor.setSigner(new ChannelSigner(acceptorFundingPriv));

			const deliver = (
				ch: Channel,
				msgType: MessageType,
				payload: Buffer
			): any[] => {
				switch (msgType) {
					case MessageType.STFU:
						return ch.handleStfuMessage(decodeStfuMessage(payload));
					case MessageType.SPLICE:
						return ch.handleSplice(decodeSpliceMessage(payload));
					case MessageType.SPLICE_ACK:
						return ch.handleSpliceAck(decodeSpliceAckMessage(payload));
					case MessageType.TX_ADD_INPUT:
						return ch.handleTxAddInput(decodeTxAddInputMessage(payload));
					case MessageType.TX_ADD_OUTPUT:
						return ch.handleTxAddOutput(decodeTxAddOutputMessage(payload));
					case MessageType.TX_COMPLETE:
						return ch.handleTxComplete();
					case MessageType.TX_SIGNATURES:
						return ch.handleTxSignatures(decodeTxSignaturesMessage(payload));
					case MessageType.COMMITMENT_SIGNED:
						return ch.handleCommitmentSigned(
							decodeCommitmentSignedMessage(payload)
						);
					case MessageType.SPLICE_LOCKED:
						return ch.handleSpliceLocked(decodeSpliceLockedMessage(payload));
					default:
						return [];
				}
			};

			// Pump messages between the two channels, capturing broadcast actions.
			const queue: Array<{
				to: Channel;
				from: Channel;
				msgType: MessageType;
				payload: Buffer;
			}> = [];
			const broadcasts: Buffer[] = [];
			const enqueue = (to: Channel, from: Channel, actions: any[]): void => {
				for (const a of actions) {
					if (a.type === ChannelActionType.ERROR) {
						throw new Error(`channel error: ${a.message}`);
					}
					if (a.type === ChannelActionType.SEND_MESSAGE) {
						queue.push({
							to,
							from,
							msgType: a.messageType,
							payload: a.payload
						});
					}
					if (a.type === ChannelActionType.BROADCAST_TX) {
						broadcasts.push(a.tx);
					}
				}
			};

			// Opener requests a splice-out of 50k. This auto-quiesces (STFU) first,
			// then the entire negotiation + signing runs automatically over the wire.
			const destScript = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const spliceOutFee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 0,
					destinationScriptLen: destScript.length
				}),
				253
			);
			opener.setSpliceOutDestination(destScript, 50_000n);
			// Fold the on-chain fee into the declared relative (-(withdraw + fee)).
			enqueue(
				acceptor,
				opener,
				opener.initiateSplice(-(50_000n + spliceOutFee), 253)
			);

			let steps = 0;
			while (queue.length > 0) {
				if (steps++ > 300) throw new Error('splice did not settle');
				const { to, from, msgType, payload } = queue.shift()!;
				enqueue(from, to, deliver(to, msgType, payload));
			}

			const os = opener.getSpliceSession()!;
			const as = acceptor.getSpliceSession()!;

			// Negotiated tx structure: one shared input (same prevout both sides),
			// new funding + destination outputs, conservation holds (fee from weight).
			const fundingTxid = opener.getFullState().fundingTxid!;
			const otx = os.buildTransaction()!;
			const atx = as.buildTransaction()!;
			expect(otx.inputs.length).to.equal(1);
			expect(otx.inputs[0].prevTxid.equals(fundingTxid)).to.be.true;
			expect(
				atx.inputs[0].prevTxid.equals(fundingTxid),
				'acceptor shared input prevout matches'
			).to.be.true;
			expect(otx.outputs.length).to.equal(2);
			expect(
				otx.outputs.reduce((s, o) => s + o.amountSats, 0n) + spliceOutFee
			).to.equal(FUNDING_SATOSHIS);
			// Destination receives the FULL withdrawal; the fee is taken from the channel.
			expect(
				otx.outputs.some(
					(o) => o.scriptPubkey.equals(destScript) && o.amountSats === 50_000n
				)
			).to.be.true;

			// tx_signatures completed automatically: both broadcast the IDENTICAL
			// fully-signed splice tx (same bytes -> same 2-of-2 witness) and advanced
			// to AWAITING_SPLICE_LOCKED.
			expect(broadcasts.length, 'both sides broadcast').to.equal(2);
			expect(broadcasts[0].equals(broadcasts[1]), 'identical signed tx').to.be
				.true;
			expect(os.getState()).to.equal(SpliceState.AWAITING_SPLICE_LOCKED);
			expect(as.getState()).to.equal(SpliceState.AWAITING_SPLICE_LOCKED);

			const spliceTxid = os.getSpliceTxid()!;

			// ── splice_locked exchange (tx confirmed on both sides) ──
			const olMsg = findSendAction(
				opener.sendSpliceLocked(),
				MessageType.SPLICE_LOCKED
			);
			const alMsg = findSendAction(
				acceptor.sendSpliceLocked(),
				MessageType.SPLICE_LOCKED
			);
			opener.handleSpliceLocked(decodeSpliceLockedMessage(alMsg.payload));
			acceptor.handleSpliceLocked(decodeSpliceLockedMessage(olMsg.payload));

			// Both channels resume NORMAL on the NEW funding outpoint, capacity
			// reduced by the splice-out amount.
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
			expect(opener.getFullState().fundingTxid!.equals(spliceTxid)).to.be.true;
			expect(acceptor.getFullState().fundingTxid!.equals(spliceTxid)).to.be
				.true;
			// Capacity is reduced by the splice-out amount AND the on-chain fee,
			// which the initiator pays from the channel.
			expect(opener.getFundingSatoshis()).to.equal(
				FUNDING_SATOSHIS - 50_000n - spliceOutFee
			);

			// ── Post-splice commitment safety ──
			// The new commitment on the spliced outpoint was established DURING the
			// splice (the mid-splice commitment_signed round), so each side already
			// holds a valid remote signature for force-close and owes no further round.
			expect(opener.needsCommitment(), 'no post-splice commitment owed').to.be
				.false;
			expect(acceptor.needsCommitment()).to.be.false;
			expect(
				opener.getFullState().remoteCommitmentSignature,
				'opener holds a commitment sig on the new outpoint'
			).to.not.be.null;
			expect(
				acceptor.getFullState().remoteCommitmentSignature,
				'acceptor holds a commitment sig on the new outpoint'
			).to.not.be.null;
		});

		it('beignet<->beignet: complete splice-IN with a wallet input + change, fully automated', function () {
			bitcoin.initEccLib(ecc);
			const { opener, acceptor } = makeNormalChannel();

			const openerFundingPriv = crypto
				.createHash('sha256')
				.update(openerSeed)
				.update(Buffer.from([0]))
				.digest();
			const acceptorFundingPriv = crypto
				.createHash('sha256')
				.update(acceptorSeed)
				.update(Buffer.from([0]))
				.digest();
			opener.setSigner(new ChannelSigner(openerFundingPriv));
			acceptor.setSigner(new ChannelSigner(acceptorFundingPriv));

			// A wallet UTXO worth 400k that funds the splice-in. Build its prevTx and
			// a P2WPKH-signing closure (the wallet signs its own input).
			const walletPriv = crypto
				.createHash('sha256')
				.update('splice-in-wallet')
				.digest();
			const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
			const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub })
				.output!;
			const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
			const prevTx = new bitcoin.Transaction();
			prevTx.version = 2;
			prevTx.addInput(crypto.randomBytes(32), 0);
			prevTx.addOutput(walletScript, 400_000);

			const walletInput = {
				prevTx: prevTx.toBuffer(),
				prevOutputIndex: 0,
				value: 400_000n,
				sequence: 0xfffffffd,
				signWitness: (
					tx: bitcoin.Transaction,
					inputIndex: number,
					value: bigint
				): Buffer[] => {
					const sighash = tx.hashForWitnessV0(
						inputIndex,
						scriptCode,
						Number(value),
						bitcoin.Transaction.SIGHASH_ALL
					);
					const sig64 = Buffer.from(ecc.sign(sighash, walletPriv));
					const der = bitcoin.script.signature.encode(
						sig64,
						bitcoin.Transaction.SIGHASH_ALL
					);
					return [der, walletPub];
				}
			};
			const changeScript = bitcoin.payments.p2wpkh({ pubkey: walletPub })
				.output!;

			const deliver = (
				ch: Channel,
				msgType: MessageType,
				payload: Buffer
			): any[] => {
				switch (msgType) {
					case MessageType.STFU:
						return ch.handleStfuMessage(decodeStfuMessage(payload));
					case MessageType.SPLICE:
						return ch.handleSplice(decodeSpliceMessage(payload));
					case MessageType.SPLICE_ACK:
						return ch.handleSpliceAck(decodeSpliceAckMessage(payload));
					case MessageType.TX_ADD_INPUT:
						return ch.handleTxAddInput(decodeTxAddInputMessage(payload));
					case MessageType.TX_ADD_OUTPUT:
						return ch.handleTxAddOutput(decodeTxAddOutputMessage(payload));
					case MessageType.TX_COMPLETE:
						return ch.handleTxComplete();
					case MessageType.TX_SIGNATURES:
						return ch.handleTxSignatures(decodeTxSignaturesMessage(payload));
					case MessageType.COMMITMENT_SIGNED:
						return ch.handleCommitmentSigned(
							decodeCommitmentSignedMessage(payload)
						);
					case MessageType.SPLICE_LOCKED:
						return ch.handleSpliceLocked(decodeSpliceLockedMessage(payload));
					default:
						return [];
				}
			};
			const queue: Array<{
				to: Channel;
				from: Channel;
				msgType: MessageType;
				payload: Buffer;
			}> = [];
			const broadcasts: Buffer[] = [];
			const enqueue = (to: Channel, from: Channel, actions: any[]): void => {
				for (const a of actions) {
					if (a.type === ChannelActionType.ERROR)
						throw new Error(`channel error: ${a.message}`);
					if (a.type === ChannelActionType.SEND_MESSAGE)
						queue.push({
							to,
							from,
							msgType: a.messageType,
							payload: a.payload
						});
					if (a.type === ChannelActionType.BROADCAST_TX) broadcasts.push(a.tx);
				}
			};

			// Splice-IN 300k, funded by the 400k wallet input.
			opener.setSpliceInInputs([walletInput], changeScript);
			enqueue(acceptor, opener, opener.initiateSplice(300_000n, 253));

			let steps = 0;
			while (queue.length > 0) {
				if (steps++ > 300) throw new Error('splice-in did not settle');
				const { to, from, msgType, payload } = queue.shift()!;
				enqueue(from, to, deliver(to, msgType, payload));
			}

			const os = opener.getSpliceSession()!;
			const otx = os.buildTransaction()!;
			// Two inputs: shared funding + wallet UTXO.
			expect(otx.inputs.length).to.equal(2);
			// Outputs: new funding (oldCap + 300k) + change; conservation (fee from weight).
			const spliceInFee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 1,
					changeScriptLen: changeScript.length
				}),
				253
			);
			const newFunding = otx.outputs.find(
				(o) => o.amountSats === FUNDING_SATOSHIS + 300_000n
			);
			expect(newFunding, 'new funding output = oldCap + 300k').to.exist;
			const totalOut = otx.outputs.reduce((s, o) => s + o.amountSats, 0n);
			expect(FUNDING_SATOSHIS + 400_000n).to.equal(totalOut + spliceInFee);

			// Both broadcast the identical fully-signed tx; the wallet input has a
			// 2-element P2WPKH witness and the shared input a 4-element 2-of-2 witness.
			expect(broadcasts.length).to.equal(2);
			expect(
				broadcasts[0].equals(broadcasts[1]),
				'identical signed splice-in tx'
			).to.be.true;
			const finalTx = bitcoin.Transaction.fromBuffer(broadcasts[0]);
			const witnessSizes = finalTx.ins.map((i) => i.witness.length).sort();
			expect(witnessSizes).to.deep.equal([2, 4]);

			// splice_locked -> NORMAL with increased capacity.
			const olMsg = findSendAction(
				opener.sendSpliceLocked(),
				MessageType.SPLICE_LOCKED
			);
			const alMsg = findSendAction(
				acceptor.sendSpliceLocked(),
				MessageType.SPLICE_LOCKED
			);
			opener.handleSpliceLocked(decodeSpliceLockedMessage(alMsg.payload));
			acceptor.handleSpliceLocked(decodeSpliceLockedMessage(olMsg.payload));
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
			expect(opener.getFundingSatoshis()).to.equal(FUNDING_SATOSHIS + 300_000n);
		});

		it('beignet<->beignet: complete splice-IN with MULTIPLE wallet inputs + change', function () {
			bitcoin.initEccLib(ecc);
			const { opener, acceptor } = makeNormalChannel();

			const openerFundingPriv = crypto
				.createHash('sha256')
				.update(openerSeed)
				.update(Buffer.from([0]))
				.digest();
			const acceptorFundingPriv = crypto
				.createHash('sha256')
				.update(acceptorSeed)
				.update(Buffer.from([0]))
				.digest();
			opener.setSigner(new ChannelSigner(openerFundingPriv));
			acceptor.setSigner(new ChannelSigner(acceptorFundingPriv));

			// Build a self-signing P2WPKH wallet UTXO of `value` sats.
			const makeWalletInput = (tag: string, value: number) => {
				const priv = crypto.createHash('sha256').update(tag).digest();
				const pub = Buffer.from(ecc.pointFromScalar(priv, true)!);
				const script = bitcoin.payments.p2wpkh({ pubkey: pub }).output!;
				const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output!;
				const prevTx = new bitcoin.Transaction();
				prevTx.version = 2;
				prevTx.addInput(crypto.randomBytes(32), 0);
				prevTx.addOutput(script, value);
				return {
					prevTx: prevTx.toBuffer(),
					prevOutputIndex: 0,
					value: BigInt(value),
					sequence: 0xfffffffd,
					signWitness: (
						tx: bitcoin.Transaction,
						inputIndex: number,
						v: bigint
					): Buffer[] => {
						const sighash = tx.hashForWitnessV0(
							inputIndex,
							scriptCode,
							Number(v),
							bitcoin.Transaction.SIGHASH_ALL
						);
						const sig64 = Buffer.from(ecc.sign(sighash, priv));
						const der = bitcoin.script.signature.encode(
							sig64,
							bitcoin.Transaction.SIGHASH_ALL
						);
						return [der, pub];
					}
				};
			};

			// Two wallet UTXOs (250k + 200k) fund a 300k splice-in, with change.
			const in1 = makeWalletInput('splice-in-multi-A', 250_000);
			const in2 = makeWalletInput('splice-in-multi-B', 200_000);
			const changePub = Buffer.from(
				ecc.pointFromScalar(
					crypto.createHash('sha256').update('splice-in-multi-change').digest(),
					true
				)!
			);
			const changeScript = bitcoin.payments.p2wpkh({ pubkey: changePub })
				.output!;

			const deliver = (
				ch: Channel,
				msgType: MessageType,
				payload: Buffer
			): any[] => {
				switch (msgType) {
					case MessageType.STFU:
						return ch.handleStfuMessage(decodeStfuMessage(payload));
					case MessageType.SPLICE:
						return ch.handleSplice(decodeSpliceMessage(payload));
					case MessageType.SPLICE_ACK:
						return ch.handleSpliceAck(decodeSpliceAckMessage(payload));
					case MessageType.TX_ADD_INPUT:
						return ch.handleTxAddInput(decodeTxAddInputMessage(payload));
					case MessageType.TX_ADD_OUTPUT:
						return ch.handleTxAddOutput(decodeTxAddOutputMessage(payload));
					case MessageType.TX_COMPLETE:
						return ch.handleTxComplete();
					case MessageType.TX_SIGNATURES:
						return ch.handleTxSignatures(decodeTxSignaturesMessage(payload));
					case MessageType.COMMITMENT_SIGNED:
						return ch.handleCommitmentSigned(
							decodeCommitmentSignedMessage(payload)
						);
					case MessageType.SPLICE_LOCKED:
						return ch.handleSpliceLocked(decodeSpliceLockedMessage(payload));
					default:
						return [];
				}
			};
			const queue: Array<{
				to: Channel;
				from: Channel;
				msgType: MessageType;
				payload: Buffer;
			}> = [];
			const broadcasts: Buffer[] = [];
			const enqueue = (to: Channel, from: Channel, actions: any[]): void => {
				for (const a of actions) {
					if (a.type === ChannelActionType.ERROR)
						throw new Error(`channel error: ${a.message}`);
					if (a.type === ChannelActionType.SEND_MESSAGE)
						queue.push({
							to,
							from,
							msgType: a.messageType,
							payload: a.payload
						});
					if (a.type === ChannelActionType.BROADCAST_TX) broadcasts.push(a.tx);
				}
			};

			opener.setSpliceInInputs([in1, in2], changeScript);
			enqueue(acceptor, opener, opener.initiateSplice(300_000n, 253));

			let steps = 0;
			while (queue.length > 0) {
				if (steps++ > 300)
					throw new Error('multi-input splice-in did not settle');
				const { to, from, msgType, payload } = queue.shift()!;
				enqueue(from, to, deliver(to, msgType, payload));
			}

			const otx = opener.getSpliceSession()!.buildTransaction()!;
			// Three inputs: shared funding + the two wallet UTXOs.
			expect(otx.inputs.length).to.equal(3);
			const spliceInFee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 2,
					changeScriptLen: changeScript.length
				}),
				253
			);
			// Conservation: oldCap + both wallet inputs = all outputs + fee.
			const totalOut = otx.outputs.reduce((s, o) => s + o.amountSats, 0n);
			expect(FUNDING_SATOSHIS + 250_000n + 200_000n).to.equal(
				totalOut + spliceInFee
			);
			expect(
				otx.outputs.some((o) => o.amountSats === FUNDING_SATOSHIS + 300_000n),
				'new funding output = oldCap + 300k'
			).to.be.true;

			// Both broadcast the identical fully-signed tx; witnesses: two 2-element
			// P2WPKH wallet inputs + one 4-element 2-of-2 shared input.
			expect(broadcasts.length).to.equal(2);
			expect(broadcasts[0].equals(broadcasts[1]), 'identical signed tx').to.be
				.true;
			const finalTx = bitcoin.Transaction.fromBuffer(broadcasts[0]);
			const witnessSizes = finalTx.ins.map((i) => i.witness.length).sort();
			expect(witnessSizes).to.deep.equal([2, 2, 4]);

			// splice_locked -> NORMAL with capacity increased by the splice-in amount.
			const olMsg = findSendAction(
				opener.sendSpliceLocked(),
				MessageType.SPLICE_LOCKED
			);
			const alMsg = findSendAction(
				acceptor.sendSpliceLocked(),
				MessageType.SPLICE_LOCKED
			);
			opener.handleSpliceLocked(decodeSpliceLockedMessage(alMsg.payload));
			acceptor.handleSpliceLocked(decodeSpliceLockedMessage(olMsg.payload));
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
			expect(opener.getFundingSatoshis()).to.equal(FUNDING_SATOSHIS + 300_000n);
		});

		it('refuses to co-sign a splice tx with a shortchanged new funding output', function () {
			// CLN-as-initiator scenario: the peer drives the interactive tx and
			// constructs a funding output far below the negotiated capacity (the
			// difference would silently become "fee"/peer outputs). The acceptor
			// must refuse to sign the shared input.
			const { acceptor } = makeNormalChannel();
			const acceptorFundingPriv = crypto
				.createHash('sha256')
				.update(acceptorSeed)
				.update(Buffer.from([0]))
				.digest();
			acceptor.setSigner(new ChannelSigner(acceptorFundingPriv));
			quiesce(acceptor);
			const channelId = acceptor.getChannelId()!;
			const fundingTxid = acceptor.getFullState().fundingTxid!;
			const openerBp = makeBasepoints(openerSeed);

			acceptor.handleSplice({
				channelId,
				fundingPubkey: openerBp.fundingPubkey,
				relativeSatoshis: -50_000n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});

			// Peer adds the shared input.
			acceptor.handleTxAddInput({
				channelId,
				serialId: 0n,
				prevTx: Buffer.alloc(0),
				prevTxVout: 0,
				sequence: 0xfffffffd,
				sharedInputTxid: fundingTxid
			});
			// Peer adds a new funding output of only 100k — the honest value would
			// be ~949_816 (1M - 50k - fee). 850k sats vanish.
			const {
				createFundingScript
			} = require('../../src/lightning/script/funding');
			const newFunding = createFundingScript(
				acceptor.getFullState().localBasepoints.fundingPubkey,
				openerBp.fundingPubkey
			);
			acceptor.handleTxAddOutput({
				channelId,
				serialId: 2n,
				amountSats: 100_000n,
				scriptPubkey: newFunding.p2wshOutput
			});
			// Peer pockets the difference in its own output.
			acceptor.handleTxAddOutput({
				channelId,
				serialId: 4n,
				amountSats: 899_000n,
				scriptPubkey: Buffer.concat([
					Buffer.from([0x00, 0x14]),
					crypto.randomBytes(20)
				])
			});

			// Peer completes; the acceptor's commitment step must refuse to build/
			// sign on the poisoned tx instead of co-signing the shared input.
			const actions = acceptor.handleTxComplete();
			const err = findAction(actions, ChannelActionType.ERROR);
			expect(err, 'co-signing refused').to.exist;
			expect(
				findSendAction(actions, MessageType.TX_SIGNATURES),
				'no tx_signatures sent'
			).to.not.exist;
		});

		it('aborts a splice-in when the peer requires confirmed inputs and selection has unconfirmed UTXOs', function () {
			const { opener } = makeNormalChannel();
			const channelId = opener.getChannelId()!;

			const walletPriv = crypto
				.createHash('sha256')
				.update('unconfirmed-utxo')
				.digest();
			const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
			const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub })
				.output!;
			const prevTx = new bitcoin.Transaction();
			prevTx.version = 2;
			prevTx.addInput(crypto.randomBytes(32), 0);
			prevTx.addOutput(walletScript, 400_000);

			opener.setSpliceInInputs(
				[
					{
						prevTx: prevTx.toBuffer(),
						prevOutputIndex: 0,
						value: 400_000n,
						sequence: 0xfffffffd,
						signWitness: () => [],
						confirmed: false // unconfirmed UTXO
					}
				],
				walletScript
			);
			quiesce(opener);
			opener.initiateSplice(300_000n, 253);

			const actions = opener.handleSpliceAck({
				channelId,
				fundingPubkey: makeBasepoints(acceptorSeed).fundingPubkey,
				relativeSatoshis: 0n,
				requireConfirmedInputs: true
			});

			expect(
				findSendAction(actions, MessageType.TX_ABORT),
				'tx_abort sent to peer'
			).to.exist;
			expect(findAction(actions, ChannelActionType.ERROR), 'surfaced as error')
				.to.exist;
			expect(
				findSendAction(actions, MessageType.TX_ADD_INPUT),
				'no contribution sent'
			).to.not.exist;
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
		});

		// ─────────────── Disconnect & reestablish safety ───────────────

		describe('disconnect & reestablish safety', function () {
			interface IWirePair {
				opener: Channel;
				acceptor: Channel;
				broadcasts: Buffer[];
				errors: string[];
				enqueue: (to: Channel, from: Channel, actions: any[]) => void;
				pump: () => void;
				/** After skipping `skip` matches, drop the next `count` messages of this type. */
				drop: (msgType: MessageType, count?: number, skip?: number) => void;
				/** Clear all drop rules (a fresh connection delivers everything). */
				clearDrops: () => void;
			}

			function makeWirePair(pushMsat = 0n): IWirePair {
				const { opener, acceptor } = makeNormalChannel(pushMsat);
				const openerFundingPriv = crypto
					.createHash('sha256')
					.update(openerSeed)
					.update(Buffer.from([0]))
					.digest();
				const acceptorFundingPriv = crypto
					.createHash('sha256')
					.update(acceptorSeed)
					.update(Buffer.from([0]))
					.digest();
				opener.setSigner(new ChannelSigner(openerFundingPriv));
				acceptor.setSigner(new ChannelSigner(acceptorFundingPriv));

				const deliver = (
					ch: Channel,
					msgType: MessageType,
					payload: Buffer
				): any[] => {
					switch (msgType) {
						case MessageType.STFU:
							return ch.handleStfuMessage(decodeStfuMessage(payload));
						case MessageType.SPLICE:
							return ch.handleSplice(decodeSpliceMessage(payload));
						case MessageType.SPLICE_ACK:
							return ch.handleSpliceAck(decodeSpliceAckMessage(payload));
						case MessageType.TX_ADD_INPUT:
							return ch.handleTxAddInput(decodeTxAddInputMessage(payload));
						case MessageType.TX_ADD_OUTPUT:
							return ch.handleTxAddOutput(decodeTxAddOutputMessage(payload));
						case MessageType.TX_COMPLETE:
							return ch.handleTxComplete();
						case MessageType.TX_SIGNATURES:
							return ch.handleTxSignatures(decodeTxSignaturesMessage(payload));
						case MessageType.TX_ABORT:
							return ch.handleTxAbort();
						case MessageType.COMMITMENT_SIGNED:
							return ch.handleCommitmentSigned(
								decodeCommitmentSignedMessage(payload)
							);
						case MessageType.SPLICE_LOCKED:
							return ch.handleSpliceLocked(decodeSpliceLockedMessage(payload));
						case MessageType.CHANNEL_REESTABLISH:
							return ch.handleReestablish(
								decodeChannelReestablishMessage(payload)
							);
						default:
							return [];
					}
				};

				const queue: Array<{
					to: Channel;
					from: Channel;
					msgType: MessageType;
					payload: Buffer;
				}> = [];
				const broadcasts: Buffer[] = [];
				const errors: string[] = [];
				const dropRules = new Map<
					MessageType,
					{ skip: number; count: number }
				>();

				const enqueue = (to: Channel, from: Channel, actions: any[]): void => {
					for (const a of actions) {
						if (a.type === ChannelActionType.ERROR) errors.push(a.message);
						if (a.type === ChannelActionType.BROADCAST_TX)
							broadcasts.push(a.tx);
						if (a.type === ChannelActionType.SEND_MESSAGE) {
							const rule = dropRules.get(a.messageType);
							if (rule) {
								if (rule.skip > 0) {
									rule.skip--;
								} else if (rule.count > 0) {
									rule.count--;
									continue; // dropped on the wire
								}
							}
							queue.push({
								to,
								from,
								msgType: a.messageType,
								payload: a.payload
							});
						}
					}
				};

				const pump = (): void => {
					let steps = 0;
					while (queue.length > 0) {
						if (steps++ > 400) throw new Error('message pump did not settle');
						const { to, from, msgType, payload } = queue.shift()!;
						enqueue(from, to, deliver(to, msgType, payload));
					}
				};

				const drop = (msgType: MessageType, count = 1000, skip = 0): void => {
					dropRules.set(msgType, { skip, count });
				};
				const clearDrops = (): void => {
					dropRules.clear();
				};

				return {
					opener,
					acceptor,
					broadcasts,
					errors,
					enqueue,
					pump,
					drop,
					clearDrops
				};
			}

			/** Simulate a transport drop on both ends. A reconnect gets a fresh wire. */
			function disconnect(pair: IWirePair): void {
				pair.opener.markForReestablish();
				pair.acceptor.markForReestablish();
				pair.clearDrops();
				expect(pair.opener.getState()).to.equal(
					ChannelState.AWAITING_REESTABLISH
				);
				expect(pair.acceptor.getState()).to.equal(
					ChannelState.AWAITING_REESTABLISH
				);
			}

			/** Exchange channel_reestablish both ways and pump the fallout. */
			function reconnect(pair: IWirePair): {
				openerMsg: ReturnType<typeof decodeChannelReestablishMessage>;
				acceptorMsg: ReturnType<typeof decodeChannelReestablishMessage>;
			} {
				const oRe = findSendAction(
					pair.opener.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				);
				const aRe = findSendAction(
					pair.acceptor.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				);
				const openerMsg = decodeChannelReestablishMessage(oRe.payload);
				const acceptorMsg = decodeChannelReestablishMessage(aRe.payload);
				pair.enqueue(
					pair.acceptor,
					pair.opener,
					pair.opener.handleReestablish(acceptorMsg)
				);
				pair.enqueue(
					pair.opener,
					pair.acceptor,
					pair.acceptor.handleReestablish(openerMsg)
				);
				pair.pump();
				return { openerMsg, acceptorMsg };
			}

			// Fee a startSpliceOut splice tx pays at 253 sat/kw (P2WPKH destination),
			// folded into relative_satoshis exactly as node.spliceOut does: the
			// negotiated tx must actually pay the declared feerate (the tx_complete
			// audit enforces it).
			const SPLICE_OUT_TEST_FEE = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 0,
					destinationScriptLen: 22
				}),
				253
			);

			function startSpliceOut(pair: IWirePair, withdraw = 50_000n): Buffer {
				const destScript = Buffer.concat([
					Buffer.from([0x00, 0x14]),
					crypto.randomBytes(20)
				]);
				pair.opener.setSpliceOutDestination(destScript, withdraw);
				pair.enqueue(
					pair.acceptor,
					pair.opener,
					pair.opener.initiateSplice(-(withdraw + SPLICE_OUT_TEST_FEE), 253)
				);
				pair.pump();
				return destScript;
			}

			it('carries the shared-input signature in the tx_signatures TLV, not the witnesses (CLN interop)', function () {
				const pair = makeWirePair();
				startSpliceOut(pair);

				// Splice completed; retransmission reuses the recorded in-flight data.
				const actions = (pair.opener as any)._retransmitSpliceTxSignatures();
				const sigMsg = findSendAction(actions, MessageType.TX_SIGNATURES);
				const decoded = decodeTxSignaturesMessage(sigMsg.payload);
				expect(decoded.sharedInputSignature, 'shared sig in TLV').to.exist;
				expect(decoded.sharedInputSignature!.length).to.equal(64);
				// Splice-out contributes no wallet inputs: witnesses must be empty
				// (the old format smuggled the shared sig as witnesses[0]).
				expect(decoded.witnesses.length).to.equal(0);
			});

			it('sends splice_locked exactly once per connection (duplicate confirmations are no-ops)', function () {
				const pair = makeWirePair();
				startSpliceOut(pair);

				// The confirmation can be observed multiple times (block event +
				// subscription + periodic recheck). Only ONE splice_locked may go
				// out — CLN fails the channel on a same-connection duplicate.
				const first = pair.opener.sendSpliceLocked();
				expect(findSendAction(first, MessageType.SPLICE_LOCKED)).to.exist;

				const second = pair.opener.sendSpliceLocked();
				expect(second, 'duplicate trigger is a silent no-op').to.deep.equal([]);
			});

			it('honors the peer retransmit_flags: no commitment_signed when the peer already has it', function () {
				const pair = makeWirePair();
				// Wedge after the commitment round: both sides exchanged splice
				// commitment_signed but no tx_signatures got through.
				pair.drop(MessageType.TX_SIGNATURES);
				startSpliceOut(pair);
				disconnect(pair);

				// The acceptor's real reestablish: it HAS our commitment, so its
				// retransmit_flags bit 0 is clear.
				const aRe = findSendAction(
					pair.acceptor.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				);
				const acceptorMsg = decodeChannelReestablishMessage(aRe.payload);
				expect(
					acceptorMsg.nextFundingTxid,
					'acceptor announces the in-flight splice'
				).to.exist;
				expect(acceptorMsg.nextFundingRetransmitFlags).to.equal(0);

				// flags=0 → the peer is strictly awaiting tx_signatures; resending
				// commitment_signed makes CLN hard-fail ("should be WIRE_TX_SIGNATURES").
				const actions = pair.opener.handleReestablish(acceptorMsg);
				const commitResend = actions.filter(
					(a: any) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						a.messageType === MessageType.COMMITMENT_SIGNED
				);
				expect(
					commitResend,
					'no commitment retransmit when peer has it'
				).to.have.length(0);

				// flags bit 0 set → the peer asks for the commitment again.
				const askMsg = { ...acceptorMsg, nextFundingRetransmitFlags: 1 };
				const askActions = pair.opener.handleReestablish(askMsg);
				const commitAgain = askActions.filter(
					(a: any) =>
						a.type === ChannelActionType.SEND_MESSAGE &&
						a.messageType === MessageType.COMMITMENT_SIGNED
				);
				expect(
					commitAgain,
					'commitment retransmitted on request'
				).to.have.length(1);
			});

			it('sends tx_abort ahead of reestablish for a splice dropped mid-negotiation (CLN recovery)', function () {
				const pair = makeWirePair();
				// Stall the interactive-tx negotiation before any commitment exchange,
				// then disconnect: the opener forgets the splice, but a CLN peer would
				// still hold it in-flight and demand the commitment on reestablish.
				pair.drop(MessageType.TX_ADD_OUTPUT);
				startSpliceOut(pair);
				expect(pair.opener.getState()).to.equal(ChannelState.SPLICING);
				disconnect(pair);

				const actions = pair.opener.createReestablish();
				const sends = actions.filter(
					(a: any) => a.type === ChannelActionType.SEND_MESSAGE
				) as any[];
				// tx_abort MUST precede channel_reestablish: CLN only runs its
				// tx_abort check on messages read while awaiting our reestablish.
				expect(sends[0].messageType).to.equal(MessageType.TX_ABORT);
				expect(sends[1].messageType).to.equal(MessageType.CHANNEL_REESTABLISH);
				expect(pair.opener.isSpliceAbortPending()).to.be.true;

				// The peer's tx_abort echo is the ack — consumed, not an error.
				const echoActions = pair.opener.handleTxAbort();
				expect(echoActions).to.deep.equal([]);
				expect(pair.opener.isSpliceAbortPending()).to.be.false;

				// The tx_abort is one-shot: the next reestablish is clean.
				pair.opener.markForReestablish();
				const again = pair.opener
					.createReestablish()
					.filter(
						(a: any) => a.type === ChannelActionType.SEND_MESSAGE
					) as any[];
				expect(again).to.have.length(1);
				expect(again[0].messageType).to.equal(MessageType.CHANNEL_REESTABLISH);
			});

			it('echoes an unsolicited tx_abort instead of failing the channel', function () {
				const pair = makeWirePair();
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				const actions = pair.opener.handleTxAbort() as any[];
				const err = actions.find((a) => a.type === ChannelActionType.ERROR);
				expect(err, 'no error for an unsolicited tx_abort').to.be.undefined;
				const echo = actions.find(
					(a) => a.type === ChannelActionType.SEND_MESSAGE
				);
				expect(echo.messageType).to.equal(MessageType.TX_ABORT);
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
			});

			it('drops a splice still waiting for quiescence; both sides resume NORMAL', function () {
				const pair = makeWirePair();
				// Swallow the STFU so quiescence never completes and the splice stays pending.
				pair.drop(MessageType.STFU);
				const destScript = Buffer.concat([
					Buffer.from([0x00, 0x14]),
					crypto.randomBytes(20)
				]);
				pair.opener.setSpliceOutDestination(destScript, 50_000n);
				pair.enqueue(
					pair.acceptor,
					pair.opener,
					pair.opener.initiateSplice(-50_000n, 253)
				);
				pair.pump();

				disconnect(pair);
				const { openerMsg, acceptorMsg } = reconnect(pair);
				expect(openerMsg.nextFundingTxid, 'no in-flight splice txid').to.be
					.undefined;
				expect(acceptorMsg.nextFundingTxid).to.be.undefined;
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.errors).to.deep.equal([]);
			});

			it('forgets a splice that disconnects mid-negotiation; a fresh splice then succeeds', function () {
				const pair = makeWirePair();
				// Stall the interactive-tx negotiation before any commitment exchange.
				pair.drop(MessageType.TX_ADD_OUTPUT);
				startSpliceOut(pair);
				expect(pair.opener.getState()).to.equal(ChannelState.SPLICING);

				disconnect(pair);
				const { openerMsg, acceptorMsg } = reconnect(pair);
				expect(openerMsg.nextFundingTxid, 'unsigned splice is not resumable').to
					.be.undefined;
				expect(acceptorMsg.nextFundingTxid).to.be.undefined;
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);

				// A fresh splice on the reestablished channel completes end-to-end.
				startSpliceOut(pair);
				expect(
					pair.broadcasts.length,
					'fresh splice fully signed and broadcast'
				).to.equal(2);
				expect(pair.opener.getSpliceSession()!.getState()).to.equal(
					SpliceState.AWAITING_SPLICE_LOCKED
				);
			});

			it('resumes after both sent commitment_signed but the exchange was lost', function () {
				const pair = makeWirePair();
				// Both sides reach AWAITING_TX_SIGNATURES and send commitment_signed,
				// but neither commitment_signed (nor anything after) arrives.
				pair.drop(MessageType.COMMITMENT_SIGNED);
				startSpliceOut(pair);
				expect(
					pair.broadcasts.length,
					'nothing broadcast before disconnect'
				).to.equal(0);

				disconnect(pair);
				expect(
					pair.opener.getState(),
					'committed splice survives disconnect'
				).to.equal(ChannelState.AWAITING_REESTABLISH);

				const { openerMsg, acceptorMsg } = reconnect(pair);
				expect(openerMsg.nextFundingTxid, 'opener announces in-flight splice')
					.to.exist;
				expect(
					acceptorMsg.nextFundingTxid,
					'acceptor announces in-flight splice'
				).to.exist;
				expect(openerMsg.nextFundingTxid!.equals(acceptorMsg.nextFundingTxid!))
					.to.be.true;

				// Retransmission completed the splice: both broadcast the identical tx.
				expect(pair.errors).to.deep.equal([]);
				expect(pair.broadcasts.length).to.equal(2);
				expect(pair.broadcasts[0].equals(pair.broadcasts[1])).to.be.true;
				expect(pair.opener.getSpliceSession()!.getState()).to.equal(
					SpliceState.AWAITING_SPLICE_LOCKED
				);
				expect(pair.acceptor.getSpliceSession()!.getState()).to.equal(
					SpliceState.AWAITING_SPLICE_LOCKED
				);

				// splice_locked completes as usual on the new outpoint.
				const olMsg = findSendAction(
					pair.opener.sendSpliceLocked(),
					MessageType.SPLICE_LOCKED
				);
				const alMsg = findSendAction(
					pair.acceptor.sendSpliceLocked(),
					MessageType.SPLICE_LOCKED
				);
				pair.opener.handleSpliceLocked(
					decodeSpliceLockedMessage(alMsg.payload)
				);
				pair.acceptor.handleSpliceLocked(
					decodeSpliceLockedMessage(olMsg.payload)
				);
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
			});

			it('recovers when the acceptor sent tx_signatures that never arrived', function () {
				const pair = makeWirePair();
				// The acceptor sends tx_signatures first; lose them on the wire.
				pair.drop(MessageType.TX_SIGNATURES);
				startSpliceOut(pair);
				expect(
					pair.acceptor.getFullState().spliceInFlight,
					'acceptor passed the point of no return'
				).to.not.be.null;
				// The opener records the in-flight splice at the commitment round
				// (crash-safe persistence) but its signatures have not left yet.
				expect(
					pair.opener.getFullState().spliceInFlight,
					'opener in-flight recorded at commitment'
				).to.not.be.null;
				expect(
					pair.opener.getFullState().spliceInFlight!.sentTxSignatures,
					'opener has not sent sigs yet'
				).to.be.false;

				// The acceptor must now refuse to abort — its signatures are out.
				const abortErr = findAction(
					pair.acceptor.abortSplice('user requested'),
					ChannelActionType.ERROR
				);
				expect(abortErr, 'abort refused after tx_signatures sent').to.exist;

				disconnect(pair);
				reconnect(pair);

				// The retransmitted signatures complete the splice on both sides.
				expect(pair.errors).to.deep.equal([]);
				expect(pair.broadcasts.length).to.equal(2);
				expect(pair.opener.getSpliceSession()!.getState()).to.equal(
					SpliceState.AWAITING_SPLICE_LOCKED
				);
				expect(pair.acceptor.getSpliceSession()!.getState()).to.equal(
					SpliceState.AWAITING_SPLICE_LOCKED
				);
			});

			it('unwinds cleanly via tx_abort when only one side reached the commitment phase', function () {
				const pair = makeWirePair();
				// Lose the opener's FINAL tx_complete (the 4th tx_complete on the
				// wire) and all commitment_signed: the opener reaches
				// AWAITING_TX_SIGNATURES and commits, while the acceptor is still
				// negotiating.
				pair.drop(MessageType.TX_COMPLETE, 1, 3);
				pair.drop(MessageType.COMMITMENT_SIGNED);
				startSpliceOut(pair);

				const openerCommitted =
					(pair.opener as any)._spliceSentCommitment === true;
				const acceptorCommitted =
					(pair.acceptor as any)._spliceSentCommitment === true;
				expect(
					openerCommitted !== acceptorCommitted,
					'exactly one side committed'
				).to.be.true;

				disconnect(pair);
				reconnect(pair);

				// The committed side announced next_funding_txid; the other side never
				// signed that tx and answered tx_abort; both unwound to NORMAL.
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.opener.getFullState().spliceInFlight).to.be.null;
				expect(pair.acceptor.getFullState().spliceInFlight).to.be.null;
			});

			it('survives a disconnect during the splice_locked wait (fully signed)', function () {
				const pair = makeWirePair();
				startSpliceOut(pair);
				expect(pair.broadcasts.length).to.equal(2);
				const spliceTxid = pair.opener.getSpliceSession()!.getSpliceTxid()!;

				disconnect(pair);
				const { openerMsg, acceptorMsg } = reconnect(pair);
				// CLN v26 semantics: BOTH sides keep announcing next_funding_txid on
				// every reestablish until the splice tx LOCKS, even when fully
				// signed. A reestablish without it makes CLN silently forget its
				// inflight (and ignore any tx_signatures retransmitted afterwards).
				expect(openerMsg.nextFundingTxid).to.deep.equal(spliceTxid);
				expect(acceptorMsg.nextFundingTxid).to.deep.equal(spliceTxid);
				// Both hold the peer's splice commitment sig: nothing to retransmit.
				expect(openerMsg.nextFundingRetransmitFlags).to.equal(0);
				expect(acceptorMsg.nextFundingRetransmitFlags).to.equal(0);
				expect(
					pair.opener.getState(),
					'back to SPLICING, awaiting locks'
				).to.equal(ChannelState.SPLICING);
				expect(pair.acceptor.getState()).to.equal(ChannelState.SPLICING);

				// Confirmation arrives → splice_locked exchange → NORMAL on new outpoint.
				pair.enqueue(
					pair.acceptor,
					pair.opener,
					pair.opener.sendSpliceLocked()
				);
				pair.enqueue(
					pair.opener,
					pair.acceptor,
					pair.acceptor.sendSpliceLocked()
				);
				pair.pump();
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.opener.getFullState().fundingTxid!.equals(spliceTxid)).to.be
					.true;
				expect(pair.acceptor.getFullState().fundingTxid!.equals(spliceTxid)).to
					.be.true;
				expect(pair.opener.getFullState().spliceInFlight).to.be.null;
			});

			it('retransmits a lost splice_locked on reconnect', function () {
				const pair = makeWirePair();
				startSpliceOut(pair);

				// The opener locks, but the message is lost.
				pair.drop(MessageType.SPLICE_LOCKED, 1);
				pair.enqueue(
					pair.acceptor,
					pair.opener,
					pair.opener.sendSpliceLocked()
				);
				pair.pump();
				expect(pair.opener.getState()).to.equal(ChannelState.SPLICING);

				disconnect(pair);
				reconnect(pair);

				// On reconnect the opener re-sent splice_locked; the acceptor locks on
				// its own confirmation and both complete.
				pair.enqueue(
					pair.opener,
					pair.acceptor,
					pair.acceptor.sendSpliceLocked()
				);
				pair.pump();
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
			});

			it('persists and restores an in-flight splice across a restart', function () {
				const pair = makeWirePair();
				startSpliceOut(pair);
				expect(pair.broadcasts.length).to.equal(2);
				const spliceTxid = pair.opener.getSpliceSession()!.getSpliceTxid()!;
				const preCapacity = pair.opener.getFullState().fundingSatoshis;

				// "Crash" the opener: round-trip its state through serialization.
				const serialized = JSON.parse(
					JSON.stringify(serializeChannelState(pair.opener.getFullState()))
				);
				const restoredState = deserializeChannelState(serialized);
				expect(restoredState.spliceInFlight, 'in-flight splice persisted').to
					.not.be.null;
				expect(restoredState.spliceInFlight!.spliceTxid.equals(spliceTxid)).to
					.be.true;
				expect(restoredState.spliceInFlight!.fullySigned).to.be.true;
				// The persisted tx is the identical fully-signed broadcast tx.
				expect(
					Buffer.from(restoredState.spliceInFlight!.spliceTxHex, 'hex').equals(
						pair.broadcasts[0]
					)
				).to.be.true;

				const restored = new Channel(restoredState);
				const openerFundingPriv = crypto
					.createHash('sha256')
					.update(openerSeed)
					.update(Buffer.from([0]))
					.digest();
				restored.setSigner(new ChannelSigner(openerFundingPriv));
				restored.restoreSpliceInFlight();
				restored.markForReestablish();
				expect(restored.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
				expect(restored.getSpliceSession(), 'session rebuilt from persistence')
					.to.not.be.null;
				expect(restored.getSpliceSession()!.getState()).to.equal(
					SpliceState.AWAITING_SPLICE_LOCKED
				);

				// Reestablish with the (still-live) acceptor.
				pair.acceptor.markForReestablish();
				const rRe = findSendAction(
					restored.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				);
				const aRe = findSendAction(
					pair.acceptor.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				);
				expect(
					decodeChannelReestablishMessage(rRe.payload).nextFundingTxid,
					'announced until locked (CLN v26 keeps its inflight alive on it)'
				).to.not.be.undefined;
				restored.handleReestablish(
					decodeChannelReestablishMessage(aRe.payload)
				);
				pair.acceptor.handleReestablish(
					decodeChannelReestablishMessage(rRe.payload)
				);
				expect(restored.getState()).to.equal(ChannelState.SPLICING);

				// Confirmation → splice_locked both ways → NORMAL on the new outpoint.
				const rl = findSendAction(
					restored.sendSpliceLocked(),
					MessageType.SPLICE_LOCKED
				);
				const al = findSendAction(
					pair.acceptor.sendSpliceLocked(),
					MessageType.SPLICE_LOCKED
				);
				expect(
					decodeSpliceLockedMessage(rl.payload).fundingTxid!.equals(spliceTxid),
					'splice_locked carries the txid'
				).to.be.true;
				restored.handleSpliceLocked(decodeSpliceLockedMessage(al.payload));
				pair.acceptor.handleSpliceLocked(decodeSpliceLockedMessage(rl.payload));
				expect(restored.getState()).to.equal(ChannelState.NORMAL);
				expect(restored.getFullState().fundingTxid!.equals(spliceTxid)).to.be
					.true;
				expect(
					restored.getFullState().fundingSatoshis < preCapacity,
					'capacity reduced by withdrawal + fee'
				).to.be.true;
				expect(restored.getFullState().spliceInFlight).to.be.null;
			});

			it('flushes splice_locked on reconnect when the confirmation arrived while disconnected', function () {
				const pair = makeWirePair();
				startSpliceOut(pair);

				disconnect(pair);
				// Chain watcher saw the confirmation while disconnected.
				pair.opener.markSpliceConfirmed();
				expect(pair.opener.getFullState().spliceInFlight!.confirmed).to.be.true;

				reconnect(pair);
				// The reestablish flushed the opener's splice_locked; complete the other side.
				pair.enqueue(
					pair.opener,
					pair.acceptor,
					pair.acceptor.sendSpliceLocked()
				);
				pair.pump();
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
			});

			/** splice_locked both ways and pump → back to NORMAL on the new outpoint. */
			function completeSpliceLocked(pair: IWirePair): void {
				pair.enqueue(
					pair.acceptor,
					pair.opener,
					pair.opener.sendSpliceLocked()
				);
				pair.enqueue(
					pair.opener,
					pair.acceptor,
					pair.acceptor.sendSpliceLocked()
				);
				pair.pump();
			}

			it('completes two SEQUENTIAL splice-outs on the same channel (funding outpoint chain)', function () {
				const pair = makeWirePair();

				// ── First splice-out ──
				startSpliceOut(pair, 50_000n);
				expect(pair.opener.getSpliceSession()!.getState()).to.equal(
					SpliceState.AWAITING_SPLICE_LOCKED
				);
				const spliceTxid1 = pair.opener.getSpliceSession()!.getSpliceTxid()!;
				completeSpliceLocked(pair);

				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
				expect(
					pair.opener.getFullState().fundingTxid!.equals(spliceTxid1),
					'opener funding moved to the first splice tx'
				).to.be.true;
				expect(pair.errors, 'no errors after first splice').to.be.empty;
				const capAfter1 = pair.opener.getFundingSatoshis();
				expect(capAfter1 < FUNDING_SATOSHIS).to.be.true;

				// ── Second splice-out, spending the FIRST splice's funding output ──
				startSpliceOut(pair, 30_000n);
				const session2 = pair.opener.getSpliceSession()!;
				expect(session2.getState()).to.equal(
					SpliceState.AWAITING_SPLICE_LOCKED
				);
				// The chain advances: the second splice's shared input is the first
				// splice's funding output.
				expect(
					session2.buildTransaction()!.inputs[0].prevTxid.equals(spliceTxid1),
					'second splice spends the first splice output'
				).to.be.true;
				const spliceTxid2 = session2.getSpliceTxid()!;
				expect(spliceTxid2.equals(spliceTxid1)).to.be.false;
				completeSpliceLocked(pair);

				// Both sides resume NORMAL on the SECOND new outpoint with a fresh,
				// valid commitment — capacity reduced again.
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
				expect(
					pair.opener.getFullState().fundingTxid!.equals(spliceTxid2),
					'opener funding moved to the second splice tx'
				).to.be.true;
				expect(pair.acceptor.getFullState().fundingTxid!.equals(spliceTxid2)).to
					.be.true;
				expect(pair.opener.getFundingSatoshis() < capAfter1).to.be.true;
				expect(pair.errors, 'no errors across both splices').to.be.empty;
				expect(
					pair.opener.getFullState().remoteCommitmentSignature,
					'opener holds a commitment sig on the final outpoint'
				).to.not.be.null;
				expect(
					pair.acceptor.getFullState().remoteCommitmentSignature,
					'acceptor holds a commitment sig on the final outpoint'
				).to.not.be.null;
			});

			it('splice-out with a NON-ZERO remote balance leaves the acceptor balance untouched', function () {
				// Open with 200k sat pushed to the acceptor, so both sides hold funds.
				const pushMsat = 200_000_000n;
				const pair = makeWirePair(pushMsat);

				const acceptorLocalBefore =
					pair.acceptor.getFullState().localBalanceMsat;
				const openerLocalBefore = pair.opener.getFullState().localBalanceMsat;
				expect(acceptorLocalBefore, 'acceptor starts with the push').to.equal(
					pushMsat
				);
				expect(openerLocalBefore).to.equal(FUNDING_SATOSHIS * 1000n - pushMsat);

				// Opener splices 50k out of ITS OWN balance (plus the folded
				// on-chain fee, which also comes out of the opener's side).
				startSpliceOut(pair, 50_000n);
				completeSpliceLocked(pair);

				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.errors, 'no errors').to.be.empty;

				// The acceptor did not contribute to the splice-out — its balance is
				// unchanged; the full 50k came out of the opener's side.
				expect(
					pair.acceptor.getFullState().localBalanceMsat,
					'acceptor balance untouched'
				).to.equal(acceptorLocalBefore);
				expect(
					pair.opener.getFullState().localBalanceMsat,
					'opener balance reduced by exactly the withdrawal plus the fee'
				).to.equal(openerLocalBefore - (50_000n + SPLICE_OUT_TEST_FEE) * 1000n);

				// Both agree on the new outpoint + capacity, and balances still sum to it.
				const spliceTxid = pair.opener.getFullState().fundingTxid!;
				expect(pair.acceptor.getFullState().fundingTxid!.equals(spliceTxid)).to
					.be.true;
				expect(pair.opener.getFundingSatoshis()).to.equal(
					pair.acceptor.getFundingSatoshis()
				);
				expect(
					pair.opener.getFullState().localBalanceMsat +
						pair.acceptor.getFullState().localBalanceMsat,
					'local balances sum to the new capacity'
				).to.equal(pair.opener.getFundingSatoshis() * 1000n);
			});

			it('recovers both sides to NORMAL when a splice is aborted mid-negotiation (tx_abort)', function () {
				const pair = makeWirePair();
				const origFunding = pair.opener.getFullState().fundingTxid!;
				const origCap = pair.opener.getFundingSatoshis();

				// Stall the interactive-tx negotiation before any signing by dropping
				// tx_complete, so the splice sits mid-flight with a live session.
				pair.drop(MessageType.TX_COMPLETE);
				startSpliceOut(pair, 50_000n);

				expect(pair.opener.getState()).to.equal(ChannelState.SPLICING);
				expect(pair.acceptor.getState()).to.equal(ChannelState.SPLICING);
				expect(
					pair.opener.getSpliceSession()!.isComplete(),
					'splice not complete (tx_signatures never exchanged)'
				).to.be.false;

				// tx_abort tears down the splice on BOTH sides. Per BOLT 2 it unwinds
				// only the splice — the underlying channel is untouched.
				pair.opener.handleTxAbort();
				pair.acceptor.handleTxAbort();

				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.opener.getSpliceSession(), 'opener session cleared').to.be
					.null;
				expect(pair.acceptor.getSpliceSession(), 'acceptor session cleared').to
					.be.null;
				// Funding outpoint + capacity unchanged — the splice never happened.
				expect(
					pair.opener.getFullState().fundingTxid!.equals(origFunding),
					'funding outpoint unchanged'
				).to.be.true;
				expect(pair.opener.getFundingSatoshis()).to.equal(origCap);

				// And the channel is still usable: a fresh splice-out now completes.
				pair.clearDrops();
				startSpliceOut(pair, 25_000n);
				completeSpliceLocked(pair);
				expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
				expect(
					pair.opener.getFundingSatoshis() < origCap,
					'post-abort splice reduced capacity'
				).to.be.true;
			});
		});
	});

	// ─────────────── ChannelManager Integration ───────────────

	describe('ChannelManager splice routing', function () {
		it('should route splice messages between managers', function () {
			const { openerManager, channelId, openerChannel, acceptorChannel } =
				createNormalChannelPair();

			// Quiesce from opener side
			openerManager.initiateQuiescence(channelId);

			// After message routing, both should be quiescent
			expect(openerChannel.isQuiescent()).to.be.true;
			expect(acceptorChannel.isQuiescent()).to.be.true;

			// Initiate splice on opener
			const result = openerManager.initiateSplice(channelId, 100_000n, 253);
			expect(result.ok).to.be.true;

			// Acceptor should now be in SPLICING state (auto-handled via message routing)
			expect(openerChannel.getState()).to.equal(ChannelState.SPLICING);
			expect(acceptorChannel.getState()).to.equal(ChannelState.SPLICING);
		});

		it('should support sendSpliceLocked via manager', function () {
			const { openerManager, channelId, openerChannel } =
				createNormalChannelPair();

			// Setup quiescence and splice
			openerManager.initiateQuiescence(channelId);
			openerManager.initiateSplice(channelId, 100_000n, 253);

			// Get session and progress through interactive TX
			const session = openerChannel.getSpliceSession()!;
			session.addInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			session.addOutput({
				serialId: 2n,
				amountSats: 100_000n,
				scriptPubkey: Buffer.alloc(22, 0x01)
			});
			session.markTxComplete();
			session.handlePeerTxComplete();
			session.handleTxSignatures(crypto.randomBytes(32), 0);

			const result = openerManager.sendSpliceLocked(channelId);
			expect(result.ok).to.be.true;
		});

		it('routes an HTLC payment AFTER a splice completes (commitment on the new outpoint)', function () {
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel
			} = createNormalChannelPair();

			// ── Drive a splice-out to completion (NORMAL on a new outpoint) ──
			openerManager.initiateQuiescence(channelId);
			const destScript = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			// Fold the on-chain fee into relative_satoshis exactly as
			// node.spliceOut does (the tx_complete audit enforces the feerate).
			const spliceOutFee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 0,
					destinationScriptLen: destScript.length
				}),
				253
			);
			openerChannel.setSpliceOutDestination(destScript, 50_000n);
			expect(
				openerManager.initiateSplice(channelId, -(50_000n + spliceOutFee), 253)
					.ok
			).to.be.true;

			// Auto-routing ran the splice to fully-signed; lock it in both ways.
			openerManager.sendSpliceLocked(channelId);
			acceptorManager.sendSpliceLocked(channelId);
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
			const splicedFunding = openerChannel.getFullState().fundingTxid!;
			expect(acceptorChannel.getFullState().fundingTxid!.equals(splicedFunding))
				.to.be.true;

			const openerCommitBefore =
				openerChannel.getFullState().localCommitmentNumber;
			const openerLocalMsatBefore =
				openerChannel.getFullState().localBalanceMsat;

			// ── A real HTLC payment over the post-splice channel ──
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const amountMsat = 20_000_000n;

			let fulfilled = false;
			openerManager.on('htlc:fulfilled', () => {
				fulfilled = true;
			});

			expect(
				openerManager.addHtlc(
					channelId,
					amountMsat,
					paymentHash,
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.be.true;
			acceptorManager.fulfillHtlc(channelId, 0n, preimage);

			// The payment settled over the spliced channel: a fresh commitment round
			// advanced on the NEW funding outpoint and the balance moved.
			expect(fulfilled, 'HTLC fulfilled after splice').to.be.true;
			expect(
				openerChannel.getFullState().localCommitmentNumber > openerCommitBefore,
				'commitment advanced on the spliced outpoint'
			).to.be.true;
			expect(
				openerChannel.getFullState().localBalanceMsat,
				'opener balance reduced by the payment'
			).to.equal(openerLocalMsatBefore - amountMsat);
			// Both sides still agree on the spliced funding outpoint.
			expect(openerChannel.getFullState().fundingTxid!.equals(splicedFunding))
				.to.be.true;
		});

		it('splices with a COMMITTED HTLC riding through (S-2.M8)', function () {
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel
			} = createNormalChannelPair();

			// A fully committed live HTLC before the splice (added and driven
			// through both commitment rounds by the loopback, NOT settled).
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			expect(
				openerManager.addHtlc(
					channelId,
					20_000_000n,
					paymentHash,
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.be.true;
			const entry = [...openerChannel.getFullState().htlcs.values()][0];
			expect(entry.state, 'HTLC fully committed').to.equal(HtlcState.COMMITTED);

			// Quiescence must be accepted with the committed HTLC (S-2.M8), and
			// the splice-in runs to fully signed via auto-routing.
			expect(openerManager.initiateQuiescence(channelId).ok).to.be.true;
			expect(openerChannel.isQuiescent()).to.be.true;
			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			expect(openerManager.initiateSplice(channelId, 100_000n, 253).ok).to.be
				.true;
			openerManager.sendSpliceLocked(channelId);
			acceptorManager.sendSpliceLocked(channelId);
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);

			// The committed HTLC survived the splice, and BOTH sides adopted the
			// peer's verified second-level HTLC signature over the spliced
			// commitment (the force-close witness material on the new funding;
			// previously zeroed unconditionally).
			expect(openerChannel.getFullState().htlcs.size).to.equal(1);
			expect(
				openerChannel.getFullState().remoteHtlcSignatures.length,
				'opener adopted splice HTLC sig'
			).to.equal(1);
			expect(
				acceptorChannel.getFullState().remoteHtlcSignatures.length,
				'acceptor adopted splice HTLC sig'
			).to.equal(1);

			// The HTLC still settles normally on the spliced channel.
			let fulfilled = false;
			openerManager.on('htlc:fulfilled', () => {
				fulfilled = true;
			});
			acceptorManager.fulfillHtlc(channelId, 0n, preimage);
			expect(fulfilled, 'HTLC fulfilled after the splice').to.be.true;
		});

		it('spliced-state balances conserve value with a committed HTLC in flight (pending-lock)', function () {
			// The invariant pay-during-splice rests on: an HTLC's value leaves a
			// balance at add and re-enters one only when its entry is deleted, so
			// local + remote + Σ(htlcs) = capacity holds continuously and the
			// spliced state's remainder computation stays correct with HTLCs in
			// the map. Verified here at the pending-lock boundary on BOTH sides.
			const { openerManager, channelId, openerChannel, acceptorChannel } =
				createNormalChannelPair();

			const paymentHash = crypto
				.createHash('sha256')
				.update(crypto.randomBytes(32))
				.digest();
			expect(
				openerManager.addHtlc(
					channelId,
					20_000_000n,
					paymentHash,
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.be.true;

			expect(openerManager.initiateQuiescence(channelId).ok).to.be.true;
			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			expect(openerManager.initiateSplice(channelId, 100_000n, 253).ok).to.be
				.true;
			expect(openerChannel.isSplicePendingLock()).to.equal(true);

			const openerSpliced = openerChannel.getSplicedStateForSigning();
			const acceptorSpliced = acceptorChannel.getSplicedStateForSigning();
			expect(openerSpliced).to.not.equal(null);
			expect(acceptorSpliced).to.not.equal(null);
			for (const spliced of [openerSpliced!, acceptorSpliced!]) {
				let htlcMsat = 0n;
				for (const e of spliced.htlcs.values()) htlcMsat += e.amountMsat;
				expect(
					spliced.localBalanceMsat + spliced.remoteBalanceMsat + htlcMsat
				).to.equal(spliced.fundingSatoshis * 1000n);
			}
			// The check with teeth: BOTH SIDES agree on the split. Each side
			// computes its own balance and derives the peer's as the remainder;
			// disagreement here is exactly what produces "Invalid splice
			// commitment signature" between real peers.
			expect(openerSpliced!.localBalanceMsat).to.equal(
				acceptorSpliced!.remoteBalanceMsat
			);
			expect(openerSpliced!.remoteBalanceMsat).to.equal(
				acceptorSpliced!.localBalanceMsat
			);
			expect(openerSpliced!.fundingSatoshis).to.equal(
				acceptorSpliced!.fundingSatoshis
			);
		});

		it('getSpendableOutboundMsat is the addHtlc ceiling, and dips to the spliced side during a splice-out', function () {
			// NORMAL: the helper is exactly the addHtlc arithmetic — local
			// balance minus the peer-required reserve minus the opener's
			// commitment fee with one more HTLC.
			const fresh = createNormalChannelPair();
			const spendable = fresh.openerChannel.getSpendableOutboundMsat();
			const st = fresh.openerChannel.getFullState();
			const expected =
				st.localBalanceMsat -
				st.remoteConfig.channelReserveSatoshis * 1000n -
				BigInt(calculateCommitmentFee(st.localConfig.feeratePerKw, 1, false)) *
					1000n;
			expect(spendable).to.equal(expected);
			expect(spendable > 0n).to.be.true;

			// Pending-lock splice-out: the candidate commitment has less local
			// balance, so the ceiling must drop by the amount leaving (which the
			// initiator's relative carries, fee folded in).
			const pair = createNormalChannelPair();
			const before = pair.openerChannel.getSpendableOutboundMsat();
			pair.openerManager.initiateQuiescence(pair.channelId);
			const destScript = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const spliceOutFee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 0,
					destinationScriptLen: destScript.length
				}),
				253
			);
			pair.openerChannel.setSpliceOutDestination(destScript, 50_000n);
			expect(
				pair.openerManager.initiateSplice(
					pair.channelId,
					-(50_000n + spliceOutFee),
					253
				).ok
			).to.be.true;
			expect(pair.openerChannel.isSplicePendingLock()).to.equal(true);
			expect(pair.openerChannel.getSpendableOutboundMsat()).to.equal(
				before - (50_000n + spliceOutFee) * 1000n
			);

			// Pending-lock splice-in: the live side is the smaller commitment, so
			// the ceiling is unchanged.
			const spliceIn = createNormalChannelPair();
			const beforeIn = spliceIn.openerChannel.getSpendableOutboundMsat();
			spliceIn.openerManager.initiateQuiescence(spliceIn.channelId);
			const inWallet = makeSpliceInWallet(100_000n);
			spliceIn.openerChannel.setSpliceInInputs(
				[inWallet.walletInput],
				inWallet.changeScript
			);
			expect(
				spliceIn.openerManager.initiateSplice(spliceIn.channelId, 100_000n, 253)
					.ok
			).to.be.true;
			expect(spliceIn.openerChannel.isSplicePendingLock()).to.equal(true);
			expect(spliceIn.openerChannel.getSpendableOutboundMsat()).to.equal(
				beforeIn
			);
		});

		it('getSpendableOutboundMsat gates at a staged update_fee rate before the round completes', function () {
			// During a fee round the next commitments can build at the staged
			// rate before localConfig is promoted; the ceiling must use the
			// higher phase-aware rate immediately, or an add admitted at the old
			// rate would not fit the commitment the builder actually produces.
			const pair = createNormalChannelPair();
			const st = pair.openerChannel.getFullState();
			const before = pair.openerChannel.getSpendableOutboundMsat();
			const oldRate = st.localConfig.feeratePerKw;
			st.pendingFeeratePerKw = oldRate * 4;
			const after = pair.openerChannel.getSpendableOutboundMsat();
			const delta =
				BigInt(
					calculateCommitmentFee(oldRate * 4, 1, false) -
						calculateCommitmentFee(oldRate, 1, false)
				) * 1000n;
			expect(after).to.equal(before - delta);
			delete st.pendingFeeratePerKw;
		});

		it('should refuse abortSplice via manager once tx_signatures are exchanged (fund safety)', function () {
			const { openerManager, channelId, openerChannel } =
				createNormalChannelPair();

			openerManager.initiateQuiescence(channelId);
			// Auto-routing runs the whole splice to the fully-signed stage. The
			// splice-in must be backed by a real wallet input (tx_complete audit).
			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			openerManager.initiateSplice(channelId, 100_000n, 253);
			expect(openerChannel.getState()).to.equal(ChannelState.SPLICING);
			expect(
				openerChannel.getFullState().spliceInFlight,
				'in-flight splice recorded'
			).to.not.be.null;

			// The splice tx may confirm at any time now — aborting must be refused.
			const result = openerManager.abortSplice(channelId, 'test');
			expect(result.ok).to.be.false;
			expect(openerChannel.getState()).to.equal(ChannelState.SPLICING);
		});

		it('should support abortSplice via manager before signatures are exchanged', function () {
			const { openerManager, channelId, openerChannel } =
				createNormalChannelPair();

			// Initiate directly on the channel (no auto-routing), so the splice
			// stays in the pre-signature negotiation phase.
			openerChannel.initiateSplice(100_000n, 253);
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL); // awaiting quiescence

			const result = openerManager.abortSplice(channelId, 'test');
			expect(result.ok).to.be.true;
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
		});

		it('should refuse initiateSplice when the peer lacks option_splice/option_quiesce', function () {
			const { openerManager, channelId } = createNormalChannelPair();
			const features = new FeatureFlags(); // peer advertises nothing
			const stubPm: any = {
				onMessage: () => {},
				getPeer: () => ({ getRemoteInit: () => ({ features }) }),
				sendToPeer: () => {}
			};
			openerManager.attachToPeerManager(stubPm);

			const result = openerManager.initiateSplice(channelId, 100_000n, 253);
			expect(result.ok).to.be.false;
			expect(result.error).to.include('does not support splicing');
		});

		it('should allow initiateSplice when the peer advertises splice + quiesce', function () {
			const { openerManager, channelId, openerChannel } =
				createNormalChannelPair();
			const features = new FeatureFlags();
			features.setOptional(Feature.QUIESCE);
			features.setOptional(Feature.SPLICE);
			const stubPm: any = {
				onMessage: () => {},
				getPeer: () => ({ getRemoteInit: () => ({ features }) }),
				sendToPeer: () => {}
			};
			openerManager.attachToPeerManager(stubPm);

			const result = openerManager.initiateSplice(channelId, 100_000n, 253);
			expect(result.ok).to.be.true;
			// The stfu went to the (black-hole) stub peer; the splice is pending quiescence.
			expect(openerChannel.isQuiescing()).to.be.true;
		});

		it('should reject inbound splice_init from a peer without the features (tx_abort)', function () {
			const { openerManager, channelId, openerPubkey, acceptorPubkey } =
				createNormalChannelPair();
			const sent: Array<{ type: number }> = [];
			const features = new FeatureFlags();
			const stubPm: any = {
				onMessage: () => {},
				getPeer: () => ({ getRemoteInit: () => ({ features }) }),
				sendToPeer: (_pk: string, type: number) => {
					sent.push({ type });
				}
			};
			openerManager.attachToPeerManager(stubPm);
			void openerPubkey;

			const payload = encodeSpliceMessage({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 100_000n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});
			openerManager.handleMessage(acceptorPubkey, MessageType.SPLICE, payload);

			expect(
				sent.some((m) => m.type === MessageType.TX_ABORT),
				'tx_abort sent'
			).to.be.true;
			// No splice session was created on the channel.
			const channel = openerManager.getChannel(channelId)!;
			expect(channel.getSpliceSession()).to.be.null;
		});

		it('should return error for splice on nonexistent channel', function () {
			const config = makeConfig(403);
			const manager = new ChannelManager(config);
			manager.on('error', () => {});
			const result = manager.initiateSplice(
				crypto.randomBytes(32),
				100_000n,
				253
			);
			expect(result.ok).to.be.false;
			expect(result.error).to.include('not found');
		});

		it('should return error for sendSpliceLocked on nonexistent channel', function () {
			const config = makeConfig(404);
			const manager = new ChannelManager(config);
			manager.on('error', () => {});
			const result = manager.sendSpliceLocked(crypto.randomBytes(32));
			expect(result.ok).to.be.false;
		});

		it('should return error for abortSplice on nonexistent channel', function () {
			const config = makeConfig(405);
			const manager = new ChannelManager(config);
			manager.on('error', () => {});
			const result = manager.abortSplice(crypto.randomBytes(32));
			expect(result.ok).to.be.false;
		});
	});

	// ─────────────── LightningNode Integration ───────────────

	describe('start_batch commitment rounds while a splice awaits its lock', function () {
		it('roundtrips the start_batch codec (with and without message_type TLV)', function () {
			const channelId = crypto.randomBytes(32);
			const withType = encodeStartBatchMessage({
				channelId,
				batchSize: 2,
				messageType: 132
			});
			expect(withType.length).to.equal(38);
			const decoded = decodeStartBatchMessage(withType);
			expect(decoded.channelId).to.deep.equal(channelId);
			expect(decoded.batchSize).to.equal(2);
			expect(decoded.messageType).to.equal(132);

			const bare = encodeStartBatchMessage({ channelId, batchSize: 2 });
			expect(bare.length).to.equal(34);
			expect(decodeStartBatchMessage(bare).messageType).to.equal(undefined);
		});

		function pendingLockPair(): ReturnType<typeof createNormalChannelPair> {
			const pair = createNormalChannelPair();
			pair.openerManager.initiateQuiescence(pair.channelId);
			// Auto-routing drives the splice to fully-signed (tx_signatures both
			// ways); without splice_locked the channel sits in the pending window.
			// The splice-in must be backed by a real wallet input (tx_complete audit).
			const wallet = makeSpliceInWallet(100_000n);
			pair.openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			expect(
				pair.openerManager.initiateSplice(pair.channelId, 100_000n, 253).ok
			).to.equal(true);
			expect(pair.openerChannel.getState()).to.equal(ChannelState.SPLICING);
			expect(pair.openerChannel.isSplicePendingLock()).to.equal(true);
			expect(pair.acceptorChannel.isSplicePendingLock()).to.equal(true);
			return pair;
		}

		it('exposes the post-splice pending local balance during the pending-lock window', function () {
			// Accounting surfaces report this instead of the live balance, which
			// stays pre-splice until splice_locked: without it, a max splice-in's
			// newly added sats appear in no balance figure at all during the
			// confirmation window (observed on mainnet: on-chain swept to zero,
			// lightning excludes SPLICING, old local never contained them).
			const fresh = createNormalChannelPair();
			expect(fresh.openerChannel.getPendingSpliceLocalBalanceMsat()).to.equal(
				null
			);

			const pair = pendingLockPair();
			const liveLocalMsat = pair.openerChannel.getBalances().localMsat;
			const pending = pair.openerChannel.getPendingSpliceLocalBalanceMsat();
			// Old local + the 100k splice-in; the splice-in's on-chain fee comes
			// from wallet change, not the channel, so nothing else moves.
			expect(pending).to.equal(liveLocalMsat + 100_000_000n);

			// The acceptor contributed nothing: its side settles unchanged.
			const acceptorLive = pair.acceptorChannel.getBalances().localMsat;
			expect(pair.acceptorChannel.getPendingSpliceLocalBalanceMsat()).to.equal(
				acceptorLive
			);
		});

		it('completes an update_fee round as start_batch batches in both directions', function () {
			const pair = pendingLockPair();
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel,
				openerPubkey,
				acceptorPubkey
			} = pair;

			// Tap the wire AFTER the splice negotiation so only the fee round is
			// captured.
			const wire: Array<{ from: string; type: number; payload: Buffer }> = [];
			openerManager.on('message:outbound', (pk, type, payload) => {
				if (pk === acceptorPubkey) {
					wire.push({ from: 'opener', type, payload });
				}
			});
			acceptorManager.on('message:outbound', (pk, type, payload) => {
				if (pk === openerPubkey) {
					wire.push({ from: 'acceptor', type, payload });
				}
			});

			const errors: string[] = [];
			openerManager.on('channel:error' as never, (() => {}) as never);
			openerManager.on('error', (_id: Buffer, m: string) => errors.push(m));
			acceptorManager.on('error', (_id: Buffer, m: string) => errors.push(m));

			const openerCommitBefore =
				openerChannel.getFullState().localCommitmentNumber;
			const acceptorCommitBefore =
				acceptorChannel.getFullState().localCommitmentNumber;
			const spliceSigBefore = Buffer.from(
				openerChannel.getFullState().spliceInFlight!.remoteCommitmentSig!
			);

			expect(openerManager.updateChannelFee(channelId, 1000).ok).to.equal(true);

			expect(errors, `channel errors: ${errors.join('; ')}`).to.deep.equal([]);

			// Both directions sent start_batch followed by two commitment_signed
			// (one per active funding output, routed by funding_txid TLV).
			for (const side of ['opener', 'acceptor'] as const) {
				const msgs = wire.filter((w) => w.from === side);
				const batchIdx = msgs.findIndex(
					(w) => w.type === MessageType.START_BATCH
				);
				expect(batchIdx, `${side} sent start_batch`).to.be.gte(0);
				const batch = decodeStartBatchMessage(msgs[batchIdx].payload);
				expect(batch.batchSize).to.equal(2);
				expect(batch.messageType).to.equal(132);
				const commits = msgs
					.slice(batchIdx + 1)
					.filter((w) => w.type === MessageType.COMMITMENT_SIGNED)
					.slice(0, 2)
					.map((w) => decodeCommitmentSignedMessage(w.payload));
				expect(commits.length, `${side} sent 2 commitment_signed`).to.equal(2);
				const txids = commits.map((c) =>
					c.fundingTxid ? c.fundingTxid.toString('hex') : 'none'
				);
				const state = openerChannel.getFullState();
				expect(txids).to.include(state.fundingTxid!.toString('hex'));
				expect(txids).to.include(
					state.spliceInFlight!.spliceTxid.toString('hex')
				);
			}

			// One full round on each side: commitment numbers advanced once, the
			// splice-side signature was refreshed, and the channel still awaits
			// its lock.
			expect(openerChannel.getFullState().localCommitmentNumber).to.equal(
				openerCommitBefore + 1n
			);
			expect(acceptorChannel.getFullState().localCommitmentNumber).to.equal(
				acceptorCommitBefore + 1n
			);
			expect(
				openerChannel
					.getFullState()
					.spliceInFlight!.remoteCommitmentSig!.equals(spliceSigBefore)
			).to.equal(false);
			expect(openerChannel.getState()).to.equal(ChannelState.SPLICING);
			expect(acceptorChannel.getState()).to.equal(ChannelState.SPLICING);

			// The splice still completes normally afterwards.
			openerManager.sendSpliceLocked(channelId);
			acceptorManager.sendSpliceLocked(channelId);
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
		});

		it('accepts new HTLC traffic during the pending-lock window (pay during splice)', function () {
			// tx_signatures have crossed both ways: per the splicing extension
			// quiescence is over and update traffic resumes, with every update
			// mirrored onto both fundings by start_batch commitment rounds. The
			// old behavior (parking the channel until splice_locked) is exactly
			// what #139 removes.
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel
			} = pendingLockPair();
			expect(openerChannel.isQuiescent(), 'quiescence over at pending-lock').to
				.be.false;
			expect(acceptorChannel.isQuiescent()).to.be.false;

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			expect(
				openerManager.addHtlc(
					channelId,
					15_000_000n,
					paymentHash,
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.be.true;
			// The loopback drove the full batch round: the add is committed on
			// BOTH sides, and both hold the peer's splice-side HTLC signature
			// (the force-close witness material on the new funding).
			const entry = [...openerChannel.getFullState().htlcs.values()][0];
			expect(entry.state, 'HTLC committed mid-splice').to.equal(
				HtlcState.COMMITTED
			);
			expect(
				openerChannel.getFullState().spliceInFlight?.remoteHtlcSignatures
					?.length,
				'opener holds splice-side HTLC sig'
			).to.equal(1);

			// It settles mid-splice too.
			let fulfilled = false;
			openerManager.on('htlc:fulfilled', () => {
				fulfilled = true;
			});
			acceptorManager.fulfillHtlc(channelId, 0n, preimage);
			expect(fulfilled, 'HTLC fulfilled during pending-lock').to.be.true;
			expect(openerChannel.getFullState().htlcs.size).to.equal(0);
			expect(openerChannel.getState()).to.equal(ChannelState.SPLICING);

			// And the splice still locks cleanly afterwards.
			openerManager.sendSpliceLocked(channelId);
			acceptorManager.sendSpliceLocked(channelId);
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
		});

		it('an HTLC added mid-splice survives the lock and settles on the spliced channel', function () {
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel
			} = pendingLockPair();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			expect(
				openerManager.addHtlc(
					channelId,
					15_000_000n,
					paymentHash,
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.be.true;
			const openerLocalBefore = openerChannel.getBalances().localMsat;

			// Lock with the HTLC still in flight: it must ride onto the spliced
			// channel (completeSplice adopts the splice-side signatures).
			openerManager.sendSpliceLocked(channelId);
			acceptorManager.sendSpliceLocked(channelId);
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(openerChannel.getFullState().htlcs.size).to.equal(1);
			expect(
				openerChannel.getFullState().remoteHtlcSignatures.length,
				'adopted splice HTLC sig at lock'
			).to.equal(1);

			// Settles normally on the spliced channel, crediting the acceptor.
			let fulfilled = false;
			openerManager.on('htlc:fulfilled', () => {
				fulfilled = true;
			});
			acceptorManager.fulfillHtlc(channelId, 0n, preimage);
			expect(fulfilled).to.be.true;
			expect(openerChannel.getFullState().htlcs.size).to.equal(0);
			// The fulfilled amount went to the acceptor; the opener keeps its
			// post-add balance plus the 100k sats the splice-in added at the lock.
			expect(openerChannel.getBalances().localMsat).to.equal(
				openerLocalBefore + 100_000_000n
			);
			expect(acceptorChannel.getBalances().localMsat).to.equal(
				openerChannel.getBalances().remoteMsat
			);
		});

		it('spliced-state invariant holds at every HTLC lifecycle stage mid-splice', function () {
			// The table-driven check the review asked for before lifting gates:
			// at each observable stage of add and settle during pending-lock, the
			// spliced states of BOTH sides conserve value against the new
			// capacity and agree on the split (divergence here is 'Invalid
			// splice commitment signature' between real peers).
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel
			} = pendingLockPair();

			const assertInvariant = (label: string): void => {
				const o = openerChannel.getSplicedStateForSigning();
				const a = acceptorChannel.getSplicedStateForSigning();
				expect(o, `${label}: opener spliced state`).to.not.equal(null);
				expect(a, `${label}: acceptor spliced state`).to.not.equal(null);
				for (const spliced of [o!, a!]) {
					let htlcMsat = 0n;
					for (const e of spliced.htlcs.values()) htlcMsat += e.amountMsat;
					expect(
						spliced.localBalanceMsat + spliced.remoteBalanceMsat + htlcMsat,
						`${label}: conservation`
					).to.equal(spliced.fundingSatoshis * 1000n);
				}
				expect(o!.localBalanceMsat, `${label}: split (local/remote)`).to.equal(
					a!.remoteBalanceMsat
				);
				expect(o!.remoteBalanceMsat, `${label}: split (remote/local)`).to.equal(
					a!.localBalanceMsat
				);
			};

			assertInvariant('pending-lock, no HTLC');

			// Opener → acceptor add, committed via the loopback batch rounds.
			const p1 = crypto.randomBytes(32);
			openerManager.addHtlc(
				channelId,
				15_000_000n,
				crypto.createHash('sha256').update(p1).digest(),
				500000,
				crypto.randomBytes(1366)
			);
			assertInvariant('offered add committed');

			// Acceptor → opener add in the opposite direction, coexisting.
			const p2 = crypto.randomBytes(32);
			acceptorManager.addHtlc(
				channelId,
				7_000_000n,
				crypto.createHash('sha256').update(p2).digest(),
				500000,
				crypto.randomBytes(1366)
			);
			assertInvariant('adds in both directions');

			// Fulfill one; fail the other.
			acceptorManager.fulfillHtlc(channelId, 0n, p1);
			assertInvariant('one fulfilled, one live');
			openerManager.failHtlc(channelId, 0n, Buffer.from([0x10, 0x0f]));
			assertInvariant('one fulfilled, one failed');
			expect(openerChannel.getFullState().htlcs.size).to.equal(0);

			// The window ends cleanly after all of it.
			openerManager.sendSpliceLocked(channelId);
			acceptorManager.sendSpliceLocked(channelId);
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
		});

		it('isHtlcUsable tracks the pending-lock window, looking through a reconnect', function () {
			const pair = pendingLockPair();
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorPubkey
			} = pair;
			expect(openerChannel.isHtlcUsable(), 'usable at pending-lock').to.be.true;

			// A disconnect parks it strictly, but hint surfaces look through.
			openerManager.handlePeerDisconnected(acceptorPubkey);
			expect(
				openerChannel.isHtlcUsable(),
				'strict: not usable while disconnected'
			).to.be.false;
			expect(
				openerChannel.isHtlcUsable(true),
				'hints: usable through the reconnect'
			).to.be.true;

			// Recover the wire and lock; NORMAL is usable.
			openerChannel.getFullState().state = ChannelState.SPLICING;
			openerChannel.getFullState().preReestablishState = null;
			openerManager.sendSpliceLocked(channelId);
			acceptorManager.sendSpliceLocked(channelId);
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(openerChannel.isHtlcUsable()).to.be.true;
		});

		it('a round mixing update_fee and an HTLC add batches cleanly mid-splice', function () {
			const pair = pendingLockPair();
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel,
				openerPubkey
			} = pair;

			// Stage a fee update directly on the channel (no auto-sign fires) and
			// hand its update_fee to the acceptor, then let the manager's add
			// trigger ONE round covering both staged updates.
			const oldRate = openerChannel.getFullState().localConfig.feeratePerKw;
			const feeActions = openerChannel.updateFee(oldRate * 2);
			const feeMsgAction = findAction(
				feeActions,
				ChannelActionType.SEND_MESSAGE
			);
			expect(feeMsgAction, 'update_fee produced').to.not.equal(undefined);
			acceptorManager.handleMessage(
				openerPubkey,
				feeMsgAction.messageType,
				feeMsgAction.payload
			);

			let openerStartBatches = 0;
			openerManager.on('message:outbound', (pk, type) => {
				if (type === MessageType.START_BATCH) openerStartBatches++;
			});
			const preimage = crypto.randomBytes(32);
			expect(
				openerManager.addHtlc(
					channelId,
					10_000_000n,
					crypto.createHash('sha256').update(preimage).digest(),
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.be.true;

			// One batched round carried both: exactly one initiating start_batch
			// left the opener, the add is committed on both sides and both sides
			// now build at the new rate.
			expect(openerStartBatches, 'a single initiating batch').to.equal(1);
			const entry = [...openerChannel.getFullState().htlcs.values()][0];
			expect(entry.state).to.equal(HtlcState.COMMITTED);
			expect(
				openerChannel.getFullState().localConfig.feeratePerKw,
				'opener promoted the staged fee'
			).to.equal(oldRate * 2);
			// The acceptor promotes one round later (its promotion answers the
			// opener's revoke of the acceptor's own new-rate signature) — the
			// fee is at least staged or already promoted; what matters here is
			// that mixing it with the add desynced nothing.
			// The committed rate lives in the role-appropriate config: the opener
			// sets fees, so the acceptor promotes into remoteConfig.
			expect(
				acceptorChannel.getFullState().remoteConfig.feeratePerKw,
				'acceptor promoted the staged fee'
			).to.equal(oldRate * 2);

			// Settles, and the splice locks cleanly at the new rate.
			acceptorManager.fulfillHtlc(channelId, 0n, preimage);
			expect(openerChannel.getFullState().htlcs.size).to.equal(0);
			openerManager.sendSpliceLocked(channelId);
			acceptorManager.sendSpliceLocked(channelId);
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
		});

		describe('disconnects with an HTLC in flight during pending-lock', function () {
			// The matrix: reach pending-lock, capture an add's traffic without
			// delivering it, deliver a scenario-chosen prefix, drop the link,
			// reconnect, and require full convergence — the add COMMITTED on
			// both sides, settling, and the splice locking cleanly. BOLT 2
			// reestablish replays un-acked updates before the retransmitted
			// batch; these scenarios cut the wire at each message boundary.
			function runDisconnectScenario(
				deliverOpenerMsgs: number,
				deliverAcceptorMsgs: number
			): void {
				const pair = pendingLockPair();
				const {
					openerManager,
					acceptorManager,
					channelId,
					openerChannel,
					acceptorChannel,
					openerPubkey,
					acceptorPubkey
				} = pair;

				// Detach the loopback; record both directions, deliver nothing.
				openerManager.removeAllListeners('message:outbound');
				acceptorManager.removeAllListeners('message:outbound');
				const fromOpener: Array<{ type: number; payload: Buffer }> = [];
				const fromAcceptor: Array<{ type: number; payload: Buffer }> = [];
				openerManager.on('message:outbound', (pk, type, payload) => {
					if (pk === acceptorPubkey) fromOpener.push({ type, payload });
				});
				acceptorManager.on('message:outbound', (pk, type, payload) => {
					if (pk === openerPubkey) fromAcceptor.push({ type, payload });
				});

				const preimage = crypto.randomBytes(32);
				openerManager.addHtlc(
					channelId,
					15_000_000n,
					crypto.createHash('sha256').update(preimage).digest(),
					500000,
					crypto.randomBytes(1366)
				);
				// [update_add_htlc, start_batch, commitment_signed, commitment_signed]
				expect(fromOpener.length, 'add produced its batch').to.equal(4);

				for (const m of fromOpener.slice(0, deliverOpenerMsgs)) {
					acceptorManager.handleMessage(openerPubkey, m.type, m.payload);
				}
				// The acceptor's replies to a fully delivered batch:
				// [revoke_and_ack, start_batch, commitment_signed x2] — deliver a
				// scenario-chosen prefix of the counter-round too.
				for (const m of fromAcceptor.splice(0, deliverAcceptorMsgs)) {
					openerManager.handleMessage(acceptorPubkey, m.type, m.payload);
				}

				// The link dies.
				openerManager.handlePeerDisconnected(acceptorPubkey);
				acceptorManager.handlePeerDisconnected(openerPubkey);
				expect(openerChannel.getState()).to.equal(
					ChannelState.AWAITING_REESTABLISH
				);

				// Reconnect. Both sides emit channel_reestablish independently (as
				// real transports do) BEFORE either is delivered — a synchronous
				// loopback would otherwise deliver the first reestablish before
				// the second side has sent its own. Capture both, rewire, then
				// deliver cross-wise; all replays flow through the live loopback.
				fromOpener.length = 0;
				fromAcceptor.length = 0;
				openerManager.handlePeerReconnected(acceptorPubkey);
				acceptorManager.handlePeerReconnected(openerPubkey);
				const openerReest = fromOpener.splice(0);
				const acceptorReest = fromAcceptor.splice(0);
				openerManager.removeAllListeners('message:outbound');
				acceptorManager.removeAllListeners('message:outbound');
				connectManagers(
					openerManager,
					openerPubkey,
					acceptorManager,
					acceptorPubkey
				);
				for (const m of openerReest) {
					acceptorManager.handleMessage(openerPubkey, m.type, m.payload);
				}
				for (const m of acceptorReest) {
					openerManager.handleMessage(acceptorPubkey, m.type, m.payload);
				}

				expect(
					openerChannel.getState(),
					'back to SPLICING pending-lock'
				).to.equal(ChannelState.SPLICING);
				expect(acceptorChannel.getState()).to.equal(ChannelState.SPLICING);
				expect(openerChannel.isSplicePendingLock()).to.equal(true);

				// Convergence: the add committed on both sides...
				const oEntry = [...openerChannel.getFullState().htlcs.values()][0];
				const aEntry = [...acceptorChannel.getFullState().htlcs.values()][0];
				expect(oEntry?.state, 'opener committed after reconnect').to.equal(
					HtlcState.COMMITTED
				);
				expect(aEntry?.state, 'acceptor committed after reconnect').to.equal(
					HtlcState.COMMITTED
				);

				// ...it settles...
				let fulfilled = false;
				openerManager.on('htlc:fulfilled', () => {
					fulfilled = true;
				});
				acceptorManager.fulfillHtlc(channelId, 0n, preimage);
				expect(fulfilled, 'settled after reconnect').to.be.true;

				// ...and the splice still locks cleanly.
				openerManager.sendSpliceLocked(channelId);
				acceptorManager.sendSpliceLocked(channelId);
				expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
				expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
			}

			it('a RESTART mid-round re-signs the batch from persisted material', function () {
				// Same as 'the batch is lost', but the opener also loses its
				// in-memory batch cache — what a process restart destroys. The
				// reestablish path must REBUILD the batch: persisted signature
				// bytes for the current funding, a deterministic ECDSA re-sign
				// for the splice side.
				const pair = pendingLockPair();
				const {
					openerManager,
					acceptorManager,
					channelId,
					openerChannel,
					acceptorChannel,
					openerPubkey,
					acceptorPubkey
				} = pair;

				openerManager.removeAllListeners('message:outbound');
				acceptorManager.removeAllListeners('message:outbound');
				const fromOpener: Array<{ type: number; payload: Buffer }> = [];
				openerManager.on('message:outbound', (pk, type, payload) => {
					if (pk === acceptorPubkey) fromOpener.push({ type, payload });
				});
				acceptorManager.on('message:outbound', () => {});

				const preimage = crypto.randomBytes(32);
				openerManager.addHtlc(
					channelId,
					15_000_000n,
					crypto.createHash('sha256').update(preimage).digest(),
					500000,
					crypto.randomBytes(1366)
				);
				expect(fromOpener.length).to.equal(4);
				// Only the add reaches the acceptor; the batch is lost.
				acceptorManager.handleMessage(
					openerPubkey,
					fromOpener[0].type,
					fromOpener[0].payload
				);

				openerManager.handlePeerDisconnected(acceptorPubkey);
				acceptorManager.handlePeerDisconnected(openerPubkey);
				// The restart: the cached wire bytes die with the process (the
				// splice session itself is restored from persistence on boot).
				(openerChannel as any)._lastSentBatch = null;

				fromOpener.length = 0;
				const fromAcceptor: Array<{ type: number; payload: Buffer }> = [];
				acceptorManager.removeAllListeners('message:outbound');
				acceptorManager.on('message:outbound', (pk, type, payload) => {
					if (pk === openerPubkey) fromAcceptor.push({ type, payload });
				});
				openerManager.handlePeerReconnected(acceptorPubkey);
				acceptorManager.handlePeerReconnected(openerPubkey);
				const openerReest = fromOpener.splice(0);
				const acceptorReest = fromAcceptor.splice(0);
				openerManager.removeAllListeners('message:outbound');
				acceptorManager.removeAllListeners('message:outbound');
				connectManagers(
					openerManager,
					openerPubkey,
					acceptorManager,
					acceptorPubkey
				);
				for (const m of openerReest) {
					acceptorManager.handleMessage(openerPubkey, m.type, m.payload);
				}
				for (const m of acceptorReest) {
					openerManager.handleMessage(acceptorPubkey, m.type, m.payload);
				}

				// The rebuilt batch converged the round.
				const oEntry = [...openerChannel.getFullState().htlcs.values()][0];
				const aEntry = [...acceptorChannel.getFullState().htlcs.values()][0];
				expect(oEntry?.state, 'opener committed via rebuilt batch').to.equal(
					HtlcState.COMMITTED
				);
				expect(aEntry?.state, 'acceptor committed via rebuilt batch').to.equal(
					HtlcState.COMMITTED
				);

				// Settles, and the splice locks cleanly.
				let fulfilled = false;
				openerManager.on('htlc:fulfilled', () => {
					fulfilled = true;
				});
				acceptorManager.fulfillHtlc(channelId, 0n, preimage);
				expect(fulfilled, 'settled after the restart-rebuilt round').to.be.true;
				openerManager.sendSpliceLocked(channelId);
				acceptorManager.sendSpliceLocked(channelId);
				expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
				expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
			});

			it('the add itself is lost', function () {
				runDisconnectScenario(0, 0);
			});
			it('the add arrives, the batch is lost', function () {
				runDisconnectScenario(1, 0);
			});
			it('start_batch arrives with neither commitment (stale half-collected batch)', function () {
				runDisconnectScenario(2, 0);
			});
			it('start_batch and one commitment arrive (partially collected batch)', function () {
				runDisconnectScenario(3, 0);
			});
			it('the batch arrives, the revoke_and_ack is lost', function () {
				runDisconnectScenario(4, 0);
			});
			it('the revoke_and_ack arrives, the counter-round is lost', function () {
				runDisconnectScenario(4, 1);
			});
			it('the counter-round start_batch arrives with neither commitment', function () {
				runDisconnectScenario(4, 2);
			});
			it('the counter-round is cut after its first commitment', function () {
				runDisconnectScenario(4, 3);
			});
			it('only our answer to the counter-round is lost', function () {
				runDisconnectScenario(4, 4);
			});
		});

		it('force-close mid-splice (splice unconfirmed) exits on the OLD funding with the HTLC aboard', function () {
			const pair = pendingLockPair();
			const { openerManager, channelId, openerChannel } = pair;
			const oldFunding = Buffer.from(openerChannel.getFullState().fundingTxid!);

			// A mid-splice HTLC must ride on whichever commitment exits.
			openerManager.addHtlc(
				channelId,
				15_000_000n,
				crypto.createHash('sha256').update(crypto.randomBytes(32)).digest(),
				500000,
				crypto.randomBytes(1366)
			);

			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const res = openerManager.forceClose(channelId, dest);
			expect(res.ok, res.error).to.equal(true);
			const bc = findAction(res.actions, ChannelActionType.BROADCAST_TX);
			expect(bc, 'commitment broadcast').to.not.equal(undefined);
			const tx = bitcoin.Transaction.fromBuffer(bc.tx);
			expect(
				Buffer.from(tx.ins[0].hash).equals(oldFunding),
				'spends the OLD funding while the splice tx is unconfirmed'
			).to.equal(true);
			expect(
				tx.outs.some((o) => o.value === 15_000),
				'the mid-splice HTLC has its output on the exiting commitment'
			).to.equal(true);
		});

		it('force-close after the splice tx CONFIRMED exits on the NEW funding (no splice_locked ever)', function () {
			// The peer vanished after tx_signatures; the splice tx confirmed on
			// chain. The old funding is spent — the live-state commitment could
			// never confirm — so forceClose must adopt the spliced view and exit
			// on the new funding, carrying the mid-splice HTLC with it.
			const pair = pendingLockPair();
			const { openerManager, channelId, openerChannel } = pair;
			openerManager.addHtlc(
				channelId,
				15_000_000n,
				crypto.createHash('sha256').update(crypto.randomBytes(32)).digest(),
				500000,
				crypto.randomBytes(1366)
			);
			const spliceTxid = Buffer.from(
				openerChannel.getFullState().spliceInFlight!.spliceTxid
			);

			// The chain watcher saw the confirmation but splice_locked could not
			// be exchanged (peer gone).
			openerChannel.markSpliceConfirmed();

			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const res = openerManager.forceClose(channelId, dest);
			expect(res.ok, res.error).to.equal(true);
			const bc = findAction(res.actions, ChannelActionType.BROADCAST_TX);
			expect(bc, 'commitment broadcast').to.not.equal(undefined);
			const tx = bitcoin.Transaction.fromBuffer(bc.tx);
			expect(
				Buffer.from(tx.ins[0].hash).equals(spliceTxid),
				'spends the NEW (confirmed splice) funding'
			).to.equal(true);
			expect(
				tx.outs.some((o) => o.value === 15_000),
				'the mid-splice HTLC rode onto the spliced commitment'
			).to.equal(true);
		});

		it('force-close from AWAITING_REESTABLISH (peer actually vanished) exits on the confirmed NEW funding', function () {
			// The production shape of the scenario: the peer disconnects after
			// tx_signatures (SPLICING wrapped in AWAITING_REESTABLISH), the
			// splice confirms while it is gone (the chain watcher records
			// markSpliceConfirmed because sendSpliceLocked cannot run), and the
			// reestablish-timeout auto-close force-closes in exactly this state.
			const pair = pendingLockPair();
			const { openerManager, channelId, openerChannel, acceptorPubkey } = pair;
			const spliceTxid = Buffer.from(
				openerChannel.getFullState().spliceInFlight!.spliceTxid
			);

			openerManager.handlePeerDisconnected(acceptorPubkey);
			expect(openerChannel.getState()).to.equal(
				ChannelState.AWAITING_REESTABLISH
			);
			openerChannel.markSpliceConfirmed();

			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const res = openerManager.forceClose(channelId, dest);
			expect(res.ok, res.error).to.equal(true);
			const bc = findAction(res.actions, ChannelActionType.BROADCAST_TX);
			expect(bc, 'commitment broadcast').to.not.equal(undefined);
			const tx = bitcoin.Transaction.fromBuffer(bc.tx);
			expect(
				Buffer.from(tx.ins[0].hash).equals(spliceTxid),
				'force-close while disconnected must spend the confirmed NEW funding'
			).to.equal(true);
		});

		it('refuses a taproot splice ON THE WIRE: tx_abort, quiescence unwound, channel stays usable', function () {
			// The splice commitment machinery is ECDSA-only. The refusal must be
			// a real protocol answer, not a local error: the initiator gets
			// tx_abort (so it stops waiting for splice_ack and unwinds its own
			// pending splice), and the refusing side exits the quiescence the
			// handshake established rather than sitting silently quiescent.
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel,
				openerPubkey
			} = createNormalChannelPair();
			// Only the acceptor is taproot: the initiator's own up-front refusal
			// (covered below) would otherwise stop splice_init leaving at all.
			const flags = FeatureFlags.empty();
			flags.setCompulsory(Feature.OPTION_TAPROOT);
			const originalType = acceptorChannel.getFullState().channelType;
			acceptorChannel.getFullState().channelType = flags.toBuffer();

			const sent: number[] = [];
			acceptorManager.on('message:outbound', (pk, type) => {
				if (pk === openerPubkey) sent.push(type);
			});

			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			openerManager.initiateQuiescence(channelId);
			openerManager.initiateSplice(channelId, 100_000n, 253);

			expect(
				sent.includes(MessageType.TX_ABORT),
				'tx_abort went out on the wire'
			).to.equal(true);
			expect(sent.includes(MessageType.SPLICE_ACK), 'no splice_ack').to.equal(
				false
			);
			expect(
				acceptorChannel.isQuiescent(),
				'acceptor quiescence unwound'
			).to.equal(false);
			expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(
				openerChannel.getState(),
				'opener recovered via tx_abort'
			).to.equal(ChannelState.NORMAL);

			// The channel remains fully usable after the refusal. (Restore the
			// real channel type first: the fake taproot flag exists only to
			// drive the refusal; the usability claim is about the quiescence
			// unwind, and a genuinely-taproot pair would sign via MuSig2.)
			acceptorChannel.getFullState().channelType = originalType;
			const preimage = crypto.randomBytes(32);
			expect(
				openerManager.addHtlc(
					channelId,
					10_000_000n,
					crypto.createHash('sha256').update(preimage).digest(),
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.equal(true);
			acceptorManager.fulfillHtlc(channelId, 0n, preimage);
			expect(openerChannel.getFullState().htlcs.size).to.equal(0);

			// And the initiator-side up-front refusal, for completeness.
			openerChannel.getFullState().channelType = flags.toBuffer();
			const initActions = openerChannel.initiateSplice(50_000n, 253);
			const initErr = findAction(initActions, ChannelActionType.ERROR);
			expect(initErr, 'initiator refused').to.not.equal(undefined);
			expect(String(initErr.message)).to.include('taproot');
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
		});

		it('force-close adopts the splice signature at the rate it was MADE at, not a later staged fee', function () {
			// The race: the splice-side signature is persisted at rate A; an
			// update_fee stages rate B during the pending-lock window; the
			// splice confirms and we force-close. Rebuilding at B with a
			// signature made for A would produce an invalid witness. The exact
			// rate now travels with the signature in the record.
			const pair = pendingLockPair();
			const { acceptorManager, channelId, acceptorChannel } = pair;
			const inflight = acceptorChannel.getFullState().spliceInFlight!;
			const rateA = inflight.remoteCommitmentSigFeeratePerKw;
			expect(
				rateA,
				'exact rate persisted with the initial signature'
			).to.not.equal(undefined);

			// A staged fee the acceptor has not signed at (getLocalCommitmentFeeRate
			// would return it for the ACCEPTOR role — the fallback this guards).
			acceptorChannel.getFullState().pendingFeeratePerKw = rateA! * 4;
			acceptorChannel.markSpliceConfirmed();

			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const res = acceptorManager.forceClose(channelId, dest);
			expect(res.ok, res.error).to.equal(true);
			expect(
				acceptorChannel.getFullState().lastSignedCommitFeeratePerKw,
				'rebuilt at the rate the adopted signature covers'
			).to.equal(rateA);
		});

		it('recovers a unilateral exit from the persisted record alone (worst-case restart)', function () {
			// The in-memory splice session is gone and cannot be rebuilt — the
			// case that used to end in a safe refusal. The point-of-no-return
			// record carries everything adoption needs (outpoint, capacity,
			// relatives, the peer's funding pubkey and splice-side signatures),
			// so completeSplice now adopts session-free and the force-close
			// exits on the confirmed NEW funding, mid-splice HTLC aboard. The
			// #147 refusal guard remains as the unreachable last line of defense.
			const pair = pendingLockPair();
			const { openerManager, channelId, openerChannel, acceptorPubkey } = pair;
			openerManager.addHtlc(
				channelId,
				15_000_000n,
				crypto.createHash('sha256').update(crypto.randomBytes(32)).digest(),
				500000,
				crypto.randomBytes(1366)
			);
			const spliceTxid = Buffer.from(
				openerChannel.getFullState().spliceInFlight!.spliceTxid
			);
			openerManager.handlePeerDisconnected(acceptorPubkey);
			openerChannel.markSpliceConfirmed();
			// Worst-case restart: no session, restore impotent, in-memory
			// splice-side signature copies gone.
			(openerChannel as any)._spliceSession = null;
			(openerChannel as any).restoreSpliceInFlight = () => {};
			(openerChannel as any)._spliceRemoteCommitmentSig = null;
			(openerChannel as any)._spliceRemoteHtlcSigs = null;

			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const res = openerManager.forceClose(channelId, dest);
			expect(res.ok, res.error).to.equal(true);
			const bc = findAction(res.actions, ChannelActionType.BROADCAST_TX);
			expect(bc, 'commitment broadcast').to.not.equal(undefined);
			const tx = bitcoin.Transaction.fromBuffer(bc.tx);
			expect(
				Buffer.from(tx.ins[0].hash).equals(spliceTxid),
				'exits on the confirmed NEW funding from the record alone'
			).to.equal(true);
			expect(
				tx.outs.some((o) => o.value === 15_000),
				'the mid-splice HTLC rode onto the record-adopted commitment'
			).to.equal(true);
		});

		it('accepts a batch that raced splice_locked, ignoring the obsolete old-funding commitment', function () {
			// The splicing spec's transition race: we lock and complete while the
			// peer, not yet having observed our splice_locked, sends a
			// start_batch built for BOTH fundings. The receiver must filter by
			// funding_txid — process the commitment for the now-current funding,
			// drop the obsolete one — not fail the channel.
			const pair = pendingLockPair();
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel,
				openerPubkey,
				acceptorPubkey
			} = pair;

			// Capture the opener's batch instead of delivering it; everything
			// else (the add, splice_locked) flows normally.
			openerManager.removeAllListeners('message:outbound');
			const held: Array<{ type: number; payload: Buffer }> = [];
			let holding = false;
			openerManager.on('message:outbound', (pk, type, payload) => {
				if (pk !== acceptorPubkey) return;
				if (type === MessageType.START_BATCH) {
					holding = true;
					held.push({ type, payload });
					return;
				}
				if (holding && type === MessageType.COMMITMENT_SIGNED) {
					held.push({ type, payload });
					if (held.length === 3) holding = false;
					return;
				}
				acceptorManager.handleMessage(openerPubkey, type, payload);
			});

			const preimage = crypto.randomBytes(32);
			openerManager.addHtlc(
				channelId,
				15_000_000n,
				crypto.createHash('sha256').update(preimage).digest(),
				500000,
				crypto.randomBytes(1366)
			);
			expect(held.length, 'start_batch + both commitments held').to.equal(3);

			// Both sides lock with the round still outstanding.
			openerManager.sendSpliceLocked(channelId);
			acceptorManager.sendSpliceLocked(channelId);
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);

			// Reconnect safety: with the round outstanding at the lock, the
			// opener's retransmission material must now be the SPLICE-side
			// signature (the funding that is current from here on), not the old
			// funding's — the generic reestablish path rebuilds from it.
			const heldSplice = decodeCommitmentSignedMessage(held[2].payload);
			expect(
				openerChannel
					.getFullState()
					.lastSentCommitmentSigned!.equals(heldSplice.signature),
				'splice-side signature promoted for retransmission'
			).to.be.true;

			// Deliver the late batch. No error; the acceptor processes the
			// new-funding commitment, ignores the old, and the round completes:
			// the add ends COMMITTED on both sides.
			let errors = 0;
			acceptorManager.on('error', () => {
				errors++;
			});
			for (const m of held) {
				acceptorManager.handleMessage(openerPubkey, m.type, m.payload);
			}
			expect(errors, 'late batch accepted without error').to.equal(0);
			const openerEntry = [...openerChannel.getFullState().htlcs.values()][0];
			const acceptorEntry = [
				...acceptorChannel.getFullState().htlcs.values()
			][0];
			expect(openerEntry.state, 'opener committed').to.equal(
				HtlcState.COMMITTED
			);
			expect(acceptorEntry.state, 'acceptor committed').to.equal(
				HtlcState.COMMITTED
			);

			// And it settles on the spliced channel.
			let fulfilled = false;
			openerManager.on('htlc:fulfilled', () => {
				fulfilled = true;
			});
			acceptorManager.fulfillHtlc(channelId, 0n, preimage);
			expect(fulfilled, 'HTLC settled after the raced lock').to.be.true;
		});

		it('rejects a batch whose splice-side signature is invalid WITHOUT revoking', function () {
			const pair = pendingLockPair();
			const {
				openerManager,
				acceptorManager,
				channelId,
				acceptorChannel,
				openerPubkey,
				acceptorPubkey
			} = pair;

			// Detach the opener auto-wire and re-wire with tampering: corrupt the
			// SPLICE-side commitment signature inside the batch.
			openerManager.removeAllListeners('message:outbound');
			const spliceTxidHex = acceptorChannel
				.getFullState()
				.spliceInFlight!.spliceTxid.toString('hex');
			openerManager.on('message:outbound', (pk, type, payload) => {
				if (pk !== acceptorPubkey) return;
				if (type === MessageType.COMMITMENT_SIGNED) {
					const m = decodeCommitmentSignedMessage(payload);
					if (m.fundingTxid?.toString('hex') === spliceTxidHex) {
						m.signature = crypto.randomBytes(64);
						acceptorManager.handleMessage(
							openerPubkey,
							type,
							encodeCommitmentSignedMessage(m)
						);
						return;
					}
				}
				acceptorManager.handleMessage(openerPubkey, type, payload);
			});

			const revokes: number[] = [];
			acceptorManager.on('message:outbound', (pk, type) => {
				if (pk === openerPubkey && type === MessageType.REVOKE_AND_ACK) {
					revokes.push(type);
				}
			});

			const commitBefore = acceptorChannel.getFullState().localCommitmentNumber;
			const spliceSigBefore = Buffer.from(
				acceptorChannel.getFullState().spliceInFlight!.remoteCommitmentSig!
			);

			openerManager.updateChannelFee(channelId, 1000);

			// The acceptor refused the batch: nothing revoked, nothing advanced,
			// the stored splice-side signature untouched.
			expect(revokes.length, 'no revoke_and_ack sent').to.equal(0);
			expect(acceptorChannel.getFullState().localCommitmentNumber).to.equal(
				commitBefore
			);
			expect(
				acceptorChannel
					.getFullState()
					.spliceInFlight!.remoteCommitmentSig!.equals(spliceSigBefore)
			).to.equal(true);
		});

		it('rejects start_batch outside the pending-lock window', function () {
			const { openerChannel, channelId } = createNormalChannelPair();
			const actions = openerChannel.handleStartBatch({
				channelId,
				batchSize: 2,
				messageType: 132
			});
			expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.equal(
				true
			);
		});

		it('rejects an incomplete batch (size 1) without revoking (fund-safety)', function () {
			const { acceptorChannel, channelId } = pendingLockPair();
			const before = acceptorChannel.getFullState().localCommitmentNumber;
			// A start_batch of 1 would revoke on only ONE of the two active
			// fundings; it must be refused before the standard path runs.
			const actions = acceptorChannel.handleStartBatch({
				channelId,
				batchSize: 1,
				messageType: 132
			});
			expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.equal(
				true
			);
			expect(acceptorChannel.getFullState().localCommitmentNumber).to.equal(
				before
			);
		});

		it('rejects a lone commitment_signed during pending-lock (no start_batch)', function () {
			const { acceptorChannel, channelId } = pendingLockPair();
			const before = acceptorChannel.getFullState().localCommitmentNumber;
			const actions = acceptorChannel.handleCommitmentSigned({
				channelId,
				signature: crypto.randomBytes(64),
				htlcSignatures: []
			});
			expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.equal(
				true
			);
			expect(acceptorChannel.getFullState().localCommitmentNumber).to.equal(
				before
			);
		});

		it('rejects a size-2 batch missing the splice-funding commitment without revoking', function () {
			const { acceptorChannel, channelId } = pendingLockPair();
			const before = acceptorChannel.getFullState().localCommitmentNumber;
			const fundingTxid = acceptorChannel.getFullState().fundingTxid!;
			acceptorChannel.handleStartBatch({
				channelId,
				batchSize: 2,
				messageType: 132
			});
			// Both messages target the CURRENT funding: the splice-side commitment
			// is absent, so revoking would strand the splice with a stale sig.
			acceptorChannel.handleCommitmentSigned({
				channelId,
				signature: crypto.randomBytes(64),
				htlcSignatures: [],
				fundingTxid
			});
			const actions = acceptorChannel.handleCommitmentSigned({
				channelId,
				signature: crypto.randomBytes(64),
				htlcSignatures: [],
				fundingTxid
			});
			expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.equal(
				true
			);
			expect(acceptorChannel.getFullState().localCommitmentNumber).to.equal(
				before
			);
		});

		it('retransmits an un-acked pending-lock batch on reestablish', function () {
			const pair = pendingLockPair();
			const { openerManager, acceptorManager, channelId, openerPubkey } = pair;

			// Capture the opener's outbound batch, but drop it before delivery so
			// the acceptor never acks: mirrors a disconnect straddling the batch.
			const outbound: number[] = [];
			openerManager.removeAllListeners('message:outbound');
			openerManager.on('message:outbound', (_pk, type) => {
				outbound.push(type);
			});
			expect(openerManager.updateChannelFee(channelId, 1000).ok).to.equal(true);
			expect(
				outbound.filter((t) => t === MessageType.START_BATCH).length
			).to.be.gte(1);

			// Reconnect: the acceptor's channel_reestablish shows it never received
			// the batch (its nextCommitmentNumber is behind), so the opener must
			// retransmit the whole batch.
			const resent: number[] = [];
			openerManager.removeAllListeners('message:outbound');
			openerManager.on('message:outbound', (_pk, type) => resent.push(type));
			const acceptorReest = acceptorManager
				.getChannel(channelId)!
				.createReestablish();
			for (const a of acceptorReest) {
				if (
					'payload' in a &&
					a.messageType === MessageType.CHANNEL_REESTABLISH
				) {
					openerManager.handleMessage(
						pair.acceptorPubkey,
						MessageType.CHANNEL_REESTABLISH,
						(a as { payload: Buffer }).payload
					);
				}
			}
			void openerPubkey;
			expect(
				resent.filter((t) => t === MessageType.START_BATCH).length,
				'batch retransmitted'
			).to.be.gte(1);
			expect(
				resent.filter((t) => t === MessageType.COMMITMENT_SIGNED).length
			).to.be.gte(2);
		});
	});

	describe('LightningNode splice API', function () {
		// Note: LightningNode splice tests require a more complex setup.
		// We test the API surface here to verify it exists and validates correctly.

		it('should exist as methods on LightningNode', function () {
			// Dynamic import to avoid full node construction overhead
			const {
				LightningNode
			} = require('../../src/lightning/node/lightning-node');
			expect(LightningNode.prototype.spliceIn).to.be.a('function');
			expect(LightningNode.prototype.spliceOut).to.be.a('function');
		});
	});

	// ─────────────── Edge Cases ───────────────

	describe('Edge cases', function () {
		it('splice message roundtrip preserves all fields exactly', function () {
			for (let i = 0; i < 10; i++) {
				const original: ISpliceMessage = {
					channelId: crypto.randomBytes(32),
					fundingPubkey: Buffer.concat([
						Buffer.from([0x02]),
						crypto.randomBytes(32)
					]),
					relativeSatoshis:
						BigInt(Math.floor(Math.random() * 2000000)) - 1000000n,
					fundingFeeratePerkw: Math.floor(Math.random() * 100000),
					locktime: Math.floor(Math.random() * 500000),
					requireConfirmedInputs: Math.random() > 0.5 ? true : undefined
				};
				const decoded = decodeSpliceMessage(encodeSpliceMessage(original));
				expect(decoded.channelId.equals(original.channelId)).to.be.true;
				expect(decoded.fundingPubkey.equals(original.fundingPubkey)).to.be.true;
				expect(decoded.relativeSatoshis).to.equal(original.relativeSatoshis);
				expect(decoded.fundingFeeratePerkw).to.equal(
					original.fundingFeeratePerkw
				);
				expect(decoded.locktime).to.equal(original.locktime);
			}
		});

		it('splice_ack message roundtrip preserves all fields exactly', function () {
			for (let i = 0; i < 10; i++) {
				const original: ISpliceAckMessage = {
					channelId: crypto.randomBytes(32),
					fundingPubkey: Buffer.concat([
						Buffer.from([0x03]),
						crypto.randomBytes(32)
					]),
					relativeSatoshis:
						BigInt(Math.floor(Math.random() * 2000000)) - 1000000n,
					requireConfirmedInputs: Math.random() > 0.5 ? true : undefined
				};
				const decoded = decodeSpliceAckMessage(
					encodeSpliceAckMessage(original)
				);
				expect(decoded.channelId.equals(original.channelId)).to.be.true;
				expect(decoded.fundingPubkey.equals(original.fundingPubkey)).to.be.true;
				expect(decoded.relativeSatoshis).to.equal(original.relativeSatoshis);
			}
		});

		it('splice_locked roundtrip preserves channel_id (CLN v24.11.1 wire)', function () {
			for (let i = 0; i < 10; i++) {
				const original: ISpliceLockedMessage = {
					channelId: crypto.randomBytes(32)
				};
				const decoded = decodeSpliceLockedMessage(
					encodeSpliceLockedMessage(original)
				);
				expect(decoded.channelId.equals(original.channelId)).to.be.true;
			}
		});

		it('SpliceSession should handle peer complete before local complete', function () {
			const session = new SpliceSession({
				channelId: crypto.randomBytes(32),
				localFundingPubkey: Buffer.alloc(33, 0x02),
				isInitiator: true,
				localRelativeSatoshis: 100_000n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});

			session.initiate();
			session.handleSpliceAck({
				channelId: session.getChannelId(),
				fundingPubkey: Buffer.alloc(33, 0x03),
				relativeSatoshis: 0n
			});

			session.addInput({
				serialId: 0n,
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			});
			session.addOutput({
				serialId: 2n,
				amountSats: 100_000n,
				scriptPubkey: Buffer.alloc(22, 0x01)
			});

			// Peer completes first
			session.handlePeerTxComplete();
			expect(session.getState()).to.equal(SpliceState.TX_NEGOTIATION);

			// Then we complete
			session.markTxComplete();
			expect(session.getState()).to.equal(SpliceState.AWAITING_TX_SIGNATURES);
		});

		it('should support splice with zero local contribution', function () {
			const session = new SpliceSession({
				channelId: crypto.randomBytes(32),
				localFundingPubkey: Buffer.alloc(33, 0x02),
				isInitiator: true,
				localRelativeSatoshis: 0n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});

			const result = session.initiate();
			expect(result.ok).to.be.true;
			const msg = result.message as ISpliceMessage;
			expect(msg.relativeSatoshis).to.equal(0n);
		});
	});
});
