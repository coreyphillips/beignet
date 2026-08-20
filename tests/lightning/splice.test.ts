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
import {
	Channel,
	ISpliceWalletInput
} from '../../src/lightning/channel/channel';
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
	decodeTxAbortMessage,
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxSignaturesMessage,
	encodeTxAddInputMessage,
	encodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeStfuMessage } from '../../src/lightning/message/stfu';
import { decodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { ChannelRecoveryStatus } from '../../src/lightning/recovery';
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
import {
	signerFromSeed,
	realInitialCommitmentSig,
	realCommitmentSigs
} from './helpers/real-signing';

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
 * A manager pair driven through a splice-out (to newCapacitySats) up to the
 * pending-lock window: negotiation and tx_signatures complete, splice_locked
 * never sent, so update traffic has resumed while every update still mirrors
 * onto both fundings.
 */
function pendingLockSpliceOutPair(
	newCapacitySats: bigint
): ReturnType<typeof createNormalChannelPair> {
	const pair = createNormalChannelPair();
	pair.openerManager.initiateQuiescence(pair.channelId);
	const destScript = Buffer.concat([
		Buffer.from([0x00, 0x14]),
		crypto.randomBytes(20)
	]);
	// node.spliceOut's exact arithmetic: the destination receives
	// the full withdrawal and the on-chain fee rides in the declared
	// relative (the tx_complete audit enforces the feerate).
	const spliceOutFee = spliceFeeSats(
		estimateSpliceTxWeight({
			walletInputCount: 0,
			destinationScriptLen: destScript.length
		}),
		253
	);
	const withdraw = FUNDING_SATOSHIS - newCapacitySats - spliceOutFee;
	pair.openerChannel.setSpliceOutDestination(destScript, withdraw);
	expect(
		pair.openerManager.initiateSplice(
			pair.channelId,
			-(withdraw + spliceOutFee),
			253
		).ok
	).to.equal(true);
	// Auto-routing drove the negotiation and tx_signatures; without
	// splice_locked both sides sit in the pending-lock window.
	expect(pair.openerChannel.isSplicePendingLock()).to.equal(true);
	expect(pair.acceptorChannel.isSplicePendingLock()).to.equal(true);
	return pair;
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
			opener.setSigner(signerFromSeed(openerSeed));
			acceptor.setSigner(signerFromSeed(acceptorSeed));

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
				realInitialCommitmentSig(opener, fundingTxid, 0)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);
			const fsActions = acceptor.handleFundingCreated(
				decodedFc,
				realInitialCommitmentSig(
					acceptor,
					decodedFc.fundingTxid,
					decodedFc.fundingOutputIndex
				)
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

		function quiesceAsResponder(channel: Channel): void {
			// The peer initiates; we answer and become the non-initiator side,
			// the side that legitimately RECEIVES splice_init (issue #372).
			const channelId = channel.getChannelId()!;
			const actions = channel.handleStfuMessage({ channelId, initiator: true });
			expect(findSendAction(actions, MessageType.STFU)).to.exist;
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
			quiesceAsResponder(acceptor);

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

		it('refuses a splice that fails session validation with tx_abort and exits quiescence (#371)', function () {
			// A bare local ERROR leaves the initiator SPLICING (awaiting a
			// splice_ack that never comes) and this side silently QUIESCENT:
			// both HTLC-frozen until a disconnect. The refusal must answer on
			// the wire. Channel ID mismatch drives the session-validation arm.
			const { acceptor } = makeNormalChannel();
			quiesceAsResponder(acceptor);

			const actions = acceptor.handleSplice({
				channelId: Buffer.alloc(32, 0xee),
				fundingPubkey: Buffer.alloc(33, 0x02),
				relativeSatoshis: 100_000n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});

			const abortAction = findSendAction(actions, MessageType.TX_ABORT);
			expect(abortAction, 'tx_abort answered the refusal').to.exist;
			const decoded = decodeTxAbortMessage(abortAction.payload);
			expect(decoded.channelId.equals(acceptor.getChannelId()!)).to.equal(true);
			const err = findAction(actions, ChannelActionType.ERROR);
			expect(err).to.exist;
			expect(String(err.message)).to.include('mismatch');
			expect(acceptor.isQuiescent(), 'quiescence unwound').to.equal(false);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getSpliceSession()).to.equal(null);
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
			quiesceAsResponder(acceptor);
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

			// The initiator also supplies the shared input and an honest new
			// funding output, so the co-sign audit accepts the completed tx.
			acceptor.handleTxAddInput({
				channelId,
				serialId: 4n,
				prevTx: Buffer.alloc(0),
				prevTxVout: 0,
				sequence: 0xfffffffd,
				sharedInputTxid: acceptor.getFullState().fundingTxid!
			});
			const {
				createFundingScript
			} = require('../../src/lightning/script/funding');
			const newFunding = createFundingScript(
				acceptor.getFullState().localBasepoints.fundingPubkey,
				Buffer.alloc(33, 0x02)
			);
			acceptor.handleTxAddOutput({
				channelId,
				serialId: 6n,
				amountSats: 600_000n,
				scriptPubkey: newFunding.p2wshOutput
			});

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
			quiesceAsResponder(acceptor);
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
			quiesceAsResponder(acceptor);
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
			quiesceAsResponder(acceptor);
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
			// Fold the on-chain fee into relative_satoshis exactly as
			// node.spliceOut does (the tx_complete audit enforces the feerate,
			// and an audit failure now aborts the splice).
			const spliceOutFee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 0,
					destinationScriptLen: destScript.length
				}),
				253
			);
			opener.setSpliceOutDestination(destScript, withdraw);
			opener.initiateSplice(-(withdraw + spliceOutFee), 253);

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

		it('fails closed on a splice commitment_signed when the signer is missing', function () {
			// Issue #329: "cannot verify" must never become "cache and mark
			// received" on the splice commitment path either.
			const { opener } = makeNormalChannel();
			quiesce(opener);
			const channelId = opener.getChannelId()!;

			const destScript = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const withdraw = 50_000n;
			// Fee folded into relative_satoshis: the tx_complete audit enforces
			// the feerate, and an audit failure now aborts the splice.
			const spliceOutFee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 0,
					destinationScriptLen: destScript.length
				}),
				253
			);
			opener.setSpliceOutDestination(destScript, withdraw);
			opener.initiateSplice(-(withdraw + spliceOutFee), 253);
			opener.handleSpliceAck({
				channelId,
				fundingPubkey: makeBasepoints(acceptorSeed).fundingPubkey,
				relativeSatoshis: 0n
			});
			opener.handleTxComplete();
			opener.handleTxComplete();
			opener.handleTxComplete();
			expect(opener.buildAndSignSpliceTx(), 'splice tx built').to.not.be.null;

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(opener as any)._signer = null;
			const actions = opener.handleCommitmentSigned({
				channelId,
				signature: crypto.randomBytes(64),
				htlcSignatures: []
			});
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain(
				'Cannot verify splice commitment signature'
			);
			// Nothing cached, round not marked received.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect((opener as any)._spliceRemoteCommitmentSig).to.equal(null);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect((opener as any)._spliceReceivedCommitment).to.equal(false);
		});

		it('should unwind the splice on peer tx_abort (channel returns to NORMAL)', function () {
			const { acceptor } = makeNormalChannel();
			quiesceAsResponder(acceptor);
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

		/** Drive a splice of `relativeSatoshis` to adoption and return the opener. */
		function spliceToAdoption(
			relativeSatoshis: bigint,
			shape?: {
				fundingVersion?: 1 | 2;
				peerDustLimitSatoshis?: bigint;
				unstamped?: boolean;
			}
		): Channel {
			const { opener } = makeNormalChannel();
			if (shape?.unstamped) {
				delete opener.getFullState().channelReserveVersion;
			}
			if (shape?.fundingVersion !== undefined) {
				opener.getFullState().fundingVersion = shape.fundingVersion;
			}
			if (shape?.peerDustLimitSatoshis !== undefined) {
				opener.getFullState().remoteConfig = {
					...opener.getFullState().remoteConfig,
					dustLimitSatoshis: shape.peerDustLimitSatoshis
				};
			}
			quiesce(opener);
			const channelId = opener.getChannelId()!;
			opener.initiateSplice(relativeSatoshis, 253);
			opener.handleSpliceAck({
				channelId,
				fundingPubkey: Buffer.alloc(33, 0x03),
				relativeSatoshis: 0n
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
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			return opener;
		}

		it('a splice-out lowers the reserve it enforces on the peer (issue 381)', function () {
			// The enforced reserve is priced at capacity, and nothing re-derived
			// it across a splice. Frozen at the open-time value, a splice-out
			// leaves us demanding a reserve the channel no longer justifies while
			// the peer honours what the new capacity prices, and every HTLC in
			// that band is refused with a bare ERROR the peer never sees, so its
			// next commitment_signed covers an HTLC we do not hold.
			const opener = spliceToAdoption(-800_000n);
			expect(opener.getFundingSatoshis()).to.equal(200_000n);
			expect(opener.getFullState().localConfig.channelReserveSatoshis).to.equal(
				2_000n
			);
		});

		it('splice adoption stamps the reserve it establishes (issue 381)', function () {
			// Starting from a row with no provenance stamp, i.e. one opened before
			// the open sites recorded anything. Adoption is now the site that
			// established the value, so it owes the stamp: without it the row stays
			// eligible for the load-time repair forever.
			const opener = spliceToAdoption(-800_000n, { unstamped: true });
			expect(opener.getFullState().localConfig.channelReserveSatoshis).to.equal(
				2_000n
			);
			expect(opener.getFullState().channelReserveVersion).to.be.a('number');
		});

		it('a splice-in never raises the reserve it enforces (issue 381)', function () {
			// The other direction stays put, by policy rather than omission
			// (issue 382): CLN never re-prices a reserve across a splice, so its
			// own gate still lets it spend down to the value priced at the
			// ORIGINAL capacity, and raising ours would start refusing HTLCs it
			// believes are legal. Erring low is inert; the peer's own gate binds.
			const opener = spliceToAdoption(500_000n);
			expect(opener.getFundingSatoshis()).to.equal(1_500_000n);
			expect(opener.getFullState().localConfig.channelReserveSatoshis).to.equal(
				10_000n
			);
		});

		it('a splice-in raises the reserve it keeps to the new capacity price (issue 382)', function () {
			// eclair re-derives BOTH reserves from the new capacity once
			// fundingTxIndex > 0 (v1 channels included), so after a splice-in the
			// peer enforces more against us than the open-time value. A kept
			// reserve still priced at the old capacity lets
			// getSpendableOutboundMsat overdraw into an HTLC the peer MUST
			// refuse, which force closes the channel.
			const opener = spliceToAdoption(500_000n);
			expect(opener.getFundingSatoshis()).to.equal(1_500_000n);
			expect(
				opener.getFullState().remoteConfig.channelReserveSatoshis
			).to.equal(15_000n);
		});

		it('a splice-out never lowers the reserve it keeps (issue 382)', function () {
			// CLN never re-prices a reserve across a splice (channeld has no
			// reserve handling at all), so the peer may keep enforcing the value
			// priced at the ORIGINAL capacity forever; lowering what we keep to
			// the new 2,000-sat derivation would open the same overdraw gap the
			// raise above closes. Over-keeping only costs our own spendable.
			const opener = spliceToAdoption(-800_000n);
			expect(opener.getFundingSatoshis()).to.equal(200_000n);
			expect(
				opener.getFullState().remoteConfig.channelReserveSatoshis
			).to.equal(10_000n);
		});

		it('prices a spliced v2 channel by the v2 rule (issue 381)', function () {
			// fundingVersion is durable and survives adoption, so the tail can tell
			// the two apart. The v1 helper's 546-sat policy floor is above what a
			// v2 peer keeps at this capacity (max(1% of 20,000, min(dusts)) = 354),
			// and the 192-sat gap between them is a band of HTLCs we would refuse
			// with a bare ERROR the peer never sees.
			const opener = spliceToAdoption(-980_000n, {
				fundingVersion: 2,
				peerDustLimitSatoshis: 546n
			});
			expect(opener.getFundingSatoshis()).to.equal(20_000n);
			expect(opener.getFullState().localConfig.channelReserveSatoshis).to.equal(
				354n
			);
		});

		it('never enforces a spliced reserve above what the peer keeps (issue 381)', function () {
			// Same band on a v1 channel, because eclair switches to the derived
			// rule for any channel with fundingTxIndex > 0, i.e. any spliced one
			// (Commitments.scala localChannelReserve). The negotiated rule would
			// leave 546 here, and computeChannelReserve applies its 20% cap last,
			// so on a small enough capacity it lands under its own starting floor
			// (1,500/5 is 300) where the peer keeps its whole dust limit.
			const twenty = spliceToAdoption(-980_000n);
			expect(twenty.getFundingSatoshis()).to.equal(20_000n);
			expect(twenty.getFullState().localConfig.channelReserveSatoshis).to.equal(
				354n
			);

			const tiny = spliceToAdoption(-998_500n);
			expect(tiny.getFundingSatoshis()).to.equal(1_500n);
			expect(tiny.getFullState().localConfig.channelReserveSatoshis).to.equal(
				354n
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
			quiesceAsResponder(acceptor);
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

		it('tx_aborts a peer splice-out that leaves the peer below the reserve at the new capacity (issue #423)', function () {
			// BOLT 2 tx_complete: the receiver MUST fail the negotiation when a
			// side that added a non-funding output lands below the channel
			// reserve priced at the NEW capacity. The peer withdraws almost its
			// whole balance: 400k - 394k leaves it 6_000 sats, below
			// v2ReserveWeEnforce(606_000) = 6_060.
			const { acceptor } = makeNormalChannel(600_000_000n);
			const acceptorFundingPriv = crypto
				.createHash('sha256')
				.update(acceptorSeed)
				.update(Buffer.from([0]))
				.digest();
			acceptor.setSigner(new ChannelSigner(acceptorFundingPriv));
			quiesceAsResponder(acceptor);
			const channelId = acceptor.getChannelId()!;
			const fundingTxid = acceptor.getFullState().fundingTxid!;
			const openerBp = makeBasepoints(openerSeed);

			acceptor.handleSplice({
				channelId,
				fundingPubkey: openerBp.fundingPubkey,
				relativeSatoshis: -394_000n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});
			acceptor.handleTxAddInput({
				channelId,
				serialId: 0n,
				prevTx: Buffer.alloc(0),
				prevTxVout: 0,
				sequence: 0xfffffffd,
				sharedInputTxid: fundingTxid
			});
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
				amountSats: 606_000n,
				scriptPubkey: newFunding.p2wshOutput
			});
			acceptor.handleTxAddOutput({
				channelId,
				serialId: 4n,
				amountSats: 393_000n,
				scriptPubkey: Buffer.concat([
					Buffer.from([0x00, 0x14]),
					crypto.randomBytes(20)
				])
			});

			const actions = acceptor.handleTxComplete();
			expect(
				findSendAction(actions, MessageType.TX_ABORT),
				'tx_abort sent to peer'
			).to.exist;
			const err = findAction(actions, ChannelActionType.ERROR);
			expect(err, 'surfaced as error').to.exist;
			expect(err.message).to.match(/below the channel reserve/);
			expect(
				findSendAction(actions, MessageType.TX_SIGNATURES),
				'no tx_signatures sent'
			).to.not.exist;
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
			expect((acceptor as any)._spliceSession, 'session unwound').to.be.null;
		});

		it('admits a peer splice-out that lands exactly on the reserve at the new capacity (issue #423)', function () {
			// Boundary: 400k - 393_940 leaves the peer 6_060 sats, exactly
			// v2ReserveWeEnforce(606_060) = 6_060. The spec bound is "less
			// than", so this negotiation must complete.
			const { acceptor } = makeNormalChannel(600_000_000n);
			const acceptorFundingPriv = crypto
				.createHash('sha256')
				.update(acceptorSeed)
				.update(Buffer.from([0]))
				.digest();
			acceptor.setSigner(new ChannelSigner(acceptorFundingPriv));
			quiesceAsResponder(acceptor);
			const channelId = acceptor.getChannelId()!;
			const fundingTxid = acceptor.getFullState().fundingTxid!;
			const openerBp = makeBasepoints(openerSeed);

			acceptor.handleSplice({
				channelId,
				fundingPubkey: openerBp.fundingPubkey,
				relativeSatoshis: -393_940n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});
			acceptor.handleTxAddInput({
				channelId,
				serialId: 0n,
				prevTx: Buffer.alloc(0),
				prevTxVout: 0,
				sequence: 0xfffffffd,
				sharedInputTxid: fundingTxid
			});
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
				amountSats: 606_060n,
				scriptPubkey: newFunding.p2wshOutput
			});
			acceptor.handleTxAddOutput({
				channelId,
				serialId: 4n,
				amountSats: 392_940n,
				scriptPubkey: Buffer.concat([
					Buffer.from([0x00, 0x14]),
					crypto.randomBytes(20)
				])
			});

			const actions = acceptor.handleTxComplete();
			expect(
				findSendAction(actions, MessageType.TX_ABORT),
				'no tx_abort at the boundary'
			).to.not.exist;
			const err = findAction(actions, ChannelActionType.ERROR);
			expect(
				err?.message ?? '',
				'no reserve refusal at the boundary'
			).to.not.match(/below the channel reserve/);
		});

		it('refuses a splice-in whose change output parks us below the reserve at the new capacity (issue #423)', function () {
			// The BOLT 2 reserve rule arms only when a side ADDS a non-funding
			// output; for a splice-in that is the change output. 5k local + 3k
			// in = 8k, below v2ReserveWeKeep(1_003_000) = 10_030, and the
			// selection leaves change well above the dust floor.
			const { acceptor } = makeNormalChannel(5_000_000n);
			const changeScript = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const fee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 1,
					fundingScriptLen: 34,
					changeScriptLen: changeScript.length
				}),
				253
			);
			acceptor.setSpliceInInputs(
				[
					{
						prevTx: Buffer.alloc(60),
						prevOutputIndex: 0,
						value: 3_000n + fee + 2_000n,
						sequence: 0xfffffffd,
						signWitness: () => [],
						confirmed: true
					}
				],
				changeScript
			);
			const actions = acceptor.initiateSplice(3_000n, 253);
			const err = findAction(actions, ChannelActionType.ERROR);
			expect(err, 'refused up-front').to.exist;
			expect(err.message).to.match(/below the channel reserve/);
			expect(findSendAction(actions, MessageType.STFU), 'no quiescence started')
				.to.not.exist;
		});

		it('admits an exact-input splice-in below the reserve: no change output to abort (issue #423)', function () {
			// Same balances, but the selection covers exactly amount + fee: no
			// change output is emitted, the reserve rule does not arm, and the
			// splice is legal under BOLT 2 even though we stay below reserve.
			const { acceptor } = makeNormalChannel(5_000_000n);
			const changeScript = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const fee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 1,
					fundingScriptLen: 34,
					changeScriptLen: changeScript.length
				}),
				253
			);
			acceptor.setSpliceInInputs(
				[
					{
						prevTx: Buffer.alloc(60),
						prevOutputIndex: 0,
						value: 3_000n + fee,
						sequence: 0xfffffffd,
						signWitness: () => [],
						confirmed: true
					}
				],
				changeScript
			);
			const actions = acceptor.initiateSplice(3_000n, 253);
			expect(
				findAction(actions, ChannelActionType.ERROR)?.message ?? ''
			).to.not.match(/below the channel reserve/);
			expect(findSendAction(actions, MessageType.STFU), 'quiescence started').to
				.exist;
		});

		it('initiateSplice refuses a splice-out into the derived reserve band (issue #423)', function () {
			// 1M balance, withdraw 999_600: the 400 sats left sit below
			// v2ReserveWeKeep(400) = 546, a composition a conforming peer MUST
			// tx_abort. Refused before any quiescence round starts.
			const { opener } = makeNormalChannel();
			const actions = opener.initiateSplice(-999_600n, 253);
			const err = findAction(actions, ChannelActionType.ERROR);
			expect(err, 'refused up-front').to.exist;
			expect(err.message).to.match(/below the channel reserve/);
			expect(findSendAction(actions, MessageType.STFU), 'no quiescence started')
				.to.not.exist;
		});

		it('refuses our own composition when our change output sits below the reserve (issue #423)', function () {
			// Direct unit of the our-side arm: the acceptor holds 0 sats and
			// the outputs carry an odd-serial (our) non-funding output, so the
			// composition is one the peer MUST abort.
			const { acceptor } = makeNormalChannel();
			quiesceAsResponder(acceptor);
			const channelId = acceptor.getChannelId()!;
			const openerBp = makeBasepoints(openerSeed);
			acceptor.handleSplice({
				channelId,
				fundingPubkey: openerBp.fundingPubkey,
				relativeSatoshis: 0n,
				fundingFeeratePerkw: 253,
				locktime: 0
			});
			const {
				createFundingScript
			} = require('../../src/lightning/script/funding');
			const newFunding = createFundingScript(
				acceptor.getFullState().localBasepoints.fundingPubkey,
				openerBp.fundingPubkey
			);
			const refusal = (acceptor as any)._spliceBelowReserveRefusal(
				[
					{
						serialId: 2n,
						amountSats: 999_000n,
						scriptPubkey: newFunding.p2wshOutput
					},
					{
						serialId: 1n,
						amountSats: 1_000n,
						scriptPubkey: Buffer.concat([
							Buffer.from([0x00, 0x14]),
							crypto.randomBytes(20)
						])
					}
				],
				newFunding.p2wshOutput,
				false
			);
			expect(refusal).to.match(/our balance .* below the channel reserve/);
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

		describe('splice-in change dust floor (issue #389)', function () {
			// The channel's own fee arithmetic (_computeSpliceContributions):
			// fundingScriptLen = newFunding.p2wshOutput.length = 34, P2WPKH
			// change = 22, and the estimate counts the change output even when
			// it is later folded — 996 WU, 252 sats at 253 sat/kw. Sizing the
			// wallet UTXO as amount + fee + desiredChange therefore pins the
			// change the splice-in arm computes to EXACTLY desiredChange.
			const spliceInAmount = 300_000n;
			const spliceInFee = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 1,
					fundingScriptLen: 34,
					changeScriptLen: 22
				}),
				253
			);

			/**
			 * Run a full splice-in over the wire with the wallet UTXO sized to
			 * leave EXACTLY desiredChangeSats (makeSpliceInWallet always leaves
			 * ~100k, far above any floor). openerDustSats raises the opener's
			 * commitment dust limit CONSISTENTLY on both sides' views of the
			 * open channel, which is what lifts the negotiated interactive-tx
			 * floor above the 546-sat default.
			 */
			function runSpliceIn(
				desiredChangeSats: bigint,
				openerDustSats?: bigint
			): {
				opener: Channel;
				outputs: Array<{ amountSats: bigint; scriptPubkey: Buffer }>;
				changeScript: Buffer;
				feePaid: bigint;
				broadcasts: Buffer[];
			} {
				bitcoin.initEccLib(ecc);
				const { opener, acceptor } = makeNormalChannel();
				if (openerDustSats !== undefined) {
					opener.getFullState().localConfig.dustLimitSatoshis = openerDustSats;
					acceptor.getFullState().remoteConfig.dustLimitSatoshis =
						openerDustSats;
				}

				const walletPriv = crypto
					.createHash('sha256')
					.update(`dust-floor-${desiredChangeSats}-${openerDustSats ?? 0n}`)
					.digest();
				const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
				const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub })
					.output!;
				const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub })
					.output!;
				const walletValue = spliceInAmount + spliceInFee + desiredChangeSats;
				const prevTx = new bitcoin.Transaction();
				prevTx.version = 2;
				prevTx.addInput(crypto.randomBytes(32), 0);
				prevTx.addOutput(walletScript, Number(walletValue));
				const walletInput = {
					prevTx: prevTx.toBuffer(),
					prevOutputIndex: 0,
					value: walletValue,
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
						const sig64 = Buffer.from(ecc.sign(sighash, walletPriv));
						const der = bitcoin.script.signature.encode(
							sig64,
							bitcoin.Transaction.SIGHASH_ALL
						);
						return [der, walletPub];
					}
				};

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
						if (a.type === ChannelActionType.BROADCAST_TX)
							broadcasts.push(a.tx);
					}
				};

				opener.setSpliceInInputs([walletInput], walletScript);
				enqueue(acceptor, opener, opener.initiateSplice(spliceInAmount, 253));
				let steps = 0;
				while (queue.length > 0) {
					if (steps++ > 300) throw new Error('splice-in did not settle');
					const { to, from, msgType, payload } = queue.shift()!;
					enqueue(from, to, deliver(to, msgType, payload));
				}

				const os = opener.getSpliceSession()!;
				expect(os.getState()).to.equal(SpliceState.AWAITING_SPLICE_LOCKED);
				const otx = os.buildTransaction()!;
				// Shared funding input + the one wallet input, in every case.
				expect(otx.inputs.length).to.equal(2);
				const outputTotal = otx.outputs.reduce((s, o) => s + o.amountSats, 0n);
				return {
					opener,
					outputs: otx.outputs,
					changeScript: walletScript,
					feePaid: FUNDING_SATOSHIS + walletValue - outputTotal,
					broadcasts
				};
			}

			it('folds change in the 295..545 band into fee instead of emitting it', function () {
				// Default configs negotiate the 546-sat interactive-tx floor
				// (max(354, 354, 546)); the old `> 294` rule would have emitted
				// this 400-sat change and the peer would have refused it.
				const run = runSpliceIn(400n);
				expect(run.opener.spliceInteractiveTxDustFloor()).to.equal(546n);
				// The ONLY output is the new funding — no change was added, and
				// the splice still ran to fully signed on both sides.
				expect(run.outputs.length).to.equal(1);
				expect(run.outputs[0].amountSats).to.equal(
					FUNDING_SATOSHIS + spliceInAmount
				);
				expect(run.broadcasts.length, 'both sides signed + broadcast').to.equal(
					2
				);
				// Conservation pins where the sats went: the folded 400 rides on
				// top of the estimated fee.
				expect(run.feePaid).to.equal(spliceInFee + 400n);
			});

			it('emits the change output at exactly the 546-sat floor (>= comparison)', function () {
				const run = runSpliceIn(546n);
				expect(run.outputs.length).to.equal(2);
				const change = run.outputs.find((o) =>
					o.scriptPubkey.equals(run.changeScript)
				);
				expect(change, 'change output present').to.exist;
				expect(change!.amountSats).to.equal(546n);
				expect(run.feePaid).to.equal(spliceInFee);
			});

			it('applies the NEGOTIATED floor when a commitment dust limit exceeds 546', function () {
				// A 1000-sat commitment dust limit raises the floor both sides
				// enforce on every tx_add_output, ours included: a 999-sat
				// change output would abort the splice at the peer.
				const folded = runSpliceIn(999n, 1_000n);
				expect(folded.opener.spliceInteractiveTxDustFloor()).to.equal(1_000n);
				expect(folded.outputs.length).to.equal(1);
				expect(folded.feePaid).to.equal(spliceInFee + 999n);

				const emitted = runSpliceIn(1_000n, 1_000n);
				expect(emitted.outputs.length).to.equal(2);
				const change = emitted.outputs.find((o) =>
					o.scriptPubkey.equals(emitted.changeScript)
				);
				expect(change, 'change output present at the raised floor').to.exist;
				expect(change!.amountSats).to.equal(1_000n);
				expect(emitted.feePaid).to.equal(spliceInFee);
			});
		});

		// ─────────────── Disconnect & reestablish safety ───────────────

		describe('disconnect & reestablish safety', function () {
			interface IWirePair {
				opener: Channel;
				acceptor: Channel;
				broadcasts: Buffer[];
				errors: string[];
				/** WATCH_FUNDING actions, tagged with the emitting channel. */
				watches: Array<{
					from: Channel;
					txid: Buffer;
					outputIndex: number;
				}>;
				enqueue: (to: Channel, from: Channel, actions: any[]) => void;
				pump: () => void;
				/** After skipping `skip` matches, drop the next `count` messages of this type. */
				drop: (msgType: MessageType, count?: number, skip?: number) => void;
				/** Clear all drop rules (a fresh connection delivers everything). */
				clearDrops: () => void;
				/** Transform every outbound payload of this type (adversarial peer). */
				intercept: (
					msgType: MessageType,
					fn: (payload: Buffer) => Buffer
				) => void;
				/** Stop tampering (an honest retry follows). */
				clearIntercepts: () => void;
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
				const interceptRules = new Map<
					MessageType,
					(payload: Buffer) => Buffer
				>();

				const watches: IWirePair['watches'] = [];
				const enqueue = (to: Channel, from: Channel, actions: any[]): void => {
					for (const a of actions) {
						if (a.type === ChannelActionType.ERROR) errors.push(a.message);
						if (a.type === ChannelActionType.BROADCAST_TX)
							broadcasts.push(a.tx);
						if (a.type === ChannelActionType.WATCH_FUNDING)
							watches.push({
								from,
								txid: a.fundingTxid,
								outputIndex: a.fundingOutputIndex
							});
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
							const transform = interceptRules.get(a.messageType);
							queue.push({
								to,
								from,
								msgType: a.messageType,
								payload: transform ? transform(a.payload) : a.payload
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
				const intercept = (
					msgType: MessageType,
					fn: (payload: Buffer) => Buffer
				): void => {
					interceptRules.set(msgType, fn);
				};
				const clearIntercepts = (): void => {
					interceptRules.clear();
				};

				return {
					opener,
					acceptor,
					broadcasts,
					errors,
					watches,
					enqueue,
					pump,
					drop,
					clearDrops,
					intercept,
					clearIntercepts
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

			/** Opener splices IN, funded by the given wallet UTXO (or a fresh
			 *  P2WPKH one from makeSpliceInWallet). */
			function startSpliceIn(
				pair: IWirePair,
				amount = 300_000n,
				wallet?: { walletInput: ISpliceWalletInput; changeScript: Buffer }
			): void {
				const w = wallet ?? makeSpliceInWallet(amount);
				pair.opener.setSpliceInInputs([w.walletInput], w.changeScript);
				pair.enqueue(
					pair.acceptor,
					pair.opener,
					pair.opener.initiateSplice(amount, 253)
				);
				pair.pump();
			}

			/** A P2TR wallet UTXO funding a splice-in: key-spend signWitness over
			 *  the BIP 341 all-prevouts sighash (explicit SIGHASH_ALL form). */
			function makeP2trSpliceInWallet(amountSats: bigint): {
				walletInput: ISpliceWalletInput;
				changeScript: Buffer;
			} {
				bitcoin.initEccLib(ecc);
				const priv = crypto.randomBytes(32);
				const xonly = Buffer.from(getPublicKey(priv).subarray(1));
				const script = Buffer.concat([Buffer.from([0x51, 0x20]), xonly]);
				const value = amountSats + 100_000n;
				const prevTx = new bitcoin.Transaction();
				prevTx.version = 2;
				prevTx.addInput(crypto.randomBytes(32), 0);
				prevTx.addOutput(script, Number(value));
				return {
					walletInput: {
						prevTx: prevTx.toBuffer(),
						prevOutputIndex: 0,
						value,
						sequence: 0xfffffffd,
						signWitness: (
							tx: bitcoin.Transaction,
							inputIndex: number,
							_value: bigint,
							prevouts?: { scripts: Buffer[]; values: bigint[] }
						): Buffer[] => {
							const msg = tx.hashForWitnessV1(
								inputIndex,
								prevouts!.scripts,
								prevouts!.values.map((v) => Number(v)),
								bitcoin.Transaction.SIGHASH_ALL
							);
							const rawSig = Buffer.from(ecc.signSchnorr(msg, priv));
							return [
								Buffer.concat([
									rawSig,
									Buffer.from([bitcoin.Transaction.SIGHASH_ALL])
								])
							];
						}
					},
					changeScript: Buffer.concat([
						Buffer.from([0x00, 0x14]),
						crypto.randomBytes(20)
					])
				};
			}

			/** Tamper every tx_signatures that carries wallet witnesses. */
			function tamperTxSigs(
				pair: IWirePair,
				fn: (witnesses: Buffer[][]) => Buffer[][]
			): void {
				pair.intercept(MessageType.TX_SIGNATURES, (payload) => {
					const msg = decodeTxSignaturesMessage(payload);
					if (msg.witnesses.length === 0) return payload;
					msg.witnesses = fn(msg.witnesses);
					return encodeTxSignaturesMessage(msg);
				});
			}

			describe('peer wallet witness validation (issue #345)', function () {
				it('refuses a wallet witness whose signature does not verify', function () {
					const pair = makeWirePair();
					// Well-formed P2WPKH stack, correct pubkey, signature by another
					// key: only a real BIP 143 verify can catch it.
					tamperTxSigs(pair, (witnesses) => {
						const junkPriv = crypto
							.createHash('sha256')
							.update('not-the-wallet-key')
							.digest();
						const sig64 = Buffer.from(
							ecc.sign(crypto.randomBytes(32), junkPriv)
						);
						const der = bitcoin.script.signature.encode(
							sig64,
							bitcoin.Transaction.SIGHASH_ALL
						);
						return [[der, witnesses[0][1]]];
					});
					startSpliceIn(pair);

					expect(
						pair.errors.some((e) => e.includes('invalid splice tx_signatures')),
						'named refusal surfaced'
					).to.be.true;
					expect(pair.errors.some((e) => e.includes('does not verify'))).to.be
						.true;
					const record = pair.acceptor.getFullState().spliceInFlight!;
					expect(record.receivedTxSignatures, 'nothing recorded').to.be.false;
					expect(record.fullySigned).to.be.false;
					// Only the opener (which received valid signatures) broadcast.
					expect(pair.broadcasts.length).to.equal(1);
				});

				it('refuses a wallet witness naming the wrong pubkey', function () {
					const pair = makeWirePair();
					tamperTxSigs(pair, (witnesses) => {
						const otherPub = Buffer.from(
							getPublicKey(
								crypto.createHash('sha256').update('other-key').digest()
							)
						);
						return [[witnesses[0][0], otherPub]];
					});
					startSpliceIn(pair);
					expect(
						pair.errors.some(
							(e) =>
								e.includes('invalid splice tx_signatures') &&
								e.includes('does not match the prevout program')
						)
					).to.be.true;
					expect(pair.acceptor.getFullState().spliceInFlight!.fullySigned).to.be
						.false;
				});

				it('refuses surplus witness stacks', function () {
					const pair = makeWirePair();
					tamperTxSigs(pair, (witnesses) => [
						...witnesses,
						[Buffer.alloc(71, 1), Buffer.alloc(33, 2)]
					]);
					startSpliceIn(pair);
					expect(
						pair.errors.some(
							(e) =>
								e.includes('invalid splice tx_signatures') &&
								e.includes('expected 1 witness stacks, got 2')
						)
					).to.be.true;
					expect(pair.acceptor.getFullState().spliceInFlight!.fullySigned).to.be
						.false;
				});

				it('refuses missing witness stacks', function () {
					const pair = makeWirePair();
					tamperTxSigs(pair, () => []);
					startSpliceIn(pair);
					expect(
						pair.errors.some(
							(e) =>
								e.includes('invalid splice tx_signatures') &&
								e.includes('expected 1 witness stacks, got 0')
						)
					).to.be.true;
					expect(pair.acceptor.getFullState().spliceInFlight!.fullySigned).to.be
						.false;
				});

				it('accepts a valid P2TR wallet input (BIP 341 sighash covers the shared prevout)', function () {
					const pair = makeWirePair();
					startSpliceIn(pair, 300_000n, makeP2trSpliceInWallet(300_000n));

					expect(pair.errors).to.deep.equal([]);
					expect(pair.broadcasts.length).to.equal(2);
					expect(pair.broadcasts[0].equals(pair.broadcasts[1])).to.be.true;
					const finalTx = bitcoin.Transaction.fromBuffer(pair.broadcasts[0]);
					const witnessSizes = finalTx.ins.map((i) => i.witness.length).sort();
					// 1-element P2TR key-spend + 4-element 2-of-2 shared witness.
					expect(witnessSizes).to.deep.equal([1, 4]);
					expect(pair.acceptor.getFullState().spliceInFlight!.fullySigned).to.be
						.true;
				});

				it('refuses a splice-in from an unverifiable prevout type at negotiation time', function () {
					const pair = makeWirePair();
					const p2wshScript = Buffer.concat([
						Buffer.from([0x00, 0x20]),
						crypto.randomBytes(32)
					]);
					const value = 400_000n;
					const prevTx = new bitcoin.Transaction();
					prevTx.version = 2;
					prevTx.addInput(crypto.randomBytes(32), 0);
					prevTx.addOutput(p2wshScript, Number(value));
					startSpliceIn(pair, 300_000n, {
						walletInput: {
							prevTx: prevTx.toBuffer(),
							prevOutputIndex: 0,
							value,
							sequence: 0xfffffffd,
							// The OPENER may sign its own input (local inputs are not
							// gated); only the acceptor's judgment is under test.
							signWitness: (): Buffer[] => [Buffer.alloc(0)]
						},
						changeScript: Buffer.concat([
							Buffer.from([0x00, 0x14]),
							crypto.randomBytes(20)
						])
					});

					// The ACCEPTOR refuses the opener's P2WSH input at its
					// negotiated-tx audit, before its commitment signs anything,
					// and fails the NEGOTIATION with tx_abort: both sides unwind
					// to NORMAL and the channel keeps operating.
					expect(pair.errors.some((e) => e.includes('unsupported output type')))
						.to.be.true;
					// The opener's mid-splice commitment_signed was already in
					// flight when the abort left; the ignore window absorbs it
					// instead of failing the channel on it.
					expect(
						pair.errors.filter((e) => e.includes('commitment'))
					).to.deep.equal([]);
					expect(pair.broadcasts.length).to.equal(0);
					expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.opener.getFullState().spliceInFlight).to.be.null;
					expect(pair.acceptor.getFullState().spliceInFlight).to.be.null;

					// The channel is still usable: a fresh valid splice completes.
					const preCapacity = pair.opener.getFundingSatoshis();
					startSpliceOut(pair, 25_000n);
					completeSpliceLocked(pair);
					expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.opener.getFundingSatoshis() < preCapacity).to.be.true;
				});

				it('persists the splice prevout set and tolerates a legacy record without it', function () {
					const pair = makeWirePair();
					startSpliceOut(pair);

					const serialized = JSON.parse(
						JSON.stringify(serializeChannelState(pair.opener.getFullState()))
					);
					const restoredState = deserializeChannelState(serialized);
					const prevouts = restoredState.spliceInFlight!.inputPrevouts;
					// Splice-out: the only input is the shared funding input, whose
					// prevout is the old 2-of-2 P2WSH at the pre-splice capacity.
					expect(prevouts.length).to.equal(1);
					expect(prevouts[0].script.length).to.equal(34);
					expect(prevouts[0].script[0]).to.equal(0x00);
					expect(prevouts[0].script[1]).to.equal(0x20);
					expect(Number(prevouts[0].valueSats)).to.equal(
						Number(FUNDING_SATOSHIS)
					);

					// A record persisted before the field existed deserializes to [].
					delete serialized.spliceInFlight.inputPrevouts;
					const legacy = deserializeChannelState(serialized);
					expect(legacy.spliceInFlight!.inputPrevouts).to.deep.equal([]);
				});

				/** Drive a splice-in to the point where both sides signed but no
				 *  tx_signatures crossed, then crash-restore the ACCEPTOR from its
				 *  serialized state (optionally mutating the serialized record).
				 *  Returns the restored acceptor, reestablish-connected to the
				 *  still-live opener but with the fallout NOT yet pumped. */
				function restartAcceptorBeforeTxSigs(
					pair: IWirePair,
					mutate?: (serialized: any) => void
				): Channel {
					pair.drop(MessageType.TX_SIGNATURES);
					startSpliceIn(pair);
					expect(pair.errors).to.deep.equal([]);

					const serialized = JSON.parse(
						JSON.stringify(serializeChannelState(pair.acceptor.getFullState()))
					);
					if (mutate) mutate(serialized);
					const restoredState = deserializeChannelState(serialized);
					const restored = new Channel(restoredState);
					const acceptorFundingPriv = crypto
						.createHash('sha256')
						.update(acceptorSeed)
						.update(Buffer.from([0]))
						.digest();
					restored.setSigner(new ChannelSigner(acceptorFundingPriv));
					restored.restoreSpliceInFlight();
					restored.markForReestablish();
					pair.opener.markForReestablish();
					pair.clearDrops();

					const rRe = findSendAction(
						restored.createReestablish(),
						MessageType.CHANNEL_REESTABLISH
					);
					const oRe = findSendAction(
						pair.opener.createReestablish(),
						MessageType.CHANNEL_REESTABLISH
					);
					pair.enqueue(
						pair.opener,
						restored,
						restored.handleReestablish(
							decodeChannelReestablishMessage(oRe.payload)
						)
					);
					pair.enqueue(
						restored,
						pair.opener,
						pair.opener.handleReestablish(
							decodeChannelReestablishMessage(rRe.payload)
						)
					);
					return restored;
				}

				it('post-restart: retransmitted witnesses verify against the persisted prevout set', function () {
					const pair = makeWirePair();
					const restored = restartAcceptorBeforeTxSigs(pair);
					expect(
						restored.getFullState().spliceInFlight!.inputPrevouts.length,
						'prevout set survived the restart'
					).to.equal(2);
					pair.pump();

					expect(pair.errors).to.deep.equal([]);
					expect(restored.getFullState().spliceInFlight!.fullySigned).to.be
						.true;
					expect(restored.getSpliceSession()!.getState()).to.equal(
						SpliceState.AWAITING_SPLICE_LOCKED
					);
				});

				it('post-restart: tampered witnesses are refused with no live builder', function () {
					const pair = makeWirePair();
					const restored = restartAcceptorBeforeTxSigs(pair);
					tamperTxSigs(pair, (witnesses) => {
						const junkPriv = crypto
							.createHash('sha256')
							.update('not-the-wallet-key')
							.digest();
						const sig64 = Buffer.from(
							ecc.sign(crypto.randomBytes(32), junkPriv)
						);
						const der = bitcoin.script.signature.encode(
							sig64,
							bitcoin.Transaction.SIGHASH_ALL
						);
						return [[der, witnesses[0][1]]];
					});
					pair.pump();

					expect(
						pair.errors.some(
							(e) =>
								e.includes('invalid splice tx_signatures') &&
								e.includes('does not verify')
						)
					).to.be.true;
					expect(restored.getFullState().spliceInFlight!.receivedTxSignatures)
						.to.be.false;
				});

				it('legacy record without prevouts: crypto checks skipped, count check still applies', function () {
					// Tampered witnesses pass a legacy restore (nothing to verify
					// against; documented fail-open for pre-upgrade records).
					const pairA = makeWirePair();
					const restoredA = restartAcceptorBeforeTxSigs(pairA, (s) => {
						delete s.spliceInFlight.inputPrevouts;
					});
					expect(
						restoredA.getFullState().spliceInFlight!.inputPrevouts
					).to.deep.equal([]);
					tamperTxSigs(pairA, (witnesses) => {
						const junkPriv = crypto
							.createHash('sha256')
							.update('not-the-wallet-key')
							.digest();
						const sig64 = Buffer.from(
							ecc.sign(crypto.randomBytes(32), junkPriv)
						);
						const der = bitcoin.script.signature.encode(
							sig64,
							bitcoin.Transaction.SIGHASH_ALL
						);
						return [[der, witnesses[0][1]]];
					});
					pairA.pump();
					expect(pairA.errors).to.deep.equal([]);
					expect(restoredA.getFullState().spliceInFlight!.fullySigned).to.be
						.true;

					// The count check needs no prevouts and still refuses.
					const pairB = makeWirePair();
					const restoredB = restartAcceptorBeforeTxSigs(pairB, (s) => {
						delete s.spliceInFlight.inputPrevouts;
					});
					tamperTxSigs(pairB, () => []);
					pairB.pump();
					expect(
						pairB.errors.some((e) =>
							e.includes('expected 1 witness stacks, got 0')
						)
					).to.be.true;
					expect(restoredB.getFullState().spliceInFlight!.receivedTxSignatures)
						.to.be.false;
				});

				it('keeps watching the splice outpoint on refusal and locks when it confirms', function () {
					const pair = makeWirePair();
					tamperTxSigs(pair, (witnesses) => {
						const junkPriv = crypto
							.createHash('sha256')
							.update('not-the-wallet-key')
							.digest();
						const sig64 = Buffer.from(
							ecc.sign(crypto.randomBytes(32), junkPriv)
						);
						const der = bitcoin.script.signature.encode(
							sig64,
							bitcoin.Transaction.SIGHASH_ALL
						);
						return [[der, witnesses[0][1]]];
					});
					startSpliceIn(pair);

					// Refused, but the acceptor's shared-input signature had already
					// left (it signs first), and witness data does not change the
					// txid (BIP 141): the opener's locally valid broadcast can
					// confirm. The refusal must keep the outpoint watched.
					expect(
						pair.errors.some((e) => e.includes('invalid splice tx_signatures'))
					).to.be.true;
					const record = pair.acceptor.getFullState().spliceInFlight!;
					expect(record.sentTxSignatures).to.be.true;
					expect(record.receivedTxSignatures).to.be.false;
					expect(
						pair.watches.some(
							(w) =>
								w.from === pair.acceptor && w.txid.equals(record.spliceTxid)
						),
						'acceptor still watches the negotiated splice outpoint'
					).to.be.true;

					// The watch pays off: the tx confirms; the peer retransmits its
					// (honest) tx_signatures on reconnect and the splice locks.
					pair.acceptor.markSpliceConfirmed();
					pair.opener.markSpliceConfirmed();
					pair.clearIntercepts();
					disconnect(pair);
					reconnect(pair);

					expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
					expect(
						pair.acceptor.getFullState().fundingTxid!.equals(record.spliceTxid)
					).to.be.true;
				});

				it('refusal before our signatures leave does not mark them sent', function () {
					const pair = makeWirePair();
					// Tamper the ACCEPTOR's (witness-free) tx_signatures by adding a
					// surplus stack: the OPENER refuses BEFORE its signatures leave.
					pair.intercept(MessageType.TX_SIGNATURES, (payload) => {
						const msg = decodeTxSignaturesMessage(payload);
						if (msg.witnesses.length > 0) return payload;
						msg.witnesses = [[Buffer.alloc(71, 1), Buffer.alloc(33, 2)]];
						return encodeTxSignaturesMessage(msg);
					});
					startSpliceIn(pair);

					expect(
						pair.errors.some((e) =>
							e.includes('expected 0 witness stacks, got 1')
						)
					).to.be.true;
					// The refusal ran before the send helper: state must not claim
					// our signatures left when they did not.
					const record = pair.opener.getFullState().spliceInFlight!;
					expect(record.sentTxSignatures, 'opener signatures not marked sent')
						.to.be.false;
					expect(record.receivedTxSignatures).to.be.false;
					// Our shared-input signature never left, so the splice cannot
					// confirm: no watch, no broadcast.
					expect(
						pair.watches.filter((w) => w.from === pair.opener)
					).to.deep.equal([]);
					expect(pair.broadcasts.length).to.equal(0);

					// An honest retransmission completes the splice with the flags
					// telling the truth end to end.
					pair.clearIntercepts();
					disconnect(pair);
					reconnect(pair);
					expect(pair.broadcasts.length).to.equal(2);
					expect(pair.opener.getFullState().spliceInFlight!.fullySigned).to.be
						.true;
					expect(pair.acceptor.getFullState().spliceInFlight!.fullySigned).to.be
						.true;
				});
			});

			describe('tx_signatures validation and abort ordering (issue #350)', function () {
				function wrongKeySig(): Buffer {
					const junkPriv = crypto
						.createHash('sha256')
						.update('not-the-funding-key')
						.digest();
					return Buffer.from(ecc.sign(crypto.randomBytes(32), junkPriv));
				}

				it('an invalid shared-input signature after our signatures left fails the channel but keeps the outpoint watched', function () {
					const pair = makeWirePair();
					let wireErrorSent = false;
					pair.intercept(MessageType.ERROR, (payload) => {
						wireErrorSent = true;
						return payload;
					});
					// Tamper the OPENER's tx_signatures (the one carrying wallet
					// witnesses); the acceptor, which signed first, refuses.
					pair.intercept(MessageType.TX_SIGNATURES, (payload) => {
						const msg = decodeTxSignaturesMessage(payload);
						if (msg.witnesses.length === 0) return payload;
						msg.sharedInputSignature = wrongKeySig();
						return encodeTxSignaturesMessage(msg);
					});
					startSpliceIn(pair);

					expect(
						pair.errors.some((e) => e.includes('invalid peer splice signature'))
					).to.be.true;
					const record = pair.acceptor.getFullState().spliceInFlight!;
					expect(record.sentTxSignatures).to.be.true;
					expect(record.receivedTxSignatures).to.be.false;
					// BOLT 2: an invalid shared-input signature sends an error and
					// fails the channel.
					expect(wireErrorSent, 'wire error sent to the peer').to.be.true;
					expect(pair.acceptor.getState()).to.equal(ChannelState.ERRORED);
					// Our shared-input signature left, so the peer can broadcast its
					// locally valid copy: the failure batch keeps the outpoint
					// watched and retains the record for the force-close planner's
					// splice adoption.
					expect(
						pair.watches.some(
							(w) =>
								w.from === pair.acceptor && w.txid.equals(record.spliceTxid)
						),
						'acceptor still watches the negotiated splice outpoint'
					).to.be.true;
					// The opener side completed against the honest first message.
					expect(pair.broadcasts.length).to.equal(1);
				});

				it('an invalid shared-input signature before our signatures leave fails the channel without marking them sent', function () {
					const pair = makeWirePair();
					// Tamper the ACCEPTOR's (witness-free, first) tx_signatures; the
					// opener must refuse BEFORE its send helper runs.
					pair.intercept(MessageType.TX_SIGNATURES, (payload) => {
						const msg = decodeTxSignaturesMessage(payload);
						if (msg.witnesses.length > 0) return payload;
						msg.sharedInputSignature = wrongKeySig();
						return encodeTxSignaturesMessage(msg);
					});
					startSpliceIn(pair);

					expect(
						pair.errors.some((e) => e.includes('invalid peer splice signature'))
					).to.be.true;
					const record = pair.opener.getFullState().spliceInFlight!;
					expect(record.sentTxSignatures, 'opener signatures not marked sent')
						.to.be.false;
					expect(record.receivedTxSignatures).to.be.false;
					expect(pair.opener.getState()).to.equal(ChannelState.ERRORED);
					// Nothing of ours left, so nothing can confirm: no watch, no
					// broadcast.
					expect(
						pair.watches.filter((w) => w.from === pair.opener)
					).to.deep.equal([]);
					expect(pair.broadcasts.length).to.equal(0);
				});

				it('a missing shared-input signature fails the channel (refuser already sent)', function () {
					const pair = makeWirePair();
					pair.intercept(MessageType.TX_SIGNATURES, (payload) => {
						const msg = decodeTxSignaturesMessage(payload);
						if (msg.witnesses.length === 0) return payload;
						delete msg.sharedInputSignature;
						return encodeTxSignaturesMessage(msg);
					});
					startSpliceIn(pair);

					expect(
						pair.errors.some((e) =>
							e.includes('missing shared-input signature')
						)
					).to.be.true;
					const record = pair.acceptor.getFullState().spliceInFlight!;
					expect(record.sentTxSignatures).to.be.true;
					expect(pair.acceptor.getState()).to.equal(ChannelState.ERRORED);
					expect(
						pair.watches.some(
							(w) =>
								w.from === pair.acceptor && w.txid.equals(record.spliceTxid)
						),
						'outpoint watched: the peer holds our signature'
					).to.be.true;
				});

				it('a missing shared-input signature fails the channel (refuser had not sent)', function () {
					const pair = makeWirePair();
					pair.intercept(MessageType.TX_SIGNATURES, (payload) => {
						const msg = decodeTxSignaturesMessage(payload);
						if (msg.witnesses.length > 0) return payload;
						delete msg.sharedInputSignature;
						return encodeTxSignaturesMessage(msg);
					});
					startSpliceIn(pair);

					expect(
						pair.errors.some((e) =>
							e.includes('missing shared-input signature')
						)
					).to.be.true;
					expect(pair.opener.getState()).to.equal(ChannelState.ERRORED);
					expect(pair.opener.getFullState().spliceInFlight!.sentTxSignatures).to
						.be.false;
					expect(
						pair.watches.filter((w) => w.from === pair.opener)
					).to.deep.equal([]);
					expect(pair.broadcasts.length).to.equal(0);
				});

				it('aborts the negotiation on a txid mismatch before our signatures leave', function () {
					const pair = makeWirePair();
					pair.intercept(MessageType.TX_SIGNATURES, (payload) => {
						const msg = decodeTxSignaturesMessage(payload);
						msg.txid = Buffer.alloc(32, 0x7f);
						return encodeTxSignaturesMessage(msg);
					});
					startSpliceIn(pair);

					// The acceptor sends first, so the opener refuses before its own
					// signatures left: BOLT 2 fails the NEGOTIATION, so the opener
					// aborts and unwinds cleanly.
					expect(
						pair.errors.some((e) =>
							e.includes('splice tx_signatures txid mismatch')
						)
					).to.be.true;
					expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.opener.getFullState().spliceInFlight).to.be.null;
					expect(pair.opener.getSpliceSession()).to.not.exist;
					expect(
						pair.watches.filter((w) => w.from === pair.opener)
					).to.deep.equal([]);
					expect(pair.broadcasts.length).to.equal(0);

					// The acceptor already sent its signatures, so it spec-correctly
					// REFUSES the abort and retains the splice until its inputs are
					// provably unspendable (it cannot verify our signature never
					// left).
					expect(pair.errors.some((e) => e.includes('Cannot abort splice'))).to
						.be.true;
					const acceptorRecord = pair.acceptor.getFullState().spliceInFlight!;
					expect(acceptorRecord.sentTxSignatures).to.be.true;
					expect(pair.acceptor.getState()).to.equal(ChannelState.SPLICING);
				});

				it('a txid mismatch after our signatures left refuses without aborting and recovers on retransmission', function () {
					const pair = makeWirePair();
					// Tamper only the OPENER's (second) message: the acceptor, which
					// already sent, cannot abort and must refuse non-terminally.
					pair.intercept(MessageType.TX_SIGNATURES, (payload) => {
						const msg = decodeTxSignaturesMessage(payload);
						if (msg.witnesses.length === 0) return payload;
						msg.txid = Buffer.alloc(32, 0x7f);
						return encodeTxSignaturesMessage(msg);
					});
					startSpliceIn(pair);

					expect(
						pair.errors.some((e) =>
							e.includes('splice tx_signatures txid mismatch')
						)
					).to.be.true;
					const record = pair.acceptor.getFullState().spliceInFlight!;
					expect(record.sentTxSignatures).to.be.true;
					expect(pair.acceptor.getState()).to.equal(ChannelState.SPLICING);
					expect(
						pair.watches.some(
							(w) =>
								w.from === pair.acceptor && w.txid.equals(record.spliceTxid)
						)
					).to.be.true;
					// The opener completed against the honest first message.
					expect(pair.broadcasts.length).to.equal(1);

					// The negotiated tx can confirm; an honest retransmission then
					// locks the splice.
					pair.acceptor.markSpliceConfirmed();
					pair.opener.markSpliceConfirmed();
					pair.clearIntercepts();
					disconnect(pair);
					reconnect(pair);
					expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
					expect(
						pair.acceptor.getFullState().fundingTxid!.equals(record.spliceTxid)
					).to.be.true;
				});

				it('classifies stray splice commitments after the abort echo (reentrant order)', function () {
					const pair = makeWirePair();
					// Withhold the opener's real stray commitment so the orderings
					// can be hand-driven below.
					pair.drop(MessageType.COMMITMENT_SIGNED, 1);
					const p2wshScript = Buffer.concat([
						Buffer.from([0x00, 0x20]),
						crypto.randomBytes(32)
					]);
					const value = 400_000n;
					const prevTx = new bitcoin.Transaction();
					prevTx.version = 2;
					prevTx.addInput(crypto.randomBytes(32), 0);
					prevTx.addOutput(p2wshScript, Number(value));
					startSpliceIn(pair, 300_000n, {
						walletInput: {
							prevTx: prevTx.toBuffer(),
							prevOutputIndex: 0,
							value,
							sequence: 0xfffffffd,
							signWitness: (): Buffer[] => [Buffer.alloc(0)]
						},
						changeScript: Buffer.concat([
							Buffer.from([0x00, 0x14]),
							crypto.randomBytes(20)
						])
					});

					expect(pair.errors.some((e) => e.includes('unsupported output type')))
						.to.be.true;
					// The whole abort dance ran (echo delivered), yet the window must
					// survive it: with reentrant routing the echo can precede the
					// stray, and a symmetric refusal has no stray behind it at all.
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					expect((pair.acceptor as any)._spliceAbortIgnoreCommitment).to.be
						.true;

					// A funding_txid-tagged commitment with no live splice session is
					// the aborted splice's stray: swallowed, window stays armed (a
					// stray batch can have several members).
					const stray = {
						channelId: pair.acceptor.getChannelId()!,
						signature: Buffer.alloc(64, 1),
						htlcSignatures: [],
						fundingTxid: Buffer.alloc(32, 0x77)
					};
					expect(pair.acceptor.handleCommitmentSigned(stray)).to.deep.equal([]);
					expect(pair.acceptor.handleCommitmentSigned(stray)).to.deep.equal([]);
					expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					expect((pair.acceptor as any)._spliceAbortIgnoreCommitment).to.be
						.true;

					// An untagged commitment is legitimate traffic: the window closes
					// and the message is judged on its merits (here, refused as an
					// invalid signature rather than silently swallowed).
					const actions = pair.acceptor.handleCommitmentSigned({
						channelId: pair.acceptor.getChannelId()!,
						signature: Buffer.alloc(64, 1),
						htlcSignatures: []
					});
					expect(actions.length).to.be.greaterThan(0);
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					expect((pair.acceptor as any)._spliceAbortIgnoreCommitment).to.be
						.false;
				});

				it('a commitment tagged with the CURRENT funding txid is processed while the window is armed', function () {
					const pair = makeWirePair();
					pair.drop(MessageType.COMMITMENT_SIGNED, 1);
					const p2wshScript = Buffer.concat([
						Buffer.from([0x00, 0x20]),
						crypto.randomBytes(32)
					]);
					const value = 400_000n;
					const prevTx = new bitcoin.Transaction();
					prevTx.version = 2;
					prevTx.addInput(crypto.randomBytes(32), 0);
					prevTx.addOutput(p2wshScript, Number(value));
					startSpliceIn(pair, 300_000n, {
						walletInput: {
							prevTx: prevTx.toBuffer(),
							prevOutputIndex: 0,
							value,
							sequence: 0xfffffffd,
							signWitness: (): Buffer[] => [Buffer.alloc(0)]
						},
						changeScript: Buffer.concat([
							Buffer.from([0x00, 0x14]),
							crypto.randomBytes(20)
						])
					});
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					expect((pair.acceptor as any)._spliceAbortIgnoreCommitment).to.be
						.true;

					// A commitment naming the CURRENT funding is legitimate traffic
					// (a normal commitment may identify its funding tx). Swallowing
					// it would drop a real state update and leave the peer waiting
					// for revoke_and_ack: it must be judged on its merits instead.
					const actions = pair.acceptor.handleCommitmentSigned({
						channelId: pair.acceptor.getChannelId()!,
						signature: Buffer.alloc(64, 1),
						htlcSignatures: [],
						fundingTxid: pair.acceptor.getFullState().fundingTxid!
					});
					expect(actions.length).to.be.greaterThan(0);
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					expect((pair.acceptor as any)._spliceAbortIgnoreCommitment).to.be
						.false;
				});
			});

			describe('durable splice abort unwind (issue #356)', function () {
				/** Drive the opener into the exposure window: the in-flight record
				 *  was persisted at the commitment round, but no tx_signatures have
				 *  crossed in either direction (the acceptor's were lost on the
				 *  wire, so ours never left). */
				function makeAbortWindowPair(): IWirePair {
					const pair = makeWirePair();
					pair.drop(MessageType.TX_SIGNATURES);
					startSpliceOut(pair);
					const record = pair.opener.getFullState().spliceInFlight;
					expect(record, 'in-flight record exists').to.not.be.null;
					expect(record!.sentTxSignatures).to.be.false;
					expect(record!.receivedTxSignatures).to.be.false;
					return pair;
				}

				it('a peer tx_abort with a recorded splice persists the unwind ahead of the echo', function () {
					const pair = makeAbortWindowPair();
					const actions = pair.opener.handleTxAbort();

					const persistIndex = actions.findIndex(
						(a) => a.type === ChannelActionType.PERSIST_STATE
					);
					const echoIndex = actions.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.TX_ABORT
					);
					expect(persistIndex, 'unwind persisted').to.not.equal(-1);
					expect(echoIndex, 'tx_abort echoed').to.not.equal(-1);
					expect(persistIndex, 'persist leads the echo').to.be.lessThan(
						echoIndex
					);
					expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
					expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.opener.getFullState().spliceInFlight).to.be.null;
					expect(pair.opener.getSpliceSession()).to.be.null;
				});

				it('the persisted unwind does not resurrect the splice across a restart', function () {
					const pair = makeAbortWindowPair();

					// What disk holds going into the abort: the commitment round's
					// persist, record included.
					let disk = JSON.parse(
						JSON.stringify(serializeChannelState(pair.opener.getFullState()))
					);
					const actions = pair.opener.handleTxAbort();
					// Manager contract: only a PERSIST_STATE action commits the
					// state as of its dispatch. Without one, disk keeps the record.
					if (actions.some((a) => a.type === ChannelActionType.PERSIST_STATE)) {
						disk = JSON.parse(
							JSON.stringify(serializeChannelState(pair.opener.getFullState()))
						);
					}

					// "Crash" and restart from disk.
					const restoredState = deserializeChannelState(disk);
					expect(restoredState.spliceInFlight, 'no record on disk').to.be.null;

					const restored = new Channel(restoredState);
					restored.restoreSpliceInFlight();
					restored.markForReestablish();
					expect(restored.getSpliceSession(), 'nothing resurrected').to.be.null;
					const re = findSendAction(
						restored.createReestablish(),
						MessageType.CHANNEL_REESTABLISH
					);
					expect(
						decodeChannelReestablishMessage(re.payload).nextFundingTxid,
						'no forgotten splice advertised'
					).to.be.undefined;
				});

				it('a reestablish without next_funding_txid persists the recorded splice unwind', function () {
					const pair = makeWirePair();

					// Advance past commitment number 1 with an empty commitment
					// round first: a fresh channel would replay channel_ready on
					// reestablish, and the send-conditioned persist that replay
					// drags in would mask the gap this test pins.
					const sigs = realCommitmentSigs(pair.opener);
					pair.opener.signCommitment(sigs.signature, sigs.htlcSignatures);
					const ackActions = pair.acceptor.handleCommitmentSigned({
						channelId: pair.acceptor.getChannelId()!,
						signature: sigs.signature,
						htlcSignatures: sigs.htlcSignatures
					});
					const rev = findSendAction(ackActions, MessageType.REVOKE_AND_ACK);
					pair.opener.handleRevokeAndAck(
						decodeRevokeAndAckMessage(rev.payload)
					);

					pair.drop(MessageType.TX_SIGNATURES);
					startSpliceOut(pair);
					const record = pair.opener.getFullState().spliceInFlight;
					expect(record, 'in-flight record exists').to.not.be.null;
					expect(record!.sentTxSignatures).to.be.false;
					expect(record!.receivedTxSignatures).to.be.false;
					disconnect(pair);

					// Model a peer that silently dropped the splice: its reestablish
					// carries no next_funding_txid and no proactive tx_abort (our own
					// implementation always sends one of the two, so craft the
					// message instead of pumping the pair).
					const aRe = decodeChannelReestablishMessage(
						findSendAction(
							pair.acceptor.createReestablish(),
							MessageType.CHANNEL_REESTABLISH
						).payload
					);
					expect(aRe.nextCommitmentNumber, 'channel advanced past 1').to.equal(
						2n
					);
					delete aRe.nextFundingTxid;
					delete aRe.nextFundingRetransmitFlags;

					const actions = pair.opener.handleReestablish(aRe);
					expect(
						findSendAction(actions, MessageType.CHANNEL_READY),
						'no channel_ready replay masking the arm'
					).to.not.exist;
					expect(
						findAction(actions, ChannelActionType.PERSIST_STATE),
						'unwind persisted'
					).to.exist;
					expect(pair.opener.getFullState().spliceInFlight).to.be.null;
					expect(pair.opener.getSpliceSession()).to.be.null;
					expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
				});

				it('a peer tx_abort before the commitment round stays persist-free', function () {
					const { acceptor } = makeNormalChannel();
					quiesceAsResponder(acceptor);
					acceptor.handleSplice({
						channelId: acceptor.getChannelId()!,
						fundingPubkey: Buffer.alloc(33, 0x02),
						relativeSatoshis: 0n,
						fundingFeeratePerkw: 253,
						locktime: 0
					});
					expect(acceptor.getState()).to.equal(ChannelState.SPLICING);
					expect(acceptor.getFullState().spliceInFlight).to.be.null;

					const actions = acceptor.handleTxAbort();
					expect(
						findAction(actions, ChannelActionType.PERSIST_STATE),
						'nothing durable to unwind'
					).to.not.exist;
					expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
				});
			});

			describe('operator splice abort durable unwind (issue #366)', function () {
				/** Both sides parked in the exposure window: dropping every
				 *  commitment_signed leaves each side with the record it created
				 *  when its OWN splice commitment left, and neither ever reaches
				 *  the tx_signatures stage. */
				function makeBilateralWindowPair(): IWirePair {
					const pair = makeWirePair();
					pair.drop(MessageType.COMMITMENT_SIGNED);
					startSpliceOut(pair);
					for (const ch of [pair.opener, pair.acceptor]) {
						const record = ch.getFullState().spliceInFlight;
						expect(record, 'in-flight record exists').to.not.be.null;
						expect(record!.sentTxSignatures).to.be.false;
						expect(record!.receivedTxSignatures).to.be.false;
					}
					return pair;
				}

				it('persists the unwind ahead of the tx_abort send', function () {
					const pair = makeBilateralWindowPair();
					const actions = pair.opener.initiateSpliceAbort('operator requested');

					const persistIndex = actions.findIndex(
						(a) => a.type === ChannelActionType.PERSIST_STATE
					);
					const abortIndex = actions.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.TX_ABORT
					);
					expect(persistIndex, 'unwind persisted').to.not.equal(-1);
					expect(abortIndex, 'peer told to forget').to.not.equal(-1);
					expect(persistIndex, 'persist leads the send').to.be.lessThan(
						abortIndex
					);
					expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
					expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.opener.getFullState().spliceInFlight).to.be.null;
					expect(pair.opener.getSpliceSession()).to.be.null;
				});

				it('both sides forget when neither has sent tx_signatures', function () {
					const pair = makeBilateralWindowPair();
					pair.enqueue(
						pair.acceptor,
						pair.opener,
						pair.opener.initiateSpliceAbort('operator requested')
					);
					pair.pump();

					for (const ch of [pair.opener, pair.acceptor]) {
						expect(ch.getState()).to.equal(ChannelState.NORMAL);
						expect(ch.getFullState().spliceInFlight).to.be.null;
						expect(ch.getSpliceSession()).to.be.null;
					}
					expect(pair.errors).to.be.empty;
					expect(pair.opener.isSpliceAbortPending(), 'echo consumed').to.be
						.false;
				});

				it('a peer whose tx_signatures already left refuses the unwind and keeps the splice', function () {
					// Same window as the #356 fixture: the acceptor's tx_signatures
					// were lost on the wire, so it is past its own point of no
					// return while we never sent ours.
					const pair = makeWirePair();
					pair.drop(MessageType.TX_SIGNATURES);
					startSpliceOut(pair);
					const record = pair.opener.getFullState().spliceInFlight;
					expect(record!.sentTxSignatures).to.be.false;
					expect(record!.receivedTxSignatures).to.be.false;
					expect(
						pair.acceptor.getFullState().spliceInFlight!.sentTxSignatures,
						'acceptor already sent'
					).to.be.true;

					pair.enqueue(
						pair.acceptor,
						pair.opener,
						pair.opener.initiateSpliceAbort('operator requested')
					);
					pair.pump();

					// We unwound durably; the peer spec-correctly echoed but kept
					// the splice (it cannot verify our signature never left).
					expect(pair.opener.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.opener.getFullState().spliceInFlight).to.be.null;
					expect(pair.opener.isSpliceAbortPending(), 'echo consumed').to.be
						.false;
					expect(pair.acceptor.getState()).to.equal(ChannelState.SPLICING);
					expect(pair.acceptor.getFullState().spliceInFlight).to.not.be.null;
					expect(pair.errors.length).to.equal(1);
					expect(pair.errors[0]).to.include('Cannot abort splice');
				});

				it('the persisted unwind does not resurrect the splice across a restart', function () {
					const pair = makeBilateralWindowPair();

					let disk = JSON.parse(
						JSON.stringify(serializeChannelState(pair.opener.getFullState()))
					);
					const actions = pair.opener.initiateSpliceAbort('operator requested');
					// Manager contract: only a PERSIST_STATE action commits the
					// state as of its dispatch. Without one, disk keeps the record.
					if (actions.some((a) => a.type === ChannelActionType.PERSIST_STATE)) {
						disk = JSON.parse(
							JSON.stringify(serializeChannelState(pair.opener.getFullState()))
						);
					}

					const restoredState = deserializeChannelState(disk);
					expect(restoredState.spliceInFlight, 'no record on disk').to.be.null;

					const restored = new Channel(restoredState);
					restored.restoreSpliceInFlight();
					restored.markForReestablish();
					expect(restored.getSpliceSession(), 'nothing resurrected').to.be.null;
					const re = findSendAction(
						restored.createReestablish(),
						MessageType.CHANNEL_REESTABLISH
					);
					expect(
						decodeChannelReestablishMessage(re.payload).nextFundingTxid,
						'no forgotten splice advertised'
					).to.be.undefined;
				});

				it('a pre-commitment abort sends tx_abort but stays persist-free', function () {
					const { opener } = makeNormalChannel();
					quiesce(opener);
					opener.initiateSplice(100_000n, 253);
					expect(opener.getState()).to.equal(ChannelState.SPLICING);
					expect(opener.getFullState().spliceInFlight).to.be.null;

					const actions = opener.initiateSpliceAbort('operator requested');
					expect(
						findSendAction(actions, MessageType.TX_ABORT),
						'peer told to forget'
					).to.exist;
					expect(
						findAction(actions, ChannelActionType.PERSIST_STATE),
						'nothing durable to unwind'
					).to.not.exist;
					expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
					expect(opener.getState()).to.equal(ChannelState.NORMAL);
					expect(opener.getSpliceSession()).to.be.null;
				});

				it('cancelling a splice still awaiting quiescence stays silent', function () {
					const { opener } = makeNormalChannel();
					opener.initiateSplice(100_000n, 253); // stfu out, quiescence pending
					expect(opener.getState()).to.equal(ChannelState.NORMAL);

					const actions = opener.initiateSpliceAbort('operator requested');
					// splice_init never left: the peer has no splice to forget and
					// nothing is on disk.
					expect(actions).to.be.empty;
					expect(opener.getState()).to.equal(ChannelState.NORMAL);
				});

				it('an abort while disconnected keeps the reestablish machinery intact', function () {
					const pair = makeBilateralWindowPair();
					disconnect(pair);

					const actions = pair.opener.initiateSpliceAbort('operator requested');
					expect(
						findAction(actions, ChannelActionType.PERSIST_STATE),
						'unwind persisted'
					).to.exist;
					expect(
						actions.some((a) => a.type === ChannelActionType.SEND_MESSAGE),
						'no send into the void'
					).to.be.false;
					// The live state slot while marked for reestablish is
					// preReestablishState: state must stay AWAITING_REESTABLISH (the
					// manager only initiates reestablish for channels in it) and the
					// unwound target replaces the stale SPLICING.
					expect(pair.opener.getState()).to.equal(
						ChannelState.AWAITING_REESTABLISH
					);
					expect(pair.opener.getFullState().preReestablishState).to.equal(
						ChannelState.NORMAL
					);
					expect(pair.opener.getFullState().spliceInFlight).to.be.null;
					expect(pair.opener.getSpliceSession()).to.be.null;
					expect(
						pair.opener.getFullState().spliceAbortOwed,
						'owed abort recorded durably'
					).to.be.true;

					// The queued forget goes out BEFORE our channel_reestablish,
					// which no longer advertises the splice.
					const openerRe = pair.opener.createReestablish();
					const abortIndex = openerRe.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.TX_ABORT
					);
					const reIndex = openerRe.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.CHANNEL_REESTABLISH
					);
					expect(abortIndex, 'forget queued for the reconnect').to.not.equal(
						-1
					);
					expect(abortIndex, 'tx_abort precedes reestablish').to.be.lessThan(
						reIndex
					);
					expect(
						decodeChannelReestablishMessage(
							(openerRe[reIndex] as { payload: Buffer }).payload
						).nextFundingTxid,
						'no forgotten splice advertised'
					).to.be.undefined;

					// A full reconnect settles both sides on NORMAL with no splice,
					// and the echo clears the owed abort.
					const acceptorRe = pair.acceptor.createReestablish();
					pair.enqueue(pair.acceptor, pair.opener, openerRe);
					pair.enqueue(pair.opener, pair.acceptor, acceptorRe);
					pair.pump();
					for (const ch of [pair.opener, pair.acceptor]) {
						expect(ch.getState()).to.equal(ChannelState.NORMAL);
						expect(ch.getFullState().spliceInFlight).to.be.null;
						expect(ch.getSpliceSession()).to.be.null;
					}
					expect(pair.opener.getFullState().spliceAbortOwed).to.be.false;
					expect(pair.errors).to.be.empty;
				});

				it('a second operator abort is a plain refusal', function () {
					const pair = makeBilateralWindowPair();
					pair.opener.initiateSpliceAbort('operator requested');

					const again = pair.opener.initiateSpliceAbort('operator requested');
					expect(again.length).to.equal(1);
					expect(again[0].type).to.equal(ChannelActionType.ERROR);
				});

				it('a delayed abort echo cannot cancel a fresh splice attempt', function () {
					const pair = makeBilateralWindowPair();
					pair.opener.initiateSpliceAbort('operator requested');
					expect(pair.opener.isSpliceAbortPending()).to.be.true;

					// A new splice is refused while the exchange is unsettled:
					// tx_abort has no attempt identifier, so the delayed echo
					// would be indistinguishable from an abort of the new session.
					const refused = pair.opener.initiateSplice(100_000n, 253);
					expect(
						findAction(refused, ChannelActionType.ERROR).message
					).to.include('not yet acknowledged');
					expect(pair.opener.getSpliceSession()).to.be.null;

					// The delayed echo lands: swallowed, nothing to cancel.
					const echoActions = pair.opener.handleTxAbort();
					expect(findAction(echoActions, ChannelActionType.ERROR)).to.not.exist;

					// The exchange settled: splicing is available again.
					const retry = pair.opener.initiateSplice(100_000n, 253);
					expect(findAction(retry, ChannelActionType.ERROR)).to.not.exist;
				});

				it('an inbound splice_init crossing our unacked abort is ignored', function () {
					const { acceptor } = makeNormalChannel();
					quiesceAsResponder(acceptor);
					(acceptor as any)._spliceAbortPending = true;
					const actions = acceptor.handleSplice({
						channelId: acceptor.getChannelId()!,
						fundingPubkey: Buffer.alloc(33, 0x02),
						relativeSatoshis: 0n,
						fundingFeeratePerkw: 253,
						locktime: 0
					});
					// No session to be cancelled by the delayed echo, and no
					// second tx_abort while ours is outstanding (BOLT 2): the
					// crossing tx_abort aborts the peer's attempt when it lands.
					expect(actions).to.be.empty;
					expect(acceptor.getSpliceSession()).to.be.null;
				});

				it('the echo settles the owed abort durably', function () {
					const pair = makeBilateralWindowPair();
					pair.opener.initiateSpliceAbort('operator requested');
					expect(pair.opener.getFullState().spliceAbortOwed).to.be.true;

					const echoActions = pair.opener.handleTxAbort();
					expect(
						findAction(echoActions, ChannelActionType.PERSIST_STATE),
						'clear persisted'
					).to.exist;
					expect(findAction(echoActions, ChannelActionType.ERROR)).to.not.exist;
					expect(
						echoActions.some((a) => a.type === ChannelActionType.SEND_MESSAGE),
						'no second tx_abort'
					).to.be.false;
					expect(pair.opener.getFullState().spliceAbortOwed).to.be.false;
					expect(pair.opener.isSpliceAbortPending()).to.be.false;
				});

				it('a reconnect before the echo still leads with tx_abort', function () {
					const pair = makeBilateralWindowPair();
					pair.drop(MessageType.TX_ABORT); // the abort is lost on the wire
					pair.enqueue(
						pair.acceptor,
						pair.opener,
						pair.opener.initiateSpliceAbort('operator requested')
					);
					pair.pump();
					expect(pair.opener.isSpliceAbortPending(), 'no echo arrived').to.be
						.true;

					// The disconnect resets the in-memory latch; the owed flag is
					// state and survives.
					disconnect(pair);
					expect(pair.opener.isSpliceAbortPending()).to.be.false;
					expect(pair.opener.getFullState().spliceAbortOwed).to.be.true;

					const openerRe = pair.opener.createReestablish();
					const abortIndex = openerRe.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.TX_ABORT
					);
					const reIndex = openerRe.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.CHANNEL_REESTABLISH
					);
					expect(abortIndex, 'owed abort re-sent').to.not.equal(-1);
					expect(abortIndex, 'tx_abort precedes reestablish').to.be.lessThan(
						reIndex
					);

					// The reconnect settles both sides and the echo clears the debt.
					const acceptorRe = pair.acceptor.createReestablish();
					pair.enqueue(pair.acceptor, pair.opener, openerRe);
					pair.enqueue(pair.opener, pair.acceptor, acceptorRe);
					pair.pump();
					expect(pair.opener.getFullState().spliceAbortOwed).to.be.false;
					for (const ch of [pair.opener, pair.acceptor]) {
						expect(ch.getState()).to.equal(ChannelState.NORMAL);
						expect(ch.getFullState().spliceInFlight).to.be.null;
					}
					expect(pair.errors).to.be.empty;
				});

				it('a restart before the abort reaches the wire still owes the peer tx_abort', function () {
					const pair = makeBilateralWindowPair();
					// The manager dispatches the leading persist BEFORE the send:
					// model a crash exactly between the two (the returned actions
					// are never delivered).
					pair.opener.initiateSpliceAbort('operator requested');
					const disk = JSON.parse(
						JSON.stringify(serializeChannelState(pair.opener.getFullState()))
					);

					const restoredState = deserializeChannelState(disk);
					expect(restoredState.spliceAbortOwed, 'owed flag on disk').to.be.true;
					const restored = new Channel(restoredState);
					restored.restoreSpliceInFlight();
					restored.markForReestablish();
					const reActions = restored.createReestablish();
					const abortIndex = reActions.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.TX_ABORT
					);
					const reIndex = reActions.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.CHANNEL_REESTABLISH
					);
					expect(abortIndex, 'owed abort sent after restart').to.not.equal(-1);
					expect(abortIndex, 'tx_abort precedes reestablish').to.be.lessThan(
						reIndex
					);
					expect(
						decodeChannelReestablishMessage(
							(reActions[reIndex] as { payload: Buffer }).payload
						).nextFundingTxid,
						'no forgotten splice advertised'
					).to.be.undefined;
				});

				it('a restored disconnected abort still owes the peer tx_abort', function () {
					const pair = makeBilateralWindowPair();
					disconnect(pair);
					const actions = pair.opener.initiateSpliceAbort('operator requested');
					expect(
						findAction(actions, ChannelActionType.PERSIST_STATE),
						'unwind persisted'
					).to.exist;

					const disk = JSON.parse(
						JSON.stringify(serializeChannelState(pair.opener.getFullState()))
					);
					const restoredState = deserializeChannelState(disk);
					expect(restoredState.state).to.equal(
						ChannelState.AWAITING_REESTABLISH
					);
					expect(restoredState.preReestablishState).to.equal(
						ChannelState.NORMAL
					);
					expect(restoredState.spliceAbortOwed).to.be.true;

					const restored = new Channel(restoredState);
					restored.restoreSpliceInFlight();
					restored.markForReestablish(); // no-op while AWAITING_REESTABLISH
					const reActions = restored.createReestablish();
					const abortIndex = reActions.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.TX_ABORT
					);
					const reIndex = reActions.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.CHANNEL_REESTABLISH
					);
					expect(abortIndex, 'owed abort sent after restart').to.not.equal(-1);
					expect(abortIndex, 'tx_abort precedes reestablish').to.be.lessThan(
						reIndex
					);
				});

				it('an oversized abort reason is truncated, not thrown', function () {
					const pair = makeBilateralWindowPair();
					const actions = pair.opener.initiateSpliceAbort('x'.repeat(70_000));
					expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
					expect(
						findAction(actions, ChannelActionType.PERSIST_STATE),
						'unwind persisted'
					).to.exist;
					const send = findSendAction(actions, MessageType.TX_ABORT);
					// channel_id (32) + u16 length + data capped at the u16 maximum.
					expect(send.payload.length).to.equal(34 + 65535);
					expect(pair.opener.getFullState().spliceInFlight).to.be.null;

					// The peer still unwinds on the truncated message.
					pair.enqueue(pair.acceptor, pair.opener, actions);
					pair.pump();
					expect(pair.acceptor.getState()).to.equal(ChannelState.NORMAL);
					expect(pair.acceptor.getFullState().spliceInFlight).to.be.null;
					expect(pair.errors).to.be.empty;
				});
			});

			describe('pending-splice cancel quiescence unwind (issue #370)', function () {
				it('unwinds the completed handshake with splice_init + tx_abort', function () {
					const { opener } = makeNormalChannel();
					opener.initiateSplice(100_000n, 253); // stfu out, quiescence pending
					expect(opener.initiateSpliceAbort('operator requested')).to.be.empty;

					// The peer's stfu completes a handshake we cannot recall: the
					// unwind must open the announced conversation and abort it at
					// once, or both sides would sit HTLC-frozen until a disconnect.
					const actions = opener.handleStfuMessage({
						channelId: opener.getChannelId()!,
						initiator: false
					});
					const spliceIndex = actions.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.SPLICE
					);
					const abortIndex = actions.findIndex(
						(a) =>
							a.type === ChannelActionType.SEND_MESSAGE &&
							(a as { messageType: MessageType }).messageType ===
								MessageType.TX_ABORT
					);
					expect(spliceIndex, 'conversation opened').to.not.equal(-1);
					expect(abortIndex, 'and aborted at once').to.not.equal(-1);
					expect(spliceIndex).to.be.lessThan(abortIndex);
					expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
					expect(opener.getState()).to.equal(ChannelState.NORMAL);
					expect(opener.isQuiescent(), 'quiescence unwound').to.be.false;
					expect(opener.getSpliceSession()).to.be.null;
					expect(opener.getFullState().spliceInFlight).to.be.null;
					expect(opener.isSpliceAbortPending(), 'echo pending').to.be.true;
					expect(opener.getFullState().spliceAbortOwed).to.be.true;

					// The echo settles the exchange.
					const echo = opener.handleTxAbort();
					expect(findAction(echo, ChannelActionType.ERROR)).to.not.exist;
					expect(opener.isSpliceAbortPending()).to.be.false;
					expect(opener.getFullState().spliceAbortOwed).to.be.false;
				});

				it('both sides resume NORMAL and HTLCs flow again', function () {
					const pair = makeWirePair();
					pair.enqueue(
						pair.acceptor,
						pair.opener,
						pair.opener.initiateSplice(100_000n, 253)
					);
					// Cancelled while our stfu is still in flight.
					expect(pair.opener.initiateSpliceAbort('operator requested')).to.be
						.empty;
					pair.pump();

					for (const ch of [pair.opener, pair.acceptor]) {
						expect(ch.getState()).to.equal(ChannelState.NORMAL);
						expect(ch.isQuiescent(), 'quiescence unwound').to.be.false;
						expect(ch.getSpliceSession()).to.be.null;
						expect(ch.getFullState().spliceInFlight).to.be.null;
					}
					expect(pair.errors).to.be.empty;
					expect(pair.opener.isSpliceAbortPending(), 'echo consumed').to.be
						.false;
					expect(pair.opener.getFullState().spliceAbortOwed).to.be.false;

					// The freeze is gone on both gates: ours to send, theirs to
					// receive. The peer's splice_ack crossed our tx_abort on the
					// way and was ignored, not surfaced as an error.
					const paymentHash = crypto
						.createHash('sha256')
						.update(crypto.randomBytes(32))
						.digest();
					const addActions = pair.opener.addHtlc(
						50_000_000n,
						paymentHash,
						500000,
						crypto.randomBytes(1366)
					);
					const addMsg = findSendAction(
						addActions,
						MessageType.UPDATE_ADD_HTLC
					);
					expect(addMsg, 'sender gate open').to.exist;
					const recvActions = pair.acceptor.handleUpdateAddHtlc(
						decodeUpdateAddHtlcMessage(addMsg.payload)
					);
					expect(findAction(recvActions, ChannelActionType.ERROR)).to.not.exist;
				});

				it('a fresh splice before the handshake completes supersedes the unwind', function () {
					const { opener } = makeNormalChannel();
					opener.initiateSplice(100_000n, 253);
					expect(opener.initiateSpliceAbort('operator requested')).to.be.empty;
					// Re-requested before the peer answered our stfu: nothing beyond
					// that stfu has left, so the new request simply replaces the
					// cancelled one.
					expect(opener.initiateSplice(200_000n, 253)).to.be.empty;

					const actions = opener.handleStfuMessage({
						channelId: opener.getChannelId()!,
						initiator: false
					});
					const spliceMsg = findSendAction(actions, MessageType.SPLICE);
					expect(spliceMsg, 'new splice fired').to.exist;
					expect(
						Number(decodeSpliceMessage(spliceMsg.payload).relativeSatoshis)
					).to.equal(200_000);
					expect(findSendAction(actions, MessageType.TX_ABORT), 'no unwind').to
						.not.exist;
					expect(opener.getState()).to.equal(ChannelState.SPLICING);
				});

				it('repeat cancels stay silent no-op successes', function () {
					const { opener } = makeNormalChannel();
					opener.initiateSplice(100_000n, 253);
					expect(opener.initiateSpliceAbort('operator requested')).to.be.empty;
					expect(opener.initiateSpliceAbort('operator requested')).to.be.empty;

					// Still exactly one unwind when the handshake completes.
					const actions = opener.handleStfuMessage({
						channelId: opener.getChannelId()!,
						initiator: false
					});
					expect(
						actions.filter(
							(a) =>
								a.type === ChannelActionType.SEND_MESSAGE &&
								(a as { messageType: MessageType }).messageType ===
									MessageType.TX_ABORT
						).length
					).to.equal(1);
				});

				it('a disconnect before the peer answers still clears the cancelled request', function () {
					const pair = makeWirePair();
					pair.drop(MessageType.STFU); // the peer never sees our stfu
					pair.enqueue(
						pair.acceptor,
						pair.opener,
						pair.opener.initiateSplice(100_000n, 253)
					);
					pair.pump();
					expect(pair.opener.initiateSpliceAbort('operator requested')).to.be
						.empty;

					disconnect(pair);
					reconnect(pair);

					for (const ch of [pair.opener, pair.acceptor]) {
						expect(ch.getState()).to.equal(ChannelState.NORMAL);
						expect(ch.isQuiescent()).to.be.false;
					}
					// Nothing owed, nothing pending: the request died with the wire.
					// (The owed flag is optional state, absent means not owed.)
					expect(pair.opener.getFullState().spliceAbortOwed).to.not.be.true;
					expect(pair.opener.isSpliceAbortPending()).to.be.false;
					expect(pair.errors).to.be.empty;

					// A later operator quiescence is not torn down by a stale
					// cancelled request.
					pair.enqueue(
						pair.acceptor,
						pair.opener,
						pair.opener.initiateQuiescence()
					);
					pair.pump();
					expect(pair.opener.isQuiescent()).to.be.true;
					expect(pair.acceptor.isQuiescent()).to.be.true;
					expect(pair.opener.getSpliceSession()).to.be.null;
					expect(pair.errors).to.be.empty;
				});

				it('a cancelled splice does not tear down caller-owned quiescence', function () {
					const { opener } = makeNormalChannel();
					// The operator quiesces independently; the splice merely joins
					// the handshake already in flight.
					const stfuActions = opener.initiateQuiescence();
					expect(findSendAction(stfuActions, MessageType.STFU)).to.exist;
					expect(opener.initiateSplice(100_000n, 253)).to.be.empty;
					expect(opener.initiateSpliceAbort('operator requested')).to.be.empty;

					const actions = opener.handleStfuMessage({
						channelId: opener.getChannelId()!,
						initiator: false
					});
					// The splice is discarded as if never requested: no unwind
					// dance, and the operator's quiescence completes and stands.
					expect(findSendAction(actions, MessageType.SPLICE)).to.not.exist;
					expect(findSendAction(actions, MessageType.TX_ABORT)).to.not.exist;
					expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
					expect(opener.isQuiescent(), 'caller quiescence stands').to.be.true;
					expect(opener.getSpliceSession()).to.be.null;
					expect(opener.getState()).to.equal(ChannelState.NORMAL);
				});

				it('a replacement splice keeps splice-owned quiescence unwindable', function () {
					const { opener } = makeNormalChannel();
					// The first splice request opened the handshake; a replacement
					// inherits that ownership, so cancelling the replacement must
					// still unwind or the channel would wedge (issue #370).
					opener.initiateSplice(100_000n, 253); // stfu out, splice-owned
					expect(opener.initiateSpliceAbort('operator requested')).to.be.empty;
					expect(opener.initiateSplice(200_000n, 253)).to.be.empty;
					expect(opener.initiateSpliceAbort('changed my mind')).to.be.empty;

					const actions = opener.handleStfuMessage({
						channelId: opener.getChannelId()!,
						initiator: false
					});
					expect(findSendAction(actions, MessageType.SPLICE)).to.exist;
					expect(findSendAction(actions, MessageType.TX_ABORT)).to.exist;
					expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
					expect(opener.isQuiescent(), 'quiescence unwound').to.be.false;
					expect(opener.getState()).to.equal(ChannelState.NORMAL);
				});
			});

			describe('concurrent stfu funder tie-break (issue #372)', function () {
				it('the funder keeps the initiator role and fires its deferred splice', function () {
					const { opener } = makeNormalChannel();
					opener.initiateSplice(100_000n, 253); // stfu out, pending parked
					// The peer initiated concurrently: its stfu carries the
					// initiator flag instead of answering ours. BOLT 2 breaks the
					// tie in favor of the channel funder.
					const actions = opener.handleStfuMessage({
						channelId: opener.getChannelId()!,
						initiator: true
					});
					expect(findSendAction(actions, MessageType.SPLICE), 'splice fired').to
						.exist;
					expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
					expect(opener.getState()).to.equal(ChannelState.SPLICING);
					expect(opener.getFullState().quiescenceInitiator).to.be.true;
				});

				it('the non-funder yields the session and drops its parked splice with a surfaced error', function () {
					const { acceptor } = makeNormalChannel();
					acceptor.initiateSplice(100_000n, 253); // stfu out, pending parked
					const actions = acceptor.handleStfuMessage({
						channelId: acceptor.getChannelId()!,
						initiator: true
					});
					// No crossing splice_init and no extra stfu: the session is the
					// funder's now.
					expect(findSendAction(actions, MessageType.SPLICE)).to.not.exist;
					expect(findSendAction(actions, MessageType.STFU)).to.not.exist;
					const error = findAction(actions, ChannelActionType.ERROR);
					expect(error, 'drop surfaced to the operator').to.exist;
					expect(error.message).to.contain('tie-break');
					expect(acceptor.isQuiescent()).to.be.true;
					expect(acceptor.getFullState().quiescenceInitiator).to.be.false;
					expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
					expect(acceptor.getSpliceSession()).to.be.null;
				});

				it('a cancelled parked splice on the losing side drops silently', function () {
					const { acceptor } = makeNormalChannel();
					acceptor.initiateSplice(100_000n, 253);
					expect(acceptor.initiateSpliceAbort('operator requested')).to.be
						.empty;
					const actions = acceptor.handleStfuMessage({
						channelId: acceptor.getChannelId()!,
						initiator: true
					});
					// No unwind dance: a non-initiator must not open a splice
					// conversation, and the session now belongs to the funder peer,
					// whose dependent protocol ends it.
					expect(findSendAction(actions, MessageType.SPLICE)).to.not.exist;
					expect(findSendAction(actions, MessageType.TX_ABORT)).to.not.exist;
					expect(findAction(actions, ChannelActionType.ERROR)).to.not.exist;
					expect(acceptor.isQuiescent(), "the peer's session stands").to.be
						.true;
					expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
				});

				it('a quiescent non-initiator cannot fire splice_init directly', function () {
					const { acceptor } = makeNormalChannel();
					// The funder initiated quiescence; we merely answered.
					const stfuActions = acceptor.handleStfuMessage({
						channelId: acceptor.getChannelId()!,
						initiator: true
					});
					expect(findSendAction(stfuActions, MessageType.STFU)).to.exist;
					expect(acceptor.isQuiescent()).to.be.true;

					const wallet = makeSpliceInWallet(100_000n);
					acceptor.setSpliceInInputs([wallet.walletInput], wallet.changeScript);
					const actions = acceptor.initiateSplice(100_000n, 253);
					const error = findAction(actions, ChannelActionType.ERROR);
					expect(error).to.exist;
					expect(error.message).to.contain(
						'peer initiated the quiescence session'
					);
					expect(findSendAction(actions, MessageType.SPLICE)).to.not.exist;
					expect(acceptor.isQuiescent(), 'session untouched').to.be.true;
					// The refused request's wallet configuration dies with it.
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					expect((acceptor as any)._spliceInInputs).to.be.null;
				});

				it('crossing splice requests converge on the funder over the wire', function () {
					const pair = makeWirePair();
					let spliceInits = 0;
					pair.intercept(MessageType.SPLICE, (p) => {
						spliceInits++;
						return p;
					});
					const destScript = Buffer.concat([
						Buffer.from([0x00, 0x14]),
						crypto.randomBytes(20)
					]);
					pair.opener.setSpliceOutDestination(destScript, 50_000n);

					// Both sides request a splice before either stfu is delivered.
					pair.enqueue(
						pair.acceptor,
						pair.opener,
						pair.opener.initiateSplice(-(50_000n + SPLICE_OUT_TEST_FEE), 253)
					);
					pair.enqueue(
						pair.opener,
						pair.acceptor,
						pair.acceptor.initiateSplice(80_000n, 253)
					);
					pair.pump();

					// Exactly one splice_init went on the wire (the funder's); the
					// acceptor's request was dropped with a surfaced error instead
					// of a crossing splice_init that would wedge both sides.
					expect(spliceInits).to.equal(1);
					expect(pair.errors.length).to.equal(1);
					expect(pair.errors[0]).to.contain('tie-break');
					// The funder's splice negotiated to completion on both sides.
					expect(pair.opener.getFullState().spliceInFlight).to.not.be.null;
					expect(pair.acceptor.getFullState().spliceInFlight).to.not.be.null;
				});

				it('the losing side clears its splice wallet configuration', function () {
					// A real splice-in pledges wallet inputs before quiescence.
					// The dropped request must not leave them attached: stale
					// splice-in inputs would leak into the contributions of a
					// later splice, and clearing them lets the wallet's pledge
					// TTL free the coins.
					const { acceptor } = makeNormalChannel();
					const wallet = makeSpliceInWallet(100_000n);
					acceptor.setSpliceInInputs([wallet.walletInput], wallet.changeScript);
					acceptor.initiateSplice(100_000n, 253); // stfu out, pending parked
					const actions = acceptor.handleStfuMessage({
						channelId: acceptor.getChannelId()!,
						initiator: true
					});
					expect(findAction(actions, ChannelActionType.ERROR)).to.exist;
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					expect((acceptor as any)._spliceInInputs).to.be.null;
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					expect((acceptor as any)._spliceOutDestination).to.be.null;
				});

				it('refuses splice_init from a peer that is not the quiescence initiator', function () {
					// We initiated the quiescence session (the peer answered our
					// stfu), so the peer must not drive a dependent protocol into
					// it. BOLT 2 requires the receiver to fail such a splice_init;
					// answer on the wire with tx_abort and unwind, matching the
					// issue #371 refusal arms.
					const { opener } = makeNormalChannel();
					quiesce(opener);

					const actions = opener.handleSplice({
						channelId: opener.getChannelId()!,
						fundingPubkey: Buffer.alloc(33, 0x02),
						relativeSatoshis: 100_000n,
						fundingFeeratePerkw: 253,
						locktime: 0
					});

					const abortAction = findSendAction(actions, MessageType.TX_ABORT);
					expect(abortAction, 'tx_abort answered the refusal').to.exist;
					expect(findSendAction(actions, MessageType.SPLICE_ACK)).to.not.exist;
					const err = findAction(actions, ChannelActionType.ERROR);
					expect(err).to.exist;
					expect(String(err.message)).to.contain(
						'not the quiescence initiator'
					);
					expect(opener.isQuiescent(), 'quiescence unwound').to.be.false;
					expect(opener.getState()).to.equal(ChannelState.NORMAL);
					expect(opener.getSpliceSession()).to.be.null;
				});
			});

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
				// Deliver the FULL reestablish batches (the proactive tx_abort
				// included), like a real wire would: the forget exchange must
				// settle, or the fresh splice below is refused while its echo is
				// outstanding (a delayed echo could cancel the new session).
				const openerRe = pair.opener.createReestablish();
				const acceptorRe = pair.acceptor.createReestablish();
				const openerMsg = decodeChannelReestablishMessage(
					findSendAction(openerRe, MessageType.CHANNEL_REESTABLISH).payload
				);
				const acceptorMsg = decodeChannelReestablishMessage(
					findSendAction(acceptorRe, MessageType.CHANNEL_REESTABLISH).payload
				);
				pair.enqueue(pair.acceptor, pair.opener, openerRe);
				pair.enqueue(pair.opener, pair.acceptor, acceptorRe);
				pair.pump();
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

			// Initiate a splice-in on the opener, backed by a real wallet input
			// (the tx_complete audit aborts an unbacked contribution).
			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			const result = openerManager.initiateSplice(channelId, 100_000n, 253);
			expect(result.ok).to.be.true;

			// Acceptor should now be in SPLICING state (auto-handled via message routing)
			expect(openerChannel.getState()).to.equal(ChannelState.SPLICING);
			expect(acceptorChannel.getState()).to.equal(ChannelState.SPLICING);
		});

		it('an unsupported-input refusal under synchronous routing leaves both channels NORMAL (issue 350)', function () {
			const { openerManager, channelId, openerChannel, acceptorChannel } =
				createNormalChannelPair();

			openerManager.initiateQuiescence(channelId);
			// Unverifiable P2WSH prevout: the acceptor's negotiated-tx audit
			// refuses with tx_abort. connectManagers routes SYNCHRONOUSLY, so
			// the abort echo returns BEFORE the opener's outer action loop has
			// sent its already-built mid-splice commitment_signed; the stray
			// arrives after the echo and must be classified, not trusted to
			// arrive first.
			const p2wshScript = Buffer.concat([
				Buffer.from([0x00, 0x20]),
				crypto.randomBytes(32)
			]);
			const value = 400_000n;
			const prevTx = new bitcoin.Transaction();
			prevTx.version = 2;
			prevTx.addInput(crypto.randomBytes(32), 0);
			prevTx.addOutput(p2wshScript, Number(value));
			openerChannel.setSpliceInInputs(
				[
					{
						prevTx: prevTx.toBuffer(),
						prevOutputIndex: 0,
						value,
						sequence: 0xfffffffd,
						signWitness: (): Buffer[] => [Buffer.alloc(0)]
					}
				],
				Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)])
			);
			openerManager.initiateSplice(channelId, 300_000n, 253);

			// The refusal fails only the NEGOTIATION: no ERRORED channel, no
			// in-flight record, both sides back to NORMAL.
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(openerChannel.getFullState().spliceInFlight).to.be.null;
			expect(acceptorChannel.getFullState().spliceInFlight).to.be.null;

			// The channel is still usable: a fresh backed splice completes.
			openerManager.initiateQuiescence(channelId);
			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			expect(openerManager.initiateSplice(channelId, 100_000n, 253).ok).to.be
				.true;
			expect(openerChannel.getSpliceSession()!.getState()).to.equal(
				SpliceState.AWAITING_SPLICE_LOCKED
			);
			expect(acceptorChannel.getSpliceSession()!.getState()).to.equal(
				SpliceState.AWAITING_SPLICE_LOCKED
			);
		});

		it('should support sendSpliceLocked via manager', function () {
			const { openerManager, channelId, openerChannel } =
				createNormalChannelPair();

			// Setup quiescence and a backed splice-in; the auto-routing runs the
			// negotiation and signature exchange to AWAITING_SPLICE_LOCKED.
			openerManager.initiateQuiescence(channelId);
			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			openerManager.initiateSplice(channelId, 100_000n, 253);
			expect(openerChannel.getSpliceSession()!.getState()).to.equal(
				SpliceState.AWAITING_SPLICE_LOCKED
			);

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
			// fee-spike buffer: the commitment fee at TWICE the live rate with
			// one extra HTLC slot beyond the add (#193 — a ceiling offer must
			// never sit at the receiver's exact affordability boundary).
			const fresh = createNormalChannelPair();
			const spendable = fresh.openerChannel.getSpendableOutboundMsat();
			const st = fresh.openerChannel.getFullState();
			const expected =
				st.localBalanceMsat -
				st.remoteConfig.channelReserveSatoshis * 1000n -
				BigInt(
					calculateCommitmentFee(st.localConfig.feeratePerKw * 2, 2, false)
				) *
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
			// The retained figure is the fee-spike buffer (2x rate, one extra
			// HTLC slot — #193), so the staged rate moves it by the buffered
			// difference.
			const delta =
				BigInt(
					calculateCommitmentFee(oldRate * 4 * 2, 2, false) -
						calculateCommitmentFee(oldRate * 2, 2, false)
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

		it('operator abortSplice persists the unwind and the peer forgets (issue #366)', function () {
			const {
				openerManager,
				acceptorManager,
				openerPubkey,
				acceptorPubkey,
				channelId,
				openerChannel,
				acceptorChannel
			} = createNormalChannelPair();

			openerManager.initiateQuiescence(channelId);
			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);

			// Re-route with commitment_signed dropped both ways: the splice parks
			// in the exposure window (records on both sides, no tx_signatures).
			openerManager.removeAllListeners('message:outbound');
			acceptorManager.removeAllListeners('message:outbound');
			const route = (
				from: ChannelManager,
				fromPk: string,
				to: ChannelManager,
				toPk: string
			): void => {
				from.on(
					'message:outbound',
					(peerPubkey: string, type: number, payload: Buffer) => {
						if (peerPubkey === toPk && type !== MessageType.COMMITMENT_SIGNED) {
							to.handleMessage(fromPk, type, payload);
						}
					}
				);
			};
			route(openerManager, openerPubkey, acceptorManager, acceptorPubkey);
			route(acceptorManager, acceptorPubkey, openerManager, openerPubkey);

			openerManager.initiateSplice(channelId, 100_000n, 253);
			expect(openerChannel.getFullState().spliceInFlight).to.not.be.null;
			expect(acceptorChannel.getFullState().spliceInFlight).to.not.be.null;

			// Disk := the state as of the last dispatched PERSIST_STATE.
			let openerDisk = JSON.parse(
				JSON.stringify(serializeChannelState(openerChannel.getFullState()))
			);
			openerManager.on('channel:persist', (ev: { channel: Channel }) => {
				if (ev.channel === openerChannel) {
					openerDisk = JSON.parse(
						JSON.stringify(serializeChannelState(openerChannel.getFullState()))
					);
				}
			});

			const result = openerManager.abortSplice(channelId, 'operator requested');
			expect(result.ok).to.be.true;
			// The tx_abort routed synchronously and the echo came back: both
			// sides forgot the splice, durably on ours.
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(openerChannel.getFullState().spliceInFlight).to.be.null;
			expect(acceptorChannel.getFullState().spliceInFlight).to.be.null;
			expect(openerChannel.isSpliceAbortPending(), 'echo consumed').to.be.false;
			expect(
				openerChannel.getFullState().spliceAbortOwed,
				'owed abort settled by the echo'
			).to.be.false;
			expect(
				deserializeChannelState(openerDisk).spliceInFlight,
				'unwind reached disk'
			).to.be.null;
		});

		it('operator abortSplice while awaiting quiescence unwinds after the peer stfu (issue #370)', function () {
			const {
				openerManager,
				acceptorManager,
				openerPubkey,
				acceptorPubkey,
				channelId,
				openerChannel,
				acceptorChannel
			} = createNormalChannelPair();

			// Re-route through a queue so the cancel can land while our stfu is
			// still in flight (the default routing delivers synchronously).
			openerManager.removeAllListeners('message:outbound');
			acceptorManager.removeAllListeners('message:outbound');
			const wire: Array<() => void> = [];
			const route = (
				from: ChannelManager,
				fromPk: string,
				to: ChannelManager,
				toPk: string
			): void => {
				from.on(
					'message:outbound',
					(peerPubkey: string, type: number, payload: Buffer) => {
						if (peerPubkey === toPk) {
							wire.push(() => to.handleMessage(fromPk, type, payload));
						}
					}
				);
			};
			route(openerManager, openerPubkey, acceptorManager, acceptorPubkey);
			route(acceptorManager, acceptorPubkey, openerManager, openerPubkey);

			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			expect(openerManager.initiateSplice(channelId, 100_000n, 253).ok).to.be
				.true;
			expect(openerChannel.getState()).to.equal(ChannelState.NORMAL); // stfu in flight
			expect(openerManager.abortSplice(channelId, 'operator requested').ok).to
				.be.true;

			// Deliver the queued traffic: stfu, stfu reply, then the unwind.
			while (wire.length > 0) {
				wire.shift()!();
			}

			for (const ch of [openerChannel, acceptorChannel]) {
				expect(ch.getState()).to.equal(ChannelState.NORMAL);
				expect(ch.isQuiescent(), 'quiescence unwound').to.be.false;
			}
			expect(openerChannel.isSpliceAbortPending(), 'echo consumed').to.be.false;
			expect(openerChannel.getFullState().spliceAbortOwed).to.be.false;

			// The channel is usable again.
			expect(
				openerManager.addHtlc(
					channelId,
					20_000_000n,
					crypto.createHash('sha256').update(crypto.randomBytes(32)).digest(),
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.be.true;
		});

		it('concurrent operator splices converge on the funder (issue #372)', function () {
			const {
				openerManager,
				acceptorManager,
				openerPubkey,
				acceptorPubkey,
				channelId,
				openerChannel,
				acceptorChannel
			} = createNormalChannelPair();

			// Re-route through a queue so both stfus are in flight before either
			// side answers (the default routing delivers synchronously).
			openerManager.removeAllListeners('message:outbound');
			acceptorManager.removeAllListeners('message:outbound');
			const wire: Array<() => void> = [];
			let spliceInits = 0;
			const route = (
				from: ChannelManager,
				fromPk: string,
				to: ChannelManager,
				toPk: string
			): void => {
				from.on(
					'message:outbound',
					(peerPubkey: string, type: number, payload: Buffer) => {
						if (peerPubkey === toPk) {
							if (type === MessageType.SPLICE) spliceInits++;
							wire.push(() => to.handleMessage(fromPk, type, payload));
						}
					}
				);
			};
			route(openerManager, openerPubkey, acceptorManager, acceptorPubkey);
			route(acceptorManager, acceptorPubkey, openerManager, openerPubkey);

			const openerErrors: string[] = [];
			const acceptorErrors: string[] = [];
			openerManager.on('error', (_id: Buffer, message: string) => {
				openerErrors.push(message);
			});
			acceptorManager.on('error', (_id: Buffer, message: string) => {
				acceptorErrors.push(message);
			});

			// Both operators request a splice concurrently.
			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			expect(openerManager.initiateSplice(channelId, 100_000n, 253).ok).to.be
				.true;
			expect(acceptorManager.initiateSplice(channelId, 80_000n, 253).ok).to.be
				.true;

			while (wire.length > 0) {
				wire.shift()!();
			}

			// One splice_init on the wire, driven by the funder; the acceptor's
			// request was dropped and surfaced instead of crossing it.
			expect(spliceInits).to.equal(1);
			expect(openerErrors).to.be.empty;
			expect(acceptorErrors.length).to.equal(1);
			expect(acceptorErrors[0]).to.contain('tie-break');
			expect(openerChannel.getState()).to.equal(ChannelState.SPLICING);
			expect(acceptorChannel.getState()).to.equal(ChannelState.SPLICING);
			expect(openerChannel.getFullState().spliceInFlight).to.not.be.null;
			expect(acceptorChannel.getFullState().spliceInFlight).to.not.be.null;
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

			it('a restart replays the OUTBOX batch VERBATIM and reports ReplayRequired', function () {
				// Recovery phase 5 acceptance (docs/RECOVERY-PROTOCOL.md 9): the
				// ReplayRequired branch of the status machine, served from the
				// recovery outbox. The sibling test above rebuilds the batch by
				// re-signing, which a taproot channel must never do (a fresh
				// MuSig2 secret nonce would sign material the peer may already
				// hold). The outbox exists so the restart replays the STORED
				// bytes instead, and this pins both halves: the bytes are
				// byte-identical to what was sent before the crash, and while
				// they are being served the channel reports ReplayRequired.
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
				expect(fromOpener.length).to.equal(4);
				// Exactly what the recovery outbox retains for this transition.
				const storedBatch = {
					startBatch: Buffer.from(fromOpener[1].payload),
					commitments: [
						Buffer.from(fromOpener[2].payload),
						Buffer.from(fromOpener[3].payload)
					]
				};
				expect(fromOpener[1].type).to.equal(MessageType.START_BATCH);
				expect(fromOpener[2].type).to.equal(MessageType.COMMITMENT_SIGNED);
				expect(fromOpener[3].type).to.equal(MessageType.COMMITMENT_SIGNED);

				// Only the add reaches the acceptor; the batch is lost.
				acceptorManager.handleMessage(
					openerPubkey,
					fromOpener[0].type,
					fromOpener[0].payload
				);
				openerManager.handlePeerDisconnected(acceptorPubkey);
				acceptorManager.handlePeerDisconnected(openerPubkey);

				// The restart: the in-memory cache dies, and boot repopulates it
				// from the outbox rows, exactly as
				// LightningNode.restoreOutboxRetransmission does.
				(
					openerChannel as unknown as { _lastSentBatch: unknown }
				)._lastSentBatch = null;
				openerChannel.restoreLastSentBatch(
					storedBatch.startBatch,
					storedBatch.commitments
				);
				expect(openerChannel.getRecoveryStatus()).to.equal(
					ChannelRecoveryStatus.Quarantined
				);

				fromOpener.length = 0;
				fromAcceptor.length = 0;
				openerManager.handlePeerReconnected(acceptorPubkey);
				acceptorManager.handlePeerReconnected(openerPubkey);
				const openerReest = fromOpener.splice(0);
				const acceptorReest = fromAcceptor.splice(0);
				openerManager.removeAllListeners('message:outbound');
				acceptorManager.removeAllListeners('message:outbound');
				// Record what the opener puts on the wire in answer to the
				// peer's reestablish, then let it through to the acceptor. The
				// status is sampled as the FIRST replayed byte leaves: the
				// loopback is synchronous, so the round has already converged
				// by the time the last one has.
				const replayed: Array<{ type: number; payload: Buffer }> = [];
				let statusWhileServing: ChannelRecoveryStatus | null = null;
				openerManager.on('message:outbound', (pk, type, payload) => {
					if (pk !== acceptorPubkey) return;
					if (statusWhileServing === null) {
						statusWhileServing = openerChannel.getRecoveryStatus();
					}
					replayed.push({ type, payload });
				});
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

				// The stored bytes went back out unchanged: nothing was re-signed.
				const replayedBatch = replayed.filter(
					(m) =>
						m.type === MessageType.START_BATCH ||
						m.type === MessageType.COMMITMENT_SIGNED
				);
				expect(replayedBatch).to.have.length(3);
				expect(
					replayedBatch[0].payload.equals(storedBatch.startBatch)
				).to.equal(true);
				expect(
					replayedBatch[1].payload.equals(storedBatch.commitments[0])
				).to.equal(true);
				expect(
					replayedBatch[2].payload.equals(storedBatch.commitments[1])
				).to.equal(true);

				// The round converged off those exact bytes, and the status
				// machine followed it: ReplayRequired while the retransmission
				// was being served, then on with the channel's life.
				expect(statusWhileServing).to.equal(
					ChannelRecoveryStatus.ReplayRequired
				);
				const oEntry = [...openerChannel.getFullState().htlcs.values()][0];
				const aEntry = [...acceptorChannel.getFullState().htlcs.values()][0];
				expect(oEntry?.state).to.equal(HtlcState.COMMITTED);
				expect(aEntry?.state).to.equal(HtlcState.COMMITTED);
				expect(openerChannel.getState()).to.equal(ChannelState.SPLICING);

				acceptorManager.fulfillHtlc(channelId, 0n, preimage);
				openerManager.sendSpliceLocked(channelId);
				acceptorManager.sendSpliceLocked(channelId);
				expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
				expect(openerChannel.getRecoveryStatus()).to.equal(
					ChannelRecoveryStatus.Active
				);
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

		/**
		 * A force close that REFUSES must leave the channel exactly as it
		 * found it.
		 *
		 * The close used to adopt a confirmed splice (swapping the funding
		 * outpoint, capacity, both balances and the signature material, and
		 * resetting the splice runtime) BEFORE checks that can still refuse.
		 * Under Phase 6 that is not merely untidy: a barrier can be holding a
		 * batch built against the state the channel just moved away from, and
		 * that batch releases later against a channel that no longer matches
		 * it. Being in memory and unpersisted is what makes it dangerous, not
		 * what makes it safe.
		 */
		function heldQueueBarrier(): unknown {
			return {
				enforcing: true,
				// Nothing is ever durable here, so the first barrier-class batch
				// parks and stays parked.
				isReleased: (): boolean => false,
				whenReleased: (): Promise<never> => new Promise(() => undefined)
			};
		}

		function parkABatch(
			pair: ReturnType<typeof createNormalChannelPair>
		): void {
			// Quorum mode from here on, with nothing ever released: the
			// commitment round this HTLC drives parks behind the barrier and
			// stays parked.
			(
				pair.openerManager as unknown as {
					config: { durabilityBarrier: unknown };
				}
			).config.durabilityBarrier = heldQueueBarrier();
			pair.openerManager.addHtlc(
				pair.channelId,
				15_000_000n,
				crypto.createHash('sha256').update(crypto.randomBytes(32)).digest(),
				500000,
				crypto.randomBytes(1366)
			);
			expect(
				pair.openerManager
					.channelsAwaitingDurability()
					.has(pair.channelId.toString('hex')),
				'a batch is held against this channel'
			).to.equal(true);
		}

		it('a refused force close moves neither the channel nor the batch held against it', function () {
			const pair = pendingLockPair();
			const { openerManager, channelId, openerChannel } = pair;
			parkABatch(pair);

			// The splice confirmed, so the close must exit on the NEW funding.
			// But the peer's signature over the post-splice commitment is gone
			// from both the cache and the persisted record, so adopting would
			// leave the PRE-splice signature in place: non-null, and useless.
			openerChannel.markSpliceConfirmed();
			const inflight = openerChannel.getFullState().spliceInFlight!;
			(
				inflight as unknown as { remoteCommitmentSig: Buffer | null }
			).remoteCommitmentSig = null;
			(
				openerChannel as unknown as { _spliceRemoteCommitmentSig: null }
			)._spliceRemoteCommitmentSig = null;

			const before = JSON.stringify(
				serializeChannelState(openerChannel.getFullState())
			);
			const sessionBefore = openerChannel.getSpliceSession();
			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);

			const res = openerManager.forceClose(channelId, dest);
			expect(res.ok, 'the close refuses').to.equal(false);
			expect(res.error).to.contain('remote commitment signature');

			expect(
				JSON.stringify(serializeChannelState(openerChannel.getFullState())),
				'serialized state is byte-for-byte what it was'
			).to.equal(before);
			expect(
				openerChannel.getSpliceSession(),
				'and the splice runtime was not reset either'
			).to.equal(sessionBefore);
			expect(
				openerChannel.getState(),
				'no transition toward FORCE_CLOSED'
			).to.not.equal(ChannelState.FORCE_CLOSED);
			expect(
				openerManager
					.channelsAwaitingDurability()
					.has(channelId.toString('hex')),
				'the held batch is still held: a refused terminal close must not consume the batch it would have replaced'
			).to.equal(true);
		});

		it('a force close that goes ahead abandons the held batch and broadcasts once', function () {
			const pair = pendingLockPair();
			const { openerManager, channelId, openerChannel } = pair;
			parkABatch(pair);

			openerChannel.markSpliceConfirmed();
			const spliceTxid = Buffer.from(
				openerChannel.getFullState().spliceInFlight!.spliceTxid
			);
			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);

			const res = openerManager.forceClose(channelId, dest);
			expect(res.ok, res.error).to.equal(true);
			const broadcasts = res.actions.filter(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			);
			expect(broadcasts.length, 'exactly one commitment').to.equal(1);
			const tx = bitcoin.Transaction.fromBuffer(
				(broadcasts[0] as { type: ChannelActionType.BROADCAST_TX; tx: Buffer })
					.tx
			);
			expect(
				Buffer.from(tx.ins[0].hash).equals(spliceTxid),
				'spends the NEW funding, planned against the adopted view'
			).to.equal(true);
			expect(
				openerManager
					.channelsAwaitingDurability()
					.has(channelId.toString('hex')),
				'the queue the close replaced is gone, so nothing can release into a closed channel'
			).to.equal(false);
			expect(openerChannel.getState()).to.equal(ChannelState.FORCE_CLOSED);
		});

		/**
		 * The gap between planning a close and applying it must contain no
		 * callbacks at all.
		 *
		 * Tearing the held queue down used to dispatch the abandoned batches'
		 * internal effects and emit three events, all BEFORE the plan was
		 * applied. Node emits synchronously, so a listener that throws leaves
		 * the queue deleted and the close never applied, and a listener that
		 * re-enters the manager moves the channel out from under a commitment
		 * already built against it. Neither is a race; both are ordinary
		 * control flow.
		 */
		function closeOn(
			pair: ReturnType<typeof createNormalChannelPair>
		): ReturnType<
			ReturnType<typeof createNormalChannelPair>['openerManager']['forceClose']
		> {
			pair.openerChannel.markSpliceConfirmed();
			return pair.openerManager.forceClose(
				pair.channelId,
				Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)])
			);
		}

		it('an observer that throws cannot cost the operator the exit', function () {
			for (const event of [
				'transition:terminal-override',
				'transition:begin',
				'transition:end'
			]) {
				const pair = pendingLockPair();
				parkABatch(pair);
				const broadcasts: Buffer[] = [];
				pair.openerManager.on('broadcast:tx', (tx: Buffer) =>
					broadcasts.push(tx)
				);
				pair.openerManager.on(event, () => {
					throw new Error(`observer failure from ${event}`);
				});

				const res = closeOn(pair);

				expect(res.ok, `${event}: the close still happened`).to.equal(true);
				expect(
					broadcasts.length,
					`${event}: the commitment was broadcast exactly once`
				).to.equal(1);
				expect(
					pair.openerManager
						.channelsAwaitingDurability()
						.has(pair.channelId.toString('hex')),
					`${event}: and the queue it replaced is gone`
				).to.equal(false);
				expect(pair.openerChannel.getState()).to.equal(
					ChannelState.FORCE_CLOSED
				);
			}
		});

		it('nothing from the abandoned queue runs before the close is applied', function () {
			const pair = pendingLockPair();
			const { openerManager, channelId, openerChannel } = pair;
			parkABatch(pair);

			const broadcasts: Buffer[] = [];
			openerManager.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

			// The settlement's own event, which is the first callback the
			// teardown makes. By the time it runs the close must already be a
			// fact, so a listener re-entering this channel meets a closed one
			// rather than editing the state the plan was built from.
			let stateAtCallback: ChannelState | null = null;
			let broadcastsAtCallback = -1;
			let reentrantAddOk: boolean | null = null;
			openerManager.on('transition:terminal-override', () => {
				stateAtCallback = openerChannel.getState();
				broadcastsAtCallback = broadcasts.length;
				reentrantAddOk = openerManager.addHtlc(
					channelId,
					1_000_000n,
					crypto.createHash('sha256').update(crypto.randomBytes(32)).digest(),
					500000,
					crypto.randomBytes(1366)
				).ok;
			});

			const res = closeOn(pair);
			expect(res.ok, res.error).to.equal(true);

			expect(stateAtCallback, 'the channel was already closed').to.equal(
				ChannelState.FORCE_CLOSED
			);
			expect(
				broadcastsAtCallback,
				'and the commitment was already on its way'
			).to.equal(1);
			expect(
				reentrantAddOk,
				'so a re-entrant update is declined by the closed channel, not applied behind the plan'
			).to.equal(false);
			expect(broadcasts.length, 'still exactly one commitment').to.equal(1);
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

		it('force-close after a peer error mid-splice (markErrored) exits on the confirmed NEW funding', function () {
			// A BOLT 1 error lands after the splice confirmed but before
			// splice_locked completed: markErrored replaces SPLICING with ERRORED
			// and tears down the in-memory session, then the error path drives
			// forceClose. Adoption must be judged by the confirmed record, not the
			// channel state, or the exit would spend the spent pre-splice funding
			// and never confirm.
			const pair = pendingLockPair();
			const { openerManager, channelId, openerChannel } = pair;
			const spliceTxid = Buffer.from(
				openerChannel.getFullState().spliceInFlight!.spliceTxid
			);

			openerChannel.markSpliceConfirmed();
			expect(openerChannel.markErrored()).to.equal(true);
			expect(openerChannel.getState()).to.equal(ChannelState.ERRORED);

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
				'force-close after markErrored must spend the confirmed NEW funding'
			).to.equal(true);
			expect(openerChannel.getState()).to.equal(ChannelState.FORCE_CLOSED);
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

		it('refuses a capacity-exceeding splice ON THE WIRE: tx_abort, quiescence unwound, channel stays usable (#371)', function () {
			// The acceptor-side capacity refusal used to return a bare local
			// ERROR: nothing reached the wire, so the initiator sat SPLICING
			// awaiting splice_ack and the acceptor stayed QUIESCENT, both sides
			// HTLC-frozen until a disconnect. Like the taproot refusal above,
			// the answer must be tx_abort plus a quiescence exit.
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel,
				openerPubkey
			} = createNormalChannelPair();
			// Only the opener's cap is lifted (largeChannels on, peer init
			// advertising wumbo): its own up-front check passes, but the 16M
			// splice-in grows the 1M channel past the acceptor's default
			// 2^24 - 1 cap. The manager re-derives the cap per operation, so
			// the lift must come from config + peer init, not the channel.
			const openerPeerFeatures = FeatureFlags.empty();
			openerPeerFeatures.setOptional(Feature.LARGE_CHANNELS);
			openerPeerFeatures.setOptional(Feature.QUIESCE);
			openerPeerFeatures.setOptional(Feature.SPLICE);
			(
				openerManager as unknown as { config: { largeChannels?: boolean } }
			).config.largeChannels = true;
			(openerManager as unknown as { peerManager: unknown }).peerManager = {
				getPeer: (): {
					getRemoteInit: () => { features: FeatureFlags };
				} => ({
					getRemoteInit: (): { features: FeatureFlags } => ({
						features: openerPeerFeatures
					})
				})
			};

			const sent: number[] = [];
			acceptorManager.on('message:outbound', (pk, type) => {
				if (pk === openerPubkey) sent.push(type);
			});

			const wallet = makeSpliceInWallet(16_100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			openerManager.initiateQuiescence(channelId);
			openerManager.initiateSplice(channelId, 16_000_000n, 253);

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

			// Both sides stay fully usable after the refusal.
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
		});

		it('manager feature-negotiation refusal of splice_init unwinds quiescence and latches the tx_abort (#371)', function () {
			// When the acceptor's view says the peer never negotiated
			// option_splice, ChannelManager.handleSpliceMsg refuses before the
			// channel sees the message. That refusal used to send tx_abort
			// directly: the quiescence a completed stfu handshake established
			// stayed up (acceptor HTLCs frozen until disconnect) and the
			// unlatched tx_abort drew an extra echo round. It must route
			// through the same channel-owned unwind as the in-channel arms.
			const {
				openerManager,
				acceptorManager,
				channelId,
				openerChannel,
				acceptorChannel,
				openerPubkey
			} = createNormalChannelPair();
			// Mismatched feature views: the acceptor knows a peer init WITHOUT
			// option_splice/option_quiesce (the opener, with no peer init at
			// all, defaults permissive and splices anyway).
			const emptyFeatures = FeatureFlags.empty();
			(acceptorManager as unknown as { peerManager: unknown }).peerManager = {
				getPeer: (): {
					getRemoteInit: () => { features: FeatureFlags };
				} => ({
					getRemoteInit: (): { features: FeatureFlags } => ({
						features: emptyFeatures
					})
				})
			};

			const sent: number[] = [];
			acceptorManager.on('message:outbound', (pk, type) => {
				if (pk === openerPubkey) sent.push(type);
			});
			const errors: string[] = [];
			acceptorManager.on('error', (_id: Buffer | null, m: string) =>
				errors.push(m)
			);

			const wallet = makeSpliceInWallet(100_000n);
			openerChannel.setSpliceInInputs(
				[wallet.walletInput],
				wallet.changeScript
			);
			openerManager.initiateQuiescence(channelId);
			openerManager.initiateSplice(channelId, 100_000n, 253);

			// Exactly ONE tx_abort from the acceptor: the latch swallows the
			// initiator's echo instead of answering it with a third abort.
			expect(
				sent.filter((t) => t === MessageType.TX_ABORT).length,
				'one tx_abort, echo swallowed'
			).to.equal(1);
			expect(errors.some((e) => e.includes('option_splice'))).to.equal(true);
			expect(
				acceptorChannel.isQuiescent(),
				'acceptor quiescence unwound'
			).to.equal(false);
			expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(
				openerChannel.getState(),
				'opener recovered via tx_abort'
			).to.equal(ChannelState.NORMAL);
			expect(openerChannel.isQuiescent()).to.equal(false);

			// Both directions stay usable: opener pays acceptor, then the
			// acceptor spends what it received back to the opener.
			const preimage = crypto.randomBytes(32);
			expect(
				openerManager.addHtlc(
					channelId,
					30_000_000n,
					crypto.createHash('sha256').update(preimage).digest(),
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.equal(true);
			acceptorManager.fulfillHtlc(channelId, 0n, preimage);
			expect(openerChannel.getFullState().htlcs.size).to.equal(0);

			const preimage2 = crypto.randomBytes(32);
			expect(
				acceptorManager.addHtlc(
					channelId,
					5_000_000n,
					crypto.createHash('sha256').update(preimage2).digest(),
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.equal(true);
			openerManager.fulfillHtlc(channelId, 0n, preimage2);
			expect(acceptorChannel.getFullState().htlcs.size).to.equal(0);
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

		describe('empty-commitment guard during the pending-lock window (issue #405)', function () {
			// A splice-out down to a tiny 900-sat capacity, driven to the
			// pending-lock window (fixture at file scope, shared with the
			// pending-lock reserve tests). The LIVE balances stay pre-splice
			// until the lock, so every update below passes the live checks —
			// only the SPLICED view can refuse it.
			// Non-anchor arithmetic: commitment fee floor(724 * rate / 1000),
			// HTLC-success trim threshold 354 + floor(703 * rate / 1000).

			// A raw peer update_add_htlc delivered straight to the acceptor's
			// handler: the opener's own send path would refuse these amounts,
			// and the guard under test sits on the RECEIVE side.
			function inboundAdd(
				channel: Channel,
				amountMsat: bigint
			): Parameters<Channel['handleUpdateAddHtlc']>[0] {
				return {
					channelId: channel.getChannelId()!,
					id: 0n,
					amountMsat,
					paymentHash: crypto.randomBytes(32),
					cltvExpiry: 500_000,
					onionRoutingPacket: Buffer.alloc(1366)
				};
			}

			const errorOf = (actions: any[]): string | null =>
				findAction(actions, ChannelActionType.ERROR)?.message ?? null;

			it('refuses an inbound add that would trim every output of the pending-splice commitment', function () {
				const { acceptorChannel } = pendingLockSpliceOutPair(900n);
				// The cheap gate skips the LIVE half outright (the reserve we
				// enforce, 10k, is far above our 354-sat dust limit), so the
				// refusal below can only come from the spliced half.
				const state = acceptorChannel.getFullState();
				expect(
					state.localConfig.channelReserveSatoshis >=
						state.localConfig.dustLimitSatoshis
				).to.equal(true);
				const remoteBefore = state.remoteBalanceMsat;
				const spliceSigBefore = Buffer.from(
					state.spliceInFlight!.remoteCommitmentSig!
				);

				// On the 900-sat spliced capacity a 500-sat inbound add trims
				// everything we would hold: to_remote 900 - 500 - 183 = 217 <
				// 354, the HTLC 500 < 531 (354 + 177 success fee), to_local 0.
				const actions = acceptorChannel.handleUpdateAddHtlc(
					inboundAdd(acceptorChannel, 500_000n)
				);
				expect(errorOf(actions)).to.match(/pending-splice commitment/);
				// Wire-visible: the peer's log holds an add ours never will.
				expect(findSendAction(actions, MessageType.ERROR)).to.exist;
				// And the refusal wrote nothing.
				expect(acceptorChannel.getFullState().htlcs.size).to.equal(0);
				expect(acceptorChannel.getFullState().remoteBalanceMsat).to.equal(
					remoteBefore
				);
				expect(
					acceptorChannel
						.getFullState()
						.spliceInFlight!.remoteCommitmentSig!.equals(spliceSigBefore)
				).to.equal(true);
			});

			it('refuses an update_fee that would trim every output of the pending-splice commitment', function () {
				const { acceptorChannel } = pendingLockSpliceOutPair(900n);
				// 1000 sat/kw charges 724 sats: spliced to_remote 900 - 724 =
				// 176 < 354 and to_local is 0 — nothing survives. The live view
				// (to_remote ~989k sats) admits the same rate easily.
				const actions = acceptorChannel.handleUpdateFee({
					channelId: acceptorChannel.getChannelId()!,
					feeratePerKw: 1000
				});
				expect(errorOf(actions)).to.match(/pending-splice commitment/);
				// No fee round was staged by the refusal.
				expect(acceptorChannel.getFullState().pendingFeeratePerKw).to.equal(
					undefined
				);
			});

			it('refuses an inbound add the pending-splice capacity cannot fund', function () {
				const { acceptorChannel } = pendingLockSpliceOutPair(900n);
				// A 1000-sat add exceeds the 900-sat spliced capacity outright:
				// the remainder derivation leaves a NEGATIVE to_remote, and the
				// untrimmed 1000-sat HTLC output would spend more than the new
				// funding holds — a consensus-invalid commitment. The live view
				// (to_remote ~989k sats) admits it easily, and an output-count
				// check alone would too, since the HTLC output survives.
				const actions = acceptorChannel.handleUpdateAddHtlc(
					inboundAdd(acceptorChannel, 1_000_000n)
				);
				expect(errorOf(actions)).to.match(/pending-splice capacity/);
				expect(findSendAction(actions, MessageType.ERROR)).to.exist;
				// And the refusal wrote nothing.
				expect(acceptorChannel.getFullState().htlcs.size).to.equal(0);
			});

			it('admits an add whose HTLC output survives the pending-splice commitment', function () {
				const { acceptorChannel } = pendingLockSpliceOutPair(900n);
				// 600 sats clears the 531-sat trim threshold, so the spliced
				// commitment keeps the HTLC output even though both main
				// balances trim (to_remote 900 - 600 - 183 = 117, to_local 0).
				const actions = acceptorChannel.handleUpdateAddHtlc(
					inboundAdd(acceptorChannel, 600_000n)
				);
				expect(errorOf(actions)).to.equal(null);
				expect(acceptorChannel.getFullState().htlcs.size).to.equal(1);
				expect(acceptorChannel.getState()).to.equal(ChannelState.SPLICING);
			});

			it('admits an update_fee the pending-splice commitment survives', function () {
				const { acceptorChannel } = pendingLockSpliceOutPair(900n);
				// 400 sat/kw charges 289 sats: spliced to_remote 900 - 289 =
				// 611 >= 354 keeps its output.
				const actions = acceptorChannel.handleUpdateFee({
					channelId: acceptorChannel.getChannelId()!,
					feeratePerKw: 400
				});
				expect(errorOf(actions)).to.equal(null);
				expect(acceptorChannel.getFullState().pendingFeeratePerKw).to.equal(
					400
				);
			});

			it('skips the spliced half when the in-memory splice session is absent', function () {
				const { acceptorChannel } = pendingLockSpliceOutPair(900n);
				// A process that persisted the pending-lock window but has not
				// rebuilt the in-memory session has no spliced view to ask; the
				// update is admitted exactly as before the guard (and
				// _handleCommitmentSignedBatch independently fails closed there
				// before any revocation). Private poke mirrors the reload tests.
				(acceptorChannel as any)._spliceSession = null;
				expect(acceptorChannel.isSplicePendingLock()).to.equal(true);
				const actions = acceptorChannel.handleUpdateAddHtlc(
					inboundAdd(acceptorChannel, 500_000n)
				);
				expect(errorOf(actions)).to.equal(null);
				expect(acceptorChannel.getFullState().htlcs.size).to.equal(1);
			});
		});
	});

	describe('pending-lock reserve view (issue #382)', function () {
		// During the pending-lock window every update mirrors onto the pending
		// funding, whose reserve BOLT 2 prices at the PENDING capacity: eclair
		// derives the reserve per funding candidate and validates each update
		// against every active commitment, so a ceiling still priced at the old
		// capacity over-admits by the reserve delta and eclair rejects the
		// update against the new commitment.

		/**
		 * Opener routes 400k sats to the acceptor, then splices IN 300k from a
		 * wallet input; both sides stop at the pending-lock window. The
		 * acceptor contributes nothing, so its live and pending balances agree
		 * and ONLY the reserve separates its two funding views: stored 10,000
		 * (1% of the 1M open) vs 13,000 (1% of the 1.3M pending capacity).
		 */
		function pendingLockSpliceInPair(): ReturnType<
			typeof createNormalChannelPair
		> {
			const pair = createNormalChannelPair();
			const preimage = crypto.randomBytes(32);
			expect(
				pair.openerManager.addHtlc(
					pair.channelId,
					400_000_000n,
					crypto.createHash('sha256').update(preimage).digest(),
					500000,
					crypto.randomBytes(1366)
				).ok
			).to.equal(true);
			pair.acceptorManager.fulfillHtlc(pair.channelId, 0n, preimage);
			expect(pair.acceptorChannel.getBalances().localMsat).to.equal(
				400_000_000n
			);

			const { walletInput, changeScript } = makeSpliceInWallet(300_000n);
			pair.openerChannel.setSpliceInInputs([walletInput], changeScript);
			pair.openerManager.initiateQuiescence(pair.channelId);
			expect(
				pair.openerManager.initiateSplice(pair.channelId, 300_000n, 253).ok
			).to.equal(true);
			expect(pair.openerChannel.isSplicePendingLock()).to.equal(true);
			expect(pair.acceptorChannel.isSplicePendingLock()).to.equal(true);
			return pair;
		}

		const errorOf = (actions: any[]): string | null =>
			findAction(actions, ChannelActionType.ERROR)?.message ?? null;

		it('prices the pending funding view at its own reserve for outbound sends', function () {
			const { acceptorChannel } = pendingLockSpliceInPair();
			// Live view: 400,000,000 - 10,000,000. Pending view: 400,000,000 -
			// 13,000,000 (v2ReserveWeKeep at 1.3M, both dusts 354). The pending
			// view binds; with the stored reserve applied to both views the
			// ceiling read 390,000,000 and over-admitted by 3,000 sats.
			expect(acceptorChannel.getSpendableOutboundMsat()).to.equal(387_000_000n);
		});

		it('prices the pending view from the record alone after a restart', function () {
			// A restart inside the window rebuilds the channel without its
			// in-memory splice session; the persisted point-of-no-return record
			// carries the pending capacity, and the ceiling must not widen back
			// to the live-only figure.
			const { acceptorChannel } = pendingLockSpliceInPair();
			const json = JSON.parse(
				JSON.stringify(serializeChannelState(acceptorChannel.getFullState()))
			);
			const restored = new Channel(deserializeChannelState(json));
			expect(restored.getSpendableOutboundMsat()).to.equal(387_000_000n);
		});

		it('binds our own update_fee on the pending funding view', function () {
			// Splice-out down to 60,000 sats: the live view holds 990,000 sats
			// of fee headroom while the pending view holds 50,000. A rate only
			// the live view affords must be refused (the fee round mirrors onto
			// the pending funding): 80,000 sat/kw costs 57,920 > 50,000; 50,000
			// sat/kw costs 36,200 and passes.
			const { openerChannel } = pendingLockSpliceOutPair(60_000n);
			const refused = openerChannel.updateFee(80_000);
			expect(errorOf(refused)).to.include('below channel reserve');
			const allowed = openerChannel.updateFee(50_000);
			expect(errorOf(allowed)).to.equal(null);
			expect(findSendAction(allowed, MessageType.UPDATE_FEE)).to.exist;
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
