/**
 * Per-splice lock depth (issue #760).
 *
 * A zero-conf channel locks a splice the moment tx_signatures complete. When
 * the splice carries an input this node does not vouch for (a stranger's
 * direct funding), that puts the stranger's coin under the live funding at
 * broadcast. A splice may now carry a lock depth: the confirmations it must
 * reach before EITHER side sends splice_locked, whatever the channel type.
 *
 * These tests pin the invariants:
 *  - the depth rides splice_init as an odd TLV and must come back on
 *    splice_ack; the legacy two-byte require_confirmed_inputs form still
 *    decodes, unknown odd TLVs are skipped, unknown even ones are refused,
 *  - on a zero-conf channel neither side locks at tx_signatures, every splice
 *    funding watch reports at the lock depth, and the lock at depth completes
 *    the splice without owing a rebroadcast,
 *  - an acceptor that drops the echo gets tx_abort before any tx_add_input,
 *  - the depth survives the durable record and a restart re-arms the funding
 *    watch with it.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';

bitcoin.initEccLib(ecc);

import {
	Channel,
	ISpliceWalletInput
} from '../../src/lightning/channel/channel';
import {
	createOpenerState,
	createAcceptorState,
	ISpliceInFlight
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
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
	ISpliceMessage,
	ISpliceAckMessage,
	SPLICE_LOCK_DEPTH_TLV,
	SPLICE_LOCK_DEPTH_MAX,
	encodeSpliceMessage,
	decodeSpliceMessage,
	encodeSpliceAckMessage,
	decodeSpliceAckMessage,
	decodeSpliceLockedMessage
} from '../../src/lightning/message/splice';
import { decodeStfuMessage } from '../../src/lightning/message/stfu';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import {
	serializeChannelState,
	deserializeChannelState,
	serializeSpliceInFlight,
	deserializeSpliceInFlight
} from '../../src/lightning/storage/serialization';
import {
	signerFromSeed,
	realInitialCommitmentSig
} from './helpers/real-signing';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { InvalidSpliceError } from '../../src/lightning/node/types';

const FUNDING_SATOSHIS = 1_000_000n;
const SPLICE_AMOUNT = 300_000n;
const OWN_UTXO_SATS = SPLICE_AMOUNT + 100_000n;
const LOCK_DEPTH = 3;

const openerSeed = Buffer.alloc(32, 0x31);
const acceptorSeed = Buffer.alloc(32, 0x32);
const openerCommitmentSeed = crypto
	.createHash('sha256')
	.update('splice-lock-depth-opener')
	.digest();
const acceptorCommitmentSeed = crypto
	.createHash('sha256')
	.update('splice-lock-depth-acceptor')
	.digest();

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
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
		firstPerCommitmentPoint: getPublicKey(keys[5])
	};
}

function zeroConfType(): Buffer {
	const flags = new FeatureFlags();
	flags.setOptional(Feature.ZERO_CONF);
	return flags.toBuffer();
}

const display = (b: Buffer): string => Buffer.from(b).reverse().toString('hex');

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

const CHANNEL_ID = Buffer.alloc(32, 0xcd);
const FUNDING_PUBKEY = getPublicKey(Buffer.alloc(32, 0x07));

function baseInit(): ISpliceMessage {
	return {
		channelId: CHANNEL_ID,
		fundingPubkey: FUNDING_PUBKEY,
		relativeSatoshis: 250_000n,
		fundingFeeratePerkw: 1_000,
		locktime: 800_000
	};
}

function baseAck(): ISpliceAckMessage {
	return {
		channelId: CHANNEL_ID,
		fundingPubkey: FUNDING_PUBKEY,
		relativeSatoshis: -20_000n
	};
}

/** The raw lock_depth TLV: bigsize type 65537, length 2, u16 value. */
function lockDepthTlv(depth: number, valueBytes = 2): Buffer {
	const value = Buffer.alloc(2);
	value.writeUInt16BE(depth, 0);
	return Buffer.concat([
		Buffer.from([0xfe, 0x00, 0x01, 0x00, 0x01]),
		Buffer.from([valueBytes]),
		value.subarray(0, Math.min(valueBytes, 2))
	]);
}

describe('Splice lock depth codec (issue #760)', function () {
	it('exposes the TLV type in the experimental odd range', function () {
		expect(SPLICE_LOCK_DEPTH_TLV).to.equal(65537);
		expect(SPLICE_LOCK_DEPTH_TLV % 2).to.equal(1);
		expect(SPLICE_LOCK_DEPTH_MAX).to.equal(2016);
	});

	it('splice_init round-trips lockDepth', function () {
		const encoded = encodeSpliceMessage({ ...baseInit(), lockDepth: 3 });
		expect(encoded.length).to.equal(81 + 8);
		expect(encoded.subarray(81).equals(lockDepthTlv(3))).to.equal(true);
		const decoded = decodeSpliceMessage(encoded);
		expect(decoded.lockDepth).to.equal(3);
		expect(decoded.requireConfirmedInputs).to.equal(undefined);
		expect(decoded.relativeSatoshis).to.equal(250_000n);
		expect(decoded.fundingFeeratePerkw).to.equal(1_000);
		expect(decoded.locktime).to.equal(800_000);
	});

	it('splice_ack round-trips lockDepth', function () {
		const encoded = encodeSpliceAckMessage({ ...baseAck(), lockDepth: 6 });
		expect(encoded.length).to.equal(73 + 8);
		const decoded = decodeSpliceAckMessage(encoded);
		expect(decoded.lockDepth).to.equal(6);
		expect(decoded.requireConfirmedInputs).to.equal(undefined);
		expect(decoded.relativeSatoshis).to.equal(-20_000n);
	});

	it('a message without the TLV decodes with lockDepth undefined', function () {
		expect(decodeSpliceMessage(encodeSpliceMessage(baseInit())).lockDepth).to.be
			.undefined;
		expect(decodeSpliceAckMessage(encodeSpliceAckMessage(baseAck())).lockDepth)
			.to.be.undefined;
	});

	it('requireConfirmedInputs alone still round-trips as the two-byte TLV', function () {
		const init = encodeSpliceMessage({
			...baseInit(),
			requireConfirmedInputs: true
		});
		expect(init.subarray(81)).to.deep.equal(Buffer.from([2, 0]));
		const decodedInit = decodeSpliceMessage(init);
		expect(decodedInit.requireConfirmedInputs).to.equal(true);
		expect(decodedInit.lockDepth).to.be.undefined;

		const ack = encodeSpliceAckMessage({
			...baseAck(),
			requireConfirmedInputs: true
		});
		expect(ack.subarray(73)).to.deep.equal(Buffer.from([2, 0]));
		expect(decodeSpliceAckMessage(ack).requireConfirmedInputs).to.equal(true);
	});

	it('decodes the legacy hand-built [2, 0] form on both messages', function () {
		const init = Buffer.concat([
			encodeSpliceMessage(baseInit()),
			Buffer.from([2, 0])
		]);
		expect(decodeSpliceMessage(init).requireConfirmedInputs).to.equal(true);
		const ack = Buffer.concat([
			encodeSpliceAckMessage(baseAck()),
			Buffer.from([2, 0])
		]);
		expect(decodeSpliceAckMessage(ack).requireConfirmedInputs).to.equal(true);
	});

	it('carries both TLVs in ascending type order', function () {
		const init = encodeSpliceMessage({
			...baseInit(),
			requireConfirmedInputs: true,
			lockDepth: 12
		});
		expect(init.subarray(81)).to.deep.equal(
			Buffer.concat([Buffer.from([2, 0]), lockDepthTlv(12)])
		);
		const decodedInit = decodeSpliceMessage(init);
		expect(decodedInit.requireConfirmedInputs).to.equal(true);
		expect(decodedInit.lockDepth).to.equal(12);

		const ack = encodeSpliceAckMessage({
			...baseAck(),
			requireConfirmedInputs: true,
			lockDepth: 12
		});
		expect(ack.subarray(73)).to.deep.equal(
			Buffer.concat([Buffer.from([2, 0]), lockDepthTlv(12)])
		);
		const decodedAck = decodeSpliceAckMessage(ack);
		expect(decodedAck.requireConfirmedInputs).to.equal(true);
		expect(decodedAck.lockDepth).to.equal(12);
	});

	it('refuses TLVs out of order', function () {
		const payload = Buffer.concat([
			encodeSpliceMessage(baseInit()),
			lockDepthTlv(3),
			Buffer.from([2, 0])
		]);
		expect(() => decodeSpliceMessage(payload)).to.throw(/out of order/);
	});

	it('skips an unknown odd TLV and keeps the known ones', function () {
		// Type 65539 (odd, experimental), one byte of value.
		const unknownOdd = Buffer.from([0xfe, 0x00, 0x01, 0x00, 0x03, 0x01, 0xaa]);
		const init = Buffer.concat([
			encodeSpliceMessage(baseInit()),
			Buffer.from([2, 0]),
			lockDepthTlv(4),
			unknownOdd
		]);
		const decodedInit = decodeSpliceMessage(init);
		expect(decodedInit.requireConfirmedInputs).to.equal(true);
		expect(decodedInit.lockDepth).to.equal(4);

		// A small odd type ahead of everything is skipped too.
		const smallOdd = Buffer.from([1, 3, 0x01, 0x02, 0x03]);
		const ack = Buffer.concat([
			encodeSpliceAckMessage(baseAck()),
			smallOdd,
			Buffer.from([2, 0]),
			lockDepthTlv(4)
		]);
		const decodedAck = decodeSpliceAckMessage(ack);
		expect(decodedAck.requireConfirmedInputs).to.equal(true);
		expect(decodedAck.lockDepth).to.equal(4);
	});

	it('refuses an unknown even TLV on both messages', function () {
		const smallEven = Buffer.from([4, 0]);
		expect(() =>
			decodeSpliceMessage(
				Buffer.concat([encodeSpliceMessage(baseInit()), smallEven])
			)
		).to.throw(/unknown even TLV type 4/);
		// 65538: even, in the experimental range, after the lock depth.
		const bigEven = Buffer.from([0xfe, 0x00, 0x01, 0x00, 0x02, 0x00]);
		expect(() =>
			decodeSpliceAckMessage(
				Buffer.concat([
					encodeSpliceAckMessage(baseAck()),
					lockDepthTlv(2),
					bigEven
				])
			)
		).to.throw(/unknown even TLV type 65538/);
	});

	it('refuses lockDepth 0 and 2017 on encode', function () {
		for (const bad of [0, SPLICE_LOCK_DEPTH_MAX + 1, -1, 1.5]) {
			expect(
				() => encodeSpliceMessage({ ...baseInit(), lockDepth: bad }),
				`splice_init lockDepth ${bad}`
			).to.throw(/lockDepth must be an integer between 1 and 2016/);
			expect(
				() => encodeSpliceAckMessage({ ...baseAck(), lockDepth: bad }),
				`splice_ack lockDepth ${bad}`
			).to.throw(/lockDepth must be an integer between 1 and 2016/);
		}
		// The bounds themselves are accepted.
		expect(
			decodeSpliceMessage(encodeSpliceMessage({ ...baseInit(), lockDepth: 1 }))
				.lockDepth
		).to.equal(1);
		expect(
			decodeSpliceMessage(
				encodeSpliceMessage({
					...baseInit(),
					lockDepth: SPLICE_LOCK_DEPTH_MAX
				})
			).lockDepth
		).to.equal(SPLICE_LOCK_DEPTH_MAX);
	});

	it('refuses lockDepth 0 and 2017 on decode', function () {
		for (const bad of [0, SPLICE_LOCK_DEPTH_MAX + 1]) {
			expect(
				() =>
					decodeSpliceMessage(
						Buffer.concat([encodeSpliceMessage(baseInit()), lockDepthTlv(bad)])
					),
				`splice_init lock_depth ${bad}`
			).to.throw(new RegExp(`lock_depth ${bad} out of range`));
			expect(
				() =>
					decodeSpliceAckMessage(
						Buffer.concat([
							encodeSpliceAckMessage(baseAck()),
							lockDepthTlv(bad)
						])
					),
				`splice_ack lock_depth ${bad}`
			).to.throw(new RegExp(`lock_depth ${bad} out of range`));
		}
	});

	it('refuses a lock_depth whose length is not two', function () {
		const oneByte = lockDepthTlv(3, 1);
		expect(() =>
			decodeSpliceMessage(
				Buffer.concat([encodeSpliceMessage(baseInit()), oneByte])
			)
		).to.throw(/lock_depth must be a u16/);
	});

	it('refuses a truncated TLV', function () {
		// Length says 2, only one value byte follows.
		const truncatedValue = lockDepthTlv(3).subarray(0, 7);
		expect(() =>
			decodeSpliceMessage(
				Buffer.concat([encodeSpliceMessage(baseInit()), truncatedValue])
			)
		).to.throw(/truncated TLV/);
		// The type bigsize itself is cut short.
		const truncatedType = Buffer.from([0xfe, 0x00, 0x01]);
		expect(() =>
			decodeSpliceAckMessage(
				Buffer.concat([encodeSpliceAckMessage(baseAck()), truncatedType])
			)
		).to.throw(/truncated bigsize/);
		// A type with a length and no value at all.
		const noValue = Buffer.from([0xfe, 0x00, 0x01, 0x00, 0x01, 0x02]);
		expect(() =>
			decodeSpliceAckMessage(
				Buffer.concat([encodeSpliceAckMessage(baseAck()), noValue])
			)
		).to.throw(/truncated TLV/);
	});
});

// ---------------------------------------------------------------------------
// Channel wire pair
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

/** An opener/acceptor pair of live channels in NORMAL. */
function makeNormalChannel(): { opener: Channel; acceptor: Channel } {
	const openerBp = makeBasepoints(openerSeed);
	const acceptorBp = makeBasepoints(acceptorSeed);
	const tempId = Buffer.alloc(32, 0xba);

	const opener = new Channel(
		createOpenerState({
			temporaryChannelId: tempId,
			fundingSatoshis: FUNDING_SATOSHIS,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBp,
			localPerCommitmentSeed: openerCommitmentSeed
		})
	);
	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: tempId,
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: acceptorBp,
			localPerCommitmentSeed: acceptorCommitmentSeed,
			remoteBasepoints: openerBp,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);
	opener.setSigner(signerFromSeed(openerSeed));
	acceptor.setSigner(signerFromSeed(acceptorSeed));

	const openMsg = findSendAction(
		opener.initiateOpen(),
		MessageType.OPEN_CHANNEL
	);
	const acceptActions = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(openMsg.payload)
	);
	opener.handleAcceptChannel(
		decodeAcceptChannelMessage(
			findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL).payload
		)
	);

	const fundingTxid = crypto.randomBytes(32);
	const fcMsg = findSendAction(
		opener.createFundingCreated(
			fundingTxid,
			0,
			realInitialCommitmentSig(opener, fundingTxid, 0)
		),
		MessageType.FUNDING_CREATED
	);
	const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);
	const fsMsg = findSendAction(
		acceptor.handleFundingCreated(
			decodedFc,
			realInitialCommitmentSig(
				acceptor,
				decodedFc.fundingTxid,
				decodedFc.fundingOutputIndex
			)
		),
		MessageType.FUNDING_SIGNED
	);
	opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

	const openerReady = opener.fundingConfirmed();
	const acceptorReady = acceptor.fundingConfirmed();
	opener.handleChannelReady(
		decodeChannelReadyMessage(
			findSendAction(acceptorReady, MessageType.CHANNEL_READY).payload
		)
	);
	acceptor.handleChannelReady(
		decodeChannelReadyMessage(
			findSendAction(openerReady, MessageType.CHANNEL_READY).payload
		)
	);
	expect(opener.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
	return { opener, acceptor };
}

interface IWirePair {
	opener: Channel;
	acceptor: Channel;
	broadcasts: Buffer[];
	errors: string[];
	errorsFrom: Array<{ from: Channel; message: string }>;
	/** Every action either side produced, tagged with its producer. */
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	actions: Array<{ from: Channel; action: any }>;
	/** Every message that actually left, tagged with its sender. */
	sent: Array<{ from: Channel; msgType: MessageType; payload: Buffer }>;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	enqueue: (to: Channel, from: Channel, actions: any[]) => void;
	pump: () => void;
	/** Transform every outbound payload of this type (adversarial peer). */
	intercept: (msgType: MessageType, fn: (payload: Buffer) => Buffer) => void;
}

/**
 * The wire pair from splice-external-inputs.test.ts, made zero-conf: both
 * sides carry option_zeroconf in their channel type and a minimum depth of 0,
 * the shape a zero-conf open leaves behind.
 */
function makeZeroConfWirePair(): IWirePair {
	const { opener, acceptor } = makeNormalChannel();
	for (const ch of [opener, acceptor]) {
		const state = ch.getFullState();
		state.channelType = zeroConfType();
		state.minimumDepth = 0;
	}

	const deliver = (
		ch: Channel,
		msgType: MessageType,
		payload: Buffer
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
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
				return ch.handleReestablish(decodeChannelReestablishMessage(payload));
			default:
				return [];
		}
	};

	interface IFrame {
		to: Channel;
		from: Channel;
		msgType: MessageType;
		payload: Buffer;
	}
	const queue: IFrame[] = [];
	const interceptRules = new Map<MessageType, (payload: Buffer) => Buffer>();
	const broadcasts: Buffer[] = [];
	const errors: string[] = [];
	const errorsFrom: IWirePair['errorsFrom'] = [];
	const actions: IWirePair['actions'] = [];
	const sent: IWirePair['sent'] = [];

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const enqueue = (to: Channel, from: Channel, produced: any[]): void => {
		for (const a of produced) {
			actions.push({ from, action: a });
			if (a.type === ChannelActionType.ERROR) {
				errors.push(a.message);
				errorsFrom.push({ from, message: a.message });
			}
			if (a.type === ChannelActionType.BROADCAST_TX) broadcasts.push(a.tx);
			if (a.type !== ChannelActionType.SEND_MESSAGE) continue;
			const transform = interceptRules.get(a.messageType);
			const payload = transform ? transform(a.payload) : a.payload;
			sent.push({ from, msgType: a.messageType, payload });
			queue.push({ to, from, msgType: a.messageType, payload });
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

	return {
		opener,
		acceptor,
		broadcasts,
		errors,
		errorsFrom,
		actions,
		sent,
		enqueue,
		pump,
		intercept: (msgType, fn): void => {
			interceptRules.set(msgType, fn);
		}
	};
}

interface IOwnWallet {
	inputs: ISpliceWalletInput[];
	changeScript: Buffer;
}

/** A splice-in contribution of one OWN P2WPKH input with a real signer. */
function makeOwnSpliceWallet(): IOwnWallet {
	const ownPriv = crypto
		.createHash('sha256')
		.update('splice-lock-depth-own-key')
		.digest();
	const ownPub = Buffer.from(ecc.pointFromScalar(ownPriv, true)!);
	const ownScriptCode = bitcoin.payments.p2pkh({ pubkey: ownPub }).output!;
	const ownPrevTx = new bitcoin.Transaction();
	ownPrevTx.version = 2;
	ownPrevTx.addInput(crypto.randomBytes(32), 0);
	ownPrevTx.addOutput(
		bitcoin.payments.p2wpkh({ pubkey: ownPub }).output!,
		Number(OWN_UTXO_SATS)
	);
	return {
		changeScript: bitcoin.payments.p2wpkh({ pubkey: ownPub }).output!,
		inputs: [
			{
				prevTx: ownPrevTx.toBuffer(),
				prevOutputIndex: 0,
				value: OWN_UTXO_SATS,
				sequence: 0xfffffffd,
				confirmed: true,
				signWitness: (
					tx: bitcoin.Transaction,
					inputIndex: number,
					value: bigint
				): Buffer[] => {
					const sighash = tx.hashForWitnessV0(
						inputIndex,
						ownScriptCode,
						Number(value),
						bitcoin.Transaction.SIGHASH_ALL
					);
					return [
						bitcoin.script.signature.encode(
							Buffer.from(ecc.sign(sighash, ownPriv)),
							bitcoin.Transaction.SIGHASH_ALL
						),
						ownPub
					];
				}
			}
		]
	};
}

/** Start the opener's splice-in and pump the negotiation to a standstill. */
function startSpliceIn(
	pair: IWirePair,
	wallet: IOwnWallet,
	options: { lockAtDepth?: number } = {}
): void {
	pair.opener.setSpliceInInputs(wallet.inputs, wallet.changeScript, options);
	pair.enqueue(
		pair.acceptor,
		pair.opener,
		pair.opener.initiateSplice(SPLICE_AMOUNT, 253)
	);
	pair.pump();
}

const sentBy = (
	pair: IWirePair,
	from: Channel,
	msgType: MessageType
): Buffer[] =>
	pair.sent
		.filter((m) => m.from === from && m.msgType === msgType)
		.map((m) => m.payload);

const actionsOfType = (
	pair: IWirePair,
	type: ChannelActionType
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
): Array<{ from: Channel; action: any }> =>
	pair.actions.filter((a) => a.action.type === type);

describe('Splice lock depth on a zero-conf channel (issue #760)', function () {
	it('negotiates the depth, holds the lock at tx_signatures, and completes at depth', function () {
		const pair = makeZeroConfWirePair();
		const wallet = makeOwnSpliceWallet();
		startSpliceIn(pair, wallet, { lockAtDepth: LOCK_DEPTH });
		expect(pair.errors).to.deep.equal([]);

		// splice_init carries the depth; splice_ack echoes it.
		const inits = sentBy(pair, pair.opener, MessageType.SPLICE);
		expect(inits).to.have.length(1);
		expect(decodeSpliceMessage(inits[0]).lockDepth).to.equal(LOCK_DEPTH);
		const acks = sentBy(pair, pair.acceptor, MessageType.SPLICE_ACK);
		expect(acks).to.have.length(1);
		expect(decodeSpliceAckMessage(acks[0]).lockDepth).to.equal(LOCK_DEPTH);

		// Both durable records carry it, and the signature exchange completed.
		const openerRecord = pair.opener.getFullState().spliceInFlight!;
		const acceptorRecord = pair.acceptor.getFullState().spliceInFlight!;
		for (const [label, record] of [
			['opener', openerRecord],
			['acceptor', acceptorRecord]
		] as Array<[string, ISpliceInFlight]>) {
			expect(record, `${label} in-flight record`).to.exist;
			expect(record.lockAtDepth, `${label} lockAtDepth`).to.equal(LOCK_DEPTH);
			expect(record.fullySigned, `${label} fullySigned`).to.equal(true);
			expect(record.sentTxSignatures, `${label} sent sigs`).to.equal(true);
			expect(record.receivedTxSignatures, `${label} got sigs`).to.equal(true);
			expect(record.localSpliceLocked, `${label} local lock`).to.equal(false);
			expect(record.remoteSpliceLocked, `${label} remote lock`).to.equal(false);
			expect(record.confirmed, `${label} confirmed`).to.equal(false);
		}
		expect(openerRecord.spliceTxid.equals(acceptorRecord.spliceTxid)).to.equal(
			true
		);
		expect(pair.broadcasts, 'both sides broadcast the splice').to.have.length(
			2
		);

		// Neither side locked: the channel waits for the chain.
		expect(sentBy(pair, pair.opener, MessageType.SPLICE_LOCKED)).to.have.length(
			0
		);
		expect(
			sentBy(pair, pair.acceptor, MessageType.SPLICE_LOCKED)
		).to.have.length(0);
		expect(pair.opener.getState()).to.equal(ChannelState.SPLICING);
		expect(pair.acceptor.getState()).to.equal(ChannelState.SPLICING);
		expect(pair.opener.isSplicePendingLock()).to.equal(true);
		expect(pair.acceptor.isSplicePendingLock()).to.equal(true);
		expect(
			actionsOfType(pair, ChannelActionType.SPLICE_COMPLETE)
		).to.have.length(0);

		// Every splice funding watch reports at the lock depth, though the
		// channel's own minimum depth is 0.
		const watches = actionsOfType(pair, ChannelActionType.WATCH_FUNDING);
		expect(watches.length, 'a watch from each side').to.be.gte(2);
		expect(watches.some((w) => w.from === pair.opener)).to.equal(true);
		expect(watches.some((w) => w.from === pair.acceptor)).to.equal(true);
		for (const w of watches) {
			expect(w.action.minimumDepth).to.equal(LOCK_DEPTH);
			expect(w.action.fundingTxid.equals(openerRecord.spliceTxid)).to.equal(
				true
			);
			expect(w.action.fundingOutputIndex).to.equal(
				openerRecord.newFundingOutputIndex
			);
		}
		expect(pair.opener.getFullState().minimumDepth).to.equal(0);
		expect(pair.acceptor.getFullState().minimumDepth).to.equal(0);

		// The chain reaches depth on both sides: the node stamps the record
		// confirmed and sends splice_locked. The splice completes.
		const spliceTxid = Buffer.from(openerRecord.spliceTxid);
		pair.opener.markSpliceConfirmed();
		pair.enqueue(pair.acceptor, pair.opener, pair.opener.sendSpliceLocked());
		pair.pump();
		expect(pair.errors).to.deep.equal([]);
		expect(
			pair.acceptor.getFullState().spliceInFlight!.remoteSpliceLocked,
			'the acceptor recorded our lock but did not answer before its depth'
		).to.equal(true);
		expect(
			sentBy(pair, pair.acceptor, MessageType.SPLICE_LOCKED)
		).to.have.length(0);
		expect(pair.acceptor.getState()).to.equal(ChannelState.SPLICING);

		pair.acceptor.markSpliceConfirmed();
		pair.enqueue(pair.opener, pair.acceptor, pair.acceptor.sendSpliceLocked());
		pair.pump();
		expect(pair.errors).to.deep.equal([]);

		expect(sentBy(pair, pair.opener, MessageType.SPLICE_LOCKED)).to.have.length(
			1
		);
		expect(
			sentBy(pair, pair.acceptor, MessageType.SPLICE_LOCKED)
		).to.have.length(1);
		const completes = actionsOfType(pair, ChannelActionType.SPLICE_COMPLETE);
		expect(completes.length, 'the splice completed').to.be.gte(1);
		expect(completes.some((c) => c.from === pair.acceptor)).to.equal(true);
		for (const ch of [pair.opener, pair.acceptor]) {
			const state = ch.getFullState();
			expect(ch.getState()).to.equal(ChannelState.NORMAL);
			expect(state.spliceInFlight).to.equal(null);
			expect(state.fundingTxid!.equals(spliceTxid)).to.equal(true);
			// The record was confirmed at adoption: no rebroadcast is owed.
			expect(state.unconfirmedSpliceTxs ?? []).to.have.length(0);
			expect(ch.buildSpliceRebroadcastActions()).to.have.length(0);
			expect(ch.isHtlcUsable()).to.equal(true);
		}
	});

	it('control: without the option the same channel locks at tx_signatures and owes a rebroadcast', function () {
		const pair = makeZeroConfWirePair();
		startSpliceIn(pair, makeOwnSpliceWallet());
		expect(pair.errors).to.deep.equal([]);

		const inits = sentBy(pair, pair.opener, MessageType.SPLICE);
		expect(decodeSpliceMessage(inits[0]).lockDepth).to.be.undefined;
		const acks = sentBy(pair, pair.acceptor, MessageType.SPLICE_ACK);
		expect(decodeSpliceAckMessage(acks[0]).lockDepth).to.be.undefined;

		// Both sides locked immediately and adopted the splice.
		expect(sentBy(pair, pair.opener, MessageType.SPLICE_LOCKED)).to.have.length(
			1
		);
		expect(
			sentBy(pair, pair.acceptor, MessageType.SPLICE_LOCKED)
		).to.have.length(1);
		expect(
			actionsOfType(pair, ChannelActionType.SPLICE_COMPLETE).length
		).to.be.gte(1);
		const watches = actionsOfType(pair, ChannelActionType.WATCH_FUNDING);
		expect(watches.length).to.be.gte(2);
		for (const w of watches) expect(w.action.minimumDepth).to.equal(0);
		for (const ch of [pair.opener, pair.acceptor]) {
			const state = ch.getFullState();
			expect(ch.getState()).to.equal(ChannelState.NORMAL);
			expect(state.spliceInFlight).to.equal(null);
			// Locked at zero confirmations: the BOLT 2 broadcast obligation
			// stays (issue #756).
			expect(state.unconfirmedSpliceTxs).to.have.length(1);
		}
	});

	it('an acceptor that strips the echo gets tx_abort before any tx_add_input', function () {
		const pair = makeZeroConfWirePair();
		pair.intercept(MessageType.SPLICE_ACK, (payload) => {
			const ack = decodeSpliceAckMessage(payload);
			delete ack.lockDepth;
			return encodeSpliceAckMessage(ack);
		});
		const preState = JSON.stringify(
			serializeChannelState(pair.opener.getFullState())
		);
		startSpliceIn(pair, makeOwnSpliceWallet(), { lockAtDepth: LOCK_DEPTH });

		// The ack the initiator saw carried no depth.
		const acks = sentBy(pair, pair.acceptor, MessageType.SPLICE_ACK);
		expect(acks).to.have.length(1);
		expect(decodeSpliceAckMessage(acks[0]).lockDepth).to.be.undefined;

		// The initiator aborted, before contributing a single input.
		expect(sentBy(pair, pair.opener, MessageType.TX_ABORT)).to.have.length(1);
		expect(sentBy(pair, pair.opener, MessageType.TX_ADD_INPUT)).to.have.length(
			0
		);
		expect(sentBy(pair, pair.opener, MessageType.TX_ADD_OUTPUT)).to.have.length(
			0
		);
		expect(pair.broadcasts).to.have.length(0);
		const aborted = actionsOfType(pair, ChannelActionType.SPLICE_ABORTED);
		expect(aborted.some((a) => a.from === pair.opener)).to.equal(true);
		expect(
			aborted
				.filter((a) => a.from === pair.opener)
				.some((a) => /lock depth 3/.test(a.action.reason))
		).to.equal(true);
		expect(
			pair.errorsFrom.some(
				(e) => e.from === pair.opener && /lock depth 3/.test(e.message)
			)
		).to.equal(true);

		// Back to the pre-splice state, on both sides once the echo lands.
		for (const ch of [pair.opener, pair.acceptor]) {
			expect(ch.getState()).to.equal(ChannelState.NORMAL);
			expect(ch.getFullState().spliceInFlight).to.equal(null);
			expect(ch.getSpliceSession()).to.equal(null);
			expect(ch.isQuiescent()).to.equal(false);
			expect(ch.isSpliceAbortPending()).to.equal(false);
			expect(ch.isHtlcUsable()).to.equal(true);
		}
		expect(
			JSON.stringify(serializeChannelState(pair.opener.getFullState()))
		).to.equal(preState);
	});
});

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/** A signed-looking splice tx: one input spending the old funding, one output. */
function spliceTxFor(oldFundingTxid: Buffer): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(Buffer.from(oldFundingTxid), 1);
	tx.addOutput(
		bitcoin.payments.p2wsh({
			redeem: { output: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE]) }
		}).output!,
		999_000
	);
	tx.ins[0].witness = [
		Buffer.alloc(72, 1),
		Buffer.alloc(72, 2),
		Buffer.alloc(71, 3)
	];
	return tx;
}

function inFlightRecord(
	spliceTx: bitcoin.Transaction,
	lockAtDepth?: number
): ISpliceInFlight {
	return {
		spliceTxid: Buffer.from(spliceTx.getHash()),
		newFundingOutputIndex: 0,
		newFundingSatoshis: 999_000n,
		spliceTxHex: spliceTx.toHex(),
		fullySigned: true,
		isInitiator: true,
		localRelativeSatoshis: 0n,
		remoteRelativeSatoshis: 0n,
		remoteFundingPubkey: makeBasepoints(Buffer.alloc(32, 9)).fundingPubkey,
		ourSharedInputSig: Buffer.alloc(64),
		ourWalletWitnesses: [],
		ourWalletInputIndices: [],
		inputPrevouts: [],
		remoteCommitmentSig: crypto.randomBytes(64),
		sentTxSignatures: true,
		receivedTxSignatures: true,
		localSpliceLocked: false,
		remoteSpliceLocked: false,
		confirmed: false,
		...(lockAtDepth !== undefined ? { lockAtDepth } : {})
	};
}

function splicingState(options: {
	zeroConf: boolean;
	lockAtDepth?: number;
}): ReturnType<typeof createOpenerState> {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(Buffer.alloc(32, 1)),
		localPerCommitmentSeed: Buffer.alloc(32, 3)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 1;
	state.remoteBasepoints = makeBasepoints(Buffer.alloc(32, 2));
	if (options.zeroConf) {
		state.channelType = zeroConfType();
		state.minimumDepth = 0;
	}
	state.spliceInFlight = inFlightRecord(
		spliceTxFor(state.fundingTxid),
		options.lockAtDepth
	);
	return state;
}

describe('Splice lock depth serialization (issue #760)', function () {
	it('round-trips spliceInFlight.lockAtDepth through the channel state row', function () {
		const state = splicingState({ zeroConf: true, lockAtDepth: 3 });
		const restored = deserializeChannelState(
			JSON.parse(JSON.stringify(serializeChannelState(state)))
		);
		expect(restored.spliceInFlight!.lockAtDepth).to.equal(3);
		expect(
			restored.spliceInFlight!.spliceTxid.equals(
				state.spliceInFlight!.spliceTxid
			)
		).to.equal(true);
		// A restored channel still knows the splice waits for the chain: the
		// zero-conf adoption stamps no rebroadcast for it.
		const channel = new Channel(restored);
		(channel as unknown as { completeSplice: () => void }).completeSplice();
		expect(channel.getFullState().unconfirmedSpliceTxs ?? []).to.have.length(0);
	});

	it('round-trips through the in-flight helpers and reads absent as undefined', function () {
		const withDepth = inFlightRecord(spliceTxFor(crypto.randomBytes(32)), 7);
		const serialized = serializeSpliceInFlight(withDepth);
		expect(serialized.lockAtDepth).to.equal(7);
		expect(
			deserializeSpliceInFlight(JSON.parse(JSON.stringify(serialized)))
				.lockAtDepth
		).to.equal(7);

		const without = inFlightRecord(spliceTxFor(crypto.randomBytes(32)));
		expect(serializeSpliceInFlight(without).lockAtDepth).to.be.undefined;
		expect(
			deserializeSpliceInFlight(serializeSpliceInFlight(without)).lockAtDepth
		).to.be.undefined;
	});

	it('a row written before the field existed reads as undefined', function () {
		const state = splicingState({ zeroConf: true, lockAtDepth: 3 });
		const row = JSON.parse(JSON.stringify(serializeChannelState(state)));
		delete row.spliceInFlight.lockAtDepth;
		const restored = deserializeChannelState(row);
		expect(restored.spliceInFlight).to.exist;
		expect(restored.spliceInFlight!.lockAtDepth).to.be.undefined;
		expect('lockAtDepth' in restored.spliceInFlight!).to.equal(true);
		// And it behaves as a plain zero-conf splice: adoption owes the
		// rebroadcast (issue #756).
		const channel = new Channel(restored);
		(channel as unknown as { completeSplice: () => void }).completeSplice();
		expect(channel.getFullState().unconfirmedSpliceTxs).to.have.length(1);
	});
});

// ---------------------------------------------------------------------------
// Node level
// ---------------------------------------------------------------------------

/** A backend that records broadcasts and answers every query empty. */
class ControlledBackend implements IChainBackend {
	broadcasts: string[] = [];
	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		return [];
	}
	async getTransaction(): Promise<Buffer> {
		throw new Error('not needed');
	}
	async broadcastTransaction(hex: string): Promise<string> {
		this.broadcasts.push(hex);
		return bitcoin.Transaction.fromHex(hex).getId();
	}
}

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`splice-lock-depth-${id}`))
		.digest();
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
}

const tick = (ms = 30): Promise<void> => new Promise((r) => setTimeout(r, ms));

const p2wpkhScript = (): Buffer =>
	Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]);

/** A caller-supplied splice input worth `valueSats`, paid to P2WPKH. */
function makeNodeInput(valueSats: number): ISpliceWalletInput {
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(p2wpkhScript(), valueSats);
	return {
		prevTx: prevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(valueSats),
		sequence: 0xfffffffd,
		signWitness: (): Buffer[] => [Buffer.alloc(71, 1), Buffer.alloc(33, 2)]
	};
}

describe('Splice lock depth on the node (issue #760)', function () {
	this.timeout(10_000);

	async function setup(seedBase: number): Promise<{
		alice: LightningNode;
		bob: LightningNode;
		channelId: Buffer;
		backend: ControlledBackend;
		outbound: number[];
		destroy: () => void;
	}> {
		const backend = new ControlledBackend();
		const configA = makeNodeConfig(seedBase);
		configA.chainBackend = backend;
		const alice = new LightningNode(configA);
		const bob = new LightningNode(makeNodeConfig(seedBase + 1));
		for (const n of [alice, bob]) {
			n.on('error', () => {});
			n.on('node:error', () => {});
		}
		const outbound: number[] = [];
		alice.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				outbound.push(type);
				if (pubkey === bob.getNodeId())
					bob.handlePeerMessage(alice.getNodeId(), type, payload);
			}
		);
		bob.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === alice.getNodeId())
					alice.handlePeerMessage(bob.getNodeId(), type, payload);
			}
		);
		const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
		const channelId = alice.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		await tick(60);
		expect(
			alice.getChannelManager().getChannel(channelId)!.getState()
		).to.equal(ChannelState.NORMAL);
		return {
			alice,
			bob,
			channelId,
			backend,
			outbound,
			destroy: (): void => {
				alice.destroy();
				bob.destroy();
			}
		};
	}

	it('spliceInWithInputs refuses a bad lockAtDepth before touching the channel', async () => {
		const fx = await setup(7601);
		const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;
		const sentBefore = fx.outbound.length;
		const before = JSON.stringify(
			serializeChannelState(channel.getFullState())
		);
		for (const bad of [0, 1.5, SPLICE_LOCK_DEPTH_MAX + 1]) {
			expect(
				() =>
					fx.alice.spliceInWithInputs(
						fx.channelId,
						100_000n,
						[makeNodeInput(200_000)],
						p2wpkhScript(),
						253,
						{ lockAtDepth: bad }
					),
				`lockAtDepth ${bad}`
			).to.throw(
				InvalidSpliceError,
				/lockAtDepth must be an integer between 1 and 2016/
			);
		}
		// Nothing reached the channel: no stfu left, no inputs were parked, no
		// depth was recorded, the state is byte-for-byte what it was.
		expect(fx.outbound.length).to.equal(sentBefore);
		expect(channel.getState()).to.equal(ChannelState.NORMAL);
		expect(channel.getSpliceSession()).to.equal(null);
		expect(channel.isQuiescent()).to.equal(false);
		const internals = channel as unknown as {
			_spliceInInputs: unknown;
			_spliceLockAtDepth: number | null;
		};
		expect(internals._spliceInInputs).to.equal(null);
		expect(internals._spliceLockAtDepth).to.equal(null);
		expect(
			JSON.stringify(serializeChannelState(channel.getFullState()))
		).to.equal(before);
		fx.destroy();
	});

	it('a restart re-arms the splice funding watch at the lock depth, not the channel minimum', async () => {
		const fx = await setup(7603);
		// The shape a depth-locked zero-conf splice leaves on disk past the
		// point of no return: signatures exchanged, transaction fully signed,
		// record waiting for the chain.
		const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;
		const state = channel.getFullState();
		state.channelType = zeroConfType();
		state.minimumDepth = 0;
		state.state = ChannelState.SPLICING;
		state.preSpliceState = ChannelState.NORMAL;
		const spliceTx = spliceTxFor(state.fundingTxid!);
		state.spliceInFlight = inFlightRecord(spliceTx, LOCK_DEPTH);

		await fx.alice.restoreChainWatches();
		await tick();

		const watcher = fx.alice.getChainWatcher()!;
		const watched = (
			watcher as unknown as {
				watchedFundings: Map<
					string,
					{ txid: string; outputIndex: number; minimumDepth: number }
				>;
			}
		).watchedFundings;
		const entry = watched.get(fx.channelId.toString('hex'));
		expect(entry, 'the splice funding is watched').to.exist;
		expect(entry!.txid).to.equal(display(Buffer.from(spliceTx.getHash())));
		expect(entry!.outputIndex).to.equal(0);
		expect(entry!.minimumDepth, 'the watch waits for the lock depth').to.equal(
			LOCK_DEPTH
		);
		fx.destroy();
	});

	it('control: a restored zero-conf splice without a lock depth is watched at the channel minimum', async () => {
		const fx = await setup(7605);
		const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;
		const state = channel.getFullState();
		state.channelType = zeroConfType();
		state.minimumDepth = 0;
		state.state = ChannelState.SPLICING;
		state.preSpliceState = ChannelState.NORMAL;
		state.spliceInFlight = inFlightRecord(spliceTxFor(state.fundingTxid!));

		await fx.alice.restoreChainWatches();
		await tick();

		const watched = (
			fx.alice.getChainWatcher()! as unknown as {
				watchedFundings: Map<string, { minimumDepth: number }>;
			}
		).watchedFundings;
		expect(watched.get(fx.channelId.toString('hex'))!.minimumDepth).to.equal(0);
		fx.destroy();
	});
});
