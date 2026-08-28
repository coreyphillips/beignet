/**
 * Splice EXTERNAL inputs (issue #592, LFBW port #532 workstream 2D).
 *
 * A splice-in may be funded by inputs the channel cannot sign: they ride the
 * interactive negotiation like our own (our serial parity, full prevTx), but
 * their witnesses arrive out of band via provideSpliceExternalWitness. These
 * tests pin the invariants:
 *  - our splice tx_signatures never leaves with a witness hole, and neither
 *    does our shared-input signature that travels with it,
 *  - a splice awaiting a witness is never broadcast and never locked, and its
 *    durable record says fullySigned: false,
 *  - a delivered witness is cryptographically verified BEFORE it is stored,
 *  - the wait survives disconnect and restart, and the reconnect never
 *    retransmits the withheld message,
 *  - the external input is attributed to US, so the peer's own witness stacks
 *    keep their count and placement.
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
	decodeSpliceMessage,
	decodeSpliceAckMessage,
	decodeSpliceLockedMessage
} from '../../src/lightning/message/splice';
import { decodeStfuMessage } from '../../src/lightning/message/stfu';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxSignaturesMessage,
	encodeTxSignaturesMessage
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
import { taprootTweakPrivateKey } from '../../src/lightning/wallet/wallet-funding-provider';

const FUNDING_SATOSHIS = 1_000_000n;
const SPLICE_AMOUNT = 300_000n;
const OWN_UTXO_SATS = SPLICE_AMOUNT + 100_000n;
const EXT_UTXO_SATS = 60_000n;

const openerSeed = Buffer.alloc(32, 0x11);
const acceptorSeed = Buffer.alloc(32, 0x22);
const openerCommitmentSeed = crypto
	.createHash('sha256')
	.update('splice-external-opener')
	.digest();
const acceptorCommitmentSeed = crypto
	.createHash('sha256')
	.update('splice-external-acceptor')
	.digest();

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
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

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
	const tempId = Buffer.alloc(32, 0xbb);

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

interface ISignalSeen {
	channelId: Buffer;
	spliceTxid: Buffer;
	newFundingOutputIndex: number;
	externalInputIndices: number[];
}

interface IWirePair {
	opener: Channel;
	acceptor: Channel;
	broadcasts: Buffer[];
	errors: string[];
	/** Errors tagged with the channel that produced them. */
	errorsFrom: Array<{ from: Channel; message: string }>;
	signals: ISignalSeen[];
	/** Every message that actually left, tagged with its sender. */
	sent: Array<{ from: Channel; msgType: MessageType; payload: Buffer }>;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	enqueue: (to: Channel, from: Channel, actions: any[]) => void;
	pump: () => void;
	/** Withhold this message type from delivery (it stays queued for later). */
	hold: (msgType: MessageType) => void;
	/** Deliver everything previously held, then pump. */
	releaseHeld: () => void;
	/** Transform every outbound payload of this type (adversarial peer). */
	intercept: (msgType: MessageType, fn: (payload: Buffer) => Buffer) => void;
	clearIntercepts: () => void;
	/** Swap in a restored channel object for one side. */
	replace: (old: Channel, next: Channel) => void;
}

function makeWirePair(): IWirePair {
	const { opener, acceptor } = makeNormalChannel();
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
	const held: IFrame[] = [];
	const holdTypes = new Set<MessageType>();
	const interceptRules = new Map<MessageType, (payload: Buffer) => Buffer>();
	const broadcasts: Buffer[] = [];
	const errors: string[] = [];
	const errorsFrom: IWirePair['errorsFrom'] = [];
	const signals: ISignalSeen[] = [];
	const sent: IWirePair['sent'] = [];
	const replacements = new Map<Channel, Channel>();
	const current = (ch: Channel): Channel => replacements.get(ch) ?? ch;

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const enqueue = (to: Channel, from: Channel, actions: any[]): void => {
		for (const a of actions) {
			if (a.type === ChannelActionType.ERROR) {
				errors.push(a.message);
				errorsFrom.push({ from, message: a.message });
			}
			if (a.type === ChannelActionType.BROADCAST_TX) broadcasts.push(a.tx);
			if (a.type === ChannelActionType.SPLICE_TX_SIGNATURES_NEEDED) {
				signals.push({
					channelId: a.channelId,
					spliceTxid: a.spliceTxid,
					newFundingOutputIndex: a.newFundingOutputIndex,
					externalInputIndices: a.externalInputIndices
				});
			}
			if (a.type !== ChannelActionType.SEND_MESSAGE) continue;
			const transform = interceptRules.get(a.messageType);
			const payload = transform ? transform(a.payload) : a.payload;
			sent.push({ from, msgType: a.messageType, payload });
			const frame = { to, from, msgType: a.messageType, payload };
			if (holdTypes.has(a.messageType)) held.push(frame);
			else queue.push(frame);
		}
	};

	const pump = (): void => {
		let steps = 0;
		while (queue.length > 0) {
			if (steps++ > 400) throw new Error('message pump did not settle');
			const { to, from, msgType, payload } = queue.shift()!;
			const target = current(to);
			enqueue(current(from), target, deliver(target, msgType, payload));
		}
	};

	return {
		opener,
		acceptor,
		broadcasts,
		errors,
		errorsFrom,
		signals,
		sent,
		enqueue,
		pump,
		hold: (msgType): void => {
			holdTypes.add(msgType);
		},
		releaseHeld: (): void => {
			holdTypes.clear();
			queue.push(...held.splice(0, held.length));
			pump();
		},
		intercept: (msgType, fn): void => {
			interceptRules.set(msgType, fn);
		},
		clearIntercepts: (): void => {
			interceptRules.clear();
		},
		replace: (old, next): void => {
			replacements.set(old, next);
		}
	};
}

interface IExternalWallet {
	inputs: ISpliceWalletInput[];
	changeScript: Buffer;
	ownPrevTx: bitcoin.Transaction;
	extPrevTx: bitcoin.Transaction;
	extPriv: Buffer;
	extPub: Buffer;
}

/**
 * A splice-in contribution of one OWN P2WPKH input (real signing closure) plus
 * one input owned by a THIRD PARTY, whose closure throws: the machinery must
 * never call it.
 */
function makeExternalSpliceWallet(
	kind: 'p2wpkh' | 'p2tr' | 'p2wsh' = 'p2wpkh'
): IExternalWallet {
	const ownPriv = crypto.createHash('sha256').update('splice-own-key').digest();
	const ownPub = Buffer.from(ecc.pointFromScalar(ownPriv, true)!);
	const ownScriptCode = bitcoin.payments.p2pkh({ pubkey: ownPub }).output!;
	const ownPrevTx = new bitcoin.Transaction();
	ownPrevTx.version = 2;
	ownPrevTx.addInput(crypto.randomBytes(32), 0);
	ownPrevTx.addOutput(
		bitcoin.payments.p2wpkh({ pubkey: ownPub }).output!,
		Number(OWN_UTXO_SATS)
	);

	const extPriv = crypto.randomBytes(32);
	const extPub = Buffer.from(ecc.pointFromScalar(extPriv, true)!);
	let extScript: Buffer;
	if (kind === 'p2wpkh') {
		extScript = bitcoin.payments.p2wpkh({ pubkey: extPub }).output!;
	} else if (kind === 'p2tr') {
		extScript = bitcoin.payments.p2tr({
			internalPubkey: extPub.subarray(1, 33)
		}).output!;
	} else {
		// Native segwit (so the tx_add_input receive checks pass) but a script
		// kind whose witness no generic validator can judge.
		extScript = Buffer.concat([
			Buffer.from([0x00, 0x20]),
			crypto.randomBytes(32)
		]);
	}
	const extPrevTx = new bitcoin.Transaction();
	extPrevTx.version = 2;
	extPrevTx.addInput(crypto.randomBytes(32), 0);
	extPrevTx.addOutput(extScript, Number(EXT_UTXO_SATS));

	return {
		ownPrevTx,
		extPrevTx,
		extPriv,
		extPub,
		changeScript: bitcoin.payments.p2wpkh({ pubkey: ownPub }).output!,
		inputs: [
			{
				prevTx: ownPrevTx.toBuffer(),
				prevOutputIndex: 0,
				value: OWN_UTXO_SATS,
				sequence: 0xfffffffd,
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
			},
			{
				prevTx: extPrevTx.toBuffer(),
				prevOutputIndex: 0,
				value: EXT_UTXO_SATS,
				sequence: 0xfffffffd,
				confirmed: true,
				external: true,
				signWitness: (): Buffer[] => {
					throw new Error('external input: the witness comes from its owner');
				}
			}
		]
	};
}

/** Start the opener's splice-in and pump the negotiation to a standstill. */
function startSpliceIn(pair: IWirePair, wallet: IExternalWallet): void {
	pair.opener.setSpliceInInputs(wallet.inputs, wallet.changeScript);
	pair.enqueue(
		pair.acceptor,
		pair.opener,
		pair.opener.initiateSplice(SPLICE_AMOUNT, 253)
	);
	pair.pump();
}

/** The external input's index in the negotiated splice tx. */
function externalIndexOf(
	record: ISpliceInFlight,
	extPrevTx: bitcoin.Transaction
): number {
	const tx = bitcoin.Transaction.fromHex(record.spliceTxHex);
	const idx = tx.ins.findIndex(
		(i) => Buffer.from(i.hash).equals(extPrevTx.getHash()) && i.index === 0
	);
	expect(idx).to.be.gte(0);
	return idx;
}

/** Sign the external P2WPKH input over the negotiated tx, as its owner would. */
function signExternalP2wpkh(
	record: ISpliceInFlight,
	wallet: IExternalWallet
): Buffer[] {
	const tx = bitcoin.Transaction.fromHex(record.spliceTxHex);
	const sighash = tx.hashForWitnessV0(
		externalIndexOf(record, wallet.extPrevTx),
		bitcoin.payments.p2pkh({ pubkey: wallet.extPub }).output!,
		Number(EXT_UTXO_SATS),
		bitcoin.Transaction.SIGHASH_ALL
	);
	return [
		bitcoin.script.signature.encode(
			Buffer.from(ecc.sign(sighash, wallet.extPriv)),
			bitcoin.Transaction.SIGHASH_ALL
		),
		wallet.extPub
	];
}

/** Drive to the received-first withhold: the acceptor signed, we did not. */
function driveToWithhold(): {
	pair: IWirePair;
	wallet: IExternalWallet;
	record: ISpliceInFlight;
	extIdx: number;
} {
	const pair = makeWirePair();
	const wallet = makeExternalSpliceWallet();
	startSpliceIn(pair, wallet);
	expect(pair.errors).to.deep.equal([]);
	const record = pair.opener.getFullState().spliceInFlight!;
	return {
		pair,
		wallet,
		record,
		extIdx: externalIndexOf(record, wallet.extPrevTx)
	};
}

describe('Splice external inputs (issue #592)', function () {
	it('withholds tx_signatures on the external hole, then completes on delivery', function () {
		const { pair, wallet, record, extIdx } = driveToWithhold();

		// The acceptor (zero contribution) signed first; we did not answer.
		expect(
			pair.sent.some(
				(m) => m.from === pair.opener && m.msgType === MessageType.TX_SIGNATURES
			),
			'our tx_signatures stayed home'
		).to.equal(false);
		expect(pair.broadcasts, 'nothing broadcast with a hole').to.deep.equal([]);
		expect(record.receivedTxSignatures).to.equal(true);
		expect(record.sentTxSignatures).to.equal(false);
		expect(record.fullySigned).to.equal(false);
		expect(record.externalInputIndices).to.deep.equal([extIdx]);
		const extPos = record.ourWalletInputIndices.indexOf(extIdx);
		expect(record.ourWalletWitnesses[extPos]).to.deep.equal([]);
		expect(record.ourWalletWitnesses[extPos === 0 ? 1 : 0].length).to.equal(2);
		// The channel stays quiescent: no payment traffic resumes on a splice
		// that cannot complete.
		expect(pair.opener.isSplicePendingLock()).to.equal(false);
		expect(pair.opener.isHtlcUsable()).to.equal(false);
		// The obligation was surfaced exactly once for this connection.
		expect(pair.signals).to.have.length(1);
		expect(pair.signals[0].externalInputIndices).to.deep.equal([extIdx]);
		expect(pair.signals[0].spliceTxid.equals(record.spliceTxid)).to.equal(true);
		expect(pair.signals[0].newFundingOutputIndex).to.equal(
			record.newFundingOutputIndex
		);

		// The owner's witness releases everything at once.
		const witness = signExternalP2wpkh(record, wallet);
		const release = pair.opener.provideSpliceExternalWitness(
			Buffer.from(wallet.extPrevTx.getHash()),
			0,
			witness
		);
		pair.enqueue(pair.acceptor, pair.opener, release);
		pair.pump();
		expect(pair.errors).to.deep.equal([]);

		const sigsSent = pair.sent.filter(
			(m) => m.from === pair.opener && m.msgType === MessageType.TX_SIGNATURES
		);
		expect(sigsSent, 'exactly one tx_signatures leaves').to.have.length(1);
		const msg = decodeTxSignaturesMessage(sigsSent[0].payload);
		expect(msg.sharedInputSignature, 'shared-input sig rides with it').to.exist;
		expect(msg.witnesses[extPos][1].equals(wallet.extPub)).to.equal(true);

		const after = pair.opener.getFullState().spliceInFlight!;
		expect(after.sentTxSignatures).to.equal(true);
		expect(after.fullySigned).to.equal(true);
		// Both sides publish their own copy once the exchange completes.
		expect(pair.broadcasts, 'the completed splice broadcasts').to.have.length(
			2
		);

		// The broadcast transaction is complete, and the third party's witness
		// verifies against its own prevout.
		const broadcast = bitcoin.Transaction.fromBuffer(pair.broadcasts[0]);
		expect(Buffer.from(broadcast.getHash()).equals(record.spliceTxid)).to.equal(
			true
		);
		for (const input of broadcast.ins) {
			expect(input.witness.length).to.be.greaterThan(0);
		}
		const extSighash = broadcast.hashForWitnessV0(
			extIdx,
			bitcoin.payments.p2pkh({ pubkey: wallet.extPub }).output!,
			Number(EXT_UTXO_SATS),
			bitcoin.Transaction.SIGHASH_ALL
		);
		expect(
			ecc.verify(
				extSighash,
				wallet.extPub,
				bitcoin.script.signature.decode(broadcast.ins[extIdx].witness[0])
					.signature
			)
		).to.equal(true);
		// Both watches were armed for the new outpoint before we released.
		expect(pair.opener.isSplicePendingLock()).to.equal(true);
	});

	it('refuses an unverifiable witness before storing it, and stays waiting', function () {
		const { pair, wallet, record, extIdx } = driveToWithhold();
		const extTxid = Buffer.from(wallet.extPrevTx.getHash());
		const good = signExternalP2wpkh(record, wallet);

		// Well-formed stack signed by another key.
		const junkPriv = crypto
			.createHash('sha256')
			.update('not-the-owner')
			.digest();
		const junkSig = bitcoin.script.signature.encode(
			Buffer.from(ecc.sign(crypto.randomBytes(32), junkPriv)),
			bitcoin.Transaction.SIGHASH_ALL
		);
		expect(() =>
			pair.opener.provideSpliceExternalWitness(extTxid, 0, [
				junkSig,
				wallet.extPub
			])
		).to.throw(/external witness rejected/);
		// An outpoint that is ours but not external.
		expect(() =>
			pair.opener.provideSpliceExternalWitness(
				Buffer.from(wallet.ownPrevTx.getHash()),
				0,
				good
			)
		).to.throw(/not an external splice input/);
		// An outpoint outside the negotiated tx.
		expect(() =>
			pair.opener.provideSpliceExternalWitness(crypto.randomBytes(32), 0, good)
		).to.throw(/not an input of the negotiated splice tx/);
		// A malformed txid is misuse, not a refusal.
		expect(() =>
			pair.opener.provideSpliceExternalWitness(Buffer.alloc(16), 0, good)
		).to.throw(/32 bytes/);

		// Nothing moved: the slot is still a hole and nothing left the node.
		const still = pair.opener.getFullState().spliceInFlight!;
		expect(
			still.ourWalletWitnesses[still.ourWalletInputIndices.indexOf(extIdx)]
		).to.deep.equal([]);
		expect(still.sentTxSignatures).to.equal(false);
		expect(pair.broadcasts).to.deep.equal([]);

		// The real witness still works afterwards, and a repeat delivery once
		// our signatures left is a no-op rather than a second send.
		pair.enqueue(
			pair.acceptor,
			pair.opener,
			pair.opener.provideSpliceExternalWitness(extTxid, 0, good)
		);
		pair.pump();
		expect(pair.opener.getFullState().spliceInFlight!.fullySigned).to.equal(
			true
		);
		expect(
			pair.opener.provideSpliceExternalWitness(extTxid, 0, good)
		).to.deep.equal([]);
	});

	it('a P2TR external witness verifies over BIP 341 and releases', function () {
		const pair = makeWirePair();
		const wallet = makeExternalSpliceWallet('p2tr');
		startSpliceIn(pair, wallet);
		expect(pair.errors).to.deep.equal([]);

		const record = pair.opener.getFullState().spliceInFlight!;
		const extIdx = externalIndexOf(record, wallet.extPrevTx);
		const tx = bitcoin.Transaction.fromHex(record.spliceTxHex);
		const sighash = tx.hashForWitnessV1(
			extIdx,
			record.inputPrevouts.map((p) => p.script),
			record.inputPrevouts.map((p) => Number(p.valueSats)),
			bitcoin.Transaction.SIGHASH_ALL
		);
		// BIP 86 key-path spend: the owner signs with the tweaked key.
		const tweaked = taprootTweakPrivateKey(wallet.extPriv, wallet.extPub);
		const witness = [
			Buffer.concat([
				Buffer.from(ecc.signSchnorr(sighash, tweaked)),
				Buffer.from([bitcoin.Transaction.SIGHASH_ALL])
			])
		];

		pair.enqueue(
			pair.acceptor,
			pair.opener,
			pair.opener.provideSpliceExternalWitness(
				Buffer.from(wallet.extPrevTx.getHash()),
				0,
				witness
			)
		);
		pair.pump();
		expect(pair.errors).to.deep.equal([]);
		expect(pair.opener.getFullState().spliceInFlight!.fullySigned).to.equal(
			true
		);
		expect(pair.broadcasts).to.have.length(2);
	});

	it('a witness delivered before the peer signs waits for the peer, then completes', function () {
		const pair = makeWirePair();
		const wallet = makeExternalSpliceWallet();
		pair.hold(MessageType.TX_SIGNATURES);
		startSpliceIn(pair, wallet);
		expect(pair.errors).to.deep.equal([]);

		const record = pair.opener.getFullState().spliceInFlight!;
		expect(record.receivedTxSignatures).to.equal(false);
		const early = pair.opener.provideSpliceExternalWitness(
			Buffer.from(wallet.extPrevTx.getHash()),
			0,
			signExternalP2wpkh(record, wallet)
		);
		// We sign SECOND (the shared input is ours), so filling the last slot
		// persists and waits rather than releasing early.
		expect(early.map((a) => a.type)).to.deep.equal([
			ChannelActionType.PERSIST_STATE
		]);
		expect(record.sentTxSignatures).to.equal(false);
		expect(pair.broadcasts).to.deep.equal([]);

		// The peer's held tx_signatures now completes the exchange normally.
		pair.releaseHeld();
		expect(pair.errors).to.deep.equal([]);
		const after = pair.opener.getFullState().spliceInFlight!;
		expect(after.sentTxSignatures).to.equal(true);
		expect(after.fullySigned).to.equal(true);
		expect(pair.broadcasts).to.have.length(2);
		expect(
			pair.signals,
			'a filled slot never asks for a witness'
		).to.deep.equal([]);
	});

	it('the external input is ours for witness partitioning: a surplus peer stack is refused', function () {
		const pair = makeWirePair();
		const wallet = makeExternalSpliceWallet();
		// The acceptor contributes nothing, so any stack it sends is surplus.
		// Only correct partitioning (the external input counted as OURS) makes
		// the expected count zero.
		pair.intercept(MessageType.TX_SIGNATURES, (payload) => {
			const msg = decodeTxSignaturesMessage(payload);
			if (msg.witnesses.length > 0) return payload;
			msg.witnesses = [[Buffer.alloc(71, 1), Buffer.alloc(33, 2)]];
			return encodeTxSignaturesMessage(msg);
		});
		startSpliceIn(pair, wallet);

		expect(
			pair.errors.some((e) => /expected 0 witness stacks, got 1/.test(e)),
			'the peer stack count is judged against our own inputs'
		).to.equal(true);
		expect(pair.opener.getFullState().spliceInFlight!.fullySigned).to.equal(
			false
		);
	});

	it('an external input paying an unverifiable script aborts before any commitment', function () {
		const pair = makeWirePair();
		const wallet = makeExternalSpliceWallet('p2wsh');
		startSpliceIn(pair, wallet);

		expect(
			pair.errorsFrom.some(
				(e) =>
					e.from === pair.opener && /unsupported output type/.test(e.message)
			),
			'we audit our OWN external input, not just the peer its inputs'
		).to.equal(true);
		expect(
			pair.sent.some(
				(m) =>
					m.from === pair.opener && m.msgType === MessageType.COMMITMENT_SIGNED
			),
			'nothing was signed for a transaction we could never complete'
		).to.equal(false);
		expect(pair.opener.getFullState().spliceInFlight).to.equal(null);
		expect(pair.broadcasts).to.deep.equal([]);
	});

	it('survives a restart: no retransmit, a fresh reminder, delivery completes', function () {
		const { pair, wallet, record, extIdx } = driveToWithhold();

		// Crash-restore the opener from disk, mid-wait.
		const serialized = JSON.parse(
			JSON.stringify(serializeChannelState(pair.opener.getFullState()))
		);
		const restored = new Channel(deserializeChannelState(serialized));
		restored.setSigner(signerFromSeed(openerSeed));
		restored.restoreSpliceInFlight();
		const restoredRecord = restored.getFullState().spliceInFlight!;
		expect(restoredRecord.externalInputIndices).to.deep.equal([extIdx]);
		expect(restoredRecord.fullySigned).to.equal(false);

		restored.markForReestablish();
		pair.acceptor.markForReestablish();
		pair.replace(pair.opener, restored);
		const sentBefore = pair.sent.length;

		const rRe = findSendAction(
			restored.createReestablish(),
			MessageType.CHANNEL_REESTABLISH
		);
		const aRe = findSendAction(
			pair.acceptor.createReestablish(),
			MessageType.CHANNEL_REESTABLISH
		);
		pair.enqueue(
			pair.acceptor,
			restored,
			restored.handleReestablish(decodeChannelReestablishMessage(aRe.payload))
		);
		pair.enqueue(
			restored,
			pair.acceptor,
			pair.acceptor.handleReestablish(
				decodeChannelReestablishMessage(rRe.payload)
			)
		);
		pair.pump();

		expect(pair.errors).to.deep.equal([]);
		expect(
			pair.sent
				.slice(sentBefore)
				.some(
					(m) => m.from === restored && m.msgType === MessageType.TX_SIGNATURES
				),
			'a withheld message is never retransmitted'
		).to.equal(false);
		expect(
			pair.signals.length,
			'the reminder is re-armed for the new connection'
		).to.equal(2);
		expect(pair.signals[1].externalInputIndices).to.deep.equal([extIdx]);

		// Delivery on the restored channel validates against the record's own
		// prevouts and completes the splice.
		pair.enqueue(
			pair.acceptor,
			restored,
			restored.provideSpliceExternalWitness(
				Buffer.from(wallet.extPrevTx.getHash()),
				0,
				signExternalP2wpkh(restoredRecord, wallet)
			)
		);
		pair.pump();
		expect(pair.errors).to.deep.equal([]);
		const done = restored.getFullState().spliceInFlight!;
		expect(done.sentTxSignatures).to.equal(true);
		expect(done.fullySigned).to.equal(true);
		expect(pair.broadcasts).to.have.length(2);
		for (const raw of pair.broadcasts) {
			expect(
				Buffer.from(bitcoin.Transaction.fromBuffer(raw).getHash()).equals(
					record.spliceTxid
				)
			).to.equal(true);
		}
	});

	it('abort is refused once the peer has signed, and the record stays waiting', function () {
		const { pair, extIdx } = driveToWithhold();
		const actions = pair.opener.abortSplice('operator changed their mind');
		expect(
			actions.some(
				(a) =>
					a.type === ChannelActionType.ERROR &&
					/cannot be aborted|may confirm/.test(a.message)
			),
			'the crossing point is what forbids the abort, hole or no hole'
		).to.equal(true);
		const record = pair.opener.getFullState().spliceInFlight!;
		expect(record.externalInputIndices).to.deep.equal([extIdx]);
		expect(record.receivedTxSignatures).to.equal(true);
		expect(record.fullySigned).to.equal(false);
	});

	it('getPendingSpliceTx hands out a copy and names the owed outpoints', function () {
		const { pair, wallet, record, extIdx } = driveToWithhold();
		const pending = pair.opener.getPendingSpliceTx()!;
		expect(pending.spliceTxid.equals(record.spliceTxid)).to.equal(true);
		expect(pending.newFundingOutputIndex).to.equal(
			record.newFundingOutputIndex
		);
		expect(pending.prevouts!.scripts.length).to.equal(pending.tx.ins.length);
		expect(pending.owedExternalInputs).to.have.length(1);
		expect(pending.owedExternalInputs[0].inputIndex).to.equal(extIdx);
		expect(
			pending.owedExternalInputs[0].prevTxid.equals(wallet.extPrevTx.getHash())
		).to.equal(true);

		// Mutating the copy cannot touch the channel's own transaction.
		pending.tx.ins[0].sequence = 0;
		expect(
			Buffer.from(pair.opener.getSpliceTransaction()!.getHash()).equals(
				record.spliceTxid
			)
		).to.equal(true);
	});

	it('serializes the external slots and tolerates rows written before them', function () {
		const { record, extIdx } = driveToWithhold();
		const round = deserializeSpliceInFlight(
			JSON.parse(JSON.stringify(serializeSpliceInFlight(record)))
		);
		expect(round.externalInputIndices).to.deep.equal([extIdx]);
		const extPos = round.ourWalletInputIndices.indexOf(extIdx);
		expect(round.ourWalletWitnesses[extPos]).to.deep.equal([]);

		const legacy = JSON.parse(JSON.stringify(serializeSpliceInFlight(record)));
		delete legacy.externalInputIndices;
		expect(deserializeSpliceInFlight(legacy).externalInputIndices).to.equal(
			undefined
		);
	});
});
