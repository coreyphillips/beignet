/**
 * BOLT 2 v2 (dual-funding): the opening signature exchange survives
 * disconnects and restarts and resumes over channel_reestablish.next_funding
 * (issues 288 and 289).
 *
 * Channel-level tests drive two real Channel instances (real secp256k1 keys,
 * caller-driven tx_signatures) through the commitment round, then interrupt
 * the exchange at every meaningful boundary:
 *  - both sides announce the same next_funding_txid after a disconnect and
 *    the exchange completes;
 *  - a lost tx_signatures is retransmitted byte-identically from the durable
 *    record, never re-signed;
 *  - a peer that lost our commitment_signed gets the identical signature
 *    re-signed on request (RFC 6979 pins the bytes), which is also the
 *    release of a commitment owed across a crash;
 *  - a peer that forgot the open (reestablish without next_funding) unwinds
 *    it via tx_abort with no echo loop;
 *  - the record round-trips through serialization byte-exactly and restores
 *    a resumable builder-less session; legacy record-less rows drop
 *    deterministically; taproot records refuse to restore;
 *  - reestablish counters for a mid-open v2 channel are the spec's 1/0/zeros;
 *  - a pre-#1289 peer signalling with next_commitment_number 0 beside a
 *    matching next_funding_txid is a retransmit request, not a failure;
 *  - divergent next_funding_txids fail the channel;
 *  - RBF is refused once tx_signatures were released and on restored
 *    sessions, and an accepted RBF clears the per-attempt record.
 *
 * Node-level tests run two LightningNodes over a droppable in-process wire
 * and prove the two issues end to end: a live disconnect after the initial
 * commitment_signed no longer destroys the opening session (289), and a full
 * process restart resumes the exchange from the durable record alone to a
 * completed open (288).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

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
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import {
	IInteractiveTxInput,
	IInteractiveTxOutput
} from '../../src/lightning/interactive-tx/types';
import { createFundingScript } from '../../src/lightning/script/funding';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxSignaturesMessage,
	decodeTxAbortMessage,
	encodeTxInitRbfMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { decodeChannelReadyMessage } from '../../src/lightning/message/channel-funding';
import {
	IChannelReestablishMessage,
	decodeChannelReestablishMessage
} from '../../src/lightning/message/channel-reestablish';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, IFundingProvider } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

// ─────────────── Channel-level helpers ───────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findPayload(actions: any[], msgType: MessageType): Buffer | null {
	for (const a of actions) {
		if (
			a.type === ChannelActionType.SEND_MESSAGE &&
			a.messageType === msgType
		) {
			return a.payload;
		}
	}
	return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findError(actions: any[]): string | null {
	for (const a of actions) {
		if (a.type === ChannelActionType.ERROR) return a.message;
	}
	return null;
}

function getPerCommitmentPoint(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, MAX_INDEX - n));
}

function makeBasepoints(fundingPub: Buffer, seed: Buffer): IChannelBasepoints {
	return {
		fundingPubkey: fundingPub,
		revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
		paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
		firstPerCommitmentPoint: getPerCommitmentPoint(seed, 0n)
	};
}

function makeInput(
	serialId: bigint,
	prevTx: Buffer,
	sequence = 0xfffffffd
): IInteractiveTxInput {
	return {
		serialId,
		prevTxid: Buffer.from(bitcoin.Transaction.fromBuffer(prevTx).getHash()),
		prevOutputIndex: 0,
		sequence,
		prevTx,
		prevTxVout: 0
	};
}

/**
 * A REAL spendable P2WPKH prevout with a signing closure: witness validation
 * binds the pubkey to the program and verifies the signature over the BIP 143
 * sighash, so the caller-driven tests must release genuine spends.
 */
interface IRealPrevOut {
	prevTx: Buffer;
	script: Buffer;
	pub: Buffer;
	sign: (
		tx: bitcoin.Transaction,
		index: number,
		prevouts: { scripts: Buffer[]; values: bigint[] }
	) => Buffer[];
}

function makeRealPrevOut(valueSats: number): IRealPrevOut {
	const priv = crypto.randomBytes(32);
	const pub = getPublicKey(priv);
	const payment = bitcoin.payments.p2wpkh({ pubkey: pub });
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(payment.output!, valueSats);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output!;
	return {
		prevTx: prevTx.toBuffer(),
		script: payment.output!,
		pub,
		sign: (tx, index) => {
			const sighash = tx.hashForWitnessV0(
				index,
				scriptCode,
				valueSats,
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [
				bitcoin.script.signature.encode(
					Buffer.from(ecc.sign(sighash, priv)),
					bitcoin.Transaction.SIGHASH_ALL
				),
				pub
			];
		}
	};
}

/** A real P2TR key-path prevout (raw x-only key program, BIP 341 spend). */
function makeRealP2trPrevOut(valueSats: number): IRealPrevOut {
	const priv = crypto.randomBytes(32);
	const xonly = Buffer.from(getPublicKey(priv).subarray(1));
	const script = Buffer.concat([Buffer.from([0x51, 0x20]), xonly]);
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(script, valueSats);
	return {
		prevTx: prevTx.toBuffer(),
		script,
		pub: xonly,
		sign: (tx, index, prevouts) => {
			const sighash = tx.hashForWitnessV1(
				index,
				prevouts.scripts,
				prevouts.values.map((v) => Number(v)),
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [
				Buffer.concat([
					Buffer.from(ecc.signSchnorr(sighash, priv)),
					Buffer.from([bitcoin.Transaction.SIGHASH_ALL])
				])
			];
		}
	};
}

interface IHarness {
	opener: Channel;
	acceptor: Channel;
	openerSigner: ChannelSigner;
	acceptorSigner: ChannelSigner;
	openerSeed: Buffer;
	acceptorSeed: Buffer;
	/** commitment_signed payloads captured but NOT yet delivered. */
	openerCommit: Buffer;
	acceptorCommit: Buffer;
	openerPrev: IRealPrevOut;
	acceptorPrev: IRealPrevOut;
	/** Genuine witnesses for each side's funding input over the negotiated tx. */
	openerWitness(): Buffer[][];
	acceptorWitness(): Buffer[][];
}

const OPENER_FUNDING = 100_000n;
const ACCEPTOR_FUNDING = 50_000n;
const TOTAL_FUNDING = OPENER_FUNDING + ACCEPTOR_FUNDING;

/**
 * Wire two real Channels through the v2 open to the point where both emitted
 * (captured, undelivered) commitment_signed and sit in AWAITING_TX_SIGNATURES.
 * Same wiring as dual-funding-commitment.test.ts: both sides contribute one
 * input; the acceptor (lower input sats) signs tx_signatures first.
 */
function driveToCommitmentExchange(
	opts: { acceptorPrev?: IRealPrevOut } = {}
): IHarness {
	const sharedTempId = crypto.randomBytes(32);

	const openerFundingPriv = crypto.randomBytes(32);
	const acceptorFundingPriv = crypto.randomBytes(32);
	const openerFundingPub = getPublicKey(openerFundingPriv);
	const acceptorFundingPub = getPublicKey(acceptorFundingPriv);
	const openerSigner = new ChannelSigner(openerFundingPriv);
	const acceptorSigner = new ChannelSigner(acceptorFundingPriv);

	const openerSeed = crypto.randomBytes(32);
	const acceptorSeed = crypto.randomBytes(32);
	const openerBp = makeBasepoints(openerFundingPub, openerSeed);
	const acceptorBp = makeBasepoints(acceptorFundingPub, acceptorSeed);

	const openerState = createOpenerState({
		temporaryChannelId: sharedTempId,
		fundingSatoshis: OPENER_FUNDING,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBp,
		localPerCommitmentSeed: openerSeed
	});
	const opener = new Channel(openerState, openerSigner);

	const acceptorState = createAcceptorState({
		temporaryChannelId: sharedTempId,
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: acceptorBp,
		localPerCommitmentSeed: acceptorSeed,
		remoteBasepoints: makeBasepoints(
			getPublicKey(crypto.randomBytes(32)),
			crypto.randomBytes(32)
		),
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	const acceptor = new Channel(acceptorState, acceptorSigner);

	const mkParams = (
		fundingSatoshis: bigint,
		state: typeof openerState,
		seed: Buffer
	): IDualFundingParams => ({
		fundingSatoshis,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: DEFAULT_CHANNEL_CONFIG.feeratePerKw,
		dustLimitSatoshis: DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis,
		maxHtlcValueInFlightMsat: DEFAULT_CHANNEL_CONFIG.maxHtlcValueInFlightMsat,
		htlcMinimumMsat: DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat,
		toSelfDelay: DEFAULT_CHANNEL_CONFIG.toSelfDelay,
		maxAcceptedHtlcs: DEFAULT_CHANNEL_CONFIG.maxAcceptedHtlcs,
		locktime: 0,
		localBasepoints: state.localBasepoints,
		localPerCommitmentSeed: state.localPerCommitmentSeed,
		secondPerCommitmentPoint: getPerCommitmentPoint(seed, 1n)
	});

	const openActions = opener.initiateOpenV2(
		mkParams(OPENER_FUNDING, openerState, openerSeed)
	);
	expect(findError(openActions)).to.equal(null);
	const openMsg = decodeOpenChannel2Message(
		findPayload(openActions, MessageType.OPEN_CHANNEL2)!
	);
	acceptorState.temporaryChannelId = Buffer.from(openMsg.channelId);

	const acceptActions = acceptor.handleOpenChannel2(
		openMsg,
		mkParams(ACCEPTOR_FUNDING, acceptorState, acceptorSeed)
	);
	expect(findError(acceptActions)).to.equal(null);
	const acceptMsg = decodeAcceptChannel2Message(
		findPayload(acceptActions, MessageType.ACCEPT_CHANNEL2)!
	);
	expect(findError(opener.handleAcceptChannel2(acceptMsg))).to.equal(null);

	const openerPrev = makeRealPrevOut(120_000);
	const acceptorPrev = opts.acceptorPrev ?? makeRealPrevOut(60_000);
	const openerInput = makeInput(0n, openerPrev.prevTx);
	const acceptorInput = makeInput(1n, acceptorPrev.prevTx);
	const funding = createFundingScript(openerFundingPub, acceptorFundingPub);
	const fundingOutput: IInteractiveTxOutput = {
		serialId: 2n,
		amountSats: TOTAL_FUNDING,
		scriptPubkey: funding.p2wshOutput
	};

	const oInAct = opener.addTxInput(openerInput);
	expect(findError(oInAct)).to.equal(null);
	acceptor.handleTxAddInput(
		decodeTxAddInputMessage(findPayload(oInAct, MessageType.TX_ADD_INPUT)!)
	);
	const aInAct = acceptor.addTxInput(acceptorInput);
	expect(findError(aInAct)).to.equal(null);
	opener.handleTxAddInput(
		decodeTxAddInputMessage(findPayload(aInAct, MessageType.TX_ADD_INPUT)!)
	);
	const oOutAct = opener.addTxOutput(fundingOutput);
	expect(findError(oOutAct)).to.equal(null);
	acceptor.handleTxAddOutput(
		decodeTxAddOutputMessage(findPayload(oOutAct, MessageType.TX_ADD_OUTPUT)!)
	);

	expect(findError(acceptor.sendTxComplete())).to.equal(null);
	opener.handleTxComplete();
	const opCompleteActions = opener.sendTxComplete();
	expect(findError(opCompleteActions)).to.equal(null);
	const openerCommit = findPayload(
		opCompleteActions,
		MessageType.COMMITMENT_SIGNED
	)!;
	expect(openerCommit).to.not.equal(null);
	const acCompleteActions = acceptor.handleTxComplete();
	const acceptorCommit = findPayload(
		acCompleteActions,
		MessageType.COMMITMENT_SIGNED
	)!;
	expect(acceptorCommit).to.not.equal(null);
	expect(opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
	expect(acceptor.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);

	const witnessFor = (
		channel: Channel,
		prev: IRealPrevOut,
		index: number
	): Buffer[][] => {
		const rec = channel.getFullState().v2InFlight!;
		const tx = bitcoin.Transaction.fromHex(rec.fundingTxHex);
		return [
			prev.sign(tx, index, {
				scripts: rec.inputPrevouts.map((p) => p.script),
				values: rec.inputPrevouts.map((p) => p.valueSats)
			})
		];
	};

	return {
		opener,
		acceptor,
		openerSigner,
		acceptorSigner,
		openerSeed,
		acceptorSeed,
		openerCommit,
		acceptorCommit,
		openerPrev,
		acceptorPrev,
		openerWitness: () => witnessFor(opener, openerPrev, 0),
		acceptorWitness: () => witnessFor(acceptor, acceptorPrev, 1)
	};
}

/** Deliver both captured commitment_signed messages across. */
function deliverCommitments(h: IHarness): void {
	expect(
		findError(
			h.acceptor.handleCommitmentSigned(
				decodeCommitmentSignedMessage(h.openerCommit)
			)
		)
	).to.equal(null);
	expect(
		findError(
			h.opener.handleCommitmentSigned(
				decodeCommitmentSignedMessage(h.acceptorCommit)
			)
		)
	).to.equal(null);
}

/** The reestablish message a channel just emitted, decoded. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function reestablishOf(actions: any[]): IChannelReestablishMessage {
	const payload = findPayload(actions, MessageType.CHANNEL_REESTABLISH);
	expect(payload, 'a channel_reestablish was emitted').to.not.equal(null);
	return decodeChannelReestablishMessage(payload!);
}

/** Complete the caller-driven tx_signatures exchange after a reconnect. */
function completeExchange(h: IHarness): void {
	// The acceptor (lower input sats) signs first.
	const accTxid = h.acceptor.getFullState().fundingTxid!;
	const accOidx = h.acceptor.getFullState().fundingOutputIndex;
	const accSig = h.acceptor.sendTxSignatures(
		accTxid,
		accOidx,
		h.acceptorWitness()
	);
	expect(findError(accSig)).to.equal(null);
	const accTxSigs = findPayload(accSig, MessageType.TX_SIGNATURES);
	expect(accTxSigs, 'acceptor releases tx_signatures first').to.not.equal(null);

	const opAfterPeer = h.opener.handleTxSignatures(
		decodeTxSignaturesMessage(accTxSigs!)
	);
	expect(findError(opAfterPeer)).to.equal(null);
	let openTxSigs = findPayload(opAfterPeer, MessageType.TX_SIGNATURES);
	if (!openTxSigs) {
		// Caller-driven: the opener still owes its witnesses.
		const openSig = h.opener.sendTxSignatures(
			h.opener.getFullState().fundingTxid!,
			h.opener.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		expect(findError(openSig)).to.equal(null);
		openTxSigs = findPayload(openSig, MessageType.TX_SIGNATURES);
	}
	expect(openTxSigs, 'opener releases tx_signatures').to.not.equal(null);
	expect(
		findError(
			h.acceptor.handleTxSignatures(decodeTxSignaturesMessage(openTxSigs!))
		)
	).to.equal(null);

	expect(h.opener.getState()).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
	expect(h.acceptor.getState()).to.equal(
		ChannelState.AWAITING_FUNDING_CONFIRMED
	);
	expect(
		h.opener
			.getFullState()
			.fundingTxid!.equals(h.acceptor.getFullState().fundingTxid!)
	).to.equal(true);
}

// ─────────────── Channel-level tests ───────────────

describe('Dual funding v2 reestablish (issues 288/289)', () => {
	it('records the open at the initial commitment_signed with the negotiated tx and ordering', () => {
		const h = driveToCommitmentExchange();
		const record = h.opener.getFullState().v2InFlight!;
		expect(
			record,
			'the record exists once commitment_signed left'
		).to.not.be.oneOf([null, undefined]);
		expect(record.fundingTxid.equals(h.opener.getFullState().fundingTxid!)).to
			.be.true;
		expect(record.isInitiator).to.equal(true);
		expect(record.localContributionSats).to.equal(OPENER_FUNDING);
		expect(record.remoteContributionSats).to.equal(ACCEPTOR_FUNDING);
		// The acceptor contributes less input value, so the opener does NOT
		// sign first; the acceptor's own record says it does.
		expect(record.weSignFirst).to.equal(false);
		expect(h.acceptor.getFullState().v2InFlight!.weSignFirst).to.equal(true);
		expect(record.sentTxSignatures).to.equal(false);
		expect(record.receivedTxSignatures).to.equal(false);
		// The negotiated tx round-trips to the recorded funding txid.
		const tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
		expect(Buffer.from(tx.getHash()).equals(record.fundingTxid)).to.be.true;
		// The peer's signature lands in the record when it arrives.
		expect(record.remoteCommitmentSig).to.equal(null);
		deliverCommitments(h);
		expect(record.remoteCommitmentSig).to.not.equal(null);
	});

	it('announces the same next_funding_txid on both sides after a disconnect and completes', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		h.opener.markForReestablish();
		h.acceptor.markForReestablish();
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(h.acceptor.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

		const opReest = h.opener.createReestablish();
		const acReest = h.acceptor.createReestablish();
		const opMsg = reestablishOf(opReest);
		const acMsg = reestablishOf(acReest);

		expect(
			opMsg.nextFundingTxid,
			'opener announces next_funding'
		).to.not.be.oneOf([null, undefined]);
		expect(
			acMsg.nextFundingTxid,
			'acceptor announces next_funding'
		).to.not.be.oneOf([null, undefined]);
		expect(opMsg.nextFundingTxid!.equals(acMsg.nextFundingTxid!)).to.be.true;
		// Both hold the peer's commitment_signed: neither asks for a retransmit.
		expect(opMsg.nextFundingRetransmitFlags).to.equal(0);
		expect(acMsg.nextFundingRetransmitFlags).to.equal(0);

		const opHandle = h.opener.handleReestablish(acMsg);
		expect(findError(opHandle)).to.equal(null);
		expect(
			findPayload(opHandle, MessageType.COMMITMENT_SIGNED),
			'no commitment retransmit when the peer did not ask'
		).to.equal(null);
		const acHandle = h.acceptor.handleReestablish(opMsg);
		expect(findError(acHandle)).to.equal(null);
		expect(findPayload(acHandle, MessageType.COMMITMENT_SIGNED)).to.equal(null);

		completeExchange(h);
	});

	it('retransmits lost tx_signatures byte-identically from the record', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// The acceptor releases its tx_signatures, but they never arrive.
		const accTxid = h.acceptor.getFullState().fundingTxid!;
		const accOidx = h.acceptor.getFullState().fundingOutputIndex;
		const accSig = h.acceptor.sendTxSignatures(
			accTxid,
			accOidx,
			h.acceptorWitness()
		);
		const original = findPayload(accSig, MessageType.TX_SIGNATURES)!;
		expect(original).to.not.equal(null);
		expect(h.acceptor.getFullState().v2InFlight!.sentTxSignatures).to.be.true;

		h.opener.markForReestablish();
		h.acceptor.markForReestablish();
		const opMsg = reestablishOf(h.opener.createReestablish());
		// The acceptor still announces: it has not received OUR tx_signatures.
		const acMsg = reestablishOf(h.acceptor.createReestablish());
		expect(acMsg.nextFundingTxid).to.not.be.oneOf([null, undefined]);

		const acHandle = h.acceptor.handleReestablish(opMsg);
		expect(findError(acHandle)).to.equal(null);
		const retransmitted = findPayload(acHandle, MessageType.TX_SIGNATURES);
		expect(retransmitted, 'acceptor retransmits tx_signatures').to.not.equal(
			null
		);
		expect(
			retransmitted!.equals(original),
			'the retransmission is byte-identical (recorded witnesses, no re-sign)'
		).to.be.true;

		expect(findError(h.opener.handleReestablish(acMsg))).to.equal(null);

		// Deliver the retransmission; the opener completes its own side.
		const opAfterPeer = h.opener.handleTxSignatures(
			decodeTxSignaturesMessage(retransmitted!)
		);
		expect(findError(opAfterPeer)).to.equal(null);
		const openSig = h.opener.sendTxSignatures(
			h.opener.getFullState().fundingTxid!,
			h.opener.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		const openTxSigs = findPayload(openSig, MessageType.TX_SIGNATURES)!;
		expect(openTxSigs).to.not.equal(null);
		expect(
			findError(
				h.acceptor.handleTxSignatures(decodeTxSignaturesMessage(openTxSigs))
			)
		).to.equal(null);
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('re-signs the identical commitment_signed for a peer that lost it (the owed release)', () => {
		const h = driveToCommitmentExchange();
		// Only the opener's commitment was delivered; the acceptor's was lost,
		// so the opener never adopted it.
		expect(
			findError(
				h.acceptor.handleCommitmentSigned(
					decodeCommitmentSignedMessage(h.openerCommit)
				)
			)
		).to.equal(null);

		h.opener.markForReestablish();
		h.acceptor.markForReestablish();

		const opMsg = reestablishOf(h.opener.createReestablish());
		// The opener lacks the acceptor's commitment: it asks via flag bit 0.
		expect(opMsg.nextFundingRetransmitFlags).to.equal(1);
		const acMsg = reestablishOf(h.acceptor.createReestablish());
		expect(acMsg.nextFundingRetransmitFlags).to.equal(0);

		const acHandle = h.acceptor.handleReestablish(opMsg);
		expect(findError(acHandle)).to.equal(null);
		const resigned = findPayload(acHandle, MessageType.COMMITMENT_SIGNED);
		expect(resigned, 'acceptor retransmits its commitment_signed').to.not.equal(
			null
		);
		expect(
			resigned!.equals(h.acceptorCommit),
			'RFC 6979 re-signs commitment #0 byte-identically'
		).to.be.true;

		expect(findError(h.opener.handleReestablish(acMsg))).to.equal(null);
		expect(
			findError(
				h.opener.handleCommitmentSigned(
					decodeCommitmentSignedMessage(resigned!)
				)
			)
		).to.equal(null);
		completeExchange(h);
	});

	it('unwinds via tx_abort when the peer reestablishes without next_funding, with no echo loop', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		h.opener.markForReestablish();

		// The peer forgot the open: its reestablish carries no next_funding.
		const forgotten: IChannelReestablishMessage = {
			channelId: h.opener.getChannelId()!,
			nextCommitmentNumber: 1n,
			nextRevocationNumber: 0n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: getPerCommitmentPoint(h.acceptorSeed, 0n)
		};
		const actions = h.opener.handleReestablish(forgotten);
		const abortPayload = findPayload(actions, MessageType.TX_ABORT);
		expect(abortPayload, 'the opener unwinds with tx_abort').to.not.equal(null);
		expect(
			decodeTxAbortMessage(abortPayload!).data.toString('utf8')
		).to.contain('without next_funding_txid');
		expect(h.opener.getState()).to.equal(ChannelState.ERRORED);
		expect(h.opener.getFullState().v2InFlight ?? null).to.equal(null);
		expect(h.opener.getFullState().dualFundingSession).to.equal(null);

		// The peer's echo is consumed silently: no answer to the answer.
		expect(h.opener.handleTxAbort()).to.deep.equal([]);
	});

	it('never unwinds on omission once tx_signatures were released', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const accTxid = h.acceptor.getFullState().fundingTxid!;
		const accSig = h.acceptor.sendTxSignatures(
			accTxid,
			h.acceptor.getFullState().fundingOutputIndex,
			h.acceptorWitness()
		);
		expect(findPayload(accSig, MessageType.TX_SIGNATURES)).to.not.equal(null);

		h.acceptor.markForReestablish();
		const forgotten: IChannelReestablishMessage = {
			channelId: h.acceptor.getChannelId()!,
			nextCommitmentNumber: 1n,
			nextRevocationNumber: 0n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: getPerCommitmentPoint(h.openerSeed, 0n)
		};
		const actions = h.acceptor.handleReestablish(forgotten);
		expect(
			findPayload(actions, MessageType.TX_ABORT),
			'no tx_abort after our witnesses left'
		).to.equal(null);
		expect(h.acceptor.getState()).to.not.equal(ChannelState.ERRORED);
		expect(h.acceptor.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);
	});

	it('fails the channel on a divergent next_funding_txid', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		h.opener.markForReestablish();

		const divergent: IChannelReestablishMessage = {
			channelId: h.opener.getChannelId()!,
			nextCommitmentNumber: 1n,
			nextRevocationNumber: 0n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: getPerCommitmentPoint(h.acceptorSeed, 0n),
			nextFundingTxid: crypto.randomBytes(32),
			nextFundingRetransmitFlags: 0
		};
		const actions = h.opener.handleReestablish(divergent);
		expect(findError(actions)).to.contain('does not match');
		expect(h.opener.getState()).to.equal(ChannelState.ERRORED);
		expect(
			findPayload(actions, MessageType.TX_ABORT),
			'a divergent txid is a wire error, never tx_abort'
		).to.equal(null);
	});

	it('pins the reestablish counters of a mid-open v2 channel to 1/0/zeros', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		h.opener.markForReestablish();
		const msg = reestablishOf(h.opener.createReestablish());
		expect(msg.nextCommitmentNumber).to.equal(1n);
		expect(msg.nextRevocationNumber).to.equal(0n);
		expect(msg.yourLastPerCommitmentSecret.equals(Buffer.alloc(32))).to.be.true;
		expect(
			msg.myCurrentPerCommitmentPoint.equals(
				getPerCommitmentPoint(h.openerSeed, 0n)
			)
		).to.be.true;
	});

	it('treats a pre-#1289 next_commitment_number 0 beside a matching txid as a retransmit request', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		h.acceptor.markForReestablish();

		const eclairStyle: IChannelReestablishMessage = {
			channelId: h.acceptor.getChannelId()!,
			nextCommitmentNumber: 0n,
			nextRevocationNumber: 0n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: getPerCommitmentPoint(h.openerSeed, 0n),
			nextFundingTxid: Buffer.from(
				h.acceptor.getFullState().v2InFlight!.fundingTxid
			),
			nextFundingRetransmitFlags: 0
		};
		const actions = h.acceptor.handleReestablish(eclairStyle);
		expect(findError(actions)).to.equal(null);
		expect(h.acceptor.getState()).to.not.equal(ChannelState.ERRORED);
		expect(
			findPayload(actions, MessageType.COMMITMENT_SIGNED),
			'number 0 means the peer lacks the initial commitment_signed'
		).to.not.equal(null);

		// Without the matching TLV the zero stays a hard failure.
		h.opener.markForReestablish();
		const bare: IChannelReestablishMessage = {
			channelId: h.opener.getChannelId()!,
			nextCommitmentNumber: 0n,
			nextRevocationNumber: 0n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: getPerCommitmentPoint(h.acceptorSeed, 0n)
		};
		const failed = h.opener.handleReestablish(bare);
		expect(findError(failed)).to.contain('next_commitment_number is 0');
		expect(h.opener.getState()).to.equal(ChannelState.ERRORED);
	});

	it('round-trips the record through serialization and resumes from the restored session', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		const serialized = serializeChannelState(h.opener.getFullState());
		const json = JSON.parse(JSON.stringify(serialized));
		expect(json.v2InFlight, 'the record serialized').to.not.be.oneOf([
			null,
			undefined
		]);
		const restored = deserializeChannelState(json);
		// Byte-exact round trip of the record itself.
		expect(
			JSON.parse(JSON.stringify(serializeChannelState(restored)))
		).to.deep.include({ fundingVersion: 2 });
		expect(JSON.stringify(serializeChannelState(restored).v2InFlight)).to.equal(
			JSON.stringify(serialized.v2InFlight)
		);
		expect(
			restored.dualFundingSession,
			'the live session never serializes'
		).to.equal(null);

		const revived = new Channel(restored, h.openerSigner);
		revived.restoreV2InFlight();
		expect(
			revived.getFullState().dualFundingSession,
			'a builder-less session was rebuilt'
		).to.not.equal(null);
		revived.markForReestablish();
		expect(revived.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

		const msg = reestablishOf(revived.createReestablish());
		expect(
			msg.nextFundingTxid!.equals(
				h.acceptor.getFullState().v2InFlight!.fundingTxid
			)
		).to.be.true;

		// The live acceptor reconnects and the exchange completes, with the
		// revived side sourcing everything from the record.
		h.acceptor.markForReestablish();
		const acMsg = reestablishOf(h.acceptor.createReestablish());
		expect(findError(revived.handleReestablish(acMsg))).to.equal(null);
		expect(findError(h.acceptor.handleReestablish(msg))).to.equal(null);

		const accSig = h.acceptor.sendTxSignatures(
			h.acceptor.getFullState().fundingTxid!,
			h.acceptor.getFullState().fundingOutputIndex,
			h.acceptorWitness()
		);
		const accTxSigs = findPayload(accSig, MessageType.TX_SIGNATURES)!;
		const revAfterPeer = revived.handleTxSignatures(
			decodeTxSignaturesMessage(accTxSigs)
		);
		expect(findError(revAfterPeer)).to.equal(null);
		const revSig = revived.sendTxSignatures(
			revived.getFullState().fundingTxid!,
			revived.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		const revTxSigs = findPayload(revSig, MessageType.TX_SIGNATURES)!;
		expect(revTxSigs).to.not.equal(null);
		expect(
			findError(
				h.acceptor.handleTxSignatures(decodeTxSignaturesMessage(revTxSigs))
			)
		).to.equal(null);
		expect(revived.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('deserializes a legacy state without a record to null and drops it deterministically', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const serialized = serializeChannelState(h.opener.getFullState());
		const json = JSON.parse(JSON.stringify(serialized));
		delete json.v2InFlight;
		const restored = deserializeChannelState(json);
		expect(restored.v2InFlight ?? null).to.equal(null);

		const revived = new Channel(restored, h.openerSigner);
		revived.restoreV2InFlight();
		expect(revived.getFullState().dualFundingSession).to.equal(null);
		revived.markForReestablish();
		expect(revived.getState()).to.equal(ChannelState.ERRORED);
	});

	it('refuses to restore a taproot record', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.opener.getFullState()))
		);
		// Forge a taproot channel type onto the row (a real one cannot exist:
		// taproot v2 opens fail closed before any signature).
		const tapFlags = new FeatureFlags();
		tapFlags.setOptional(Feature.OPTION_TAPROOT);
		json.channelType = tapFlags.toBuffer().toString('hex');
		const restored = deserializeChannelState(json);
		const revived = new Channel(restored, h.openerSigner);
		revived.restoreV2InFlight();
		expect(
			revived.getFullState().dualFundingSession,
			'no session is rebuilt for a taproot record'
		).to.equal(null);
	});

	it('aborts a pre-commitment open on disconnect (the other half of the boundary)', () => {
		// A fresh opener stopped before any commitment_signed.
		const sharedTempId = crypto.randomBytes(32);
		const openerFundingPriv = crypto.randomBytes(32);
		const openerSeed = crypto.randomBytes(32);
		const openerState = createOpenerState({
			temporaryChannelId: sharedTempId,
			fundingSatoshis: OPENER_FUNDING,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(
				getPublicKey(openerFundingPriv),
				openerSeed
			),
			localPerCommitmentSeed: openerSeed
		});
		const opener = new Channel(
			openerState,
			new ChannelSigner(openerFundingPriv)
		);
		const openActions = opener.initiateOpenV2({
			fundingSatoshis: OPENER_FUNDING,
			fundingFeeratePerkw: 1000,
			commitmentFeeratePerkw: DEFAULT_CHANNEL_CONFIG.feeratePerKw,
			dustLimitSatoshis: DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: DEFAULT_CHANNEL_CONFIG.maxHtlcValueInFlightMsat,
			htlcMinimumMsat: DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat,
			toSelfDelay: DEFAULT_CHANNEL_CONFIG.toSelfDelay,
			maxAcceptedHtlcs: DEFAULT_CHANNEL_CONFIG.maxAcceptedHtlcs,
			locktime: 0,
			localBasepoints: openerState.localBasepoints,
			localPerCommitmentSeed: openerState.localPerCommitmentSeed,
			secondPerCommitmentPoint: getPerCommitmentPoint(openerSeed, 1n)
		});
		expect(findError(openActions)).to.equal(null);
		expect(opener.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		expect(opener.getFullState().v2InFlight ?? null).to.equal(null);

		opener.markForReestablish();
		expect(
			opener.getState(),
			'nothing resumable exists before commitment_signed'
		).to.equal(ChannelState.ERRORED);
	});

	it('refuses RBF after tx_signatures were released and on restored sessions; accepted RBF retains the rollback record until post-ack traffic', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// Accepted RBF before any signatures: the previous attempt's record
		// is RETAINED as rollback state (the ack may never arrive, or the
		// initiator may never commit it). tx_init_rbf is received by the
		// ACCEPTOR (the opener initiates).
		const preRecord = h.acceptor.getFullState().v2InFlight;
		expect(preRecord).to.not.be.oneOf([null, undefined]);
		const rbfHandle = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findError(rbfHandle)).to.equal(null);
		expect(
			findPayload(rbfHandle, MessageType.TX_ACK_RBF),
			'pre-signature RBF is acked'
		).to.not.equal(null);
		expect(
			rbfHandle.some((a) => a.type === ChannelActionType.PERSIST_STATE),
			'the provisional acceptance persists'
		).to.be.true;
		expect(
			h.acceptor.getFullState().v2InFlight,
			'the rollback record is retained'
		).to.equal(preRecord);
		expect(h.acceptor.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);

		// The first post-ack interactive message proves the initiator
		// committed to the replacement: the rollback record clears, durably.
		const prev = makeRealPrevOut(120_000);
		const commitActions = h.acceptor.handleTxAddInput({
			channelId: h.acceptor.getChannelId()!,
			serialId: 0n,
			prevTx: prev.prevTx,
			prevTxVout: 0,
			sequence: 0xfffffffd
		});
		expect(findError(commitActions)).to.equal(null);
		expect(
			commitActions.some((a) => a.type === ChannelActionType.PERSIST_STATE),
			'the record clear persists at the commit point'
		).to.be.true;
		expect(h.acceptor.getFullState().v2InFlight ?? null).to.equal(null);

		// After a release, RBF is refused in both directions.
		const g = driveToCommitmentExchange();
		deliverCommitments(g);
		const accSig = g.acceptor.sendTxSignatures(
			g.acceptor.getFullState().fundingTxid!,
			g.acceptor.getFullState().fundingOutputIndex,
			g.acceptorWitness()
		);
		expect(findPayload(accSig, MessageType.TX_SIGNATURES)).to.not.equal(null);
		expect(findError(g.acceptor.initiateTxRbf(2000))).to.contain(
			'after tx_signatures'
		);
		const refused = g.acceptor.handleTxInitRbf({
			channelId: g.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findPayload(refused, MessageType.TX_ABORT)).to.not.equal(null);

		// A restored (builder-less) session cannot renegotiate. The revived
		// OPENER has not released tx_signatures, so the refusal it hits is the
		// restored-session one, in both directions.
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(g.opener.getFullState()))
		);
		const revived = new Channel(deserializeChannelState(json), g.openerSigner);
		revived.restoreV2InFlight();
		const restoredRefusal = revived.handleTxInitRbf({
			channelId: revived.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		const abort = findPayload(restoredRefusal, MessageType.TX_ABORT);
		expect(abort).to.not.equal(null);
		expect(decodeTxAbortMessage(abort!).data.toString('utf8')).to.contain(
			'restored'
		);
		expect(findError(revived.initiateTxRbf(2000))).to.contain('restored');
	});

	it('tx_init_rbf replaces nothing until the ack: the attempt survives the request window', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const before = h.opener.getFullState().v2InFlight!;

		const initActions = h.opener.initiateTxRbf(2000);
		expect(findError(initActions)).to.equal(null);
		expect(findPayload(initActions, MessageType.TX_INIT_RBF)).to.not.equal(
			null
		);
		// Nothing was replaced, nothing needs persisting: the current attempt
		// is still live and durable, so a disconnect here resumes it.
		expect(initActions.some((a) => a.type === ChannelActionType.PERSIST_STATE))
			.to.be.false;
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(h.opener.getFullState().v2InFlight).to.equal(before);

		// A disconnect in the request window forgets the pending request and
		// resumes the existing attempt over reestablish, both ways.
		h.opener.markForReestablish();
		h.acceptor.markForReestablish();
		const opMsg = reestablishOf(h.opener.createReestablish());
		expect(opMsg.nextFundingTxid!.equals(before.fundingTxid)).to.be.true;
		const acMsg = reestablishOf(h.acceptor.createReestablish());
		expect(findError(h.opener.handleReestablish(acMsg))).to.equal(null);
		expect(findError(h.acceptor.handleReestablish(opMsg))).to.equal(null);
		completeExchange(h);
	});

	it('permits only one outstanding RBF request; the ack applies the first', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// The first request pends; a second is refused while it waits, so
		// the eventual ack can only apply the parameters the peer saw.
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const second = h.opener.initiateTxRbf(3000);
		expect(findError(second)).to.contain('already pending');
		expect(findPayload(second, MessageType.TX_INIT_RBF)).to.equal(null);

		const ackActions = h.opener.handleTxAckRbf();
		expect(findError(ackActions)).to.equal(null);
		expect(
			h.opener
				.getFullState()
				.dualFundingSession!.getLocalParams()!.fundingFeeratePerkw,
			'the renegotiation prices at the FIRST request'
		).to.equal(2000);
	});

	it('a refused tx_init_rbf preserves the current attempt on both sides', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const before = Buffer.from(h.opener.getFullState().v2InFlight!.fundingTxid);

		// The receiver refuses (a feerate below its 25/24 floor, modelling a
		// peer with a different fee view); the refusal mutates nothing there.
		const refusal = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 1001
		});
		expect(findPayload(refusal, MessageType.TX_ABORT)).to.not.equal(null);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_TX_SIGNATURES
		);
		expect(h.acceptor.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);

		// The initiator, holding a pending request, treats the tx_abort as
		// the refusal it is: only the pending request dies. No teardown, no
		// error, and the attempt is not abandoned.
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const answer = h.opener.handleTxAbort();
		expect(findError(answer)).to.equal(null);
		expect(
			findPayload(answer, MessageType.TX_ABORT),
			'the abort is echoed as its ack'
		).to.not.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(h.opener.getFullState().v2InFlight!.fundingTxid.equals(before)).to
			.be.true;
		expect(h.opener.isAbandonedV2Open()).to.be.false;

		// The refusing receiver swallows the echo (it sent the abort itself),
		// and the ORIGINAL attempt still completes.
		expect(h.acceptor.handleTxAbort()).to.deep.equal([]);
		completeExchange(h);
	});

	it('tx_ack_rbf begins the renegotiation: record cleared, persisted, state knocked back', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const ackActions = h.opener.handleTxAckRbf();
		expect(findError(ackActions)).to.equal(null);
		expect(
			ackActions.some((a) => a.type === ChannelActionType.PERSIST_STATE),
			'the agreed replacement persists'
		).to.be.true;
		expect(h.opener.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		expect(h.opener.getFullState().v2InFlight ?? null).to.equal(null);

		// An unsolicited ack acknowledges nothing.
		const g = driveToCommitmentExchange();
		deliverCommitments(g);
		expect(g.opener.handleTxAckRbf()).to.deep.equal([]);
		expect(g.opener.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);
	});

	it('refuses RBF on a completed open: nothing reaches the wire after channel_ready', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);

		// channel_ready both ways: the record clears, but the session object
		// survives (at AWAITING_CHANNEL_READY), so every pre-round-6 guard
		// passes and only the session-state check stands between a caller and
		// a tx_init_rbf the peer would refuse with tx_abort.
		const opReady = h.opener.fundingConfirmed();
		const opReadyPayload = findPayload(opReady, MessageType.CHANNEL_READY)!;
		const acReady = h.acceptor.fundingConfirmed();
		const acReadyPayload = findPayload(acReady, MessageType.CHANNEL_READY)!;
		expect(
			findError(
				h.opener.handleChannelReady(decodeChannelReadyMessage(acReadyPayload))
			)
		).to.equal(null);
		expect(
			findError(
				h.acceptor.handleChannelReady(decodeChannelReadyMessage(opReadyPayload))
			)
		).to.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.NORMAL);
		expect(h.opener.getFullState().v2InFlight ?? null).to.equal(null);
		expect(h.opener.getFullState().dualFundingSession).to.not.be.oneOf([
			null,
			undefined
		]);

		const actions = h.opener.initiateTxRbf(2000);
		expect(findError(actions)).to.contain('not renegotiable');
		expect(findPayload(actions, MessageType.TX_INIT_RBF)).to.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.NORMAL);
	});

	it('records the fully signed funding tx for rebroadcast and clears the record at NORMAL', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);

		const record = h.opener.getFullState().v2InFlight!;
		expect(record.receivedTxSignatures).to.be.true;
		expect(record.sentTxSignatures).to.be.true;
		expect(record.fullySigned, 'both witness sets recorded').to.be.true;
		const pending = h.opener.getFullState().pendingFundingTxHex;
		expect(
			pending,
			'the funding tx is staged for (re)broadcast'
		).to.not.be.oneOf([null, undefined]);
		const tx = bitcoin.Transaction.fromHex(pending!);
		expect(
			Buffer.from(tx.getHash()).equals(h.opener.getFullState().fundingTxid!)
		).to.be.true;
		expect(tx.ins.every((i) => i.witness.length > 0)).to.equal(true);

		// channel_ready both ways ends the opening phase: the record clears.
		const opReady = h.opener.fundingConfirmed();
		const opReadyPayload = findPayload(opReady, MessageType.CHANNEL_READY)!;
		const acReady = h.acceptor.fundingConfirmed();
		const acReadyPayload = findPayload(acReady, MessageType.CHANNEL_READY)!;
		expect(
			findError(
				h.opener.handleChannelReady(decodeChannelReadyMessage(acReadyPayload))
			)
		).to.equal(null);
		expect(
			findError(
				h.acceptor.handleChannelReady(decodeChannelReadyMessage(opReadyPayload))
			)
		).to.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.NORMAL);
		expect(h.acceptor.getState()).to.equal(ChannelState.NORMAL);
		expect(h.opener.getFullState().v2InFlight ?? null).to.equal(null);
		expect(h.acceptor.getFullState().v2InFlight ?? null).to.equal(null);
	});

	/**
	 * Drive to the mirrored-loss shape: the acceptor released its
	 * tx_signatures and the opener completed (fully signed, state
	 * AWAITING_FUNDING_CONFIRMED), but the opener's own tx_signatures never
	 * reached the acceptor.
	 */
	function driveToFullySignedWithLostFinal(h: IHarness): Buffer {
		deliverCommitments(h);
		const accSig = h.acceptor.sendTxSignatures(
			h.acceptor.getFullState().fundingTxid!,
			h.acceptor.getFullState().fundingOutputIndex,
			h.acceptorWitness()
		);
		const accTxSigs = findPayload(accSig, MessageType.TX_SIGNATURES)!;
		expect(accTxSigs).to.not.equal(null);
		expect(
			findError(
				h.opener.handleTxSignatures(decodeTxSignaturesMessage(accTxSigs))
			)
		).to.equal(null);
		const openSig = h.opener.sendTxSignatures(
			h.opener.getFullState().fundingTxid!,
			h.opener.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		const openTxSigs = findPayload(openSig, MessageType.TX_SIGNATURES)!;
		expect(openTxSigs, 'the opener released its tx_signatures').to.not.equal(
			null
		);
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.opener.getFullState().v2InFlight!.fullySigned).to.be.true;
		return openTxSigs;
	}

	it('replays tx_signatures for a fully signed side whose final message was lost', () => {
		const h = driveToCommitmentExchange();
		const openTxSigs = driveToFullySignedWithLostFinal(h);

		h.opener.markForReestablish();
		h.acceptor.markForReestablish();

		// The acceptor lacks our tx_signatures, so it still announces; the
		// fully signed opener does not (BOLT 2: MUST omit once received).
		const acMsg = reestablishOf(h.acceptor.createReestablish());
		expect(acMsg.nextFundingTxid).to.not.be.oneOf([null, undefined]);
		const opMsg = reestablishOf(h.opener.createReestablish());
		expect(opMsg.nextFundingTxid ?? undefined).to.equal(undefined);

		// The opener answers with a byte-identical replay, never tx_abort:
		// this is the regression the state-scoped routing used to hit (the
		// splice handler answered the open's txid with tx_abort).
		const opHandle = h.opener.handleReestablish(acMsg);
		expect(findError(opHandle)).to.equal(null);
		expect(
			findPayload(opHandle, MessageType.TX_ABORT),
			'no tx_abort for an open we are fully signed on'
		).to.equal(null);
		const replayed = findPayload(opHandle, MessageType.TX_SIGNATURES);
		expect(replayed, 'the recorded witnesses replay').to.not.equal(null);
		expect(replayed!.equals(openTxSigs)).to.be.true;

		// The acceptor sees the opener's reestablish without next_funding:
		// with its own tx_signatures already released, omission is expected
		// and nothing unwinds.
		const acHandle = h.acceptor.handleReestablish(opMsg);
		expect(findPayload(acHandle, MessageType.TX_ABORT)).to.equal(null);
		expect(h.acceptor.getState()).to.not.equal(ChannelState.ERRORED);

		expect(
			findError(
				h.acceptor.handleTxSignatures(decodeTxSignaturesMessage(replayed!))
			)
		).to.equal(null);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('records a confirmation arriving while disconnected and flushes it on reestablish', () => {
		const h = driveToCommitmentExchange();
		driveToFullySignedWithLostFinal(h);
		h.opener.markForReestablish();
		h.acceptor.markForReestablish();

		// The chain watcher fires while the channel is AWAITING_REESTABLISH:
		// the one-shot confirmation must land on the durable record instead
		// of evaporating against the state gate.
		const confirmActions = h.opener.fundingConfirmed();
		expect(findPayload(confirmActions, MessageType.CHANNEL_READY)).to.equal(
			null
		);
		expect(
			confirmActions.some((a) => a.type === ChannelActionType.PERSIST_STATE),
			'the recorded confirmation persists'
		).to.be.true;
		expect(h.opener.getFullState().v2InFlight!.confirmed).to.be.true;

		// The next reestablish flushes channel_ready beside the replay.
		const acMsg = reestablishOf(h.acceptor.createReestablish());
		const opHandle = h.opener.handleReestablish(acMsg);
		expect(findError(opHandle)).to.equal(null);
		expect(
			findPayload(opHandle, MessageType.CHANNEL_READY),
			'the parked confirmation flushes as channel_ready'
		).to.not.equal(null);
	});

	it('flushes a confirmation that arrived mid-exchange when the exchange completes', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// Confirmed while the signature exchange is still incomplete.
		const confirmActions = h.opener.fundingConfirmed();
		expect(findPayload(confirmActions, MessageType.CHANNEL_READY)).to.equal(
			null
		);
		expect(h.opener.getFullState().v2InFlight!.confirmed).to.be.true;

		const accSig = h.acceptor.sendTxSignatures(
			h.acceptor.getFullState().fundingTxid!,
			h.acceptor.getFullState().fundingOutputIndex,
			h.acceptorWitness()
		);
		const accTxSigs = findPayload(accSig, MessageType.TX_SIGNATURES)!;
		expect(
			findError(
				h.opener.handleTxSignatures(decodeTxSignaturesMessage(accTxSigs))
			)
		).to.equal(null);
		const openSig = h.opener.sendTxSignatures(
			h.opener.getFullState().fundingTxid!,
			h.opener.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		expect(
			findPayload(openSig, MessageType.CHANNEL_READY),
			'the exchange completion flushes the parked confirmation'
		).to.not.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
	});

	it('rolls a provisionally accepted RBF back to the previous attempt on restore; committed residue is still removed', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const attempt0Txid = Buffer.from(
			h.acceptor.getFullState().v2InFlight!.fundingTxid
		);
		const rbfHandle = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findPayload(rbfHandle, MessageType.TX_ACK_RBF)).to.not.equal(null);
		expect(h.acceptor.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);

		// The shape a crash right after the accepted RBF persists: a
		// DUAL_FUNDING_V2 row WITH the retained rollback record (the
		// renegotiated session itself never serializes).
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.acceptor.getFullState()))
		);
		const restored = deserializeChannelState(json);
		expect(restored.v2InFlight).to.not.be.oneOf([null, undefined]);

		// The live-disconnect half: the rollback branch restores the
		// previous attempt (builder-less, restart-equivalent) and keeps the
		// channel for reestablish.
		const revived = new Channel(restored, h.acceptorSigner);
		revived.restoreV2InFlight();
		revived.markForReestablish();
		expect(revived.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(
			revived.getFullState().v2InFlight!.fundingTxid.equals(attempt0Txid),
			'the previous attempt is what survives'
		).to.be.true;

		// The restart half: the row rolls back and restores as a resumable
		// channel instead of being deleted.
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const idHex = h.acceptor.getChannelId()!.toString('hex');
		storage.saveChannel(idHex, deserializeChannelState(json), '02'.repeat(33));
		storage.saveChannelKeyIndex(idHex, 7);
		const node = new LightningNode(
			makeNodeConfig(26, { storage, recovery: { enabled: true } })
		);
		node.on('node:error', () => {});
		const rolled = node.getChannelManager().listChannels();
		expect(rolled).to.have.length(1);
		expect(rolled[0].getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(
			rolled[0].getFullState().v2InFlight!.fundingTxid.equals(attempt0Txid)
		).to.be.true;
		expect(storage.loadAllChannels(), 'the row survives').to.have.length(1);
		node.destroy();

		// The INITIATOR-side crash shape: the ack committed the replacement,
		// so the row is DUAL_FUNDING_V2 with NO record. Nothing is resumable
		// in it; the node removes it durably and restores no channel.
		const residueJson = JSON.parse(JSON.stringify(json));
		residueJson.v2InFlight = null;
		const residue = deserializeChannelState(residueJson);
		expect(residue.v2InFlight ?? null).to.equal(null);
		const revivedResidue = new Channel(residue, h.acceptorSigner);
		revivedResidue.restoreV2InFlight();
		revivedResidue.markForReestablish();
		expect(revivedResidue.getState()).to.equal(ChannelState.ERRORED);

		const residueStorage = new SqliteStorage(':memory:');
		residueStorage.open();
		residueStorage.saveChannel(
			idHex,
			deserializeChannelState(residueJson),
			'02'.repeat(33)
		);
		// The residue held per-channel key index 7. Removing the row must not
		// forget the index, or the next channel would reuse funding keys and
		// the per-commitment seed of a channel that once existed.
		residueStorage.saveChannelKeyIndex(idHex, 7);
		const residueNode = new LightningNode(
			makeNodeConfig(26, {
				storage: residueStorage,
				recovery: { enabled: true }
			})
		);
		residueNode.on('node:error', () => {});
		expect(residueNode.getChannelManager().listChannels()).to.have.length(0);
		expect(residueStorage.loadAllChannels()).to.have.length(0);
		expect(
			managerOf(residueNode).nextChannelIndex,
			'the key index advanced past the removed residue'
		).to.be.at.least(8);
		residueNode.destroy();
	});

	it('isAbandonedV2Open covers only dead unfunded opens; a recorded abort waits for its echo', () => {
		// Aborting a RECORDED attempt tears nothing down until the peer's
		// echo confirms it heard: the peer holds our commitment_signed, so a
		// lost abort must leave the attempt resumable.
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const abortActions = h.opener.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);
		expect(findPayload(abortActions, MessageType.TX_ABORT)).to.not.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(h.opener.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);
		expect(h.opener.isAbandonedV2Open()).to.be.false;

		// The echo lands: both sides agreed, the teardown runs durably and
		// the channel becomes removable everywhere.
		const echoActions = h.opener.handleTxAbort();
		expect(
			echoActions.some((a) => a.type === ChannelActionType.PERSIST_STATE),
			'the teardown persists'
		).to.be.true;
		expect(h.opener.getState()).to.equal(ChannelState.ERRORED);
		expect(h.opener.isAbandonedV2Open()).to.be.true;

		// A fully signed open is NOT abandoned even when it errors: the
		// funding tx is staged for (re)broadcast and the peer holds it too.
		// It cannot be aborted either; the broadcast is owed.
		const g = driveToCommitmentExchange();
		deliverCommitments(g);
		completeExchange(g);
		expect(findError(g.opener.abortDualFunding('too late'))).to.contain(
			'after tx_signatures'
		);
		g.opener.getFullState().state = ChannelState.ERRORED;
		expect(g.opener.isAbandonedV2Open()).to.be.false;
	});

	it('verifies peer tx_signatures against their negotiated prevouts', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const cid = h.opener.getChannelId()!;
		const txid = Buffer.from(h.opener.getFullState().v2InFlight!.fundingTxid);
		const genuine = h.acceptorWitness();

		// Wrong stack count (the peer owns exactly one P2WPKH input).
		let actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [genuine[0], genuine[0]]
		});
		expect(findError(actions)).to.contain('witness stacks');

		// An empty stack cannot spend a segwit input.
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[]]
		});
		expect(findError(actions)).to.contain('empty witness stack');

		// The zero-filled placeholder the old shape check let through is not
		// a P2WPKH spend at all.
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[Buffer.alloc(72)]]
		});
		expect(findError(actions)).to.contain('P2WPKH witness');

		// A zero-filled element beside the right pubkey is not DER.
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[Buffer.alloc(72), genuine[0][1]]]
		});
		expect(findError(actions)).to.contain('valid DER');

		// A genuine signature re-encoded with a non-ALL sighash byte.
		const decoded = bitcoin.script.signature.decode(genuine[0][0]);
		const nonAll = bitcoin.script.signature.encode(decoded.signature, 0x83);
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[nonAll, genuine[0][1]]]
		});
		expect(findError(actions)).to.contain('not SIGHASH_ALL');

		// A pubkey that does not hash to the prevout program.
		const alienPub = Buffer.concat([
			Buffer.from([0x02]),
			crypto.randomBytes(32)
		]);
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[genuine[0][0], alienPub]]
		});
		expect(findError(actions)).to.contain('does not match the prevout program');

		// A genuine-shaped signature that does not verify (one flipped byte in
		// the r value): binding alone is not enough, the crypto must hold.
		const corrupted = Buffer.from(genuine[0][0]);
		corrupted[10] ^= 0x01;
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[corrupted, genuine[0][1]]]
		});
		expect(findError(actions)).to.contain('does not verify');

		// None of the refusals recorded anything: the peer can retransmit.
		expect(h.opener.getFullState().v2InFlight!.receivedTxSignatures).to.be
			.false;

		// The genuine spend of the negotiated prevout is accepted.
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: genuine
		});
		expect(findError(actions)).to.equal(null);
	});

	it('refuses high-S signatures and contains malformed program points', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const cid = h.opener.getChannelId()!;
		const txid = Buffer.from(h.opener.getFullState().v2InFlight!.fundingTxid);
		const genuine = h.acceptorWitness();

		// The genuine signature with s replaced by n - s: identical validity
		// under lax rules, refused under strict (BIP 62 low-S) verification.
		const N = BigInt(
			'0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
		);
		const decoded = bitcoin.script.signature.decode(genuine[0][0]);
		const r = decoded.signature.subarray(0, 32);
		const sVal = BigInt('0x' + decoded.signature.subarray(32).toString('hex'));
		const highS = Buffer.from((N - sVal).toString(16).padStart(64, '0'), 'hex');
		const highSig = bitcoin.script.signature.encode(
			Buffer.concat([r, highS]),
			bitcoin.Transaction.SIGHASH_ALL
		);
		let actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[highSig, genuine[0][1]]]
		});
		expect(findError(actions)).to.contain('does not verify');

		// A prevout program built from an off-curve point: the verifier throw
		// is contained and the negotiation fails, instead of the exception
		// escaping the validator.
		let badPub: Buffer;
		do {
			badPub = Buffer.concat([Buffer.from([0x02]), crypto.randomBytes(32)]);
		} while (ecc.isPoint(badPub));
		const badScript = bitcoin.payments.p2wpkh({
			hash: bitcoin.crypto.hash160(badPub)
		}).output!;
		const badPrevTx = new bitcoin.Transaction();
		badPrevTx.version = 2;
		badPrevTx.addInput(crypto.randomBytes(32), 0);
		badPrevTx.addOutput(badScript, 60_000);
		const badPrev: IRealPrevOut = {
			prevTx: badPrevTx.toBuffer(),
			script: badScript,
			pub: badPub,
			sign: () => []
		};
		const g = driveToCommitmentExchange({ acceptorPrev: badPrev });
		deliverCommitments(g);
		actions = g.opener.handleTxSignatures({
			channelId: g.opener.getChannelId()!,
			txid: Buffer.from(g.opener.getFullState().v2InFlight!.fundingTxid),
			witnesses: [[genuine[0][0], badPub]]
		});
		expect(findError(actions)).to.contain('does not verify');
		expect(g.opener.getFullState().v2InFlight!.receivedTxSignatures).to.be
			.false;
	});

	it('refuses P2WSH funding inputs at negotiation and tells the peer via tx_abort', () => {
		const sharedTempId = crypto.randomBytes(32);
		const openerFundingPriv = crypto.randomBytes(32);
		const acceptorFundingPriv = crypto.randomBytes(32);
		const openerSeed = crypto.randomBytes(32);
		const acceptorSeed = crypto.randomBytes(32);
		const openerState = createOpenerState({
			temporaryChannelId: sharedTempId,
			fundingSatoshis: OPENER_FUNDING,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(
				getPublicKey(openerFundingPriv),
				openerSeed
			),
			localPerCommitmentSeed: openerSeed
		});
		const opener = new Channel(
			openerState,
			new ChannelSigner(openerFundingPriv)
		);
		const acceptorState = createAcceptorState({
			temporaryChannelId: sharedTempId,
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(
				getPublicKey(acceptorFundingPriv),
				acceptorSeed
			),
			localPerCommitmentSeed: acceptorSeed,
			remoteBasepoints: makeBasepoints(
				getPublicKey(crypto.randomBytes(32)),
				crypto.randomBytes(32)
			),
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		});
		const acceptor = new Channel(
			acceptorState,
			new ChannelSigner(acceptorFundingPriv)
		);
		const mkParams = (
			fundingSatoshis: bigint,
			state: typeof openerState,
			seed: Buffer
		): IDualFundingParams => ({
			fundingSatoshis,
			fundingFeeratePerkw: 1000,
			commitmentFeeratePerkw: DEFAULT_CHANNEL_CONFIG.feeratePerKw,
			dustLimitSatoshis: DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: DEFAULT_CHANNEL_CONFIG.maxHtlcValueInFlightMsat,
			htlcMinimumMsat: DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat,
			toSelfDelay: DEFAULT_CHANNEL_CONFIG.toSelfDelay,
			maxAcceptedHtlcs: DEFAULT_CHANNEL_CONFIG.maxAcceptedHtlcs,
			locktime: 0,
			localBasepoints: state.localBasepoints,
			localPerCommitmentSeed: state.localPerCommitmentSeed,
			secondPerCommitmentPoint: getPerCommitmentPoint(seed, 1n)
		});
		const openMsg = decodeOpenChannel2Message(
			findPayload(
				opener.initiateOpenV2(
					mkParams(OPENER_FUNDING, openerState, openerSeed)
				),
				MessageType.OPEN_CHANNEL2
			)!
		);
		acceptorState.temporaryChannelId = Buffer.from(openMsg.channelId);
		const acceptMsg = decodeAcceptChannel2Message(
			findPayload(
				acceptor.handleOpenChannel2(
					openMsg,
					mkParams(ACCEPTOR_FUNDING, acceptorState, acceptorSeed)
				),
				MessageType.ACCEPT_CHANNEL2
			)!
		);
		opener.handleAcceptChannel2(acceptMsg);

		const openerPrev = makeRealPrevOut(120_000);
		const p2wshScript = Buffer.concat([
			Buffer.from([0x00, 0x20]),
			crypto.randomBytes(32)
		]);
		const p2wshPrevTx = new bitcoin.Transaction();
		p2wshPrevTx.version = 2;
		p2wshPrevTx.addInput(crypto.randomBytes(32), 0);
		p2wshPrevTx.addOutput(p2wshScript, 60_000);

		const oIn = opener.addTxInput(makeInput(0n, openerPrev.prevTx));
		acceptor.handleTxAddInput(
			decodeTxAddInputMessage(findPayload(oIn, MessageType.TX_ADD_INPUT)!)
		);
		const aIn = acceptor.addTxInput(makeInput(1n, p2wshPrevTx.toBuffer()));
		opener.handleTxAddInput(
			decodeTxAddInputMessage(findPayload(aIn, MessageType.TX_ADD_INPUT)!)
		);
		const funding = createFundingScript(
			getPublicKey(openerFundingPriv),
			getPublicKey(acceptorFundingPriv)
		);
		const oOut = opener.addTxOutput({
			serialId: 2n,
			amountSats: TOTAL_FUNDING,
			scriptPubkey: funding.p2wshOutput
		});
		acceptor.handleTxAddOutput(
			decodeTxAddOutputMessage(findPayload(oOut, MessageType.TX_ADD_OUTPUT)!)
		);
		acceptor.sendTxComplete();
		opener.handleTxComplete();

		// Both sides complete at the opener's tx_complete: the audit refuses
		// the P2WSH input BEFORE the commitment round, and the refusal goes
		// to the PEER as tx_abort rather than dying as a local error the peer
		// would wait out forever.
		const completing = opener.sendTxComplete();
		expect(findError(completing)).to.contain('unsupported output type');
		const abortPayload = findPayload(completing, MessageType.TX_ABORT);
		expect(abortPayload, 'the peer is told to forget the open').to.not.equal(
			null
		);
		expect(opener.getState()).to.equal(ChannelState.ERRORED);
		expect(
			findPayload(completing, MessageType.COMMITMENT_SIGNED),
			'nothing was signed for the refused negotiation'
		).to.equal(null);

		// The peer processes the abort and converges with its echo.
		void decodeTxAbortMessage(abortPayload!);
		const acAborted = acceptor.handleTxAbort();
		expect(acceptor.getState()).to.equal(ChannelState.ERRORED);
		expect(
			findPayload(acAborted, MessageType.TX_ABORT),
			'the acceptor acks with its echo'
		).to.not.equal(null);
	});

	it('verifies P2TR peer inputs: explicit SIGHASH_ALL key-spend only', () => {
		const h = driveToCommitmentExchange({
			acceptorPrev: makeRealP2trPrevOut(60_000)
		});
		deliverCommitments(h);
		const cid = h.opener.getChannelId()!;
		const txid = Buffer.from(h.opener.getFullState().v2InFlight!.fundingTxid);
		const genuine = h.acceptorWitness();

		// The 64-byte SIGHASH_DEFAULT shorthand is refused: BOLT 2 names
		// SIGHASH_ALL, which only the explicit 65-byte form carries.
		let actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[genuine[0][0].subarray(0, 64)]]
		});
		expect(findError(actions)).to.contain('explicit SIGHASH_ALL');

		// A 65-byte signature with a non-ALL type byte is refused.
		const wrongType = Buffer.from(genuine[0][0]);
		wrongType[64] = 0x02;
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[wrongType]]
		});
		expect(findError(actions)).to.contain('explicit SIGHASH_ALL');

		// A well-formed signature that does not verify against the output key.
		const corrupted = Buffer.from(genuine[0][0]);
		corrupted[10] ^= 0x01;
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[corrupted]]
		});
		expect(findError(actions)).to.contain('does not verify');

		// Script-path spends fail closed: the leaf semantics cannot be
		// verified generically, so no multi-element stack is accepted.
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[Buffer.alloc(70), crypto.randomBytes(33)]]
		});
		expect(findError(actions)).to.contain(
			'script-path spends are not supported'
		);

		// The genuine explicit-ALL key-spend verifies and is accepted.
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: genuine
		});
		expect(findError(actions)).to.equal(null);
	});

	it('ignores tx_signatures once either side sent channel_ready', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		// Capture the acceptor's valid tx_signatures for the later replay.
		const accSig = h.acceptor.sendTxSignatures(
			h.acceptor.getFullState().fundingTxid!,
			h.acceptor.getFullState().fundingOutputIndex,
			h.acceptorWitness()
		);
		const accTxSigs = decodeTxSignaturesMessage(
			findPayload(accSig, MessageType.TX_SIGNATURES)!
		);
		expect(findError(h.opener.handleTxSignatures(accTxSigs))).to.equal(null);
		const openSig = h.opener.sendTxSignatures(
			h.opener.getFullState().fundingTxid!,
			h.opener.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		expect(
			findError(
				h.acceptor.handleTxSignatures(
					decodeTxSignaturesMessage(
						findPayload(openSig, MessageType.TX_SIGNATURES)!
					)
				)
			)
		).to.equal(null);

		// channel_ready both ways: NORMAL, record cleared, session lives on.
		const opReady = decodeChannelReadyMessage(
			findPayload(h.opener.fundingConfirmed(), MessageType.CHANNEL_READY)!
		);
		const acReady = decodeChannelReadyMessage(
			findPayload(h.acceptor.fundingConfirmed(), MessageType.CHANNEL_READY)!
		);
		h.opener.handleChannelReady(acReady);
		h.acceptor.handleChannelReady(opReady);
		expect(h.opener.getState()).to.equal(ChannelState.NORMAL);
		expect(h.opener.getFullState().v2InFlight ?? null).to.equal(null);
		expect(h.opener.getFullState().dualFundingSession).to.not.equal(null);

		// Replaying the original valid tx_signatures must be ignored: BOLT 2
		// ends the opening exchange at channel_ready, and without the gate
		// the replay recreated the record and pulled the channel back to
		// AWAITING_FUNDING_CONFIRMED.
		const replay = h.opener.handleTxSignatures(accTxSigs);
		expect(replay).to.deep.equal([]);
		expect(h.opener.getState()).to.equal(ChannelState.NORMAL);
		expect(h.opener.getFullState().v2InFlight ?? null).to.equal(null);
	});

	it('answers an alien next_funding_txid from a fully signed side with tx_abort, not failure', () => {
		const h = driveToCommitmentExchange();
		driveToFullySignedWithLostFinal(h);
		h.opener.markForReestablish();

		// The fully signed opener did not advertise next_funding, so BOLT 2
		// reserves the hard failure for the both-advertised mismatch; an
		// unknown peer txid gets tx_abort naming THAT negotiation, and
		// nothing of the completed open unwinds.
		const alien: IChannelReestablishMessage = {
			channelId: h.opener.getChannelId()!,
			nextCommitmentNumber: 1n,
			nextRevocationNumber: 0n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: getPerCommitmentPoint(h.acceptorSeed, 0n),
			nextFundingTxid: crypto.randomBytes(32),
			nextFundingRetransmitFlags: 0
		};
		const actions = h.opener.handleReestablish(alien);
		expect(findPayload(actions, MessageType.TX_ABORT)).to.not.equal(null);
		expect(h.opener.getState()).to.not.equal(ChannelState.ERRORED);
		expect(h.opener.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);
	});

	it('flushes a parked confirmation when both reestablish messages omit next_funding', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		h.opener.markForReestablish();
		h.acceptor.markForReestablish();

		// Confirmed while disconnected, after a COMPLETE exchange: both sides
		// hold tx_signatures, so both reestablish messages correctly omit
		// next_funding and no retransmission arm will run.
		expect(
			h.opener
				.fundingConfirmed()
				.some((a) => a.type === ChannelActionType.PERSIST_STATE)
		).to.be.true;
		expect(h.opener.getFullState().v2InFlight!.confirmed).to.be.true;

		const acMsg = reestablishOf(h.acceptor.createReestablish());
		expect(acMsg.nextFundingTxid ?? undefined).to.equal(undefined);
		const opHandle = h.opener.handleReestablish(acMsg);
		expect(findError(opHandle)).to.equal(null);
		expect(
			findPayload(opHandle, MessageType.CHANNEL_READY),
			'the parked confirmation flushes with no next_funding in sight'
		).to.not.equal(null);
	});
});

// ─────────────── Node-level helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`v2-reest-seed-${id}`).digest();
}

function makeNodeBasepoints(seedId: number): {
	basepoints: IChannelBasepoints;
	fundingPrivkey: Buffer;
	htlcSecret: Buffer;
} {
	const seed = makeSeed(seedId);
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
		basepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: perCommitmentPointFromSecret(
				generateFromSeed(makeSeed(seedId + 100), MAX_INDEX)
			)
		},
		fundingPrivkey: keys[0],
		htlcSecret: keys[4]
	};
}

function makeNodeConfig(
	seedId: number,
	opts: {
		storage?: SqliteStorage;
		recovery?: INodeConfig['recovery'];
		fundingProvider?: IFundingProvider;
	} = {}
): INodeConfig {
	const seed = makeSeed(seedId);
	const { basepoints, fundingPrivkey, htlcSecret } = makeNodeBasepoints(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: basepoints,
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret: htlcSecret,
		...opts
	};
}

/** A real spendable P2WPKH UTXO with a working witness-signing closure. */
function makeWalletInput(valueSats: number): ISpliceWalletInput {
	const priv = crypto.randomBytes(32);
	const pub = getPublicKey(priv);
	const payment = bitcoin.payments.p2wpkh({ pubkey: pub });
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(payment.output!, valueSats);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output!;
	return {
		prevTx: prevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(valueSats),
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value): Buffer[] => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				scriptCode,
				Number(value),
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [
				bitcoin.script.signature.encode(
					Buffer.from(ecc.sign(sighash, priv)),
					bitcoin.Transaction.SIGHASH_ALL
				),
				pub
			];
		}
	};
}

function fundingProviderWith(input: ISpliceWalletInput): IFundingProvider {
	const changeScript = bitcoin.payments.p2wpkh({
		hash: crypto.randomBytes(20)
	}).output!;
	return {
		buildFundingTransaction: async () => {
			throw new Error('v1 funding must not run for a v2 open');
		},
		broadcastTransaction: async () => 'unused',
		selectSpliceInputs: async () => ({ inputs: [input], changeScript }),
		selectMaxDualFundingInputs: async () => ({ inputs: [input], changeScript })
	};
}

const managerOf = (node: LightningNode): ChannelManager =>
	(node as unknown as { channelManager: ChannelManager }).channelManager;

interface IWire {
	/** Queue everything instead of delivering (reestablish FIFO). */
	hold(): void;
	/** Deliver everything queued, then resume direct delivery. */
	drain(): void;
	/** Drop this message type when sent by this node (counts drops). */
	dropFrom(node: LightningNode, type: MessageType): void;
	clearDrops(): void;
	dropped(type: MessageType): number;
	sent(node: LightningNode, type: MessageType): number;
}

/**
 * An in-process wire between two nodes with drop and hold controls. Wiring is
 * per-node-object: a destroyed node stops emitting and a replacement node
 * must be wired again.
 */
function wireNodes(a: LightningNode, b: LightningNode): IWire {
	let holding = false;
	const queue: Array<() => void> = [];
	const drops = new Map<string, number>();
	const sends = new Map<string, number>();
	let dropRules: Array<{ from: LightningNode; type: MessageType }> = [];

	const attach = (from: LightningNode, to: LightningNode): void => {
		from.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey !== to.getNodeId()) return;
				const sk = `${from.getNodeId()}:${type}`;
				sends.set(sk, (sends.get(sk) ?? 0) + 1);
				if (dropRules.some((r) => r.from === from && r.type === type)) {
					drops.set(String(type), (drops.get(String(type)) ?? 0) + 1);
					return;
				}
				const deliver = (): void =>
					to.handlePeerMessage(from.getNodeId(), type, payload);
				if (holding) queue.push(deliver);
				else deliver();
			}
		);
	};
	attach(a, b);
	attach(b, a);

	return {
		hold: () => {
			holding = true;
		},
		drain: () => {
			holding = false;
			while (queue.length) queue.shift()!();
		},
		dropFrom: (node, type) => {
			dropRules.push({ from: node, type });
		},
		clearDrops: () => {
			dropRules = [];
		},
		dropped: (type) => drops.get(String(type)) ?? 0,
		sent: (node, type) => sends.get(`${node.getNodeId()}:${type}`) ?? 0
	};
}

async function settle(pred: () => boolean, ms = 3000): Promise<void> {
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		if (pred()) return;
		await new Promise((resolve) => setImmediate(resolve));
	}
}

// ─────────────── Node-level tests ───────────────

describe('Dual funding v2 reestablish, node level (issues 288/289)', function () {
	this.timeout(20_000);

	it('a live disconnect after commitment_signed reestablishes and completes (289)', async function () {
		const opener = new LightningNode(
			makeNodeConfig(21, {
				storage: (() => {
					const s = new SqliteStorage(':memory:');
					s.open();
					return s;
				})(),
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(22));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);

		// The acceptor contributes nothing, so it signs first: drop its
		// tx_signatures to strand the exchange mid-flight.
		wire.dropFrom(acceptor, MessageType.TX_SIGNATURES);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.TX_SIGNATURES) > 0);
		expect(wire.dropped(MessageType.TX_SIGNATURES)).to.be.greaterThan(0);
		expect(channel.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(channel.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);

		// The channel was promoted at the point of no return: it is resolvable
		// by its permanent id, which is what lets reestablish find it.
		const channelId = channel.getChannelId()!;
		expect(managerOf(opener).getChannel(channelId)).to.not.equal(undefined);

		// ── The disconnect that used to destroy the session (issue 289) ──
		managerOf(opener).handlePeerDisconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		expect(channel.getState(), 'the open survives the disconnect').to.equal(
			ChannelState.AWAITING_REESTABLISH
		);
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		expect(acceptorChannel, 'the acceptor kept its side too').to.not.equal(
			undefined
		);
		expect(acceptorChannel.getState()).to.equal(
			ChannelState.AWAITING_REESTABLISH
		);

		// ── Reconnect: both reestablish, the exchange resumes and completes ──
		wire.clearDrops();
		wire.hold();
		managerOf(opener).handlePeerReconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerReconnected(opener.getNodeId());
		wire.drain();

		await settle(
			() =>
				channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED &&
				acceptorChannel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(acceptorChannel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(
			channel
				.getFullState()
				.fundingTxid!.equals(acceptorChannel.getFullState().fundingTxid!)
		).to.be.true;
		// The acceptor sent tx_signatures twice: the dropped one, the resumed one.
		expect(wire.sent(acceptor, MessageType.TX_SIGNATURES)).to.be.greaterThan(1);

		opener.destroy();
		acceptor.destroy();
	});

	it('a successful RBF renegotiates to completion at the new feerate', async function () {
		const opener = new LightningNode(
			makeNodeConfig(61, {
				storage: (() => {
					const s = new SqliteStorage(':memory:');
					s.open();
					return s;
				})(),
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(62));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		// Strand the exchange inside the RBF window: the acceptor never sees
		// our commitment_signed, so neither side releases tx_signatures.
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		const attempt0Txid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);

		// The real production path: the opener requests, the peer acks, the
		// ack restarts and reprices the interactive-tx exchange, and the
		// replacement negotiates through to its own signatures.
		wire.clearDrops();
		const rbfActions = channel.initiateTxRbf(2000);
		expect(findError(rbfActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, rbfActions);

		await settle(
			() =>
				channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED &&
				acceptorChannel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(acceptorChannel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		// The replacement is a NEW funding tx priced at the accepted feerate,
		// recorded as attempt 1 on BOTH sides (the acceptor's record must not
		// carry the stale open_channel2 feerate).
		const openerRecord = channel.getFullState().v2InFlight!;
		const acceptorRecord = acceptorChannel.getFullState().v2InFlight!;
		expect(openerRecord.fundingTxid.equals(attempt0Txid)).to.be.false;
		expect(openerRecord.fundingTxid.equals(acceptorRecord.fundingTxid)).to.be
			.true;
		expect(openerRecord.fundingFeeratePerkw).to.equal(2000);
		expect(acceptorRecord.fundingFeeratePerkw).to.equal(2000);
		expect(openerRecord.rbfAttempt).to.equal(1);
		expect(acceptorRecord.rbfAttempt).to.equal(1);

		opener.destroy();
		acceptor.destroy();
	});

	it('a lost tx_ack_rbf converges: both sides resume the previous attempt', async function () {
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(63, {
				storage: (() => {
					const s = new SqliteStorage(':memory:');
					s.open();
					return s;
				})(),
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(64, {
				storage: acceptorStorage,
				recovery: { enabled: true }
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		const attempt0Txid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);

		// The opener requests; the acceptor accepts and persists the
		// provisional replacement, but its ack never arrives.
		wire.clearDrops();
		wire.dropFrom(acceptor, MessageType.TX_ACK_RBF);
		const rbfActions = channel.initiateTxRbf(2000);
		expect(findError(rbfActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, rbfActions);
		await settle(() => wire.dropped(MessageType.TX_ACK_RBF) > 0);
		expect(acceptorChannel.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		expect(
			acceptorChannel.getFullState().v2InFlight,
			'the rollback record is retained'
		).to.not.be.oneOf([null, undefined]);

		// Disconnect: the opener never saw the ack (its request died with
		// the connection); the receiver rolls back to the previous attempt.
		const voided: Buffer[] = [];
		acceptor.on('channel:voided', (e: { channelId: Buffer }) => {
			voided.push(e.channelId);
		});
		managerOf(opener).handlePeerDisconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(channel.getFullState().v2InFlight!.fundingTxid.equals(attempt0Txid))
			.to.be.true;
		const kept = managerOf(acceptor).getChannel(channelId);
		expect(kept, 'the acceptor kept its side').to.not.equal(undefined);
		expect(kept!.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(
			kept!.getFullState().v2InFlight!.fundingTxid.equals(attempt0Txid),
			'rolled back to the previous attempt'
		).to.be.true;
		expect(voided).to.have.length(0);

		// Reconnect: both sides resume and complete the PREVIOUS attempt.
		wire.clearDrops();
		wire.hold();
		managerOf(opener).handlePeerReconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerReconnected(opener.getNodeId());
		wire.drain();
		await settle(
			() =>
				channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED &&
				kept!.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(kept!.getState()).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
		expect(channel.getFullState().fundingTxid!.equals(attempt0Txid)).to.be.true;
		expect(kept!.getFullState().fundingTxid!.equals(attempt0Txid)).to.be.true;

		opener.destroy();
		acceptor.destroy();
	});

	it('a failed initiator persist at the ack rolls both sides back to the previous attempt', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(65, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(66, {
				storage: acceptorStorage,
				recovery: { enabled: true }
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const attempt0Txid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);
		wire.clearDrops();

		// The OPENER's disk refuses exactly when the ack arrives: the
		// replacement never commits on the initiating side, and the first
		// contribution of the new round is withheld behind that failed
		// persist, so the receiver never sees post-ack traffic.
		const recovery = (
			opener as unknown as {
				recovery: { commit: (...a: unknown[]) => unknown };
			}
		).recovery;
		const realCommit = recovery.commit.bind(recovery);
		let refuse = false;
		recovery.commit = (...args: unknown[]): unknown =>
			refuse
				? {
						committed: false,
						released: [],
						frameSequence: null,
						error: new Error('disk full')
				  }
				: realCommit(...args);

		const rbfActions = channel.initiateTxRbf(2000);
		expect(findError(rbfActions)).to.equal(null);
		refuse = true;
		const preAckAddInputs = wire.sent(opener, MessageType.TX_ADD_INPUT);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, rbfActions);
		await settle(() => wire.sent(acceptor, MessageType.TX_ACK_RBF) > 0);
		expect(
			wire.sent(opener, MessageType.TX_ADD_INPUT),
			'the first contribution is withheld behind the failed persist'
		).to.equal(preAckAddInputs);
		refuse = false;

		// Disconnect: the opener re-restores the previous attempt from disk
		// (its RBF persist rolled back); the receiver, having seen no
		// post-ack traffic, rolls back in memory.
		managerOf(opener).handlePeerDisconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		const openerRestored = managerOf(opener).getChannel(channelId);
		expect(
			openerRestored,
			'the opener re-restored the durable attempt'
		).to.not.equal(undefined);
		expect(openerRestored!.getState()).to.equal(
			ChannelState.AWAITING_REESTABLISH
		);
		expect(
			openerRestored!
				.getFullState()
				.v2InFlight!.fundingTxid.equals(attempt0Txid)
		).to.be.true;
		const kept = managerOf(acceptor).getChannel(channelId)!;
		expect(kept.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(kept.getFullState().v2InFlight!.fundingTxid.equals(attempt0Txid)).to
			.be.true;

		// Reconnect: the previous attempt completes on both sides.
		wire.hold();
		managerOf(opener).handlePeerReconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerReconnected(opener.getNodeId());
		wire.drain();
		await settle(
			() =>
				openerRestored!.getState() ===
					ChannelState.AWAITING_FUNDING_CONFIRMED &&
				kept.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(openerRestored!.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(kept.getState()).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
		expect(openerRestored!.getFullState().fundingTxid!.equals(attempt0Txid)).to
			.be.true;

		opener.destroy();
		acceptor.destroy();
	});

	it('voids instead of force-closing an errored v2 open whose signatures never left', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(67, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(68));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		expect(channel.getFullState().v2InFlight!.sentTxSignatures).to.be.false;

		// The diverged-RBF terminal: the peer dropped its side entirely, so
		// reestablish is answered with the manager's unknown-channel error.
		// Our witnesses never left, nobody can broadcast this funding tx,
		// and force-closing would broadcast a commitment spending an
		// outpoint that will never exist. The channel voids instead.
		managerOf(acceptor).voidChannel(channelId);
		const voided: Buffer[] = [];
		opener.on('channel:voided', (e: { channelId: Buffer }) => {
			voided.push(e.channelId);
		});
		managerOf(opener).handlePeerDisconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		wire.clearDrops();
		wire.hold();
		managerOf(opener).handlePeerReconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerReconnected(opener.getNodeId());
		wire.drain();

		await settle(() => voided.length > 0);
		expect(voided).to.have.length(1);
		expect(voided[0].equals(channelId)).to.be.true;
		expect(managerOf(opener).getChannel(channelId)).to.equal(undefined);
		expect(openerStorage.loadAllChannels()).to.have.length(0);

		opener.destroy();
		acceptor.destroy();
	});

	it('rolls a provisionally accepted RBF back to the previous attempt on a live disconnect', async function () {
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(27, {
				storage: (() => {
					const s = new SqliteStorage(':memory:');
					s.open();
					return s;
				})(),
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(28, {
				storage: acceptorStorage,
				recovery: { enabled: true }
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		// Drop the opener's commitment_signed: the acceptor crosses its own
		// point of no return (record created) but releases no tx_signatures,
		// which is the only window an RBF can still be accepted in.
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId);
		expect(acceptorChannel, 'the acceptor promoted its side').to.not.equal(
			undefined
		);
		expect(acceptorChannel!.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);

		// The opener renegotiates; the acceptor accepts, knocks back into
		// DUAL_FUNDING_V2 and RETAINS the previous attempt's record as
		// rollback state (no post-ack traffic ever arrives here: the opener
		// node never actually initiated, so the ack acknowledges nothing).
		const attempt0Txid = Buffer.from(
			acceptorChannel!.getFullState().v2InFlight!.fundingTxid
		);
		managerOf(acceptor).handleMessage(
			opener.getNodeId(),
			MessageType.TX_INIT_RBF,
			encodeTxInitRbfMessage({ channelId, locktime: 0, feerate: 2000 })
		);
		expect(acceptorChannel!.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		const provisional = acceptorStorage.loadAllChannels();
		expect(provisional).to.have.length(1);
		expect(provisional[0].state.state).to.equal(ChannelState.DUAL_FUNDING_V2);
		expect(provisional[0].state.v2InFlight).to.not.be.oneOf([null, undefined]);

		// A live disconnect before any post-ack traffic rolls the receiver
		// back to the previous attempt: the peer may never have seen the ack
		// (it did not, here), so the previous attempt is the only shared
		// truth. Nothing is removed and nothing terminal fires.
		const voided: Buffer[] = [];
		acceptor.on('channel:voided', (e: { channelId: Buffer }) => {
			voided.push(e.channelId);
		});
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		const kept = managerOf(acceptor).getChannel(channelId);
		expect(kept, 'the channel survives the disconnect').to.not.equal(undefined);
		expect(kept!.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(
			kept!.getFullState().v2InFlight!.fundingTxid.equals(attempt0Txid),
			'rolled back to the previous attempt'
		).to.be.true;
		expect(acceptorStorage.loadAllChannels()).to.have.length(1);
		expect(voided).to.have.length(0);

		opener.destroy();
		acceptor.destroy();
	});

	it('the tx_abort handshake removes a dead unfunded v2 open from both sides, durably', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(69, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(70, {
				storage: acceptorStorage,
				recovery: { enabled: true }
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		expect(managerOf(acceptor).getChannel(channelId)).to.not.equal(undefined);
		expect(openerStorage.loadAllChannels()).to.have.length(1);
		expect(acceptorStorage.loadAllChannels()).to.have.length(1);
		wire.clearDrops();

		const openerVoided: Buffer[] = [];
		opener.on('channel:voided', (e: { channelId: Buffer }) => {
			openerVoided.push(e.channelId);
		});
		const acceptorVoided: Buffer[] = [];
		acceptor.on('channel:voided', (e: { channelId: Buffer }) => {
			acceptorVoided.push(e.channelId);
		});

		// The operator aborts the stranded open. The abort reaches the peer,
		// which errors, echoes and removes itself; the echo completes the
		// handshake on the aborting side and removes it there too. Rows go
		// with the registrations on both sides.
		const abortActions = channel.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, abortActions);
		await settle(
			() =>
				managerOf(opener).getChannel(channelId) === undefined &&
				managerOf(acceptor).getChannel(channelId) === undefined
		);
		expect(managerOf(opener).getChannel(channelId)).to.equal(undefined);
		expect(managerOf(acceptor).getChannel(channelId)).to.equal(undefined);
		expect(openerStorage.loadAllChannels()).to.have.length(0);
		expect(acceptorStorage.loadAllChannels()).to.have.length(0);
		expect(openerVoided).to.have.length(1);
		expect(acceptorVoided).to.have.length(1);

		opener.destroy();
		acceptor.destroy();
	});

	it('a lost abort echo keeps the aborter alive; the diverged terminal voids it on reconnect', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(71, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(72));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		wire.clearDrops();
		// The peer heard the abort and removed its side, but its echo dies:
		// with no confirmation, the aborting side must NOT tear down (the
		// echo is the only proof the peer agreed to forget).
		wire.dropFrom(acceptor, MessageType.TX_ABORT);

		const abortActions = channel.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, abortActions);
		await settle(() => wire.dropped(MessageType.TX_ABORT) > 0);
		expect(managerOf(acceptor).getChannel(channelId)).to.equal(undefined);
		expect(managerOf(opener).getChannel(channelId)).to.not.equal(undefined);
		expect(channel.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(channel.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);

		// A disconnect keeps the recorded attempt AND its row: the un-echoed
		// abort dies with the connection.
		managerOf(opener).handlePeerDisconnected(acceptor.getNodeId());
		expect(managerOf(opener).getChannel(channelId)).to.not.equal(undefined);
		expect(openerStorage.loadAllChannels()).to.have.length(1);

		// On reconnect the peer answers reestablish with unknown-channel;
		// our signatures never left, so the diverged terminal VOIDS the
		// channel rather than force-closing into a nonexistent funding tx.
		const voided: Buffer[] = [];
		opener.on('channel:voided', (e: { channelId: Buffer }) => {
			voided.push(e.channelId);
		});
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		wire.clearDrops();
		wire.hold();
		managerOf(opener).handlePeerReconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerReconnected(opener.getNodeId());
		wire.drain();
		await settle(() => voided.length > 0);
		expect(voided).to.have.length(1);
		expect(managerOf(opener).getChannel(channelId)).to.equal(undefined);
		expect(openerStorage.loadAllChannels()).to.have.length(0);

		opener.destroy();
		acceptor.destroy();
	});

	it('a lost tx_abort keeps the recorded attempt on both sides; reconnect resumes it', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(73, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(74, {
				storage: acceptorStorage,
				recovery: { enabled: true }
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		const attempt0Txid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);
		wire.clearDrops();

		// The abort itself is lost: the peer still holds our verified
		// commitment_signed, so NOTHING may be discarded on our side.
		wire.dropFrom(opener, MessageType.TX_ABORT);
		const abortActions = channel.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, abortActions);
		await settle(() => wire.dropped(MessageType.TX_ABORT) > 0);
		expect(channel.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(managerOf(acceptor).getChannel(channelId)).to.not.equal(undefined);

		// Disconnect: both sides keep the channel AND the row (this used to
		// reap the aborting side while the peer still had everything).
		managerOf(opener).handlePeerDisconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		expect(managerOf(opener).getChannel(channelId)).to.not.equal(undefined);
		expect(openerStorage.loadAllChannels()).to.have.length(1);
		expect(acceptorStorage.loadAllChannels()).to.have.length(1);

		// Reconnect: the abort never happened; the attempt resumes and
		// completes on both sides.
		wire.clearDrops();
		wire.hold();
		managerOf(opener).handlePeerReconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerReconnected(opener.getNodeId());
		wire.drain();
		await settle(
			() =>
				channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED &&
				acceptorChannel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(acceptorChannel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(channel.getFullState().fundingTxid!.equals(attempt0Txid)).to.be
			.true;

		opener.destroy();
		acceptor.destroy();
	});

	it('a failed RBF persist keeps the previous durable attempt recoverable', async function () {
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(29, {
				storage: (() => {
					const s = new SqliteStorage(':memory:');
					s.open();
					return s;
				})(),
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(30, {
				storage: acceptorStorage,
				recovery: { enabled: true }
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		expect(acceptorChannel.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);

		// The disk refuses from here: the RBF clear never commits, so
		// tx_ack_rbf is withheld with it and the durable truth stays the
		// previous attempt.
		const recovery = (
			acceptor as unknown as {
				recovery: { commit: (...a: unknown[]) => unknown };
			}
		).recovery;
		const realCommit = recovery.commit.bind(recovery);
		let refuse = true;
		recovery.commit = (...args: unknown[]): unknown =>
			refuse
				? {
						committed: false,
						released: [],
						frameSequence: null,
						error: new Error('disk full')
				  }
				: realCommit(...args);

		managerOf(acceptor).handleMessage(
			opener.getNodeId(),
			MessageType.TX_INIT_RBF,
			encodeTxInitRbfMessage({ channelId, locktime: 0, feerate: 2000 })
		);
		expect(acceptorChannel.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		expect(
			wire.sent(acceptor, MessageType.TX_ACK_RBF),
			'tx_ack_rbf is withheld behind the failed persist'
		).to.equal(0);
		refuse = false;

		const voided: Buffer[] = [];
		acceptor.on('channel:voided', (e: { channelId: Buffer }) => {
			voided.push(e.channelId);
		});
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());

		// The peer never adopted the renegotiation: the previous attempt is
		// still the durable truth, and it is re-restored rather than deleted.
		const rows = acceptorStorage.loadAllChannels();
		expect(rows).to.have.length(1);
		expect(rows[0].state.state).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(rows[0].state.v2InFlight).to.not.be.oneOf([null, undefined]);
		const restored = managerOf(acceptor).getChannel(channelId);
		expect(restored, 'the durable attempt restored in place').to.not.equal(
			undefined
		);
		expect(restored!.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(voided, 'no terminal event for a recoverable open').to.have.length(
			0
		);

		opener.destroy();
		acceptor.destroy();
	});

	it('a two-sided disconnect after a failed RBF persist resumes the original attempt on both sides', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(31, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(32, {
				storage: acceptorStorage,
				recovery: { enabled: true }
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		// Strand the exchange mid-round so the RBF stays acceptable.
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const attemptTxid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);

		// The acceptor's disk refuses from here: its accept never commits and
		// the ack is withheld with it.
		const recovery = (
			acceptor as unknown as {
				recovery: { commit: (...a: unknown[]) => unknown };
			}
		).recovery;
		const realCommit = recovery.commit.bind(recovery);
		let refuse = true;
		recovery.commit = (...args: unknown[]): unknown =>
			refuse
				? {
						committed: false,
						released: [],
						frameSequence: null,
						error: new Error('disk full')
				  }
				: realCommit(...args);

		// The initiator REALLY initiates: with the renegotiation deferred to
		// the ack, nothing of its attempt is replaced or re-persisted.
		const openerChannel = managerOf(opener).getChannel(channelId)!;
		const initActions = openerChannel.initiateTxRbf(2000);
		const initPayload = findPayload(initActions, MessageType.TX_INIT_RBF)!;
		expect(initPayload).to.not.equal(null);
		managerOf(acceptor).handleMessage(
			opener.getNodeId(),
			MessageType.TX_INIT_RBF,
			initPayload
		);
		expect(
			wire.sent(acceptor, MessageType.TX_ACK_RBF),
			'the ack is withheld behind the failed persist'
		).to.equal(0);
		refuse = false;

		// Both sides disconnect. This was the split: the initiator used to
		// have committed DUAL_FUNDING_V2 at initiate time and lost its row,
		// while the receiver restored the old attempt and then failed as
		// unknown on reconnect.
		managerOf(opener).handlePeerDisconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		const openerRows = openerStorage.loadAllChannels();
		expect(openerRows, 'the initiator kept its attempt').to.have.length(1);
		expect(openerRows[0].state.v2InFlight).to.not.be.oneOf([null, undefined]);
		expect(acceptorStorage.loadAllChannels()).to.have.length(1);

		// Reconnect: the original attempt resumes and completes on BOTH sides.
		wire.clearDrops();
		wire.hold();
		managerOf(opener).handlePeerReconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerReconnected(opener.getNodeId());
		wire.drain();
		const openerAfter = managerOf(opener).getChannel(channelId)!;
		const acceptorAfter = managerOf(acceptor).getChannel(channelId)!;
		await settle(
			() =>
				openerAfter.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED &&
				acceptorAfter.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(openerAfter.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(acceptorAfter.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(openerAfter.getFullState().fundingTxid!.equals(attemptTxid)).to.be
			.true;
		expect(acceptorAfter.getFullState().fundingTxid!.equals(attemptTxid)).to.be
			.true;

		opener.destroy();
		acceptor.destroy();
	});

	it('contains storage read failures during the abandonment decision', async function () {
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(33, {
				storage: (() => {
					const s = new SqliteStorage(':memory:');
					s.open();
					return s;
				})(),
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(34, {
				storage: acceptorStorage,
				recovery: { enabled: true }
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);
		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		managerOf(acceptor).handleMessage(
			opener.getNodeId(),
			MessageType.TX_INIT_RBF,
			encodeTxInitRbfMessage({ channelId, locktime: 0, feerate: 2000 })
		);
		expect(managerOf(acceptor).getChannel(channelId)!.getState()).to.equal(
			ChannelState.DUAL_FUNDING_V2
		);

		// The disk starts throwing exactly when the abandonment decision
		// needs it: the failure must not escape the disconnect handler, and
		// nothing durable may be touched blind.
		const storageAny = acceptorStorage as unknown as {
			loadChannel: (id: string) => unknown;
		};
		const realLoad = storageAny.loadChannel.bind(acceptorStorage);
		storageAny.loadChannel = () => {
			throw new Error('io error');
		};
		expect(() =>
			managerOf(acceptor).handlePeerDisconnected(opener.getNodeId())
		).to.not.throw();
		storageAny.loadChannel = realLoad;
		expect(
			acceptorStorage.loadAllChannels(),
			'the row survives for a restart to re-evaluate'
		).to.have.length(1);

		opener.destroy();
		acceptor.destroy();
	});

	it('a restart resumes the exchange from the durable record to a completed open (288)', async function () {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v2-reest-'));
		const dbPath = path.join(dir, 'opener.db');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();

		const opener1 = new LightningNode(
			makeNodeConfig(23, {
				storage: storage1,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(24));
		opener1.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire1 = wireNodes(opener1, acceptor);
		wire1.dropFrom(acceptor, MessageType.TX_SIGNATURES);

		const channel1 = opener1.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => wire1.dropped(MessageType.TX_SIGNATURES) > 0);
		expect(channel1.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		const channelId = channel1.getChannelId()!;
		const fundingTxid = Buffer.from(channel1.getFullState().fundingTxid!);

		// ── The process dies. The acceptor sees only a disconnect. ──
		opener1.destroy();
		managerOf(acceptor).handlePeerDisconnected(opener1.getNodeId());

		// ── A new process restores from the durable record alone: no funding
		//    provider, no wallet closures, only what the row carries. ──
		const storage2 = new SqliteStorage(dbPath);
		storage2.open();
		const opener2 = new LightningNode(
			makeNodeConfig(23, { storage: storage2, recovery: { enabled: true } })
		);
		opener2.on('node:error', () => {});
		const restored = managerOf(opener2).getChannel(channelId);
		expect(restored, 'the row restored under its permanent id').to.not.equal(
			undefined
		);
		expect(restored!.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(
			restored!.getFullState().dualFundingSession,
			'a builder-less session was rebuilt from the record'
		).to.not.equal(null);

		const wire2 = wireNodes(opener2, acceptor);
		wire2.hold();
		managerOf(opener2).handlePeerReconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerReconnected(opener2.getNodeId());
		wire2.drain();

		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		await settle(
			() =>
				restored!.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED &&
				acceptorChannel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(restored!.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(acceptorChannel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(restored!.getFullState().fundingTxid!.equals(fundingTxid)).to.be
			.true;

		// The restored side holds the fully signed funding tx for rebroadcast.
		const record = restored!.getFullState().v2InFlight!;
		expect(record.fullySigned).to.be.true;
		const pending = restored!.getFullState().pendingFundingTxHex;
		expect(pending).to.not.be.oneOf([null, undefined]);
		expect(
			Buffer.from(bitcoin.Transaction.fromHex(pending!).getHash()).equals(
				fundingTxid
			)
		).to.be.true;

		opener2.destroy();
		acceptor.destroy();
		fs.rmSync(dir, { recursive: true, force: true });
	});
});
