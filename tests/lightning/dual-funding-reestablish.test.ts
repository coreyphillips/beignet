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
	createAcceptorState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	MAX_DUST_LIMIT_SATOSHIS
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
	decodeTxAckRbfMessage,
	encodeTxInitRbfMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { decodeChannelReadyMessage } from '../../src/lightning/message/channel-funding';
import { IUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
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
import { ILeaseRates } from '../../src/lightning/gossip/types';
import { reconstructFromFrames } from '../../src/lightning/recovery';

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

/**
 * A real P2TR key-path prevout (raw x-only key program, BIP 341 spend).
 * 'all' signs the explicit 65-byte SIGHASH_ALL form; 'default' signs the
 * 64-byte SIGHASH_DEFAULT shorthand (a different BIP 341 message: the hash
 * type byte is part of the preimage).
 */
function makeRealP2trPrevOut(
	valueSats: number,
	sighash: 'all' | 'default' = 'all'
): IRealPrevOut {
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
			const hashType =
				sighash === 'default'
					? bitcoin.Transaction.SIGHASH_DEFAULT
					: bitcoin.Transaction.SIGHASH_ALL;
			const msg = tx.hashForWitnessV1(
				index,
				prevouts.scripts,
				prevouts.values.map((v) => Number(v)),
				hashType
			);
			const rawSig = Buffer.from(ecc.signSchnorr(msg, priv));
			return [
				sighash === 'default'
					? rawSig
					: Buffer.concat([rawSig, Buffer.from([hashType])])
			];
		}
	};
}

interface IHarness {
	opener: Channel;
	acceptor: Channel;
	openerSigner: ChannelSigner;
	acceptorSigner: ChannelSigner;
	/** The acceptor's raw funding key, for manager-level signer rebuilds. */
	acceptorFundingPriv: Buffer;
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
 * input; the acceptor (lower input sats) signs tx_signatures first. With
 * acceptorNoInput the acceptor contributes nothing (no sats, no inputs), so
 * its side of the attempt is broadcastable the moment its commitment_signed
 * leaves.
 *
 * openerDust / acceptorDust raise one side's dust_limit_satoshis, both on the
 * wire and in its own config (production keeps the two in step: the advertised
 * value and localConfig both come from the node's channelConfig). Commitment #0
 * carries no HTLCs and both outputs sit far above any value used here, so
 * nothing trims and the real signature exchange still completes.
 */
function driveToCommitmentExchange(
	opts: {
		acceptorPrev?: IRealPrevOut;
		acceptorNoInput?: boolean;
		openerDust?: bigint;
		acceptorDust?: bigint;
	} = {}
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

	if (opts.openerDust !== undefined) {
		openerState.localConfig.dustLimitSatoshis = opts.openerDust;
	}
	if (opts.acceptorDust !== undefined) {
		acceptorState.localConfig.dustLimitSatoshis = opts.acceptorDust;
	}

	const mkParams = (
		fundingSatoshis: bigint,
		state: typeof openerState,
		seed: Buffer
	): IDualFundingParams => ({
		fundingSatoshis,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: DEFAULT_CHANNEL_CONFIG.feeratePerKw,
		dustLimitSatoshis: state.localConfig.dustLimitSatoshis,
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

	const acceptorFunding = opts.acceptorNoInput ? 0n : ACCEPTOR_FUNDING;
	const acceptActions = acceptor.handleOpenChannel2(
		openMsg,
		mkParams(acceptorFunding, acceptorState, acceptorSeed)
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
		amountSats: OPENER_FUNDING + acceptorFunding,
		scriptPubkey: funding.p2wshOutput
	};

	const oInAct = opener.addTxInput(openerInput);
	expect(findError(oInAct)).to.equal(null);
	acceptor.handleTxAddInput(
		decodeTxAddInputMessage(findPayload(oInAct, MessageType.TX_ADD_INPUT)!)
	);
	if (!opts.acceptorNoInput) {
		const aInAct = acceptor.addTxInput(acceptorInput);
		expect(findError(aInAct)).to.equal(null);
		opener.handleTxAddInput(
			decodeTxAddInputMessage(findPayload(aInAct, MessageType.TX_ADD_INPUT)!)
		);
	}
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
		acceptorFundingPriv,
		openerSeed,
		acceptorSeed,
		openerCommit,
		acceptorCommit,
		openerPrev,
		acceptorPrev,
		openerWitness: () => witnessFor(opener, openerPrev, 0),
		acceptorWitness: () =>
			opts.acceptorNoInput ? [] : witnessFor(acceptor, acceptorPrev, 1)
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

	it('surfaces the owed caller-driven release after a restart and completes once re-driven (307)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// Restart the ACCEPTOR: it signs first, so its release is due the
		// moment reestablish completes, while its witnesses (caller-driven,
		// held only in memory) died with the process.
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.acceptor.getFullState()))
		);
		const revived = new Channel(
			deserializeChannelState(json),
			h.acceptorSigner
		);
		revived.restoreV2InFlight();
		revived.markForReestablish();
		h.opener.markForReestablish();

		const revMsg = reestablishOf(revived.createReestablish());
		const opMsg = reestablishOf(h.opener.createReestablish());
		const opReestActions = h.opener.handleReestablish(revMsg);
		expect(findError(opReestActions)).to.equal(null);
		// The opener signs second and the peer's signatures are not in yet:
		// nothing is owed from its caller at this point.
		expect(
			opReestActions.some(
				(a) => a.type === ChannelActionType.TX_SIGNATURES_NEEDED
			)
		).to.equal(false);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const revActions: any[] = revived.handleReestablish(opMsg);
		expect(findError(revActions)).to.equal(null);
		const record = revived.getFullState().v2InFlight!;
		const needed = revActions.filter(
			(a) => a.type === ChannelActionType.TX_SIGNATURES_NEEDED
		);
		expect(needed.length, 'the resume surfaces the owed release').to.equal(1);
		expect(needed[0].channelId.equals(revived.getChannelId()!)).to.equal(true);
		expect(needed[0].fundingTxid.equals(record.fundingTxid)).to.equal(true);
		expect(needed[0].fundingOutputIndex).to.equal(record.fundingOutputIndex);
		expect(needed[0].inputIndices).to.deep.equal([1]);

		// One-shot per connection cycle: a second flush does not re-signal...
		expect(
			revived
				.handleReestablish(opMsg)
				.some((a) => a.type === ChannelActionType.TX_SIGNATURES_NEEDED)
		).to.equal(false);
		// ...but the NEXT reconnect re-arms the reminder while still owed.
		revived.markForReestablish();
		expect(
			revived
				.handleReestablish(opMsg)
				.filter((a) => a.type === ChannelActionType.TX_SIGNATURES_NEEDED).length
		).to.equal(1);

		// The embedder re-drives with witnesses over the recorded funding tx
		// and the exchange completes.
		const accSig = revived.sendTxSignatures(
			revived.getFullState().fundingTxid!,
			revived.getFullState().fundingOutputIndex,
			h.acceptorWitness()
		);
		expect(findError(accSig)).to.equal(null);
		const accTxSigs = findPayload(accSig, MessageType.TX_SIGNATURES);
		expect(accTxSigs, 'the re-driven release leaves').to.not.equal(null);

		// The LIVE opener now owes its own caller-driven witnesses: the same
		// signal fires the moment the ordering gate opens.
		const opAfterPeer = h.opener.handleTxSignatures(
			decodeTxSignaturesMessage(accTxSigs!)
		);
		expect(findError(opAfterPeer)).to.equal(null);
		expect(
			opAfterPeer.filter(
				(a) => a.type === ChannelActionType.TX_SIGNATURES_NEEDED
			).length
		).to.equal(1);
		const opSig = h.opener.sendTxSignatures(
			h.opener.getFullState().fundingTxid!,
			h.opener.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		expect(findError(opSig)).to.equal(null);
		const opTxSigs = findPayload(opSig, MessageType.TX_SIGNATURES)!;
		expect(
			findError(revived.handleTxSignatures(decodeTxSignaturesMessage(opTxSigs)))
		).to.equal(null);
		expect(revived.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('a restarted second-signer surfaces the owed release when the peer signatures arrive (307)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// Restart the OPENER: it signs second, so nothing is owed at
		// reestablish; the obligation surfaces when the peer's tx_signatures
		// arrive and the ordering gate opens.
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.opener.getFullState()))
		);
		const revived = new Channel(deserializeChannelState(json), h.openerSigner);
		revived.restoreV2InFlight();
		revived.markForReestablish();
		h.acceptor.markForReestablish();

		const revMsg = reestablishOf(revived.createReestablish());
		const acMsg = reestablishOf(h.acceptor.createReestablish());
		const revReestActions = revived.handleReestablish(acMsg);
		expect(findError(revReestActions)).to.equal(null);
		expect(
			revReestActions.some(
				(a) => a.type === ChannelActionType.TX_SIGNATURES_NEEDED
			)
		).to.equal(false);
		expect(findError(h.acceptor.handleReestablish(revMsg))).to.equal(null);

		const accSig = h.acceptor.sendTxSignatures(
			h.acceptor.getFullState().fundingTxid!,
			h.acceptor.getFullState().fundingOutputIndex,
			h.acceptorWitness()
		);
		const accTxSigs = findPayload(accSig, MessageType.TX_SIGNATURES)!;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const revAfterPeer: any[] = revived.handleTxSignatures(
			decodeTxSignaturesMessage(accTxSigs)
		);
		expect(findError(revAfterPeer)).to.equal(null);
		const needed = revAfterPeer.filter(
			(a) => a.type === ChannelActionType.TX_SIGNATURES_NEEDED
		);
		expect(needed.length, 'the owed release surfaces').to.equal(1);
		expect(needed[0].inputIndices).to.deep.equal([0]);

		const revSig = revived.sendTxSignatures(
			revived.getFullState().fundingTxid!,
			revived.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		expect(findError(revSig)).to.equal(null);
		const revTxSigs = findPayload(revSig, MessageType.TX_SIGNATURES)!;
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

	it('the manager relays channel:txsigs-needed after restore and provideTxSignatures completes the exchange (307)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// Restart the acceptor INTO a ChannelManager, through the real restore
		// path (signer rebuilt from the manager config, restoreV2InFlight and
		// markForReestablish inside restoreChannel).
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.acceptor.getFullState()))
		);
		const revived = new Channel(deserializeChannelState(json));
		const mgr = new ChannelManager({
			localBasepoints: makeBasepoints(
				getPublicKey(crypto.randomBytes(32)),
				crypto.randomBytes(32)
			),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: h.acceptorFundingPriv
		});
		mgr.on('error', () => {});
		const peerHex = getPublicKey(crypto.randomBytes(32)).toString('hex');
		mgr.restoreChannel(revived, peerHex);
		expect(revived.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

		const outbound: Array<{ type: number; payload: Buffer }> = [];
		mgr.on('message:outbound', (_p: string, type: number, payload: Buffer) => {
			outbound.push({ type, payload });
		});
		const events: Array<{
			channelId: Buffer;
			fundingTxid: Buffer;
			fundingOutputIndex: number;
			inputIndices: number[];
		}> = [];
		let cbResult: { ok: boolean; error?: string } | null = null;
		let cbResolved: boolean | null = null;
		mgr.on(
			'channel:txsigs-needed',
			(
				channelId: Buffer,
				fundingTxid: Buffer,
				fundingOutputIndex: number,
				inputIndices: number[]
			) => {
				events.push({
					channelId,
					fundingTxid,
					fundingOutputIndex,
					inputIndices
				});
				// Restored channels live in the permanent map: resolvable.
				cbResolved = mgr.getChannel(channelId) !== undefined;
				// Answer synchronously inside the callback, through the public
				// path an embedder uses.
				cbResult = mgr.provideTxSignatures(
					channelId,
					fundingTxid,
					fundingOutputIndex,
					h.acceptorWitness()
				);
			}
		);

		h.opener.markForReestablish();
		const opReest = findPayload(
			h.opener.createReestablish(),
			MessageType.CHANNEL_REESTABLISH
		)!;
		mgr.handleMessage(peerHex, MessageType.CHANNEL_REESTABLISH, opReest);

		const record = revived.getFullState().v2InFlight!;
		expect(events.length, 'the manager relayed the reminder').to.equal(1);
		expect(events[0].channelId.equals(revived.getChannelId()!)).to.equal(true);
		expect(events[0].fundingTxid.equals(record.fundingTxid)).to.equal(true);
		expect(events[0].fundingOutputIndex).to.equal(record.fundingOutputIndex);
		expect(events[0].inputIndices).to.deep.equal([1]);
		expect(cbResolved, 'getChannel resolves a restored channel').to.equal(true);
		expect(cbResult!.ok, cbResult!.error ?? '').to.equal(true);
		const sigsOut = outbound.find((m) => m.type === MessageType.TX_SIGNATURES);
		expect(
			sigsOut,
			'the re-driven tx_signatures left the manager'
		).to.not.be.oneOf([null, undefined]);

		// The live opener completes the exchange.
		expect(
			findError(
				h.opener.handleTxSignatures(decodeTxSignaturesMessage(sigsOut!.payload))
			)
		).to.equal(null);
		const opSig = h.opener.sendTxSignatures(
			h.opener.getFullState().fundingTxid!,
			h.opener.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		expect(findError(opSig)).to.equal(null);
		const opTxSigs = findPayload(opSig, MessageType.TX_SIGNATURES)!;
		mgr.handleMessage(peerHex, MessageType.TX_SIGNATURES, opTxSigs);
		expect(revived.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('provideTxSignatures resolves a temp-resident channel inside the pre-promotion callback (307)', () => {
		const h = driveToCommitmentExchange();
		// Both commitments crossed on the opener side only; the acceptor's
		// arrives THROUGH the manager below, with the acceptor still living in
		// the temporary map exactly as in the live open.
		expect(
			findError(
				h.opener.handleCommitmentSigned(
					decodeCommitmentSignedMessage(h.acceptorCommit)
				)
			)
		).to.equal(null);

		const mgr = new ChannelManager({
			localBasepoints: makeBasepoints(
				getPublicKey(crypto.randomBytes(32)),
				crypto.randomBytes(32)
			),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32)
		});
		mgr.on('error', () => {});
		const peerHex = getPublicKey(crypto.randomBytes(32)).toString('hex');
		const tempIdHex = h.acceptor.getTemporaryChannelId().toString('hex');
		(mgr as unknown as { tempChannels: Map<string, Channel> }).tempChannels.set(
			tempIdHex,
			h.acceptor
		);
		(mgr as unknown as { channelPeers: Map<string, string> }).channelPeers.set(
			tempIdHex,
			peerHex
		);

		const outbound: Array<{ type: number; payload: Buffer }> = [];
		mgr.on('message:outbound', (_p: string, type: number, payload: Buffer) => {
			outbound.push({ type, payload });
		});
		let cbResult: { ok: boolean; error?: string } | null = null;
		let cbResolved: boolean | null = null;
		mgr.on('channel:txsigs-needed', (channelId: Buffer) => {
			// The live exchange emits BEFORE promotion, so the permanent id is
			// not yet resolvable through getChannel...
			cbResolved = mgr.getChannel(channelId) !== undefined;
			// ...but the public response path must still work right here.
			const record = h.acceptor.getFullState().v2InFlight!;
			cbResult = mgr.provideTxSignatures(
				channelId,
				Buffer.from(record.fundingTxid),
				record.fundingOutputIndex,
				h.acceptorWitness()
			);
		});

		mgr.handleMessage(peerHex, MessageType.COMMITMENT_SIGNED, h.openerCommit);

		expect(cbResolved, 'the event fired before promotion').to.equal(false);
		expect(cbResult, 'the reminder fired').to.not.equal(null);
		expect(cbResult!.ok, cbResult!.error ?? '').to.equal(true);
		const sigsOut = outbound.find((m) => m.type === MessageType.TX_SIGNATURES);
		expect(sigsOut, 'the release left through the manager').to.not.be.oneOf([
			null,
			undefined
		]);
		expect(
			mgr.getChannel(h.acceptor.getChannelId()!),
			'the channel was promoted by the time the handler returned'
		).to.not.equal(undefined);

		// The live opener completes the exchange.
		expect(
			findError(
				h.opener.handleTxSignatures(decodeTxSignaturesMessage(sigsOut!.payload))
			)
		).to.equal(null);
		const opSig = h.opener.sendTxSignatures(
			h.opener.getFullState().fundingTxid!,
			h.opener.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		expect(findError(opSig)).to.equal(null);
		const opTxSigs = findPayload(opSig, MessageType.TX_SIGNATURES)!;
		mgr.handleMessage(peerHex, MessageType.TX_SIGNATURES, opTxSigs);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('a failed persist suppresses channel:txsigs-needed; the reconnect re-arms it (307)', () => {
		const h = driveToCommitmentExchange();
		expect(
			findError(
				h.opener.handleCommitmentSigned(
					decodeCommitmentSignedMessage(h.acceptorCommit)
				)
			)
		).to.equal(null);

		const mgr = new ChannelManager({
			localBasepoints: makeBasepoints(
				getPublicKey(crypto.randomBytes(32)),
				crypto.randomBytes(32)
			),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32)
		});
		mgr.on('error', () => {});
		const peerHex = getPublicKey(crypto.randomBytes(32)).toString('hex');
		const tempIdHex = h.acceptor.getTemporaryChannelId().toString('hex');
		(mgr as unknown as { tempChannels: Map<string, Channel> }).tempChannels.set(
			tempIdHex,
			h.acceptor
		);
		(mgr as unknown as { channelPeers: Map<string, string> }).channelPeers.set(
			tempIdHex,
			peerHex
		);

		let refusePersist = true;
		mgr.on('channel:persist', (ev: { request?: { committed: boolean } }) => {
			if (refusePersist && ev.request) {
				ev.request.committed = false;
			}
		});
		let events = 0;
		mgr.on('channel:txsigs-needed', () => {
			events++;
		});

		// The batch whose persist failed may have withheld our own
		// commitment_signed; a listener answering the reminder would put
		// tx_signatures on the wire ahead of it, so the reminder is withheld
		// with the sends.
		mgr.handleMessage(peerHex, MessageType.COMMITMENT_SIGNED, h.openerCommit);
		expect(events, 'a failed persist suppresses the reminder').to.equal(0);

		// Persistence recovers and the peer reconnects: the reminder fires.
		refusePersist = false;
		mgr.handlePeerDisconnected(peerHex);
		h.opener.markForReestablish();
		const opReest = findPayload(
			h.opener.createReestablish(),
			MessageType.CHANNEL_REESTABLISH
		)!;
		mgr.handleMessage(peerHex, MessageType.CHANNEL_REESTABLISH, opReest);
		expect(events, 'the reconnect re-armed the reminder').to.equal(1);
	});

	it('leaves the reserves of a still-negotiating v2 open to the record (issue 381)', () => {
		// restoreChannel runs restoreV2InFlight immediately before the enforced-
		// reserve repair, and _restoreV2RecordSnapshot owns BOTH reserves for the
		// active attempt: capacity, balances and reserves are re-paired together,
		// and an RBF rollback re-pairs them again. A repair that re-derived from
		// the top-level capacity would fight that, and can skew against it in the
		// crash window where the top-level capacity belongs to a later attempt
		// than the record. Nothing is lost by waiting, since the row is not NORMAL
		// and admits no HTLC; the repair lands once channel_ready nulls the record.
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.opener.getFullState()))
		);
		expect(json.v2InFlight, 'the fixture has a live record').to.not.be.oneOf([
			null,
			undefined
		]);
		// A value the derivation would happily lower, so what keeps it is the
		// guard rather than the arithmetic agreeing by accident.
		json.localConfig.channelReserveSatoshis = '10000';
		// And no provenance stamp, i.e. a row from a build that never wrote one.
		// Without stripping it the repair would skip on the stamp rather than on
		// the live record, and this would stop testing the guard it names.
		delete json.channelReserveVersion;
		const revived = new Channel(deserializeChannelState(json), h.openerSigner);
		revived.repairEnforcedChannelReserve();
		expect(
			revived.getFullState().localConfig.channelReserveSatoshis,
			'the repair deferred to the record'
		).to.equal(10_000n);

		// And the record is what supplies the right value, on the same load.
		revived.restoreV2InFlight();
		expect(revived.getFullState().localConfig.channelReserveSatoshis).to.equal(
			1_500n
		);
		// And it stamps provenance, so a later load does not re-derive what the
		// record just established (issue 381).
		expect(revived.getFullState().channelReserveVersion).to.be.a('number');
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

	it('accepts RBF after tx_signatures were released (issue 360 spec window), refuses it on restored sessions; accepted RBF retains the rollback record until post-ack traffic', () => {
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

		// Post-ack traffic does NOT clear the record: the rollback state is
		// retained through the whole renegotiation and is only replaced,
		// atomically, by the NEW attempt's record at its commitment persist.
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
			h.acceptor.getFullState().v2InFlight,
			'the rollback record survives replacement-round traffic'
		).to.equal(preRecord);

		// After a release, the spec window is OPEN (issue #360): an inbound
		// tx_init_rbf on the broadcastable attempt is acked, and the
		// broadcastable record is retained as the rollback attempt. Only the
		// non-initiator restriction still refuses the acceptor's own request.
		const g = driveToCommitmentExchange();
		deliverCommitments(g);
		const accSig = g.acceptor.sendTxSignatures(
			g.acceptor.getFullState().fundingTxid!,
			g.acceptor.getFullState().fundingOutputIndex,
			g.acceptorWitness()
		);
		expect(findPayload(accSig, MessageType.TX_SIGNATURES)).to.not.equal(null);
		expect(findError(g.acceptor.initiateTxRbf(2000))).to.contain(
			'Only initiator'
		);
		const postReleaseRecord = g.acceptor.getFullState().v2InFlight;
		expect(postReleaseRecord!.sentTxSignatures).to.equal(true);
		const acked = g.acceptor.handleTxInitRbf({
			channelId: g.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findError(acked)).to.equal(null);
		expect(
			findPayload(acked, MessageType.TX_ACK_RBF),
			'post-release RBF is acked in the spec window'
		).to.not.equal(null);
		expect(
			g.acceptor.getFullState().v2InFlight,
			'the broadcastable record is retained as rollback state'
		).to.equal(postReleaseRecord);
		expect(g.acceptor.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);

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
			h.opener.getFullState().dualFundingSession!.getLocalParams()!
				.fundingFeeratePerkw,
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
		expect(h.acceptor.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
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
		expect(h.opener.getFullState().v2InFlight!.fundingTxid.equals(before)).to.be
			.true;
		expect(h.opener.isAbandonedV2Open()).to.be.false;

		// The refusing receiver swallows the echo (it sent the abort itself),
		// and the ORIGINAL attempt still completes.
		expect(h.acceptor.handleTxAbort()).to.deep.equal([]);
		completeExchange(h);
	});

	it('tx_ack_rbf begins the renegotiation and retains the rollback record until the peer answers', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const preRecord = h.opener.getFullState().v2InFlight;
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const ackActions = h.opener.handleTxAckRbf();
		expect(findError(ackActions)).to.equal(null);
		expect(
			ackActions.some((a) => a.type === ChannelActionType.PERSIST_STATE),
			'the agreed replacement persists'
		).to.be.true;
		expect(h.opener.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		// Symmetric with the receiver: the ack proves acceptance, not that
		// the peer will ever SEE the new round (our first contribution can
		// be lost), so the previous attempt's record is retained.
		expect(
			h.opener.getFullState().v2InFlight,
			'the rollback record is retained through the ack'
		).to.equal(preRecord);

		// Replacement-round traffic does NOT clear it either: the record is
		// only replaced, atomically, by the NEW attempt's record at its
		// commitment persist, so no separate clear-write can fail apart.
		const commitActions = h.opener.handleTxComplete();
		expect(findError(commitActions)).to.equal(null);
		expect(
			h.opener.getFullState().v2InFlight,
			'the rollback record survives replacement-round traffic'
		).to.equal(preRecord);

		// An unsolicited ack acknowledges nothing.
		const g = driveToCommitmentExchange();
		deliverCommitments(g);
		expect(g.opener.handleTxAckRbf()).to.deep.equal([]);
		expect(g.opener.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);
	});

	it('refuses a second RBF while the accepted replacement is unrecorded; the guard reopens at the replacement commitment', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const preRecord = h.opener.getFullState().v2InFlight!;
		expect(preRecord.rbfAttempt).to.equal(0);

		// Request 1 is accepted: the renegotiation begins at the ack.
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const ackAnswer = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findPayload(ackAnswer, MessageType.TX_ACK_RBF)).to.not.equal(null);
		expect(findError(h.opener.handleTxAckRbf())).to.equal(null);

		// The race window is provably open: the retained record still
		// describes the replaced attempt while the session already counts
		// the accepted replacement round.
		const session = h.opener.getFullState().dualFundingSession!;
		expect(h.opener.getFullState().v2InFlight).to.equal(preRecord);
		expect(session.getRbfCount()).to.equal(1);
		expect(preRecord.rbfAttempt).to.equal(0);

		// A second request priced against the retained record (1100 clears
		// attempt 0's floor of 1041 but not the replacement's floor of 2083)
		// would pass the local pre-check and fail at ack time with the peer
		// already committed; it is refused locally with nothing on the wire.
		const second = h.opener.initiateTxRbf(1100);
		expect(findError(second)).to.contain('still renegotiating');
		expect(findPayload(second, MessageType.TX_INIT_RBF)).to.equal(null);
		expect(second.some((a) => a.type === ChannelActionType.PERSIST_STATE)).to.be
			.false;
		expect(h.opener.getFullState().v2InFlight).to.equal(preRecord);
		expect(session.getLocalParams()!.fundingFeeratePerkw).to.equal(2000);
		expect(session.getRbfCount()).to.equal(1);

		// The replacement round completes caller-driven (same contributions,
		// repriced): its commitment persist swaps the record in atomically.
		const fundingScript = bitcoin.Transaction.fromHex(preRecord.fundingTxHex)
			.outs[preRecord.fundingOutputIndex].script;
		const oInAct = h.opener.addTxInput(makeInput(0n, h.openerPrev.prevTx));
		expect(findError(oInAct)).to.equal(null);
		h.acceptor.handleTxAddInput(
			decodeTxAddInputMessage(findPayload(oInAct, MessageType.TX_ADD_INPUT)!)
		);
		const aInAct = h.acceptor.addTxInput(makeInput(1n, h.acceptorPrev.prevTx));
		expect(findError(aInAct)).to.equal(null);
		h.opener.handleTxAddInput(
			decodeTxAddInputMessage(findPayload(aInAct, MessageType.TX_ADD_INPUT)!)
		);
		const oOutAct = h.opener.addTxOutput({
			serialId: 2n,
			amountSats: TOTAL_FUNDING,
			scriptPubkey: fundingScript
		});
		expect(findError(oOutAct)).to.equal(null);
		h.acceptor.handleTxAddOutput(
			decodeTxAddOutputMessage(findPayload(oOutAct, MessageType.TX_ADD_OUTPUT)!)
		);
		expect(findError(h.acceptor.sendTxComplete())).to.equal(null);
		h.opener.handleTxComplete();
		const opComplete = h.opener.sendTxComplete();
		expect(findError(opComplete)).to.equal(null);
		const openerCommit = findPayload(opComplete, MessageType.COMMITMENT_SIGNED);
		expect(openerCommit).to.not.equal(null);
		const acComplete = h.acceptor.handleTxComplete();
		const acceptorCommit = findPayload(
			acComplete,
			MessageType.COMMITMENT_SIGNED
		);
		expect(acceptorCommit).to.not.equal(null);
		expect(
			findError(
				h.acceptor.handleCommitmentSigned(
					decodeCommitmentSignedMessage(openerCommit!)
				)
			)
		).to.equal(null);
		expect(
			findError(
				h.opener.handleCommitmentSigned(
					decodeCommitmentSignedMessage(acceptorCommit!)
				)
			)
		).to.equal(null);
		const swapped = h.opener.getFullState().v2InFlight!;
		expect(swapped).to.not.equal(preRecord);
		expect(swapped.rbfAttempt).to.equal(1);
		expect(swapped.fundingFeeratePerkw).to.equal(2000);

		// With the replacement recorded the guard reopens: a further RBF at
		// the recorded attempt's floor goes out normally.
		const third = h.opener.initiateTxRbf(2083);
		expect(findError(third)).to.equal(null);
		expect(findPayload(third, MessageType.TX_INIT_RBF)).to.not.equal(null);
	});

	it('an ack-time initiateRbf failure unwinds on the wire: tx_abort out, the peer rolls back, the echo is swallowed', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		const preRecord = h.opener.getFullState().v2InFlight!;
		const attempt0Txid = Buffer.from(preRecord.fundingTxid);

		// The peer accepts the request: it is now mid-replacement, holding
		// its own retained rollback record.
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const ackAnswer = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findPayload(ackAnswer, MessageType.TX_ACK_RBF)).to.not.equal(null);
		expect(h.acceptor.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		expect(
			h.acceptor.getFullState().dualFundingSession!.getRbfCount()
		).to.equal(1);

		// The stale-record guard makes this arm unreachable through the
		// public API, so induce the session failure directly: the channel
		// must still unwind ON THE WIRE, never with a bare local error that
		// leaves the committed peer waiting for tx_add_* forever.
		const session = h.opener.getFullState().dualFundingSession!;
		session.initiateRbf = (): { ok: boolean; error?: string } => ({
			ok: false,
			error: 'induced ack-time failure'
		});
		const ack = h.opener.handleTxAckRbf();
		const abortPayload = findPayload(ack, MessageType.TX_ABORT);
		expect(abortPayload, 'the failed ack unwinds on the wire').to.not.equal(
			null
		);
		expect(
			decodeTxAbortMessage(abortPayload!).data.toString('utf8')
		).to.contain('induced ack-time failure');
		expect(findError(ack)).to.contain('induced ack-time failure');
		// The failure fired before the session mutated anything: the current
		// attempt stays fully live, nothing to roll back or persist.
		expect(ack.some((a) => a.type === ChannelActionType.PERSIST_STATE)).to.be
			.false;
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(h.opener.getFullState().v2InFlight).to.equal(preRecord);
		expect(preRecord.rbfAttempt).to.equal(0);

		// The peer's retained rollback record returns it to the shared
		// previous attempt, durably, and it answers with the echo.
		const peerAnswer = h.acceptor.handleTxAbort();
		expect(
			peerAnswer.some((a) => a.type === ChannelActionType.PERSIST_STATE),
			'the rollback persists'
		).to.be.true;
		expect(findPayload(peerAnswer, MessageType.TX_ABORT)).to.not.equal(null);
		expect(h.acceptor.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		const peerRecord = h.acceptor.getFullState().v2InFlight!;
		expect(peerRecord.fundingTxid.equals(attempt0Txid)).to.be.true;
		expect(peerRecord.rbfAttempt).to.equal(0);
		expect(
			h.acceptor.getFullState().dualFundingSession!.getRbfCount()
		).to.equal(0);

		// The echo lands in the sent-latch swallow (no _v2AbortPending
		// teardown), and the original attempt still completes on both sides.
		expect(h.opener.handleTxAbort()).to.deep.equal([]);
		completeExchange(h);
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	/**
	 * Drive the opener into the rollback-abort state: request accepted by
	 * the peer (which is now mid-replacement), then the ack-time session
	 * failure induced white-box so handleTxAckRbf sends the unwind abort.
	 */
	function induceRollbackAbort(h: IHarness): void {
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const ackAnswer = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findPayload(ackAnswer, MessageType.TX_ACK_RBF)).to.not.equal(null);
		const session = h.opener.getFullState().dualFundingSession!;
		session.initiateRbf = (): { ok: boolean; error?: string } => ({
			ok: false,
			error: 'induced ack-time failure'
		});
		const ack = h.opener.handleTxAckRbf();
		expect(findPayload(ack, MessageType.TX_ABORT)).to.not.equal(null);
	}

	it('serializes RBF and operator aborts behind an un-echoed rollback abort; the echo thaws the release and reopens them', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		induceRollbackAbort(h);

		// While the rollback abort is un-echoed, everything that would
		// overlap the exchange is refused: a delayed echo must never be
		// taken for a newer abort's answer, and no witnesses may cross the
		// peer's rollback.
		expect(findError(h.opener.initiateTxRbf(2083))).to.contain(
			'awaiting its echo'
		);
		expect(findError(h.opener.abortDualFunding('too eager'))).to.contain(
			'awaiting its echo'
		);
		expect(
			findError(
				h.opener.sendTxSignatures(
					h.opener.getFullState().fundingTxid!,
					h.opener.getFullState().fundingOutputIndex,
					h.openerWitness()
				)
			)
		).to.contain('frozen');

		// The peer rolls back and echoes; the echo completes the exchange.
		expect(
			findPayload(h.acceptor.handleTxAbort(), MessageType.TX_ABORT)
		).to.not.equal(null);
		expect(h.opener.handleTxAbort()).to.deep.equal([]);

		// A subsequent operator abort now runs the FULL handshake: the
		// peer's latch was reset by its rollback echo, so the abort is
		// answered (not silently swallowed) and the teardown completes on
		// both sides at the echo.
		const abortActions = h.opener.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);
		expect(findPayload(abortActions, MessageType.TX_ABORT)).to.not.equal(null);
		const peerAnswer = h.acceptor.handleTxAbort();
		expect(
			findPayload(peerAnswer, MessageType.TX_ABORT),
			'the peer answers the abort instead of swallowing it'
		).to.not.equal(null);
		const teardown = h.opener.handleTxAbort();
		expect(teardown.some((a) => a.type === ChannelActionType.PERSIST_STATE)).to
			.be.true;
		expect(h.opener.getState()).to.equal(ChannelState.ERRORED);
		expect(h.acceptor.getState()).to.equal(ChannelState.ERRORED);
	});

	it('a lost rollback abort or lost echo converges over reestablish to the shared attempt', () => {
		// Echo lost: the peer rolled back durably, our latches die with the
		// connection, and both sides resume attempt 0.
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		induceRollbackAbort(h);
		expect(
			findPayload(h.acceptor.handleTxAbort(), MessageType.TX_ABORT)
		).to.not.equal(null);
		// The echo is never delivered.
		h.opener.markForReestablish();
		h.acceptor.markForReestablish();
		const opMsg = reestablishOf(h.opener.createReestablish());
		const acMsg = reestablishOf(h.acceptor.createReestablish());
		expect(findError(h.opener.handleReestablish(acMsg))).to.equal(null);
		expect(findError(h.acceptor.handleReestablish(opMsg))).to.equal(null);
		completeExchange(h);
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		// Abort lost: the peer is still mid-replacement when the connection
		// dies; its own markForReestablish rolls it back to the retained
		// attempt and both sides resume it.
		const g = driveToCommitmentExchange();
		deliverCommitments(g);
		induceRollbackAbort(g);
		expect(g.acceptor.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		g.opener.markForReestablish();
		g.acceptor.markForReestablish();
		// The disconnect armed the rollback: the retained attempt-0 record
		// is restored behind the reestablish gate.
		expect(g.acceptor.getFullState().v2InFlight!.rbfAttempt).to.equal(0);
		expect(
			g.acceptor.getFullState().dualFundingSession!.getRbfCount()
		).to.equal(0);
		const gOpMsg = reestablishOf(g.opener.createReestablish());
		const gAcMsg = reestablishOf(g.acceptor.createReestablish());
		expect(findError(g.opener.handleReestablish(gAcMsg))).to.equal(null);
		expect(findError(g.acceptor.handleReestablish(gOpMsg))).to.equal(null);
		completeExchange(g);
		expect(g.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('a peer operator abort crossing the rollback abort resolves both sides to the shared attempt', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		induceRollbackAbort(h);

		// Before our rollback abort arrives, the peer (mid-replacement)
		// operator-aborts: the two aborts cross on the wire.
		const peerAbort = h.acceptor.abortDualFunding('going away');
		expect(findError(peerAbort)).to.equal(null);
		expect(findPayload(peerAbort, MessageType.TX_ABORT)).to.not.equal(null);

		// Our abort reaches the peer as the answer to its own: mid-
		// renegotiation its retained record is rollback state, so it rolls
		// back to attempt 0 instead of tearing down, with no second abort.
		const peerResolution = h.acceptor.handleTxAbort();
		expect(
			peerResolution.some((a) => a.type === ChannelActionType.PERSIST_STATE)
		).to.be.true;
		expect(findPayload(peerResolution, MessageType.TX_ABORT)).to.equal(null);
		expect(h.acceptor.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(h.acceptor.getFullState().v2InFlight!.rbfAttempt).to.equal(0);

		// The peer's abort reaches us as the answer that completes our
		// exchange: swallowed, latches cleared, attempt untouched.
		expect(h.opener.handleTxAbort()).to.deep.equal([]);
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(h.opener.getFullState().v2InFlight!.rbfAttempt).to.equal(0);

		// Both sides sit on the shared attempt and it still completes.
		completeExchange(h);
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('freezes the old attempt while an RBF request is pending; the ack revalidates the binding', () => {
		// The acceptor contributes MORE, so the opener signs first: without
		// the freeze, the crossed commitment_signed below would release
		// attempt 0's tx_signatures while the peer may already have accepted
		// the replacement.
		const h = driveToCommitmentExchange({
			acceptorPrev: makeRealPrevOut(300_000)
		});
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);

		const crossed = h.opener.handleCommitmentSigned(
			decodeCommitmentSignedMessage(h.acceptorCommit)
		);
		expect(findError(crossed)).to.equal(null);
		expect(
			findPayload(crossed, MessageType.TX_SIGNATURES),
			'the release is frozen while the request is un-acked'
		).to.equal(null);
		expect(h.opener.getFullState().v2InFlight!.sentTxSignatures).to.be.false;

		// A refusal thaws it: the request dies, the attempt is untouched,
		// and the signature exchange completes normally from here (this
		// caller-driven harness releases witnesses explicitly, so the thaw
		// shows as the exchange succeeding rather than as an inline
		// retransmit).
		const answer = h.opener.handleTxAbort();
		expect(findError(answer)).to.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(
			findError(
				h.acceptor.handleCommitmentSigned(
					decodeCommitmentSignedMessage(h.openerCommit)
				)
			)
		).to.equal(null);
		// The opener contributes less here, so IT signs first (the inverse
		// of completeExchange's usual ordering).
		const opSig = h.opener.sendTxSignatures(
			h.opener.getFullState().fundingTxid!,
			h.opener.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		expect(findError(opSig)).to.equal(null);
		const opTxSigs = findPayload(opSig, MessageType.TX_SIGNATURES);
		expect(opTxSigs, 'the thawed release goes out').to.not.equal(null);
		const acAfter = h.acceptor.handleTxSignatures(
			decodeTxSignaturesMessage(opTxSigs!)
		);
		expect(findError(acAfter)).to.equal(null);
		let acTxSigs = findPayload(acAfter, MessageType.TX_SIGNATURES);
		if (!acTxSigs) {
			const acSig = h.acceptor.sendTxSignatures(
				h.acceptor.getFullState().fundingTxid!,
				h.acceptor.getFullState().fundingOutputIndex,
				h.acceptorWitness()
			);
			expect(findError(acSig)).to.equal(null);
			acTxSigs = findPayload(acSig, MessageType.TX_SIGNATURES);
		}
		expect(acTxSigs).to.not.equal(null);
		expect(
			findError(
				h.opener.handleTxSignatures(decodeTxSignaturesMessage(acTxSigs!))
			)
		).to.equal(null);
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		// The ack revalidates the binding: if the window closed while the
		// request was in flight (an attempt confirmed here; channel_ready
		// crossing works the same way), the renegotiation refuses on the
		// wire and keeps the attempt. A record whose witnesses merely left
		// no longer invalidates the ack: that IS the spec window (issue 360).
		const g = driveToCommitmentExchange();
		deliverCommitments(g);
		expect(findError(g.opener.initiateTxRbf(2000))).to.equal(null);
		g.opener.getFullState().v2InFlight!.confirmed = true;
		const stale = g.opener.handleTxAckRbf();
		expect(
			findPayload(stale, MessageType.TX_ABORT),
			'the invalidated request unwinds on the wire'
		).to.not.equal(null);
		expect(g.opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(g.opener.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);
	});

	// ─────── Issue 360: RBF in the BOLT 2 spec window (post-signatures) ───────

	it('closes the spec window at channel_ready and at a confirmed attempt (issue 360)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const ready = h.opener.fundingConfirmed();
		expect(findPayload(ready, MessageType.CHANNEL_READY)).to.not.equal(null);
		expect(findError(h.opener.initiateTxRbf(2000))).to.contain('channel_ready');
		const refusal = h.opener.handleTxInitRbf({
			channelId: h.opener.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		const abort = findPayload(refusal, MessageType.TX_ABORT);
		expect(abort).to.not.equal(null);
		expect(decodeTxAbortMessage(abort!).data.toString('utf8')).to.contain(
			'channel_ready'
		);

		// A parked confirmation closes the window the same way.
		const g = driveToCommitmentExchange();
		deliverCommitments(g);
		completeExchange(g);
		g.opener.getFullState().v2InFlight!.confirmed = true;
		expect(findError(g.opener.initiateTxRbf(2000))).to.contain('confirmed');
		const confRefusal = g.opener.handleTxInitRbf({
			channelId: g.opener.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		const confAbort = findPayload(confRefusal, MessageType.TX_ABORT);
		expect(confAbort).to.not.equal(null);
		expect(decodeTxAbortMessage(confAbort!).data.toString('utf8')).to.contain(
			'confirmed'
		);
	});

	it('a post-signatures acceptance rolls back to AWAITING_FUNDING_CONFIRMED on disconnect (issue 360)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		expect(h.acceptor.getFullState().v2InFlight!.sentTxSignatures).to.equal(
			true
		);
		const acked = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findPayload(acked, MessageType.TX_ACK_RBF)).to.not.equal(null);
		expect(h.acceptor.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);

		h.acceptor.markForReestablish();
		const st = h.acceptor.getFullState();
		expect(st.state).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(
			st.preReestablishState,
			'a broadcastable rollback attempt waits on the chain, not the peer'
		).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
		expect(st.v2InFlight!.rbfAttempt).to.equal(0);
		expect(st.dualFundingSession!.getRbfCount()).to.equal(0);
	});

	it('an operator abort of a post-signatures renegotiation returns both sides to the completed attempt (issue 360)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const attempt0 = Buffer.from(
			h.opener.getFullState().v2InFlight!.fundingTxid
		);
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const acked = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findPayload(acked, MessageType.TX_ACK_RBF)).to.not.equal(null);
		expect(
			findError(
				h.opener.handleTxAckRbf(
					decodeTxAckRbfMessage(findPayload(acked, MessageType.TX_ACK_RBF)!)
				)
			)
		).to.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);

		const abortActions = h.opener.abortDualFunding(
			'operator cancelled the bump'
		);
		expect(
			findPayload(abortActions, MessageType.TX_ABORT),
			'the renegotiation abort reaches the wire despite the released signatures'
		).to.not.equal(null);
		const answer = h.acceptor.handleTxAbort();
		expect(findPayload(answer, MessageType.TX_ABORT), 'echoed').to.not.equal(
			null
		);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.acceptor.getFullState().v2InFlight!.fundingTxid.equals(attempt0))
			.to.be.true;
		expect(h.opener.handleTxAbort()).to.deep.equal([
			{ type: ChannelActionType.PERSIST_STATE }
		]);
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.opener.getFullState().v2InFlight!.fundingTxid.equals(attempt0)).to
			.be.true;
	});

	it('a confirmation landing mid-renegotiation abandons the RBF attempt and readies the channel (issue 360)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const acked = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(
			findError(
				h.opener.handleTxAckRbf(
					decodeTxAckRbfMessage(findPayload(acked, MessageType.TX_ACK_RBF)!)
				)
			)
		).to.equal(null);

		// BOLT 2: "If the previous transaction confirms in the middle of an
		// RBF attempt, the attempt MUST be abandoned."
		const confirmed = h.opener.fundingConfirmed();
		expect(
			findPayload(confirmed, MessageType.TX_ABORT),
			'the renegotiation is abandoned on the wire'
		).to.not.equal(null);
		const openerReady = findPayload(confirmed, MessageType.CHANNEL_READY);
		expect(openerReady, 'channel_ready flows in the same batch').to.not.equal(
			null
		);
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
		expect(h.opener.getFullState().v2InFlight!.rbfAttempt).to.equal(0);

		// The acceptor rolls back on the abandon signal (wire order: the
		// abort precedes the channel_ready), readies at its own depth
		// callback, and both reach NORMAL.
		const answer = h.acceptor.handleTxAbort();
		expect(findPayload(answer, MessageType.TX_ABORT)).to.not.equal(null);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(
			findError(
				h.acceptor.handleChannelReady(decodeChannelReadyMessage(openerReady!))
			)
		).to.equal(null);
		expect(h.opener.handleTxAbort(), 'the echo is swallowed').to.deep.equal([]);
		const accReady = h.acceptor.fundingConfirmed();
		const accReadyMsg = findPayload(accReady, MessageType.CHANNEL_READY);
		expect(accReadyMsg).to.not.equal(null);
		expect(h.acceptor.getState()).to.equal(ChannelState.NORMAL);
		expect(
			findError(
				h.opener.handleChannelReady(decodeChannelReadyMessage(accReadyMsg!))
			)
		).to.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.NORMAL);
	});

	it('a channel_ready received mid-renegotiation abandons the RBF attempt and is processed (issue 360 review)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const acked = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(
			findError(
				h.opener.handleTxAckRbf(
					decodeTxAckRbfMessage(findPayload(acked, MessageType.TX_ACK_RBF)!)
				)
			)
		).to.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);

		// Peer-first confirmation race: the acceptor confirmed and readied;
		// its channel_ready reaches the still-renegotiating opener. BOLT 2:
		// a valid channel_ready mid-RBF abandons the attempt.
		const accActions = h.acceptor.fundingConfirmed();
		const readyMsg = findPayload(accActions, MessageType.CHANNEL_READY);
		expect(readyMsg).to.not.equal(null);
		const processed = h.opener.handleChannelReady(
			decodeChannelReadyMessage(readyMsg!)
		);
		expect(findError(processed), 'not "Unexpected channel_ready"').to.equal(
			null
		);
		expect(
			findPayload(processed, MessageType.TX_ABORT),
			'the RBF attempt is abandoned on the wire'
		).to.not.equal(null);
		const st = h.opener.getFullState();
		expect(st.remoteChannelReady).to.equal(true);
		expect(st.v2InFlight!.rbfAttempt).to.equal(0);
		expect(st.dualFundingSession!.getRbfCount()).to.equal(0);
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
	});

	it('a malformed channel_ready is rejected before it can abandon an RBF attempt (issue 376)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const acked = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(
			findError(
				h.opener.handleTxAckRbf(
					decodeTxAckRbfMessage(findPayload(acked, MessageType.TX_ACK_RBF)!)
				)
			)
		).to.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);

		// BOLT 2 abandons the attempt only for a VALID channel_ready. An
		// all-zero point is not a curve point: it must be refused with the
		// renegotiation untouched and nothing stored.
		const bad = h.opener.handleChannelReady({
			channelId: h.opener.getChannelId()!,
			secondPerCommitmentPoint: Buffer.alloc(33)
		});
		expect(findError(bad)).to.contain('second_per_commitment_point');
		expect(
			findPayload(bad, MessageType.TX_ABORT),
			'nothing was abandoned'
		).to.equal(null);
		const st = h.opener.getFullState();
		expect(st.remoteChannelReady).to.equal(false);
		expect(st.remoteNextPerCommitmentPoint).to.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
	});

	it('a BOLT 1 error mid-renegotiation rolls back before failing the channel (issue 376)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const attempt0 = Buffer.from(
			h.acceptor.getFullState().v2InFlight!.fundingTxid
		);
		const capacityBefore = h.acceptor.getFullState().fundingSatoshis;
		const record = h.acceptor.getFullState().v2InFlight!;

		h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000,
			fundingOutputContribution: record.remoteContributionSats + 20_000n
		});
		expect(h.acceptor.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);

		// ERRORED is force-closeable. Without the rollback the channel would
		// keep the replacement's amounts while the outpoint and the stored
		// peer signature still belong to attempt 0, and the close rebuilt
		// from that would not be covered by the signature.
		expect(h.acceptor.markErrored()).to.equal(true);
		const st = h.acceptor.getFullState();
		expect(st.state).to.equal(ChannelState.ERRORED);
		expect(Number(st.fundingSatoshis)).to.equal(Number(capacityBefore));
		expect(st.fundingTxid!.equals(attempt0)).to.equal(true);
		expect(st.v2InFlight!.rbfAttempt).to.equal(0);
	});

	it('a peer error mid-open resumes the attempt that has its own signature (issue 376 review)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const attempt0 = Buffer.from(
			h.opener.getFullState().v2InFlight!.fundingTxid
		);
		const sig0 = Buffer.from(
			h.opener.getFullState().remoteCommitmentSignature!
		);

		// Drive a replacement all the way to its record install, but never let
		// the peer's commitment_signed for it arrive: the record swap
		// re-points the funding outpoint at attempt 1 while the top-level
		// signature still belongs to attempt 0.
		const preRecord = h.opener.getFullState().v2InFlight!;
		// A distinct locktime so the replacement is a DIFFERENT transaction
		// (same inputs and outputs otherwise, so the txids would collide).
		expect(findError(h.opener.initiateTxRbf(2000, 500))).to.equal(null);
		const acked = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 500,
			feerate: 2000
		});
		h.opener.handleTxAckRbf(
			decodeTxAckRbfMessage(findPayload(acked, MessageType.TX_ACK_RBF)!)
		);
		const fundingScript = bitcoin.Transaction.fromHex(preRecord.fundingTxHex)
			.outs[preRecord.fundingOutputIndex].script;
		const oIn = h.opener.addTxInput(makeInput(0n, h.openerPrev.prevTx));
		h.acceptor.handleTxAddInput(
			decodeTxAddInputMessage(findPayload(oIn, MessageType.TX_ADD_INPUT)!)
		);
		const aIn = h.acceptor.addTxInput(makeInput(1n, h.acceptorPrev.prevTx));
		h.opener.handleTxAddInput(
			decodeTxAddInputMessage(findPayload(aIn, MessageType.TX_ADD_INPUT)!)
		);
		const oOut = h.opener.addTxOutput({
			serialId: 2n,
			amountSats: TOTAL_FUNDING,
			scriptPubkey: fundingScript
		});
		h.acceptor.handleTxAddOutput(
			decodeTxAddOutputMessage(findPayload(oOut, MessageType.TX_ADD_OUTPUT)!)
		);
		h.acceptor.sendTxComplete();
		h.opener.handleTxComplete();
		expect(findError(h.opener.sendTxComplete())).to.equal(null);
		const recorded = h.opener.getFullState().v2InFlight!;
		expect(recorded.rbfAttempt, 'the replacement recorded itself').to.equal(1);
		expect(
			recorded.remoteCommitmentSig,
			'but is unsigned by the peer'
		).to.equal(null);
		expect(
			recorded.fundingTxid.equals(attempt0),
			'and is a different transaction'
		).to.equal(false);

		expect(h.opener.markErrored()).to.equal(true);
		const st = h.opener.getFullState();
		// The replacement had no signature of its own, so leaving it current
		// would let a close report success while broadcasting a commitment
		// whose witness does not verify over the outpoint it spends.
		expect(st.state).to.equal(ChannelState.ERRORED);
		expect(st.fundingTxid!.equals(attempt0), 'attempt 0 is current').to.equal(
			true
		);
		expect(
			st.remoteCommitmentSignature!.equals(sig0),
			"and carries attempt 0's own signature"
		).to.equal(true);
	});

	it('an unencodable RBF request never installs the pending latch (issue 360 review)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		// locktime -1 fails the u32 encode; the request must die BEFORE the
		// pending latch is installed, or every later request is refused as
		// "already pending" until disconnect.
		const bad = h.opener.initiateTxRbf(2000, -1);
		expect(findError(bad)).to.contain('cannot RBF');
		expect(findPayload(bad, MessageType.TX_INIT_RBF)).to.equal(null);
		const good = h.opener.initiateTxRbf(2000);
		expect(findError(good), 'the latch stayed clean').to.equal(null);
		expect(findPayload(good, MessageType.TX_INIT_RBF)).to.not.equal(null);
	});

	/** Drive the open all the way to NORMAL on both sides. */
	const driveToNormal = (h: IHarness): void => {
		deliverCommitments(h);
		completeExchange(h);
		const opReady = findPayload(
			h.opener.fundingConfirmed(),
			MessageType.CHANNEL_READY
		)!;
		const acReady = findPayload(
			h.acceptor.fundingConfirmed(),
			MessageType.CHANNEL_READY
		)!;
		expect(
			findError(h.opener.handleChannelReady(decodeChannelReadyMessage(acReady)))
		).to.equal(null);
		expect(
			findError(
				h.acceptor.handleChannelReady(decodeChannelReadyMessage(opReady))
			)
		).to.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.NORMAL);
		expect(h.acceptor.getState()).to.equal(ChannelState.NORMAL);
	};

	const inboundHtlc = (
		side: Channel,
		amountMsat: bigint,
		id = 0n
	): IUpdateAddHtlcMessage => ({
		channelId: side.getChannelId()!,
		id,
		amountMsat,
		paymentHash: crypto.randomBytes(32),
		cltvExpiry: 800_000,
		onionRoutingPacket: Buffer.alloc(1366)
	});

	it('derives both channel reserves from capacity on a v2 open (issue 379)', () => {
		// A v2 open exchanges no channel_reserve_satoshis: both peers derive it
		// from the total capacity. remoteConfig's (what THEY require of US) was
		// already derived; localConfig's (what WE require of THEM) never was, so
		// it sat at the static DEFAULT_CHANNEL_CONFIG value for the channel's
		// whole life while a conforming peer computed 1% of capacity.
		const h = driveToCommitmentExchange();
		for (const side of [h.opener, h.acceptor]) {
			const state = side.getFullState();
			expect(Number(state.fundingSatoshis)).to.equal(Number(TOTAL_FUNDING));
			expect(Number(state.remoteConfig.channelReserveSatoshis)).to.equal(1_500);
			expect(Number(state.localConfig.channelReserveSatoshis)).to.equal(1_500);
		}
	});

	it('accepts an inbound HTLC down to the derived reserve, not the static one (issue 379)', () => {
		// handleUpdateAddHtlc gates the peer on localConfig.channelReserveSatoshis.
		// Undervived, that rejected every HTLC leaving the peer under 10,000 sat on
		// a 150,000-sat channel, where BOLT 2 gives the peer 1,500: an honest peer's
		// spec-legal HTLC failed the channel.
		const h = driveToCommitmentExchange();
		driveToNormal(h);
		// The opener funded 100,000 and holds 50,000 of the acceptor's on its
		// remote side; as OPENER it adds no commitment fee to the peer's floor.
		expect(Number(h.opener.getFullState().remoteBalanceMsat)).to.equal(
			Number(ACCEPTOR_FUNDING * 1000n)
		);

		// One msat below the reserve is still refused, at the derived value.
		expect(
			findError(
				h.opener.handleUpdateAddHtlc(inboundHtlc(h.opener, 48_500_001n))
			)
		).to.match(/cannot afford HTLC above channel reserve/);

		// Exactly at the reserve is legal, and was refused before the derivation.
		// On a PRISTINE channel: since issue 404 the refusal above fails the one it
		// was measured on.
		const admits = driveToCommitmentExchange();
		driveToNormal(admits);
		expect(
			findError(
				admits.opener.handleUpdateAddHtlc(
					inboundHtlc(admits.opener, 48_500_000n)
				)
			)
		).to.equal(null);
		expect(Number(admits.opener.getFullState().remoteBalanceMsat)).to.equal(
			1_500_000
		);
	});

	it('pairs each side of the derived reserve with the right dust limit (issue 379)', () => {
		// At equal dust limits both reserves are the same number, so nothing above
		// would notice them swapped. BOLT 2 does not say whose dust_limit floors
		// the reserve; beignet takes the maximum for what we keep (so our reserve
		// output is never dust in either commitment) and the minimum for what we
		// enforce (so it is never above what a conforming peer computes for
		// itself). A zero-contribution acceptor puts capacity at 100,000, whose 1%
		// sits below the raised dust limit, so the two values separate.
		const h = driveToCommitmentExchange({
			acceptorNoInput: true,
			acceptorDust: MAX_DUST_LIMIT_SATOSHIS
		});
		// Both peers derive the same pair, whichever side they are on: the
		// opener from accept_channel2, the acceptor from open_channel2.
		for (const side of [h.opener, h.acceptor]) {
			const state = side.getFullState();
			expect(Number(state.fundingSatoshis)).to.equal(Number(OPENER_FUNDING));
			expect(Number(state.remoteConfig.channelReserveSatoshis)).to.equal(1_062);
			expect(Number(state.localConfig.channelReserveSatoshis)).to.equal(1_000);
		}
	});

	it('accepts a changed funding_output_contribution and re-derives capacity, balances and reserve (issue 376)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const record = h.acceptor.getFullState().v2InFlight!;
		// Primitives, not the state object: getFullState hands back the live
		// state, so a later read would see the post-change values.
		const beforeCapacity = h.acceptor.getFullState().fundingSatoshis;
		const beforeReserve =
			h.acceptor.getFullState().remoteConfig.channelReserveSatoshis;
		const beforeLocalReserve =
			h.acceptor.getFullState().localConfig.channelReserveSatoshis;
		const raised = record.remoteContributionSats + 20_000n;

		// BOLT 2 allows a different contribution per attempt: accepted, and
		// the ack still restates OUR unchanged side verbatim.
		const acked = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000,
			fundingOutputContribution: raised
		});
		const ackPayload = findPayload(acked, MessageType.TX_ACK_RBF);
		expect(ackPayload).to.not.equal(null);
		expect(
			decodeTxAckRbfMessage(ackPayload!).fundingOutputContribution
		).to.equal(record.localContributionSats);

		const after = h.acceptor.getFullState();
		expect(Number(after.fundingSatoshis)).to.equal(
			Number(beforeCapacity + 20_000n)
		);
		// Non-lease v2: each side's balance is exactly its contribution.
		expect(Number(after.remoteBalanceMsat)).to.equal(Number(raised * 1000n));
		expect(Number(after.localBalanceMsat)).to.equal(
			Number(record.localContributionSats * 1000n)
		);
		// Both reserves are capacity-derived, so both move with it (issue 379).
		expect(Number(after.remoteConfig.channelReserveSatoshis)).to.be.greaterThan(
			Number(beforeReserve)
		);
		expect(Number(beforeLocalReserve)).to.equal(1_500);
		expect(Number(after.localConfig.channelReserveSatoshis)).to.equal(1_700);
		// The retained attempt keeps the amounts IT was negotiated at, so the
		// rollback below has somewhere to return to.
		expect(Number(after.v2InFlight!.fundingSatoshis!)).to.equal(
			Number(beforeCapacity)
		);
	});

	it('rolling back a changed-contribution replacement restores the previous attempt amounts (issue 376)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const record = h.acceptor.getFullState().v2InFlight!;
		const beforeCapacity = h.acceptor.getFullState().fundingSatoshis;
		const beforeReserve =
			h.acceptor.getFullState().remoteConfig.channelReserveSatoshis;
		const beforeLocalReserve =
			h.acceptor.getFullState().localConfig.channelReserveSatoshis;
		const beforeRemoteMsat = h.acceptor.getFullState().remoteBalanceMsat;

		h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000,
			fundingOutputContribution: record.remoteContributionSats + 20_000n
		});
		expect(
			Number(h.acceptor.getFullState().fundingSatoshis),
			'applied'
		).to.equal(Number(beforeCapacity + 20_000n));

		// The peer walks away from the renegotiation: the retained attempt
		// resumes, amounts included, or its commitment would be rebuilt at the
		// replacement's capacity and the stored signature would not cover it.
		h.acceptor.handleTxAbort();
		const rolled = h.acceptor.getFullState();
		expect(Number(rolled.fundingSatoshis)).to.equal(Number(beforeCapacity));
		expect(Number(rolled.remoteBalanceMsat)).to.equal(Number(beforeRemoteMsat));
		expect(Number(rolled.remoteConfig.channelReserveSatoshis)).to.equal(
			Number(beforeReserve)
		);
		// The reserve we enforce on the peer is per-attempt too (issue 379): the
		// replacement raised it to 1,700 and the retained attempt owns 1,500.
		expect(Number(beforeLocalReserve)).to.equal(1_500);
		expect(Number(rolled.localConfig.channelReserveSatoshis)).to.equal(1_500);
		expect(rolled.v2InFlight!.rbfAttempt).to.equal(0);
	});

	it('refuses a replacement that trims our own commitment to nothing (issue 379)', () => {
		// The both-sides-below-reserve rule alone does not cover asymmetric dust
		// limits. With ours at 1,062 and the peer's at 354, a 751/500 split at
		// 253 sat/kw leaves us 568 after the 183-sat fee and the peer 500: the
		// peer clears the 354 reserve we enforce, so the reserve rule passes,
		// but OUR commitment trims both outputs at 1,062 and is built with none.
		// The peer's commitment is fine, so we would be the only side without a
		// unilateral exit.
		const h = driveToCommitmentExchange({
			openerDust: MAX_DUST_LIMIT_SATOSHIS
		});
		deliverCommitments(h);
		completeExchange(h);
		const openerState = h.opener.getFullState();
		expect(Number(openerState.localConfig.dustLimitSatoshis)).to.equal(1_062);
		expect(Number(openerState.remoteConfig.dustLimitSatoshis)).to.equal(354);

		const refusal = (
			h.opener as unknown as {
				_v2RbfContributionRefusal: (l: bigint, r: bigint) => string | null;
			}
		)._v2RbfContributionRefusal(751n, 500n);
		expect(refusal).to.match(/trims every commitment #0 output at the 1062/);

		// The same split with matching low dust limits is viable and accepted.
		const symmetric = driveToCommitmentExchange();
		deliverCommitments(symmetric);
		completeExchange(symmetric);
		expect(
			(
				symmetric.opener as unknown as {
					_v2RbfContributionRefusal: (l: bigint, r: bigint) => string | null;
				}
			)._v2RbfContributionRefusal(751n, 500n)
		).to.equal(null);
	});

	it('admits a replacement whose larger output lands exactly on the dust limit (issue 388)', () => {
		// Same asymmetric pairing as above, at the boundary. We are the opener,
		// so the 183-sat fee is ours: 1,245 leaves us on exactly 1,062, which the
		// builder keeps as an output because it trims strictly BELOW the limit.
		// Neither commitment is empty, so the replacement is viable.
		const h = driveToCommitmentExchange({
			openerDust: MAX_DUST_LIMIT_SATOSHIS
		});
		deliverCommitments(h);
		completeExchange(h);
		const refusalOfSplit = (l: bigint, r: bigint): string | null =>
			(
				h.opener as unknown as {
					_v2RbfContributionRefusal: (a: bigint, b: bigint) => string | null;
				}
			)._v2RbfContributionRefusal(l, r);

		expect(refusalOfSplit(1_245n, 355n), 'exactly on the limit').to.equal(null);
		// One satoshi lower really does trim both of our outputs away.
		expect(refusalOfSplit(1_244n, 355n), 'one satoshi below').to.match(
			/trims every commitment #0 output at the 1062/
		);
	});

	it('refuses out-of-bounds contribution changes attempt-scoped, in both directions (issue 376)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const record = h.acceptor.getFullState().v2InFlight!;
		const capacityBefore = h.acceptor.getFullState().fundingSatoshis;

		const cases: Array<{ contribution: bigint; expect: string }> = [
			{ contribution: -1n, expect: 'negative' },
			{ contribution: 1n, expect: 'commitment fee' },
			{ contribution: 21_000_000n * 100_000_000n, expect: 'exceeds maximum' }
		];
		for (const c of cases) {
			const refusal = h.acceptor.handleTxInitRbf({
				channelId: h.acceptor.getChannelId()!,
				locktime: 0,
				feerate: 2000,
				fundingOutputContribution: c.contribution
			});
			const abort = findPayload(refusal, MessageType.TX_ABORT);
			expect(abort, `refused ${c.contribution}`).to.not.equal(null);
			expect(decodeTxAbortMessage(abort!).data.toString('utf8')).to.contain(
				c.expect
			);
			// Attempt-scoped: the recorded attempt and its amounts survive.
			expect(h.acceptor.getState()).to.equal(
				ChannelState.AWAITING_FUNDING_CONFIRMED
			);
			expect(Number(h.acceptor.getFullState().fundingSatoshis)).to.equal(
				Number(capacityBefore)
			);
			expect(h.acceptor.getFullState().v2InFlight!.rbfAttempt).to.equal(0);
		}

		// Outbound: an ack naming an out-of-bounds remote contribution unwinds
		// on the wire and keeps the recorded attempt.
		const g = driveToCommitmentExchange();
		deliverCommitments(g);
		completeExchange(g);
		expect(findError(g.opener.initiateTxRbf(2000))).to.equal(null);
		const unwound = g.opener.handleTxAckRbf({
			channelId: g.opener.getChannelId()!,
			fundingOutputContribution: -5n
		});
		const gAbort = findPayload(unwound, MessageType.TX_ABORT);
		expect(gAbort).to.not.equal(null);
		expect(decodeTxAbortMessage(gAbort!).data.toString('utf8')).to.contain(
			'negative'
		);
		expect(g.opener.getFullState().v2InFlight!.rbfAttempt).to.equal(0);
		expect(record.remoteContributionSats).to.not.equal(undefined);
	});

	it('an absent funding_output_contribution still means unchanged (issue 376)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const before = h.acceptor.getFullState();
		const capacityBefore = before.fundingSatoshis;
		const remoteBefore = before.v2InFlight!.remoteContributionSats;

		// Beignet peers predating the TLV omit it while keeping their
		// contribution, so absent must never be read as a withdrawal.
		const acked = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findPayload(acked, MessageType.TX_ACK_RBF)).to.not.equal(null);
		const after = h.acceptor.getFullState();
		expect(Number(after.fundingSatoshis)).to.equal(Number(capacityBefore));
		expect(
			Number(after.dualFundingSession!.getRemoteFundingSatoshis())
		).to.equal(Number(remoteBefore));
	});

	it('refuses a replacement that does not double-spend the completed attempt (issue 360)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const record = h.acceptor.getFullState().v2InFlight!;
		const attempt0Tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
		const fundingOut = attempt0Tx.outs[record.fundingOutputIndex];

		const acked = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findPayload(acked, MessageType.TX_ACK_RBF)).to.not.equal(null);

		// The opener's replacement arrives spending only FRESH prevouts: no
		// input of attempt 0 is double-spent, so both txs could confirm.
		// BOLT 2: the receiver MUST fail the negotiation.
		const fresh = makeRealPrevOut(250_000);
		expect(
			findError(
				h.acceptor.handleTxAddInput({
					channelId: h.acceptor.getChannelId()!,
					serialId: 0n,
					prevTx: fresh.prevTx,
					prevTxVout: 0,
					sequence: 0xfffffffd
				})
			)
		).to.equal(null);
		expect(
			findError(
				h.acceptor.handleTxAddOutput({
					channelId: h.acceptor.getChannelId()!,
					serialId: 2n,
					amountSats: BigInt(fundingOut.value),
					scriptPubkey: Buffer.from(fundingOut.script)
				})
			)
		).to.equal(null);
		expect(findError(h.acceptor.sendTxComplete())).to.equal(null);
		const result = h.acceptor.handleTxComplete();
		const abort = findPayload(result, MessageType.TX_ABORT);
		expect(abort, 'the non-conflicting replacement is refused').to.not.equal(
			null
		);
		expect(decodeTxAbortMessage(abort!).data.toString('utf8')).to.contain(
			'double-spend'
		);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.acceptor.getFullState().v2InFlight!.rbfAttempt).to.equal(0);
	});

	it('refuses a replacement paying less than the previous attempt (issue 360)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const record = h.acceptor.getFullState().v2InFlight!;
		const attempt0Tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
		const fundingOut = attempt0Tx.outs[record.fundingOutputIndex];
		// Inflate the RECORDED prevout values: the previous attempt now
		// appears to have paid an enormous fee, so any honest replacement
		// pays less and must be refused (BOLT 2's total-fee floor).
		record.inputPrevouts[0].valueSats += 10_000_000n;

		const acked = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(findPayload(acked, MessageType.TX_ACK_RBF)).to.not.equal(null);
		// An honest replacement: the opener re-spends its attempt-0 input
		// (satisfying the double-spend rule) plus a fresh one for the fee.
		expect(
			findError(
				h.acceptor.handleTxAddInput({
					channelId: h.acceptor.getChannelId()!,
					serialId: 0n,
					prevTx: h.openerPrev.prevTx,
					prevTxVout: 0,
					sequence: 0xfffffffd
				})
			)
		).to.equal(null);
		const topUp = makeRealPrevOut(200_000);
		expect(
			findError(
				h.acceptor.handleTxAddInput({
					channelId: h.acceptor.getChannelId()!,
					serialId: 4n,
					prevTx: topUp.prevTx,
					prevTxVout: 0,
					sequence: 0xfffffffd
				})
			)
		).to.equal(null);
		expect(
			findError(
				h.acceptor.handleTxAddOutput({
					channelId: h.acceptor.getChannelId()!,
					serialId: 2n,
					amountSats: BigInt(fundingOut.value),
					scriptPubkey: Buffer.from(fundingOut.script)
				})
			)
		).to.equal(null);
		expect(findError(h.acceptor.sendTxComplete())).to.equal(null);
		const result = h.acceptor.handleTxComplete();
		const abort = findPayload(result, MessageType.TX_ABORT);
		expect(abort).to.not.equal(null);
		expect(decodeTxAbortMessage(abort!).data.toString('utf8')).to.contain(
			"below the previous attempt's fee"
		);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('v2PreviousAttempts round-trips serialization; absent stays absent (issue 360)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const st = h.opener.getFullState();
		const prev = { ...st.v2InFlight! };
		st.v2PreviousAttempts = [prev];
		const json = JSON.parse(JSON.stringify(serializeChannelState(st)));
		const restored = deserializeChannelState(json);
		expect(restored.v2PreviousAttempts).to.have.length(1);
		const r = restored.v2PreviousAttempts![0];
		expect(r.fundingTxid.equals(prev.fundingTxid)).to.be.true;
		expect(r.fundingOutputIndex).to.equal(prev.fundingOutputIndex);
		expect(r.fundingTxHex).to.equal(prev.fundingTxHex);
		expect(r.sentTxSignatures).to.equal(prev.sentTxSignatures);
		expect(r.fullySigned).to.equal(prev.fullySigned);
		expect(r.rbfAttempt).to.equal(prev.rbfAttempt);
		expect(r.localContributionSats).to.equal(prev.localContributionSats);
		expect(r.inputPrevouts.length).to.equal(prev.inputPrevouts.length);

		delete json.v2PreviousAttempts;
		expect(deserializeChannelState(json).v2PreviousAttempts).to.equal(
			undefined
		);
	});

	it('per-attempt amounts round-trip; a legacy row without them stays absent (issue 376)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const st = h.opener.getFullState();
		const record = st.v2InFlight!;
		// Every record written now snapshots the amounts its commitment was
		// built at.
		expect(record.fundingSatoshis).to.not.equal(undefined);

		const json = JSON.parse(JSON.stringify(serializeChannelState(st)));
		const restored = deserializeChannelState(json).v2InFlight!;
		expect(Number(restored.fundingSatoshis!)).to.equal(
			Number(record.fundingSatoshis!)
		);
		expect(Number(restored.localBalanceMsat!)).to.equal(
			Number(record.localBalanceMsat!)
		);
		expect(Number(restored.remoteBalanceMsat!)).to.equal(
			Number(record.remoteBalanceMsat!)
		);
		expect(Number(restored.remoteChannelReserveSatoshis!)).to.equal(
			Number(record.remoteChannelReserveSatoshis!)
		);
		expect(Number(restored.localChannelReserveSatoshis!)).to.equal(
			Number(record.localChannelReserveSatoshis!)
		);

		// Rows persisted before contribution changes existed carry none, and
		// must deserialize as absent rather than as zero: those attempts share
		// the live amounts, and a zero here would wipe the channel's capacity
		// on the next rollback.
		delete json.v2InFlight.fundingSatoshis;
		delete json.v2InFlight.localBalanceMsat;
		delete json.v2InFlight.remoteBalanceMsat;
		delete json.v2InFlight.remoteChannelReserveSatoshis;
		delete json.v2InFlight.localChannelReserveSatoshis;
		const legacy = deserializeChannelState(json).v2InFlight!;
		expect(legacy.fundingSatoshis).to.equal(undefined);
		expect(legacy.localBalanceMsat).to.equal(undefined);
		expect(legacy.remoteBalanceMsat).to.equal(undefined);
		expect(legacy.remoteChannelReserveSatoshis).to.equal(undefined);
		expect(legacy.localChannelReserveSatoshis).to.equal(undefined);
	});

	it('re-derives the enforced reserve for a row that predates it (issue 379)', () => {
		// localChannelReserveSatoshis is optional INDEPENDENTLY of the amounts
		// group: rows written by the version that introduced per-attempt amounts
		// carry the other four and not this one, because the v2 open did not
		// derive it yet. Restoring such a row must re-derive from the attempt's
		// own capacity, never write undefined into a required bigint (which
		// throws on the next persist, and again in the inbound-HTLC gate).
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.opener.getFullState()))
		);
		delete json.v2InFlight.localChannelReserveSatoshis;
		json.localConfig.channelReserveSatoshis = '10000';
		// Such a row's REMOTE reserve was also written by that version, i.e. by
		// the capped helper, from the peer's dust limit alone and, on a leased
		// open, from the pre-lease-fee capacity. Restoring it verbatim would
		// reinstate the very defect this derivation fixes, so both sides are
		// re-derived. 1,000 stands in for any such stale value.
		json.v2InFlight.remoteChannelReserveSatoshis = '1000';

		const restored = deserializeChannelState(json);
		restored.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
		// A rebuilt channel, not the live one: restoreV2InFlight returns early
		// when a dual-funding session is already present.
		const revived = new Channel(restored, h.openerSigner);
		revived.restoreV2InFlight();
		const revivedState = revived.getFullState();
		expect(Number(revivedState.localConfig.channelReserveSatoshis)).to.equal(
			1_500
		);
		expect(Number(revivedState.remoteConfig.channelReserveSatoshis)).to.equal(
			1_500
		);

		// A row with no snapshot at all leaves the AMOUNTS untouched (those
		// attempts all shared the live amounts by construction) but still owes
		// both reserves a derivation: such a row predates the v2 open deriving
		// either one, and the load-time repairs defer to this method for any row
		// carrying a record, so nothing else would ever reach it (issue 387).
		const bare = JSON.parse(
			JSON.stringify(serializeChannelState(h.opener.getFullState()))
		);
		for (const field of [
			'fundingSatoshis',
			'localBalanceMsat',
			'remoteBalanceMsat',
			'remoteChannelReserveSatoshis',
			'localChannelReserveSatoshis'
		]) {
			delete bare.v2InFlight[field];
		}
		bare.localConfig.channelReserveSatoshis = '10000';
		bare.remoteConfig.channelReserveSatoshis = '10000';
		delete bare.channelReserveVersion;
		const bareState = deserializeChannelState(bare);
		bareState.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
		const liveCapacity = bareState.fundingSatoshis;
		const liveLocalMsat = bareState.localBalanceMsat;
		const bareChannel = new Channel(bareState, h.openerSigner);
		bareChannel.restoreV2InFlight();
		const bareAfter = bareChannel.getFullState();
		expect(Number(bareAfter.localConfig.channelReserveSatoshis)).to.equal(
			1_500
		);
		expect(Number(bareAfter.remoteConfig.channelReserveSatoshis)).to.equal(
			1_500
		);
		expect(bareAfter.channelReserveVersion).to.be.a('number');
		// The amounts really are left alone.
		expect(Number(bareAfter.fundingSatoshis)).to.equal(Number(liveCapacity));
		expect(Number(bareAfter.localBalanceMsat)).to.equal(Number(liveLocalMsat));
	});

	/**
	 * Issue 387: a v2 open recorded before #383 derived either reserve was never
	 * admitted against BOLT 2's initial-commitment rules either, so a restart can
	 * resume signature exchange on a split whose commitment #0 has no outputs at
	 * all. Refusing on load keeps our witnesses off the wire, which is the last
	 * point at which the funding can still be kept off chain.
	 */
	function legacyUnviableRow(opts: { broadcastable: boolean }): Channel {
		const h = driveToCommitmentExchange();
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.opener.getFullState()))
		);
		for (const field of [
			'fundingSatoshis',
			'localBalanceMsat',
			'remoteBalanceMsat',
			'remoteChannelReserveSatoshis',
			'localChannelReserveSatoshis'
		]) {
			delete json.v2InFlight[field];
		}
		delete json.channelReserveVersion;
		// A split whose every commitment output trims: our 1,062-sat dust limit
		// against the peer's 354, and a 1,244/355 split where the 183-sat fee we
		// owe as opener leaves 1,061.
		json.localConfig.dustLimitSatoshis = '1062';
		json.remoteConfig.dustLimitSatoshis = '354';
		json.fundingSatoshis = '1599';
		json.localBalanceMsat = '1244000';
		json.remoteBalanceMsat = '355000';
		json.v2InFlight.sentTxSignatures = false;
		json.v2InFlight.receivedTxSignatures = false;
		json.v2InFlight.fullySigned = false;
		// Broadcastable means the peer needs no witness bytes from us, so
		// dropping the record could not keep the funding off chain.
		json.v2InFlight.ourWalletInputIndices = opts.broadcastable ? [] : [0];
		json.v2InFlight.ourWitnesses = opts.broadcastable ? [] : [['00']];
		const state = deserializeChannelState(json);
		state.state = ChannelState.AWAITING_TX_SIGNATURES;
		return new Channel(state, h.openerSigner);
	}

	it('refuses to resume a legacy v2 open whose commitment #0 has no outputs (issue 387)', () => {
		const revived = legacyUnviableRow({ broadcastable: false });
		revived.restoreV2InFlight();
		expect(revived.refuseUnviableV2InFlight(), 'refused').to.equal('refused');
		const after = revived.getFullState();
		expect(after.state).to.equal(ChannelState.ERRORED);
		expect(after.v2InFlight).to.equal(null);
		expect(after.dualFundingSession).to.equal(null);
	});

	it('still resumes a legacy v2 open the peer can publish without us (issue 387)', () => {
		// Dropping the record would not stop the transaction, it would only
		// discard what the confirmation adoption needs and retire our own
		// rebroadcast obligation. Same unviable split as above.
		const revived = legacyUnviableRow({ broadcastable: true });
		revived.restoreV2InFlight();
		expect(revived.isV2AttemptBroadcastable(), 'broadcastable').to.equal(true);
		expect(revived.refuseUnviableV2InFlight(), 'left alone').to.equal('none');
		const after = revived.getFullState();
		expect(after.state).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(after.v2InFlight).to.not.equal(null);
	});

	it('an outputless replacement rolls back to the retained candidate, it does not resume (issue 387)', () => {
		// isV2AttemptBroadcastable is CHANNEL-wide: it answers true while any
		// retained attempt is publishable. Asking it about the current record
		// let a broadcastable previous attempt wave an unsigned, outputless
		// REPLACEMENT through, which then resumed and released tx_signatures.
		// The current record has to be asked about itself.
		const h = driveToCommitmentExchange();
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.opener.getFullState()))
		);
		const viableCapacity =
			json.v2InFlight.fundingSatoshis ?? json.fundingSatoshis;
		// The retained candidate: signed, so publishable, and viable.
		json.v2PreviousAttempts = [
			{
				...JSON.parse(JSON.stringify(json.v2InFlight)),
				sentTxSignatures: true,
				fundingSatoshis: viableCapacity,
				localBalanceMsat: json.localBalanceMsat,
				remoteBalanceMsat: json.remoteBalanceMsat
			}
		];
		// The current replacement: unsigned, needs witness bytes from us, and
		// its commitment #0 has no outputs at 1,062 against 354.
		json.localConfig.dustLimitSatoshis = '1062';
		json.remoteConfig.dustLimitSatoshis = '354';
		json.v2InFlight.sentTxSignatures = false;
		json.v2InFlight.receivedTxSignatures = false;
		json.v2InFlight.fullySigned = false;
		json.v2InFlight.ourWalletInputIndices = [0];
		json.v2InFlight.ourWitnesses = [['00']];
		json.v2InFlight.fundingSatoshis = '1599';
		json.v2InFlight.localBalanceMsat = '1244000';
		json.v2InFlight.remoteBalanceMsat = '355000';
		const state = deserializeChannelState(json);
		state.state = ChannelState.AWAITING_TX_SIGNATURES;
		const revived = new Channel(state, h.openerSigner);
		revived.restoreV2InFlight();
		// Precondition: the channel-wide answer is true here, which is exactly
		// what used to skip the check.
		expect(revived.isV2AttemptBroadcastable(), 'channel-wide').to.equal(true);

		expect(revived.refuseUnviableV2InFlight()).to.equal('rolled-back');
		const after = revived.getFullState();
		// The candidate is RETAINED and resumed, not condemned: the peer may
		// still publish it.
		expect(after.state).to.not.equal(ChannelState.ERRORED);
		expect(after.v2InFlight).to.not.equal(null);
		expect(after.v2InFlight!.sentTxSignatures).to.equal(true);
		expect(Number(after.fundingSatoshis)).to.equal(Number(viableCapacity));
		expect(after.v2PreviousAttempts ?? []).to.have.length(0);
	});

	it('the restore path is what refuses it, and reports why (issue 387)', () => {
		// Callable is not enough: the refusal is only worth anything if the load
		// the node actually performs runs it.
		const revived = legacyUnviableRow({ broadcastable: false });
		const mgr = new ChannelManager({
			localBasepoints: makeBasepoints(
				getPublicKey(crypto.randomBytes(32)),
				crypto.randomBytes(32)
			),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32)
		});
		const errors: string[] = [];
		mgr.on('error', (_id: Buffer | null, message: string) => {
			errors.push(message);
		});
		mgr.restoreChannel(
			revived,
			getPublicKey(crypto.randomBytes(32)).toString('hex')
		);
		expect(revived.getState()).to.equal(ChannelState.ERRORED);
		expect(revived.getFullState().v2InFlight).to.equal(null);
		expect(errors.join('|')).to.match(/no broadcastable output/);
	});

	it('the refusal is durable, so the unsafe row does not come back (issue 387)', () => {
		// Disposing of the open in memory only leaves the original
		// AWAITING_TX_SIGNATURES row on disk, where every restart restores and
		// re-refuses it. An ERRORED channel is never reconnected, so nothing
		// else would ever clear it.
		const h = driveToCommitmentExchange();
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.opener.getFullState()))
		);
		for (const field of [
			'fundingSatoshis',
			'localBalanceMsat',
			'remoteBalanceMsat',
			'remoteChannelReserveSatoshis',
			'localChannelReserveSatoshis'
		]) {
			delete json.v2InFlight[field];
		}
		delete json.channelReserveVersion;
		json.localConfig.dustLimitSatoshis = '1062';
		json.remoteConfig.dustLimitSatoshis = '354';
		json.fundingSatoshis = '1599';
		json.localBalanceMsat = '1244000';
		json.remoteBalanceMsat = '355000';
		json.v2InFlight.sentTxSignatures = false;
		json.v2InFlight.receivedTxSignatures = false;
		json.v2InFlight.fullySigned = false;
		json.v2InFlight.ourWalletInputIndices = [0];
		json.v2InFlight.ourWitnesses = [['00']];
		json.state = ChannelState.AWAITING_TX_SIGNATURES;

		const storage = new SqliteStorage(':memory:');
		storage.open();
		const idHex = h.opener.getChannelId()!.toString('hex');
		storage.saveChannel(idHex, deserializeChannelState(json), '02'.repeat(33));
		storage.saveChannelKeyIndex(idHex, 3);

		const node = new LightningNode(
			makeNodeConfig(31, { storage, recovery: { enabled: true } })
		);
		node.on('node:error', () => {});
		const restored = node.getChannelManager().listChannels();
		expect(restored).to.have.length(1);
		expect(restored[0].getState()).to.equal(ChannelState.ERRORED);
		// The row on DISK is what the next boot reads, so that is what has to
		// have changed.
		const rows = storage.loadAllChannels();
		expect(rows, 'the row is kept, not deleted').to.have.length(1);
		expect(rows[0].state.state, 'condemned on disk').to.equal(
			ChannelState.ERRORED
		);
		expect(rows[0].state.v2InFlight ?? null).to.equal(null);
		const persisted = rows[0].state;
		node.destroy();

		// And the next boot, which sees exactly those persisted bytes, finds it
		// already disposed of rather than resurrecting the open.
		const restart = new SqliteStorage(':memory:');
		restart.open();
		restart.saveChannel(idHex, persisted, '02'.repeat(33));
		restart.saveChannelKeyIndex(idHex, 3);
		const second = new LightningNode(
			makeNodeConfig(31, { storage: restart, recovery: { enabled: true } })
		);
		second.on('node:error', () => {});
		const again = second.getChannelManager().listChannels();
		expect(again).to.have.length(1);
		expect(again[0].getState()).to.equal(ChannelState.ERRORED);
		expect(again[0].getFullState().v2InFlight ?? null).to.equal(null);
		second.destroy();
	});

	it('leaves a viable legacy v2 open alone (issue 387)', () => {
		// The guard has to be observable in BOTH directions: an ordinary
		// 100,000/50,000 legacy row still resumes.
		const h = driveToCommitmentExchange();
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(h.opener.getFullState()))
		);
		for (const field of [
			'fundingSatoshis',
			'localBalanceMsat',
			'remoteBalanceMsat',
			'remoteChannelReserveSatoshis',
			'localChannelReserveSatoshis'
		]) {
			delete json.v2InFlight[field];
		}
		json.v2InFlight.sentTxSignatures = false;
		json.v2InFlight.receivedTxSignatures = false;
		json.v2InFlight.ourWalletInputIndices = [0];
		const state = deserializeChannelState(json);
		state.state = ChannelState.AWAITING_TX_SIGNATURES;
		const revived = new Channel(state, h.openerSigner);
		revived.restoreV2InFlight();
		expect(revived.refuseUnviableV2InFlight()).to.equal('none');
		expect(revived.getFullState().v2InFlight).to.not.equal(null);
		expect(revived.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
	});

	it('never errors a rollback or an adoption of a signed attempt (issue 387)', () => {
		// restoreV2InFlight is also the rollback and adoption path: the check
		// lives outside it because _rollbackToRetainedV2Attempt runs from
		// markForReestablish on every disconnect, and adoption runs on an
		// attempt that has already confirmed.
		const h = driveToCommitmentExchange();
		deliverCommitments(h);
		completeExchange(h);
		const record = h.acceptor.getFullState().v2InFlight!;
		h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000,
			fundingOutputContribution: record.remoteContributionSats + 20_000n
		});
		// The peer walks away: the retained attempt resumes through
		// restoreV2InFlight, and nothing about that is allowed to error.
		h.acceptor.handleTxAbort();
		expect(h.acceptor.getState()).to.not.equal(ChannelState.ERRORED);
		expect(h.acceptor.getFullState().v2InFlight).to.not.equal(null);
		h.acceptor.markForReestablish();
		expect(h.acceptor.getState()).to.not.equal(ChannelState.ERRORED);
		expect(h.acceptor.getFullState().v2InFlight).to.not.equal(null);
	});

	it('survives consecutive refusals and a refusal followed by an operator abort', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// Refusal 1: the exchange completes and leaves no stale latches.
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const refusal1 = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 1001
		});
		expect(findPayload(refusal1, MessageType.TX_ABORT)).to.not.equal(null);
		const echo1 = h.opener.handleTxAbort();
		expect(findPayload(echo1, MessageType.TX_ABORT)).to.not.equal(null);
		expect(h.acceptor.handleTxAbort()).to.deep.equal([]);

		// Refusal 2: a second request is neither blocked nor silently
		// swallowed by the first exchange's latch, on either side.
		expect(findError(h.opener.initiateTxRbf(2100))).to.equal(null);
		const refusal2 = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 1001
		});
		expect(
			findPayload(refusal2, MessageType.TX_ABORT),
			'the second refusal reaches the wire'
		).to.not.equal(null);
		const echo2 = h.opener.handleTxAbort();
		expect(findPayload(echo2, MessageType.TX_ABORT)).to.not.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(h.acceptor.handleTxAbort()).to.deep.equal([]);

		// An operator abort after the refusals must not be swallowed either:
		// the full handshake still runs and the aborter tears down at the
		// echo.
		const abortActions = h.opener.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);
		expect(findPayload(abortActions, MessageType.TX_ABORT)).to.not.equal(null);
		const peerAnswer = h.acceptor.handleTxAbort();
		expect(
			findPayload(peerAnswer, MessageType.TX_ABORT),
			'the peer answers the abort'
		).to.not.equal(null);
		const teardown = h.opener.handleTxAbort();
		expect(
			teardown.some((a) => a.type === ChannelActionType.PERSIST_STATE),
			'the echo completes the teardown'
		).to.be.true;
		expect(h.opener.getState()).to.equal(ChannelState.ERRORED);
	});

	it('answers a peer operator abort arriving after a refusal echo (issue 337)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// A refused RBF request completes its abort exchange: refusal out,
		// echo back, echo swallowed by the refuser's own latch.
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const refusal = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 1001
		});
		expect(findPayload(refusal, MessageType.TX_ABORT)).to.not.equal(null);
		expect(
			findPayload(h.opener.handleTxAbort(), MessageType.TX_ABORT)
		).to.not.equal(null);
		expect(h.acceptor.handleTxAbort()).to.deep.equal([]);

		// The refuser then aborts the attempt itself and waits for the echo
		// before its deferred teardown (signature release stays frozen). The
		// requester's latch from the refusal echo must not swallow it.
		const abortActions = h.acceptor.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);
		expect(findPayload(abortActions, MessageType.TX_ABORT)).to.not.equal(null);
		const answer = h.opener.handleTxAbort();
		expect(
			findPayload(answer, MessageType.TX_ABORT),
			'the abort is answered, not swallowed'
		).to.not.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.ERRORED);

		// The echo completes the aborter's deferred teardown.
		const teardown = h.acceptor.handleTxAbort();
		expect(
			teardown.some((a) => a.type === ChannelActionType.PERSIST_STATE),
			'the echo completes the teardown'
		).to.be.true;
		expect(h.acceptor.getState()).to.equal(ChannelState.ERRORED);
	});

	it('a broadcastable-keep echo stays latched: an abort retry is consumed, not answered (issue 337)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// The acceptor releases its witnesses: from here the opener can
		// complete and broadcast the funding tx without further bytes from
		// the acceptor, so the acceptor must keep the attempt on any abort.
		const accSig = h.acceptor.sendTxSignatures(
			h.acceptor.getFullState().fundingTxid!,
			h.acceptor.getFullState().fundingOutputIndex,
			h.acceptorWitness()
		);
		expect(findError(accSig)).to.equal(null);
		expect(
			findError(
				h.opener.handleTxSignatures(
					decodeTxSignaturesMessage(
						findPayload(accSig, MessageType.TX_SIGNATURES)!
					)
				)
			)
		).to.equal(null);

		// The opener aborts; the acceptor echoes and keeps.
		expect(findError(h.opener.abortDualFunding('operator cancelled'))).to.equal(
			null
		);
		const echo1 = h.acceptor.handleTxAbort();
		expect(
			findPayload(echo1, MessageType.TX_ABORT),
			'the abort is echoed'
		).to.not.equal(null);
		expect(h.acceptor.getState()).to.not.equal(ChannelState.ERRORED);
		expect(h.acceptor.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);

		// The operator retries before that echo is processed (legal: a
		// pending abort only bars RBF and rollback exchanges, not a
		// re-send). tx_abort has no exchange identifier, so the retained
		// side cannot tell the retry from a duplicate or an answer to its
		// own echo: the keep-echo's latch stays sticky and the retry is
		// consumed, never answered with a second echo (which could feed the
		// issue-294 loop). The retry is redundant anyway: the first echo,
		// already in flight, completes the aborter's exchange.
		const abort2 = h.opener.abortDualFunding('operator retry');
		expect(findError(abort2)).to.equal(null);
		expect(findPayload(abort2, MessageType.TX_ABORT)).to.not.equal(null);
		expect(
			h.acceptor.handleTxAbort(),
			'the retry is consumed, not answered'
		).to.deep.equal([]);
		expect(h.acceptor.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);

		// One delivered echo completes the aborter's deferred teardown.
		const teardown = h.opener.handleTxAbort();
		expect(
			teardown.some((a) => a.type === ChannelActionType.PERSIST_STATE),
			'the echo completes the teardown'
		).to.be.true;
		expect(h.opener.getState()).to.equal(ChannelState.ERRORED);
	});

	it('a kept zero-input attempt consumes further aborts without answering (issue 337)', () => {
		const h = driveToCommitmentExchange({ acceptorNoInput: true });
		deliverCommitments(h);

		// The opener aborts. The acceptor contributed no inputs, so the
		// opener can broadcast the recorded funding tx without it: the
		// acceptor echoes the abort but keeps the record, state and watch.
		expect(findError(h.opener.abortDualFunding('operator cancelled'))).to.equal(
			null
		);
		const echo1 = h.acceptor.handleTxAbort();
		expect(
			findPayload(echo1, MessageType.TX_ABORT),
			'the abort is echoed'
		).to.not.equal(null);
		expect(h.acceptor.getState()).to.not.equal(ChannelState.ERRORED);
		expect(h.acceptor.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);

		// The echo completes the opener's deferred teardown (its own side
		// is not broadcastable: its witnesses never left).
		const teardown = h.opener.handleTxAbort();
		expect(teardown.some((a) => a.type === ChannelActionType.PERSIST_STATE)).to
			.be.true;
		expect(h.opener.getState()).to.equal(ChannelState.ERRORED);

		// A further abort at the retained side is indistinguishable from a
		// duplicate or an answer to the keep-echo (tx_abort has no exchange
		// identifier), so the sticky latch consumes it without a second
		// echo, and the attempt stays kept.
		expect(
			h.acceptor.handleTxAbort(),
			'the next abort is consumed, not answered'
		).to.deep.equal([]);
		expect(h.acceptor.getState()).to.not.equal(ChannelState.ERRORED);
		expect(h.acceptor.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);
	});

	it('a zero-input aborter keeps the attempt at the echo and consumes later aborts (issue 337)', () => {
		// Before the commitment exchange completes, a zero-input acceptor
		// has not yet auto-released its empty tx_signatures, so an operator
		// abort of the recorded open is still legal, and its own side of
		// the attempt is already broadcastable (no witness bytes owed).
		const h = driveToCommitmentExchange({ acceptorNoInput: true });
		const abortActions = h.acceptor.abortDualFunding('going away');
		expect(findError(abortActions)).to.equal(null);
		expect(findPayload(abortActions, MessageType.TX_ABORT)).to.not.equal(null);

		// The opener answers and tears down (nothing broadcastable there).
		const answer = h.opener.handleTxAbort();
		expect(
			findPayload(answer, MessageType.TX_ABORT),
			'the abort is answered'
		).to.not.equal(null);
		expect(h.opener.getState()).to.equal(ChannelState.ERRORED);

		// The echo completes the aborter's exchange, but the attempt stays
		// kept: the peer holds a commitment_signed over a funding tx it can
		// complete without us.
		expect(
			h.acceptor.handleTxAbort(),
			'the echo completes the exchange'
		).to.deep.equal([]);
		expect(h.acceptor.getState()).to.not.equal(ChannelState.ERRORED);
		expect(h.acceptor.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);

		// A further abort at the retained side is indistinguishable from a
		// duplicate or an answer to our answer (tx_abort has no exchange
		// identifier), so the sticky latch consumes it without a second
		// echo, and the attempt stays kept.
		expect(
			h.acceptor.handleTxAbort(),
			'the next abort is consumed, not answered'
		).to.deep.equal([]);
		expect(h.acceptor.getState()).to.not.equal(ChannelState.ERRORED);
		expect(h.acceptor.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);
	});

	it('keeps the refusal-echo latch when the resumed release sent tx_signatures (issue 337)', () => {
		const h = driveToCommitmentExchange();
		deliverCommitments(h);

		// The opener stages its witnesses; it signs second (larger
		// contribution), so nothing leaves yet.
		const staged = h.opener.sendTxSignatures(
			h.opener.getFullState().fundingTxid!,
			h.opener.getFullState().fundingOutputIndex,
			h.openerWitness()
		);
		expect(findError(staged)).to.equal(null);
		expect(findPayload(staged, MessageType.TX_SIGNATURES)).to.equal(null);

		// The opener requests an RBF; the acceptor's tx_signatures (it
		// signs first) cross the request on the wire. The frozen release
		// holds while the request is unanswered.
		expect(findError(h.opener.initiateTxRbf(2000))).to.equal(null);
		const accSig = h.acceptor.sendTxSignatures(
			h.acceptor.getFullState().fundingTxid!,
			h.acceptor.getFullState().fundingOutputIndex,
			h.acceptorWitness()
		);
		expect(findError(accSig)).to.equal(null);
		const crossed = h.opener.handleTxSignatures(
			decodeTxSignaturesMessage(findPayload(accSig, MessageType.TX_SIGNATURES)!)
		);
		expect(findError(crossed)).to.equal(null);
		expect(
			findPayload(crossed, MessageType.TX_SIGNATURES),
			'the release stays frozen behind the pending request'
		).to.equal(null);

		// The acceptor refuses the crossed request (delivered below the 25/24
		// floor; a broadcastable attempt itself no longer refuses in the
		// issue-360 spec window). The refusal completes the exchange at the
		// opener: echo out, and the thawed release sends the staged
		// witnesses in the same batch.
		const refusal = h.acceptor.handleTxInitRbf({
			channelId: h.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 1001
		});
		expect(findPayload(refusal, MessageType.TX_ABORT)).to.not.equal(null);
		const answer = h.opener.handleTxAbort();
		expect(
			findPayload(answer, MessageType.TX_ABORT),
			'the refusal is echoed'
		).to.not.equal(null);
		expect(
			findPayload(answer, MessageType.TX_SIGNATURES),
			'the resumed release sends the staged witnesses'
		).to.not.equal(null);

		// Our witnesses have left: BOLT 2 forbids sending tx_abort after
		// transmitting tx_signatures, so the latch stays sticky and any
		// later inbound abort is consumed, never answered with an echo.
		expect(
			h.opener.handleTxAbort(),
			'no tx_abort leaves after tx_signatures'
		).to.deep.equal([]);
	});

	it('freezes commitment and signature release while an abort is pending, and serializes abort with RBF', () => {
		// Opener signs first (smaller contribution) so a crossed
		// commitment_signed would trigger its release.
		const h = driveToCommitmentExchange({
			acceptorPrev: makeRealPrevOut(300_000)
		});
		const abortActions = h.opener.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);

		// Crossed commitment: no signature may leave behind our own abort.
		const crossed = h.opener.handleCommitmentSigned(
			decodeCommitmentSignedMessage(h.acceptorCommit)
		);
		expect(findError(crossed)).to.equal(null);
		expect(
			findPayload(crossed, MessageType.TX_SIGNATURES),
			'the release is frozen while the abort is un-echoed'
		).to.equal(null);
		expect(h.opener.getFullState().v2InFlight!.sentTxSignatures).to.be.false;

		// The caller-driven release honors the same freeze.
		expect(
			findError(
				h.opener.sendTxSignatures(
					h.opener.getFullState().fundingTxid!,
					h.opener.getFullState().fundingOutputIndex,
					h.openerWitness()
				)
			)
		).to.contain('frozen');

		// Abort and RBF are mutually exclusive in both orders.
		expect(findError(h.opener.initiateTxRbf(2000))).to.contain(
			'awaiting its echo'
		);
		const g = driveToCommitmentExchange();
		deliverCommitments(g);
		expect(findError(g.opener.initiateTxRbf(2000))).to.equal(null);
		expect(findError(g.opener.abortDualFunding('too eager'))).to.contain(
			'awaiting its answer'
		);
		// A peer's RBF request crossing OUR abort: the abort already on the
		// wire serves as its refusal, so nothing more leaves (no second
		// abort, never an ack) and the pending teardown is CANCELLED; the
		// crossed exchange resolves with both sides keeping the attempt.
		const k = driveToCommitmentExchange();
		deliverCommitments(k);
		expect(findError(k.acceptor.abortDualFunding('going away'))).to.equal(null);
		const crossedInit = k.acceptor.handleTxInitRbf({
			channelId: k.acceptor.getChannelId()!,
			locktime: 0,
			feerate: 2000
		});
		expect(crossedInit).to.deep.equal([]);
		expect(k.acceptor.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		// The requester's echo of our abort then completes a refusal
		// exchange, never a teardown: the attempt survives on this side too.
		expect(k.acceptor.handleTxAbort()).to.deep.equal([]);
		expect(k.acceptor.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(k.acceptor.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);
	});

	it('keeps a zero-input attempt when the peer reestablishes without next_funding', async function () {
		// Node-level: the acceptor contributed nothing, so the opener can
		// broadcast the recorded funding tx without any witness bytes from
		// the acceptor. A peer claiming (or appearing) to have forgotten the
		// open must not make the acceptor discard what the opener can still
		// publish.
		const opener = new LightningNode(
			makeNodeConfig(81, {
				storage: (() => {
					const s = new SqliteStorage(':memory:');
					s.open();
					return s;
				})(),
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(82));
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
		expect(
			acceptorChannel.getFullState().v2InFlight!.ourWalletInputIndices
		).to.have.length(0);

		managerOf(opener).handlePeerDisconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		const msg = reestablishOf(channel.createReestablish());
		delete msg.nextFundingTxid;
		delete msg.nextFundingRetransmitFlags;
		const answer = acceptorChannel.handleReestablish(msg);
		expect(findError(answer)).to.equal(null);
		expect(
			acceptorChannel.getState(),
			'the broadcastable attempt is not unwound'
		).to.not.equal(ChannelState.ERRORED);
		expect(acceptorChannel.getFullState().v2InFlight).to.not.be.oneOf([
			null,
			undefined
		]);

		opener.destroy();
		acceptor.destroy();
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
		expect(findError(actions), 'the request is refused locally').to.not.equal(
			null
		);
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
		// EXACTLY one: the flush runs before the channel_ready retransmit arm
		// and sets localChannelReady, so without the queued-send dedup the
		// retransmit fired too and one reestablish put two channel_ready
		// messages on the wire (issue 421).
		expect(
			opHandle.filter(
				(a) =>
					a.type === ChannelActionType.SEND_MESSAGE &&
					a.messageType === MessageType.CHANNEL_READY
			).length,
			'exactly one channel_ready leaves (issue 421)'
		).to.equal(1);
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

	it('verifies P2TR peer inputs: key-spend with SIGHASH_DEFAULT or explicit SIGHASH_ALL', () => {
		const h = driveToCommitmentExchange({
			acceptorPrev: makeRealP2trPrevOut(60_000)
		});
		deliverCommitments(h);
		const cid = h.opener.getChannelId()!;
		const txid = Buffer.from(h.opener.getFullState().v2InFlight!.fundingTxid);
		const genuine = h.acceptorWitness();

		// A 64-byte witness is judged against the SIGHASH_DEFAULT message,
		// not waved through: this signature was made over the SIGHASH_ALL
		// message, so presented in the shorthand form it must fail the
		// schnorr verify (the hash type byte is part of the preimage).
		let actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[genuine[0][0].subarray(0, 64)]]
		});
		expect(findError(actions)).to.contain('does not verify');

		// A 65-byte signature with a non-ALL type byte is refused.
		const wrongType = Buffer.from(genuine[0][0]);
		wrongType[64] = 0x02;
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[wrongType]]
		});
		expect(findError(actions)).to.contain('explicit SIGHASH_ALL');

		// A 65-byte signature with a trailing 0x00 is refused: BIP 341
		// forbids the explicit form for SIGHASH_DEFAULT.
		const explicitDefault = Buffer.from(genuine[0][0]);
		explicitDefault[64] = 0x00;
		actions = h.opener.handleTxSignatures({
			channelId: cid,
			txid,
			witnesses: [[explicitDefault]]
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

	it('accepts a genuine 64-byte SIGHASH_DEFAULT P2TR key-spend witness', () => {
		// Bitcoin Core and libwally sign taproot inputs with SIGHASH_DEFAULT
		// by default, so eclair and CLN peers emit the 64-byte shorthand.
		const h = driveToCommitmentExchange({
			acceptorPrev: makeRealP2trPrevOut(60_000, 'default')
		});
		deliverCommitments(h);
		const cid = h.opener.getChannelId()!;
		const txid = Buffer.from(h.opener.getFullState().v2InFlight!.fundingTxid);
		const genuine = h.acceptorWitness();
		expect(genuine[0][0].length).to.equal(64);

		const actions = h.opener.handleTxSignatures({
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

// Lease-seller rates for tests whose ACCEPTOR must contribute inputs: a
// zero-input acceptor's attempt is broadcastable by the opener alone, so it
// refuses RBF; the lease is the node-level path to a contributing acceptor.
const LEASE_RATES: ILeaseRates = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100,
	leaseFeeBaseSat: 500,
	channelFeeMaxBaseMsat: 1_000,
	channelFeeMaxProportionalThousandths: 10
};

/** openChannelV2 params buying a lease so the acceptor contributes. */
function leaseOpenParams(): {
	fundingSatoshis: bigint;
	fundingFeeratePerkw: number;
	requestFunds: { requestedSats: bigint; blockheight: number };
	maxLeaseRates: ILeaseRates;
} {
	return {
		fundingSatoshis: 150_000n,
		fundingFeeratePerkw: 1000,
		requestFunds: { requestedSats: 50_000n, blockheight: 800_000 },
		maxLeaseRates: LEASE_RATES
	};
}

function makeNodeConfig(
	seedId: number,
	opts: {
		storage?: SqliteStorage;
		recovery?: INodeConfig['recovery'];
		fundingProvider?: IFundingProvider;
		leaseRates?: ILeaseRates;
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

/**
 * A provider that hands out the given inputs one selection at a time, so a
 * contribution raise can be served with coins the open did not already
 * register. Records what was asked for and what was released.
 */
function recordingFundingProvider(
	inputs: ISpliceWalletInput[]
): IFundingProvider & {
	selectCalls: bigint[];
	dualCalls: Array<{ amountSats: bigint; initiator: boolean; topUp: boolean }>;
	released: Array<{ txid: string; vout: number }>;
} {
	const changeScript = bitcoin.payments.p2wpkh({
		hash: crypto.randomBytes(20)
	}).output!;
	// selectCalls records every amount asked of the wallet whichever selector
	// served it; dualCalls additionally records the dual-funding-aware calls
	// with the role they were priced for (issue #380).
	const selectCalls: bigint[] = [];
	const dualCalls: Array<{
		amountSats: bigint;
		initiator: boolean;
		topUp: boolean;
	}> = [];
	const released: Array<{ txid: string; vout: number }> = [];
	let next = 0;
	const take = (
		amountSats: bigint
	): { inputs: ISpliceWalletInput[]; changeScript: Buffer } => {
		selectCalls.push(amountSats);
		const input = inputs[Math.min(next, inputs.length - 1)];
		next++;
		return { inputs: [input], changeScript };
	};
	return {
		selectCalls,
		dualCalls,
		released,
		buildFundingTransaction: async () => {
			throw new Error('v1 funding must not run for a v2 open');
		},
		broadcastTransaction: async () => 'unused',
		selectSpliceInputs: async (amountSats: bigint) => take(amountSats),
		selectDualFundingInputs: async (
			amountSats: bigint,
			_feeratePerKw: number,
			initiator: boolean,
			topUp = false
		) => {
			dualCalls.push({ amountSats, initiator, topUp });
			return take(amountSats);
		},
		selectMaxDualFundingInputs: async () => ({
			inputs: [inputs[0]],
			changeScript
		}),
		releaseInputPledges: async (outpoints) => {
			released.push(...outpoints);
		}
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

/**
 * Wait until pred() holds, or give up after `ms`.
 *
 * Two phases on purpose. The first 25 ms drain the microtask and immediate
 * queues at full speed, so a predicate that only needs the pending promise
 * callbacks (the funding provider's async input selection, a storage write's
 * continuation) resolves with no added latency. After that it parks on a real
 * sleep: the old body spun on setImmediate for the WHOLE deadline, so every
 * call whose predicate is EXPECTED to stay false held a core at 100% until it
 * expired. Under mocha --parallel that is one pegged core per worker.
 *
 * Still returns silently on timeout. Several call sites deliberately wait on a
 * predicate that must never become true.
 */
async function settle(pred: () => boolean, ms = 3000): Promise<void> {
	const deadline = Date.now() + ms;
	const spinUntil = Math.min(deadline, Date.now() + 25);
	while (Date.now() < spinUntil) {
		if (pred()) return;
		await new Promise((resolve) => setImmediate(resolve));
	}
	while (Date.now() < deadline) {
		if (pred()) return;
		await new Promise((resolve) => setTimeout(resolve, 5));
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
		const acceptor = new LightningNode(
			makeNodeConfig(62, {
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		// Strand the exchange inside the RBF window: the acceptor never sees
		// our commitment_signed, so neither side releases tx_signatures.
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		const attempt0Txid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);

		// The real production path: the opener requests, the peer acks, the
		// ack restarts and reprices the interactive-tx exchange, and the
		// replacement negotiates through to its own signatures. Capture the
		// funding txid each side's record holds at the instant its
		// replacement commitment_signed leaves: the commitment MUST spend
		// the replacement outpoint, never the retained attempt 0's.
		wire.clearDrops();
		const commitmentRecordTxids: Buffer[] = [];
		const captureAt = (node: LightningNode, ch: () => Channel | undefined) =>
			node.on('message:outbound', (_p: string, type: number) => {
				if (type === MessageType.COMMITMENT_SIGNED) {
					const rec = ch()?.getFullState().v2InFlight;
					if (rec) commitmentRecordTxids.push(Buffer.from(rec.fundingTxid));
				}
			});
		captureAt(opener, () => channel);
		captureAt(acceptor, () => managerOf(acceptor).getChannel(channelId));
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

		// Every replacement commitment_signed left with the record already
		// describing the replacement: no commitment ever signed attempt 0's
		// outpoint during the renegotiation (both peers would otherwise lack
		// a valid unilateral exit if attempt 1 confirms).
		expect(commitmentRecordTxids.length).to.be.greaterThan(1);
		for (const txid of commitmentRecordTxids) {
			expect(
				txid.equals(openerRecord.fundingTxid),
				'commitment signed over the replacement outpoint'
			).to.be.true;
		}

		// A restored attempt 1 keeps its record: the rebuilt session carries
		// the record's attempt number, so the next sync must never mistake
		// it for retained rollback state and erase it.
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(channel.getFullState()))
		);
		const restored = deserializeChannelState(json);
		const revived = new Channel(restored);
		revived.restoreV2InFlight();
		expect(
			restored.dualFundingSession!.getRbfCount(),
			'the restored session carries the attempt number'
		).to.equal(1);
		expect(revived.getFullState().v2InFlight!.rbfAttempt).to.equal(1);

		opener.destroy();
		acceptor.destroy();
	});

	// Drive a completed v2 open, RBF it post-signatures through the public
	// API, and return everything the adoption tests need (issue 360).
	async function driveSpecWindowRbf(
		seedA: number,
		seedB: number
	): Promise<{
		opener: LightningNode;
		acceptor: LightningNode;
		channel: Channel;
		acceptorChannel: Channel;
		channelId: Buffer;
		attempt0Txid: Buffer;
		attempt1Txid: Buffer;
	}> {
		const opener = new LightningNode(
			makeNodeConfig(seedA, {
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
			makeNodeConfig(seedB, {
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		wireNodes(opener, acceptor);

		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
		await settle(
			() =>
				channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED &&
				!!channel.getFullState().v2InFlight?.fullySigned
		);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		await settle(
			() =>
				acceptorChannel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		const attempt0Txid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);

		// The public API drives the whole replacement (issue 360).
		const result = opener.rbfOpenChannelV2(channelId, 2000);
		expect(result.ok, result.error).to.equal(true);
		await settle(
			() =>
				channel.getFullState().v2InFlight?.rbfAttempt === 1 &&
				!!channel.getFullState().v2InFlight?.fullySigned &&
				acceptorChannel.getFullState().v2InFlight?.rbfAttempt === 1 &&
				!!acceptorChannel.getFullState().v2InFlight?.fullySigned
		);
		const attempt1Txid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);
		return {
			opener,
			acceptor,
			channel,
			acceptorChannel,
			channelId,
			attempt0Txid,
			attempt1Txid
		};
	}

	/**
	 * A plain (non-lease) v2 open driven to a completed attempt 0, whose
	 * contribution the opener may then change. Lease opens keep the refusal,
	 * so the spec-window helper above cannot serve these.
	 */
	async function driveNonLeaseOpen(
		seedA: number,
		seedB: number,
		openerInputs: ISpliceWalletInput[],
		open?: { fundingSatoshis?: bigint; fundingFeeratePerkw?: number }
	): Promise<{
		opener: LightningNode;
		acceptor: LightningNode;
		channel: Channel;
		acceptorChannel: Channel;
		channelId: Buffer;
		provider: ReturnType<typeof recordingFundingProvider>;
		attempt0Txid: Buffer;
	}> {
		const provider = recordingFundingProvider(openerInputs);
		const opener = new LightningNode(
			makeNodeConfig(seedA, { fundingProvider: provider })
		);
		const acceptor = new LightningNode(makeNodeConfig(seedB, {}));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		wireNodes(opener, acceptor);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: open?.fundingSatoshis ?? 100_000n,
			fundingFeeratePerkw: open?.fundingFeeratePerkw ?? 1000
		});
		await settle(
			() =>
				channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED &&
				!!channel.getFullState().v2InFlight?.fullySigned
		);
		// Fail here rather than leaving callers to trip over a null channel id:
		// an open that aborted is the interesting fact, not the TypeError.
		expect(channel.getState(), 'the v2 open did not complete').to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		await settle(
			() =>
				acceptorChannel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		return {
			opener,
			acceptor,
			channel,
			acceptorChannel,
			channelId,
			provider,
			attempt0Txid: Buffer.from(channel.getFullState().v2InFlight!.fundingTxid)
		};
	}

	it('folds sub-dust change into the fee instead of aborting the open (issue 380)', async function () {
		// Exact-parity selection can leave change in the band between the
		// P2WPKH dust limit (294) and the interactive-tx floor (546): one
		// 100_000 coin covers a 99_005 contribution plus its 700-sat fee at
		// 1000 sat/kw with 295 sats over. Emitting that as change fails our own
		// builder's dust check (and the peer's), aborting a fundable open.
		const t = await driveNonLeaseOpen(195, 196, [makeWalletInput(100_000)], {
			fundingSatoshis: 99_005n,
			fundingFeeratePerkw: 1000
		});
		try {
			expect(t.channel.getState()).to.equal(
				ChannelState.AWAITING_FUNDING_CONFIRMED
			);
			const tx = bitcoin.Transaction.fromHex(
				t.channel.getFullState().v2InFlight!.fundingTxHex
			);
			// The 295 sats became extra fee rather than a rejected output.
			expect(tx.outs, 'no change output was added').to.have.length(1);
			expect(tx.outs[0].value).to.equal(99_005);
			const paidFee = 100_000 - 99_005;
			expect(paidFee).to.equal(995);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('still emits change at or above the interactive-tx dust floor (issue 380)', async function () {
		// The other side of the same boundary: 1300 sats of change clears the
		// 546-sat floor, so it must reach the funding tx rather than be paid
		// away as fee.
		const t = await driveNonLeaseOpen(197, 198, [makeWalletInput(100_000)], {
			fundingSatoshis: 98_000n,
			fundingFeeratePerkw: 1000
		});
		try {
			expect(t.channel.getState()).to.equal(
				ChannelState.AWAITING_FUNDING_CONFIRMED
			);
			const tx = bitcoin.Transaction.fromHex(
				t.channel.getFullState().v2InFlight!.fundingTxHex
			);
			expect(tx.outs, 'funding output plus change').to.have.length(2);
			const values = tx.outs.map((o) => o.value).sort((a, b) => a - b);
			expect(values).to.deep.equal([1_300, 98_000]);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('sizes the open and its raise with the dual-funding selector (issue 380)', async function () {
		const topUp = makeWalletInput(120_000);
		const t = await driveNonLeaseOpen(193, 194, [
			makeWalletInput(120_000),
			topUp
		]);
		try {
			// The open itself: a fresh contribution priced as the initiator.
			expect(t.provider.dualCalls).to.deep.equal([
				{ amountSats: 100_000n, initiator: true, topUp: false }
			]);
			const res = t.opener.rbfOpenChannelV2(
				t.channelId,
				2000,
				undefined,
				150_000n
			);
			expect(res.ok, res.error).to.equal(true);
			await settle(
				() =>
					t.channel.getFullState().v2InFlight?.rbfAttempt === 1 &&
					!!t.channel.getFullState().v2InFlight?.fullySigned
			);
			// The shortfall too: RBF initiation is opener-only, so the top-up is
			// priced with the initiator's fee share and never with the splice
			// weight, which reserves for a shared funding input a v2 open funding
			// transaction does not have.
			expect(t.provider.dualCalls).to.have.length(2);
			expect(t.provider.dualCalls[1].initiator).to.equal(true);
			expect(t.provider.dualCalls[1].amountSats > 0n).to.equal(true);
			// topUp: the shortfall already covers the fixed fee terms over the
			// registered inputs, so only the marginal per-input weight is owed.
			expect(t.provider.dualCalls[1].topUp).to.equal(true);
			expect(
				t.provider.selectCalls,
				'every wallet request went through the dual-funding selector'
			).to.deep.equal(t.provider.dualCalls.map((c) => c.amountSats));
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('lowers our own contribution without touching the wallet (issue 376)', async function () {
		const t = await driveNonLeaseOpen(131, 132, [makeWalletInput(200_000)]);
		try {
			const before = t.channel.getFullState().fundingSatoshis;
			const callsBefore = t.provider.selectCalls.length;
			// A decrease is funded by the inputs already registered, so it is
			// answered synchronously and needs no coin selection.
			const res = t.opener.rbfOpenChannelV2(
				t.channelId,
				2000,
				undefined,
				80_000n
			);
			expect(res.ok, res.error).to.equal(true);
			expect(t.provider.selectCalls.length, 'no wallet selection').to.equal(
				callsBefore
			);
			await settle(
				() =>
					t.channel.getFullState().v2InFlight?.rbfAttempt === 1 &&
					!!t.channel.getFullState().v2InFlight?.fullySigned &&
					t.acceptorChannel.getFullState().v2InFlight?.rbfAttempt === 1
			);
			for (const side of [t.channel, t.acceptorChannel]) {
				const st = side.getFullState();
				expect(
					Number(
						st.v2InFlight!.localContributionSats +
							st.v2InFlight!.remoteContributionSats
					)
				).to.equal(80_000);
				expect(Number(st.fundingSatoshis)).to.equal(80_000);
				expect(Number(st.fundingSatoshis)).to.be.lessThan(Number(before));
			}
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('raises our own contribution with a wallet top-up (issue 376)', async function () {
		// The registered input cannot cover 150k, so the raise needs a second.
		const topUp = makeWalletInput(120_000);
		const t = await driveNonLeaseOpen(133, 134, [
			makeWalletInput(120_000),
			topUp
		]);
		try {
			const callsBefore = t.provider.selectCalls.length;
			const res = t.opener.rbfOpenChannelV2(
				t.channelId,
				2000,
				undefined,
				150_000n
			);
			expect(res.ok, res.error).to.equal(true);
			await settle(
				() =>
					t.channel.getFullState().v2InFlight?.rbfAttempt === 1 &&
					!!t.channel.getFullState().v2InFlight?.fullySigned &&
					t.acceptorChannel.getFullState().v2InFlight?.rbfAttempt === 1
			);
			expect(
				t.provider.selectCalls.length,
				'the shortfall was requested from the wallet'
			).to.equal(callsBefore + 1);
			for (const side of [t.channel, t.acceptorChannel]) {
				expect(Number(side.getFullState().fundingSatoshis)).to.equal(150_000);
			}
			// BOLT 2 still holds: the replacement double-spends attempt 0.
			const st = t.channel.getFullState();
			const prevTx = bitcoin.Transaction.fromHex(
				st.v2PreviousAttempts![0].fundingTxHex
			);
			const newTx = bitcoin.Transaction.fromHex(st.v2InFlight!.fundingTxHex);
			const newIns = new Set(
				newTx.ins.map((i) => `${i.hash.toString('hex')}:${i.index}`)
			);
			expect(
				prevTx.ins.some((i) =>
					newIns.has(`${i.hash.toString('hex')}:${i.index}`)
				),
				'the replacement still double-spends attempt 0'
			).to.be.true;
			expect(newTx.ins.length, 'the top-up input joined the set').to.equal(
				prevTx.ins.length + 1
			);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a refused contribution raise hands its top-up pledges back (issue 376)', async function () {
		const t = await driveNonLeaseOpen(135, 136, [
			makeWalletInput(120_000),
			makeWalletInput(120_000)
		]);
		try {
			// The acceptor refuses anything above its cap, so the replacement
			// dies attempt-scoped and the coins selected for it are freed.
			t.acceptorChannel.setMaxFundingSatoshis(120_000n);
			const res = t.opener.rbfOpenChannelV2(
				t.channelId,
				2000,
				undefined,
				150_000n
			);
			expect(res.ok, res.error).to.equal(true);
			await settle(() => t.provider.released.length > 0);
			expect(t.provider.released.length).to.be.greaterThan(0);
			// Attempt 0 survives on both sides.
			for (const side of [t.channel, t.acceptorChannel]) {
				expect(side.getFullState().v2InFlight!.rbfAttempt).to.equal(0);
			}
			expect(
				t.channel.getFullState().v2InFlight!.fundingTxid.equals(t.attempt0Txid)
			).to.be.true;
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a raise never contributes a coin the open already spends (issue 376)', async function () {
		const shared = makeWalletInput(120_000);
		// The wallet hands back the SAME coin the open already registered: its
		// pledge lapsed while the attempt sat unsigned. Contributing it twice
		// would build a funding tx with a duplicate prevout.
		const t = await driveNonLeaseOpen(147, 148, [shared, shared]);
		try {
			const res = t.opener.rbfOpenChannelV2(
				t.channelId,
				2000,
				undefined,
				150_000n
			);
			expect(res.ok).to.equal(true);
			await settle(
				() => t.channel.getFullState().v2InFlight?.rbfAttempt === 1,
				5_000
			);
			const st = t.channel.getFullState();
			// Dropping the duplicate leaves only the 120k already registered,
			// which cannot fund a 150k contribution, so the raise is refused
			// and attempt 0 stands. Keeping it would have looked affordable
			// (the coin counted twice) and produced a replacement spending the
			// same outpoint twice: consensus-invalid.
			expect(
				st.v2InFlight!.rbfAttempt,
				'the unaffordable raise was refused, not negotiated'
			).to.equal(0);
			for (const rec of [st.v2InFlight!, ...(st.v2PreviousAttempts ?? [])]) {
				const tx = bitcoin.Transaction.fromHex(rec.fundingTxHex);
				const outpoints = tx.ins.map(
					(i) => `${i.hash.toString('hex')}:${i.index}`
				);
				expect(
					new Set(outpoints).size,
					'no duplicate prevout in any funding tx'
				).to.equal(outpoints.length);
			}
			// And the coin attempt 0 actually spends was NEVER handed back:
			// unfreezing it would let the next wallet spend orphan the channel.
			const sharedTxid = bitcoin.Transaction.fromBuffer(shared.prevTx).getId();
			expect(
				t.provider.released.some(
					(o) => o.txid === sharedTxid && o.vout === shared.prevOutputIndex
				),
				'the registered funding coin was never released'
			).to.equal(false);
			const attempt0Tx = bitcoin.Transaction.fromHex(
				st.v2InFlight!.fundingTxHex
			);
			expect(
				attempt0Tx.ins.some(
					(i) =>
						Buffer.from(i.hash).reverse().toString('hex') === sharedTxid &&
						i.index === shared.prevOutputIndex
				),
				'attempt 0 does spend that coin, so releasing it would have been unsafe'
			).to.equal(true);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a raise refused before the wire still hands its top-up pledges back (issue 376)', async function () {
		const t = await driveNonLeaseOpen(145, 146, [
			makeWalletInput(120_000),
			makeWalletInput(120_000)
		]);
		try {
			// Refused locally by the BOLT 2 feerate floor, so nothing is sent and
			// the latch is never installed: the selected coins are held only by
			// the request itself and would otherwise stay frozen until the
			// wallet's pledge TTL.
			const res = t.opener.rbfOpenChannelV2(
				t.channelId,
				1,
				undefined,
				150_000n
			);
			expect(res.ok).to.equal(true); // optimistic: the raise needs a top-up
			await settle(() => t.provider.released.length > 0);
			expect(
				t.provider.released.length,
				'the never-registered top-up was released'
			).to.be.greaterThan(0);
			expect(t.channel.getFullState().v2InFlight!.rbfAttempt).to.equal(0);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('rejects an out-of-range contribution at the API boundary (issue 376)', async function () {
		const t = await driveNonLeaseOpen(137, 138, [makeWalletInput(200_000)]);
		try {
			expect(() =>
				t.opener.rbfOpenChannelV2(t.channelId, 2000, undefined, 0n)
			).to.throw('positive bigint');
			expect(() =>
				t.opener.rbfOpenChannelV2(t.channelId, 2000, undefined, -1n)
			).to.throw('positive bigint');
			expect(() =>
				t.opener.rbfOpenChannelV2(
					t.channelId,
					2000,
					undefined,
					0x8000000000000000n
				)
			).to.throw('funding_output_contribution range');
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a post-signatures RBF renegotiates to completion through the public API (issue 360)', async function () {
		const t = await driveSpecWindowRbf(101, 102);
		try {
			expect(t.attempt1Txid.equals(t.attempt0Txid)).to.be.false;
			for (const side of [t.channel, t.acceptorChannel]) {
				const st = side.getFullState();
				expect(st.state).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
				expect(st.v2InFlight!.fundingFeeratePerkw).to.equal(2000);
				expect(st.v2InFlight!.fundingTxid.equals(t.attempt1Txid)).to.be.true;
				// The superseded broadcastable attempt is retained durably and
				// stays a live candidate.
				expect(st.v2PreviousAttempts).to.have.length(1);
				const prev = st.v2PreviousAttempts![0];
				expect(prev.fundingTxid.equals(t.attempt0Txid)).to.be.true;
				expect(prev.rbfAttempt).to.equal(0);
				expect(prev.fullySigned).to.equal(true);
				expect(side.isV2AttemptBroadcastable()).to.equal(true);
				// The replacement double-spends attempt 0 (reused inputs).
				const prevTx = bitcoin.Transaction.fromHex(prev.fundingTxHex);
				const newTx = bitcoin.Transaction.fromHex(st.v2InFlight!.fundingTxHex);
				const newIns = new Set(
					newTx.ins.map((i) => `${i.hash.toString('hex')}:${i.index}`)
				);
				expect(
					prevTx.ins.some((i) =>
						newIns.has(`${i.hash.toString('hex')}:${i.index}`)
					),
					'the replacement double-spends attempt 0'
				).to.be.true;
				// The staged rebroadcast follows the newest attempt.
				expect(st.pendingFundingTxHex).to.equal(st.v2InFlight!.fundingTxHex);
			}
			// A second bump stacks another candidate behind the first.
			const again = t.opener.rbfOpenChannelV2(t.channelId, 4000);
			expect(again.ok, again.error).to.equal(true);
			await settle(
				() =>
					t.channel.getFullState().v2InFlight?.rbfAttempt === 2 &&
					!!t.channel.getFullState().v2InFlight?.fullySigned &&
					t.acceptorChannel.getFullState().v2InFlight?.rbfAttempt === 2
			);
			expect(t.channel.getFullState().v2PreviousAttempts).to.have.length(2);
			expect(
				t.channel
					.getFullState()
					.v2PreviousAttempts![1].fundingTxid.equals(t.attempt1Txid)
			).to.be.true;
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('an ERRORED channel adopts a superseded attempt that confirms (issue 376 review)', async function () {
		const t = await driveSpecWindowRbf(149, 150);
		try {
			// A peer error fails the channel while the signed replacement is
			// current and attempt 0 is retained as a live candidate.
			expect(t.channel.markErrored()).to.equal(true);
			expect(t.channel.getState()).to.equal(ChannelState.ERRORED);
			expect(t.channel.getFullState().v2PreviousAttempts).to.have.length(1);

			// Attempt 0 wins the race. ERRORED is force-closeable, so this
			// confirmation still decides which funding any exit must spend; it
			// used to fall through the state gate and be dropped silently,
			// leaving no stamp for the force-close adoption to find either.
			const oldTxidHex = Buffer.from(t.attempt0Txid).reverse().toString('hex');
			managerOf(t.opener).handleFundingConfirmed(t.channelId, oldTxidHex);
			const st = t.channel.getFullState();
			expect(st.state, 'the channel stays failed').to.equal(
				ChannelState.ERRORED
			);
			expect(
				st.fundingTxid!.equals(t.attempt0Txid),
				'the confirmed attempt is adopted'
			).to.equal(true);
			expect(st.v2InFlight!.confirmed).to.equal(true);
			expect(st.v2PreviousAttempts ?? []).to.have.length(0);

			// And the close it now plans spends the funding that is on chain.
			const script = bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!;
			const res = managerOf(t.opener).forceClose(t.channelId, script);
			expect(res.ok, res.error).to.equal(true);
			const broadcast = res.actions.find(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			) as { tx: Buffer } | undefined;
			const commitment = bitcoin.Transaction.fromBuffer(broadcast!.tx);
			expect(
				Buffer.from(commitment.ins[0].hash).equals(t.attempt0Txid)
			).to.equal(true);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a late wallet selection cannot revive a closed channel (issue 376 review)', async function () {
		const t = await driveNonLeaseOpen(151, 152, [
			makeWalletInput(120_000),
			makeWalletInput(120_000)
		]);
		try {
			// The raise needs a top-up, so the request waits on the wallet.
			let release!: () => void;
			const gate = new Promise<void>((resolve) => {
				release = resolve;
			});
			const provider = t.provider as unknown as {
				selectSpliceInputs: (a: bigint, f: number) => Promise<unknown>;
			};
			const realSelect = provider.selectSpliceInputs.bind(provider);
			provider.selectSpliceInputs = async (a: bigint, f: number) => {
				await gate;
				return realSelect(a, f);
			};
			const res = t.opener.rbfOpenChannelV2(
				t.channelId,
				2000,
				undefined,
				150_000n
			);
			expect(res.ok).to.equal(true);

			// The channel force-closes while the selection is still in flight.
			const script = bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!;
			expect(managerOf(t.opener).forceClose(t.channelId, script).ok).to.equal(
				true
			);
			expect(t.channel.getState()).to.equal(ChannelState.FORCE_CLOSED);

			// Now the wallet answers. The request must be refused outright: it
			// would otherwise drag the closed channel back into a funding
			// renegotiation whose commitment is already on the network.
			release();
			await settle(() => t.provider.released.length > 0, 5_000);
			expect(t.channel.getState(), 'the close stands').to.equal(
				ChannelState.FORCE_CLOSED
			);
			expect(t.channel.getFullState().v2InFlight?.rbfAttempt ?? 0).to.equal(0);
			expect(
				t.provider.released.length,
				'the coins selected for the dead request are handed back'
			).to.be.greaterThan(0);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a force close after a superseded attempt confirmed spends the confirmed funding (issue 376)', async function () {
		const t = await driveSpecWindowRbf(139, 140);
		try {
			// The depth callback fires while disconnected, so the winning
			// attempt is only STAMPED confirmed: the live outpoint still names
			// the replacement it beat.
			t.channel.markForReestablish();
			expect(t.channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
			const oldTxidHex = Buffer.from(t.attempt0Txid).reverse().toString('hex');
			managerOf(t.opener).handleFundingConfirmed(t.channelId, oldTxidHex);
			expect(
				t.channel.getFullState().v2PreviousAttempts!.some((r) => r.confirmed),
				'the winner is stamped but not adopted'
			).to.equal(true);
			expect(
				t.channel.getFullState().fundingTxid!.equals(t.attempt1Txid),
				'live state still names the replacement'
			).to.equal(true);

			const script = bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!;
			const res = managerOf(t.opener).forceClose(t.channelId, script);
			expect(res.ok, res.error).to.equal(true);

			// The close must spend the funding that is actually on chain;
			// the replacement's output can never exist.
			const broadcast = res.actions.find(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			) as { tx: Buffer } | undefined;
			expect(broadcast, 'a commitment was broadcast').to.not.equal(undefined);
			const commitment = bitcoin.Transaction.fromBuffer(broadcast!.tx);
			expect(
				Buffer.from(commitment.ins[0].hash).equals(t.attempt0Txid),
				'the close spends the CONFIRMED attempt'
			).to.equal(true);
			const st = t.channel.getFullState();
			expect(st.fundingTxid!.equals(t.attempt0Txid)).to.equal(true);
			expect(st.v2InFlight!.confirmed).to.equal(true);
			expect(st.v2PreviousAttempts ?? []).to.have.length(0);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a force close adopts the confirmed attempt with BOTH its reserves (issue 379)', async function () {
		// The adoption carries the amounts the confirmed attempt's commitment was
		// signed at. With a contribution change the two attempts have different
		// capacities, so the reserves differ too: attempt 0 at 100,000 enforces
		// 1,000 on the peer, the replacement at 150,000 enforces 1,500.
		const t = await driveNonLeaseOpen(191, 192, [
			makeWalletInput(120_000),
			makeWalletInput(120_000)
		]);
		try {
			expect(
				t.opener.rbfOpenChannelV2(t.channelId, 2000, undefined, 150_000n).ok
			).to.equal(true);
			await settle(
				() =>
					t.channel.getFullState().v2InFlight?.rbfAttempt === 1 &&
					!!t.channel.getFullState().v2InFlight?.fullySigned
			);
			expect(
				Number(t.channel.getFullState().localConfig.channelReserveSatoshis)
			).to.equal(1_500);

			// The depth callback lands while the channel cannot act on it, so the
			// superseded winner is only stamped.
			t.channel.markForReestablish();
			managerOf(t.opener).handleFundingConfirmed(
				t.channelId,
				Buffer.from(t.attempt0Txid).reverse().toString('hex')
			);
			const script = bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!;
			const res = managerOf(t.opener).forceClose(t.channelId, script);
			expect(res.ok, res.error).to.equal(true);

			const st = t.channel.getFullState();
			expect(st.fundingTxid!.equals(t.attempt0Txid)).to.equal(true);
			expect(Number(st.fundingSatoshis)).to.equal(100_000);
			expect(Number(st.remoteConfig.channelReserveSatoshis)).to.equal(1_000);
			expect(Number(st.localConfig.channelReserveSatoshis)).to.equal(1_000);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('adopts the replacement when it confirms; every candidate clears (issue 360)', async function () {
		const t = await driveSpecWindowRbf(103, 104);
		try {
			const newTxidHex = Buffer.from(t.attempt1Txid).reverse().toString('hex');
			managerOf(t.opener).handleFundingConfirmed(t.channelId, newTxidHex);
			managerOf(t.acceptor).handleFundingConfirmed(t.channelId, newTxidHex);
			await settle(
				() =>
					t.channel.getState() === ChannelState.NORMAL &&
					t.acceptorChannel.getState() === ChannelState.NORMAL
			);
			for (const side of [t.channel, t.acceptorChannel]) {
				const st = side.getFullState();
				expect(st.state).to.equal(ChannelState.NORMAL);
				expect(st.fundingTxid!.equals(t.attempt1Txid)).to.be.true;
				expect(st.v2PreviousAttempts ?? []).to.have.length(0);
				expect(st.v2InFlight).to.equal(null);
			}
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('adopts the SUPERSEDED attempt when it wins the race to depth (issue 360)', async function () {
		const t = await driveSpecWindowRbf(105, 106);
		try {
			// Each attempt's commitment signs a different funding outpoint:
			// the adoption must also activate the ADOPTED attempt's commitment
			// signature, or forceClose would broadcast a commitment spending
			// an output that can never exist (review finding).
			const sides = [t.channel, t.acceptorChannel];
			const adoptedSigs = sides.map((side) =>
				Buffer.from(
					side.getFullState().v2PreviousAttempts![0].remoteCommitmentSig!
				)
			);
			const replacementSigs = sides.map((side) =>
				Buffer.from(side.getFullState().remoteCommitmentSignature!)
			);
			const oldTxidHex = Buffer.from(t.attempt0Txid).reverse().toString('hex');
			managerOf(t.opener).handleFundingConfirmed(t.channelId, oldTxidHex);
			managerOf(t.acceptor).handleFundingConfirmed(t.channelId, oldTxidHex);
			await settle(
				() =>
					t.channel.getState() === ChannelState.NORMAL &&
					t.acceptorChannel.getState() === ChannelState.NORMAL
			);
			for (const [i, side] of sides.entries()) {
				const st = side.getFullState();
				expect(st.state).to.equal(ChannelState.NORMAL);
				expect(
					st.fundingTxid!.equals(t.attempt0Txid),
					'the confirmed superseded attempt is adopted'
				).to.be.true;
				expect(st.fundingOutputIndex).to.be.a('number');
				expect(st.v2PreviousAttempts ?? []).to.have.length(0);
				expect(st.v2InFlight).to.equal(null);
				expect(
					st.remoteCommitmentSignature!.equals(adoptedSigs[i]),
					"the ADOPTED attempt's commitment signature is active"
				).to.be.true;
				expect(
					st.remoteCommitmentSignature!.equals(replacementSigs[i]),
					"the replacement's signature was replaced"
				).to.be.false;
			}
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a restart preserves the candidate set and still adopts the superseded attempt (issue 360)', async function () {
		const t = await driveSpecWindowRbf(107, 108);
		try {
			// Restart-equivalent at the channel layer: the row round-trips and
			// the rebuilt channel still tracks both candidates.
			const json = JSON.parse(
				JSON.stringify(serializeChannelState(t.channel.getFullState()))
			);
			const revived = new Channel(deserializeChannelState(json));
			revived.restoreV2InFlight();
			expect(revived.getFullState().v2PreviousAttempts).to.have.length(1);
			const adoptedSig = Buffer.from(
				revived.getFullState().v2PreviousAttempts![0].remoteCommitmentSig!
			);
			// A confirmation that does not say WHICH attempt is ambiguous with
			// candidates tracked: refused, nothing guessed, nothing mutated
			// (review finding).
			const ambiguous = revived.fundingConfirmed();
			expect(findError(ambiguous)).to.contain('ambiguous');
			expect(revived.getFullState().v2PreviousAttempts).to.have.length(1);
			const adoption = revived.fundingConfirmed(t.attempt0Txid);
			expect(findError(adoption)).to.equal(null);
			expect(
				findPayload(adoption, MessageType.CHANNEL_READY),
				'the revived channel readies on the adopted attempt'
			).to.not.equal(null);
			const st = revived.getFullState();
			expect(st.fundingTxid!.equals(t.attempt0Txid)).to.be.true;
			expect(st.v2InFlight!.fundingTxid.equals(t.attempt0Txid)).to.be.true;
			expect(st.v2PreviousAttempts ?? []).to.have.length(0);
			expect(st.state).to.equal(ChannelState.AWAITING_CHANNEL_READY);
			expect(
				st.remoteCommitmentSignature!.equals(adoptedSig),
				"the adopted attempt's commitment signature is active"
			).to.be.true;
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a restart re-pairs a rolled-back attempt with its own amounts (issue 376)', async function () {
		const t = await driveNonLeaseOpen(141, 142, [makeWalletInput(200_000)]);
		try {
			const attempt0Capacity = t.acceptorChannel.getFullState().fundingSatoshis;
			const record = t.acceptorChannel.getFullState().v2InFlight!;
			// The acceptor accepts a raise: live state now carries the
			// REPLACEMENT's amounts while the retained record is still attempt 0.
			t.acceptorChannel.handleTxInitRbf({
				channelId: t.channelId,
				locktime: 0,
				feerate: 2000,
				fundingOutputContribution: record.remoteContributionSats + 30_000n
			});
			const rowState = t.acceptorChannel.getFullState();
			expect(Number(rowState.fundingSatoshis)).to.equal(
				Number(attempt0Capacity + 30_000n)
			);
			expect(rowState.state).to.equal(ChannelState.DUAL_FUNDING_V2);

			// Crash HERE: the acceptance persisted, the replacement never
			// recorded itself. The restart rolls the row back to attempt 0 and
			// must restore attempt 0's amounts with it.
			const json = JSON.parse(JSON.stringify(serializeChannelState(rowState)));
			const restored = deserializeChannelState(json);
			restored.state = restored.v2InFlight!.sentTxSignatures
				? ChannelState.AWAITING_FUNDING_CONFIRMED
				: ChannelState.AWAITING_TX_SIGNATURES;
			const revived = new Channel(restored);
			revived.restoreV2InFlight();
			const st = revived.getFullState();
			expect(
				Number(st.fundingSatoshis),
				'capacity follows the resumed attempt'
			).to.equal(Number(attempt0Capacity));
			expect(Number(st.remoteBalanceMsat)).to.equal(
				Number(st.v2InFlight!.remoteBalanceMsat!)
			);
			expect(Number(st.remoteConfig.channelReserveSatoshis)).to.equal(
				Number(st.v2InFlight!.remoteChannelReserveSatoshis!)
			);
			// Both reserves follow the resumed attempt (issue 379): the raise put
			// 1,300 in live state and attempt 0 owns 1,000.
			expect(Number(st.localConfig.channelReserveSatoshis)).to.equal(1_000);
			expect(Number(st.localConfig.channelReserveSatoshis)).to.equal(
				Number(st.v2InFlight!.localChannelReserveSatoshis!)
			);
			// And a fully signed retained attempt resumes waiting on the chain,
			// not on the peer (the live-resync mapping).
			expect(st.v2InFlight!.sentTxSignatures).to.equal(true);
			expect(st.state).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('the live resync resumes a fully signed attempt on the chain, not on the peer (issue 376)', async function () {
		const t = await driveNonLeaseOpen(143, 144, [makeWalletInput(200_000)]);
		try {
			const row = t.acceptorChannel.getFullState();
			expect(row.v2InFlight!.sentTxSignatures).to.equal(true);
			// The shape the resync sees: a provisionally accepted RBF whose
			// persist failed, rolled back to a retained attempt that already
			// released its witnesses.
			row.state = ChannelState.DUAL_FUNDING_V2;
			const resumed = (
				t.acceptor as unknown as {
					v2RetainedAttemptState: (r: typeof row.v2InFlight) => ChannelState;
				}
			).v2RetainedAttemptState(row.v2InFlight);
			expect(resumed, 'a signed attempt waits on the chain').to.equal(
				ChannelState.AWAITING_FUNDING_CONFIRMED
			);

			// An attempt that never released its witnesses still waits on the peer.
			const unsigned = {
				...row.v2InFlight!,
				sentTxSignatures: false,
				fullySigned: false
			};
			expect(
				(
					t.acceptor as unknown as {
						v2RetainedAttemptState: (r: typeof unsigned) => ChannelState;
					}
				).v2RetainedAttemptState(unsigned)
			).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a force-closed open adopts a confirmed superseded attempt and re-drives the close (issue 360 review)', async function () {
		const t = await driveSpecWindowRbf(109, 110);
		try {
			const adoptedSig = Buffer.from(
				t.channel.getFullState().v2PreviousAttempts![0].remoteCommitmentSig!
			);
			// Force-close while every attempt is unconfirmed: the broadcast
			// commitment spends attempt 1's funding output.
			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const closed = t.opener.forceCloseChannel(t.channelId, dest);
			expect(closed.ok, closed.error).to.equal(true);
			expect(t.channel.getState()).to.equal(ChannelState.FORCE_CLOSED);

			// Attempt 0 wins the race to depth: the close just broadcast can
			// never confirm. The channel must adopt the confirmed attempt and
			// the node must re-drive the close against it.
			const oldTxidHex = Buffer.from(t.attempt0Txid).reverse().toString('hex');
			managerOf(t.opener).handleFundingConfirmed(t.channelId, oldTxidHex);
			// The watcher's confirmation callback (manager first, then the
			// node handler) drives the re-drive in production; invoke the
			// handler the same way here (no chain watcher in this fixture).
			(
				t.opener as unknown as {
					onFundingWatchConfirmed(id: Buffer, txid?: string): void;
				}
			).onFundingWatchConfirmed(t.channelId, oldTxidHex);
			const idHex = t.channelId.toString('hex');
			await settle(
				() =>
					(
						t.opener as unknown as {
							_lastCloseBroadcast: Map<string, { txid: string }>;
						}
					)._lastCloseBroadcast.get(idHex) !== undefined
			);

			const st = t.channel.getFullState();
			expect(st.state, 'the terminal state is kept').to.equal(
				ChannelState.FORCE_CLOSED
			);
			expect(st.fundingTxid!.equals(t.attempt0Txid)).to.be.true;
			expect(st.v2InFlight!.confirmed).to.equal(true);
			expect(st.v2PreviousAttempts ?? []).to.have.length(0);
			expect(
				st.remoteCommitmentSignature!.equals(adoptedSig),
				"the adopted attempt's commitment signature is active"
			).to.be.true;

			// The re-driven close spends the ADOPTED funding outpoint.
			const rebuilt = managerOf(t.opener).rebuildForceCloseCommitment(
				t.channelId,
				5
			);
			expect(rebuilt.ok, rebuilt.error).to.equal(true);
			const closeTx = bitcoin.Transaction.fromBuffer(rebuilt.tx!);
			expect(closeTx.ins).to.have.length(1);
			expect(
				Buffer.from(closeTx.ins[0].hash).equals(t.attempt0Txid),
				'the close spends the funding that is actually on chain'
			).to.be.true;
			expect(closeTx.ins[0].index).to.equal(st.fundingOutputIndex);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('rbfOpenChannelV2 validates u32 inputs before touching the channel (issue 360 review)', async function () {
		const t = await driveSpecWindowRbf(111, 112);
		try {
			expect(() => t.opener.rbfOpenChannelV2(t.channelId, 4000, -1)).to.throw(
				'u32'
			);
			expect(() => t.opener.rbfOpenChannelV2(t.channelId, 2 ** 32)).to.throw(
				'u32'
			);
			// Nothing was poisoned: the next valid bump goes through.
			const ok = t.opener.rbfOpenChannelV2(t.channelId, 4000);
			expect(ok.ok, ok.error).to.equal(true);
			await settle(
				() =>
					t.channel.getFullState().v2InFlight?.rbfAttempt === 2 &&
					!!t.channel.getFullState().v2InFlight?.fullySigned
			);
			expect(t.channel.getFullState().v2PreviousAttempts).to.have.length(2);
		} finally {
			t.opener.destroy();
			t.acceptor.destroy();
		}
	});

	it('a signer failure at the replacement commitment converges both sides', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(89, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(90, {
				storage: acceptorStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);
		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		wire.clearDrops();

		// The opener's signer refuses exactly once: at the REPLACEMENT
		// commitment (attempt 0's commitments were signed during the open).
		const signer = (
			channel as unknown as {
				_signer: { signCommitmentTx: (...a: unknown[]) => unknown };
			}
		)._signer;
		const realSign = signer.signCommitmentTx.bind(signer);
		let failOnce = true;
		signer.signCommitmentTx = (...args: unknown[]): unknown => {
			if (failOnce) {
				failOnce = false;
				throw new Error('signer unavailable');
			}
			return realSign(...args);
		};

		const rbfActions = channel.initiateTxRbf(2000);
		expect(findError(rbfActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, rbfActions);
		// The failing batch REPLACED the tx_complete that would have pushed
		// the peer over its commitment point, so the peer never committed
		// the replacement: BOTH sides roll back to the shared attempt 0 and
		// stay live, and BOTH managers and durable rows agree, with no
		// disconnect needed.
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		await settle(
			() =>
				channel.getState() === ChannelState.AWAITING_TX_SIGNATURES &&
				acceptorChannel.getState() === ChannelState.AWAITING_TX_SIGNATURES
		);
		expect(channel.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(acceptorChannel.getState()).to.equal(
			ChannelState.AWAITING_TX_SIGNATURES
		);
		expect(channel.getFullState().v2InFlight!.rbfAttempt).to.equal(0);
		expect(acceptorChannel.getFullState().v2InFlight!.rbfAttempt).to.equal(0);
		expect(
			channel
				.getFullState()
				.v2InFlight!.fundingTxid.equals(
					acceptorChannel.getFullState().v2InFlight!.fundingTxid
				),
			'both sides track the same attempt'
		).to.be.true;
		const openerRows = openerStorage.loadAllChannels();
		const acceptorRows = acceptorStorage.loadAllChannels();
		expect(openerRows).to.have.length(1);
		expect(acceptorRows).to.have.length(1);
		expect(
			openerRows[0].state.v2InFlight!.fundingTxid.equals(
				acceptorRows[0].state.v2InFlight!.fundingTxid
			),
			'both durable rows agree'
		).to.be.true;

		opener.destroy();
		acceptor.destroy();
	});

	it('the mirrored acceptor signer failure converges both sides to removal', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(91, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(92, {
				storage: acceptorStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);
		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		wire.clearDrops();

		// The ACCEPTOR's signer refuses once, at its replacement commitment.
		// The acceptor is the side RECEIVING the completing tx_complete, and
		// its sender's commitment is queued right behind that message: the
		// failure must be terminal, because the peer has already durably
		// committed the replacement.
		const signer = (
			acceptorChannel as unknown as {
				_signer: { signCommitmentTx: (...a: unknown[]) => unknown };
			}
		)._signer;
		const realSign = signer.signCommitmentTx.bind(signer);
		let failOnce = true;
		signer.signCommitmentTx = (...args: unknown[]): unknown => {
			if (failOnce) {
				failOnce = false;
				throw new Error('signer unavailable');
			}
			return realSign(...args);
		};

		const rbfActions = channel.initiateTxRbf(2000);
		expect(findError(rbfActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, rbfActions);

		// BOTH managers and BOTH durable rows converge to nothing over the
		// abort handshake, on the live connection: the opener committed the
		// replacement and is torn down by the abort; the acceptor's terminal
		// failure removes it at the echo. Neither attempt is broadcastable.
		await settle(
			() =>
				managerOf(opener).getChannel(channelId) === undefined &&
				managerOf(acceptor).getChannel(channelId) === undefined
		);
		expect(managerOf(opener).getChannel(channelId)).to.equal(undefined);
		expect(managerOf(acceptor).getChannel(channelId)).to.equal(undefined);
		expect(openerStorage.loadAllChannels()).to.have.length(0);
		expect(acceptorStorage.loadAllChannels()).to.have.length(0);

		opener.destroy();
		acceptor.destroy();
	});

	it('a crash between the terminal persist and the abort echo cannot resurrect the channel', async function () {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v2-term-'));
		const dbPath = path.join(dir, 'acceptor.db');
		const acceptorStorage = new SqliteStorage(dbPath);
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(93, {
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
			makeNodeConfig(94, {
				storage: acceptorStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);
		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		wire.clearDrops();
		// The abort's ECHO from the opener never arrives: the acceptor's
		// handshake cleanup cannot run, modelling a crash right after the
		// terminal persist and abort send.
		wire.dropFrom(opener, MessageType.TX_ABORT);

		const signer = (
			acceptorChannel as unknown as {
				_signer: { signCommitmentTx: (...a: unknown[]) => unknown };
			}
		)._signer;
		signer.signCommitmentTx = (): unknown => {
			throw new Error('signer unavailable');
		};
		const rbfActions = channel.initiateTxRbf(2000);
		expect(findError(rbfActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, rbfActions);
		await settle(() => wire.dropped(MessageType.TX_ABORT) > 0);
		expect(acceptorChannel.getState()).to.equal(ChannelState.ERRORED);
		const rows = acceptorStorage.loadAllChannels();
		expect(rows).to.have.length(1);
		expect(rows[0].state.condemned, 'the terminal row is condemned').to.be.true;
		acceptor.destroy();

		// The restart deletes the condemned row instead of restoring a
		// permanently tracked inert channel, and fires the terminal event
		// exactly once.
		const acceptorStorage2 = new SqliteStorage(dbPath);
		acceptorStorage2.open();
		const revivedVoided: Buffer[] = [];
		const revived = new LightningNode(
			makeNodeConfig(94, {
				storage: acceptorStorage2,
				recovery: { enabled: true }
			})
		);
		revived.on('node:error', () => {});
		revived.on('channel:voided', (e: { channelId: Buffer }) => {
			revivedVoided.push(e.channelId);
		});
		expect(
			revived.getChannelManager().listChannels(),
			'the condemned terminal row never restores'
		).to.have.length(0);
		expect(acceptorStorage2.loadAllChannels()).to.have.length(0);
		await settle(() => revivedVoided.length > 0, 1000);
		expect(revivedVoided).to.have.length(1);
		expect(revivedVoided[0].equals(channelId)).to.be.true;

		opener.destroy();
		revived.destroy();
	});

	it('a zero-input acceptor refuses RBF while its commitment exchange is incomplete; both sides keep the broadcastable attempt', async function () {
		const opener = new LightningNode(
			makeNodeConfig(83, {
				storage: (() => {
					const s = new SqliteStorage(':memory:');
					s.open();
					return s;
				})(),
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(84));
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

		// The acceptor contributed no inputs, so attempt 0 is broadcastable
		// by the opener alone, and the dropped commitment_signed left the
		// acceptor without the opener's commitment signature: a superseded
		// attempt it cannot force-close must never enter the candidate set,
		// so the replacement is refused until the exchange completes (in the
		// issue-360 spec window a COMPLETED broadcastable attempt accepts).
		const rbfActions = channel.initiateTxRbf(2000);
		expect(findError(rbfActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, rbfActions);
		await settle(() => wire.sent(acceptor, MessageType.TX_ABORT) > 0);
		expect(wire.sent(acceptor, MessageType.TX_ACK_RBF)).to.equal(0);
		expect(acceptorChannel.getState()).to.equal(
			ChannelState.AWAITING_TX_SIGNATURES
		);
		expect(channel.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(channel.getFullState().v2InFlight!.fundingTxid.equals(attempt0Txid))
			.to.be.true;

		opener.destroy();
		acceptor.destroy();
	});

	it('a failed persist at the replacement commitment rolls both sides back to the previous attempt', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(85, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(86, {
				storage: acceptorStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);
		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const attempt0Txid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);
		wire.clearDrops();

		// The opener's disk accepts exactly ONE more commit (the ack that
		// makes the replacement provisional) and then refuses: the failure
		// lands on the commitment persist that would have replaced the
		// rollback record. With no separate clear-write, BOTH sides still
		// hold attempt 0 and roll back to it.
		const recovery = (
			opener as unknown as {
				recovery: { commit: (...a: unknown[]) => unknown };
			}
		).recovery;
		const realCommit = recovery.commit.bind(recovery);
		let allowed = 1;
		let refusing = false;
		recovery.commit = (...args: unknown[]): unknown => {
			if (!refusing) return realCommit(...args);
			if (allowed > 0) {
				allowed--;
				return realCommit(...args);
			}
			return {
				committed: false,
				released: [],
				frameSequence: null,
				error: new Error('disk full')
			};
		};

		const rbfActions = channel.initiateTxRbf(2000);
		expect(findError(rbfActions)).to.equal(null);
		refusing = true;
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, rbfActions);
		await settle(() => wire.sent(acceptor, MessageType.TX_ACK_RBF) > 0);
		refusing = false;
		// Let the deferred blocked-transition resync land: the opener
		// re-restores the durable attempt from its row.
		await new Promise((resolve) => setImmediate(resolve));
		await new Promise((resolve) => setImmediate(resolve));

		// The replacement never became durable on the opener (its row still
		// carries attempt 0, and the blocked-transition resync restored it),
		// while the acceptor's own commitment persist DID land (attempt 1).
		// The sides now hold different attempts; because an accepted RBF
		// requires both to have contributed inputs and neither released
		// witnesses, NEITHER attempt is broadcastable by anyone.
		managerOf(opener).handlePeerDisconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		const openerRestored = managerOf(opener).getChannel(channelId);
		expect(openerRestored).to.not.equal(undefined);
		expect(
			openerRestored!
				.getFullState()
				.v2InFlight!.fundingTxid.equals(attempt0Txid),
			'the opener holds the durable attempt 0'
		).to.be.true;
		const kept = managerOf(acceptor).getChannel(channelId)!;
		expect(
			kept.getFullState().v2InFlight!.fundingTxid.equals(attempt0Txid),
			'the acceptor durably committed the replacement'
		).to.be.false;

		// Reconnect: the divergent next_funding advertisements hard-fail the
		// open on both sides, and with nothing broadcastable the terminal is
		// a clean mutual void, never a broadcast into nothing.
		const openerVoided: Buffer[] = [];
		opener.on('channel:voided', (e: { channelId: Buffer }) => {
			openerVoided.push(e.channelId);
		});
		const acceptorVoided: Buffer[] = [];
		acceptor.on('channel:voided', (e: { channelId: Buffer }) => {
			acceptorVoided.push(e.channelId);
		});
		wire.hold();
		managerOf(opener).handlePeerReconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerReconnected(opener.getNodeId());
		wire.drain();
		await settle(() => openerVoided.length > 0 && acceptorVoided.length > 0);
		expect(openerVoided).to.have.length(1);
		expect(acceptorVoided).to.have.length(1);
		expect(managerOf(opener).getChannel(channelId)).to.equal(undefined);
		expect(managerOf(acceptor).getChannel(channelId)).to.equal(undefined);
		expect(openerStorage.loadAllChannels()).to.have.length(0);
		expect(acceptorStorage.loadAllChannels()).to.have.length(0);

		opener.destroy();
		acceptor.destroy();
	});

	it('retains the channel when neither deletion nor cleanup intent can be persisted', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(87, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(88));
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

		// Both the row deletion AND the condemnation write refuse: with no
		// durable trace of the removal decision, a restart would silently
		// restore the row as a live channel. The node must keep it TRACKED
		// instead of orphaning it. (Only the CONDEMNED save is refused, so
		// the abort's own state persist still lands and the cleanup path is
		// genuinely reached.)
		(
			openerStorage as unknown as { deleteChannel: (id: string) => void }
		).deleteChannel = (): void => {
			throw new Error('disk full');
		};
		const realSave = openerStorage.saveChannel.bind(openerStorage);
		(
			openerStorage as unknown as {
				saveChannel: (id: string, state: IChannelState, peer: string) => void;
			}
		).saveChannel = (id: string, state: IChannelState, peer: string): void => {
			if (state.condemned) throw new Error('disk full');
			realSave(id, state, peer);
		};
		const voided: Buffer[] = [];
		opener.on('channel:voided', (e: { channelId: Buffer }) => {
			voided.push(e.channelId);
		});
		const abortActions = channel.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, abortActions);
		await settle(
			() => managerOf(opener).getChannel(channelId) !== undefined,
			4000
		);
		expect(
			managerOf(opener).getChannel(channelId),
			'the channel stays tracked without a durable removal'
		).to.not.equal(undefined);
		expect(voided).to.have.length(0);
		expect(openerStorage.loadAllChannels()).to.have.length(1);

		opener.destroy();
		acceptor.destroy();
	});

	it('a lost first post-ack contribution rolls BOTH sides back to the previous attempt', async function () {
		const openerStorage = new SqliteStorage(':memory:');
		openerStorage.open();
		const acceptorStorage = new SqliteStorage(':memory:');
		acceptorStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(77, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(
			makeNodeConfig(78, {
				storage: acceptorStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
		await settle(() => wire.dropped(MessageType.COMMITMENT_SIGNED) > 0);
		const channelId = channel.getChannelId()!;
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
		const attempt0Txid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);
		wire.clearDrops();

		// The RBF is accepted and acked, but the initiator's first
		// contribution of the new round never arrives: NEITHER side has
		// causal proof the other observed the replacement round, so both
		// retained their rollback records.
		wire.dropFrom(opener, MessageType.TX_ADD_INPUT);
		const rbfActions = channel.initiateTxRbf(2000);
		expect(findError(rbfActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, rbfActions);
		await settle(() => wire.dropped(MessageType.TX_ADD_INPUT) > 0);
		expect(channel.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
		expect(
			channel.getFullState().v2InFlight,
			'the initiator retained its rollback record through the ack'
		).to.not.be.oneOf([null, undefined]);

		// Disconnect: both sides roll back to the shared previous attempt,
		// keeping their rows. This used to delete the initiator's row while
		// the receiver rolled back.
		managerOf(opener).handlePeerDisconnected(acceptor.getNodeId());
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		expect(managerOf(opener).getChannel(channelId)).to.not.equal(undefined);
		expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(channel.getFullState().v2InFlight!.fundingTxid.equals(attempt0Txid))
			.to.be.true;
		expect(openerStorage.loadAllChannels()).to.have.length(1);
		expect(acceptorChannel.getState()).to.equal(
			ChannelState.AWAITING_REESTABLISH
		);
		expect(
			acceptorChannel
				.getFullState()
				.v2InFlight!.fundingTxid.equals(attempt0Txid)
		).to.be.true;
		expect(acceptorStorage.loadAllChannels()).to.have.length(1);

		// Reconnect: the shared previous attempt resumes and completes.
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
		expect(channel.getFullState().fundingTxid!.equals(attempt0Txid)).to.be.true;

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
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
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
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
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
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		// Drop the opener's commitment_signed: the acceptor crosses its own
		// point of no return (record created) but releases no tx_signatures,
		// which is the only window an RBF can still be accepted in.
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
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

		// The operator aborts the stranded open. The opener contributed the
		// only wallet input, so ITS attempt is not broadcastable by the peer
		// and the echo completes its teardown and removal. The ACCEPTOR
		// contributed nothing: the opener needs no witness bytes from it and
		// could broadcast the funding tx alone, so the acceptor keeps its
		// record, state and row despite the abort (zero-local-input
		// broadcastability).
		const abortActions = channel.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, abortActions);
		await settle(() => managerOf(opener).getChannel(channelId) === undefined);
		expect(managerOf(opener).getChannel(channelId)).to.equal(undefined);
		expect(openerStorage.loadAllChannels()).to.have.length(0);
		expect(openerVoided).to.have.length(1);

		const kept = managerOf(acceptor).getChannel(channelId);
		expect(kept, 'the zero-input acceptor keeps its side').to.not.equal(
			undefined
		);
		expect(kept!.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);
		expect(kept!.getFullState().v2InFlight).to.not.be.oneOf([null, undefined]);
		expect(acceptorStorage.loadAllChannels()).to.have.length(1);
		expect(acceptorVoided).to.have.length(0);

		opener.destroy();
		acceptor.destroy();
	});

	it('a lost abort echo keeps BOTH sides alive; reconnect resumes the attempt', async function () {
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
		const attempt0Txid = Buffer.from(
			channel.getFullState().v2InFlight!.fundingTxid
		);
		wire.clearDrops();
		// The zero-input acceptor hears the abort and keeps its side (the
		// attempt is broadcastable by the opener alone); its echo dies on
		// the wire, so the aborting opener must not tear down either (the
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
		expect(managerOf(acceptor).getChannel(channelId)).to.not.equal(undefined);
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

		// Reconnect: the abort never completed anywhere, so the shared
		// attempt simply resumes and completes.
		managerOf(acceptor).handlePeerDisconnected(opener.getNodeId());
		const acceptorChannel = managerOf(acceptor).getChannel(channelId)!;
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
		expect(channel.getFullState().fundingTxid!.equals(attempt0Txid)).to.be.true;

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
		expect(channel.getFullState().fundingTxid!.equals(attempt0Txid)).to.be.true;

		opener.destroy();
		acceptor.destroy();
	});

	it('defers the terminal void when the row deletion fails; a restart completes it', async function () {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v2-void-'));
		const dbPath = path.join(dir, 'opener.db');
		const openerStorage = new SqliteStorage(dbPath);
		openerStorage.open();
		const opener = new LightningNode(
			makeNodeConfig(75, {
				storage: openerStorage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(76));
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

		// The opener's disk refuses deletions: the abort handshake (its echo
		// completes the teardown) removes its registration, but the row
		// survives, so the terminal event must NOT fire; a voided claim here
		// would be a lie a restart disproves.
		const realDelete = openerStorage.deleteChannel.bind(openerStorage);
		const refuseDelete = true;
		(
			openerStorage as unknown as { deleteChannel: (id: string) => void }
		).deleteChannel = (id: string): void => {
			if (refuseDelete) throw new Error('disk full');
			realDelete(id);
		};
		const voided: Buffer[] = [];
		opener.on('channel:voided', (e: { channelId: Buffer }) => {
			voided.push(e.channelId);
		});
		const abortActions = channel.abortDualFunding('operator cancelled');
		expect(findError(abortActions)).to.equal(null);
		(
			managerOf(opener) as unknown as {
				processActions: (p: string, c: Channel, a: unknown[]) => void;
			}
		).processActions(acceptor.getNodeId(), channel, abortActions);
		await settle(() => managerOf(opener).getChannel(channelId) === undefined);
		expect(managerOf(opener).getChannel(channelId)).to.equal(undefined);
		expect(
			voided,
			'no terminal event without a durable deletion'
		).to.have.length(0);
		expect(openerStorage.loadAllChannels()).to.have.length(1);
		expect(openerStorage.loadAllChannels()[0].state.condemned).to.be.true;

		// The condemnation is JOURNALED: a verified-frame reconstruction
		// must rebuild the row condemned too, or recovery would resurrect a
		// channel whose deletion was already decided.
		const journal = (
			opener as unknown as {
				recovery: {
					options: {
						journal?: { loadVerifiedFrames: () => unknown };
					};
				};
			}
		).recovery.options.journal;
		expect(journal, 'the node journals recovery frames').to.not.equal(
			undefined
		);
		const rebuilt = new SqliteStorage(':memory:');
		rebuilt.open();
		reconstructFromFrames(
			rebuilt,
			journal!.loadVerifiedFrames() as Parameters<
				typeof reconstructFromFrames
			>[1]
		);
		const rebuiltRows = rebuilt.loadAllChannels();
		expect(rebuiltRows).to.have.length(1);
		expect(
			rebuiltRows[0].state.condemned,
			'reconstruction preserves the condemnation'
		).to.be.true;
		rebuilt.close();
		opener.destroy();

		// A restart whose deletions STILL fail must not restore the
		// condemned row as a live channel (the intent rides the row itself,
		// so no unreadable side-store can lose it), and must not fire the
		// terminal event either.
		const openerStorageStillFailing = new SqliteStorage(dbPath);
		openerStorageStillFailing.open();
		(
			openerStorageStillFailing as unknown as {
				deleteChannel: (id: string) => void;
			}
		).deleteChannel = (): void => {
			throw new Error('disk full');
		};
		const stillFailingVoided: Buffer[] = [];
		const stillFailing = new LightningNode(
			makeNodeConfig(75, {
				storage: openerStorageStillFailing,
				recovery: { enabled: false }
			})
		);
		stillFailing.on('node:error', () => {});
		stillFailing.on('channel:voided', (e: { channelId: Buffer }) => {
			stillFailingVoided.push(e.channelId);
		});
		expect(
			stillFailing.getChannelManager().listChannels(),
			'a condemned row never restores as a live channel'
		).to.have.length(0);
		await settle(() => stillFailingVoided.length > 0, 300);
		expect(stillFailingVoided).to.have.length(0);
		expect(openerStorageStillFailing.loadAllChannels()).to.have.length(1);
		stillFailing.destroy();

		// The healthy restart completes the owed deletion WITHOUT waiting
		// for another peer disconnect, and only then does the terminal
		// event fire, exactly once.
		const openerStorage2 = new SqliteStorage(dbPath);
		openerStorage2.open();
		const revivedVoided: Buffer[] = [];
		const revived = new LightningNode(
			makeNodeConfig(75, {
				storage: openerStorage2,
				recovery: { enabled: true }
			})
		);
		revived.on('node:error', () => {});
		revived.on('channel:voided', (e: { channelId: Buffer }) => {
			revivedVoided.push(e.channelId);
		});
		expect(revived.getChannelManager().listChannels()).to.have.length(0);
		expect(openerStorage2.loadAllChannels()).to.have.length(0);
		await settle(() => revivedVoided.length > 0, 1000);
		expect(revivedVoided).to.have.length(1);
		expect(revivedVoided[0].equals(channelId)).to.be.true;

		acceptor.destroy();
		revived.destroy();
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
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
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
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		// Strand the exchange mid-round so the RBF stays acceptable.
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);

		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
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
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(150_000)),
				leaseRates: LEASE_RATES
			})
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = wireNodes(opener, acceptor);
		wire.dropFrom(opener, MessageType.COMMITMENT_SIGNED);
		const channel = opener.openChannelV2(
			acceptor.getNodeId(),
			leaseOpenParams()
		);
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
