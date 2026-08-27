/**
 * Dual-funding EXTERNAL inputs (issue #554, LFBW port #532 workstream 2B).
 *
 * A v2 open may contribute inputs owned by a THIRD PARTY: they ride the
 * interactive negotiation like our own inputs (our serial parity, full
 * prevTx), but their witnesses arrive out of band via
 * provideV2ExternalWitness. These tests pin the invariants:
 *  - our tx_signatures never leaves with a witness hole: the release is
 *    withheld until every external slot is filled, and the owed slots are
 *    surfaced once per connection through TX_SIGNATURES_NEEDED,
 *  - a delivered witness is cryptographically verified against the
 *    recorded prevouts BEFORE it is stored (garbage never releases),
 *  - the wait survives a restart: the durable record carries the external
 *    indices and the negotiated tx, and provideV2ExternalWitness completes
 *    the open on a restored, builder-less channel,
 *  - the assembled funding tx aligns witnesses by tx-input order and its
 *    txid equals the negotiated outpoint,
 *  - the waiting open stays cleanly abortable (no witness ever released).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

import { Channel } from '../../src/lightning/channel/channel';
import {
	createOpenerState,
	createAcceptorState,
	IV2InFlight
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
import { IInteractiveTxInput } from '../../src/lightning/interactive-tx/types';
import { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import { createFundingScript } from '../../src/lightning/script/funding';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxSignaturesMessage,
	decodeTxAbortMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import {
	serializeChannelState,
	deserializeChannelState,
	serializeV2InFlight,
	deserializeV2InFlight
} from '../../src/lightning/storage/serialization';
import { taprootTweakPrivateKey } from '../../src/lightning/wallet/wallet-funding-provider';

// ─────────────── Helpers ───────────────

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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findTxSigsNeeded(actions: any[]): { inputIndices: number[] } | null {
	for (const a of actions) {
		if (a.type === ChannelActionType.TX_SIGNATURES_NEEDED) return a;
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

const OPENER_FUNDING = 100_000n;
const ACCEPTOR_FUNDING = 50_000n;
const TOTAL_FUNDING = OPENER_FUNDING + ACCEPTOR_FUNDING;
const OWN_UTXO_SATS = 40_000;
const EXT_UTXO_SATS = 30_000;
const FUNDING_FEERATE = 1000;

interface IWithholdSetup {
	opener: Channel;
	acceptor: Channel;
	aCommitHandle: unknown[];
	oCommitHandle: unknown[];
	ownPrevTx: bitcoin.Transaction;
	ownPub: Buffer;
	ownScriptCode: Buffer;
	extPrevTx: bitcoin.Transaction;
	extPriv: Buffer;
	extPub: Buffer;
	extScript: Buffer;
	openerPriv: Buffer;
	openerPub: Buffer;
	openerPrevTx: bitcoin.Transaction;
}

/**
 * Drive two real channels to the point where the acceptor's tx_signatures
 * release is due but withheld on an unfilled external slot. The acceptor
 * contributes one OWN P2WPKH input (signed via its closure) plus one
 * EXTERNAL input owned by a third party (P2WPKH by default, P2TR when
 * requested); the opener contributes one input and the funding output.
 * The acceptor's input total (70k) is below the opener's (120k), so BOLT 2
 * ordering makes the acceptor sign first: the stall is entirely ours.
 */
function driveToWithhold(externalKind: 'p2wpkh' | 'p2tr'): IWithholdSetup {
	const sharedTempId = crypto.randomBytes(32);
	const openerFundingPriv = crypto.randomBytes(32);
	const acceptorFundingPriv = crypto.randomBytes(32);
	const openerFundingPub = getPublicKey(openerFundingPriv);
	const acceptorFundingPub = getPublicKey(acceptorFundingPriv);
	const openerSeed = crypto.randomBytes(32);
	const acceptorSeed = crypto.randomBytes(32);

	const openerState = createOpenerState({
		temporaryChannelId: sharedTempId,
		fundingSatoshis: OPENER_FUNDING,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(openerFundingPub, openerSeed),
		localPerCommitmentSeed: openerSeed
	});
	const opener = new Channel(openerState, new ChannelSigner(openerFundingPriv));

	const acceptorState = createAcceptorState({
		temporaryChannelId: sharedTempId,
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(acceptorFundingPub, acceptorSeed),
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

	// Own P2WPKH wallet input with a real signing closure.
	const ownPriv = crypto.randomBytes(32);
	const ownPub = getPublicKey(ownPriv);
	const ownScriptCode = bitcoin.payments.p2pkh({ pubkey: ownPub }).output!;
	const ownPrevTx = new bitcoin.Transaction();
	ownPrevTx.version = 2;
	ownPrevTx.addInput(crypto.randomBytes(32), 0);
	ownPrevTx.addOutput(
		bitcoin.payments.p2wpkh({ pubkey: ownPub }).output!,
		OWN_UTXO_SATS
	);
	const ownInput: ISpliceWalletInput = {
		prevTx: ownPrevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(OWN_UTXO_SATS),
		sequence: 0xfffffffd,
		signWitness: (tx, inputIndex, value) => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				ownScriptCode,
				Number(value),
				bitcoin.Transaction.SIGHASH_ALL
			);
			const der = bitcoin.script.signature.encode(
				Buffer.from(ecc.sign(sighash, ownPriv)),
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [der, ownPub];
		}
	};

	// The EXTERNAL input: a third party's UTXO. The witness comes out of
	// band, so the closure is a throwing stub the machinery must never call.
	const extPriv = crypto.randomBytes(32);
	const extPub = getPublicKey(extPriv);
	const extScript =
		externalKind === 'p2wpkh'
			? bitcoin.payments.p2wpkh({ pubkey: extPub }).output!
			: bitcoin.payments.p2tr({ internalPubkey: extPub.subarray(1, 33) })
					.output!;
	const extPrevTx = new bitcoin.Transaction();
	extPrevTx.version = 2;
	extPrevTx.addInput(crypto.randomBytes(32), 0);
	extPrevTx.addOutput(extScript, EXT_UTXO_SATS);
	const externalInput: ISpliceWalletInput = {
		prevTx: extPrevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(EXT_UTXO_SATS),
		sequence: 0xfffffffd,
		signWitness: () => {
			throw new Error('external input: the witness comes from its owner');
		},
		confirmed: true,
		external: true
	};

	const changeScript = bitcoin.payments.p2wpkh({
		hash: crypto.randomBytes(20)
	}).output!;
	acceptor.setDualFundingContribution(
		[ownInput, externalInput],
		changeScript,
		ACCEPTOR_FUNDING,
		FUNDING_FEERATE
	);

	const params = (
		state: typeof openerState,
		seed: Buffer,
		sats: bigint
	): IDualFundingParams => ({
		fundingSatoshis: sats,
		fundingFeeratePerkw: FUNDING_FEERATE,
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
		params(openerState, openerSeed, OPENER_FUNDING)
	);
	expect(findError(openActions)).to.equal(null);
	const openMsg = decodeOpenChannel2Message(
		findPayload(openActions, MessageType.OPEN_CHANNEL2)!
	);
	acceptorState.temporaryChannelId = Buffer.from(openMsg.channelId);
	const acceptActions = acceptor.handleOpenChannel2(
		openMsg,
		params(acceptorState, acceptorSeed, ACCEPTOR_FUNDING)
	);
	expect(findError(acceptActions)).to.equal(null);
	opener.handleAcceptChannel2(
		decodeAcceptChannel2Message(
			findPayload(acceptActions, MessageType.ACCEPT_CHANNEL2)!
		)
	);

	// Interactive-tx: opener input -> own input; funding output -> external
	// input; complete -> change; complete -> completes plus commitments.
	const openerPriv = crypto.randomBytes(32);
	const openerPub = getPublicKey(openerPriv);
	const openerPrevTx = new bitcoin.Transaction();
	openerPrevTx.version = 2;
	openerPrevTx.addInput(crypto.randomBytes(32), 0);
	openerPrevTx.addOutput(
		bitcoin.payments.p2wpkh({ pubkey: openerPub }).output!,
		120_000
	);
	const openerInput: IInteractiveTxInput = {
		serialId: 0n,
		prevTxid: Buffer.from(openerPrevTx.getHash()),
		prevOutputIndex: 0,
		sequence: 0xfffffffd,
		prevTx: openerPrevTx.toBuffer(),
		prevTxVout: 0
	};

	const oIn = opener.addTxInput(openerInput);
	expect(findError(oIn)).to.equal(null);
	const aTurn1 = acceptor.handleTxAddInput(
		decodeTxAddInputMessage(findPayload(oIn, MessageType.TX_ADD_INPUT)!)
	);
	expect(findError(aTurn1)).to.equal(null);
	opener.handleTxAddInput(
		decodeTxAddInputMessage(findPayload(aTurn1, MessageType.TX_ADD_INPUT)!)
	);

	const funding = createFundingScript(openerFundingPub, acceptorFundingPub);
	const oOut = opener.addTxOutput({
		serialId: 2n,
		amountSats: TOTAL_FUNDING,
		scriptPubkey: funding.p2wshOutput
	});
	expect(findError(oOut)).to.equal(null);
	const aTurn2 = acceptor.handleTxAddOutput(
		decodeTxAddOutputMessage(findPayload(oOut, MessageType.TX_ADD_OUTPUT)!)
	);
	expect(findError(aTurn2)).to.equal(null);
	const extInPayload = findPayload(aTurn2, MessageType.TX_ADD_INPUT);
	expect(
		extInPayload,
		'the EXTERNAL input rides an ordinary turn'
	).to.not.equal(null);
	const extInMsg = decodeTxAddInputMessage(extInPayload!);
	expect(extInMsg.serialId % 2n).to.equal(1n);
	expect(
		bitcoin.Transaction.fromBuffer(extInMsg.prevTx!)
			.getHash()
			.equals(extPrevTx.getHash()),
		'wire form carries the third-party prevTx like any of ours'
	).to.be.true;
	opener.handleTxAddInput(extInMsg);

	const oComplete1 = opener.sendTxComplete();
	expect(findError(oComplete1)).to.equal(null);
	const aTurn3 = acceptor.handleTxComplete();
	expect(findError(aTurn3)).to.equal(null);
	const changePayload = findPayload(aTurn3, MessageType.TX_ADD_OUTPUT);
	expect(changePayload, 'change output after both inputs').to.not.equal(null);
	opener.handleTxAddOutput(decodeTxAddOutputMessage(changePayload!));

	const oComplete2 = opener.sendTxComplete();
	expect(findError(oComplete2)).to.equal(null);
	const aTurn4 = acceptor.handleTxComplete();
	expect(findError(aTurn4)).to.equal(null);
	const acceptorCommit = findPayload(aTurn4, MessageType.COMMITMENT_SIGNED);
	expect(
		acceptorCommit,
		'acceptor commits with the external hole'
	).to.not.equal(null);
	const oAfter = opener.handleTxComplete();
	expect(findError(oAfter)).to.equal(null);
	const openerCommit = findPayload(oAfter, MessageType.COMMITMENT_SIGNED);
	expect(openerCommit).to.not.equal(null);

	const aCommitHandle = acceptor.handleCommitmentSigned(
		decodeCommitmentSignedMessage(openerCommit!)
	);
	expect(findError(aCommitHandle)).to.equal(null);
	const oCommitHandle = opener.handleCommitmentSigned(
		decodeCommitmentSignedMessage(acceptorCommit!)
	);
	expect(findError(oCommitHandle)).to.equal(null);

	return {
		opener,
		acceptor,
		aCommitHandle,
		oCommitHandle,
		ownPrevTx,
		ownPub,
		ownScriptCode,
		extPrevTx,
		extPriv,
		extPub,
		extScript,
		openerPriv,
		openerPub,
		openerPrevTx
	};
}

/** The external input's index in the negotiated funding tx. */
function externalIndexOf(
	record: IV2InFlight,
	extPrevTx: bitcoin.Transaction
): number {
	const tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
	const idx = tx.ins.findIndex(
		(i) => Buffer.from(i.hash).equals(extPrevTx.getHash()) && i.index === 0
	);
	expect(idx).to.be.gte(0);
	return idx;
}

/** Sign the external P2WPKH input over the negotiated tx as its owner. */
function signExternalP2wpkh(
	record: IV2InFlight,
	extPrevTx: bitcoin.Transaction,
	extPriv: Buffer,
	extPub: Buffer
): Buffer[] {
	const tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
	const idx = externalIndexOf(record, extPrevTx);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: extPub }).output!;
	const sighash = tx.hashForWitnessV0(
		idx,
		scriptCode,
		EXT_UTXO_SATS,
		bitcoin.Transaction.SIGHASH_ALL
	);
	return [
		bitcoin.script.signature.encode(
			Buffer.from(ecc.sign(sighash, extPriv)),
			bitcoin.Transaction.SIGHASH_ALL
		),
		extPub
	];
}

describe('Dual funding external inputs (issue #554)', function () {
	it('withholds tx_signatures on the external hole, then completes end to end', function () {
		const s = driveToWithhold('p2wpkh');
		const { opener, acceptor } = s;

		// The release was due (we sign first) but NOTHING left: no
		// tx_signatures from either side, and the owed external slot was
		// surfaced exactly once.
		expect(findPayload(s.aCommitHandle, MessageType.TX_SIGNATURES)).to.equal(
			null
		);
		expect(findPayload(s.oCommitHandle, MessageType.TX_SIGNATURES)).to.equal(
			null
		);
		const record = acceptor.getFullState().v2InFlight!;
		const extIdx = externalIndexOf(record, s.extPrevTx);
		const needed = findTxSigsNeeded(s.aCommitHandle);
		expect(needed, 'the owed slot is surfaced').to.not.equal(null);
		expect(needed!.inputIndices).to.deep.equal([extIdx]);
		expect(record.externalInputIndices).to.deep.equal([extIdx]);
		// The OWN input was signed at record creation; the external slot is
		// an empty placeholder.
		const extPos = record.ourWalletInputIndices.indexOf(extIdx);
		expect(record.ourWitnesses[extPos]).to.deep.equal([]);
		const ownPos = extPos === 0 ? 1 : 0;
		expect(record.ourWitnesses[ownPos].length).to.equal(2);
		// The obligation signal is one-shot per connection.
		const flushAgain = (
			acceptor as unknown as { _maybeSendV2TxSigs(): unknown[] }
		)._maybeSendV2TxSigs();
		expect(flushAgain).to.deep.equal([]);

		// Garbage is refused BEFORE storage; the open stays waiting.
		expect(() =>
			acceptor.provideV2ExternalWitness(Buffer.from(s.extPrevTx.getHash()), 0, [
				crypto.randomBytes(71),
				s.extPub
			])
		).to.throw('external witness rejected');
		// A witness for an outpoint that is not external is refused by name.
		expect(() =>
			acceptor.provideV2ExternalWitness(
				Buffer.from(s.ownPrevTx.getHash()),
				0,
				signExternalP2wpkh(record, s.extPrevTx, s.extPriv, s.extPub)
			)
		).to.throw('not an external funding input');
		// An outpoint outside the negotiated tx is refused by name.
		expect(() =>
			acceptor.provideV2ExternalWitness(crypto.randomBytes(32), 0, [
				crypto.randomBytes(71),
				s.extPub
			])
		).to.throw('not an input of the negotiated funding tx');

		// The owner's REAL witness releases the exchange.
		const witness = signExternalP2wpkh(
			record,
			s.extPrevTx,
			s.extPriv,
			s.extPub
		);
		const release = acceptor.provideV2ExternalWitness(
			Buffer.from(s.extPrevTx.getHash()),
			0,
			witness
		);
		expect(findError(release)).to.equal(null);
		const aSigsPayload = findPayload(release, MessageType.TX_SIGNATURES);
		expect(
			aSigsPayload,
			'the last witness releases tx_signatures'
		).to.not.equal(null);
		const aSigs = decodeTxSignaturesMessage(aSigsPayload!);
		expect(aSigs.witnesses.length).to.equal(2);
		// Witnesses ride in tx-input order: the external one sits at its slot.
		const witnessAtExt = aSigs.witnesses[extPos];
		expect(witnessAtExt[1].equals(s.extPub)).to.be.true;

		// The opener validates and accepts them (the external witness is
		// indistinguishable from our own on the wire).
		const oAfterPeerSigs = opener.handleTxSignatures(aSigs);
		expect(findError(oAfterPeerSigs)).to.equal(null);

		// Opener releases its own side (caller-driven) and the acceptor
		// assembles and broadcasts the funding tx.
		const openerRecord = opener.getFullState().v2InFlight!;
		const negotiated = bitcoin.Transaction.fromHex(openerRecord.fundingTxHex);
		const openerScriptCode = bitcoin.payments.p2pkh({
			pubkey: s.openerPub
		}).output!;
		const openerSighash = negotiated.hashForWitnessV0(
			negotiated.ins.findIndex(
				(i) =>
					Buffer.from(i.hash).equals(s.openerPrevTx.getHash()) && i.index === 0
			),
			openerScriptCode,
			120_000,
			bitcoin.Transaction.SIGHASH_ALL
		);
		const openerWitness = [
			bitcoin.script.signature.encode(
				Buffer.from(ecc.sign(openerSighash, s.openerPriv)),
				bitcoin.Transaction.SIGHASH_ALL
			),
			s.openerPub
		];
		const oSigsActions = opener.sendTxSignatures(
			opener.getFullState().fundingTxid!,
			opener.getFullState().fundingOutputIndex,
			[openerWitness]
		);
		expect(findError(oSigsActions)).to.equal(null);
		const oSigsPayload =
			findPayload(oSigsActions, MessageType.TX_SIGNATURES) ??
			findPayload(oAfterPeerSigs, MessageType.TX_SIGNATURES);
		expect(oSigsPayload).to.not.equal(null);

		const aFinal = acceptor.handleTxSignatures(
			decodeTxSignaturesMessage(oSigsPayload!)
		);
		expect(findError(aFinal)).to.equal(null);
		const broadcast = aFinal.find(
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(a: any) => a.type === ChannelActionType.BROADCAST_TX
		);
		expect(broadcast, 'assembled funding tx broadcasts').to.exist;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const assembled = bitcoin.Transaction.fromBuffer((broadcast as any).tx);
		expect(assembled.ins.length).to.equal(3);
		expect(
			Buffer.from(assembled.getHash()).equals(record.fundingTxid),
			'rebuilt txid equals the negotiated outpoint'
		).to.be.true;
		for (const input of assembled.ins) {
			expect(input.witness.length).to.be.greaterThan(0);
		}
		// The external input's witness verifies over the assembled tx.
		const assembledExtIdx = assembled.ins.findIndex(
			(i) => Buffer.from(i.hash).equals(s.extPrevTx.getHash()) && i.index === 0
		);
		const extScriptCode = bitcoin.payments.p2pkh({
			pubkey: s.extPub
		}).output!;
		const extSighash = assembled.hashForWitnessV0(
			assembledExtIdx,
			extScriptCode,
			EXT_UTXO_SATS,
			bitcoin.Transaction.SIGHASH_ALL
		);
		const extSig = bitcoin.script.signature.decode(
			assembled.ins[assembledExtIdx].witness[0]
		).signature;
		expect(ecc.verify(extSighash, s.extPub, extSig)).to.be.true;
		expect(acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('a P2TR external witness verifies over BIP 341 and releases', function () {
		const s = driveToWithhold('p2tr');
		const { acceptor, opener } = s;
		const record = acceptor.getFullState().v2InFlight!;
		const extIdx = externalIndexOf(record, s.extPrevTx);

		// Sign as the taproot owner: key-spend over the BIP 341 sighash with
		// an explicit SIGHASH_ALL byte, tweaked key.
		const tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
		const scripts = record.inputPrevouts.map((p) => p.script);
		const values = record.inputPrevouts.map((p) => Number(p.valueSats));
		const sighash = tx.hashForWitnessV1(
			extIdx,
			scripts,
			values,
			bitcoin.Transaction.SIGHASH_ALL
		);
		const tweaked = taprootTweakPrivateKey(s.extPriv, s.extPub);
		const schnorr = Buffer.from(ecc.signSchnorr(sighash, tweaked));
		const witness = [
			Buffer.concat([schnorr, Buffer.from([bitcoin.Transaction.SIGHASH_ALL])])
		];

		const release = acceptor.provideV2ExternalWitness(
			Buffer.from(s.extPrevTx.getHash()),
			0,
			witness
		);
		expect(findError(release)).to.equal(null);
		const aSigsPayload = findPayload(release, MessageType.TX_SIGNATURES);
		expect(aSigsPayload).to.not.equal(null);
		// The opener validates the schnorr witness as an ordinary peer input.
		const oAfterPeerSigs = opener.handleTxSignatures(
			decodeTxSignaturesMessage(aSigsPayload!)
		);
		expect(findError(oAfterPeerSigs)).to.equal(null);
	});

	it('the wait survives a restart: the restored channel completes on delivery', function () {
		const s = driveToWithhold('p2wpkh');
		const before = s.acceptor.getFullState();
		const extIdxBefore = externalIndexOf(before.v2InFlight!, s.extPrevTx);

		// Serialize while the external slot is still owed, then restore into
		// a fresh Channel (builder-less session, closures gone).
		const row = deserializeChannelState(serializeChannelState(before));
		expect(row.v2InFlight!.externalInputIndices).to.deep.equal([extIdxBefore]);
		const restored = new Channel(
			row,
			new ChannelSigner(crypto.randomBytes(32))
		);
		restored.restoreV2InFlight();
		expect(
			row.dualFundingSession,
			'session restored builder-less'
		).to.not.equal(null);

		// The owner's witness, delivered AFTER the restart, still verifies
		// (the record carries the negotiated tx and prevouts) and releases.
		const witness = signExternalP2wpkh(
			row.v2InFlight!,
			s.extPrevTx,
			s.extPriv,
			s.extPub
		);
		const release = restored.provideV2ExternalWitness(
			Buffer.from(s.extPrevTx.getHash()),
			0,
			witness
		);
		expect(findError(release)).to.equal(null);
		const sigs = findPayload(release, MessageType.TX_SIGNATURES);
		expect(sigs, 'restored channel releases tx_signatures').to.not.equal(null);
		expect(row.v2InFlight!.sentTxSignatures).to.be.true;
		const decoded = decodeTxSignaturesMessage(sigs!);
		expect(decoded.witnesses.length).to.equal(2);

		// A late duplicate delivery after the release is a harmless no-op.
		expect(
			restored.provideV2ExternalWitness(
				Buffer.from(s.extPrevTx.getHash()),
				0,
				witness
			)
		).to.deep.equal([]);
	});

	it('the waiting open aborts cleanly without ever releasing a witness', function () {
		const s = driveToWithhold('p2wpkh');
		const { opener, acceptor } = s;

		const abort = acceptor.abortDualFunding('external witness timeout');
		expect(findError(abort)).to.equal(null);
		const abortPayload = findPayload(abort, MessageType.TX_ABORT);
		expect(abortPayload, 'tx_abort leaves').to.not.equal(null);
		// Teardown waits for the echo: the attempt is still resumable.
		expect(acceptor.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);

		expect(decodeTxAbortMessage(abortPayload!).channelId.length).to.equal(32);
		const oAbort = opener.handleTxAbort();
		const echoPayload = findPayload(oAbort, MessageType.TX_ABORT);
		expect(echoPayload, 'peer echoes the abort').to.not.equal(null);
		acceptor.handleTxAbort();
		expect(acceptor.getState()).to.equal(ChannelState.ERRORED);

		// No tx_signatures ever crossed in either direction.
		for (const batch of [abort, oAbort]) {
			expect(findPayload(batch, MessageType.TX_SIGNATURES)).to.equal(null);
		}
	});

	it('externalInputIndices round-trips through serialization with placeholders', function () {
		const record: IV2InFlight = {
			fundingTxid: crypto.randomBytes(32),
			fundingOutputIndex: 1,
			fundingTxHex: 'aa',
			fullySigned: false,
			isInitiator: false,
			localContributionSats: 50_000n,
			remoteContributionSats: 100_000n,
			fundingFeeratePerkw: 1000,
			weSignFirst: true,
			ourWitnesses: [
				[Buffer.from('0102', 'hex'), Buffer.from('03', 'hex')],
				[]
			],
			ourWalletInputIndices: [0, 2],
			externalInputIndices: [2],
			inputPrevouts: [
				{ script: Buffer.from('0014', 'hex'), valueSats: 40_000n }
			],
			remoteCommitmentSig: null,
			sentTxSignatures: false,
			receivedTxSignatures: false,
			confirmed: false,
			rbfAttempt: 0
		};
		const back = deserializeV2InFlight(serializeV2InFlight(record));
		expect(back.externalInputIndices).to.deep.equal([2]);
		expect(back.ourWitnesses[1]).to.deep.equal([]);
		expect(back.ourWitnesses[0].length).to.equal(2);
		// Records without external inputs stay shaped exactly as before.
		const plain = deserializeV2InFlight(
			serializeV2InFlight({ ...record, externalInputIndices: undefined })
		);
		expect(plain.externalInputIndices).to.equal(undefined);
	});
});
