/**
 * Dual-funding ACCEPTOR wallet-input contribution (v2 open, real keys).
 *
 * A lease seller (bLIP-0051 lessor) must FUND its fundingSatoshis share of
 * the interactive funding tx. With a contribution registered via
 * setDualFundingContribution, the acceptor now automatically:
 *  - contributes its wallet inputs + change output on its interactive-tx
 *    turns (one per turn, odd serial ids),
 *  - signs those inputs via the wallet closures and releases them in
 *    tx_signatures (BOLT 2 ordering: lower input total signs first),
 *  - assembles and broadcasts the fully-signed funding tx once the peer's
 *    witnesses arrive.
 * Previously nothing funded the acceptor share, so a real leased open toward
 * beignet-as-seller died insufficiently funded.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

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
import { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import { spliceFeeSats } from '../../src/lightning/channel/splice-weight';
import { createFundingScript } from '../../src/lightning/script/funding';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';

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
const ACCEPTOR_FUNDING = 50_000n; // the "leased" contribution
const TOTAL_FUNDING = OPENER_FUNDING + ACCEPTOR_FUNDING;
const WALLET_UTXO_SATS = 60_000;
const FUNDING_FEERATE = 1000;

describe('Dual funding acceptor contribution (auto-driven, real keys)', function () {
	it('contributes, signs and broadcasts the acceptor share end to end', function () {
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

		// ── The acceptor's REAL P2WPKH wallet UTXO + signing closure ──
		const walletPriv = crypto.randomBytes(32);
		const walletPub = getPublicKey(walletPriv);
		const walletPayment = bitcoin.payments.p2wpkh({ pubkey: walletPub });
		const walletPrevTx = new bitcoin.Transaction();
		walletPrevTx.version = 2;
		walletPrevTx.addInput(crypto.randomBytes(32), 0);
		walletPrevTx.addOutput(walletPayment.output!, WALLET_UTXO_SATS);
		const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
		const walletInput: ISpliceWalletInput = {
			prevTx: walletPrevTx.toBuffer(),
			prevOutputIndex: 0,
			value: BigInt(WALLET_UTXO_SATS),
			sequence: 0xfffffffd,
			signWitness: (tx, inputIndex, value) => {
				const sighash = tx.hashForWitnessV0(
					inputIndex,
					scriptCode,
					Number(value),
					bitcoin.Transaction.SIGHASH_ALL
				);
				const der = bitcoin.script.signature.encode(
					Buffer.from(ecc.sign(sighash, walletPriv)),
					bitcoin.Transaction.SIGHASH_ALL
				);
				return [der, walletPub];
			}
		};
		const changeScript = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20)
		}).output!;
		acceptor.setDualFundingContribution(
			[walletInput],
			changeScript,
			ACCEPTOR_FUNDING,
			FUNDING_FEERATE
		);

		const openerParams: IDualFundingParams = {
			fundingSatoshis: OPENER_FUNDING,
			fundingFeeratePerkw: FUNDING_FEERATE,
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
		};
		const acceptorParams: IDualFundingParams = {
			fundingSatoshis: ACCEPTOR_FUNDING,
			fundingFeeratePerkw: FUNDING_FEERATE,
			commitmentFeeratePerkw: DEFAULT_CHANNEL_CONFIG.feeratePerKw,
			dustLimitSatoshis: DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: DEFAULT_CHANNEL_CONFIG.maxHtlcValueInFlightMsat,
			htlcMinimumMsat: DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat,
			toSelfDelay: DEFAULT_CHANNEL_CONFIG.toSelfDelay,
			maxAcceptedHtlcs: DEFAULT_CHANNEL_CONFIG.maxAcceptedHtlcs,
			locktime: 0,
			localBasepoints: acceptorState.localBasepoints,
			localPerCommitmentSeed: acceptorState.localPerCommitmentSeed,
			secondPerCommitmentPoint: getPerCommitmentPoint(acceptorSeed, 1n)
		};

		// ── open_channel2 / accept_channel2 ──
		const openActions = opener.initiateOpenV2(openerParams);
		expect(findError(openActions)).to.equal(null);
		const openMsg = decodeOpenChannel2Message(
			findPayload(openActions, MessageType.OPEN_CHANNEL2)!
		);
		acceptorState.temporaryChannelId = Buffer.from(openMsg.channelId);
		const acceptActions = acceptor.handleOpenChannel2(openMsg, acceptorParams);
		expect(findError(acceptActions)).to.equal(null);
		opener.handleAcceptChannel2(
			decodeAcceptChannel2Message(
				findPayload(acceptActions, MessageType.ACCEPT_CHANNEL2)!
			)
		);

		// ── interactive-tx. The opener contributes manually; every acceptor
		//    turn is AUTO-DRIVEN by the registered contribution. ──
		const openerPrevTx = new bitcoin.Transaction();
		openerPrevTx.version = 2;
		openerPrevTx.addInput(crypto.randomBytes(32), 0);
		openerPrevTx.addOutput(
			Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
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

		// opener input -> acceptor auto-replies with ITS wallet input.
		const oIn = opener.addTxInput(openerInput);
		expect(findError(oIn)).to.equal(null);
		const aTurn1 = acceptor.handleTxAddInput(
			decodeTxAddInputMessage(findPayload(oIn, MessageType.TX_ADD_INPUT)!)
		);
		expect(findError(aTurn1)).to.equal(null);
		const aInPayload = findPayload(aTurn1, MessageType.TX_ADD_INPUT);
		expect(
			aInPayload,
			'acceptor auto-contributes its wallet input'
		).to.not.equal(null);
		const aInMsg = decodeTxAddInputMessage(aInPayload!);
		expect(aInMsg.serialId % 2n).to.equal(1n); // odd = acceptor
		expect(
			opener.handleTxAddInput(aInMsg).length,
			'opener records the acceptor input'
		).to.equal(0);

		// opener funding output -> acceptor auto-replies with its CHANGE.
		const funding = createFundingScript(openerFundingPub, acceptorFundingPub);
		const fundingOutput: IInteractiveTxOutput = {
			serialId: 2n,
			amountSats: TOTAL_FUNDING,
			scriptPubkey: funding.p2wshOutput
		};
		const oOut = opener.addTxOutput(fundingOutput);
		expect(findError(oOut)).to.equal(null);
		const aTurn2 = acceptor.handleTxAddOutput(
			decodeTxAddOutputMessage(findPayload(oOut, MessageType.TX_ADD_OUTPUT)!)
		);
		expect(findError(aTurn2)).to.equal(null);
		const aOutPayload = findPayload(aTurn2, MessageType.TX_ADD_OUTPUT);
		expect(aOutPayload, 'acceptor auto-adds its change output').to.not.equal(
			null
		);
		const aOutMsg = decodeTxAddOutputMessage(aOutPayload!);
		// Matches _computeDualFundingContributions' reserved weight (with the
		// interactive-tx balance-check cushion): 320 WU per input + 140 WU change.
		const expectedFee = spliceFeeSats(320 + 140, FUNDING_FEERATE);
		expect(aOutMsg.amountSats).to.equal(
			BigInt(WALLET_UTXO_SATS) - ACCEPTOR_FUNDING - expectedFee
		);
		expect(aOutMsg.scriptPubkey.equals(changeScript)).to.be.true;
		expect(opener.handleTxAddOutput(aOutMsg).length).to.equal(0);

		// opener completes -> acceptor auto-completes (and, once the opener's
		// tx_complete lands on it, emits its commitment_signed).
		const oComplete = opener.sendTxComplete();
		expect(findError(oComplete)).to.equal(null);
		const aTurn3 = acceptor.handleTxComplete();
		expect(findError(aTurn3)).to.equal(null);
		const aCompletePayload = findPayload(aTurn3, MessageType.TX_COMPLETE);
		expect(aCompletePayload, 'acceptor auto-sends tx_complete').to.not.equal(
			null
		);
		const acceptorCommit = findPayload(aTurn3, MessageType.COMMITMENT_SIGNED);
		expect(
			acceptorCommit,
			'acceptor emits commitment_signed once both completed'
		).to.not.equal(null);
		const oAfterComplete = opener.handleTxComplete();
		expect(findError(oAfterComplete)).to.equal(null);
		const openerCommit = findPayload(
			oAfterComplete,
			MessageType.COMMITMENT_SIGNED
		);
		expect(openerCommit, 'opener emits commitment_signed').to.not.equal(null);
		expect(acceptor.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);

		// ── commitment_signed exchange. The acceptor (60k input total vs the
		//    opener's 120k) signs tx_signatures FIRST — automatically, with the
		//    wallet-closure witnesses. ──
		const aCommitHandle = acceptor.handleCommitmentSigned(
			decodeCommitmentSignedMessage(openerCommit!)
		);
		expect(findError(aCommitHandle)).to.equal(null);
		const oCommitHandle = opener.handleCommitmentSigned(
			decodeCommitmentSignedMessage(acceptorCommit!)
		);
		expect(findError(oCommitHandle)).to.equal(null);

		// The acceptor's tx_signatures were auto-released during the commitment
		// flush (its wallet inputs signed via the closures).
		const aSigsPayload =
			findPayload(aCommitHandle, MessageType.TX_SIGNATURES) ??
			findPayload(oCommitHandle, MessageType.TX_SIGNATURES);
		expect(
			aSigsPayload,
			'acceptor auto-releases signed tx_signatures'
		).to.not.equal(null);
		const aSigs = decodeTxSignaturesMessage(aSigsPayload!);
		expect(aSigs.witnesses.length).to.equal(1);
		expect(aSigs.witnesses[0].length).to.equal(2);
		expect(aSigs.witnesses[0][1].equals(walletPub)).to.be.true;

		// Opener releases its own after the peer's arrive (manual, as before).
		const oAfterPeerSigs = opener.handleTxSignatures(aSigs);
		expect(findError(oAfterPeerSigs)).to.equal(null);
		const oSigsDeferred = opener.sendTxSignatures(
			opener.getFullState().fundingTxid!,
			opener.getFullState().fundingOutputIndex,
			[[Buffer.alloc(72)]]
		);
		expect(findError(oSigsDeferred)).to.equal(null);
		const oSigsPayload =
			findPayload(oSigsDeferred, MessageType.TX_SIGNATURES) ??
			findPayload(oAfterPeerSigs, MessageType.TX_SIGNATURES);
		expect(oSigsPayload, 'opener releases tx_signatures').to.not.equal(null);

		// Acceptor receives them and BROADCASTS the assembled funding tx.
		const aFinal = acceptor.handleTxSignatures(
			decodeTxSignaturesMessage(oSigsPayload!)
		);
		expect(findError(aFinal)).to.equal(null);
		const broadcast = aFinal.find(
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(a: any) => a.type === ChannelActionType.BROADCAST_TX
		);
		expect(broadcast, 'acceptor broadcasts the assembled funding tx').to.exist;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const assembled = bitcoin.Transaction.fromBuffer((broadcast as any).tx);
		expect(assembled.ins.length).to.equal(2);
		expect(assembled.getId()).to.equal(
			Buffer.from(acceptor.getFullState().fundingTxid!)
				.reverse()
				.toString('hex')
		);
		// Every input carries a witness; ours is a VALID P2WPKH signature.
		const ourIdx = assembled.ins.findIndex(
			(i) => Buffer.from(i.hash).equals(walletPrevTx.getHash()) && i.index === 0
		);
		expect(ourIdx).to.be.gte(0);
		for (const input of assembled.ins) {
			expect(input.witness.length).to.be.greaterThan(0);
		}
		const w = assembled.ins[ourIdx].witness;
		const sighash = assembled.hashForWitnessV0(
			ourIdx,
			scriptCode,
			WALLET_UTXO_SATS,
			bitcoin.Transaction.SIGHASH_ALL
		);
		const sig = bitcoin.script.signature.decode(w[0]).signature;
		expect(ecc.verify(sighash, walletPub, sig)).to.be.true;

		// Both sides reached AWAITING_FUNDING_CONFIRMED with matching outpoints.
		expect(acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(
			acceptor
				.getFullState()
				.fundingTxid!.equals(opener.getFullState().fundingTxid!)
		).to.be.true;
		expect(acceptor.getFundingSatoshis()).to.equal(TOTAL_FUNDING);
	});

	it('contributes MULTIPLE wallet inputs across turns (opener re-sends tx_complete)', function () {
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
		const opener = new Channel(
			openerState,
			new ChannelSigner(openerFundingPriv)
		);
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

		// TWO wallet UTXOs (40k + 30k) funding the 50k contribution.
		const walletPriv = crypto.randomBytes(32);
		const walletPub = getPublicKey(walletPriv);
		const walletPayment = bitcoin.payments.p2wpkh({ pubkey: walletPub });
		const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
		const makeWalletInput = (sats: number): ISpliceWalletInput => {
			const prev = new bitcoin.Transaction();
			prev.version = 2;
			prev.addInput(crypto.randomBytes(32), 0);
			prev.addOutput(walletPayment.output!, sats);
			return {
				prevTx: prev.toBuffer(),
				prevOutputIndex: 0,
				value: BigInt(sats),
				sequence: 0xfffffffd,
				signWitness: (tx, inputIndex, value) => {
					const sighash = tx.hashForWitnessV0(
						inputIndex,
						scriptCode,
						Number(value),
						bitcoin.Transaction.SIGHASH_ALL
					);
					const der = bitcoin.script.signature.encode(
						Buffer.from(ecc.sign(sighash, walletPriv)),
						bitcoin.Transaction.SIGHASH_ALL
					);
					return [der, walletPub];
				}
			};
		};
		const changeScript = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20)
		}).output!;
		acceptor.setDualFundingContribution(
			[makeWalletInput(40_000), makeWalletInput(30_000)],
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
		const openMsg = decodeOpenChannel2Message(
			findPayload(openActions, MessageType.OPEN_CHANNEL2)!
		);
		acceptorState.temporaryChannelId = Buffer.from(openMsg.channelId);
		const acceptActions = acceptor.handleOpenChannel2(
			openMsg,
			params(acceptorState, acceptorSeed, ACCEPTOR_FUNDING)
		);
		opener.handleAcceptChannel2(
			decodeAcceptChannel2Message(
				findPayload(acceptActions, MessageType.ACCEPT_CHANNEL2)!
			)
		);

		const openerPrev = new bitcoin.Transaction();
		openerPrev.version = 2;
		openerPrev.addInput(crypto.randomBytes(32), 0);
		openerPrev.addOutput(
			Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
			120_000
		);

		// Turn 1: opener input -> our wallet input #1.
		const oIn = opener.addTxInput({
			serialId: 0n,
			prevTxid: Buffer.from(openerPrev.getHash()),
			prevOutputIndex: 0,
			sequence: 0xfffffffd,
			prevTx: openerPrev.toBuffer(),
			prevTxVout: 0
		});
		const aTurn1 = acceptor.handleTxAddInput(
			decodeTxAddInputMessage(findPayload(oIn, MessageType.TX_ADD_INPUT)!)
		);
		const in1 = decodeTxAddInputMessage(
			findPayload(aTurn1, MessageType.TX_ADD_INPUT)!
		);
		opener.handleTxAddInput(in1);

		// Turn 2: opener funding output -> our wallet input #2.
		const funding = createFundingScript(openerFundingPub, acceptorFundingPub);
		const oOut = opener.addTxOutput({
			serialId: 2n,
			amountSats: TOTAL_FUNDING,
			scriptPubkey: funding.p2wshOutput
		});
		const aTurn2 = acceptor.handleTxAddOutput(
			decodeTxAddOutputMessage(findPayload(oOut, MessageType.TX_ADD_OUTPUT)!)
		);
		const in2Payload = findPayload(aTurn2, MessageType.TX_ADD_INPUT);
		expect(in2Payload, 'second wallet input on the second turn').to.not.equal(
			null
		);
		opener.handleTxAddInput(decodeTxAddInputMessage(in2Payload!));

		// Turn 3: opener completes -> our CHANGE output.
		const oComplete1 = opener.sendTxComplete();
		expect(findError(oComplete1)).to.equal(null);
		const aTurn3 = acceptor.handleTxComplete();
		const changePayload = findPayload(aTurn3, MessageType.TX_ADD_OUTPUT);
		expect(changePayload, 'change output after both inputs').to.not.equal(null);
		const changeMsg = decodeTxAddOutputMessage(changePayload!);
		const expectedFee = spliceFeeSats(320 * 2 + 140, FUNDING_FEERATE);
		expect(changeMsg.amountSats).to.equal(
			70_000n - ACCEPTOR_FUNDING - expectedFee
		);
		opener.handleTxAddOutput(changeMsg);

		// The opener re-sends tx_complete (its earlier one was invalidated by
		// our add); our next turn finishes with our own tx_complete.
		const oComplete2 = opener.sendTxComplete();
		expect(findError(oComplete2)).to.equal(null);
		const aTurn4 = acceptor.handleTxComplete();
		expect(findError(aTurn4)).to.equal(null);
		expect(
			findPayload(aTurn4, MessageType.TX_COMPLETE),
			'acceptor completes once contributions are exhausted'
		).to.not.equal(null);
		const acceptorCommit = findPayload(aTurn4, MessageType.COMMITMENT_SIGNED);
		expect(acceptorCommit).to.not.equal(null);
		const oAfter = opener.handleTxComplete();
		const openerCommit = findPayload(oAfter, MessageType.COMMITMENT_SIGNED);
		expect(openerCommit).to.not.equal(null);

		// Commitment round; the acceptor (70k < 120k input total) auto-signs
		// BOTH wallet inputs into its tx_signatures.
		const aCommitHandle = acceptor.handleCommitmentSigned(
			decodeCommitmentSignedMessage(openerCommit!)
		);
		expect(findError(aCommitHandle)).to.equal(null);
		const oCommitHandle = opener.handleCommitmentSigned(
			decodeCommitmentSignedMessage(acceptorCommit!)
		);
		expect(findError(oCommitHandle)).to.equal(null);
		const aSigsPayload =
			findPayload(aCommitHandle, MessageType.TX_SIGNATURES) ??
			findPayload(oCommitHandle, MessageType.TX_SIGNATURES);
		expect(aSigsPayload, 'acceptor auto-releases tx_signatures').to.not.equal(
			null
		);
		const aSigs = decodeTxSignaturesMessage(aSigsPayload!);
		expect(aSigs.witnesses.length).to.equal(2);
		for (const w of aSigs.witnesses) {
			expect(w.length).to.equal(2);
			expect(w[1].equals(walletPub)).to.be.true;
		}
	});
});
