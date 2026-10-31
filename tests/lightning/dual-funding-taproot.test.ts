import {
	classifyCommitmentTx,
	classifyOutputs
} from '../../src/lightning/chain/output-resolver';
import { CommitmentType } from '../../src/lightning/chain/types';
import { selectFundingEpoch } from '../../src/lightning/channel/funding-state';
import { decodeChannelReadyMessage } from '../../src/lightning/message/channel-funding';
import {
	decodeSpliceMessage,
	decodeSpliceAckMessage,
	decodeSpliceLockedMessage
} from '../../src/lightning/message/splice';
import { decodeStfuMessage } from '../../src/lightning/message/stfu';
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
import {
	createTaprootFundingScript,
	taprootKeySpendSighash
} from '../../src/lightning/script/funding-taproot';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxCompleteMessage,
	decodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';

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

function makeRealPrevOut(valueSats: number): {
	prevTx: Buffer;
	sign: (tx: bitcoin.Transaction, index: number) => Buffer[];
} {
	const priv = crypto.randomBytes(32);
	const pub = getPublicKey(priv);
	const payment = bitcoin.payments.p2wpkh({ pubkey: pub });
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(payment.output!, valueSats);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output!;
	return {
		prevTx: tx.toBuffer(),
		sign: (spend, index) => {
			const sighash = spend.hashForWitnessV0(
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

interface IHarness {
	opener: Channel;
	acceptor: Channel;
	openerSigner: ChannelSigner;
	acceptorSigner: ChannelSigner;
	openerSeed: Buffer;
	acceptorSeed: Buffer;

	openerCommit: Buffer;
	acceptorCommit: Buffer;

	openerWitness(): Buffer[][];
	acceptorWitness(): Buffer[][];
}

const OPENER_FUNDING = 100_000n;
const ACCEPTOR_FUNDING = 50_000n;
const TOTAL_FUNDING = OPENER_FUNDING + ACCEPTOR_FUNDING;

function driveToCommitmentExchange(
	commitmentFeeratePerkw: number = DEFAULT_CHANNEL_CONFIG.feeratePerKw
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
	opener.enableTaprootInteractiveFunding();

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
	acceptor.enableTaprootInteractiveFunding();

	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT);
	const openerParams: IDualFundingParams = {
		channelType: flags.toBuffer(),
		fundingSatoshis: OPENER_FUNDING,
		fundingFeeratePerkw: 1000,

		commitmentFeeratePerkw,
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
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw,
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

	const openActions = opener.initiateOpenV2(openerParams);
	expect(findError(openActions)).to.equal(null);
	const openPayload = findPayload(openActions, MessageType.OPEN_CHANNEL2)!;
	const openMsg = decodeOpenChannel2Message(openPayload);

	acceptorState.temporaryChannelId = Buffer.from(openMsg.channelId);

	const acceptActions = acceptor.handleOpenChannel2(openMsg, acceptorParams);
	expect(findError(acceptActions)).to.equal(null);
	const acceptPayload = findPayload(
		acceptActions,
		MessageType.ACCEPT_CHANNEL2
	)!;
	const acceptMsg = decodeAcceptChannel2Message(acceptPayload);

	const handleAcceptActions = opener.handleAcceptChannel2(acceptMsg);
	expect(findError(handleAcceptActions)).to.equal(null);

	const openerPrev = makeRealPrevOut(120_000);
	const acceptorPrev = makeRealPrevOut(60_000);
	const openerInput = makeInput(0n, openerPrev.prevTx);
	const acceptorInput = makeInput(1n, acceptorPrev.prevTx);

	const funding = createTaprootFundingScript(
		openerFundingPub,
		acceptorFundingPub
	);
	const fundingOutput: IInteractiveTxOutput = {
		serialId: 2n,
		amountSats: TOTAL_FUNDING,
		scriptPubkey: funding.p2trOutput
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

	const acCompleteA = acceptor.sendTxComplete();
	expect(findError(acCompleteA)).to.equal(null);
	expect(
		findPayload(acCompleteA, MessageType.COMMITMENT_SIGNED),
		'acceptor must NOT sign before the opener has also completed'
	).to.equal(null);
	opener.handleTxComplete(
		decodeTxCompleteMessage(findPayload(acCompleteA, MessageType.TX_COMPLETE)!)
	);

	const opCompleteActions = opener.sendTxComplete();
	expect(findError(opCompleteActions)).to.equal(null);
	const openerCommit = findPayload(
		opCompleteActions,
		MessageType.COMMITMENT_SIGNED
	);
	expect(
		openerCommit,
		'opener emits commitment_signed after both tx_completes'
	).to.not.equal(null);
	expect(opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);

	const acCompleteActions = acceptor.handleTxComplete(
		decodeTxCompleteMessage(
			findPayload(opCompleteActions, MessageType.TX_COMPLETE)!
		)
	);
	expect(findError(acCompleteActions)).to.equal(null);
	const acceptorCommit = findPayload(
		acCompleteActions,
		MessageType.COMMITMENT_SIGNED
	);
	expect(
		acceptorCommit,
		'acceptor emits commitment_signed once both tx_completes are in'
	).to.not.equal(null);
	expect(acceptor.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);

	const witnessFor = (channel: Channel, index: number): Buffer[][] => {
		const rec = channel.getFullState().v2InFlight!;
		const tx = bitcoin.Transaction.fromHex(rec.fundingTxHex);
		return [index === 0 ? openerPrev.sign(tx, 0) : acceptorPrev.sign(tx, 1)];
	};

	return {
		opener,
		acceptor,
		openerSigner,
		acceptorSigner,
		openerSeed,
		acceptorSeed,
		openerCommit: openerCommit!,
		acceptorCommit: acceptorCommit!,
		openerWitness: () => witnessFor(opener, 0),
		acceptorWitness: () => witnessFor(acceptor, 1)
	};
}

describe('native Taproot dual funding', () => {
	it('opens with both wallet contributions and restores broadcastable MuSig2 exits', () => {
		const h = driveToCommitmentExchange(1500);
		const originalExits = new Map<Channel, bitcoin.Transaction>();
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
		const a = h.acceptor.getFullState(),
			o = h.opener.getFullState();
		const acceptSigs = h.acceptor.sendTxSignatures(
			a.fundingTxid!,
			a.fundingOutputIndex,
			h.acceptorWitness()
		);
		expect(findError(acceptSigs)).to.equal(null);
		expect(
			findError(
				h.opener.handleTxSignatures(
					decodeTxSignaturesMessage(
						findPayload(acceptSigs, MessageType.TX_SIGNATURES)!
					)
				)
			)
		).to.equal(null);
		const openSigs = h.opener.sendTxSignatures(
			o.fundingTxid!,
			o.fundingOutputIndex,
			h.openerWitness()
		);
		expect(findError(openSigs)).to.equal(null);
		expect(
			findError(
				h.acceptor.handleTxSignatures(
					decodeTxSignaturesMessage(
						findPayload(openSigs, MessageType.TX_SIGNATURES)!
					)
				)
			)
		).to.equal(null);
		for (const [original, signer] of [
			[h.opener, h.openerSigner],
			[h.acceptor, h.acceptorSigner]
		] as const) {
			const restored = new Channel(
				deserializeChannelState(serializeChannelState(original.getFullState())),
				signer
			);
			restored.restoreV2InFlight();
			expect(restored.getFullState().v2InFlight!.fullySigned).to.equal(true);
			const result = restored.forceClose(signer);
			expect(findError(result)).to.equal(null);
			const broadcast = result.find(
				(action) => action.type === ChannelActionType.BROADCAST_TX
			)!;
			if (broadcast.type !== ChannelActionType.BROADCAST_TX)
				throw new Error('Missing close');
			const tx = bitcoin.Transaction.fromBuffer(broadcast.tx),
				state = restored.getFullState();
			originalExits.set(original, tx);
			const funding = createTaprootFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints!.fundingPubkey
			);
			expect(
				ecc.verifySchnorr(
					taprootKeySpendSighash(
						tx,
						0,
						[funding.p2trOutput],
						[Number(state.fundingSatoshis)]
					),
					funding.outputKey,
					tx.ins[0].witness[0]
				)
			).to.equal(true);
		}
		const oReady = h.opener.fundingConfirmed(),
			aReady = h.acceptor.fundingConfirmed();
		h.opener.handleChannelReady(
			decodeChannelReadyMessage(findPayload(aReady, MessageType.CHANNEL_READY)!)
		);
		h.acceptor.handleChannelReady(
			decodeChannelReadyMessage(findPayload(oReady, MessageType.CHANNEL_READY)!)
		);
		const oldFunding = Buffer.from(h.opener.getFullState().fundingTxid!);
		const wallet = makeRealPrevOut(50000),
			prior = bitcoin.Transaction.fromBuffer(wallet.prevTx);
		h.opener.setSpliceInInputs(
			[
				{
					prevTx: wallet.prevTx,
					prevOutputIndex: 0,
					value: 50000n,
					sequence: 0xfffffffd,
					signWitness: (tx, index) => wallet.sign(tx, index)
				}
			],
			prior.outs[0].script,
			{ lockAtDepth: 1 }
		);
		const queue: Array<{ to: Channel; from: Channel; actions: any[] }> = [];
		queue.push({
			to: h.acceptor,
			from: h.opener,
			actions: h.opener.initiateSplice(30000n, 253)
		});
		const broadcasts: bitcoin.Transaction[] = [];
		let iterations = 0;
		const pump = () => {
			while (queue.length) {
				if (++iterations > 100)
					throw new Error('Splice exchange did not settle');
				const { to, from, actions } = queue.shift()!;
				expect(findError(actions)).to.equal(null);
				for (const action of actions) {
					if (action.type === ChannelActionType.BROADCAST_TX)
						broadcasts.push(bitcoin.Transaction.fromBuffer(action.tx));
					if (action.type !== ChannelActionType.SEND_MESSAGE) continue;
					const payload = action.payload;
					let next: any[] = [];
					switch (action.messageType) {
						case MessageType.STFU:
							next = to.handleStfuMessage(decodeStfuMessage(payload));
							break;
						case MessageType.SPLICE:
							next = to.handleSplice(decodeSpliceMessage(payload));
							break;
						case MessageType.SPLICE_ACK:
							next = to.handleSpliceAck(decodeSpliceAckMessage(payload));
							break;
						case MessageType.TX_ADD_INPUT:
							next = to.handleTxAddInput(decodeTxAddInputMessage(payload));
							break;
						case MessageType.TX_ADD_OUTPUT:
							next = to.handleTxAddOutput(decodeTxAddOutputMessage(payload));
							break;
						case MessageType.TX_COMPLETE:
							next = to.handleTxComplete(decodeTxCompleteMessage(payload));
							break;
						case MessageType.TX_SIGNATURES:
							next = to.handleTxSignatures(decodeTxSignaturesMessage(payload));
							break;
						case MessageType.COMMITMENT_SIGNED:
							next = to.handleCommitmentSigned(
								decodeCommitmentSignedMessage(payload)
							);
							break;
						case MessageType.SPLICE_LOCKED:
							next = to.handleSpliceLocked(decodeSpliceLockedMessage(payload));
							break;
						case MessageType.TX_ABORT:
							throw new Error(
								'Splice aborted: ' + payload.subarray(34).toString()
							);
					}
					queue.push({ to: from, from: to, actions: next });
				}
			}
		};
		pump();
		expect(broadcasts.length).to.be.greaterThan(0);
		const splice = broadcasts[0],
			state = h.opener.getFullState(),
			funding = createTaprootFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints!.fundingPubkey
			);
		const index = splice.ins.findIndex((i) => i.hash.equals(oldFunding));
		const scripts = splice.ins.map((i) =>
			i.hash.equals(oldFunding) ? funding.p2trOutput : prior.outs[0].script
		);
		const values = splice.ins.map((i) =>
			i.hash.equals(oldFunding) ? Number(TOTAL_FUNDING) : 50000
		);
		expect(
			ecc.verifySchnorr(
				taprootKeySpendSighash(splice, index, scripts, values),
				funding.outputKey,
				splice.ins[index].witness[0]
			)
		).to.equal(true);
		for (const [original, signer] of [
			[h.opener, h.openerSigner],
			[h.acceptor, h.acceptorSigner]
		] as const) {
			const restored = new Channel(
				deserializeChannelState(serializeChannelState(original.getFullState())),
				signer
			);
			restored.restoreSpliceInFlight();
			const pending = restored.getFullState().spliceInFlight!;
			expect(pending.taprootRound!.ourSharedPartial).to.have.length(32);
			restored.markSpliceSeenOnChain(123);
			const result = restored.forceClose(signer);
			expect(findError(result)).to.equal(null);
			const action = result.find(
				(candidate) => candidate.type === ChannelActionType.BROADCAST_TX
			)!;
			if (action.type !== ChannelActionType.BROADCAST_TX)
				throw new Error('Missing pending splice exit');
			const close = bitcoin.Transaction.fromBuffer(action.tx);
			expect(close.ins[0].hash).to.deep.equal(splice.getHash());
			expect(
				ecc.verifySchnorr(
					taprootKeySpendSighash(
						close,
						0,
						[funding.p2trOutput],
						[Number(pending.newFundingSatoshis)]
					),
					funding.outputKey,
					close.ins[0].witness[0]
				)
			).to.equal(true);
			expect(restored.getFullState().fundingTxid).to.deep.equal(oldFunding);
		}
		h.opener.markSpliceConfirmed();
		h.acceptor.markSpliceConfirmed();
		queue.push({
			from: h.opener,
			to: h.acceptor,
			actions: h.opener.sendSpliceLocked()
		});
		queue.push({
			from: h.acceptor,
			to: h.opener,
			actions: h.acceptor.sendSpliceLocked()
		});
		pump();
		expect(Buffer.from(h.opener.getFullState().localNextNonce!)).to.deep.equal(
			h.acceptor.getFullState().remoteNonce
		);
		expect(
			Buffer.from(h.acceptor.getFullState().localNextNonce!)
		).to.deep.equal(h.opener.getFullState().remoteNonce);
		for (const [original, signer] of [
			[h.opener, h.openerSigner],
			[h.acceptor, h.acceptorSigner]
		] as const) {
			expect(original.getState()).to.equal(ChannelState.NORMAL);
			const restored = new Channel(
				deserializeChannelState(serializeChannelState(original.getFullState())),
				signer
			);
			const historic = selectFundingEpoch(
				restored.getFullState(),
				oldFunding,
				o.fundingOutputIndex
			);
			expect(historic.fundingSatoshis).to.equal(TOTAL_FUNDING);
			const originalExit = originalExits.get(original)!;
			expect(
				classifyCommitmentTx(originalExit, restored.getFullState()).type
			).equal(CommitmentType.OUR_COMMITMENT);
			expect(
				classifyOutputs(
					originalExit,
					restored.getFullState(),
					CommitmentType.OUR_COMMITMENT,
					historic.localCommitmentNumber
				).length
			).greaterThan(0);
			const oldCloseView = restored.closeViewForSpentOutpoint(
				{
					txid: Buffer.from(oldFunding).reverse().toString('hex'),
					outputIndex: o.fundingOutputIndex
				},
				true
			);
			expect(oldCloseView.view!.fundingTxid).deep.equal(oldFunding);
			const recovered = new Channel(
				deserializeChannelState(serializeChannelState(restored.getFullState())),
				signer
			);
			expect(recovered.getForceCloseBroadcastView()!.fundingTxid).deep.equal(
				oldFunding
			);
			expect(
				recovered.getForceCloseBroadcastView()!.remoteSigningNonce
			).deep.equal(historic.remoteSigningNonce);
			// Selecting the historical view never replaces the live funding record.
			expect(recovered.getFullState().fundingTxid).deep.equal(
				original.getFullState().fundingTxid
			);

			expect(() =>
				selectFundingEpoch(restored.getFullState(), Buffer.alloc(32, 99), 0)
			).to.throw('Unknown historical');
			const result = restored.forceClose(signer);
			expect(findError(result)).to.equal(null);
			const action = result.find(
				(candidate) => candidate.type === ChannelActionType.BROADCAST_TX
			)!;
			if (action.type !== ChannelActionType.BROADCAST_TX)
				throw new Error('Missing adopted splice exit');
			const close = bitcoin.Transaction.fromBuffer(action.tx);
			expect(close.ins[0].hash).to.deep.equal(splice.getHash());
			expect(
				ecc.verifySchnorr(
					taprootKeySpendSighash(
						close,
						0,
						[funding.p2trOutput],
						[Number(restored.getFullState().fundingSatoshis)]
					),
					funding.outputKey,
					close.ins[0].witness[0]
				)
			).to.equal(true);
		}
	});
});
