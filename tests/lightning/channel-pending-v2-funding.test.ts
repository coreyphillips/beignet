/**
 * Channel.getPendingV2FundingTx (issue #612, LFBW port #532 workstream 4C).
 *
 * The v2 twin of getPendingSpliceTx: what a third-party input owner needs to
 * sign an EXTERNAL input of a dual-funded open. Until this existed a host had
 * to reach getRawChannel(id).getFullState().v2InFlight and read fundingTxHex,
 * inputPrevouts and externalInputIndices itself, which is state access rather
 * than an API.
 *
 * Pinned here: the transaction comes back as a COPY (mutating it must not
 * invalidate signatures already made over the channel's own), the owed
 * outpoints are exactly the ones channel:txsigs-needed names, the prevout set
 * covers every input (a short one would make a BIP 341 signer sign against the
 * wrong script), and nothing is answered before the commitment round.
 */

import { expect } from 'chai';
import crypto from 'crypto';
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
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
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
import { createFundingScript } from '../../src/lightning/script/funding';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';

// ─────────────── Harness ───────────────

/* eslint-disable @typescript-eslint/no-explicit-any */
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

function findTxSigsNeeded(
	actions: any[]
): { inputIndices: number[]; externalInputIndices?: number[] } | null {
	for (const a of actions) {
		if (a.type === ChannelActionType.TX_SIGNATURES_NEEDED) return a;
	}
	return null;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

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
const ACCEPTOR_FUNDING = 20_000n;
const EXT_UTXO_SATS = 30_000;
const FUNDING_FEERATE = 1000;

interface ISetup {
	acceptor: Channel;
	acceptorActions: unknown[];
	extPrevTx: bitcoin.Transaction;
}

/**
 * Drive a real v2 open to the point where the acceptor's tx_signatures is due
 * and withheld on a third party's unfilled witness slot, exactly the shape a
 * direct-funded open reaches. The acceptor contributes ONE input and it is the
 * external one, which is what direct funding always does; its 30k total is
 * below the opener's 120k, so BOLT 2 ordering makes it sign first and the
 * stall is entirely on our side.
 */
function driveToOwedWitness(): ISetup {
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

	const extPub = getPublicKey(crypto.randomBytes(32));
	const extScript = bitcoin.payments.p2wpkh({ pubkey: extPub }).output!;
	const extPrevTx = new bitcoin.Transaction();
	extPrevTx.version = 2;
	extPrevTx.addInput(crypto.randomBytes(32), 0);
	extPrevTx.addOutput(extScript, EXT_UTXO_SATS);
	const externalInput: ISpliceWalletInput = {
		prevTx: extPrevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(EXT_UTXO_SATS),
		sequence: 0xfffffffd,
		signWitness: (): Buffer[] => {
			throw new Error('external input: the witness comes from its owner');
		},
		confirmed: true,
		external: true
	};
	acceptor.setDualFundingContribution(
		[externalInput],
		bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) }).output!,
		ACCEPTOR_FUNDING,
		FUNDING_FEERATE
	);

	const params = (
		state: IChannelState,
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

	const openerPub = getPublicKey(crypto.randomBytes(32));
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
		amountSats: OPENER_FUNDING + ACCEPTOR_FUNDING,
		scriptPubkey: funding.p2wshOutput
	});
	expect(findError(oOut)).to.equal(null);
	const aTurn2 = acceptor.handleTxAddOutput(
		decodeTxAddOutputMessage(findPayload(oOut, MessageType.TX_ADD_OUTPUT)!)
	);
	expect(findError(aTurn2)).to.equal(null);
	const changePayload = findPayload(aTurn2, MessageType.TX_ADD_OUTPUT);
	expect(changePayload, 'acceptor answers with its change').to.not.equal(null);
	opener.handleTxAddOutput(decodeTxAddOutputMessage(changePayload!));

	const oComplete = opener.sendTxComplete();
	expect(findError(oComplete)).to.equal(null);
	const aTurn3 = acceptor.handleTxComplete();
	expect(findError(aTurn3)).to.equal(null);
	const acceptorCommit = findPayload(aTurn3, MessageType.COMMITMENT_SIGNED);
	expect(
		acceptorCommit,
		'acceptor commits with the external hole'
	).to.not.equal(null);
	const oAfter = opener.handleTxComplete();
	expect(findError(oAfter)).to.equal(null);
	const openerCommit = findPayload(oAfter, MessageType.COMMITMENT_SIGNED);
	expect(openerCommit).to.not.equal(null);

	const acceptorActions = acceptor.handleCommitmentSigned(
		decodeCommitmentSignedMessage(openerCommit!)
	);
	expect(findError(acceptorActions)).to.equal(null);
	opener.handleCommitmentSigned(decodeCommitmentSignedMessage(acceptorCommit!));

	return { acceptor, acceptorActions, extPrevTx };
}

// ─────────────── Tests ───────────────

describe('Channel.getPendingV2FundingTx (issue #612)', () => {
	it('answers nothing before the commitment round has recorded an attempt', () => {
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: OPENER_FUNDING,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(
				getPublicKey(crypto.randomBytes(32)),
				crypto.randomBytes(32)
			),
			localPerCommitmentSeed: crypto.randomBytes(32)
		});
		const channel = new Channel(
			state,
			new ChannelSigner(crypto.randomBytes(32))
		);
		expect(channel.getPendingV2FundingTx()).to.equal(null);
	});

	it('names exactly the outpoints channel:txsigs-needed asks for', () => {
		const { acceptor, acceptorActions, extPrevTx } = driveToOwedWitness();
		const needed = findTxSigsNeeded(acceptorActions as unknown[]);
		expect(needed, 'the withhold is surfaced').to.not.equal(null);
		expect(needed!.externalInputIndices).to.not.equal(undefined);

		const pending = acceptor.getPendingV2FundingTx();
		expect(pending, 'the accessor answers once the record exists').to.not.equal(
			null
		);
		expect(pending!.owedExternalInputs.map((o) => o.inputIndex)).to.deep.equal(
			needed!.externalInputIndices
		);
		const owed = pending!.owedExternalInputs[0];
		expect(Buffer.from(owed.prevTxid).equals(extPrevTx.getHash())).to.be.true;
		expect(owed.prevOutputIndex).to.equal(0);
		expect(
			Buffer.from(pending!.tx.ins[owed.inputIndex].hash).equals(
				extPrevTx.getHash()
			),
			'the named index is the input it describes'
		).to.be.true;
	});

	it('carries a prevout for every input, and the funding outpoint', () => {
		const { acceptor } = driveToOwedWitness();
		const pending = acceptor.getPendingV2FundingTx()!;
		expect(pending.prevouts, 'prevouts resolve').to.not.equal(null);
		expect(pending.prevouts!.scripts.length).to.equal(pending.tx.ins.length);
		expect(pending.prevouts!.values.length).to.equal(pending.tx.ins.length);
		const owed = pending.owedExternalInputs[0];
		expect(pending.prevouts!.values[owed.inputIndex]).to.equal(
			BigInt(EXT_UTXO_SATS)
		);
		expect(pending.fundingTxid.equals(Buffer.from(pending.tx.getHash()))).to.be
			.true;
		expect(pending.tx.outs[pending.fundingOutputIndex].value).to.equal(
			Number(OPENER_FUNDING + ACCEPTOR_FUNDING)
		);
	});

	it('returns a copy: mutating it cannot reach the channel', () => {
		const { acceptor } = driveToOwedWitness();
		const first = acceptor.getPendingV2FundingTx()!;
		const before = first.tx.toHex();
		first.tx.outs[0].value = 1;
		first.tx.ins[0].sequence = 0;
		const second = acceptor.getPendingV2FundingTx()!;
		expect(second.tx.toHex()).to.equal(before);
		expect(second.tx.getHash().equals(first.fundingTxid)).to.be.true;
	});
});
