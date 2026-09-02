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
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
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
	extPriv: Buffer;
	extPub: Buffer;
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

	const extPriv = crypto.randomBytes(32);
	const extPub = getPublicKey(extPriv);
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

	return { acceptor, acceptorActions, extPrevTx, extPriv, extPub };
}

/** The third party's witness over the negotiated transaction. */
function signExternalInput(setup: ISetup): Buffer[] {
	const pending = setup.acceptor.getPendingV2FundingTx()!;
	const owed = pending.owedExternalInputs[0];
	const sighash = pending.tx.hashForWitnessV0(
		owed.inputIndex,
		bitcoin.payments.p2pkh({ pubkey: setup.extPub }).output!,
		EXT_UTXO_SATS,
		bitcoin.Transaction.SIGHASH_ALL
	);
	return [
		bitcoin.script.signature.encode(
			Buffer.from(ecc.sign(sighash, setup.extPriv)),
			bitcoin.Transaction.SIGHASH_ALL
		),
		setup.extPub
	];
}

/**
 * A ChannelManager holding the acceptor from `driveToOwedWitness`, resident
 * under its temporary id the way a live v2 exchange keeps it.
 */
function managerHolding(
	acceptor: Channel,
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	barrier?: any
): ChannelManager {
	const fundingPriv = crypto.randomBytes(32);
	const seed = crypto.randomBytes(32);
	const mgr = new ChannelManager({
		localBasepoints: makeBasepoints(getPublicKey(fundingPriv), seed),
		localPerCommitmentSeed: seed,
		localFundingPrivkey: fundingPriv,
		htlcBasepointSecret: crypto.randomBytes(32),
		...(barrier ? { durabilityBarrier: barrier } : {})
	});
	mgr.on('error', () => {});
	const tempHex = acceptor.getTemporaryChannelId().toString('hex');
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const internals = mgr as any;
	internals.tempChannels.set(tempHex, acceptor);
	internals.channelPeers.set(tempHex, getPublicKey(seed).toString('hex'));
	return mgr;
}

/** The opener side of a v2 open, as createDualFundedChannel takes it. */
function openerParams(
	fundingPriv: Buffer,
	seed: Buffer
): IDualFundingParams & {
	localBasepoints: IChannelBasepoints;
	localPerCommitmentSeed: Buffer;
	secondPerCommitmentPoint: Buffer;
} {
	return {
		fundingSatoshis: OPENER_FUNDING,
		fundingFeeratePerkw: FUNDING_FEERATE,
		commitmentFeeratePerkw: DEFAULT_CHANNEL_CONFIG.feeratePerKw,
		dustLimitSatoshis: DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis,
		maxHtlcValueInFlightMsat: DEFAULT_CHANNEL_CONFIG.maxHtlcValueInFlightMsat,
		htlcMinimumMsat: DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat,
		toSelfDelay: DEFAULT_CHANNEL_CONFIG.toSelfDelay,
		maxAcceptedHtlcs: DEFAULT_CHANNEL_CONFIG.maxAcceptedHtlcs,
		locktime: 0,
		localBasepoints: makeBasepoints(getPublicKey(fundingPriv), seed),
		localPerCommitmentSeed: seed,
		secondPerCommitmentPoint: getPerCommitmentPoint(seed, 1n)
	};
}

/** Quorum mode with nothing ever released: the first gated batch parks. */
function heldQueueBarrier(): unknown {
	return {
		enforcing: true,
		isReleased: (): boolean => false,
		whenReleased: (): Promise<never> => new Promise(() => undefined)
	};
}

/**
 * A LightningNode whose manager holds the acceptor the same way managerHolding
 * does, optionally in quorum mode with nothing released.
 */
function nodeHolding(acceptor: Channel, parked = false): LightningNode {
	const seed = crypto.randomBytes(32);
	const node = new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(
			getPublicKey(crypto.randomBytes(32)),
			seed
		),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto.randomBytes(32),
		network: Network.REGTEST
	});
	node.on('error', () => undefined);
	node.on('node:error', () => undefined);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const internals = (node as any).channelManager;
	if (parked) internals.config.durabilityBarrier = heldQueueBarrier();
	const tempHex = acceptor.getTemporaryChannelId().toString('hex');
	internals.tempChannels.set(tempHex, acceptor);
	internals.channelPeers.set(tempHex, getPublicKey(seed).toString('hex'));
	return node;
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

	/**
	 * The owed list empties as slots fill, so on its own it reads a funding that
	 * has taken a third party's witness as one that never had an external input
	 * at all. A caller resuming a delivery it crashed part way through needs to
	 * tell those two apart (issue #645).
	 */
	it('moves a delivered slot to filled and reports the release', () => {
		const setup = driveToOwedWitness();
		const before = setup.acceptor.getPendingV2FundingTx()!;
		expect(before.filledExternalInputs).to.deep.equal([]);
		expect(before.sentTxSignatures).to.equal(false);

		setup.acceptor.provideV2ExternalWitness(
			Buffer.from(setup.extPrevTx.getHash()),
			0,
			signExternalInput(setup)
		);
		const after = setup.acceptor.getPendingV2FundingTx()!;
		expect(after.owedExternalInputs).to.deep.equal([]);
		expect(after.filledExternalInputs.map((i) => i.inputIndex)).to.deep.equal(
			before.owedExternalInputs.map((i) => i.inputIndex)
		);
		expect(
			after.filledExternalInputs[0].prevTxid.equals(setup.extPrevTx.getHash())
		).to.equal(true);
		expect(after.sentTxSignatures).to.equal(true);
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

describe('ChannelManager.createDualFundedChannel dispatch failure (issue #612)', () => {
	it('retains no channel when the open_channel2 dispatch throws', () => {
		const fundingPriv = crypto.randomBytes(32);
		const seed = crypto.randomBytes(32);
		const mgr = new ChannelManager({
			localBasepoints: makeBasepoints(getPublicKey(fundingPriv), seed),
			localPerCommitmentSeed: seed,
			localFundingPrivkey: fundingPriv,
			htlcBasepointSecret: crypto.randomBytes(32)
		});
		const peer = getPublicKey(crypto.randomBytes(32)).toString('hex');
		mgr.on('message:outbound', () => {
			throw new Error('transport is gone');
		});

		// The caller gets an exception and no Channel, so nothing it can do
		// would ever reach this negotiation again.
		expect(() =>
			mgr.createDualFundedChannel(peer, openerParams(fundingPriv, seed))
		).to.throw('transport is gone');
		expect(mgr.listChannels()).to.have.length(0);
		expect(mgr.getChannelsByPeer(peer)).to.have.length(0);
	});
});

describe('ChannelManager.provideV2ExternalWitness reporting (issue #612)', () => {
	it('reports a clean release when the tx_signatures reach the wire', () => {
		const setup = driveToOwedWitness();
		const mgr = managerHolding(setup.acceptor);
		const sent: number[] = [];
		mgr.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});

		const result = mgr.provideV2ExternalWitness(
			setup.acceptor.getChannelId()!,
			Buffer.from(setup.extPrevTx.getHash()),
			0,
			signExternalInput(setup)
		);
		expect(result.ok).to.equal(true);
		expect(result.sendsWithheld).to.equal(false);
		expect(sent).to.include(MessageType.TX_SIGNATURES);
	});

	/**
	 * The obligation to the input's owner is discharged by the tx_signatures,
	 * and a batch the quorum barrier parked has not sent them: a refused
	 * release drops the held bytes outright. `ok` alone would tell a caller
	 * holding a receipt for that owner to hand it over.
	 */
	it('reports a witness whose tx_signatures the barrier parked', () => {
		const setup = driveToOwedWitness();
		const mgr = managerHolding(setup.acceptor, heldQueueBarrier());
		const sent: number[] = [];
		mgr.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});

		const result = mgr.provideV2ExternalWitness(
			setup.acceptor.getChannelId()!,
			Buffer.from(setup.extPrevTx.getHash()),
			0,
			signExternalInput(setup)
		);
		expect(result.ok, 'the channel took the witness').to.equal(true);
		expect(result.sendsWithheld, 'and nothing left').to.equal(true);
		expect(sent).to.not.include(MessageType.TX_SIGNATURES);
	});

	/**
	 * The owner re-sends its witness, as it must when no receipt came back. The
	 * channel already holds it and releases nothing, so the repeat carries no
	 * progress of its own: without consulting the queue it would report a clean
	 * dispatch for the same parked bytes.
	 */
	it('still reports withheld when the witness is retried behind the queue', () => {
		const setup = driveToOwedWitness();
		const mgr = managerHolding(setup.acceptor, heldQueueBarrier());
		const sent: number[] = [];
		mgr.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});
		const witness = signExternalInput(setup);
		const channelId = setup.acceptor.getChannelId()!;
		const prevTxid = Buffer.from(setup.extPrevTx.getHash());

		mgr.provideV2ExternalWitness(channelId, prevTxid, 0, witness);
		const retry = mgr.provideV2ExternalWitness(channelId, prevTxid, 0, witness);
		expect(retry.ok).to.equal(true);
		expect(
			retry.actions,
			'the channel had nothing left to release'
		).to.have.length(0);
		expect(retry.sendsWithheld).to.equal(true);
		expect(sent).to.not.include(MessageType.TX_SIGNATURES);
	});
});

describe('LightningNode.getPendingV2FundingTx release flag (issue #645)', () => {
	/**
	 * The channel marks the release as it BUILDS the batch, so recovery reading
	 * that mark alone would hand over a receipt earned by tx_signatures the
	 * barrier is still holding, and a refused release drops those outright.
	 */
	it('answers no release while the tx_signatures are parked', () => {
		const setup = driveToOwedWitness();
		const node = nodeHolding(setup.acceptor, true);
		const channelId = setup.acceptor.getChannelId()!;

		const result = node.provideV2ExternalWitness(
			channelId,
			Buffer.from(setup.extPrevTx.getHash()),
			0,
			signExternalInput(setup)
		);
		expect(result.sendsWithheld, 'nothing left').to.equal(true);
		expect(
			setup.acceptor.getPendingV2FundingTx()!.sentTxSignatures,
			'the channel recorded the release'
		).to.equal(true);
		const pending = node.getPendingV2FundingTx(channelId)!;
		expect(pending.filledExternalInputs).to.have.length(1);
		expect(pending.sentTxSignatures).to.equal(false);
	});

	it('answers the release once the tx_signatures reach the wire', () => {
		const setup = driveToOwedWitness();
		const node = nodeHolding(setup.acceptor);
		const channelId = setup.acceptor.getChannelId()!;

		const result = node.provideV2ExternalWitness(
			channelId,
			Buffer.from(setup.extPrevTx.getHash()),
			0,
			signExternalInput(setup)
		);
		expect(result.sendsWithheld).to.equal(false);
		expect(node.getPendingV2FundingTx(channelId)!.sentTxSignatures).to.equal(
			true
		);
	});
});

describe('ChannelManager.abortDualFundedOpen (issue #612)', () => {
	/**
	 * A RECORDED attempt tears down only on the peer's echo, and a disconnect
	 * before it resumes the negotiation. Reporting that as a release would let
	 * a host tell a third party the exchange is over while its funding is live.
	 */
	it('reports a tx_abort still awaiting the peer echo as pending', () => {
		const setup = driveToOwedWitness();
		const mgr = managerHolding(setup.acceptor);
		const sent: number[] = [];
		mgr.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});

		const result = mgr.abortDualFundedOpen(
			setup.acceptor.getChannelId()!,
			'direct funding session failed'
		);
		expect(result.ok).to.equal(true);
		expect(result.pending).to.equal(true);
		expect(sent).to.include(MessageType.TX_ABORT);
		expect(setup.acceptor.isV2AbortAwaitingEcho()).to.equal(true);
		// Nothing is torn down: the peer holds our verified commitment_signed.
		expect(setup.acceptor.getPendingV2FundingTx()).to.not.equal(null);
		// And the channel stays registered, because the echo is what ends it.
		expect(mgr.listChannels()).to.have.length(1);
	});

	/**
	 * A pre-record abort kills the negotiation on the spot: nothing was signed
	 * and nothing durable exists. Leaving the ERRORED lifecycle registered would
	 * strand it in listChannels until the peer echoed or the connection dropped.
	 */
	it('retains nothing when the abort killed the open outright', () => {
		const fundingPriv = crypto.randomBytes(32);
		const seed = crypto.randomBytes(32);
		const mgr = new ChannelManager({
			localBasepoints: makeBasepoints(getPublicKey(fundingPriv), seed),
			localPerCommitmentSeed: seed,
			localFundingPrivkey: fundingPriv,
			htlcBasepointSecret: crypto.randomBytes(32)
		});
		mgr.on('error', () => {});
		const peer = getPublicKey(crypto.randomBytes(32)).toString('hex');
		const sent: number[] = [];
		mgr.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});
		const channel = mgr.createDualFundedChannel(
			peer,
			openerParams(fundingPriv, seed)
		);

		const result = mgr.abortDualFundedOpen(
			channel.getTemporaryChannelId(),
			'direct funding session failed'
		);
		expect(result.ok).to.equal(true);
		expect(result.pending).to.equal(false);
		expect(sent).to.include(MessageType.TX_ABORT);
		expect(mgr.listChannels()).to.have.length(0);
		expect(mgr.getChannelsByPeer(peer)).to.have.length(0);
	});

	it('retains nothing when the tx_abort dispatch throws', () => {
		const fundingPriv = crypto.randomBytes(32);
		const seed = crypto.randomBytes(32);
		const mgr = new ChannelManager({
			localBasepoints: makeBasepoints(getPublicKey(fundingPriv), seed),
			localPerCommitmentSeed: seed,
			localFundingPrivkey: fundingPriv,
			htlcBasepointSecret: crypto.randomBytes(32)
		});
		mgr.on('error', () => {});
		const peer = getPublicKey(crypto.randomBytes(32)).toString('hex');
		const channel = mgr.createDualFundedChannel(
			peer,
			openerParams(fundingPriv, seed)
		);
		mgr.on('message:outbound', () => {
			throw new Error('transport is gone');
		});

		expect(() =>
			mgr.abortDualFundedOpen(channel.getTemporaryChannelId())
		).to.throw('transport is gone');
		expect(mgr.listChannels()).to.have.length(0);
		expect(mgr.getChannelsByPeer(peer)).to.have.length(0);
	});
});
