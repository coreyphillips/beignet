/**
 * #2151 Step 3a, contract test 3: every splice path but the conversion
 * transport refuses a splice_init or splice_ack carrying the asset
 * conversion TLV (65540), each by its own text (section 7), and the channel
 * stays usable: an update round succeeds afterwards.
 *
 * The TLV is appended by hand (BigSize type, BigSize length, a 32-byte
 * digest and a channel type), since a codec without the TLV cannot write
 * it. A codec without it refuses the bytes as an unknown even TLV, so on a
 * tree without Step 3a these tests fail at that decode, never at the guard.
 *
 * Avoiding tautologies:
 * - the plain final splice_init carries no lock depth, since today's lock
 *   depth refusal would refuse it with the same text otherwise;
 * - the asset splice_init and splice_ack carry a valid lock depth, so
 *   validOptions and the depth echo pass and only the new guard refuses;
 * - the composite splice_ack contributes nothing, so the composite branch
 *   would let it through.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import sinon from 'sinon';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	Channel,
	type ISpliceWalletInput
} from '../../src/lightning/channel/channel';
import {
	createAcceptorState,
	createOpenerState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import type { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	decodeAcceptChannelMessage,
	decodeOpenChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeChannelReadyMessage,
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage
} from '../../src/lightning/message/channel-funding';
import {
	decodeSpliceAckMessage,
	decodeSpliceMessage,
	encodeSpliceAckMessage,
	encodeSpliceMessage
} from '../../src/lightning/message/splice';
import { decodeStfuMessage } from '../../src/lightning/message/stfu';
import {
	decodeTxAbortMessage,
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { decodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { encodeBigSize } from '../../src/lightning/message/codec';
import { FinalSpliceTransport } from '../../src/lightning/channel/final-splice-transport';
import { FinalSpliceSession } from '../../src/lightning/channel/final-splice-session';
import type { IFinalOpeningMessage } from '../../src/lightning/channel/final-opening-runtime';
import {
	prepareAssetSpliceAgreement,
	type IAssetSpliceContext,
	type IAssetSplicePlanner
} from '../../src/lightning/channel/asset-splice-agreement';
import {
	assetSpliceLayoutDigest,
	type IAssetSpliceLayout
} from '../../src/lightning/channel/asset-splice-manifest';
import { REGTEST_CHAIN_HASH } from '../../src/lightning/chain/hashes';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import type { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { assetSpliceUpdateHead } from '../../src/lightning/storage/asset-update-history';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from '../../src/lightning/features/asset-opening';
import {
	signerFromSeed,
	realInitialCommitmentSig
} from './helpers/real-signing';
import { writableState } from './helpers/writable-state';
import { createNode, openReadyChannel } from './helpers/loopback-nodes';
import type { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	assetTypePair,
	plainTypePair,
	scratch,
	type Scratch
} from './helpers/channel-type-pairs';
import {
	assetRounds,
	plainRounds,
	type ITypeDevice
} from './helpers/channel-type-record';
import { PLAIN_TARGET_TYPE_HEX } from './helpers/conversion-terms-sample';

bitcoin.initEccLib(ecc);

const LEGACY_TEXT = 'Asset conversion is not offered on this channel';

/** The asset conversion TLV record: type 65540, a 32-byte digest, then the type. */
function conversionTlv(targetTypeHex = PLAIN_TARGET_TYPE_HEX): Buffer {
	const value = Buffer.concat([
		Buffer.alloc(32, 0x5a),
		Buffer.from(targetTypeHex, 'hex')
	]);
	return Buffer.concat([
		encodeBigSize(65540n),
		encodeBigSize(BigInt(value.length)),
		value
	]);
}
/** A splice message with the TLV appended: 65540 sorts after 2 and 65537. */
const withConversion = (payload: Buffer, targetTypeHex?: string): Buffer =>
	Buffer.concat([payload, conversionTlv(targetTypeHex)]);

const abortText = (payload: Buffer): string =>
	decodeTxAbortMessage(payload).data.toString();

describe('Asset conversion TLV fixture (#2151 step 3a, test 3)', () => {
	it('is the record of type 65540 after every TLV of a splice message', () => {
		const tlv = conversionTlv();
		expect(tlv.subarray(0, 5).toString('hex')).to.equal('fe00010004');
		expect(tlv[5]).to.equal(32 + 11);
		expect(tlv).to.have.length(5 + 1 + 43);
		const long = conversionTlv(ASSET_SPLICE_RECOVERY_TYPE_HEX);
		expect(long.subarray(5, 6).toString('hex')).to.be.oneOf(['fd', 'fe']);
	});
});

// ---------------------------------------------------------------------------
// Legacy channels: Channel.handleSplice and Channel.handleSpliceAck.
// ---------------------------------------------------------------------------

const FUNDING_SATOSHIS = 1_000_000n;
const SPLICE_AMOUNT = 300_000n;
const OWN_UTXO_SATS = SPLICE_AMOUNT + 100_000n;
const openerSeed = Buffer.alloc(32, 0x41);
const acceptorSeed = Buffer.alloc(32, 0x42);
const commitmentSeed = (tag: string): Buffer =>
	crypto.createHash('sha256').update(tag).digest();

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys = Array.from({ length: 6 }, (_, i) =>
		crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest()
	);
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: getPublicKey(keys[5])
	};
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Action = any;
const sendOf = (actions: Action[], type: MessageType): Action =>
	actions.find(
		(a: Action) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === type
	);

/** An opener and acceptor pair of live legacy channels in NORMAL. */
function makeNormalChannel(): { opener: Channel; acceptor: Channel } {
	const openerBp = makeBasepoints(openerSeed);
	const tempId = Buffer.alloc(32, 0xbb);
	const opener = new Channel(
		createOpenerState({
			temporaryChannelId: tempId,
			fundingSatoshis: FUNDING_SATOSHIS,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBp,
			localPerCommitmentSeed: commitmentSeed('conversion-refusal-opener')
		})
	);
	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: tempId,
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(acceptorSeed),
			localPerCommitmentSeed: commitmentSeed('conversion-refusal-acceptor'),
			remoteBasepoints: openerBp,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);
	opener.setSigner(signerFromSeed(openerSeed));
	acceptor.setSigner(signerFromSeed(acceptorSeed));
	const open = sendOf(opener.initiateOpen(), MessageType.OPEN_CHANNEL);
	const accepted = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(open.payload)
	);
	opener.handleAcceptChannel(
		decodeAcceptChannelMessage(
			sendOf(accepted, MessageType.ACCEPT_CHANNEL).payload
		)
	);
	const fundingTxid = crypto.randomBytes(32);
	const created = sendOf(
		opener.createFundingCreated(
			fundingTxid,
			0,
			realInitialCommitmentSig(opener, fundingTxid, 0)
		),
		MessageType.FUNDING_CREATED
	);
	const fc = decodeFundingCreatedMessage(created.payload);
	const signed = sendOf(
		acceptor.handleFundingCreated(
			fc,
			realInitialCommitmentSig(acceptor, fc.fundingTxid, fc.fundingOutputIndex)
		),
		MessageType.FUNDING_SIGNED
	);
	opener.handleFundingSigned(decodeFundingSignedMessage(signed.payload));
	const openerReady = opener.fundingConfirmed();
	const acceptorReady = acceptor.fundingConfirmed();
	opener.handleChannelReady(
		decodeChannelReadyMessage(
			sendOf(acceptorReady, MessageType.CHANNEL_READY).payload
		)
	);
	acceptor.handleChannelReady(
		decodeChannelReadyMessage(
			sendOf(openerReady, MessageType.CHANNEL_READY).payload
		)
	);
	expect(opener.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
	return { opener, acceptor };
}

interface ILegacyPair {
	opener: Channel;
	acceptor: Channel;
	actions: { from: Channel; action: Action }[];
	sent: { from: Channel; type: MessageType; payload: Buffer }[];
	enqueue(to: Channel, from: Channel, produced: Action[]): void;
	pump(): void;
	intercept(type: MessageType, fn: (payload: Buffer) => Buffer): void;
}

/** A wire between the two channels, decoding each message as a peer would. */
function legacyPair(): ILegacyPair {
	const { opener, acceptor } = makeNormalChannel();
	const deliver = (
		ch: Channel,
		type: MessageType,
		payload: Buffer
	): Action[] => {
		switch (type) {
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
			case MessageType.UPDATE_ADD_HTLC:
				return ch.handleUpdateAddHtlc(decodeUpdateAddHtlcMessage(payload));
			default:
				return [];
		}
	};
	const queue: {
		to: Channel;
		from: Channel;
		type: MessageType;
		payload: Buffer;
	}[] = [];
	const rules = new Map<MessageType, (payload: Buffer) => Buffer>();
	const actions: ILegacyPair['actions'] = [];
	const sent: ILegacyPair['sent'] = [];
	const enqueue = (to: Channel, from: Channel, produced: Action[]): void => {
		for (const a of produced) {
			actions.push({ from, action: a });
			if (a.type !== ChannelActionType.SEND_MESSAGE) continue;
			const rule = rules.get(a.messageType);
			const payload = rule ? rule(a.payload) : a.payload;
			sent.push({ from, type: a.messageType, payload });
			queue.push({ to, from, type: a.messageType, payload });
		}
	};
	return {
		opener,
		acceptor,
		actions,
		sent,
		enqueue,
		pump(): void {
			for (let steps = 0; queue.length; steps++) {
				if (steps > 400) throw new Error('message pump did not settle');
				const { to, from, type, payload } = queue.shift()!;
				enqueue(from, to, deliver(to, type, payload));
			}
		},
		intercept(type, fn): void {
			rules.set(type, fn);
		}
	};
}

/** One P2WPKH input the opener owns, with a real signer. */
function ownWallet(): { inputs: ISpliceWalletInput[]; changeScript: Buffer } {
	const priv = commitmentSeed('conversion-refusal-own-key');
	const pub = Buffer.from(ecc.pointFromScalar(priv, true)!);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output!;
	const prev = new bitcoin.Transaction();
	prev.version = 2;
	prev.addInput(crypto.randomBytes(32), 0);
	prev.addOutput(
		bitcoin.payments.p2wpkh({ pubkey: pub }).output!,
		Number(OWN_UTXO_SATS)
	);
	return {
		changeScript: bitcoin.payments.p2wpkh({ pubkey: pub }).output!,
		inputs: [
			{
				prevTx: prev.toBuffer(),
				prevOutputIndex: 0,
				value: OWN_UTXO_SATS,
				sequence: 0xfffffffd,
				confirmed: true,
				signWitness: (tx, index, value): Buffer[] => {
					const sighash = tx.hashForWitnessV0(
						index,
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
			}
		]
	};
}

const sentBy = (
	pair: ILegacyPair,
	from: Channel,
	type: MessageType
): Buffer[] =>
	pair.sent
		.filter((m) => m.from === from && m.type === type)
		.map((m) => m.payload);
const errorsOf = (pair: ILegacyPair, from: Channel): string[] =>
	pair.actions
		.filter((a) => a.from === from && a.action.type === ChannelActionType.ERROR)
		.map((a) => String(a.action.message));

/** Both channels back in NORMAL, and an HTLC from the opener lands at the acceptor. */
function expectUsable(pair: ILegacyPair): void {
	for (const ch of [pair.opener, pair.acceptor])
		expect(ch.getState()).to.equal(ChannelState.NORMAL);
	const before = pair.actions.length;
	const adds = sentBy(pair, pair.opener, MessageType.UPDATE_ADD_HTLC).length;
	pair.enqueue(
		pair.acceptor,
		pair.opener,
		pair.opener.addHtlc(
			50_000_000n,
			crypto.createHash('sha256').update('conversion-refusal').digest(),
			500_000,
			Buffer.alloc(1366)
		)
	);
	pair.pump();
	expect(sentBy(pair, pair.opener, MessageType.UPDATE_ADD_HTLC)).to.have.length(
		adds + 1
	);
	const later = pair.actions.slice(before);
	expect(
		later.filter((a) => a.action.type === ChannelActionType.ERROR),
		'errors after the refusal'
	).to.deep.equal([]);
}

describe('Legacy channels refuse the asset conversion TLV (#2151 step 3a, test 3)', function () {
	it('refuses a splice_init carrying it with tx_abort and the error, and the channel then takes an HTLC', () => {
		const pair = legacyPair();
		pair.intercept(MessageType.SPLICE, (payload) => withConversion(payload));
		const wallet = ownWallet();
		pair.opener.setSpliceInInputs(wallet.inputs, wallet.changeScript);
		pair.enqueue(
			pair.acceptor,
			pair.opener,
			pair.opener.initiateSplice(SPLICE_AMOUNT, 253)
		);
		pair.pump();
		expect(sentBy(pair, pair.opener, MessageType.SPLICE)).to.have.length(1);
		const aborts = sentBy(pair, pair.acceptor, MessageType.TX_ABORT);
		expect(aborts.map(abortText)).to.deep.equal([LEGACY_TEXT]);
		// By inclusion: refuseSpliceInit may prefix the action text (amendment v3.1 item 8).
		const errors = errorsOf(pair, pair.acceptor);
		expect(errors).to.have.length(1);
		expect(errors[0]).to.include(LEGACY_TEXT);
		expect(sentBy(pair, pair.acceptor, MessageType.SPLICE_ACK)).to.be.empty;
		expect(sentBy(pair, pair.opener, MessageType.TX_ADD_INPUT)).to.be.empty;
		expectUsable(pair);
	});

	it('refuses a splice_ack carrying it with tx_abort, the abort and the error, and the channel then takes an HTLC', () => {
		const pair = legacyPair();
		pair.intercept(MessageType.SPLICE_ACK, (payload) =>
			withConversion(payload)
		);
		const wallet = ownWallet();
		pair.opener.setSpliceInInputs(wallet.inputs, wallet.changeScript);
		pair.enqueue(
			pair.acceptor,
			pair.opener,
			pair.opener.initiateSplice(SPLICE_AMOUNT, 253)
		);
		pair.pump();
		expect(sentBy(pair, pair.acceptor, MessageType.SPLICE_ACK)).to.have.length(
			1
		);
		expect(
			sentBy(pair, pair.opener, MessageType.TX_ABORT).map(abortText)
		).to.deep.equal([LEGACY_TEXT]);
		const errors = errorsOf(pair, pair.opener);
		expect(errors.some((e) => e.includes(LEGACY_TEXT))).to.equal(true);
		expect(sentBy(pair, pair.opener, MessageType.TX_ADD_INPUT)).to.be.empty;
		expectUsable(pair);
	});

	it('refuses it in a composite splice (#1922) before the composite branch, and the channel then takes an HTLC', () => {
		const pair = legacyPair();
		pair.intercept(MessageType.SPLICE_ACK, (payload) =>
			withConversion(payload)
		);
		const state = writableState(pair.opener);
		const destination = bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(Buffer.alloc(32, 0x44))
		}).output!;
		expect(
			pair.opener.setCompositeSpliceContribution({
				compositeId: Buffer.alloc(32, 0x19),
				inputs: [
					{
						serialId: 0n,
						prevTxid: Buffer.from(state.fundingTxid!),
						prevOutputIndex: state.fundingOutputIndex!,
						prevTx: Buffer.alloc(0),
						valueSats: state.fundingSatoshis,
						shared: true
					}
				],
				outputs: [
					{ serialId: 2n, scriptPubkey: destination, amountSats: 50_000n }
				]
			})
		).to.equal(null);
		pair.enqueue(
			pair.acceptor,
			pair.opener,
			pair.opener.initiateSplice(-60_000n, 253)
		);
		pair.pump();
		const acks = sentBy(pair, pair.acceptor, MessageType.SPLICE_ACK);
		expect(acks).to.have.length(1);
		// The acceptor adds nothing, so the composite branch alone would go on.
		expect(
			decodeSpliceAckMessage(
				acks[0].subarray(0, acks[0].length - conversionTlv().length)
			).relativeSatoshis
		).to.equal(0n);
		expect(
			sentBy(pair, pair.opener, MessageType.TX_ABORT).map(abortText)
		).to.deep.equal([LEGACY_TEXT]);
		expect(
			errorsOf(pair, pair.opener).some((e) => e.includes(LEGACY_TEXT))
		).to.equal(true);
		expect(sentBy(pair, pair.opener, MessageType.TX_ADD_INPUT)).to.be.empty;
		expectUsable(pair);
	});
});

describe('Legacy channels on the node refuse the asset conversion TLV (#2151 step 3a, test 3)', function () {
	const nodes: LightningNode[] = [];
	afterEach(() => {
		for (const n of nodes.splice(0)) n.destroy();
	});
	const tick = (ms = 60): Promise<void> =>
		new Promise((resolve) => setTimeout(resolve, ms));

	/** Two loopback nodes over a ready legacy channel, with the TLV added to one message type. */
	interface INodePair {
		alice: LightningNode;
		bob: LightningNode;
		id: Buffer;
		sent: { from: 'alice' | 'bob'; type: number; payload: Buffer }[];
		errors: string[];
	}
	async function nodePair(
		seed: number,
		carrying: MessageType
	): Promise<INodePair> {
		const alice = createNode('conversion-refusal', seed),
			bob = createNode('conversion-refusal', seed + 1);
		nodes.push(alice, bob);
		const sent: INodePair['sent'] = [];
		const errors: string[] = [];
		for (const n of [alice, bob]) {
			n.on('node:error', (e: unknown) => errors.push(String(e)));
			n.getChannelManager().on('error', (_id: unknown, message: string) =>
				errors.push(String(message))
			);
		}
		const link = (
			from: LightningNode,
			to: LightningNode,
			name: 'alice' | 'bob'
		): void => {
			from.on(
				'message:outbound',
				(pubkey: string, type: number, raw: Buffer) => {
					const payload = type === carrying ? withConversion(raw) : raw;
					sent.push({ from: name, type, payload });
					if (pubkey === to.getNodeId())
						to.handlePeerMessage(from.getNodeId(), type, payload);
				}
			);
		};
		link(alice, bob, 'alice');
		link(bob, alice, 'bob');
		const id = openReadyChannel(alice, bob);
		await tick();
		return { alice, bob, id, sent, errors };
	}

	async function refusedOnNode(
		carrying: MessageType.SPLICE | MessageType.SPLICE_ACK,
		seed: number
	): Promise<void> {
		const { alice, bob, id, sent, errors } = await nodePair(seed, carrying);
		const destination = bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(Buffer.alloc(32, 0x45))
		}).output!;
		expect(alice.spliceOut(id, 50_000n, 253, destination).ok).to.equal(true);
		await tick(100);
		const refuser = carrying === MessageType.SPLICE ? 'bob' : 'alice';
		expect(
			sent
				.filter((m) => m.from === refuser && m.type === MessageType.TX_ABORT)
				.map((m) => abortText(m.payload))
		).to.deep.equal([LEGACY_TEXT]);
		expect(errors.some((e) => e.includes(LEGACY_TEXT))).to.equal(true);
		expect(sent.some((m) => m.type === MessageType.TX_ADD_INPUT)).to.equal(
			false
		);
		for (const n of [alice, bob])
			expect(n.getChannelManager().getChannel(id)!.getState()).to.equal(
				ChannelState.NORMAL
			);
		const result = alice
			.getChannelManager()
			.addHtlc(id, 1_000_000n, Buffer.alloc(32, 3), 500, Buffer.alloc(1366));
		expect(result.ok, result.error).to.equal(true);
		await tick();
		expect(
			sent.some(
				(m) => m.from === 'alice' && m.type === MessageType.UPDATE_ADD_HTLC
			)
		).to.equal(true);
		for (const n of [alice, bob])
			expect(n.getChannelManager().getChannel(id)!.getState()).to.equal(
				ChannelState.NORMAL
			);
	}

	it('refuses a splice_init carrying it at the acceptor, and the channel then takes an HTLC', async () => {
		await refusedOnNode(MessageType.SPLICE, 9201);
	});

	it('refuses a splice_ack carrying it at the initiator, and the channel then takes an HTLC', async () => {
		await refusedOnNode(MessageType.SPLICE_ACK, 9211);
	});
});

// ---------------------------------------------------------------------------
// Plain final channels: FinalSpliceSession behind FinalSpliceTransport.
// ---------------------------------------------------------------------------

const EMPTY_PLAN = {
	localDelta: '0',
	feeBudget: '0',
	feerate: 1000,
	locktime: 0,
	inputs: [],
	outputs: []
};

interface IFinalSide {
	wire: FinalSpliceTransport;
	sent: IFinalOpeningMessage[];
	failures: string[];
}
function finalTransport(
	store: SqliteStorage,
	root: ITypeDevice['root'],
	id: string
): IFinalSide {
	const sent: IFinalOpeningMessage[] = [];
	const failures: string[] = [];
	const wire = new FinalSpliceTransport(
		{ storage: store, root },
		() => ({ releaseInputPledges: async (): Promise<void> => {} }),
		async () => 'unspent',
		undefined,
		(_peer, type, payload) => sent.push({ type, payload }),
		() => {},
		() => {},
		() => {},
		() => false,
		(_id, reason) => failures.push(reason)
	);
	wire.fundingDepth(id, true);
	return { wire, sent, failures };
}

describe('Plain final channels refuse the asset conversion TLV (#2151 step 3a, test 3)', function () {
	this.timeout(60000);
	let s: Scratch;
	let thrown: ReturnType<typeof sinon.spy>;
	beforeEach(() => {
		s = scratch('conversion-refusal-final-');
		thrown = sinon.spy(FinalSpliceSession.prototype, 'receive');
	});
	afterEach(() => {
		sinon.restore();
		s.release();
	});
	const errorsThrown = (): string[] =>
		thrown.exceptions.filter(Boolean).map((e: Error) => e.message);

	async function negotiate(
		pair: ReturnType<typeof plainTypePair>
	): Promise<{ i: IFinalSide; a: IFinalSide; live: () => boolean }> {
		const { id, devices } = pair;
		const opener = devices.findIndex(
			(d) => d.store.loadFinalOpening(id)!.isInitiator
		);
		const sides = [opener, 1 - opener].map((i) =>
			finalTransport(devices[i].store, devices[i].root, id)
		);
		const [i, a] = sides;
		const live = (): boolean => true;
		i.wire.start(id, EMPTY_PLAN);
		expect(i.sent.map((m) => m.type)).to.deep.equal([MessageType.STFU]);
		await a.wire.receive(id, i.sent[0], true, live);
		expect(a.sent.map((m) => m.type)).to.deep.equal([MessageType.STFU]);
		await i.wire.receive(id, a.sent[0], true, live);
		expect(i.sent.map((m) => m.type)).to.deep.equal([
			MessageType.STFU,
			MessageType.SPLICE
		]);
		return { i, a, live };
	}

	it('refuses a splice_init carrying it, without a lock depth, as an unsupported proposal, and an update round follows', async () => {
		const pair = plainTypePair(s, 0, 6);
		const { i, a, live } = await negotiate(pair);
		const init = i.sent[1].payload;
		// No lock depth: today's lock depth refusal would refuse it otherwise.
		expect(decodeSpliceMessage(init).lockDepth).to.equal(undefined);
		await a.wire.receive(
			pair.id,
			{ type: MessageType.SPLICE, payload: withConversion(init) },
			true,
			live
		);
		expect(errorsThrown()).to.include('Unsupported splice proposal');
		const abort = a.sent.at(-1)!;
		expect(abort.type).to.equal(MessageType.TX_ABORT);
		expect(abortText(abort.payload)).to.equal('Refused splice negotiation');
		expect(a.sent.map((m) => m.type)).not.to.include(MessageType.SPLICE_ACK);
		await i.wire.receive(pair.id, abort, true, live);
		const echo = i.sent.at(-1)!;
		expect(echo.type).to.equal(MessageType.TX_ABORT);
		await a.wire.receive(pair.id, echo, true, live);
		expect(() => plainRounds(pair.devices, pair.id, 1)).not.to.throw();
		expect(pair.stores[0].loadFinalUpdateStatus(pair.id)!.localHeight).to.equal(
			1n
		);
	});

	it('refuses a splice_ack carrying it as an unexpected acknowledgment, and an update round follows', async () => {
		const pair = plainTypePair(s, 0, 6);
		const { i, a, live } = await negotiate(pair);
		await a.wire.receive(pair.id, i.sent[1], true, live);
		const ack = a.sent.at(-1)!;
		expect(ack.type).to.equal(MessageType.SPLICE_ACK);
		await i.wire.receive(
			pair.id,
			{ type: MessageType.SPLICE_ACK, payload: withConversion(ack.payload) },
			true,
			live
		);
		expect(errorsThrown()).to.include('Unexpected splice acknowledgment');
		const abort = i.sent.at(-1)!;
		expect(abort.type).to.equal(MessageType.TX_ABORT);
		expect(abortText(abort.payload)).to.equal('Refused splice negotiation');
		expect(i.sent.map((m) => m.type)).not.to.include(MessageType.TX_ADD_INPUT);
		await a.wire.receive(pair.id, abort, true, live);
		const echo = a.sent.at(-1)!;
		expect(echo.type).to.equal(MessageType.TX_ABORT);
		await i.wire.receive(pair.id, echo, true, live);
		expect(() => plainRounds(pair.devices, pair.id, 1)).not.to.throw();
		expect(pair.stores[0].loadFinalUpdateStatus(pair.id)!.localHeight).to.equal(
			1n
		);
	});
});

// ---------------------------------------------------------------------------
// Asset channels: AssetSpliceTransport over two original devices.
// ---------------------------------------------------------------------------

describe('Asset splices refuse the asset conversion TLV (#2151 step 3a, test 3)', function () {
	this.timeout(60000);
	let s: Scratch;
	beforeEach(() => {
		s = scratch('conversion-refusal-asset-');
	});
	afterEach(() => s.release());

	async function refused(
		type: MessageType.SPLICE | MessageType.SPLICE_ACK,
		text: string
	): Promise<void> {
		const pair = await assetTypePair(s, 0, 6);
		const { p, id } = pair;
		let seen = 0;
		await p.start();
		await p.drain((packet) => {
			if (packet.type === type) {
				seen++;
				// A valid lock depth, so validOptions and the depth echo pass.
				expect(
					(type === MessageType.SPLICE
						? decodeSpliceMessage(packet.wire)
						: decodeSpliceAckMessage(packet.wire)
					).lockDepth
				).to.equal(3);
				packet.wire = withConversion(packet.wire, PLAIN_TARGET_TYPE_HEX);
			}
			return true;
		});
		expect(seen).to.equal(1);
		expect(p.errors).to.include(text);
		const later =
			type === MessageType.SPLICE
				? MessageType.SPLICE_ACK
				: MessageType.TX_ADD_INPUT;
		expect(
			p.sent.filter(
				(m) =>
					m.type === later && m.from === (type === MessageType.SPLICE ? 1 : 0)
			)
		).to.be.empty;
		expect(p.sent.some((m) => m.type === MessageType.TX_ABORT)).to.equal(true);
		expect(p.broadcasts).to.be.empty;
		const before = assetSpliceUpdateHead(pair.devices[0].store, id).nextNumber;
		await assetRounds(pair.devices, id, Number(before));
		for (const d of pair.devices)
			expect(assetSpliceUpdateHead(d.store, id).nextNumber).to.equal(
				before + 1n
			);
	}

	it('refuses a splice_init carrying it in checkProposal, and an update round follows', async () => {
		await refused(MessageType.SPLICE, 'Unsupported asset splice proposal');
	});

	it('refuses a splice_ack carrying it as unmatched, and an update round follows', async () => {
		await refused(
			MessageType.SPLICE_ACK,
			'Unmatched asset splice acknowledgement'
		);
	});
});

// ---------------------------------------------------------------------------
// prepareAssetSpliceAgreement and checkLayout (through assetSpliceLayoutDigest).
// ---------------------------------------------------------------------------

const hash = (n: number): Buffer => Buffer.alloc(32, n);
const key = (n: number): Buffer => getPublicKey(hash(n));
const SATS = 600000;
const ASSET_ID = hash(1).toString('hex');

/** The layout of asset-splice-manifest.test.ts, rebuilt here. */
function layoutFixture(): IAssetSpliceLayout {
	const parent = new bitcoin.Transaction();
	parent.version = 2;
	parent.addInput(hash(9), 1);
	const root = hash(22);
	parent.addOutput(
		createTaprootFundingScript(key(2), key(3), undefined, root).p2trOutput,
		SATS
	);
	const init = {
		channelId: hash(4),
		fundingPubkey: key(5),
		relativeSatoshis: -3000n,
		fundingFeeratePerkw: 1000,
		locktime: 0,
		lockDepth: 3
	};
	const ack = {
		channelId: init.channelId,
		fundingPubkey: key(6),
		relativeSatoshis: 0n,
		lockDepth: 3
	};
	return {
		attempt: hash(7),
		chainHash: REGTEST_CHAIN_HASH,
		channelId: init.channelId,
		init: encodeSpliceMessage(init),
		ack: encodeSpliceAckMessage(ack),
		parent,
		parentIndex: 0,
		parentKeys: [key(2), key(3)],
		parentRoot: root,
		stateNumber: 0n,
		feeBudgets: [1000n, 0n],
		maxAcceptedHtlcs: [8, 8],
		commitmentRecordLimits: [
			[{ type: 65537n, maxBytes: 2000 }],
			[{ type: 65537n, maxBytes: 2000 }]
		],
		dust: 546n,
		parentBalances: {
			issuances: [
				{ assetId: ASSET_ID, funding: 60n, initiator: 40n, acceptor: 20n }
			],
			htlcs: []
		},
		movements: [
			{
				assetId: ASSET_ID,
				owner: 'initiator',
				inputs: 0n,
				change: 0n,
				withdrawals: 10n,
				delta: -10n
			}
		],
		proposalDigests: [hash(11), hash(12)],
		inputs: [
			{
				serialId: 0n,
				prevTxid: parent.getHash(),
				prevOutputIndex: 0,
				sequence: 0xfffffffd,
				isShared: true
			}
		],
		outputs: [
			{
				serialId: 2n,
				role: 'funding',
				amountSats: BigInt(SATS) - 3000n,
				descriptorHash: hash(13)
			},
			{
				serialId: 4n,
				role: 'withdrawal',
				amountSats: 2000n,
				descriptorHash: hash(14)
			}
		]
	};
}

describe('Asset splice agreement and layout refuse the asset conversion TLV (#2151 step 3a, test 3)', () => {
	it('keeps the layout digest of a layout without it', () => {
		expect(assetSpliceLayoutDigest(layoutFixture())).to.have.length(32);
	});

	for (const field of ['init', 'ack'] as const)
		it(`refuses a layout whose ${field} carries it as invalid negotiation terms`, () => {
			const layout = layoutFixture();
			layout[field] = withConversion(layout[field]);
			expect(() => assetSpliceLayoutDigest(layout)).to.throw(
				'Invalid asset splice negotiation terms'
			);
		});

	function agreementInputs(): {
		l: IAssetSpliceLayout;
		ctx: IAssetSpliceContext;
		host: IAssetSplicePlanner;
		channel: Parameters<typeof prepareAssetSpliceAgreement>[2];
		calls: string[];
	} {
		const l = layoutFixture();
		const parent = {
			oldOutpoint: { hash: l.parent.getHash(), index: l.parentIndex },
			stateNumber: 0n,
			walletGeneration: 4 as const
		};
		const ctx: IAssetSpliceContext = {
			...parent,
			attempt: l.attempt,
			channelId: l.channelId.toString('hex'),
			peer: key(33).toString('hex'),
			isInitiator: true,
			currentParent: () => ({ ...parent })
		};
		const calls: string[] = [];
		const host: IAssetSplicePlanner = {
			proposeSplice: async () => hash(11),
			spliceContribution: () => -3000n,
			abandonSplice: async () => {},
			describeSplice: async () => {
				calls.push('describeSplice');
				throw new Error('Stub planner was asked to describe the splice');
			},
			prepareSplice: async () => {
				calls.push('prepareSplice');
				throw new Error('Stub planner was asked to prepare the splice');
			}
		};
		const channel = {
			parent: {
				fundingTxHex: l.parent.toHex(),
				fundingOutputIndex: l.parentIndex,
				localFundingPubkey: l.parentKeys[0].toString('hex'),
				remoteFundingPubkey: l.parentKeys[1].toString('hex'),
				localFundingKeyIndex: 0
			},
			parentRoot: l.parentRoot,
			maxAcceptedHtlcs: l.maxAcceptedHtlcs,
			dust: l.dust
		};
		return { l, ctx, host, channel, calls };
	}

	it('reaches the planner for messages without it', async () => {
		const { l, ctx, host, channel, calls } = agreementInputs();
		const error = await prepareAssetSpliceAgreement(
			host,
			ctx,
			channel,
			l.init,
			l.ack,
			[hash(11), hash(12)]
		).then(
			() => null,
			(e: Error) => e.message
		);
		expect(error).to.equal('Stub planner was asked to describe the splice');
		expect(calls).to.deep.equal(['describeSplice']);
	});

	for (const field of ['init', 'ack'] as const)
		it(`refuses a ${
			field === 'init' ? 'splice_init' : 'splice_ack'
		} carrying it before the planner`, async () => {
			const { l, ctx, host, channel, calls } = agreementInputs();
			const init = field === 'init' ? withConversion(l.init) : l.init;
			const ack = field === 'ack' ? withConversion(l.ack) : l.ack;
			const error = await prepareAssetSpliceAgreement(
				host,
				ctx,
				channel,
				init,
				ack,
				[hash(11), hash(12)]
			).then(
				() => null,
				(e: Error) => e.message
			);
			expect(error).to.equal(
				'Asset splice does not agree with the local parent or depth'
			);
			expect(calls).to.deep.equal([]);
		});
});
