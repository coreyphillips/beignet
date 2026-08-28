/**
 * ChannelManager orchestration for splice external inputs (issue #592):
 *
 *  - a splice withholding its tx_signatures surfaces the owed witnesses as
 *    channel:splice-txsigs-needed, once per connection cycle;
 *  - provideSpliceExternalWitness dispatches the channel's actions (send,
 *    broadcast) and completes the splice on both peers;
 *  - a refused delivery is NOT a channel failure: the result says so and no
 *    'error' event is emitted (the initiateFundingRbf refusal convention),
 *    while an unknown channel is a lookup failure and does emit one.
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
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ISpliceInFlight } from '../../src/lightning/channel/channel-state';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const FUNDING_SATOSHIS = 1_000_000n;
const SPLICE_AMOUNT = 300_000n;
const OWN_UTXO_SATS = SPLICE_AMOUNT + 100_000n;
const EXT_UTXO_SATS = 60_000n;

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`splice-ext-seed-${id}`).digest();
}

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

function makeConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest()
	};
}

interface IHarness {
	openerManager: ChannelManager;
	acceptorManager: ChannelManager;
	openerChannel: Channel;
	acceptorChannel: Channel;
	channelId: Buffer;
	openerPubkey: string;
	acceptorPubkey: string;
	signals: Array<{
		channelId: Buffer;
		spliceTxid: Buffer;
		newFundingOutputIndex: number;
		externalInputIndices: number[];
	}>;
	broadcasts: Buffer[];
	errors: string[];
	extPrevTx: bitcoin.Transaction;
	extPriv: Buffer;
	extPub: Buffer;
}

/**
 * Two connected managers whose channel is mid-splice, withholding its
 * tx_signatures on one third-party input. The acceptor contributes nothing, so
 * (BOLT 2 ordering) its tx_signatures arrives first and the stall is entirely
 * ours.
 */
function spliceWithheldPair(): IHarness {
	const openerConfig = makeConfig(801);
	const acceptorConfig = makeConfig(802);
	const openerPubkey =
		openerConfig.localBasepoints.fundingPubkey.toString('hex');
	const acceptorPubkey =
		acceptorConfig.localBasepoints.fundingPubkey.toString('hex');
	const openerManager = new ChannelManager(openerConfig);
	const acceptorManager = new ChannelManager(acceptorConfig);
	const errors: string[] = [];
	openerManager.on('error', (_id: Buffer, err: string) => errors.push(err));
	acceptorManager.on('error', () => undefined);

	openerManager.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (peer === acceptorPubkey) {
				acceptorManager.handleMessage(openerPubkey, type, payload);
			}
		}
	);
	acceptorManager.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (peer === openerPubkey) {
				openerManager.handleMessage(acceptorPubkey, type, payload);
			}
		}
	);

	const openerChannel = openerManager.openChannel(
		acceptorPubkey,
		FUNDING_SATOSHIS
	);
	openerManager.createFunding(
		openerChannel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	);
	const channelId = openerChannel.getChannelId()!;
	openerManager.handleFundingConfirmed(channelId);
	acceptorManager.handleFundingConfirmed(channelId);
	const acceptorChannel = acceptorManager.getChannelsByPeer(openerPubkey)[0];
	expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);

	// One own input (real closure) plus one third-party input.
	const ownPriv = crypto.createHash('sha256').update('mgr-own-key').digest();
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
	const extPrevTx = new bitcoin.Transaction();
	extPrevTx.version = 2;
	extPrevTx.addInput(crypto.randomBytes(32), 0);
	extPrevTx.addOutput(
		bitcoin.payments.p2wpkh({ pubkey: extPub }).output!,
		Number(EXT_UTXO_SATS)
	);
	const inputs: ISpliceWalletInput[] = [
		{
			prevTx: ownPrevTx.toBuffer(),
			prevOutputIndex: 0,
			value: OWN_UTXO_SATS,
			sequence: 0xfffffffd,
			signWitness: (tx, inputIndex, value): Buffer[] => [
				bitcoin.script.signature.encode(
					Buffer.from(
						ecc.sign(
							tx.hashForWitnessV0(
								inputIndex,
								ownScriptCode,
								Number(value),
								bitcoin.Transaction.SIGHASH_ALL
							),
							ownPriv
						)
					),
					bitcoin.Transaction.SIGHASH_ALL
				),
				ownPub
			]
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
	];

	const signals: IHarness['signals'] = [];
	openerManager.on(
		'channel:splice-txsigs-needed',
		(
			id: Buffer,
			spliceTxid: Buffer,
			newFundingOutputIndex: number,
			externalInputIndices: number[]
		) => {
			signals.push({
				channelId: id,
				spliceTxid,
				newFundingOutputIndex,
				externalInputIndices
			});
		}
	);
	const broadcasts: Buffer[] = [];
	openerManager.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

	openerChannel.setSpliceInInputs(
		inputs,
		bitcoin.payments.p2wpkh({ pubkey: ownPub }).output!
	);
	expect(
		openerManager.initiateSplice(channelId, SPLICE_AMOUNT, 253).ok
	).to.equal(true);

	return {
		openerManager,
		acceptorManager,
		openerChannel,
		acceptorChannel,
		channelId,
		openerPubkey,
		acceptorPubkey,
		signals,
		broadcasts,
		errors,
		extPrevTx,
		extPriv,
		extPub
	};
}

/** The owner's witness for the external input, over the negotiated tx. */
function ownerWitness(record: ISpliceInFlight, h: IHarness): Buffer[] {
	const tx = bitcoin.Transaction.fromHex(record.spliceTxHex);
	const idx = tx.ins.findIndex(
		(i) => Buffer.from(i.hash).equals(h.extPrevTx.getHash()) && i.index === 0
	);
	expect(idx).to.be.gte(0);
	const sighash = tx.hashForWitnessV0(
		idx,
		bitcoin.payments.p2pkh({ pubkey: h.extPub }).output!,
		Number(EXT_UTXO_SATS),
		bitcoin.Transaction.SIGHASH_ALL
	);
	return [
		bitcoin.script.signature.encode(
			Buffer.from(ecc.sign(sighash, h.extPriv)),
			bitcoin.Transaction.SIGHASH_ALL
		),
		h.extPub
	];
}

describe('ChannelManager splice external witness (issue #592)', function () {
	it('signals the owed witness, then releases the splice on delivery', function () {
		const h = spliceWithheldPair();
		const record = h.openerChannel.getFullState().spliceInFlight!;

		expect(h.signals, 'the obligation is surfaced once').to.have.length(1);
		expect(h.signals[0].channelId.equals(h.channelId)).to.equal(true);
		expect(h.signals[0].spliceTxid.equals(record.spliceTxid)).to.equal(true);
		expect(h.signals[0].externalInputIndices).to.deep.equal(
			record.externalInputIndices
		);
		expect(record.receivedTxSignatures, 'the peer signed first').to.equal(true);
		expect(record.sentTxSignatures).to.equal(false);
		expect(record.fullySigned).to.equal(false);
		expect(h.broadcasts, 'a hole is never broadcast').to.deep.equal([]);

		const result = h.openerManager.provideSpliceExternalWitness(
			h.channelId,
			Buffer.from(h.extPrevTx.getHash()),
			0,
			ownerWitness(record, h)
		);
		expect(result.ok).to.equal(true);
		expect(h.errors).to.deep.equal([]);
		expect(h.broadcasts, 'the completed splice is dispatched').to.have.length(
			1
		);

		const after = h.openerChannel.getFullState().spliceInFlight!;
		expect(after.sentTxSignatures).to.equal(true);
		expect(after.fullySigned).to.equal(true);
		// Our tx_signatures reached the peer, so its own splice is complete too.
		expect(
			h.acceptorChannel.getFullState().spliceInFlight!.fullySigned
		).to.equal(true);
	});

	it('a refused delivery is not a channel failure', function () {
		const h = spliceWithheldPair();
		const record = h.openerChannel.getFullState().spliceInFlight!;

		const bad = h.openerManager.provideSpliceExternalWitness(
			h.channelId,
			Buffer.from(h.extPrevTx.getHash()),
			0,
			[crypto.randomBytes(71), h.extPub]
		);
		expect(bad.ok).to.equal(false);
		expect(bad.error).to.match(/external witness rejected/);
		expect(bad.actions, 'nothing is dispatched').to.deep.equal([]);
		expect(h.errors, 'a bad witness never fails the channel').to.deep.equal([]);
		expect(h.broadcasts).to.deep.equal([]);
		expect(h.openerChannel.getFullState().spliceInFlight!.fullySigned).to.equal(
			false
		);

		// An unknown channel is a lookup failure, which does surface.
		const unknown = crypto.randomBytes(32);
		const missing = h.openerManager.provideSpliceExternalWitness(
			unknown,
			Buffer.from(h.extPrevTx.getHash()),
			0,
			ownerWitness(record, h)
		);
		expect(missing.ok).to.equal(false);
		expect(missing.error).to.match(/Channel not found/);
		expect(h.errors.some((e) => /Channel not found/.test(e))).to.equal(true);
	});

	it('re-arms the reminder on reconnect without retransmitting anything', function () {
		const h = spliceWithheldPair();
		const { openerPubkey, acceptorPubkey } = h;
		expect(h.signals).to.have.length(1);

		const sent: number[] = [];
		h.openerManager.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});
		h.openerManager.handlePeerDisconnected(acceptorPubkey);
		h.acceptorManager.handlePeerDisconnected(openerPubkey);
		// The peer reconnects first: its channel_reestablish is what drives our
		// own resume, and delivery here is synchronous.
		h.acceptorManager.handlePeerReconnected(openerPubkey);
		h.openerManager.handlePeerReconnected(acceptorPubkey);

		expect(h.signals, 'a new connection asks again').to.have.length(2);
		expect(
			sent.includes(MessageType.TX_SIGNATURES),
			'a withheld tx_signatures is never replayed'
		).to.equal(false);
		expect(h.broadcasts).to.deep.equal([]);
		expect(h.openerChannel.getFullState().spliceInFlight!.fullySigned).to.equal(
			false
		);
	});
});
