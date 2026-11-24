import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import {
	buildFinalSpliceCandidate,
	finalSpliceFeeError,
	type IFinalSpliceTerms
} from '../../src/lightning/channel/final-splice-candidate';
import { spliceConstruction } from '../../src/lightning/channel/final-splice-transcript';
import type { IFinalSpliceAttempt } from '../../src/lightning/channel/final-splice-state';
import {
	encodeTxAddInputMessage,
	type ITxAddInputMessage
} from '../../src/lightning/message/interactive-tx';
import { MessageType } from '../../src/lightning/message/types';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { alice, bob } from './helpers/final-opening-signing';
import { inputTransaction } from './helpers/final-opening';

const oldLocalKey = alice.keys.channelBasepoints.fundingPubkey,
	oldPeerKey = bob.keys.channelBasepoints.fundingPubkey;
const newLocalKey = alice.keys.channelBasepoints.paymentBasepoint,
	newPeerKey = bob.keys.channelBasepoints.paymentBasepoint;
const parent = new Transaction();
parent.version = 2;
parent.addInput(Buffer.alloc(32, 8), 0);
parent.addOutput(
	createTaprootFundingScript(oldLocalKey, oldPeerKey).p2trOutput,
	237432
);
const terms: IFinalSpliceTerms = {
	parent,
	parentIndex: 0,
	oldLocalKey,
	oldPeerKey,
	newLocalKey,
	newPeerKey,
	localIsSpliceInitiator: false,
	localDelta: 0n,
	peerDelta: -12707n,
	localFeeBudget: 0n,
	feerate: 1250,
	dust: 354n,
	locktime: 0
};
const external = inputTransaction(1712, 25000);
const shared = {
	serialId: 0n,
	prevTxid: parent.getHash(),
	prevOutputIndex: 0,
	sequence: 0xfffffffd,
	isShared: true
};
const id = Buffer.alloc(32, 7);
const base = {
	channelId: id,
	serialId: 0n,
	prevTx: Buffer.alloc(0),
	prevTxVout: 0,
	sequence: 0xfffffffd
};

function withdrawal(fee: bigint): ReturnType<typeof buildFinalSpliceCandidate> {
	const peerDelta = -12000n - fee;
	return buildFinalSpliceCandidate(
		{ ...terms, peerDelta },
		[shared],
		[
			{
				serialId: 2n,
				amountSats: 237432n + peerDelta,
				scriptPubkey: createTaprootFundingScript(newLocalKey, newPeerKey)
					.p2trOutput
			},
			{
				serialId: 4n,
				amountSats: 12000n,
				scriptPubkey: external.outs[0].script
			}
		]
	);
}

function construction(
	input: ITxAddInputMessage,
	resolved?: Transaction
): ReturnType<typeof spliceConstruction> {
	const attempt: IFinalSpliceAttempt = {
		intent: {
			initiator: false,
			parent: {
				fundingTxHex: parent.toHex(),
				fundingOutputIndex: 0,
				localFundingPubkey: oldLocalKey.toString('hex'),
				remoteFundingPubkey: oldPeerKey.toString('hex'),
				localFundingKeyIndex: 1
			},
			localFundingKeyIndex: 2,
			localFundingPubkey: newLocalKey.toString('hex'),
			localDelta: '0',
			feeBudget: '0',
			feerate: 1250,
			locktime: 0,
			inputs: [],
			outputs: []
		},
		messages: [
			{
				kind: 'wire',
				local: false,
				type: MessageType.TX_ADD_INPUT,
				payload: encodeTxAddInputMessage(input).toString('hex'),
				resolvedPrevTx: resolved?.toHex()
			}
		]
	};
	return spliceConstruction(attempt, terms);
}

describe('Final splice shared funding and withdrawal fee', () => {
	it('accepts the 707 sat peer withdrawal at 1250 sat/kw and refuses 706 sats on the same output scripts', () => {
		const { tx, sharedIndex } = withdrawal(707n);
		tx.setWitness(sharedIndex, [Buffer.alloc(64)]);
		expect(tx.weight()).to.equal(568);
		expect(tx.outs.map((o) => o.value)).to.deep.equal([224725, 12000]);
		expect(() => withdrawal(706n)).to.throw(/fee/i);
		expect(() => withdrawal(708n)).to.throw(/fee/i);
		expect(() => withdrawal(710n)).not.to.throw();
	});
	it('keeps the strict minimum for local funding, an extra input, and the one sat/vbyte relay floor', () => {
		for (const qualifier of [
			{ localIsSpliceInitiator: true },
			{ localDelta: 1n },
			{ localFeeBudget: 1n },
			{ peerDelta: 0n }
		]) {
			expect(
				finalSpliceFeeError(707n, 568, { ...terms, ...qualifier }, true)
			).to.be.a('string');
		}
		expect(finalSpliceFeeError(707n, 568, terms, false)).to.be.a('string');
		expect(
			finalSpliceFeeError(141n, 568, { ...terms, feerate: 250 }, true)
		).to.be.a('string');
	});
	it('accepts only the current shared outpoint with an empty previous transaction', () => {
		const declared = { ...base, sharedInputTxid: parent.getHash() };
		expect(construction(declared).localTurn).to.equal(true);
		for (const change of [
			{ prevTx: parent.toBuffer() },
			{ sharedInputTxid: external.getHash() },
			{ prevTxVout: 1 }
		]) {
			expect(() => construction({ ...declared, ...change })).to.throw(
				/shared splice input/i
			);
		}
		expect(() => construction(declared, parent)).to.throw(
			/shared splice input/i
		);
		expect(() => construction(base)).to.throw(/shared splice input/i);
	});
	it('verifies compact wallet inputs against the full transaction for both supported TLV encodings', () => {
		const { value, script } = external.outs[0];
		for (const type of [2, 1111] as const) {
			const compact = {
				txid: external.getHash(),
				amount: BigInt(value),
				script,
				type
			};
			expect(
				construction({ ...base, prevTxOut: compact }, external).localTurn
			).to.equal(true);
			expect(() => construction({ ...base, prevTxOut: compact })).to.throw(
				/unverified compact/i
			);
			for (const change of [
				{ amount: compact.amount + 1n },
				{ txid: parent.getHash() },
				{ script: parent.outs[0].script }
			]) {
				expect(() =>
					construction(
						{ ...base, prevTxOut: { ...compact, ...change } },
						external
					)
				).to.throw(/unverified compact/i);
			}
		}
		expect(
			construction({ ...base, prevTx: external.toBuffer() }).localTurn
		).to.equal(true);
	});
});
