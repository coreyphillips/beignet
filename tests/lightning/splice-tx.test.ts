import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	buildSpliceTx,
	findInputIndex,
	findOutputIndex,
	signSpliceSharedInput,
	verifySpliceSharedInput,
	finalizeSpliceSharedWitness,
	newFundingOutput,
	ISpliceTxInput,
	ISpliceTxOutput
} from '../../src/lightning/channel/splice-tx';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { createFundingScript } from '../../src/lightning/script/funding';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const REGTEST = bitcoin.networks.regtest;

/** Build a throwaway "current funding" tx with a single 2-of-2 output. */
function makeCurrentFundingTx(
	fundingScript: Buffer,
	valueSats: number
): { txid: Buffer; vout: number } {
	const prev = new bitcoin.Transaction();
	prev.version = 2;
	// Arbitrary dummy input so the tx is well-formed; irrelevant to the splice.
	prev.addInput(crypto.randomBytes(32), 0);
	prev.addOutput(fundingScript, valueSats);
	return { txid: Buffer.from(prev.getHash()), vout: 0 };
}

describe('Splice transaction construction & shared-input signing', function () {
	const privA = crypto.randomBytes(32);
	const privB = crypto.randomBytes(32);
	const pubA = getPublicKey(privA);
	const pubB = getPublicKey(privB);
	const signerA = new ChannelSigner(privA);
	const signerB = new ChannelSigner(privB);

	const CAPACITY = 1_000_000;

	it('orders inputs and outputs by serial_id and builds a v2 tx', function () {
		const inputs: ISpliceTxInput[] = [
			{
				serialId: 4n,
				prevTxid: Buffer.alloc(32, 0x11),
				prevOutputIndex: 1,
				sequence: 0xfffffffd
			},
			{
				serialId: 0n,
				prevTxid: Buffer.alloc(32, 0x22),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			}
		];
		const outputs: ISpliceTxOutput[] = [
			{ serialId: 3n, script: Buffer.alloc(22, 0x00), valueSats: 500n },
			{ serialId: 1n, script: Buffer.alloc(34, 0x00), valueSats: 700n }
		];
		const tx = buildSpliceTx(inputs, outputs, 0);
		expect(tx.version).to.equal(2);
		// serial 0 input first
		expect(Buffer.from(tx.ins[0].hash).equals(Buffer.alloc(32, 0x22))).to.be
			.true;
		// serial 1 output first
		expect(tx.outs[0].value).to.equal(700);
		expect(tx.outs[1].value).to.equal(500);
	});

	it('builds and co-signs a splice-OUT transaction spending the old 2-of-2', function () {
		// Current funding output (old 2-of-2 of A and B).
		const oldFunding = createFundingScript(pubA, pubB, REGTEST);
		const { txid: fundingTxid, vout } = makeCurrentFundingTx(
			oldFunding.p2wshOutput,
			CAPACITY
		);

		// Splice-out: withdraw 200k to a wallet address; fee 500 sats.
		const withdraw = 200_000;
		const fee = 500;
		const newCapacity = CAPACITY - withdraw - fee;

		// New funding output reuses the same funding pubkeys (valid; beignet does
		// not rotate). Could also be fresh keys.
		const newFunding = newFundingOutput(pubA, pubB, REGTEST);
		const destScript = bitcoin.payments.p2wpkh({
			pubkey: pubA,
			network: REGTEST
		}).output!;

		const inputs: ISpliceTxInput[] = [
			{
				serialId: 0n,
				prevTxid: fundingTxid,
				prevOutputIndex: vout,
				sequence: 0xfffffffd
			}
		];
		const outputs: ISpliceTxOutput[] = [
			{
				serialId: 0n,
				script: newFunding.script,
				valueSats: BigInt(newCapacity)
			},
			{ serialId: 1n, script: destScript, valueSats: BigInt(withdraw) }
		];

		const tx = buildSpliceTx(inputs, outputs, 0);

		// The shared input and new funding output are locatable in the built tx.
		const sharedIdx = findInputIndex(tx, fundingTxid, vout);
		expect(sharedIdx).to.equal(0);
		const newFundingIdx = findOutputIndex(tx, newFunding.script);
		expect(newFundingIdx).to.be.gte(0);
		expect(tx.outs[newFundingIdx].value).to.equal(newCapacity);

		// Both parties sign the shared 2-of-2 input.
		const sigA = signSpliceSharedInput(
			tx,
			sharedIdx,
			oldFunding.witnessScript,
			BigInt(CAPACITY),
			signerA
		);
		const sigB = signSpliceSharedInput(
			tx,
			sharedIdx,
			oldFunding.witnessScript,
			BigInt(CAPACITY),
			signerB
		);

		// Each signature verifies against the other party's pubkey + sighash.
		expect(
			verifySpliceSharedInput(
				tx,
				sharedIdx,
				oldFunding.witnessScript,
				BigInt(CAPACITY),
				pubA,
				sigA
			)
		).to.be.true;
		expect(
			verifySpliceSharedInput(
				tx,
				sharedIdx,
				oldFunding.witnessScript,
				BigInt(CAPACITY),
				pubB,
				sigB
			)
		).to.be.true;

		// A wrong signature must NOT verify.
		expect(
			verifySpliceSharedInput(
				tx,
				sharedIdx,
				oldFunding.witnessScript,
				BigInt(CAPACITY),
				pubA,
				sigB
			)
		).to.be.false;

		// Assemble the 2-of-2 witness (sig order follows lexicographic pubkey order).
		finalizeSpliceSharedWitness(
			tx,
			sharedIdx,
			sigA,
			sigB,
			pubA,
			pubB,
			oldFunding.witnessScript
		);
		const witness = tx.ins[sharedIdx].witness;
		expect(witness.length).to.equal(4); // OP_0, sig1, sig2, witnessScript
		expect(witness[0].length).to.equal(0); // OP_0 dummy
		expect(witness[3].equals(oldFunding.witnessScript)).to.be.true;
		// Conservation: inputs (capacity) == outputs + fee.
		expect(newCapacity + withdraw + fee).to.equal(CAPACITY);
	});

	it('builds a splice-IN transaction (extra wallet input + change)', function () {
		const oldFunding = createFundingScript(pubA, pubB, REGTEST);
		const { txid: fundingTxid, vout } = makeCurrentFundingTx(
			oldFunding.p2wshOutput,
			CAPACITY
		);

		// Splice-in 300k from a wallet UTXO worth 350k, fee 500, change 49.5k.
		const spliceIn = 300_000;
		const walletUtxoValue = 350_000;
		const fee = 500;
		const change = walletUtxoValue - spliceIn - fee;
		const newCapacity = CAPACITY + spliceIn;

		const newFunding = newFundingOutput(pubA, pubB, REGTEST);
		const changeScript = bitcoin.payments.p2wpkh({
			pubkey: pubA,
			network: REGTEST
		}).output!;
		const walletUtxoTxid = crypto.randomBytes(32);

		const inputs: ISpliceTxInput[] = [
			{
				serialId: 0n,
				prevTxid: fundingTxid,
				prevOutputIndex: vout,
				sequence: 0xfffffffd
			},
			{
				serialId: 2n,
				prevTxid: walletUtxoTxid,
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			}
		];
		const outputs: ISpliceTxOutput[] = [
			{
				serialId: 0n,
				script: newFunding.script,
				valueSats: BigInt(newCapacity)
			},
			{ serialId: 2n, script: changeScript, valueSats: BigInt(change) }
		];

		const tx = buildSpliceTx(inputs, outputs, 0);
		expect(tx.ins.length).to.equal(2);
		const newFundingIdx = findOutputIndex(tx, newFunding.script);
		expect(tx.outs[newFundingIdx].value).to.equal(newCapacity);
		// Conservation: capacity + walletUtxo == newCapacity + change + fee.
		expect(CAPACITY + walletUtxoValue).to.equal(newCapacity + change + fee);
	});
});
