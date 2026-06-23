import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { createFundingScript } from '../../src/lightning/script/funding';
import { buildToLocalScript } from '../../src/lightning/script/commitment';
import {
	buildOfferedHtlcScript,
	buildReceivedHtlcScript,
	buildHtlcOutputScript
} from '../../src/lightning/script/htlc';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import {
	buildClosingTx,
	calculateClosingFee,
	IClosingTxParams
} from '../../src/lightning/chain/closing';
import {
	buildToLocalSweepTx,
	buildToLocalDelayedWitness,
	buildHtlcSuccessWitness,
	buildHtlcTimeoutWitness,
	buildSecondLevelSweepTx,
	buildToRemoteClaimTx,
	buildToRemoteWitness,
	signSweepInput,
	signP2wpkhInput
} from '../../src/lightning/chain/sweep';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;

function makePrivkey(seed: string): Buffer {
	return crypto.createHash('sha256').update(Buffer.from(seed)).digest();
}

function makeP2wpkhScript(pubkey: Buffer): Buffer {
	return bitcoin.payments.p2wpkh({ pubkey, network }).output!;
}

function makeFundingTxid(): string {
	return crypto.randomBytes(32).toString('hex');
}

describe('Chain Closing & Sweep (Phase 4A)', function () {
	const localPrivkey = makePrivkey('local-funding');
	const remotePrivkey = makePrivkey('remote-funding');
	const localPubkey = getPublicKey(localPrivkey);
	const remotePubkey = getPublicKey(remotePrivkey);

	const localDestPrivkey = makePrivkey('local-dest');
	const remoteDestPrivkey = makePrivkey('remote-dest');
	const localDestPubkey = getPublicKey(localDestPrivkey);
	const remoteDestPubkey = getPublicKey(remoteDestPrivkey);

	const localScript = makeP2wpkhScript(localDestPubkey);
	const remoteScript = makeP2wpkhScript(remoteDestPubkey);

	const fundingTxid = makeFundingTxid();
	const fundingOutputIndex = 0;
	const fundingAmount = 1_000_000n;

	describe('buildClosingTx', function () {
		it('should build a closing tx with two valid outputs', function () {
			const params: IClosingTxParams = {
				fundingTxid,
				fundingOutputIndex,
				fundingAmount,
				localScriptPubkey: localScript,
				remoteScriptPubkey: remoteScript,
				localAmount: 600_000n,
				remoteAmount: 399_000n,
				feeAmount: 1_000n
			};

			const result = buildClosingTx(params);
			expect(result.tx.version).to.equal(2);
			expect(result.tx.locktime).to.equal(0);
			expect(result.tx.ins).to.have.length(1);
			expect(result.tx.ins[0].sequence).to.equal(0xffffffff);
			expect(result.tx.outs).to.have.length(2);
			expect(result.outputMap.local).to.not.be.undefined;
			expect(result.outputMap.remote).to.not.be.undefined;
		});

		it('should omit dust local output', function () {
			const params: IClosingTxParams = {
				fundingTxid,
				fundingOutputIndex,
				fundingAmount,
				localScriptPubkey: localScript,
				remoteScriptPubkey: remoteScript,
				localAmount: 100n, // below P2WPKH dust (294)
				remoteAmount: 999_000n,
				feeAmount: 900n
			};

			const result = buildClosingTx(params);
			expect(result.tx.outs).to.have.length(1);
			expect(result.outputMap.local).to.be.undefined;
			expect(result.outputMap.remote).to.equal(0);
		});

		it('should omit dust remote output', function () {
			const params: IClosingTxParams = {
				fundingTxid,
				fundingOutputIndex,
				fundingAmount,
				localScriptPubkey: localScript,
				remoteScriptPubkey: remoteScript,
				localAmount: 999_000n,
				remoteAmount: 200n, // below dust
				feeAmount: 800n
			};

			const result = buildClosingTx(params);
			expect(result.tx.outs).to.have.length(1);
			expect(result.outputMap.local).to.equal(0);
			expect(result.outputMap.remote).to.be.undefined;
		});

		it('should sort outputs by BIP 69 (value, then scriptPubKey)', function () {
			const params: IClosingTxParams = {
				fundingTxid,
				fundingOutputIndex,
				fundingAmount,
				localScriptPubkey: localScript,
				remoteScriptPubkey: remoteScript,
				localAmount: 500_000n,
				remoteAmount: 499_000n,
				feeAmount: 1_000n
			};

			const result = buildClosingTx(params);
			// Smaller value should come first
			expect(result.tx.outs[0].value).to.be.at.most(result.tx.outs[1].value);
		});

		it('should sort by scriptPubKey when values are equal', function () {
			const equalAmount = 499_500n;
			const params: IClosingTxParams = {
				fundingTxid,
				fundingOutputIndex,
				fundingAmount,
				localScriptPubkey: localScript,
				remoteScriptPubkey: remoteScript,
				localAmount: equalAmount,
				remoteAmount: equalAmount,
				feeAmount: 1_000n
			};

			const result = buildClosingTx(params);
			expect(result.tx.outs).to.have.length(2);
			// When values are equal, sorted by scriptPubKey
			const cmp = Buffer.compare(
				result.tx.outs[0].script,
				result.tx.outs[1].script
			);
			expect(cmp).to.be.lessThan(0);
		});

		it('should set correct version, locktime, and sequence', function () {
			const params: IClosingTxParams = {
				fundingTxid,
				fundingOutputIndex,
				fundingAmount,
				localScriptPubkey: localScript,
				remoteScriptPubkey: remoteScript,
				localAmount: 500_000n,
				remoteAmount: 499_000n,
				feeAmount: 1_000n
			};

			const result = buildClosingTx(params);
			expect(result.tx.version).to.equal(2);
			expect(result.tx.locktime).to.equal(0);
			expect(result.tx.ins[0].sequence).to.equal(0xffffffff);
		});

		it('should produce a valid round-trip signable closing tx', function () {
			const params: IClosingTxParams = {
				fundingTxid,
				fundingOutputIndex,
				fundingAmount,
				localScriptPubkey: localScript,
				remoteScriptPubkey: remoteScript,
				localAmount: 600_000n,
				remoteAmount: 399_000n,
				feeAmount: 1_000n
			};

			const result = buildClosingTx(params);
			const funding = createFundingScript(localPubkey, remotePubkey, network);

			const localSigner = new ChannelSigner(localPrivkey);
			const remoteSigner = new ChannelSigner(remotePrivkey);

			const localSig = localSigner.signClosingTx(
				result.tx,
				funding.witnessScript,
				Number(fundingAmount)
			);
			const remoteSig = remoteSigner.signClosingTx(
				result.tx,
				funding.witnessScript,
				Number(fundingAmount)
			);

			// Both signatures should be 64 bytes (compact)
			expect(localSig).to.have.length(64);
			expect(remoteSig).to.have.length(64);

			// Build witness and set
			const witness = ChannelSigner.buildFundingWitness(
				localSig,
				remoteSig,
				localPubkey,
				remotePubkey,
				funding.witnessScript
			);
			result.tx.setWitness(0, witness);

			// Verify the tx can be serialized
			const serialized = result.tx.toBuffer();
			expect(serialized.length).to.be.greaterThan(0);
		});
	});

	describe('calculateClosingFee', function () {
		it('should return a positive fee', function () {
			const fee = calculateClosingFee(253, 22, 22);
			expect(Number(fee)).to.be.greaterThan(0);
		});

		it('should increase with fee rate', function () {
			const fee1 = calculateClosingFee(253, 22, 22);
			const fee2 = calculateClosingFee(506, 22, 22);
			expect(Number(fee2)).to.be.greaterThan(Number(fee1));
		});

		it('should increase with longer scripts', function () {
			const fee1 = calculateClosingFee(253, 22, 22);
			const fee2 = calculateClosingFee(253, 34, 34);
			expect(Number(fee2)).to.be.greaterThan(Number(fee1));
		});
	});

	describe('buildToLocalSweepTx', function () {
		const revocationPrivkey = makePrivkey('revocation');
		const revocationPubkey = getPublicKey(revocationPrivkey);
		const delayedPrivkey = makePrivkey('delayed');
		const delayedPubkey = getPublicKey(delayedPrivkey);
		const toSelfDelay = 144;
		const toLocalScript = buildToLocalScript(
			revocationPubkey,
			delayedPubkey,
			toSelfDelay
		);
		const commitmentTxid = makeFundingTxid();

		it('should build sweep tx with correct CSV sequence', function () {
			const tx = buildToLocalSweepTx({
				commitmentTxid,
				outputIndex: 0,
				amount: 500_000n,
				witnessScript: toLocalScript,
				toSelfDelay,
				destinationScript: localScript,
				feeSatoshis: 500n
			});

			expect(tx.version).to.equal(2);
			expect(tx.locktime).to.equal(0);
			expect(tx.ins[0].sequence).to.equal(toSelfDelay);
			expect(tx.outs[0].value).to.equal(499_500);
		});

		it('should throw if fee exceeds value', function () {
			expect(() =>
				buildToLocalSweepTx({
					commitmentTxid,
					outputIndex: 0,
					amount: 100n,
					witnessScript: toLocalScript,
					toSelfDelay,
					destinationScript: localScript,
					feeSatoshis: 500n
				})
			).to.throw('Fee exceeds available value');
		});

		it('should produce correct delayed witness format', function () {
			const tx = buildToLocalSweepTx({
				commitmentTxid,
				outputIndex: 0,
				amount: 500_000n,
				witnessScript: toLocalScript,
				toSelfDelay,
				destinationScript: localScript,
				feeSatoshis: 500n
			});

			const sig = signSweepInput(tx, 0, toLocalScript, 500_000, delayedPrivkey);

			const witness = buildToLocalDelayedWitness(sig, toLocalScript);
			expect(witness).to.have.length(3);
			expect(witness[0]).to.deep.equal(sig); // signature
			expect(witness[1]).to.have.length(0); // OP_FALSE for OP_ELSE
			expect(witness[2]).to.deep.equal(toLocalScript); // witness script
		});
	});

	describe('HTLC Witnesses', function () {
		const revocationPrivkey = makePrivkey('htlc-revocation');
		const revocationPubkey = getPublicKey(revocationPrivkey);
		const localHtlcPrivkey = makePrivkey('local-htlc');
		const localHtlcPubkey = getPublicKey(localHtlcPrivkey);
		const remoteHtlcPrivkey = makePrivkey('remote-htlc');
		const remoteHtlcPubkey = getPublicKey(remoteHtlcPrivkey);
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();

		it('should build HTLC-success witness: 0, remotesig, localsig, preimage, script', function () {
			const htlcScript = buildReceivedHtlcScript(
				revocationPubkey,
				localHtlcPubkey,
				remoteHtlcPubkey,
				paymentHash,
				500
			);

			const remoteSig = Buffer.alloc(72, 0xaa); // mock DER sig
			const localSig = Buffer.alloc(72, 0xbb);

			const witness = buildHtlcSuccessWitness(
				remoteSig,
				localSig,
				preimage,
				htlcScript
			);

			expect(witness).to.have.length(5);
			expect(witness[0]).to.have.length(0); // OP_0 dummy
			expect(witness[1]).to.deep.equal(remoteSig);
			expect(witness[2]).to.deep.equal(localSig);
			expect(witness[3]).to.deep.equal(preimage);
			expect(witness[4]).to.deep.equal(htlcScript);
		});

		it('should build HTLC-timeout witness: 0, remotesig, localsig, 0, script', function () {
			const htlcScript = buildOfferedHtlcScript(
				revocationPubkey,
				localHtlcPubkey,
				remoteHtlcPubkey,
				paymentHash
			);

			const remoteSig = Buffer.alloc(72, 0xcc);
			const localSig = Buffer.alloc(72, 0xdd);

			const witness = buildHtlcTimeoutWitness(remoteSig, localSig, htlcScript);

			expect(witness).to.have.length(5);
			expect(witness[0]).to.have.length(0); // OP_0 dummy
			expect(witness[1]).to.deep.equal(remoteSig);
			expect(witness[2]).to.deep.equal(localSig);
			expect(witness[3]).to.have.length(0); // OP_0 for timeout path
			expect(witness[4]).to.deep.equal(htlcScript);
		});
	});

	describe('buildSecondLevelSweepTx', function () {
		const revocationPubkey = getPublicKey(makePrivkey('rev2'));
		const delayedPrivkey = makePrivkey('delayed2');
		const delayedPubkey = getPublicKey(delayedPrivkey);
		const toSelfDelay = 144;
		const htlcOutputScript = buildHtlcOutputScript(
			revocationPubkey,
			delayedPubkey,
			toSelfDelay
		);
		const htlcTxid = makeFundingTxid();

		it('should build second-level sweep with CSV sequence', function () {
			const tx = buildSecondLevelSweepTx({
				htlcTxid,
				outputIndex: 0,
				amount: 50_000n,
				witnessScript: htlcOutputScript,
				toSelfDelay,
				destinationScript: localScript,
				feeSatoshis: 300n
			});

			expect(tx.version).to.equal(2);
			expect(tx.ins[0].sequence).to.equal(toSelfDelay);
			expect(tx.outs[0].value).to.equal(49_700);
		});

		it('should use delayed witness (same format as to_local)', function () {
			const tx = buildSecondLevelSweepTx({
				htlcTxid,
				outputIndex: 0,
				amount: 50_000n,
				witnessScript: htlcOutputScript,
				toSelfDelay,
				destinationScript: localScript,
				feeSatoshis: 300n
			});

			const sig = signSweepInput(
				tx,
				0,
				htlcOutputScript,
				50_000,
				delayedPrivkey
			);

			const witness = buildToLocalDelayedWitness(sig, htlcOutputScript);
			expect(witness).to.have.length(3);
			expect(witness[1]).to.have.length(0); // OP_FALSE for delayed path
		});

		it('should throw if fee exceeds value', function () {
			expect(() =>
				buildSecondLevelSweepTx({
					htlcTxid,
					outputIndex: 0,
					amount: 100n,
					witnessScript: htlcOutputScript,
					toSelfDelay,
					destinationScript: localScript,
					feeSatoshis: 500n
				})
			).to.throw('Fee exceeds available value');
		});
	});

	describe('buildToRemoteClaimTx', function () {
		const paymentPrivkey = makePrivkey('payment');
		const paymentPubkey = getPublicKey(paymentPrivkey);
		const commitmentTxid = makeFundingTxid();

		it('should build P2WPKH claim with no delay', function () {
			const tx = buildToRemoteClaimTx({
				commitmentTxid,
				outputIndex: 1,
				amount: 400_000n,
				destinationScript: localScript,
				feeSatoshis: 300n
			});

			expect(tx.version).to.equal(2);
			expect(tx.ins[0].sequence).to.equal(0xffffffff); // no delay
			expect(tx.outs[0].value).to.equal(399_700);
		});

		it('should build correct P2WPKH witness: sig, pubkey', function () {
			const tx = buildToRemoteClaimTx({
				commitmentTxid,
				outputIndex: 1,
				amount: 400_000n,
				destinationScript: localScript,
				feeSatoshis: 300n
			});

			const sig = signP2wpkhInput(
				tx,
				0,
				paymentPubkey,
				400_000,
				paymentPrivkey
			);

			const witness = buildToRemoteWitness(sig, paymentPubkey);
			expect(witness).to.have.length(2);
			expect(witness[0]).to.deep.equal(sig);
			expect(witness[1]).to.deep.equal(paymentPubkey);
		});

		it('should throw if fee exceeds value', function () {
			expect(() =>
				buildToRemoteClaimTx({
					commitmentTxid,
					outputIndex: 1,
					amount: 100n,
					destinationScript: localScript,
					feeSatoshis: 500n
				})
			).to.throw('Fee exceeds available value');
		});
	});

	describe('signSweepInput', function () {
		it('should produce a DER signature with SIGHASH_ALL', function () {
			const privkey = makePrivkey('signer');
			const pubkey = getPublicKey(privkey);
			const witnessScript = buildToLocalScript(
				getPublicKey(makePrivkey('rev')),
				pubkey,
				144
			);

			const tx = buildToLocalSweepTx({
				commitmentTxid: makeFundingTxid(),
				outputIndex: 0,
				amount: 100_000n,
				witnessScript,
				toSelfDelay: 144,
				destinationScript: localScript,
				feeSatoshis: 500n
			});

			const sig = signSweepInput(tx, 0, witnessScript, 100_000, privkey);

			// Should end with SIGHASH_ALL (0x01)
			expect(sig[sig.length - 1]).to.equal(0x01);
			// Should start with DER sequence tag
			expect(sig[0]).to.equal(0x30);
			// Length should be reasonable for DER
			expect(sig.length).to.be.greaterThan(60);
			expect(sig.length).to.be.lessThan(75);
		});
	});

	describe('signP2wpkhInput', function () {
		it('should produce valid P2WPKH signature', function () {
			const privkey = makePrivkey('p2wpkh-signer');
			const pubkey = getPublicKey(privkey);

			const tx = buildToRemoteClaimTx({
				commitmentTxid: makeFundingTxid(),
				outputIndex: 0,
				amount: 200_000n,
				destinationScript: localScript,
				feeSatoshis: 300n
			});

			const sig = signP2wpkhInput(tx, 0, pubkey, 200_000, privkey);
			expect(sig[sig.length - 1]).to.equal(0x01); // SIGHASH_ALL
			expect(sig[0]).to.equal(0x30); // DER
		});
	});
});
