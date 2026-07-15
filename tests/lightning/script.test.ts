import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	createFundingScript,
	getFundingScriptHash
} from '../../src/lightning/script/funding';
import {
	buildCommitmentTx,
	buildToLocalScript,
	calculateObscuredCommitmentNumber,
	sortCommitmentOutputs,
	DUST_LIMIT_P2WSH,
	DUST_LIMIT_P2WPKH
} from '../../src/lightning/script/commitment';
import {
	buildOfferedHtlcScript,
	buildReceivedHtlcScript,
	buildHtlcOutputScript,
	buildHtlcSuccessTx,
	buildHtlcTimeoutTx
} from '../../src/lightning/script/htlc';
import {
	buildToLocalPenaltyWitness,
	buildHtlcPenaltyWitness
} from '../../src/lightning/script/revocation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

bitcoin.initEccLib(ecc);

describe('Lightning Scripts (BOLT 3)', function () {
	// ─── Funding Script Tests ───────────────────────────────────

	describe('Funding Script', function () {
		it('Should create a valid 2-of-2 multisig P2WSH', function () {
			const localPriv = crypto.randomBytes(32);
			const remotePriv = crypto.randomBytes(32);
			const localPub = getPublicKey(localPriv);
			const remotePub = getPublicKey(remotePriv);

			const result = createFundingScript(localPub, remotePub);

			// Should have all components
			expect(result.witnessScript).to.be.instanceOf(Buffer);
			expect(result.p2wshOutput).to.be.instanceOf(Buffer);
			expect(result.address).to.be.a('string');

			// Witness script should start with OP_2 and end with OP_CHECKMULTISIG
			expect(result.witnessScript[0]).to.equal(bitcoin.opcodes.OP_2);
			expect(result.witnessScript[result.witnessScript.length - 1]).to.equal(
				bitcoin.opcodes.OP_CHECKMULTISIG
			);
		});

		it('Should sort pubkeys lexicographically', function () {
			const localPriv = crypto.randomBytes(32);
			const remotePriv = crypto.randomBytes(32);
			const localPub = getPublicKey(localPriv);
			const remotePub = getPublicKey(remotePriv);

			const result1 = createFundingScript(localPub, remotePub);
			const result2 = createFundingScript(remotePub, localPub);

			// Same result regardless of argument order
			expect(result1.witnessScript.equals(result2.witnessScript)).to.be.true;
			expect(result1.address).to.equal(result2.address);
		});

		it('Should produce different addresses for different key pairs', function () {
			const priv1a = crypto.randomBytes(32);
			const priv1b = crypto.randomBytes(32);
			const priv2a = crypto.randomBytes(32);
			const priv2b = crypto.randomBytes(32);

			const result1 = createFundingScript(
				getPublicKey(priv1a),
				getPublicKey(priv1b)
			);
			const result2 = createFundingScript(
				getPublicKey(priv2a),
				getPublicKey(priv2b)
			);

			expect(result1.address).to.not.equal(result2.address);
		});

		it('Should reject non-33-byte pubkeys', function () {
			expect(() =>
				createFundingScript(Buffer.alloc(32), Buffer.alloc(33))
			).to.throw('33 bytes');
			expect(() =>
				createFundingScript(Buffer.alloc(33), Buffer.alloc(65))
			).to.throw('33 bytes');
		});

		it('Should produce correct P2WSH script hash', function () {
			const localPub = getPublicKey(crypto.randomBytes(32));
			const remotePub = getPublicKey(crypto.randomBytes(32));

			const result = createFundingScript(localPub, remotePub);
			const scriptHash = getFundingScriptHash(result.witnessScript);

			// P2WSH output: OP_0 <32-byte-hash>
			expect(result.p2wshOutput.length).to.equal(34);
			expect(result.p2wshOutput[0]).to.equal(0x00); // OP_0
			expect(result.p2wshOutput[1]).to.equal(0x20); // push 32 bytes
			expect(result.p2wshOutput.subarray(2).equals(scriptHash)).to.be.true;
		});

		it('Should work with regtest network', function () {
			const localPub = getPublicKey(crypto.randomBytes(32));
			const remotePub = getPublicKey(crypto.randomBytes(32));

			const result = createFundingScript(
				localPub,
				remotePub,
				bitcoin.networks.regtest
			);
			expect(result.address).to.match(/^bcrt1/);
		});

		it('Should work with testnet network', function () {
			const localPub = getPublicKey(crypto.randomBytes(32));
			const remotePub = getPublicKey(crypto.randomBytes(32));

			const result = createFundingScript(
				localPub,
				remotePub,
				bitcoin.networks.testnet
			);
			expect(result.address).to.match(/^tb1/);
		});
	});

	// ─── Commitment Transaction Tests ───────────────────────────

	describe('Commitment Transaction', function () {
		it('Should calculate obscured commitment number', function () {
			const openBasepoint = getPublicKey(crypto.randomBytes(32));
			const acceptBasepoint = getPublicKey(crypto.randomBytes(32));

			const obscured = calculateObscuredCommitmentNumber(
				openBasepoint,
				acceptBasepoint,
				0n
			);

			// Should be a 48-bit value
			expect(obscured >= 0n).to.be.true;
			expect(obscured < 2n ** 48n).to.be.true;
		});

		it('Should XOR commitment number with mask', function () {
			const openBasepoint = getPublicKey(crypto.randomBytes(32));
			const acceptBasepoint = getPublicKey(crypto.randomBytes(32));

			const obscured0 = calculateObscuredCommitmentNumber(
				openBasepoint,
				acceptBasepoint,
				0n
			);
			const obscured1 = calculateObscuredCommitmentNumber(
				openBasepoint,
				acceptBasepoint,
				1n
			);

			// XOR with 0 gives the mask, XOR with 1 flips the last bit
			expect(obscured0 ^ obscured1).to.equal(1n);
		});

		it('Should build to_local script', function () {
			const revocationPub = getPublicKey(crypto.randomBytes(32));
			const delayedPub = getPublicKey(crypto.randomBytes(32));
			const toSelfDelay = 144;

			const script = buildToLocalScript(revocationPub, delayedPub, toSelfDelay);
			expect(script).to.be.instanceOf(Buffer);
			expect(script.length).to.be.greaterThan(0);

			// Verify script structure with ASM
			const asm = bitcoin.script.toASM(script);
			expect(asm).to.include('OP_IF');
			expect(asm).to.include('OP_ELSE');
			expect(asm).to.include('OP_CHECKSEQUENCEVERIFY');
			expect(asm).to.include('OP_CHECKSIG');
			expect(asm).to.include('OP_ENDIF');
		});

		it('Should build a commitment transaction', function () {
			const revocationPub = getPublicKey(crypto.randomBytes(32));
			const delayedPub = getPublicKey(crypto.randomBytes(32));
			const remotePub = getPublicKey(crypto.randomBytes(32));
			const openBasepoint = getPublicKey(crypto.randomBytes(32));
			const acceptBasepoint = getPublicKey(crypto.randomBytes(32));

			const obscured = calculateObscuredCommitmentNumber(
				openBasepoint,
				acceptBasepoint,
				42n
			);

			const result = buildCommitmentTx({
				fundingTxid: 'a'.repeat(64),
				fundingOutputIndex: 0,
				fundingAmount: 1_000_000n,
				obscuredCommitmentNumber: obscured,
				localAmount: 700_000n,
				revocationPubkey: revocationPub,
				localDelayedPubkey: delayedPub,
				toSelfDelay: 144,
				remoteAmount: 300_000n,
				remotePaymentPubkey: remotePub
			});

			// Should have version 2
			expect(result.tx.version).to.equal(2);

			// Should have 1 input
			expect(result.tx.ins.length).to.equal(1);

			// Should have 2 outputs (to_local + to_remote)
			expect(result.tx.outs.length).to.equal(2);

			// Locktime should have upper bits set
			expect(result.tx.locktime & 0x20000000).to.equal(0x20000000);
		});

		it('Should trim dust outputs', function () {
			const revocationPub = getPublicKey(crypto.randomBytes(32));
			const delayedPub = getPublicKey(crypto.randomBytes(32));
			const remotePub = getPublicKey(crypto.randomBytes(32));

			const result = buildCommitmentTx({
				fundingTxid: 'b'.repeat(64),
				fundingOutputIndex: 0,
				fundingAmount: 1_000_000n,
				obscuredCommitmentNumber: 0n,
				localAmount: 100n, // Below dust
				revocationPubkey: revocationPub,
				localDelayedPubkey: delayedPub,
				toSelfDelay: 144,
				remoteAmount: 999_900n,
				remotePaymentPubkey: remotePub
			});

			// Only to_remote should be present (to_local is dust)
			expect(result.tx.outs.length).to.equal(1);
			expect(result.outputMap.toLocal).to.be.undefined;
			expect(result.outputMap.toRemote).to.equal(0);
		});

		it('Should sort outputs by value then scriptPubKey', function () {
			const outputs = [
				{ script: Buffer.from([0x03]), value: 1000n },
				{ script: Buffer.from([0x01]), value: 500n },
				{ script: Buffer.from([0x02]), value: 500n }
			];

			const sorted = sortCommitmentOutputs(outputs);
			expect(Number(sorted[0].value)).to.equal(500);
			expect(sorted[0].script[0]).to.equal(0x01);
			expect(Number(sorted[1].value)).to.equal(500);
			expect(sorted[1].script[0]).to.equal(0x02);
			expect(Number(sorted[2].value)).to.equal(1000);
		});

		it('BOLT 3: orders identical HTLC outputs by cltv_expiry (S-3.M2)', function () {
			// Two OFFERED HTLCs with the same amount and payment_hash produce an
			// identical scriptPubKey (the offered-HTLC script omits cltv_expiry), so
			// BIP 69 alone cannot order them. BOLT 3 orders them by cltv_expiry
			// ascending; without it the htlc_signature index mapping diverges from
			// LND/CLN/eclair/LDK and a valid commitment_signed is rejected.
			const revocationPub = getPublicKey(crypto.randomBytes(32));
			const delayedPub = getPublicKey(crypto.randomBytes(32));
			const remotePub = getPublicKey(crypto.randomBytes(32));
			const localHtlcPub = getPublicKey(crypto.randomBytes(32));
			const remoteHtlcPub = getPublicKey(crypto.randomBytes(32));
			const paymentHash = crypto
				.createHash('sha256')
				.update(crypto.randomBytes(32))
				.digest();

			const htlcScript = buildOfferedHtlcScript(
				revocationPub,
				localHtlcPub,
				remoteHtlcPub,
				paymentHash
			);
			const mkHtlc = (cltvExpiry: number) => ({
				script: htlcScript,
				amount: 100_000n,
				cltvExpiry,
				paymentHash
			});

			const result = buildCommitmentTx({
				fundingTxid: 'c'.repeat(64),
				fundingOutputIndex: 0,
				fundingAmount: 1_000_000n,
				obscuredCommitmentNumber: 0n,
				localAmount: 400_000n,
				revocationPubkey: revocationPub,
				localDelayedPubkey: delayedPub,
				toSelfDelay: 144,
				remoteAmount: 300_000n,
				remotePaymentPubkey: remotePub,
				// Pass the HIGHER cltv first: the sort must reorder so the lower one
				// (index 1) is placed first.
				htlcOutputs: [mkHtlc(600), mkHtlc(500)]
			});

			expect(result.outputMap.htlcs).to.have.length(2);
			// The first HTLC output corresponds to the lower-cltv HTLC (original
			// index 1); the second to the higher-cltv one (original index 0).
			expect(result.outputMap.htlcOriginalIndices).to.deep.equal([1, 0]);
		});
	});

	// ─── HTLC Script Tests ──────────────────────────────────────

	describe('HTLC Scripts', function () {
		const revocationPub = getPublicKey(
			Buffer.from(
				'1111111111111111111111111111111111111111111111111111111111111111',
				'hex'
			)
		);
		const localHtlcPub = getPublicKey(
			Buffer.from(
				'2222222222222222222222222222222222222222222222222222222222222222',
				'hex'
			)
		);
		const remoteHtlcPub = getPublicKey(
			Buffer.from(
				'3333333333333333333333333333333333333333333333333333333333333333',
				'hex'
			)
		);
		const paymentHash = crypto.createHash('sha256').update('preimage').digest();

		it('Should build an offered HTLC script', function () {
			const script = buildOfferedHtlcScript(
				revocationPub,
				localHtlcPub,
				remoteHtlcPub,
				paymentHash
			);

			expect(script).to.be.instanceOf(Buffer);

			const asm = bitcoin.script.toASM(script);
			expect(asm).to.include('OP_DUP');
			expect(asm).to.include('OP_HASH160');
			expect(asm).to.include('OP_CHECKMULTISIG');
			expect(asm).to.include('OP_CHECKSIG');
		});

		it('Should build a received HTLC script', function () {
			const script = buildReceivedHtlcScript(
				revocationPub,
				localHtlcPub,
				remoteHtlcPub,
				paymentHash,
				500000
			);

			expect(script).to.be.instanceOf(Buffer);

			const asm = bitcoin.script.toASM(script);
			expect(asm).to.include('OP_DUP');
			expect(asm).to.include('OP_HASH160');
			expect(asm).to.include('OP_CHECKLOCKTIMEVERIFY');
			expect(asm).to.include('OP_CHECKMULTISIG');
		});

		it('Should build an HTLC output script (second-level)', function () {
			const delayedPub = getPublicKey(crypto.randomBytes(32));
			const script = buildHtlcOutputScript(revocationPub, delayedPub, 144);

			const asm = bitcoin.script.toASM(script);
			expect(asm).to.include('OP_IF');
			expect(asm).to.include('OP_CHECKSEQUENCEVERIFY');
			expect(asm).to.include('OP_CHECKSIG');
		});

		it('Should reject payment hash of wrong length', function () {
			expect(() =>
				buildOfferedHtlcScript(
					revocationPub,
					localHtlcPub,
					remoteHtlcPub,
					Buffer.alloc(20)
				)
			).to.throw('32 bytes');

			expect(() =>
				buildReceivedHtlcScript(
					revocationPub,
					localHtlcPub,
					remoteHtlcPub,
					Buffer.alloc(20),
					100
				)
			).to.throw('32 bytes');
		});

		it('Should build an HTLC-success transaction', function () {
			const delayedPub = getPublicKey(crypto.randomBytes(32));
			const tx = buildHtlcSuccessTx(
				'a'.repeat(64),
				0,
				50_000n,
				revocationPub,
				delayedPub,
				144,
				1_000n
			);

			expect(tx.version).to.equal(2);
			expect(tx.locktime).to.equal(0);
			expect(tx.ins.length).to.equal(1);
			expect(tx.ins[0].sequence).to.equal(0);
			expect(tx.outs.length).to.equal(1);
			expect(tx.outs[0].value).to.equal(49_000);
		});

		it('Should build an HTLC-timeout transaction', function () {
			const delayedPub = getPublicKey(crypto.randomBytes(32));
			const cltvExpiry = 500000;
			const tx = buildHtlcTimeoutTx(
				'b'.repeat(64),
				1,
				50_000n,
				cltvExpiry,
				revocationPub,
				delayedPub,
				144,
				1_000n
			);

			expect(tx.version).to.equal(2);
			expect(tx.locktime).to.equal(cltvExpiry);
			expect(tx.ins.length).to.equal(1);
			expect(tx.ins[0].sequence).to.equal(0);
			expect(tx.outs.length).to.equal(1);
			expect(tx.outs[0].value).to.equal(49_000);
		});
	});

	// ─── Revocation/Penalty Tests ───────────────────────────────

	describe('Revocation/Penalty', function () {
		it('Should build a to_local penalty witness', function () {
			const sig = Buffer.alloc(72, 0x30);
			const witnessScript = Buffer.alloc(100, 0x01);

			const witness = buildToLocalPenaltyWitness(sig, witnessScript);

			expect(witness.length).to.equal(3);
			expect(witness[0]).to.equal(sig);
			expect(witness[1].equals(Buffer.from([0x01]))).to.be.true;
			expect(witness[2]).to.equal(witnessScript);
		});

		it('Should build an HTLC penalty witness', function () {
			const sig = Buffer.alloc(72, 0x30);
			const revPub = getPublicKey(crypto.randomBytes(32));
			const witnessScript = Buffer.alloc(200, 0x01);

			const witness = buildHtlcPenaltyWitness(sig, revPub, witnessScript);

			expect(witness.length).to.equal(3);
			expect(witness[0]).to.equal(sig);
			expect(witness[1]).to.equal(revPub);
			expect(witness[2]).to.equal(witnessScript);
		});
	});

	// ─── Dust Limit Constants ───────────────────────────────────

	describe('Dust Limits', function () {
		it('Should have correct P2WSH dust limit', function () {
			expect(DUST_LIMIT_P2WSH).to.equal(546);
		});

		it('Should have correct P2WPKH dust limit', function () {
			expect(DUST_LIMIT_P2WPKH).to.equal(294);
		});
	});
});
