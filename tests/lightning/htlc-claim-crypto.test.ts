/**
 * Cryptographic validation (no bitcoind) for the on-chain HTLC-timeout claim
 * added in the 2026-06 audit remediation (H3). Proves the witness signature
 * actually satisfies OP_CHECKSIG against the received-HTLC script's timeout-path
 * pubkey over the correct BIP143 sighash, and that the claim's timelock fields
 * are set so OP_CHECKLOCKTIMEVERIFY is enforced.
 *
 * The end-to-end relay/timelock-enforcement check lives in the regtest test
 * tests/lightning/interop/htlc-claim-mempool.test.ts (testmempoolaccept).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { buildReceivedHtlcScript } from '../../src/lightning/script/htlc';
import {
	buildRemoteHtlcTimeoutClaimTx,
	buildRemoteHtlcTimeoutWitness,
	signSweepInput
} from '../../src/lightning/chain/sweep';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

function key(seed: string): { priv: Buffer; pub: Buffer } {
	const priv = crypto.createHash('sha256').update(seed).digest();
	return {
		priv,
		pub: Buffer.from(ECPair.fromPrivateKey(priv, { network }).publicKey)
	};
}

describe('H3: remote HTLC-timeout claim witness (crypto validation)', function () {
	it('signature verifies against the timeout-path pubkey (our HTLC key)', function () {
		const revocation = key('h3c-rev');
		const localHtlc = key('h3c-local'); // their HTLC key on their commitment
		const remoteHtlc = key('h3c-remote'); // OUR HTLC key — timeout-path signer
		const paymentHash = crypto.randomBytes(32);
		const cltvExpiry = 800_000;

		const htlcScript = buildReceivedHtlcScript(
			revocation.pub,
			localHtlc.pub,
			remoteHtlc.pub,
			paymentHash,
			cltvExpiry,
			false
		);
		const p2wsh = bitcoin.payments.p2wsh({
			redeem: { output: htlcScript },
			network
		});

		const amount = 70_000n;
		const claimTx = buildRemoteHtlcTimeoutClaimTx({
			commitmentTxid: Buffer.alloc(32, 0xab).toString('hex'),
			outputIndex: 0,
			amount,
			witnessScript: htlcScript,
			destinationScript: p2wsh.output!,
			feeSatoshis: 2_000n,
			cltvExpiry,
			inputSequence: 0xfffffffd
		});

		const sig = signSweepInput(
			claimTx,
			0,
			htlcScript,
			Number(amount),
			remoteHtlc.priv
		);
		const witness = buildRemoteHtlcTimeoutWitness(sig, htlcScript);
		claimTx.setWitness(0, witness);

		// 1. Timelock enforced: nLockTime == cltv_expiry, sequence not final.
		expect(claimTx.locktime).to.equal(cltvExpiry);
		expect(claimTx.ins[0].sequence).to.not.equal(0xffffffff);

		// 2. Witness selects the timeout branch: [sig, <empty>, witnessScript].
		expect(witness).to.have.length(3);
		expect(
			witness[1].length,
			'branch selector must be empty (size != 32)'
		).to.equal(0);
		expect(witness[2].equals(htlcScript)).to.equal(true);

		// 3. The signature satisfies OP_CHECKSIG: it must verify against OUR HTLC
		//    pubkey (the script's timeout-path key) over the BIP143 sighash with
		//    the witnessScript as scriptCode. A wrong key/sighash => unspendable.
		const sighash = claimTx.hashForWitnessV0(
			0,
			htlcScript,
			Number(amount),
			bitcoin.Transaction.SIGHASH_ALL
		);
		const sig64 = bitcoin.script.signature.decode(sig).signature; // DER -> 64B compact
		expect(
			ecc.verify(sighash, remoteHtlc.pub, sig64),
			'timeout signature must verify against our HTLC pubkey'
		).to.equal(true);
		// And NOT against their key (sanity: right key is required).
		expect(ecc.verify(sighash, localHtlc.pub, sig64)).to.equal(false);
	});
});
