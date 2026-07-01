/**
 * option_taproot full lifecycle — funding → commitment → co-signed spend
 * (regtest, M4.5).
 *
 * Ties together the whole taproot channel crypto: fund a real 2-of-2 MuSig2
 * key-spend P2TR funding output on regtest, build a commitment transaction whose
 * outputs are the taproot to_local/to_remote outputs, co-sign the funding
 * key-spend with MuSig2 partial signatures, aggregate, and confirm bitcoind
 * accepts the broadcast. Auto-skips if regtest bitcoind is unreachable.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';
import { bitcoinRpc, mineBlocks } from './shared-helpers';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput
} from '../../../src/lightning/script/commitment-taproot';
import { generateNonce } from '../../../src/lightning/crypto/musig';
import {
	taprootCommitmentSighash,
	startCommitmentSigningSession,
	partialSignCommitment,
	verifyPartialCommitmentSig,
	aggregateCommitmentSig
} from '../../../src/lightning/channel/commitment-musig';

bitcoin.initEccLib(ecc);
const NETWORK = bitcoin.networks.regtest;

async function bitcoindUp(): Promise<boolean> {
	try {
		await bitcoinRpc('getblockchaininfo');
		return true;
	} catch {
		return false;
	}
}

const kp = (): { priv: Buffer; pub: Buffer } => {
	const priv = crypto.randomBytes(32);
	return { priv, pub: Buffer.from(ecc.pointFromScalar(priv, true)!) };
};

describe('Interop: option_taproot commitment co-sign + spend (regtest)', function () {
	this.timeout(60_000);
	let skip = false;
	before(async function () {
		this.timeout(20_000);
		skip = !(await bitcoindUp());
	});

	it('funds, builds, co-signs and broadcasts a taproot commitment', async function () {
		if (skip) this.skip();

		const local = kp();
		const remote = kp();

		// 1. Fund the 2-of-2 MuSig2 key-spend P2TR funding output.
		const funding = createTaprootFundingScript(local.pub, remote.pub, NETWORK);
		const fundTxid = (await bitcoinRpc('sendtoaddress', [
			funding.address,
			0.01
		])) as string;
		await mineBlocks(1);
		const fundTx = (await bitcoinRpc('getrawtransaction', [fundTxid, true])) as {
			vout: { value: number; n: number; scriptPubKey: { address?: string } }[];
		};
		const fout = fundTx.vout.find(
			(v) => v.scriptPubKey.address === funding.address
		)!;
		const fundingValue = Math.round(fout.value * 1e8);

		// 2. Build the commitment tx: spends the funding, pays into taproot
		//    to_local + to_remote outputs.
		const revoke = kp();
		const delayed = kp();
		const toLocal = buildTaprootToLocalOutput(revoke.pub, delayed.pub, 144, NETWORK);
		const toRemote = buildTaprootToRemoteOutput(remote.pub, NETWORK);

		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(Buffer.from(fundTxid, 'hex').reverse(), fout.n);
		const half = Math.floor((fundingValue - 500) / 2);
		tx.addOutput(toLocal.output, half);
		tx.addOutput(toRemote.output, fundingValue - 500 - half);

		// 3. MuSig2 co-sign the funding key-spend over the commitment sighash.
		const sighash = taprootCommitmentSighash(
			tx,
			funding.p2trOutput,
			fundingValue
		);
		const localNonce = generateNonce({
			publicKey: local.pub,
			secretKey: local.priv,
			sessionId: crypto.randomBytes(32),
			msg: sighash
		});
		const remoteNonce = generateNonce({
			publicKey: remote.pub,
			secretKey: remote.priv,
			sessionId: crypto.randomBytes(32),
			msg: sighash
		});

		const sessionL = startCommitmentSigningSession(
			sighash,
			local.pub,
			remote.pub,
			localNonce,
			Buffer.from(remoteNonce)
		);
		const sessionR = startCommitmentSigningSession(
			sighash,
			remote.pub,
			local.pub,
			remoteNonce,
			Buffer.from(localNonce)
		);
		const localPartial = partialSignCommitment(sessionL, local.priv, localNonce);
		const remotePartial = partialSignCommitment(
			sessionR,
			remote.priv,
			remoteNonce
		);
		expect(
			verifyPartialCommitmentSig(
				sessionL,
				remotePartial,
				remote.pub,
				Buffer.from(remoteNonce)
			)
		).to.be.true;

		const finalSig = aggregateCommitmentSig(
			sessionL,
			localPartial,
			remotePartial
		);
		tx.ins[0].witness = [finalSig];

		// 4. The network accepts the co-signed taproot commitment.
		const [res] = (await bitcoinRpc('testmempoolaccept', [
			[tx.toHex()]
		])) as { allowed: boolean; ['reject-reason']?: string }[];
		expect(res.allowed, res['reject-reason']).to.be.true;

		// And it actually confirms.
		await bitcoinRpc('sendrawtransaction', [tx.toHex()]);
		await mineBlocks(1);
		const mined = (await bitcoinRpc('getrawtransaction', [
			tx.getId(),
			true
		])) as { confirmations?: number };
		expect((mined.confirmations ?? 0) >= 1).to.be.true;
	});
});
