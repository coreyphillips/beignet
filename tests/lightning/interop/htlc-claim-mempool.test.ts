/**
 * Regtest mempool-acceptance validation for the on-chain HTLC claims added by
 * the 2026-06 security audit remediation (bitcoind only, no LND/CLN):
 *
 *  - H3: buildRemoteHtlcTimeoutClaimTx / buildRemoteHtlcTimeoutWitness — reclaim
 *    OUR offered HTLC from the counterparty's commitment via the received-HTLC
 *    script's CLTV-timeout path. Proves bitcoind accepts the witness AND enforces
 *    the timelock (the claim is rejected before cltv_expiry, accepted after).
 *  - H2: the HTLC-output penalty witness (buildHtlcPenaltyWitness) on a revoked
 *    commitment — proves the justice spend of an HTLC output is relay-valid (the
 *    H2 code change is classification/persistence; the witness is what funds rely
 *    on, so we validate it here against a real node).
 *
 * Needs only bitcoind. Skips cleanly when unreachable. Run via:
 *   npx mocha --exit --timeout 120000 -r ts-node/register \
 *     tests/lightning/interop/htlc-claim-mempool.test.ts
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { bitcoinRpc, ensureBitcoindFunds, mineBlocks } from './shared-helpers';
import {
	buildReceivedHtlcScript,
	buildOfferedHtlcScript
} from '../../../src/lightning/script/htlc';
import {
	buildRemoteHtlcTimeoutClaimTx,
	buildRemoteHtlcTimeoutWitness,
	signSweepInput
} from '../../../src/lightning/chain/sweep';
import {
	buildPenaltyTx,
	signPenaltyInput,
	buildHtlcPenaltyWitness
} from '../../../src/lightning/script/revocation';
import {
	deriveRevocationPubkey,
	deriveRevocationPrivkey,
	perCommitmentPointFromSecret
} from '../../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

interface IFundedUtxo {
	priv: Buffer;
	pubkey: Buffer;
	prevTx: Buffer;
	vout: number;
	value: bigint;
}

async function fundP2wpkh(seed: string, amountSats: number): Promise<IFundedUtxo> {
	const priv = crypto.createHash('sha256').update(`htlcclaim-${seed}`).digest();
	const keyPair = ECPair.fromPrivateKey(priv, { network });
	const pubkey = Buffer.from(keyPair.publicKey);
	const address = bitcoin.payments.p2wpkh({ pubkey, network }).address!;
	const txid = (await bitcoinRpc('sendtoaddress', [address, amountSats / 1e8])) as string;
	await mineBlocks(1);
	const wtx = (await bitcoinRpc('gettransaction', [txid])) as { hex: string };
	const tx = bitcoin.Transaction.fromHex(wtx.hex);
	const script = bitcoin.payments.p2wpkh({ pubkey, network }).output!;
	const vout = tx.outs.findIndex((o) => o.script.equals(script));
	if (vout < 0) throw new Error('funded vout not found');
	return { priv, pubkey, prevTx: Buffer.from(tx.toBuffer()), vout, value: BigInt(tx.outs[vout].value) };
}

/** Spend a funded P2WPKH UTXO into a single P2WSH(htlcScript) output, confirm it. */
async function publishHtlcOutput(
	u: IFundedUtxo,
	htlcScript: Buffer,
	htlcValue: bigint
): Promise<{ txid: string; vout: number }> {
	const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: htlcScript }, network });
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(bitcoin.Transaction.fromBuffer(u.prevTx).getHash(), u.vout, 0xffffffff);
	tx.addOutput(p2wsh.output!, Number(htlcValue));
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: u.pubkey, network }).output!;
	const sig = signSweepInput(tx, 0, scriptCode, Number(u.value), u.priv);
	tx.setWitness(0, [sig, u.pubkey]);
	await bitcoinRpc('sendrawtransaction', [tx.toHex()]);
	await mineBlocks(1);
	return { txid: tx.getId(), vout: 0 };
}

async function testmempoolaccept(
	rawTxs: string[]
): Promise<Array<{ allowed: boolean; ['reject-reason']?: string }>> {
	return (await bitcoinRpc('testmempoolaccept', [rawTxs])) as Array<{ allowed: boolean }>;
}

async function destScript(label: string): Promise<Buffer> {
	const addr = (await bitcoinRpc('getnewaddress', [label, 'bech32'])) as string;
	return bitcoin.address.toOutputScript(addr, network);
}

async function blockHeight(): Promise<number> {
	const info = (await bitcoinRpc('getblockchaininfo')) as { blocks: number };
	return info.blocks;
}

function key(seed: string): { priv: Buffer; pub: Buffer } {
	const priv = crypto.createHash('sha256').update(`htlckey-${seed}`).digest();
	return { priv, pub: Buffer.from(ECPair.fromPrivateKey(priv, { network }).publicKey) };
}

describe('Interop: on-chain HTLC claim mempool acceptance (regtest)', function () {
	this.timeout(120_000);
	let skipAll = false;

	before(async function () {
		try {
			await bitcoinRpc('getblockchaininfo');
			await ensureBitcoindFunds(2);
		} catch {
			skipAll = true;
			console.log('    ⚠ bitcoind not available — skipping HTLC claim mempool tests.');
			this.skip();
		}
	});

	it('H3: timeout-claim is rejected before CLTV and accepted after (non-anchor)', async function () {
		if (skipAll) this.skip();

		// Our offered HTLC on their commitment uses the received-HTLC script, whose
		// timeout path is signed by remote_htlcpubkey (our key).
		const revocation = key('h3-rev');
		const localHtlc = key('h3-localhtlc'); // their htlc key on their commitment
		const remoteHtlc = key('h3-remotehtlc'); // OUR htlc key
		const paymentHash = crypto.randomBytes(32);

		const cltvExpiry = (await blockHeight()) + 6;
		const htlcScript = buildReceivedHtlcScript(
			revocation.pub,
			localHtlc.pub,
			remoteHtlc.pub,
			paymentHash,
			cltvExpiry,
			false
		);

		const fundingUtxo = await fundP2wpkh('h3-funding', 80_000);
		const htlcValue = 70_000n;
		const { txid, vout } = await publishHtlcOutput(fundingUtxo, htlcScript, htlcValue);

		const buildClaim = async (): Promise<bitcoin.Transaction> => {
			const claimTx = buildRemoteHtlcTimeoutClaimTx({
				commitmentTxid: txid,
				outputIndex: vout,
				amount: htlcValue,
				witnessScript: htlcScript,
				destinationScript: await destScript('h3-claim'),
				feeSatoshis: 2_000n,
				cltvExpiry,
				inputSequence: 0xfffffffd
			});
			const sig = signSweepInput(claimTx, 0, htlcScript, Number(htlcValue), remoteHtlc.priv);
			claimTx.setWitness(0, buildRemoteHtlcTimeoutWitness(sig, htlcScript));
			return claimTx;
		};

		// Before CLTV maturity: must be rejected (non-final / CLTV not satisfied).
		const early = await buildClaim();
		const [earlyRes] = await testmempoolaccept([early.toHex()]);
		expect(earlyRes.allowed, 'claim must be rejected before cltv_expiry').to.be.false;

		// Mine past the expiry, then the SAME claim must be accepted.
		const need = cltvExpiry - (await blockHeight());
		if (need > 0) await mineBlocks(need + 1);
		const mature = await buildClaim();
		const [matureRes] = await testmempoolaccept([mature.toHex()]);
		expect(matureRes.allowed, matureRes['reject-reason']).to.be.true;
	});

	it('H2: HTLC-output penalty spend on a revoked commitment is relay-valid', async function () {
		if (skipAll) this.skip();

		// On a revoked commitment, every output (incl. HTLCs) is claimable with the
		// revocation key. Build an offered-HTLC output (as it appears on the
		// cheater's commitment) and spend it via the penalty path.
		const perCommitmentSecret = crypto.randomBytes(32);
		const perCommitmentPoint = perCommitmentPointFromSecret(perCommitmentSecret);
		const revBase = key('h2-revbase');
		const localHtlc = key('h2-localhtlc');
		const remoteHtlc = key('h2-remotehtlc');
		const paymentHash = crypto.randomBytes(32);

		const revocationPubkey = deriveRevocationPubkey(revBase.pub, perCommitmentPoint);
		const revocationPrivkey = deriveRevocationPrivkey(
			revBase.priv,
			perCommitmentSecret,
			revBase.pub,
			perCommitmentPoint
		);

		const htlcScript = buildOfferedHtlcScript(
			revocationPubkey,
			localHtlc.pub,
			remoteHtlc.pub,
			paymentHash,
			false
		);

		const fundingUtxo = await fundP2wpkh('h2-funding', 80_000);
		const htlcValue = 70_000n;
		const { txid, vout } = await publishHtlcOutput(fundingUtxo, htlcScript, htlcValue);
		const revokedTx = bitcoin.Transaction.fromHex(
			((await bitcoinRpc('getrawtransaction', [txid])) as string) || ''
		);

		const witnessScripts = new Map<number, Buffer>([[vout, htlcScript]]);
		const penaltyTx = buildPenaltyTx({
			revokedTx,
			revocationPrivkey,
			destinationAddress: bitcoin.address.fromOutputScript(
				await destScript('h2-penalty'),
				network
			),
			feeRatePerVbyte: 5,
			outputIndices: [vout],
			witnessScripts,
			network
		});
		const sig = signPenaltyInput(
			penaltyTx,
			0,
			htlcScript,
			Number(htlcValue),
			revocationPrivkey
		);
		penaltyTx.setWitness(0, buildHtlcPenaltyWitness(sig, revocationPubkey, htlcScript));

		const [res] = await testmempoolaccept([penaltyTx.toHex()]);
		expect(res.allowed, res['reject-reason']).to.be.true;
	});
});
