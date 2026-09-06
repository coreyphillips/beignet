/** Bitcoin Core script/CLTV verification. Requires the shared regtest node. */
import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	buildSwapHtlc,
	buildSwapClaimTx,
	buildSwapRefundTx,
	extractSwapPreimage,
	ISwapSpend
} from '../../../src/lightning/swaps';
import { getPublicKey, sign } from '../../../src/lightning/crypto/ecdh';
import { bitcoinRpc, ensureBitcoindFunds, mineBlocks } from './shared-helpers';

const network = bitcoin.networks.regtest;
const claimKey = Buffer.alloc(32, 0x41);
const refundKey = Buffer.alloc(32, 0x42);
const preimage = Buffer.alloc(32, 0x43);

async function height(): Promise<number> {
	return ((await bitcoinRpc('getblockchaininfo')) as { blocks: number }).blocks;
}

async function fundedSwap(secret = preimage): Promise<ISwapSpend> {
	const htlc = {
		paymentHash: bitcoin.crypto.sha256(secret),
		claimPublicKey: getPublicKey(claimKey),
		refundPublicKey: getPublicKey(refundKey),
		refundHeight: (await height()) + 12
	};
	const output = buildSwapHtlc(htlc, network);
	const txid = (await bitcoinRpc('sendtoaddress', [
		output.address,
		0.001
	])) as string;
	await mineBlocks(1);
	const walletTx = (await bitcoinRpc('gettransaction', [txid])) as {
		hex: string;
	};
	const fundingTransaction = bitcoin.Transaction.fromHex(walletTx.hex);
	const outputIndex = fundingTransaction.outs.findIndex((out) =>
		out.script.equals(output.outputScript)
	);
	if (outputIndex < 0)
		throw new Error('Swap output missing from funding transaction');
	return {
		htlc,
		fundingTransaction,
		outputIndex,
		destinationScript: bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(claimKey),
			network
		}).output!,
		feeSatoshis: 2000n,
		privateKey: claimKey
	};
}

async function accepts(
	tx: bitcoin.Transaction
): Promise<{ allowed: boolean; 'reject-reason'?: string }> {
	const results = (await bitcoinRpc('testmempoolaccept', [
		[tx.toHex()]
	])) as Array<{ allowed: boolean; 'reject-reason'?: string }>;
	return results[0];
}

function signature(
	tx: bitcoin.Transaction,
	params: ISwapSpend,
	privateKey: Buffer,
	hashType = bitcoin.Transaction.SIGHASH_ALL
): Buffer {
	const script = buildSwapHtlc(params.htlc).witnessScript;
	return bitcoin.script.signature.encode(
		sign(
			tx.hashForWitnessV0(
				0,
				script,
				params.fundingTransaction.outs[params.outputIndex].value,
				hashType
			),
			privateKey
		),
		hashType
	);
}

describe('Interop: P2WSH swap script and refund finality (regtest)', function () {
	this.timeout(120_000);
	before(async function () {
		let chain: string;
		try {
			chain = ((await bitcoinRpc('getblockchaininfo')) as { chain: string })
				.chain;
		} catch {
			if (process.env.REQUIRE_SWAP_REGTEST === '1')
				throw new Error('Required swap regtest node is unavailable');
			this.skip();
			return;
		}
		expect(chain, 'Only run these funding tests on regtest').to.equal(
			'regtest'
		);
		await ensureBitcoindFunds(1);
	});

	it('accepts claims, enforces the exact refund-height boundary, and permits late claims until spent', async () => {
		const params = await fundedSwap();
		const claim = buildSwapClaimTx({ ...params, preimage });
		const refund = buildSwapRefundTx({ ...params, privateKey: refundKey });
		const acceptedClaim = await accepts(claim);
		expect(acceptedClaim.allowed, acceptedClaim['reject-reason']).to.be.true;
		expect((await accepts(refund)).allowed).to.be.false;
		await mineBlocks(params.htlc.refundHeight - 1 - (await height()));
		expect(await height()).to.equal(params.htlc.refundHeight - 1);
		expect(
			(await accepts(refund)).allowed,
			'refund cannot enter a block at its nLockTime'
		).to.be.false;
		await mineBlocks(1);
		const acceptedRefund = await accepts(refund);
		expect(acceptedRefund.allowed, acceptedRefund['reject-reason']).to.be.true;
		expect(
			(await accepts(claim)).allowed,
			'CLTV does not disable the claim branch'
		).to.be.true;
		expect(extractSwapPreimage(claim, params)?.equals(preimage)).to.be.true;
		await bitcoinRpc('sendrawtransaction', [refund.toHex()]);
		await mineBlocks(1);
		expect(
			(await accepts(claim)).allowed,
			'confirmed refund consumes the output'
		).to.be.false;
	});

	it('rejects fully signed refund attempts that bypass CLTV with a final sequence or lower locktime', async () => {
		const params = await fundedSwap();
		await mineBlocks(params.htlc.refundHeight - (await height()));
		for (const change of ['final-sequence', 'low-locktime']) {
			const tx = buildSwapRefundTx({ ...params, privateKey: refundKey });
			if (change === 'final-sequence') tx.ins[0].sequence = 0xffffffff;
			else tx.locktime = params.htlc.refundHeight - 1;
			tx.ins[0].witness[0] = signature(tx, params, refundKey);
			expect((await accepts(tx)).allowed, change).to.be.false;
		}
	});

	it('extracts claims using every defined ECDSA sighash type accepted by Core', async () => {
		const params = await fundedSwap();
		for (const hashType of [
			bitcoin.Transaction.SIGHASH_ALL,
			bitcoin.Transaction.SIGHASH_NONE,
			bitcoin.Transaction.SIGHASH_SINGLE,
			bitcoin.Transaction.SIGHASH_ALL |
				bitcoin.Transaction.SIGHASH_ANYONECANPAY,
			bitcoin.Transaction.SIGHASH_NONE |
				bitcoin.Transaction.SIGHASH_ANYONECANPAY,
			bitcoin.Transaction.SIGHASH_SINGLE |
				bitcoin.Transaction.SIGHASH_ANYONECANPAY
		]) {
			const tx = buildSwapClaimTx({ ...params, preimage });
			tx.ins[0].witness[0] = signature(tx, params, claimKey, hashType);
			const result = await accepts(tx);
			expect(result.allowed, `sighash ${hashType}: ${result['reject-reason']}`)
				.to.be.true;
			expect(extractSwapPreimage(tx, params)?.equals(preimage)).to.be.true;
		}
	});

	it('rejects wrong preimages, wrong branch keys, nonminimal selectors and unsigned output changes', async () => {
		const params = await fundedSwap();
		for (const change of ['preimage', 'key', 'selector', 'output']) {
			const tx = buildSwapClaimTx({ ...params, preimage });
			if (change === 'preimage') tx.ins[0].witness[1] = Buffer.alloc(32);
			if (change === 'key')
				tx.ins[0].witness[0] = signature(tx, params, refundKey);
			if (change === 'selector') tx.ins[0].witness[2] = Buffer.from([2]);
			if (change === 'output') tx.outs[0].value--;
			expect((await accepts(tx)).allowed, change).to.be.false;
			expect(extractSwapPreimage(tx, params)).to.equal(undefined);
		}
	});

	for (const length of [31, 33]) {
		it(`enforces a 32-byte preimage in script even when a ${length}-byte secret matches the hash`, async () => {
			const secret = Buffer.alloc(length, 0x43);
			const params = await fundedSwap(secret);
			// Deliberately bypass the builder's preimage check to test consensus script execution.
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(
				params.fundingTransaction.getHash(),
				params.outputIndex,
				0xfffffffd
			);
			tx.addOutput(params.destinationScript, 98_000);
			tx.setWitness(0, [
				signature(tx, params, claimKey),
				secret,
				Buffer.from([1]),
				buildSwapHtlc(params.htlc).witnessScript
			]);
			expect((await accepts(tx)).allowed).to.be.false;
			expect(extractSwapPreimage(tx, params)).to.equal(undefined);
		});
	}
});
