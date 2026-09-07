/**
 * Swap chain resolver (issue #737, phase 2) over a scripted chain source
 * seeded from the P2WSH fixture: funding status, spend classification with
 * preimage extraction, confirmation policy, backend answers that do not
 * hash to the requested txid, reorg demotion, a claim racing a refund, and
 * the first-observation-after-restart rule.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import fs from 'fs';
import path from 'path';
import { computeScriptHash } from '../../src/lightning/chain/chain-watcher';
import {
	ISwapChainSource,
	ISwapHtlc,
	SwapChainResolver,
	buildSwapClaimTx,
	buildSwapHtlc,
	buildSwapRefundTx
} from '../../src/lightning/swaps';

interface IVector {
	claimPrivateKey: string;
	refundPrivateKey: string;
	preimage: string;
	paymentHash: string;
	claimPublicKey: string;
	refundPublicKey: string;
	refundHeight: number;
	fundingTransaction: string;
	fundingOutputIndex: number;
	destinationScript: string;
	claimTransaction: string;
	refundTransaction: string;
}

const vector: IVector = JSON.parse(
	fs.readFileSync(
		path.join(__dirname, 'fixtures', 'swaps', 'p2wsh.json'),
		'utf8'
	)
);

const htlc: ISwapHtlc = {
	paymentHash: Buffer.from(vector.paymentHash, 'hex'),
	claimPublicKey: Buffer.from(vector.claimPublicKey, 'hex'),
	refundPublicKey: Buffer.from(vector.refundPublicKey, 'hex'),
	refundHeight: vector.refundHeight
};
const fundingTx = bitcoin.Transaction.fromHex(vector.fundingTransaction);
const fundingTxid = fundingTx.getId();
const claimTx = bitcoin.Transaction.fromHex(vector.claimTransaction);
const refundTx = bitcoin.Transaction.fromHex(vector.refundTransaction);
const scriptHash = computeScriptHash(buildSwapHtlc(htlc).outputScript);

/** A chain source scripted by the test: history entries plus raw bytes. */
class FakeSource implements ISwapChainSource {
	height = 800_010;
	history = new Map<string, Array<{ txid: string; height: number }>>();
	txs = new Map<string, Buffer>();
	broadcasts: string[] = [];
	broadcastTxidOverride?: string;
	fetches: string[] = [];

	currentHeight(): number {
		return this.height;
	}
	async getTransaction(txid: string): Promise<Buffer> {
		this.fetches.push(txid);
		const raw = this.txs.get(txid);
		if (!raw) throw new Error(`unknown tx ${txid}`);
		return raw;
	}
	async getScriptHashHistory(
		hash: string
	): Promise<Array<{ txid: string; height: number }>> {
		return [...(this.history.get(hash) ?? [])];
	}
	async broadcastTransaction(rawTxHex: string): Promise<string> {
		this.broadcasts.push(rawTxHex);
		return (
			this.broadcastTxidOverride ??
			bitcoin.Transaction.fromHex(rawTxHex).getId()
		);
	}

	/** Place a transaction in the history at a height (0 = mempool). */
	add(tx: bitcoin.Transaction, height: number, raw = tx.toBuffer()): void {
		const list = this.history.get(scriptHash) ?? [];
		const existing = list.find((h) => h.txid === tx.getId());
		if (existing) existing.height = height;
		else list.push({ txid: tx.getId(), height });
		this.history.set(scriptHash, list);
		this.txs.set(tx.getId(), raw);
	}
	remove(txid: string): void {
		const list = (this.history.get(scriptHash) ?? []).filter(
			(h) => h.txid !== txid
		);
		this.history.set(scriptHash, list);
	}
}

function resolver(
	source: FakeSource,
	policy = { fundingConfirmations: 2, resolutionConfirmations: 3 }
): SwapChainResolver {
	return new SwapChainResolver(source, policy, bitcoin.networks.bitcoin);
}

const funding = { txid: fundingTxid, vout: vector.fundingOutputIndex };

describe('Swap chain resolver (issue #737 phase 2)', function () {
	it('validates the confirmation policy', function () {
		expect(
			() =>
				new SwapChainResolver(new FakeSource(), {
					fundingConfirmations: 0,
					resolutionConfirmations: 1
				})
		).to.throw(/fundingConfirmations/);
	});

	it('reports absent funding and discovers candidates when no outpoint is given', async function () {
		const source = new FakeSource();
		const r = resolver(source);
		const absent = await r.observe({ htlc, funding });
		expect(absent.funding.kind).to.equal('absent');
		expect(absent.spends).to.have.length(0);
		expect(absent.verifiedThisSession).to.equal(false);

		source.add(fundingTx, 800_005);
		const found = await r.observe({ htlc });
		expect(found.candidates).to.deep.equal([
			{ txid: fundingTxid, vout: 0, valueSat: 100_000n, height: 800_005 }
		]);
	});

	it('tracks funding from mempool to confirmed and applies the policy depth', async function () {
		const source = new FakeSource();
		const r = resolver(source);
		source.add(fundingTx, 0);
		let obs = await r.observe({ htlc, funding });
		expect(obs.funding.kind).to.equal('mempool');
		expect(obs.verifiedThisSession).to.equal(false);

		source.add(fundingTx, 800_010);
		obs = await r.observe({ htlc, funding });
		expect(obs.funding).to.include({
			kind: 'confirmed',
			height: 800_010,
			confirmations: 1,
			meetsPolicy: false
		});
		expect(obs.verifiedThisSession).to.equal(true);

		source.height = 800_011;
		obs = await r.observe({ htlc, funding });
		expect(obs.funding).to.include({ confirmations: 2, meetsPolicy: true });
		if (obs.funding.kind === 'confirmed') {
			expect(obs.funding.valueSat).to.equal(100_000n);
		}
	});

	it('demotes a recorded funding the chain no longer confirms', async function () {
		const source = new FakeSource();
		const r = resolver(source);
		const gone = await r.observe({
			htlc,
			funding,
			recorded: { fundingHeight: 800_005 }
		});
		expect(gone.funding).to.deep.equal({
			kind: 'reorged-out',
			previousHeight: 800_005
		});
		source.add(fundingTx, 0);
		const back = await r.observe({
			htlc,
			funding,
			recorded: { fundingHeight: 800_005 }
		});
		expect(back.funding.kind).to.equal('reorged-out');
		if (back.funding.kind === 'reorged-out') {
			expect(back.funding.tx?.getId()).to.equal(fundingTxid);
		}
	});

	it('classifies a claim with its preimage, at any depth, and a refund', async function () {
		const source = new FakeSource();
		const r = resolver(source);
		source.add(fundingTx, 800_000);
		source.add(claimTx, 0);
		let obs = await r.observe({ htlc, funding });
		expect(obs.spends).to.have.length(1);
		expect(obs.spends[0]).to.include({
			kind: 'claim',
			height: 0,
			confirmations: 0,
			meetsPolicy: false
		});
		expect(obs.spends[0].preimage!.toString('hex')).to.equal(vector.preimage);
		expect(obs.winning).to.equal(undefined);

		source.add(claimTx, 800_008);
		obs = await r.observe({ htlc, funding });
		expect(obs.spends[0]).to.include({ confirmations: 3, meetsPolicy: true });
		expect(obs.winning!.txid).to.equal(claimTx.getId());

		const other = new FakeSource();
		other.add(fundingTx, 800_000);
		other.add(refundTx, 800_009);
		const refund = await resolver(other).observe({ htlc, funding });
		expect(refund.spends[0]).to.include({
			kind: 'refund',
			confirmations: 2,
			meetsPolicy: false
		});
		expect(refund.spends[0].preimage).to.equal(undefined);
	});

	it('classifies a spend with any other witness as unknown', async function () {
		const source = new FakeSource();
		source.add(fundingTx, 800_000);
		const odd = buildSwapRefundTx({
			htlc,
			fundingTransaction: fundingTx,
			outputIndex: 0,
			destinationScript: Buffer.from(vector.destinationScript, 'hex'),
			feeSatoshis: 1_000n,
			privateKey: Buffer.from(vector.refundPrivateKey, 'hex')
		});
		odd.setWitness(0, [
			odd.ins[0].witness[0],
			Buffer.from([1, 2]),
			odd.ins[0].witness[2]
		]);
		source.add(odd, 800_009);
		const obs = await resolver(source).observe({ htlc, funding });
		expect(obs.spends[0].kind).to.equal('unknown');
	});

	it('ignores a transaction that does not spend the funding outpoint', async function () {
		const source = new FakeSource();
		source.add(fundingTx, 800_000);
		const unrelated = new bitcoin.Transaction();
		unrelated.version = 2;
		unrelated.addInput(Buffer.alloc(32, 9), 0);
		unrelated.addOutput(buildSwapHtlc(htlc).outputScript, 5_000);
		source.add(unrelated, 800_009);
		const obs = await resolver(source).observe({ htlc, funding });
		expect(obs.spends).to.have.length(0);
	});

	it('refuses a backend answer that does not hash to the requested txid', async function () {
		const source = new FakeSource();
		source.add(fundingTx, 800_000, claimTx.toBuffer());
		let failed: unknown;
		try {
			await resolver(source).observe({ htlc, funding });
		} catch (err) {
			failed = err;
		}
		expect(String(failed)).to.match(/returned transaction/);
	});

	it('refuses a funding outpoint that does not pay the contract', async function () {
		const source = new FakeSource();
		source.add(fundingTx, 800_000);
		let failed: unknown;
		try {
			await resolver(source).observe({
				htlc,
				funding: { txid: fundingTxid, vout: 5 }
			});
		} catch (err) {
			failed = err;
		}
		expect(String(failed)).to.match(/does not pay the swap contract/);
	});

	it('reports a demoted resolution when the recorded spend left or moved', async function () {
		const source = new FakeSource();
		const r = resolver(source);
		source.add(fundingTx, 800_000);
		source.add(refundTx, 800_005);
		const steady = await r.observe({
			htlc,
			funding,
			recorded: { resolutionTxid: refundTx.getId(), resolutionHeight: 800_005 }
		});
		expect(steady.demoted).to.equal(undefined);

		source.add(refundTx, 0);
		const moved = await r.observe({
			htlc,
			funding,
			recorded: { resolutionTxid: refundTx.getId(), resolutionHeight: 800_005 }
		});
		expect(moved.demoted).to.deep.equal({
			previousTxid: refundTx.getId(),
			previousHeight: 800_005
		});

		source.remove(refundTx.getId());
		const gone = await r.observe({
			htlc,
			funding,
			recorded: { resolutionTxid: refundTx.getId(), resolutionHeight: 800_005 }
		});
		expect(gone.demoted!.previousTxid).to.equal(refundTx.getId());
	});

	it('reports both a late claim and a broadcast refund, the deeper one winning', async function () {
		const source = new FakeSource();
		source.height = 800_012;
		source.add(fundingTx, 800_000);
		source.add(refundTx, 0);
		source.add(claimTx, 800_011);
		const obs = await resolver(source).observe({ htlc, funding });
		expect(obs.spends.map((s) => s.kind).sort()).to.deep.equal([
			'claim',
			'refund'
		]);
		expect(obs.winning!.kind).to.equal('claim');
		expect(obs.winning!.preimage!.toString('hex')).to.equal(vector.preimage);
	});

	it('caches fetched transactions', async function () {
		const source = new FakeSource();
		const r = resolver(source);
		source.add(fundingTx, 800_000);
		source.add(claimTx, 800_005);
		await r.observe({ htlc, funding });
		await r.observe({ htlc, funding });
		expect(source.fetches).to.deep.equal([fundingTxid, claimTx.getId()]);
	});

	it('broadcast verifies the reported txid', async function () {
		const source = new FakeSource();
		const r = resolver(source);
		const claim = buildSwapClaimTx({
			htlc,
			fundingTransaction: fundingTx,
			outputIndex: 0,
			destinationScript: Buffer.from(vector.destinationScript, 'hex'),
			feeSatoshis: 1_000n,
			privateKey: Buffer.from(vector.claimPrivateKey, 'hex'),
			preimage: Buffer.from(vector.preimage, 'hex')
		});
		expect(await r.broadcast(claim.toHex())).to.equal(claim.getId());
		source.broadcastTxidOverride = 'ff'.repeat(32);
		let failed: unknown;
		try {
			await r.broadcast(claim.toHex());
		} catch (err) {
			failed = err;
		}
		expect(String(failed)).to.match(/Broadcast returned txid/);
		expect(source.broadcasts).to.have.length(2);
	});
});
