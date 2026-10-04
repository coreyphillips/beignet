import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { generateMnemonic } from 'bip39';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { BeignetNode, BeignetNodeOptions } from '../../../src/cli/beignet-node';
import { bitcoinRpc, ensureBitcoindFunds, mineBlocks } from './shared-helpers';

async function until(check: () => Promise<boolean>): Promise<void> {
	const deadline = Date.now() + 45_000;
	while (!(await check())) {
		if (Date.now() >= deadline) throw new Error('Chain observation timed out');
		await new Promise((resolve) => setTimeout(resolve, 500));
	}
}

describe('Interop: durable loose-coin sweep (regtest)', function () {
	this.timeout(180_000);
	before(async function () {
		try {
			await bitcoinRpc('getblockchaininfo');
		} catch {
			this.skip();
		}
		await ensureBitcoindFunds();
	});

	it('signs below the channelize floor, restarts after a lost broadcast reply, and leaves later receipts untouched', async () => {
		const directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-sweep-regtest-')
		);
		const options: BeignetNodeOptions = {
			mnemonic: generateMnemonic(),
			network: 'regtest',
			dataDir: directory,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false,
			feeEstimationSource: 'electrum',
			listenPort: 0,
			autoBootstrap: false,
			autoReconnect: false,
			autoGossipSync: false,
			rapidGossipSync: false,
			logLevel: 'silent',
			dailySpendLimitSats: 20_000,
			maxPaymentSats: 20_000
		};
		let node: BeignetNode | undefined;
		const start = async () => {
			const instance = await BeignetNode.create(options);
			await instance.waitForInitialSync();
			return instance;
		};
		try {
			node = await start();
			const receive = await node.getNewAddress();
			const fundingTxid = (await bitcoinRpc('sendtoaddress', [
				receive,
				0.0002
			])) as string;
			await mineBlocks(1);
			await until(async () => {
				await node!.refreshWallet();
				return node!.listUtxos().some((coin) => coin.txid === fundingTxid);
			});
			const coin = node
				.listUtxos()
				.find((entry) => entry.txid === fundingTxid)!;
			const address = (await bitcoinRpc('getnewaddress', [
				'',
				'bech32m'
			])) as string;
			const requestId = 'durable-regtest-sweep';
			const prepared = await node.prepareOnchainSweep({
				requestId,
				address,
				satsPerVbyte: 2,
				debitSats: 20_000,
				maxFeeSats: 1000,
				inputOutpoints: [{ txid: coin.txid, vout: coin.vout }]
			});
			expect(prepared.status).to.equal('prepared');
			expect(prepared.amountSats! + prepared.feeSats!).to.equal(20_000);
			expect(await bitcoinRpc('gettxout', [coin.txid, coin.vout])).to.not.equal(
				null
			);
			await node.destroy();
			node = await start();
			expect(node.getOnchainSweep(requestId)).to.deep.equal(prepared);
			const laterTxid = (await bitcoinRpc('sendtoaddress', [
				receive,
				0.00003
			])) as string;
			await mineBlocks(1);
			await until(async () => {
				await node!.refreshWallet();
				return node!.listUtxos().some((entry) => entry.txid === laterTxid);
			});
			const internal = node as unknown as {
				_broadcastRawTx(hex: string): Promise<unknown>;
			};
			const broadcast = internal._broadcastRawTx.bind(node);
			let firstHex = '';
			internal._broadcastRawTx = async (hex) => {
				firstHex = hex;
				await broadcast(hex);
				throw new Error('Broadcast reply lost after acceptance');
			};
			const ambiguous = await node.submitOnchainSweep(requestId);
			expect(ambiguous.status).to.equal('submitted');
			expect(ambiguous.error).to.include('reply lost');
			const tx = bitcoin.Transaction.fromHex(firstHex);
			expect(tx.getId()).to.equal(prepared.txid);
			expect(
				tx.ins.map((input) => ({
					txid: Buffer.from(input.hash).reverse().toString('hex'),
					vout: input.index
				}))
			).to.deep.equal([{ txid: coin.txid, vout: coin.vout }]);
			expect(tx.outs).to.have.length(1);
			expect(
				tx.outs[0].script.equals(
					bitcoin.address.toOutputScript(address, bitcoin.networks.regtest)
				)
			).to.equal(true);
			await node.destroy();
			node = await start();
			const restarted = node as unknown as {
				_broadcastRawTx(hex: string): Promise<unknown>;
			};
			const rebroadcast = restarted._broadcastRawTx.bind(node);
			let attempts = 0;
			restarted._broadcastRawTx = async (hex) => {
				expect(hex).to.equal(firstHex);
				attempts++;
				return rebroadcast(hex);
			};
			const submitted = await node.submitOnchainSweep(requestId);
			expect(submitted.txid).to.equal(prepared.txid);
			expect(attempts).to.equal(1);
			await mineBlocks(1);
			await until(async () => {
				await node!.refreshWallet();
				return node!.getOnchainSweep(requestId)?.status === 'confirmed';
			});
			expect((await node.submitOnchainSweep(requestId)).status).to.equal(
				'confirmed'
			);
			expect(attempts).to.equal(1);
			expect(
				node
					.listOnchainTransactions()
					.filter((row) => row.txid === prepared.txid)
			).to.have.length(1);
			expect(
				node
					.listUtxos()
					.filter((entry) => entry.txid === laterTxid)
					.reduce((total, entry) => total + entry.valueSats, 0)
			).to.equal(3000);
		} finally {
			await node?.destroy();
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
});
