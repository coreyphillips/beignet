import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import { BeignetNode } from '../../../src/cli/beignet-node';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { createFundingScript } from '../../../src/lightning/script/funding';
import { ChannelState } from '../../../src/lightning/channel/types';
import { IRREVOCABLE_DEPTH } from '../../../src/lightning/chain/types';
import { createNode, connectNodes } from '../helpers/loopback-nodes';
import { bitcoinRpc, ensureBitcoindFunds, mineBlocks } from './shared-helpers';

describe('Interop: external cooperative close payout (regtest)', function () {
	this.timeout(120_000);
	before(async function () {
		try {
			await bitcoinRpc('getblockchaininfo');
		} catch {
			this.skip();
		}
		await ensureBitcoindFunds();
	});

	for (const walletIsOpener of [true, false]) {
		it(`pays an external P2TR address, retains one send and resolves the balance, wallet opener=${walletIsOpener}`, async () => {
			const dir = fs.mkdtempSync(
				path.join(os.tmpdir(), 'beignet-external-close-rt-')
			);
			const storage = new SqliteStorage(path.join(dir, 'wallet.db'));
			storage.open();
			const wallet = createNode(
				`external-close-rt-${walletIsOpener}`,
				1,
				storage
			);
			const peer = createNode(`external-close-rt-${walletIsOpener}`, 2);
			const errors: unknown[] = [];
			wallet.on('node:error', (error: unknown) => errors.push(error));
			peer.on('node:error', (error: unknown) => errors.push(error));
			try {
				const openingHeight = (await bitcoinRpc('getblockcount')) as number;
				wallet.handleNewBlock(openingHeight);
				peer.handleNewBlock(openingHeight);
				connectNodes(wallet, peer);
				const opener = walletIsOpener ? wallet : peer;
				const acceptor = walletIsOpener ? peer : wallet;
				const channel = opener.openChannel(
					acceptor.getNodeId(),
					1_000_000n,
					400_000_000n
				);
				const state = channel.getFullState();
				const funding = createFundingScript(
					state.localBasepoints.fundingPubkey,
					state.remoteBasepoints!.fundingPubkey,
					bitcoin.networks.regtest
				);
				const fundingTxid = (await bitcoinRpc('sendtoaddress', [
					funding.address,
					0.01
				])) as string;
				await mineBlocks(1);
				const fundedHeight = (await bitcoinRpc('getblockcount')) as number;
				wallet.handleNewBlock(fundedHeight);
				peer.handleNewBlock(fundedHeight);
				const funded = (await bitcoinRpc('getrawtransaction', [
					fundingTxid,
					true
				])) as {
					vout: Array<{ n: number; scriptPubKey: { address?: string } }>;
				};
				const index = funded.vout.find(
					(out) => out.scriptPubKey.address === funding.address
				)!.n;
				const channelId = opener.createFunding(
					channel,
					Buffer.from(fundingTxid, 'hex').reverse(),
					index,
					crypto.randomBytes(64)
				)!;
				opener.handleFundingConfirmed(channelId);
				acceptor.handleFundingConfirmed(channelId);
				expect(
					opener.getChannelManager().updateChannelFee(channelId, 2500).ok
				).to.equal(true);
				// Both peers use the same current chain estimate for closing.
				for (const participant of [wallet, peer]) {
					participant
						.getChannelManager()
						.getChannel(channelId)!
						.setClosingFeeratePerKw(10_000);
				}
				const address = (await bitcoinRpc('getnewaddress', [
					'',
					'bech32m'
				])) as string;
				const destination = bitcoin.address.toOutputScript(
					address,
					bitcoin.networks.regtest
				);
				const api = Object.assign(Object.create(BeignetNode.prototype), {
					node: wallet,
					networkName: 'regtest',
					wallet: { transactions: {}, getBalance: () => 0 }
				}) as BeignetNode;
				const assertNoWalletBalance = () => {
					expect(api.getBalance().lightning).to.equal(0);
					expect(api.getBalance().total).to.equal(0);
					expect(api.getInfo().pendingCloseBalanceSats).to.equal(0);
				};
				const quote = await api.closeQuote(channelId.toString('hex'), address);
				expect(quote.amountSats + quote.feeSats).to.equal(
					walletIsOpener ? 600000 : 400000
				);
				expect(
					(await api.closeChannel(channelId.toString('hex'), false, address)).ok
				).to.equal(true);
				expect(errors).to.deep.equal([]);
				const closed = wallet
					.getChannelManager()
					.getChannel(channelId)!
					.getFullState();
				expect(closed.state).to.equal(ChannelState.CLOSED);
				assertNoWalletBalance();
				const tx = bitcoin.Transaction.fromHex(
					closed.lastCooperativeCloseTxHex!
				);
				const outputIndex = tx.outs.findIndex((out) =>
					out.script.equals(destination)
				);
				expect(outputIndex).to.be.at.least(0);
				await bitcoinRpc('sendrawtransaction', [tx.toHex()]);
				await mineBlocks(1);
				const height = (await bitcoinRpc('getblockcount')) as number;
				wallet.handleFundingSpent(
					channelId,
					tx,
					height,
					Buffer.from('0014' + '33'.repeat(20), 'hex')
				);
				const payout = (await bitcoinRpc('gettxout', [
					tx.getId(),
					outputIndex
				])) as { value: number; confirmations: number };
				expect(Math.round(payout.value * 100_000_000)).to.equal(
					tx.outs[outputIndex].value
				);
				expect(payout.confirmations).to.be.at.least(1);
				assertNoWalletBalance();
				const history = api.listOnchainTransactions();
				expect(history).to.have.length(1);
				expect(history[0]).to.include({
					txid: tx.getId(),
					address,
					valueSats: tx.outs[outputIndex].value,
					type: 'sent',
					confirmed: true
				});
				expect(history[0].valueSats + history[0].feeSats).to.equal(
					walletIsOpener ? 600000 : 400000
				);
				await mineBlocks(IRREVOCABLE_DEPTH);
				wallet.handleNewBlock((await bitcoinRpc('getblockcount')) as number);
				expect(wallet.getChannel(channelId)!.closeStatus!.resolution).to.equal(
					'resolved'
				);
				expect(wallet.getChannel(channelId)!.spendableOutboundMsat).to.equal(
					0n
				);
				assertNoWalletBalance();
				expect(api.listOnchainTransactions()).to.have.length(1);
			} finally {
				wallet.destroy();
				peer.destroy();
				fs.rmSync(dir, { recursive: true, force: true });
			}
		});
	}
});
