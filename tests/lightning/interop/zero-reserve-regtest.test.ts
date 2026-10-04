/** Real funding and splice transactions for negotiated wallet reserve waivers. */
import { expect } from 'chai';
import * as net from 'net';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { Feature, FeatureFlags } from '../../../src/lightning/features/flags';
import {
	REGTEST_CHAIN_HASH,
	ChannelState
} from '../../../src/lightning/channel/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../../src/lightning/storage/serialization';
import { Channel } from '../../../src/lightning/channel/channel';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import {
	BitcoindFundingProvider,
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	ensureBitcoindFunds,
	sleep
} from './shared-helpers';

async function waitFor(test: () => boolean, label: string): Promise<void> {
	const until = Date.now() + 30_000;
	while (!test()) {
		if (Date.now() > until) throw new Error(`Timed out waiting for ${label}`);
		await sleep(50);
	}
}

async function freePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const server = net.createServer();
		server.on('error', reject);
		server.listen(0, '127.0.0.1', () => {
			const port = (server.address() as net.AddressInfo).port;
			server.close(() => resolve(port));
		});
	});
}

describe('Regtest: negotiated zero reserve and splice max', function () {
	this.timeout(180_000);
	before(async function () {
		try {
			await bitcoinRpc('getblockcount');
		} catch {
			this.skip();
		}
		await ensureBitcoindFunds(5);
	});
	for (const primaryOpens of [false, true]) {
		for (const version of [1, 2]) {
			for (const destination of ['p2wpkh', 'p2tr', 'p2wsh'] as const) {
				it(`${
					primaryOpens ? 'primary' : 'wallet'
				}-opened v${version} retains only its commitment cost after max to ${destination}`, async function () {
					const provider = new BitcoindFundingProvider();
					const directory = fs.mkdtempSync(
						path.join(os.tmpdir(), 'zero-reserve-regtest-')
					);
					const tag = `zero-reserve-${version}-${destination}-${Date.now()}`;
					const broadcastErrors: string[] = [];
					const features = LightningNode.defaultFeatures();
					if (version === 1) {
						features.clearBit(Feature.DUAL_FUND);
						features.clearBit(Feature.DUAL_FUND + 1);
					}
					features.setOptional(Feature.SPLICE);
					features.setOptional(Feature.QUIESCE);
					const make = (role: 'primary' | 'wallet') => {
						const storage = new SqliteStorage(
							path.join(directory, `${role}.sqlite`)
						);
						storage.open();
						const keys = deriveLightningKeysFromMnemonic(
							TEST_MNEMONIC,
							`${tag}-${role}`,
							LnCoinType.REGTEST
						);
						const node = new LightningNode({
							...keys,
							network: Network.REGTEST,
							enableNetworking: true,
							localFeatures: FeatureFlags.fromBuffer(features.toBuffer()),
							chainHashes: [REGTEST_CHAIN_HASH],
							preferAnchors: true,
							fundingProvider: provider,
							storage,
							zeroReserve: {
								advertise: true,
								role,
								waiveClientReserve: role === 'primary'
							}
						});
						node.on('error', () => undefined);
						node.on('broadcast:tx', (raw: Buffer) => {
							provider
								.broadcastTransaction(raw.toString('hex'))
								.catch((error) => broadcastErrors.push(String(error)));
						});
						node.on('node:error', (e: { code: string; message: string }) =>
							console.log(`    ${role}: ${e.code}: ${e.message}`)
						);
						return node;
					};
					const primary = make('primary');
					let wallet = make('wallet');
					try {
						const port = await freePort();
						await primary.listen(port);
						primary.addTrustedPeer(wallet.getNodeId());
						wallet.addTrustedPeer(primary.getNodeId());
						await wallet.connectPeer(primary.getNodeId(), '127.0.0.1', port);
						await waitFor(
							() => wallet.peerFundingInfo(primary.getNodeId()).peerKnown,
							'peer init'
						);
						const opener = primaryOpens ? primary : wallet;
						const acceptor = primaryOpens ? wallet : primary;
						if (primaryOpens)
							primary.getChannelManager().setJitClients([wallet.getNodeId()]);
						let opened: Channel;
						if (version === 2) {
							await provider.prefundFeeInputs(1, 1_200_000);
							const contribution = await provider.selectFeeBumpInputs(0n, 253);
							opened = opener.openChannelV2(acceptor.getNodeId(), {
								fundingSatoshis: 1_000_000n,
								fundingFeeratePerkw: 1000,
								commitmentFeeratePerkw: 253,
								trusted: true,
								contribution
							});
						} else {
							opened = opener.openChannel(
								acceptor.getNodeId(),
								1_000_000n,
								0n,
								1,
								false,
								true
							);
						}
						await waitFor(
							() => opened.getState() === ChannelState.NORMAL,
							'wallet channel ready'
						);
						const id = opened.getChannelId()!;
						const channel = wallet.getChannelManager().getChannel(id)!;
						const peer = primary.getChannelManager().getChannel(id)!;
						expect(channel.getFullState().localReserveWaived).to.equal(true);
						expect(peer.getFullState().remoteReserveWaived).to.equal(true);
						expect(peer.getFullState().localReserveWaived === true).to.equal(
							false
						);
						await mineBlocks(6);
						const tip = (await bitcoinRpc('getblockcount')) as number;
						for (const node of [wallet, primary]) {
							node.handleFundingConfirmed(id);
							node.handleNewBlock(tip);
						}
						const paid = opener.sendPayment(
							acceptor.createInvoice({
								description: 'fund both channel sides',
								amountMsat: 100_000_001n
							}).bolt11
						);
						await opener.waitForPayment(paid.paymentHash, 30_000);
						await waitFor(
							() =>
								channel.getFullState().htlcs.size === 0 &&
								peer.getFullState().htlcs.size === 0,
							'payment removal'
						);
						const address = (await bitcoinRpc('getnewaddress', [
							'',
							destination === 'p2tr' ? 'bech32m' : 'bech32'
						])) as string;
						const script =
							destination === 'p2wsh'
								? bitcoin.payments.p2wsh({
										redeem: { output: Buffer.from([0x51]) },
										network: bitcoin.networks.regtest
								  }).output!
								: bitcoin.address.toOutputScript(
										address,
										bitcoin.networks.regtest
								  );
						const quote = wallet.spliceQuote(id, 'out', 1000, script);
						expect(quote.reserveSats).to.equal(0);
						expect(quote.commitmentCostSats).to.equal(primaryOpens ? 0 : 944);
						const refused = wallet.spliceOut(
							id,
							BigInt(quote.maxAmountSats + 1),
							1000,
							script
						);
						expect(refused.ok).to.equal(false);
						const accepted = wallet.spliceOut(
							id,
							BigInt(quote.maxAmountSats),
							1000,
							script
						);
						expect(accepted.ok, accepted.error).to.equal(true);
						await waitFor(
							() => !!channel.getFullState().spliceFundingTxid,
							'signed splice'
						);
						const txid = Buffer.from(channel.getFullState().spliceFundingTxid!)
							.reverse()
							.toString('hex');
						let tx: bitcoin.Transaction | undefined;
						const until = Date.now() + 30_000;
						while (!tx && Date.now() < until) {
							try {
								tx = bitcoin.Transaction.fromHex(
									(await bitcoinRpc('getrawtransaction', [txid])) as string
								);
							} catch {
								await sleep(100);
							}
						}
						expect(
							tx,
							`splice broadcast accepted by bitcoind: ${broadcastErrors.join(
								'; '
							)}`
						).to.exist;
						expect(
							tx!.outs.find((o) => o.script.equals(script))!.value
						).to.equal(quote.maxAmountSats);
						await mineBlocks(6);
						for (const node of [wallet, primary]) {
							if (
								node.getChannelManager().getChannel(id)!.getState() ===
								ChannelState.SPLICING
							)
								node.getChannelManager().sendSpliceLocked(id);
						}
						await waitFor(
							() =>
								channel.getState() === ChannelState.NORMAL &&
								peer.getState() === ChannelState.NORMAL,
							'splice lock'
						);
						expect(channel.getFullState().localBalanceMsat).to.equal(
							primaryOpens ? 1n : 944_999n
						);
						expect(peer.getFullState().localBalanceMsat).to.equal(
							primaryOpens ? 899_999_999n : 100_000_001n
						);
						const restored = new Channel(
							deserializeChannelState(
								serializeChannelState(channel.getFullState())
							)
						);
						restored.repairKeptChannelReserve();
						expect(restored.getFullState().localReserveWaived).to.equal(true);
						expect(
							restored.getFullState().remoteConfig.channelReserveSatoshis
						).to.equal(0n);
						expect(restored.spliceReserveWeKeepSats(5_000_000n)).to.equal(0n);
						if (destination === 'p2wpkh') {
							const balance = channel.getFullState().localBalanceMsat;
							wallet.destroy();
							await sleep(100);
							wallet = make('wallet');
							const reopened = wallet.getChannelManager().getChannel(id)!;
							expect(reopened.getFullState().localReserveWaived).to.equal(true);
							expect(
								reopened.getFullState().remoteConfig.channelReserveSatoshis
							).to.equal(0n);
							expect(reopened.getFullState().localBalanceMsat).to.equal(
								balance
							);
							await wallet.connectPeer(primary.getNodeId(), '127.0.0.1', port);
							await waitFor(
								() =>
									reopened.getState() === ChannelState.NORMAL &&
									reopened.isHtlcUsable(),
								'restored channel reestablishment'
							);
						}
					} finally {
						wallet.destroy();
						primary.destroy();
						fs.rmSync(directory, { recursive: true, force: true });
					}
				});
			}
		}
	}
});
