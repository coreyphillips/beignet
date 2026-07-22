/**
 * Interop: issue #158 — the DEFAULT open path against a dual-fund peer.
 *
 * Production features advertise option_dual_fund, but openChannel always sent
 * a v1 open_channel, which a dual-fund CLN rejects at negotiation with
 * "OPT_DUAL_FUND: cannot use open_channel". The fix routes openChannel to the
 * v2 flow when the peer negotiated dual funding, and the channel manager
 * auto-funds the initiator's interactive-tx contribution from the funding
 * provider (BOLT 2: the initiator sends the first tx_add_input and
 * contributes the shared funding output, paying the feerate over the common
 * fields and that output).
 *
 * This is the coverage the issue called out as missing: createInteropNode
 * deliberately omits DUAL_FUND (adding it flips CLN's own fundchannel to v2
 * for every other tier), so the production feature set was never exercised.
 * Like v2-dualfund-interop.test.ts, this file builds its own dual-fund node.
 *
 * Requires the `cln` container with --experimental-dual-fund. Auto-skips when
 * CLN is unreachable or does not advertise option_dual_fund.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	waitForClnPeerChannelNormal,
	CLN_P2P_HOST,
	CLN_P2P_PORT,
	sleep
} from './cln-helpers';
import {
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	ensureBitcoindFunds
} from './shared-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	REGTEST_CHAIN_HASH,
	ChannelState
} from '../../../src/lightning/channel/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import { ISpliceWalletInput } from '../../../src/lightning/channel/channel';
import { IFundingProvider } from '../../../src/lightning/node/types';

bitcoin.initEccLib(ecc);

describe('Interop: default openChannel auto-funds a v2 open vs CLN (regtest)', function () {
	this.timeout(300_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let skipAll = false;
	let node: LightningNode | undefined;

	before(async function () {
		this.timeout(60_000);
		if (!(await isClnAvailable())) {
			skipAll = true;
			console.log('    [skip] CLN container not reachable');
			this.skip();
			return;
		}
		cln = (await createClnClient())!;
		await waitForClnSync(cln);
		const info = (await cln.getInfo()) as unknown as {
			id: string;
			our_features?: { init: string };
		};
		clnPubkey = info.id;
		const init = BigInt(`0x${info.our_features?.init ?? '0'}`);
		if (((init >> 28n) & 1n) === 0n && ((init >> 29n) & 1n) === 0n) {
			skipAll = true;
			console.log('    [skip] CLN lacks --experimental-dual-fund');
			this.skip();
			return;
		}
		await ensureBitcoindFunds(2.0);
	});

	after(function () {
		if (node) {
			try {
				node.disconnectPeer(clnPubkey);
			} catch {
				/* ignore */
			}
			try {
				node.destroy();
			} catch {
				/* ignore */
			}
		}
	});

	it('plain openChannel with production features reaches NORMAL on both sides', async function () {
		if (skipAll) this.skip();

		// A real wallet UTXO the funding provider selects and signs, playing
		// the role WalletFundingProvider plays in the daemon.
		const walletPriv = crypto
			.createHash('sha256')
			.update(Buffer.from(`autofund-wallet-${Date.now()}`))
			.digest();
		const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
		const walletPayment = bitcoin.payments.p2wpkh({
			pubkey: walletPub,
			network: bitcoin.networks.regtest
		});
		const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
		const utxoValue = 600_000;
		const fundTxid = (await bitcoinRpc('sendtoaddress', [
			walletPayment.address!,
			utxoValue / 1e8
		])) as string;
		await mineBlocks(1);
		const prevRaw = (await bitcoinRpc('getrawtransaction', [
			fundTxid
		])) as string;
		const prevTx = bitcoin.Transaction.fromHex(prevRaw);
		const prevVout = prevTx.outs.findIndex((o) =>
			Buffer.from(o.script).equals(walletPayment.output!)
		);
		expect(prevVout).to.be.gte(0);

		const fundingProvider: IFundingProvider = {
			buildFundingTransaction: async () => {
				throw new Error('v1 funding must not run for a dual-fund peer');
			},
			broadcastTransaction: async (txHex: string) =>
				(await bitcoinRpc('sendrawtransaction', [txHex])) as string,
			selectSpliceInputs: async (
				_amountSats: bigint,
				_feeratePerKw: number
			): Promise<{ inputs: ISpliceWalletInput[]; changeScript: Buffer }> => ({
				inputs: [
					{
						prevTx: prevTx.toBuffer(),
						prevOutputIndex: prevVout,
						value: BigInt(utxoValue),
						sequence: 0xfffffffd,
						confirmed: true,
						signWitness: (tx, inputIndex, value): Buffer[] => {
							const sighash = tx.hashForWitnessV0(
								inputIndex,
								scriptCode,
								Number(value),
								bitcoin.Transaction.SIGHASH_ALL
							);
							const der = bitcoin.script.signature.encode(
								Buffer.from(ecc.sign(sighash, walletPriv)),
								bitcoin.Transaction.SIGHASH_ALL
							);
							return [der, walletPub];
						}
					}
				],
				changeScript: walletPayment.output!
			})
		};

		const keys = deriveLightningKeysFromMnemonic(
			TEST_MNEMONIC,
			`autofund-seed-${Date.now()}`,
			LnCoinType.REGTEST
		);
		node = new LightningNode({
			nodePrivateKey: keys.nodePrivateKey,
			channelBasepoints: keys.channelBasepoints,
			perCommitmentSeed: keys.perCommitmentSeed,
			fundingPrivkey: keys.fundingPrivkey,
			htlcBasepointSecret: keys.htlcBasepointSecret,
			network: Network.REGTEST,
			enableNetworking: true,
			// The point of the test: the PRODUCTION feature set, dual fund
			// included, not the interop helper's reduced set.
			localFeatures: LightningNode.defaultFeatures(),
			chainHashes: [REGTEST_CHAIN_HASH],
			preferAnchors: true,
			fundingProvider
		});
		const peerErrors: string[] = [];
		node.on('node:error', (e: { code?: string; message?: string }) => {
			peerErrors.push(`${e.code}: ${e.message}`);
		});
		node.on('error', () => {});
		// No chain watcher in this harness: relay broadcast:tx to bitcoind
		// ourselves (the daemon's Electrum chain watcher does this in
		// production). Duplicate submissions are fine; CLN may broadcast too.
		node.on('broadcast:tx', (tx: Buffer) => {
			bitcoinRpc('sendrawtransaction', [tx.toString('hex')]).catch(() => {
				/* already known / already broadcast */
			});
		});

		await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await sleep(1500);

		// The plain v1 API, exactly what the dashboard's connect-and-open uses.
		const channel = node.openChannel(clnPubkey, 500_000n, undefined, 4);
		expect(channel.getFullState().state).to.equal(ChannelState.DUAL_FUNDING_V2);

		// Negotiation, auto-contribution, commitment round, tx_signatures.
		const negotiationDeadline = Date.now() + 45_000;
		while (Date.now() < negotiationDeadline) {
			if (channel.getFullState().fundingTxid) break;
			if (peerErrors.some((e) => /cannot use open_channel/i.test(e))) break;
			await sleep(500);
		}
		expect(
			peerErrors.filter((e) => /cannot use open_channel/i.test(e)),
			'CLN must not reject the open as v1'
		).to.deep.equal([]);
		const st = channel.getFullState();
		expect(st.fundingTxid, 'funding tx negotiated and signed').to.exist;

		const displayTxid = Buffer.from(st.fundingTxid!).reverse().toString('hex');
		let seen = false;
		const bcastDeadline = Date.now() + 30_000;
		while (Date.now() < bcastDeadline) {
			try {
				await bitcoinRpc('getrawtransaction', [displayTxid]);
				seen = true;
				break;
			} catch {
				await sleep(1000);
			}
		}
		expect(seen, 'funding tx reached bitcoind').to.equal(true);

		await mineBlocks(6);
		await sleep(2000);
		const channelId = channel.getChannelId();
		expect(channelId, 'channel promoted to its v2 channel_id').to.exist;
		node.handleFundingConfirmed(channelId!);

		await waitForClnPeerChannelNormal(cln, node.getNodeId(), 60_000);
		const readyDeadline = Date.now() + 30_000;
		while (Date.now() < readyDeadline) {
			if (channel.getState() === ChannelState.NORMAL) break;
			await sleep(500);
		}
		expect(channel.getState(), 'beignet side NORMAL').to.equal(
			ChannelState.NORMAL
		);

		const { channels } = await cln.listChannels();
		const entry = (channels || []).find(
			(c) => c.peer_id === node!.getNodeId() && c.state === 'CHANNELD_NORMAL'
		);
		expect(entry, 'CLN lists the channel NORMAL').to.exist;
		expect(entry!.funding_txid).to.equal(displayTxid);
		console.log(
			`    auto-funded v2 open: channel ${
				entry!.channel_id
			} funding ${displayTxid}`
		);
	});
});
