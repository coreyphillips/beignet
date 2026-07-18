/**
 * Interop: bLIP-0051 liquidity ads — beignet is the SELLER (lessor) vs live
 * CLN (regtest).
 *
 * CLN buys inbound liquidity with `fundchannel ... request_amt compact_lease`:
 * beignet answers open_channel2's request_funds with a signed will_fund at its
 * configured leaseRates, FUNDS its contribution from the wallet (the new
 * acceptor-side dual-funding contribution: auto tx_add_input/change, auto
 * tx_signatures via the wallet closures), and the leased channel opens NORMAL
 * on both sides with beignet recorded as the lessor.
 *
 * Then blocks are mined so CLN (the opener) sends update_blockheight: beignet
 * runs the two-phase height round and the channel STAYS NORMAL with
 * leaseCommitBlockheight advanced — the live validation of the
 * update_blockheight machine.
 *
 * Requires the `cln` container with --experimental-dual-fund; auto-skips
 * otherwise.
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
	fundClnWallet,
	waitFor,
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
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
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
import {
	ILeaseRates,
	encodeLeaseRates
} from '../../../src/lightning/gossip/types';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';

bitcoin.initEccLib(ecc);

/** Our lessor terms; CLN's compact_lease must match what we sign. */
const RATES: ILeaseRates = {
	fundingWeightWitness: 666,
	leaseFeeBasis: 50, // 0.50%
	leaseFeeBaseSat: 2,
	channelFeeMaxBaseMsat: 100_000,
	channelFeeMaxProportionalThousandths: 2
};

const CLN_FUNDING = 400_000; // CLN's own contribution
const REQUEST_AMT = 100_000; // the lease CLN buys from us
const WALLET_UTXO_SATS = 200_000; // our on-chain UTXO funding the lease

/** CLN compact_lease: hex of the wire lease_rates (tu32 base msat) — the
 * exact subtype layout beignet's encodeLeaseRates emits (validated vs CLN in
 * the wire-format work). */
function compactLease(r: ILeaseRates): string {
	return encodeLeaseRates(r).toString('hex');
}

describe('Interop: beignet SELLS a lease to CLN (option_will_fund seller + update_blockheight)', function () {
	this.timeout(300_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let skipAll = false;
	let node: LightningNode | undefined;

	before(async function () {
		this.timeout(120_000);
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
		// The BUYER needs confirmed on-chain funds for its own contribution.
		await fundClnWallet(cln);
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

	it('funds and opens the leased channel NORMAL, then survives update_blockheight rounds', async function () {
		if (skipAll) this.skip();

		// ── A REAL confirmed P2WPKH wallet UTXO for our lease contribution ──
		const walletPriv = crypto
			.createHash('sha256')
			.update(Buffer.from('lease-seller-wallet-key'))
			.digest();
		const walletPub = getPublicKey(walletPriv);
		const walletPayment = bitcoin.payments.p2wpkh({
			pubkey: walletPub,
			network: bitcoin.networks.regtest
		});
		const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
		const fundTxid = (await bitcoinRpc('sendtoaddress', [
			walletPayment.address!,
			WALLET_UTXO_SATS / 1e8
		])) as string;
		await mineBlocks(1);
		const prevTxHex = (await bitcoinRpc('getrawtransaction', [
			fundTxid
		])) as string;
		const prevTx = bitcoin.Transaction.fromHex(prevTxHex);
		const prevVout = prevTx.outs.findIndex((o) =>
			o.script.equals(walletPayment.output!)
		);
		expect(prevVout).to.be.gte(0);

		const walletInput: ISpliceWalletInput = {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: prevVout,
			value: BigInt(WALLET_UTXO_SATS),
			sequence: 0xfffffffd,
			confirmed: true,
			signWitness: (tx, inputIndex, value) => {
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
		};
		const changeScript = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20),
			network: bitcoin.networks.regtest
		}).output!;

		const fundingProvider: IFundingProvider = {
			buildFundingTransaction: async () => {
				throw new Error('not used in this test');
			},
			broadcastTransaction: async (txHex: string) => {
				try {
					return (await bitcoinRpc('sendrawtransaction', [txHex])) as string;
				} catch {
					// The opener (CLN) usually broadcasts first; a duplicate is fine.
					return bitcoin.Transaction.fromHex(txHex).getId();
				}
			},
			selectSpliceInputs: async () => ({
				inputs: [walletInput],
				changeScript
			})
		};

		// ── The seller node: leaseRates configured (advertises
		//    option_will_fund) + the wallet-backed funding provider ──
		const keys = deriveLightningKeysFromMnemonic(
			TEST_MNEMONIC,
			'interop-seed-270',
			LnCoinType.REGTEST
		);
		const features = FeatureFlags.empty();
		features.setOptional(Feature.DATA_LOSS_PROTECT);
		features.setOptional(Feature.STATIC_REMOTE_KEY);
		features.setOptional(Feature.PAYMENT_SECRET);
		features.setOptional(Feature.TLV_ONION);
		features.setOptional(Feature.CHANNEL_TYPE);
		features.setOptional(Feature.GOSSIP_QUERIES);
		features.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
		features.setOptional(Feature.DUAL_FUND);

		node = new LightningNode({
			nodePrivateKey: keys.nodePrivateKey,
			channelBasepoints: keys.channelBasepoints,
			perCommitmentSeed: keys.perCommitmentSeed,
			fundingPrivkey: keys.fundingPrivkey,
			htlcBasepointSecret: keys.htlcBasepointSecret,
			network: Network.REGTEST,
			enableNetworking: true,
			localFeatures: features,
			chainHashes: [REGTEST_CHAIN_HASH],
			preferAnchors: true,
			leaseRates: RATES,
			fundingProvider
		});
		node.on('node:error', (e: { code?: string; message?: string }) => {
			console.log(`    [node:error] ${e.code}: ${e.message}`);
		});
		const tip = (await bitcoinRpc('getblockcount', [])) as number;
		node.handleNewBlock(tip);
		await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await sleep(1500);

		// ── CLN BUYS the lease (v2 open with request_amt + our compact_lease) ──
		const fundRes = (await cln.fundChannelLease(
			node.getNodeId(),
			CLN_FUNDING,
			REQUEST_AMT,
			compactLease(RATES)
		)) as unknown as { txid?: string; channel_id?: string };
		expect(fundRes.txid, 'CLN negotiated + broadcast the funding tx').to.exist;
		console.log(`    leased funding tx ${fundRes.txid}`);

		// The lease channel exists on our side with the lessor bookkeeping.
		const channel = (await waitFor(() => {
			const chans = node!.getChannelManager().listChannels();
			return chans.length > 0 ? chans[0] : null;
		}, 30_000))!;
		expect(channel, 'lease channel created').to.exist;
		const state = channel.getFullState();
		expect(state.isLessor, 'we are the lessor').to.equal(true);
		expect(state.leaseExpiry, 'lease expiry recorded').to.be.a('number');
		expect(state.leaseCommitBlockheight, 'agreed blockheight recorded').to.be.a(
			'number'
		);
		const openHeight = state.leaseCommitBlockheight!;

		// ── Confirm + reach NORMAL on both sides ──
		await mineBlocks(6);
		const tip2 = (await bitcoinRpc('getblockcount', [])) as number;
		node.handleNewBlock(tip2);
		const channelId = channel.getChannelId();
		expect(channelId, 'channel promoted').to.exist;
		node.handleFundingConfirmed(channelId!);
		await waitForClnPeerChannelNormal(cln, node.getNodeId(), 60_000);
		await waitFor(
			() => (channel.getState() === ChannelState.NORMAL ? true : null),
			30_000
		);
		console.log(
			`    LEASED CHANNEL OPEN (beignet lessor): CLN ${CLN_FUNDING} + ` +
				`our lease ${REQUEST_AMT}, capacity ${state.fundingSatoshis}, ` +
				`lease_expiry ${state.leaseExpiry}`
		);
		expect(Number(state.fundingSatoshis)).to.be.gte(CLN_FUNDING + REQUEST_AMT);

		// ── update_blockheight: mine blocks; CLN (opener) advances the agreed
		//    height; our two-phase machine must keep the channel NORMAL. ──
		await mineBlocks(3);
		const tip3 = (await bitcoinRpc('getblockcount', [])) as number;
		node.handleNewBlock(tip3);
		const advanced = (await waitFor(() => {
			const h = channel.getFullState().leaseCommitBlockheight;
			return h !== undefined && h > openHeight ? h : null;
		}, 90_000))!;
		console.log(
			`    update_blockheight LIVE: agreed height ${openHeight} -> ${advanced}`
		);
		expect(advanced).to.be.greaterThan(openHeight);
		expect(
			channel.getState(),
			'channel NORMAL after the height round'
		).to.equal(ChannelState.NORMAL);

		// A second round keeps working too.
		await mineBlocks(3);
		const tip4 = (await bitcoinRpc('getblockcount', [])) as number;
		node.handleNewBlock(tip4);
		const advanced2 = (await waitFor(() => {
			const h = channel.getFullState().leaseCommitBlockheight;
			return h !== undefined && h > advanced ? h : null;
		}, 90_000))!;
		expect(advanced2).to.be.greaterThan(advanced);
		expect(channel.getState()).to.equal(ChannelState.NORMAL);

		// CLN still lists the channel healthy.
		const { channels } = await cln.listChannels();
		const entry = (channels || []).find(
			(c) => c.peer_id === node!.getNodeId() && c.state === 'CHANNELD_NORMAL'
		);
		expect(entry, 'CLN lists the leased channel NORMAL').to.exist;
		console.log(
			'    SELLER-SIDE LEASE + update_blockheight VALIDATED vs live CLN'
		);
	});
});
