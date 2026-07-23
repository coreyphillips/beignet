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
	payClnInvoiceStrict,
	payBeignetInvoiceStrict,
	waitFor,
	CLN_P2P_HOST,
	CLN_P2P_PORT,
	sleep
} from './cln-helpers';
import {
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	ensureBitcoindFunds,
	setupRoutingForChannel
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
		this.timeout(600_000);

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
			`interop-seed-270-${Date.now() % 100000}`,
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
			// The on-chain claim of our static-remotekey (lease-locked) to_remote
			// signs with the PAYMENT basepoint secret; the sweep is consensus-
			// invalid without it.
			paymentBasepointSecret: keys.paymentBasepointSecret,
			revocationBasepointSecret: keys.revocationBasepointSecret,
			delayedPaymentBasepointSecret: keys.delayedPaymentBasepointSecret,
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

		// ── Payments over the leased channel, both directions ──
		setupRoutingForChannel(node, clnPubkey);
		await sleep(2000);
		await payClnInvoiceStrict(node, cln, 20_000_000, 'lessor-pays-buyer');
		await payBeignetInvoiceStrict(node, cln, 15_000_000, 'buyer-pays-lessor');
		expect(
			channel.getState(),
			'channel NORMAL after payments both ways'
		).to.equal(ChannelState.NORMAL);
		console.log('    payments over the leased channel OK (20k out, 15k in)');

		// ── CLN force-closes: our whole lessor balance sits in the
		//    LEASE-LOCKED to_remote (pure CSV). Sweep it after maturity —
		//    the consensus-level validation of the CLN lease scripts. ──
		const broadcasts: Buffer[] = [];
		node.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
		const st = channel.getFullState();
		const fundingTxidInternal = st.fundingTxid!;
		const fundingVout = st.fundingOutputIndex;
		const leaseCsvNow = st.leaseExpiry! - st.leaseCommitBlockheight!;
		// beignet does not advertise option_shutdown_anysegwit, so give CLN an
		// explicit v0 destination or its close RPC refuses its default (v1) addr.
		const clnDest = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20),
			network: bitcoin.networks.regtest
		}).address!;
		await cln.closeChannel(node.getNodeId(), {
			unilateraltimeout: 1,
			destination: clnDest
		});
		const closingHex = (await waitFor(async () => {
			const mem = (await bitcoinRpc('getrawmempool', [])) as string[];
			for (const txid of mem) {
				const hex = (await bitcoinRpc('getrawtransaction', [txid])) as string;
				const t = bitcoin.Transaction.fromHex(hex);
				if (
					t.ins.some(
						(i) =>
							Buffer.from(i.hash).equals(fundingTxidInternal) &&
							i.index === fundingVout
					)
				) {
					return hex;
				}
			}
			return null;
		}, 60_000))!;
		const closingTx = bitcoin.Transaction.fromHex(closingHex);
		await mineBlocks(1);
		const confHeight = (await bitcoinRpc('getblockcount', [])) as number;
		const destScript = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20),
			network: bitcoin.networks.regtest
		}).output!;
		node
			.getChannelManager()
			.handleFundingSpent(channelId!, closingTx, confHeight, destScript);

		// The claim is HELD until the lease CSV matures (BIP68). Mine past it
		// and release.
		console.log(`    mining ${leaseCsvNow + 1} blocks to mature the lease CSV`);
		await mineBlocks(leaseCsvNow + 1);
		const tipFinal = (await bitcoinRpc('getblockcount', [])) as number;
		const before = broadcasts.length;
		node.handleNewBlock(tipFinal);
		await sleep(3000);
		const closingHash = Buffer.from(closingTx.getHash());
		const sweep = broadcasts
			.slice(before)
			.map((b) => bitcoin.Transaction.fromBuffer(b))
			.find((t) => t.ins.some((i) => Buffer.from(i.hash).equals(closingHash)));
		expect(
			sweep,
			'lease-locked to_remote sweep broadcast after CSV maturity'
		).to.not.equal(undefined);
		// CLN pure-CSV lease: input nSequence = remaining lease, NO nLockTime.
		const swIn = sweep!.ins.find((i) =>
			Buffer.from(i.hash).equals(closingHash)
		)!;
		expect(swIn.sequence, 'sweep sequence = remaining lease CSV').to.equal(
			leaseCsvNow
		);
		expect(sweep!.locktime).to.equal(0);
		expect(Buffer.from(sweep!.outs[0].script).equals(destScript)).to.be.true;

		// Consensus-valid on a REAL node: accepted + confirmed.
		try {
			await bitcoinRpc('sendrawtransaction', [sweep!.toHex()]);
		} catch (e) {
			const msg = (e as Error).message || '';
			if (!/already/i.test(msg)) throw e;
		}
		await mineBlocks(1);
		const swConf = (await bitcoinRpc('getrawtransaction', [
			sweep!.getId(),
			true
		])) as { confirmations?: number };
		expect(
			swConf.confirmations ?? 0,
			'lease sweep CONFIRMED on-chain'
		).to.be.gte(1);
		// The lessor balance came home: 100k lease + 673 fee - 20k + 15k
		// payments, minus the sweep fee.
		expect(sweep!.outs[0].value).to.be.greaterThan(90_000);
		console.log(
			`    LEASE-LOCKED to_remote SWEPT + CONFIRMED on-chain ` +
				`(${sweep!.outs[0].value} sat, CSV ${leaseCsvNow}) — ` +
				`lease scripts consensus-validated`
		);
	});
});
