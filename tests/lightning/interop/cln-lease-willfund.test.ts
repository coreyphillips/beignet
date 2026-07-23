/**
 * Interop: bLIP-0051 liquidity ads (option_will_fund) vs live CLN (regtest).
 *
 * beignet is the BUYER (lessee): it opens a v2 channel with request_funds and
 * validates CLN's signed will_fund reply — the byte-exact lease_rates layout
 * and will_fund sighash implemented from CLN's own source in the wire-format
 * fixes, verified here against a real CLN lessor for the first time. CLN
 * contributes the leased amount into the interactive tx; the channel opens
 * with the lease fee moved to the seller and lease_expiry recorded.
 *
 * Requires the `cln` container with --experimental-dual-fund; auto-skips
 * otherwise. CLN is configured as a lessor via `funderupdate`.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { execSync } from 'child_process';
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
import { createFundingScript } from '../../../src/lightning/script/funding';
import { buildSpliceTx } from '../../../src/lightning/channel/splice-tx';

bitcoin.initEccLib(ecc);

const CLN_CONTAINER = process.env.CLN_CONTAINER || 'cln';

/** CLN's configured lessor terms (see before hook). */
const CLN_LEASE = {
	leaseFeeBaseMsat: 2000, // 2 sat flat
	leaseFeeBasis: 50, // 0.50%
	fundingWeight: 666,
	channelFeeMaxBaseMsat: 100_000,
	channelFeeMaxProportionalThousandths: 2
};

function createLeaseBuyerNode(seedId: number): LightningNode {
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		`interop-seed-${seedId}`,
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

	return new LightningNode({
		nodePrivateKey: keys.nodePrivateKey,
		channelBasepoints: keys.channelBasepoints,
		perCommitmentSeed: keys.perCommitmentSeed,
		fundingPrivkey: keys.fundingPrivkey,
		htlcBasepointSecret: keys.htlcBasepointSecret,
		network: Network.REGTEST,
		enableNetworking: true,
		localFeatures: features,
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true
	});
}

describe('Interop: option_will_fund lease vs CLN (regtest)', function () {
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

		// Configure CLN as a lessor: fund ONLY lease requests, matching up to
		// 100% of the opener's contribution (the funder clamps its actual
		// contribution to the requested lease amount), at the fixed terms above.
		execSync(
			`docker exec ${CLN_CONTAINER} lightning-cli --network=regtest -k funderupdate ` +
				`policy=match policy_mod=100 leases_only=true fund_probability=100 fuzz_percent=0 ` +
				`lease_fee_base_msat=${CLN_LEASE.leaseFeeBaseMsat} ` +
				`lease_fee_basis=${CLN_LEASE.leaseFeeBasis} ` +
				`funding_weight=${CLN_LEASE.fundingWeight} ` +
				`channel_fee_max_base_msat=${CLN_LEASE.channelFeeMaxBaseMsat} ` +
				`channel_fee_max_proportional_thousandths=${CLN_LEASE.channelFeeMaxProportionalThousandths}`,
			{ encoding: 'utf8' }
		);
		// The lessor needs confirmed on-chain funds to contribute.
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

	it('buys inbound liquidity: CLN will_fund verifies live, CLN contributes the lease, fee and funding accounting match', async function () {
		if (skipAll) this.skip();

		node = createLeaseBuyerNode(260);
		node.on('node:error', (e: { code?: string; message?: string }) => {
			console.log(`    [node:error] ${e.code}: ${e.message}`);
		});
		await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await sleep(1500);

		// Our wallet UTXO for the opener contribution.
		const walletPriv = crypto
			.createHash('sha256')
			.update(Buffer.from('lease-willfund-wallet'))
			.digest();
		const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
		const walletPayment = bitcoin.payments.p2wpkh({
			pubkey: walletPub,
			network: bitcoin.networks.regtest
		});
		const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
		const utxoValue = 700_000;
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

		const tipInfo = (await bitcoinRpc('getblockchaininfo')) as {
			blocks: number;
		};

		// ── open_channel2 with request_funds ──
		const FUNDING = 500_000n;
		const REQUESTED = 100_000n;
		const FEERATE_FUNDING = 1000;
		const channel = node.openChannelV2(clnPubkey, {
			fundingSatoshis: FUNDING,
			fundingFeeratePerkw: FEERATE_FUNDING,
			commitmentFeeratePerkw: 253,
			requestFunds: {
				requestedSats: REQUESTED,
				blockheight: tipInfo.blocks
			},
			// Buyer's own ceiling, comfortably above CLN's configured terms.
			maxLeaseRates: {
				fundingWeightWitness: 800,
				leaseFeeBasis: 100,
				leaseFeeBaseSat: 10,
				channelFeeMaxBaseMsat: 200_000,
				channelFeeMaxProportionalThousandths: 5
			}
		});

		// Wait for CLN's accept_channel2 (with will_fund).
		const acceptDeadline = Date.now() + 20_000;
		while (Date.now() < acceptDeadline) {
			if (channel.getFullState().remoteBasepoints) break;
			await sleep(300);
		}
		const state = channel.getFullState();
		expect(state.remoteBasepoints, 'CLN sent accept_channel2').to.exist;

		// The lease was validated and priced: handleAcceptChannel2 verified the
		// signed will_fund (byte-exact sighash), bounded the fee by our ceiling,
		// moved it to the seller and stamped lease_expiry.
		expect(state.leaseExpiry, 'lease_expiry recorded on the buyer').to.be.a(
			'number'
		);
		expect(state.leaseExpiry! > tipInfo.blocks).to.equal(true);
		// CLN lease accounting (validated live): the fee rides in the FUNDING
		// TX, the seller's channel balance is credited fee + contribution, and
		// our balance stays intact.
		const leaseFee = state.leaseFeeSats!;
		expect(leaseFee > 0n, 'lease fee computed').to.equal(true);
		// base 2 + 0.5% of 100k (500) + 666 weight at 1000 sat/kw = 1168 sat.
		expect(leaseFee).to.equal(1168n);
		expect(state.localBalanceMsat, 'our balance undebited').to.equal(
			FUNDING * 1000n
		);

		const session = channel.getDualFundingSession()!;
		const sellerSats = session.getRemoteFundingSatoshis();
		expect(
			sellerSats >= REQUESTED,
			`CLN contributed at least the requested lease (${sellerSats})`
		).to.equal(true);

		// ── interactive tx: our input, the TOTAL funding output, our change ──
		const funding = createFundingScript(
			state.localBasepoints.fundingPubkey,
			state.remoteBasepoints!.fundingPubkey
		);
		const FEE = 900n;
		// The funding output totals BOTH contributions PLUS the lease fee (paid
		// by us through the funding tx).
		const totalFunding = FUNDING + sellerSats + leaseFee;
		const change = BigInt(utxoValue) - FUNDING - leaseFee - FEE;

		const send = (actions: ReturnType<typeof channel.sendTxComplete>): void =>
			node!.getChannelManager()['processActions'](clnPubkey, channel, actions);

		send(
			channel.addTxInput({
				serialId: 0n,
				prevTxid: Buffer.from(fundTxid, 'hex').reverse(),
				prevOutputIndex: prevVout,
				sequence: 0xfffffffd,
				prevTx: prevTx.toBuffer(),
				prevTxVout: prevVout
			})
		);
		await sleep(700);
		send(
			channel.addTxOutput({
				serialId: 2n,
				amountSats: totalFunding,
				scriptPubkey: funding.p2wshOutput
			})
		);
		await sleep(700);
		send(
			channel.addTxOutput({
				serialId: 4n,
				amountSats: change,
				scriptPubkey: walletPayment.output!
			})
		);
		await sleep(700);
		send(channel.sendTxComplete());

		// CLN adds its lease input(s)/change, replies tx_complete, and the v2
		// commitment round runs; wait for the negotiated funding outpoint.
		const sigDeadline = Date.now() + 40_000;
		while (Date.now() < sigDeadline) {
			if (channel.getFullState().fundingTxid) break;
			await sleep(300);
		}
		const negotiated = channel.getFullState();
		expect(negotiated.fundingTxid, 'funding outpoint negotiated').to.exist;
		expect(negotiated.fundingSatoshis).to.equal(totalFunding);

		// The funding tx both sides derived pays the lease-inclusive output and
		// carries CLN's lease input(s).
		const built = session.buildTransaction()!;
		const txHasClnInput = built.inputs.some((i) => i.serialId % 2n === 1n);
		expect(txHasClnInput, 'CLN contributed lease input(s)').to.equal(true);
		console.log(
			`    will_fund VERIFIED live: CLN leased ${sellerSats} sat for a ` +
				`${leaseFee} sat fee (funding output ${totalFunding} sat, ` +
				`lease_expiry ${state.leaseExpiry})`
		);

		// The mid-open commitment round already ran (via auto-routing) when
		// tx_complete completed. With the CLN pure-CSV lease scripts, CLN's
		// commitment signature over OUR leased commitment now VERIFIES — the
		// channel would have ERRORED otherwise (asserted here).
		expect(channel.getState(), 'no commitment-sig error').to.not.equal(
			ChannelState.ERRORED
		);

		// Sign our wallet input over the negotiated funding tx and release
		// tx_signatures; CLN then sends its own (its lease input witnesses).
		const tx = buildSpliceTx(
			built.inputs.map((i) => ({
				serialId: i.serialId,
				prevTxid:
					i.prevTx && i.prevTx.length >= 32
						? bitcoin.Transaction.fromBuffer(i.prevTx).getHash()
						: i.prevTxid,
				prevOutputIndex: i.prevTxVout ?? i.prevOutputIndex,
				sequence: i.sequence
			})),
			built.outputs.map((o) => ({
				serialId: o.serialId,
				script: o.scriptPubkey,
				valueSats: o.amountSats
			})),
			built.locktime
		);
		expect(
			Buffer.from(tx.getHash()).equals(negotiated.fundingTxid!),
			'locally rebuilt funding tx matches the negotiated txid'
		).to.equal(true);
		const ourIndex = tx.ins.findIndex(
			(i) =>
				Buffer.from(i.hash).equals(prevTx.getHash()) && i.index === prevVout
		);
		expect(ourIndex, 'our wallet input present').to.be.gte(0);
		const sighash = tx.hashForWitnessV0(
			ourIndex,
			scriptCode,
			utxoValue,
			bitcoin.Transaction.SIGHASH_ALL
		);
		const der = bitcoin.script.signature.encode(
			Buffer.from(ecc.sign(sighash, walletPriv)),
			bitcoin.Transaction.SIGHASH_ALL
		);
		node
			.getChannelManager()
			['processActions'](
				clnPubkey,
				channel,
				channel.sendTxSignatures(
					negotiated.fundingTxid!,
					negotiated.fundingOutputIndex,
					[[der, walletPub]]
				)
			);

		// Wait for CLN's tx_signatures, then broadcast (CLN may or may not).
		await waitFor(() => {
			const w = session.getRemoteWitnesses();
			return w && w.length > 0 ? w : null;
		}, 30_000);
		const displayTxid = Buffer.from(negotiated.fundingTxid!)
			.reverse()
			.toString('hex');
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
		if (!seen) {
			tx.setWitness(ourIndex, [der, walletPub]);
			const remoteWitnesses = session.getRemoteWitnesses() || [];
			expect(
				remoteWitnesses.length,
				'CLN tx_signatures witnesses received'
			).to.equal(tx.ins.length - 1);
			let w = 0;
			for (let idx = 0; idx < tx.ins.length; idx++) {
				if (idx === ourIndex) continue;
				tx.setWitness(idx, remoteWitnesses[w++]);
			}
			await bitcoinRpc('sendrawtransaction', [tx.toHex()]);
		}
		await mineBlocks(6);
		await sleep(2000);

		const channelId = channel.getChannelId();
		expect(channelId, 'channel promoted').to.exist;
		node.handleFundingConfirmed(channelId!);

		await waitForClnPeerChannelNormal(cln, node.getNodeId(), 60_000);
		const readyDeadline = Date.now() + 30_000;
		while (Date.now() < readyDeadline) {
			if (channel.getState() === ChannelState.NORMAL) break;
			await sleep(500);
		}
		expect(channel.getState(), 'beignet leased channel NORMAL').to.equal(
			ChannelState.NORMAL
		);

		const { channels } = await cln.listChannels();
		const entry = (channels || []).find(
			(c) => c.peer_id === node!.getNodeId() && c.state === 'CHANNELD_NORMAL'
		);
		expect(entry, 'CLN lists the leased channel NORMAL').to.exist;
		console.log(
			`    LEASED CHANNEL OPEN vs CLN: total ${totalFunding} sat ` +
				`(ours ${FUNDING} + CLN lease ${sellerSats}), fee ${leaseFee} sat, ` +
				`lease_expiry ${state.leaseExpiry} — commitment scripts CLN-verified`
		);
	});
});
