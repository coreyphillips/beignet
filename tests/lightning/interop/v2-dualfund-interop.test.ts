/**
 * Interop: BOLT 2 v2 (dual-funded) channel establishment vs live CLN.
 *
 * Validates the spec-correct v2 channel_id derivation live for the first
 * time: temporary_channel_id = SHA256(zeros33 || opener_revocation_basepoint)
 * and channel_id = SHA256(lesser_revocation_basepoint || greater), plus the
 * whole open_channel2 -> accept_channel2 -> interactive-tx -> commitment ->
 * tx_signatures flow, ending with a REAL on-chain funding tx confirming and
 * BOTH implementations reporting the SAME channel_id with the channel usable
 * (CLN reaches CHANNELD_NORMAL).
 *
 * Requires the `cln` container with --experimental-dual-fund. Auto-skips
 * when CLN is unreachable or does not advertise option_dual_fund.
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
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { REGTEST_CHAIN_HASH } from '../../../src/lightning/channel/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import { createFundingScript } from '../../../src/lightning/script/funding';
import { buildSpliceTx } from '../../../src/lightning/channel/splice-tx';
import { ChannelState } from '../../../src/lightning/channel/types';

bitcoin.initEccLib(ecc);

/**
 * Like createInteropNode, plus option_dual_fund. Deliberately NOT added to
 * the shared helper: once both peers advertise it, CLN switches its own
 * fundchannel to v2 opens, changing the behavior of every other CLN tier.
 */
function createDualFundNode(seedId: number): LightningNode {
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

describe('Interop: v2 dual-funded open vs CLN (regtest)', function () {
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
		// option_dual_fund = bit 28/29 of the init features.
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

	it('beignet opens a v2 channel to CLN; channel_ids MATCH and CLN reaches NORMAL', async function () {
		if (skipAll) this.skip();

		node = createDualFundNode(230);
		node.on('node:error', (e: { code?: string; message?: string }) => {
			console.log(`    [node:error] ${e.code}: ${e.message}`);
		});
		await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await sleep(1500);

		// A REAL wallet UTXO we control, to contribute as the opener.
		const walletPriv = crypto
			.createHash('sha256')
			.update(Buffer.from('v2-dualfund-wallet'))
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

		// ── open_channel2 / accept_channel2 ──
		const FUNDING = 500_000n;
		const FEERATE_FUNDING = 1000;
		const channel = node.openChannelV2(clnPubkey, {
			fundingSatoshis: FUNDING,
			fundingFeeratePerkw: FEERATE_FUNDING,
			commitmentFeeratePerkw: 253
		});

		// Wait for CLN's accept_channel2 (remote basepoints land on the state).
		const acceptDeadline = Date.now() + 20_000;
		while (Date.now() < acceptDeadline) {
			if (channel.getFullState().remoteBasepoints) break;
			await sleep(300);
		}
		const state = channel.getFullState();
		expect(state.remoteBasepoints, 'CLN sent accept_channel2').to.exist;

		// The BOLT 2 v2 channel_id: SHA256(lesser_rev || greater_rev).
		const ourRev = state.localBasepoints.revocationBasepoint;
		const theirRev = state.remoteBasepoints!.revocationBasepoint;
		const [lesser, greater] =
			Buffer.compare(ourRev, theirRev) < 0
				? [ourRev, theirRev]
				: [theirRev, ourRev];
		const expectedChannelId = crypto
			.createHash('sha256')
			.update(Buffer.concat([lesser, greater]))
			.digest();

		// ── interactive-tx: our wallet input, the funding output, our change ──
		const funding = createFundingScript(
			state.localBasepoints.fundingPubkey,
			state.remoteBasepoints!.fundingPubkey
		);
		// Opener pays for its own inputs/outputs plus the common fields; a
		// conservative flat fee comfortably above CLN's minimum check.
		const FEE = 800n;
		const change = BigInt(utxoValue) - FUNDING - FEE;

		// The interactive tx is TURN-BASED: the peer answers every tx_add_* with
		// its own message (tx_complete when it has nothing to add), and our next
		// contribution is our reply to THAT. Give each round trip a beat.
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
				amountSats: FUNDING,
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

		// CLN replies tx_complete -> the v2 commitment round runs automatically;
		// wait for the negotiated funding outpoint to land on the state.
		const sigDeadline = Date.now() + 30_000;
		while (Date.now() < sigDeadline) {
			if (channel.getFullState().fundingTxid) break;
			await sleep(300);
		}
		const negotiated = channel.getFullState();
		expect(negotiated.fundingTxid, 'funding outpoint negotiated').to.exist;

		// Sign OUR wallet input over the negotiated tx and release tx_signatures
		// (CLN contributed no inputs, so it signs first; ours are held until its
		// tx_signatures arrive, then flushed automatically).
		const session = channel.getDualFundingSession()!;
		const built = session.buildTransaction()!;
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
		expect(ourIndex, 'our wallet input present in the funding tx').to.be.gte(0);
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
		const sigActions = channel.sendTxSignatures(
			negotiated.fundingTxid!,
			negotiated.fundingOutputIndex,
			[[der, walletPub]]
		);
		node.getChannelManager()['processActions'](clnPubkey, channel, sigActions);

		// Wait for the fully-signed funding tx to be broadcastable: CLN sends its
		// (empty) tx_signatures, ours flush, and the funding tx reaches bitcoind.
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
			// CLN may leave broadcast to the opener (the only contributor): apply
			// our witness and submit the tx ourselves.
			tx.setWitness(ourIndex, [der, walletPub]);
			await bitcoinRpc('sendrawtransaction', [tx.toHex()]);
		}
		await mineBlocks(6);
		await sleep(2000);

		// ── channel_ready both ways -> NORMAL, with MATCHING channel_ids ──
		const channelId = channel.getChannelId();
		expect(channelId, 'channel promoted with the derived channel_id').to.exist;
		expect(
			channelId!.equals(expectedChannelId),
			'beignet channel_id equals SHA256(lesser_rev || greater_rev)'
		).to.equal(true);

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

		// CLN reports the SAME channel_id — the PR #6 derivation interops.
		const { channels } = await cln.listChannels();
		const entry = (channels || []).find(
			(c) => c.peer_id === node!.getNodeId() && c.state === 'CHANNELD_NORMAL'
		);
		expect(entry, 'CLN lists the channel NORMAL').to.exist;
		expect(entry!.channel_id).to.equal(channelId!.toString('hex'));
		expect(entry!.funding_txid).to.equal(displayTxid);
		console.log(
			`    v2 channel open: channel_id ${
				entry!.channel_id
			} funding ${displayTxid}`
		);
	});
});
