/**
 * Interop: CLN bumps a v2 (dual-funded) open with a CHANGED amount (issue #376).
 *
 * CLN's `openchannel_bump` takes an amount argument, and BOLT 2 explicitly
 * allows a different funding_output_contribution per RBF attempt ("it may be
 * different from the contribution made in the previously completed
 * transaction"). Beignet used to refuse any change attempt-scoped, so a CLN
 * peer bumping with a different amount kept the original attempt instead of
 * completing the bump. This drives the real thing: CLN opens to beignet, then
 * bumps with a larger amount, and beignet must renegotiate to a replacement at
 * the NEW capacity and settle to NORMAL on it.
 *
 * Requires the `cln` container with --experimental-dual-fund. Auto-skips when
 * CLN is unreachable or does not advertise option_dual_fund.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	waitForClnPeerChannelNormal,
	fundClnWallet,
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
import { ChannelState } from '../../../src/lightning/channel/types';
import { Channel } from '../../../src/lightning/channel/channel';

bitcoin.initEccLib(ecc);

/** The v2 open CLN starts, and the amount it bumps to. */
const OPEN_AMOUNT = 200_000;
const BUMPED_AMOUNT = 260_000;
/** Comfortably clear of CLN's own floor and of beignet's 25/24 RBF floor. */
const OPEN_FEERATE_PERKW = 2000;
const BUMP_FEERATE_PERKW = 4000;

function createDualFundNode(seedId: string): LightningNode {
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		seedId,
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

async function waitFor<T>(
	fn: () => T | null,
	timeoutMs: number,
	label: string
): Promise<T> {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const value = fn();
		if (value !== null && value !== undefined) return value;
		if (Date.now() > deadline)
			throw new Error(`timed out waiting for ${label}`);
		await sleep(300);
	}
}

describe('Interop: CLN v2 open RBF with a changed amount (regtest)', function () {
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
		// CLN funds BOTH attempts from its own wallet, and the bump reserves a
		// fresh set of UTXOs on top of the first attempt's.
		await fundClnWallet(cln, 1.0);
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

	it('completes a bump that changes the funding contribution, and settles NORMAL on it', async function () {
		if (skipAll) this.skip();

		node = createDualFundNode('interop-seed-cln-rbf-376-1');
		node.on('node:error', (e: { code?: string; message?: string }) => {
			console.log(`    [node:error] ${e.code}: ${e.message}`);
		});
		const tip = (await bitcoinRpc('getblockcount', [])) as number;
		node.handleNewBlock(tip);
		// Beignet dials CLN; CLN then opens back over the same connection.
		await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await sleep(1500);

		// ── CLN opens a v2 channel to us ──
		const funded = await cln.fundPsbt(
			OPEN_AMOUNT + 20_000,
			`${OPEN_FEERATE_PERKW}perkw`
		);
		const opened = await cln.openChannelInit(
			node.getNodeId(),
			OPEN_AMOUNT,
			funded.psbt,
			{ feeratePerKw: OPEN_FEERATE_PERKW }
		);
		const channelId = opened.channel_id;
		let psbt = opened.psbt;
		let secured = opened.commitments_secured;
		for (let i = 0; i < 12 && !secured; i++) {
			const step = await cln.openChannelUpdate(channelId, psbt);
			psbt = step.psbt;
			secured = step.commitments_secured;
			if (!secured) await sleep(400);
		}
		expect(secured, 'CLN secured commitments for attempt 0').to.equal(true);
		const signed = await cln.signPsbt(psbt);
		const attempt0 = await cln.openChannelSigned(channelId, signed.signed_psbt);
		expect(attempt0.txid, 'attempt 0 was signed and broadcast').to.exist;
		console.log(`    attempt 0 funding tx ${attempt0.txid}`);

		const channel: Channel = await waitFor(
			() => {
				const chans = node!.getChannelManager().listChannels();
				return chans.length > 0 ? chans[0] : null;
			},
			30_000,
			'the v2 channel on our side'
		);
		await waitFor(
			() =>
				channel.getFullState().v2InFlight?.fullySigned === true ? true : null,
			30_000,
			'our record of attempt 0'
		);
		const attempt0Capacity = channel.getFullState().fundingSatoshis;
		const attempt0Remote =
			channel.getFullState().v2InFlight!.remoteContributionSats;
		expect(Number(attempt0Remote)).to.equal(OPEN_AMOUNT);

		// ── CLN bumps with a DIFFERENT amount ──
		// Funded from attempt 0's own inputs, so the replacement double-spends
		// it as BOLT 2 requires (and they are reserved for that attempt, hence
		// utxopsbt with reservedok).
		const attempt0Tx = bitcoin.Transaction.fromHex(attempt0.tx);
		const attempt0Utxos = attempt0Tx.ins.map(
			(i) => `${Buffer.from(i.hash).reverse().toString('hex')}:${i.index}`
		);
		const bumpFunded = await cln.utxoPsbt(
			BUMPED_AMOUNT + 20_000,
			`${BUMP_FEERATE_PERKW}perkw`,
			attempt0Utxos
		);
		const bumped = await cln.openChannelBump(
			channelId,
			BUMPED_AMOUNT,
			bumpFunded.psbt,
			{ feeratePerKw: BUMP_FEERATE_PERKW }
		);
		let bumpPsbt = bumped.psbt;
		let bumpSecured = bumped.commitments_secured;
		for (let i = 0; i < 12 && !bumpSecured; i++) {
			const step = await cln.openChannelUpdate(channelId, bumpPsbt);
			bumpPsbt = step.psbt;
			bumpSecured = step.commitments_secured;
			if (!bumpSecured) await sleep(400);
		}
		expect(
			bumpSecured,
			'the changed-amount bump was NOT refused: commitments secured'
		).to.equal(true);
		const bumpSignedPsbt = await cln.signPsbt(bumpPsbt);
		const attempt1 = await cln.openChannelSigned(
			channelId,
			bumpSignedPsbt.signed_psbt
		);
		expect(attempt1.txid, 'the replacement was signed and broadcast').to.exist;
		expect(attempt1.txid).to.not.equal(attempt0.txid);
		console.log(`    replacement funding tx ${attempt1.txid}`);

		// ── Our side renegotiated to the new amount ──
		await waitFor(
			() =>
				channel.getFullState().v2InFlight?.rbfAttempt === 1 &&
				channel.getFullState().v2InFlight?.fullySigned === true
					? true
					: null,
			30_000,
			'our record of the replacement'
		);
		const after = channel.getFullState();
		expect(
			Number(after.v2InFlight!.remoteContributionSats),
			"the peer's changed contribution was adopted"
		).to.equal(BUMPED_AMOUNT);
		expect(Number(after.fundingSatoshis)).to.equal(
			Number(attempt0Capacity) + (BUMPED_AMOUNT - OPEN_AMOUNT)
		);
		expect(Number(after.remoteBalanceMsat)).to.equal(BUMPED_AMOUNT * 1000);
		// The superseded attempt is retained with ITS own amounts.
		expect(after.v2PreviousAttempts).to.have.length(1);
		expect(Number(after.v2PreviousAttempts![0].fundingSatoshis!)).to.equal(
			Number(attempt0Capacity)
		);

		// ── Confirm the replacement; both sides reach NORMAL on it ──
		await mineBlocks(6);
		const tip2 = (await bitcoinRpc('getblockcount', [])) as number;
		node.handleNewBlock(tip2);
		node.handleFundingConfirmed(channel.getChannelId()!, attempt1.txid);
		await waitForClnPeerChannelNormal(cln, node.getNodeId(), 60_000);
		await waitFor(
			() => (channel.getState() === ChannelState.NORMAL ? true : null),
			30_000,
			'our channel to reach NORMAL'
		);
		const settled = channel.getFullState();
		expect(Number(settled.fundingSatoshis)).to.equal(
			Number(attempt0Capacity) + (BUMPED_AMOUNT - OPEN_AMOUNT)
		);
		expect(settled.v2PreviousAttempts ?? []).to.have.length(0);
		console.log(
			`    RBF WITH CHANGED AMOUNT COMPLETED: ${OPEN_AMOUNT} -> ` +
				`${BUMPED_AMOUNT}, capacity ${settled.fundingSatoshis}`
		);
	});
});
