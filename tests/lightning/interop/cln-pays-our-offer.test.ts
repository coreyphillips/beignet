/**
 * Interop: a live CLN pays OUR BOLT 12 offer while we have NO announced
 * channels (issue #544, LFBW port #532 workstream 1D).
 *
 * This is the production LFBW shape end to end against a real payer: the
 * offer of an unannounced node must carry blinded MESSAGE paths (or no
 * external payer can deliver an invoice_request at all), and the issued
 * invoice must carry a BOLT 4-exact blinded PAYMENT path through the peer.
 * CLN plays payer AND introduction node: it delivers the invoice_request
 * over our message path, validates the payment path it gets back (exactly
 * one identifier per hop, honest payinfo, sane constraints), relays into
 * the blinded hop and settles. A single wrong TLV anywhere fails the run.
 *
 * Requires the `cln` container; auto-skips otherwise.
 */

import { expect } from 'chai';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	waitForClnPeerChannelNormal,
	waitFor,
	sleep,
	CLN_P2P_HOST,
	CLN_P2P_PORT
} from './cln-helpers';
import { mineBlocks, bitcoinRpc, TEST_MNEMONIC } from './shared-helpers';
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

describe('Interop: CLN pays our offer (unannounced node)', function () {
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
		const info = (await cln.getInfo()) as unknown as { id: string };
		clnPubkey = info.id;
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

	it('fetches the invoice over our blinded message path and pays the blinded payment path', async function () {
		if (skipAll) this.skip();

		const keys = deriveLightningKeysFromMnemonic(
			TEST_MNEMONIC,
			`cln-pays-offer-${Date.now() % 100000}`,
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
		features.setOptional(Feature.ONION_MESSAGES);
		features.setOptional(Feature.ROUTE_BLINDING);

		node = new LightningNode({
			nodePrivateKey: keys.nodePrivateKey,
			channelBasepoints: keys.channelBasepoints,
			perCommitmentSeed: keys.perCommitmentSeed,
			fundingPrivkey: keys.fundingPrivkey,
			htlcBasepointSecret: keys.htlcBasepointSecret,
			paymentBasepointSecret: keys.paymentBasepointSecret,
			revocationBasepointSecret: keys.revocationBasepointSecret,
			delayedPaymentBasepointSecret: keys.delayedPaymentBasepointSecret,
			network: Network.REGTEST,
			enableNetworking: true,
			localFeatures: features,
			chainHashes: [REGTEST_CHAIN_HASH],
			preferAnchors: true
		});
		node.on('node:error', (e: { code?: string; message?: string }) => {
			console.log(`    [node:error] ${e.code}: ${e.message}`);
		});
		const tip0 = (await bitcoinRpc('getblockcount', [])) as number;
		node.handleNewBlock(tip0);
		await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await sleep(1500);

		// CLN funds an UNANNOUNCED channel toward us: CLN holds the outbound
		// liquidity (it is the payer) and announce:false keeps the channel out
		// of gossip at any depth, so our reachability gate stays on the
		// private branch, exactly the LFBW wallet shape.
		const fund = (await cln.fundChannel(
			node.getNodeId(),
			1_000_000,
			undefined,
			false
		)) as unknown as { txid?: string };
		expect(fund.txid, 'CLN funded the channel').to.exist;
		await mineBlocks(6);
		const tip1 = (await bitcoinRpc('getblockcount', [])) as number;
		node.handleNewBlock(tip1);

		const channel = (await waitFor(() => {
			const chans = node!.getChannelManager().listChannels();
			return chans.length > 0 ? chans[0] : null;
		}, 30_000))!;
		const channelId = channel.getChannelId();
		expect(channelId, 'channel id known').to.exist;
		node.handleFundingConfirmed(channelId!);
		await waitForClnPeerChannelNormal(cln, node.getNodeId(), 90_000);
		await waitFor(
			() => (channel.getState() === ChannelState.NORMAL ? true : null),
			30_000
		);

		// Our offer: an unannounced node MUST auto-build blinded message paths
		// with the peer (CLN) as introduction, or CLN cannot deliver the
		// invoice_request at all.
		const amountMsat = 25_000_000n;
		const { offer, encoded } = node.createOffer({
			description: 'lfbw private wallet offer',
			amount: amountMsat
		});
		expect(offer.paths, 'offer carries blinded message paths').to.have.length(
			1
		);
		expect(offer.paths![0].introductionNodeId).to.deep.equal(
			Buffer.from(clnPubkey, 'hex')
		);
		console.log(`    offer minted: intro=${clnPubkey.slice(0, 16)}...`);

		const settled: Buffer[] = [];
		node.on('invoice:settled', (...args: unknown[]) => {
			settled.push(args[0] as Buffer);
		});

		// CLN fetches the invoice: the invoice_request travels over our
		// blinded MESSAGE path (intro = CLN itself), our node answers over
		// CLN's reply path, and CLN validates the returned PAYMENT path.
		const fetched = (await cln.fetchInvoice(encoded)) as unknown as {
			invoice?: string;
		};
		expect(fetched.invoice, 'CLN fetched our BOLT 12 invoice').to.exist;
		console.log('    invoice fetched over the blinded message path');

		// CLN pays it: relays into the blinded payment path (itself as the
		// introduction) and our node settles. This is the consensus-level
		// verdict on the whole 1D shape.
		const paid = (await cln.pay(fetched.invoice!)) as unknown as {
			status?: string;
			payment_preimage?: string;
		};
		expect(paid.status, 'CLN payment complete').to.equal('complete');
		expect(paid.payment_preimage, 'preimage revealed').to.exist;
		await waitFor(() => (settled.length > 0 ? true : null), 20_000);
		console.log(
			`    CLN PAID OUR UNANNOUNCED OFFER: ${amountMsat} msat settled`
		);
	});
});
