/**
 * INTEROP — an LND sender pays a wallet that has NO CHANNEL, through a JIT
 * intercept SCID hint (issue #594).
 *
 *     LND  --real channel-->  alice (beignet LSP)  ..intercept scid..>  bob
 *                                                   (channel does not exist)
 *
 * Bob registers a receive intent with alice over the beignet custom message
 * type; alice mints an intercept SCID and bob puts it in a BOLT 11 route hint.
 * LND routes to it like any other private-channel hint, alice's forwarding path
 * misses the SCID, the JIT engine holds the HTLC, opens a zero-conf channel to
 * bob with alice's own coins, forwards, and bob settles. LND's payment returns
 * a preimage for an invoice that was unpayable when it was created.
 *
 * This is the piece nothing else can prove: that a real sender accepts a hint
 * whose SCID belongs to no channel, and that the whole hold-fund-forward round
 * fits inside a live payment's timeout.
 *
 * Requires the interop stack (docker/docker-compose.yml). Auto-skips when LND
 * is unreachable, like the other interop suites.
 */

import { expect } from 'chai';
import * as net from 'net';
import crypto from 'crypto';
import { LndRestClient } from './lnd-client';
import {
	isLndAvailable,
	createLndClient,
	cleanupLndState,
	fundLndWallet,
	waitForLndChannels,
	waitForLndSync,
	LND_P2P_HOST,
	LND_P2P_PORT
} from './lnd-helpers';
import {
	BitcoindFundingProvider,
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	setupRoutingForChannel,
	sleep
} from './shared-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { REGTEST_CHAIN_HASH } from '../../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import { BeignetCustomSubtype } from '../../../src/lightning/message/custom';
import {
	IJitReceiveAck,
	decodeJitAck,
	encodeJitAuthorization
} from '../../../src/lightning/liquidity/jit-receive';
import { INodeConfig } from '../../../src/lightning/node/types';

const LND_TO_ALICE_SAT = 1_000_000;
const PAYMENT_MSAT = 20_000_000n;
/** Comfortably above the engine's 40-block minimum cushion. */
const HINT_CLTV_DELTA = 80;
/** LSPS2 opening fee the second case charges, and bob's allowance for it. */
const OPENING_FEE_SAT = 100n;

/**
 * v1-capable features: deliberately NO option_dual_fund, because the
 * bitcoind funding provider these tests use implements only the v1
 * buildFundingTransaction path, and BOLT 2 forbids a v1 open once dual
 * funding is negotiated.
 */
function jitFeatures(): FeatureFlags {
	const f = FeatureFlags.empty();
	f.setOptional(Feature.DATA_LOSS_PROTECT);
	f.setOptional(Feature.STATIC_REMOTE_KEY);
	f.setOptional(Feature.PAYMENT_SECRET);
	f.setOptional(Feature.TLV_ONION);
	f.setOptional(Feature.CHANNEL_TYPE);
	f.setOptional(Feature.GOSSIP_QUERIES);
	f.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	f.setOptional(Feature.SCID_ALIAS);
	f.setOptional(Feature.ZERO_CONF);
	return f;
}

function makeNode(
	passphrase: string,
	extra: Partial<INodeConfig> = {}
): LightningNode {
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		passphrase,
		LnCoinType.REGTEST
	);
	const node = new LightningNode({
		nodePrivateKey: keys.nodePrivateKey,
		channelBasepoints: keys.channelBasepoints,
		perCommitmentSeed: keys.perCommitmentSeed,
		fundingPrivkey: keys.fundingPrivkey,
		htlcBasepointSecret: keys.htlcBasepointSecret,
		revocationBasepointSecret: keys.revocationBasepointSecret,
		paymentBasepointSecret: keys.paymentBasepointSecret,
		delayedPaymentBasepointSecret: keys.delayedPaymentBasepointSecret,
		network: Network.REGTEST,
		enableNetworking: true,
		localFeatures: jitFeatures(),
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true,
		...extra
	});
	node.on('node:error', () => undefined);
	node.on('error', () => undefined);
	return node;
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

describe('Interop: LND pays through a JIT intercept SCID (issue #594)', function () {
	this.timeout(240_000);

	let lnd: LndRestClient;
	let lndPubkey: string;
	let skipAll = false;
	let alice: LightningNode | null = null;
	let bob: LightningNode | null = null;

	before(async function () {
		this.timeout(60_000);
		if (!(await isLndAvailable())) {
			skipAll = true;
			console.log('    [skip] LND container not reachable');
			this.skip();
			return;
		}
		const client = await createLndClient();
		if (!client) {
			skipAll = true;
			this.skip();
			return;
		}
		lnd = client;
		await waitForLndSync(lnd);
		await cleanupLndState(lnd);
		lndPubkey = (await lnd.getInfo()).identity_pubkey;
	});

	beforeEach(function () {
		if (skipAll) this.skip();
	});

	afterEach(function () {
		for (const n of [alice, bob]) {
			try {
				n?.destroy();
			} catch {
				/* ignore */
			}
		}
		alice = null;
		bob = null;
	});

	it('opens a zero-conf channel mid-payment and settles', async function () {
		alice = makeNode('jit-lsp-901', {
			fundingProvider: new BitcoindFundingProvider(),
			jitReceive: {
				enabled: true,
				fundingBufferSats: 20_000n,
				maxClientFundingSats: 500_000n
			}
		});
		bob = makeNode('jit-wallet-902');
		const aliceId = alice.getNodeId();
		const bobId = bob.getNodeId();

		// ── LND funds a channel to alice, so LND has the outbound to spend ──
		await fundLndWallet(lnd, 110);
		await alice.connectPeer(lndPubkey, LND_P2P_HOST, LND_P2P_PORT);
		await sleep(2_000);
		await lnd.openChannelSync(aliceId, LND_TO_ALICE_SAT, 0);
		await mineBlocks(6);
		await sleep(3_000);
		const inbound = alice.getChannelManager().listChannels();
		expect(inbound.length, 'alice has the LND channel').to.be.greaterThan(0);
		alice.handleFundingConfirmed(inbound[0].getChannelId()!);
		await waitForLndChannels(lnd, 1, 30_000);
		setupRoutingForChannel(alice, lndPubkey);
		const tip = (await bitcoinRpc('getblockcount')) as number;
		alice.handleNewBlock(tip);
		bob.handleNewBlock(tip);

		// ── bob connects to alice and trusts it for the coming zero-conf open ──
		const bobPort = await freePort();
		await bob.listen(bobPort);
		bob.addTrustedPeer(aliceId);
		await alice.connectPeer(bobId, '127.0.0.1', bobPort);
		await sleep(1_500);
		expect(
			alice.listChannels().filter((c) => c.peerPubkey === bobId),
			'no channel to bob yet'
		).to.have.length(0);

		// ── bob registers a receive intent; alice mints the intercept SCID ──
		let ack: IJitReceiveAck | undefined;
		bob.on('custom-message', (m: { subtype: number; payload: Buffer }) => {
			if (m.subtype === BeignetCustomSubtype.JIT_RECEIVE_ACK) {
				ack = decodeJitAck(m.payload);
			}
		});
		bob.sendCustomMessage(
			aliceId,
			BeignetCustomSubtype.JIT_RECEIVE_AUTHORIZATION,
			encodeJitAuthorization({
				requestId: crypto.randomBytes(8),
				maxAmountMsat: PAYMENT_MSAT,
				expectedTotalMsat: PAYMENT_MSAT,
				targetRemainingInboundSat: 50_000n,
				expirySeconds: 600
			})
		);
		await sleep(1_000);
		expect(ack, 'bob received the ack').to.not.equal(undefined);
		expect(ack!.accepted).to.equal(true);

		// ── the invoice: unpayable today, its only hint is the intercept SCID ──
		const invoice = bob.createInvoice({
			amountMsat: PAYMENT_MSAT,
			description: 'jit receive',
			extraRoutingHints: [
				[
					{
						pubkey: Buffer.from(aliceId, 'hex'),
						shortChannelId: ack!.interceptScid,
						feeBaseMsat: 1_000,
						feeProportionalMillionths: 1,
						cltvExpiryDelta: HINT_CLTV_DELTA
					}
				]
			]
		});

		const opened = new Promise<void>((resolve, reject) => {
			alice!.once('jit:forwarded', () => resolve());
			alice!.once('jit:failed', (d: { reason: string }) =>
				reject(new Error(`JIT funding failed: ${d.reason}`))
			);
		});

		const payment = await lnd.sendPaymentSync(invoice.bolt11);
		expect(payment.payment_error || '').to.equal('');
		expect(payment.payment_preimage).to.be.a('string');
		await opened;

		// The channel alice funded mid-payment is real and carries the receive.
		const jitChannels = alice.listChannels();
		expect(jitChannels.filter((c) => c.peerPubkey === bobId)).to.have.length(1);
		expect(bob.listChannels()).to.have.length(1);
		// The settle rides a commitment round after LND's payment returns.
		const settled = Date.now() + 20_000;
		while (
			bob.listChannels()[0].localBalanceMsat < PAYMENT_MSAT &&
			Date.now() < settled
		) {
			await sleep(250);
		}
		expect(
			Number(bob.listChannels()[0].localBalanceMsat),
			'bob was credited the receive'
		).to.be.greaterThanOrEqual(Number(PAYMENT_MSAT));
		// The intent is consumed: it authorized one receive, not a standing
		// right to be funded again.
		expect(alice.getJitReceiveManager()!.listIntents()).to.have.length(0);
		expect(alice.getChannelManager().isTrustedPeer(bobId)).to.equal(false);
	});

	// The 3B wallet half of the same round trip (issue #595): one call
	// registers the intent, embeds the hint and records the fee allowance,
	// and the LSP charges an opening fee this time. The skim is what makes
	// this the interesting case: the HTLC bob receives is SHORT of the
	// amount its onion declares, so without the allowance BOLT 4 has him
	// fail a payment LND already considers made.
	it('createJitInvoice settles a delivery the LSP skimmed its fee from', async function () {
		alice = makeNode('jit-lsp-903', {
			fundingProvider: new BitcoindFundingProvider(),
			jitReceive: {
				enabled: true,
				fundingBufferSats: 20_000n,
				maxClientFundingSats: 500_000n,
				flatFeeSat: OPENING_FEE_SAT
			}
		});
		bob = makeNode('jit-wallet-904');
		const aliceId = alice.getNodeId();
		const bobId = bob.getNodeId();

		await fundLndWallet(lnd, 110);
		await alice.connectPeer(lndPubkey, LND_P2P_HOST, LND_P2P_PORT);
		await sleep(2_000);
		await lnd.openChannelSync(aliceId, LND_TO_ALICE_SAT, 0);
		await mineBlocks(6);
		await sleep(3_000);
		const inbound = alice.getChannelManager().listChannels();
		expect(inbound.length, 'alice has the LND channel').to.be.greaterThan(0);
		alice.handleFundingConfirmed(inbound[0].getChannelId()!);
		await waitForLndChannels(lnd, 1, 30_000);
		setupRoutingForChannel(alice, lndPubkey);
		const tip = (await bitcoinRpc('getblockcount')) as number;
		alice.handleNewBlock(tip);
		bob.handleNewBlock(tip);

		const bobPort = await freePort();
		await bob.listen(bobPort);
		bob.addTrustedPeer(aliceId);
		await alice.connectPeer(bobId, '127.0.0.1', bobPort);
		await sleep(1_500);

		const invoice = await bob.createJitInvoice({
			lspPubkeyHex: aliceId,
			amountMsat: PAYMENT_MSAT,
			description: 'jit receive with fee',
			targetRemainingInboundSat: 50_000n
		});
		expect(invoice.flatFeeSat, 'the quote bob agreed to').to.equal(
			OPENING_FEE_SAT
		);

		const opened = new Promise<void>((resolve, reject) => {
			alice!.once('jit:forwarded', () => resolve());
			alice!.once('jit:failed', (d: { reason: string }) =>
				reject(new Error(`JIT funding failed: ${d.reason}`))
			);
		});

		const payment = await lnd.sendPaymentSync(invoice.bolt11);
		expect(payment.payment_error || '').to.equal('');
		expect(payment.payment_preimage).to.be.a('string');
		await opened;

		const delivered = PAYMENT_MSAT - OPENING_FEE_SAT * 1000n;
		const settled = Date.now() + 20_000;
		while (
			bob.listChannels()[0]?.localBalanceMsat < delivered &&
			Date.now() < settled
		) {
			await sleep(250);
		}
		expect(
			Number(bob.listChannels()[0].localBalanceMsat),
			'bob was credited the delivery net of the agreed fee'
		).to.be.greaterThanOrEqual(Number(delivered));
		// And no more than that: the skim is bounded by the quote, so a fee
		// larger than the one bob registered would have failed the HTLC.
		expect(
			Number(bob.listChannels()[0].localBalanceMsat),
			'the skim is exactly the quoted fee'
		).to.be.lessThan(Number(PAYMENT_MSAT));
	});
});
