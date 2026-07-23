/**
 * INTEROP — beignet FORWARDS an HTLC addressed by a channel's real SCID.
 *
 * This is the coverage gap that let a real bug ship. beignet registered only
 * SCID *aliases* in its forwarding lookup table, never the real confirmed SCID,
 * so every payment routed THROUGH a beignet node was failed back with
 * unknown_next_peer (0x400A) while direct payments kept working, because a final
 * hop payload carries no short_channel_id at all. Nothing in the suite forwarded
 * through an intermediate beignet node, so it all stayed green.
 *
 *     alice (beignet)  --AB, in-process-->  bob (beignet)  --BC, real-->  LND
 *                                                              real SCID
 *
 * bob holds a real, funded, announced channel to live LND. The real SCID is not
 * injected by the test: it is assigned when LND's announcement_signatures
 * arrives at announcement depth, which makes the assignment path itself
 * interop-validated. alice then routes to LND using that SCID out of its graph,
 * exactly as a real sender does from gossip, and bob must resolve it to forward.
 *
 * The test deliberately does NOT call registerChannelScid for the BC channel.
 * Registering it by hand would paper over the very bug under test.
 *
 * Requires the interop stack (docker/docker-compose.yml). Auto-skips when LND is
 * unreachable, like the other interop suites. Set LND_REST_PORT / LND_P2P_PORT
 * when the default host ports are taken.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { LndRestClient } from './lnd-client';
import {
	createLndClient,
	setupBeignetFundedChannel,
	waitForInvoiceSettled,
	waitForLndSync
} from './lnd-helpers';
import { TEST_MNEMONIC, mineBlocks, sleep, bitcoinRpc } from './shared-helpers';
import { REGTEST_CHAIN_HASH } from '../../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import { Network } from '../../../src/lightning/invoice/types';

const SEED_BOB = 8801;
const SEED_ALICE = 8802;

const AB_CAPACITY_SAT = 500_000n;
const BC_CAPACITY_SAT = 500_000n;
const PAYMENT_SAT = 5_000;

// One policy for the BC hop, used both as bob's real forwarding policy and as
// the channel_update alice routes against, so the fee/CLTV alice attaches is
// exactly what bob enforces. A mismatch surfaces as fee_insufficient or
// incorrect_cltv_expiry and would muddy what this test is actually proving.
const BC_POLICY = {
	feeBaseMsat: 1000,
	feeProportionalMillionths: 1,
	cltvExpiryDelta: 40
};

/**
 * The sender. Networking is OFF deliberately: ChannelManager.openChannel
 * requires a live socket whenever a PeerManager exists, so a networked alice
 * could only reach bob over real TCP, making the open asynchronous and the test
 * timing-dependent. Without a PeerManager every message falls through to
 * message:outbound and the alice<->bob handshake runs synchronously, which is
 * how the in-process forwarding tests already work. The interop value of this
 * test lives entirely in the bob<->LND leg.
 */
function createSenderNode(seedId: number): LightningNode {
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

	return new LightningNode({
		nodePrivateKey: keys.nodePrivateKey,
		channelBasepoints: keys.channelBasepoints,
		perCommitmentSeed: keys.perCommitmentSeed,
		fundingPrivkey: keys.fundingPrivkey,
		htlcBasepointSecret: keys.htlcBasepointSecret,
		network: Network.REGTEST,
		enableNetworking: false,
		localFeatures: features,
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true
	});
}

/** Relay messages between two in-process beignet nodes. */
function wireInProcess(a: LightningNode, b: LightningNode): void {
	// channel-manager sendMessage tries its PeerManager first and only emits
	// message:outbound when the peer has no socket. bob's LND traffic therefore
	// goes over TCP untouched, and only the alice<->bob leg lands here.
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId()) {
			b.handlePeerMessage(a.getNodeId(), type, payload);
		}
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId()) {
			a.handlePeerMessage(b.getNodeId(), type, payload);
		}
	});
}

/** Open and confirm an in-process channel, funder -> acceptor. */
function openInProcessChannel(
	funder: LightningNode,
	acceptor: LightningNode,
	capacitySat: bigint
): Buffer {
	const channel = funder.openChannel(acceptor.getNodeId(), capacitySat);
	const channelId = funder.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	funder.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	return channelId;
}

/**
 * Wait for the real SCID to be assigned on a channel. Mines while waiting so
 * LND crosses announcement depth and sends announcement_signatures.
 */
async function waitForRealScid(
	node: LightningNode,
	channelId: Buffer,
	timeoutMs: number
): Promise<Buffer> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const channel = node.getChannelManager().getChannel(channelId);
		const scid = channel?.getFullState().shortChannelId;
		if (scid) return scid;
		await mineBlocks(1);
		await sleep(2000);
	}
	throw new Error(
		'No real short_channel_id assigned before timeout. Without it there is ' +
			'nothing to address the forward by, so the test cannot run.'
	);
}

/** Add a synthetic announced edge so alice can route over a channel. */
function addGraphEdge(
	node: LightningNode,
	scid: Buffer,
	pubA: Buffer,
	pubB: Buffer,
	policy = BC_POLICY
): void {
	const aIsNode1 = Buffer.compare(pubA, pubB) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: REGTEST_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aIsNode1 ? pubA : pubB,
		nodeId2: aIsNode1 ? pubB : pubA,
		bitcoinKey1: Buffer.alloc(33),
		bitcoinKey2: Buffer.alloc(33)
	});
	const ts = Math.floor(Date.now() / 1000);
	for (const dir of [0, 1]) {
		node.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: ts,
			messageFlags: 0x01,
			channelFlags: dir,
			cltvExpiryDelta: policy.cltvExpiryDelta,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: policy.feeBaseMsat,
			feeProportionalMillionths: policy.feeProportionalMillionths,
			htlcMaximumMsat: 400_000_000n
		});
	}
}

function registeredScids(node: LightningNode): Set<string> {
	return new Set(
		(
			node as unknown as { scidToChannelId: Map<string, Buffer> }
		).scidToChannelId.keys()
	);
}

describe('Interop — beignet forwards an HTLC addressed by the real SCID', function () {
	this.timeout(300_000);

	let lnd: LndRestClient | null = null;
	let lndPubkey = '';
	let alice: LightningNode | null = null;
	let bob: LightningNode | null = null;

	before(async function () {
		lnd = await createLndClient();
		if (!lnd) {
			console.log(
				'    [skip] lnd not reachable (REST 8081, override with LND_REST_PORT)'
			);
			this.skip();
			return;
		}
		lndPubkey = (await lnd.getInfo()).identity_pubkey;

		// LND refuses to fund a channel while it considers itself out of sync, and
		// it judges that partly on the age of the chain tip. A regtest chain left
		// idle for a while therefore fails the open with a bare "internal error".
		// Mine a fresh tip and wait for LND to catch up before opening anything.
		await mineBlocks(6);
		await waitForLndSync(lnd, 60_000);
	});

	after(function () {
		for (const node of [alice, bob]) {
			try {
				node?.destroy();
			} catch {
				/* ignore */
			}
		}
	});

	it('routes alice -> bob -> LND over the real SCID and settles', async function () {
		if (!lnd) {
			this.skip();
			return;
		}

		// ── bob: real, funded, announced channel to live LND ──
		const setup = await setupBeignetFundedChannel(
			lnd,
			lndPubkey,
			SEED_BOB,
			BC_CAPACITY_SAT
		);
		bob = setup.node;
		const bcChannelId = setup.channelId;

		// The real SCID appears only once LND's announcement_signatures lands, so
		// this also proves beignet assigns it from a live peer's message.
		const realScid = await waitForRealScid(bob, bcChannelId, 120_000);
		console.log(`    real SCID for bob->LND: ${realScid.toString('hex')}`);

		// THE REGRESSION: beignet must register the real SCID itself. Before the
		// fix this map held only aliases and the forward below failed 0x400A.
		expect(
			registeredScids(bob).has(realScid.toString('hex')),
			'bob must accept forwards addressed by the real SCID'
		).to.be.true;

		bob.setChannelPolicy(bcChannelId, BC_POLICY);

		// ── alice: sender, wired to bob in-process ──
		alice = createSenderNode(SEED_ALICE);
		wireInProcess(alice, bob);
		const abChannelId = openInProcessChannel(alice, bob, AB_CAPACITY_SAT);

		// alice's view of the network: its own hop to bob, and bob's hop to LND
		// named by the REAL SCID, which is how a real sender sees it via gossip.
		const abScid = Buffer.from('0000640000010000', 'hex');
		alice.registerChannelScid(abChannelId, abScid);
		addGraphEdge(
			alice,
			abScid,
			Buffer.from(alice.getNodeId(), 'hex'),
			Buffer.from(bob.getNodeId(), 'hex')
		);
		addGraphEdge(
			alice,
			realScid,
			Buffer.from(bob.getNodeId(), 'hex'),
			Buffer.from(lndPubkey, 'hex')
		);

		// Both beignet nodes run without a chain backend here, so their block
		// height would otherwise be 0 and the absolute outgoing_cltv_value alice
		// derives would sit far in LND's past. LND rejects that at the final hop as
		// incorrect_or_unknown_payment_details, which looks nothing like a routing
		// problem and is a genuinely confusing way to fail.
		const chainHeight = (await bitcoinRpc('getblockcount')) as number;
		alice.handleNewBlock(chainHeight);
		bob.handleNewBlock(chainHeight);

		// Record what bob actually forwards. listForwards() is not usable here:
		// that ledger is written through storage and this bob has none.
		const forwards: Array<{ inChannelId: string; outChannelId: string }> = [];
		bob.on('htlc:forward', (inChannelId: Buffer, outChannelId: Buffer) => {
			forwards.push({
				inChannelId: inChannelId.toString('hex'),
				outChannelId: outChannelId.toString('hex')
			});
		});

		// ── the payment ──
		const invoice = await lnd.addInvoice(PAYMENT_SAT, 'forward-by-real-scid');
		const payment = alice.sendPayment(invoice.payment_request);
		expect(payment).to.have.property('paymentHash');

		const result = await alice.waitForPayment(payment.paymentHash, 90_000);
		expect(
			result,
			`alice's payment must complete (failureCode ${alice.getPayment(
				payment.paymentHash
			)?.failureCode})`
		).to.exist;

		// Strict: LND actually received and settled the forwarded HTLC.
		const settled = await waitForInvoiceSettled(
			lnd,
			payment.paymentHash.toString('hex'),
			30_000
		);
		expect(settled.settled, 'LND invoice must be settled').to.be.true;
		expect(BigInt(settled.amtPaidMsat)).to.equal(BigInt(PAYMENT_SAT) * 1000n);

		// Strict: the payment really went THROUGH bob, in over the alice channel and
		// out over the LND channel, rather than reaching LND by some other path.
		expect(forwards, 'bob must forward exactly once').to.have.length(1);
		expect(forwards[0].inChannelId).to.equal(abChannelId.toString('hex'));
		expect(forwards[0].outChannelId).to.equal(bcChannelId.toString('hex'));

		console.log(
			`\n    ✓ ${PAYMENT_SAT} sat forwarded alice->bob->LND over real SCID ${realScid.toString(
				'hex'
			)}`
		);
	});
});
