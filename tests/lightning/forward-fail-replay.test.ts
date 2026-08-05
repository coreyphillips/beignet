/**
 * A replayed update_fail_htlc must re-drive the refund it authorizes, and
 * a downstream failure that cannot yet reach the inbound leg must not
 * destroy the forward linkage a later attempt needs (issue 297, the fail
 * side of issue 295's mechanism).
 *
 * Unlike the fulfill side, the fail pipeline's commit ordering turned
 * out to be restart-safe by construction (verified by commit tracing):
 * the upstream refund commits BEFORE the outbound FAILED state ever
 * persists, and the linkage delete rides that same later commit, so the
 * settled-durable-with-nothing-propagated disk shape cannot exist for
 * fails and no kill sweep cell can strand a restart. What remains real
 * is the live surface: a replayed update_fail_htlc was swallowed by the
 * channel dedup (nothing re-drives the refund it authorizes), and a
 * downstream fail arriving while the inbound peer was disconnected
 * durably consumed the forward linkage around a REFUSED upstream fail
 * (the staged delete flushed standalone), losing the association the
 * CLTV sweeper itself needs and leaving a force close as the only exit.
 * Repairs mirror the fulfill side: the dedup re-emits HTLC_FAILED after
 * validation, the forwarder checks the inbound leg can carry the fail
 * before consuming the linkage, and the reestablish-tail owed pass also
 * fails legs whose downstream durably failed, with a synthesized
 * temporary_channel_failure when the downstream's reason bytes died
 * with the process.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	BITCOIN_CHAIN_HASH,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';

const ALICE_SEED = 81;
const BOB_SEED = 82;
const CHARLIE_SEED = 83;

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(`fulfill-replay-seed-${id}`)
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(
	seedId: number,
	storage?: IStorageBackend,
	recovery?: INodeConfig['recovery']
): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		storage,
		recovery
	};
}

function createNode(
	seedId: number,
	storage?: IStorageBackend,
	recovery?: INodeConfig['recovery']
): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, storage, recovery));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

interface ICut {
	val: boolean;
}

interface IWireGate {
	hold: boolean;
	queue: Array<{ to: LightningNode; from: string; type: number; p: Buffer }>;
}

/**
 * Event-relay wire for one node pair with a cut switch (the pair's link is
 * down, or the victim's process is gone) and an optional hold gate. A real
 * connection delivers BOTH channel_reestablish messages before any response
 * they trigger, so a live reconnect holds the wire and drains it in order.
 */
function wire(
	a: LightningNode,
	b: LightningNode,
	cut: ICut,
	gate?: IWireGate
): void {
	const route = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (cut.val) return;
			if (pk !== to.getNodeId()) return;
			if (gate?.hold) {
				gate.queue.push({ to, from: from.getNodeId(), type: t, p });
				return;
			}
			to.handlePeerMessage(from.getNodeId(), t, p);
		});
	};
	route(a, b);
	route(b, a);
}

/** One full disconnect/reconnect cycle on two LIVE nodes over their wire. */
async function cycleConnection(
	a: LightningNode,
	b: LightningNode,
	cut: ICut,
	gate: IWireGate
): Promise<void> {
	cut.val = true;
	a.getChannelManager().handlePeerDisconnected(b.getNodeId());
	b.getChannelManager().handlePeerDisconnected(a.getNodeId());
	await settle();
	cut.val = false;
	gate.hold = true;
	a.getChannelManager().handlePeerReconnected(b.getNodeId());
	b.getChannelManager().handlePeerReconnected(a.getNodeId());
	while (gate.queue.length > 0) {
		const m = gate.queue.shift()!;
		m.to.handlePeerMessage(m.from, m.type, m.p);
	}
	gate.hold = false;
	await settle();
}

/**
 * Barrier-tolerant open: a quorum-mode participant parks its gated funding
 * messages until the frame behind them is released, so each step waits for
 * the state it needs instead of assuming the synchronous loopback finished.
 */
async function openReadyChannel(
	opener: LightningNode,
	acceptor: LightningNode
): Promise<Buffer> {
	const channel = opener.openChannel(acceptor.getNodeId(), 1_000_000n);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	await waitFor(
		() => channel.getState() !== ChannelState.SENT_FUNDING_CREATED,
		'funding_signed to arrive'
	);
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	await waitFor(
		() => channel.getState() === ChannelState.NORMAL,
		'the opened channel to reach NORMAL'
	);
	return channelId;
}

/** Add an announced channel + both-direction updates to a node's graph. */
function addGraphChannel(
	node: LightningNode,
	scid: Buffer,
	pubA: Buffer,
	pubB: Buffer
): void {
	const aIs1 = Buffer.compare(pubA, pubB) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aIs1 ? pubA : pubB,
		nodeId2: aIs1 ? pubB : pubA,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const dir of [0, 1]) {
		node.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: dir,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		});
	}
}

function nodePubkey(seedId: number): Buffer {
	return getPublicKey(makeNodeConfig(seedId).nodePrivateKey);
}

interface IForwardWorld {
	alice: LightningNode;
	bob: LightningNode;
	charlie: LightningNode;
	abChannelId: Buffer;
	bcChannelId: Buffer;
	cutAB: ICut;
	cutBC: ICut;
	gateAB: IWireGate;
}

/**
 * Alice -> Bob -> Charlie with a known fee: Bob's policy is base 5000 /
 * ppm 0, propagated to Charlie's invoice hint so the payer attaches the
 * exact fee. Same shape as forwarding-history.test.ts.
 */
async function setupForwardWorld(
	bobStorage?: IStorageBackend,
	bobRecovery?: INodeConfig['recovery']
): Promise<IForwardWorld> {
	const alice = createNode(ALICE_SEED);
	const bob = createNode(BOB_SEED, bobStorage, bobRecovery);
	const charlie = createNode(CHARLIE_SEED);
	const cutAB: ICut = { val: false };
	const cutBC: ICut = { val: false };
	const gateAB: IWireGate = { hold: false, queue: [] };
	wire(alice, bob, cutAB, gateAB);
	wire(bob, charlie, cutBC);

	const abChannelId = await openReadyChannel(alice, bob);
	const bcChannelId = await openReadyChannel(bob, charlie);
	await waitFor(
		() =>
			[alice, bob, charlie].every((n) =>
				n
					.getChannelManager()
					.listChannels()
					.every((c) => c.getState() === ChannelState.NORMAL)
			),
		'every channel on every node to reach NORMAL'
	);

	const scidAB = encodeShortChannelId({
		block: 830,
		txIndex: 1,
		outputIndex: 0
	});
	const scidBC = encodeShortChannelId({
		block: 830,
		txIndex: 2,
		outputIndex: 0
	});
	bob.registerChannelScid(abChannelId, scidAB);
	bob.registerChannelScid(bcChannelId, scidBC);
	alice.registerChannelScid(abChannelId, scidAB);
	bob
		.getChannelManager()
		.getChannel(bcChannelId)!
		.getFullState().remoteScidAlias = scidBC;
	charlie
		.getChannelManager()
		.getChannel(bcChannelId)!
		.getFullState().remoteScidAlias = scidBC;
	addGraphChannel(alice, scidAB, nodePubkey(ALICE_SEED), nodePubkey(BOB_SEED));
	bob.setChannelPolicy(bcChannelId, {
		feeBaseMsat: 5000,
		feeProportionalMillionths: 0
	});

	return {
		alice,
		bob,
		charlie,
		abChannelId,
		bcChannelId,
		cutAB,
		cutBC,
		gateAB
	};
}

async function settle(rounds = 6): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

async function waitFor(
	predicate: () => boolean,
	what: string,
	timeoutMs = 10_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() > deadline) {
			throw new Error(`timed out waiting for ${what}`);
		}
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

describe('Replayed update_fail_htlc re-drives the refund (issue 297)', () => {
	it('a replayed fail re-emits HTLC_FAILED instead of a silent no-op', async function () {
		this.timeout(20_000);
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED);
		const aliceId = alice.getNodeId();
		const bobId = bob.getNodeId();

		let captured: Buffer | null = null;
		const aliceToBobCut = { val: false };
		bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== aliceId) return;
			if (t === MessageType.UPDATE_FAIL_HTLC) {
				captured = Buffer.from(p);
				aliceToBobCut.val = true;
			}
			alice.handlePeerMessage(bobId, t, p);
		});
		alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== bobId) return;
			if (aliceToBobCut.val) return;
			bob.handlePeerMessage(aliceId, t, p);
		});

		await openReadyChannel(alice, bob);
		addGraphChannel(
			alice,
			encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 }),
			nodePubkey(ALICE_SEED),
			nodePubkey(BOB_SEED)
		);
		alice.registerChannelScid(
			alice.getChannelManager().listChannels()[0].getChannelId()!,
			encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 })
		);

		let failEvents = 0;
		alice.getChannelManager().on('htlc:failed', () => {
			failEvents++;
		});

		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'fail replay unit',
			hold: true
		});
		const payment = alice.sendPayment(invoice.bolt11);
		await settle();
		expect(payment.status, 'held payment pending').to.equal(
			PaymentStatus.PENDING
		);
		bob.cancelHoldInvoice(invoice.paymentHash);
		await settle();
		expect(captured, 'fail bytes captured').to.not.equal(null);
		expect(failEvents, 'one fail event so far').to.equal(1);
		expect(payment.status, 'payment failed by the cancel').to.equal(
			PaymentStatus.FAILED
		);
		const channel = alice.getChannelManager().listChannels()[0];
		expect(
			channel.getFullState().htlcs.get('offered-0')?.state,
			'entry parked in FAILED'
		).to.equal(HtlcState.FAILED);

		// BOLT 2 retransmission: the identical bytes after a reconnect.
		alice.handlePeerMessage(bobId, MessageType.UPDATE_FAIL_HTLC, captured!);
		await settle();
		expect(failEvents, 'the replay re-emitted the fail event').to.equal(2);
		expect(
			channel.getFullState().htlcs.get('offered-0')?.state,
			'entry unchanged by the replay'
		).to.equal(HtlcState.FAILED);
		expect(payment.status, 'payment stays failed').to.equal(
			PaymentStatus.FAILED
		);

		alice.destroy();
		bob.destroy();
	});

	it('a live inbound disconnect during the downstream fail keeps the linkage and refunds on reconnect', async function () {
		this.timeout(30_000);
		const world = await setupForwardWorld();
		const { alice, bob, charlie } = world;

		const invoice = charlie.createInvoice({
			amountMsat: 80_000n,
			description: 'live disconnect fail',
			hold: true
		});
		const payment = alice.sendPayment(invoice.bolt11);
		await waitFor(
			() => charlie.listHoldInvoices().some((h) => h.state === 'ACCEPTED'),
			'the HTLC to park at Charlie'
		);

		world.cutAB.val = true;
		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		bob.getChannelManager().handlePeerDisconnected(alice.getNodeId());
		await settle();

		charlie.cancelHoldInvoice(invoice.paymentHash);
		await settle(10);

		const bobInternals = bob as unknown as {
			forwardedHtlcs: Map<string, unknown>;
		};
		expect(
			bobInternals.forwardedHtlcs.size,
			'forward linkage survives the refused fail'
		).to.equal(1);

		await cycleConnection(alice, bob, world.cutAB, world.gateAB);
		await waitFor(
			() => payment.status === PaymentStatus.FAILED,
			'the payer to be refunded after the reconnect'
		);
		const inbound = bob.getChannelManager().getChannel(world.abChannelId)!;
		await waitFor(
			() =>
				![...inbound.getFullState().htlcs.values()].some(
					(h) => h.state === HtlcState.COMMITTED
				),
			'the inbound HTLC to leave COMMITTED'
		);
		expect(
			bobInternals.forwardedHtlcs.size,
			'linkage cleared by the refund'
		).to.equal(0);

		alice.destroy();
		bob.destroy();
		charlie.destroy();
	});
});
