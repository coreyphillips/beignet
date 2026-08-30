/**
 * A forwarded inbound leg is not refunded upstream until the DOWNSTREAM
 * removal round completes (issue #623).
 *
 * handleHtlcFailed used to treat the peer's update_fail_htlc as terminal on
 * arrival and refund the inbound leg from the htlc:failed event, with the
 * outgoing entry still FAILED and both removal phase flags false. That refund
 * cannot be retracted, but the downstream leg can still be claimed: a
 * disconnect rolls it back to COMMITTED and the peer may retransmit a fulfill,
 * or claim the offered output on chain from the last commitment we signed. The
 * late preimage is then worthless upstream (canFulfillHtlc refuses the FAILED
 * inbound entry), so we pay downstream for a forward we already refunded. A
 * payee holds that window open for as long as it likes simply by withholding
 * its commitment_signed.
 *
 * The refund now waits for isOutgoingLegTerminallyFailed, the same predicate
 * the deferred paths use, with the downstream's reason bytes held on the
 * linkage so the payer still learns why.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	BITCOIN_CHAIN_HASH,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';

// ─── Shared node plumbing ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`fwd-fail-deferral-${id}`))
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

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
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
		htlcSafetyMargin: 6
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function nodePubkey(seedId: number): Buffer {
	return getPublicKey(makeNodeConfig(seedId).nodePrivateKey);
}

async function settle(rounds = 8): Promise<void> {
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
		if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

// ─── Synthetic fixture: one forward, outgoing leg in a chosen removal phase ───

const HEIGHT = 800_000;

interface IForwardFixture {
	alice: LightningNode;
	carol: LightningNode;
	inChannelId: Buffer;
	outChannelId: Buffer;
	outKey: string;
	preimage: Buffer;
	paymentHash: Buffer;
	inHtlcs: Map<string, IHtlcEntry>;
	outHtlcs: Map<string, IHtlcEntry>;
	/** Every failHtlc the node asked the manager for, in order. */
	failed: Array<{ channelId: string; htlcId: bigint; reason: Buffer }>;
	destroy: () => void;
}

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId())
			b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId())
			a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

function openSyncChannel(a: LightningNode, b: LightningNode): Buffer {
	const channel = a.openChannel(b.getNodeId(), 1_000_000n);
	const channelId = a.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	a.handleFundingConfirmed(channelId);
	b.handleFundingConfirmed(channelId);
	return channelId;
}

/** Alice forwards Bob -> Carol, with the outgoing leg COMMITTED and live. */
function makeForward(seedBase: number): IForwardFixture {
	const alice = createNode(seedBase); // forwarder
	const bob = createNode(seedBase + 1); // upstream (inbound)
	const carol = createNode(seedBase + 2); // downstream (outbound)
	connectNodes(alice, bob);
	connectNodes(alice, carol);
	const inChannelId = openSyncChannel(alice, bob);
	const outChannelId = openSyncChannel(alice, carol);

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const a = alice as any;
	a.currentBlockHeight = HEIGHT;

	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	const inHtlcs: Map<string, IHtlcEntry> = a.channelManager
		.getChannel(inChannelId)
		.getFullState().htlcs;
	inHtlcs.set('received-7', {
		id: 7n,
		amountMsat: 50_000n,
		paymentHash,
		cltvExpiry: HEIGHT + 500,
		onionRoutingPacket: Buffer.alloc(1366),
		direction: HtlcDirection.RECEIVED,
		state: HtlcState.COMMITTED
	});

	const outHtlcs: Map<string, IHtlcEntry> = a.channelManager
		.getChannel(outChannelId)
		.getFullState().htlcs;
	outHtlcs.set('offered-7', {
		id: 7n,
		amountMsat: 49_000n,
		paymentHash,
		cltvExpiry: HEIGHT + 400,
		onionRoutingPacket: Buffer.alloc(1366),
		direction: HtlcDirection.OFFERED,
		state: HtlcState.COMMITTED,
		addLocallyRevoked: true,
		addRemoteCommitted: true
	});

	const outKey = `${outChannelId.toString('hex')}:offered-7`;
	a.forwardedHtlcs.set(outKey, { inChannelId, inHtlcId: 7n });

	const failed: Array<{ channelId: string; htlcId: bigint; reason: Buffer }> =
		[];
	const realFail = a.channelManager.failHtlc.bind(a.channelManager);
	a.channelManager.failHtlc = (
		channelId: Buffer,
		htlcId: bigint,
		reason: Buffer
	): unknown => {
		failed.push({ channelId: channelId.toString('hex'), htlcId, reason });
		return realFail(channelId, htlcId, reason);
	};

	return {
		alice,
		carol,
		inChannelId,
		outChannelId,
		outKey,
		preimage,
		paymentHash,
		inHtlcs,
		outHtlcs,
		failed,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
			carol.destroy();
		}
	};
}

/** The exact entry shape handleUpdateFailHtlc leaves: both phases still to go. */
function markProvisionallyFailed(f: IForwardFixture): void {
	const entry = f.outHtlcs.get('offered-7')!;
	entry.state = HtlcState.FAILED;
	entry.removalLocallyRevoked = false;
	entry.removalRemoteCommitted = false;
}

const failedInbound = (f: IForwardFixture): boolean =>
	f.failed.some(
		(c) => c.channelId === f.inChannelId.toString('hex') && c.htlcId === 7n
	);

const linkageHeld = (f: IForwardFixture): boolean =>
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(f.alice as any).forwardedHtlcs.has(f.outKey);

/** Downstream reason bytes distinctive enough to recognise on the wire. */
const DOWNSTREAM_REASON = Buffer.alloc(292, 0xab);

describe('Deferred forward fails (issue #623)', function () {
	this.timeout(10_000);

	it('the downstream update_fail_htlc alone does not refund upstream', function () {
		const f = makeForward(600);
		markProvisionallyFailed(f);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).handleHtlcFailed(f.outChannelId, 7n, DOWNSTREAM_REASON);

		expect(failedInbound(f), 'inbound never refunded upstream').to.equal(false);
		expect(f.inHtlcs.get('received-7')!.state).to.equal(HtlcState.COMMITTED);
		expect(linkageHeld(f), 'linkage retained').to.equal(true);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const held = (f.alice as any).forwardedHtlcs.get(f.outKey);
		expect(
			held.failReason?.equals(DOWNSTREAM_REASON),
			'downstream reason bytes held'
		).to.equal(true);
		f.destroy();
	});

	it('a rollback then a late preimage still pays upstream', function () {
		// The theft in one run: refund the inbound on the fail's arrival and
		// everything below would be value paid downstream for a forward we
		// already refunded.
		const f = makeForward(610);
		markProvisionallyFailed(f);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = f.alice as any;
		a.handleHtlcFailed(f.outChannelId, 7n, DOWNSTREAM_REASON);
		expect(failedInbound(f)).to.equal(false);

		// Carol drops before the removal round completes: markForReestablish
		// restores the leg she never committed, and she can claim it again.
		a.channelManager.handlePeerDisconnected(f.carol.getNodeId());
		expect(f.outHtlcs.get('offered-7')!.state).to.equal(HtlcState.COMMITTED);

		a.handleOnChainPreimageLearned(f.paymentHash, f.preimage);

		expect(
			f.inHtlcs.get('received-7')!.state,
			'the inbound leg still collectable'
		).to.equal(HtlcState.FULFILLED);
		expect(linkageHeld(f), 'linkage consumed by the fulfill').to.equal(false);
		f.destroy();
	});

	it('the completed removal round releases the refund with the downstream reason', function () {
		const f = makeForward(620);
		markProvisionallyFailed(f);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = f.alice as any;
		a.handleHtlcFailed(f.outChannelId, 7n, DOWNSTREAM_REASON);
		expect(failedInbound(f)).to.equal(false);

		// The removal became irrevocable: handleRevokeAndAck's settlement loop
		// dropped the entry from a channel that is still NORMAL.
		f.outHtlcs.delete('offered-7');
		a.drainForwardsAwaitingRemoval(f.outChannelId);

		expect(failedInbound(f), 'inbound refunded upstream').to.equal(true);
		expect(linkageHeld(f), 'linkage consumed').to.equal(false);
		const sent = f.failed.find(
			(c) => c.channelId === f.inChannelId.toString('hex')
		)!;
		expect(
			sent.reason.equals(DOWNSTREAM_REASON),
			'the held downstream bytes were relayed, not a synthesized failure'
		).to.equal(true);
		f.destroy();
	});

	it('a leg already past its removal round is refunded on arrival', function () {
		// Nothing to wait for: the replayed fail finds an entry the settlement
		// loop already dropped, so the refund must not be held back.
		const f = makeForward(630);
		f.outHtlcs.delete('offered-7');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).handleHtlcFailed(f.outChannelId, 7n, DOWNSTREAM_REASON);

		expect(failedInbound(f), 'inbound refunded upstream').to.equal(true);
		expect(linkageHeld(f), 'linkage consumed').to.equal(false);
		f.destroy();
	});
});

// ─── Live three-node wire ───

const ALICE_SEED = 701;
const BOB_SEED = 702;
const CHARLIE_SEED = 703;

interface IWireFilter {
	/** Return false to drop (and record) the message instead of delivering it. */
	allow: (from: string, to: string, type: number) => boolean;
	dropped: Array<{ to: LightningNode; from: string; type: number; p: Buffer }>;
}

function wire(a: LightningNode, b: LightningNode, filter?: IWireFilter): void {
	const route = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			if (filter && !filter.allow(from.getNodeId(), pk, t)) {
				filter.dropped.push({
					to,
					from: from.getNodeId(),
					type: t,
					p: Buffer.from(p)
				});
				return;
			}
			to.handlePeerMessage(from.getNodeId(), t, p);
		});
	};
	route(a, b);
	route(b, a);
}

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

interface IWorld {
	alice: LightningNode;
	bob: LightningNode;
	charlie: LightningNode;
	abChannelId: Buffer;
	bcChannelId: Buffer;
	filterBC: IWireFilter;
	destroy: () => void;
}

/** Alice -> Bob -> Charlie, with the Bob/Charlie link filterable. */
async function setupWorld(): Promise<IWorld> {
	const alice = createNode(ALICE_SEED);
	const bob = createNode(BOB_SEED);
	const charlie = createNode(CHARLIE_SEED);
	const filterBC: IWireFilter = { allow: () => true, dropped: [] };
	wire(alice, bob);
	wire(bob, charlie, filterBC);

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
		block: 840,
		txIndex: 1,
		outputIndex: 0
	});
	const scidBC = encodeShortChannelId({
		block: 840,
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
		filterBC,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
			charlie.destroy();
		}
	};
}

describe('Deferred forward fails over a live wire (issue #623)', () => {
	it('a healthy downstream failure still refunds the payer', async function () {
		this.timeout(30_000);
		const world = await setupWorld();
		const { alice, bob, charlie } = world;

		const invoice = charlie.createInvoice({
			amountMsat: 80_000n,
			description: 'clean fail',
			hold: true
		});
		const payment = alice.sendPayment(invoice.bolt11);
		await waitFor(
			() => charlie.listHoldInvoices().some((h) => h.state === 'ACCEPTED'),
			'the HTLC to park at Charlie'
		);

		charlie.cancelHoldInvoice(invoice.paymentHash);
		await waitFor(
			() => payment.status === PaymentStatus.FAILED,
			'the payer to be refunded once the removal round completed'
		);
		const bobInternals = bob as unknown as {
			forwardedHtlcs: Map<string, unknown>;
		};
		expect(
			bobInternals.forwardedHtlcs.size,
			'linkage cleared by the refund'
		).to.equal(0);

		world.destroy();
	});

	it('a withheld commitment_signed holds the refund, and releasing it completes', async function () {
		this.timeout(30_000);
		const world = await setupWorld();
		const { alice, bob, charlie } = world;
		const charlieId = charlie.getNodeId();

		const invoice = charlie.createInvoice({
			amountMsat: 80_000n,
			description: 'withheld removal round',
			hold: true
		});
		const payment = alice.sendPayment(invoice.bolt11);
		await waitFor(
			() => charlie.listHoldInvoices().some((h) => h.state === 'ACCEPTED'),
			'the HTLC to park at Charlie'
		);

		// The attack: Charlie fails the HTLC but never signs the removal, so
		// the leg stays rolled-back-able and claimable for as long as she likes.
		world.filterBC.allow = (from, _to, type): boolean =>
			!(from === charlieId && type === MessageType.COMMITMENT_SIGNED);
		charlie.cancelHoldInvoice(invoice.paymentHash);
		await settle(12);

		const bobInternals = bob as unknown as {
			forwardedHtlcs: Map<string, unknown>;
		};
		const outbound = bob.getChannelManager().getChannel(world.bcChannelId)!;
		const outEntry = [...outbound.getFullState().htlcs.values()].find(
			(h) => h.direction === HtlcDirection.OFFERED
		)!;
		expect(outEntry.state, 'downstream leg failed but provisional').to.equal(
			HtlcState.FAILED
		);
		expect(
			outEntry.removalRemoteCommitted,
			'removal round unfinished'
		).to.equal(false);
		expect(payment.status, 'payer NOT refunded').to.equal(
			PaymentStatus.PENDING
		);
		expect(
			bobInternals.forwardedHtlcs.size,
			'forward linkage retained'
		).to.equal(1);
		const inbound = bob.getChannelManager().getChannel(world.abChannelId)!;
		expect(
			[...inbound.getFullState().htlcs.values()].some(
				(h) =>
					h.direction === HtlcDirection.RECEIVED &&
					h.state === HtlcState.COMMITTED
			),
			'inbound leg still COMMITTED, so a late preimage is still claimable'
		).to.equal(true);

		// Charlie relents: the withheld round completes and the refund follows,
		// so the hold is a delay and not a stall.
		world.filterBC.allow = (): boolean => true;
		for (const m of world.filterBC.dropped.splice(0)) {
			m.to.handlePeerMessage(m.from, m.type, m.p);
		}
		await waitFor(
			() => payment.status === PaymentStatus.FAILED,
			'the payer to be refunded once the removal round completed'
		);
		expect(
			bobInternals.forwardedHtlcs.size,
			'linkage cleared by the refund'
		).to.equal(0);

		world.destroy();
	});
});
