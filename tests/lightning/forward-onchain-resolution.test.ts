/**
 * S-2.M3 regression: a forwarded HTLC whose OUTGOING leg resolves on-chain by
 * timeout must fail the INBOUND HTLC off-chain (update_fail_htlc) instead of
 * leaving scanForwardTimeouts to force-close the healthy inbound channel.
 *
 * The chain monitor marks the offered-HTLC output IRREVOCABLY_RESOLVED and the
 * OUTPUT_RESOLVED action flows through ChannelManager.processChainActions as
 * the output:resolved event; the node-level consumer added for this finding
 * back-propagates the failure upstream. Before the fix the event had no
 * consumer, so the inbound leg stayed COMMITTED until the forward-timeout scan
 * force-closed the inbound channel.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	HtlcDirection,
	HtlcState,
	IHtlcEntry,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	MonitorState,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { INVALID_ONION_BLINDING } from '../../src/lightning/onion/types';

// ─── Helpers (model: audit-remediation.test.ts) ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`fwd-resolution-seed-${id}`))
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
			.digest()
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	return node;
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

function openReadyChannel(alice: LightningNode, bob: LightningNode): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

interface IForwardFixture {
	alice: LightningNode;
	bob: LightningNode;
	carol: LightningNode;
	inChannelId: Buffer;
	outChannelId: Buffer;
	paymentHash: Buffer;
	outKey: string;
	height: number;
}

/**
 * Alice forwards Bob -> Carol: inbound received-7 COMMITTED on the Bob channel,
 * outbound offered-7 on the Carol channel, legs linked in forwardedHtlcs, and a
 * ChainMonitor on the outgoing channel holding the offered-HTLC output with its
 * confirmed timeout spend one block short of irrevocable depth.
 */
function setupForwardWithResolvingOutgoingLeg(): IForwardFixture {
	const alice = createNode(31);
	const bob = createNode(32);
	const carol = createNode(33);
	connectNodes(alice, bob);
	connectNodes(alice, carol);
	const inChannelId = openReadyChannel(alice, bob);
	const outChannelId = openReadyChannel(alice, carol);

	const height = 800_000;
	(alice as any).currentBlockHeight = height;
	const paymentHash = crypto.randomBytes(32);

	const inChan = (alice as any).channelManager.getChannel(inChannelId);
	const inbound: IHtlcEntry = {
		id: 7n,
		amountMsat: 50_000n,
		paymentHash,
		cltvExpiry: height + 40,
		onionRoutingPacket: Buffer.alloc(1366),
		direction: HtlcDirection.RECEIVED,
		state: HtlcState.COMMITTED
	};
	inChan.getFullState().htlcs.set('received-7', inbound);

	const outChan = (alice as any).channelManager.getChannel(outChannelId);
	const outSt = outChan.getFullState();
	const outbound: IHtlcEntry = {
		id: 7n,
		amountMsat: 49_000n,
		paymentHash,
		cltvExpiry: height - 140,
		onionRoutingPacket: Buffer.alloc(1366),
		direction: HtlcDirection.OFFERED,
		state: HtlcState.COMMITTED
	};
	outSt.htlcs.set('offered-7', outbound);

	const outKey = `${outChannelId.toString('hex')}:offered-7`;
	(alice as any).forwardedHtlcs.set(outKey, { inChannelId, inHtlcId: 7n });

	// Outgoing channel force-closed; our HTLC-timeout claim confirmed 99 blocks
	// ago. The next block pushes it to IRREVOCABLE_DEPTH (100) and the monitor
	// emits OUTPUT_RESOLVED for the offered-HTLC output.
	const monitor = new ChainMonitor(
		outSt,
		Buffer.alloc(22),
		1,
		crypto.randomBytes(32),
		crypto.randomBytes(32)
	);
	(monitor as any)._state = MonitorState.RESOLVING;
	(monitor as any)._trackedOutputs = [
		{
			txid: crypto.randomBytes(32).toString('hex'),
			outputIndex: 0,
			amount: 49n,
			outputType: OutputType.OFFERED_HTLC,
			status: OutputStatus.SPEND_CONFIRMED,
			confirmationHeight: height - 99,
			paymentHash,
			htlcId: 7n,
			resolutionTxid: crypto.randomBytes(32).toString('hex')
		}
	];
	(alice as any).channelManager.monitors.set(
		outChannelId.toString('hex'),
		monitor
	);

	return {
		alice,
		bob,
		carol,
		inChannelId,
		outChannelId,
		paymentHash,
		outKey,
		height
	};
}

describe('S-2.M3: on-chain timeout of a forwarded outgoing leg', function () {
	this.timeout(10_000);

	it('fails the inbound HTLC off-chain instead of force-closing it', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outKey, height } = fx;

		let forceClose = false;
		alice.on('node:error', (err: any) => {
			if (err.code === 'FORWARD_TIMEOUT_FORCE_CLOSE') forceClose = true;
		});
		const UPDATE_FAIL_HTLC = 131;
		let failsSentUpstream = 0;
		alice.on('message:outbound', (pubkey: string, type: number) => {
			if (pubkey === fx.bob.getNodeId() && type === UPDATE_FAIL_HTLC)
				failsSentUpstream++;
		});

		// Reach irrevocable depth: monitor emits OUTPUT_RESOLVED for offered-7.
		(alice as any).channelManager.handleNewBlock(height + 1);

		// update_fail_htlc went upstream and the inbound HTLC completed the
		// removal round (FAILED, then dropped from the map on revoke).
		expect(failsSentUpstream).to.equal(1);
		const inbound = (alice as any).channelManager
			.getChannel(inChannelId)
			.getFullState()
			.htlcs.get('received-7');
		expect(
			inbound === undefined || inbound.state === HtlcState.FAILED
		).to.equal(true);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);

		// The forward-timeout scan now has nothing to force-close.
		(alice as any).scanForwardTimeouts(height + 1);
		expect(forceClose).to.equal(false);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('fails a blinded inbound leg with invalid_onion_blinding', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outKey, height } = fx;

		// The inbound HTLC arrived inside a blinded route with the blinding point
		// in update_add_htlc ('mid' hop): the failure MUST be an
		// update_fail_malformed_htlc carrying invalid_onion_blinding.
		(alice as any).blindedIncomingHtlcs.set(
			`${inChannelId.toString('hex')}:7`,
			'mid'
		);
		const malformedCalls: Array<{ failureCode: number }> = [];
		const realFailMalformed = (
			alice as any
		).channelManager.failMalformedHtlc.bind((alice as any).channelManager);
		(alice as any).channelManager.failMalformedHtlc = (
			channelId: Buffer,
			htlcId: bigint,
			sha256OfOnion: Buffer,
			failureCode: number
		): ReturnType<typeof realFailMalformed> => {
			malformedCalls.push({ failureCode });
			return realFailMalformed(channelId, htlcId, sha256OfOnion, failureCode);
		};

		(alice as any).channelManager.handleNewBlock(height + 1);

		expect(malformedCalls).to.have.length(1);
		expect(malformedCalls[0].failureCode).to.equal(INVALID_ONION_BLINDING);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('retains the forward linkage when the inbound fulfill is refused (issue 558)', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outChannelId, outKey } = fx;

		// A real preimage/hash pair on both legs: the eventual fulfill
		// verifies sha256(preimage) against the HTLC's payment hash.
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const inChan = (alice as any).channelManager.getChannel(inChannelId);
		const outChan = (alice as any).channelManager.getChannel(outChannelId);
		inChan.getFullState().htlcs.get('received-7').paymentHash = paymentHash;
		outChan.getFullState().htlcs.get('offered-7').paymentHash = paymentHash;

		// The inbound channel is mid-reestablish (restart, or the peer
		// disconnected) when the downstream HTLC-success confirms on-chain.
		inChan.getFullState().state = ChannelState.AWAITING_REESTABLISH;

		const UPDATE_FULFILL_HTLC = 130;
		let fulfillsSentUpstream = 0;
		alice.on('message:outbound', (pubkey: string, type: number) => {
			if (pubkey === fx.bob.getNodeId() && type === UPDATE_FULFILL_HTLC)
				fulfillsSentUpstream++;
		});

		(alice as any).channelManager.emit(
			'preimage:learned',
			paymentHash,
			preimage
		);

		// The fulfill was refused (wrong state): no settle went out, the
		// linkage survives for the retry pass, the inbound HTLC is untouched,
		// and the preimage is durable on the node for that retry.
		expect(fulfillsSentUpstream).to.equal(0);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(true);
		expect(inChan.getFullState().htlcs.get('received-7').state).to.equal(
			HtlcState.COMMITTED
		);
		expect((alice as any).preimages.has(paymentHash.toString('hex'))).to.equal(
			true
		);

		// The restore-time redispatch pass still sees the outgoing leg and
		// skips: no second forward for value the downstream already claimed.
		let redispatched = 0;
		(alice as any).handleIncomingHtlc = () => {
			redispatched++;
		};
		inChan.getFullState().htlcs.get('received-7').forwardEmitted = true;
		(alice as any).redispatchUnresolvedReceivedHtlcs(inChannelId);
		expect(redispatched).to.equal(0);

		// Reestablish completes: the owed pass settles upstream from the
		// persisted preimage and only now consumes the linkage.
		inChan.getFullState().state = ChannelState.NORMAL;
		(alice as any).channelManager.emit('channel:reestablished', inChannelId);

		expect(fulfillsSentUpstream).to.equal(1);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);
		const inbound = inChan.getFullState().htlcs.get('received-7');
		expect(
			inbound === undefined || inbound.state === HtlcState.FULFILLED
		).to.equal(true);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('settles upstream after a splice on the inbound channel (issue 558)', async () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outChannelId, outKey } = fx;

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const inChan = (alice as any).channelManager.getChannel(inChannelId);
		const outChan = (alice as any).channelManager.getChannel(outChannelId);
		inChan.getFullState().htlcs.get('received-7').paymentHash = paymentHash;
		outChan.getFullState().htlcs.get('offered-7').paymentHash = paymentHash;

		// The inbound channel is quiescing for a splice when the downstream
		// HTLC-success confirms on-chain.
		inChan.getFullState().state = ChannelState.SPLICING;

		const UPDATE_FULFILL_HTLC = 130;
		let fulfillsSentUpstream = 0;
		alice.on('message:outbound', (pubkey: string, type: number) => {
			if (pubkey === fx.bob.getNodeId() && type === UPDATE_FULFILL_HTLC)
				fulfillsSentUpstream++;
		});

		(alice as any).channelManager.emit(
			'preimage:learned',
			paymentHash,
			preimage
		);

		expect(fulfillsSentUpstream).to.equal(0);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(true);

		// quiescence:ended fires while the channel still cannot carry updates
		// (taproot channels stay parked until splice_locked): the owed pass
		// runs, refuses again, and keeps the linkage.
		(alice as any).channelManager.emit(
			'quiescence:ended',
			inChannelId.toString('hex')
		);
		await new Promise((resolve) => setImmediate(resolve));
		expect(fulfillsSentUpstream).to.equal(0);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(true);
		expect(inChan.getFullState().htlcs.get('received-7').state).to.equal(
			HtlcState.COMMITTED
		);

		// splice_locked exchanged both ways: the channel is NORMAL again and
		// splice:complete (not channel:reestablished) is what a live splice
		// emits. The owed pass must settle upstream from here.
		inChan.getFullState().state = ChannelState.NORMAL;
		(alice as any).channelManager.emit('splice:complete', inChannelId);
		await new Promise((resolve) => setImmediate(resolve));

		expect(fulfillsSentUpstream).to.equal(1);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);
		const inbound = inChan.getFullState().htlcs.get('received-7');
		expect(
			inbound === undefined || inbound.state === HtlcState.FULFILLED
		).to.equal(true);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('retains the forward linkage when the inbound channel is quiescing (issue 569)', async () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outChannelId, outKey } = fx;

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const inChan = (alice as any).channelManager.getChannel(inChannelId);
		const outChan = (alice as any).channelManager.getChannel(outChannelId);
		inChan.getFullState().htlcs.get('received-7').paymentHash = paymentHash;
		outChan.getFullState().htlcs.get('offered-7').paymentHash = paymentHash;

		// Real quiescence, not a state mutation: stfu exchanged over the wire,
		// while the ChannelState stays NORMAL for the whole session. This is
		// the shape the issue-558 gate missed.
		expect(
			(alice as any).channelManager.initiateQuiescence(inChannelId).ok
		).to.equal(true);
		expect(inChan.isQuiescing()).to.equal(true);
		expect(inChan.getState()).to.equal(ChannelState.NORMAL);

		const UPDATE_FULFILL_HTLC = 130;
		let fulfillsSentUpstream = 0;
		alice.on('message:outbound', (pubkey: string, type: number) => {
			if (pubkey === fx.bob.getNodeId() && type === UPDATE_FULFILL_HTLC)
				fulfillsSentUpstream++;
		});

		(alice as any).channelManager.emit(
			'preimage:learned',
			paymentHash,
			preimage
		);

		// Refused, not deferred around a durable delete: nothing on the wire,
		// the linkage survives as the durable retry token, the inbound HTLC is
		// untouched, and the preimage is durable for the retry.
		expect(fulfillsSentUpstream).to.equal(0);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(true);
		expect(inChan.getFullState().htlcs.get('received-7').state).to.equal(
			HtlcState.COMMITTED
		);
		expect((alice as any).preimages.has(paymentHash.toString('hex'))).to.equal(
			true
		);

		// A crash in this window must not re-forward on restart: the linkage
		// row still answers findOutgoingLeg.
		let redispatched = 0;
		(alice as any).handleIncomingHtlc = () => {
			redispatched++;
		};
		inChan.getFullState().htlcs.get('received-7').forwardEmitted = true;
		(alice as any).redispatchUnresolvedReceivedHtlcs(inChannelId);
		expect(redispatched).to.equal(0);

		// Quiescence ends: the owed pass settles upstream and only now
		// consumes the linkage.
		inChan.exitQuiescence();
		(alice as any).channelManager.emit(
			'quiescence:ended',
			inChannelId.toString('hex')
		);
		await new Promise((resolve) => setImmediate(resolve));

		expect(fulfillsSentUpstream).to.equal(1);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);
		const inbound = inChan.getFullState().htlcs.get('received-7');
		expect(
			inbound === undefined || inbound.state === HtlcState.FULFILLED
		).to.equal(true);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('per-block owed pass completes the settle after a quiescence exit that emits no event (issue 569)', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outChannelId, outKey, height } = fx;

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const inChan = (alice as any).channelManager.getChannel(inChannelId);
		const outChan = (alice as any).channelManager.getChannel(outChannelId);
		inChan.getFullState().htlcs.get('received-7').paymentHash = paymentHash;
		outChan.getFullState().htlcs.get('offered-7').paymentHash = paymentHash;

		expect(
			(alice as any).channelManager.initiateQuiescence(inChannelId).ok
		).to.equal(true);
		expect(inChan.isQuiescing()).to.equal(true);

		const UPDATE_FULFILL_HTLC = 130;
		let fulfillsSentUpstream = 0;
		alice.on('message:outbound', (pubkey: string, type: number) => {
			if (pubkey === fx.bob.getNodeId() && type === UPDATE_FULFILL_HTLC)
				fulfillsSentUpstream++;
		});

		(alice as any).channelManager.emit(
			'preimage:learned',
			paymentHash,
			preimage
		);
		expect(fulfillsSentUpstream).to.equal(0);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(true);

		// Terminal-shaped exit: the session ends without 'quiescence:ended'.
		// The per-block invariant keeper must finish the owed settle.
		inChan.exitQuiescence();
		(alice as any).handleNewBlock(height + 1);

		expect(fulfillsSentUpstream).to.equal(1);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);
		const inbound = inChan.getFullState().htlcs.get('received-7');
		expect(
			inbound === undefined || inbound.state === HtlcState.FULFILLED
		).to.equal(true);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('refuses the on-chain-timeout upstream fail while quiescing and keeps the linkage (issue 569)', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outKey, height } = fx;
		const inChan = (alice as any).channelManager.getChannel(inChannelId);

		expect(
			(alice as any).channelManager.initiateQuiescence(inChannelId).ok
		).to.equal(true);
		expect(inChan.isQuiescing()).to.equal(true);

		const UPDATE_FAIL_HTLC = 131;
		let failsSentUpstream = 0;
		alice.on('message:outbound', (pubkey: string, type: number) => {
			if (pubkey === fx.bob.getNodeId() && type === UPDATE_FAIL_HTLC)
				failsSentUpstream++;
		});

		// Irrevocable depth reached while the inbound channel is quiescing:
		// the upstream fail must be refused with the linkage and shared
		// secret intact, not parked in memory around a durable delete.
		(alice as any).channelManager.handleNewBlock(height + 1);
		expect(failsSentUpstream).to.equal(0);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(true);
		expect(inChan.getFullState().htlcs.get('received-7').state).to.equal(
			HtlcState.COMMITTED
		);

		// Terminal-shaped quiescence exit (no event): the per-block owed pass
		// re-derives the fail from the monitor's resolved-without-preimage
		// record and refunds upstream.
		inChan.exitQuiescence();
		(alice as any).handleNewBlock(height + 2);

		expect(failsSentUpstream).to.equal(1);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);
		const inbound = inChan.getFullState().htlcs.get('received-7');
		expect(
			inbound === undefined || inbound.state === HtlcState.FAILED
		).to.equal(true);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('fails only the exact timed-out leg when same-hash MPP parts share the outgoing channel (issue 569)', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outChannelId, outKey, height, paymentHash } =
			fx;
		const inChan = (alice as any).channelManager.getChannel(inChannelId);
		const outChan = (alice as any).channelManager.getChannel(outChannelId);

		// A second forward of the SAME payment hash (an MPP part or a retry)
		// rides the same channels: received-8 upstream, offered-8 downstream,
		// its own linkage row. Only htlc 7's output resolved on-chain; htlc
		// 8's output is unresolved and the downstream can still claim it.
		inChan.getFullState().htlcs.set('received-8', {
			id: 8n,
			amountMsat: 50_000n,
			paymentHash,
			cltvExpiry: height + 40,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.COMMITTED,
			// Already dispatched as a forward, like the linkage row says: keeps
			// the revoke-time incoming-HTLC dispatch from re-decoding the
			// fixture's placeholder onion when leg 7's removal round completes.
			forwardEmitted: true
		});
		outChan.getFullState().htlcs.set('offered-8', {
			id: 8n,
			amountMsat: 49_000n,
			paymentHash,
			cltvExpiry: height - 140,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.OFFERED,
			state: HtlcState.COMMITTED
		});
		const outKey8 = `${outChannelId.toString('hex')}:offered-8`;
		(alice as any).forwardedHtlcs.set(outKey8, {
			inChannelId,
			inHtlcId: 8n
		});
		const monitor = (alice as any).channelManager.monitors.get(
			outChannelId.toString('hex')
		);
		monitor._trackedOutputs[0].status = OutputStatus.IRREVOCABLY_RESOLVED;

		const UPDATE_FAIL_HTLC = 131;
		let failsSentUpstream = 0;
		alice.on('message:outbound', (pubkey: string, type: number) => {
			if (pubkey === fx.bob.getNodeId() && type === UPDATE_FAIL_HTLC)
				failsSentUpstream++;
		});

		(alice as any).settleForwardsOwedUpstream(inChannelId);

		// Exactly leg 7 failed upstream; leg 8 is untouched and its linkage
		// survives, because its output may yet be claimed with the preimage.
		expect(failsSentUpstream).to.equal(1);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);
		expect((alice as any).forwardedHtlcs.has(outKey8)).to.equal(true);
		const inbound8 = inChan.getFullState().htlcs.get('received-8');
		expect(inbound8.state).to.equal(HtlcState.COMMITTED);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('recovers the blinded mid-hop wire form after a restart loses the role map (issue 569)', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outKey, height } = fx;
		const inChan = (alice as any).channelManager.getChannel(inChannelId);

		// Restart shape: the durable HTLC entry still carries the blinding
		// point from update_add_htlc (a MID hop), but the memory-only role
		// map is empty. The failure must still take the BOLT 4 form for a
		// mid hop: update_fail_malformed_htlc with invalid_onion_blinding,
		// never a plain update_fail_htlc that exposes the failure shape.
		inChan.getFullState().htlcs.get('received-7').blindingPoint =
			crypto.randomBytes(33);
		expect((alice as any).blindedIncomingHtlcs.size).to.equal(0);

		const UPDATE_FAIL_HTLC = 131;
		let plainFails = 0;
		alice.on('message:outbound', (pubkey: string, type: number) => {
			if (pubkey === fx.bob.getNodeId() && type === UPDATE_FAIL_HTLC)
				plainFails++;
		});
		const malformedCalls: Array<{ failureCode: number }> = [];
		const realFailMalformed = (
			alice as any
		).channelManager.failMalformedHtlc.bind((alice as any).channelManager);
		(alice as any).channelManager.failMalformedHtlc = (
			channelId: Buffer,
			htlcId: bigint,
			sha256OfOnion: Buffer,
			failureCode: number
		): ReturnType<typeof realFailMalformed> => {
			malformedCalls.push({ failureCode });
			return realFailMalformed(channelId, htlcId, sha256OfOnion, failureCode);
		};

		(alice as any).channelManager.handleNewBlock(height + 1);

		expect(malformedCalls).to.have.length(1);
		expect(malformedCalls[0].failureCode).to.equal(INVALID_ONION_BLINDING);
		expect(plainFails).to.equal(0);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('a refused retry emits no forward-failed events until the fail is actually carried (issue 569)', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outKey, height } = fx;
		const inChan = (alice as any).channelManager.getChannel(inChannelId);

		expect(
			(alice as any).channelManager.initiateQuiescence(inChannelId).ok
		).to.equal(true);
		expect(inChan.isQuiescing()).to.equal(true);

		let failedEvents = 0;
		alice.on('htlc:forward-failed', () => {
			failedEvents++;
		});

		// The on-chain resolution and two per-block owed retries all land
		// while the inbound channel is quiescing: every one is refused, the
		// HTLC stays COMMITTED, and NO failure may be reported for it.
		(alice as any).channelManager.handleNewBlock(height + 1);
		(alice as any).settleForwardsOwedUpstream(inChannelId);
		(alice as any).settleForwardsOwedUpstream(inChannelId);
		expect(failedEvents).to.equal(0);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(true);
		expect(inChan.getFullState().htlcs.get('received-7').state).to.equal(
			HtlcState.COMMITTED
		);

		// Quiescence over: the retry carries the fail and reports it once.
		inChan.exitQuiescence();
		(alice as any).settleForwardsOwedUpstream(inChannelId);
		expect(failedEvents).to.equal(1);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('harvests a preimage stranded in restored monitor state (issue 557)', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, outChannelId, outKey } = fx;

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const inChan = (alice as any).channelManager.getChannel(inChannelId);
		const outChan = (alice as any).channelManager.getChannel(outChannelId);
		inChan.getFullState().htlcs.get('received-7').paymentHash = paymentHash;
		outChan.getFullState().htlcs.get('offered-7').paymentHash = paymentHash;

		// Crash aftermath: the outgoing monitor was persisted with the scanned
		// preimage in knownPreimages (first commit), but the process died before
		// PREIMAGE_LEARNED reached the node's preimage store (second commit).
		// The restored monitor already records the spend, so the re-reported
		// spend and a fresh scan are both suppressed on the next boot.
		const monitor = (alice as any).channelManager.monitors.get(
			outChannelId.toString('hex')
		);
		monitor._trackedOutputs[0].paymentHash = paymentHash;
		monitor._knownPreimages.set(paymentHash.toString('hex'), preimage);

		const UPDATE_FULFILL_HTLC = 130;
		let fulfillsSentUpstream = 0;
		alice.on('message:outbound', (pubkey: string, type: number) => {
			if (pubkey === fx.bob.getNodeId() && type === UPDATE_FULFILL_HTLC)
				fulfillsSentUpstream++;
		});

		// The startup restore path.
		(alice as any).channelManager.restoreMonitor(
			outChannelId.toString('hex'),
			monitor
		);

		// The harvest re-emitted preimage:learned: the preimage reached the
		// node store, the inbound leg settled upstream, and the linkage was
		// consumed. Before the fix nothing recovered the preimage, so the
		// inbound HTLC stayed COMMITTED until it was failed back or timed out.
		expect((alice as any).preimages.has(paymentHash.toString('hex'))).to.equal(
			true
		);
		expect(fulfillsSentUpstream).to.equal(1);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);
		const inbound = inChan.getFullState().htlcs.get('received-7');
		expect(
			inbound === undefined || inbound.state === HtlcState.FULFILLED
		).to.equal(true);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('does not re-emit a harvested preimage the node store already holds (issue 557)', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, outChannelId } = fx;

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();

		// Both commits landed before the restart: the restore path re-records
		// every stored preimage into the manager before monitors are restored.
		(alice as any).preimages.set(paymentHash.toString('hex'), preimage);
		(alice as any).channelManager.recordPreimage(paymentHash, preimage);

		const monitor = (alice as any).channelManager.monitors.get(
			outChannelId.toString('hex')
		);
		monitor._knownPreimages.set(paymentHash.toString('hex'), preimage);

		let learned = 0;
		(alice as any).channelManager.on('preimage:learned', () => learned++);
		(alice as any).channelManager.restoreMonitor(
			outChannelId.toString('hex'),
			monitor
		);

		expect(learned).to.equal(0);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});

	it('leaves the forward alone when the preimage is already known', () => {
		const fx = setupForwardWithResolvingOutgoingLeg();
		const { alice, inChannelId, paymentHash, outKey, height } = fx;

		// Downstream settled: the fulfill path owns the inbound leg. The resolved
		// offered output (e.g. our own second-level success claim) must not
		// trigger an upstream failure.
		(alice as any).preimages.set(
			paymentHash.toString('hex'),
			crypto.randomBytes(32)
		);

		(alice as any).channelManager.handleNewBlock(height + 1);

		const inbound = (alice as any).channelManager
			.getChannel(inChannelId)
			.getFullState()
			.htlcs.get('received-7');
		expect(inbound.state).to.equal(HtlcState.COMMITTED);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(true);

		fx.alice.destroy();
		fx.bob.destroy();
		fx.carol.destroy();
	});
});
