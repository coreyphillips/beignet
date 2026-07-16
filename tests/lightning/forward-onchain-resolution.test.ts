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
		): void => {
			malformedCalls.push({ failureCode });
			realFailMalformed(channelId, htlcId, sha256OfOnion, failureCode);
		};

		(alice as any).channelManager.handleNewBlock(height + 1);

		expect(malformedCalls).to.have.length(1);
		expect(malformedCalls[0].failureCode).to.equal(INVALID_ONION_BLINDING);
		expect((alice as any).forwardedHtlcs.has(outKey)).to.equal(false);

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
