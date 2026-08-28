/**
 * A forwarded inbound HTLC is never failed off-chain on time alone, however
 * the expiry is noticed (issue #575).
 *
 * scanForwardTimeouts applies the BOLT 2 rule at twice the safety margin and
 * normally settles a forward before the narrower scanExpiringHtlcs sees it,
 * but that ordering only holds when blocks arrive one at a time. A node
 * offline across the window between the two thresholds catches up in a
 * single handleNewBlock past both, and the restore-time scan used to run the
 * narrow scanner with no forward scan in the same pass at all. Either way
 * scanExpiringHtlcs reached a live forward and failed it upstream on time
 * alone, which is unrecoverable: the FAILED entry hides the forward from
 * scanForwardTimeouts (so the inbound is never force-closed) AND makes the
 * late downstream preimage unusable upstream (canFulfillHtlc refuses a
 * FAILED entry), so we pay downstream and refund upstream for one forward.
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

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`fwd-expiry-${id}`))
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
		// Pinned so the two thresholds (6 and 12 blocks) are explicit here.
		htlcSafetyMargin: 6
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	node.on('node:error', () => {});
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
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

const HEIGHT = 800_000;

interface IForwardFixture {
	alice: LightningNode;
	bob: LightningNode;
	carol: LightningNode;
	inChannelId: Buffer;
	outChannelId: Buffer;
	outKey: string;
	paymentHash: Buffer;
	inHtlcs: Map<string, IHtlcEntry>;
	outHtlcs: Map<string, IHtlcEntry>;
	/** Every failHtlc the node asked the manager for, in order. */
	failed: Array<{ channelId: string; htlcId: bigint }>;
	forceClosed: Buffer[];
	destroy: () => void;
}

/**
 * Alice forwards Bob -> Carol: an inbound received HTLC whose expiry is
 * already inside the narrow margin, a live outbound offered HTLC, and the
 * linkage row between them.
 */
function makeForward(
	seedBase: number,
	opts?: {
		outboundState?: HtlcState;
		linkage?: boolean;
		/** Drop the outgoing entry, as a completed removal round does. */
		outboundGone?: boolean;
		/** Give the outgoing channel a monitor with a timed-out HTLC output. */
		outboundTimedOutOnChain?: boolean;
		/** Record the forward's preimage before the scan runs. */
		preimageKnown?: boolean;
	}
): IForwardFixture {
	const alice = createNode(seedBase); // forwarder
	const bob = createNode(seedBase + 1); // upstream (inbound)
	const carol = createNode(seedBase + 2); // downstream (outbound)
	connectNodes(alice, bob);
	connectNodes(alice, carol);
	const inChannelId = openReadyChannel(alice, bob);
	const outChannelId = openReadyChannel(alice, carol);

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const a = alice as any;
	a.currentBlockHeight = HEIGHT;

	const paymentHash = crypto.randomBytes(32);
	const inHtlcs: Map<string, IHtlcEntry> = a.channelManager
		.getChannel(inChannelId)
		.getFullState().htlcs;
	inHtlcs.set('received-7', {
		id: 7n,
		amountMsat: 50_000n,
		paymentHash,
		// Inside the narrow margin (6): the arm under test.
		cltvExpiry: HEIGHT + 5,
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
		// Well beyond any expiry scan, so the outbound leg stays live and
		// only the inbound arm under test can act.
		cltvExpiry: HEIGHT + 500,
		onionRoutingPacket: Buffer.alloc(1366),
		direction: HtlcDirection.OFFERED,
		state: opts?.outboundState ?? HtlcState.COMMITTED
	});

	if (opts?.outboundGone) outHtlcs.delete('offered-7');

	if (opts?.outboundTimedOutOnChain) {
		// Outgoing channel force-closed and our HTLC-timeout claim is buried:
		// the durable proof that the downstream can never claim.
		const outState = a.channelManager.getChannel(outChannelId).getFullState();
		const monitor = new ChainMonitor(
			outState,
			Buffer.alloc(22),
			1,
			crypto.randomBytes(32),
			crypto.randomBytes(32)
		);
		monitor._state = MonitorState.RESOLVING;
		monitor._trackedOutputs = [
			{
				txid: crypto.randomBytes(32).toString('hex'),
				outputIndex: 0,
				amount: 49n,
				outputType: OutputType.OFFERED_HTLC,
				status: OutputStatus.IRREVOCABLY_RESOLVED,
				confirmationHeight: HEIGHT - 100,
				paymentHash,
				htlcId: 7n,
				resolutionTxid: crypto.randomBytes(32).toString('hex')
			}
		];
		a.channelManager.monitors.set(outChannelId.toString('hex'), monitor);
	}

	if (opts?.preimageKnown) {
		a.preimages.set(paymentHash.toString('hex'), crypto.randomBytes(32));
	}

	const outKey = `${outChannelId.toString('hex')}:offered-7`;
	if (opts?.linkage !== false) {
		a.forwardedHtlcs.set(outKey, { inChannelId, inHtlcId: 7n });
	}

	const failed: Array<{ channelId: string; htlcId: bigint }> = [];
	const realFail = a.channelManager.failHtlc.bind(a.channelManager);
	a.channelManager.failHtlc = (
		channelId: Buffer,
		htlcId: bigint,
		reason: Buffer
	): unknown => {
		failed.push({ channelId: channelId.toString('hex'), htlcId });
		return realFail(channelId, htlcId, reason);
	};

	const forceClosed: Buffer[] = [];
	alice.on('node:error', (err: { code: string; channelId?: Buffer }) => {
		if (err.code === 'FORWARD_TIMEOUT_FORCE_CLOSE' && err.channelId) {
			forceClosed.push(err.channelId);
		}
	});

	return {
		alice,
		bob,
		carol,
		inChannelId,
		outChannelId,
		outKey,
		paymentHash,
		inHtlcs,
		outHtlcs,
		failed,
		forceClosed,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
			carol.destroy();
		}
	};
}

const failedInbound = (f: IForwardFixture): boolean =>
	f.failed.some(
		(c) => c.channelId === f.inChannelId.toString('hex') && c.htlcId === 7n
	);

const forceClosedInbound = (f: IForwardFixture): boolean =>
	f.forceClosed.some((id) => id.equals(f.inChannelId));

// ─── Tests ───

describe('Forwarded inbound expiry on a catch-up block jump (issue #575)', function () {
	this.timeout(10_000);

	it('force-closes instead of failing upstream when the whole window is skipped', function () {
		const f = makeForward(300);
		// Offline below the wide threshold, then one block past the narrow
		// one: exactly the production shape, and the ordering in which the
		// forward scan never gets a chance to act first.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).currentBlockHeight = HEIGHT - 20;
		f.alice.handleNewBlock(HEIGHT + 1);

		expect(failedInbound(f), 'inbound never refunded upstream').to.equal(false);
		expect(f.inHtlcs.get('received-7')!.state).to.not.equal(HtlcState.FAILED);
		expect(forceClosedInbound(f), 'inbound force-closed instead').to.equal(
			true
		);
		// The linkage survives so a late downstream settlement can still be
		// carried upstream on chain.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((f.alice as any).forwardedHtlcs.has(f.outKey)).to.equal(true);
		f.destroy();
	});

	it('applies the same rule when the narrow scan runs alone (restore path)', function () {
		// The restore-time scan calls this scanner directly; before the fix no
		// forward scan ran in that pass at all.
		const f = makeForward(310);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanExpiringHtlcs(HEIGHT + 1);

		expect(failedInbound(f)).to.equal(false);
		expect(forceClosedInbound(f)).to.equal(true);
		f.destroy();
	});

	it('a blinded forward is gated too, before the blinded fail-back', function () {
		const f = makeForward(320);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = f.alice as any;
		let blindedFails = 0;
		a.blindedRoleFor = (): string => 'mid';
		a.failBlindedIncomingHtlc = (): void => {
			blindedFails++;
		};
		a.scanExpiringHtlcs(HEIGHT + 1);

		expect(blindedFails, 'blinded fail-back never reached').to.equal(0);
		expect(forceClosedInbound(f)).to.equal(true);
		f.destroy();
	});

	it('still fails upstream once the outbound leg is terminally FAILED', function () {
		// The refund is owed exactly then: we owe the downstream nothing.
		const f = makeForward(330, { outboundState: HtlcState.FAILED });
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanExpiringHtlcs(HEIGHT + 1);

		expect(failedInbound(f), 'inbound refunded upstream').to.equal(true);
		expect(forceClosedInbound(f), 'no force-close needed').to.equal(false);
		f.destroy();
	});

	it('still fails upstream when the outbound entry is gone from a live channel', function () {
		// The shape settleForwardsOwedUpstream reconciles later in the same
		// block: the downstream fail completed its removal round but the fail
		// owed upstream never became durable. Force-closing here would burn a
		// usable channel minutes before the reconciliation refunds it.
		const f = makeForward(350, { outboundGone: true });
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).currentBlockHeight = HEIGHT - 20;
		f.alice.handleNewBlock(HEIGHT + 1);

		expect(failedInbound(f), 'inbound refunded upstream').to.equal(true);
		expect(forceClosedInbound(f), 'no force-close needed').to.equal(false);
		f.destroy();
	});

	it('still fails upstream when the outbound leg timed out on chain', function () {
		// The on-chain form of the same durable failure (issue 569).
		const f = makeForward(360, {
			outboundGone: true,
			outboundTimedOutOnChain: true
		});
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanExpiringHtlcs(HEIGHT + 1);

		expect(failedInbound(f), 'inbound refunded upstream').to.equal(true);
		expect(forceClosedInbound(f), 'no force-close needed').to.equal(false);
		f.destroy();
	});

	it('never reads an absent outbound leg as failed while we hold its preimage', function () {
		// Absence means "failed" only because a fulfill would have made the
		// preimage durable first. Holding one inverts that: the downstream was
		// paid, so refunding upstream is the double-pay the rule exists to
		// prevent. Driven through the forward scan, whose refund arm is the one
		// the inference can reach.
		const f = makeForward(370, { outboundGone: true, preimageKnown: true });
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanForwardTimeouts(HEIGHT + 1);

		expect(failedInbound(f), 'inbound never refunded upstream').to.equal(false);
		expect(forceClosedInbound(f), 'resolved on chain instead').to.equal(true);
		f.destroy();
	});

	it('leaves a non-forwarded received HTLC on the ordinary off-chain path', function () {
		const f = makeForward(340, { linkage: false });
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanExpiringHtlcs(HEIGHT + 1);

		expect(failedInbound(f), 'plain inbound still failed on time').to.equal(
			true
		);
		expect(forceClosedInbound(f)).to.equal(false);
		f.destroy();
	});
});
