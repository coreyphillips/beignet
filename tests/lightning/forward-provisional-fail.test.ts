/**
 * A FAILED outgoing leg is only terminal once its removal round is (issue
 * #590).
 *
 * handleUpdateFailHtlc sets HtlcState.FAILED with both removal phase flags
 * false, and the settlement loop DELETES the entry the moment the removal
 * becomes irrevocable — so a FAILED entry still in the map is a removal in
 * flight, not a finished one. Reading the state alone let every refund path
 * (the owed-fail reconciliation and both expiry scanners) fail the inbound
 * leg upstream while the downstream could still claim: a disconnect rolls
 * the leg back to COMMITTED, the peer retransmits a fulfill (or publishes
 * the commitment that still carries the offered output and claims with an
 * HTLC-success), and the late preimage is then unusable upstream because
 * canFulfillHtlc refuses a FAILED entry. We would pay B and refund A for one
 * forward.
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
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`fwd-provisional-fail-${id}`))
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
	carol: LightningNode;
	inChannelId: Buffer;
	outChannelId: Buffer;
	outKey: string;
	preimage: Buffer;
	paymentHash: Buffer;
	inHtlcs: Map<string, IHtlcEntry>;
	outHtlcs: Map<string, IHtlcEntry>;
	/** Every failHtlc the node asked the manager for, in order. */
	failed: Array<{ channelId: string; htlcId: bigint }>;
	forceClosed: Buffer[];
	destroy: () => void;
}

/**
 * Alice forwards Bob -> Carol, with the outgoing leg sitting in whichever
 * removal phase the caller names. `removal: 'none'` is the exact state
 * handleUpdateFailHtlc leaves behind; `undefined` flags are the legacy
 * "already committed" encoding a pre-two-phase state carries.
 */
function makeForward(
	seedBase: number,
	removal: 'none' | 'locally-revoked' | 'legacy'
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

	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	const inHtlcs: Map<string, IHtlcEntry> = a.channelManager
		.getChannel(inChannelId)
		.getFullState().htlcs;
	inHtlcs.set('received-7', {
		id: 7n,
		amountMsat: 50_000n,
		paymentHash,
		// Inside the narrow margin (6), so both expiry scanners reach it.
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
		cltvExpiry: HEIGHT + 500,
		onionRoutingPacket: Buffer.alloc(1366),
		direction: HtlcDirection.OFFERED,
		state: HtlcState.FAILED,
		...(removal === 'none'
			? { removalLocallyRevoked: false, removalRemoteCommitted: false }
			: {}),
		...(removal === 'locally-revoked'
			? { removalLocallyRevoked: true, removalRemoteCommitted: false }
			: {})
	});

	const outKey = `${outChannelId.toString('hex')}:offered-7`;
	a.forwardedHtlcs.set(outKey, { inChannelId, inHtlcId: 7n });

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
		carol,
		inChannelId,
		outChannelId,
		outKey,
		preimage,
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

const linkageHeld = (f: IForwardFixture): boolean =>
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(f.alice as any).forwardedHtlcs.has(f.outKey);

// ─── Tests ───

describe('Provisional FAILED outgoing legs (issue #590)', function () {
	this.timeout(10_000);

	it('the owed-fail pass leaves an unfinished removal alone', function () {
		const f = makeForward(400, 'none');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).settleForwardsOwedUpstream(f.inChannelId);

		expect(failedInbound(f), 'inbound never refunded upstream').to.equal(false);
		expect(f.inHtlcs.get('received-7')!.state).to.equal(HtlcState.COMMITTED);
		expect(linkageHeld(f), 'linkage retained').to.equal(true);
		f.destroy();
	});

	it('a removal we revoked for but the peer has not is still unfinished', function () {
		// The second phase: our own commitments no longer carry the HTLC, but
		// the last commitment WE signed for the peer still does and the peer
		// has not revoked it, so an HTLC-success can still spend it.
		const f = makeForward(410, 'locally-revoked');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).settleForwardsOwedUpstream(f.inChannelId);

		expect(failedInbound(f), 'inbound never refunded upstream').to.equal(false);
		expect(linkageHeld(f), 'linkage retained').to.equal(true);
		f.destroy();
	});

	it('a legacy FAILED entry with no removal flags still refunds upstream', function () {
		// Absent flags mean "already committed/revoked" (the pre-two-phase
		// encoding), so the refund is owed and must not be held back.
		const f = makeForward(420, 'legacy');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).settleForwardsOwedUpstream(f.inChannelId);

		expect(failedInbound(f), 'inbound refunded upstream').to.equal(true);
		expect(linkageHeld(f), 'linkage consumed').to.equal(false);
		f.destroy();
	});

	it('a disconnect rollback then a late on-chain preimage still pays upstream', function () {
		// The whole issue in one run: refund the inbound here and the rollback
		// below would leave us paying downstream for a forward we already
		// refunded.
		const f = makeForward(430, 'none');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = f.alice as any;
		a.settleForwardsOwedUpstream(f.inChannelId);
		expect(failedInbound(f)).to.equal(false);

		// Carol drops before the removal round completes: markForReestablish
		// restores the leg it never committed.
		a.channelManager.handlePeerDisconnected(f.carol.getNodeId());
		expect(f.outHtlcs.get('offered-7')!.state).to.equal(HtlcState.COMMITTED);

		// Carol claims on chain instead, revealing the preimage.
		a.handleOnChainPreimageLearned(f.paymentHash, f.preimage);

		expect(f.inHtlcs.get('received-7')!.state).to.equal(HtlcState.FULFILLED);
		expect(linkageHeld(f), 'linkage consumed by the fulfill').to.equal(false);
		f.destroy();
	});

	it('scanExpiringHtlcs force-closes the inbound instead of refunding', function () {
		const f = makeForward(440, 'none');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanExpiringHtlcs(HEIGHT + 1);

		expect(failedInbound(f), 'inbound never refunded upstream').to.equal(false);
		expect(forceClosedInbound(f), 'inbound force-closed instead').to.equal(
			true
		);
		expect(linkageHeld(f), 'linkage retained').to.equal(true);
		f.destroy();
	});

	it('scanForwardTimeouts force-closes the inbound instead of refunding', function () {
		const f = makeForward(450, 'none');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanForwardTimeouts(HEIGHT + 1);

		expect(failedInbound(f), 'inbound never refunded upstream').to.equal(false);
		expect(forceClosedInbound(f), 'inbound force-closed instead').to.equal(
			true
		);
		expect(linkageHeld(f), 'linkage retained').to.equal(true);
		f.destroy();
	});
});
