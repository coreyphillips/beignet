/**
 * Regression tests for security finding C4 — preimage → ChainMonitor wiring.
 *
 * The single-payment receive path (fulfillPayment) correctly delivers learned
 * preimages to the chain monitors via ChannelManager.recordPreimage, so a
 * received HTLC can still be swept on-chain if the channel force-closes during
 * settlement. Two other settle paths previously did NOT:
 *
 *   1. MPP receive completion (handleMppPart) — fulfilled each part but never
 *      recorded the preimage.
 *   2. HTLC forwarding (handleHtlcFulfilled, forwarded branch) — learned the
 *      preimage from the downstream fulfill and propagated it upstream, but
 *      never recorded it for the incoming channel.
 *
 * In both cases, a force-close in the settle window would leave the monitor
 * without the preimage, and the counterparty reclaims the value via timeout —
 * a direct loss of funds. These tests drive the two completion paths and assert
 * the preimage reaches every chain monitor (and the retained preimage store that
 * seeds monitors created later, e.g. on force-close). They fail without the fix.
 *
 * The downstream "recordPreimage → on-chain HTLC-success sweep" behaviour itself
 * is already covered by chain-monitor.test.ts; here we only verify the wiring.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
	};
}

function makeNode(): LightningNode {
	const node = new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		perCommitmentSeed: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(),
		fundingPrivkey: crypto.randomBytes(32)
	});
	node.on('error', () => {});
	return node;
}

/**
 * A minimal stand-in for a ChainMonitor that records every addPreimage call so
 * we can assert the settle paths fan the preimage out to the monitors. Returns
 * no chain actions so ChannelManager.processChainActions is a no-op.
 */
function installFakeMonitor(node: LightningNode): {
	channelId: Buffer;
	calls: Array<{ hash: string; preimage: string }>;
} {
	const calls: Array<{ hash: string; preimage: string }> = [];
	const channelId = crypto.randomBytes(32);
	const fakeMonitor = {
		addPreimage(hash: Buffer, preimage: Buffer): unknown[] {
			calls.push({
				hash: hash.toString('hex'),
				preimage: preimage.toString('hex')
			});
			return [];
		}
	};
	const cm = node.getChannelManager() as unknown as {
		monitors: Map<string, unknown>;
		fulfillHtlc: (...args: unknown[]) => void;
	};
	cm.monitors.set(channelId.toString('hex'), fakeMonitor);
	// Stub fulfillHtlc — the settle paths call it after recordPreimage; we only
	// care about the preimage wiring, not the (absent) real channel.
	cm.fulfillHtlc = () => {};
	return { channelId, calls };
}

describe('C4 regression: preimage → ChainMonitor wiring', function () {
	it('records the preimage to monitors when an MPP payment completes', function () {
		const node = makeNode();
		const { calls } = installFakeMonitor(node);

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto
			.createHash('sha256')
			.update(preimage)
			.digest();
		const paymentSecret = crypto.randomBytes(32);
		const totalMsat = 1000n;

		const part1Channel = crypto.randomBytes(32);
		const part2Channel = crypto.randomBytes(32);
		const hopPayload = {
			amountToForwardMsat: 600n,
			outgoingCltvValue: 500,
			paymentSecret,
			totalMsat
		};

		const internal = node as unknown as {
			handleMppPart: (
				channelId: Buffer,
				htlcId: bigint,
				amountMsat: bigint,
				paymentHash: Buffer,
				hopPayload: unknown,
				preimage: Buffer
			) => void;
		};

		// First part — not enough yet, must not complete (and must not record).
		internal.handleMppPart(part1Channel, 0n, 600n, paymentHash, hopPayload, preimage);
		expect(calls.length, 'no preimage recorded before MPP completes').to.equal(0);

		// Second part — total now exceeds totalMsat, payment completes.
		internal.handleMppPart(part2Channel, 0n, 600n, paymentHash, hopPayload, preimage);

		expect(calls.length, 'preimage must be delivered to the monitor').to.be.greaterThan(0);
		expect(calls[0].hash).to.equal(paymentHash.toString('hex'));
		expect(calls[0].preimage).to.equal(preimage.toString('hex'));

		// Retained store seeds monitors created later (e.g. on force-close).
		const cm = node.getChannelManager() as unknown as {
			_knownPreimages: Map<string, Buffer>;
		};
		expect(cm._knownPreimages.get(paymentHash.toString('hex'))).to.deep.equal(
			preimage
		);

		node.destroy();
	});

	it('records the preimage to monitors when a forwarded HTLC is fulfilled', function () {
		const node = makeNode();
		const { calls } = installFakeMonitor(node);

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto
			.createHash('sha256')
			.update(preimage)
			.digest();

		const outChannelId = crypto.randomBytes(32);
		const outHtlcId = 7n;
		const inChannelId = crypto.randomBytes(32);
		const inHtlcId = 3n;

		// Register the forward mapping the downstream fulfill will match.
		const internal = node as unknown as {
			forwardedHtlcs: Map<
				string,
				{ inChannelId: Buffer; inHtlcId: bigint }
			>;
			handleHtlcFulfilled: (
				channelId: Buffer,
				htlcId: bigint,
				preimage: Buffer
			) => void;
		};
		const outKey = `${outChannelId.toString('hex')}:offered-${outHtlcId}`;
		internal.forwardedHtlcs.set(outKey, { inChannelId, inHtlcId });

		// Downstream peer fulfills our offered HTLC — we learn the preimage and
		// must record it against the incoming channel before settling upstream.
		internal.handleHtlcFulfilled(outChannelId, outHtlcId, preimage);

		expect(
			calls.length,
			'forwarded preimage must be delivered to the monitor'
		).to.be.greaterThan(0);
		expect(calls[0].hash).to.equal(paymentHash.toString('hex'));
		expect(calls[0].preimage).to.equal(preimage.toString('hex'));

		const cm = node.getChannelManager() as unknown as {
			_knownPreimages: Map<string, Buffer>;
		};
		expect(cm._knownPreimages.get(paymentHash.toString('hex'))).to.deep.equal(
			preimage
		);

		node.destroy();
	});
});
