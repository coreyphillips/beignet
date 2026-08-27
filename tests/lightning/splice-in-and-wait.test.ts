/**
 * LightningNode.spliceInAndWait (issue #572): resolves on splice:complete
 * for the channel, rejects on a SPLICE_IN_FAILED node error scoped to it or
 * on timeout, and throws when spliceIn refuses synchronously. The listeners
 * are registered BEFORE spliceIn runs so a synchronous completion cannot be
 * lost, and every settle path removes them.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ILightningError } from '../../src/lightning/node/types';

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

function createTestNode(): LightningNode {
	const seed = crypto
		.createHash('sha256')
		.update('splice-in-and-wait-node')
		.digest();
	const node = new LightningNode({
		nodePrivateKey: crypto
			.createHash('sha256')
			.update('splice-in-and-wait-priv')
			.digest(),
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		network: Network.REGTEST
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/** Replace spliceIn with a recording stub returning a fixed result. */
function stubSpliceIn(
	node: LightningNode,
	result: { ok: boolean; error?: string }
): Array<{ channelId: Buffer; amountSats: bigint; feeratePerKw: number }> {
	const calls: Array<{
		channelId: Buffer;
		amountSats: bigint;
		feeratePerKw: number;
	}> = [];
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(node as any).spliceIn = (
		channelId: Buffer,
		amountSats: bigint,
		feeratePerKw = 253
	): { ok: boolean; error?: string } => {
		calls.push({ channelId, amountSats, feeratePerKw });
		return result;
	};
	return calls;
}

function waitListenerCount(node: LightningNode): number {
	return (
		node.listenerCount('splice:complete') + node.listenerCount('node:error')
	);
}

describe('LightningNode.spliceInAndWait (issue #572)', function () {
	this.timeout(10_000);

	it('resolves on splice:complete for the channel and ignores other ids', async function () {
		const node = createTestNode();
		const baseline = waitListenerCount(node);
		const channelId = crypto.randomBytes(32);
		const calls = stubSpliceIn(node, { ok: true });

		const wait = node.spliceInAndWait(channelId, 50_000n, 5_000, 300);
		// Another channel's completion must not settle this wait.
		node.emit('splice:complete', {
			channelId: crypto.randomBytes(32),
			fundingTxid: crypto.randomBytes(32)
		});
		node.emit('splice:complete', {
			channelId,
			fundingTxid: crypto.randomBytes(32)
		});
		await wait;

		expect(calls).to.have.length(1);
		expect(calls[0].channelId.equals(channelId)).to.equal(true);
		expect(calls[0].feeratePerKw).to.equal(300);
		expect(waitListenerCount(node), 'listeners removed').to.equal(baseline);
		node.destroy();
	});

	it('rejects on a SPLICE_IN_FAILED scoped to the channel', async function () {
		const node = createTestNode();
		const baseline = waitListenerCount(node);
		const channelId = crypto.randomBytes(32);
		stubSpliceIn(node, { ok: true });

		const wait = node.spliceInAndWait(channelId, 50_000n);
		// A different channel's failure and an unrelated error code pass by.
		node.emit('node:error', {
			code: 'SPLICE_IN_FAILED',
			channelId: crypto.randomBytes(32),
			message: 'someone else',
			timestamp: Date.now()
		} as ILightningError);
		node.emit('node:error', {
			code: 'CHANNEL_ERROR',
			channelId,
			message: 'unrelated',
			timestamp: Date.now()
		} as ILightningError);
		node.emit('node:error', {
			code: 'SPLICE_IN_FAILED',
			channelId,
			message: 'wallet selection failed',
			timestamp: Date.now()
		} as ILightningError);

		let error = '';
		try {
			await wait;
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal('wallet selection failed');
		expect(waitListenerCount(node), 'listeners removed').to.equal(baseline);
		node.destroy();
	});

	it('throws when spliceIn refuses synchronously, leaving nothing armed', async function () {
		const node = createTestNode();
		const baseline = waitListenerCount(node);
		const channelId = crypto.randomBytes(32);
		stubSpliceIn(node, { ok: false, error: 'Channel not found' });

		let error = '';
		try {
			await node.spliceInAndWait(channelId, 50_000n);
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal('Channel not found');
		expect(waitListenerCount(node), 'no leaked listeners').to.equal(baseline);
		node.destroy();
	});

	it('rejects on timeout', async function () {
		const node = createTestNode();
		const channelId = crypto.randomBytes(32);
		stubSpliceIn(node, { ok: true });

		let error = '';
		try {
			await node.spliceInAndWait(channelId, 50_000n, 100);
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.match(/not locked within 100ms/);
		node.destroy();
	});
});
