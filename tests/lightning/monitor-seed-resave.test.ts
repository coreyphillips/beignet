/**
 * Seeding a restored chain monitor with the preimages the manager knows
 * saves it only when it learns something or a claim is built. Before, every
 * restored monitor was saved again on every start, whatever it held.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import { ChainActionType } from '../../src/lightning/chain/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`monitor-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
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
		firstPerCommitmentPoint: getPublicKey(keys[5])
	};
}

function makeManager(id: number): ChannelManager {
	const cfg: IChannelManagerConfig = {
		localBasepoints: makeBasepoints(makeSeed(id)),
		localPerCommitmentSeed: makeSeed(100 + id),
		localFundingPrivkey: makeSeed(200 + id)
	};
	const cm = new ChannelManager(cfg);
	cm.on('error', () => {});
	return cm;
}

function makePreimage(): { hash: Buffer; preimage: Buffer } {
	const preimage = crypto.randomBytes(32);
	return {
		preimage,
		hash: crypto.createHash('sha256').update(preimage).digest()
	};
}

/** A restored monitor holding `held`, as the real ChainMonitor keeps them. */
function holding(
	held: Map<string, Buffer>,
	actions: () => unknown[] = () => []
): ChainMonitor {
	return {
		getKnownPreimages: () => held,
		addPreimage: (hash: Buffer, preimage: Buffer): unknown[] => {
			held.set(hash.toString('hex'), preimage);
			return actions();
		}
	} as unknown as ChainMonitor;
}

function savesOf(cm: ChannelManager): string[] {
	const saved: string[] = [];
	cm.on('monitor:updated', (channelIdHex: string) => saved.push(channelIdHex));
	return saved;
}

describe('ChannelManager: seeding a restored monitor', function () {
	it('does not save a monitor that already holds every known preimage', function () {
		const cm = makeManager(1);
		const a = makePreimage();
		const b = makePreimage();
		cm.recordPreimage(a.hash, a.preimage);
		cm.recordPreimage(b.hash, b.preimage);
		const saved = savesOf(cm);

		const held = new Map([
			[a.hash.toString('hex'), a.preimage],
			[b.hash.toString('hex'), b.preimage]
		]);
		cm.restoreMonitor('aa'.repeat(32), holding(held));

		expect(saved).to.deep.equal([]);
		expect(held.size).to.equal(2);
	});

	it('saves a monitor that learns a preimage it did not hold', function () {
		const cm = makeManager(2);
		const a = makePreimage();
		const b = makePreimage();
		cm.recordPreimage(a.hash, a.preimage);
		cm.recordPreimage(b.hash, b.preimage);
		const saved = savesOf(cm);

		const held = new Map([[a.hash.toString('hex'), a.preimage]]);
		cm.restoreMonitor('bb'.repeat(32), holding(held));

		expect(saved).to.deep.equal(['bb'.repeat(32)]);
		expect(held.get(b.hash.toString('hex'))?.equals(b.preimage)).to.equal(true);
	});

	it('saves a monitor whose preimage for a hash differs from the known one', function () {
		const cm = makeManager(3);
		const a = makePreimage();
		cm.recordPreimage(a.hash, a.preimage);
		const saved = savesOf(cm);

		const held = new Map([[a.hash.toString('hex'), crypto.randomBytes(32)]]);
		cm.restoreMonitor('cc'.repeat(32), holding(held));

		expect(saved).to.deep.equal(['cc'.repeat(32)]);
		expect(held.get(a.hash.toString('hex'))?.equals(a.preimage)).to.equal(true);
	});

	it('saves and routes a claim built from preimages the monitor already held', function () {
		const cm = makeManager(4);
		const a = makePreimage();
		cm.recordPreimage(a.hash, a.preimage);
		const saved = savesOf(cm);
		const tx = Buffer.from('c0ffee', 'hex');
		const broadcasts: Buffer[] = [];
		cm.on('broadcast:tx', (sent: Buffer) => broadcasts.push(sent));

		const held = new Map([[a.hash.toString('hex'), a.preimage]]);
		cm.restoreMonitor(
			'dd'.repeat(32),
			holding(held, () => [{ type: ChainActionType.BROADCAST_TX, tx }])
		);

		// Saved before routing, and again after, as before.
		expect(saved).to.deep.equal(['dd'.repeat(32), 'dd'.repeat(32)]);
		expect(broadcasts).to.deep.equal([tx]);
	});

	it('saves a monitor that cannot say what it holds, as before', function () {
		const cm = makeManager(5);
		const a = makePreimage();
		cm.recordPreimage(a.hash, a.preimage);
		const saved = savesOf(cm);

		const legacy = {
			addPreimage: (): unknown[] => []
		} as unknown as ChainMonitor;
		cm.restoreMonitor('ee'.repeat(32), legacy);

		expect(saved).to.deep.equal(['ee'.repeat(32)]);
	});

	it('saves nothing when no preimage is known', function () {
		const cm = makeManager(6);
		const saved = savesOf(cm);
		cm.restoreMonitor('ff'.repeat(32), holding(new Map()));
		expect(saved).to.deep.equal([]);
	});
});
