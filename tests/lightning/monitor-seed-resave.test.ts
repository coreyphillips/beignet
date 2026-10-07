/**
 * Seeding skips redundant saves only for fully resolved monitors that
 * already hold every known preimage. Active monitors can build held claims
 * without returning actions, so they retain their existing save behavior.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	ChainActionType,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { buildRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { setupNormalChannels } from './helpers/revoked-commitment-fixture';

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
	actions: () => unknown[] = () => [],
	fullyResolved = true
): ChainMonitor {
	return {
		getKnownPreimages: () => held,
		isFullyResolved: () => fullyResolved,
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
	it('does not save a fully resolved monitor that already holds every known preimage', function () {
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

	it('still saves an active monitor that already holds every known preimage', function () {
		const cm = makeManager(7);
		const a = makePreimage();
		cm.recordPreimage(a.hash, a.preimage);
		const saved = savesOf(cm);
		const held = new Map([[a.hash.toString('hex'), a.preimage]]);
		cm.restoreMonitor(
			'ab'.repeat(32),
			holding(held, () => [], false)
		);
		expect(saved).to.deep.equal(['ab'.repeat(32)]);
	});

	it('saves a restored anchor HTLC claim held for CSV maturity without an action', function () {
		const { opener, openerPrivkeys: keys } = setupNormalChannels();
		const { hash, preimage } = makePreimage();
		const channelId = opener.getChannelId()!;
		opener.handleUpdateAddHtlc({
			channelId,
			id: 0n,
			amountMsat: 50_000_000n,
			paymentHash: hash,
			cltvExpiry: 120,
			onionRoutingPacket: Buffer.alloc(1366)
		});
		const state = opener.getFullState();
		for (const entry of state.htlcs.values()) entry.addLocallyRevoked = true;
		const flags = FeatureFlags.empty();
		flags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
		state.channelType = flags.toBuffer();
		const commitment = buildRemoteCommitment(
			state,
			state.remoteCurrentPerCommitmentPoint!
		).result.tx;
		const network = bitcoin.networks.regtest;
		const destination = bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(keys[0]),
			network
		}).output!;
		// The preimage is durable, but a fee spike prevented building the claim.
		const monitor = new ChainMonitor(
			state,
			destination,
			1000,
			keys[1],
			keys[2],
			network,
			keys[3],
			keys[4]
		);
		monitor.addPreimage(hash, preimage);
		monitor.handleFundingSpent(commitment, 100);
		const stored = monitor.getFullState();
		expect(stored.knownPreimages![hash.toString('hex')]).to.equal(
			preimage.toString('hex')
		);
		expect(
			stored.trackedOutputs.find(
				(o) => o.outputType === OutputType.RECEIVED_HTLC
			)?.sweepTxHex
		).to.equal(undefined);

		// At the startup fee the claim becomes economic, but its CSV is not mature.
		const restored = ChainMonitor.restore(
			stored,
			state,
			destination,
			10,
			keys[1],
			keys[2],
			network,
			keys[3],
			keys[4]
		);
		const cm = makeManager(8);
		cm.recordPreimage(hash, preimage);
		const saved = savesOf(cm);
		const broadcasts: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
		cm.restoreMonitor(channelId.toString('hex'), restored);

		const held = restored
			.getTrackedOutputs()
			.find((o) => o.outputType === OutputType.RECEIVED_HTLC)!;
		expect(held.sweepTxHex).to.be.a('string');
		expect(held.maturityHeight).to.equal(101);
		expect(held.status).to.equal(OutputStatus.CONFIRMED);
		expect(broadcasts).to.deep.equal([]);
		expect(saved).to.deep.equal([channelId.toString('hex')]);
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

	it('saves a monitor that cannot report whether it is fully resolved', function () {
		const cm = makeManager(9);
		const a = makePreimage();
		cm.recordPreimage(a.hash, a.preimage);
		const saved = savesOf(cm);
		const legacy = {
			getKnownPreimages: () => new Map([[a.hash.toString('hex'), a.preimage]]),
			addPreimage: (): unknown[] => []
		} as unknown as ChainMonitor;
		cm.restoreMonitor('ef'.repeat(32), legacy);
		expect(saved).to.deep.equal(['ef'.repeat(32)]);
	});

	it('saves nothing when no preimage is known', function () {
		const cm = makeManager(6);
		const saved = savesOf(cm);
		cm.restoreMonitor(
			'ff'.repeat(32),
			holding(new Map(), () => [], false)
		);
		expect(saved).to.deep.equal([]);
	});
});
