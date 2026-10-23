/**
 * A chain monitor stores, and is saved for, only the preimages of its own
 * channel's HTLCs. Every recorded preimage used to go into every monitor the
 * node had, each saved alone, so each settled HTLC cost one write per monitor
 * of a map holding every preimage the node had ever learned.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChainMonitor,
	IChainMonitorState
} from '../../src/lightning/chain/chain-monitor';
import {
	ITrackedOutput,
	MonitorState,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { Channel } from '../../src/lightning/channel/channel';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { buildRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { setupNormalChannels } from './helpers/revoked-commitment-fixture';
import { COMMIT_ALL } from './helpers/channel-persistence';

const network = bitcoin.networks.regtest;

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`monitor-scope-${id}`))
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
		localFundingPrivkey: makeSeed(200 + id),
		persistence: COMMIT_ALL
	};
	const cm = new ChannelManager(cfg);
	cm.on('error', () => {});
	return cm;
}

interface IPreimage {
	hash: Buffer;
	preimage: Buffer;
}

function makePreimage(): IPreimage {
	const preimage = crypto.randomBytes(32);
	return {
		preimage,
		hash: crypto.createHash('sha256').update(preimage).digest()
	};
}

function hex(p: IPreimage): string {
	return p.hash.toString('hex');
}

interface IFixture {
	channel: Channel;
	state: IChannelState;
	keys: Buffer[];
	destination: Buffer;
}

/** A channel carrying one received HTLC of `hash`, committed on both sides. */
function channelWithReceivedHtlc(hash: Buffer): IFixture {
	const { opener, openerPrivkeys: keys } = setupNormalChannels();
	opener.handleUpdateAddHtlc({
		channelId: opener.getChannelId()!,
		id: 0n,
		amountMsat: 10_000_000n,
		paymentHash: hash,
		cltvExpiry: 500,
		onionRoutingPacket: Buffer.alloc(1366)
	});
	const state = opener.getFullState();
	for (const entry of state.htlcs.values()) entry.addLocallyRevoked = true;
	const destination = bitcoin.payments.p2wpkh({
		pubkey: getPublicKey(keys[0]),
		network
	}).output!;
	return { channel: opener, state, keys, destination };
}

function monitorOf(f: IFixture): ChainMonitor {
	return new ChainMonitor(
		f.state,
		f.destination,
		10,
		f.keys[1],
		f.keys[2],
		network,
		f.keys[3],
		f.keys[4]
	);
}

function restoredMonitor(f: IFixture, saved: IChainMonitorState): ChainMonitor {
	return ChainMonitor.restore(
		saved,
		f.state,
		f.destination,
		10,
		f.keys[1],
		f.keys[2],
		network,
		f.keys[3],
		f.keys[4]
	);
}

function theirCommitment(f: IFixture): bitcoin.Transaction {
	return buildRemoteCommitment(
		f.state,
		f.state.remoteCurrentPerCommitmentPoint!
	).result.tx;
}

/** The node writes one saveChainMonitor of the full state per update. */
function savesOf(
	cm: ChannelManager
): { channelIdHex: string; state: IChainMonitorState }[] {
	const saved: { channelIdHex: string; state: IChainMonitorState }[] = [];
	cm.on('monitor:updated', (channelIdHex: string, monitor: ChainMonitor) =>
		saved.push({ channelIdHex, state: monitor.getFullState() })
	);
	return saved;
}

function receivedHtlc(monitor: ChainMonitor): ITrackedOutput {
	return monitor
		.getTrackedOutputs()
		.find((o) => o.outputType === OutputType.RECEIVED_HTLC)!;
}

describe('Chain monitors keep only their own preimages', function () {
	this.timeout(20_000);

	it('saves only the resolving monitor among 50 watching ones, with only its own hash', function () {
		const cm = makeManager(1);
		// Preimages of payments settled long ago, read back from the node's store.
		const settled = Array.from({ length: 20 }, makePreimage);
		for (const p of settled) cm.recordPreimage(p.hash, p.preimage);

		const watching = channelWithReceivedHtlc(makePreimage().hash);
		for (let i = 0; i < 50; i++) {
			cm.restoreMonitor(i.toString(16).padStart(64, '0'), monitorOf(watching));
		}

		// The peer force-closed on its current commitment before we knew the
		// preimage of the HTLC it pays us.
		const owed = makePreimage();
		const resolving = channelWithReceivedHtlc(owed.hash);
		const monitor = monitorOf(resolving);
		monitor.handleFundingSpent(theirCommitment(resolving), 100);
		expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
		const resolvingId = 'ff'.repeat(32);
		cm.restoreMonitor(resolvingId, monitor);

		const saved = savesOf(cm);
		const broadcasts: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
		cm.recordPreimage(owed.hash, owed.preimage);

		// Saved before its claim is routed and again after, and nothing else.
		expect(saved.map((s) => s.channelIdHex)).to.deep.equal([
			resolvingId,
			resolvingId
		]);
		expect(broadcasts).to.have.length(1);
		for (const { state } of saved) {
			expect(state.knownPreimages).to.deep.equal({
				[hex(owed)]: owed.preimage.toString('hex')
			});
		}
		expect(receivedHtlc(monitor).status).to.equal(OutputStatus.SPEND_BROADCAST);
		for (const [id, other] of cm.getMonitors()) {
			if (id === resolvingId) continue;
			expect(other.getFullState().knownPreimages).to.deep.equal({});
		}
	});

	it('hands a watching monitor the preimage of its channel HTLC, which the close then claims with', function () {
		const cm = makeManager(2);
		const p = makePreimage();
		const f = channelWithReceivedHtlc(p.hash);
		const monitor = monitorOf(f);
		const id = 'a2'.repeat(32);
		cm.restoreMonitor(id, monitor);

		const saved = savesOf(cm);
		cm.recordPreimage(p.hash, p.preimage);
		expect(saved.map((s) => s.channelIdHex)).to.deep.equal([id]);
		expect(saved[0].state.knownPreimages).to.deep.equal({
			[hex(p)]: p.preimage.toString('hex')
		});

		monitor.handleFundingSpent(theirCommitment(f), 100);
		expect(receivedHtlc(monitor).sweepTxHex).to.be.a('string');
	});

	it('wants the preimage of a received removal our commitment still carries', function () {
		const p = makePreimage();
		const f = channelWithReceivedHtlc(p.hash);
		// Fulfilled and gone from the map, but the commitment the peer's stored
		// signature covers predates the removal.
		f.state.signedLocalRemovals = [...f.state.htlcs.values()];
		f.state.htlcs.clear();
		const monitor = monitorOf(f);

		expect(monitor.wantsPreimage(p.hash)).to.equal(true);
		expect(monitor.wantsPreimage(makePreimage().hash)).to.equal(false);
		monitor.addPreimage(p.hash, p.preimage);
		expect(
			monitor.getKnownPreimages().get(hex(p))?.equals(p.preimage)
		).to.equal(true);
	});

	it('neither hands nor saves a fully resolved monitor, even for its own HTLC', function () {
		const cm = makeManager(3);
		const p = makePreimage();
		const f = channelWithReceivedHtlc(p.hash);
		const monitor = restoredMonitor(f, {
			monitorState: MonitorState.FULLY_RESOLVED,
			commitmentBroadcast: null,
			trackedOutputs: [],
			currentBlockHeight: 900
		});
		cm.restoreMonitor('a3'.repeat(32), monitor);

		const saved = savesOf(cm);
		cm.recordPreimage(p.hash, p.preimage);
		expect(saved).to.deep.equal([]);
		expect(monitor.getFullState().knownPreimages).to.deep.equal({});
	});

	it('trims a monitor saved with every preimage on restore, and saves it once', function () {
		const cm = makeManager(4);
		const own = makePreimage();
		const others = Array.from({ length: 10 }, makePreimage);
		// The node's store, recorded at startup before monitors are restored.
		for (const p of [own, ...others]) cm.recordPreimage(p.hash, p.preimage);
		// Durable only in the monitor: a crash before the node saved it.
		const stranded = makePreimage();

		const f = channelWithReceivedHtlc(own.hash);
		const monitor = restoredMonitor(f, {
			monitorState: MonitorState.FULLY_RESOLVED,
			commitmentBroadcast: null,
			trackedOutputs: [],
			currentBlockHeight: 900,
			knownPreimages: Object.fromEntries(
				[own, ...others, stranded].map((p) => [
					hex(p),
					p.preimage.toString('hex')
				])
			)
		});
		const saved = savesOf(cm);
		const learned: string[] = [];
		cm.on('preimage:learned', (hash: Buffer) =>
			learned.push(hash.toString('hex'))
		);
		const id = 'a4'.repeat(32);
		cm.restoreMonitor(id, monitor);

		expect(saved.map((s) => s.channelIdHex)).to.deep.equal([id]);
		expect(Object.keys(saved[0].state.knownPreimages!).sort()).to.deep.equal(
			[hex(own), hex(stranded)].sort()
		);
		expect(learned).to.deep.equal([hex(stranded)]);
	});

	it('retires the monitor of a voided channel', function () {
		const cm = makeManager(5);
		const p = makePreimage();
		const f = channelWithReceivedHtlc(p.hash);
		const channelId = f.channel.getChannelId()!;
		cm.restoreChannel(f.channel, getPublicKey(makeSeed(300)).toString('hex'));
		cm.restoreMonitor(channelId.toString('hex'), monitorOf(f));
		expect(cm.getMonitor(channelId)).to.not.equal(undefined);

		expect(cm.voidChannel(channelId)).to.equal(true);
		expect(cm.getMonitor(channelId)).to.equal(undefined);
		const saved = savesOf(cm);
		cm.recordPreimage(p.hash, p.preimage);
		expect(saved).to.deep.equal([]);
	});
});
