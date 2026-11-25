import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { AssetSpliceUpdateTransport } from '../../src/lightning/channel/asset-splice-update-transport';
import { sha256 } from '../../src/lightning/crypto/provider';
import {
	ASSET_OPEN_CHUNK_SIZE,
	decodeAssetOpenFrame,
	encodeAssetOpenFrame
} from '../../src/lightning/message/asset-open';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import { MessageType as M } from '../../src/lightning/message/types';
import {
	setupFundedAssetUpdatePair,
	assetUpdateTestHost
} from './helpers/asset-splice-update';

interface Packet {
	from: number;
	type: number;
	wire: Buffer;
}
interface ConnectedPair {
	f: Awaited<ReturnType<typeof setupFundedAssetUpdatePair>>['f'];
	sides: AssetSpliceUpdateTransport[];
	start(htlcId: bigint): Promise<void>;
	pending: Packet[];
	history: Packet[];
	retained: number[];
	completed: number[];
	errors: string[];
	idle(): Promise<void>;
	deliver(packet: Packet): void;
	drain(drop?: (packet: Packet) => boolean): Promise<void>;
}
async function connectedPair(dir: string): Promise<ConnectedPair> {
	const { f } = await setupFundedAssetUpdatePair(dir);
	const errors: string[] = [],
		completed: number[] = [],
		retained: number[] = [];
	const pending: Packet[] = [],
		history: Packet[] = [];
	const sides = f.devices.map(
		({ store, party }, i) =>
			new AssetSpliceUpdateTransport(
				{ storage: store, root: party.root },
				assetUpdateTestHost(i, retained),
				() => ({
					peer: f.devices[1 - i].party.binding.nodeId,
					originalInitiator: i === 0
				}),
				() => 600900,
				(_peer, type, wire) => {
					const packet = { from: i, type, wire };
					pending.push(packet);
					history.push(packet);
				},
				async () => {
					completed.push(i);
				},
				(_id, reason) => {
					errors.push(reason);
				}
			)
	);
	function deliver(packet: Packet): void {
		const side = sides[1 - packet.from],
			peer = f.devices[packet.from].party.binding.nodeId;
		if (packet.type === BEIGNET_CUSTOM_MESSAGE_TYPE)
			side.custom(peer, decodeCustomMessage(packet.wire).payload);
		else assert(side.handle(peer, packet.type, packet.wire));
	}
	const idle = (): Promise<void> =>
		new Promise((resolve) => setImmediate(resolve));
	async function drain(drop?: (packet: Packet) => boolean): Promise<void> {
		for (let i = 0; i < 600; i++) {
			const packet = pending.shift();
			if (packet && !drop?.(packet)) deliver(packet);
			await idle();
			if (!pending.length && !sides.some((side) => side['queues'].size)) return;
		}
		assert.fail('Update transport failed to drain');
	}
	const start = (htlcId: bigint): Promise<void> =>
		sides[0].start(f.id, [
			{
				kind: 'add',
				htlc: {
					id: htlcId,
					offeredBy: 'local',
					paymentHash: sha256(Buffer.from([Number(htlcId)])),
					amountMsat: 5000000n,
					cltvExpiry: 601000,
					allocations: [{ assetId: '4c'.repeat(32), units: 3n }]
				}
			}
		]);
	return {
		f,
		sides,
		start,
		pending,
		history,
		retained,
		completed,
		errors,
		idle,
		deliver,
		drain
	};
}

describe('asset update session and historical replay', function () {
	this.timeout(90000);
	let dir: string;
	let pair: ConnectedPair;
	beforeEach(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-update-session-'));
		pair = await connectedPair(dir);
	});
	afterEach(() => {
		for (const d of pair.f.devices) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	it('keeps the next local layout active when a settled peer proof arrives before its acknowledgement', async () => {
		const { f, start, drain, history, retained, completed, errors, deliver } =
			pair;
		await start(0n);
		await drain();
		assert.deepEqual([...completed].sort(), [0, 1]);
		const previous = history.find(
			(packet) =>
				packet.from === 1 &&
				packet.type === BEIGNET_CUSTOM_MESSAGE_TYPE &&
				decodeAssetOpenFrame(
					decodeCustomMessage(packet.wire).payload.subarray(40)
				).phase === 'exit'
		);
		assert(previous);
		await start(1n);
		deliver(previous);
		await drain();
		assert.deepEqual(errors, []);
		assert.equal(
			completed.length,
			4,
			'both devices must finish the second round'
		);
		assert.equal(retained.length, 4);
		assert(
			f.devices.every(
				(d) => d.store.assetSpliceUpdateHead(f.id).nextNumber === 3n
			)
		);
	});
	it('recognizes an exact historical BOLT batch and revocation while the next intent is awaiting acknowledgement', async () => {
		const { f, start, drain, history, retained, completed, errors, deliver } =
			pair;
		await start(0n);
		await drain();
		const previous = history.filter(
			(packet) =>
				packet.from === 1 && packet.type !== BEIGNET_CUSTOM_MESSAGE_TYPE
		);
		assert.equal(previous.length, 4);
		await start(1n);
		for (const packet of previous) deliver(packet);
		await drain();
		assert.deepEqual(errors, []);
		assert.equal(completed.length, 4);
		assert.equal(retained.length, 4);
		assert(
			f.devices.every(
				(d) => d.store.assetSpliceUpdateHead(f.id).nextNumber === 3n
			)
		);
	});
	it('resumes a newer layout after the other device reconnects missing the last revocation', async () => {
		const { f, start, sides, pending, completed, errors, retained, drain } =
			pair;
		await start(0n);
		let dropped = false;
		await drain((packet) => {
			if (dropped || packet.from !== 0 || packet.type !== M.REVOKE_AND_ACK)
				return false;
			dropped = true;
			return true;
		});
		assert(dropped);
		assert.deepEqual(completed, [0]);
		await start(1n);
		pending.splice(0);
		for (const [i, side] of sides.entries())
			side.disconnected(f.devices[1 - i].party.binding.nodeId);
		for (const [i, side] of sides.entries())
			side.resume(f.devices[1 - i].party.binding.nodeId, f.id);
		await drain();
		assert.deepEqual(errors, []);
		assert.equal(completed.length, 4);
		assert.equal(retained.length, 4);
		assert(
			f.devices.every(
				(d) => d.store.assetSpliceUpdateHead(f.id).nextNumber === 3n
			)
		);
	});
	it('declines a queued local request when its original connection is gone', async () => {
		const { f, sides, pending, retained, start, idle } = pair;
		const initial = f.devices[0].store.readAssetSpliceJournal(f.id).hash;
		const attempt = start(0n);
		sides[0].disconnected(f.devices[1].party.binding.nodeId);
		sides[0].resume(f.devices[1].party.binding.nodeId, f.id);
		await assert.rejects(attempt, /disconnected/i);
		await idle();
		assert.equal(f.devices[0].store.readAssetSpliceJournal(f.id).hash, initial);
		assert.equal(pending.length, 0);
		assert.equal(retained.length, 0);
	});
	for (const queued of [true, false]) {
		it(
			queued
				? 'drops an inbound layout queued on the previous connection to the same device'
				: 'drops partial prior-connection layout chunks before any session was created',
			async () => {
				const {
					f,
					start,
					drain,
					pending,
					sides,
					retained,
					completed,
					errors,
					idle,
					deliver
				} = pair;
				await start(0n);
				const layout = pending.shift();
				assert(layout);
				const peer = f.devices[0].party.binding.nodeId;
				const initial = f.devices[1].store.readAssetSpliceJournal(f.id).hash;
				if (queued) deliver(layout);
				else {
					const payload = decodeCustomMessage(layout.wire).payload;
					const partial = encodeAssetOpenFrame({
						phase: 'layout',
						attempt: Buffer.alloc(32, 17),
						total: ASSET_OPEN_CHUNK_SIZE + 1,
						digest: Buffer.alloc(32, 22),
						offset: 0,
						bytes: Buffer.alloc(ASSET_OPEN_CHUNK_SIZE)
					});
					sides[1].custom(
						peer,
						Buffer.concat([payload.subarray(0, 40), partial])
					);
					await idle();
				}
				sides[1].disconnected(peer);
				sides[1].resume(peer, f.id);
				await idle();
				assert.equal(
					f.devices[1].store.readAssetSpliceJournal(f.id).hash,
					initial,
					'pre-disconnect layout cannot authorize work on the new connection'
				);
				assert.equal(pending.length, 0);
				deliver(layout);
				await drain();
				assert.deepEqual(errors, []);
				assert.equal(retained.length, 2);
				assert.equal(completed.length, 2);
			}
		);
	}
});
