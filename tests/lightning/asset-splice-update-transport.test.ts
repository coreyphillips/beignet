import { decodeStartBatchMessage } from '../../src/lightning/message/splice';
import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	setupFundedAssetUpdatePair,
	assetUpdateTestHost
} from './helpers/asset-splice-update';
import { AssetSpliceUpdateTransport } from '../../src/lightning/channel/asset-splice-update-transport';
import {
	BeignetCustomSubtype,
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import { MessageType as M } from '../../src/lightning/message/types';
import { sha256 } from '../../src/lightning/crypto/provider';

describe('asset update peer transport on enrolled devices', function () {
	this.timeout(90000);
	for (const scenario of [
		'complete',
		'dropped revoke',
		'short batch',
		'interleaved batch'
	])
		it(
			scenario === 'short batch'
				? 'rejects a declared batch missing a live funding'
				: scenario === 'interleaved batch'
				? 'refuses an unrelated wire between funding signatures'
				: scenario === 'dropped revoke'
				? 'replays exact signed commitments after one device missed the final revocation'
				: 'carries two-holder proofs and tagged Bitcoin signatures before either prior state can be revoked',
			async () => {
				const dropRevocation = scenario === 'dropped revoke';
				const dir = fs.mkdtempSync(
					path.join(os.tmpdir(), 'asset-updates-peer-')
				);
				const pair = await setupFundedAssetUpdatePair(dir),
					f = pair.f,
					errors: string[] = [],
					done: number[] = [],
					seen: number[] = [];
				const packets: { from: number; type: number; wire: Buffer }[] = [];
				let currentHeight: number | undefined = 600900;
				const makeSides = () =>
					f.devices.map(
						({ store, party }, i) =>
							new AssetSpliceUpdateTransport(
								{ storage: store, root: party.root },
								assetUpdateTestHost(i),
								(id) =>
									id === f.id
										? {
												peer: f.devices[1 - i].party.binding.nodeId,
												originalInitiator: i === 0
										  }
										: undefined,
								() => currentHeight,
								(_peer, type, raw) =>
									packets.push({ from: i, type, wire: raw }),
								async () => {
									done.push(i);
								},
								(_id, err) => errors.push(err)
							)
					);
				let sides = makeSides();
				const delivered: Buffer[] = [];
				let skipped: Buffer | undefined,
					restarted = false;
				const hash = sha256(Buffer.alloc(32, 13));
				try {
					const add = {
						kind: 'add' as const,
						htlc: {
							offeredBy: 'local' as const,
							id: 0n,
							amountMsat: 5000000n,
							cltvExpiry: 601000,
							paymentHash: hash,
							allocations: [{ assetId: '4c'.repeat(32), units: 3n }]
						}
					};
					if (scenario === 'complete') {
						currentHeight = undefined;
						await assert.rejects(
							sides[0].start('00'.repeat(32), [add]),
							/established enrolled channel/
						);
						await assert.rejects(
							sides[0].start(f.id, [add]),
							/waiting for verified live funding/
						);
						assert.equal(packets.length, 0);
						assert.equal(
							f.devices[0].store.assetSpliceUpdateHead(f.id).inProgress,
							undefined
						);
						currentHeight = 600900;
					}
					await assert.rejects(() =>
						sides[0].start(f.id, [
							{ ...add, htlc: { ...add.htlc, offeredBy: 'peer' } }
						])
					);
					await sides[0].start(f.id, [add]);
					for (
						let tries = 0;
						done.length < 2 && tries < 5000 && !errors.length;
						tries++
					) {
						if (
							dropRevocation &&
							skipped &&
							done.length === 1 &&
							packets.length === 0 &&
							!restarted
						) {
							for (const [i, s] of sides.entries())
								s.disconnected(f.devices[1 - i].party.binding.nodeId);
							sides = makeSides();
							for (const [i, s] of sides.entries())
								s.resume(f.devices[1 - i].party.binding.nodeId, f.id);
							restarted = true;
						}
						const msg = packets.shift();
						if (msg) {
							const peer = f.devices[msg.from].party.binding.nodeId,
								to = sides[1 - msg.from];
							if (dropRevocation && !skipped && msg.type === M.REVOKE_AND_ACK) {
								skipped = Buffer.from(msg.wire);
								continue;
							}
							if (msg.type === M.START_BATCH) {
								const header = decodeStartBatchMessage(msg.wire);
								assert.equal(header.batchSize, 2);
								assert.equal(header.messageType, M.COMMITMENT_SIGNED);
								if (scenario === 'short batch') msg.wire.writeUInt16BE(1, 32);
								if (scenario === 'interleaved batch') {
									assert(to.handle(peer, msg.type, msg.wire));
									assert(to.collect(peer, M.PING, Buffer.alloc(4)));
									break;
								}
							}
							seen.push(msg.type);
							if (msg.type === M.REVOKE_AND_ACK) delivered.push(msg.wire);
							if (msg.type === BEIGNET_CUSTOM_MESSAGE_TYPE) {
								const m = decodeCustomMessage(msg.wire);
								assert.equal(m.subtype, BeignetCustomSubtype.ASSET_UPDATE);
								to.custom(peer, m.payload);
							} else assert(to.handle(peer, msg.type, msg.wire));
						}
						await new Promise<void>((resolve) => setImmediate(resolve));
					}
					if (scenario === 'short batch' || scenario === 'interleaved batch') {
						assert(errors.some((e) => e.includes('batch')));
						assert.equal(delivered.length, 0);
						assert(
							f.devices.every(
								(d) => d.store.assetSpliceUpdateHead(f.id).nextNumber === 1n
							)
						);
						return;
					}
					assert.deepEqual(errors, []);
					assert.deepEqual(done.sort(), [0, 1]);
					if (dropRevocation) {
						assert(restarted);
						assert(delivered.some((packet) => packet.equals(skipped!)));
					} else
						assert.equal(
							seen.filter((x) => x === M.COMMITMENT_SIGNED).length,
							4
						);
					if (!dropRevocation)
						assert.equal(seen.filter((x) => x === M.REVOKE_AND_ACK).length, 2);
					assert(
						f.devices.every(
							(d) => d.store.assetSpliceUpdateHead(f.id).nextNumber === 2n
						)
					);
				} finally {
					for (const d of f.devices) d.store.close();
					fs.rmSync(dir, { recursive: true, force: true });
				}
			}
		);
});
