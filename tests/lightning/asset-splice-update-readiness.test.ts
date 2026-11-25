import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { AssetSpliceUpdateTransport } from '../../src/lightning/channel/asset-splice-update-transport';
import {
	ChannelManager,
	type IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { decodeAssetOpenFrame } from '../../src/lightning/message/asset-open';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import { MessageType as M } from '../../src/lightning/message/types';
import {
	setupFundedAssetUpdatePair,
	assetUpdateTestHost
} from './helpers/asset-splice-update';

describe('an admitted asset update waiting for its live funding observation', function () {
	this.timeout(90000);
	for (const gap of [
		'incoming layout',
		'peer share',
		'wallet share',
		'wallet retention',
		'peer revocation',
		'disconnect'
	]) {
		it('preserves the exact round across a funding gap at ' + gap, async () => {
			const dir = fs.mkdtempSync(
				path.join(os.tmpdir(), 'asset-update-readiness-')
			);
			const s = await setupFundedAssetUpdatePair(dir);
			const { devices, id } = s.f;
			const manager = new ChannelManager({
				finalOpening: {
					storage: devices[1].store,
					root: devices[1].party.root
				},
				persistence: { persist: () => 'committed' }
			} as unknown as IChannelManagerConfig);
			const height = 600900,
				txid = s.s.tx.getId();
			const ready = (): number | undefined => manager['assetUpdateHeight'](id);
			const prove = async (): Promise<{
				txid: string;
				blockHash: string;
				confirmations: number;
			}> => ({
				txid,
				blockHash: '5a'.repeat(32),
				confirmations: 1
			});
			const sample = async (current = (): boolean => true): Promise<void> => {
				await manager.observeAssetSpliceFunding(
					id,
					txid,
					height,
					prove,
					current
				);
				manager.observeFinalFunding(id, txid, height, false);
			};
			const completed: number[] = [],
				errors: string[] = [];
			const packets: { from: number; type: number; raw: Buffer }[] = [];
			const revokes: number[] = [];
			let paused = false;
			const suspend = (): void => {
				assert.equal(ready(), height);
				paused = true;
				manager.suspendAssetSpliceFunding(id, txid);
				assert.equal(ready(), undefined);
			};
			try {
				manager.handleNewBlock(height);
				manager.restoreAssetSpliceWatches(id);
				await sample();
				assert.equal(ready(), height);
				const sides = devices.map((d, i) => {
					const host = assetUpdateTestHost(i);
					return new AssetSpliceUpdateTransport(
						{ storage: d.store, root: d.party.root },
						{
							...host,
							async signAssetUpdateViews(round): Promise<Buffer> {
								const bytes = await host.signAssetUpdateViews(round);
								if (i === 1 && gap === 'wallet share' && !paused) suspend();
								return bytes;
							},
							async retainAssetUpdateViews(round, members): Promise<void> {
								await host.retainAssetUpdateViews(round, members);
								if (i === 1 && gap === 'wallet retention' && !paused) suspend();
							}
						},
						() => ({
							peer: devices[1 - i].party.binding.nodeId,
							originalInitiator: i === 0
						}),
						() => (i === 1 ? ready() : height),
						(peer, type, raw) => {
							assert.equal(peer, devices[1 - i].party.binding.nodeId);
							if (type === M.REVOKE_AND_ACK) revokes.push(i);
							packets.push({ from: i, type, raw });
						},
						async () => {
							completed.push(i);
						},
						(_id, e) => {
							errors.push(e);
						}
					);
				});
				Object.assign(manager, { assetUpdates: sides[1] });
				const drain = async (): Promise<void> => {
					for (let n = 0; n < 1000; n++) {
						const p = packets.shift();
						if (p) {
							const peer = devices[p.from].party.binding.nodeId,
								to = sides[1 - p.from];
							if (p.type === BEIGNET_CUSTOM_MESSAGE_TYPE) {
								const { payload } = decodeCustomMessage(p.raw);
								const phase = decodeAssetOpenFrame(payload.subarray(40)).phase;
								if (
									p.from === 0 &&
									!paused &&
									(((gap === 'peer share' || gap === 'disconnect') &&
										phase === 'exit') ||
										(gap === 'incoming layout' && phase === 'layout'))
								)
									suspend();
								to.custom(peer, payload);
							} else {
								if (
									p.from === 0 &&
									!paused &&
									gap === 'peer revocation' &&
									p.type === M.REVOKE_AND_ACK
								)
									suspend();
								assert(to.handle(peer, p.type, p.raw));
							}
						}
						await new Promise<void>((r) => setImmediate(r));
						if (
							!packets.length &&
							sides.every((side) => side['queues'].size === 0)
						)
							return;
					}
					assert.fail('Asset update transport failed to drain');
				};
				await sides[0].start(id, [
					{
						kind: 'add',
						htlc: {
							id: 0n,
							offeredBy: 'local',
							amountMsat: 5000000n,
							paymentHash: Buffer.alloc(32, 7),
							cltvExpiry: 601000,
							allocations: [{ assetId: '4c'.repeat(32), units: 3n }]
						}
					}
				]);
				await drain();
				assert(paused);
				if (gap === 'incoming layout')
					assert(
						!devices[1].store
							.readAssetSpliceJournal<{ kind: string }>(id)
							.records.some((row) => row.kind === 'asset-update-peer')
					);
				assert(!completed.includes(1));
				const stamp = devices[1].store.readAssetSpliceJournal(id).hash;
				const before = [...revokes];
				await sample(() => false);
				manager.observeFinalFunding(id, txid, undefined, false);
				await drain();
				assert.deepEqual(revokes, before);
				assert.equal(devices[1].store.readAssetSpliceJournal(id).hash, stamp);
				if (gap === 'disconnect')
					sides[1].disconnected(devices[0].party.binding.nodeId);
				await sample();
				await sample();
				await drain();
				assert.deepEqual(errors, []);
				if (gap === 'disconnect') {
					assert(!completed.includes(1));
					assert.deepEqual(revokes, before);
					return;
				}
				assert.deepEqual(completed.sort(), [0, 1]);
				assert.deepEqual(revokes.sort(), [0, 1]);
				assert(
					devices.every(
						(d) => d.store.assetSpliceUpdateHead(id).nextNumber === 2n
					)
				);
				const settled = devices[1].store.readAssetSpliceJournal(id).hash;
				await sample();
				await drain();
				assert.equal(devices[1].store.readAssetSpliceJournal(id).hash, settled);
				assert.equal(revokes.length, 2);
			} finally {
				for (const d of devices) d.store.close();
				fs.rmSync(dir, { recursive: true, force: true });
			}
		});
	}
});
