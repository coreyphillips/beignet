import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import sinon from 'sinon';
import type { IAssetSpliceContext } from '../../src/lightning/channel/asset-splice-agreement';
import { MessageType as M } from '../../src/lightning/message/types';
import { setupAssetSplicePeerTransport } from './helpers/asset-splice-peer-transport';

describe('Original-device splice observation during asynchronous wallet exit verification', function () {
	this.timeout(90000);
	for (const mode of [
		'resume',
		'disconnect',
		'close',
		'different root',
		'expiry'
	] as const) {
		it(
			'distinguishes an observation refresh from changed authority on ' + mode,
			async () => {
				const dir = fs.mkdtempSync(
					path.join(os.tmpdir(), 'splice-exit-observation-')
				);
				let refreshing = false;
				const p = setupAssetSplicePeerTransport(dir, () => refreshing);
				try {
					const { id, available } = p,
						device = p.f.devices[0],
						side = p.sides[0],
						peer = p.f.devices[1].party.binding.nodeId;
					const parent = p.s.layout.parent.getId();
					const verify = p.walletHosts[0].verifySpliceExits.bind(
						p.walletHosts[0]
					);
					let calls = 0,
						ctx: IAssetSpliceContext | undefined;
					p.walletHosts[0].verifySpliceExits = async (
						c,
						...rest
					): ReturnType<typeof verify> => {
						ctx = c;
						assert(c.currentParent());
						assert.equal(c.parentObservationPending?.(), false);
						calls++;
						await new Promise<void>((resolve) => setImmediate(resolve));
						if (calls === 1) {
							available[0] = false;
							assert.equal(c.currentParent(), undefined);
							assert.equal(c.parentObservationPending?.(), false);
							refreshing = true;
							assert.equal(c.parentObservationPending?.(), true);
							throw Error('Wallet parent observation pending');
						}
						const proof = await verify(c, ...rest);
						if (calls === 2) available[0] = false;
						return proof;
					};
					const signed = (): number =>
						p.sent.filter(
							(x) =>
								x.from === 0 &&
								(x.type === M.COMMITMENT_SIGNED || x.type === M.TX_SIGNATURES)
						).length;
					await p.start();
					await p.drain();
					assert.equal(calls, 1);
					assert(ctx);
					assert.equal(signed(), 0);
					assert.deepEqual(p.errors, ['Wallet parent observation pending']);
					const stamp = device.store.readAssetSpliceJournal(id).hash;
					if (mode === 'disconnect') {
						p.connected[0] = false;
						side.disconnected(peer);
						p.connected[0] = true;
					}
					if (mode === 'close')
						device.store.requestFinalOpeningExit(
							id,
							p.s.layout.parent.getHash()
						);
					if (mode === 'different root') {
						const original = device.store.loadFinalDaemonOpening.bind(
							device.store
						);
						sinon
							.stub(device.store, 'loadFinalDaemonOpening')
							.callsFake((c: string) => {
								const d = original(c);
								if (!d?.session.assetEvidence) return d;
								return {
									...d,
									session: {
										...d.session,
										assetEvidence: {
											...d.session.assetEvidence,
											fundingRoot: 'e4'.repeat(32)
										}
									}
								};
							});
					}
					if (mode === 'expiry') {
						const clock = sinon.useFakeTimers({
							now: Date.now() + 120001,
							toFake: ['Date']
						});
						try {
							assert.equal(ctx.parentObservationPending?.(), false);
						} finally {
							clock.restore();
						}
						return;
					}
					if (mode !== 'resume') {
						assert.equal(ctx.parentObservationPending?.(), false);
						available[0] = true;
						side.fundingObserved(id, parent, () => true);
						await p.drain();
						assert.equal(calls, 1);
						assert.equal(signed(), 0);
						assert.equal(p.broadcasts.length, 0);
						return;
					}
					available[0] = true;
					let fresh = true;
					side.fundingObserved(id, parent, () => fresh);
					fresh = false;
					side.fundingObserved(id, p.s.tx.getId(), () => true);
					await p.drain();
					assert.equal(calls, 1);
					assert.equal(device.store.readAssetSpliceJournal(id).hash, stamp);
					side.fundingObserved(id, parent, () => true);
					await p.drain();
					assert.equal(calls, 2);
					assert.equal(signed(), 0);
					assert.equal(p.broadcasts.length, 0);
					assert.equal(ctx.parentObservationPending?.(), true);
					available[0] = true;
					side.fundingObserved(id, parent, () => true);
					await p.drain();
					assert.equal(calls, 3);
					assert.equal(p.broadcasts.length, 2);
					assert.equal(p.broadcasts[0].tx.toHex(), p.broadcasts[1].tx.toHex());
					assert.equal(
						p.sent.filter((x) => x.from === 0 && x.type === M.TX_SIGNATURES)
							.length,
						1
					);
					available[0] = false;
					assert.equal(ctx.parentObservationPending?.(), false);
				} finally {
					p.close();
					fs.rmSync(dir, { recursive: true, force: true });
				}
			}
		);
	}
});
