import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import sinon from 'sinon';
import { encodeTxAbortMessage } from '../../src/lightning/message/interactive-tx';
import { MessageType as M } from '../../src/lightning/message/types';
import { assetUpdateTestHost } from './helpers/asset-splice-update';
import { setupAssetSplicePeerTransport } from './helpers/asset-splice-peer-transport';

async function signUpdatedFee(
	p: ReturnType<typeof setupAssetSplicePeerTransport>
): Promise<void> {
	const rounds = p.f.devices.map((d) =>
		d.store.assetSpliceUpdateBatch(
			p.id,
			d.party.root,
			1n,
			[{ kind: 'fee', feeratePerKw: 1100 }],
			() => 600000
		)
	);
	const hosts = rounds.map((_, i) => assetUpdateTestHost(i, [], 1));
	const offers = rounds.map((r) => r.offer());
	rounds.forEach((r, i) => r.acceptOffer(offers[1 - i]));
	const joint = await Promise.all([
		rounds[0].signAssetShares(hosts[0]),
		rounds[1].signAssetShares(hosts[1])
	]);
	const children = await Promise.all([
		rounds[0].signAssetHtlcs(hosts[0], joint),
		rounds[1].signAssetHtlcs(hosts[1], joint)
	]);
	await Promise.all(
		rounds.map((r, i) => r.verifyAssetShares(hosts[i], joint, children))
	);
	const commitments = rounds.map((r) => r.commitments());
	await Promise.all(
		rounds.map((r, i) => r.acceptCommitments(hosts[i], commitments[1 - i]))
	);
	const revokes = rounds.map((r) => r.revocation());
	rounds.forEach((r, i) => r.receiveRevocation(revokes[1 - i]));
}
describe('Remote asset splice quiescence during a local parent observation', function () {
	this.timeout(90000);
	let dir: string, p: ReturnType<typeof setupAssetSplicePeerTransport>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-remote-stfu-'));
		p = setupAssetSplicePeerTransport(dir);
	});
	afterEach(() => {
		p.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	for (const mode of [
		'recover',
		'abort',
		'disconnect',
		'expire',
		'changed state',
		'close'
	] as const) {
		it(
			'binds an unanswered request to the current adopted funding on ' + mode,
			async () => {
				await p.start();
				await p.drain();
				const parent = await p.adopt();
				const { id, f, available, sent, errors, sides } = p;
				const receiver = sides[1],
					peer = f.devices[0].party.binding.nodeId,
					store = f.devices[1].store;
				const before = store.readAssetSpliceJournal(id),
					at = sent.length;
				let walletCalls = 0;
				p.walletHosts[1].proposeSplice = async (): Promise<Buffer> => {
					walletCalls++;
					throw Error('Local wallet refused this issuance');
				};
				const clock = sinon.useFakeTimers({
					now: Date.now(),
					shouldClearNativeTimers: true,
					toFake: ['Date', 'setTimeout', 'clearTimeout']
				});
				try {
					available[1] = false;
					// STFU contains only this channel and its initiator flag. An earlier
					// genuine peer request can arrive while both devices complete a new state.
					if (mode !== 'changed state') await p.start();
					const request =
						mode === 'changed state'
							? sent.find((v) => v.from === 0 && v.type === M.STFU)!
							: p.packets.shift()!;
					assert.equal(request.type, M.STFU);
					p.deliver(request);
					await p.idle();
					assert.equal(errors.length, 0);
					assert.equal(store.readAssetSpliceJournal(id).hash, before.hash);
					assert(!sent.slice(at).some((v) => v.from === 1));
					assert.equal(walletCalls, 0);
					clock.tick(1000);
					p.deliver(request);
					await p.idle();
					if (mode === 'abort') {
						assert(
							receiver.handle(
								peer,
								M.TX_ABORT,
								encodeTxAbortMessage({
									channelId: Buffer.from(id, 'hex'),
									data: Buffer.from('Splice abandoned')
								})
							)
						);
						await p.idle();
						assert.equal(
							sent
								.slice(at)
								.filter((v) => v.from === 1 && v.type === M.TX_ABORT).length,
							1
						);
					} else if (mode === 'disconnect') {
						p.connected[1] = false;
						receiver.disconnected(peer);
						p.connected[1] = true;
					} else if (mode === 'expire') {
						clock.tick(119000);
						await p.idle();
					} else if (mode === 'changed state') {
						await signUpdatedFee(p);
						assert.equal(
							store.assetSpliceUpdateHead(id).committed?.height,
							'1'
						);
					} else if (mode === 'close') {
						store.requestFinalOpeningExit(
							id,
							p.s.tx.getHash(),
							store.loadAdoptedAssetSpliceReceipt(id)!.candidate.outputIndex
						);
					}
					const stamp = store.readAssetSpliceJournal(id).hash;
					available[1] = true;
					receiver.fundingObserved(id, parent, () => false);
					receiver.fundingObserved(id, p.s.layout.parent.getId(), () => true);
					await p.idle();
					assert.equal(store.readAssetSpliceJournal(id).hash, stamp);
					if (mode === 'changed state') assert(!receiver['inbound'].has(id));
					receiver.fundingObserved(id, parent, () => true);
					receiver.fundingObserved(id, parent, () => true);
					await p.idle();
					if (mode !== 'recover') {
						assert.equal(walletCalls, 0);
						assert.equal(store.readAssetSpliceJournal(id).hash, stamp);
						assert.equal(
							sent.slice(at).filter((v) => v.from === 1 && v.type === M.STFU)
								.length,
							0
						);
						return;
					}
					assert.equal(
						sent.slice(at).filter((v) => v.from === 1 && v.type === M.STFU)
							.length,
						1
					);
					await p.drain();
					assert.equal(walletCalls, 1);
					assert(errors.includes('Local wallet refused this issuance'));
					assert.equal(
						sent
							.slice(at)
							.filter((v) => v.from === 1 && v.type === M.TX_SIGNATURES).length,
						0
					);
				} finally {
					clock.restore();
				}
			}
		);
	}
});
