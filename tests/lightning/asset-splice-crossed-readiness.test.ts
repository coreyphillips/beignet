import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { MessageType as M } from '../../src/lightning/message/types';
import { setupAssetSplicePeerTransport } from './helpers/asset-splice-peer-transport';

describe('Asset splice admission when both original wallets request quiescence', function () {
	this.timeout(90000);
	let dir: string, pair: ReturnType<typeof setupAssetSplicePeerTransport>;
	beforeEach(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-crossed-'));
		pair = setupAssetSplicePeerTransport(dir);
		await pair.start();
		await pair.drain();
		await pair.adopt();
	});
	afterEach(() => {
		pair.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('keeps a deferred peer request when a fresh local request crosses it', async () => {
		const { id, f, sides, available, sent } = pair;
		const before = sent.length;
		const stamp = f.devices[1].store.readAssetSpliceJournal(id).hash;
		available[1] = false;
		await pair.start();
		pair.deliver(pair.packets.shift()!);
		await assert.rejects(
			sides[1].start(id, {
				fundingFeeratePerkw: f.terms[1].feerate,
				minimumDepth: 3
			}),
			/idle channel/
		);
		assert.equal(f.devices[1].store.readAssetSpliceJournal(id).hash, stamp);
		available[1] = true;
		sides[1].fundingObserved(id, pair.s.tx.getId(), () => true);
		await pair.idle();
		assert.equal(
			sent
				.slice(before)
				.filter((packet) => packet.from === 1 && packet.type === M.STFU).length,
			1
		);
		assert.deepEqual(pair.errors, []);
	});

	for (const delivery of ['queued', 'before-abort', 'after-abort'] as const) {
		it(
			'retires both unsigned starts after the losing device loses its funding observation, proposal ' +
				delivery,
			async () => {
				const { id, f, s, sides, available, packets, sent } = pair;
				const before = f.devices.map(
					({ store }) => store.readAssetSpliceJournal(id).records.length
				);
				const at = sent.length;
				let loserWalletCalls = 0;
				pair.walletHosts[1].proposeSplice = async (): Promise<Buffer> => {
					loserWalletCalls++;
					throw Error('The losing wallet should not draw a proposal');
				};
				await pair.start();
				await sides[1].start(id, {
					fundingFeeratePerkw: f.terms[1].feerate,
					minimumDepth: 3
				});
				const [winnerStfu, loserStfu] = packets.splice(0);
				assert.equal(winnerStfu.type, M.STFU);
				assert.equal(loserStfu.type, M.STFU);
				available[1] = false;
				pair.deliver(loserStfu);
				await pair.idle();
				const proposal = packets.shift()!;
				assert.equal(proposal.type, M.SPLICE);
				pair.deliver(winnerStfu);
				if (delivery === 'queued') pair.deliver(proposal);
				await pair.idle();
				const abort = packets.shift();
				assert.equal(
					abort?.type,
					M.TX_ABORT,
					'The losing device must cancel both unsigned attempts'
				);
				if (delivery === 'before-abort') pair.deliver(proposal);
				pair.deliver(abort!);
				await pair.idle();
				if (delivery === 'after-abort') pair.deliver(proposal);
				const ack = packets.shift()!;
				assert.equal(ack.type, M.TX_ABORT);
				pair.deliver(ack);
				await pair.idle();
				assert.equal(packets.length, 0);
				assert.equal(loserWalletCalls, 0);
				assert(!sent.slice(at).some((p) => p.type === M.TX_SIGNATURES));
				const stamps = f.devices.map(({ store }, i) => {
					const journal = store.readAssetSpliceJournal<{
						kind: string;
						field?: string;
						index?: number;
					}>(id);
					const rows = journal.records.slice(before[i]);
					const begins = rows.filter((row) => row.kind === 'peer-splice');
					assert.equal(begins.length, 1);
					assert(
						rows.some(
							(row) =>
								row.kind === 'peer-splice-stage' &&
								row.field === 'retired' &&
								row.index === begins[0].index
						)
					);
					assert(
						!rows.some((row) =>
							[
								'splice-authorization-start',
								'wallet-inputs',
								'funding-reserved',
								'funding-released'
							].includes(row.kind)
						)
					);
					return journal.hash;
				});
				available[1] = true;
				sides[1].fundingObserved(id, s.tx.getId(), () => true);
				await pair.drain();
				assert.deepEqual(
					f.devices.map(({ store }) => store.readAssetSpliceJournal(id).hash),
					stamps
				);
			}
		);
	}
});
