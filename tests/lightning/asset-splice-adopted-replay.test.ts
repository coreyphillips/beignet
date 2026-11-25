import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { MessageType as M } from '../../src/lightning/message/types';
import {
	receivedAdoptedSpliceSignature,
	type AdoptedSpliceReplayEvent
} from '../../src/lightning/storage/asset-splice-release-replay';
import { setupAssetSplicePeerTransport } from './helpers/asset-splice-peer-transport';

describe('previously adopted asset splice signatures during a new negotiation', function () {
	this.timeout(60000);
	it('consumes exact historic peer signatures while preserving the new unsigned attempt', async () => {
		const dir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'asset-splice-adopted-replay-')
		);
		const pair = setupAssetSplicePeerTransport(dir);
		const { id, f, sent, sides } = pair;
		try {
			await pair.start();
			await pair.drain();
			assert.deepEqual(pair.errors, []);
			await pair.adopt();
			const previous = sent.filter(
				(p) =>
					p.from === 1 &&
					(p.type === M.COMMITMENT_SIGNED || p.type === M.TX_SIGNATURES)
			);
			assert.equal(previous.length, 2);
			await pair.start();
			const store = f.devices[0].store,
				peer = f.devices[1].party.binding.nodeId;
			const before = store.readAssetSpliceJournal<AdoptedSpliceReplayEvent>(id);
			const count = sent.length;
			for (const packet of [...previous, ...previous])
				assert(sides[0].handle(peer, packet.type, packet.wire));
			await pair.idle();
			assert.deepEqual(pair.errors, []);
			assert.equal(store.readAssetSpliceJournal(id).hash, before.hash);
			assert.equal(sent.length, count);
			const begins = before.records.filter((r) => r.kind === 'peer-splice');
			assert.equal(begins.length, 2);
			const [old, current] = begins;
			assert(old.kind === 'peer-splice' && current.kind === 'peer-splice');
			const noOuterMarkers = before.records.filter(
				(r) =>
					r.kind !== 'peer-splice-stage' ||
					!['peer-share', 'peer-witness'].includes(r.field)
			);
			for (const p of previous) {
				assert(
					receivedAdoptedSpliceSignature(
						noOuterMarkers,
						current.index,
						p.type,
						p.wire
					)
				);
				assert(
					!receivedAdoptedSpliceSignature(
						before.records,
						old.index,
						p.type,
						p.wire
					)
				);
				const changed = Buffer.from(p.wire);
				changed[changed.length - 1] ^= 1;
				assert(
					!receivedAdoptedSpliceSignature(
						before.records,
						current.index,
						p.type,
						changed
					)
				);
				assert(
					!receivedAdoptedSpliceSignature(
						before.records.filter((r) => r.kind !== 'asset-splice-imported'),
						current.index,
						p.type,
						p.wire
					)
				);
				assert(
					!receivedAdoptedSpliceSignature(
						before.records.filter(
							(r) => r.kind !== 'peer-splice-stage' || r.field !== 'assembled'
						),
						current.index,
						p.type,
						p.wire
					)
				);
			}
		} finally {
			pair.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
