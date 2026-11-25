import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { decodeAssetOpenFrame } from '../../src/lightning/message/asset-open';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../../src/lightning/message/channel-commitment';
import { MessageType as M } from '../../src/lightning/message/types';
import {
	setupAssetSplicePeerTransport,
	type SplicePeerPacket
} from './helpers/asset-splice-peer-transport';

function exitShare(p: SplicePeerPacket): boolean {
	if (p.type !== BEIGNET_CUSTOM_MESSAGE_TYPE) return false;
	const { subtype, payload } = decodeCustomMessage(p.wire);
	return (
		subtype === BeignetCustomSubtype.ASSET_SPLICE &&
		decodeAssetOpenFrame(payload).phase === 'exit'
	);
}

describe('Asset splice Bitcoin packets during local funding revalidation', function () {
	this.timeout(90000);
	let dir: string, pair: ReturnType<typeof setupAssetSplicePeerTransport>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-candidate-packets-'));
		pair = setupAssetSplicePeerTransport(dir);
	});
	afterEach(() => {
		pair.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	for (const stage of [
		'exit verification',
		'exit retention',
		'disconnect'
	] as const) {
		it(
			'retains only the exact candidate until a fresh parent observation at ' +
				stage,
			async () => {
				const { id, f, s, available, sides, sent, errors, broadcasts } = pair;
				const left = sides[0];
				const parent = s.layout.parent.getId();
				// Only normal peer frames precede the gap. One confirmed parent read is pending.
				let peerCommit: SplicePeerPacket | undefined;
				await pair.start();
				await pair.drain((p) => {
					if (p.from !== 1) return true;
					if (stage !== 'exit retention' && exitShare(p)) available[0] = false;
					if (stage === 'exit retention' && p.type === M.COMMITMENT_SIGNED) {
						peerCommit = p;
						return false;
					}
					if (p.type === M.TX_SIGNATURES) available[0] = false;
					return true;
				});
				peerCommit ??= sent.find(
					(p) => p.from === 1 && p.type === M.COMMITMENT_SIGNED
				);
				assert(peerCommit, 'peer signed the frozen candidate');
				assert.equal(available[0], false);
				const repeat =
					stage === 'exit retention'
						? sent.find((p) => p.type === M.TX_SIGNATURES && p.from === 1)!
						: peerCommit;
				assert(repeat);
				pair.deliver(repeat);
				if (stage === 'exit retention') pair.deliver(peerCommit);
				await pair.drain();
				assert.deepEqual(errors, []);
				assert.equal(broadcasts.length, 0);
				assert(!sent.some((p) => p.from === 0 && p.type === M.TX_SIGNATURES));
				const stamp = f.devices[0].store.readAssetSpliceJournal(id).hash;
				if (stage === 'exit verification') {
					const changed = decodeCommitmentSignedMessage(peerCommit.wire);
					pair.deliver({
						...peerCommit,
						wire: encodeCommitmentSignedMessage({
							...changed,
							fundingTxid: Buffer.alloc(32, 2)
						})
					});
					await pair.drain();
					assert.match(errors.pop()!, /candidate|funding/i);
					assert.equal(
						f.devices[0].store.readAssetSpliceJournal(id).hash,
						stamp
					);
				}
				if (stage === 'disconnect') {
					pair.connected[0] = false;
					left.disconnected(f.devices[1].party.binding.nodeId);
				}
				available[0] = true;
				left.fundingObserved(id, parent, () => false);
				left.fundingObserved(id, s.tx.getId(), () => true);
				await pair.drain();
				assert.equal(f.devices[0].store.readAssetSpliceJournal(id).hash, stamp);
				left.fundingObserved(id, parent, () => true);
				left.fundingObserved(id, parent, () => true);
				await pair.drain();
				assert.deepEqual(errors, []);
				if (stage === 'disconnect') {
					assert.equal(broadcasts.length, 0);
					assert.equal(
						f.devices[0].store.readAssetSpliceJournal(id).hash,
						stamp
					);
					return;
				}
				assert.deepEqual(broadcasts.map((b) => b.from).sort(), [0, 1]);
				assert.equal(broadcasts[0].tx.toHex(), broadcasts[1].tx.toHex());
				assert(broadcasts[0].tx.ins.every((input) => input.witness.length > 0));
				assert.equal(sent.filter((p) => p.type === M.TX_SIGNATURES).length, 2);
				const done = f.devices[0].store.readAssetSpliceJournal(id).hash;
				left.fundingObserved(id, parent, () => true);
				await pair.drain();
				assert.equal(f.devices[0].store.readAssetSpliceJournal(id).hash, done);
			}
		);
	}
});
