import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { AssetSpliceConstruction } from '../../src/lightning/channel/asset-splice-construction';
import {
	decodeTxAddInputMessage,
	decodeTxCompleteMessage,
	encodeTxCompleteMessage,
	encodeTxAddOutputMessage
} from '../../src/lightning/message/interactive-tx';
import { MessageType as M } from '../../src/lightning/message/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	constructionFixture as fixture,
	localPromise
} from './helpers/asset-splice-construction';

const tag = (n: number) => Buffer.alloc(32, n);
describe('durable interactive construction of an exact asset splice', () => {
	let dir: string, s: ReturnType<typeof fixture>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-construction-'));
		s = fixture(dir);
	});
	afterEach(() => {
		for (const d of s?.f.devices ?? []) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('exchanges the exact shared and external inputs, outputs and separate final nonce promises and reconstructs the same signed digest on both peers', () => {
		const sides = [s.open(0), s.open(1)],
			types: number[] = [],
			interim: Buffer[] = [];
		for (let step = 0; step < 20; step++) {
			const i = step % 2,
				other = 1 - i;
			const next = sides[i].next();
			if (!next) break;
			types.push(next.type);
			assert.deepEqual(sides[i].replay(), next);
			if (next.type === M.TX_ADD_INPUT) {
				const input = decodeTxAddInputMessage(next.payload, { taproot: true });
				if (input.serialId === 0n) {
					assert.deepEqual(input.sharedInputTxid, s.layout.parent.getHash());
					assert.equal(input.prevTx.length, 0);
				} else assert.deepEqual(input.prevTx, s.layout.inputs[1].prevTx);
			}
			if (next.type === M.TX_COMPLETE && !next.payload.equals(s.payloads[i]))
				interim.push(next.payload);
			sides[other].receive(next.type, next.payload);
			sides[other].receive(next.type, next.payload);
		}
		assert.deepEqual(types, [
			M.TX_ADD_INPUT,
			M.TX_COMPLETE,
			M.TX_ADD_INPUT,
			M.TX_COMPLETE,
			M.TX_ADD_OUTPUT,
			M.TX_COMPLETE,
			M.TX_ADD_OUTPUT,
			M.TX_COMPLETE,
			M.TX_COMPLETE
		]);
		assert.equal(new Set(interim.map((x) => x.toString('hex'))).size, 3);
		for (const i of [0, 1]) {
			const a = sides[i].agreement();
			assert(a);
			assert.deepEqual(a.candidate.tx.toBuffer(), s.tx.toBuffer());
			assert.deepEqual(a.candidate.digest, s.verified[i].candidate.digest);
			assert.deepEqual(
				a.local,
				decodeTxCompleteMessage(s.payloads[i], { taproot: true })
			);
			assert.deepEqual(
				a.peer,
				decodeTxCompleteMessage(s.payloads[1 - i], { taproot: true })
			);
		}
	});
	it('replays a persisted outbound frame after restart and refuses altered bytes, wrong turns, removed items and a conflicting candidate for the same attempt', () => {
		let left = s.open(0);
		const right = s.open(1),
			sent = left.next()!;
		assert.equal(right.next(), undefined);
		const before = s.f.devices[1].store.readAssetSpliceJournal(s.f.id);
		const changed = Buffer.from(sent.payload);
		changed[changed.length - 1] ^= 1;
		for (const [type, data] of [
			[M.TX_ADD_INPUT, changed],
			[M.TX_REMOVE_INPUT, sent.payload],
			[M.TX_COMPLETE, s.payloads[1]]
		] as const)
			assert.throws(() => right.receive(type, data));
		assert.deepEqual(
			s.f.devices[1].store.readAssetSpliceJournal(s.f.id),
			before
		);
		const d = s.f.devices[0];
		d.store.close();
		d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		left = s.open(0);
		assert.deepEqual(left.replay(), sent);
		assert.throws(
			() =>
				new AssetSpliceConstruction(
					s.layout,
					s.verified[0],
					localPromise(s.layout.channelId, 2),
					d.store
				)
		);
		assert.throws(
			() =>
				new AssetSpliceConstruction(
					{ ...s.layout, stateNumber: 1n },
					s.verified[0],
					s.payloads[0],
					d.store
				)
		);
		right.receive(sent.type, sent.payload);
		const reply = right.next()!;
		assert.equal(reply.type, M.TX_COMPLETE);
		left.receive(reply.type, reply.payload);
		const next = left.next()!;
		assert.equal(next.type, M.TX_ADD_INPUT);
		assert.throws(() =>
			right.receive(
				M.TX_ADD_OUTPUT,
				encodeTxAddOutputMessage({
					channelId: s.layout.channelId,
					serialId: 4n,
					amountSats: 9999n,
					scriptPubkey: s.tx.outs[0].script
				})
			)
		);
		right.receive(next.type, next.payload);
	});
	it('refuses missing, aliased, reflected, noncanonical and wrong-channel completion nonces without advancing the turn', () => {
		const left = s.open(0),
			right = s.open(1),
			first = left.next()!;
		right.receive(first.type, first.payload);
		const peer = decodeTxCompleteMessage(s.payloads[1], { taproot: true });
		for (const payload of [
			peer.channelId,
			encodeTxCompleteMessage({
				...peer,
				fundingInputNonce: peer.commitNonces!.next
			}),
			s.payloads[0],
			Buffer.concat([s.payloads[1], Buffer.from([7, 0])]),
			encodeTxCompleteMessage({ ...peer, channelId: tag(99) })
		]) {
			assert.throws(() => left.receive(M.TX_COMPLETE, payload));
		}
		const valid = right.next()!;
		left.receive(valid.type, valid.payload);
		assert.equal(left.next()!.type, M.TX_ADD_INPUT);
	});
});
