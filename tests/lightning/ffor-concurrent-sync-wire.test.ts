import { expect } from 'chai';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
	bitmapLength,
	bitmapSet,
	decodeFforSyncMessage,
	decodeFforSyncReplyMessage,
	encodeFforSyncUnsigned,
	encodeFforSyncReplyUnsigned,
	fforMessageDigest,
	fforSyncSnapshotContent,
	fforWireBytes,
	signFforMessage,
	verifyFforMessage
} from '../../src/lightning/ffor/messages';
import {
	FF_SYNC_TYPE,
	FF_SYNC_REPLY_TYPE
} from '../../src/lightning/ffor/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

interface Vector {
	bytes: number;
	hex: string;
	digest: string;
	bitmap?: string;
}
const vectors = JSON.parse(
	readFileSync(
		join(__dirname, 'fixtures/ffor/concurrent-receive-wire.json'),
		'utf8'
	)
) as { request: Vector; responses: Record<string, Vector> };
const request = {
	channelId: Buffer.alloc(32, 0x11),
	epochId: Buffer.alloc(32, 0x22),
	activationHash: Buffer.alloc(32, 0x33),
	nonce: Buffer.alloc(32, 0x44)
};
const dummySignature = Buffer.alloc(64, 0x55);

describe('FFOR concurrent receipt sync wire', () => {
	it('matches the independent 194-byte request and digest', () => {
		const unsigned = encodeFforSyncUnsigned(request);
		const wire = fforWireBytes(
			FF_SYNC_TYPE,
			Buffer.concat([unsigned, dummySignature])
		);
		expect(wire.length).to.equal(vectors.request.bytes);
		expect(wire.toString('hex')).to.equal(vectors.request.hex);
		expect(fforMessageDigest(FF_SYNC_TYPE, unsigned).toString('hex')).to.equal(
			vectors.request.digest
		);
		expect(decodeFforSyncMessage(wire.subarray(2))).to.deep.equal({
			...request,
			signature: dummySignature
		});
	});

	for (const numSlots of [1, 9, 483]) {
		it(`matches the independent ${numSlots}-slot reply and digest`, () => {
			const settled = Buffer.alloc(bitmapLength(numSlots));
			const preimages = Array.from({ length: numSlots }, (_, i) => {
				const k = i + 1;
				bitmapSet(settled, k);
				const preimage = Buffer.alloc(32);
				preimage.writeUInt32BE(k, 28);
				return { k, preimage };
			});
			const reply = {
				...request,
				snapshotSeq: 7n,
				numSlots,
				settled,
				preimages
			};
			const unsigned = encodeFforSyncReplyUnsigned(reply);
			const wire = fforWireBytes(
				FF_SYNC_REPLY_TYPE,
				Buffer.concat([unsigned, dummySignature])
			);
			const vector = vectors.responses[String(numSlots)];
			expect(wire.length).to.equal(vector.bytes);
			expect(wire.toString('hex')).to.equal(vector.hex);
			expect(
				fforMessageDigest(FF_SYNC_REPLY_TYPE, unsigned).toString('hex')
			).to.equal(vector.digest);
			expect(decodeFforSyncReplyMessage(wire.subarray(2))).to.deep.equal({
				...reply,
				signature: dummySignature
			});
		});
	}

	it('round trips empty sequence zero with a real generated node signature', () => {
		const privateKey = Buffer.alloc(32, 9);
		const reply = {
			...request,
			snapshotSeq: 0n,
			numSlots: 9,
			settled: Buffer.alloc(2),
			preimages: []
		};
		const body = signFforMessage(
			FF_SYNC_REPLY_TYPE,
			encodeFforSyncReplyUnsigned(reply),
			privateKey
		);
		expect(
			verifyFforMessage(FF_SYNC_REPLY_TYPE, body, getPublicKey(privateKey))
		).to.be.true;
		expect(decodeFforSyncReplyMessage(body).snapshotSeq).to.equal(0n);
	});

	it('keeps canonical content independent of nonce and sequence', () => {
		const first = {
			...request,
			snapshotSeq: 2n,
			numSlots: 1,
			settled: Buffer.alloc(1),
			preimages: []
		};
		const next = { ...first, nonce: Buffer.alloc(32, 8), snapshotSeq: 3n };
		expect(fforSyncSnapshotContent(first).equals(fforSyncSnapshotContent(next)))
			.to.be.true;
		expect(
			encodeFforSyncReplyUnsigned(first).equals(
				encodeFforSyncReplyUnsigned(next)
			)
		).to.be.false;
	});

	it('checks local serializer bounds and bitmap completeness', () => {
		const empty = {
			...request,
			snapshotSeq: 0n,
			numSlots: 1,
			settled: Buffer.alloc(1),
			preimages: []
		};
		expect(() =>
			encodeFforSyncReplyUnsigned({ ...empty, numSlots: 484 })
		).to.throw('slot count');
		expect(() =>
			encodeFforSyncReplyUnsigned({ ...empty, settled: Buffer.from([2]) })
		).to.throw('unused bitmap bits');
		expect(() =>
			encodeFforSyncReplyUnsigned({ ...empty, settled: Buffer.from([1]) })
		).to.throw('preimage count');
	});
});
