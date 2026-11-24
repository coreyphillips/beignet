import { expect } from 'chai';
import { createHash } from 'crypto';
import {
	AssetOpenObjectReceiver,
	decodeAssetOpenFrame,
	decodeAssetOpenConsent,
	encodeAssetOpenConsent,
	encodeAssetOpenFrame,
	type IAssetOpenFrame
} from '../../src/lightning/message/asset-open';
import {
	BeignetCustomSubtype,
	encodeCustomMessage
} from '../../src/lightning/message/custom';

const chunkSize = 32 * 1024;
const maxSize = 4 * 1024 * 1024;
const attempt = Buffer.from('11'.repeat(32), 'hex');
const vectorDigest = Buffer.from(
	'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
	'hex'
);
const phases = [
	'layout',
	'authorization',
	'final',
	'exit',
	'layout_ack',
	'final_ack',
	'construction_checkpoint'
] as const;

function vector(phase: IAssetOpenFrame['phase'] = 'layout'): IAssetOpenFrame {
	const ack =
		phase === 'layout_ack' ||
		phase === 'final_ack' ||
		phase === 'construction_checkpoint';
	return {
		phase,
		attempt: Buffer.from(attempt),
		digest: Buffer.from(vectorDigest),
		total: ack ? 0 : 3,
		offset: 0,
		bytes: Buffer.from(ack ? '' : 'abc')
	};
}

function chunks(bytes: Buffer): IAssetOpenFrame[] {
	const digest = createHash('sha256').update(bytes).digest();
	const result: IAssetOpenFrame[] = [];
	for (let offset = 0; offset < bytes.length; offset += chunkSize) {
		result.push({
			phase: 'layout',
			attempt: Buffer.from(attempt),
			digest: Buffer.from(digest),
			total: bytes.length,
			offset,
			bytes: Buffer.from(bytes.subarray(offset, offset + chunkSize))
		});
	}
	return result;
}

describe('Asset opening wire version 1', function () {
	for (const [code, phase] of phases.entries()) {
		it(`pins the ${phase} frame on the custom envelope`, function () {
			const frame = vector(phase);
			const hex =
				'01' +
				code.toString(16).padStart(2, '0') +
				'11'.repeat(32) +
				vectorDigest.toString('hex') +
				(code < 4 ? '0000000300000000616263' : '0000000000000000');
			const raw = Buffer.from(hex, 'hex');
			expect(BeignetCustomSubtype[96]).to.match(/asset.*open/i);
			expect(
				encodeCustomMessage(96, encodeAssetOpenFrame(frame))
			).to.deep.equal(Buffer.from('00010060' + hex, 'hex'));
			expect(decodeAssetOpenFrame(raw)).to.deep.equal(frame);
		});
	}

	it('pins the consent envelope to the attempt and prepared allocation', function () {
		const signature = Buffer.alloc(64, 0x43);
		const bytes = Buffer.from(
			'01' + '11'.repeat(32) + vectorDigest.toString('hex') + '43'.repeat(64),
			'hex'
		);
		const consent = { attempt, digest: vectorDigest, signature };
		expect(decodeAssetOpenConsent(bytes)).to.deep.equal(consent);
		expect(
			encodeCustomMessage(
				BeignetCustomSubtype.ASSET_OPEN_CONSENT,
				encodeAssetOpenConsent(consent)
			)
		).to.deep.equal(Buffer.concat([Buffer.from('00010061', 'hex'), bytes]));
		for (const raw of [
			bytes.subarray(0, 128),
			Buffer.concat([bytes, Buffer.of(0)]),
			Buffer.concat([Buffer.of(2), bytes.subarray(1)])
		])
			expect(() => decodeAssetOpenConsent(raw)).to.throw();
		expect(() =>
			encodeAssetOpenConsent({ ...consent, signature: Buffer.alloc(65) })
		).to.throw();
	});

	it('refuses unsupported versions, phases, and truncated frames', function () {
		const raw = encodeAssetOpenFrame(vector());
		for (let n = 0; n < raw.length; n++) {
			expect(() => decodeAssetOpenFrame(raw.subarray(0, n))).to.throw();
		}
		for (const [position, value] of [
			[0, 0],
			[0, 2],
			[1, 7],
			[1, 255]
		]) {
			const copy = Buffer.from(raw);
			copy[position] = value;
			expect(() => decodeAssetOpenFrame(copy)).to.throw();
		}
	});

	it('refuses lengths, offsets and acknowledgements outside the wire contract', function () {
		const base = vector();
		for (const invalid of [
			{ ...base, attempt: Buffer.alloc(33) },
			{ ...base, digest: Buffer.alloc(31) },
			{ ...base, total: -1 },
			{ ...base, total: 1.5 },
			{ ...base, offset: 1 },
			{ ...base, offset: chunkSize },
			{ ...base, total: 0, bytes: Buffer.alloc(0) },
			{ ...base, total: maxSize + 1, bytes: Buffer.alloc(chunkSize) },
			{ ...base, total: chunkSize + 1, bytes: Buffer.alloc(chunkSize + 1) },
			{ ...base, total: chunkSize + 1 },
			{ ...vector('layout_ack'), total: 1 },
			{ ...vector('final_ack'), offset: chunkSize },
			{ ...vector('final_ack'), bytes: Buffer.from([0]) }
		]) {
			expect(() => encodeAssetOpenFrame(invalid)).to.throw();
		}
		for (const [phase, total, offset, length] of [
			[0, 0, 0, 0],
			[1, maxSize + 1, 0, chunkSize],
			[2, chunkSize + 1, 1, chunkSize],
			[3, 7, 0, 8],
			[4, 1, 0, 1],
			[5, 0, 0, 1]
		]) {
			const header = encodeAssetOpenFrame(base).subarray(0, 74);
			header[1] = phase;
			header.writeUInt32BE(total, 66);
			header.writeUInt32BE(offset, 70);
			expect(() =>
				decodeAssetOpenFrame(Buffer.concat([header, Buffer.alloc(length)]))
			).to.throw();
		}
	});

	it('round trips the last full chunk at the 4 MiB object boundary', function () {
		const frame = {
			...vector(),
			total: maxSize,
			offset: maxSize - chunkSize,
			bytes: Buffer.alloc(chunkSize, 0x7f)
		};
		expect(decodeAssetOpenFrame(encodeAssetOpenFrame(frame))).to.deep.equal(
			frame
		);
	});
});

describe('Asset opening proof object assembly', function () {
	const bytes = Buffer.concat([
		Buffer.alloc(chunkSize, 0xab),
		Buffer.from('end')
	]);

	it('assembles in order and accepts exact chunk replays', function () {
		const [first, last] = chunks(bytes);
		const receiver = new AssetOpenObjectReceiver(
			attempt,
			'layout',
			bytes.length
		);
		expect(receiver.receive(first)).to.equal(undefined);
		expect(
			receiver.receive(decodeAssetOpenFrame(encodeAssetOpenFrame(first)))
		).to.equal(undefined);
		expect(receiver.receive(last)).to.deep.equal(bytes);
		expect(() => receiver.receive(last)).not.to.throw();
	});

	it('checks the attempt, phase and configured byte limit before assembly', function () {
		const [first] = chunks(bytes);
		for (const changed of [
			{ ...first, attempt: Buffer.alloc(32, 0x22) },
			{ ...first, phase: 'authorization' as const },
			{ ...first, phase: 'layout_ack' as const },
			{ ...first, total: 0xffffffff }
		]) {
			const receiver = new AssetOpenObjectReceiver(attempt, 'layout', maxSize);
			expect(() => receiver.receive(changed)).to.throw();
		}
		const receiver = new AssetOpenObjectReceiver(
			attempt,
			'layout',
			bytes.length - 1
		);
		expect(() => receiver.receive(first)).to.throw();
	});

	it('rejects missing prefixes and changes to previously accepted bytes or metadata', function () {
		const [first, last] = chunks(bytes);
		expect(() =>
			new AssetOpenObjectReceiver(attempt, 'layout', maxSize).receive(last)
		).to.throw();
		for (const different of [
			{ ...first, bytes: Buffer.alloc(chunkSize, 0xcc) },
			{ ...last, total: bytes.length + 1, bytes: Buffer.from('ends') },
			{ ...last, digest: Buffer.alloc(32, 0xcc) }
		]) {
			const receiver = new AssetOpenObjectReceiver(attempt, 'layout', maxSize);
			receiver.receive(first);
			expect(() => receiver.receive(different)).to.throw();
		}
	});

	it('accepts a complete object only when its SHA-256 matches', function () {
		const [first, last] = chunks(bytes);
		const receiver = new AssetOpenObjectReceiver(attempt, 'layout', maxSize);
		receiver.receive(first);
		expect(() =>
			receiver.receive({ ...last, bytes: Buffer.from('bad') })
		).to.throw();
	});

	it('owns the bytes it accepts even when the transport reuses its buffer', function () {
		const [first, last] = chunks(bytes);
		const receiver = new AssetOpenObjectReceiver(attempt, 'layout', maxSize);
		receiver.receive(first);
		first.bytes.fill(0);
		first.digest.fill(0);
		expect(receiver.receive(last)).to.deep.equal(bytes);
	});
});
