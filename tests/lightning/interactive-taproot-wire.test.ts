import { expect } from 'chai';
import {
	decodeTxCompleteMessage,
	decodeTxSignaturesMessage,
	encodeTxCompleteMessage,
	encodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';

describe('Taproot interactive transaction messages', function () {
	const channelId = Buffer.alloc(32, 0x11);
	const txid = Buffer.from(
		'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		'hex'
	);
	const taproot = { taproot: true };

	// Each nonce contains two distinct compressed secp256k1 points, in
	// order from G through 6G. The partial scalar is a separate wire fixture.
	const current = Buffer.from(
		'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
			'02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
		'hex'
	);
	const next = Buffer.from(
		'02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9' +
			'02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13',
		'hex'
	);
	const fundingInputNonce = Buffer.from(
		'022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4' +
			'03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
		'hex'
	);
	const partial = Buffer.alloc(32, 0x33);
	const commitNonces = { current, next };
	const sharedInputPartialSignatureWithNonce = Buffer.concat([
		partial,
		fundingInputNonce
	]);
	const witnesses = [[Buffer.from('abcd', 'hex'), Buffer.from('ef', 'hex')]];
	const signatures = { channelId, txid, witnesses };

	// Eclair v0.14.0 InteractiveTxTlv and CommonCodecs. Spell out the
	// type and length bytes, independently of the engine's TLV helpers.
	const commitmentRecord = Buffer.concat([
		Buffer.from('0484', 'hex'),
		current,
		next
	]);
	const fundingRecord = Buffer.concat([
		Buffer.from('0642', 'hex'),
		fundingInputNonce
	]);
	const partialRecord = Buffer.concat([
		Buffer.from('0262', 'hex'),
		partial,
		fundingInputNonce
	]);
	// One witness, six serialized bytes, two stack elements abcd and ef.
	const signatureHeader = Buffer.concat([
		channelId,
		txid,
		Buffer.from('000100060202abcd01ef', 'hex')
	]);

	describe('tx_complete', function () {
		const vectors = [
			{
				name: 'v2 commitment nonces',
				fields: { commitNonces },
				records: [commitmentRecord]
			},
			{
				name: 'shared funding input nonce',
				fields: { fundingInputNonce },
				records: [fundingRecord]
			},
			{
				name: 'both records in increasing type order',
				fields: { fundingInputNonce, commitNonces },
				records: [commitmentRecord, fundingRecord]
			}
		];
		for (const { name, fields, records } of vectors) {
			it(`encodes and decodes ${name}`, function () {
				const frame = Buffer.concat([channelId, ...records]);
				const message = { channelId, ...fields };
				expect(encodeTxCompleteMessage(message)).to.deep.equal(frame);
				expect(decodeTxCompleteMessage(frame, taproot)).to.deep.equal(message);
			});
		}

		it('preserves ordinary frames and the default treatment of trailing bytes', function () {
			const message = { channelId };
			expect(encodeTxCompleteMessage(message)).to.deep.equal(channelId);
			expect(decodeTxCompleteMessage(channelId, taproot)).to.deep.equal(
				message
			);
			expect(
				decodeTxCompleteMessage(Buffer.concat([channelId, commitmentRecord]))
			).to.deep.equal(message);
			expect(
				decodeTxCompleteMessage(Buffer.concat([channelId, Buffer.from([4])]))
			).to.deep.equal(message);
		});

		it('skips optional records on both sides of a recognized record', function () {
			const frame = Buffer.concat([
				channelId,
				Buffer.from('0301aa', 'hex'),
				commitmentRecord,
				Buffer.from('0701bb', 'hex')
			]);
			expect(decodeTxCompleteMessage(frame, taproot)).to.deep.equal({
				channelId,
				commitNonces
			});
		});

		for (const size of [65, 67]) {
			it(`rejects a ${size}-byte nonce in each encoder position`, function () {
				const bad = Buffer.alloc(size);
				for (const fields of [
					{ commitNonces: { current: bad, next } },
					{ commitNonces: { current, next: bad } },
					{ fundingInputNonce: bad }
				]) {
					expect(() =>
						encodeTxCompleteMessage({ channelId, ...fields })
					).to.throw();
				}
			});
		}

		for (const [type, size] of [
			[4, 131],
			[4, 133],
			[6, 65],
			[6, 67]
		]) {
			it(`rejects a type ${type} record declaring ${size} bytes`, function () {
				const frame = Buffer.concat([
					channelId,
					Buffer.from([type, size]),
					Buffer.alloc(size)
				]);
				expect(() => decodeTxCompleteMessage(frame, taproot)).to.throw();
			});
		}
	});

	describe('tx_signatures', function () {
		it('places the partial scalar and public nonce after the wallet witnesses', function () {
			const message = { ...signatures, sharedInputPartialSignatureWithNonce };
			const frame = Buffer.concat([signatureHeader, partialRecord]);
			expect(encodeTxSignaturesMessage(message)).to.deep.equal(frame);
			expect(decodeTxSignaturesMessage(frame, taproot)).to.deep.equal(message);
			expect(() => decodeTxSignaturesMessage(frame)).to.throw(
				/unknown required TLV type: 2/i
			);
		});

		it('preserves the legacy shared-input signature and ordinary object shape', function () {
			const sharedInputSignature = Buffer.alloc(64, 0x44);
			const message = { ...signatures, sharedInputSignature };
			const frame = Buffer.concat([
				signatureHeader,
				Buffer.from('0040', 'hex'),
				sharedInputSignature
			]);
			expect(encodeTxSignaturesMessage(signatures)).to.deep.equal(
				signatureHeader
			);
			expect(decodeTxSignaturesMessage(signatureHeader, taproot)).to.deep.equal(
				signatures
			);
			expect(encodeTxSignaturesMessage(message)).to.deep.equal(frame);
			expect(decodeTxSignaturesMessage(frame)).to.deep.equal(message);
			expect(decodeTxSignaturesMessage(frame, taproot)).to.deep.equal(message);
			const shortLegacy = Buffer.concat([
				signatureHeader,
				Buffer.from('0001aa', 'hex')
			]);
			expect(decodeTxSignaturesMessage(shortLegacy)).to.deep.equal(signatures);
		});

		for (const size of [63, 65]) {
			it(`rejects a legacy signature of ${size} bytes in negotiated decoding`, function () {
				const frame = Buffer.concat([
					signatureHeader,
					Buffer.from([0, size]),
					Buffer.alloc(size)
				]);
				expect(() => decodeTxSignaturesMessage(frame, taproot)).to.throw();
			});
		}

		it('refuses both signature forms for a single shared funding input', function () {
			const sharedInputSignature = Buffer.alloc(64, 0x44);
			const frame = Buffer.concat([
				signatureHeader,
				Buffer.from('0040', 'hex'),
				sharedInputSignature,
				partialRecord
			]);
			expect(() =>
				encodeTxSignaturesMessage({
					...signatures,
					sharedInputSignature,
					sharedInputPartialSignatureWithNonce
				})
			).to.throw();
			expect(() => decodeTxSignaturesMessage(frame, taproot)).to.throw();
		});

		it('skips an optional record before the shared-input partial', function () {
			const frame = Buffer.concat([
				signatureHeader,
				Buffer.from('0101ab', 'hex'),
				partialRecord
			]);
			expect(decodeTxSignaturesMessage(frame, taproot)).to.deep.equal({
				...signatures,
				sharedInputPartialSignatureWithNonce
			});
		});

		for (const size of [97, 99]) {
			it(`rejects a shared-input partial with nonce of ${size} bytes`, function () {
				const bad = Buffer.alloc(size);
				const frame = Buffer.concat([
					signatureHeader,
					Buffer.from([2, size]),
					bad
				]);
				expect(() =>
					encodeTxSignaturesMessage({
						...signatures,
						sharedInputPartialSignatureWithNonce: bad
					})
				).to.throw();
				expect(() => decodeTxSignaturesMessage(frame, taproot)).to.throw();
			});
		}
	});

	for (const { name, header, record, decode } of [
		{
			name: 'tx_complete',
			header: channelId,
			record: fundingRecord,
			decode: decodeTxCompleteMessage
		},
		{
			name: 'tx_signatures',
			header: signatureHeader,
			record: partialRecord,
			decode: decodeTxSignaturesMessage
		}
	]) {
		describe(`${name} negotiated TLV framing`, function () {
			const type = record[0];
			const length = record[1];
			const value = record.subarray(2);
			const cases = [
				{
					name: 'duplicate records',
					tail: Buffer.concat([record, record]),
					error: /order/i
				},
				{
					name: 'decreasing types',
					tail: Buffer.concat([record, Buffer.from([1, 0])]),
					error: /order/i
				},
				{
					name: 'unknown required type',
					tail: Buffer.from([8, 0]),
					error: /unknown required TLV type: 8/i
				},
				{
					name: 'truncated payload',
					tail: record.subarray(0, -1),
					error: /bytes|truncat/i
				},
				{
					name: 'noncanonical type',
					tail: Buffer.concat([Buffer.from([0xfd, 0, type, length]), value]),
					error: /canonical/i
				},
				{
					name: 'noncanonical length',
					tail: Buffer.concat([Buffer.from([type, 0xfd, 0, length]), value]),
					error: /canonical/i
				}
			];
			for (const { name: condition, tail, error } of cases) {
				it(`rejects ${condition}`, function () {
					expect(() => decode(Buffer.concat([header, tail]), taproot)).to.throw(
						error
					);
				});
			}
		});
	}
});
