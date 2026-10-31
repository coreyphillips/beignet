import { expect } from 'chai';
import { bech32 } from 'bech32';
import fixture from './conformance/vectors/bolt11/lnd-blinded-invoice.json';
import {
	decode,
	wordsToBuffer,
	decodeTaggedField
} from '../../src/lightning/invoice';
import {
	decodeLndInvoiceBlindedPath,
	encodeLndInvoiceBlindedPath
} from '../../src/lightning/onion/blinded-path';

describe('Pinned LND blinded invoice framing', () => {
	it('decodes the upstream invoice and reproduces both tag20 payloads byte for byte', () => {
		const invoice = decode(fixture.invoice);
		expect(invoice.blindedPaths).to.have.length(2);
		expect(invoice.blindedPaths![0].payInfo).to.deep.equal({
			feeBaseMsat: 40,
			feeProportionalMillionths: 20,
			cltvExpiryDelta: 130,
			htlcMinimumMsat: 2n,
			htlcMaximumMsat: 100n
		});
		const words = bech32.decode(fixture.invoice, 10000).words.slice(7, -104);
		let offset = 0,
			paths = 0;
		while (offset < words.length) {
			const field = decodeTaggedField(words, offset);
			offset = field.nextOffset;
			if (field.type !== 20) continue;
			const bytes = wordsToBuffer(field.dataWords);
			expect(
				encodeLndInvoiceBlindedPath(invoice.blindedPaths![paths++])
			).to.deep.equal(bytes);
		}
		expect(paths).to.equal(2);
	});
	it('rejects truncated, trailing and excessive hop/ciphertext lengths', () => {
		const entry = decode(fixture.invoice).blindedPaths![0];
		const bytes = encodeLndInvoiceBlindedPath(entry);
		for (let length = 0; length < bytes.length; length++)
			expect(() =>
				decodeLndInvoiceBlindedPath(bytes.subarray(0, length))
			).to.throw();
		expect(() =>
			decodeLndInvoiceBlindedPath(Buffer.concat([bytes, Buffer.alloc(1)]))
		).to.throw('Trailing');
		const count = Buffer.from(bytes);
		count[61] = 8;
		expect(() => decodeLndInvoiceBlindedPath(count)).to.throw();
		const tooLarge = {
			...entry,
			path: {
				...entry.path,
				blindedHops: [
					{ ...entry.path.blindedHops[0], encryptedData: Buffer.alloc(536) }
				]
			}
		};
		expect(() => encodeLndInvoiceBlindedPath(tooLarge)).to.throw();
	});
});
