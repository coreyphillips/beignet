/**
 * LND's blinded payment path field in a BOLT 11 invoice (tag 20, zpay32),
 * issue #2093.
 *
 * The field is read only where the caller asks for it, which a node does
 * when asset channels are configured. Beignet's own field (tag 25) is still
 * the one it writes, and the bytes of an invoice it creates are pinned here.
 */

import { expect } from 'chai';
import { bech32 } from 'bech32';
import * as secp from '@noble/secp256k1';
import fixture from './conformance/vectors/bolt11/lnd-blinded-invoice.json';
import { decode } from '../../src/lightning/invoice/decode';
import { encode } from '../../src/lightning/invoice/encode';
import { IInvoice, Network, TagType } from '../../src/lightning/invoice/types';
import {
	decodeTaggedField,
	wordsToBuffer
} from '../../src/lightning/invoice/words';
import { encodeBigSize } from '../../src/lightning/message/codec';
import type { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	IBlindedPaymentPath,
	decodeLndInvoiceBlindedPath,
	encodeBlindedPayInfo
} from '../../src/lightning/onion/blinded-path';
import { assetHost, plainHost } from './helpers/auxiliary-nodes';

const LND_TAG = 20;

interface ITaggedField {
	type: number;
	/** The field's data as 5-bit words; not every field is whole bytes. */
	words: number[];
}

/** Every tagged field of an invoice, in the order it carries them. */
function taggedFields(invoice: string): ITaggedField[] {
	// Seven words of timestamp come before the fields, 104 of signature after.
	const words = bech32.decode(invoice, 10_000).words.slice(7, -104);
	const fields: ITaggedField[] = [];
	let offset = 0;
	while (offset < words.length) {
		const field = decodeTaggedField(words, offset);
		offset = field.nextOffset;
		fields.push({ type: field.type, words: field.dataWords });
	}
	return fields;
}

/**
 * One path in the framing of tag 20: payinfo, the path key, the hop count,
 * then each hop's key and its length-prefixed data, the first hop under the
 * introduction node's own key. Written here only to show the read loses
 * nothing; the engine writes no such field.
 */
function frame(entry: IBlindedPaymentPath): Buffer {
	const { path, payInfo } = entry;
	const parts = [
		encodeBlindedPayInfo(payInfo),
		path.blindingPoint,
		Buffer.from([path.blindedHops.length])
	];
	path.blindedHops.forEach((hop, index) => {
		parts.push(
			index === 0 ? path.introductionNodeId : hop.blindedNodeId,
			encodeBigSize(BigInt(hop.encryptedData.length)),
			hop.encryptedData
		);
	});
	return Buffer.concat(parts);
}

/** An invoice without the two members the option changes. */
function rest(invoice: IInvoice): Record<string, unknown> {
	const copy: Record<string, unknown> = { ...invoice };
	delete copy.blindedPaths;
	delete copy.unknownTags;
	return copy;
}

describe('BOLT 11 tag 20: the blinded payment paths of an LND invoice (issue #2093)', () => {
	/** The bytes of each tag 20 field of the upstream invoice. */
	const lndFields = taggedFields(fixture.invoice)
		.filter((field) => field.type === LND_TAG)
		.map((field) => wordsToBuffer(field.words));

	it('carries two of them in the upstream invoice', () => {
		expect(lndFields).to.have.length(2);
	});

	it('reads both paths where the caller asks for them, and loses nothing of either', () => {
		const invoice = decode(fixture.invoice, { lndBlindedPaths: true });
		const paths = invoice.blindedPaths ?? [];
		expect(paths).to.have.length(2);
		expect(paths[0].payInfo).to.deep.equal({
			feeBaseMsat: 40,
			feeProportionalMillionths: 20,
			cltvExpiryDelta: 130,
			htlcMinimumMsat: 2n,
			htlcMaximumMsat: 100n
		});
		paths.forEach((entry, index) => {
			expect(frame(entry), `path ${index}`).to.deep.equal(lndFields[index]);
			// The first hop is named by the introduction node's own key.
			expect(entry.path.introductionNodeId).to.deep.equal(
				entry.path.blindedHops[0].blindedNodeId
			);
		});
		expect((invoice.unknownTags ?? []).map((tag) => tag.type)).to.not.include(
			LND_TAG
		);
	});

	it('leaves the field an unknown one for a caller that does not ask, as it always was', () => {
		const plain = decode(fixture.invoice);
		expect(plain).to.not.have.property('blindedPaths');
		const unknown = plain.unknownTags ?? [];
		expect(unknown.filter((tag) => tag.type === LND_TAG)).to.have.length(2);

		// Nothing else about the invoice reads differently either way.
		const asked = decode(fixture.invoice, { lndBlindedPaths: true });
		expect(rest(asked)).to.deep.equal(rest(plain));
		expect(asked.unknownTags ?? []).to.deep.equal(
			unknown.filter((tag) => tag.type !== LND_TAG)
		);
		expect(decode(fixture.invoice, {})).to.deep.equal(plain);
		expect(decode(fixture.invoice, { lndBlindedPaths: false })).to.deep.equal(
			plain
		);
	});

	it('refuses a path that is cut short, runs on, or names more hops than seven', () => {
		const bytes = lndFields[0];
		const entry = decodeLndInvoiceBlindedPath(bytes);
		for (let length = 0; length < bytes.length; length++) {
			expect(
				() => decodeLndInvoiceBlindedPath(bytes.subarray(0, length)),
				`cut to ${length} bytes`
			).to.throw();
		}
		expect(() =>
			decodeLndInvoiceBlindedPath(Buffer.concat([bytes, Buffer.alloc(1)]))
		).to.throw('Trailing BOLT 11 blinded path bytes');
		const hops = Buffer.from(bytes);
		// The hop count follows the payinfo and the 33-byte path key.
		hops[encodeBlindedPayInfo(entry.payInfo).length + 33] = 8;
		expect(() => decodeLndInvoiceBlindedPath(hops)).to.throw(
			'Invalid BOLT 11 blinded path'
		);
		expect(() => decodeLndInvoiceBlindedPath(Buffer.alloc(640))).to.throw(
			'Oversized BOLT 11 blinded path'
		);
	});

	describe('in a node', () => {
		let nodes: LightningNode[] = [];

		afterEach(() => {
			for (const node of nodes) node.destroy();
			nodes = [];
		});

		/** The invoice as the node reads one it is asked to pay. */
		const read = (node: LightningNode): IInvoice =>
			(
				node as unknown as { decodeBolt11(invoice: string): IInvoice }
			).decodeBolt11(fixture.invoice);

		it('is read by a node with asset channels, and by no other', () => {
			const assets = assetHost('lnd-tag20', 1).node;
			const plain = plainHost('lnd-tag20', 2).node;
			nodes.push(assets, plain);
			expect(read(assets).blindedPaths).to.have.length(2);
			expect(read(plain)).to.deep.equal(decode(fixture.invoice));
			expect(read(plain)).to.not.have.property('blindedPaths');
		});

		it('is in no invoice a node creates, with asset channels or without', () => {
			const hosts = [
				assetHost('lnd-tag20', 3).node,
				plainHost('lnd-tag20', 4).node
			];
			nodes.push(...hosts);
			for (const node of hosts) {
				const { bolt11 } = node.createInvoice({
					amountMsat: 1_000n,
					description: 'pinned'
				});
				expect(taggedFields(bolt11).map((field) => field.type)).to.not.include(
					LND_TAG
				);
			}
		});
	});

	describe('what the encoder writes', () => {
		const point = (byte: number): Buffer =>
			Buffer.from(secp.getPublicKey(Buffer.alloc(32, byte), true));
		const base = {
			network: Network.REGTEST,
			amountMsat: 50_000_000n,
			timestamp: 1_700_000_000,
			paymentHash: Buffer.alloc(32, 0x21),
			paymentSecret: Buffer.alloc(32, 0x22),
			description: 'pinned',
			privateKey: Buffer.alloc(32, 0x11)
		};
		const blindedPaths: IBlindedPaymentPath[] = [
			{
				path: {
					introductionNodeId: point(0x31),
					blindingPoint: point(0x32),
					blindedHops: [
						{
							blindedNodeId: point(0x33),
							encryptedData: Buffer.alloc(20, 0x41)
						},
						{
							blindedNodeId: point(0x34),
							encryptedData: Buffer.alloc(21, 0x42)
						}
					]
				},
				payInfo: {
					feeBaseMsat: 1000,
					feeProportionalMillionths: 250,
					cltvExpiryDelta: 144,
					htlcMinimumMsat: 1n,
					htlcMaximumMsat: 100_000_000n
				}
			}
		];

		// Both strings were taken from the encoder as it was before tag 20
		// was read, from the inputs above. The signature is deterministic.
		const PLAIN =
			'lnbcrt500u1pj48ugqpp5yysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysssp5yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qdq2wp5kumn9vsdg5r7eckah8xxapx69u5sqt9846ev992gk8yn7wzmgc8svraeqy37epgunuj7p7rych0dxrkd4xww8wu7fys82tjkxhtk64qf2kkhjspmj6fxy';
		const BLINDED =
			'lnbcrt500u1pj48ugqpp5yysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysssp5yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qdq2wp5kumn9vse2vqypkjv85dhgtzmvxd4vazp225cef3v6hfxwdrp3w79hn7403et7whqszjzvemwl5xq6tl7ca65l2c845cvayagwy7j96tpw0mcurppq0q42syq3uw2kakn7lpxhefuxff4l7j23cdfl8pnu2rkzezcuxhvjnt3a3kyqpgs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5zqjq0jaxx5h2awf4fhr4egnrjeu9kfagtn756kzhthjypypzjttx9gqp2sjzgfpyysjzgfpyysjzgfpyysjzgfpyyssqqqp7sqqqqraqpyqqqqqqqqqqqqqsqqqqqqzltcgqqqqqffhplzgy98k9r0n3005dmtet7wwwafy7825854095ua3v89a9zun825t022yckax56fez59ygpkeaqr7404dm65mdkce9ggr2pj73esp9aua26';

		it('is byte for byte what it was, with blinded paths and without', () => {
			expect(encode(base)).to.equal(PLAIN);
			expect(encode({ ...base, blindedPaths })).to.equal(BLINDED);
		});

		it('carries blinded paths under tag 25, never under tag 20', () => {
			const types = taggedFields(encode({ ...base, blindedPaths })).map(
				(field) => field.type
			);
			expect(
				types.filter((type) => type === TagType.BLINDED_PATHS)
			).to.have.length(1);
			expect(TagType.BLINDED_PATHS).to.equal(25);
			expect(types).to.not.include(LND_TAG);
		});

		it('reads its own blinded paths back the same whether or not tag 20 is read', () => {
			const invoice = encode({ ...base, blindedPaths });
			const plain = decode(invoice);
			expect(plain.blindedPaths).to.deep.equal(blindedPaths);
			expect(decode(invoice, { lndBlindedPaths: true })).to.deep.equal(plain);
		});
	});
});
