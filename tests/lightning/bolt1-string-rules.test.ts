/**
 * Issue #2039: the BOLT 1 string rule (lightning/bolts#1341) and minimal
 * features encoding, applied by every reader and writer that carries them:
 * BOLT 11 `d`, offer_description, offer_issuer, invreq_payer_note, the BOLT 12
 * features fields, invreq_bip_353_name, and node_announcement and
 * channel_announcement at gossip intake.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { bech32 } from 'bech32';
import {
	assertBolt1String,
	decodeBolt1String
} from '../../src/lightning/message/field-rules';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import {
	BECH32_MAX_LIMIT,
	Network,
	TagType,
	TIMESTAMP_WORDS
} from '../../src/lightning/invoice/types';
import {
	bufferToWords,
	encodeTaggedField,
	encodeUintToWords
} from '../../src/lightning/invoice/words';
import { signInvoice } from '../../src/lightning/invoice/signing';
import { buildHrp } from '../../src/lightning/invoice/amount';
import { encodeTlvStream, ITlvRecord } from '../../src/lightning/message/tlv';
import {
	OfferTlvType,
	InvoiceRequestTlvType,
	InvoiceTlvType,
	encodeOfferTlv,
	decodeOfferTlv,
	encodeInvoiceRequestTlv,
	decodeInvoiceRequestTlv,
	encodeInvoiceTlv,
	decodeInvoiceTlv,
	getTlvRecords,
	encodeTlvRecordRaw
} from '../../src/lightning/offer/tlv';
import { IOffer, IBolt12Invoice } from '../../src/lightning/offer/types';
import {
	encodeChannelAnnouncementMessage,
	decodeChannelAnnouncementMessage,
	encodeNodeAnnouncementMessage,
	decodeNodeAnnouncementMessage
} from '../../src/lightning/gossip/messages';
import { signNodeAnnouncement } from '../../src/lightning/gossip/validation';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import { INodeAnnouncementMessage } from '../../src/lightning/gossip/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	deserializeGraphNode,
	serializeGraphNode
} from '../../src/lightning/storage/serialization';
import { loadVectors, hexToBuffer } from './conformance/helpers';

const cp = (code: number): string => String.fromCodePoint(code);

/** Characters the BOLT 1 reader rule refuses, with the class each is in. */
const FORBIDDEN: Array<[string, number]> = [
	['NUL (Cc)', 0x0000],
	['DEL (Cc)', 0x007f],
	['line feed (Cc)', 0x000a],
	['zero-width space (Cf)', 0x200b],
	['right-to-left override (Cf)', 0x202e],
	['byte order mark (Cf)', 0xfeff],
	['private use (Co)', 0xe000],
	['line separator (Zl)', 0x2028],
	['paragraph separator (Zp)', 0x2029]
];

/** Byte strings that are not UTF-8 at all. */
const INVALID_UTF8: Array<[string, Buffer]> = [
	['ff fe', Buffer.from([0xff, 0xfe])],
	['an encoded surrogate (ed a0 80)', Buffer.from([0xed, 0xa0, 0x80])],
	['a truncated sequence (e2 80)', Buffer.from([0x61, 0xe2, 0x80])]
];

const ACCEPTED = [
	'1 cup of coffee',
	'ナンセンス 1杯',
	'café ' + cp(0x1f600),
	''
];

/** `a<ch>b` as UTF-8, so the bad character sits mid-string. */
function withChar(code: number): Buffer {
	return Buffer.from('a' + cp(code) + 'b', 'utf8');
}

function hex4(code: number): string {
	return 'U+' + code.toString(16).toUpperCase().padStart(4, '0');
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const k = (i: number): Buffer =>
		getPublicKey(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	return {
		fundingPubkey: k(0),
		revocationBasepoint: k(1),
		paymentBasepoint: k(2),
		delayedPaymentBasepoint: k(3),
		htlcBasepoint: k(4),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(
	extra: { alias?: string; eagerGossipVerify?: boolean } = {}
): LightningNode {
	return new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(crypto.randomBytes(32)),
		perCommitmentSeed: crypto.randomBytes(32),
		fundingPrivkey: crypto.randomBytes(32),
		...extra
	});
}

describe('BOLT 1 string rule and minimal features (#2039)', () => {
	describe('the shared rule', () => {
		for (const [name, code] of FORBIDDEN) {
			it(`a reader and a writer refuse ${name}`, () => {
				expect(() => decodeBolt1String(withChar(code), 'Field')).to.throw(
					`Field contains ${hex4(code)}, which BOLT 1 forbids`
				);
				expect(() => assertBolt1String('a' + cp(code) + 'b', 'Field')).to.throw(
					`Field contains ${hex4(code)}`
				);
			});
		}

		it('a leading byte order mark is refused, not stripped', () => {
			const bytes = Buffer.from(cp(0xfeff) + 'hi', 'utf8');
			expect(() => decodeBolt1String(bytes, 'Field')).to.throw('U+FEFF');
		});

		for (const [name, bytes] of INVALID_UTF8) {
			it(`a reader refuses invalid UTF-8: ${name}`, () => {
				expect(() => decodeBolt1String(bytes, 'Field')).to.throw(
					'Field is not valid UTF-8'
				);
			});
		}

		it('a writer refuses a lone surrogate and an unassigned code point', () => {
			expect(() =>
				assertBolt1String(String.fromCharCode(0xd800), 'F')
			).to.throw('U+D800');
			// U+0378 is unassigned (Cn): a writer MUST NOT send it, a reader
			// MAY take it and does.
			expect(() => assertBolt1String(cp(0x0378), 'F')).to.throw('U+0378');
			expect(decodeBolt1String(Buffer.from(cp(0x0378), 'utf8'), 'F')).to.equal(
				cp(0x0378)
			);
		});

		it('ordinary text passes both ways', () => {
			for (const text of ACCEPTED) {
				assertBolt1String(text, 'F');
				expect(decodeBolt1String(Buffer.from(text, 'utf8'), 'F')).to.equal(
					text
				);
			}
		});
	});

	describe('BOLT 11 d field', () => {
		const payeeKey = crypto.randomBytes(32);

		/** A correctly signed invoice whose d field holds `description` as is. */
		function rawInvoice(description: Buffer): string {
			const hrp = buildHrp(Network.REGTEST);
			const words = [
				...encodeUintToWords(1_700_000_000, TIMESTAMP_WORDS),
				...encodeTaggedField(
					TagType.PAYMENT_HASH,
					bufferToWords(crypto.randomBytes(32))
				),
				...encodeTaggedField(
					TagType.PAYMENT_SECRET,
					bufferToWords(crypto.randomBytes(32))
				),
				...encodeTaggedField(TagType.DESCRIPTION, bufferToWords(description))
			];
			const sig = signInvoice(hrp, words, payeeKey);
			return bech32.encode(
				hrp,
				[...words, ...bufferToWords(sig)],
				BECH32_MAX_LIMIT
			);
		}

		it('the raw builder makes an invoice decode accepts', () => {
			for (const text of ACCEPTED) {
				const inv = decodeInvoice(rawInvoice(Buffer.from(text, 'utf8')));
				expect(inv.description).to.equal(text);
			}
		});

		for (const [name, code] of FORBIDDEN) {
			it(`decode refuses ${name}, and encode will not write it`, () => {
				expect(() => decodeInvoice(rawInvoice(withChar(code)))).to.throw(
					`Invoice field d contains ${hex4(code)}`
				);
				expect(() =>
					encodeInvoice({
						network: Network.REGTEST,
						paymentHash: crypto.randomBytes(32),
						paymentSecret: crypto.randomBytes(32),
						description: 'a' + cp(code) + 'b',
						privateKey: payeeKey
					})
				).to.throw(`Invoice description contains ${hex4(code)}`);
			});
		}

		for (const [name, bytes] of INVALID_UTF8) {
			it(`decode refuses invalid UTF-8: ${name}`, () => {
				expect(() => decodeInvoice(rawInvoice(bytes))).to.throw(
					'Invoice field d is not valid UTF-8'
				);
			});
		}

		for (const hold of [false, true]) {
			it(`rejected descriptions leave no invoice state (hold=${hold})`, () => {
				const node = makeNode();
				const options = {
					description: 'a' + cp(0x202e) + 'b',
					hold,
					paymentHash: hold ? crypto.randomBytes(32) : undefined
				};
				try {
					expect(() => node.createInvoice(options)).to.throw(
						'Invoice description contains U+202E'
					);
					expect(node['preimages'].size).to.equal(0);
					expect(node['paymentSecrets'].size).to.equal(0);
					expect(node['heldInvoiceHashes'].size).to.equal(0);
					expect(() =>
						node.createInvoice({ ...options, description: 'corrected' })
					).to.not.throw();
				} finally {
					node.destroy();
				}
			});
		}
	});

	describe('BOLT 12 offers', () => {
		const issuerId = getPublicKey(crypto.randomBytes(32));

		function rawOffer(records: ITlvRecord[]): Buffer {
			return encodeTlvStream(
				[
					...records,
					{ type: BigInt(OfferTlvType.ISSUER_ID), value: issuerId }
				].sort((a, b) => (a.type < b.type ? -1 : 1))
			);
		}
		const description = (value: Buffer): ITlvRecord => ({
			type: BigInt(OfferTlvType.DESCRIPTION),
			value
		});

		for (const [name, code] of FORBIDDEN) {
			it(`offer_description with ${name} is refused`, () => {
				expect(() =>
					decodeOfferTlv(rawOffer([description(withChar(code))]))
				).to.throw(`Offer description contains ${hex4(code)}`);
			});
		}

		it('offer_issuer with U+0000 is refused', () => {
			const data = rawOffer([
				description(Buffer.from('ok')),
				{ type: BigInt(OfferTlvType.ISSUER), value: withChar(0) }
			]);
			expect(() => decodeOfferTlv(data)).to.throw(
				'Offer issuer contains U+0000'
			);
		});

		it('offer_features of 00 or 00 02 is refused', () => {
			for (const features of [[0x00], [0x00, 0x02]]) {
				const data = rawOffer([
					description(Buffer.from('ok')),
					{
						type: BigInt(OfferTlvType.FEATURES),
						value: Buffer.from(features)
					}
				]);
				expect(() => decodeOfferTlv(data)).to.throw(
					'Offer features are not minimally encoded'
				);
			}
		});

		it('the writer will not produce any of them', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'ok',
				issuerId
			};
			expect(() =>
				encodeOfferTlv({ ...offer, description: 'a' + cp(0x202e) })
			).to.throw('Offer description contains U+202E');
			expect(() => encodeOfferTlv({ ...offer, issuer: cp(0x200b) })).to.throw(
				'Offer issuer contains U+200B'
			);
			expect(() =>
				encodeOfferTlv({ ...offer, features: Buffer.from([0x00, 0x02]) })
			).to.throw('Offer features are not minimally encoded');
			const ok = decodeOfferTlv(
				encodeOfferTlv({ ...offer, issuer: 'Bob', features: Buffer.from([2]) })
			).offer;
			expect(ok.issuer).to.equal('Bob');
		});
	});

	describe('BOLT 12 invoice requests', () => {
		const payerKey = getPublicKey(crypto.randomBytes(32));
		const PAYER_KEY = BigInt(InvoiceRequestTlvType.PAYER_KEY);

		function rawRequest(records: ITlvRecord[]): Buffer {
			return encodeTlvStream(
				[...records, { type: PAYER_KEY, value: payerKey }].sort((a, b) =>
					a.type < b.type ? -1 : 1
				)
			);
		}
		const note = (value: Buffer): ITlvRecord => ({
			type: BigInt(InvoiceRequestTlvType.PAYER_NOTE),
			value
		});
		const bip353 = (value: Buffer): ITlvRecord => ({
			type: BigInt(InvoiceRequestTlvType.BIP_353_NAME),
			value
		});
		const nameField = (name: string, domain: string): Buffer =>
			Buffer.concat([
				Buffer.from([name.length]),
				Buffer.from(name, 'latin1'),
				Buffer.from([domain.length]),
				Buffer.from(domain, 'latin1')
			]);

		it('invreq_payer_note with U+0000 or invalid UTF-8 is refused', () => {
			expect(() =>
				decodeInvoiceRequestTlv(rawRequest([note(withChar(0))]))
			).to.throw('Invoice request payer note contains U+0000');
			expect(() =>
				decodeInvoiceRequestTlv(rawRequest([note(Buffer.from([0x61, 0xff]))]))
			).to.throw('Invoice request payer note is not valid UTF-8');
			const ok = decodeInvoiceRequestTlv(
				rawRequest([note(Buffer.from('Table 5'))])
			);
			expect(ok.request.payerNote).to.equal('Table 5');
		});

		it('invreq_features that is not minimal is refused', () => {
			const data = rawRequest([
				{
					type: BigInt(InvoiceRequestTlvType.FEATURES),
					value: Buffer.from([0x00, 0x02])
				}
			]);
			expect(() => decodeInvoiceRequestTlv(data)).to.throw(
				'Invoice request features are not minimally encoded'
			);
		});

		it('the writer will not produce a bad payer note or features', () => {
			const request = { payerKey, offerId: Buffer.alloc(32) };
			expect(() =>
				encodeInvoiceRequestTlv({ ...request, payerNote: 'x' + cp(0x202e) })
			).to.throw('Invoice request payer note contains U+202E');
			expect(() =>
				encodeInvoiceRequestTlv({ ...request, features: Buffer.from([0x00]) })
			).to.throw('Invoice request features are not minimally encoded');
		});

		it('a well-formed invreq_bip_353_name is accepted and kept', () => {
			const value = nameField('bob_1', 'pay.Example-2.com');
			const { records } = decodeInvoiceRequestTlv(rawRequest([bip353(value)]));
			const kept = records.find(
				(r) => r.type === BigInt(InvoiceRequestTlvType.BIP_353_NAME)
			);
			expect(kept?.value.equals(value)).to.equal(true);
			// Empty parts carry no byte outside the set.
			decodeInvoiceRequestTlv(rawRequest([bip353(nameField('', ''))]));
		});

		it('invreq_bip_353_name with a byte outside the set is refused', () => {
			for (const [name, domain] of [
				['a b', 'example.com'],
				['bob', 'x!.com'],
				['bob@x', 'example.com'],
				['b' + cp(0xe9), 'example.com']
			]) {
				expect(
					() =>
						decodeInvoiceRequestTlv(
							rawRequest([bip353(nameField(name, domain))])
						),
					`${name} @ ${domain}`
				).to.throw('invreq_bip_353_name has a byte outside');
			}
		});

		it('invreq_bip_353_name whose lengths do not fill the record is refused', () => {
			const full = nameField('bob', 'example.com');
			for (const value of [
				Buffer.alloc(0),
				full.subarray(0, 4),
				full.subarray(0, full.length - 1),
				Buffer.concat([full, Buffer.from([0x61])])
			]) {
				expect(() =>
					decodeInvoiceRequestTlv(rawRequest([bip353(value)]))
				).to.throw('invreq_bip_353_name length does not match its fields');
			}
		});
	});

	describe('BOLT 12 invoices', () => {
		const invoice: IBolt12Invoice = {
			paymentHash: crypto.randomBytes(32),
			amount: 1000n,
			description: '',
			createdAt: 1_700_000_000n,
			nodeId: getPublicKey(crypto.randomBytes(32))
		};

		function withRecord(record: ITlvRecord): Buffer {
			const records = [...getTlvRecords(encodeInvoiceTlv(invoice)), record];
			records.sort((a, b) => (a.type < b.type ? -1 : 1));
			return Buffer.concat(records.map(encodeTlvRecordRaw));
		}

		it('invoice_features of 00 00 02 00 00 is refused, and not written', () => {
			const features = Buffer.from([0x00, 0x00, 0x02, 0x00, 0x00]);
			expect(() =>
				decodeInvoiceTlv(
					withRecord({ type: BigInt(InvoiceTlvType.FEATURES), value: features })
				)
			).to.throw('Invoice features are not minimally encoded');
			expect(() => encodeInvoiceTlv({ ...invoice, features })).to.throw(
				'Invoice features are not minimally encoded'
			);
		});

		it('a mirrored offer_description is read under the same rule', () => {
			const data = withRecord({
				type: BigInt(OfferTlvType.DESCRIPTION),
				value: withChar(0x202e)
			});
			expect(() => decodeInvoiceTlv(data)).to.throw(
				'Invoice offer description contains U+202E'
			);
			const ok = withRecord({
				type: BigInt(OfferTlvType.DESCRIPTION),
				value: Buffer.from('coffee')
			});
			expect(decodeInvoiceTlv(ok).invoice.description).to.equal('coffee');
		});
	});

	describe('gossip', () => {
		const nodeKey = crypto.randomBytes(32);

		function nodeAnnouncement(
			fields: Partial<INodeAnnouncementMessage> = {},
			key: Buffer = nodeKey,
			timestamp = 1_700_000_000
		): Buffer {
			const payload = encodeNodeAnnouncementMessage({
				signature: Buffer.alloc(64),
				features: Buffer.alloc(0),
				timestamp,
				nodeId: getPublicKey(key),
				rgbColor: Buffer.from([1, 2, 3]),
				alias: Buffer.alloc(32),
				addresses: [],
				...fields
			});
			signNodeAnnouncement(payload, key).copy(payload, 0);
			return payload;
		}
		const alias = (text: Buffer): Buffer => {
			const out = Buffer.alloc(32);
			text.copy(out);
			return out;
		};

		it('node_announcement: an alias with a forbidden character is refused', () => {
			for (const [, code] of FORBIDDEN) {
				const payload = nodeAnnouncement({ alias: alias(withChar(code)) });
				expect(() => decodeNodeAnnouncementMessage(payload)).to.throw(
					`node_announcement alias contains ${hex4(code)}`
				);
			}
			const invalid = nodeAnnouncement({ alias: alias(Buffer.from([0xff])) });
			expect(() => decodeNodeAnnouncementMessage(invalid)).to.throw(
				'node_announcement alias is not valid UTF-8'
			);
		});

		it('node_announcement: trailing zero bytes are padding, not characters', () => {
			const payload = nodeAnnouncement({
				alias: alias(Buffer.from('ナンセンス', 'utf8'))
			});
			const msg = decodeNodeAnnouncementMessage(payload);
			expect(msg.alias.subarray(0, 15).toString('utf8')).to.equal('ナンセンス');
		});

		it('node_announcement: features of 00 or 00 02 are refused', () => {
			for (const features of [[0x00], [0x00, 0x02]]) {
				const payload = nodeAnnouncement({ features: Buffer.from(features) });
				expect(() => decodeNodeAnnouncementMessage(payload)).to.throw(
					'node_announcement features are not minimally encoded'
				);
			}
		});

		it('channel_announcement: features of 00 are refused', () => {
			const key = (): Buffer => getPublicKey(crypto.randomBytes(32));
			const ann = {
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				chainHash: REGTEST_CHAIN_HASH,
				shortChannelId: Buffer.alloc(8, 1),
				nodeId1: key(),
				nodeId2: key(),
				bitcoinKey1: key(),
				bitcoinKey2: key()
			};
			expect(() =>
				decodeChannelAnnouncementMessage(
					encodeChannelAnnouncementMessage({
						...ann,
						features: Buffer.from([0x00])
					})
				)
			).to.throw('channel_announcement features are not minimally encoded');
			decodeChannelAnnouncementMessage(
				encodeChannelAnnouncementMessage({ ...ann, features: Buffer.from([2]) })
			);
		});

		describe('intake', () => {
			// The private key behind the upstream alias vectors.
			const vectorKey = Buffer.alloc(32, 0x11);
			const vectorNodeId = getPublicKey(vectorKey);
			const vectors = loadVectors<{
				cases: Array<{ name: string; announcement: string }>;
			}>('bolt07/node-announcement-alias.json').cases;

			for (const eagerGossipVerify of [true, false]) {
				it(`ignores the six upstream alias vectors (eager verify ${eagerGossipVerify})`, () => {
					const node = makeNode({ eagerGossipVerify });
					try {
						const graph = node.getGraph();
						const other = getPublicKey(crypto.randomBytes(32));
						const [nodeId1, nodeId2] =
							Buffer.compare(vectorNodeId, other) < 0
								? [vectorNodeId, other]
								: [other, vectorNodeId];
						expect(
							graph.addChannelAnnouncement(
								{
									nodeSignature1: crypto.randomBytes(64),
									nodeSignature2: crypto.randomBytes(64),
									bitcoinSignature1: crypto.randomBytes(64),
									bitcoinSignature2: crypto.randomBytes(64),
									features: Buffer.alloc(0),
									chainHash: REGTEST_CHAIN_HASH,
									shortChannelId: Buffer.alloc(8, 7),
									nodeId1,
									nodeId2,
									bitcoinKey1: other,
									bitcoinKey2: other
								},
								{ verified: true }
							)
						).to.equal(true);
						const intake = node as unknown as {
							handleNodeAnnouncement(payload: Buffer): void;
						};
						for (const v of vectors) {
							intake.handleNodeAnnouncement(
								hexToBuffer(v.announcement).subarray(2)
							);
							expect(
								graph.getNode(vectorNodeId)?.announcement,
								v.name
							).to.equal(undefined);
						}
						// The same announcement with a clean alias is taken.
						intake.handleNodeAnnouncement(
							nodeAnnouncement(
								{ alias: alias(Buffer.from('lightningrocks')) },
								vectorKey,
								0x67b64b00
							)
						);
						expect(graph.getNode(vectorNodeId)?.announcement).to.not.equal(
							undefined
						);
					} finally {
						node.destroy();
					}
				});
			}

			it('a stored announcement that breaks the rules is dropped on restore', () => {
				const graph = new NetworkGraph(REGTEST_CHAIN_HASH);
				const restore = (
					fields: Partial<INodeAnnouncementMessage>
				): INodeAnnouncementMessage | undefined => {
					const key = crypto.randomBytes(32);
					const payload = nodeAnnouncement({}, key);
					const announcement = {
						...decodeNodeAnnouncementMessage(payload),
						...fields
					};
					// Through the storage form, so the restored fields are what a
					// SqliteStorage row gives back.
					graph.restoreNode(
						deserializeGraphNode(
							serializeGraphNode({
								nodeId: announcement.nodeId,
								channels: new Set(['00'.repeat(8)]),
								announcement,
								announcementVerified: true
							})
						)
					);
					return graph.getNode(announcement.nodeId)?.announcement;
				};
				expect(restore({ alias: alias(withChar(0x202e)) })).to.equal(undefined);
				expect(restore({ features: Buffer.from([0x00]) })).to.equal(undefined);
				expect(restore({ alias: alias(Buffer.from('fine')) })).to.not.equal(
					undefined
				);
			});
		});
	});

	describe('our own alias', () => {
		it('a node will not start with an alias holding U+202E', () => {
			expect(() => makeNode({ alias: 'shop' + cp(0x202e) + 'evil' })).to.throw(
				'Node alias contains U+202E, which BOLT 1 forbids'
			);
		});

		it('a clean alias is announced as given', () => {
			const node = makeNode({ alias: 'café ' + cp(0x26a1) });
			try {
				const payload = (
					node as unknown as {
						buildNodeAnnouncement(t: number): Buffer | null;
					}
				).buildNodeAnnouncement(1_700_000_000);
				const msg = decodeNodeAnnouncementMessage(payload!);
				const text = msg.alias
					.subarray(0, msg.alias.indexOf(0))
					.toString('utf8');
				expect(text).to.equal('café ' + cp(0x26a1));
			} finally {
				node.destroy();
			}
		});
	});
});
