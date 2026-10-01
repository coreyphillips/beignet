/**
 * BOLT 1: an unknown even TLV type fails the message, an unknown odd one is
 * skipped. Each parser gets its fixed fields (all zero, which every decoder
 * here accepts) followed by a single TLV record.
 */

import { expect } from 'chai';
import { decodeInitMessage } from '../../src/lightning/message/init';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../src/lightning/message/channel-funding';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import {
	decodeTxAddInputMessage,
	decodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { decodeStartBatchMessage } from '../../src/lightning/message/splice';

interface IParser {
	name: string;
	fixedLength: number;
	decode: (payload: Buffer) => unknown;
}

const PARSERS: IParser[] = [
	{ name: 'init', fixedLength: 4, decode: decodeInitMessage },
	{ name: 'open_channel', fixedLength: 319, decode: decodeOpenChannelMessage },
	{
		name: 'accept_channel',
		fixedLength: 270,
		decode: decodeAcceptChannelMessage
	},
	{
		name: 'funding_created',
		fixedLength: 130,
		decode: decodeFundingCreatedMessage
	},
	{
		name: 'funding_signed',
		fixedLength: 96,
		decode: decodeFundingSignedMessage
	},
	{ name: 'channel_ready', fixedLength: 65, decode: decodeChannelReadyMessage },
	{
		name: 'commitment_signed',
		fixedLength: 98,
		decode: decodeCommitmentSignedMessage
	},
	{
		name: 'revoke_and_ack',
		fixedLength: 97,
		decode: decodeRevokeAndAckMessage
	},
	{
		name: 'channel_reestablish',
		fixedLength: 113,
		decode: decodeChannelReestablishMessage
	},
	{
		name: 'open_channel2',
		fixedLength: 344,
		decode: decodeOpenChannel2Message
	},
	{
		name: 'accept_channel2',
		fixedLength: 303,
		decode: decodeAcceptChannel2Message
	},
	{ name: 'tx_signatures', fixedLength: 66, decode: decodeTxSignaturesMessage },
	{
		name: 'update_add_htlc',
		fixedLength: 1450,
		decode: decodeUpdateAddHtlcMessage
	},
	{ name: 'tx_add_input', fixedLength: 50, decode: decodeTxAddInputMessage },
	{ name: 'start_batch', fixedLength: 34, decode: decodeStartBatchMessage }
];

function parser(name: string): IParser {
	const p = PARSERS.find((x) => x.name === name);
	if (!p) throw new Error(`no parser named ${name}`);
	return p;
}

/**
 * Parsers that once read TLV type and length as single bytes, each with its
 * one known record and that record's required value length.
 */
const KNOWN_RECORDS: Array<{
	parser: IParser;
	type: number;
	length: number;
	field: string;
}> = [
	{
		parser: parser('update_add_htlc'),
		type: 0,
		length: 33,
		field: 'blindingPoint'
	},
	{
		parser: parser('tx_add_input'),
		type: 0,
		length: 32,
		field: 'sharedInputTxid'
	},
	{ parser: parser('start_batch'), type: 1, length: 2, field: 'messageType' }
];

function withRecord(fixedLength: number, type: number, value: Buffer): Buffer {
	return Buffer.concat([
		Buffer.alloc(fixedLength),
		Buffer.from([type, value.length]),
		value
	]);
}

describe('BOLT 1 unknown TLV types in wire messages', function () {
	for (const p of PARSERS) {
		describe(p.name, function () {
			it('rejects an unknown even type', function () {
				expect(() =>
					p.decode(withRecord(p.fixedLength, 10, Buffer.alloc(2)))
				).to.throw('Unknown required TLV type: 10');
			});

			it('skips an unknown odd type', function () {
				expect(() =>
					p.decode(withRecord(p.fixedLength, 11, Buffer.alloc(2)))
				).to.not.throw();
			});
		});
	}

	for (const p of PARSERS.filter((x) => x.name.endsWith('_channel2'))) {
		it(`${p.name} accepts upfront_shutdown_script (0)`, function () {
			expect(() =>
				p.decode(withRecord(p.fixedLength, 0, Buffer.alloc(0)))
			).to.not.throw();
		});

		it(`${p.name} refuses require_confirmed_inputs (2), which the open does not honour`, function () {
			expect(() =>
				p.decode(withRecord(p.fixedLength, 2, Buffer.alloc(0)))
			).to.throw('Unknown required TLV type: 2');
		});
	}

	for (const k of KNOWN_RECORDS) {
		const { parser: p } = k;
		const fixed = Buffer.alloc(p.fixedLength);

		it(`${p.name} rejects an unknown even multi-byte BigSize type (256)`, function () {
			const payload = Buffer.concat([fixed, Buffer.from('fd010000', 'hex')]);
			expect(() => p.decode(payload)).to.throw(
				'Unknown required TLV type: 256'
			);
		});

		it(`${p.name} skips an unknown odd multi-byte BigSize type (257)`, function () {
			const payload = Buffer.concat([fixed, Buffer.from('fd010100', 'hex')]);
			expect(() => p.decode(payload)).to.not.throw();
		});

		it(`${p.name} decodes its known record (type ${k.type})`, function () {
			const decoded = p.decode(
				withRecord(p.fixedLength, k.type, Buffer.alloc(k.length, 1))
			) as Record<string, unknown>;
			expect(decoded[k.field]).to.not.equal(undefined);
		});

		it(`${p.name} rejects its known record at the wrong length`, function () {
			expect(() =>
				p.decode(withRecord(p.fixedLength, k.type, Buffer.alloc(k.length - 1)))
			).to.throw(`must be ${k.length} bytes`);
		});
	}
});
