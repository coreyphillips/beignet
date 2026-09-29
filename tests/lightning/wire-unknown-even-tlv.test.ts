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
import { decodeTxSignaturesMessage } from '../../src/lightning/message/interactive-tx';

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
	{ name: 'tx_signatures', fixedLength: 66, decode: decodeTxSignaturesMessage }
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
});
