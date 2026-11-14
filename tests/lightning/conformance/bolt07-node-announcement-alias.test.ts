/**
 * BOLT 7: node_announcement alias vectors (bolt07/node-announcement-alias.json).
 *
 * Each announcement is validly signed and differs from an acceptable one only
 * in its alias, which holds a character the BOLT 1 string rule forbids. The
 * spec says implementations MUST ignore them, so the decoder refuses each one.
 * Gossip intake is covered in tests/lightning/bolt1-string-rules.test.ts.
 */

import { expect } from 'chai';
import { decodeNodeAnnouncementMessage } from '../../../src/lightning/gossip/messages';
import { verifyNodeAnnouncement } from '../../../src/lightning/gossip/validation';
import { INodeAnnouncementMessage } from '../../../src/lightning/gossip/types';
import { loadVectors, hexToBuffer } from './helpers';

interface IAliasCase {
	name: string;
	alias: string;
	announcement: string;
}

const NODE_ANNOUNCEMENT_TYPE = 257;

const { cases } = loadVectors<{ cases: IAliasCase[] }>(
	'bolt07/node-announcement-alias.json'
);

describe('BOLT 7 conformance: node_announcement alias vectors', () => {
	it('has the six upstream vectors', () => {
		expect(cases).to.have.length(6);
	});

	for (const c of cases) {
		describe(c.name, () => {
			const wire = hexToBuffer(c.announcement);
			const payload = wire.subarray(2);
			const flen = payload.readUInt16BE(64);
			const nodeIdAt = 64 + 2 + flen + 4;
			const aliasAt = nodeIdAt + 33 + 3;

			it('is a validly signed node_announcement carrying the vector alias', () => {
				expect(wire.readUInt16BE(0)).to.equal(NODE_ANNOUNCEMENT_TYPE);
				const alias = Buffer.alloc(32);
				Buffer.from(c.alias, 'utf8').copy(alias);
				expect(payload.subarray(aliasAt, aliasAt + 32).equals(alias)).to.equal(
					true
				);
				const signedFields = {
					signature: payload.subarray(0, 64),
					nodeId: payload.subarray(nodeIdAt, nodeIdAt + 33)
				} as INodeAnnouncementMessage;
				expect(verifyNodeAnnouncement(signedFields, payload)).to.equal(true);
			});

			it('is refused by the decoder for its alias', () => {
				expect(() => decodeNodeAnnouncementMessage(payload)).to.throw(
					/node_announcement alias contains U\+/
				);
			});
		});
	}
});
