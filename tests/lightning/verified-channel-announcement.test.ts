import { expect } from 'chai';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	BITCOIN_CHAIN_HASH,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import {
	encodeShortChannelId,
	IGraphChannel
} from '../../src/lightning/gossip/types';
import {
	makeSignedChannelAnnouncement,
	makeSignedChannelKeys
} from './helpers/signed-gossip';

describe('Verified channel announcement lookup', () => {
	const scid = encodeShortChannelId({ block: 500, txIndex: 2, outputIndex: 0 });
	const otherScid = encodeShortChannelId({
		block: 500,
		txIndex: 3,
		outputIndex: 0
	});

	for (const verified of [true, undefined] as const) {
		const provenance = verified ? 'cached verified' : 'deferred';
		for (const mismatch of ['SCID', 'chain'] as const) {
			it(`rejects a ${provenance} restored announcement for another ${mismatch}`, () => {
				const graph = new NetworkGraph();
				const { msg } = makeSignedChannelAnnouncement(
					mismatch === 'SCID' ? otherScid : scid,
					makeSignedChannelKeys(),
					mismatch === 'chain' ? REGTEST_CHAIN_HASH : BITCOIN_CHAIN_HASH
				);
				const row: IGraphChannel = {
					shortChannelId: scid,
					nodeId1: msg.nodeId1,
					nodeId2: msg.nodeId2,
					features: msg.features,
					announcement: msg,
					announcementVerified: verified,
					announcementVerifyDeferred: verified ? undefined : true
				};
				graph.restoreChannel(row);
				expect(graph.getVerifiedChannelAnnouncement(scid)).to.equal(undefined);
			});
		}
	}

	for (const valid of [true, false]) {
		it(`resolves a matching deferred announcement with ${
			valid ? 'valid' : 'invalid'
		} signatures`, () => {
			const graph = new NetworkGraph(REGTEST_CHAIN_HASH);
			const { msg } = makeSignedChannelAnnouncement(
				scid,
				makeSignedChannelKeys(),
				REGTEST_CHAIN_HASH
			);
			if (!valid) msg.bitcoinSignature2[40] ^= 1;
			graph.addChannelAnnouncement(msg, { verified: 'deferred' });
			const row = graph.getChannel(scid)!;
			expect(row.announcementVerifyDeferred).to.equal(true);
			expect(graph.getVerifiedChannelAnnouncement(scid)).to.equal(
				valid ? msg : undefined
			);
			expect(row.announcementVerified).to.equal(valid);
			expect(row.announcementVerifyDeferred).to.equal(undefined);
			expect(graph.getVerifiedChannelAnnouncement(scid)).to.equal(
				valid ? msg : undefined
			);
		});
	}
});
