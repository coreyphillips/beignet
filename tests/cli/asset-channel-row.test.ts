/**
 * The daemon's channel rows (GET /channels, listChannels, getChannel) say
 * which channel is an asset channel, and say nothing new about any other.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { getOpenApiSpec } from '../../src/cli/openapi';

const host = {
	node: {
		getFforEpoch: (): undefined => undefined,
		getChannelManager: () => ({ getPeerForChannel: () => 'peerpk' }),
		peerSupportsSplicing: (): null => null
	}
};

const row = {
	channelId: Buffer.alloc(32, 7),
	peerPubkey: 'peerpk',
	state: 'NORMAL',
	localBalanceMsat: 60_000_000n,
	remoteBalanceMsat: 40_000_000n,
	fundingSatoshis: 100_000n,
	channelType: null,
	htlcUsable: true
};

const toChannelInfo = (
	input: Record<string, unknown>
): Record<string, unknown> =>
	(
		BeignetNode.prototype as unknown as {
			toChannelInfo(this: unknown, ch: unknown): Record<string, unknown>;
		}
	).toChannelInfo.call(host, input);

describe('the asset flag on a daemon channel row', () => {
	it('is true on an asset channel and is no key at all on any other', () => {
		const ordinary = toChannelInfo(row);
		expect('auxiliary' in ordinary).to.equal(false);
		expect(JSON.stringify(ordinary)).to.not.include('auxiliary');

		const asset = toChannelInfo({ ...row, auxiliary: true });
		expect(asset.auxiliary).to.equal(true);

		// The flag is the only difference: the row's own figures stay on it.
		const { auxiliary: _flag, ...rest } = asset;
		expect(JSON.stringify(rest)).to.equal(JSON.stringify(ordinary));
		expect(asset.localBalanceSats).to.equal(60_000);
		expect(asset.capacitySats).to.equal(100_000);
	});

	it("is documented for the API, with the balance key that holds an asset channel's sats", () => {
		const spec = JSON.stringify(getOpenApiSpec());
		expect(spec).to.include('"auxiliary":{"type":"boolean"');
		expect(spec).to.include('"assetChannelSats"');
	});
});
