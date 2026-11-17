/**
 * Asset channels and the daemon's bitcoin figures (issue #2093).
 *
 * An asset channel's bitcoin only carries asset outputs: it cannot be sent
 * or received as a Lightning payment. The engine's liquidity snapshot leaves
 * such a channel out, and so does everything the daemon computes over the
 * channel rows itself: what it can send, what it can receive, the sendable
 * figures of GET /liquidity and the errored balance of GET /balance. The
 * rows of an ordinary channel are counted as they always were.
 *
 * Offline: the methods are called on a stand-in wallet whose node lists the
 * rows given, the way the daemon's own loops read them.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';

type Row = Record<string, unknown>;

const row = (fill: number, extra: Row = {}): Row => ({
	channelId: Buffer.alloc(32, fill),
	peerPubkey: 'peerpk',
	state: 'NORMAL',
	localBalanceMsat: 60_000_000n,
	remoteBalanceMsat: 40_000_000n,
	localReserveMsat: 1_000_000n,
	remoteReserveMsat: 1_000_000n,
	spendableOutboundMsat: 58_000_000n,
	fundingSatoshis: 100_000n,
	channelType: null,
	htlcUsable: true,
	...extra
});

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => Record<string, unknown>
>;

/** A wallet whose node lists `rows`. */
const walletOf = (rows: Row[]): unknown => ({
	node: {
		listChannels: (): Row[] => rows,
		getFforEpoch: (): undefined => undefined,
		getChannelManager: (): unknown => ({
			getPeerForChannel: (): string => 'peerpk'
		}),
		peerSupportsSplicing: (): null => null,
		// The engine's snapshot, which leaves asset channels out itself.
		getLiquiditySnapshot: (): Row => ({
			totalLocalBalanceSats: 0,
			totalRemoteBalanceSats: 0,
			totalCapacitySats: 0,
			channelCount: 0,
			activeChannelCount: 0,
			outboundLiquidityPct: 0,
			inboundLiquidityPct: 0,
			recommendations: []
		})
	},
	toChannelInfo: methods.toChannelInfo
});

const figures = (
	rows: Row[]
): {
	send: Record<string, unknown>;
	receive: Record<string, unknown>;
	liquidity: Record<string, unknown>;
	errored: unknown;
} => {
	const wallet = walletOf(rows);
	return {
		send: methods.canSend.call(wallet, 10_000),
		receive: methods.canReceive.call(wallet, 10_000),
		liquidity: methods.getLiquiditySnapshot.call(wallet),
		errored: methods.getErroredBalanceSats.call(wallet)
	};
};

describe('Asset channels are left out of what the daemon can send, receive and count (#2093)', () => {
	const asset = row(7, { auxiliary: true });
	const ordinary = row(8);

	it('answers nothing to send or receive for a wallet whose only channel is an asset channel', () => {
		const { send, receive, liquidity } = figures([asset]);
		expect(send.canSend).to.equal(false);
		expect(send.availableSats).to.equal(0);
		expect(send.bestChannelId ?? null).to.equal(null);
		expect(receive.canReceive).to.equal(false);
		expect(receive.availableSats).to.equal(0);
		expect(receive.bestChannelId ?? null).to.equal(null);
		expect(liquidity.sendableSats).to.equal(0);
		expect(liquidity.maxSendableSats).to.equal(0);
		expect(liquidity.reserveSats).to.equal(0);
	});

	it('counts an ordinary channel exactly as it did, with an asset channel beside it or without', () => {
		const alone = figures([ordinary]);
		const beside = figures([asset, ordinary]);
		expect(alone.send.canSend).to.equal(true);
		expect(alone.send.availableSats).to.equal(59_000);
		expect(alone.receive.canReceive).to.equal(true);
		expect(alone.receive.availableSats).to.equal(39_000);
		expect(alone.liquidity.sendableSats).to.equal(59_000);
		expect(alone.liquidity.maxSendableSats).to.equal(58_000);
		expect(alone.liquidity.reserveSats).to.equal(1_000);
		expect(beside).to.deep.equal(alone);
		expect(beside.send.bestChannelId).to.equal(
			(ordinary.channelId as Buffer).toString('hex')
		);
	});

	it('does not count an errored asset channel as an errored Lightning balance', () => {
		expect(
			figures([row(7, { auxiliary: true, state: 'ERRORED' })]).errored
		).to.equal(0);
		expect(figures([row(8, { state: 'ERRORED' })]).errored).to.equal(60_000);
	});
});
