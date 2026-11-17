/**
 * What mainnet readiness tells a wallet that holds only asset channels
 * (issue #2093).
 *
 * The channel checks of mainnet readiness are about sending and receiving
 * bitcoin, so they read ordinary channels only. Four of them tell a
 * wallet with no channel that it has none, or none that is active, and a
 * wallet whose only channels are asset channels was told the same, which
 * is not true of it. Those four now say that it has no ordinary Lightning
 * channel and that asset channels are not counted, with the status they
 * had.
 *
 * A wallet without an asset channel is answered the bytes master answers,
 * pinned below, and so is a wallet with ordinary channels, ready or not,
 * whatever asset channels it holds beside them.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { ChannelState } from '../../src/lightning/channel/types';

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => unknown
>;

type Row = Record<string, unknown>;
interface ICheck {
	name: string;
	status: string;
	severity: string;
	message: string;
}
interface IReport {
	score: number;
	ready: boolean;
	checks: ICheck[];
}

/** The whole answer of the daemon over a node that lists `rows`, as JSON. */
const readiness = (rows: Row[]): string =>
	JSON.stringify(
		methods.getMainnetReadiness.call({
			storage: {},
			backupPath: '/backups',
			electrumServerCount: 2,
			getHealth: (): Row => ({ electrumConnected: true }),
			getFeeSnapshot: (): Row => ({ sampleCount: 3 }),
			channelBackupReadiness: (): Row => ({
				name: 'CHANNEL_BACKUP',
				status: 'PASS',
				severity: 'WARNING',
				message: 'backed up'
			}),
			node: {
				getNodeInfo: (): Row => ({ networkingEnabled: true }),
				listChannels: (): Row[] => rows,
				getGraph: (): Row => ({
					getChannelCount: (): number => 5,
					getNodeCount: (): number => 4
				})
			}
		})
	);

const channel = (localSats: bigint, extra: Row = {}): Row => ({
	state: 'NORMAL',
	channelType: null,
	fundingSatoshis: 1_000_000n,
	localBalanceMsat: localSats * 1000n,
	...extra
});

/** An asset channel in a state, as the node lists one. */
const asset = (state: ChannelState = ChannelState.NORMAL): Row =>
	channel(500_000n, { state, auxiliary: true });

/**
 * What master (4fdaeb60) answers, printed there by the `readiness` and
 * `channel` above for a wallet with no channel, with one ordinary channel,
 * with two, and with one that is still waiting for its funding to confirm.
 * A dash of master's own sentences is written as its escape.
 */
const MASTER = {
	none: '{"score":95,"ready":true,"checks":[{"name":"STORAGE_CONFIGURED","status":"PASS","severity":"CRITICAL","message":"SQLite storage is configured"},{"name":"CHAIN_BACKEND_CONNECTED","status":"PASS","severity":"CRITICAL","message":"Chain backend connected"},{"name":"AUTO_RECONNECT_ENABLED","status":"PASS","severity":"WARNING","message":"Networking and auto-reconnect enabled"},{"name":"ANCHOR_CHANNELS_PREFERRED","status":"PASS","severity":"WARNING","message":"No channels yet (anchor will be used by default)"},{"name":"HAS_ACTIVE_CHANNEL","status":"WARN","severity":"INFO","message":"No active channels \u2014 open a channel to send/receive payments"},{"name":"GOSSIP_GRAPH_POPULATED","status":"PASS","severity":"INFO","message":"Gossip graph has 4 nodes and 5 channels"},{"name":"FEE_ESTIMATOR_AVAILABLE","status":"PASS","severity":"WARNING","message":"Fee estimator active (3 samples)"},{"name":"ELECTRUM_REDUNDANCY","status":"PASS","severity":"WARNING","message":"2 Electrum servers configured for failover"},{"name":"BACKUP_CONFIGURED","status":"PASS","severity":"WARNING","message":"Automated backups configured to /backups"},{"name":"SUFFICIENT_CHANNELS","status":"PASS","severity":"WARNING","message":"No channels yet"},{"name":"CHANNEL_BALANCE_HEALTH","status":"PASS","severity":"INFO","message":"No active channels to assess"},{"name":"CHANNEL_BACKUP","status":"PASS","severity":"WARNING","message":"backed up"}]}',
	one: '{"score":80,"ready":true,"checks":[{"name":"STORAGE_CONFIGURED","status":"PASS","severity":"CRITICAL","message":"SQLite storage is configured"},{"name":"CHAIN_BACKEND_CONNECTED","status":"PASS","severity":"CRITICAL","message":"Chain backend connected"},{"name":"AUTO_RECONNECT_ENABLED","status":"PASS","severity":"WARNING","message":"Networking and auto-reconnect enabled"},{"name":"ANCHOR_CHANNELS_PREFERRED","status":"WARN","severity":"WARNING","message":"No anchor channels \u2014 consider opening anchor channels for improved fee management"},{"name":"HAS_ACTIVE_CHANNEL","status":"PASS","severity":"INFO","message":"1 active channel(s)"},{"name":"GOSSIP_GRAPH_POPULATED","status":"PASS","severity":"INFO","message":"Gossip graph has 4 nodes and 5 channels"},{"name":"FEE_ESTIMATOR_AVAILABLE","status":"PASS","severity":"WARNING","message":"Fee estimator active (3 samples)"},{"name":"ELECTRUM_REDUNDANCY","status":"PASS","severity":"WARNING","message":"2 Electrum servers configured for failover"},{"name":"BACKUP_CONFIGURED","status":"PASS","severity":"WARNING","message":"Automated backups configured to /backups"},{"name":"SUFFICIENT_CHANNELS","status":"WARN","severity":"WARNING","message":"Only 1 ready channel \u2014 single channel is a point of failure"},{"name":"CHANNEL_BALANCE_HEALTH","status":"PASS","severity":"INFO","message":"Channel balances are healthy"},{"name":"CHANNEL_BACKUP","status":"PASS","severity":"WARNING","message":"backed up"}]}',
	two: '{"score":90,"ready":true,"checks":[{"name":"STORAGE_CONFIGURED","status":"PASS","severity":"CRITICAL","message":"SQLite storage is configured"},{"name":"CHAIN_BACKEND_CONNECTED","status":"PASS","severity":"CRITICAL","message":"Chain backend connected"},{"name":"AUTO_RECONNECT_ENABLED","status":"PASS","severity":"WARNING","message":"Networking and auto-reconnect enabled"},{"name":"ANCHOR_CHANNELS_PREFERRED","status":"WARN","severity":"WARNING","message":"No anchor channels \u2014 consider opening anchor channels for improved fee management"},{"name":"HAS_ACTIVE_CHANNEL","status":"PASS","severity":"INFO","message":"2 active channel(s)"},{"name":"GOSSIP_GRAPH_POPULATED","status":"PASS","severity":"INFO","message":"Gossip graph has 4 nodes and 5 channels"},{"name":"FEE_ESTIMATOR_AVAILABLE","status":"PASS","severity":"WARNING","message":"Fee estimator active (3 samples)"},{"name":"ELECTRUM_REDUNDANCY","status":"PASS","severity":"WARNING","message":"2 Electrum servers configured for failover"},{"name":"BACKUP_CONFIGURED","status":"PASS","severity":"WARNING","message":"Automated backups configured to /backups"},{"name":"SUFFICIENT_CHANNELS","status":"PASS","severity":"WARNING","message":"2 ready channels (redundancy OK)"},{"name":"CHANNEL_BALANCE_HEALTH","status":"PASS","severity":"INFO","message":"Channel balances are healthy"},{"name":"CHANNEL_BACKUP","status":"PASS","severity":"WARNING","message":"backed up"}]}',
	waiting:
		'{"score":75,"ready":true,"checks":[{"name":"STORAGE_CONFIGURED","status":"PASS","severity":"CRITICAL","message":"SQLite storage is configured"},{"name":"CHAIN_BACKEND_CONNECTED","status":"PASS","severity":"CRITICAL","message":"Chain backend connected"},{"name":"AUTO_RECONNECT_ENABLED","status":"PASS","severity":"WARNING","message":"Networking and auto-reconnect enabled"},{"name":"ANCHOR_CHANNELS_PREFERRED","status":"WARN","severity":"WARNING","message":"No anchor channels \u2014 consider opening anchor channels for improved fee management"},{"name":"HAS_ACTIVE_CHANNEL","status":"WARN","severity":"INFO","message":"No active channels \u2014 open a channel to send/receive payments"},{"name":"GOSSIP_GRAPH_POPULATED","status":"PASS","severity":"INFO","message":"Gossip graph has 4 nodes and 5 channels"},{"name":"FEE_ESTIMATOR_AVAILABLE","status":"PASS","severity":"WARNING","message":"Fee estimator active (3 samples)"},{"name":"ELECTRUM_REDUNDANCY","status":"PASS","severity":"WARNING","message":"2 Electrum servers configured for failover"},{"name":"BACKUP_CONFIGURED","status":"PASS","severity":"WARNING","message":"Automated backups configured to /backups"},{"name":"SUFFICIENT_CHANNELS","status":"WARN","severity":"WARNING","message":"Only 0 ready channel \u2014 single channel is a point of failure"},{"name":"CHANNEL_BALANCE_HEALTH","status":"PASS","severity":"INFO","message":"No active channels to assess"},{"name":"CHANNEL_BACKUP","status":"PASS","severity":"WARNING","message":"backed up"}]}'
};

const ANCHOR =
	'No ordinary Lightning channel yet (anchor will be used by default); asset channels are not counted here';
const SUFFICIENT =
	'No ordinary Lightning channel yet; asset channels are not counted here';
const ACTIVE =
	'No active ordinary Lightning channel: open one to send and receive bitcoin over Lightning; asset channels are not counted here';
const HEALTH =
	'No active ordinary Lightning channel to assess; asset channels are not counted here';

/** The sentence each of the four checks has for an asset-only wallet. */
const ASSET_ONLY: Record<string, string> = {
	ANCHOR_CHANNELS_PREFERRED: ANCHOR,
	HAS_ACTIVE_CHANNEL: ACTIVE,
	SUFFICIENT_CHANNELS: SUFFICIENT,
	CHANNEL_BALANCE_HEALTH: HEALTH
};

/** An ordinary channel that is still waiting for its funding to confirm. */
const waiting = (): Row =>
	channel(500_000n, { state: 'AWAITING_FUNDING_CONFIRMED' });

describe('Mainnet readiness and a wallet that holds only asset channels (#2093)', () => {
	it('answers a wallet without an asset channel the bytes master answers', () => {
		expect(readiness([])).to.equal(MASTER.none);
		expect(readiness([channel(500_000n)])).to.equal(MASTER.one);
		expect(readiness([channel(950_000n), channel(500_000n)])).to.equal(
			MASTER.two
		);
		expect(readiness([waiting()])).to.equal(MASTER.waiting);
		// What master tells a wallet with no channel, and one with no
		// active channel, in the four checks.
		const sentences = (pinned: string): string[][] =>
			(JSON.parse(pinned) as IReport).checks
				.filter((check) => check.name in ASSET_ONLY)
				.map((check) => [check.name, check.status, check.message]);
		expect(sentences(MASTER.none)).to.deep.equal([
			[
				'ANCHOR_CHANNELS_PREFERRED',
				'PASS',
				'No channels yet (anchor will be used by default)'
			],
			[
				'HAS_ACTIVE_CHANNEL',
				'WARN',
				'No active channels \u2014 open a channel to send/receive payments'
			],
			['SUFFICIENT_CHANNELS', 'PASS', 'No channels yet'],
			['CHANNEL_BALANCE_HEALTH', 'PASS', 'No active channels to assess']
		]);
		expect(sentences(MASTER.waiting)).to.deep.equal([
			[
				'ANCHOR_CHANNELS_PREFERRED',
				'WARN',
				'No anchor channels \u2014 consider opening anchor channels for improved fee management'
			],
			[
				'HAS_ACTIVE_CHANNEL',
				'WARN',
				'No active channels \u2014 open a channel to send/receive payments'
			],
			[
				'SUFFICIENT_CHANNELS',
				'WARN',
				'Only 0 ready channel \u2014 single channel is a point of failure'
			],
			['CHANNEL_BALANCE_HEALTH', 'PASS', 'No active channels to assess']
		]);
		const none = JSON.parse(MASTER.none) as IReport;
		expect(
			none.checks
				.filter((check) => check.message.startsWith('No channels yet'))
				.map((check) => [check.name, check.status, check.message])
		).to.deep.equal([
			[
				'ANCHOR_CHANNELS_PREFERRED',
				'PASS',
				'No channels yet (anchor will be used by default)'
			],
			['SUFFICIENT_CHANNELS', 'PASS', 'No channels yet']
		]);
	});

	it('answers a wallet with ordinary channels the same bytes, whatever asset channels are beside them', () => {
		for (const state of Object.values(ChannelState)) {
			expect(readiness([channel(500_000n), asset(state)]), state).to.equal(
				MASTER.one
			);
			expect(
				readiness([
					asset(state),
					channel(950_000n),
					asset(),
					channel(500_000n)
				]),
				state
			).to.equal(MASTER.two);
			// An ordinary channel that is not ready is still an ordinary
			// channel: master's sentences, not those of an asset-only wallet.
			expect(readiness([asset(state), waiting(), asset()]), state).to.equal(
				MASTER.waiting
			);
		}
	});

	it('tells a wallet whose only channels are asset channels that it has no ordinary Lightning channel, in the four checks that said it had no channel or no active one', () => {
		const none = JSON.parse(MASTER.none) as IReport;
		for (const rows of [
			[asset()],
			[asset(), asset(ChannelState.AWAITING_REESTABLISH)],
			[asset(ChannelState.AWAITING_FUNDING_CONFIRMED)],
			[asset(ChannelState.FORCE_CLOSED)]
		]) {
			const answer = JSON.parse(readiness(rows)) as IReport;
			// The score, the verdict and every status are those of a wallet
			// with no channel: only four sentences differ.
			expect(answer.score).to.equal(none.score);
			expect(answer.ready).to.equal(none.ready);
			expect(answer.checks.map((check) => check.name)).to.deep.equal(
				none.checks.map((check) => check.name)
			);
			for (const [index, check] of answer.checks.entries()) {
				const expected =
					check.name in ASSET_ONLY
						? { ...none.checks[index], message: ASSET_ONLY[check.name] }
						: none.checks[index];
				expect(check, check.name).to.deep.equal(expected);
			}
			expect(
				answer.checks.filter((check) =>
					check.message.includes('asset channels')
				)
			).to.have.length(4);
		}
	});

	it('uses those words for no wallet without an asset channel, and no dash in them', () => {
		for (const pinned of Object.values(MASTER)) {
			expect(pinned).to.not.include('ordinary Lightning channel');
			expect(pinned).to.not.include('asset channels');
		}
		for (const sentence of Object.values(ASSET_ONLY)) {
			expect(sentence).to.match(/; asset channels are not counted here$/);
			expect(sentence).to.not.include('\u2014');
			expect(sentence).to.not.include('\u2013');
		}
	});
});
