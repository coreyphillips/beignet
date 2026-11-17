/**
 * Two daemons whose extension supplies asset channels and a fee policy
 * open an asset channel in the fixed mode (issue #2093).
 *
 * Fixed HTLC outputs (feature bit 451) are offered only by a node whose
 * funding provider keeps the fee coin pool their spends take a fee from.
 * In the daemon that is the wallet's provider, and it keeps the pool when
 * the extension's attachment supplied `fixedOutputFees` beside
 * `auxiliaryChannels`. No test here turns asset channels on, gives a hook
 * for the older HTLC signatures, or tells a node what its peer advertises:
 * each daemon reads the features the other really puts in its init.
 *
 * A daemon whose extension supplies asset channels and no fee policy does
 * not offer fixed HTLC outputs. Its row of GET /extensions says so, which
 * the row of an extension whose policy the wallet took does not.
 */

import { expect } from 'chai';
import * as http from 'http';
import {
	EXTENSION_API_VERSION,
	IBeignetExtension,
	IExtensionAttachment
} from '../../src/cli/extension';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryFundingDescriptor
} from '../../src/lightning/channel/auxiliary-funding';
import {
	ChannelState,
	isFixedAssetHtlcChannel
} from '../../src/lightning/channel/types';
import {
	openAssetChannel,
	type IAssetHost
} from '../lightning/helpers/auxiliary-nodes';
import { referenceProvider } from '../lightning/helpers/auxiliary-pair';
import {
	bootStreamDaemon,
	IStreamDaemon,
	joinStreamDaemons,
	STREAM_MNEMONICS,
	streamTurns
} from './helpers/event-stream';

const FEES = {
	maxFeeSatoshis: 10_000n,
	maxTotalFeeSatoshis: 1_000_000n,
	maxPreparationFeeSatoshis: 10_000n,
	feeCoinCount: 4
};

type Row = Record<string, unknown>;

/** GET a path of a daemon and parse what it answers. */
const get = (port: number, path: string): Promise<Record<string, unknown>> =>
	new Promise((resolve, reject) => {
		http
			.get({ hostname: '127.0.0.1', port, path }, (res) => {
				let text = '';
				res.setEncoding('utf8');
				res.on('data', (chunk: string) => (text += chunk));
				res.on('end', () => {
					try {
						resolve(JSON.parse(text) as Record<string, unknown>);
					} catch (err) {
						reject(err);
					}
				});
			})
			.on('error', reject);
	});

describe('Two daemons and an asset channel in the fixed mode (#2093)', function () {
	this.timeout(120_000);
	const daemons: IStreamDaemon[] = [];

	afterEach(async () => {
		for (const daemon of daemons.splice(0)) await daemon.close();
	});

	/** A daemon whose extension supplies asset channels, with a fee policy or without. */
	const boot = async (
		tag: string,
		mnemonic: string,
		fees: boolean
	): Promise<{ daemon: IStreamDaemon; host: IAssetHost }> => {
		const incoming = new Map<string, IAuxiliaryFundingDescriptor>();
		const auxiliaryChannels: IAuxiliaryChannelConfig = {
			provider: referenceProvider(),
			resolveIncoming: (_peer, id) => incoming.get(id.toString('hex'))
		};
		const assets: IBeignetExtension = {
			id: 'assets',
			version: '1.0.0',
			api: EXTENSION_API_VERSION,
			attach: (): IExtensionAttachment => ({
				auxiliaryChannels,
				...(fees ? { fixedOutputFees: FEES } : {})
			})
		};
		const daemon = await bootStreamDaemon(tag, mnemonic, {
			extensions: [assets]
		});
		daemons.push(daemon);
		const errors: string[] = [];
		daemon.node.on(
			'node:error',
			(error: { code?: string; message?: string }) => {
				errors.push(`${error.code ?? ''}: ${error.message ?? ''}`);
			}
		);
		return {
			daemon,
			host: { node: daemon.node, incoming, broadcasts: [], errors }
		};
	};

	/** Each daemon reads the features the other advertises. */
	const join = (a: IStreamDaemon, b: IStreamDaemon): void => {
		const reads = (one: IStreamDaemon, peer: IStreamDaemon): void => {
			(
				one.node as unknown as { peerInitFeatures: () => unknown }
			).peerInitFeatures = (): unknown => peer.node.getLocalFeatures();
		};
		reads(a, b);
		reads(b, a);
		joinStreamDaemons(a, b);
	};

	/** The row of the one extension, as GET /extensions answers it. */
	const extensionRow = async (daemon: IStreamDaemon): Promise<Row> => {
		const answer = (await get(daemon.port, '/extensions')) as {
			result: { extensions: Row[] };
		};
		expect(answer.result.extensions).to.have.length(1);
		return answer.result.extensions[0];
	};

	/** What a daemon without a chain always says, and nothing else. */
	const errorsOf = (host: IAssetHost): string[] =>
		host.errors.filter(
			(error) =>
				!error.startsWith('FUNDING_BROADCAST_FAILED') &&
				!error.startsWith('CHAIN_WATCHER_START_FAILED')
		);

	const REFUSAL =
		'New asset channels require fixed HTLC outputs or explicit peer compatibility';

	it('advertises fixed HTLC outputs from a daemon whose extension supplies asset channels and a fee policy, and two of them open an asset channel in the fixed mode', async () => {
		const { daemon: alice, host: aliceHost } = await boot(
			'alice',
			STREAM_MNEMONICS[0],
			true
		);
		const { daemon: bob, host: bobHost } = await boot(
			'bob',
			STREAM_MNEMONICS[1],
			true
		);
		join(alice, bob);
		for (const daemon of [alice, bob]) {
			// The init: the overlay of asset channels and fixed HTLC outputs
			// by their optional bits, and neither by its required bit.
			const bits = daemon.node.getLocalFeatures().listSetBits();
			expect(bits).to.include(2025);
			expect(bits).to.include(451);
			expect(bits).to.not.include(450);
			// The wallet took the policy and keeps the pool, so the row of
			// the extension says nothing of one.
			expect(daemon.node.getFixedOutputFeeStatus()?.available).to.equal(true);
			expect(await extensionRow(daemon)).to.deep.equal({
				id: 'assets',
				version: '1.0.0',
				state: 'ready',
				generation: 1,
				routes: [],
				events: []
			});
		}
		// What a host reads before its wallet prepares the funding.
		expect(alice.node.getAuxiliaryHtlcMode(bob.node.getNodeId())).to.equal(
			'fixed'
		);
		expect(bob.node.getAuxiliaryHtlcMode(alice.node.getNodeId())).to.equal(
			'fixed'
		);

		const channelId = await openAssetChannel(aliceHost, bobHost, {
			tag: 'fixed mode',
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		await streamTurns();
		for (const daemon of [alice, bob]) {
			const state = daemon.node
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			expect(state.state).to.equal(ChannelState.NORMAL);
			expect(isFixedAssetHtlcChannel(state.channelType)).to.equal(true);
			expect(daemon.node.getAuxiliaryChannelInfo(channelId)).to.include({
				localAssetBalance: daemon === alice ? 9000n : 1000n
			});
		}
		expect(errorsOf(aliceHost)).to.deep.equal([]);
		expect(errorsOf(bobHost)).to.deep.equal([]);
	});

	it('does not advertise them from a daemon whose extension supplies asset channels without a fee policy, says so on GET /extensions, and opens no asset channel with a peer that does', async () => {
		const { daemon: alice, host: aliceHost } = await boot(
			'alice',
			STREAM_MNEMONICS[0],
			false
		);
		const { daemon: bob, host: bobHost } = await boot(
			'bob',
			STREAM_MNEMONICS[1],
			true
		);
		join(alice, bob);
		// Asset channels are advertised, fixed HTLC outputs are not.
		const bits = alice.node.getLocalFeatures().listSetBits();
		expect(bits).to.include(2025);
		expect(bits).to.not.include(451);
		expect(bits).to.not.include(450);
		expect(alice.node.getFixedOutputFeeStatus()).to.equal(undefined);
		// A host reads why on the row of the extension. The peer's row, whose
		// wallet keeps the pool, says nothing.
		expect(await extensionRow(alice)).to.deep.equal({
			id: 'assets',
			version: '1.0.0',
			state: 'ready',
			generation: 1,
			routes: [],
			events: [],
			fixedOutputFees: { available: false, supplied: false }
		});
		expect(await extensionRow(bob)).to.not.have.property('fixedOutputFees');

		// Neither side gave a hook for the older signatures, so no asset
		// channel can be opened between them, in either direction: the mode
		// read and the opening are refused in the same words.
		for (const [one, other] of [
			[alice, bob],
			[bob, alice]
		]) {
			expect(() =>
				one.node.getAuxiliaryHtlcMode(other.node.getNodeId())
			).to.throw(REFUSAL);
		}
		for (const [opener, acceptor, tag] of [
			[aliceHost, bobHost, 'no pool'],
			[bobHost, aliceHost, 'no pool back']
		] as const) {
			let failure = '';
			try {
				await openAssetChannel(opener, acceptor, {
					tag,
					openerUnits: 9000n,
					acceptorUnits: 1000n
				});
			} catch (error) {
				failure = (error as Error).message;
			}
			expect(failure, tag).to.include(REFUSAL);
		}
		for (const daemon of [alice, bob]) {
			expect(
				daemon.node.listChannels().filter((channel) => channel.auxiliary)
			).to.deep.equal([]);
		}
		expect(errorsOf(aliceHost)).to.deep.equal([]);
		expect(errorsOf(bobHost)).to.deep.equal([]);
	});
});
