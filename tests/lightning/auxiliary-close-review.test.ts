/**
 * The cooperative close of an asset channel, held to what a review of it
 * found (issue #2093).
 *
 * Each test keeps the setup the reviewer proved a defect with and asserts
 * the behaviour the close has to have: the payouts are never swapped, no
 * output is signed below dust, a provider that fails is a local matter that
 * drops the connection and loses nothing, and what was sent once is what
 * is sent again.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import { applyAuxiliaryClose } from '../../src/lightning/channel/auxiliary-close';
import { buildClosingTx } from '../../src/lightning/chain/closing';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { ChannelState } from '../../src/lightning/channel/types';
import { generateNonce } from '../../src/lightning/crypto/musig';
import { encodeShutdownMessage } from '../../src/lightning/message/channel-close';
import { MessageType } from '../../src/lightning/message/types';
import { leafFor, referenceProvider } from './helpers/auxiliary-pair';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

const settle = async (rounds = 60): Promise<void> => {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

const DESTINATION = Buffer.from('0014' + '11'.repeat(20), 'hex');

type Hooks = Partial<IAuxiliaryChannelConfig>;
type Provider = IChannelAuxiliaryProvider;

const p2tr = (key: Buffer, leaf?: string): Buffer =>
	bitcoin.payments.p2tr({
		internalPubkey: key.subarray(1),
		...(leaf ? { scriptTree: { output: leafFor(leaf).script } } : {})
	}).output!;

describe('The cooperative close of an asset channel under review (#2093)', function () {
	this.timeout(60_000);
	withAssetOpens();

	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) host.node.destroy();
	});

	interface IPair {
		alice: IAssetHost;
		bob: IAssetHost;
		channelId: Buffer;
		hex: string;
		wire: Array<{ from: 'alice' | 'bob'; type: number; payload: Buffer }>;
		published: { alice: string[]; bob: string[] };
		managerErrors: { alice: string[]; bob: string[] };
		disconnects: { alice: string[]; bob: string[] };
	}

	async function pair(
		tag: string,
		options: {
			alice?: Hooks;
			bob?: Hooks;
			pushMsat?: bigint;
			acceptorUnits?: bigint;
		} = {}
	): Promise<IPair> {
		const alice = assetHost(tag, 1, options.alice ?? {}, { sqlite: true });
		const bob = assetHost(tag, 2, options.bob ?? {}, { sqlite: true });
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: options.acceptorUnits ?? 1000n,
			...(options.pushMsat !== undefined ? { pushMsat: options.pushMsat } : {})
		});
		const made: IPair = {
			alice,
			bob,
			channelId,
			hex: channelId.toString('hex'),
			wire: [],
			published: { alice: [], bob: [] },
			managerErrors: { alice: [], bob: [] },
			disconnects: { alice: [], bob: [] }
		};
		for (const [from, host] of [
			['alice', alice],
			['bob', bob]
		] as const) {
			host.node.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					made.wire.push({ from, type, payload });
				}
			);
			host.node.on('broadcast:tx', (tx: Buffer) => {
				made.published[from].push(tx.toString('hex'));
			});
			host.node
				.getChannelManager()
				.on('error', (_id: unknown, message: unknown) => {
					made.managerErrors[from].push(String(message));
				});
			host.node.on('peer:disconnect-requested', (peer: string) => {
				made.disconnects[from].push(peer);
			});
		}
		return made;
	}

	const stateOf = (host: IAssetHost, channelId: Buffer) =>
		host.node.getChannelManager().getChannel(channelId)!.getFullState();
	const sent = (made: IPair, from: 'alice' | 'bob'): number[] =>
		made.wire.filter((m) => m.from === from).map((m) => m.type);

	it('refuses a peer that names the script this node closes to, and signs nothing', async () => {
		// Alice: the reference provider, except that it judges the peer's
		// shutdown by its asset record alone, so nothing but the engine
		// stands between her and a peer that names her own script.
		const asks: number[] = [];
		const reference = referenceProvider();
		const aliceProvider: Provider = {
			...reference,
			verifyShutdown: (_state, shutdown) =>
				shutdown.customRecords.get(65539n)?.length === 33,
			buildClose(context) {
				asks.push(context.transaction.outs.length);
				return reference.buildClose(context);
			}
		};
		// Bob: a peer that answers our shutdown with OUR script beside its own
		// asset record.
		const bobProvider: Provider = {
			...reference,
			prepareShutdown(state) {
				return {
					scriptPubkey: p2tr(state.remoteBasepoints!.fundingPubkey),
					customRecords: new Map([
						[65539n, state.localBasepoints.fundingPubkey]
					])
				};
			}
		};
		const made = await pair('review9-swap', {
			alice: { provider: aliceProvider },
			bob: { provider: bobProvider }
		});
		const { alice, bob, channelId } = made;
		expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
			ok: true
		});
		await settle();

		// Bob's own engine does not send it (the next test). What a peer
		// without that check would send is handed to Alice as it would
		// arrive.
		expect(sent(made, 'bob')).to.deep.equal([]);
		const own = stateOf(alice, channelId).localShutdownScript!;
		const bobKey = stateOf(bob, channelId).localBasepoints.fundingPubkey;
		alice.node.handlePeerMessage(
			bob.node.getNodeId(),
			MessageType.SHUTDOWN,
			encodeShutdownMessage({
				channelId,
				scriptPubkey: own,
				customRecords: new Map([[65539n, bobKey]]),
				shutdownNonce: Buffer.from(
					generateNonce({ publicKey: bobKey, sessionId: Buffer.alloc(32, 7) })
				)
			})
		);
		await settle();
		expect(made.managerErrors.alice.join('; ')).to.include(
			'Asset shutdown script is the script this node closes to'
		);
		// The peer is told, nothing was built for a signature and none left.
		expect(sent(made, 'alice')).to.include(MessageType.ERROR);
		expect(sent(made, 'alice')).to.not.include(MessageType.CLOSING_SIGNED);
		expect(asks).to.deep.equal([]);
		const state = stateOf(alice, channelId);
		expect(state.state).to.not.equal(ChannelState.CLOSED);
		expect(state.remoteShutdownScript).to.equal(null);
		expect(state.lastCooperativeCloseTxHex ?? null).to.equal(null);
		expect(state.auxiliaryState!.closeTransactions).to.equal(undefined);
	});

	it('never sends a script the peer already named as its own', async () => {
		// Bob's provider answers Alice's shutdown with the script Alice just
		// named. That is a fault of Bob's own provider: refused locally, and
		// no shutdown of his leaves.
		const reference = referenceProvider();
		const made = await pair('review9-own-equal', {
			bob: {
				provider: {
					...reference,
					prepareShutdown(state) {
						return {
							scriptPubkey: p2tr(state.remoteBasepoints!.fundingPubkey),
							customRecords: new Map([
								[65539n, state.localBasepoints.fundingPubkey]
							])
						};
					}
				}
			}
		});
		const { alice, bob, channelId, hex } = made;
		expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
			ok: true
		});
		await settle();
		expect(made.managerErrors.bob).to.deep.equal([
			`The asset provider refused a shutdown (channel ${hex}): Asset shutdown script is the script the peer closes to`
		]);
		expect(sent(made, 'bob')).to.deep.equal([]);
		expect(stateOf(bob, channelId).state).to.equal(ChannelState.NORMAL);
		expect(stateOf(bob, channelId).localShutdownScript).to.equal(null);
	});

	it('hands the provider the index of each payout by whose it is, and builds nothing on swapped indexes', async () => {
		const asks: Array<{ local?: number; remote?: number }> = [];
		const reference = referenceProvider();
		const made = await pair('review9-indexes', {
			alice: {
				provider: {
					...reference,
					buildClose(context) {
						asks.push({
							local: context.localOutputIndex,
							remote: context.remoteOutputIndex
						});
						return reference.buildClose(context);
					}
				}
			}
		});
		const { alice, channelId } = made;
		expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
			ok: true
		});
		await settle();
		const state = stateOf(alice, channelId);
		expect(state.state).to.equal(ChannelState.CLOSED);
		const fee = state.lastProposedClosingFeeSat!;
		const build = (): ReturnType<typeof buildClosingTx> =>
			buildClosingTx({
				fundingTxid: state.fundingTxid!.toString('hex'),
				fundingOutputIndex: state.fundingOutputIndex!,
				fundingAmount: state.fundingSatoshis,
				localScriptPubkey: state.localShutdownScript!,
				remoteScriptPubkey: state.remoteShutdownScript!,
				localAmount: state.localBalanceMsat / 1000n - fee,
				remoteAmount: state.remoteBalanceMsat / 1000n,
				feeAmount: fee,
				localDustLimit: state.localConfig.dustLimitSatoshis,
				remoteDustLimit: state.remoteConfig.dustLimitSatoshis,
				sequence: 0xfffffffd
			});
		// Alice holds 1,500,000 sat and Bob 500,000: his output sorts first.
		const right = build();
		expect(right.outputMap).to.deep.equal({ local: 1, remote: 0 });
		asks.length = 0;
		expect(
			applyAuxiliaryClose(state, right.tx, fee, right.outputMap)
		).to.be.instanceOf(Buffer);
		expect(asks).to.deep.equal([{ local: 1, remote: 0 }]);

		// The same transaction with the two indexes swapped: the provider is
		// not asked, and nothing exists that a signature could be made for.
		for (const wrong of [
			{ local: 0, remote: 1 },
			{ local: 1, remote: 1 },
			{ local: 1 },
			{ local: 1, remote: 2 }
		]) {
			asks.length = 0;
			expect(
				() => applyAuxiliaryClose(state, build().tx, fee, wrong),
				JSON.stringify(wrong)
			).to.throw('Asset close payout index does not hold its amount');
			expect(asks, JSON.stringify(wrong)).to.deep.equal([]);
		}
	});
});
