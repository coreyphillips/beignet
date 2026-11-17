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
import {
	AUXILIARY_CLOSE_ASSET_OUTPUT_MINIMUM,
	applyAuxiliaryClose
} from '../../src/lightning/channel/auxiliary-close';
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

/** The whole-layout provider of tests/lightning/auxiliary-close.test.ts. */
function withSeparateAnchors(provider: Provider): Provider {
	return {
		...provider,
		extraCloseOutputScriptLengths: (state) =>
			[state.auxiliaryState!.localBalance, state.auxiliaryState!.remoteBalance]
				.filter((units) => units > 0n)
				.map(() => 34),
		buildClose(context) {
			const auxiliary = context.state.auxiliaryState!;
			const outputs: Array<{
				value: bigint;
				script: Buffer;
				side: 'local' | 'remote';
				asset: boolean;
			}> = [];
			for (const [side, amount, units, records, script, dust] of [
				[
					'local',
					context.localAmount,
					auxiliary.localBalance,
					auxiliary.localShutdownRecords,
					context.state.localShutdownScript,
					context.localDustLimit
				],
				[
					'remote',
					context.remoteAmount,
					auxiliary.remoteBalance,
					auxiliary.remoteShutdownRecords,
					context.state.remoteShutdownScript,
					context.remoteDustLimit
				]
			] as const) {
				if (units > 0n) {
					const anchor = p2tr(records!.get(65539n)!, `anchor:${units}`);
					const rest = amount - AUXILIARY_CLOSE_ASSET_OUTPUT_MINIMUM;
					if (rest > dust) {
						outputs.push(
							{
								value: AUXILIARY_CLOSE_ASSET_OUTPUT_MINIMUM,
								script: anchor,
								side,
								asset: true
							},
							{ value: rest, script: script!, side, asset: false }
						);
					} else {
						outputs.push({ value: amount, script: anchor, side, asset: true });
					}
				} else if (amount > dust) {
					outputs.push({ value: amount, script: script!, side, asset: false });
				}
			}
			outputs.sort((a, b) =>
				a.value !== b.value
					? a.value < b.value
						? -1
						: 1
					: a.script.compare(b.script)
			);
			return {
				outputs,
				outputScripts: new Map(),
				customData: Buffer.from('split close assets')
			};
		}
	};
}

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

	// The whole-layout provider without the trim of a payout that is dust.
	const untrimmed = (): Provider => {
		const split = withSeparateAnchors(referenceProvider());
		return {
			...split,
			buildClose(context) {
				return split.buildClose({
					...context,
					localDustLimit: 0n,
					remoteDustLimit: 0n
				});
			}
		};
	};
	for (const [what, acceptorUnits, pushMsat, cause] of [
		[
			// Bob holds no units and 100 sat, and is laid out an output of
			// 100 sat where he is owed nothing.
			'the payout of a party without units',
			0n,
			100_000n,
			'Bitcoin close payout changed'
		],
		[
			// Bob holds units and 430 sat: an anchor of 330 sat and a rest of
			// 100 sat to his own script.
			'the rest of a party with units',
			1000n,
			430_000n,
			'Asset close payout is below dust'
		]
	] as const) {
		it(`signs no whole layout that keeps ${what} below dust, and the channel can still be force closed`, async () => {
			const made = await pair(`review9-dust-${acceptorUnits}`, {
				alice: { provider: untrimmed() },
				bob: { provider: untrimmed() },
				acceptorUnits,
				pushMsat
			});
			const { alice, bob, channelId, hex } = made;
			expect(stateOf(bob, channelId).localBalanceMsat).to.equal(pushMsat);
			expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
				ok: true
			});
			await settle();
			// The provider's answer is refused before anything is signed.
			expect(made.managerErrors.alice).to.deep.equal([
				`The asset provider refused a cooperative close (channel ${hex}): ${cause}`
			]);
			expect(sent(made, 'alice')).to.not.include(MessageType.CLOSING_SIGNED);
			expect(sent(made, 'bob')).to.not.include(MessageType.CLOSING_SIGNED);
			expect(made.published).to.deep.equal({ alice: [], bob: [] });
			for (const host of [alice, bob]) {
				const state = stateOf(host, channelId);
				expect(state.state).to.equal(ChannelState.NEGOTIATING_CLOSING);
				expect(state.auxiliaryState!.closeTransactions).to.equal(undefined);
			}
			// The unilateral exit is still there.
			expect(alice.node.forceCloseChannel(channelId, DESTINATION).ok).to.equal(
				true
			);
			expect(stateOf(alice, channelId).state).to.equal(
				ChannelState.FORCE_CLOSED
			);
		});
	}

	it('closes with the dust payout of a party without units trimmed, in the whole layout and in the scripts variant', async () => {
		for (const separate of [true, false]) {
			const provider = (): Hooks =>
				separate ? { provider: withSeparateAnchors(referenceProvider()) } : {};
			const made = await pair(`review9-dust-trim-${separate}`, {
				alice: provider(),
				bob: provider(),
				acceptorUnits: 0n,
				pushMsat: 100_000n
			});
			const { alice, bob, channelId } = made;
			expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
				ok: true
			});
			await settle();
			expect(
				made.managerErrors.alice.concat(made.managerErrors.bob),
				String(separate)
			).to.deep.equal([]);
			for (const host of [alice, bob]) {
				expect(stateOf(host, channelId).state).to.equal(ChannelState.CLOSED);
			}
			expect(made.published.alice).to.have.length(1);
			const tx = bitcoin.Transaction.fromHex(made.published.alice[0]);
			// Bob's 100 sat are in no output: every output is one a node
			// relays.
			for (const out of tx.outs) {
				expect(out.value, String(separate)).to.be.at.least(330);
			}
			expect(tx.outs.map((out) => out.value)).to.not.include(100);
		}
	});

	it('refuses a scripts answer that lays a script over the payout of a party without units', async () => {
		const reference = referenceProvider();
		const made = await pair('review9-no-units-script', {
			alice: {
				provider: {
					...reference,
					buildClose(context) {
						const answer = reference.buildClose(context);
						answer.outputScripts.set(
							context.remoteOutputIndex!,
							p2tr(context.state.localBasepoints.fundingPubkey, 'not theirs')
						);
						return answer;
					}
				}
			},
			acceptorUnits: 0n
		});
		const { alice, channelId, hex } = made;
		expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
			ok: true
		});
		await settle();
		expect(made.managerErrors.alice).to.deep.equal([
			`The asset provider refused a cooperative close (channel ${hex}): Bitcoin close payout changed`
		]);
		expect(sent(made, 'alice')).to.not.include(MessageType.CLOSING_SIGNED);
		expect(stateOf(alice, channelId).state).to.equal(
			ChannelState.NEGOTIATING_CLOSING
		);
	});

	// The live closing feerate of a node, as its fee estimate would set it.
	const atRate = (host: IAssetHost, satPerKw: number): void => {
		(
			host.node.getChannelManager() as unknown as {
				config: { getClosingFeeratePerKw?: () => number };
			}
		).config.getClosingFeeratePerKw = () => satPerKw;
	};
	for (const [proposer, responder] of [
		[4000, 4000],
		[20_000, 20_000],
		// Two honest nodes that read the mempool apart.
		[20_000, 4000],
		[1000, 20_000]
	] as const) {
		it(`closes at the live feerate: proposed at ${proposer} sat/kw to a node that estimates ${responder}`, async () => {
			const made = await pair(`review9-rate-${proposer}-${responder}`);
			const { alice, bob, channelId } = made;
			atRate(alice, proposer);
			atRate(bob, responder);
			expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
				ok: true
			});
			await settle();
			expect(
				made.managerErrors.alice.concat(made.managerErrors.bob)
			).to.deep.equal([]);
			for (const host of [alice, bob]) {
				expect(stateOf(host, channelId).state).to.equal(ChannelState.CLOSED);
			}
			expect(made.published.alice).to.have.length(1);
			const tx = bitcoin.Transaction.fromHex(made.published.alice[0]);
			const fee =
				Number(stateOf(alice, channelId).fundingSatoshis) -
				tx.outs.reduce((sum, out) => sum + out.value, 0);
			expect(BigInt(fee)).to.equal(
				stateOf(alice, channelId).lastProposedClosingFeeSat
			);
			// The fee is the proposer's feerate for the transaction, far
			// above what the pinned commitment feerate of 253 sat/kw gives.
			expect((fee * 1000) / tx.weight()).to.be.within(
				proposer * 0.9,
				proposer * 1.15
			);
		});
	}

	it('still refuses a fee far above its own estimate, as a local matter that leaves the channel whole', async () => {
		const made = await pair('review9-rate-absurd');
		const { alice, bob, channelId } = made;
		atRate(alice, 200_000);
		atRate(bob, 4000);
		expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
			ok: true
		});
		await settle();
		expect(made.managerErrors.bob).to.have.length(1);
		const refusal =
			/Taproot closing fee (\d+) outside acceptable range \[(\d+), (\d+)\]/.exec(
				made.managerErrors.bob[0]
			)!;
		expect(refusal, made.managerErrors.bob[0]).to.not.equal(null);
		const [fee, floor, ceiling] = refusal.slice(1).map(Number);
		expect(fee).to.be.above(ceiling);
		// Ten times this node's own estimate at 4000 sat/kw, and down to the
		// relay floor of 253 sat/kw.
		expect(ceiling / floor).to.be.within(150, 165);
		// Nothing is signed, and the peer is not blamed for our estimate.
		expect(sent(made, 'bob')).to.not.include(MessageType.CLOSING_SIGNED);
		expect(sent(made, 'bob')).to.not.include(MessageType.ERROR);
		expect(made.published).to.deep.equal({ alice: [], bob: [] });
		for (const host of [alice, bob]) {
			expect(stateOf(host, channelId).state).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);
		}
	});
});
