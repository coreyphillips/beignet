/**
 * Issue #2093: an asset channel that ends with a commitment on the chain.
 *
 * Both nodes follow a chain of their own through their own watcher. The
 * chain judges every spend: the commitment under the funding key that
 * commits to the asset root, and each sweep against the script tree of the
 * output it spends, asset leaf included.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	CommitmentType,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import {
	prepareAuxiliarySweep,
	type IAuxiliarySweepSource
} from '../../src/lightning/chain/auxiliary-sweep';
import { taprootPair, hash } from './helpers/auxiliary-pair';
import { issuances } from './helpers/grouped-asset-fixture';
import type {
	IAuxiliarySweepResult,
	IAuxiliaryCommitmentData,
	IChannelAuxiliaryProvider
} from '../../src/lightning/channel/auxiliary';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	ASSET_SWEEP_SCRIPT,
	SWEEP_DESTINATION,
	assetChainWorld,
	sweepingProvider,
	errorsOf,
	settle,
	sweepData,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

describe('an asset channel with a commitment on the chain (issue #2093)', function () {
	this.timeout(120_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());

	const output = (
		host: IAssetHost,
		channelId: Buffer,
		type: OutputType
	): ITrackedOutput => {
		const found = trackedOutputs(host, channelId).filter(
			(tracked) => tracked.outputType === type
		);
		expect(found, `${type} outputs`).to.have.length(1);
		return found[0];
	};

	/** Alice force closes, and the commitment is in a block. */
	const closedByAlice = async (pair: IAssetChainPair): Promise<string> => {
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.error).to.equal(undefined);
		expect(closed.ok).to.equal(true);
		await settle();
		// The chain took a key spend of the funding output: the signature
		// is by the two funding keys under the asset root.
		expect(pair.chain.mempool.has(closed.commitmentTxid!)).to.equal(true);
		await world.mine(pair, 1);
		return closed.commitmentTxid!;
	};

	/** The sweep of one tracked output, as the chain confirmed it. */
	const confirmedSweep = (
		pair: IAssetChainPair,
		tracked: ITrackedOutput
	): bitcoin.Transaction => {
		expect(tracked.resolutionTxid, 'a spend the monitor saw').to.be.a('string');
		const entry = pair.chain.confirmed.get(tracked.resolutionTxid!);
		expect(entry, 'the spend is in a block').to.not.equal(undefined);
		return entry!.tx;
	};

	it('is closed by its opener: the peer takes its units after one block and the closer after its delay, each with the asset side its provider made', async () => {
		const pair = await world.open('aux-force-close');
		const { alice, bob, channelId } = pair;
		const commitmentTxid = await closedByAlice(pair);

		const aliceMonitor = alice.node.getChannelMonitorState(channelId)!;
		const bobMonitor = bob.node.getChannelMonitorState(channelId)!;
		expect(aliceMonitor.commitmentBroadcast).to.include({
			txid: commitmentTxid,
			commitmentType: CommitmentType.OUR_COMMITMENT
		});
		expect(bobMonitor.commitmentBroadcast).to.include({
			txid: commitmentTxid,
			commitmentType: CommitmentType.THEIR_CURRENT_COMMITMENT
		});
		const number = aliceMonitor.commitmentBroadcast!.commitmentNumber;
		// Each tracks its own balance output as one that carries units.
		expect(
			output(alice, channelId, OutputType.TO_LOCAL).auxiliaryCommitmentNumber
		).to.equal(number);
		expect(
			output(bob, channelId, OutputType.TO_REMOTE).auxiliaryCommitmentNumber
		).to.equal(number);

		// Bob's output waits one block, Alice's her delay.
		await world.mine(pair, 3);
		const bobOutput = output(bob, channelId, OutputType.TO_REMOTE);
		expect(bobOutput.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		const bobSweep = confirmedSweep(pair, bobOutput);
		expect(pair.sweeps.bob).to.have.length(1);
		expect(pair.sweeps.bob[0]).to.include({
			side: 'remote',
			commitmentNumber: number
		});
		expect(pair.sweeps.bob[0].kinds).to.deep.equal(['to_remote']);
		// The units go where the provider said, with all the bitcoin of the
		// output but the fee, and the asset side is kept with the sweep.
		expect(bobSweep.outs).to.have.length(1);
		expect(bobSweep.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(bobSweep.outs[0].value).to.be.greaterThan(400_000);
		// The provider saw the sweep paying the node's own destination, and
		// only the script of its output was changed after.
		const asked = bobSweep.clone();
		asked.outs[0].script = Buffer.from(pair.sweeps.bob[0].destination, 'hex');
		expect(asked.getId()).to.equal(pair.sweeps.bob[0].txid);
		const bobData = bobOutput.auxiliaryData!;
		expect(
			bobData.subarray(0, sweepData(pair.sweeps.bob[0]).length).toString()
		).to.equal(sweepData(pair.sweeps.bob[0]));
		expect(bobData.length).to.equal(sweepData(pair.sweeps.bob[0]).length + 64);
		expect(bobOutput.auxiliarySweepAttempts).to.deep.equal({
			[bobSweep.getId()]: {
				transaction: bobSweep.toHex(),
				auxiliaryData: bobData,
				offered: true
			}
		});
		expect(bobOutput.resolutionTxHex).to.equal(bobSweep.toHex());
		expect(bobOutput.auxiliaryRefusal).to.equal(undefined);
		expect(bobOutput.auxiliaryFeeFunding).to.equal(undefined);

		expect(output(alice, channelId, OutputType.TO_LOCAL).status).to.equal(
			OutputStatus.CONFIRMED
		);
		const delay = alice.node
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState().remoteConfig.toSelfDelay;
		await world.mine(pair, delay + 2);
		const aliceOutput = output(alice, channelId, OutputType.TO_LOCAL);
		expect(aliceOutput.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		const aliceSweep = confirmedSweep(pair, aliceOutput);
		expect(pair.sweeps.alice).to.have.length(1);
		expect(pair.sweeps.alice[0]).to.include({
			side: 'local',
			commitmentNumber: number
		});
		expect(pair.sweeps.alice[0].kinds).to.deep.equal(['to_local_delayed']);
		expect(aliceSweep.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(aliceSweep.ins[0].sequence).to.equal(delay);
		// She signed her sweep when the commitment confirmed and again as the
		// fee rate was read anew while it waited: only the one she published
		// is kept.
		expect(aliceOutput.auxiliarySweepAttempts).to.deep.equal({
			[aliceSweep.getId()]: {
				transaction: aliceSweep.toHex(),
				auxiliaryData: aliceOutput.auxiliaryData,
				offered: true
			}
		});
		expect(aliceOutput.resolutionTxHex).to.equal(aliceSweep.toHex());
		// Nothing either node published was turned away by the chain.
		expect(pair.backends.alice.refused).to.deep.equal([]);
		expect(pair.backends.bob.refused).to.deep.equal([]);
		expect(errorsOf(alice)).to.deep.equal([]);
		expect(errorsOf(bob)).to.deep.equal([]);
	});

	it('is closed by its acceptor: the opener takes its units after one block', async () => {
		const pair = await world.open('aux-force-close-bob');
		const { alice, bob, channelId } = pair;
		const closed = bob.node.forceCloseChannel(channelId, SWEEP_DESTINATION);
		expect(closed.error).to.equal(undefined);
		await settle();
		await world.mine(pair, 4);
		expect(
			alice.node.getChannelMonitorState(channelId)!.commitmentBroadcast
		).to.include({
			txid: closed.commitmentTxid,
			commitmentType: CommitmentType.THEIR_CURRENT_COMMITMENT
		});
		const mine = output(alice, channelId, OutputType.TO_REMOTE);
		expect(mine.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		const sweep = confirmedSweep(pair, mine);
		expect(sweep.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(pair.sweeps.alice.map((call) => call.kinds)).to.deep.equal([
			['to_remote']
		]);
		expect(mine.auxiliarySweepAttempts![sweep.getId()].transaction).to.equal(
			sweep.toHex()
		);
		expect(output(bob, channelId, OutputType.TO_LOCAL).status).to.equal(
			OutputStatus.CONFIRMED
		);
		expect(pair.backends.alice.refused).to.deep.equal([]);
		expect(errorsOf(alice)).to.deep.equal([]);
		expect(errorsOf(bob)).to.deep.equal([]);
	});

	it('says once why its provider will not make the asset side of a sweep, publishes nothing meanwhile, and tries again on every block', async () => {
		let refusing = true;
		const pair = await world.open('aux-force-close-refused', {
			control: {
				bob: {
					refuse: () => (refusing ? 'the proofs are not here yet' : undefined)
				}
			}
		});
		const { bob, channelId } = pair;
		const said = `The asset provider refused a sweep (channel ${channelId.toString(
			'hex'
		)}): the proofs are not here yet`;
		await closedByAlice(pair);
		await world.mine(pair, 1);
		const asked = pair.sweeps.bob.length;
		expect(asked).to.be.greaterThan(0);
		await world.mine(pair, 2);
		const waiting = output(bob, channelId, OutputType.TO_REMOTE);
		expect(waiting.status).to.equal(OutputStatus.CONFIRMED);
		expect(waiting.sweepTxHex).to.equal(undefined);
		expect(waiting.auxiliaryData).to.equal(undefined);
		expect(waiting.auxiliarySweepAttempts).to.equal(undefined);
		expect(waiting.auxiliaryRefusal).to.equal(said);
		expect(pair.backends.bob.published).to.deep.equal([]);
		// Asked again on the blocks since, and said once.
		expect(pair.sweeps.bob.length).to.be.greaterThan(asked);
		expect(
			errorsOf(bob).filter((error) => error.includes(said))
		).to.have.length(1);

		refusing = false;
		await world.mine(pair, 3);
		const swept = output(bob, channelId, OutputType.TO_REMOTE);
		expect(swept.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		expect(swept.auxiliaryRefusal).to.equal(undefined);
		expect(
			confirmedSweep(pair, swept).outs[0].script.equals(ASSET_SWEEP_SCRIPT)
		).to.equal(true);
		expect(Object.keys(swept.auxiliarySweepAttempts!)).to.deep.equal([
			swept.resolutionTxid
		]);
		expect(pair.backends.bob.refused).to.deep.equal([]);
	});

	it('takes nothing from its provider but an answer it can use: each other answer is a refusal, and nothing is published', async () => {
		const P2WPKH = Buffer.concat([
			Buffer.from('0014', 'hex'),
			Buffer.alloc(20)
		]);
		const answers: Array<
			[string, string, (right: IAuxiliarySweepResult) => unknown]
		> = [
			['nothing', 'it answered nothing', (): unknown => undefined],
			[
				'no data',
				'it answered without the asset side of the sweep, or with one too large to keep',
				(right): unknown => ({ ...right, customData: Buffer.alloc(0) })
			],
			[
				'data that is not bytes',
				'it answered without the asset side of the sweep, or with one too large to keep',
				(right): unknown => ({ ...right, customData: 'x' })
			],
			[
				'no output',
				'it named no output that receives the units',
				(right): unknown => ({ ...right, outputScripts: new Map() })
			],
			[
				'outputs that are not a map',
				'it named no output that receives the units',
				(right): unknown => ({
					...right,
					outputScripts: { 0: ASSET_SWEEP_SCRIPT }
				})
			],
			[
				'an output the sweep does not have',
				'it named an output the sweep does not have, or a script that is not P2TR',
				(right): unknown => ({
					...right,
					outputScripts: new Map([[1, ASSET_SWEEP_SCRIPT]])
				})
			],
			[
				'a script that is not P2TR',
				'it named an output the sweep does not have, or a script that is not P2TR',
				(right): unknown => ({
					...right,
					outputScripts: new Map([[0, P2WPKH]])
				})
			],
			[
				'a promise',
				'it answered without the asset side of the sweep, or with one too large to keep',
				async (right): Promise<unknown> => right
			]
		];
		let now: ((right: IAuxiliarySweepResult) => unknown) | undefined =
			answers[0][2];
		const pair = await world.open('aux-force-close-answers', {
			control: {
				bob: {
					answer: (_context, right): unknown => (now ? now(right) : right)
				}
			}
		});
		const { bob, channelId } = pair;
		await closedByAlice(pair);
		for (const [name, reason, answer] of answers) {
			now = answer;
			const asked = pair.sweeps.bob.length;
			await world.mine(pair, 1);
			expect(pair.sweeps.bob.length, name).to.be.greaterThan(asked);
			const waiting = output(bob, channelId, OutputType.TO_REMOTE);
			expect(waiting.sweepTxHex, name).to.equal(undefined);
			expect(waiting.auxiliaryRefusal, name).to.equal(
				`The asset provider refused a sweep (channel ${channelId.toString(
					'hex'
				)}): ${reason}`
			);
		}
		expect(pair.backends.bob.published).to.deep.equal([]);
		now = undefined;
		await world.mine(pair, 3);
		expect(output(bob, channelId, OutputType.TO_REMOTE).status).to.equal(
			OutputStatus.SPEND_CONFIRMED
		);
		expect(pair.backends.bob.refused).to.deep.equal([]);
	});

	it('stores the asset side of a sweep before the sweep is published', async () => {
		const pair = await world.open('aux-force-close-stored');
		const { bob, channelId } = pair;
		const storedAtPublish: boolean[] = [];
		const publish = pair.backends.bob.broadcastTransaction.bind(
			pair.backends.bob
		);
		pair.backends.bob.broadcastTransaction = async (
			hex: string
		): Promise<string> => {
			const txid = bitcoin.Transaction.fromHex(hex).getId();
			const stored = bob
				.storage!.loadAllChainMonitors()
				.find((row) => row.channelId === channelId.toString('hex'));
			storedAtPublish.push(
				!!stored?.state.trackedOutputs.some(
					(tracked) =>
						tracked.auxiliarySweepAttempts?.[txid]?.transaction === hex &&
						!!tracked.auxiliarySweepAttempts[txid].auxiliaryData?.length
				)
			);
			return publish(hex);
		};
		await closedByAlice(pair);
		await world.mine(pair, 3);
		expect(output(bob, channelId, OutputType.TO_REMOTE).status).to.equal(
			OutputStatus.SPEND_CONFIRMED
		);
		expect(storedAtPublish.length).to.be.greaterThan(0);
		expect(storedAtPublish).to.not.include(false);
	});

	it('does not publish a spend of units while the row that holds its asset side cannot be stored, and publishes it once it can', async () => {
		const pair = await world.open('aux-force-close-unstored');
		const { bob, channelId } = pair;
		const storage = bob.storage!;
		const save = storage.saveChainMonitor.bind(storage);
		let failing = true;
		storage.saveChainMonitor = (id, state): void => {
			if (
				failing &&
				state.trackedOutputs.some((tracked) => tracked.auxiliaryData)
			) {
				throw new Error('the disk is full');
			}
			save(id, state);
		};
		const said: string[] = [];
		bob.node
			.getChannelManager()
			.on('error', (_id: unknown, message: unknown) => {
				said.push(String(message));
			});
		await closedByAlice(pair);
		await world.mine(pair, 3);
		const held = output(bob, channelId, OutputType.TO_REMOTE);
		expect(held.sweepTxHex).to.be.a('string');
		expect(pair.backends.bob.published).to.deep.equal([]);
		expect(said).to.include(
			`A spend of an output of an asset channel waits for its monitor to be stored (channel ${channelId.toString(
				'hex'
			)})`
		);

		// Stored on the next block, and the held spend leaves with it.
		failing = false;
		await world.mine(pair, 1);
		expect(pair.backends.bob.published).to.deep.equal([held.sweepTxHex]);
		await world.mine(pair, 1);
		const swept = output(bob, channelId, OutputType.TO_REMOTE);
		expect(swept.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		expect(swept.resolutionTxHex).to.equal(held.sweepTxHex);
		expect(
			confirmedSweep(pair, swept).outs[0].script.equals(ASSET_SWEEP_SCRIPT)
		).to.equal(true);
		expect(pair.backends.bob.refused).to.deep.equal([]);
	});

	it('signs a sweep of units anew when it has not confirmed after six blocks, stores the new asset side before it leaves, and keeps both', async () => {
		const pair = await world.open('aux-force-close-rebuilt');
		const { bob, channelId } = pair;
		// The chain is not told of what Bob publishes at first: his sweep
		// does not confirm.
		const publish = pair.backends.bob.broadcastTransaction.bind(
			pair.backends.bob
		);
		const lost: string[] = [];
		const storedAtPublish: boolean[] = [];
		let losing = true;
		pair.backends.bob.broadcastTransaction = async (
			hex: string
		): Promise<string> => {
			const txid = bitcoin.Transaction.fromHex(hex).getId();
			const row = bob
				.storage!.loadAllChainMonitors()
				.find((stored) => stored.channelId === channelId.toString('hex'));
			storedAtPublish.push(
				!!row?.state.trackedOutputs.some(
					(tracked) =>
						tracked.auxiliarySweepAttempts?.[txid]?.transaction === hex &&
						tracked.auxiliarySweepAttempts[txid].offered === true
				)
			);
			if (losing) {
				lost.push(hex);
				return txid;
			}
			return publish(hex);
		};
		await closedByAlice(pair);
		await world.mine(pair, 3);
		expect(lost).to.have.length(1);
		const first = bitcoin.Transaction.fromHex(lost[0]);
		losing = false;
		await world.mine(pair, 8);
		const swept = output(bob, channelId, OutputType.TO_REMOTE);
		expect(swept.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		const second = confirmedSweep(pair, swept);
		// The second pays more, so it is another transaction.
		expect(second.getId()).to.not.equal(first.getId());
		expect(second.outs[0].value).to.be.lessThan(first.outs[0].value);
		expect(second.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(Object.keys(swept.auxiliarySweepAttempts!)).to.deep.equal([
			first.getId(),
			second.getId()
		]);
		expect(swept.auxiliarySweepAttempts![second.getId()]).to.deep.equal({
			transaction: second.toHex(),
			auxiliaryData: swept.auxiliaryData,
			offered: true
		});
		expect(
			swept.auxiliarySweepAttempts![first.getId()].auxiliaryData!.equals(
				swept.auxiliaryData!
			)
		).to.equal(false);
		expect(storedAtPublish).to.not.include(false);
		expect(pair.backends.bob.refused).to.deep.equal([]);
	});

	it('holds the signed sweep of the closer across a restart: the row reads back as it was written, and the sweep that confirms has its asset side', async () => {
		const pair = await world.open('aux-force-close-restart');
		const { channelId } = pair;
		await closedByAlice(pair);
		await world.mine(pair, 2);
		const before = output(pair.alice, channelId, OutputType.TO_LOCAL);
		expect(before.status).to.equal(OutputStatus.CONFIRMED);
		// The sweep is signed and held for its delay, with its asset side.
		expect(before.sweepTxHex).to.be.a('string');
		expect(before.auxiliaryData).to.be.instanceOf(Buffer);
		expect(pair.sweeps.alice.length).to.be.greaterThan(0);
		// What the database holds is what the node holds, field for field.
		const row = pair.alice
			.storage!.loadAllChainMonitors()
			.find((stored) => stored.channelId === channelId.toString('hex'))!;
		expect(
			row.state.trackedOutputs.find(
				(tracked) => tracked.outputType === OutputType.TO_LOCAL
			)
		).to.deep.equal(before);

		await world.restartAlice(pair, 'aux-force-close-restart');
		const restored = output(pair.alice, channelId, OutputType.TO_LOCAL);
		expect(restored.status).to.equal(OutputStatus.CONFIRMED);
		expect(restored.auxiliaryCommitmentNumber).to.equal(
			before.auxiliaryCommitmentNumber
		);
		const held = bitcoin.Transaction.fromHex(restored.sweepTxHex!);
		expect(restored.auxiliarySweepAttempts![held.getId()]).to.deep.equal({
			transaction: restored.sweepTxHex,
			auxiliaryData: restored.auxiliaryData
		});

		const delay = pair.alice.node
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState().remoteConfig.toSelfDelay;
		await world.mine(pair, delay + 2);
		const swept = output(pair.alice, channelId, OutputType.TO_LOCAL);
		expect(swept.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		const sweep = confirmedSweep(pair, swept);
		expect(sweep.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(swept.auxiliarySweepAttempts![sweep.getId()]).to.deep.equal({
			transaction: sweep.toHex(),
			auxiliaryData: swept.auxiliaryData,
			offered: true
		});
		expect(swept.resolutionTxHex).to.equal(sweep.toHex());
		expect(pair.backends.alice.refused).to.deep.equal([]);
		expect(errorsOf(pair.alice)).to.deep.equal([]);
	});

	it('sweeps three issuances from one delayed output and retains the signed attempt across restart', async () => {
		const tag = 'grouped delayed sweep';
		const records = (
			owner: 'local' | 'remote'
		): Array<{ id: string; units: string }> =>
			issuances.map((item) => ({
				id: item.id.toString('hex'),
				units: item[owner].toString()
			}));
		const expected = records('local');
		const units = (side: 'local' | 'remote'): bigint =>
			issuances.reduce((sum, item) => sum + item[side], 0n);
		const checked = new Map<string, number>();
		const makeProvider = (): IChannelAuxiliaryProvider => {
			const provider = sweepingProvider([], {
				answer: (context, right) => {
					if (
						context.side !== 'local' ||
						context.inputs[0].kind !== 'to_local_delayed'
					)
						return right;
					expect(context.inputs).to.have.length(1);
					const input = context.inputs[0];
					const view = context.state.auxiliaryState!.localCommitments.get(
						context.commitmentNumber
					)!;
					const stored = JSON.parse(view.customData.toString());
					expect(stored.issuances).to.deep.equal(expected);
					expect(stored.index).to.equal(input.commitmentOutputIndex);
					const outpoint = context.transaction.ins[input.transactionInputIndex];
					expect(outpoint.index).to.equal(input.commitmentOutputIndex);
					checked.set(
						Buffer.from(outpoint.hash).reverse().toString('hex'),
						outpoint.index
					);
					return {
						...right,
						customData: Buffer.from(JSON.stringify(stored.issuances))
					};
				}
			});
			const build = provider.buildCommitment;
			provider.buildCommitment = (context): IAuxiliaryCommitmentData => {
				const view = build(context);
				const holderUnits =
					context.side === 'local'
						? context.localAssetBalance
						: context.remoteAssetBalance;
				const owner = holderUnits === units('local') ? 'local' : 'remote';
				expect(holderUnits).to.equal(units(owner));
				const index = context.outputs.find(
					(out) => out.role === 'to_local'
				)!.outputIndex;
				return {
					...view,
					customData: Buffer.from(
						JSON.stringify({ index, issuances: records(owner) })
					)
				};
			};
			return provider;
		};
		const hooks = { provider: makeProvider() };
		const pair = await world.open(tag, {
			openerUnits: units('local'),
			acceptorUnits: units('remote'),
			hooks: { alice: hooks, bob: { provider: makeProvider() } }
		});
		const commitmentTxid = await closedByAlice(pair);
		await world.mine(pair, 2);
		const before = output(pair.alice, pair.channelId, OutputType.TO_LOCAL);
		const bytes = Buffer.from(JSON.stringify(expected));
		expect(checked.get(commitmentTxid)).to.equal(before.outputIndex);
		expect(before.auxiliaryData).to.deep.equal(bytes);
		const held = bitcoin.Transaction.fromHex(before.sweepTxHex!);
		expect(held.ins).to.have.length(1);
		const stored = pair.alice
			.storage!.loadAllChainMonitors()
			.find((r) => r.channelId === pair.channelId.toString('hex'))!;
		expect(
			stored.state.trackedOutputs.find(
				(o) => o.outputType === OutputType.TO_LOCAL
			)!.auxiliarySweepAttempts![held.getId()]
		).to.deep.equal({ transaction: held.toHex(), auxiliaryData: bytes });
		await world.restartAlice(pair, tag, undefined, undefined, hooks);
		const again = output(pair.alice, pair.channelId, OutputType.TO_LOCAL);
		expect(again.auxiliarySweepAttempts).to.deep.equal(
			before.auxiliarySweepAttempts
		);
		const delay = pair.alice.node
			.getChannelManager()
			.getChannel(pair.channelId)!
			.getFullState().remoteConfig.toSelfDelay;
		await world.mine(pair, delay + 2);
		const swept = output(pair.alice, pair.channelId, OutputType.TO_LOCAL);
		const confirmed = confirmedSweep(pair, swept);
		expect(confirmed.outs[0].script).to.deep.equal(ASSET_SWEEP_SCRIPT);
		expect(swept.auxiliarySweepAttempts![confirmed.getId()]).to.deep.equal({
			transaction: confirmed.toHex(),
			auxiliaryData: bytes,
			offered: true
		});
	});

	it('keeps sweep data through four MiB and requires one commitment for asset-bearing inputs', () => {
		const pair = taprootPair(117);
		const state = pair.aliceChannel.getFullState();
		const source = (n: number): IAuxiliarySweepSource => ({
			kind: 'to_local_delayed',
			commitmentOutputIndex: 0,
			privateKey: hash(`sweep test key ${n}`),
			output: {
				txid: hash(`sweep commitment ${n}`).toString('hex'),
				outputIndex: 0,
				amount: 5000n,
				outputType: OutputType.TO_LOCAL,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 100,
				auxiliaryCommitmentNumber: BigInt(n)
			}
		});
		const txFor = (inputs: IAuxiliarySweepSource[]): bitcoin.Transaction => {
			const tx = new bitcoin.Transaction();
			for (const { output: tracked } of inputs)
				tx.addInput(
					Buffer.from(tracked.txid, 'hex').reverse(),
					tracked.outputIndex
				);
			tx.addOutput(SWEEP_DESTINATION, 4500);
			return tx;
		};
		const one = [source(1)];
		const original = txFor(one);
		const limit = 4 * 1024 * 1024;
		let data = Buffer.alloc(limit, 0x31);
		let calls = 0;
		pair.aliceProvider.prepareSweep = (): IAuxiliarySweepResult => {
			calls++;
			return {
				customData: data,
				outputScripts: new Map([[0, ASSET_SWEEP_SCRIPT]])
			};
		};
		const accepted = original.clone();
		const result = prepareAuxiliarySweep(
			state,
			true,
			accepted,
			one,
			SWEEP_DESTINATION
		);
		if (!result.assets || !result.ok)
			throw new Error('expected an asset sweep');
		expect(result.data.equals(data)).to.equal(true);
		expect(accepted.outs[0].script).to.deep.equal(ASSET_SWEEP_SCRIPT);
		data = Buffer.alloc(limit + 1, 0x32);
		const large = original.clone();
		const largeBefore = large.toHex();
		const tooLarge = prepareAuxiliarySweep(
			state,
			true,
			large,
			one,
			SWEEP_DESTINATION
		);
		expect(tooLarge).to.include({ assets: true, ok: false });
		expect(tooLarge)
			.to.have.property('refusal')
			.that.includes('too large to keep');
		expect(large.toHex()).to.equal(largeBefore);
		expect(calls).to.equal(2);
		const two = [source(1), source(2)];
		const mixed = txFor(two);
		const mixedBefore = mixed.toHex();
		const refused = prepareAuxiliarySweep(
			state,
			true,
			mixed,
			two,
			SWEEP_DESTINATION
		);
		expect(refused).to.include({ assets: true, ok: false });
		expect(refused)
			.to.have.property('refusal')
			.that.includes('inputs are of different commitments');
		expect(mixed.toHex()).to.equal(mixedBefore);
		expect(calls).to.equal(2);
	});

	it('keeps an output of units that cannot pay its own fee, says so in its row, and publishes nothing for it', async () => {
		// Bob holds units and next to no bitcoin.
		const pair = await world.open('aux-force-close-poor', {
			pushMsat: 1_000_000n
		});
		const { bob, channelId } = pair;
		await closedByAlice(pair);
		await world.mine(pair, 4);
		const poor = output(bob, channelId, OutputType.TO_REMOTE);
		expect(poor.amount).to.equal(1000n);
		expect(poor.auxiliaryCommitmentNumber).to.be.a('bigint');
		expect(poor.status).to.equal(OutputStatus.CONFIRMED);
		expect(poor.auxiliaryFeeFunding).to.equal(true);

		// Its spend is held with no fee input, and its row says what it waits
		// for: this node was given no wallet to take one from.
		expect(bitcoin.Transaction.fromHex(poor.sweepTxHex!).ins).to.have.length(1);
		expect(poor.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_WALLET_UNAVAILABLE'
		});
		// The provider is not asked about a spend that cannot go out.

		expect(pair.sweeps.bob).to.deep.equal([]);
		expect(pair.backends.bob.published).to.deep.equal([]);
	});

	it('sweeps an output without units as an ordinary one, asking its provider nothing', async () => {
		const pair = await world.open('aux-force-close-plain', {
			openerUnits: 10_000n,
			acceptorUnits: 0n
		});
		const { bob, channelId } = pair;
		await closedByAlice(pair);
		await world.mine(pair, 3);
		const plain = output(bob, channelId, OutputType.TO_REMOTE);
		expect(plain.auxiliaryCommitmentNumber).to.equal(undefined);
		expect(plain.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		const sweep = confirmedSweep(pair, plain);
		expect(sweep.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(false);
		expect(plain.auxiliaryData).to.equal(undefined);
		expect(plain.auxiliarySweepAttempts).to.equal(undefined);
		expect(pair.sweeps.bob).to.deep.equal([]);
		expect(pair.backends.bob.refused).to.deep.equal([]);
	});
});
