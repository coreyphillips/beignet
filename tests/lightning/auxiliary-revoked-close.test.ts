/**
 * Issue #2093: a revoked commitment of an asset channel on the chain.
 *
 * The cheater publishes a commitment it has revoked. The other node reads
 * the asset side of that commitment back from its store of revoked views,
 * takes its own balance output and punishes the cheater's, each with the
 * asset side its provider makes. The chain judges every spend against the
 * script tree of the output it spends, asset leaf included.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import type Database from 'better-sqlite3';
import {
	CommitmentType,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import type { IChannelState } from '../../src/lightning/channel/channel-state';
import type { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	ASSET_SWEEP_SCRIPT,
	assetChainWorld,
	errorsOf,
	payUnits,
	settle,
	trackedOutputs,
	type IAssetChainOptions,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

describe('a revoked commitment of an asset channel on the chain (issue #2093)', function () {
	this.timeout(120_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());

	const valued: IAssetChainOptions = {
		hooks: {
			bob: {
				valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }) =>
					(context.auxiliaryAmount ?? 0n) * 1000n
			}
		}
	};
	const stateOf = (host: IAssetHost, channelId: Buffer): IChannelState =>
		host.node.getChannelManager().getChannel(channelId)!.getFullState();
	const outputs = (
		host: IAssetHost,
		channelId: Buffer,
		type: OutputType
	): ITrackedOutput[] =>
		trackedOutputs(host, channelId).filter(
			(tracked) => tracked.outputType === type
		);
	const confirmedSpend = (
		pair: IAssetChainPair,
		tracked: ITrackedOutput
	): bitcoin.Transaction => {
		expect(tracked.resolutionTxid, 'a spend the monitor saw').to.be.a('string');
		const entry = pair.chain.confirmed.get(tracked.resolutionTxid!);
		expect(entry, 'the spend is in a block').to.not.equal(undefined);
		return entry!.tx;
	};

	/**
	 * What the chain turned away of what Alice published, but for what the
	 * previous release publishes too: a claim that waits a block, ahead of
	 * the block, and a sweep signed anew at another fee for an output that a
	 * sweep of hers has already spent.
	 */
	const unexpectedRefusals = (pair: IAssetChainPair): string[] =>
		pair.backends.alice.refused
			.map((refusal) => refusal.reason)
			.filter(
				(reason) =>
					!reason.includes('is already spent by') &&
					!reason.includes('waits 1 blocks on an unconfirmed output')
			);

	/**
	 * Bob keeps the commitment he holds now, the channel moves on by two
	 * payments, and Bob publishes what he kept. The number of that
	 * commitment, and its id.
	 */
	const cheated = async (
		pair: IAssetChainPair,
		beforePublishing: () => void = (): void => undefined
	): Promise<{ number: bigint; txid: string }> => {
		const { alice, bob, channelId } = pair;
		const channel = bob.node.getChannelManager().getChannel(channelId)!;
		const number = channel.getFullState().localCommitmentNumber;
		const plan = channel.prepareForceClose(channel.getSigner()!);
		if (!plan.ok) throw new Error(plan.error);
		const kept = bitcoin.Transaction.fromBuffer(plan.commitmentTx);
		await payUnits(pair, 100n);
		await payUnits(pair, 100n);
		// The view of that commitment has left Alice's memory and her row.
		const auxiliary = stateOf(alice, channelId).auxiliaryState!;
		expect(auxiliary.remoteCommitments.has(number)).to.equal(false);
		expect(auxiliary.revokedCommitments?.has(number) ?? false).to.equal(false);
		beforePublishing();
		await pair.backends.bob.broadcastTransaction(kept.toHex());
		await settle();
		expect(pair.chain.mempool.has(kept.getId())).to.equal(true);
		return { number, txid: kept.getId() };
	};

	it('is punished: the node reads the asset side back from its store, takes its own units and those of the cheater, each with the asset side its provider made', async () => {
		const pair = await world.open('aux-revoked-close', valued);
		const { alice, channelId } = pair;
		const { number, txid } = await cheated(pair);
		expect(
			(alice.storage as SqliteStorage).loadAuxiliaryRevokedCommitment(
				channelId.toString('hex'),
				number
			)
		).to.not.equal(null);

		await world.mine(pair, 4);
		expect(
			alice.node.getChannelMonitorState(channelId)!.commitmentBroadcast
		).to.include({
			txid,
			commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
			commitmentNumber: number
		});
		const auxiliary = stateOf(alice, channelId).auxiliaryState!;
		expect(auxiliary.revokedCommitmentHeld).to.equal(number);
		expect(auxiliary.revokedCommitments!.has(number)).to.equal(true);

		// Bob's output of that commitment, taken with the revocation key.
		const [theirs] = outputs(alice, channelId, OutputType.TO_LOCAL);
		expect(theirs.auxiliaryCommitmentNumber).to.equal(number);
		expect(theirs.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		const penalty = confirmedSpend(pair, theirs);
		expect(penalty.ins).to.have.length(1);
		expect(penalty.outs).to.have.length(1);
		expect(penalty.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(theirs.auxiliarySweepAttempts![penalty.getId()]).to.deep.equal({
			transaction: penalty.toHex(),
			auxiliaryData: theirs.auxiliaryData,
			offered: true
		});
		// Alice's own output of that commitment.
		const [mine] = outputs(alice, channelId, OutputType.TO_REMOTE);
		expect(mine.auxiliaryCommitmentNumber).to.equal(number);
		expect(mine.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		const claim = confirmedSpend(pair, mine);
		expect(claim.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(mine.auxiliarySweepAttempts![claim.getId()]).to.deep.equal({
			transaction: claim.toHex(),
			auxiliaryData: mine.auxiliaryData,
			offered: true
		});

		// The provider was asked for each, for the revoked commitment.
		const asked = pair.sweeps.alice.map((call) => ({
			side: call.side,
			number: call.commitmentNumber,
			kinds: call.kinds.join(',')
		}));
		expect(asked).to.deep.include({
			side: 'remote',
			number,
			kinds: 'to_local_revocation'
		});
		expect(asked).to.deep.include({
			side: 'remote',
			number,
			kinds: 'to_remote'
		});
		expect(unexpectedRefusals(pair)).to.deep.equal([]);
		expect(
			errorsOf(alice).filter((error) => !error.startsWith('BROADCAST_FAILED'))
		).to.deep.equal([]);
	});

	it('is punished after a restart of the node between the commitment and its claims', async () => {
		const pair = await world.open('aux-revoked-restart', valued);
		const { channelId } = pair;
		const { number } = await cheated(pair);
		await world.mine(pair, 1);
		expect(
			pair.alice.node.getChannelMonitorState(channelId)!.commitmentBroadcast!
				.commitmentType
		).to.equal(CommitmentType.THEIR_REVOKED_COMMITMENT);

		await world.restartAlice(pair, 'aux-revoked-restart');
		expect(
			stateOf(pair.alice, channelId).auxiliaryState!.revokedCommitmentHeld
		).to.equal(number);
		await world.mine(pair, 10);
		for (const type of [OutputType.TO_LOCAL, OutputType.TO_REMOTE]) {
			const [tracked] = outputs(pair.alice, channelId, type);
			expect(tracked.status, type).to.equal(OutputStatus.SPEND_CONFIRMED);
			expect(
				confirmedSpend(pair, tracked).outs[0].script.equals(ASSET_SWEEP_SCRIPT),
				type
			).to.equal(true);
		}
		expect(unexpectedRefusals(pair)).to.deep.equal([]);
		expect(
			errorsOf(pair.alice).filter(
				(error) => !error.startsWith('BROADCAST_FAILED')
			)
		).to.deep.equal([]);
	});

	it('without the asset side of that commitment says so, naming the channel and the commitment, and punishes the output without units only', async () => {
		// Bob holds no units in the commitment he keeps.
		const pair = await world.open('aux-revoked-lost', {
			...valued,
			openerUnits: 10_000n,
			acceptorUnits: 0n
		});
		const { alice, channelId } = pair;
		const hex = channelId.toString('hex');
		const said: string[] = [];
		alice.node
			.getChannelManager()
			.on('error', (_id: unknown, message: unknown) => {
				said.push(String(message));
			});
		// As on a node restored from a recovery frame: the store is empty.
		const { number } = await cheated(pair, () => {
			(alice.storage as unknown as { db: Database.Database }).db
				.prepare('DELETE FROM auxiliary_revoked_commitments')
				.run();
		});

		await world.mine(pair, 4);
		expect(said).to.include(
			`The asset side of revoked commitment ${number} is not held, so its outputs that carry units cannot be punished (channel ${hex})`
		);
		expect(
			alice.node.getChannelMonitorState(channelId)!.commitmentBroadcast!
				.commitmentType
		).to.equal(CommitmentType.THEIR_REVOKED_COMMITMENT);
		// The cheater's output carries no units: it is punished as an
		// ordinary one, to the node's own destination.
		const [theirs] = outputs(alice, channelId, OutputType.TO_LOCAL);
		expect(theirs.auxiliaryCommitmentNumber).to.equal(undefined);
		expect(theirs.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		expect(
			confirmedSpend(pair, theirs).outs[0].script.equals(ASSET_SWEEP_SCRIPT)
		).to.equal(false);
		expect(theirs.auxiliaryData).to.equal(undefined);
		// The node's own output carries its units and is not found.
		expect(outputs(alice, channelId, OutputType.TO_REMOTE)).to.deep.equal([]);
		expect(pair.sweeps.alice).to.deep.equal([]);
		expect(unexpectedRefusals(pair)).to.deep.equal([]);
	});
});
