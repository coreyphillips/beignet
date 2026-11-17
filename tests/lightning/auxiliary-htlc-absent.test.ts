/**
 * The HTLCs of an asset channel that are on no output of the commitment
 * that confirmed (issue #2093 step 10).
 *
 * A commitment can come to the chain before an HTLC is in it, or after the
 * HTLC has left it while the peer's revocation for that is still owed.
 * Nothing on the chain then says how the HTLC ended, so the node says it
 * once that commitment can no longer be replaced: every test here puts the
 * commitment on a test chain through the real monitor and reads what the
 * host was told (onHtlcResolved), when, and how often.
 */

import { expect } from 'chai';
import { IRREVOCABLE_DEPTH, OutputType } from '../../src/lightning/chain/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	gateMessages,
	holdUnits,
	payUnits,
	settle,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

const outcomes: { alice: string[]; bob: string[] } = { alice: [], bob: [] };
const told =
	(who: 'alice' | 'bob') =>
	(context: {
		direction: string;
		outcome: string;
		auxiliaryAmount: bigint;
	}): void => {
		outcomes[who].push(
			`${context.direction}:${context.outcome}:${context.auxiliaryAmount}`
		);
	};
const hooks = {
	alice: { onHtlcResolved: told('alice') },
	bob: {
		valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }): bigint =>
			context.auxiliaryAmount! * 1000n,
		onHtlcResolved: told('bob')
	}
};
/** The HTLCs a host's channel holds, as `direction:state`. */
const htlcsOf = (host: IAssetHost, pair: IAssetChainPair): string[] =>
	[
		...(host.node
			.getChannelManager()
			.getChannel(pair.channelId)
			?.getFullState()
			.htlcs.values() ?? [])
	].map((entry) => `${entry.direction}:${entry.state}`);
/** The parts of a hold invoice a node still has parked. */
const parkedOf = (host: IAssetHost, paymentHash: Buffer): number =>
	(host.node as unknown as { heldHtlcs: Map<string, unknown[]> }).heldHtlcs.get(
		paymentHash.toString('hex')
	)?.length ?? 0;

describe('the HTLCs of an asset channel that the confirmed commitment does not carry (issue #2093 step 10)', function () {
	this.timeout(120000);
	withAssetOpens();
	const world = assetChainWorld();
	beforeEach(() => {
		outcomes.alice = [];
		outcomes.bob = [];
	});
	afterEach(() => world.dispose());

	const opened = async (tag: string): Promise<IAssetChainPair> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks
		});
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		return pair;
	};
	/** Nothing either node sends reaches the other from here on. */
	const cut = (pair: IAssetChainPair): void => {
		gateMessages(pair, 'alice', () => true);
		gateMessages(pair, 'bob', () => true);
	};
	/** The height of the block the commitment is in. */
	const commitmentHeight = (pair: IAssetChainPair): number => {
		const funding = pair.funding.getId();
		for (const entry of pair.chain.confirmed.values()) {
			if (
				entry.tx.ins.some(
					(input) =>
						Buffer.from(input.hash).reverse().toString('hex') === funding
				)
			) {
				return entry.height;
			}
		}
		throw new Error('the commitment is not in a block');
	};
	/**
	 * One node closes by itself, with the other hearing of it from the chain
	 * alone, and the chain goes on to one block short of the depth at which
	 * the commitment is there for good.
	 */
	const closedAndAlmostBuried = async (
		pair: IAssetChainPair,
		closer: 'alice' | 'bob'
	): Promise<number> => {
		cut(pair);
		const closed = pair[closer].node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 1);
		const height = commitmentHeight(pair);
		pair.chain.advance(height + IRREVOCABLE_DEPTH - 1 - pair.chain.height);
		await settle();
		return height;
	};

	it('says an HTLC it offered has failed when the commitment of the peer that confirmed was made before the HTLC, once that commitment is there for good', async function () {
		const pair = await opened('aux-absent-theirs');
		// Nothing of the offer reaches Bob, whose commitment stays as it was.
		gateMessages(pair, 'alice', () => true);
		const offer = await holdUnits(pair, 5000n, 'theirs', 60, false);
		expect(htlcsOf(pair.alice, pair)).to.have.length(1);
		expect(htlcsOf(pair.bob, pair)).to.deep.equal([]);

		await closedAndAlmostBuried(pair, 'bob');
		expect(outcomes.alice, 'one block short of the depth').to.deep.equal([]);
		await world.mine(pair, 1);
		expect(outcomes.alice).to.deep.equal(['OFFERED:failed:5000']);
		expect(outcomes.bob).to.deep.equal([]);
		expect(pair.alice.node.getPayment(offer.paymentHash)?.status).to.equal(
			PaymentStatus.FAILED
		);
		// Told once: the blocks that follow say nothing more.
		await world.mine(pair, 3);
		expect(outcomes.alice).to.deep.equal(['OFFERED:failed:5000']);
	});

	it('says an HTLC has failed on both sides when the commitment of the node that offered it confirmed without it, and says it once across a restart', async function () {
		const tag = 'aux-absent-ours';
		const pair = await opened(tag);
		// Bob takes the offer and signs for it; his answer never arrives, so
		// the commitment Alice holds is the one from before the HTLC.
		gateMessages(pair, 'bob', () => true);
		const offer = await holdUnits(pair, 5000n, 'ours', 60, false);
		expect(htlcsOf(pair.alice, pair)).to.have.length(1);
		expect(htlcsOf(pair.bob, pair)).to.have.length(1);
		expect(parkedOf(pair.bob, offer.paymentHash)).to.equal(0);

		await closedAndAlmostBuried(pair, 'alice');
		expect(outcomes, 'one block short of the depth').to.deep.equal({
			alice: [],
			bob: []
		});
		await world.mine(pair, 1);
		expect(outcomes.alice).to.deep.equal(['OFFERED:failed:5000']);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
		expect(pair.alice.node.getPayment(offer.paymentHash)?.status).to.equal(
			PaymentStatus.FAILED
		);

		// What says the ending is recorded is in the monitor's row: Alice,
		// started again from her database, does not say it a second time.
		await world.mine(pair, 2);
		await world.restartAlice(pair, tag, undefined, undefined, hooks.alice);
		await world.mine(pair, 3);
		expect(outcomes.alice).to.deep.equal(['OFFERED:failed:5000']);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
	});

	it('says nothing more of an HTLC that had left the channel before the commitment that confirmed', async function () {
		const pair = await opened('aux-absent-removed');
		await payUnits(pair, 5000n);
		expect(outcomes).to.deep.equal({
			alice: ['OFFERED:fulfilled:5000'],
			bob: ['RECEIVED:fulfilled:5000']
		});
		expect(
			htlcsOf(pair.alice, pair).concat(htlcsOf(pair.bob, pair))
		).to.deep.equal([]);

		await closedAndAlmostBuried(pair, 'alice');
		await world.mine(pair, 4);
		expect(outcomes).to.deep.equal({
			alice: ['OFFERED:fulfilled:5000'],
			bob: ['RECEIVED:fulfilled:5000']
		});
	});

	it('says an HTLC is fulfilled when the commitment that confirmed is the one it had already left by the preimage, with the revocation for that still owed', async function () {
		const pair = await opened('aux-absent-settled');
		const held = await holdUnits(pair, 5000n, 'settled');
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(1);
		// Bob settles and signs the commitment of Alice without the HTLC.
		// Her revocation of the one before never reaches him.
		gateMessages(pair, 'alice', () => true);
		expect(
			pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage)
		).to.equal(true);
		await settle();
		expect(htlcsOf(pair.alice, pair)).to.deep.equal(['OFFERED:FULFILLED']);
		expect(htlcsOf(pair.bob, pair)).to.deep.equal(['RECEIVED:FULFILLED']);
		expect(pair.alice.node.getPayment(held.paymentHash)?.status).to.equal(
			PaymentStatus.COMPLETED
		);
		const before = { alice: [...outcomes.alice], bob: [...outcomes.bob] };

		await closedAndAlmostBuried(pair, 'alice');
		expect(outcomes, 'one block short of the depth').to.deep.equal(before);
		await world.mine(pair, 1);
		expect(outcomes.alice).to.deep.equal(['OFFERED:fulfilled:5000']);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:fulfilled:5000']);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(0);
		expect(pair.bob.node.getPayment(held.paymentHash)?.status).to.equal(
			PaymentStatus.COMPLETED
		);
		await world.mine(pair, 3);
		expect(outcomes.alice).to.have.length(1);
		expect(outcomes.bob).to.have.length(1);
	});

	it('says an HTLC has failed to a node that has no output of its own on the commitment that confirmed, and only then is done with the channel', async function () {
		// Bob holds neither units nor bitcoin in the channel: the commitment
		// of Alice pays him nothing, and he has nothing to sweep.
		const pair = await world.open('aux-absent-no-output', {
			acceptorUnits: 0n,
			pushMsat: 0n,
			feeWallet: { alice: true, bob: true },
			hooks
		});
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		gateMessages(pair, 'bob', () => true);
		await holdUnits(pair, 5000n, 'no-output', 60, false);
		expect(htlcsOf(pair.bob, pair)).to.have.length(1);

		await closedAndAlmostBuried(pair, 'alice');
		const monitorOf = (): { monitorState: string; own: number } => {
			const state = pair.bob.node.getChannelMonitorState(pair.channelId);
			return {
				monitorState: String(state?.monitorState),
				own: (state?.trackedOutputs ?? []).filter(
					(output) => output.outputType !== OutputType.TO_LOCAL
				).length
			};
		};
		const short = monitorOf();
		expect(outcomes.bob, 'one block short of the depth').to.deep.equal([]);
		await world.mine(pair, 1);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
		// Nothing on the commitment is Bob's, and his monitor was not done
		// with the channel before that.
		expect(short).to.deep.equal({ monitorState: 'RESOLVING', own: 0 });
		await world.mine(pair, 2);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
		expect(
			String(
				pair.bob.node.getChannelMonitorState(pair.channelId)?.monitorState ??
					'FULLY_RESOLVED'
			)
		).to.equal('FULLY_RESOLVED');
	});
});
