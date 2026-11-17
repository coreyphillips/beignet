/**
 * A hold invoice whose HTLC is on a channel that went on chain (issue
 * #2093 step 10).
 *
 * On chain a hold follows the clock it follows in an open channel. A
 * settle is taken while the expiry of the HTLC is more than the cancel
 * margin away (HELD_HTLC_EXPIRY_MARGIN, 18 blocks), and what
 * settleHeldHtlc answers is what is written down: taken, the decision is
 * settle and the claim is made; refused, there is no decision and nothing
 * is published. At the margin a hold nobody decided is ended by the node:
 * the decision is fail and the invoice ends cancelled. A host that cancels
 * before that does the same. And an HTLC the node will not claim is told
 * to the host as failed once its expiry has passed and the commitment is
 * there for good, whether or not the payer ever takes its output back.
 * The stagings are those of the review of step 10.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as crypto from 'crypto';
import { expect } from 'chai';
import {
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import type { ITrackedOutput } from '../../src/lightning/chain/types';
import { HELD_HTLC_EXPIRY_MARGIN } from '../../src/lightning/node/config';
import { PaymentStatus } from '../../src/lightning/node/types';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	errorsOf,
	holdUnits,
	settle,
	trackedOutputs,
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

describe('a hold invoice whose HTLC is on an asset channel that is on chain (issue #2093 step 10)', function () {
	this.timeout(180000);
	withAssetOpens();
	const world = assetChainWorld();
	let holdEvents: string[] = [];
	beforeEach(() => {
		outcomes.alice = [];
		outcomes.bob = [];
		holdEvents = [];
	});
	afterEach(() => world.dispose());

	const htlcOf = (
		host: IAssetHost,
		pair: IAssetChainPair
	): ITrackedOutput | undefined =>
		trackedOutputs(host, pair.channelId).find(
			(output) =>
				!output.isSecondLevelHtlc &&
				(output.outputType === OutputType.OFFERED_HTLC ||
					output.outputType === OutputType.RECEIVED_HTLC)
		);
	const isSpent = (output: ITrackedOutput | undefined): boolean =>
		!!output &&
		[OutputStatus.SPEND_CONFIRMED, OutputStatus.IRREVOCABLY_RESOLVED].includes(
			output.status
		);
	const parkedOf = (host: IAssetHost, paymentHash: Buffer): number =>
		host.node
			.listHeldHtlcs()
			.filter((held) => held.paymentHash.equals(paymentHash))
			.reduce((sum, held) => sum + held.htlcCount, 0);
	const decisionOf = (
		host: IAssetHost,
		pair: IAssetChainPair,
		htlcId: bigint
	): string | undefined =>
		host.node.getChannelManager().auxiliaryHtlcDecision(pair.channelId, htlcId)
			?.outcome;
	const shows = (witness: Buffer[], paymentHash: Buffer): boolean =>
		witness.some(
			(el) =>
				el.length === 32 &&
				crypto.createHash('sha256').update(el).digest().equals(paymentHash)
		);

	/** A hold of 5000 units, parked with Bob, on the commitment Alice put on chain. */
	const heldOnChain = async (
		tag: string
	): Promise<{
		pair: IAssetChainPair;
		held: Awaited<ReturnType<typeof holdUnits>>;
		commitmentHeight: number;
		published: Array<{ who: string; height: number; preimage: boolean }>;
	}> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks
		});
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		for (const name of ['hold:settled', 'hold:cancelled']) {
			pair.bob.node.on(
				name as never,
				((event: { reason?: string }) =>
					holdEvents.push(
						event?.reason ? `${name}:${event.reason}` : name
					)) as never
			);
		}
		const held = await holdUnits(pair, 5000n, tag);
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		const outpoint = htlcOf(pair.bob, pair)!;
		expect(outpoint.outputType).to.equal(OutputType.RECEIVED_HTLC);
		const commitmentHeight = pair.chain.confirmed.get(outpoint.txid)!.height;
		// Everything either side hands to the chain for the HTLC output,
		// with the height of the chain at that moment.
		const published: Array<{
			who: string;
			height: number;
			preimage: boolean;
		}> = [];
		for (const who of ['alice', 'bob'] as const) {
			const backend = pair.backends[who];
			const publish = backend.broadcastTransaction.bind(backend);
			backend.broadcastTransaction = async (hex: string): Promise<string> => {
				const tx = bitcoin.Transaction.fromHex(hex);
				const input = tx.ins.find(
					(i) =>
						Buffer.from(i.hash).reverse().toString('hex') === outpoint.txid &&
						i.index === outpoint.outputIndex
				);
				if (input) {
					published.push({
						who,
						height: pair.chain.height,
						preimage: shows(input.witness, held.paymentHash)
					});
				}
				return publish(hex);
			};
		}
		expect(holdEvents).to.deep.equal([]);
		return { pair, held, commitmentHeight, published };
	};
	/** Block by block to a height, every block announced. */
	const mineTo = async (
		pair: IAssetChainPair,
		height: number
	): Promise<void> => {
		while (pair.chain.height < height) await world.mine(pair, 1);
	};

	it('takes a settle asked for one block before the cancel margin: the answer is yes, the decision is written, and the claim is in a block before the expiry', async () => {
		const { pair, held, published } = await heldOnChain('aux-hold-chain-taken');
		await mineTo(pair, held.cltvExpiry - HELD_HTLC_EXPIRY_MARGIN - 1);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(1);
		expect(decisionOf(pair.bob, pair, 0n)).to.equal(undefined);

		expect(
			pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage)
		).to.equal(true);
		await settle();
		expect(decisionOf(pair.bob, pair, 0n)).to.equal('settle');
		// A cancel is refused from here: the settle stands.
		expect(pair.bob.node.cancelHoldInvoice(held.paymentHash)).to.equal(null);
		for (let i = 0; i < 12 && !isSpent(htlcOf(pair.bob, pair)); i++) {
			await world.mine(pair, 1);
		}
		const claimed = htlcOf(pair.bob, pair)!;
		expect(isSpent(claimed), 'the HTLC output is spent').to.equal(true);
		expect(
			claimed.auxiliarySweepAttempts?.[claimed.resolutionTxid!]
		).to.not.equal(undefined);
		expect(
			pair.chain.confirmed.get(claimed.resolutionTxid!)!.height
		).to.be.below(held.cltvExpiry);
		expect(
			published.filter((p) => p.who === 'bob' && !p.preimage)
		).to.deep.equal([]);

		pair.chain.advance(IRREVOCABLE_DEPTH);
		await settle();
		await world.mine(pair, 2);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:fulfilled:5000']);
		expect(holdEvents).to.deep.equal(['hold:settled']);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(0);
		expect(pair.bob.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('ends a hold nobody decided at the cancel margin, and refuses a settle asked for one block before the expiry: no decision to settle, no preimage published, the payer takes the HTLC back', async () => {
		const { pair, held, published } = await heldOnChain('aux-hold-chain-late');
		await mineTo(pair, held.cltvExpiry - HELD_HTLC_EXPIRY_MARGIN - 1);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(1);
		expect(holdEvents).to.deep.equal([]);
		// The block at which an open channel would have failed the hold back.
		await world.mine(pair, 1);
		expect(pair.chain.height).to.equal(
			held.cltvExpiry - HELD_HTLC_EXPIRY_MARGIN
		);
		expect(holdEvents).to.deep.equal(['hold:cancelled:expiry-scan']);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(0);
		expect(decisionOf(pair.bob, pair, 0n)).to.equal('fail');

		await mineTo(pair, held.cltvExpiry - 1);
		const answered = pair.bob.node.settleHeldHtlc(
			held.paymentHash,
			held.preimage
		);
		await settle();
		// What is answered and what is written down are the same thing.
		expect(answered).to.equal(false);
		expect(decisionOf(pair.bob, pair, 0n)).to.equal('fail');
		for (let i = 0; i < 8 && !isSpent(htlcOf(pair.bob, pair)); i++) {
			await world.mine(pair, 1);
		}
		expect(published.filter((p) => p.preimage)).to.deep.equal([]);
		expect(published.filter((p) => p.who === 'bob')).to.deep.equal([]);
		const taken = htlcOf(pair.bob, pair)!;
		expect(isSpent(taken), 'the payer took the HTLC back').to.equal(true);
		expect(taken.resolutionTxid).to.equal(
			htlcOf(pair.alice, pair)!.resolutionTxid
		);

		pair.chain.advance(IRREVOCABLE_DEPTH);
		await settle();
		await world.mine(pair, 2);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
		expect(outcomes.alice).to.deep.equal(['OFFERED:failed:5000']);
		expect(holdEvents).to.deep.equal(['hold:cancelled:expiry-scan']);
		expect(pair.bob.node.getPayment(held.paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('tells the host that an HTLC nobody claims has failed once its expiry has passed and the commitment is there for good, though the payer never takes the output back', async () => {
		const { pair, held, commitmentHeight } = await heldOnChain(
			'aux-hold-chain-nobody'
		);
		// The payer's node is gone from here: it never makes its timeout.
		pair.alice.node.destroy();
		pair.backends.alice.close();

		await mineTo(pair, held.cltvExpiry - HELD_HTLC_EXPIRY_MARGIN);
		expect(holdEvents).to.deep.equal(['hold:cancelled:expiry-scan']);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(0);
		expect(decisionOf(pair.bob, pair, 0n)).to.equal('fail');
		expect(outcomes.bob).to.deep.equal([]);

		// Not before the expiry has passed and the commitment is 100 deep.
		const due = Math.max(held.cltvExpiry, commitmentHeight + IRREVOCABLE_DEPTH);
		pair.chain.advance(due - 2 - pair.chain.height);
		await settle();
		await world.mine(pair, 1);
		expect(pair.chain.height).to.equal(due - 1);
		expect(outcomes.bob).to.deep.equal([]);
		await world.mine(pair, 1);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
		expect(htlcOf(pair.bob, pair)!.status).to.equal(OutputStatus.CONFIRMED);

		// However long nobody spends the output, nothing more is said.
		for (let i = 0; i < 30; i++) await world.mine(pair, 1);
		pair.chain.advance(270);
		await settle();
		await world.mine(pair, 2);
		expect(htlcOf(pair.bob, pair)!.status).to.equal(OutputStatus.CONFIRMED);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
		expect(pair.bob.node.cancelHoldInvoice(held.paymentHash)).to.equal(null);
		expect(holdEvents).to.deep.equal(['hold:cancelled:expiry-scan']);
		expect(
			errorsOf(pair.bob).filter((e) => e.includes('Cannot fail HTLC'))
		).to.deep.equal([]);
	});

	it('lets the host cancel the hold while the channel is on chain: the decision is written, the hold ends, no channel error is raised, and a settle after it is refused', async () => {
		const { pair, held, published } = await heldOnChain(
			'aux-hold-chain-cancel'
		);
		const errors = errorsOf(pair.bob).length;
		expect(pair.bob.node.cancelHoldInvoice(held.paymentHash)).to.deep.equal({
			htlcsFailed: 1
		});
		await settle();
		expect(holdEvents).to.deep.equal(['hold:cancelled:api']);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(0);
		expect(decisionOf(pair.bob, pair, 0n)).to.equal('fail');
		expect(errorsOf(pair.bob).slice(errors)).to.deep.equal([]);

		expect(
			pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage)
		).to.equal(false);
		await settle();
		expect(decisionOf(pair.bob, pair, 0n)).to.equal('fail');
		await mineTo(pair, held.cltvExpiry);
		for (let i = 0; i < 8 && !isSpent(htlcOf(pair.bob, pair)); i++) {
			await world.mine(pair, 1);
		}
		expect(published.filter((p) => p.who === 'bob')).to.deep.equal([]);
		expect(isSpent(htlcOf(pair.bob, pair))).to.equal(true);
		pair.chain.advance(IRREVOCABLE_DEPTH);
		await settle();
		await world.mine(pair, 2);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
		expect(holdEvents).to.deep.equal(['hold:cancelled:api']);
	});
});
