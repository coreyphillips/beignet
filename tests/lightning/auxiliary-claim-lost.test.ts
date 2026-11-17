/**
 * A claim of an asset HTLC that lost on the chain (issue #2093 step 10).
 *
 * The node decided to settle an HTLC, gave its preimage out, and the
 * payer's timeout took the output all the same. That is not an ordinary
 * failure: the payer may hold the preimage and the units were not
 * received. The host is told failed with `preimageRevealed`, the record
 * of the payment follows the chain, and one error is raised when the
 * expiry passes with no claim of the node in a block, not a hundred
 * blocks later. The staging is that of the review of step 10.
 */

import * as crypto from 'crypto';
import { expect } from 'chai';
import {
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import type { ITrackedOutput } from '../../src/lightning/chain/types';
import type { IChannelAuxiliaryState } from '../../src/lightning/channel/auxiliary';
import { HtlcDirection } from '../../src/lightning/channel/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	deserializeAuxiliaryState,
	serializeAuxiliaryState
} from '../../src/lightning/storage/auxiliary-serialization';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	gateMessages,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

const COMMITMENT_SIGNED = 132;
const LATE = 'ASSET_HTLC_CLAIM_UNCONFIRMED_AT_EXPIRY';

const outcomes: { alice: string[]; bob: string[] } = { alice: [], bob: [] };
const told =
	(who: 'alice' | 'bob') =>
	(context: {
		direction: string;
		outcome: string;
		auxiliaryAmount: bigint;
		preimageRevealed?: true;
	}): void => {
		outcomes[who].push(
			`${context.direction}:${context.outcome}:${context.auxiliaryAmount}${
				context.preimageRevealed ? ':preimage revealed' : ''
			}`
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

describe('a claim of an asset HTLC that lost on the chain is said as a loss (issue #2093 step 10)', function () {
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
	const showsPreimage = (
		pair: IAssetChainPair,
		output: ITrackedOutput,
		paymentHash: Buffer
	): boolean =>
		pair.chain.confirmed
			.get(output.resolutionTxid ?? '')
			?.tx.ins.some((input) =>
				input.witness.some(
					(el) =>
						el.length === 32 &&
						crypto.createHash('sha256').update(el).digest().equals(paymentHash)
				)
			) === true;
	/** The payee's wallet has no coin: a claim of its own cannot be paid for. */
	const opened = async (tag: string): Promise<IAssetChainPair> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks
		});
		pair.wallets.alice!.fund(100_000);
		pair.wallets.alice!.fund(100_000);
		await world.mine(pair, 1);
		for (const name of ['hold:settled', 'hold:cancelled']) {
			pair.bob.node.on(name as never, (() => holdEvents.push(name)) as never);
		}
		return pair;
	};
	const late = (host: IAssetHost): string[] =>
		host.errors.filter((error) => error.includes(LATE));
	const mineTo = async (
		pair: IAssetChainPair,
		height: number
	): Promise<void> => {
		while (pair.chain.height < height) await world.mine(pair, 1);
	};

	it('tells the host failed with preimageRevealed, sets its payment record failed, and raises one error at the expiry, for an HTLC it settled in the channel whose claim on the chain never confirmed', async () => {
		const pair = await opened('aux-claim-lost');
		const { alice, bob, chain, channelId } = pair;
		const held = await holdUnits(pair, 5000n, 'claim lost');
		// The payer takes the preimage, revokes, and never signs the HTLC
		// out of the payee's commitment.
		let cut = false;
		gateMessages(pair, 'alice', (type) => {
			if (type === COMMITMENT_SIGNED) cut = true;
			return cut;
		});
		expect(bob.node.settleHeldHtlc(held.paymentHash, held.preimage)).to.equal(
			true
		);
		await settle();
		expect(outcomes.bob).to.deep.equal(['RECEIVED:fulfilled:5000']);
		expect(bob.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);

		// The payee closes by itself 18 blocks before the expiry, and its
		// claim waits for a coin its wallet never has.
		chain.advance(held.cltvExpiry - 19 - chain.height);
		await settle();
		await world.mine(pair, 2);
		expect(
			bob.errors.filter((e) => e.includes('HTLC_CLAIM_FORCE_CLOSE'))
		).to.have.length(1);
		expect(htlcOf(bob, pair)!.outputType).to.equal(OutputType.RECEIVED_HTLC);
		await mineTo(pair, held.cltvExpiry - 1);
		expect(late(bob)).to.deep.equal([]);
		// The expiry: said once, now, with the channel named.
		await world.mine(pair, 1);
		expect(late(bob)).to.have.length(1);
		expect(late(bob)[0]).to.include(channelId.toString('hex'));
		expect(late(bob)[0]).to.include(`${held.cltvExpiry}`);

		// The payer's timeout takes the output.
		for (let i = 0; i < 8 && !isSpent(htlcOf(bob, pair)); i++) {
			await world.mine(pair, 1);
		}
		const taken = htlcOf(bob, pair)!;
		expect(isSpent(taken), 'the payer took the HTLC back').to.equal(true);
		expect(showsPreimage(pair, taken, held.paymentHash)).to.equal(false);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:fulfilled:5000']);

		chain.advance(IRREVOCABLE_DEPTH);
		await settle();
		await world.mine(pair, 2);
		await settle();
		expect(outcomes.bob).to.deep.equal([
			'RECEIVED:fulfilled:5000',
			'RECEIVED:failed:5000:preimage revealed'
		]);
		expect(bob.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(late(bob)).to.have.length(1);
		expect(late(alice)).to.deep.equal([]);
	});

	it('tells the host failed without the mark for a hold settled on the chain whose claim was never signed: the preimage did not leave the node', async () => {
		const pair = await opened('aux-claim-unsigned');
		const { alice, bob, chain, channelId } = pair;
		const held = await holdUnits(pair, 5000n, 'claim unsigned');
		const closed = alice.node.forceCloseChannel(channelId, SWEEP_DESTINATION);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		expect(bob.node.settleHeldHtlc(held.paymentHash, held.preimage)).to.equal(
			true
		);
		await settle();
		await mineTo(pair, held.cltvExpiry - 1);
		// No claim was ever funded and signed: nothing carries the preimage.
		expect(
			Object.keys(htlcOf(bob, pair)!.auxiliarySweepAttempts ?? {})
		).to.deep.equal([]);
		expect(pair.wallets.bob!.sent).to.have.length(0);
		expect(late(bob)).to.deep.equal([]);
		await world.mine(pair, 1);
		expect(late(bob)).to.have.length(1);
		for (let i = 0; i < 8 && !isSpent(htlcOf(bob, pair)); i++) {
			await world.mine(pair, 1);
		}
		expect(isSpent(htlcOf(bob, pair))).to.equal(true);
		chain.advance(IRREVOCABLE_DEPTH);
		await settle();
		await world.mine(pair, 2);
		await settle();
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
		expect(holdEvents).to.deep.equal(['hold:cancelled']);
		expect(bob.node.getPayment(held.paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
		expect(late(bob)).to.have.length(1);
	});

	it('writes and reads back the mark with the outcome it is on, and refuses a malformed one', () => {
		const state: IChannelAuxiliaryState = {
			channelData: Buffer.from([0]),
			localBalance: 0n,
			remoteBalance: 0n,
			localCommitments: new Map(),
			remoteCommitments: new Map(),
			resolvedHtlcs: new Map([
				[
					`${HtlcDirection.RECEIVED}:3`,
					{
						htlcId: 3n,
						direction: HtlcDirection.RECEIVED,
						paymentHash: Buffer.alloc(32, 5),
						auxiliaryAmount: 5000n,
						outcome: 'failed' as const,
						preimageRevealed: true as const
					}
				]
			])
		};
		const written = serializeAuxiliaryState(state);
		expect(written.resolvedHtlcs![0][1].preimageRevealed).to.equal(true);
		const read = deserializeAuxiliaryState(JSON.parse(JSON.stringify(written)));
		expect(read.resolvedHtlcs).to.deep.equal(state.resolvedHtlcs);
		expect(serializeAuxiliaryState(read)).to.deep.equal(written);
		const malformed = JSON.parse(JSON.stringify(written));
		malformed.resolvedHtlcs[0][1].preimageRevealed = 'yes';
		expect(() => deserializeAuxiliaryState(malformed)).to.throw();
		const fulfilled = JSON.parse(JSON.stringify(written));
		fulfilled.resolvedHtlcs[0][1].outcome = 'fulfilled';
		expect(() => deserializeAuxiliaryState(fulfilled)).to.throw();
	});
});
