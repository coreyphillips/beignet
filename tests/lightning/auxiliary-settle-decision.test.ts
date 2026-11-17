/**
 * What the node decided for each HTLC it received on an asset channel, as
 * a record (issue #2093 step 10).
 *
 * A claim by preimage on the chain is made for an HTLC the node decided to
 * settle, and for no other. The decision is written with the channel's
 * row for that HTLC, by its id, when the node decides: a fulfil it makes,
 * a fail it makes, a hold settled or cancelled. It is read wherever the
 * HTLC sits by then, and a preimage that is merely stored for the payment
 * hash decides nothing. The stagings are those of the review of step 10.
 */

import * as crypto from 'crypto';
import { expect } from 'chai';
import {
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import type { ITrackedOutput } from '../../src/lightning/chain/types';
import { HtlcState } from '../../src/lightning/channel/types';
import type {
	IAuxiliaryHtlcDecision,
	IChannelAuxiliaryState
} from '../../src/lightning/channel/auxiliary';
import {
	deserializeAuxiliaryState,
	serializeAuxiliaryState
} from '../../src/lightning/storage/auxiliary-serialization';
import { PaymentStatus } from '../../src/lightning/node/types';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import { amountRecord } from './helpers/auxiliary-pair';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	disconnect,
	gateMessages,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

const COMMITMENT_SIGNED = 132;
const UPDATE_FAIL_HTLC = 131;
const UPDATE_FAIL_MALFORMED_HTLC = 135;

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
const value = (context: { auxiliaryAmount?: bigint }): bigint =>
	context.auxiliaryAmount! * 1000n;
const hooks = {
	alice: { valueIncomingHtlc: value, onHtlcResolved: told('alice') },
	bob: { valueIncomingHtlc: value, onHtlcResolved: told('bob') }
};

/** What a node wrote down for an HTLC it received, as read from its channel. */
const decisionOf = (
	host: IAssetHost,
	pair: IAssetChainPair,
	htlcId: bigint
): string | undefined =>
	(
		host.node.getChannelManager().getChannel(pair.channelId)!.getFullState()
			.auxiliaryState as unknown as
			| { htlcDecisions?: Map<string, { outcome: string }> }
			| undefined
	)?.htlcDecisions?.get(htlcId.toString())?.outcome;

describe('the settle decision of an asset channel is a record for each HTLC (issue #2093 step 10)', function () {
	this.timeout(180000);
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
	const htlcsOnChain = (
		host: IAssetHost,
		pair: IAssetChainPair
	): ITrackedOutput[] =>
		trackedOutputs(host, pair.channelId).filter(
			(output) =>
				!output.isSecondLevelHtlc &&
				(output.outputType === OutputType.OFFERED_HTLC ||
					output.outputType === OutputType.RECEIVED_HTLC)
		);
	const htlcOf = (
		host: IAssetHost,
		pair: IAssetChainPair,
		htlcId?: bigint
	): ITrackedOutput | undefined =>
		htlcsOnChain(host, pair).find(
			(output) => htlcId === undefined || output.htlcId === htlcId
		);
	const isSpent = (output: ITrackedOutput | undefined): boolean =>
		!!output &&
		[OutputStatus.SPEND_CONFIRMED, OutputStatus.IRREVOCABLY_RESOLVED].includes(
			output.status
		);
	/** Whether the spend of an HTLC output shows the preimage of a hash. */
	const showsPreimage = (
		pair: IAssetChainPair,
		output: ITrackedOutput,
		paymentHash: Buffer
	): boolean => {
		const spend = pair.chain.confirmed.get(output.resolutionTxid ?? '');
		const input = spend?.tx.ins.find(
			(i) =>
				Buffer.from(i.hash).reverse().toString('hex') === output.txid &&
				i.index === output.outputIndex
		);
		return (
			input?.witness.some(
				(el) =>
					el.length === 32 &&
					crypto.createHash('sha256').update(el).digest().equals(paymentHash)
			) === true
		);
	};

	it('claims an HTLC it settled in the channel when the payer answers with its revocation and never signs the HTLC out of the commitment: the decision is read for the HTLC among the kept removals', async () => {
		const pair = await opened('aux-decision-kept');
		const { alice, bob, chain, channelId } = pair;
		const held = await holdUnits(pair, 5000n, 'kept removal');

		// From the settle on Bob hears Alice's revoke_and_ack and nothing
		// after it: she does not sign his next commitment.
		let cut = false;
		gateMessages(pair, 'alice', (type) => {
			if (type === COMMITMENT_SIGNED) cut = true;
			return cut;
		});
		expect(bob.node.settleHeldHtlc(held.paymentHash, held.preimage)).to.equal(
			true
		);
		await settle();
		expect(cut).to.equal(true);
		expect(alice.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(bob.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		const state = bob.node
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		expect(
			[...state.htlcs.values()].filter((e) =>
				e.paymentHash.equals(held.paymentHash)
			)
		).to.have.length(0);
		expect(
			(state.signedLocalRemovals ?? []).filter((e) =>
				e.paymentHash.equals(held.paymentHash)
			)
		).to.have.length(1);
		// The decision is with the channel, for the HTLC, wherever it sits.
		expect(decisionOf(bob, pair, 0n)).to.equal('settle');
		expect(outcomes.bob).to.deep.equal(['RECEIVED:fulfilled:5000']);

		// Bob closes by itself 18 blocks before the expiry.
		chain.advance(held.cltvExpiry - 19 - chain.height);
		await settle();
		expect(htlcOf(bob, pair), 'still open').to.equal(undefined);
		await world.mine(pair, 2);
		expect(
			bob.errors.filter((e) => e.includes('HTLC_CLAIM_FORCE_CLOSE'))
		).to.have.length(1);
		expect(htlcOf(bob, pair)!.outputType).to.equal(OutputType.RECEIVED_HTLC);

		// And claims: his transaction, with the preimage, in a block before
		// the expiry at which the payer could take the output back.
		for (let i = 0; i < 12 && !isSpent(htlcOf(bob, pair)); i++) {
			await world.mine(pair, 1);
		}
		const claimed = htlcOf(bob, pair)!;
		expect(isSpent(claimed), 'the HTLC output is spent').to.equal(true);
		expect(
			claimed.auxiliarySweepAttempts?.[claimed.resolutionTxid!],
			'by the transaction of the node itself'
		).to.not.equal(undefined);
		expect(showsPreimage(pair, claimed, held.paymentHash)).to.equal(true);
		expect(chain.confirmed.get(claimed.resolutionTxid!)!.height).to.be.below(
			held.cltvExpiry
		);

		chain.advance(IRREVOCABLE_DEPTH);
		await settle();
		await world.mine(pair, 2);
		// Told once, when the payer revoked; the chain adds nothing.
		expect(outcomes.bob).to.deep.equal(['RECEIVED:fulfilled:5000']);
		expect(outcomes.alice).to.deep.equal(['OFFERED:fulfilled:5000']);
		expect(bob.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	/**
	 * `payee` issues a plain invoice for `asked` units, `payer` offers
	 * `offered` units for it, the payee fails the HTLC back and the payer
	 * never hears the fail.
	 */
	const refusedHtlc = async (
		pair: IAssetChainPair,
		payer: 'alice' | 'bob',
		asked: bigint,
		offered: bigint
	): Promise<{ paymentHash: Buffer; cltvExpiry: number; htlcId: bigint }> => {
		const payee = pair[payer === 'alice' ? 'bob' : 'alice'];
		const invoice = payee.node.createInvoice({
			amountMsat: asked * 1000n,
			description: 'a plain invoice for units'
		});
		let cut = false;
		const gate = gateMessages(
			pair,
			payer === 'alice' ? 'bob' : 'alice',
			(type) => {
				if (type === UPDATE_FAIL_HTLC || type === UPDATE_FAIL_MALFORMED_HTLC) {
					cut = true;
				}
				return cut;
			}
		);
		pair[payer].node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(payee.node.getNodeId(), 'hex'),
						shortChannelId: Buffer.alloc(8, 9),
						amountToForwardMsat: offered * 1000n,
						outgoingCltvValue: pair.chain.height + 60
					}
				]
			},
			invoice.paymentHash,
			60,
			invoice.paymentSecret,
			undefined,
			undefined,
			undefined,
			undefined,
			{
				assetPayment: {
					channelId: pair.channelId,
					wireAmountMsat: 354_000n,
					customRecords: amountRecord(offered)
				}
			}
		);
		await settle();
		const entry = [
			...payee.node
				.getChannelManager()
				.getChannel(pair.channelId)!
				.getFullState()
				.htlcs.values()
		].find((e) => e.paymentHash.equals(invoice.paymentHash))!;
		expect(entry, 'the HTLC is in the channel').to.not.equal(undefined);
		// The payee decided to fail this HTLC: it is not what the invoice asks.
		expect(entry.state).to.equal(HtlcState.FAILED);
		expect(gate.kept.map((message) => message.type)).to.include(
			UPDATE_FAIL_HTLC
		);
		return {
			paymentHash: invoice.paymentHash,
			cltvExpiry: entry.cltvExpiry,
			htlcId: entry.id
		};
	};

	it('does not close the channel for an HTLC of a plain invoice it failed back, whose fail the peer never took: the stored preimage of the invoice is no decision', async () => {
		const pair = await opened('aux-decision-plain-close');
		const refused = await refusedHtlc(pair, 'alice', 5000n, 100n);
		expect(decisionOf(pair.bob, pair, refused.htlcId)).to.equal('fail');
		disconnect(pair);
		await settle();

		// Through the 18 blocks before the expiry at which the node closes
		// for an HTLC it has a claim on: it has none here, and keeps the
		// channel. Taking the HTLC back at the expiry is the payer's to do.
		pair.chain.advance(refused.cltvExpiry - 19 - pair.chain.height);
		await settle();
		await world.mine(pair, 18);
		expect(pair.chain.height).to.equal(refused.cltvExpiry - 1);
		expect(
			pair.bob.errors.filter((e) => e.includes('HTLC_CLAIM_FORCE_CLOSE'))
		).to.deep.equal([]);
		expect(htlcOf(pair.bob, pair), 'still open').to.equal(undefined);
	});

	it('does not claim, after a restart, an HTLC of 100 units it had failed back for an invoice of 500: the decision is read back with the channel and the payer takes the HTLC back', async () => {
		const tag = 'aux-decision-plain-restart';
		// Alice is the payee here: she is the host these tests can restart.
		const pair = await opened(tag);
		const refused = await refusedHtlc(pair, 'bob', 500n, 100n);
		expect(decisionOf(pair.alice, pair, refused.htlcId)).to.equal('fail');
		disconnect(pair);
		await settle();

		// The payer closes: its commitment carries the HTLC.
		const closed = pair.bob.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 3);
		const before = htlcOf(pair.alice, pair)!;
		expect(before.outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(before.sweepTxHex).to.equal(undefined);

		// The restart hands every stored preimage to the chain monitors,
		// the one of this invoice among them.
		await world.restartAlice(pair, tag, undefined, undefined, hooks.alice);
		expect(decisionOf(pair.alice, pair, refused.htlcId)).to.equal('fail');
		while (pair.chain.height < refused.cltvExpiry) {
			await world.mine(pair, 1);
			expect(
				htlcOf(pair.alice, pair)!.sweepTxHex,
				`height ${pair.chain.height}`
			).to.equal(undefined);
		}
		expect(pair.wallets.alice!.sent).to.have.length(0);
		for (let i = 0; i < 8 && !isSpent(htlcOf(pair.alice, pair)); i++) {
			await world.mine(pair, 1);
		}
		const taken = htlcOf(pair.alice, pair)!;
		expect(isSpent(taken), 'the payer took the HTLC back').to.equal(true);
		expect(taken.resolutionTxid).to.equal(
			htlcOf(pair.bob, pair)!.resolutionTxid
		);
		expect(showsPreimage(pair, taken, refused.paymentHash)).to.equal(false);
		expect(pair.wallets.alice!.sent).to.have.length(0);
	});

	it('does not claim an HTLC by a decision to settle another HTLC of the same payment hash: each HTLC has its own', async () => {
		const pair = await opened('aux-decision-other');
		const { alice, bob, channelId } = pair;
		const held = await holdUnits(pair, 5000n, 'another htlc');
		gateMessages(pair, 'alice', () => true);
		gateMessages(pair, 'bob', () => true);
		const closed = alice.node.forceCloseChannel(channelId, SWEEP_DESTINATION);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		expect(htlcOf(bob, pair)!.htlcId).to.equal(0n);

		// A decision to settle with the preimage of this very payment hash,
		// written for an HTLC with another id, and the preimage handed to
		// the monitors: by payment hash this would be a claim.
		const state = bob.node
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		state.auxiliaryState!.htlcDecisions = new Map([
			['7', { outcome: 'settle', preimage: held.preimage }]
		]);
		bob.node
			.getChannelManager()
			.recordPreimage(held.paymentHash, held.preimage);
		await settle();
		await world.mine(pair, 3);
		const kept = htlcOf(bob, pair)!;
		expect(kept.status).to.equal(OutputStatus.CONFIRMED);
		expect(kept.sweepTxHex).to.equal(undefined);
		expect(pair.wallets.bob!.sent).to.have.length(0);

		// The decision for the HTLC itself is what a claim is made by.
		bob.node.settleHeldHtlc(held.paymentHash, held.preimage);
		await settle();
		expect(decisionOf(bob, pair, 0n)).to.equal('settle');
		for (let i = 0; i < 12 && !isSpent(htlcOf(bob, pair)); i++) {
			await world.mine(pair, 1);
		}
		const claimed = htlcOf(bob, pair)!;
		expect(isSpent(claimed), 'the HTLC output is spent').to.equal(true);
		expect(showsPreimage(pair, claimed, held.paymentHash)).to.equal(true);
		expect(
			claimed.auxiliarySweepAttempts?.[claimed.resolutionTxid!]
		).to.not.equal(undefined);
	});

	it('writes and reads back both kinds of decision with the asset state, and refuses a malformed one', () => {
		const state: IChannelAuxiliaryState = {
			channelData: Buffer.from([0]),
			localBalance: 0n,
			remoteBalance: 0n,
			localCommitments: new Map(),
			remoteCommitments: new Map(),
			htlcDecisions: new Map<string, IAuxiliaryHtlcDecision>([
				['0', { outcome: 'settle', preimage: Buffer.alloc(32, 7) }],
				['12', { outcome: 'fail' }]
			])
		};
		const written = serializeAuxiliaryState(state);
		expect(written.htlcDecisions).to.deep.equal([
			['0', '07'.repeat(32)],
			['12', '']
		]);
		const read = deserializeAuxiliaryState(JSON.parse(JSON.stringify(written)));
		expect(read.htlcDecisions).to.deep.equal(state.htlcDecisions);
		expect(serializeAuxiliaryState(read)).to.deep.equal(written);
		for (const malformed of [
			[['x', '']],
			[['0', 'zz']],
			[['0', '07'.repeat(31)]],
			[
				['0', ''],
				['0', '']
			]
		]) {
			expect(
				() =>
					deserializeAuxiliaryState({
						...written,
						htlcDecisions: malformed as [string, string][]
					}),
				JSON.stringify(malformed)
			).to.throw();
		}
	});
});
