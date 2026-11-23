/**
 * A plain HTLC on an asset channel, settled on the node's own commitment.
 *
 * The node is the payee of an ordinary hold invoice, and its peer pays it
 * with an HTLC that carries no units on their asset channel, as a peer
 * whose forwarding picks the asset channel for an ordinary payment does.
 * The host values that HTLC at the bitcoin it carries. The node settles the
 * hold while the peer is away, so that its decision to settle is written
 * and no fulfil can leave, and closes the channel by force: its own
 * commitment goes to the chain with the HTLC on it.
 *
 * There the HTLC is claimed by the HTLC-success transaction the peer
 * signed for, which keeps the output the peer signed and takes its whole
 * fee from inputs of the fee pool. A fee raise asks the pool again, and
 * each funded transaction is a spend of the node's own, whichever of them
 * confirms: the node tracks the output it made, which waits out the delay
 * and is swept then as an ordinary second-level output is, paying its own
 * fee. A sweep of that output declined as uneconomic is made once the fee
 * rate allows it, and one that is not in a block has its fee raised.
 *
 * Each case runs on the overlay type alone and on the fixed type (feature
 * bit 450), with the node on a SQLite file. In each, every spend either
 * node made pays the rate it was first asked at for the size it has, the
 * chain refused nothing of the node's, and no HTLC-success left the node
 * without its fee input.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import { OutputStatus } from '../../src/lightning/chain/types';
import { isFixedAssetHtlcChannel } from '../../src/lightning/channel/types';
import { withAssetOpens } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	disconnect,
	errorsOf,
	settle,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';
import { decisionOf, receivedEntries } from './helpers/auxiliary-parts-checks';
import {
	feeOf,
	isSpent,
	offerPlainHtlc,
	parkedOf,
	preimageOf,
	receivedHtlcOutput,
	secondLevelOutput,
	valuePlainHtlc,
	withholdSpends
} from './helpers/auxiliary-plain-htlc-chain';

/** The two kinds of asset channel: the overlay alone, and the fixed type. */
const TYPES = [
	{ name: 'the overlay alone', tag: 'overlay', fixed: false },
	{ name: 'the fixed type (bit 450)', tag: 'fixed', fixed: true }
] as const;
type ChannelKind = (typeof TYPES)[number];

/** What the peer pays with its plain HTLC, in satoshis. */
const PAID_SAT = 50_000;
/**
 * A payment whose second-level output is worth less than its own sweep at
 * HIGH_RATE, and worth sweeping at LOW_RATE (sat/vB).
 */
const SMALL_SAT = 8_000;
const HIGH_RATE = 100;
const LOW_RATE = 2;

/** One plain HTLC the node settled, on its own commitment in the chain's view. */
interface IOwnClose {
	pair: IAssetChainPair;
	tag: string;
	kind: ChannelKind;
	amountSat: number;
	cltvExpiry: number;
	/** Every transaction the node sent to spend the HTLC output, kept from the chain. */
	sent: string[];
	/** Hand a kept transaction to the chain. */
	publish: (hex: string) => void;
}

describe("a plain HTLC on an asset channel, settled on the node's own commitment", function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(function () {
		// Every spend either node made in a test that passed paid the rate
		// its output was first given a spend at, for the size it really
		// has, and none was refused as below the relay floor.
		const underpaid =
			this.currentTest?.state === 'passed' ? world.underpaid() : [];
		world.dispose();
		expect(underpaid).to.deep.equal([]);
	});

	const hooksOf = (
		kind: ChannelKind
	): NonNullable<Parameters<typeof world.open>[1]>['hooks'] => {
		// The fixed type: each node reads the features the other advertises,
		// and neither host allows the HTLC signatures of a channel without
		// bit 450.
		const fixed = kind.fixed ? { allowLegacyHtlcSignatures: undefined } : {};
		return {
			alice: { valueIncomingHtlc: valuePlainHtlc, ...fixed },
			bob: { ...fixed }
		};
	};

	const until = async (
		what: string,
		pair: IAssetChainPair,
		reached: () => boolean,
		most = 40
	): Promise<void> => {
		for (let i = 0; i < most && !reached(); i++) await world.mine(pair, 1);
		if (!reached()) {
			throw new Error(
				`never reached: ${what}; alice: ${errorsOf(pair.alice).join(
					' | '
				)}; refused: ${JSON.stringify(pair.backends.alice.refused)}`
			);
		}
	};
	/** Let blocks pass up to a height, the nodes hearing only of the last. */
	const passTo = async (
		pair: IAssetChainPair,
		height: number
	): Promise<void> => {
		if (pair.chain.height < height) {
			pair.chain.advance(height - pair.chain.height);
			await settle();
		}
	};
	const confirmed = (
		pair: IAssetChainPair,
		txid: string | undefined
	): { tx: bitcoin.Transaction; height: number } => {
		const entry = txid ? pair.chain.confirmed.get(txid) : undefined;
		if (!entry) throw new Error(`transaction ${txid} is not in a block`);
		return entry;
	};
	const delayOf = (pair: IAssetChainPair): number =>
		pair.alice.node
			.getChannelManager()
			.getChannel(pair.channelId)!
			.getFullState().remoteConfig.toSelfDelay;
	/** The fee rate the node's monitors price its spends at, as its estimator gives it. */
	const estimate = (pair: IAssetChainPair, satPerVbyte: number): void => {
		pair.alice.node
			.getChannelManager()
			.updateMonitorFeeRates(satPerVbyte * 250, [
				pair.channelId.toString('hex')
			]);
	};

	/**
	 * Open the pair, have the peer pay a hold invoice of the node with a
	 * plain HTLC on the asset channel, settle the hold while the peer is
	 * away and close by force. From then on what the node sends to spend
	 * the HTLC output is kept from the chain.
	 */
	const settledOnOwnCommitment = async (
		tag: string,
		kind: ChannelKind,
		amountSat = PAID_SAT
	): Promise<IOwnClose> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			...(kind.fixed ? { realInit: true } : {}),
			hooks: hooksOf(kind)
		});
		expect(
			isFixedAssetHtlcChannel(
				pair.alice.node
					.getChannelManager()
					.getChannel(pair.channelId)!
					.getFullState().channelType
			),
			'the type of the asset channel'
		).to.equal(kind.fixed);
		// Two coins each: the child that pays for a commitment takes one.
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);

		const { preimage, paymentHash } = preimageOf(tag);
		const amountMsat = BigInt(amountSat) * 1000n;
		const invoice = pair.alice.node.createInvoice({
			amountMsat,
			description: `plain ${tag}`,
			hold: true,
			paymentHash
		});
		const cltvExpiry = pair.chain.height + 80;
		offerPlainHtlc(pair.bob, pair.alice, pair.channelId, {
			amountMsat,
			paymentHash,
			paymentSecret: invoice.paymentSecret,
			cltvExpiry
		});
		await settle();
		expect(
			parkedOf(pair.alice, paymentHash),
			`the node holds the plain HTLC: ${errorsOf(pair.alice).join('; ')}`
		).to.equal(1);
		const [held] = receivedEntries(pair.alice, pair.channelId, paymentHash);
		expect(held.amountMsat).to.equal(amountMsat);
		expect(held.auxiliaryAmount, 'the HTLC carries no units').to.equal(
			undefined
		);

		// The peer is away: the settle binds though no fulfil can leave, and
		// the decision to settle is written for the HTLC.
		disconnect(pair);
		expect(pair.alice.node.settleHeldHtlc(paymentHash, preimage)).to.equal(
			false
		);
		await settle();
		expect(decisionOf(pair.alice, pair.channelId, held.id)).to.equal('settle');

		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		const output = receivedHtlcOutput(pair.alice, pair.channelId)!;
		expect(output.amount).to.equal(BigInt(amountSat));
		expect(output.htlcId).to.equal(held.id);
		expect(
			output.auxiliaryCommitmentNumber,
			'an output without units'
		).to.equal(undefined);
		const { kept, publish } = withholdSpends(pair.chain, output);
		return {
			pair,
			tag,
			kind,
			amountSat,
			cltvExpiry,
			sent: kept,
			publish
		};
	};

	/** Stop the node and start it again from its database, with the hooks it had. */
	const restart = async (s: IOwnClose): Promise<void> => {
		await world.restartAlice(
			s.pair,
			s.tag,
			undefined,
			undefined,
			hooksOf(s.kind)!.alice
		);
	};

	/** The node's HTLC-success transactions, as it sent them. */
	const successes = (s: IOwnClose): bitcoin.Transaction[] =>
		s.sent.map((hex) => bitcoin.Transaction.fromHex(hex));

	/** Every HTLC-success the node sent took its fee from inputs of the fee pool. */
	const expectEachFunded = (s: IOwnClose): void => {
		expect(s.sent.length).to.be.greaterThan(0);
		for (const tx of successes(s)) {
			expect(
				tx.ins.length,
				`the HTLC-success ${tx.getId()} has its fee input`
			).to.be.greaterThan(1);
			expect(
				tx.outs.map((out) => out.value),
				'the one output the peer signed for'
			).to.deep.equal([s.amountSat]);
		}
	};

	/** The node sent two funded HTLC-success transactions, the second at a raised fee. */
	const twoFunded = async (
		s: IOwnClose
	): Promise<[bitcoin.Transaction, bitcoin.Transaction]> => {
		await until(
			'a second funded HTLC-success',
			s.pair,
			() => s.sent.length >= 2,
			24
		);
		const [first, second] = successes(s);
		expect(second.getId()).to.not.equal(first.getId());
		expect(feeOf(s.pair.chain, second)).to.be.greaterThan(
			feeOf(s.pair.chain, first)
		);
		expectEachFunded(s);
		return [first, second];
	};

	/** An HTLC-success of the node's is in a block, and it knows it as its own. */
	const expectOwnSecondLevel = (
		s: IOwnClose,
		success: bitcoin.Transaction
	): { maturity: number } => {
		const spent = receivedHtlcOutput(s.pair.alice, s.pair.channelId)!;
		expect(spent.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		expect(spent.resolutionTxid).to.equal(success.getId());
		const at = confirmed(s.pair, success.getId()).height;
		expect(at).to.be.lessThan(s.cltvExpiry);
		const delayed = secondLevelOutput(s.pair.alice, s.pair.channelId);
		expect(
			delayed,
			'the node tracks the output its HTLC-success made'
		).to.not.equal(undefined);
		expect(delayed!.txid).to.equal(success.getId());
		expect(delayed!.outputIndex).to.equal(0);
		expect(delayed!.amount).to.equal(BigInt(s.amountSat));
		return { maturity: at + delayOf(s.pair) };
	};

	/**
	 * Where the node's sweeps go: the script its close was given, or, from
	 * a restart on, the sweep destination of the node.
	 */
	const paysTheNode = (s: IOwnClose, script: Buffer): boolean =>
		[SWEEP_DESTINATION, s.pair.alice.node.getSweepDestinationScript()].some(
			(own) => own.equals(script)
		);

	/**
	 * The delayed output of an HTLC-success of the node's is swept once the
	 * delay has passed, and not ahead of it: the sweep pays its own fee from
	 * the output and sends the rest where the node's sweeps go.
	 */
	const expectSweptAfterDelay = async (
		s: IOwnClose,
		success: bitcoin.Transaction,
		maturity: number
	): Promise<bitcoin.Transaction> => {
		await passTo(s.pair, maturity - 1);
		expect(
			s.pair.chain.spender(success.getId(), 0),
			'nothing spends the output ahead of its delay'
		).to.equal(undefined);
		await until(
			'the sweep of the delayed output in a block',
			s.pair,
			() => isSpent(secondLevelOutput(s.pair.alice, s.pair.channelId)),
			12
		);
		const swept = secondLevelOutput(s.pair.alice, s.pair.channelId)!;
		const sweep = confirmed(s.pair, swept.resolutionTxid);
		expect(sweep.height).to.be.at.least(maturity);
		expect(sweep.tx.ins.length).to.equal(1);
		expect(
			Buffer.from(sweep.tx.ins[0].hash).reverse().toString('hex')
		).to.equal(success.getId());
		expect(sweep.tx.outs.length).to.equal(1);
		expect(
			paysTheNode(s, sweep.tx.outs[0].script),
			'the sweep pays a script of the node'
		).to.equal(true);
		expect(sweep.tx.outs[0].value + feeOf(s.pair.chain, sweep.tx)).to.equal(
			s.amountSat
		);
		expect(s.pair.backends.alice.refused).to.deep.equal([]);
		expectEachFunded(s);
		return sweep.tx;
	};

	/**
	 * The node's one funded HTLC-success confirms while fees are high: the
	 * node tracks the output it made, and declines its sweep as uneconomic,
	 * since it would pay more than the output holds.
	 */
	const declinedAtHighRate = async (
		s: IOwnClose
	): Promise<{ success: bitcoin.Transaction; maturity: number }> => {
		const declined: Array<{ txid: string; feeRatePerVbyte: number }> = [];
		s.pair.alice.node
			.getChannelManager()
			.on(
				'sweep:uneconomic',
				(_id: Buffer, action: { txid: string; feeRatePerVbyte: number }) => {
					declined.push(action);
				}
			);
		await until('a funded HTLC-success', s.pair, () => s.sent.length >= 1, 6);
		const [success] = successes(s);
		estimate(s.pair, HIGH_RATE);
		s.publish(s.sent[0]);
		await world.mine(s.pair, 1);
		const { maturity } = expectOwnSecondLevel(s, success);
		expect(
			secondLevelOutput(s.pair.alice, s.pair.channelId)!.sweepTxHex,
			'no sweep at the high rate'
		).to.equal(undefined);
		expect(
			declined
				.filter((action) => action.txid === success.getId())
				.map((action) => action.feeRatePerVbyte),
			'the sweep is declined as uneconomic at the high rate'
		).to.deep.equal([HIGH_RATE]);
		return { success, maturity };
	};

	for (const kind of TYPES) {
		describe(`on ${kind.name}`, () => {
			it('keeps each funded HTLC-success as its own: when the first of two confirms, the node tracks the output it made and sweeps it after the delay', async () => {
				const s = await settledOnOwnCommitment(
					`plain-own-first-${kind.tag}`,
					kind
				);
				const [first] = await twoFunded(s);
				s.publish(s.sent[0]);
				await world.mine(s.pair, 1);
				const { maturity } = expectOwnSecondLevel(s, first);
				await expectSweptAfterDelay(s, first, maturity);
			});

			it('tracks the output of the latest funded HTLC-success when that one confirms, and sweeps it after the delay', async () => {
				const s = await settledOnOwnCommitment(
					`plain-own-latest-${kind.tag}`,
					kind
				);
				const [, second] = await twoFunded(s);
				s.publish(s.sent[1]);
				await world.mine(s.pair, 1);
				const { maturity } = expectOwnSecondLevel(s, second);
				await expectSweptAfterDelay(s, second, maturity);
			});

			it('makes the sweep of the delayed output once the fee rate falls, after declining it as uneconomic at a high rate, and the sweep confirms', async () => {
				const s = await settledOnOwnCommitment(
					`plain-own-uneconomic-${kind.tag}`,
					kind,
					SMALL_SAT
				);
				const { success, maturity } = await declinedAtHighRate(s);
				await world.mine(s.pair, 2);
				expect(
					secondLevelOutput(s.pair.alice, s.pair.channelId)!.sweepTxHex,
					'no sweep while the rate is high'
				).to.equal(undefined);

				// The rate falls: the sweep is made at it, held to the delay.
				estimate(s.pair, LOW_RATE);
				await world.mine(s.pair, 1);
				expect(
					secondLevelOutput(s.pair.alice, s.pair.channelId)!.sweepTxHex,
					'the sweep is made once the rate falls'
				).to.not.equal(undefined);
				await expectSweptAfterDelay(s, success, maturity);
			});

			it('raises the fee of the sweep of the delayed output when it is not in a block, and the raised sweep confirms', async () => {
				const s = await settledOnOwnCommitment(
					`plain-own-raise-${kind.tag}`,
					kind
				);
				await until(
					'a funded HTLC-success',
					s.pair,
					() => s.sent.length >= 1,
					6
				);
				const [success] = successes(s);
				s.publish(s.sent[0]);
				await world.mine(s.pair, 1);
				const { maturity } = expectOwnSecondLevel(s, success);
				// From here the chain is not told of what spends the delayed
				// output either.
				const sweeps = withholdSpends(s.pair.chain, {
					txid: success.getId(),
					outputIndex: 0
				});
				await passTo(s.pair, maturity - 1);
				await until(
					'the sweep of the delayed output sent',
					s.pair,
					() => sweeps.kept.length >= 1,
					4
				);
				await until(
					'a sweep of the delayed output at a raised fee',
					s.pair,
					() => sweeps.kept.length >= 2,
					24
				);
				const [first, raised] = sweeps.kept.map((hex) =>
					bitcoin.Transaction.fromHex(hex)
				);
				expect(raised.getId()).to.not.equal(first.getId());
				expect(feeOf(s.pair.chain, raised)).to.be.greaterThan(
					feeOf(s.pair.chain, first)
				);
				for (const tx of [first, raised]) {
					expect(tx.ins.length).to.equal(1);
					expect(paysTheNode(s, tx.outs[0].script)).to.equal(true);
				}
				sweeps.publish(sweeps.kept[1]);
				await world.mine(s.pair, 1);
				const swept = secondLevelOutput(s.pair.alice, s.pair.channelId)!;
				expect(swept.status).to.equal(OutputStatus.SPEND_CONFIRMED);
				expect(swept.resolutionTxid).to.equal(raised.getId());
				expect(s.pair.backends.alice.refused).to.deep.equal([]);
				expectEachFunded(s);
			});

			it('over SQLite, a restart between the two funded HTLC-success transactions: the first confirms, and the node tracks its output and sweeps it after the delay', async () => {
				const s = await settledOnOwnCommitment(
					`plain-own-restart-funded-${kind.tag}`,
					kind
				);
				await until(
					'a funded HTLC-success',
					s.pair,
					() => s.sent.length >= 1,
					6
				);
				await restart(s);
				const [first] = await twoFunded(s);
				s.publish(s.sent[0]);
				await world.mine(s.pair, 1);
				const { maturity } = expectOwnSecondLevel(s, first);
				await expectSweptAfterDelay(s, first, maturity);
			});

			it('over SQLite, a restart between the confirmation of the first of two funded HTLC-success transactions and the sweep: the sweep is made after the delay and confirms', async () => {
				const s = await settledOnOwnCommitment(
					`plain-own-restart-swept-${kind.tag}`,
					kind
				);
				const [first] = await twoFunded(s);
				s.publish(s.sent[0]);
				await world.mine(s.pair, 1);
				const { maturity } = expectOwnSecondLevel(s, first);
				await restart(s);
				expectOwnSecondLevel(s, first);
				await expectSweptAfterDelay(s, first, maturity);
			});

			it('over SQLite, a restart while the sweep of the delayed output is declined as uneconomic: at a rate that allows it the sweep is made, and it confirms', async () => {
				const s = await settledOnOwnCommitment(
					`plain-own-restart-declined-${kind.tag}`,
					kind,
					SMALL_SAT
				);
				const { success, maturity } = await declinedAtHighRate(s);
				await restart(s);
				expectOwnSecondLevel(s, success);
				estimate(s.pair, LOW_RATE);
				await world.mine(s.pair, 1);
				expect(
					secondLevelOutput(s.pair.alice, s.pair.channelId)!.sweepTxHex,
					'the sweep is made at a rate that allows it'
				).to.not.equal(undefined);
				await expectSweptAfterDelay(s, success, maturity);
			});
		});
	}
});
