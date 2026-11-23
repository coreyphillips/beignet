/**
 * The released 0.45.0 over the database of a payee that took a plain HTLC
 * on an asset channel, and this build over the database 0.45.0 wrote of
 * one.
 *
 * Carol is the payee and Bob her peer, with an asset channel between them
 * and, where a case needs it, an ordinary channel beside it. Bob pays an
 * ordinary invoice of Carol's with an HTLC that carries no units on the
 * asset channel: an add of his channel manager, his channel asked for no
 * asset side, as a peer whose forwarding picks the asset channel offers
 * one. Carol's host values such an HTLC at the bitcoin it carries.
 *
 * Carol is stopped, and the published LightningNode of 0.45.0 is started
 * over her database, on the same chain, with this tree's reference provider
 * and the hooks she had; or this build is started over a database 0.45.0
 * wrote. What each reads:
 * - 0.45.0 reads the funded HTLC-success transactions this build recorded
 *   for a plain HTLC on Carol's own commitment, knows the first of them as
 *   its own when that one confirms, and sweeps the output it made;
 * - 0.45.0 reads a payment this build settled with a plain part on the
 *   asset channel as completed;
 * - this build reads a completed payment 0.45.0 wrote whose part on the
 *   asset channel was not fulfilled: it sends that fulfil on the
 *   reestablish, and when the channel cannot take it, writes the part's
 *   decision to settle, by which a close claims it on the chain.
 *
 * The released build is not a dependency of this repository. The suite runs
 * when BEIGNET_RELEASED_0_45_0 names an installed copy of it, and is skipped
 * without it:
 *
 *   npm install --prefix "$DIR" beignet@0.45.0
 *   BEIGNET_RELEASED_0_45_0="$DIR/node_modules/beignet" \
 *     npx mocha -r ts-node/register tests/lightning/auxiliary-plain-htlc-downgrade.test.ts
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import { OutputStatus } from '../../src/lightning/chain/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	forwardChainWorld,
	type IForwardWorld,
	type IForwardWorldOptions
} from './helpers/auxiliary-forward-world';
import { rounds } from './helpers/auxiliary-forward-scene';
import {
	turns,
	withAssetOpens,
	type IAssetHost,
	type IEngineBuild
} from './helpers/auxiliary-nodes';
import { SWEEP_DESTINATION, errorsOf } from './helpers/auxiliary-on-chain';
import {
	UPDATE_FULFILL_HTLC,
	collected,
	decisionOf,
	endsOf,
	receivedEntries,
	refusing,
	unitsOf,
	wireWatch
} from './helpers/auxiliary-parts-checks';
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

const RELEASED = process.env.BEIGNET_RELEASED_0_45_0;

/** The released build's node and storage, as its dist has them. */
const released = (): IEngineBuild => {
	const from = (file: string): Record<string, unknown> =>
		// eslint-disable-next-line @typescript-eslint/no-var-requires
		require(path.join(RELEASED as string, 'dist', 'lightning', file));
	return {
		LightningNode: from('node/lightning-node.js')
			.LightningNode as IEngineBuild['LightningNode'],
		SqliteStorage: from('storage/sqlite-storage.js')
			.SqliteStorage as IEngineBuild['SqliteStorage']
	};
};

/** A record with the keys that hold nothing left out, as storage gives it back. */
const plain = (record: object): Record<string, unknown> =>
	Object.fromEntries(
		Object.entries(record).filter(([, value]) => value !== undefined)
	);

/** What Bob pays Carol in each case, in millisatoshis: whole, or as two parts. */
const PAID_MSAT = 50_000_000n;
const ORDINARY_PART_MSAT = 3_000_000n;
const PLAIN_PART_MSAT = 2_000_000n;
const SET_MSAT = ORDINARY_PART_MSAT + PLAIN_PART_MSAT;

describe('the released 0.45.0 and a plain HTLC on an asset channel, each build over the database of the other', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	before(function () {
		if (!RELEASED) this.skip();
		const manifest = JSON.parse(
			fs.readFileSync(path.join(RELEASED as string, 'package.json'), 'utf8')
		) as { name: string; version: string };
		expect([manifest.name, manifest.version]).to.deep.equal([
			'beignet',
			'0.45.0'
		]);
	});

	/**
	 * Bob and Carol with an asset channel Bob opened (the outgoing link of
	 * the world), an ordinary channel beside it with `ordinaryBeside`, and
	 * Alice with an ordinary channel to Bob that no case uses. Carol runs
	 * from a database file; Bob and Carol each have a fee wallet with two
	 * coins in a block.
	 */
	const open = async (
		tag: string,
		options: { ordinaryBeside?: boolean } & Partial<IForwardWorldOptions> = {}
	): Promise<IForwardWorld> => {
		const { ordinaryBeside, ...rest } = options;
		const w = await world.open(tag, {
			kinds: { in: 'ordinary', out: 'asset' },
			carolOnFile: true,
			feeWallet: { bob: true, carol: true },
			hooks: { carol: { valueIncomingHtlc: valuePlainHtlc } },
			...(ordinaryBeside ? { secondOut: 'ordinary' as const } : {}),
			...rest
		});
		for (const name of ['bob', 'carol'] as const) {
			for (let i = 0; i < 2; i++) w.wallets[name]!.fund(100_000);
		}
		await world.mine(w, 1);
		return w;
	};

	/** Stop Carol and start her again on `build`, or on this build when it is left out. */
	const restartOn = async (
		w: IForwardWorld,
		tag: string,
		build: IEngineBuild | undefined,
		options: { reconnect?: boolean; whileDown?: () => void } = {}
	): Promise<void> => {
		await world.restartCarol(w, tag, {
			...(build ? { build } : {}),
			...(options.whileDown ? { whileDown: options.whileDown } : {}),
			reconnect: options.reconnect !== false
		});
		if (build) {
			expect(
				w.hosts.carol.node,
				'Carol runs the released build'
			).to.be.instanceOf(build.LightningNode);
		}
	};

	/** Bob's HTLCs to Carol for a hash that are in one of his channels. */
	const offeredBy = (
		w: IForwardWorld,
		channelId: Buffer,
		paymentHash: Buffer
	): number =>
		[
			...(w.hosts.bob.node
				.getChannelManager()
				.getChannel(channelId)
				?.getFullState().htlcs ?? new Map())
		].filter(
			([key, entry]) =>
				key.startsWith('offered-') && entry.paymentHash.equals(paymentHash)
		).length;

	const until = async (
		what: string,
		w: IForwardWorld,
		reached: () => boolean,
		most = 40
	): Promise<void> => {
		for (let i = 0; i < most && !reached(); i++) await world.mine(w, 1);
		if (!reached()) {
			throw new Error(
				`never reached: ${what}; carol: ${errorsOf(w.hosts.carol).join(
					' | '
				)}; refused: ${JSON.stringify(w.backends.carol.refused)}`
			);
		}
	};
	/** Where Carol's sweeps go: the script her close was given, or her node's own. */
	const paysCarol = (host: IAssetHost, script: Buffer): boolean =>
		[SWEEP_DESTINATION, host.node.getSweepDestinationScript()].some((own) =>
			own.equals(script)
		);

	it('reads the two funded HTLC-success transactions this build recorded for a plain HTLC on its own commitment: when the first of them confirms, 0.45.0 knows it as its own by the recorded attempt and sweeps the output it made after the delay', async () => {
		const tag = 'plain-downgrade-attempts';
		const w = await open(tag);
		const { carol, bob } = w.hosts;
		const { preimage, paymentHash } = preimageOf(tag);
		const invoice = carol.node.createInvoice({
			amountMsat: PAID_MSAT,
			description: `plain ${tag}`,
			hold: true,
			paymentHash
		});
		offerPlainHtlc(bob, carol, w.outChannel, {
			amountMsat: PAID_MSAT,
			paymentHash,
			paymentSecret: invoice.paymentSecret,
			cltvExpiry: w.chain.height + 80
		});
		await turns(80);
		expect(
			parkedOf(carol, paymentHash),
			`Carol holds the plain HTLC: ${errorsOf(carol).join('; ')}`
		).to.equal(1);
		const [held] = receivedEntries(carol, w.outChannel, paymentHash);

		// Bob is away: the settle binds though no fulfil can leave, and Carol
		// closes the asset channel by force.
		world.cut(w, 'out');
		expect(carol.node.settleHeldHtlc(paymentHash, preimage)).to.equal(false);
		await turns(40);
		expect(decisionOf(carol, w.outChannel, held.id)).to.equal('settle');
		const closed = carol.node.forceCloseChannel(
			w.outChannel,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await turns(40);
		const output = receivedHtlcOutput(carol, w.outChannel)!;
		expect(output.auxiliaryCommitmentNumber).to.equal(undefined);
		const outpoint = { txid: output.txid, outputIndex: output.outputIndex };
		const { kept: sent, publish } = withholdSpends(w.chain, outpoint);
		await until(
			'two funded HTLC-success transactions',
			w,
			() => sent.length >= 2,
			24
		);
		const [first, second] = sent.map((hex) => bitcoin.Transaction.fromHex(hex));
		expect(second.getId()).to.not.equal(first.getId());
		for (const tx of [first, second]) {
			expect(tx.ins.length, 'each with its fee input').to.be.greaterThan(1);
		}
		expect(
			Object.keys(
				receivedHtlcOutput(carol, w.outChannel)!.auxiliarySweepAttempts ?? {}
			),
			'this build records each funded HTLC-success of the output'
		).to.include.members([first.getId(), second.getId()]);

		await restartOn(w, tag, released(), { reconnect: false });
		await turns(40);
		const restored = receivedHtlcOutput(w.hosts.carol, w.outChannel);
		expect(restored, '0.45.0 reads the monitor of the channel').to.not.equal(
			undefined
		);
		expect(restored!.status).to.not.equal(OutputStatus.SPEND_CONFIRMED);

		publish(sent[0]);
		await world.mine(w, 1);
		const spent = receivedHtlcOutput(w.hosts.carol, w.outChannel)!;
		expect(spent.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		expect(spent.resolutionTxid).to.equal(first.getId());
		const delayed = secondLevelOutput(w.hosts.carol, w.outChannel);
		expect(
			delayed,
			'0.45.0 tracks the output of the first funded HTLC-success'
		).to.not.equal(undefined);
		expect(delayed!.txid).to.equal(first.getId());
		expect(delayed!.amount).to.equal(PAID_MSAT / 1000n);
		const maturity =
			w.chain.confirmed.get(first.getId())!.height +
			w.hosts.carol.node
				.getChannelManager()
				.getChannel(w.outChannel)!
				.getFullState().remoteConfig.toSelfDelay;
		await world.passTo(w, maturity - 1);
		expect(w.chain.spender(first.getId(), 0)).to.equal(undefined);
		await until(
			'the sweep of the delayed output in a block',
			w,
			() => isSpent(secondLevelOutput(w.hosts.carol, w.outChannel)),
			12
		);
		const swept = secondLevelOutput(w.hosts.carol, w.outChannel)!;
		const sweep = w.chain.confirmed.get(swept.resolutionTxid!)!;
		expect(sweep.height).to.be.at.least(maturity);
		expect(sweep.tx.ins.length, 'the sweep pays its own fee').to.equal(1);
		expect(sweep.tx.outs.length).to.equal(1);
		expect(paysCarol(w.hosts.carol, sweep.tx.outs[0].script)).to.equal(true);
		expect(sweep.tx.outs[0].value + feeOf(w.chain, sweep.tx)).to.equal(
			Number(PAID_MSAT / 1000n)
		);
	});

	it('reads a payment this build settled with an ordinary part and a plain part on the asset channel as completed, as this build wrote it', async () => {
		const tag = 'plain-downgrade-set';
		const w = await open(tag, { ordinaryBeside: true });
		const { carol, bob } = w.hosts;
		const invoice = carol.node.createInvoice({
			amountMsat: SET_MSAT,
			description: `plain ${tag}`
		});
		const part = {
			paymentHash: invoice.paymentHash,
			paymentSecret: invoice.paymentSecret,
			cltvExpiry: w.chain.height + 80,
			totalMsat: SET_MSAT
		};
		// The ordinary part first, then the plain part on the asset channel.
		offerPlainHtlc(bob, carol, w.outChannel2!, {
			...part,
			amountMsat: ORDINARY_PART_MSAT
		});
		await turns(80);
		expect(collected(carol, invoice.paymentHash)).to.equal(1);
		offerPlainHtlc(bob, carol, w.outChannel, {
			...part,
			amountMsat: PLAIN_PART_MSAT
		});
		await rounds(
			'both parts fulfilled on the channels of the peer',
			() =>
				offeredBy(w, w.outChannel, invoice.paymentHash) === 0 &&
				offeredBy(w, w.outChannel2!, invoice.paymentHash) === 0
		);
		const record = carol.node.getPayment(invoice.paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.COMPLETED);
		expect(record.settledHtlcs).to.have.length(2);
		expect(record.auxiliary).to.equal(undefined);
		const written = plain(record);

		await restartOn(w, tag, released());
		const read = w.hosts.carol.node.getPayment(invoice.paymentHash);
		expect(read, '0.45.0 has the payment').to.not.equal(null);
		expect(read!.status).to.equal(PaymentStatus.COMPLETED);
		expect(plain(read!)).to.deep.equal(written);
		// On the reestablish nothing of the set is asked again.
		await turns(80);
		expect(
			receivedEntries(w.hosts.carol, w.outChannel, invoice.paymentHash)
		).to.deep.equal([]);
		expect(w.hosts.carol.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	describe('a completed payment 0.45.0 wrote, whose plain part on the asset channel it did not fulfil', () => {
		/**
		 * Carol runs 0.45.0 from the open on. Bob pays an ordinary invoice of
		 * hers in two parts: the plain part on the asset channel, then, with
		 * Carol's provider refusing every commitment of the asset channel,
		 * the ordinary part, which completes the set. 0.45.0 records the
		 * payment completed, both parts settled, and fulfils the ordinary
		 * part; the fulfil of the plain part is refused, and no decision to
		 * settle it is written.
		 */
		const writtenByRelease = async (
			tag: string
		): Promise<{
			w: IForwardWorld;
			arm: { down: boolean };
			paymentHash: Buffer;
			plainId: bigint;
			cltvExpiry: number;
		}> => {
			const arm = { down: false };
			const w = await open(tag, {
				ordinaryBeside: true,
				wrapProvider: { carol: refusing(arm) }
			});
			await restartOn(w, tag, released());
			const carol = w.hosts.carol;
			const invoice = carol.node.createInvoice({
				amountMsat: SET_MSAT,
				description: `plain ${tag}`
			});
			const cltvExpiry = w.chain.height + 60;
			const part = {
				paymentHash: invoice.paymentHash,
				paymentSecret: invoice.paymentSecret,
				cltvExpiry,
				totalMsat: SET_MSAT
			};
			offerPlainHtlc(w.hosts.bob, carol, w.outChannel, {
				...part,
				amountMsat: PLAIN_PART_MSAT
			});
			await rounds(
				'0.45.0 collects the plain part',
				() => collected(carol, invoice.paymentHash) === 1
			);
			const [plainPart] = receivedEntries(
				carol,
				w.outChannel,
				invoice.paymentHash
			);
			arm.down = true;
			offerPlainHtlc(w.hosts.bob, carol, w.outChannel2!, {
				...part,
				amountMsat: ORDINARY_PART_MSAT
			});
			await rounds(
				'0.45.0 completes the payment',
				() =>
					carol.node.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.COMPLETED
			);
			await turns(80);
			const record = carol.node.getPayment(invoice.paymentHash)!;
			expect(record.settledHtlcs).to.have.length(2);
			expect(
				offeredBy(w, w.outChannel2!, invoice.paymentHash),
				'the ordinary part is fulfilled'
			).to.equal(0);
			expect(
				receivedEntries(carol, w.outChannel, invoice.paymentHash).map(
					(entry) => entry.id
				),
				'the plain part is not fulfilled'
			).to.deep.equal([plainPart.id]);
			expect(decisionOf(carol, w.outChannel, plainPart.id)).to.equal(undefined);
			return {
				w,
				arm,
				paymentHash: invoice.paymentHash,
				plainId: plainPart.id,
				cltvExpiry
			};
		};

		it('this build sends the fulfil of the plain part on the reestablish, and the channel of the peer takes it', async () => {
			const tag = 'plain-upgrade-resend';
			const r = await writtenByRelease(tag);
			const { w } = r;
			const held = w.hosts.carol.node.getChannel(
				w.outChannel
			)!.localBalanceMsat;
			await restartOn(w, tag, undefined, {
				reconnect: false,
				whileDown: () => {
					r.arm.down = false;
				}
			});
			const sent = wireWatch(w.hosts.carol);
			await world.reconnect(w, 'out');
			await rounds(
				'the channel of the peer takes the fulfil',
				() => offeredBy(w, w.outChannel, r.paymentHash) === 0
			);
			expect(endsOf(sent, w.outChannel, r.plainId)).to.deep.equal([
				UPDATE_FULFILL_HTLC
			]);
			expect(
				receivedEntries(w.hosts.carol, w.outChannel, r.paymentHash)
			).to.deep.equal([]);
			expect(
				w.hosts.carol.node.getChannel(w.outChannel)!.localBalanceMsat - held
			).to.equal(PLAIN_PART_MSAT);
			// Units on both sides as they were: Bob opened with 9000, Carol 1000.
			expect(unitsOf(w.hosts.carol, w.outChannel)).to.equal(1000n);
			expect(unitsOf(w.hosts.bob, w.outChannel)).to.equal(9000n);
			expect(w.hosts.carol.node.getPayment(r.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('when the asset channel cannot take the fulfil on the reestablish, this build writes the decision to settle the plain part: a close as its expiry nears claims it on the chain', async () => {
			const tag = 'plain-upgrade-claim';
			const r = await writtenByRelease(tag);
			const { w } = r;
			// The provider of this build refuses as 0.45.0's did.
			await restartOn(w, tag, undefined, { reconnect: false });
			const sent = wireWatch(w.hosts.carol);
			await world.reconnect(w, 'out');
			await turns(80);
			expect(
				endsOf(sent, w.outChannel, r.plainId),
				'no fulfil leaves'
			).to.deep.equal([]);
			expect(
				decisionOf(w.hosts.carol, w.outChannel, r.plainId),
				'the decision to settle the part is written'
			).to.equal('settle');

			// No close while the expiry is far.
			await world.passTo(w, r.cltvExpiry - 30);
			expect(
				w.hosts.carol.node.getChannel(w.outChannel)?.state,
				'the channel is open while the expiry is far'
			).to.equal(ChannelState.NORMAL);
			await until(
				'the claim of the plain part in a block',
				w,
				() => {
					const output = receivedHtlcOutput(w.hosts.carol, w.outChannel);
					if (!isSpent(output)) return false;
					const spend = w.chain.confirmed.get(output!.resolutionTxid!);
					return (
						!!spend &&
						spend.tx.ins.some((input) =>
							input.witness.some(
								(element) =>
									element.length === 32 &&
									bitcoin.crypto.sha256(element).equals(r.paymentHash)
							)
						)
					);
				},
				30
			);
			const claimed = receivedHtlcOutput(w.hosts.carol, w.outChannel)!;
			expect(claimed.htlcId).to.equal(r.plainId);
			expect(
				w.chain.confirmed.get(claimed.resolutionTxid!)!.height
			).to.be.lessThan(r.cltvExpiry);
			expect(w.hosts.carol.node.getPayment(r.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(
				endsOf(sent, w.outChannel, r.plainId),
				'nothing ended the part off the chain: no fulfil, no fail'
			).to.deep.equal([]);
		});
	});
});
