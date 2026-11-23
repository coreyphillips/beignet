/**
 * A plain HTLC on an asset channel that goes on chain while it is part of
 * an ordinary payment: a hold invoice whose HTLC is parked, or a set in
 * parts with one part there.
 *
 * Carol is the wallet; Bob, her peer, offers her plain HTLCs over his
 * asset channel with her, and over his ordinary one. A hold settled on the
 * chain stays parked until the claim of its HTLC is 100 blocks deep, and
 * ends COMPLETED then, as an ordinary payment: no asset mark on its records
 * or on its hold:settled. An HTLC under the dust limit has no output and
 * ends with its commitment 100 deep, cancelled. A set whose asset-channel
 * part is on the chain when it completes reveals nothing.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import fs from 'fs';
import {
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import { HELD_HTLC_EXPIRY_MARGIN } from '../../src/lightning/node/config';
import { PaymentStatus } from '../../src/lightning/node/types';
import { forwardChainWorld } from './helpers/auxiliary-forward-world';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	errorsOf,
	trackedOutputs
} from './helpers/auxiliary-on-chain';
import {
	UPDATE_FAIL_HTLC,
	UPDATE_FULFILL_HTLC,
	bobHasOut,
	bobOffers,
	collectedOf,
	decisionOf,
	endsOfOffer,
	endsSent,
	hex,
	holdEventsOf,
	logsOf,
	monitorsKnow,
	openPlainWorld,
	parkedOf,
	sha256,
	until,
	type IPlainOffer,
	type IPlainWorld,
	type Log
} from './helpers/auxiliary-plain-scene';

describe('a plain HTLC on an asset channel that is on the chain, in a hold or a set', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = forwardChainWorld();
	const files: string[] = [];
	afterEach(() => {
		world.dispose();
		for (const file of files.splice(0)) fs.rmSync(file, { force: true });
	});

	/** Carol's first-level output of an HTLC she received on a channel. */
	const outputOf = (
		host: IAssetHost,
		channelId: Buffer,
		offer: IPlainOffer
	): ITrackedOutput | undefined =>
		trackedOutputs(host, channelId).find(
			(output) =>
				!output.isSecondLevelHtlc &&
				output.outputType === OutputType.RECEIVED_HTLC &&
				output.htlcId === offer.htlcId
		);
	const spent = (output: ITrackedOutput | undefined): boolean =>
		!!output &&
		[OutputStatus.SPEND_CONFIRMED, OutputStatus.IRREVOCABLY_RESOLVED].includes(
			output.status
		);
	/** Whether the spend of an output in a block shows the preimage of the hash. */
	const showsPreimage = (
		pw: IPlainWorld,
		output: ITrackedOutput,
		paymentHash: Buffer
	): boolean =>
		pw.w.chain.confirmed
			.get(output.resolutionTxid ?? '')
			?.tx.ins.some(
				(input) =>
					Buffer.from(input.hash).reverse().toString('hex') === output.txid &&
					input.index === output.outputIndex &&
					input.witness.some(
						(element) =>
							element.length === 32 && sha256(element).equals(paymentHash)
					)
			) === true;
	const mineUntil = async (
		what: string,
		pw: IPlainWorld,
		reached: () => boolean,
		most = 20
	): Promise<void> => {
		for (let i = 0; i < most && !reached(); i++) await world.mine(pw.w, 1);
		if (!reached()) {
			throw new Error(
				`never reached: ${what}; bob ${errorsOf(pw.w.hosts.bob).join(
					' | '
				)}; carol ${errorsOf(pw.w.hosts.carol).join(' | ')}`
			);
		}
	};
	/** Every transaction Carol hands to the chain that spends one of `outputs`. */
	const publishedBy = (
		pw: IPlainWorld,
		outputs: () => Array<ITrackedOutput | undefined>
	): string[] => {
		const published: string[] = [];
		const backend = pw.w.backends.carol;
		const publish = backend.broadcastTransaction.bind(backend);
		backend.broadcastTransaction = async (txHex: string): Promise<string> => {
			const tx = bitcoin.Transaction.fromHex(txHex);
			const watched = outputs().filter(
				(output): output is ITrackedOutput => output !== undefined
			);
			if (
				tx.ins.some((input) =>
					watched.some(
						(output) =>
							Buffer.from(input.hash).reverse().toString('hex') ===
								output.txid && input.index === output.outputIndex
					)
				)
			) {
				published.push(tx.getId());
			}
			return publish(txHex);
		};
		return published;
	};
	/** Carol's logs of a hash, by action. */
	const actionsOf = (logs: Log[], paymentHash: Buffer, from = 0): string[] =>
		logs
			.slice(from)
			.filter((log) => log.data.paymentHash === hex(paymentHash))
			.map((log) => log.action);

	interface IHeld {
		pw: IPlainWorld;
		preimage: Buffer;
		paymentHash: Buffer;
		offer: IPlainOffer;
		/** The part on Bob's ordinary channel, in a set of two. */
		ordinary?: IPlainOffer;
		amountMsat: bigint;
		events: ReturnType<typeof holdEventsOf>;
		logs: Log[];
		/** The height the commitment that went on chain is in. */
		commitmentHeight: number;
		commitmentTxid: string;
	}

	/**
	 * A hold invoice of Carol's paid by a plain HTLC on the asset channel (and
	 * one on the ordinary channel with `mixed`), parked; then the asset
	 * channel goes on chain by the commitment of `closer`.
	 */
	const heldOnChain = async (
		tag: string,
		options: {
			closer: 'bob' | 'carol';
			amountMsat?: bigint;
			expiryDelta?: number;
			mixed?: boolean;
		}
	): Promise<IHeld> => {
		const pw = await openPlainWorld(world, tag);
		const { w } = pw;
		const carol = w.hosts.carol;
		const events = holdEventsOf(carol);
		const logs = logsOf(carol);
		const preimage = sha256(`${tag} preimage`);
		const paymentHash = sha256(preimage);
		const assetMsat = options.amountMsat ?? 50_000_000n;
		const amountMsat = options.mixed ? assetMsat + 30_000_000n : assetMsat;
		const invoice = carol.node.createInvoice({
			amountMsat,
			description: `held ${tag}`,
			hold: true,
			paymentHash
		});
		const ordinary = options.mixed
			? bobOffers(pw, w.outChannel2!, invoice, 30_000_000n, {
					totalMsat: amountMsat,
					expiryDelta: options.expiryDelta,
					label: 'ordinary part'
			  })
			: undefined;
		if (ordinary) {
			await until(
				'the ordinary part is parked',
				() => parkedOf(carol, paymentHash) === 1
			);
		}
		const offer = bobOffers(pw, w.outChannel, invoice, assetMsat, {
			totalMsat: amountMsat,
			expiryDelta: options.expiryDelta,
			label: 'asset-channel part'
		});
		await until(
			'the hold is parked',
			() => parkedOf(carol, paymentHash) === (options.mixed ? 2 : 1)
		);
		const closer = options.closer === 'bob' ? w.hosts.bob : carol;
		const closed = closer.node.forceCloseChannel(
			w.outChannel,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await world.mine(w, 1);
		const commitmentTxid = closed.commitmentTxid!;
		const commitment = w.chain.confirmed.get(commitmentTxid);
		expect(commitment, 'the commitment is in a block').to.not.equal(undefined);
		expect(parkedOf(carol, paymentHash)).to.equal(options.mixed ? 2 : 1);
		return {
			pw,
			preimage,
			paymentHash,
			offer,
			...(ordinary ? { ordinary } : {}),
			amountMsat,
			events,
			logs,
			commitmentHeight: commitment!.height,
			commitmentTxid
		};
	};

	/**
	 * Settle a hold whose HTLC is on chain, and have its output claimed: the
	 * settle is taken, the decision written, and the claim is in a block.
	 * Gives the height of the claim and the logs the settle wrote.
	 */
	const settleOnChain = async (
		held: IHeld,
		/** What the settle answers; null where the case does not say. */
		answer: boolean | null = true
	): Promise<{ claimHeight: number; settleLogs: string[]; after: number }> => {
		const { pw, offer, paymentHash, preimage, logs } = held;
		const carol = pw.w.hosts.carol;
		expect(pw.w.chain.height).to.be.below(
			offer.cltvExpiry - HELD_HTLC_EXPIRY_MARGIN
		);
		const mark = logs.length;
		const answered = carol.node.settleHeldHtlc(paymentHash, preimage);
		if (answer !== null) {
			expect(answered, 'the settle is taken').to.equal(answer);
		}
		const settleLogs = actionsOf(logs, paymentHash, mark);
		const after = logs.length;
		expect(decisionOf(carol, pw.w.outChannel, offer.htlcId)).to.equal('settle');
		await mineUntil('the HTLC output is claimed', pw, () =>
			spent(outputOf(pw.w.hosts.carol, pw.w.outChannel, offer))
		);
		const output = outputOf(pw.w.hosts.carol, pw.w.outChannel, offer)!;
		expect(output.txid).to.equal(held.commitmentTxid);
		expect(
			showsPreimage(pw, output, paymentHash),
			'claimed by the preimage'
		).to.equal(true);
		return {
			claimHeight: pw.w.chain.confirmed.get(output.resolutionTxid!)!.height,
			settleLogs,
			after
		};
	};

	/** The hold has ended COMPLETED, as an ordinary payment, with one hold:settled. */
	const expectSettledHold = (held: IHeld, carol: IAssetHost): void => {
		const { paymentHash, amountMsat, pw } = held;
		expect(parkedOf(carol, paymentHash)).to.equal(0);
		const payment = carol.node.getPayment(paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect('auxiliary' in payment).to.equal(false);
		const invoice = carol.node.getInvoice(hex(paymentHash))!;
		expect('auxiliary' in invoice).to.equal(false);
		const settled = held.events.filter((e) => e.name === 'hold:settled');
		expect(settled).to.have.length(1);
		expect(settled[0].event.heldAmountMsat).to.equal(amountMsat);
		expect('auxiliary' in settled[0].event).to.equal(false);
		expect(
			held.events.filter((e) => e.name === 'hold:cancelled')
		).to.deep.equal([]);
		expect(pw.log.resolved).to.deep.equal([]);
	};

	for (const closer of ['bob', 'carol'] as const) {
		const whose = closer === 'bob' ? "the peer's" : "the wallet's own";
		it(`settles a hold whose plain HTLC is on ${whose} commitment: the decision is written, the HTLC claimed, the hold parked until the claim is 100 deep and COMPLETED at that depth, with no asset mark, and not driven again at each block`, async () => {
			const held = await heldOnChain(`plain-hold-chain-${closer}`, { closer });
			const { pw, paymentHash } = held;
			const carol = pw.w.hosts.carol;
			const { claimHeight, settleLogs, after } = await settleOnChain(held);
			expect(settleLogs.length, 'the settle says what it did').to.be.above(0);
			// Blocks pass while the claim deepens: the settle is not asked again.
			await world.mine(pw.w, 3);
			expect(
				actionsOf(held.logs, paymentHash, after).filter((action) =>
					settleLogs.includes(action)
				),
				'no repeat of the settle at each block'
			).to.deep.equal([]);

			await world.passTo(pw.w, claimHeight + IRREVOCABLE_DEPTH - 1);
			expect(
				parkedOf(carol, paymentHash),
				'parked a block short of that depth'
			).to.equal(1);
			expect(carol.node.getPayment(paymentHash)!.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(held.events.map((e) => e.name)).to.deep.equal(['hold:accepted']);
			await world.mine(pw.w, 1);
			expectSettledHold(held, carol);

			// Nothing more once it has ended.
			const ended = held.logs.length;
			await world.mine(pw.w, 3);
			expect(
				held.events.filter((e) => e.name !== 'hold:accepted')
			).to.have.length(1);
			expect(
				actionsOf(held.logs, paymentHash, ended).filter((action) =>
					settleLogs.includes(action)
				)
			).to.deep.equal([]);
		});
	}

	it("cancels a hold whose plain HTLC is on the peer's commitment at once with a decision to fail; the peer's timeout then spends the output, and nothing is lowered or told", async () => {
		const held = await heldOnChain('plain-hold-chain-cancel', {
			closer: 'bob'
		});
		const { pw, paymentHash, offer } = held;
		const carol = pw.w.hosts.carol;
		const published = publishedBy(pw, () => [
			outputOf(pw.w.hosts.carol, pw.w.outChannel, offer)
		]);
		expect(carol.node.cancelHoldInvoice(paymentHash)).to.deep.equal({
			htlcsFailed: 1
		});
		expect(parkedOf(carol, paymentHash)).to.equal(0);
		expect(decisionOf(carol, pw.w.outChannel, offer.htlcId)).to.equal('fail');
		expect(held.events.map((e) => e.name)).to.deep.equal([
			'hold:accepted',
			'hold:cancelled'
		]);
		await world.passTo(pw.w, offer.cltvExpiry - 1);
		await mineUntil("the peer's timeout spends the output", pw, () =>
			spent(outputOf(carol, pw.w.outChannel, offer))
		);
		const output = outputOf(carol, pw.w.outChannel, offer)!;
		expect(showsPreimage(pw, output, paymentHash)).to.equal(false);
		expect(published, 'Carol published nothing for it').to.deep.equal([]);
		await world.passTo(pw.w, pw.w.chain.height + IRREVOCABLE_DEPTH);
		await world.mine(pw.w, 2);
		expect(carol.node.getPayment(paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
		expect(pw.log.resolved).to.deep.equal([]);
		expect(held.events.map((e) => e.name)).to.deep.equal([
			'hold:accepted',
			'hold:cancelled'
		]);
	});

	for (const settledFirst of [false, true]) {
		it(`ends a hold whose plain HTLC under the dust limit has no output on the commitment${
			settledFirst ? ', settled on chain first,' : ''
		} cancelled once the commitment is 100 deep, parked a block short of that, with no claim and nothing published`, async () => {
			const tag = `plain-hold-chain-dust-${settledFirst}`;
			const held = await heldOnChain(tag, {
				closer: 'bob',
				amountMsat: 300_000n,
				expiryDelta: 150
			});
			const { pw, paymentHash, offer, commitmentHeight } = held;
			const carol = pw.w.hosts.carol;
			// Beyond the confirmation, the depth and the cancel margin.
			expect(offer.cltvExpiry).to.be.above(
				commitmentHeight + IRREVOCABLE_DEPTH + HELD_HTLC_EXPIRY_MARGIN
			);
			expect(outputOf(carol, pw.w.outChannel, offer), 'no output').to.equal(
				undefined
			);
			// Everything Carol hands to the chain from here.
			const backend = pw.w.backends.carol;
			const sent: string[] = [];
			const publish = backend.broadcastTransaction.bind(backend);
			backend.broadcastTransaction = async (txHex: string): Promise<string> => {
				sent.push(txHex);
				return publish(txHex);
			};
			if (settledFirst) {
				carol.node.settleHeldHtlc(paymentHash, held.preimage);
				await world.mine(pw.w, 1);
			}
			await world.passTo(pw.w, commitmentHeight + IRREVOCABLE_DEPTH - 1);
			expect(
				parkedOf(carol, paymentHash),
				'parked a block short of that depth'
			).to.equal(1);
			await world.mine(pw.w, 1);
			expect(parkedOf(carol, paymentHash)).to.equal(0);
			expect(held.events.map((e) => e.name)).to.deep.equal([
				'hold:accepted',
				'hold:cancelled'
			]);
			expect(carol.node.getPayment(paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(
				sent.filter((txHex) =>
					bitcoin.Transaction.fromHex(txHex).ins.some((input) =>
						input.witness.some(
							(element) =>
								element.length === 32 && sha256(element).equals(paymentHash)
						)
					)
				),
				'no claim shows the preimage'
			).to.deep.equal([]);
			expect(pw.log.resolved).to.deep.equal([]);
		});
	}

	it('settles a hold set with a plain part on the asset channel and one on the ordinary channel while the asset channel is on chain: the ordinary part fulfilled, the other claimed by its decision, and the hold ends once both have, with the whole amount and one hold:settled', async () => {
		const held = await heldOnChain('plain-hold-chain-mixed', {
			closer: 'bob',
			mixed: true
		});
		const { pw, paymentHash, offer, ordinary, preimage } = held;
		const carol = pw.w.hosts.carol;
		const sent = endsSent(carol);
		const { claimHeight } = await settleOnChain(held, null);
		await until(
			'the ordinary part is settled',
			() => bobHasOut(pw, pw.w.outChannel2!, paymentHash) === 0
		);
		const ends = endsOfOffer(sent, ordinary!);
		expect(ends.map((end) => end.type)).to.deep.equal([UPDATE_FULFILL_HTLC]);
		expect(ends[0].preimage!.equals(preimage)).to.equal(true);

		await world.passTo(pw.w, claimHeight + IRREVOCABLE_DEPTH - 1);
		expect(
			parkedOf(carol, paymentHash),
			'parked a block short of that depth'
		).to.equal(1);
		await world.mine(pw.w, 1);
		expectSettledHold(held, carol);
		const payment = carol.node.getPayment(paymentHash)!;
		expect(payment.amountMsat).to.equal(80_000_000n);
		expect(payment.settledHtlcs).to.have.members([
			`${hex(offer.channelId)}:${offer.htlcId}`,
			`${hex(ordinary!.channelId)}:${ordinary!.htlcId}`
		]);
	});

	it('cancels a hold set with a plain part on the asset channel and one on the ordinary channel while the asset channel is on chain: both parts end', async () => {
		const held = await heldOnChain('plain-hold-chain-mixed-cancel', {
			closer: 'bob',
			mixed: true
		});
		const { pw, paymentHash, offer, ordinary } = held;
		const carol = pw.w.hosts.carol;
		const sent = endsSent(carol);
		expect(carol.node.cancelHoldInvoice(paymentHash)).to.deep.equal({
			htlcsFailed: 2
		});
		await until(
			'the ordinary part is failed back',
			() => bobHasOut(pw, pw.w.outChannel2!, paymentHash) === 0
		);
		expect(endsOfOffer(sent, ordinary!).map((end) => end.type)).to.deep.equal([
			UPDATE_FAIL_HTLC
		]);
		expect(decisionOf(carol, pw.w.outChannel, offer.htlcId)).to.equal('fail');
		expect(parkedOf(carol, paymentHash)).to.equal(0);
		expect(
			held.events.filter((e) => e.name !== 'hold:accepted').map((e) => e.name)
		).to.deep.equal(['hold:cancelled']);
		expect(carol.node.getPayment(paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('ends a hold settled on chain COMPLETED at the depth of its claim after a restart over SQLite between the decision and the end', async () => {
		const tag = 'plain-hold-chain-restart';
		const held = await heldOnChain(tag, { closer: 'bob' });
		const { pw, paymentHash } = held;
		const { claimHeight } = await settleOnChain(held);
		await world.restartCarol(pw.w, tag, { hooks: pw.hooks, reconnect: false });
		const carol = pw.w.hosts.carol;
		held.events = holdEventsOf(carol);
		expect(parkedOf(carol, paymentHash)).to.equal(1);
		await world.passTo(pw.w, claimHeight + IRREVOCABLE_DEPTH - 1);
		expect(
			parkedOf(carol, paymentHash),
			'parked a block short of that depth'
		).to.equal(1);
		await world.mine(pw.w, 1);
		expect(parkedOf(carol, paymentHash)).to.equal(0);
		const payment = carol.node.getPayment(paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect('auxiliary' in payment).to.equal(false);
		const settled = held.events.filter((e) => e.name === 'hold:settled');
		expect(settled).to.have.length(1);
		expect('auxiliary' in settled[0].event).to.equal(false);
	});

	it('reveals nothing for an ordinary set whose part on the asset channel is on chain when the last part arrives: the ordinary part is failed back, the other has no decision to settle, nothing claims it, and the peer takes it back by its timeout', async () => {
		const pw = await openPlainWorld(world, 'plain-set-chain');
		const { w } = pw;
		const carol = w.hosts.carol;
		const sent = endsSent(carol);
		const invoice = carol.node.createInvoice({
			amountMsat: 80_000_000n,
			description: 'paid in parts'
		});
		const plain = bobOffers(pw, w.outChannel, invoice, 50_000_000n, {
			totalMsat: 80_000_000n,
			label: 'plain part'
		});
		await until(
			'Carol collects the plain part',
			() => collectedOf(carol, invoice.paymentHash) === 1
		);
		const closed = w.hosts.bob.node.forceCloseChannel(
			w.outChannel,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await world.mine(w, 1);
		const published = publishedBy(pw, () => [
			outputOf(carol, w.outChannel, plain)
		]);
		const ordinary = bobOffers(pw, w.outChannel2!, invoice, 30_000_000n, {
			totalMsat: 80_000_000n,
			label: 'ordinary part'
		});
		await until(
			'the ordinary part ends',
			() => bobHasOut(pw, w.outChannel2!, invoice.paymentHash) === 0
		);
		expect(
			sent.filter((end) => end.type === UPDATE_FULFILL_HTLC),
			'no fulfil left'
		).to.deep.equal([]);
		expect(endsOfOffer(sent, ordinary).map((end) => end.type)).to.deep.equal([
			UPDATE_FAIL_HTLC
		]);
		expect(monitorsKnow(carol, invoice.paymentHash)).to.equal(false);
		expect(decisionOf(carol, w.outChannel, plain.htlcId)).to.not.equal(
			'settle'
		);
		expect(carol.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);

		await world.passTo(w, plain.cltvExpiry - 1);
		await mineUntil("the peer's timeout spends the output", pw, () =>
			spent(outputOf(carol, w.outChannel, plain))
		);
		const output = outputOf(carol, w.outChannel, plain)!;
		expect(showsPreimage(pw, output, invoice.paymentHash)).to.equal(false);
		expect(published, 'Carol published nothing for it').to.deep.equal([]);
		expect(pw.log.resolved).to.deep.equal([]);
	});
});
