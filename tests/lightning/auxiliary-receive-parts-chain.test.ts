/**
 * Issue #2098, step 8: every part of a committed set of asset parts is
 * claimed, on the chain too. Once the payee has written the set's record
 * COMPLETED, nothing gives a part up: a part whose fulfil was refused is
 * claimed by its preimage when its channel goes to the chain, a part whose
 * fulfil the payee's own provider keeps refusing is taken to the chain at
 * the claim buffer and claimed there, a part whose settle decision did not
 * land is never failed back off the chain, and a part the payer takes back
 * on the chain lowers the record once, which turns FAILED only when every
 * part was lost. The record is kept while a part it names is open.
 *
 * Bitcoin in, asset out, on the chain world of auxiliary-forward-world.ts:
 * Alice pays Carol's ordinary invoice in parts through Bob, whose host makes
 * each part an asset HTLC to Carol.
 *
 * Written first: on the build before step 8, where no set of asset parts
 * is collected, each case fails at the commit it starts from. The contract
 * is "The commit, and every part claimed" and "A part lost on the chain"
 * in docs/EXTENSIONS.md.
 */

import { expect } from 'chai';
import { IRREVOCABLE_DEPTH } from '../../src/lightning/chain/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	forwardChainWorld,
	payInParts
} from './helpers/auxiliary-forward-world';
import {
	openPartsScene,
	rounds,
	type IPartsScene
} from './helpers/auxiliary-forward-scene';
import {
	turns,
	withAssetForwards,
	withAssetOpens,
	withAssetPartsReceived
} from './helpers/auxiliary-nodes';
import { SWEEP_DESTINATION, settle } from './helpers/auxiliary-on-chain';
import {
	alicePaid,
	carolsRecord,
	claimedByPreimage,
	committed,
	decisionOf,
	endsOf,
	errorCodes,
	hex,
	isSpent,
	keeping,
	keyOf,
	lossesOf,
	onCommit,
	openReceived,
	partsOf,
	receivedEntries,
	receivedOutputs,
	refusing,
	showsPreimage,
	watchManager,
	wireWatch
} from './helpers/auxiliary-parts-checks';

/** max(18, htlcSafetyMargin) at the margin these nodes run with. */
const CLAIM_BUFFER = 18;

describe('every part of a committed set of asset parts is claimed on the chain (issue #2098, step 8)', function () {
	this.timeout(240_000);
	withAssetOpens();
	withAssetForwards();
	withAssetPartsReceived();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	/** Blocks, one at a time, until `reached`, or throw with what is missing. */
	const untilMined = async (
		s: IPartsScene,
		what: string,
		reached: () => boolean,
		most = 30
	): Promise<void> => {
		for (let i = 0; i < most && !reached(); i++) await world.mine(s.w, 1);
		if (!reached()) {
			throw new Error(
				`never reached: ${what} at ${
					s.w.chain.height
				}; carol: ${s.w.hosts.carol.errors.join(' | ')}`
			);
		}
	};

	/** The channels Carol took to the chain herself. */
	const carolCloses = (s: IPartsScene): string[] => {
		const closed: string[] = [];
		s.w.hosts.carol.node.on(
			'channel:force-closing',
			(event: { channelId: Buffer; initiator: 'local' | 'remote' }) => {
				if (event.initiator === 'local') closed.push(hex(event.channelId));
			}
		);
		return closed;
	};

	/** Bob takes his channel with Carol to the chain while she does not hear him. */
	const bobCloses = async (s: IPartsScene): Promise<void> => {
		world.cut(s.w, 'out');
		const closed = s.w.hosts.bob.node.forceCloseChannel(
			s.w.outChannel,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await world.mine(s.w, 1);
	};

	it('after the commit, Bob takes the channel of the parts whose fulfils Carol refused to the chain, and Carol claims each there by its preimage before its expiry; the record stays COMPLETED and Alice is paid', async () => {
		const tag = 'parts-chain-bob-closes';
		const arm = { down: false };
		const s = await openPartsScene(world, tag, {
			world: { wrapProvider: { carol: refusing(arm) } },
			coins: 4
		});
		// From the commit on, Carol's provider refuses every removal.
		onCommit(s, () => {
			arm.down = true;
		});
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		await committed(s, invoice);
		await turns(50);
		const carol = s.w.hosts.carol;
		const parts = receivedEntries(carol, s.w.outChannel, invoice.paymentHash);
		expect(parts.length, 'both fulfils were refused').to.equal(2);
		for (const part of parts) {
			expect(decisionOf(carol, s.w.outChannel, part.id)).to.equal('settle');
		}
		const expiry = Math.min(...parts.map((part) => part.cltvExpiry));

		await bobCloses(s);
		// The provider is back for the claim on the chain.
		arm.down = false;
		await untilMined(
			s,
			'Carol claims both parts by their preimage',
			() =>
				claimedByPreimage(s, s.w.outChannel, invoice.paymentHash).length === 2
		);
		for (const output of claimedByPreimage(
			s,
			s.w.outChannel,
			invoice.paymentHash
		)) {
			expect(output.confirmationHeight).to.be.lessThan(expiry);
		}
		expect(carolsRecord(s, invoice)!.status).to.equal(PaymentStatus.COMPLETED);
		expect(
			Object.keys(partsOf(carolsRecord(s, invoice)) ?? {})
		).to.have.members(parts.map((part) => keyOf(s.w.outChannel, part.id)));
		await alicePaid(s, invoice);
		expect(lossesOf(s, invoice)).to.deep.equal([]);
	});

	it("a part whose fulfil Carol's own provider keeps refusing on an open channel is taken to the chain at the claim buffer and claimed there by its preimage, not left to its expiry", async () => {
		const tag = 'parts-chain-claim-buffer';
		const arm = { down: false };
		const s = await openPartsScene(world, tag, {
			world: { wrapProvider: { carol: refusing(arm) } },
			coins: 4
		});
		const closed = carolCloses(s);
		onCommit(s, () => {
			arm.down = true;
		});
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		await committed(s, invoice);
		await turns(50);
		const carol = s.w.hosts.carol;
		const parts = receivedEntries(carol, s.w.outChannel, invoice.paymentHash);
		expect(parts.length, 'both fulfils were refused').to.equal(2);
		const expiry = Math.min(...parts.map((part) => part.cltvExpiry));

		// The channel stays open and its peer connected; the provider refuses.
		await world.passTo(s.w, expiry - CLAIM_BUFFER - 2);
		await world.mine(s.w, 1);
		expect(closed, 'Carol keeps the channel before the buffer').to.deep.equal(
			[]
		);
		expect(
			carol.node.getChannelManager().getChannel(s.w.outChannel)?.getState()
		).to.equal(ChannelState.NORMAL);
		await untilMined(
			s,
			'Carol takes the channel to the chain',
			() => closed.includes(hex(s.w.outChannel)),
			3
		);
		expect(s.w.chain.height).to.equal(expiry - CLAIM_BUFFER);
		arm.down = false;
		await untilMined(
			s,
			'Carol claims both parts by their preimage',
			() =>
				claimedByPreimage(s, s.w.outChannel, invoice.paymentHash).length === 2
		);
		for (const output of claimedByPreimage(
			s,
			s.w.outChannel,
			invoice.paymentHash
		)) {
			expect(output.confirmationHeight).to.be.lessThan(expiry);
		}
		expect(carolsRecord(s, invoice)!.status).to.equal(PaymentStatus.COMPLETED);
		await alicePaid(s, invoice);
	});

	it('a committed part whose settle decision does not land is never failed back, inside htlcSafetyMargin too, and is claimed by its preimage once the write lands', async () => {
		const tag = 'parts-chain-decision-late';
		const keep = { keep: new Set<string>() };
		const margin = 12;
		const s = await openPartsScene(world, tag, {
			world: {
				wrapProvider: { carol: keeping(keep) },
				nodes: { carol: { htlcSafetyMargin: margin } }
			},
			coins: 4
		});
		const carol = s.w.hosts.carol;
		const watch = watchManager(carol);
		const sent = wireWatch(carol);
		// The write of one part's settle decision fails until `write.fails` is false.
		const write = { fails: true, part: '' };
		const misses: string[] = [];
		const manager = carol.node.getChannelManager();
		const decide = manager.recordAuxiliaryHtlcDecision.bind(manager);
		manager.recordAuxiliaryHtlcDecision = (
			channelId,
			htlcId,
			outcome,
			preimage
		): boolean => {
			if (write.fails && keyOf(channelId, htlcId) === write.part) {
				misses.push(write.part);
				return false;
			}
			return decide(channelId, htlcId, outcome, preimage);
		};
		onCommit(s, () => {
			// The part of the set with the higher id: its decision does not
			// land, and its fulfil is refused.
			const parts = openReceived(carol, s.w.outChannel);
			write.part = keyOf(s.w.outChannel, parts[parts.length - 1].id);
			keep.keep.add(write.part);
		});
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		await committed(s, invoice);
		await turns(50);
		const left = receivedEntries(carol, s.w.outChannel, invoice.paymentHash);
		expect(
			left.map((part) => keyOf(s.w.outChannel, part.id)),
			'the other part was fulfilled'
		).to.deep.equal([write.part]);
		const [part] = left;
		expect(decisionOf(carol, s.w.outChannel, part.id)).to.equal(undefined);

		// Inside htlcSafetyMargin, where an HTLC without a claim is failed off the chain.
		await world.passTo(s.w, part.cltvExpiry - margin);
		await world.mine(s.w, 2);
		expect(watch.fails, 'the part is never failed back').to.deep.equal([]);
		expect(
			endsOf(sent, s.w.outChannel, part.id),
			'no fail of the part was sent'
		).to.deep.equal([]);
		expect(
			misses.length,
			'the decision is written again on each block'
		).to.be.at.least(3);
		const output = receivedOutputs(carol, s.w.outChannel, invoice.paymentHash);
		expect(
			output.filter(
				(entry) =>
					isSpent(entry) && !showsPreimage(s, entry, invoice.paymentHash)
			),
			'nothing of the part went back to Bob'
		).to.deep.equal([]);

		write.fails = false;
		await untilMined(
			s,
			'Carol claims the part by its preimage',
			() =>
				claimedByPreimage(s, s.w.outChannel, invoice.paymentHash).length === 1,
			8
		);
		expect(
			claimedByPreimage(s, s.w.outChannel, invoice.paymentHash)[0]
				.confirmationHeight
		).to.be.lessThan(part.cltvExpiry);
		expect(watch.fails).to.deep.equal([]);
		expect(endsOf(sent, s.w.outChannel, part.id)).to.deep.equal([]);
		expect(carolsRecord(s, invoice)!.status).to.equal(PaymentStatus.COMPLETED);
		expect(
			Object.keys(partsOf(carolsRecord(s, invoice)) ?? {}).length
		).to.equal(2);
	});

	/**
	 * The parts named take no fulfil, and Carol's provider signs no claim:
	 * Bob takes the channel to the chain and his timeouts take each such
	 * part back after its expiry, there for good IRREVOCABLE_DEPTH on.
	 */
	async function lose(
		tag: string,
		refuse: 'one' | 'all'
	): Promise<{
		s: IPartsScene;
		invoice: Awaited<ReturnType<typeof payInParts>>;
		failed: unknown[];
		parts: string[];
		/** Each part's value, as the record had it at the commit. */
		values: Record<string, string>;
	}> {
		const keep = { keep: new Set<string>() };
		const arm = { down: false };
		const s = await openPartsScene(world, tag, {
			world: {
				wrapProvider: {
					carol: (provider) => keeping(keep)(refusing(arm)(provider))
				},
				control: {
					carol: { refuse: () => 'the asset store signs no claim' }
				}
			},
			coins: 4
		});
		const carol = s.w.hosts.carol;
		const failed: unknown[] = [];
		carol.node.on('payment:failed', (payment: unknown) => {
			failed.push(payment);
		});
		onCommit(s, () => {
			if (refuse === 'all') {
				arm.down = true;
				return;
			}
			const parts = openReceived(carol, s.w.outChannel);
			keep.keep.add(keyOf(s.w.outChannel, parts[parts.length - 1].id));
		});
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		await committed(s, invoice);
		await turns(50);
		const values = partsOf(carolsRecord(s, invoice)) ?? {};
		const open = receivedEntries(carol, s.w.outChannel, invoice.paymentHash);
		expect(open.length).to.equal(refuse === 'all' ? 2 : 1);
		const expiry = Math.min(...open.map((part) => part.cltvExpiry));
		await bobCloses(s);
		// The provider is back; it is the claim it will not sign.
		arm.down = false;
		await world.passTo(s.w, expiry - 1);
		await untilMined(
			s,
			"Bob's timeouts take the parts back",
			() =>
				receivedOutputs(carol, s.w.outChannel, invoice.paymentHash).filter(
					(output) =>
						isSpent(output) && !showsPreimage(s, output, invoice.paymentHash)
				).length === open.length,
			12
		);
		s.w.chain.advance(IRREVOCABLE_DEPTH);
		await settle();
		await world.mine(s.w, 2);
		await settle();
		return {
			s,
			invoice,
			failed,
			parts: open.map((part) => keyOf(s.w.outChannel, part.id)),
			values
		};
	}

	it('a part the payer takes back on the chain after the commit leaves the record, which stays COMPLETED lowered by its value, logged and raised once; two more blocks change nothing', async () => {
		const { s, invoice, failed, parts, values } = await lose(
			'parts-chain-one-lost',
			'one'
		);
		const carol = s.w.hosts.carol;
		const [lostKey] = parts;
		await rounds('the loss is counted', () => lossesOf(s, invoice).length > 0);
		const record = (): ReturnType<typeof carolsRecord> =>
			carolsRecord(s, invoice);
		const counted = (): unknown => ({
			losses: lossesOf(s, invoice).map((log) => ({
				...log.data,
				lostMsat: String(log.data.lostMsat),
				partsLeft: String(log.data.partsLeft)
			})),
			errors: errorCodes(carol).filter(
				(code) => code === 'ASSET_HTLC_CLAIM_LOST'
			).length,
			failed: failed.length,
			status: record()?.status,
			receivedMsat: record()?.receivedMsat,
			parts: partsOf(record())
		});
		const [channelHex, htlcId] = lostKey.split(':');
		expect(Object.keys(values).length, 'two parts at the commit').to.equal(2);
		const keptKey = Object.keys(values).find((key) => key !== lostKey)!;
		expect(counted()).to.deep.equal({
			losses: [
				{
					paymentHash: hex(invoice.paymentHash),
					channelId: channelHex,
					htlcId,
					lostMsat: values[lostKey],
					partsLeft: '1'
				}
			],
			errors: 1,
			failed: 0,
			status: PaymentStatus.COMPLETED,
			receivedMsat: BigInt(values[keptKey]),
			parts: { [keptKey]: values[keptKey] }
		});
		const before = JSON.stringify(counted(), (_key, value: unknown) =>
			typeof value === 'bigint' ? value.toString() : value
		);
		await world.mine(s.w, 2);
		await settle();
		expect(
			JSON.stringify(counted(), (_key, value: unknown) =>
				typeof value === 'bigint' ? value.toString() : value
			),
			'counted once'
		).to.equal(before);
	});

	it('with every part of a committed set taken back on the chain, the record turns FAILED with one payment:failed', async () => {
		const { s, invoice, failed, parts } = await lose(
			'parts-chain-all-lost',
			'all'
		);
		await rounds(
			'the record fails',
			() => carolsRecord(s, invoice)?.status === PaymentStatus.FAILED
		);
		expect(failed.length, 'payment:failed once').to.equal(1);
		expect(
			lossesOf(s, invoice)
				.map((log) => `${log.data.channelId}:${log.data.htlcId}`)
				.sort()
		).to.deep.equal([...parts].sort());
		expect(
			lossesOf(s, invoice).map((log) => String(log.data.partsLeft))
		).to.have.members(['1', '0']);
		await world.mine(s.w, 2);
		await settle();
		expect(failed.length).to.equal(1);
		expect(lossesOf(s, invoice).length).to.equal(2);
		expect(carolsRecord(s, invoice)?.status).to.equal(PaymentStatus.FAILED);
	});

	it('a COMPLETED record with a part still open is not pruned at completedPaymentTtlMs, with its channel open and once the channel is on the chain', async () => {
		const tag = 'parts-chain-not-pruned';
		const arm = { down: false };
		const s = await openPartsScene(world, tag, {
			world: {
				wrapProvider: { carol: refusing(arm) },
				control: { carol: { refuse: () => 'the asset store signs no claim' } }
			},
			coins: 4
		});
		onCommit(s, () => {
			arm.down = true;
		});
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		await committed(s, invoice);
		await turns(50);
		const carol = s.w.hosts.carol;
		expect(
			receivedEntries(carol, s.w.outChannel, invoice.paymentHash).length
		).to.equal(2);
		const resources = carol.node as unknown as {
			resourceConfig: { completedPaymentTtlMs: number };
		};
		resources.resourceConfig.completedPaymentTtlMs = 0;
		await new Promise((resolve) => setTimeout(resolve, 5));
		carol.node.pruneCompletedPayments();
		expect(
			carolsRecord(s, invoice)?.status,
			'kept with its channel open'
		).to.equal(PaymentStatus.COMPLETED);

		await bobCloses(s);
		arm.down = false;
		await world.mine(s.w, 2);
		expect(
			receivedOutputs(carol, s.w.outChannel, invoice.paymentHash).filter(
				(output) => !isSpent(output)
			).length,
			'the parts are open on the chain'
		).to.equal(2);
		carol.node.pruneCompletedPayments();
		expect(
			carolsRecord(s, invoice)?.status,
			'kept with its channel on the chain'
		).to.equal(PaymentStatus.COMPLETED);
		expect(
			Object.keys(partsOf(carolsRecord(s, invoice)) ?? {}).length
		).to.equal(2);
	});
});
