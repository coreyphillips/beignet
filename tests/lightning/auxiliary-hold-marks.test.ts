/**
 * Issue #2093: a held asset HTLC is marked like everything else an asset
 * channel carried.
 *
 * The node's hold:accepted, hold:settled and hold:cancelled events and the
 * rows of listHoldInvoices and listHeldHtlcs carry auxiliary: true when a
 * part of the set is an HTLC that holds units, and heldAmountMsat stays
 * what the node has for it. A hold paid over an ordinary channel between
 * the same two nodes has none of it: its events, its rows and what the
 * node stores of the parked set have exactly the keys they had.
 */

import { expect } from 'chai';
import { createHash } from 'crypto';
import type {
	IHoldCancelledEvent,
	IHoldInvoiceStateEvent
} from '../../src/lightning/node/types';
import {
	assetHost,
	connectHosts,
	failingProvider,
	openAssetChannel,
	payAssetUnits,
	turns,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';

/** The keys of a hold:accepted and a hold:settled event without units. */
const STATE_EVENT_KEYS = [
	'paymentHash',
	'state',
	'heldAmountMsat',
	'htlcCount',
	'minFinalCltvExpiry',
	'earliestExpiry',
	'cancelMarginBlocks',
	'cancelHeight'
];
/** The keys of a hold:cancelled event without units. */
const CANCELLED_EVENT_KEYS = [
	'paymentHash',
	'reason',
	'htlcsFailed',
	'heldAmountMsat',
	'minFinalCltvExpiry',
	'earliestExpiry',
	'cancelMarginBlocks',
	'cancelHeight'
];
/** The keys of a listHoldInvoices row without units. */
const ROW_KEYS = [
	'paymentHash',
	'bolt11',
	'amountMsat',
	'description',
	'expiry',
	'createdAt',
	'state',
	'heldAmountMsat',
	'htlcCount',
	'minFinalCltvExpiry',
	'earliestExpiry',
	'cancelMarginBlocks',
	'cancelHeight'
];

type THoldEvent =
	| { name: 'hold:accepted' | 'hold:settled'; event: IHoldInvoiceStateEvent }
	| { name: 'hold:cancelled'; event: IHoldCancelledEvent };

describe('the marks of a held asset HTLC (issue #2093 step 8)', function () {
	this.timeout(60_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			try {
				host.node.destroy();
			} catch {
				// already destroyed
			}
			try {
				host.storage?.close();
			} catch {
				// already closed
			}
		}
	});

	const sha = (data: Buffer | string): Buffer =>
		createHash('sha256').update(data).digest();

	/** Alice and Bob with an asset channel, and what Bob's node said of holds. */
	async function pair(
		tag: string,
		options: { arm?: { down: boolean }; ordinary?: boolean } = {}
	): Promise<{
		alice: IAssetHost;
		bob: IAssetHost;
		channelId: Buffer;
		events: THoldEvent[];
	}> {
		const alice = assetHost(tag, 1, {}, { sqlite: true });
		const bob = assetHost(
			tag,
			2,
			{
				...(options.arm
					? {
							provider: failingProvider(
								(method) => method === 'buildCommitment' && options.arm!.down
							)
					  }
					: {}),
				// An HTLC without units is not the host's to value.
				valueIncomingHtlc: (context) =>
					context.auxiliaryAmount === undefined
						? undefined
						: context.auxiliaryAmount * 1000n
			},
			{ sqlite: true }
		);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		if (options.ordinary) openReadyChannel(alice.node, bob.node);
		const events: THoldEvent[] = [];
		bob.node.on('hold:accepted', (event) =>
			events.push({ name: 'hold:accepted', event })
		);
		bob.node.on('hold:settled', (event) =>
			events.push({ name: 'hold:settled', event })
		);
		bob.node.on('hold:cancelled', (event) =>
			events.push({ name: 'hold:cancelled', event })
		);
		return { alice, bob, channelId, events };
	}

	/** Alice pays 5000 units to a hold invoice of Bob, who holds the HTLC. */
	async function holdUnits(
		alice: IAssetHost,
		bob: IAssetHost,
		channelId: Buffer,
		tag: string
	): Promise<{ paymentHash: Buffer; preimage: Buffer }> {
		const preimage = sha(`${tag} preimage`);
		const paymentHash = sha(preimage);
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'held units',
			hold: true,
			paymentHash
		});
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);
		return { paymentHash, preimage };
	}

	const rowOf = (
		host: IAssetHost,
		paymentHash: Buffer
	): ReturnType<IAssetHost['node']['listHoldInvoices']>[number] =>
		host.node
			.listHoldInvoices()
			.find((row) => row.paymentHash === paymentHash.toString('hex'))!;

	const stored = (host: IAssetHost): string =>
		host.storage!.loadMetadata('held_htlcs') ?? '';

	it('says auxiliary: true on hold:accepted, on the rows while the HTLC is held, on hold:settled and on the row of the settled invoice', async () => {
		const { alice, bob, channelId, events } = await pair('hold-marks-settle');
		const { paymentHash, preimage } = await holdUnits(
			alice,
			bob,
			channelId,
			'hold-marks-settle'
		);
		expect(events.map((entry) => entry.name)).to.deep.equal(['hold:accepted']);
		const accepted = events[0].event as IHoldInvoiceStateEvent;
		expect(accepted.auxiliary).to.equal(true);
		expect(accepted.state).to.equal('ACCEPTED');
		expect(accepted.htlcCount).to.equal(1);
		// What the node has for the HTLC: what the host valued its units at.
		expect(accepted.heldAmountMsat).to.equal(5_000_000n);

		const held = rowOf(bob, paymentHash);
		expect(held.state).to.equal('ACCEPTED');
		expect(held.auxiliary).to.equal(true);
		expect(held.heldAmountMsat).to.equal(5_000_000n);
		expect(held.htlcCount).to.equal(1);
		expect(bob.node.listHeldHtlcs()).to.deep.equal([
			{ paymentHash, amountMsat: 5_000_000n, htlcCount: 1, auxiliary: true }
		]);
		// The parked HTLC is stored with the mark of an HTLC that carries
		// units, which the node keeps for the time its channel may be gone.
		expect(
			(
				JSON.parse(stored(bob)) as Array<{
					htlcs: Array<{ auxiliary?: true }>;
				}>
			)[0].htlcs.map((parked) => parked.auxiliary)
		).to.deep.equal([true]);

		expect(bob.node.settleHeldHtlc(paymentHash, preimage)).to.equal(true);
		await turns(200);
		expect(events.map((entry) => entry.name)).to.deep.equal([
			'hold:accepted',
			'hold:settled'
		]);
		const settled = events[1].event as IHoldInvoiceStateEvent;
		expect(settled.auxiliary).to.equal(true);
		expect(settled.state).to.equal('SETTLED');
		expect(settled.heldAmountMsat).to.equal(5_000_000n);
		expect(settled.htlcCount).to.equal(1);

		const after = rowOf(bob, paymentHash);
		expect(after.state).to.equal('SETTLED');
		expect(after.auxiliary).to.equal(true);
		expect(after.heldAmountMsat).to.equal(0n);
		expect(after.htlcCount).to.equal(0);
		expect(bob.node.listHeldHtlcs()).to.deep.equal([]);
	});

	it('says auxiliary: true on hold:cancelled, and the row of the cancelled invoice, which holds nothing, does not', async () => {
		const { alice, bob, channelId, events } = await pair('hold-marks-cancel');
		const { paymentHash } = await holdUnits(
			alice,
			bob,
			channelId,
			'hold-marks-cancel'
		);
		expect(bob.node.cancelHoldInvoice(paymentHash)?.htlcsFailed).to.equal(1);
		await turns(200);
		expect(events.map((entry) => entry.name)).to.deep.equal([
			'hold:accepted',
			'hold:cancelled'
		]);
		const cancelled = events[1].event as IHoldCancelledEvent;
		expect(cancelled.auxiliary).to.equal(true);
		expect(cancelled.reason).to.equal('api');
		expect(cancelled.htlcsFailed).to.equal(1);
		expect(cancelled.heldAmountMsat).to.equal(5_000_000n);

		const after = rowOf(bob, paymentHash);
		expect(after.state).to.equal('CANCELLED');
		expect(Object.keys(after)).to.deep.equal(ROW_KEYS);
		expect(bob.node.listHeldHtlcs()).to.deep.equal([]);
	});

	it('keeps the mark with a settle the asset provider refused, so the event of the settle made later still says it', async () => {
		const arm = { down: false };
		const { alice, bob, channelId, events } = await pair('hold-marks-owed', {
			arm
		});
		const { paymentHash, preimage } = await holdUnits(
			alice,
			bob,
			channelId,
			'hold-marks-owed'
		);
		arm.down = true;
		expect(bob.node.settleHeldHtlc(paymentHash, preimage)).to.equal(false);
		await turns(100);
		expect(events.map((entry) => entry.name)).to.deep.equal(['hold:accepted']);
		const parked = JSON.parse(stored(bob)) as Array<{
			hashHex: string;
			resolution?: Record<string, unknown>;
		}>;
		expect(parked).to.have.length(1);
		expect(parked[0].resolution).to.deep.equal({
			outcome: 'settle',
			resolved: [],
			auxiliary: true
		});
		expect(rowOf(bob, paymentHash).auxiliary).to.equal(true);

		arm.down = false;
		(
			bob.node as unknown as { retryAuxiliaryOwed: () => void }
		).retryAuxiliaryOwed();
		await turns(200);
		expect(events.map((entry) => entry.name)).to.deep.equal([
			'hold:accepted',
			'hold:settled'
		]);
		expect((events[1].event as IHoldInvoiceStateEvent).auxiliary).to.equal(
			true
		);
		expect(rowOf(bob, paymentHash).auxiliary).to.equal(true);
	});

	it('leaves a hold paid over an ordinary channel between the same two nodes as it was: no event, row or stored set has the key', async () => {
		const { alice, bob, events } = await pair('hold-marks-ordinary', {
			ordinary: true
		});
		const preimage = sha('hold-marks-ordinary preimage');
		const paymentHash = sha(preimage);
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'held bitcoin',
			hold: true,
			paymentHash
		});
		alice.node.sendPayment(invoice.bolt11);
		await turns(200);
		expect(events.map((entry) => entry.name)).to.deep.equal(['hold:accepted']);
		expect(Object.keys(events[0].event)).to.deep.equal(STATE_EVENT_KEYS);
		expect(events[0].event.heldAmountMsat).to.equal(5_000_000n);
		expect(Object.keys(rowOf(bob, paymentHash))).to.deep.equal(ROW_KEYS);
		expect(rowOf(bob, paymentHash).state).to.equal('ACCEPTED');
		expect(bob.node.listHeldHtlcs()).to.deep.equal([
			{ paymentHash, amountMsat: 5_000_000n, htlcCount: 1 }
		]);
		expect(Object.keys(bob.node.listHeldHtlcs()[0])).to.deep.equal([
			'paymentHash',
			'amountMsat',
			'htlcCount'
		]);
		expect(stored(bob)).to.not.include('auxiliary');

		expect(bob.node.settleHeldHtlc(paymentHash, preimage)).to.equal(true);
		await turns(200);
		expect(events.map((entry) => entry.name)).to.deep.equal([
			'hold:accepted',
			'hold:settled'
		]);
		expect(Object.keys(events[1].event)).to.deep.equal(STATE_EVENT_KEYS);
		expect(Object.keys(rowOf(bob, paymentHash))).to.deep.equal(ROW_KEYS);
		expect(rowOf(bob, paymentHash).state).to.equal('SETTLED');

		const second = sha(sha('hold-marks-ordinary second'));
		const other = bob.node.createInvoice({
			amountMsat: 2_000_000n,
			description: 'held and failed back',
			hold: true,
			paymentHash: second
		});
		alice.node.sendPayment(other.bolt11);
		await turns(200);
		expect(bob.node.cancelHoldInvoice(second)?.htlcsFailed).to.equal(1);
		await turns(200);
		expect(events.map((entry) => entry.name)).to.deep.equal([
			'hold:accepted',
			'hold:settled',
			'hold:accepted',
			'hold:cancelled'
		]);
		expect(Object.keys(events[2].event)).to.deep.equal(STATE_EVENT_KEYS);
		expect(Object.keys(events[3].event)).to.deep.equal(CANCELLED_EVENT_KEYS);
		expect(Object.keys(rowOf(bob, second))).to.deep.equal(ROW_KEYS);
		expect(stored(bob)).to.not.include('auxiliary');
	});
});
