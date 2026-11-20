/**
 * Issue #2098, step 7: a gate by which whoever wraps the node can refuse a
 * forward with an asset leg before anything is offered, as
 * setAuxiliaryPaymentGate does for an asset payment.
 *
 * The node asks the gate once for each offer, synchronously, after its
 * host's terms are read and the forward's checks before the add have
 * passed, and before the link is staged and the outgoing HTLC added. A
 * refusal (a string, a refusal with its own code, a throw, or a promise)
 * offers and links nothing: the incoming HTLC fails back with
 * temporary_channel_failure, the host is told that the outgoing leg was
 * never offered, and the log says why. The gate is given copies, and is
 * never asked about an ordinary forward or one that the host or the
 * node's own checks refused before it.
 */

import { expect } from 'chai';
import { HtlcDirection } from '../../src/lightning/channel/types';
import {
	FORWARD_CARRIER_MSAT,
	forwardChainWorld,
	type IForwardWorld
} from './helpers/auxiliary-forward-world';
import { withAssetForwards, withAssetOpens } from './helpers/auxiliary-nodes';
import { amountRecord } from './helpers/auxiliary-pair';
import {
	FORWARD_MSAT,
	INCOMING_MSAT,
	INCOMING_UNITS,
	MSAT_PER_UNIT,
	incomingWorth,
	legEnds,
	openScene,
	rounds,
	settleAtCarol,
	shapeName,
	type IScene,
	type ISceneOptions,
	type Shape
} from './helpers/auxiliary-forward-scene';

/** A forward as the gate is given it (IAuxiliaryGatedForward). */
interface IGated {
	paymentHash: Buffer;
	shortChannelId: Buffer;
	incoming: {
		channelId: Buffer;
		peerPubkey: string;
		htlcId: bigint;
		wireAmountMsat: bigint;
		auxiliaryAmount?: bigint;
		valueMsat: bigint;
		auxiliaryChannel: boolean;
	};
	outgoing: {
		channelId: Buffer;
		peerPubkey: string;
		wireAmountMsat: bigint;
		amountMsat: bigint;
		auxiliaryChannel: boolean;
	};
	feeMsat: bigint;
}

type Gate = (forward: IGated) => unknown;

const setGate = (w: IForwardWorld, gate: Gate | undefined): void =>
	(
		w.hosts.bob.node as unknown as {
			setAuxiliaryForwardGate: (gate: Gate | undefined) => void;
		}
	).setAuxiliaryForwardGate(gate);

describe('a gate refuses a forward with an asset leg before anything is offered (issue #2098, step 7)', function () {
	this.timeout(240_000);
	withAssetOpens();
	withAssetForwards();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	/** A scene whose Bob has `gate` set before Alice pays; what it was given. */
	async function gated(
		tag: string,
		shape: Shape,
		gate: Gate,
		options: ISceneOptions = {}
	): Promise<{ s: IScene; given: IGated[] }> {
		const given: IGated[] = [];
		const s = await openScene(world, tag, shape, {
			...options,
			beforeSend: (opened) => {
				setGate(opened.w, (forward) => {
					given.push(forward);
					return gate(forward);
				});
				options.beforeSend?.(opened);
			}
		});
		return { s, given };
	}

	/** What a refusal leaves: nothing offered or linked, the payer failed, the host told. */
	async function refusedBy(s: IScene, said: string): Promise<void> {
		await rounds(
			'the payer failed',
			() =>
				s.w.hosts.alice.node.getPayment(s.held.paymentHash)?.status === 'FAILED'
		);
		const out = s.w.hosts.bob.node
			.getChannelManager()
			.getChannel(s.w.outChannel)!
			.getFullState();
		expect(
			[...out.htlcs.values()].filter(
				(entry) => entry.direction === HtlcDirection.OFFERED
			),
			'nothing offered'
		).to.have.length(0);
		expect(out.localHtlcCounter).to.equal(0n);
		expect(s.w.hosts.bob.storage!.loadAllForwardedHtlcs()).to.have.length(0);
		await rounds('both ends told', () => s.told.length >= 2);
		expect(legEnds(s)).to.deep.equal([
			'incoming:failed',
			'outgoing:never-offered'
		]);
		const declined = s.logs.filter(
			(log) => log.action === 'asset_forward_declined'
		);
		expect(declined).to.have.length(1);
		expect(String(declined[0].data.reason)).to.contain(said);
		expect(s.w.hosts.bob.node.listForwards()).to.have.length(0);
	}

	const SHAPES: Array<{ shape: Shape; quote: boolean }> = [
		{ shape: ['ordinary', 'asset'], quote: false },
		{ shape: ['ordinary', 'asset'], quote: true },
		{ shape: ['asset', 'ordinary'], quote: false },
		{ shape: ['asset', 'asset'], quote: false },
		{ shape: ['asset', 'asset'], quote: true }
	];

	for (const { shape, quote } of SHAPES) {
		const tag = `${shape.join('-')}${quote ? '-q' : ''}`;

		it(`${shapeName(shape)}${
			quote ? ', by a quote' : ''
		}: a refusal by a string offers nothing, fails the payer back and tells the host`, async () => {
			const { s, given } = await gated(
				`fwd-gate-str-${tag}`,
				shape,
				() => 'not today',
				{ quote, held: false }
			);
			expect(given).to.have.length(1);
			await refusedBy(s, 'not today');
		});

		it(`${shapeName(shape)}${
			quote ? ', by a quote' : ''
		}: is given the forward as the contract says, and copies it may change`, async () => {
			const { s, given } = await gated(
				`fwd-gate-given-${tag}`,
				shape,
				(forward) => {
					// Changing what it was given changes nothing of the forward.
					forward.paymentHash.fill(0);
					forward.shortChannelId.fill(0);
					forward.incoming.channelId.fill(0);
					forward.outgoing.channelId.fill(0);
					return undefined;
				},
				{ quote }
			);
			expect(given).to.have.length(1);
			const forward = given[0];
			const [inKind, outKind] = shape;
			const worth = incomingWorth(shape);
			expect(forward.incoming).to.deep.include({
				peerPubkey: s.w.hosts.alice.node.getNodeId(),
				htlcId: 0n,
				wireAmountMsat:
					inKind === 'asset' ? FORWARD_CARRIER_MSAT : INCOMING_MSAT,
				valueMsat: worth,
				auxiliaryChannel: inKind === 'asset'
			});
			expect(forward.incoming.auxiliaryAmount).to.equal(
				inKind === 'asset' ? INCOMING_UNITS : undefined
			);
			expect(forward.outgoing).to.deep.include({
				peerPubkey: s.w.hosts.carol.node.getNodeId(),
				wireAmountMsat:
					outKind === 'asset' ? FORWARD_CARRIER_MSAT : FORWARD_MSAT,
				amountMsat: FORWARD_MSAT,
				auxiliaryChannel: outKind === 'asset'
			});
			expect(forward.feeMsat).to.equal(worth - FORWARD_MSAT);
			// The forward went on as if the gate had changed nothing.
			await settleAtCarol(s);
			const [row] = s.w.hosts.bob.node.listForwards();
			expect(row).to.deep.include({
				inChannelId: s.w.inChannel.toString('hex'),
				outChannelId: s.w.outChannel.toString('hex'),
				nextHopScid: s.next.toString('hex'),
				amountInMsat: worth
			});
		});
	}

	it('a refusal with its own code logs the code and the sentence', async () => {
		const { s } = await gated(
			'fwd-gate-code',
			['asset', 'asset'],
			() => ({ reason: 'SERVICE_DRAINING', message: 'the node is draining' }),
			{ held: false }
		);
		await refusedBy(s, 'the node is draining');
		const declined = s.logs.find(
			(log) => log.action === 'asset_forward_declined'
		)!;
		expect(declined.data.gateReason).to.equal('SERVICE_DRAINING');
	});

	it('a gate that throws refuses', async () => {
		const { s } = await gated(
			'fwd-gate-throw',
			['ordinary', 'asset'],
			() => {
				throw new Error('limits unreadable');
			},
			{ held: false }
		);
		await refusedBy(s, 'limits unreadable');
	});

	it('a gate that answers with a promise refuses', async () => {
		const { s } = await gated(
			'fwd-gate-promise',
			['asset', 'ordinary'],
			() => Promise.resolve(undefined),
			{ held: false }
		);
		await refusedBy(s, 'promise');
	});

	// Found by the independent review of this step: what the gate threw or
	// answered was read outside any guard, so an answer the node could not
	// read left the forward stuck until a backstop failed it near expiry.
	it('a gate whose throw cannot be read refuses at once', async () => {
		const { s, given } = await gated(
			'fwd-gate-unreadable-throw',
			['ordinary', 'asset'],
			() => {
				// No prototype: String() of it throws.
				throw Object.create(null);
			},
			{ held: false }
		);
		expect(given).to.have.length(1);
		await refusedBy(s, 'could not be read');
	});

	it("a gate whose refusal's sentence cannot be read refuses at once", async () => {
		const { s } = await gated(
			'fwd-gate-unreadable-refusal',
			['asset', 'ordinary'],
			() => ({
				reason: 'POLICY',
				get message(): string {
					throw new Error('message unreadable');
				}
			}),
			{ held: false }
		);
		await refusedBy(s, 'could not be read');
	});

	it("a host whose throw cannot be read is refused at once, as any host's throw is", async () => {
		const s = await openScene(
			world,
			'fwd-host-unreadable-throw',
			['asset', 'ordinary'],
			{
				answer: () => {
					throw Object.create(null);
				},
				held: false
			}
		);
		await rounds(
			'the payer failed',
			() =>
				s.w.hosts.alice.node.getPayment(s.held.paymentHash)?.status === 'FAILED'
		);
		expect(s.asked).to.have.length(1);
		const out = s.w.hosts.bob.node
			.getChannelManager()
			.getChannel(s.w.outChannel)!
			.getFullState();
		expect(out.localHtlcCounter).to.equal(0n);
		const declined = s.logs.filter(
			(log) => log.action === 'asset_forward_declined'
		);
		expect(declined).to.have.length(1);
		expect(String(declined[0].data.reason)).to.contain('the host refused');
	});

	it('a gate set and then removed is not asked, and the forward goes on', async () => {
		let asked = 0;
		const s = await openScene(world, 'fwd-gate-removed', ['asset', 'asset'], {
			beforeSend: (opened) => {
				setGate(opened.w, () => {
					asked++;
					return 'refused';
				});
				setGate(opened.w, undefined);
			}
		});
		await settleAtCarol(s);
		expect(asked).to.equal(0);
		expect(s.w.hosts.bob.node.listForwards()).to.have.length(1);
	});

	it('is never asked about an ordinary forward', async () => {
		const { s, given } = await gated(
			'fwd-gate-ordinary',
			['ordinary', 'ordinary'],
			() => 'refused'
		);
		await settleAtCarol(s);
		expect(given).to.have.length(0);
	});

	it('is never asked about a forward its host does not take', async () => {
		const { s, given } = await gated(
			'fwd-gate-host-refused',
			['asset', 'asset'],
			() => undefined,
			{ answer: () => undefined, held: false }
		);
		await rounds(
			'the payer failed',
			() =>
				s.w.hosts.alice.node.getPayment(s.held.paymentHash)?.status === 'FAILED'
		);
		expect(s.asked).to.have.length(1);
		expect(given).to.have.length(0);
	});

	it("is never asked about a forward the node's own checks refused before it", async () => {
		const { s, given } = await gated(
			'fwd-gate-engine-refused',
			['asset', 'ordinary'],
			() => undefined,
			{
				// Short of the amount to forward and the fee.
				answer: () => ({ incomingValueMsat: FORWARD_MSAT - 1n }),
				held: false
			}
		);
		await rounds(
			'the payer failed',
			() =>
				s.w.hosts.alice.node.getPayment(s.held.paymentHash)?.status === 'FAILED'
		);
		expect(s.asked).to.have.length(1);
		expect(given).to.have.length(0);
	});

	it('a forward the gate let through may still be refused by the channel at the add', async () => {
		const { s, given } = await gated(
			'fwd-gate-then-add',
			['asset', 'asset'],
			() => undefined,
			{
				// More units than Bob holds on his channel with Carol.
				answer: (_request, terms) => ({
					...terms,
					outgoingHtlc: {
						customRecords: amountRecord(99_999n),
						wireAmountMsat: FORWARD_CARRIER_MSAT
					}
				}),
				held: false
			}
		);
		await rounds('the refusal', () => s.refused.length >= 1);
		expect(given).to.have.length(1);
		expect(given[0].incoming.valueMsat).to.equal(
			INCOMING_UNITS * MSAT_PER_UNIT
		);
		expect(s.refused[0].auxiliary).to.equal(true);
	});
});
