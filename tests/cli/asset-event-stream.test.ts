/**
 * What two daemons stream of an asset channel between them, and of an
 * ordinary one (issue #2093).
 *
 * Two daemons with an asset channel provider are joined over a loopback.
 * An asset channel is opened between them, an asset payment is sent each
 * way, one is held and settled and one is held and failed back. Everything
 * each daemon relays of it is read twice, as its SSE stream and as the
 * bodies its webhook delivers, and every event of the asset channel, of
 * its payments, of the invoices they paid and of its holds says
 * `auxiliary: true`. Each asset payment is sent over the route the node
 * itself finds for the asset channel (`queryAuxiliaryRoute`), as a host
 * sends one, and its event carries the fee of that route as a number.
 *
 * The same is then done over an ordinary channel between the same two
 * wallets, which by then hold the asset channel and its payments. What
 * they stream of it is the bytes pinned below, which the same flow printed
 * on master (4fdaeb60) from tests/cli/helpers/event-stream.ts: no event of
 * an ordinary channel has a field it did not have.
 */

import { expect } from 'chai';
import {
	EXTENSION_API_VERSION,
	IBeignetExtension
} from '../../src/cli/extension';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryFundingDescriptor
} from '../../src/lightning/channel/auxiliary-funding';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from '../lightning/helpers/auxiliary-nodes';
import {
	amountRecord,
	referenceProvider
} from '../lightning/helpers/auxiliary-pair';
import { createHash } from 'crypto';
import {
	asWebhookSends,
	bootStreamDaemon,
	IStreamDaemon,
	joinStreamDaemons,
	normalise,
	ordinaryFlow,
	STREAM_MNEMONICS,
	streamsDrained,
	streamTurns,
	TFrame
} from './helpers/event-stream';

/**
 * What master streams of the ordinary flow, by daemon: `alice` opens the
 * channel and `bob` holds the two held payments.
 */
const MASTER = {
	alice: [
		'channel:opening {"channelId":"<hex1>","fundingTxid":"<hex2>"}',
		'channel:ready {"channelId":"<hex1>"}',
		'payment:sent {"paymentHash":"<hex3>","amountSats":20000,"status":"COMPLETED","direction":"OUTGOING","createdAt":<time>,"preimage":"<hex4>","completedAt":<time>,"feeSats":0,"route":{"hops":[{"pubkey":"<hex5>","shortChannelId":"<hex6>","feeMsat":0}],"totalFeeMsat":0,"hopCount":1},"metadata":{"_invoice":"<bolt11>"}}',
		'payment:received {"paymentHash":"<hex7>","amountSats":7000,"status":"COMPLETED","direction":"INCOMING","createdAt":<time>,"preimage":"<hex8>","completedAt":<time>}',
		'invoice:settled {"paymentHash":"<hex7>","bolt11":"<bolt11>","amountSats":7000}',
		'payment:sent {"paymentHash":"<hex9>","amountSats":5000,"status":"COMPLETED","direction":"OUTGOING","createdAt":<time>,"preimage":"<hex10>","completedAt":<time>,"feeSats":0,"route":{"hops":[{"pubkey":"<hex5>","shortChannelId":"<hex6>","feeMsat":0}],"totalFeeMsat":0,"hopCount":1},"metadata":{"_invoice":"<bolt11>"}}',
		'payment:failed {"paymentHash":"<hex11>","amountSats":3000,"status":"FAILED","direction":"OUTGOING","createdAt":<time>,"completedAt":<time>,"failureCode":16399,"failureDescription":"PERM|incorrect_or_unknown_payment_details","feeSats":0,"route":{"hops":[{"pubkey":"<hex5>","shortChannelId":"<hex6>","feeMsat":0}],"totalFeeMsat":0,"hopCount":1}}'
	],
	bob: [
		'channel:opening {"channelId":"<hex1>","fundingTxid":"<hex2>"}',
		'channel:ready {"channelId":"<hex1>"}',
		'payment:received {"paymentHash":"<hex3>","amountSats":20000,"status":"COMPLETED","direction":"INCOMING","createdAt":<time>,"preimage":"<hex4>","completedAt":<time>}',
		'invoice:settled {"paymentHash":"<hex3>","bolt11":"<bolt11>","amountSats":20000}',
		'payment:sent {"paymentHash":"<hex5>","amountSats":7000,"status":"COMPLETED","direction":"OUTGOING","createdAt":<time>,"preimage":"<hex6>","completedAt":<time>,"feeSats":0,"route":{"hops":[{"pubkey":"<hex7>","shortChannelId":"<hex8>","feeMsat":0}],"totalFeeMsat":0,"hopCount":1},"metadata":{"_invoice":"<bolt11>"}}',
		'hold:accepted {"paymentHash":"<hex9>","state":"ACCEPTED","heldAmountMsat":"5000000","htlcCount":1,"minFinalCltvExpiry":40,"earliestExpiry":44,"cancelMarginBlocks":18,"cancelHeight":26}',
		'payment:received {"paymentHash":"<hex9>","amountSats":5000,"status":"COMPLETED","direction":"INCOMING","createdAt":<time>,"preimage":"<hex10>","completedAt":<time>}',
		'invoice:settled {"paymentHash":"<hex9>","bolt11":"<bolt11>","amountSats":5000}',
		'hold:settled {"paymentHash":"<hex9>","state":"SETTLED","heldAmountMsat":"5000000","htlcCount":1,"minFinalCltvExpiry":40,"earliestExpiry":44,"cancelMarginBlocks":18,"cancelHeight":26}',
		'hold:accepted {"paymentHash":"<hex11>","state":"ACCEPTED","heldAmountMsat":"3000000","htlcCount":1,"minFinalCltvExpiry":40,"earliestExpiry":44,"cancelMarginBlocks":18,"cancelHeight":26}',
		'hold:cancelled {"paymentHash":"<hex11>","state":"CANCELLED","heldAmountMsat":"3000000","htlcCount":1,"minFinalCltvExpiry":40,"earliestExpiry":44,"cancelMarginBlocks":18,"cancelHeight":26,"reason":"api"}'
	]
};

const sha = (data: Buffer | string): Buffer =>
	createHash('sha256').update(data).digest();

/** An extension that supplies the node's asset channels, and nothing else. */
const assets = (given: IAuxiliaryChannelConfig): IBeignetExtension => ({
	id: 'assets',
	version: '1.0.0',
	api: EXTENSION_API_VERSION,
	attach: () => ({ auxiliaryChannels: given })
});

/** What a peer that runs asset channels advertises in its init. */
const assetPeerFeatures = (): FeatureFlags => {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.STATIC_REMOTE_KEY);
	flags.setOptional(Feature.OPTION_TAPROOT);
	flags.setOptional(Feature.OPTION_TAPROOT_OVERLAY);
	return flags;
};

const names = (frames: TFrame[]): string[] => frames.map(([event]) => event);

const dataOf = (frames: TFrame[], event: string): Record<string, unknown>[] =>
	frames
		.filter(([name]) => name === event)
		.map(([, data]) => JSON.parse(data) as Record<string, unknown>);

/**
 * An asset payment as a host sends one: over the route the node itself
 * finds for the asset channel, with the units in the record the provider
 * reads. A route written by hand has no totals, and an event of a payment
 * sent over one has no fee to say.
 */
const payUnits = (
	payer: IAssetHost,
	payee: IAssetHost,
	channelId: Buffer,
	invoice: { paymentHash: Buffer; paymentSecret?: Buffer },
	units: bigint
): void => {
	const route = payer.node.queryAuxiliaryRoute(
		channelId,
		Buffer.from(payee.node.getNodeId(), 'hex'),
		units * 1000n,
		units * 1000n
	);
	expect(route, 'a route over the asset channel').to.not.equal(null);
	expect(route!.hops).to.have.length(1);
	expect(route!.totalFeeMsat).to.equal(0n);
	payer.node.sendPaymentToRoute(
		route!,
		invoice.paymentHash,
		40,
		invoice.paymentSecret,
		undefined,
		undefined,
		undefined,
		undefined,
		{
			assetPayment: {
				channelId,
				wireAmountMsat: 354_000n,
				customRecords: amountRecord(units)
			}
		}
	);
};

/** The frames as a webhook sends them, in an order two lists can share. */
const sorted = (frames: TFrame[]): string[] =>
	frames.map(([event, data]) => `${event} ${data}`).sort();

describe('What two daemons stream of an asset channel and of an ordinary one (issue #2093 step 8)', function () {
	this.timeout(120_000);
	withAssetOpens();
	const daemons: IStreamDaemon[] = [];

	afterEach(async () => {
		for (const daemon of daemons.splice(0)) await daemon.close();
	});

	/** A daemon with an asset channel provider, as a host of asset channels. */
	const boot = async (
		tag: string,
		mnemonic: string
	): Promise<{ daemon: IStreamDaemon; host: IAssetHost }> => {
		const incoming = new Map<string, IAuxiliaryFundingDescriptor>();
		const daemon = await bootStreamDaemon(tag, mnemonic, {
			extensions: [
				assets({
					provider: referenceProvider(),
					allowLegacyHtlcSignatures: () => true,
					resolveIncoming: (_peer, id) => incoming.get(id.toString('hex')),
					// An HTLC without units is not the host's to value.
					valueIncomingHtlc: (context) =>
						context.auxiliaryAmount === undefined
							? undefined
							: context.auxiliaryAmount * 1000n
				})
			]
		});
		daemons.push(daemon);
		// The loopback exchanges no init, so the node is told what its peer
		// advertises in place of reading it.
		(
			daemon.node as unknown as { peerInitFeatures: () => FeatureFlags }
		).peerInitFeatures = assetPeerFeatures;
		const errors: string[] = [];
		daemon.node.on(
			'node:error',
			(error: { code?: string; message?: string }) => {
				errors.push(`${error.code ?? ''}: ${error.message ?? ''}`);
			}
		);
		return {
			daemon,
			host: { node: daemon.node, incoming, broadcasts: [], errors }
		};
	};

	it('marks every event of the asset channel, its payments, its invoices and its holds over SSE and webhooks, and streams an ordinary channel between the same wallets in the bytes master streams', async () => {
		const { daemon: alice, host: aliceHost } = await boot(
			'alice',
			STREAM_MNEMONICS[0]
		);
		const { daemon: bob, host: bobHost } = await boot(
			'bob',
			STREAM_MNEMONICS[1]
		);
		joinStreamDaemons(alice, bob);

		// The asset channel, a payment each way, one held and settled and
		// one held and failed back.
		const channelId = await openAssetChannel(aliceHost, bobHost, {
			tag: 'event stream',
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		await streamTurns();
		const there = bob.node.createInvoice({
			amountMsat: 1_000_000n,
			description: 'units there'
		});
		payUnits(aliceHost, bobHost, channelId, there, 1000n);
		await streamTurns();
		const back = alice.node.createInvoice({
			amountMsat: 500_000n,
			description: 'units back'
		});
		payUnits(bobHost, aliceHost, channelId, back, 500n);
		await streamTurns();
		const preimage = sha('units held and settled');
		const held = bob.node.createInvoice({
			amountMsat: 2_000_000n,
			description: 'units held',
			hold: true,
			paymentHash: sha(preimage)
		});
		payUnits(aliceHost, bobHost, channelId, held, 2000n);
		await streamTurns();
		expect(bob.node.settleHeldHtlc(sha(preimage), preimage)).to.equal(true);
		await streamTurns();
		const refused = sha(sha('units held and failed back'));
		const failed = bob.node.createInvoice({
			amountMsat: 1_500_000n,
			description: 'units failed back',
			hold: true,
			paymentHash: refused
		});
		payUnits(aliceHost, bobHost, channelId, failed, 1500n);
		await streamTurns();
		expect(bob.node.cancelHoldInvoice(refused)?.htlcsFailed).to.equal(1);
		await streamTurns();
		await streamsDrained([alice, bob]);
		// These daemons have no chain to watch or to broadcast to, and say
		// so; nothing else went wrong.
		expect(
			[...aliceHost.errors, ...bobHost.errors].filter(
				(error) =>
					!error.startsWith('FUNDING_BROADCAST_FAILED') &&
					!error.startsWith('CHAIN_WATCHER_START_FAILED')
			)
		).to.deep.equal([]);

		const asset = {
			alice: { sse: alice.sse.splice(0), hooks: alice.hooks.splice(0) },
			bob: { sse: bob.sse.splice(0), hooks: bob.hooks.splice(0) }
		};
		expect(names(asset.alice.sse)).to.deep.equal([
			'channel:opening',
			'channel:ready',
			'payment:sent',
			'payment:received',
			'invoice:settled',
			'payment:sent',
			'payment:failed'
		]);
		expect(names(asset.bob.sse)).to.deep.equal([
			'channel:opening',
			'channel:ready',
			'payment:received',
			'invoice:settled',
			'payment:sent',
			'hold:accepted',
			'payment:received',
			'invoice:settled',
			'hold:settled',
			'hold:accepted',
			'hold:cancelled'
		]);
		for (const [who, stream] of Object.entries(asset)) {
			// Every one of them says it is an asset's, on both ways out.
			for (const [event, data] of [...stream.sse, ...stream.hooks]) {
				expect(
					(JSON.parse(data) as { auxiliary?: unknown }).auxiliary,
					`${who} ${event} ${data}`
				).to.equal(true);
			}
			// A webhook is sent what the stream carried, less the preimage.
			expect(sorted(stream.hooks), who).to.deep.equal(
				sorted(stream.sse.map(asWebhookSends))
			);
		}
		const id = channelId.toString('hex');
		for (const stream of [asset.alice.sse, asset.bob.sse]) {
			expect(dataOf(stream, 'channel:opening')[0].channelId).to.equal(id);
			expect(dataOf(stream, 'channel:ready')[0].channelId).to.equal(id);
		}
		// What an asset payment out was worth to its payee is beside the
		// bitcoin that carried it.
		expect(
			dataOf(asset.alice.sse, 'payment:sent').map(
				(data) => data.auxiliaryValueSats
			)
		).to.deep.equal([1000, 2000]);
		expect(
			dataOf(asset.bob.sse, 'payment:sent').map(
				(data) => data.auxiliaryValueSats
			)
		).to.deep.equal([500]);
		// Each went out over the route the node found for it, so its event
		// says what the route cost as a number: nothing, over a channel
		// with the payee itself.
		for (const [who, stream] of Object.entries(asset)) {
			for (const frames of [stream.sse, stream.hooks]) {
				const out = [
					...dataOf(frames, 'payment:sent'),
					...dataOf(frames, 'payment:failed')
				];
				expect(out, who).to.have.length(who === 'alice' ? 3 : 1);
				for (const data of out) {
					expect(data.feeSats, who).to.equal(0);
					expect(data.route, who).to.include({
						totalFeeMsat: 0,
						hopCount: 1
					});
				}
			}
		}
		// A hold says what the node holds for the HTLC.
		expect(
			[
				...dataOf(asset.bob.sse, 'hold:accepted'),
				...dataOf(asset.bob.sse, 'hold:settled'),
				...dataOf(asset.bob.sse, 'hold:cancelled')
			].map((data) => [data.state, data.heldAmountMsat])
		).to.deep.equal([
			['ACCEPTED', '2000000'],
			['ACCEPTED', '1500000'],
			['SETTLED', '2000000'],
			['CANCELLED', '1500000']
		]);

		// The same over an ordinary channel between the same two wallets.
		await ordinaryFlow(alice, bob);
		await streamsDrained([alice, bob]);
		expect(normalise(alice.sse)).to.deep.equal(MASTER.alice);
		expect(normalise(bob.sse)).to.deep.equal(MASTER.bob);
		for (const daemon of [alice, bob]) {
			expect(sorted(daemon.hooks)).to.deep.equal(
				sorted(daemon.sse.map(asWebhookSends))
			);
			for (const [, data] of [...daemon.sse, ...daemon.hooks]) {
				expect(data).to.not.include('auxiliary');
			}
		}
	});

	it('streams the ordinary flow in the bytes master streams from two wallets that hold nothing else', async () => {
		const { daemon: alice } = await boot('alice', STREAM_MNEMONICS[0]);
		const { daemon: bob } = await boot('bob', STREAM_MNEMONICS[1]);
		joinStreamDaemons(alice, bob);
		await ordinaryFlow(alice, bob);
		await streamsDrained([alice, bob]);
		// BEIGNET_PRINT_STREAM=1 prints what this build streams, in the
		// form pinned above.
		if (process.env.BEIGNET_PRINT_STREAM === '1') {
			process.stdout.write(
				`${JSON.stringify({
					alice: normalise(alice.sse),
					bob: normalise(bob.sse)
				})}\n`
			);
		}
		expect(normalise(alice.sse)).to.deep.equal(MASTER.alice);
		expect(normalise(bob.sse)).to.deep.equal(MASTER.bob);
	});
});
