/**
 * Issue #2098, step 8: an asset invoice paid in parts. A host that opts in
 * (`receiveInParts: true`) has its node collect the HTLCs that carry units
 * and belong to one set, each at the value the host gives it, and settle
 * them together once the set is worth what its parts declare: the set's
 * records are written alone first, then every part gets its settle
 * decision, then its fulfil. A set with a part at risk is failed back whole
 * before anything is written or revealed. Without the opt-in, with the
 * build's switch off, or without BASIC_MPP, such a part is refused as
 * before, byte for byte.
 *
 * Most cases run bitcoin in, asset out, on the chain world of
 * auxiliary-forward-world.ts: Alice pays an ordinary invoice of Carol's in
 * parts, Bob's host makes each part an asset HTLC to Carol. The cases a
 * payer of this build cannot send (a plain part beside an asset one, a
 * part from a second peer, a hold invoice's parts) put hand-built HTLCs on
 * two loopback nodes.
 *
 * Written first: on the build before step 8 the cases of new behaviour
 * fail and the regression cases pass. The contract is "An asset invoice
 * paid in parts" in docs/EXTENSIONS.md.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { AUXILIARY_CHANNELS_API } from '../../src/lightning/channel/auxiliary-api';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import type { IAuxiliaryIncomingHtlc } from '../../src/lightning/channel/auxiliary-funding';
import { HtlcState } from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	computeMerkleRootFromRecords,
	computeSignatureHash,
	encodeInvoiceRequestTlv,
	encodeOfferTlv,
	getTlvRecords,
	schnorrSign,
	type IBolt12Invoice,
	type IInvoiceRequest
} from '../../src/lightning/offer';
import {
	constructOnionPacket,
	encodeOnionPacket
} from '../../src/lightning/onion/construct';
import {
	aliasOf,
	forwardChainWorld,
	partsInvoice,
	payInParts,
	sendPart,
	type IPartsInvoice
} from './helpers/auxiliary-forward-world';
import {
	QUOTE_RECORD,
	listenCarol,
	openPartsScene,
	rounds,
	type IPartQuote,
	type IPartsScene
} from './helpers/auxiliary-forward-scene';
import {
	RECEIVE_IN_PARTS,
	assetHost,
	connectHosts,
	openAssetChannel,
	turns,
	withAssetForwards,
	withAssetOpens,
	withAssetPartsReceived,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { amountRecord, hash } from './helpers/auxiliary-pair';
import { openReadyChannel } from './helpers/loopback-nodes';

type Log = { category: string; action: string; data: Record<string, unknown> };
type PendingSets = Map<
	string,
	{
		totalMsat: bigint;
		receivedParts: Array<{
			channelId: Buffer;
			htlcId: bigint;
			amountMsat: bigint;
			status: string;
		}>;
	}
>;

const hex = (value: Buffer): string => value.toString('hex');
const sha256 = (value: Buffer): Buffer =>
	crypto.createHash('sha256').update(value).digest();

/** The parts a host collects for a hash, still pending, in its set. */
const collected = (host: IAssetHost, paymentHash: Buffer): number =>
	(
		(
			host.node as unknown as { pendingMppPayments: PendingSets }
		).pendingMppPayments.get(hex(paymentHash))?.receivedParts ?? []
	).filter((part) => part.status === PaymentStatus.PENDING).length;

/** The HTLCs a host has received for a hash on a channel, still committed there. */
const heldOn = (
	host: IAssetHost,
	channelId: Buffer,
	paymentHash: Buffer
): number =>
	[
		...(host.node.getChannelManager().getChannel(channelId)?.getFullState()
			.htlcs ?? new Map())
	].filter(
		([key, entry]) =>
			key.startsWith('received-') &&
			entry.paymentHash.equals(paymentHash) &&
			entry.state === HtlcState.COMMITTED
	).length;

const decisionOf = (
	host: IAssetHost,
	channelId: Buffer,
	htlcId: bigint
): string | undefined =>
	host.node.getChannelManager().auxiliaryHtlcDecision(channelId, htlcId)
		?.outcome;

const metadataOf = (
	payment: object | undefined
): Record<string, string> | undefined =>
	(payment as { metadata?: Record<string, string> } | undefined)?.metadata;

const refusalsIn = (logs: Log[], paymentHash: Buffer): Log[] =>
	logs.filter(
		(log) =>
			log.action === 'asset_multi_part_refused' &&
			log.data.paymentHash === hex(paymentHash)
	);

const unitsOf = (host: IAssetHost, channelId: Buffer): bigint =>
	host.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance;

/** The settle decisions and fulfils a host's channel manager was asked for, in order. */
interface IWatch {
	decisions: Array<{ key: string; outcome: string; written: boolean }>;
	/** Each fulfil, with the parts whose settle decision was written before it. */
	fulfils: Array<{ key: string; decidedBefore: string[] }>;
}
function watchManager(host: IAssetHost): IWatch {
	const watch: IWatch = { decisions: [], fulfils: [] };
	const manager = host.node.getChannelManager();
	const decide = manager.recordAuxiliaryHtlcDecision.bind(manager);
	manager.recordAuxiliaryHtlcDecision = (
		channelId,
		htlcId,
		outcome,
		preimage
	): boolean => {
		const written = decide(channelId, htlcId, outcome, preimage);
		watch.decisions.push({
			key: `${hex(channelId)}:${htlcId}`,
			outcome,
			written
		});
		return written;
	};
	const fulfil = manager.fulfillHtlc.bind(manager);
	manager.fulfillHtlc = (
		channelId,
		htlcId,
		preimage
	): ReturnType<typeof fulfil> => {
		watch.fulfils.push({
			key: `${hex(channelId)}:${htlcId}`,
			decidedBefore: watch.decisions
				.filter((decision) => decision.outcome === 'settle' && decision.written)
				.map((decision) => decision.key)
		});
		return fulfil(channelId, htlcId, preimage);
	};
	return watch;
}

describe('an asset invoice paid in parts (issue #2098, step 8)', function () {
	this.timeout(120_000);
	withAssetOpens();
	withAssetForwards();
	withAssetPartsReceived();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	/** What Carol's host was asked about the parts of an invoice, in order. */
	const asksFor = (
		s: IPartsScene,
		invoice: IPartsInvoice
	): IAuxiliaryIncomingHtlc[] =>
		s.carolAsks.filter((ask) => ask.paymentHash.equals(invoice.paymentHash));
	const partKey = (part: { channelId: Buffer; htlcId: bigint }): string =>
		`${hex(part.channelId)}:${part.htlcId}`;
	const carolsRecord = (
		s: IPartsScene,
		invoice: IPartsInvoice
	): ReturnType<LightningNode['getPayment']> =>
		s.w.hosts.carol.node.getPayment(invoice.paymentHash);
	const alicesStatus = (
		s: IPartsScene,
		invoice: IPartsInvoice
	): PaymentStatus | undefined =>
		s.w.hosts.alice.node.getPayment(invoice.paymentHash)?.status;
	const alicePaid = async (
		s: IPartsScene,
		invoice: IPartsInvoice
	): Promise<void> => {
		await rounds(
			'Alice is paid',
			() => alicesStatus(s, invoice) === PaymentStatus.COMPLETED,
			60
		);
		await turns(100);
	};
	const aliceFailed = (s: IPartsScene, invoice: IPartsInvoice): Promise<void> =>
		rounds(
			'the payment fails at Alice',
			() => alicesStatus(s, invoice) === PaymentStatus.FAILED,
			60
		);

	/** A set that was not settled: logged, nothing written, nothing revealed. */
	async function expectNotSettled(
		s: IPartsScene,
		invoice: IPartsInvoice,
		reason: string,
		watch: IWatch
	): Promise<void> {
		const logged = s.carolLogs.filter(
			(log) =>
				log.action === 'asset_set_not_settled' &&
				log.data.paymentHash === hex(invoice.paymentHash)
		);
		expect(
			[...new Set(logged.map((log) => log.data.reason))],
			'the set is not settled, with its reason'
		).to.deep.equal([reason]);
		// Bob never learns the preimage, however often the link comes back.
		for (let i = 0; i < 2; i++) {
			world.cut(s.w, 'out');
			await world.reconnect(s.w, 'out');
		}
		await aliceFailed(s, invoice);
		await turns(100);
		expect(watch.fulfils, 'no fulfil was tried').to.deep.equal([]);
		expect(
			watch.decisions.filter((decision) => decision.outcome === 'settle'),
			'no settle decision was written'
		).to.deep.equal([]);
		expect(
			s.w.hosts.alice.node.getPayment(invoice.paymentHash)?.preimage,
			'nothing was revealed'
		).to.equal(undefined);
		expect(carolsRecord(s, invoice)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
		expect(
			s.received.filter((payment) =>
				payment.paymentHash.equals(invoice.paymentHash)
			)
		).to.deep.equal([]);
		for (const ask of asksFor(s, invoice)) {
			expect(
				decisionOf(s.w.hosts.carol, ask.channelId, ask.htlcId),
				`no settle decision for ${partKey(ask)}`
			).to.not.equal('settle');
		}
		expect(
			heldOn(s.w.hosts.carol, s.w.outChannel, invoice.paymentHash)
		).to.equal(0);
		expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(1000n);
	}

	describe('collected and settled', () => {
		it('two parts under one quote are settled together, the host asked once per part and the second time with the first part at its value', async () => {
			const tag = 'parts-one-quote';
			const s = await openPartsScene(world, tag);
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
			await rounds(
				'Carol is asked about both parts',
				() => asksFor(s, invoice).length >= 2
			);
			const asks = asksFor(s, invoice);
			expect(asks[0].acceptedHtlcs).to.deep.equal([]);
			expect(
				asks[1].acceptedHtlcs.map((part) => ({
					key: partKey(part),
					amountMsat: part.amountMsat
				}))
			).to.deep.equal([
				{
					key: partKey(asks[0]),
					amountMsat: asks[0].auxiliaryAmount! * 1000n
				}
			]);
			await alicePaid(s, invoice);
			expect(
				asksFor(s, invoice).length,
				'the host is asked once per part'
			).to.equal(2);
			const record = carolsRecord(s, invoice)!;
			expect(record.status).to.equal(PaymentStatus.COMPLETED);
			expect(record.settledHtlcs).to.have.members(asks.map(partKey));
			// The units moved: 3000 and 2000 to Carol, who held 1000.
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(6000n);
			expect(
				heldOn(s.w.hosts.carol, s.w.outChannel, invoice.paymentHash)
			).to.equal(0);
		});

		it('two parts under two quotes are each valued at their own quote and settled together', async () => {
			const tag = 'parts-two-quotes';
			const quotes: IPartQuote[] = [
				{ id: 1, msatPerUnit: 1000n },
				{ id: 2, msatPerUnit: 500n }
			];
			const s = await openPartsScene(world, tag, {
				quotes,
				// The first part is priced under one quote, the second under another.
				quoteOf: (request) =>
					request.amountToForwardMsat === 3_000_000n ? quotes[0] : quotes[1]
			});
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
			await rounds(
				'Carol is asked about both parts',
				() => asksFor(s, invoice).length >= 2
			);
			const asks = asksFor(s, invoice);
			expect(
				asks.map((ask) => [
					ask.customRecords.get(QUOTE_RECORD)?.[0],
					ask.auxiliaryAmount
				])
			).to.have.deep.members([
				[1, 3000n],
				[2, 4000n]
			]);
			await alicePaid(s, invoice);
			const record = carolsRecord(s, invoice)!;
			expect(record.status).to.equal(PaymentStatus.COMPLETED);
			const values = JSON.parse(
				metadataOf(record)?._auxiliaryReceivedParts ?? '{}'
			) as Record<string, string>;
			expect(Object.values(values)).to.have.members(['3000000', '2000000']);
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(8000n);
		});

		it('the part that completes a set is topped up by under a unit per part, and the set settles at the invoice exactly', async () => {
			const tag = 'parts-rounding-top-up';
			const s = await openPartsScene(world, tag);
			// 3000 and 2999 units: 1000 msat short of the invoice of 6,000,000.
			const invoice = await payInParts(s.w, tag, [3_000_600n, 2_999_400n], {
				invoiceMsat: 6_000_000n
			});
			await rounds(
				'Carol is asked about both parts',
				() => asksFor(s, invoice).length >= 2
			);
			expect(
				asksFor(s, invoice).map((ask) => ask.auxiliaryAmount)
			).to.have.members([3000n, 2999n]);
			await alicePaid(s, invoice);

			const record = carolsRecord(s, invoice)!;
			expect(record.status).to.equal(PaymentStatus.COMPLETED);
			const values = JSON.parse(
				metadataOf(record)?._auxiliaryReceivedParts ?? '{}'
			) as Record<string, string>;
			expect(Object.values(values)).to.deep.equal(['3000000', '3000000']);
			// The values reach the invoice, so no other amount is recorded.
			expect(record.receivedMsat).to.equal(undefined);
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(6999n);
		});

		it('a host that does not top up leaves the set short: its parts are held, unsettled, until the timeout fails each back', async () => {
			const tag = 'parts-rounding-short';
			const s = await openPartsScene(world, tag, { topUp: false });
			const invoice = await payInParts(s.w, tag, [3_000_600n, 2_999_400n], {
				invoiceMsat: 6_000_000n
			});
			const carol = s.w.hosts.carol;
			expect(
				collected(carol, invoice.paymentHash),
				'both parts are held'
			).to.equal(2);
			expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(2);
			expect(carolsRecord(s, invoice)!.status).to.equal(PaymentStatus.PENDING);
			expect(alicesStatus(s, invoice)).to.equal(PaymentStatus.PENDING);

			// The set's time runs out.
			const timer = carol.node as unknown as {
				mppTimeoutMs: number;
				failTimedOutMppPayments: () => void;
			};
			timer.mppTimeoutMs = 0;
			await turns(2);
			timer.failTimedOutMppPayments();
			await aliceFailed(s, invoice);
			expect(collected(carol, invoice.paymentHash)).to.equal(0);
			expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(0);
			expect(carolsRecord(s, invoice)!.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(unitsOf(carol, s.w.outChannel)).to.equal(1000n);
		});

		it('eight parts on one channel are collected and settled together', async () => {
			const tag = 'parts-eight';
			const s = await openPartsScene(world, tag, { coins: 12 });
			const invoice = await payInParts(
				s.w,
				tag,
				Array.from({ length: 8 }, () => 500_000n),
				{ rounds: 16 }
			);
			await rounds(
				'Carol is asked about all eight parts',
				() => asksFor(s, invoice).length >= 8
			);
			await alicePaid(s, invoice);
			const record = carolsRecord(s, invoice)!;
			expect(record.status).to.equal(PaymentStatus.COMPLETED);
			expect(record.settledHtlcs?.length).to.equal(8);
			expect(
				record.settledHtlcs!.every((key) =>
					key.startsWith(`${hex(s.w.outChannel)}:`)
				)
			).to.equal(true);
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(5000n);
		});

		it('a ninth part on one channel is refused by Bob before anything is offered, while Carol holds the eight in the set', async () => {
			const tag = 'parts-ninth';
			const s = await openPartsScene(world, tag, { coins: 12 });
			const invoice = await payInParts(
				s.w,
				tag,
				Array.from({ length: 9 }, () => 500_000n),
				{ rounds: 16 }
			);
			await rounds(
				'Bob declines the ninth',
				() =>
					s.logs.some(
						(log) =>
							log.action === 'asset_forward_declined' &&
							/no more than 8/.test(String(log.data.reason))
					),
				40
			);
			const carol = s.w.hosts.carol;
			expect(asksFor(s, invoice).length, 'Carol never saw a ninth').to.equal(8);
			expect(collected(carol, invoice.paymentHash)).to.equal(8);
			expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(8);
			expect(carolsRecord(s, invoice)!.status).to.equal(PaymentStatus.PENDING);
		});

		it('a set over two asset channels of one peer is collected and settled together', async () => {
			const tag = 'parts-two-channels';
			const s = await openPartsScene(world, tag, {
				world: { secondOut: 'asset' }
			});
			const second = aliasOf(s.w.hosts.bob, s.w.outChannel2!);
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n], {
				part: (index) => (index === 1 ? { next: second } : {})
			});
			await rounds(
				'Carol is asked about both parts',
				() => asksFor(s, invoice).length >= 2
			);
			expect(
				asksFor(s, invoice).map((ask) => hex(ask.channelId))
			).to.have.members([hex(s.w.outChannel), hex(s.w.outChannel2!)]);
			await alicePaid(s, invoice);
			const record = carolsRecord(s, invoice)!;
			expect(record.status).to.equal(PaymentStatus.COMPLETED);
			expect(
				record.settledHtlcs!.map((key) => key.split(':')[0])
			).to.have.members([hex(s.w.outChannel), hex(s.w.outChannel2!)]);
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(4000n);
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel2!)).to.equal(3000n);
		});
	});

	describe('refused with nothing kept, as today (regression)', () => {
		/**
		 * Today's refusal, byte for byte: every asset part of the set is failed
		 * back at once, logged with exactly today's fields and no reason.
		 */
		async function todaysRefusal(
			tag: string,
			options: Parameters<typeof openPartsScene>[2]
		): Promise<void> {
			const s = await openPartsScene(world, tag, options);
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
			await aliceFailed(s, invoice);
			const asks = asksFor(s, invoice);
			expect(asks.length).to.equal(2);
			expect(
				refusalsIn(s.carolLogs, invoice.paymentHash).map((log) => log.data)
			).to.deep.equal(
				asks.map((ask) => ({
					paymentHash: hex(invoice.paymentHash),
					channelId: hex(ask.channelId),
					htlcId: ask.htlcId.toString(),
					valuedMsat: (ask.auxiliaryAmount! * 1000n).toString(),
					declaredTotalMsat: '5000000'
				}))
			);
			expect(collected(s.w.hosts.carol, invoice.paymentHash)).to.equal(0);
			expect(
				heldOn(s.w.hosts.carol, s.w.outChannel, invoice.paymentHash)
			).to.equal(0);
			expect(carolsRecord(s, invoice)!.status).to.equal(PaymentStatus.PENDING);
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(1000n);
		}

		it('without the opt-in, each asset part of a set is refused as today, the log included', async () => {
			await todaysRefusal('parts-no-opt-in', { optIn: false });
		});

		it('without BASIC_MPP among the node features, an opted-in host is refused each asset part as today', async () => {
			const features = LightningNode.defaultFeatures();
			features.clearBit(Feature.BASIC_MPP);
			features.clearBit(Feature.BASIC_MPP + 1);
			await todaysRefusal('parts-no-mpp', {
				world: { nodes: { carol: { localFeatures: features } } }
			});
		});

		describe('with the build switch off', () => {
			withAssetPartsReceived(false);
			it('an opted-in host is refused each asset part of a set as today, the log included', async () => {
				await todaysRefusal('parts-switch-off', {});
			});
		});
	});

	describe('refused with nothing kept', () => {
		const hosts: IAssetHost[] = [];
		afterEach(() => {
			for (const host of hosts.splice(0)) {
				try {
					host.node.destroy();
				} catch {
					// already destroyed
				}
				host.storage?.close();
			}
		});

		/** The scid openReadyChannel gives the ordinary channel of a pair. */
		const ORDINARY_SCID = Buffer.from('0001f40000010000', 'hex');

		/**
		 * Alice and Bob on loopback, with an asset channel (9000 and 1000
		 * units) and an ordinary one; Dave, with an asset channel to Bob, when
		 * asked. Bob is the payee, values a part at its units, and opts in.
		 */
		async function payee(
			tag: string,
			options: {
				dave?: boolean;
				/** Runs before Bob has a peer or a channel. */
				beforeChannels?: (bob: IAssetHost) => void;
			} = {}
		): Promise<{
			alice: IAssetHost;
			bob: IAssetHost;
			dave?: IAssetHost;
			assetId: Buffer;
			ordinaryId: Buffer;
			daveId?: Buffer;
			logs: Log[];
		}> {
			const alice = assetHost(tag, 1, {}, { sqlite: true });
			const bob = assetHost(
				tag,
				2,
				{
					valueIncomingHtlc: (context) =>
						context.auxiliaryAmount === undefined
							? undefined
							: context.auxiliaryAmount * 1000n,
					...RECEIVE_IN_PARTS
				},
				{ sqlite: true }
			);
			hosts.push(alice, bob);
			const logs: Log[] = [];
			bob.node.on('log', (log: Log) => {
				logs.push(log);
			});
			options.beforeChannels?.(bob);
			connectHosts(alice, bob);
			const assetId = await openAssetChannel(alice, bob, {
				tag,
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			const ordinaryId = openReadyChannel(alice.node, bob.node);
			if (!options.dave) return { alice, bob, assetId, ordinaryId, logs };
			const dave = assetHost(tag, 3, {}, { sqlite: true });
			hosts.push(dave);
			connectHosts(dave, bob);
			const daveId = await openAssetChannel(dave, bob, {
				tag: `${tag} dave`,
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			return { alice, bob, dave, assetId, ordinaryId, daveId, logs };
		}

		/**
		 * A payer puts an asset part on its channel by hand, as a peer of
		 * another build may: `units` in the records, a 354 sat carrier, and an
		 * onion of one hop that declares `totalMsat` (with no payment data at
		 * all when `bare`).
		 */
		function assetPart(
			payer: IAssetHost,
			payeeHost: IAssetHost,
			channelId: Buffer,
			invoice: { paymentHash: Buffer; paymentSecret: Buffer },
			part: { units: bigint; totalMsat?: bigint; bare?: boolean }
		): void {
			const packet = constructOnionPacket(
				hash(`part ${hex(channelId)} ${part.units} ${Math.random()}`),
				[
					{
						pubkey: Buffer.from(payeeHost.node.getNodeId(), 'hex'),
						payload: {
							amountToForwardMsat: part.units * 1000n,
							outgoingCltvValue: 40,
							...(part.bare
								? {}
								: {
										paymentSecret: invoice.paymentSecret,
										totalMsat: part.totalMsat
								  })
						}
					}
				],
				invoice.paymentHash
			);
			const added = payer.node
				.getChannelManager()
				.addHtlc(
					channelId,
					354_000n,
					invoice.paymentHash,
					40,
					encodeOnionPacket(packet),
					undefined,
					undefined,
					{ customRecords: amountRecord(part.units) }
				);
			expect(added.ok, added.error).to.equal(true);
		}

		/** Alice pays a plain part over the ordinary channel, declaring the total. */
		function plainPart(
			alice: IAssetHost,
			bob: IAssetHost,
			invoice: { paymentHash: Buffer; paymentSecret: Buffer },
			amountMsat: bigint,
			totalMsat: bigint
		): void {
			alice.node.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
							shortChannelId: ORDINARY_SCID,
							amountToForwardMsat: amountMsat,
							outgoingCltvValue: 40
						}
					]
				},
				invoice.paymentHash,
				40,
				invoice.paymentSecret,
				totalMsat
			);
		}

		const reasonsOf = (logs: Log[], paymentHash: Buffer): unknown[] =>
			refusalsIn(logs, paymentHash).map((log) => log.data.reason);

		it('a plain part beside an asset part being collected is refused as a mixed set, and the asset part stays in the set', async () => {
			const { alice, bob, assetId, ordinaryId, logs } = await payee(
				'parts-mixed-plain-second'
			);
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'mixed, plain second'
			});
			assetPart(alice, bob, assetId, invoice, {
				units: 3000n,
				totalMsat: 5_000_000n
			});
			await turns(200);
			expect(
				collected(bob, invoice.paymentHash),
				'the asset part is kept'
			).to.equal(1);
			plainPart(alice, bob, invoice, 2_000_000n, 5_000_000n);
			await turns(200);
			expect(reasonsOf(logs, invoice.paymentHash)).to.deep.equal(['mixed']);
			expect(heldOn(bob, ordinaryId, invoice.paymentHash)).to.equal(0);
			expect(heldOn(bob, assetId, invoice.paymentHash)).to.equal(1);
			expect(collected(bob, invoice.paymentHash)).to.equal(1);
			expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
		});

		it('an asset part beside a plain part being collected is refused as a mixed set, and the plain part stays in the set', async () => {
			const { alice, bob, assetId, ordinaryId, logs } = await payee(
				'parts-mixed-asset-second'
			);
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'mixed, asset second'
			});
			plainPart(alice, bob, invoice, 2_000_000n, 5_000_000n);
			await turns(200);
			expect(
				collected(bob, invoice.paymentHash),
				'the plain part is kept'
			).to.equal(1);
			assetPart(alice, bob, assetId, invoice, {
				units: 3000n,
				totalMsat: 5_000_000n
			});
			await turns(200);
			expect(reasonsOf(logs, invoice.paymentHash)).to.deep.equal(['mixed']);
			expect(heldOn(bob, assetId, invoice.paymentHash)).to.equal(0);
			expect(heldOn(bob, ordinaryId, invoice.paymentHash)).to.equal(1);
			expect(collected(bob, invoice.paymentHash)).to.equal(1);
			expect(unitsOf(bob, assetId)).to.equal(1000n);
		});

		it('an asset part of a set for a hold invoice is refused: a hold invoice stays paid by one asset HTLC', async () => {
			const { alice, bob, assetId, logs } = await payee('parts-hold');
			const preimage = hash('parts-hold preimage');
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'a hold invoice in parts',
				hold: true,
				paymentHash: sha256(preimage)
			});
			assetPart(alice, bob, assetId, invoice, {
				units: 3000n,
				totalMsat: 5_000_000n
			});
			await turns(200);
			expect(reasonsOf(logs, invoice.paymentHash)).to.deep.equal(['hold']);
			expect(heldOn(bob, assetId, invoice.paymentHash)).to.equal(0);
			expect(
				(
					bob.node as unknown as { heldHtlcs: Map<string, unknown[]> }
				).heldHtlcs.get(hex(invoice.paymentHash)) ?? []
			).to.deep.equal([]);
			expect(unitsOf(bob, assetId)).to.equal(1000n);
		});

		it('an asset part from a second peer is refused, and the part from the first peer stays in the set', async () => {
			const { alice, bob, dave, assetId, daveId, logs } = await payee(
				'parts-second-peer',
				{ dave: true }
			);
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'two peers'
			});
			assetPart(alice, bob, assetId, invoice, {
				units: 3000n,
				totalMsat: 5_000_000n
			});
			await turns(200);
			assetPart(dave!, bob, daveId!, invoice, {
				units: 2000n,
				totalMsat: 5_000_000n
			});
			await turns(200);
			expect(reasonsOf(logs, invoice.paymentHash)).to.deep.equal(['peer']);
			expect(heldOn(bob, daveId!, invoice.paymentHash)).to.equal(0);
			expect(heldOn(bob, assetId, invoice.paymentHash)).to.equal(1);
			expect(collected(bob, invoice.paymentHash)).to.equal(1);
			expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
		});

		/** The payee issues a BOLT 12 invoice, whose blinded path ends at it. */
		function bolt12Invoice(
			payeeHost: IAssetHost,
			amountMsat: bigint
		): IBolt12Invoice {
			const payerKey = hash('a payer of parts over a blinded path');
			const offers = payeeHost.node.getOfferManager();
			const { offer } = offers.createOffer({
				description: 'parts over a blinded path',
				amount: amountMsat
			});
			const request: IInvoiceRequest = {
				payerKey: getPublicKey(payerKey),
				offerId: offer.offerId,
				amount: amountMsat,
				metadata: hash('payer metadata').subarray(0, 16)
			};
			const offerTlv = encodeOfferTlv(offer);
			request.signature = schnorrSign(
				computeSignatureHash(
					'lightninginvoice_requestsignature',
					computeMerkleRootFromRecords(
						getTlvRecords(encodeInvoiceRequestTlv(request, offerTlv))
					)
				),
				payerKey
			);
			const invoice = offers.handleInvoiceRequest(
				encodeInvoiceRequestTlv(request, offerTlv)
			);
			expect(invoice, 'the payee issued a BOLT 12 invoice').to.not.equal(null);
			return invoice!;
		}

		it('a blinded asset part of a set is refused', async () => {
			// Issued before Bob has a channel, the invoice's blinded path is
			// Bob alone: he is its introduction node and its end.
			let invoice: IBolt12Invoice | undefined;
			const { alice, bob, assetId, logs } = await payee('parts-blinded', {
				beforeChannels: (host) => {
					invoice = bolt12Invoice(host, 5_000_000n);
				}
			});
			const path = invoice!.paths![0];
			expect(path.blindedHops.length).to.equal(1);
			const packet = constructOnionPacket(
				hash('parts-blinded session'),
				[
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						payload: {
							amountToForwardMsat: 3_000_000n,
							outgoingCltvValue: 40,
							encryptedRecipientData: path.blindedHops[0].encryptedData,
							blindingPoint: path.blindingPoint,
							// The first part of two: the blinded final hop declares the total.
							totalAmountMsat: 5_000_000n
						}
					}
				],
				invoice!.paymentHash
			);
			const added = alice.node
				.getChannelManager()
				.addHtlc(
					assetId,
					354_000n,
					invoice!.paymentHash,
					40,
					encodeOnionPacket(packet),
					undefined,
					undefined,
					{ customRecords: amountRecord(3000n) }
				);
			expect(added.ok, added.error).to.equal(true);
			await turns(200);
			expect(reasonsOf(logs, invoice!.paymentHash)).to.deep.equal(['blinded']);
			expect(heldOn(bob, assetId, invoice!.paymentHash)).to.equal(0);
			expect(collected(bob, invoice!.paymentHash)).to.equal(0);
			expect(unitsOf(bob, assetId)).to.equal(1000n);
		});

		it('an asset part that declares no total while a set is being collected is refused, though it is worth the invoice alone', async () => {
			const { alice, bob, assetId, logs } = await payee('parts-no-total');
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'no total'
			});
			assetPart(alice, bob, assetId, invoice, {
				units: 3000n,
				totalMsat: 5_000_000n
			});
			await turns(200);
			expect(collected(bob, invoice.paymentHash)).to.equal(1);
			// An onion with a secret always declares a total, so a part without
			// one passes the per-part checks only for a hash without a secret:
			// the secret is taken away to reach the gate.
			(
				bob.node as unknown as { paymentSecrets: Map<string, Buffer> }
			).paymentSecrets.delete(hex(invoice.paymentHash));
			assetPart(alice, bob, assetId, invoice, { units: 5000n, bare: true });
			await turns(200);
			expect(reasonsOf(logs, invoice.paymentHash)).to.deep.equal(['no-total']);
			expect(heldOn(bob, assetId, invoice.paymentHash)).to.equal(1);
			expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
		});

		it('a part that declares another total fails the whole set back', async () => {
			const { alice, bob, assetId } = await payee('parts-total-mismatch');
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'two totals'
			});
			assetPart(alice, bob, assetId, invoice, {
				units: 3000n,
				totalMsat: 5_000_000n
			});
			await turns(200);
			expect(
				collected(bob, invoice.paymentHash),
				'the first part is kept'
			).to.equal(1);
			assetPart(alice, bob, assetId, invoice, {
				units: 2000n,
				totalMsat: 6_000_000n
			});
			await turns(200);
			expect(collected(bob, invoice.paymentHash)).to.equal(0);
			expect(heldOn(bob, assetId, invoice.paymentHash)).to.equal(0);
			expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			expect(unitsOf(bob, assetId)).to.equal(1000n);
		});

		describe('an ordinary set on ordinary channels, byte for byte (regression)', () => {
			for (const optIn of [false, true]) {
				it(`is settled as today ${
					optIn ? 'with' : 'without'
				} the opt-in, with no new key on its record`, async () => {
					const tag = `parts-ordinary-${optIn ? 'opted-in' : 'not-opted-in'}`;
					const alice = assetHost(tag, 1, {}, { sqlite: true });
					const bob = assetHost(
						tag,
						2,
						{
							valueIncomingHtlc: (context) =>
								context.auxiliaryAmount === undefined
									? undefined
									: context.auxiliaryAmount * 1000n,
							...(optIn ? RECEIVE_IN_PARTS : {})
						},
						{ sqlite: true }
					);
					hosts.push(alice, bob);
					connectHosts(alice, bob);
					await openAssetChannel(alice, bob, {
						tag,
						openerUnits: 9000n,
						acceptorUnits: 1000n
					});
					openReadyChannel(alice.node, bob.node);
					const received: unknown[] = [];
					bob.node.on('payment:received', (payment: unknown) => {
						received.push(payment);
					});
					const invoice = bob.node.createInvoice({
						amountMsat: 5_000_000n,
						description: 'an ordinary set'
					});
					plainPart(alice, bob, invoice, 3_000_000n, 5_000_000n);
					await turns(200);
					plainPart(alice, bob, invoice, 2_000_000n, 5_000_000n);
					await turns(200);
					expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
						PaymentStatus.COMPLETED
					);
					const record = bob.node.getPayment(invoice.paymentHash)!;
					expect(record.status).to.equal(PaymentStatus.COMPLETED);
					expect(record.settledHtlcs?.length).to.equal(2);
					expect(received.length).to.equal(1);
					expect(Object.keys(record).sort()).to.deep.equal(ORDINARY_SET_KEYS);
					expect(record.auxiliary).to.equal(undefined);
					expect(metadataOf(record)?._auxiliaryReceivedParts).to.equal(
						undefined
					);
				});
			}
		});
	});

	describe('no commit with a part at risk', () => {
		it('a part inside the claim buffer: the whole set fails back, with nothing written and nothing revealed', async () => {
			const tag = 'parts-risk-expiry';
			const s = await openPartsScene(world, tag);
			const watch = watchManager(s.w.hosts.carol);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			sendPart(s.w, invoice, 3_000_000n);
			await rounds(
				'Carol holds the first part in the set',
				() => collected(s.w.hosts.carol, invoice.paymentHash) === 1
			);
			// The first part expires 60 blocks above the tip it was sent at: 45
			// blocks on, it is inside the claim buffer of 18.
			await world.passTo(s.w, s.w.chain.height + 45);
			sendPart(s.w, invoice, 2_000_000n);
			await rounds('the second part reaches Carol', () =>
				s.carolLogs.some((log) => log.action === 'asset_set_not_settled')
			);
			await expectNotSettled(s, invoice, 'expiry', watch);
		});

		it('a channel that cannot take a fulfil now, as while it quiesces: the whole set fails back, with nothing written and nothing revealed', async () => {
			const tag = 'parts-risk-channel';
			const s = await openPartsScene(world, tag);
			const watch = watchManager(s.w.hosts.carol);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			sendPart(s.w, invoice, 3_000_000n);
			await rounds(
				'Carol holds the first part in the set',
				() => collected(s.w.hosts.carol, invoice.paymentHash) === 1
			);
			const channel = s.w.hosts.carol.node
				.getChannelManager()
				.getChannel(s.w.outChannel)!;
			const canFulfill = channel.canFulfillHtlc.bind(channel);
			(channel as unknown as { canFulfillHtlc: () => boolean }).canFulfillHtlc =
				(): boolean => false;
			try {
				sendPart(s.w, invoice, 2_000_000n);
				await rounds('the second part reaches Carol', () =>
					s.carolLogs.some((log) => log.action === 'asset_set_not_settled')
				);
			} finally {
				(
					channel as unknown as { canFulfillHtlc: typeof canFulfill }
				).canFulfillHtlc = canFulfill;
			}
			await expectNotSettled(s, invoice, 'channel', watch);
		});

		it('a provider that would refuse a part fulfil: the whole set fails back, with nothing written and nothing revealed', async () => {
			const tag = 'parts-risk-provider';
			const arm = { down: false };
			const s = await openPartsScene(world, tag, {
				world: { wrapProvider: { carol: refusing(arm) } },
				// From the part that completes the set on, Carol's provider
				// cannot build a commitment.
				onCarolAsk: (context, scene) => {
					if (
						scene.carolAsks.filter((ask) =>
							ask.paymentHash.equals(context.paymentHash)
						).length === 2
					) {
						arm.down = true;
					}
				}
			});
			const watch = watchManager(s.w.hosts.carol);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			sendPart(s.w, invoice, 3_000_000n);
			await rounds(
				'Carol holds the first part in the set',
				() => collected(s.w.hosts.carol, invoice.paymentHash) === 1
			);
			sendPart(s.w, invoice, 2_000_000n);
			await rounds('the second part reaches Carol', () => arm.down);
			await turns(20);
			// The provider takes removals again; what it refused is asked for again.
			arm.down = false;
			(
				s.w.hosts.carol.node as unknown as { retryAuxiliaryOwed: () => void }
			).retryAuxiliaryOwed();
			await world.mine(s.w, 1);
			await expectNotSettled(s, invoice, 'provider', watch);
		});
	});

	describe('the commit', () => {
		it('writes the record COMPLETED with every part and its value, tells the host once, and writes the settle decision of every part before any part is fulfilled', async () => {
			const tag = 'parts-commit';
			const s = await openPartsScene(world, tag);
			const watch = watchManager(s.w.hosts.carol);
			// The parts declare a total above the invoice, within twice it.
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_500_000n], {
				invoiceMsat: 5_000_000n,
				totalMsat: 5_500_000n
			});
			await alicePaid(s, invoice);

			const asks = asksFor(s, invoice);
			expect(asks.length).to.equal(2);
			const record = carolsRecord(s, invoice)!;
			expect(record.status).to.equal(PaymentStatus.COMPLETED);
			expect(record.settledHtlcs).to.have.members(asks.map(partKey));
			expect(record.settledHtlcs!.length).to.equal(2);
			expect(record.auxiliary).to.equal(true);
			expect(record.amountMsat).to.equal(5_000_000n);
			expect(record.receivedMsat).to.equal(5_500_000n);
			expect(
				JSON.parse(metadataOf(record)?._auxiliaryReceivedParts ?? '{}')
			).to.deep.equal(
				Object.fromEntries(
					asks.map((ask) => [
						partKey(ask),
						(ask.auxiliaryAmount! * 1000n).toString()
					])
				)
			);
			const mine = (event: { paymentHash?: unknown }): boolean =>
				Buffer.isBuffer(event.paymentHash) &&
				event.paymentHash.equals(invoice.paymentHash);
			expect(s.received.filter(mine).length, 'payment:received once').to.equal(
				1
			);
			expect(
				s.settled.filter((event) => mine(event as { paymentHash?: unknown }))
					.length,
				'invoice:settled once'
			).to.equal(1);
			// Every part's settle decision is written before any part is fulfilled.
			expect(
				watch.fulfils.map((fulfil) => fulfil.key),
				'every part is fulfilled'
			).to.include.members(asks.map(partKey));
			expect(watch.fulfils[0].decidedBefore).to.have.members(asks.map(partKey));
			expect(
				heldOn(s.w.hosts.carol, s.w.outChannel, invoice.paymentHash)
			).to.equal(0);
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(6500n);
		});
	});

	describe('a restart', () => {
		it('while a set is being collected: Carol collects it again, each part valued afresh, and it settles', async () => {
			const tag = 'parts-restart-collecting';
			const s = await openPartsScene(world, tag, {
				world: { carolOnFile: true }
			});
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			sendPart(s.w, invoice, 3_000_000n);
			await rounds(
				'Carol holds the first part in the set',
				() => collected(s.w.hosts.carol, invoice.paymentHash) === 1
			);
			await world.restartCarol(s.w, tag);
			listenCarol(s);
			await rounds(
				'Carol collects the first part again',
				() => collected(s.w.hosts.carol, invoice.paymentHash) === 1
			);
			expect(
				asksFor(s, invoice).length,
				'the first part is valued afresh'
			).to.equal(2);
			sendPart(s.w, invoice, 2_000_000n);
			await alicePaid(s, invoice);
			const record = carolsRecord(s, invoice)!;
			expect(record.status).to.equal(PaymentStatus.COMPLETED);
			expect(record.settledHtlcs!.length).to.equal(2);
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(6000n);
		});

		it('after the commit: Carol restarts and every part not yet fulfilled is fulfilled, the host told of the payment once', async () => {
			const tag = 'parts-restart-committed';
			const arm = { down: false };
			const s = await openPartsScene(world, tag, {
				world: { carolOnFile: true, wrapProvider: { carol: refusing(arm) } }
			});
			// From the commit on, Carol's provider refuses every removal: the
			// records are written, and no fulfil leaves before the restart.
			s.w.hosts.carol.node.on('log', (log: { action: string }) => {
				if (log.action === 'asset_set_committed') arm.down = true;
			});
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
			expect(carolsRecord(s, invoice)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
			arm.down = false;
			await world.restartCarol(s.w, tag);
			listenCarol(s);
			await alicePaid(s, invoice);
			expect(
				heldOn(s.w.hosts.carol, s.w.outChannel, invoice.paymentHash)
			).to.equal(0);
			expect(
				s.received.filter((payment) =>
					payment.paymentHash.equals(invoice.paymentHash)
				).length
			).to.equal(1);
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(6000n);
		});
	});

	describe('the contract', () => {
		it('names receiveInParts, declared or among the surfaces, and never both', () => {
			const declared = (
				AUXILIARY_CHANNELS_API as unknown as { declared: readonly string[] }
			).declared;
			const named = [
				declared.includes('receiveInParts'),
				AUXILIARY_CHANNELS_API.surfaces.includes(
					'receiveInParts' as (typeof AUXILIARY_CHANNELS_API.surfaces)[number]
				)
			];
			expect(named.filter(Boolean).length).to.equal(1);
		});
	});
});

/** The keys of an incoming record an ordinary set settles today. */
const ORDINARY_SET_KEYS = [
	'amountMsat',
	'completedAt',
	'createdAt',
	'direction',
	'paymentHash',
	'preimage',
	'settledHtlcs',
	'status'
];

/**
 * A provider that throws in buildCommitment while `arm.down`, as one whose
 * asset store refuses a removal; otherwise the one it wraps.
 */
function refusing(arm: {
	down: boolean;
}): (provider: IChannelAuxiliaryProvider) => IChannelAuxiliaryProvider {
	return (provider) =>
		new Proxy(provider, {
			get(target, key, receiver): unknown {
				const value = Reflect.get(target, key, receiver) as unknown;
				if (typeof value !== 'function') return value;
				return (...args: unknown[]): unknown => {
					if (arm.down && key === 'buildCommitment') {
						throw new Error('provider down in buildCommitment');
					}
					return (value as (...rest: unknown[]) => unknown).apply(target, args);
				};
			}
		});
}
