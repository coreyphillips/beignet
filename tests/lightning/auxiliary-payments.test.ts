/**
 * Issue #2093, step 8: asset HTLCs and the payment paths that carry them.
 *
 * An HTLC of an asset channel carries asset units in custom records beside
 * a small bitcoin amount. The host values every incoming HTLC that ends at
 * a provider node, is told how each asset HTLC ended, and can read back
 * what an HTLC it sent carries. A node without a provider, and a provider
 * node paying an ordinary invoice over an ordinary channel, do what they
 * did before, byte for byte.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	AuxiliaryPaymentError,
	PaymentStatus
} from '../../src/lightning/node/types';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { channel as lightningChannel } from '../../src/lightning';
import { HtlcDirection } from '../../src/lightning/channel/types';
import {
	constructOnionPacket,
	encodeOnionPacket
} from '../../src/lightning/onion/construct';
import {
	decodeUpdateAddHtlcMessage,
	encodeUpdateAddHtlcMessage
} from '../../src/lightning/message/channel-update';
import {
	amountRecord,
	referenceProvider,
	taprootPair
} from './helpers/auxiliary-pair';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import {
	assetHost,
	connectHosts,
	fixRandomness,
	openAssetChannel,
	plainHost,
	restoreRandomness,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';

const sha256 = (value: Buffer | string): Buffer =>
	crypto.createHash('sha256').update(value).digest();

const settle = async (): Promise<void> => {
	for (let i = 0; i < 40; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

/** The scid openReadyChannel gives the ordinary channel of a pair. */
const ORDINARY_SCID = Buffer.from('0001f40000010000', 'hex');

/**
 * An ordinary invoice of 5,000 satoshis paid over an ordinary channel
 * between two loopback nodes without a provider, by the source of the
 * previous release (4fdaeb60) under the counter of fixRandomness: the hash
 * of every message of the payment in order, and of its update_add_htlc.
 */
const ORDINARY_PAYMENT = {
	transcript:
		'e511e648ceb43c6407addea04ee31ebe4d15717b9311b956c5cc715959750a6f',
	add: 'eff1138607597794fda4e7cf96bb1e419f71e77db5c5666247ee16347d477816'
};

interface IAsked {
	hook: string;
	inTransaction: boolean | undefined;
	context: Record<string, unknown>;
	seen?: Record<string, unknown>;
}
interface IHolder {
	host?: IAssetHost;
}
type Hooks = Partial<IAuxiliaryChannelConfig>;
type Valuation = (context: {
	auxiliaryAmount?: bigint;
	paymentHash: Buffer;
}) => bigint | undefined;

describe('Asset payments (issue #2093, step 8)', function () {
	this.timeout(60_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	const directories: string[] = [];
	afterEach(() => {
		restoreRandomness();
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
		for (const directory of directories.splice(0)) {
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});

	/** Hooks that note every call and whether a storage transaction was open. */
	function noting(
		asked: IAsked[],
		holder: IHolder,
		value: Valuation,
		seen?: () => Record<string, unknown>
	): Hooks {
		return {
			valueIncomingHtlc: (context) => {
				asked.push({
					hook: 'valueIncomingHtlc',
					inTransaction: holder.host?.storage?.inTransaction(),
					context: context as unknown as Record<string, unknown>,
					...(seen ? { seen: seen() } : {})
				});
				return value(context);
			},
			onHtlcResolved: (context) => {
				asked.push({
					hook: 'onHtlcResolved',
					inTransaction: holder.host?.storage?.inTransaction(),
					context: context as unknown as Record<string, unknown>
				});
			}
		};
	}

	/** Alice and Bob with an asset channel (9000 and 1000 units) and an ordinary one. */
	async function pair(
		tag: string,
		options: {
			sqlite?: boolean;
			/** A database file for Alice, so she can be restarted from it. */
			alicePath?: string;
			/** Without the ordinary channel beside the asset channel. */
			assetOnly?: boolean;
			alice?: (holder: IHolder) => Hooks;
			bob?: (holder: IHolder) => Hooks;
		} = {}
	): Promise<{
		alice: IAssetHost;
		bob: IAssetHost;
		channelId: Buffer;
		ordinaryId: Buffer;
	}> {
		const aliceHolder: IHolder = {};
		const bobHolder: IHolder = {};
		const alice = assetHost(tag, 1, options.alice?.(aliceHolder) ?? {}, {
			sqlite: options.sqlite,
			sqlitePath: options.alicePath
		});
		const bob = assetHost(tag, 2, options.bob?.(bobHolder) ?? {}, {
			sqlite: options.sqlite
		});
		aliceHolder.host = alice;
		bobHolder.host = bob;
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		const ordinaryId = options.assetOnly
			? Buffer.alloc(32)
			: openReadyChannel(alice.node, bob.node);
		return { alice, bob, channelId, ordinaryId };
	}

	const hopsTo = (
		host: IAssetHost,
		amountMsat: bigint,
		scid: Buffer
	): Parameters<IAssetHost['node']['sendPaymentToRoute']>[0] => ({
		hops: [
			{
				pubkey: Buffer.from(host.node.getNodeId(), 'hex'),
				shortChannelId: scid,
				amountToForwardMsat: amountMsat,
				outgoingCltvValue: 40
			}
		]
	});

	type Invoice = { paymentHash: Buffer; paymentSecret?: Buffer };

	/** Alice pays Bob's invoice with `units` over the asset channel. */
	function payUnits(
		alice: IAssetHost,
		bob: IAssetHost,
		channelId: Buffer,
		invoice: Invoice,
		amountMsat: bigint,
		units: bigint,
		extra: { expectedHtlcId?: bigint } = {}
	): void {
		alice.node.sendPaymentToRoute(
			hopsTo(bob, amountMsat, Buffer.alloc(8, 9)),
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
					customRecords: amountRecord(units),
					...extra
				}
			}
		);
	}

	/** Alice pays Bob's invoice in bitcoin over the ordinary channel. */
	function payBitcoin(
		alice: IAssetHost,
		bob: IAssetHost,
		invoice: Invoice,
		amountMsat: bigint
	): void {
		alice.node.sendPaymentToRoute(
			hopsTo(bob, amountMsat, ORDINARY_SCID),
			invoice.paymentHash,
			40,
			invoice.paymentSecret
		);
	}

	const units = (host: IAssetHost, channelId: Buffer): [bigint, bigint] => {
		const info = host.node.getAuxiliaryChannelInfo(channelId)!;
		return [info.localAssetBalance, info.remoteAssetBalance];
	};
	const same = (value: unknown, expected: Buffer): boolean =>
		Buffer.isBuffer(value) && value.equals(expected);

	for (const sqlite of [false, true]) {
		const where = sqlite ? 'SQLite' : 'memory';
		it(`pays an asset invoice in units over an asset channel, and tells each host once how its HTLC ended (${where})`, async () => {
			const aliceAsked: IAsked[] = [];
			const bobAsked: IAsked[] = [];
			const ref: { alice?: IAssetHost; channelId?: Buffer; hash?: Buffer } = {};
			const { alice, bob, channelId } = await pair(`aux-pay-${where}`, {
				sqlite,
				alice: (holder) => noting(aliceAsked, holder, () => undefined),
				bob: (holder) =>
					noting(
						bobAsked,
						holder,
						(context) => context.auxiliaryAmount! * 1000n,
						// What the sender can read while its HTLC is in flight.
						() => ({
							htlcs: ref.alice!.node.getAuxiliaryPaymentHtlcs(ref.hash!),
							info: ref.alice!.node.getAuxiliaryChannelInfo(ref.channelId!)
						})
					)
			});
			ref.alice = alice;
			ref.channelId = channelId;
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'five thousand units'
			});
			ref.hash = invoice.paymentHash;

			payUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n, {
				expectedHtlcId: 0n
			});
			await settle();

			expect(
				alice.errors
					.concat(bob.errors)
					// Left by opening the ordinary channel by hand: the host's
					// funding provider funds asset channels only.
					.filter((error) => !error.startsWith('AUTO_FUNDING_FAILED'))
			).to.deep.equal([]);
			expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			// The units moved, and nothing is in flight.
			expect(units(alice, channelId)).to.deep.equal([4000n, 6000n]);
			expect(units(bob, channelId)).to.deep.equal([6000n, 4000n]);
			expect(
				alice.node.getAuxiliaryChannelInfo(channelId)!.htlcs
			).to.deep.equal([]);

			// Bob's host valued the one HTLC, outside any storage transaction.
			const valued = bobAsked.filter((a) => a.hook === 'valueIncomingHtlc');
			expect(valued).to.have.length(1);
			expect(valued[0].inTransaction).to.equal(sqlite ? false : undefined);
			expect(valued[0].context.auxiliaryAmount).to.equal(5000n);
			expect(valued[0].context.wireAmountMsat).to.equal(354_000n);
			expect(valued[0].context.isFinalHop).to.equal(true);
			expect(valued[0].context.htlcId).to.equal(0n);
			expect(same(valued[0].context.channelId, channelId)).to.equal(true);
			expect(
				(valued[0].context.invoice as { paymentHash: string }).paymentHash
			).to.equal(invoice.paymentHash.toString('hex'));

			// While the HTLC was in flight the sender could read what it carries,
			// and its units were in neither balance.
			const seen = valued[0].seen as {
				htlcs: ReturnType<IAssetHost['node']['getAuxiliaryPaymentHtlcs']>;
				info: NonNullable<
					ReturnType<IAssetHost['node']['getAuxiliaryChannelInfo']>
				>;
			};
			expect(seen.htlcs).to.have.length(1);
			expect(same(seen.htlcs[0].channelId, channelId)).to.equal(true);
			expect(seen.htlcs[0].htlcId).to.equal(0n);
			expect(seen.htlcs[0].amountMsat).to.equal(5_000_000n);
			expect(seen.htlcs[0].htlc!.direction).to.equal('offered');
			expect(seen.htlcs[0].htlc!.wireAmountMsat).to.equal(354_000n);
			expect(seen.htlcs[0].htlc!.auxiliaryAmount).to.equal(5000n);
			expect([...seen.htlcs[0].htlc!.customRecords]).to.deep.equal([
				...amountRecord(5000n)
			]);
			expect(seen.info.localAssetBalance).to.equal(4000n);
			expect(seen.info.remoteAssetBalance).to.equal(1000n);
			expect(seen.info.htlcs).to.have.length(1);
			expect(seen.info.htlcs[0].htlcId).to.equal(0n);
			// Once it has ended the payment still names its HTLC.
			const after = alice.node.getAuxiliaryPaymentHtlcs(invoice.paymentHash);
			expect(after).to.have.length(1);
			expect(after[0].htlcId).to.equal(0n);
			expect(after[0].htlc).to.equal(undefined);

			// Each host is told once how its HTLC ended, by channel and HTLC id.
			for (const [asked, direction] of [
				[aliceAsked, HtlcDirection.OFFERED],
				[bobAsked, HtlcDirection.RECEIVED]
			] as const) {
				const resolved = asked.filter((a) => a.hook === 'onHtlcResolved');
				expect(resolved).to.have.length(1);
				expect(resolved[0].inTransaction).to.equal(sqlite ? false : undefined);
				expect(resolved[0].context.htlcId).to.equal(0n);
				expect(same(resolved[0].context.channelId, channelId)).to.equal(true);
				expect(resolved[0].context.direction).to.equal(direction);
				expect(resolved[0].context.outcome).to.equal('fulfilled');
				expect(resolved[0].context.auxiliaryAmount).to.equal(5000n);
				expect(
					same(resolved[0].context.paymentHash, invoice.paymentHash)
				).to.equal(true);
			}
			// The sender's host was asked to value nothing.
			expect(
				aliceAsked.filter((a) => a.hook === 'valueIncomingHtlc')
			).to.deep.equal([]);

			// The node's Lightning balance is its ordinary channel's; what it
			// has on the asset channel is reported apart, and not at all by a
			// node without one.
			const balance = alice.node.getBalance();
			const ordinaryRow = alice.node
				.listChannels()
				.find((row) => !row.channelId.equals(channelId))!;
			const assetState = alice.node
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			expect(balance.localBalanceMsat).to.equal(ordinaryRow.localBalanceMsat);
			expect(balance.remoteBalanceMsat).to.equal(ordinaryRow.remoteBalanceMsat);
			expect(balance.auxiliaryBalanceMsat).to.equal(
				assetState.localBalanceMsat
			);
			// The liquidity the node reports, and what it plans rebalances
			// from, is its ordinary channel alone.
			const liquidity = alice.node.getLiquiditySnapshot();
			expect(liquidity.channelCount).to.equal(1);
			expect(liquidity.totalCapacitySats).to.equal(
				Number(ordinaryRow.fundingSatoshis)
			);
			expect(liquidity.totalLocalBalanceSats).to.equal(
				Number(ordinaryRow.localBalanceMsat / 1000n)
			);
			expect(
				JSON.stringify(
					[
						liquidity.recommendations,
						alice.node.planRebalanceRecommendations()
					],
					(_key, value) =>
						typeof value === 'bigint' ? value.toString() : value
				)
			).to.not.include(channelId.toString('hex'));
			// What picks a channel with a peer for a splice, or decides that a
			// wallet already has one to receive on, passes the asset channel
			// by, though it was opened first.
			const choosers = alice.node as unknown as {
				usableChannelWith(peer: string): Buffer | null;
				liveChannelWith(peer: string): Buffer | null;
			};
			expect(
				same(
					choosers.usableChannelWith(bob.node.getNodeId()),
					ordinaryRow.channelId
				)
			).to.equal(true);
			expect(
				same(
					choosers.liveChannelWith(bob.node.getNodeId()),
					ordinaryRow.channelId
				)
			).to.equal(true);
			const plain = plainHost(`aux-pay-plain-${where}`, 5, { sqlite });
			hosts.push(plain);
			expect('auxiliaryBalanceMsat' in plain.node.getBalance()).to.equal(false);

			// The channel list marks the asset channel and no other.
			const rows = alice.node.listChannels();
			const assetRow = rows.find((row) => row.channelId.equals(channelId))!;
			expect(assetRow.auxiliary).to.equal(true);
			expect(rows.length).to.equal(2);
			for (const row of rows) {
				if (row !== assetRow) expect('auxiliary' in row).to.equal(false);
			}
		});
	}

	it('tells a host again, after a restart, of an outcome it did not take', async () => {
		const firstRun: IAsked[] = [];
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-redeliver-'));
		directories.push(directory);
		const alicePath = path.join(directory, 'alice.sqlite');
		const { alice, bob, channelId } = await pair('aux-redeliver', {
			alicePath,
			alice: (holder) => ({
				onHtlcResolved: (context) => {
					firstRun.push({
						hook: 'onHtlcResolved',
						inTransaction: holder.host?.storage?.inTransaction(),
						context: context as unknown as Record<string, unknown>
					});
					throw new Error('the asset store is down');
				}
			}),
			bob: () => ({
				valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n
			})
		});
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'redelivered'
		});
		payUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await settle();
		expect(firstRun.length).to.be.at.least(1);
		expect(
			alice.errors.some((error) =>
				error.includes(
					`Asset resolution callback failed (channel ${channelId.toString(
						'hex'
					)}): the asset store is down`
				)
			)
		).to.equal(true);

		// The node stops and starts again from its storage.
		alice.node.destroy();
		const secondRun: IAsked[] = [];
		const holder: IHolder = {};
		const restarted = assetHost(
			'aux-redeliver',
			1,
			noting(secondRun, holder, () => undefined),
			{
				sqlitePath: alicePath,
				// The outcome is delivered while the node restores, before
				// the constructor returns.
				onStorage: (storage) => {
					holder.host = { storage } as IAssetHost;
				}
			}
		);
		hosts.push(restarted);
		await settle();
		const resolved = secondRun.filter((a) => a.hook === 'onHtlcResolved');
		expect(resolved).to.have.length(1);
		expect(resolved[0].inTransaction).to.equal(false);
		expect(resolved[0].context.htlcId).to.equal(0n);
		expect(resolved[0].context.outcome).to.equal('fulfilled');
		expect(same(resolved[0].context.channelId, channelId)).to.equal(true);
		expect(units(restarted, channelId)).to.deep.equal([4000n, 6000n]);
	});

	describe('an ordinary invoice paid over an ordinary channel', () => {
		async function ordinaryPayment(provider: boolean): Promise<{
			transcript: string;
			add: string;
			asked: IAsked[];
			statuses: Array<PaymentStatus | undefined>;
		}> {
			fixRandomness('pay-golden');
			const asked: IAsked[] = [];
			const make = (seed: number): IAssetHost =>
				provider
					? assetHost(
							'pay-golden',
							seed,
							noting(asked, {}, () => undefined)
					  )
					: plainHost('pay-golden', seed);
			const alice = make(1);
			const bob = make(2);
			hosts.push(alice, bob);
			const wire: string[] = [];
			for (const [from, host] of [
				['alice', alice],
				['bob', bob]
			] as const) {
				host.node.on(
					'message:outbound',
					(_peer: string, type: number, payload: Buffer) => {
						wire.push(`${from}:${type}:${payload.toString('hex')}`);
					}
				);
			}
			connectHosts(alice, bob);
			openReadyChannel(alice.node, bob.node);
			const start = wire.length;
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'ordinary invoice'
			});
			payBitcoin(alice, bob, invoice, 5_000_000n);
			await settle();
			const sent = wire.slice(start);
			return {
				transcript: sha256(sent.join('\n')).toString('hex'),
				add: sha256(sent[0]).toString('hex'),
				asked,
				statuses: [
					alice.node.getPayment(invoice.paymentHash)?.status,
					bob.node.getPayment(invoice.paymentHash)?.status
				]
			};
		}

		it('between nodes without a provider is the payment it was before, byte for byte', async () => {
			const paid = await ordinaryPayment(false);
			expect(paid.statuses).to.deep.equal([
				PaymentStatus.COMPLETED,
				PaymentStatus.COMPLETED
			]);
			expect({ transcript: paid.transcript, add: paid.add }).to.deep.equal(
				ORDINARY_PAYMENT
			);
			expect(paid.asked).to.deep.equal([]);
		});

		it('between provider nodes whose host answers "not mine" is the same payment, byte for byte', async () => {
			const paid = await ordinaryPayment(true);
			expect(paid.statuses).to.deep.equal([
				PaymentStatus.COMPLETED,
				PaymentStatus.COMPLETED
			]);
			expect({ transcript: paid.transcript, add: paid.add }).to.deep.equal(
				ORDINARY_PAYMENT
			);
			// The receiving host was asked once, about a plain HTLC, and no
			// host was told of an asset HTLC ending.
			expect(paid.asked.map((a) => a.hook)).to.deep.equal([
				'valueIncomingHtlc'
			]);
			const context = paid.asked[0].context;
			expect('auxiliaryAmount' in context).to.equal(false);
			expect((context.customRecords as Map<bigint, Buffer>).size).to.equal(0);
			expect(context.isFinalHop).to.equal(true);
			expect(context.wireAmountMsat).to.equal(5_000_000n);
		});
	});

	describe('a plain HTLC that pays an invoice the host claims', () => {
		const claimed =
			(hash: () => Buffer | undefined): Valuation =>
			(context) => {
				const mine = hash();
				if (mine && context.paymentHash.equals(mine)) {
					throw new Error('this invoice is paid in asset units');
				}
				return undefined;
			};

		it('is failed back over an ordinary channel, never settled, and the invoice stays unpaid', async () => {
			const asked: IAsked[] = [];
			const claim: { hash?: Buffer } = {};
			const { alice, bob, ordinaryId } = await pair('aux-claim-ordinary', {
				sqlite: true,
				bob: (holder) =>
					noting(
						asked,
						holder,
						claimed(() => claim.hash)
					)
			});
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'an asset invoice with a nominal face'
			});
			claim.hash = invoice.paymentHash;
			const before = bob.node.getChannel(ordinaryId)!.localBalanceMsat;

			payBitcoin(alice, bob, invoice, 5_000_000n);
			await settle();

			const payment = alice.node.getPayment(invoice.paymentHash)!;
			expect(payment.status).to.equal(PaymentStatus.FAILED);
			expect(payment.preimage).to.equal(undefined);
			expect(bob.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(bob.node.getChannel(ordinaryId)!.localBalanceMsat).to.equal(
				before
			);
			expect(asked.map((a) => a.hook)).to.deep.equal(['valueIncomingHtlc']);
			expect(asked[0].inTransaction).to.equal(false);
			expect('auxiliaryAmount' in asked[0].context).to.equal(false);
			// A later ordinary invoice is still paid: only the claimed hash is refused.
			const other = bob.node.createInvoice({
				amountMsat: 1_000_000n,
				description: 'ordinary'
			});
			payBitcoin(alice, bob, other, 1_000_000n);
			await settle();
			expect(alice.node.getPayment(other.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('is failed back over an asset channel too, never settled, and the invoice stays unpaid', async () => {
			const asked: IAsked[] = [];
			const claim: { hash?: Buffer } = {};
			const { alice, bob, channelId } = await pair('aux-claim-asset', {
				bob: (holder) =>
					noting(
						asked,
						holder,
						claimed(() => claim.hash)
					)
			});
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'an asset invoice with a nominal face'
			});
			claim.hash = invoice.paymentHash;
			// This node never offers a plain HTLC on an asset channel, but a
			// peer may. Alice's channel is made to, as such a peer would.
			const manager = alice.node.getChannelManager();
			const channel = manager.getChannel(channelId)!;
			(
				channel as unknown as { _prepareAuxiliaryHtlc: () => void }
			)._prepareAuxiliaryHtlc = () => undefined;
			const packet = constructOnionPacket(
				sha256('claimed over an asset channel'),
				[
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						payload: {
							amountToForwardMsat: 5_000_000n,
							outgoingCltvValue: 40,
							paymentSecret: invoice.paymentSecret,
							totalMsat: 5_000_000n
						}
					}
				],
				invoice.paymentHash
			);
			const added = manager.addHtlc(
				channelId,
				5_000_000n,
				invoice.paymentHash,
				40,
				encodeOnionPacket(packet)
			);
			expect(added.ok, added.error).to.equal(true);
			await settle();

			expect(asked.map((a) => a.hook)).to.deep.equal(['valueIncomingHtlc']);
			expect('auxiliaryAmount' in asked[0].context).to.equal(false);
			expect(same(asked[0].context.channelId, channelId)).to.equal(true);
			expect(asked[0].context.wireAmountMsat).to.equal(5_000_000n);
			expect(bob.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			// Failed back and gone from both sides, with every balance where it was.
			expect(channel.getFullState().htlcs.size).to.equal(0);
			expect(
				bob.node.getChannelManager().getChannel(channelId)!.getFullState().htlcs
					.size
			).to.equal(0);
			expect(units(alice, channelId)).to.deep.equal([9000n, 1000n]);
			expect(units(bob, channelId)).to.deep.equal([1000n, 9000n]);
		});

		it('that the host does not know is failed back over an asset channel all the same: nothing of an asset channel is an ordinary payment', async () => {
			const asked: IAsked[] = [];
			const { alice, bob, channelId } = await pair('aux-unknown-asset', {
				bob: (holder) =>
					// "Not mine": on an ordinary channel the node would go on
					// to its own invoice logic and settle.
					noting(asked, holder, () => undefined)
			});
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'an asset invoice with a nominal face'
			});
			// This node never offers a plain HTLC on an asset channel, but a
			// peer may. Alice's channel is made to, as such a peer would.
			const manager = alice.node.getChannelManager();
			const channel = manager.getChannel(channelId)!;
			(
				channel as unknown as { _prepareAuxiliaryHtlc: () => void }
			)._prepareAuxiliaryHtlc = () => undefined;
			const packet = constructOnionPacket(
				sha256('unknown over an asset channel'),
				[
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						payload: {
							amountToForwardMsat: 5_000_000n,
							outgoingCltvValue: 40,
							paymentSecret: invoice.paymentSecret,
							totalMsat: 5_000_000n
						}
					}
				],
				invoice.paymentHash
			);
			const added = manager.addHtlc(
				channelId,
				5_000_000n,
				invoice.paymentHash,
				40,
				encodeOnionPacket(packet)
			);
			expect(added.ok, added.error).to.equal(true);
			await settle();

			expect(asked.map((a) => a.hook)).to.deep.equal(['valueIncomingHtlc']);
			expect('auxiliaryAmount' in asked[0].context).to.equal(false);
			expect(same(asked[0].context.channelId, channelId)).to.equal(true);
			expect(asked[0].context.wireAmountMsat).to.equal(5_000_000n);
			expect(bob.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			// Failed back and gone from both sides, with every balance where it was.
			expect(channel.getFullState().htlcs.size).to.equal(0);
			expect(
				bob.node.getChannelManager().getChannel(channelId)!.getFullState().htlcs
					.size
			).to.equal(0);
			expect(units(alice, channelId)).to.deep.equal([9000n, 1000n]);
			expect(units(bob, channelId)).to.deep.equal([1000n, 9000n]);
		});
	});

	describe('a host that does not accept an asset HTLC', () => {
		const answers: Array<[string, () => unknown]> = [
			[
				'throws',
				(): never => {
					throw new Error('no quote');
				}
			],
			[
				'answers "not mine" for an HTLC that carries asset units',
				() => undefined
			],
			['answers zero', () => 0n],
			['answers a negative', () => -1n],
			['answers null', () => null],
			['answers a number', () => 5_000_000],
			['answers more than a u64', () => 2n ** 64n]
		];
		answers.forEach(([what, answer], index) => {
			it(`${what}: the HTLC is failed back, the units return and the invoice stays unpaid`, async () => {
				const { alice, bob, channelId } = await pair(`aux-refuse-${index}`, {
					bob: () => ({
						valueIncomingHtlc: answer as () => bigint | undefined
					})
				});
				const invoice = bob.node.createInvoice({
					amountMsat: 5_000_000n,
					description: 'refused'
				});
				payUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
				await settle();
				expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
					PaymentStatus.FAILED
				);
				expect(bob.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
					PaymentStatus.COMPLETED
				);
				expect(units(alice, channelId)).to.deep.equal([9000n, 1000n]);
				expect(units(bob, channelId)).to.deep.equal([1000n, 9000n]);
			});
		});

		it('has no valuation hook: an asset HTLC is failed back, and an ordinary payment is untouched', async () => {
			const { alice, bob, channelId } = await pair('aux-no-hook');
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'no hook'
			});
			payUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
			await settle();
			expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(units(alice, channelId)).to.deep.equal([9000n, 1000n]);
			const ordinary = bob.node.createInvoice({
				amountMsat: 2_000_000n,
				description: 'ordinary'
			});
			payBitcoin(alice, bob, ordinary, 2_000_000n);
			await settle();
			expect(alice.node.getPayment(ordinary.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('tells the sending host that its HTLC failed, by channel and HTLC id', async () => {
			const asked: IAsked[] = [];
			const { alice, bob, channelId } = await pair('aux-refuse-told', {
				sqlite: true,
				alice: (holder) => noting(asked, holder, () => undefined),
				bob: () => ({
					valueIncomingHtlc: (): never => {
						throw new Error('no quote');
					}
				})
			});
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'refused'
			});
			payUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
			await settle();
			const resolved = asked.filter((a) => a.hook === 'onHtlcResolved');
			expect(resolved).to.have.length(1);
			expect(resolved[0].context.outcome).to.equal('failed');
			expect(resolved[0].context.htlcId).to.equal(0n);
			expect(resolved[0].inTransaction).to.equal(false);
			expect(same(resolved[0].context.channelId, channelId)).to.equal(true);
		});
	});

	describe('an asset payment that cannot be sent is refused by name, with nothing sent', () => {
		it('names the reason and the channel', async () => {
			const { alice, bob, channelId, ordinaryId } = await pair('aux-typed');
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'typed'
			});
			const sent: number[] = [];
			alice.node.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const refused = (
				run: () => unknown,
				code: string,
				channel: Buffer
			): void => {
				let error: unknown;
				try {
					run();
				} catch (err) {
					error = err;
				}
				expect(error, code).to.be.instanceOf(AuxiliaryPaymentError);
				const typed = error as AuxiliaryPaymentError;
				expect(typed.code).to.equal(code);
				expect(typed.channelId).to.equal(channel.toString('hex'));
				expect(typed.message).to.match(
					new RegExp(`\\(channel ${channel.toString('hex')}\\)$`)
				);
			};
			// No records.
			refused(
				() =>
					alice.node.sendPaymentToRoute(
						hopsTo(bob, 5_000_000n, Buffer.alloc(8, 9)),
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
								customRecords: new Map()
							}
						}
					),
				'ASSET_PAYMENT_INVALID',
				channelId
			);
			// Not an asset channel.
			refused(
				() => payUnits(alice, bob, ordinaryId, invoice, 5_000_000n, 5000n),
				'ASSET_PAYMENT_CHANNEL_MISMATCH',
				ordinaryId
			);
			// Prepared for another HTLC id than the channel's next.
			refused(
				() =>
					payUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n, {
						expectedHtlcId: 7n
					}),
				'ASSET_PAYMENT_CIRCUIT_CHANGED',
				channelId
			);
			expect(sent).to.deep.equal([]);
			expect(units(alice, channelId)).to.deep.equal([9000n, 1000n]);
			expect(
				alice.node.getChannelManager().getChannel(channelId)!.getFullState()
					.localHtlcCounter
			).to.equal(0n);
		});
	});

	describe('a gate set on the node', () => {
		it('refuses an asset payment by name before anything is recorded or sent, and lets ordinary payments be', async () => {
			const { alice, bob, channelId } = await pair('aux-gate', {
				bob: () => ({
					valueIncomingHtlc: (context) =>
						context.auxiliaryAmount === undefined
							? undefined
							: context.auxiliaryAmount * 1000n
				})
			});
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'gated'
			});
			const sent: number[] = [];
			alice.node.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			const seen: Array<Record<string, unknown>> = [];
			const refusing: Array<[string, () => string | undefined, string]> = [
				[
					'a reason',
					() => 'Asset payments are refused while a spending limit is set',
					'Asset payments are refused while a spending limit is set'
				],
				[
					'a throw',
					(): never => {
						throw new Error('the limits could not be read');
					},
					'the limits could not be read'
				]
			];
			for (const [what, answer, reason] of refusing) {
				alice.node.setAuxiliaryPaymentGate((payment) => {
					seen.push(payment);
					return answer();
				});
				let error: unknown;
				try {
					payUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
				} catch (err) {
					error = err;
				}
				expect(error, what).to.be.instanceOf(AuxiliaryPaymentError);
				const typed = error as AuxiliaryPaymentError;
				expect(typed.code).to.equal('ASSET_PAYMENT_REFUSED');
				expect(typed.channelId).to.equal(channelId.toString('hex'));
				expect(typed.message).to.equal(
					`${reason} (channel ${channelId.toString('hex')})`
				);
			}
			expect(seen).to.have.length(2);
			expect(seen[0].amountMsat).to.equal(5_000_000n);
			expect(seen[0].wireAmountMsat).to.equal(354_000n);
			expect(same(seen[0].channelId, channelId)).to.equal(true);
			expect(same(seen[0].paymentHash, invoice.paymentHash)).to.equal(true);
			expect(sent).to.deep.equal([]);
			expect(alice.node.getPayment(invoice.paymentHash)).to.equal(undefined);
			expect(units(alice, channelId)).to.deep.equal([9000n, 1000n]);

			// The gate is not asked about an ordinary payment.
			const ordinary = bob.node.createInvoice({
				amountMsat: 1_000_000n,
				description: 'ordinary'
			});
			payBitcoin(alice, bob, ordinary, 1_000_000n);
			await settle();
			expect(alice.node.getPayment(ordinary.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(seen).to.have.length(2);

			// Letting it through, and removing the gate, both pay.
			alice.node.setAuxiliaryPaymentGate(() => undefined);
			payUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
			await settle();
			expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			alice.node.setAuxiliaryPaymentGate(undefined);
			const second = bob.node.createInvoice({
				amountMsat: 1_000_000n,
				description: 'ungated'
			});
			payUnits(alice, bob, channelId, second, 1_000_000n, 1000n);
			await settle();
			expect(alice.node.getPayment(second.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});
	});

	describe('an ordinary payment whose route names an asset channel', () => {
		it('leaves over the ordinary channel to that peer, and the asset channel carries nothing', async () => {
			const { alice, bob, channelId, ordinaryId } =
				await pair('aux-plain-scid');
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'ordinary'
			});
			const scid =
				alice.node.getAuxiliaryChannelInfo(channelId)!.shortChannelId!;
			const before = alice.node.getChannel(ordinaryId)!.localBalanceMsat;
			alice.node.sendPaymentToRoute(
				hopsTo(bob, 5_000_000n, scid),
				invoice.paymentHash,
				40,
				invoice.paymentSecret
			);
			await settle();
			expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(alice.node.getChannel(ordinaryId)!.localBalanceMsat).to.equal(
				before - 5_000_000n
			);
			const asset = alice.node
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			expect(asset.localHtlcCounter).to.equal(0n);
			expect(units(alice, channelId)).to.deep.equal([9000n, 1000n]);
		});

		it('is refused when the asset channel is the only channel to that peer', async () => {
			const { alice, bob, channelId } = await pair('aux-plain-only', {
				assetOnly: true
			});
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'ordinary'
			});
			const scid =
				alice.node.getAuxiliaryChannelInfo(channelId)!.shortChannelId!;
			const sent: number[] = [];
			alice.node.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			let error: unknown;
			try {
				alice.node.sendPaymentToRoute(
					hopsTo(bob, 5_000_000n, scid),
					invoice.paymentHash,
					40,
					invoice.paymentSecret
				);
			} catch (err) {
				error = err;
			}
			await settle();
			expect(
				error !== undefined ||
					alice.node.getPayment(invoice.paymentHash)?.status ===
						PaymentStatus.FAILED
			).to.equal(true);
			expect(sent).to.deep.equal([]);
			expect(units(alice, channelId)).to.deep.equal([9000n, 1000n]);
			expect(
				alice.node.getChannelManager().getChannel(channelId)!.getFullState()
					.htlcs.size
			).to.equal(0);
		});
	});

	describe('a node between an asset channel and an ordinary one', () => {
		const noted =
			(asked: IAsked[], holder: IHolder) =>
			(hook: string, context: unknown): void => {
				asked.push({
					hook,
					inTransaction: holder.host?.storage?.inTransaction(),
					context: context as Record<string, unknown>
				});
			};
		/** Alice, Bob in the middle on SQLite, and Carol. */
		function trio(
			tag: string,
			bobHooks: (holder: IHolder) => Hooks,
			carolHooks: Hooks = {}
		): { alice: IAssetHost; bob: IAssetHost; carol: IAssetHost } {
			const holder: IHolder = {};
			const alice = assetHost(tag, 1);
			const bob = assetHost(tag, 2, bobHooks(holder), { sqlite: true });
			const carol = assetHost(tag, 3, carolHooks);
			holder.host = bob;
			hosts.push(alice, bob, carol);
			connectHosts(alice, bob);
			connectHosts(bob, carol);
			return { alice, bob, carol };
		}
		const through = (
			bob: IAssetHost,
			carol: IAssetHost,
			scidToCarol: Buffer
		): Parameters<IAssetHost['node']['sendPaymentToRoute']>[0] => ({
			hops: [
				{
					pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
					shortChannelId: ORDINARY_SCID,
					amountToForwardMsat: 5_010_000n,
					outgoingCltvValue: 240
				},
				{
					pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
					shortChannelId: scidToCarol,
					amountToForwardMsat: 5_000_000n,
					outgoingCltvValue: 40
				}
			]
		});

		it('fails back an asset HTLC that is not for it, without asking its host, and forwards nothing', async () => {
			const asked: IAsked[] = [];
			const { alice, bob, carol } = trio('aux-forward-out', (holder) => ({
				// A host that would take the forward: it is not asked.
				valueIncomingHtlc: (context) => {
					noted(asked, holder)('valueIncomingHtlc', context);
					return context.auxiliaryAmount! * 1000n;
				},
				onHtlcResolved: (context) =>
					noted(asked, holder)('onHtlcResolved', context)
			}));
			const channelId = await openAssetChannel(alice, bob, {
				tag: 'forward out',
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			const ordinaryId = openReadyChannel(bob.node, carol.node);
			const ordinaryChannel = bob.node
				.getChannelManager()
				.getChannel(ordinaryId)!;
			const invoice = carol.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'paid in units, received in bitcoin'
			});
			alice.node.sendPaymentToRoute(
				through(
					bob,
					carol,
					(ordinaryChannel.getFullState().shortChannelId ??
						ordinaryChannel.getFullState().scidAlias)!
				),
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
						customRecords: amountRecord(5010n)
					}
				}
			);
			await settle();

			expect(asked.filter((a) => a.hook === 'valueIncomingHtlc')).to.deep.equal(
				[]
			);
			expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(carol.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(units(alice, channelId)).to.deep.equal([9000n, 1000n]);
			// Nothing went out over the ordinary channel, and the forwarding
			// ledger has no row.
			expect(ordinaryChannel.getFullState().localHtlcCounter).to.equal(0n);
			expect(bob.storage!.listForwardingEvents()).to.deep.equal([]);
			const resolved = asked.filter((a) => a.hook === 'onHtlcResolved');
			expect(resolved).to.have.length(1);
			expect(resolved[0].inTransaction).to.equal(false);
			expect(resolved[0].context.direction).to.equal(HtlcDirection.RECEIVED);
			expect(resolved[0].context.outcome).to.equal('failed');
		});

		it('forwards nothing out over an asset channel that a route names', async () => {
			const asked: IAsked[] = [];
			const { alice, bob, carol } = trio(
				'aux-forward-in',
				(holder) => ({
					valueIncomingHtlc: (context) => {
						noted(asked, holder)('valueIncomingHtlc', context);
						return undefined;
					},
					onHtlcResolved: (context) =>
						noted(asked, holder)('onHtlcResolved', context)
				}),
				{ valueIncomingHtlc: () => 5_000_000n }
			);
			const ordinaryId = openReadyChannel(alice.node, bob.node);
			const channelId = await openAssetChannel(bob, carol, {
				tag: 'forward in',
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			const invoice = carol.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'paid in bitcoin over an asset channel'
			});
			const before = bob.node.getChannel(ordinaryId)!.localBalanceMsat;
			alice.node.sendPaymentToRoute(
				through(
					bob,
					carol,
					bob.node.getAuxiliaryChannelInfo(channelId)!.shortChannelId!
				),
				invoice.paymentHash,
				40,
				invoice.paymentSecret
			);
			await settle();

			// The HTLC came in over an ordinary channel and does not end here:
			// the host is asked nothing, and nothing is placed on the asset
			// channel.
			expect(asked).to.deep.equal([]);
			expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(carol.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(
				bob.node.getChannelManager().getChannel(channelId)!.getFullState()
					.localHtlcCounter
			).to.equal(0n);
			expect(units(bob, channelId)).to.deep.equal([9000n, 1000n]);
			expect(bob.node.getChannel(ordinaryId)!.localBalanceMsat).to.equal(
				before
			);
			expect(bob.storage!.listForwardingEvents()).to.deep.equal([]);
		});
	});

	describe('a route for an asset payment', () => {
		it('leaves over the named asset channel, which no ordinary route uses', async () => {
			const { alice, bob, channelId, ordinaryId } = await pair('aux-route', {
				bob: () => ({
					valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n
				})
			});
			const destination = Buffer.from(bob.node.getNodeId(), 'hex');
			const scid =
				alice.node.getAuxiliaryChannelInfo(channelId)!.shortChannelId!;
			const route = alice.node.queryAuxiliaryRoute(
				channelId,
				destination,
				5_000_000n,
				5_000_000n
			)!;
			expect(route.hops).to.have.length(1);
			expect(same(route.hops[0].shortChannelId, scid)).to.equal(true);
			expect(route.hops[0].amountToForwardMsat).to.equal(5_000_000n);
			// Not an asset channel: no asset route.
			expect(
				alice.node.queryAuxiliaryRoute(
					ordinaryId,
					destination,
					5_000_000n,
					5_000_000n
				)
			).to.equal(null);
			// The first hop may not be asked to carry less than the payment.
			let error: unknown;
			try {
				alice.node.queryAuxiliaryRoute(
					channelId,
					destination,
					5_000_000n,
					4_999_999n
				);
			} catch (err) {
				error = err;
			}
			expect(error).to.be.instanceOf(AuxiliaryPaymentError);
			expect((error as AuxiliaryPaymentError).code).to.equal(
				'ASSET_PAYMENT_INVALID'
			);
			// The route pays.
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'by route'
			});
			alice.node.sendPaymentToRoute(
				route,
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
						customRecords: amountRecord(5000n)
					}
				}
			);
			await settle();
			expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});
	});

	describe('an HTLC of an asset channel', () => {
		const add = (
			asset: boolean,
			records: Map<bigint, Buffer> | undefined,
			amountMsat = 50_000_000n
		): {
			made: ReturnType<typeof taprootPair>;
			result: { ok: boolean; error?: string };
		} => {
			const made = taprootPair(8100 + (asset ? 1 : 0), { asset });
			const result = made.alice.addHtlc(
				made.id,
				amountMsat,
				sha256('asset htlc'),
				500,
				Buffer.alloc(1366),
				undefined,
				undefined,
				records ? { customRecords: records } : undefined
			);
			return { made, result };
		};

		it('carries its units out of the sender balance, and its records on the wire', () => {
			const { made, result } = add(true, amountRecord(5n));
			expect(result.ok, result.error).to.equal(true);
			const alice = made.aliceChannel.getFullState();
			const bob = made.bobChannel.getFullState();
			expect(alice.auxiliaryState!.localBalance).to.equal(995n);
			expect(alice.htlcs.get('offered-0')!.auxiliaryAmount).to.equal(5n);
			expect(bob.htlcs.get('received-0')!.auxiliaryAmount).to.equal(5n);
			expect([...bob.htlcs.get('received-0')!.customRecords!]).to.deep.equal([
				...amountRecord(5n)
			]);
			// In flight the units are in neither balance, on either side.
			expect(bob.auxiliaryState!.remoteBalance).to.equal(995n);
			expect(bob.auxiliaryState!.localBalance).to.equal(0n);
		});

		const refusals: Array<
			[string, boolean, Map<bigint, Buffer> | undefined, bigint, RegExp]
		> = [
			[
				'a plain HTLC offered on an asset channel',
				true,
				undefined,
				50_000_000n,
				/an asset channel offers only asset HTLCs$/
			],
			[
				'custom records on an ordinary channel',
				false,
				amountRecord(5n),
				50_000_000n,
				/custom records need an asset channel$/
			],
			[
				'more units than the sender holds',
				true,
				amountRecord(1001n),
				50_000_000n,
				/insufficient asset balance$/
			],
			[
				'a carrier below the dust limit',
				true,
				amountRecord(5n),
				353_000n,
				/asset HTLC carrier is below the negotiated dust limit$/
			]
		];
		for (const [what, asset, records, amountMsat, reason] of refusals) {
			it(`refuses ${what}, naming the channel, and spends no HTLC id`, () => {
				const { made, result } = add(asset, records, amountMsat);
				expect(result.ok).to.equal(false);
				expect(result.error).to.match(reason);
				expect(result.error).to.include(`(channel ${made.id.toString('hex')})`);
				const state = made.aliceChannel.getFullState();
				expect(state.localHtlcCounter).to.equal(0n);
				expect(state.htlcs.size).to.equal(0);
				expect(made.bobChannel.getFullState().htlcs.size).to.equal(0);
			});
		}
	});

	describe('a provider whose verification answers something other than true', () => {
		for (const [what, answer] of [
			['a promise of false', async (): Promise<boolean> => false],
			['a promise of true', async (): Promise<boolean> => true],
			['the number 1', (): number => 1],
			['nothing', (): undefined => undefined]
		] as const) {
			it(`${what}: the asset signatures are not taken as verified, and nothing is paid on them`, async () => {
				// A provider written as async by mistake answers a promise for
				// every asset signature of the peer, which is truthy.
				const provider = {
					...referenceProvider(),
					verifyHtlcs: answer as unknown
				} as IChannelAuxiliaryProvider;
				const alice = assetHost(`aux-verify-answer-${what}`, 1);
				const bob = assetHost(`aux-verify-answer-${what}`, 2, {
					provider,
					valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n
				});
				hosts.push(alice, bob);
				connectHosts(alice, bob);
				let channelId: Buffer | undefined;
				try {
					channelId = await openAssetChannel(alice, bob, {
						tag: `verify answer ${what}`,
						openerUnits: 9000n,
						acceptorUnits: 1000n
					});
				} catch {
					// Refused at the opening: the answer was checked there.
					return;
				}
				const invoice = bob.node.createInvoice({
					amountMsat: 5_000_000n,
					description: 'verified by something that is not true'
				});
				alice.node.sendPaymentToRoute(
					hopsTo(bob, 5_000_000n, Buffer.alloc(8, 9)),
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
							customRecords: amountRecord(5000n)
						}
					}
				);
				await settle();
				await settle();
				expect(bob.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
					PaymentStatus.COMPLETED
				);
				expect(alice.node.getPayment(invoice.paymentHash)!.status).to.not.equal(
					PaymentStatus.COMPLETED
				);
				// Bob holds no more units than before.
				expect(units(bob, channelId)[0]).to.equal(1000n);
			});
		}
	});

	describe('what the build says it offers a host', () => {
		it('is one constant at the lightning entry, with a version and the surfaces present', () => {
			const api = lightningChannel.AUXILIARY_CHANNELS_API;
			// 0 until the build can also close and defend an asset channel:
			// asset openings are off in it, and a host treats it as unsupported.
			expect(api.version).to.equal(1);
			expect([...api.surfaces]).to.deep.equal([
				'valueIncomingHtlc:three-outcome',
				'sendPaymentToRoute:assetPayment',
				'getAuxiliaryPaymentHtlcs',
				'onHtlcResolved:htlcId',
				'queryAuxiliaryRoute',
				'fundAuxiliaryChannel:unsigned',
				'onFundingSigned',
				'abandonAuxiliaryOpen',
				'IChannelInfo.auxiliary',
				'setAuxiliaryPaymentGate',
				'getChannelMonitorState',
				'IPaymentInfo.auxiliary',
				'IPaymentInfo.auxiliaryValueMsat',
				'IInvoiceInfo.auxiliary',
				'IAuxiliaryChannelInfo.undeliveredOutcomes',
				'onHtlcResolved:never-sent',
				'getFixedOutputFeeStatus',
				'IPaymentInfo.unresolved',
				'IHoldInvoiceStateEvent.auxiliary',
				// Issue #2098, step 5: forwards with an asset leg, and the coins
				// a split of the fee coin pool would make.
				'prepareForward',
				'getFixedOutputFeeStatus:splitCoins',
				// Issue #2098, step 6: what a node that forwards keeps for its
				// spends with a deadline, and the host's opt-in at the settle.
				'getFixedOutputFeeStatus:reserve',
				'requireFeeCoinsToSettle',
				'onForwardLegResolved:quote'
			]);
			expect(Object.isFrozen(api)).to.equal(true);
			expect(Object.isFrozen(api.surfaces)).to.equal(true);
			// Each named member is there to be called.
			const node = assetHost('aux-api', 1);
			hosts.push(node);
			for (const member of [
				'getAuxiliaryPaymentHtlcs',
				'queryAuxiliaryRoute',
				'abandonAuxiliaryOpen',
				'fundAuxiliaryChannel',
				'getAuxiliaryChannelInfo',
				'setAuxiliaryPaymentGate'
			] as const) {
				expect(typeof node.node[member]).to.equal('function');
			}
		});
	});

	describe('update_add_htlc', () => {
		const base = {
			channelId: Buffer.alloc(32, 0x11),
			id: 7n,
			amountMsat: 354_000n,
			paymentHash: Buffer.alloc(32, 0x22),
			cltvExpiry: 800_000,
			onionRoutingPacket: Buffer.alloc(1366, 0x33)
		};

		it('reads back the custom records it was written with, in type order', () => {
			const records = new Map<bigint, Buffer>([
				[70_000n, Buffer.from('bb', 'hex')],
				[65_536n, Buffer.from('aa', 'hex')]
			]);
			const payload = encodeUpdateAddHtlcMessage({
				...base,
				customRecords: records
			});
			const read = decodeUpdateAddHtlcMessage(payload, { customRecords: true });
			expect([...read.customRecords!]).to.deep.equal([
				[65_536n, Buffer.from('aa', 'hex')],
				[70_000n, Buffer.from('bb', 'hex')]
			]);
			expect(read.id).to.equal(7n);
			// The standard reader, which a channel without asset state uses,
			// refuses the even custom type as it always did.
			expect(() => decodeUpdateAddHtlcMessage(payload)).to.throw();
		});

		it('is the same bytes as before without custom records, and reads none', () => {
			const plain = encodeUpdateAddHtlcMessage(base);
			expect(plain.length).to.equal(32 + 8 + 8 + 32 + 4 + 1366);
			expect(
				encodeUpdateAddHtlcMessage({
					...base,
					customRecords: new Map()
				}).equals(plain)
			).to.equal(true);
			const read = decodeUpdateAddHtlcMessage(plain, { customRecords: true });
			expect('customRecords' in read).to.equal(false);
		});

		it('refuses a custom record below the custom range', () => {
			expect(() =>
				encodeUpdateAddHtlcMessage({
					...base,
					customRecords: new Map([[65_535n, Buffer.from('aa', 'hex')]])
				})
			).to.throw();
		});
	});
});
