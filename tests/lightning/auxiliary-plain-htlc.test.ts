/**
 * A plain HTLC on an asset channel: an HTLC with no units and no custom
 * records that a peer offers on an asset channel, as an ordinary payment
 * of an invoice of the node. The node's host values it at the bitcoin it
 * carries, and from there it is an ordinary payment: settled, held and
 * cancelled as on an ordinary channel, collected into a set beside a part
 * on an ordinary channel, and claimed on the chain by the decision written
 * for it. The bitcoin it brings is on the node's side of the asset
 * channel, where only the channel's own figures and auxiliaryBalanceMsat
 * count it, and the host is never told of it as of an asset HTLC.
 *
 * A hash the node is paying itself is never taken that way: a plain HTLC
 * of it on an asset channel is failed back with no ask of the host, so a
 * circular payment never ends over an asset channel.
 *
 * No payer of this engine sends such an HTLC, so the peer here is made to,
 * and what the peer's channel did with it stands for the payer's side.
 */

import fs from 'fs';
import * as bitcoin from 'bitcoinjs-lib';
import type Database from 'better-sqlite3';
import { expect } from 'chai';
import {
	CommitmentType,
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	HtlcState,
	isFixedAssetHtlcChannel
} from '../../src/lightning/channel/types';
import { INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS } from '../../src/lightning/onion/types';
import type { IHeldInvoiceSnapshot } from '../../src/lightning/node/types';
import type {
	IRecoveryCommitResult,
	SafetyTransition
} from '../../src/lightning/recovery/types';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	payAssetUnits,
	reconnectHosts,
	turns,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { forwardChainWorld } from './helpers/auxiliary-forward-world';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	errorsOf,
	gateMessages,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';
import { refusing } from './helpers/auxiliary-parts-checks';
import { amountRecord } from './helpers/auxiliary-pair';
import {
	UPDATE_FAIL_HTLC,
	UPDATE_FULFILL_HTLC,
	asksOf,
	bobHasOut,
	bobOffers,
	collectedOf,
	decisionOf,
	endsOfOffer,
	endsSent,
	failureCodeOf,
	hex,
	holdEventsOf,
	localMsat,
	monitorsKnow,
	offerHtlc,
	openPlainWorld,
	parkedOf,
	plainHostLog,
	plainValuer,
	sha256,
	unitsOn,
	until,
	type IPlainHostLog,
	type IPlainOffer,
	type IPlainWorld
} from './helpers/auxiliary-plain-scene';
import { openReadyChannel } from './helpers/loopback-nodes';

const REVOKE_AND_ACK = 133;

/** The two kinds of asset channel: the overlay alone, and the fixed type. */
const TYPES = [
	{ name: 'the overlay alone', tag: 'overlay', fixed: false },
	{ name: 'the fixed type (bit 450)', tag: 'fixed', fixed: true }
] as const;
type ChannelKind = (typeof TYPES)[number];

/** A host's storage, as the node commits each transition to it. */
interface ICommitHolder {
	recovery: {
		commit: (transition: SafetyTransition) => IRecoveryCommitResult;
	};
}

/** Whether a transition makes the record of a hash COMPLETED. */
const completes = (
	transition: SafetyTransition,
	paymentHash: Buffer
): boolean =>
	transition.mutations.some(
		(mutation) =>
			mutation.type === 'payment_state' &&
			mutation.paymentHash === hex(paymentHash) &&
			mutation.payment.status === PaymentStatus.COMPLETED
	);

/**
 * A host's storage refuses the first transition that `refuses` picks out,
 * and takes every other. Gives what the refused one carried; `restore`
 * puts the storage back as it was.
 */
function refuseOnce(
	host: IAssetHost,
	refuses: (transition: SafetyTransition) => boolean
): { refused: SafetyTransition[]; restore: () => void } {
	const holder = host.node as unknown as ICommitHolder;
	const commit = holder.recovery.commit.bind(holder.recovery);
	const refused: SafetyTransition[] = [];
	holder.recovery.commit = (transition): IRecoveryCommitResult => {
		if (refused.length === 0 && refuses(transition)) {
			refused.push(transition);
			return {
				committed: false,
				released: [],
				frameSequence: null,
				error: new Error('the disk refuses the write')
			};
		}
		return commit(transition);
	};
	return {
		refused,
		restore: (): void => {
			holder.recovery.commit = commit;
		}
	};
}

/** The channels whose rows a transition writes, by id in hex. */
const rowsOf = (transition: SafetyTransition): string[] =>
	transition.mutations.flatMap((mutation) =>
		mutation.type === 'channel_state' ? [mutation.channelId] : []
	);

/** The final CLTV of the HTLCs of the loopback pair, whose nodes have no chain. */
const EXPIRY = 40;

interface IPlainPair {
	/** Offers plain HTLCs on the asset channel; opened it, with 9000 units. */
	peer: IAssetHost;
	/** The node whose host values a plain HTLC that pays its invoice. */
	wallet: IAssetHost;
	assetId: Buffer;
	/** The wallet's ordinary channel with the peer, which the wallet opened. */
	ordinaryId: Buffer;
	/** An ordinary channel the peer opened, when asked for. */
	peerOrdinaryId?: Buffer;
	log: IPlainHostLog;
}

describe('a plain HTLC on an asset channel', function () {
	this.timeout(120_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			try {
				host.node.destroy();
			} catch {
				// Destroyed already.
			}
			try {
				host.storage?.close();
			} catch {
				// Closed already.
			}
		}
	});

	async function plainPair(
		tag: string,
		options: { peerOrdinary?: boolean } = {}
	): Promise<IPlainPair> {
		const log = plainHostLog();
		const peer = assetHost(tag, 1);
		const wallet = assetHost(tag, 2, plainValuer(log));
		hosts.push(peer, wallet);
		connectHosts(peer, wallet);
		const assetId = await openAssetChannel(peer, wallet, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		const ordinaryId = openReadyChannel(wallet.node, peer.node);
		const peerOrdinaryId = options.peerOrdinary
			? openReadyChannel(peer.node, wallet.node)
			: undefined;
		await turns(40);
		return {
			peer,
			wallet,
			assetId,
			ordinaryId,
			...(peerOrdinaryId ? { peerOrdinaryId } : {}),
			log
		};
	}

	const pubkeyOf = (host: IAssetHost): Buffer =>
		Buffer.from(host.node.getNodeId(), 'hex');

	/** The HTLCs a host's channel holds, of any state. */
	const htlcsOn = (host: IAssetHost, channelId: Buffer): number =>
		host.node.getChannelManager().getChannel(channelId)!.getFullState().htlcs
			.size;

	/**
	 * Hold what the wallet sends the peer over its own ordinary channel: what
	 * the wallet offers there stays with it, and the peer never sees it.
	 */
	const holdOrdinary = (s: IPlainPair): void => {
		gateMessages(
			{ alice: s.peer, bob: s.wallet } as unknown as IAssetChainPair,
			'bob',
			(_type, payload) =>
				payload.length >= 32 && payload.subarray(0, 32).equals(s.ordinaryId)
		);
	};

	/**
	 * The wallet pays its own invoice in a circle: out to the peer over its
	 * ordinary channel, and back to itself. The first leg is held at the
	 * peer, which never sees it.
	 */
	const payOwnInvoice = async (
		s: IPlainPair,
		invoice: { paymentHash: Buffer; paymentSecret: Buffer },
		amountMsat: bigint
	): Promise<void> => {
		holdOrdinary(s);
		s.wallet.node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: pubkeyOf(s.peer),
						shortChannelId: Buffer.alloc(8, 1),
						amountToForwardMsat: amountMsat + 1000n,
						outgoingCltvValue: EXPIRY + 40
					},
					{
						pubkey: pubkeyOf(s.wallet),
						shortChannelId: Buffer.alloc(8, 2),
						amountToForwardMsat: amountMsat,
						outgoingCltvValue: EXPIRY
					}
				]
			},
			invoice.paymentHash,
			EXPIRY,
			invoice.paymentSecret
		);
		await turns(40);
		const payment = s.wallet.node.getPayment(invoice.paymentHash)!;
		expect(payment.direction).to.equal('OUTGOING');
		expect(payment.status).to.equal(PaymentStatus.PENDING);
		expect(
			s.wallet.node.getOutgoingHtlcs(invoice.paymentHash).htlcs.length,
			'the first leg is out'
		).to.equal(1);
	};

	describe('paying an ordinary invoice of the node', () => {
		for (const [what, amountMsat] of [
			['one plain HTLC', 50_000_000n],
			['one plain HTLC under the dust limit of the channel (354 sat)', 300_000n]
		] as const) {
			it(`settles it when ${what} pays it: the peer's channel takes the preimage, the bitcoin is on the wallet's side of the asset channel and in auxiliaryBalanceMsat, the units are where they were, and nothing says asset`, async () => {
				const s = await plainPair(`plain-single-${amountMsat}`);
				const { peer, wallet, assetId } = s;
				const sent = endsSent(wallet);
				const invoice = wallet.node.createInvoice({
					amountMsat,
					description: 'an ordinary invoice'
				});
				// The decision the wallet holds for the HTLC when its fulfil leaves.
				const atFulfil: Array<string | undefined> = [];
				wallet.node.on(
					'message:outbound',
					(_pubkey: string, type: number, payload: Buffer) => {
						if (
							type === UPDATE_FULFILL_HTLC &&
							payload.subarray(0, 32).equals(assetId)
						) {
							atFulfil.push(
								decisionOf(wallet, assetId, payload.readBigUInt64BE(32))
							);
						}
					}
				);
				const start = {
					wallet: localMsat(wallet, assetId),
					peer: localMsat(peer, assetId),
					balance: wallet.node.getBalance()
				};
				expect(start.balance.auxiliaryBalanceMsat).to.equal(start.wallet);

				const offer = offerHtlc(
					peer,
					wallet,
					assetId,
					invoice.paymentHash,
					amountMsat,
					EXPIRY,
					{ paymentSecret: invoice.paymentSecret, label: 'single' }
				);
				await until(
					'the HTLC is settled on both sides',
					() =>
						wallet.node.getPayment(invoice.paymentHash)?.status ===
							PaymentStatus.COMPLETED &&
						htlcsOn(peer, assetId) === 0 &&
						htlcsOn(wallet, assetId) === 0
				);

				// The host valued it at the bitcoin it carries.
				const asks = asksOf(s.log, invoice.paymentHash);
				expect(asks).to.have.length(1);
				expect('auxiliaryAmount' in asks[0]).to.equal(false);
				expect(asks[0].wireAmountMsat).to.equal(amountMsat);
				// The peer's channel took the preimage, and the decision to
				// settle was held while the wallet's commitment carried it.
				const ends = endsOfOffer(sent, offer);
				expect(ends.map((end) => end.type)).to.deep.equal([
					UPDATE_FULFILL_HTLC
				]);
				expect(sha256(ends[0].preimage!).equals(invoice.paymentHash)).to.equal(
					true
				);
				expect(atFulfil).to.deep.equal(['settle']);
				// Bitcoin moved, units did not.
				expect(localMsat(wallet, assetId)).to.equal(start.wallet + amountMsat);
				expect(localMsat(peer, assetId)).to.equal(start.peer - amountMsat);
				expect(unitsOn(wallet, assetId)).to.deep.equal([1000n, 9000n]);
				expect(unitsOn(peer, assetId)).to.deep.equal([9000n, 1000n]);
				// The records are an ordinary payment's.
				const payment = wallet.node.getPayment(invoice.paymentHash)!;
				expect(payment.status).to.equal(PaymentStatus.COMPLETED);
				expect('auxiliary' in payment).to.equal(false);
				expect(
					'auxiliary' in wallet.node.getInvoice(hex(invoice.paymentHash))!
				).to.equal(false);
				expect(s.log.resolved).to.deep.equal([]);
				// Counted apart from what can be sent over Lightning.
				const balance = wallet.node.getBalance();
				expect(balance.auxiliaryBalanceMsat).to.equal(
					start.balance.auxiliaryBalanceMsat! + amountMsat
				);
				expect(balance.localBalanceMsat).to.equal(
					start.balance.localBalanceMsat
				);
			});
		}
	});

	describe('a hash the node is paying is not taken over an asset channel', () => {
		it('fails a plain HTLC of it back with incorrect_or_unknown_payment_details and never asks the host: the wallet pays its own invoice in a circle, and the last leg comes over the asset channel', async () => {
			const s = await plainPair('plain-own-circle');
			const { peer, wallet, assetId } = s;
			const invoice = wallet.node.createInvoice({
				amountMsat: 50_000_000n,
				description: 'a circle'
			});
			await payOwnInvoice(s, invoice, 50_000_000n);
			const sent = endsSent(wallet);
			const start = {
				wallet: localMsat(wallet, assetId),
				peer: localMsat(peer, assetId)
			};

			const offer = offerHtlc(
				peer,
				wallet,
				assetId,
				invoice.paymentHash,
				50_000_000n,
				EXPIRY,
				{ paymentSecret: invoice.paymentSecret, label: 'last leg' }
			);
			await until(
				'the HTLC is gone from the asset channel',
				() => htlcsOn(peer, assetId) === 0 && htlcsOn(wallet, assetId) === 0
			);

			expect(
				asksOf(s.log, invoice.paymentHash).length,
				'the host is not asked'
			).to.equal(0);
			const ends = endsOfOffer(sent, offer);
			expect(ends.map((end) => end.type)).to.deep.equal([UPDATE_FAIL_HTLC]);
			expect(failureCodeOf(offer, ends[0])).to.equal(
				INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
			);
			// Nothing credited, and the wallet's own payment keeps its record.
			expect(localMsat(wallet, assetId)).to.equal(start.wallet);
			expect(localMsat(peer, assetId)).to.equal(start.peer);
			const payment = wallet.node.getPayment(invoice.paymentHash)!;
			expect(payment.direction).to.equal('OUTGOING');
			expect(payment.status).to.equal(PaymentStatus.PENDING);
			expect(payment.preimage).to.equal(undefined);
			expect(s.log.resolved).to.deep.equal([]);
		});

		const sources: Array<
			[string, (s: IPlainPair, paymentHash: Buffer) => Promise<string>]
		> = [
			[
				'an outgoing payment record of the hash, its HTLC failed back',
				async (s, paymentHash): Promise<string> => {
					// One hop to the peer, which knows no invoice of the hash.
					s.wallet.node.sendPaymentToRoute(
						{
							hops: [
								{
									pubkey: pubkeyOf(s.peer),
									shortChannelId: Buffer.alloc(8, 1),
									amountToForwardMsat: 1_000_000n,
									outgoingCltvValue: EXPIRY
								}
							]
						},
						paymentHash,
						EXPIRY
					);
					await until(
						'the payment failed',
						() =>
							s.wallet.node.getPayment(paymentHash)?.status ===
							PaymentStatus.FAILED
					);
					expect(
						s.wallet.node.getOutgoingHtlcs(paymentHash).htlcs.length
					).to.equal(0);
					return 'OUTGOING';
				}
			],
			[
				'a retry context of the hash',
				async (s, paymentHash): Promise<string> => {
					(
						s.wallet.node as unknown as {
							paymentRetryContexts: Map<string, unknown>;
						}
					).paymentRetryContexts.set(hex(paymentHash), {
						excludedChannels: new Set<string>(),
						retryCount: 0,
						maxRetries: 3
					});
					return 'INCOMING';
				}
			],
			[
				'an HTLC of the hash the wallet offered on its ordinary channel',
				async (s, paymentHash): Promise<string> => {
					holdOrdinary(s);
					offerHtlc(
						s.wallet,
						s.peer,
						s.ordinaryId,
						paymentHash,
						1_000_000n,
						EXPIRY,
						{ label: 'offered by the wallet' }
					);
					await turns(40);
					expect(
						s.wallet.node.getOutgoingHtlcs(paymentHash).htlcs.length
					).to.equal(1);
					return 'INCOMING';
				}
			]
		];
		sources.forEach(([what, paying], index) => {
			it(`fails it back and never asks the host with only ${what}, and credits nothing`, async () => {
				const s = await plainPair(`plain-own-source-${index}`);
				const { peer, wallet, assetId } = s;
				const invoice = wallet.node.createInvoice({
					amountMsat: 5_000_000n,
					description: 'paid by the wallet'
				});
				const direction = await paying(s, invoice.paymentHash);
				const status = wallet.node.getPayment(invoice.paymentHash)!.status;
				const sent = endsSent(wallet);
				const start = localMsat(wallet, assetId);

				const offer = offerHtlc(
					peer,
					wallet,
					assetId,
					invoice.paymentHash,
					5_000_000n,
					EXPIRY,
					{ paymentSecret: invoice.paymentSecret, label: `source ${index}` }
				);
				await until(
					'the HTLC is gone from the asset channel',
					() => htlcsOn(peer, assetId) === 0 && htlcsOn(wallet, assetId) === 0
				);

				expect(
					asksOf(s.log, invoice.paymentHash).length,
					'the host is not asked'
				).to.equal(0);
				const ends = endsOfOffer(sent, offer);
				expect(ends.map((end) => end.type)).to.deep.equal([UPDATE_FAIL_HTLC]);
				expect(failureCodeOf(offer, ends[0])).to.equal(
					INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
				);
				expect(localMsat(wallet, assetId)).to.equal(start);
				const payment = wallet.node.getPayment(invoice.paymentHash)!;
				expect(payment.direction).to.equal(direction);
				expect(payment.status).to.equal(status);
				expect(payment.status).to.not.equal(PaymentStatus.COMPLETED);
			});
		});

		it('does not ask again about, or fail back, a plain HTLC parked for a hold ahead of the wallet paying its hash, when the channel is reestablished: the hold stays and settles', async () => {
			const s = await plainPair('plain-own-parked');
			const { peer, wallet, assetId } = s;
			const preimage = sha256('plain own parked preimage');
			const paymentHash = sha256(preimage);
			const invoice = wallet.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'held',
				hold: true,
				paymentHash
			});
			const offer = offerHtlc(
				peer,
				wallet,
				assetId,
				paymentHash,
				5_000_000n,
				EXPIRY,
				{ paymentSecret: invoice.paymentSecret, label: 'parked' }
			);
			await until(
				'the HTLC is parked',
				() => parkedOf(wallet, paymentHash) === 1
			);
			expect(asksOf(s.log, paymentHash)).to.have.length(1);

			// The wallet pays the hash on: an HTLC of it out on its ordinary channel.
			holdOrdinary(s);
			const sent = endsSent(wallet);
			offerHtlc(wallet, peer, s.ordinaryId, paymentHash, 1_000_000n, EXPIRY, {
				label: 'paid on'
			});
			await turns(40);
			expect(wallet.node.getOutgoingHtlcs(paymentHash).htlcs.length).to.equal(
				1
			);
			await reconnectHosts(peer, wallet);

			expect(asksOf(s.log, paymentHash), 'not asked again').to.have.length(1);
			expect(endsOfOffer(sent, offer), 'nothing sent for it').to.deep.equal([]);
			expect(parkedOf(wallet, paymentHash)).to.equal(1);
			expect(
				wallet.node
					.getChannelManager()
					.getChannel(assetId)!
					.getFullState()
					.htlcs.get(`received-${offer.htlcId}`)?.state
			).to.equal(HtlcState.COMMITTED);

			expect(wallet.node.settleHeldHtlc(paymentHash, preimage)).to.equal(true);
			await until('the HTLC is settled', () => htlcsOn(peer, assetId) === 0);
			const ends = endsOfOffer(sent, offer);
			expect(ends.map((end) => end.type)).to.deep.equal([UPDATE_FULFILL_HTLC]);
			expect(ends[0].preimage!.equals(preimage)).to.equal(true);
		});

		it('asks the host about an HTLC with units of a hash the wallet is paying, as about any', async () => {
			const s = await plainPair('plain-own-units');
			const { peer, wallet, assetId } = s;
			const invoice = wallet.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'a circle'
			});
			await payOwnInvoice(s, invoice, 5_000_000n);
			offerHtlc(peer, wallet, assetId, invoice.paymentHash, 354_000n, EXPIRY, {
				paymentSecret: invoice.paymentSecret,
				totalMsat: 5_000_000n,
				customRecords: amountRecord(5000n),
				label: 'units'
			});
			await until(
				'the host is asked',
				() => asksOf(s.log, invoice.paymentHash).length > 0
			);
			const asks = asksOf(s.log, invoice.paymentHash);
			expect(asks).to.have.length(1);
			expect(asks[0].auxiliaryAmount).to.equal(5000n);
			expect(asks[0].channelId.equals(assetId)).to.equal(true);
		});

		it('asks the host about a plain HTLC of a hash the wallet is paying that comes over an ordinary channel, as about any', async () => {
			const s = await plainPair('plain-own-ordinary', { peerOrdinary: true });
			const { peer, wallet } = s;
			const invoice = wallet.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'a circle'
			});
			await payOwnInvoice(s, invoice, 5_000_000n);
			offerHtlc(
				peer,
				wallet,
				s.peerOrdinaryId!,
				invoice.paymentHash,
				5_000_000n,
				EXPIRY,
				{ paymentSecret: invoice.paymentSecret, label: 'ordinary leg' }
			);
			await until(
				'the host is asked',
				() => asksOf(s.log, invoice.paymentHash).length > 0
			);
			const asks = asksOf(s.log, invoice.paymentHash);
			expect(asks).to.have.length(1);
			expect('auxiliaryAmount' in asks[0]).to.equal(false);
			expect(asks[0].channelId.equals(s.peerOrdinaryId!)).to.equal(true);
		});
	});

	describe('paying a hold invoice of the node, off the chain', () => {
		const heldPlain = async (
			tag: string
		): Promise<{
			s: IPlainPair;
			preimage: Buffer;
			paymentHash: Buffer;
			offer: ReturnType<typeof offerHtlc>;
			sent: ReturnType<typeof endsSent>;
			events: ReturnType<typeof holdEventsOf>;
			/** The peer's bitcoin on the asset channel with no HTLC out. */
			peerBefore: bigint;
		}> => {
			const s = await plainPair(tag);
			const preimage = sha256(`${tag} preimage`);
			const paymentHash = sha256(preimage);
			const invoice = s.wallet.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'held',
				hold: true,
				paymentHash
			});
			const sent = endsSent(s.wallet);
			const events = holdEventsOf(s.wallet);
			const peerBefore = localMsat(s.peer, s.assetId);
			const offer = offerHtlc(
				s.peer,
				s.wallet,
				s.assetId,
				paymentHash,
				5_000_000n,
				EXPIRY,
				{ paymentSecret: invoice.paymentSecret, label: tag }
			);
			await until(
				'the HTLC is parked',
				() => parkedOf(s.wallet, paymentHash) === 1
			);
			expect(asksOf(s.log, paymentHash)).to.have.length(1);
			expect(events.map((e) => e.name)).to.deep.equal(['hold:accepted']);
			expect('auxiliary' in events[0].event).to.equal(false);
			return { s, preimage, paymentHash, offer, sent, events, peerBefore };
		};

		it('parks it, then settles it: the peer takes the preimage, the payment is COMPLETED, and hold:settled carries no asset mark', async () => {
			const { s, preimage, paymentHash, offer, sent, events } =
				await heldPlain('plain-hold-settle');
			const start = localMsat(s.wallet, s.assetId);
			expect(s.wallet.node.settleHeldHtlc(paymentHash, preimage)).to.equal(
				true
			);
			await until(
				'the HTLC is settled',
				() =>
					htlcsOn(s.peer, s.assetId) === 0 && htlcsOn(s.wallet, s.assetId) === 0
			);
			const ends = endsOfOffer(sent, offer);
			expect(ends.map((end) => end.type)).to.deep.equal([UPDATE_FULFILL_HTLC]);
			expect(ends[0].preimage!.equals(preimage)).to.equal(true);
			expect(parkedOf(s.wallet, paymentHash)).to.equal(0);
			const payment = s.wallet.node.getPayment(paymentHash)!;
			expect(payment.status).to.equal(PaymentStatus.COMPLETED);
			expect('auxiliary' in payment).to.equal(false);
			expect(
				'auxiliary' in s.wallet.node.getInvoice(hex(paymentHash))!
			).to.equal(false);
			const settled = events.filter((e) => e.name === 'hold:settled');
			expect(settled).to.have.length(1);
			expect(settled[0].event.heldAmountMsat).to.equal(5_000_000n);
			expect('auxiliary' in settled[0].event).to.equal(false);
			expect(localMsat(s.wallet, s.assetId)).to.equal(start + 5_000_000n);
			expect(unitsOn(s.wallet, s.assetId)).to.deep.equal([1000n, 9000n]);
			expect(s.log.resolved).to.deep.equal([]);
		});

		it('parks it, then cancels it: the HTLC fails back, its bitcoin stays with the peer, and the host is told nothing', async () => {
			const { s, paymentHash, offer, sent, events, peerBefore } =
				await heldPlain('plain-hold-cancel');
			expect(s.wallet.node.cancelHoldInvoice(paymentHash)).to.deep.equal({
				htlcsFailed: 1
			});
			await until(
				'the HTLC is failed back',
				() =>
					htlcsOn(s.peer, s.assetId) === 0 && htlcsOn(s.wallet, s.assetId) === 0
			);
			const ends = endsOfOffer(sent, offer);
			expect(ends.map((end) => end.type)).to.deep.equal([UPDATE_FAIL_HTLC]);
			expect(failureCodeOf(offer, ends[0])).to.equal(
				INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
			);
			expect(localMsat(s.peer, s.assetId)).to.equal(peerBefore);
			expect(parkedOf(s.wallet, paymentHash)).to.equal(0);
			expect(s.wallet.node.getPayment(paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(events.map((e) => e.name)).to.deep.equal([
				'hold:accepted',
				'hold:cancelled'
			]);
			expect(s.log.resolved).to.deep.equal([]);
		});

		it("reads a swap's hold set with a plain part on the asset channel as complete, as the node's own snapshot does", async () => {
			const { s, paymentHash } = await heldPlain('plain-hold-swap');
			const own = s.wallet.node.getHeldInvoiceSnapshot(paymentHash)!;
			expect(own.complete).to.equal(true);
			expect(own.committedMsat).to.equal(5_000_000n);
			const forSwap = (
				s.wallet.node as unknown as {
					swapHeldSnapshot: (hash: Buffer) => IHeldInvoiceSnapshot | null;
				}
			).swapHeldSnapshot(paymentHash);
			expect(forSwap).to.deep.equal(own);
		});
	});

	describe('what an HTLC with units is told', () => {
		it('tells the host of the end of an HTLC with units, and of no HTLC without units, on one asset channel', async () => {
			const s = await plainPair('plain-told');
			const { peer, wallet, assetId } = s;
			const units = wallet.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'units'
			});
			payAssetUnits(peer, wallet, assetId, units, 5_000_000n, 5000n);
			await until(
				'the units are paid',
				() =>
					wallet.node.getPayment(units.paymentHash)?.status ===
					PaymentStatus.COMPLETED
			);
			const plain = wallet.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'plain'
			});
			offerHtlc(peer, wallet, assetId, plain.paymentHash, 5_000_000n, EXPIRY, {
				paymentSecret: plain.paymentSecret,
				label: 'told'
			});
			await until(
				'the plain HTLC is paid',
				() =>
					wallet.node.getPayment(plain.paymentHash)?.status ===
						PaymentStatus.COMPLETED && htlcsOn(peer, assetId) === 0
			);
			// One for an unknown hash on the asset channel: not the host's, failed back.
			offerHtlc(peer, wallet, assetId, sha256('unknown'), 5_000_000n, EXPIRY, {
				label: 'unknown'
			});
			await until(
				'the unknown HTLC is gone',
				() => htlcsOn(peer, assetId) === 0
			);
			await turns(100);

			expect(
				s.log.resolved.map(
					(r) => `${r.direction}:${r.outcome}:${r.auxiliaryAmount}`
				)
			).to.deep.equal(['RECEIVED:fulfilled:5000']);
			expect(
				(s.log.resolved[0].paymentHash as Buffer).equals(units.paymentHash)
			).to.equal(true);
			expect(wallet.node.getPayment(units.paymentHash)!.auxiliary).to.equal(
				true
			);
			expect(
				'auxiliary' in wallet.node.getPayment(plain.paymentHash)!
			).to.equal(false);
		});
	});

	describe('an ordinary invoice paid in parts, one of them on the asset channel', () => {
		const fworld = forwardChainWorld();
		afterEach(() => fworld.dispose());

		const keyOf = (offer: IPlainOffer): string =>
			`${hex(offer.channelId)}:${offer.htlcId}`;

		/**
		 * Stop Carol in the settle of a set: a copy of her database is taken,
		 * and nothing she sends from then on reaches Bob. At the first fulfil
		 * of the hash, or with `atCommit` at the write that makes its record
		 * COMPLETED when that comes first. `restart` brings her back on the
		 * copy, not yet connected to Bob.
		 */
		const stopIn = (
			pw: IPlainWorld,
			tag: string,
			paymentHash: Buffer,
			atCommit = false
		): {
			stopped: () => boolean;
			restart: (
				options?: Omit<
					NonNullable<Parameters<typeof fworld.restartCarol>[2]>,
					'hooks' | 'reconnect' | 'whileDown'
				>
			) => Promise<void>;
		} => {
			const { w } = pw;
			const image = `${w.carolPath!}.image`;
			let stopped = false;
			const stop = (): void => {
				if (stopped) return;
				stopped = true;
				fworld.silence(w, 'out');
				for (const suffix of ['', '-wal']) {
					fs.rmSync(`${image}${suffix}`, { force: true });
					if (fs.existsSync(`${w.carolPath!}${suffix}`)) {
						fs.copyFileSync(`${w.carolPath!}${suffix}`, `${image}${suffix}`);
					}
				}
			};
			const manager = w.hosts.carol.node.getChannelManager();
			const fulfil = manager.fulfillHtlc.bind(manager);
			manager.fulfillHtlc = (
				channelId,
				htlcId,
				preimage
			): ReturnType<typeof fulfil> => {
				if (sha256(preimage).equals(paymentHash)) stop();
				return fulfil(channelId, htlcId, preimage);
			};
			if (atCommit) {
				const holder = w.hosts.carol.node as unknown as ICommitHolder;
				const commit = holder.recovery.commit.bind(holder.recovery);
				holder.recovery.commit = (transition): IRecoveryCommitResult => {
					if (completes(transition, paymentHash)) stop();
					return commit(transition);
				};
			}
			return {
				stopped: () => stopped,
				restart: async (options = {}): Promise<void> => {
					try {
						await fworld.restartCarol(w, tag, {
							...options,
							hooks: pw.hooks,
							reconnect: false,
							whileDown: () => {
								for (const suffix of ['', '-wal', '-shm']) {
									fs.rmSync(`${w.carolPath!}${suffix}`, { force: true });
								}
								for (const suffix of ['', '-wal']) {
									if (fs.existsSync(`${image}${suffix}`)) {
										fs.copyFileSync(
											`${image}${suffix}`,
											`${w.carolPath!}${suffix}`
										);
									}
								}
							}
						});
					} finally {
						for (const suffix of ['', '-wal']) {
							fs.rmSync(`${image}${suffix}`, { force: true });
						}
					}
				}
			};
		};

		/** The transactions Carol hands to the chain that show the preimage of a hash. */
		const preimageShown = (pw: IPlainWorld, paymentHash: Buffer): string[] => {
			const shown: string[] = [];
			const backend = pw.w.backends.carol;
			const publish = backend.broadcastTransaction.bind(backend);
			backend.broadcastTransaction = async (txHex: string): Promise<string> => {
				const tx = bitcoin.Transaction.fromHex(txHex);
				if (
					tx.ins.some((input) =>
						input.witness.some(
							(element) =>
								element.length === 32 && sha256(element).equals(paymentHash)
						)
					)
				) {
					shown.push(tx.getId());
				}
				return publish(txHex);
			};
			return shown;
		};

		it('collects the ordinary part and then the plain part on the asset channel, settles both, and has the decision of the asset-channel part written when its first fulfil leaves', async () => {
			const pw = await openPlainWorld(fworld, 'plain-set');
			const { w } = pw;
			const carol = w.hosts.carol;
			const sent = endsSent(carol);
			const invoice = carol.node.createInvoice({
				amountMsat: 8_000_000n,
				description: 'paid in parts'
			});
			const assetNext = w.hosts.bob.node
				.getChannelManager()
				.getChannel(w.outChannel)!
				.getFullState().localHtlcCounter;
			// The decision of the asset-channel part when the first fulfil leaves.
			const atFirst: Array<string | undefined> = [];
			carol.node.on('message:outbound', (_pubkey: string, type: number) => {
				if (type === UPDATE_FULFILL_HTLC && atFirst.length === 0) {
					atFirst.push(decisionOf(carol, w.outChannel, assetNext));
				}
			});
			const start = {
				asset: localMsat(carol, w.outChannel),
				ordinary: localMsat(carol, w.outChannel2!)
			};
			const ordinary = bobOffers(pw, w.outChannel2!, invoice, 3_000_000n, {
				totalMsat: 8_000_000n,
				label: 'ordinary part'
			});
			await until(
				'Carol collects the ordinary part',
				() => collectedOf(carol, invoice.paymentHash) === 1
			);
			const plain = bobOffers(pw, w.outChannel, invoice, 5_000_000n, {
				totalMsat: 8_000_000n,
				label: 'plain part'
			});
			expect(plain.htlcId).to.equal(assetNext);
			await until(
				'both parts are settled at Bob',
				() =>
					bobHasOut(pw, w.outChannel, invoice.paymentHash) === 0 &&
					bobHasOut(pw, w.outChannel2!, invoice.paymentHash) === 0
			);

			expect(asksOf(pw.log, invoice.paymentHash)).to.have.length(2);
			for (const offer of [ordinary, plain]) {
				const ends = endsOfOffer(sent, offer);
				expect(
					ends.map((end) => end.type),
					keyOf(offer)
				).to.deep.equal([UPDATE_FULFILL_HTLC]);
				expect(sha256(ends[0].preimage!).equals(invoice.paymentHash)).to.equal(
					true
				);
			}
			expect(atFirst).to.deep.equal(['settle']);
			const record = carol.node.getPayment(invoice.paymentHash)!;
			expect(record.status).to.equal(PaymentStatus.COMPLETED);
			expect(record.settledHtlcs).to.have.members([
				keyOf(ordinary),
				keyOf(plain)
			]);
			expect('auxiliary' in record).to.equal(false);
			expect(localMsat(carol, w.outChannel)).to.equal(start.asset + 5_000_000n);
			expect(localMsat(carol, w.outChannel2!)).to.equal(
				start.ordinary + 3_000_000n
			);
			expect(pw.log.resolved).to.deep.equal([]);
		});

		it('reveals nothing when the provider refuses the round that would settle the asset-channel part: no fulfil on any channel, no preimage to a monitor, no settle decision, and every part failed back', async () => {
			const arm = { down: false };
			const pw = await openPlainWorld(fworld, 'plain-set-provider', {
				wrapProvider: refusing(arm),
				// From the part that completes the set on, Carol's provider
				// cannot build a commitment.
				onAsk: (context, log) => {
					if (asksOf(log, context.paymentHash).length === 1) arm.down = true;
				}
			});
			const { w } = pw;
			const carol = w.hosts.carol;
			const sent = endsSent(carol);
			const invoice = carol.node.createInvoice({
				amountMsat: 8_000_000n,
				description: 'paid in parts'
			});
			const ordinary = bobOffers(pw, w.outChannel2!, invoice, 3_000_000n, {
				totalMsat: 8_000_000n,
				label: 'ordinary part'
			});
			await until(
				'Carol collects the ordinary part',
				() => collectedOf(carol, invoice.paymentHash) === 1
			);
			const plain = bobOffers(pw, w.outChannel, invoice, 5_000_000n, {
				totalMsat: 8_000_000n,
				label: 'plain part'
			});
			await until('the asset-channel part reaches Carol', () => arm.down);
			await until(
				'the ordinary part is failed back',
				() => bobHasOut(pw, w.outChannel2!, invoice.paymentHash) === 0
			);
			expect(monitorsKnow(carol, invoice.paymentHash)).to.equal(false);
			expect(decisionOf(carol, w.outChannel, plain.htlcId)).to.not.equal(
				'settle'
			);
			// The provider takes removals again: the part it refused is failed back.
			arm.down = false;
			(
				carol.node as unknown as { retryAuxiliaryOwed: () => void }
			).retryAuxiliaryOwed();
			for (
				let i = 0;
				i < 5 && bobHasOut(pw, w.outChannel, invoice.paymentHash) > 0;
				i++
			) {
				await fworld.mine(w, 1);
			}
			await until(
				'the asset-channel part is failed back',
				() => bobHasOut(pw, w.outChannel, invoice.paymentHash) === 0
			);

			expect(
				sent.filter((end) => end.type === UPDATE_FULFILL_HTLC),
				'no fulfil left'
			).to.deep.equal([]);
			for (const offer of [ordinary, plain]) {
				expect(
					endsOfOffer(sent, offer).map((end) => end.type),
					keyOf(offer)
				).to.deep.equal([UPDATE_FAIL_HTLC]);
			}
			expect(monitorsKnow(carol, invoice.paymentHash)).to.equal(false);
			expect(decisionOf(carol, w.outChannel, plain.htlcId)).to.not.equal(
				'settle'
			);
			expect(carol.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(pw.log.resolved).to.deep.equal([]);
		});

		it('writes the record and the decisions of two asset-channel parts in one transition: refused by the storage, nothing is written or revealed, and the set fails back', async () => {
			const pw = await openPlainWorld(fworld, 'plain-set-unwritten', {
				secondOut: 'asset'
			});
			const { w } = pw;
			const carol = w.hosts.carol;
			const sent = endsSent(carol);
			const invoice = carol.node.createInvoice({
				amountMsat: 8_000_000n,
				description: 'paid in parts'
			});
			const storage = refuseOnce(carol, (transition) =>
				completes(transition, invoice.paymentHash)
			);
			try {
				const first = bobOffers(pw, w.outChannel, invoice, 5_000_000n, {
					totalMsat: 8_000_000n,
					label: 'first part'
				});
				await until(
					'Carol collects the first part',
					() => collectedOf(carol, invoice.paymentHash) === 1
				);
				const second = bobOffers(pw, w.outChannel2!, invoice, 3_000_000n, {
					totalMsat: 8_000_000n,
					label: 'second part'
				});
				await until(
					'both parts are failed back',
					() =>
						bobHasOut(pw, w.outChannel, invoice.paymentHash) === 0 &&
						bobHasOut(pw, w.outChannel2!, invoice.paymentHash) === 0
				);
				expect(storage.refused, 'the write was refused').to.have.length(1);
				expect(
					rowsOf(storage.refused[0]),
					'the rows of both channels, with the record'
				).to.have.members([hex(w.outChannel), hex(w.outChannel2!)]);
				expect(
					sent.filter((end) => end.type === UPDATE_FULFILL_HTLC),
					'no fulfil left'
				).to.deep.equal([]);
				for (const offer of [first, second]) {
					expect(
						endsOfOffer(sent, offer).map((end) => end.type),
						keyOf(offer)
					).to.deep.equal([UPDATE_FAIL_HTLC]);
					expect(decisionOf(carol, offer.channelId, offer.htlcId)).to.not.equal(
						'settle'
					);
				}
				expect(monitorsKnow(carol, invoice.paymentHash)).to.equal(false);
				expect(carol.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
					PaymentStatus.COMPLETED
				);
			} finally {
				storage.restore();
			}
		});

		it('sends the fulfils and settles the set after a restart over SQLite between the write of its record and decisions and the first fulfil', async () => {
			const tag = 'plain-set-restart';
			const pw = await openPlainWorld(fworld, tag);
			const { w } = pw;
			const carol = w.hosts.carol;
			const invoice = carol.node.createInvoice({
				amountMsat: 8_000_000n,
				description: 'paid in parts'
			});
			// What is on disk when the first fulfil is about to be made, with
			// nothing Carol sends from then on reaching Bob: the node stops there.
			const image = `${w.carolPath!}.image`;
			const manager = carol.node.getChannelManager();
			const fulfil = manager.fulfillHtlc.bind(manager);
			let stopped = false;
			manager.fulfillHtlc = (
				channelId,
				htlcId,
				preimage
			): ReturnType<typeof fulfil> => {
				if (!stopped && sha256(preimage).equals(invoice.paymentHash)) {
					stopped = true;
					fworld.silence(w, 'out');
					for (const suffix of ['', '-wal']) {
						fs.rmSync(`${image}${suffix}`, { force: true });
						if (fs.existsSync(`${w.carolPath!}${suffix}`)) {
							fs.copyFileSync(`${w.carolPath!}${suffix}`, `${image}${suffix}`);
						}
					}
				}
				return fulfil(channelId, htlcId, preimage);
			};
			const ordinary = bobOffers(pw, w.outChannel2!, invoice, 3_000_000n, {
				totalMsat: 8_000_000n,
				label: 'ordinary part'
			});
			await until(
				'Carol collects the ordinary part',
				() => collectedOf(carol, invoice.paymentHash) === 1
			);
			const plain = bobOffers(pw, w.outChannel, invoice, 5_000_000n, {
				totalMsat: 8_000_000n,
				label: 'plain part'
			});
			await until('Carol is about to fulfil', () => stopped);
			await turns(40);

			try {
				await fworld.restartCarol(w, tag, {
					hooks: pw.hooks,
					reconnect: false,
					whileDown: () => {
						for (const suffix of ['', '-wal', '-shm']) {
							fs.rmSync(`${w.carolPath!}${suffix}`, { force: true });
						}
						for (const suffix of ['', '-wal']) {
							if (fs.existsSync(`${image}${suffix}`)) {
								fs.copyFileSync(
									`${image}${suffix}`,
									`${w.carolPath!}${suffix}`
								);
							}
						}
					}
				});
			} finally {
				for (const suffix of ['', '-wal']) {
					fs.rmSync(`${image}${suffix}`, { force: true });
				}
			}
			const again = w.hosts.carol;
			expect(
				decisionOf(again, w.outChannel, plain.htlcId),
				'the decision of the asset-channel part is on disk'
			).to.equal('settle');
			const sent = endsSent(again);
			await fworld.reconnect(w, 'out');
			await until(
				'both parts are settled at Bob',
				() =>
					bobHasOut(pw, w.outChannel, invoice.paymentHash) === 0 &&
					bobHasOut(pw, w.outChannel2!, invoice.paymentHash) === 0
			);
			for (const offer of [ordinary, plain]) {
				const ends = endsOfOffer(sent, offer);
				expect(
					ends.map((end) => end.type),
					keyOf(offer)
				).to.deep.equal([UPDATE_FULFILL_HTLC]);
				expect(sha256(ends[0].preimage!).equals(invoice.paymentHash)).to.equal(
					true
				);
			}
			await until(
				'the payment is COMPLETED',
				() =>
					again.node.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.COMPLETED
			);
			expect(
				again.node.getPayment(invoice.paymentHash)!.settledHtlcs
			).to.have.members([keyOf(ordinary), keyOf(plain)]);
		});

		it('fulfils every part after a restart over SQLite at the first fulfil, whatever the host answers then: the record COMPLETED and the decision of the asset-channel part were written together ahead of it', async () => {
			const tag = 'plain-set-stop-fulfil';
			const host = { down: false, ordinary: '', asked: 0 };
			const pw = await openPlainWorld(fworld, tag, {
				onAsk: (context) => {
					host.asked++;
					if (host.down && hex(context.channelId) === host.ordinary) {
						throw new Error('the host is starting');
					}
				}
			});
			const { w } = pw;
			host.ordinary = hex(w.outChannel2!);
			const carol = w.hosts.carol;
			const invoice = carol.node.createInvoice({
				amountMsat: 8_000_000n,
				description: 'paid in parts'
			});
			const stop = stopIn(pw, tag, invoice.paymentHash);
			const ordinary = bobOffers(pw, w.outChannel2!, invoice, 3_000_000n, {
				totalMsat: 8_000_000n,
				label: 'ordinary part'
			});
			await until(
				'Carol collects the ordinary part',
				() => collectedOf(carol, invoice.paymentHash) === 1
			);
			const plain = bobOffers(pw, w.outChannel, invoice, 5_000_000n, {
				totalMsat: 8_000_000n,
				label: 'plain part'
			});
			await until('Carol is about to fulfil', stop.stopped);
			await turns(40);
			await stop.restart();

			const again = w.hosts.carol;
			const record = again.node.getPayment(invoice.paymentHash)!;
			expect(record.status, 'the record on disk').to.equal(
				PaymentStatus.COMPLETED
			);
			expect(record.settledHtlcs).to.have.members([
				keyOf(ordinary),
				keyOf(plain)
			]);
			expect(decisionOf(again, w.outChannel, plain.htlcId)).to.equal('settle');
			const sent = endsSent(again);
			const asked = host.asked;
			host.down = true;
			await fworld.reconnect(w, 'out');
			await until(
				'both parts are settled at Bob',
				() =>
					bobHasOut(pw, w.outChannel, invoice.paymentHash) === 0 &&
					bobHasOut(pw, w.outChannel2!, invoice.paymentHash) === 0
			);
			for (const offer of [ordinary, plain]) {
				const ends = endsOfOffer(sent, offer);
				expect(
					ends.map((end) => end.type),
					keyOf(offer)
				).to.deep.equal([UPDATE_FULFILL_HTLC]);
				expect(sha256(ends[0].preimage!).equals(invoice.paymentHash)).to.equal(
					true
				);
			}
			expect(host.asked, 'the host is not asked again').to.equal(asked);
			expect(again.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it("reveals nothing and claims nothing after a restart over SQLite from ahead of the set's commit: when the provider refuses the round as the set completes again, every part fails back and no spend of Carol's shows the preimage, at the claim buffer either", async () => {
			const tag = 'plain-set-stop-commit';
			const arm = { down: false };
			const host = { arming: false, ordinary: '' };
			const pw = await openPlainWorld(fworld, tag, {
				// From the ask about the asset-channel part on, once armed,
				// Carol's provider builds no commitment.
				onAsk: (context) => {
					if (host.arming && hex(context.channelId) !== host.ordinary) {
						arm.down = true;
					}
				}
			});
			const { w } = pw;
			host.ordinary = hex(w.outChannel2!);
			const carol = w.hosts.carol;
			const invoice = carol.node.createInvoice({
				amountMsat: 8_000_000n,
				description: 'paid in parts'
			});
			const stop = stopIn(pw, tag, invoice.paymentHash, true);
			const ordinary = bobOffers(pw, w.outChannel2!, invoice, 3_000_000n, {
				totalMsat: 8_000_000n,
				label: 'ordinary part'
			});
			await until(
				'Carol collects the ordinary part',
				() => collectedOf(carol, invoice.paymentHash) === 1
			);
			const plain = bobOffers(pw, w.outChannel, invoice, 5_000_000n, {
				totalMsat: 8_000_000n,
				label: 'plain part'
			});
			await until('Carol is about to settle', stop.stopped);
			await turns(40);
			await stop.restart({ wrapProvider: refusing(arm) });

			const again = w.hosts.carol;
			expect(again.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(decisionOf(again, w.outChannel, plain.htlcId)).to.not.equal(
				'settle'
			);
			const sent = endsSent(again);
			const shown = preimageShown(pw, invoice.paymentHash);
			host.arming = true;
			await fworld.reconnect(w, 'out');
			await until(
				'the ordinary part is failed back',
				() => bobHasOut(pw, w.outChannel2!, invoice.paymentHash) === 0
			);
			host.arming = false;
			arm.down = false;
			(
				again.node as unknown as { retryAuxiliaryOwed: () => void }
			).retryAuxiliaryOwed();
			for (
				let i = 0;
				i < 5 && bobHasOut(pw, w.outChannel, invoice.paymentHash) > 0;
				i++
			) {
				await fworld.mine(w, 1);
			}
			await until(
				'the asset-channel part is failed back',
				() => bobHasOut(pw, w.outChannel, invoice.paymentHash) === 0
			);
			for (const offer of [ordinary, plain]) {
				expect(
					endsOfOffer(sent, offer).map((end) => end.type),
					keyOf(offer)
				).to.deep.equal([UPDATE_FAIL_HTLC]);
			}
			await fworld.passTo(w, plain.cltvExpiry - 18);
			await fworld.mine(w, 12);
			expect(shown, 'no spend shows the preimage').to.deep.equal([]);
			expect(again.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
		});

		it("takes back at a restart a decision to settle the asset-channel part that stands with its set's record not COMPLETED: the part fails back, and nothing claims it at the claim buffer", async () => {
			const tag = 'plain-set-take-back';
			const pw = await openPlainWorld(fworld, tag);
			const { w } = pw;
			const carol = w.hosts.carol;
			const invoice = carol.node.createInvoice({
				amountMsat: 8_000_000n,
				description: 'paid in parts'
			});
			const plain = bobOffers(pw, w.outChannel, invoice, 5_000_000n, {
				totalMsat: 8_000_000n,
				label: 'plain part'
			});
			await until(
				'Carol collects the plain part',
				() => collectedOf(carol, invoice.paymentHash) === 1
			);
			// A decision no commit of the set wrote: the set is not complete.
			const preimage = (
				carol.node as unknown as { preimages: Map<string, Buffer> }
			).preimages.get(hex(invoice.paymentHash))!;
			expect(
				carol.node
					.getChannelManager()
					.recordAuxiliaryHtlcDecision(
						w.outChannel,
						plain.htlcId,
						'settle',
						preimage
					)
			).to.equal(true);
			await fworld.restartCarol(w, tag, { hooks: pw.hooks, reconnect: false });

			const again = w.hosts.carol;
			expect(again.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			expect(decisionOf(again, w.outChannel, plain.htlcId)).to.equal('fail');
			const sent = endsSent(again);
			const shown = preimageShown(pw, invoice.paymentHash);
			await fworld.reconnect(w, 'out');
			await until(
				'Carol collects the plain part again',
				() => collectedOf(again, invoice.paymentHash) === 1
			);
			// The set never completes: its part times out.
			(again.node as unknown as { mppTimeoutMs: number }).mppTimeoutMs = 0;
			await new Promise((resolve) => setTimeout(resolve, 5));
			again.node.failTimedOutMppPayments();
			await until(
				'the plain part is failed back',
				() => bobHasOut(pw, w.outChannel, invoice.paymentHash) === 0
			);
			expect(endsOfOffer(sent, plain).map((end) => end.type)).to.deep.equal([
				UPDATE_FAIL_HTLC
			]);
			await fworld.passTo(w, plain.cltvExpiry - 18);
			await fworld.mine(w, 12);
			expect(shown, 'no spend shows the preimage').to.deep.equal([]);
			expect(again.node.getPayment(invoice.paymentHash)!.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
		});

		it("writes the decisions of a hold set's asset-channel parts ahead of any fulfil: the write refused by the storage, nothing is revealed and the set stays parked, and the settle asked again at the next block settles every part", async () => {
			const tag = 'plain-hold-set-unwritten';
			const pw = await openPlainWorld(fworld, tag);
			const { w } = pw;
			const carol = w.hosts.carol;
			const sent = endsSent(carol);
			const events = holdEventsOf(carol);
			const preimage = sha256(`${tag} preimage`);
			const paymentHash = sha256(preimage);
			const invoice = carol.node.createInvoice({
				amountMsat: 8_000_000n,
				description: 'held in parts',
				hold: true,
				paymentHash
			});
			const ordinary = bobOffers(pw, w.outChannel2!, invoice, 3_000_000n, {
				totalMsat: 8_000_000n,
				label: 'ordinary part'
			});
			await until(
				'the ordinary part is parked',
				() => parkedOf(carol, paymentHash) === 1
			);
			const plain = bobOffers(pw, w.outChannel, invoice, 5_000_000n, {
				totalMsat: 8_000_000n,
				label: 'plain part'
			});
			await until(
				'the set is parked',
				() => parkedOf(carol, paymentHash) === 2
			);
			// The first write of the decision to settle the asset-channel part.
			const storage = refuseOnce(carol, (transition) =>
				transition.mutations.some(
					(mutation) =>
						mutation.type === 'channel_state' &&
						mutation.channelId === hex(w.outChannel) &&
						mutation.state.auxiliaryState?.htlcDecisions?.get(
							plain.htlcId.toString()
						)?.outcome === 'settle'
				)
			);
			try {
				expect(carol.node.settleHeldHtlc(paymentHash, preimage)).to.equal(
					false
				);
				await turns(40);
				expect(storage.refused, 'the write was refused').to.have.length(1);
				expect(sent, 'nothing left Carol').to.deep.equal([]);
				expect(monitorsKnow(carol, paymentHash)).to.equal(false);
				expect(decisionOf(carol, w.outChannel, plain.htlcId)).to.equal(
					undefined
				);
				expect(parkedOf(carol, paymentHash)).to.equal(2);
				expect(bobHasOut(pw, w.outChannel, paymentHash)).to.equal(1);
				expect(bobHasOut(pw, w.outChannel2!, paymentHash)).to.equal(1);
				expect(
					events.filter((e) => e.name !== 'hold:accepted'),
					'the hold has not ended'
				).to.deep.equal([]);

				await fworld.mine(w, 1);
				await until(
					'both parts are settled at Bob',
					() =>
						bobHasOut(pw, w.outChannel, paymentHash) === 0 &&
						bobHasOut(pw, w.outChannel2!, paymentHash) === 0
				);
			} finally {
				storage.restore();
			}
			for (const offer of [ordinary, plain]) {
				expect(
					endsOfOffer(sent, offer).map((end) => end.type),
					keyOf(offer)
				).to.deep.equal([UPDATE_FULFILL_HTLC]);
			}
			const record = carol.node.getPayment(paymentHash)!;
			expect(record.status).to.equal(PaymentStatus.COMPLETED);
			expect(record.settledHtlcs).to.have.members([
				keyOf(ordinary),
				keyOf(plain)
			]);
			expect(
				events.filter((e) => e.name !== 'hold:accepted').map((e) => e.name)
			).to.deep.equal(['hold:settled']);
		});
	});

	describe("on the chain, from the peer's commitment", () => {
		const chainWorld = assetChainWorld();
		const kept: string[] = [];
		afterEach(() => {
			chainWorld.dispose();
			for (const file of kept.splice(0)) fs.rmSync(file, { force: true });
		});

		/**
		 * Alice is the peer and Bob the wallet, each with a fee wallet, on an
		 * asset channel of the kind given: the overlay alone unless said.
		 */
		const chainPair = async (
			tag: string,
			coins: { alice: number; bob: number } = { alice: 2, bob: 2 },
			kind: ChannelKind = TYPES[0]
		): Promise<{ pair: IAssetChainPair; log: IPlainHostLog }> => {
			const log = plainHostLog();
			// The fixed type: each node reads the features the other
			// advertises, and neither host allows the HTLC signatures of a
			// channel without bit 450.
			const fixed = kind.fixed ? { allowLegacyHtlcSignatures: undefined } : {};
			const pair = await chainWorld.open(tag, {
				feeWallet: { alice: true, bob: true },
				...(kind.fixed ? { realInit: true } : {}),
				hooks: { alice: { ...fixed }, bob: { ...plainValuer(log), ...fixed } }
			});
			expect(
				isFixedAssetHtlcChannel(
					pair.bob.node
						.getChannelManager()
						.getChannel(pair.channelId)!
						.getFullState().channelType
				),
				'the type of the asset channel'
			).to.equal(kind.fixed);
			for (let i = 0; i < coins.alice; i++) pair.wallets.alice!.fund(100_000);
			for (let i = 0; i < coins.bob; i++) pair.wallets.bob!.fund(100_000);
			await chainWorld.mine(pair, 1);
			return { pair, log };
		};
		const receivedOutput = (
			host: IAssetHost,
			pair: IAssetChainPair,
			txid?: string
		): ITrackedOutput | undefined =>
			trackedOutputs(host, pair.channelId).find(
				(output) =>
					!output.isSecondLevelHtlc &&
					(txid === undefined || output.txid === txid) &&
					(output.outputType === OutputType.RECEIVED_HTLC ||
						output.outputType === OutputType.OFFERED_HTLC)
			);
		const spent = (output: ITrackedOutput | undefined): boolean =>
			!!output &&
			[
				OutputStatus.SPEND_CONFIRMED,
				OutputStatus.IRREVOCABLY_RESOLVED
			].includes(output.status);
		const showsPreimage = (
			pair: IAssetChainPair,
			output: ITrackedOutput,
			paymentHash: Buffer
		): boolean =>
			pair.chain.confirmed
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
		/**
		 * Whether an output was taken by its key alone (the revocation key,
		 * one signature) in a block below the HTLC's expiry, where no spend of
		 * the peer's is valid.
		 */
		const byRevocation = (
			pair: IAssetChainPair,
			output: ITrackedOutput,
			cltvExpiry: number
		): boolean => {
			const entry = pair.chain.confirmed.get(output.resolutionTxid ?? '');
			const input = entry?.tx.ins.find(
				(candidate) =>
					Buffer.from(candidate.hash).reverse().toString('hex') ===
						output.txid && candidate.index === output.outputIndex
			);
			return (
				!!entry && entry.height < cltvExpiry && input?.witness.length === 1
			);
		};
		const mineUntil = async (
			what: string,
			pair: IAssetChainPair,
			reached: () => boolean,
			most = 20
		): Promise<void> => {
			for (let i = 0; i < most && !reached(); i++) {
				await chainWorld.mine(pair, 1);
			}
			if (!reached()) {
				throw new Error(
					`never reached: ${what}; alice ${errorsOf(pair.alice).join(
						' | '
					)}; bob ${errorsOf(pair.bob).join(' | ')}`
				);
			}
		};

		for (const kind of TYPES) {
			it(`claims a plain HTLC it settled directly from the peer's commitment with the preimage of its decision, the fee paid from the output, on ${kind.name}`, async () => {
				const { pair, log } = await chainPair(
					`plain-chain-claim-${kind.tag}`,
					undefined,
					kind
				);
				const { alice, bob, channelId } = pair;
				const invoice = bob.node.createInvoice({
					amountMsat: 50_000_000n,
					description: 'ordinary'
				});
				// From Bob's fulfil on, nothing he sends reaches Alice.
				let quiet = false;
				gateMessages(pair, 'bob', (type) => {
					if (type === UPDATE_FULFILL_HTLC) quiet = true;
					return quiet;
				});
				const offer = offerHtlc(
					alice,
					bob,
					channelId,
					invoice.paymentHash,
					50_000_000n,
					pair.chain.height + 60,
					{ paymentSecret: invoice.paymentSecret, label: 'claimed' }
				);
				await until(
					'Bob settles',
					() =>
						bob.node.getPayment(invoice.paymentHash)?.status ===
						PaymentStatus.COMPLETED
				);
				expect(decisionOf(bob, channelId, offer.htlcId)).to.equal('settle');
				const closed = alice.node.forceCloseChannel(
					channelId,
					SWEEP_DESTINATION
				);
				expect(closed.ok, closed.error).to.equal(true);
				await mineUntil('the HTLC output is claimed', pair, () =>
					spent(receivedOutput(bob, pair, closed.commitmentTxid))
				);

				const output = receivedOutput(bob, pair, closed.commitmentTxid)!;
				expect(output.amount).to.equal(50_000n);
				expect(showsPreimage(pair, output, invoice.paymentHash)).to.equal(true);
				const claim = pair.chain.confirmed.get(output.resolutionTxid!)!.tx;
				expect(claim.ins, 'no input but the HTLC output').to.have.length(1);
				const paidOut = claim.outs.reduce((sum, out) => sum + out.value, 0);
				expect(paidOut).to.be.above(0);
				expect(paidOut).to.be.below(50_000);
				await chainWorld.mine(pair, 2);
				expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
					PaymentStatus.COMPLETED
				);
				expect(log.resolved).to.deep.equal([]);
				expect(
					errorsOf(bob).filter((e) => e.startsWith('ASSET_HTLC_CLAIM_LOST'))
				).to.deep.equal([]);
			});
		}

		for (const decided of ['decided to fail', 'never decided'] as const) {
			it(`lets the peer take a plain HTLC it ${decided} back by its timeout, with records as an ordinary channel's: no end told, nothing lowered, no claim lost`, async () => {
				const tag = `plain-chain-timeout-${decided.split(' ')[0]}`;
				const { pair, log } = await chainPair(tag);
				const { alice, bob, channelId } = pair;
				// An invoice of more than the HTLC brings, which Bob fails.
				const invoice = bob.node.createInvoice({
					amountMsat: decided === 'decided to fail' ? 60_000_000n : 50_000_000n,
					description: 'ordinary'
				});
				let quiet = false;
				if (decided === 'decided to fail') {
					// From Bob's fail on, nothing he sends reaches Alice.
					gateMessages(pair, 'bob', (type) => {
						if (type === UPDATE_FAIL_HTLC) quiet = true;
						return quiet;
					});
				} else {
					// Alice's revocation never reaches Bob: he never takes the HTLC
					// as committed, and never decides.
					gateMessages(pair, 'alice', (type) => {
						if (type === REVOKE_AND_ACK) quiet = true;
						return quiet;
					});
				}
				const offer = offerHtlc(
					alice,
					bob,
					channelId,
					invoice.paymentHash,
					50_000_000n,
					pair.chain.height + 40,
					{ paymentSecret: invoice.paymentSecret, label: tag }
				);
				await until('the gate closes', () => quiet);
				await turns(40);
				expect(decisionOf(bob, channelId, offer.htlcId)).to.equal(
					decided === 'decided to fail' ? 'fail' : undefined
				);
				const closed = alice.node.forceCloseChannel(
					channelId,
					SWEEP_DESTINATION
				);
				expect(closed.ok, closed.error).to.equal(true);
				await chainWorld.mine(pair, 1);
				const start = receivedOutput(bob, pair, closed.commitmentTxid);
				expect(start, 'Bob tracks the HTLC output').to.not.equal(undefined);
				const published: string[] = [];
				const backend = pair.backends.bob;
				const publish = backend.broadcastTransaction.bind(backend);
				backend.broadcastTransaction = async (
					txHex: string
				): Promise<string> => {
					const tx = bitcoin.Transaction.fromHex(txHex);
					if (
						tx.ins.some(
							(input) =>
								Buffer.from(input.hash).reverse().toString('hex') ===
									start!.txid && input.index === start!.outputIndex
						)
					) {
						published.push(tx.getId());
					}
					return publish(txHex);
				};
				await chainWorld.mine(pair, 1);
				const expiry = offer.cltvExpiry;
				if (pair.chain.height < expiry - 1) {
					pair.chain.advance(expiry - 1 - pair.chain.height);
				}
				await mineUntil('the peer takes the HTLC back', pair, () =>
					spent(receivedOutput(bob, pair, closed.commitmentTxid))
				);
				const output = receivedOutput(bob, pair, closed.commitmentTxid)!;
				expect(showsPreimage(pair, output, invoice.paymentHash)).to.equal(
					false
				);
				expect(published, 'Bob published nothing for it').to.deep.equal([]);
				pair.chain.advance(IRREVOCABLE_DEPTH);
				await chainWorld.mine(pair, 2);
				expect(log.resolved).to.deep.equal([]);
				expect(
					errorsOf(bob).filter((e) => e.startsWith('ASSET_HTLC_CLAIM_LOST'))
				).to.deep.equal([]);
				expect(bob.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
					PaymentStatus.COMPLETED
				);
			});
		}

		/**
		 * Alice pays a hold invoice of Bob's with a plain HTLC and keeps a copy
		 * of her store while it is in flight. Bob cancels, the HTLC fails back
		 * and Alice revokes the commitment that held it; she then puts the
		 * copy back and force closes from it.
		 */
		const cheated = async (
			tag: string,
			coins: { alice: number; bob: number },
			beforeClose?: (pair: IAssetChainPair) => void,
			kind: ChannelKind = TYPES[0]
		): Promise<{
			pair: IAssetChainPair;
			log: IPlainHostLog;
			txid: string;
			cltvExpiry: number;
		}> => {
			const { pair, log } = await chainPair(tag, coins, kind);
			const preimage = sha256(`${tag} preimage`);
			const paymentHash = sha256(preimage);
			const invoice = pair.bob.node.createInvoice({
				amountMsat: 50_000_000n,
				description: 'held',
				hold: true,
				paymentHash
			});
			const offer = offerHtlc(
				pair.alice,
				pair.bob,
				pair.channelId,
				paymentHash,
				50_000_000n,
				pair.chain.height + 60,
				{ paymentSecret: invoice.paymentSecret, label: tag }
			);
			await until(
				'the HTLC is parked',
				() => parkedOf(pair.bob, paymentHash) === 1
			);
			const stateOf = (): {
				localCommitmentNumber: bigint;
				htlcs: Map<string, unknown>;
			} =>
				pair.alice.node
					.getChannelManager()
					.getChannel(pair.channelId)!
					.getFullState();
			const number = stateOf().localCommitmentNumber;
			const copy = `${pair.alicePath}.kept`;
			kept.push(copy);
			(pair.alice.storage as unknown as { db: Database.Database }).db.exec(
				`VACUUM INTO '${copy}'`
			);
			pair.bob.node.cancelHoldInvoice(paymentHash);
			await until('the HTLC failed back', () => stateOf().htlcs.size === 0);
			await chainWorld.restartAlice(pair, tag, undefined, () => {
				for (const suffix of ['', '-wal', '-shm']) {
					fs.rmSync(`${pair.alicePath}${suffix}`, { force: true });
				}
				fs.copyFileSync(copy, pair.alicePath);
			});
			expect(stateOf().localCommitmentNumber).to.equal(number);
			beforeClose?.(pair);
			const closed = pair.alice.node.forceCloseChannel(
				pair.channelId,
				SWEEP_DESTINATION
			);
			expect(closed.ok, closed.error).to.equal(true);
			await settle();
			return {
				pair,
				log,
				txid: closed.commitmentTxid!,
				cltvExpiry: offer.cltvExpiry
			};
		};

		for (const kind of TYPES) {
			it(`takes the plain HTLC output of a revoked commitment of the peer with the revocation key, on ${kind.name}`, async () => {
				const tag = `plain-chain-revoked-${kind.tag}`;
				const { pair, log, txid, cltvExpiry } = await cheated(
					tag,
					{ alice: 2, bob: 2 },
					undefined,
					kind
				);
				await chainWorld.mine(pair, 1);
				expect(
					pair.bob.node.getChannelMonitorState(pair.channelId)!
						.commitmentBroadcast
				).to.include({
					txid,
					commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT
				});
				const output = receivedOutput(pair.bob, pair, txid)!;
				expect(output.amount).to.equal(50_000n);
				await mineUntil('the penalty is in a block', pair, () =>
					spent(receivedOutput(pair.bob, pair, txid))
				);
				const taken = receivedOutput(pair.bob, pair, txid)!;
				expect(
					byRevocation(pair, taken, cltvExpiry),
					'taken by the revocation key'
				).to.equal(true);
				expect(
					showsPreimage(pair, taken, sha256(sha256(`${tag} preimage`)))
				).to.equal(false);
				expect(log.resolved).to.deep.equal([]);
			});

			it(`follows the plain HTLC output of a revoked commitment of the peer into the peer's second-level transaction, and takes that output with the revocation key, on ${kind.name}`, async () => {
				// Bob's transactions are turned away until the peer's timeout is in.
				let away = true;
				const { pair, txid, cltvExpiry } = await cheated(
					`plain-chain-revoked-second-${kind.tag}`,
					{ alice: 2, bob: 2 },
					(cheatedPair) => {
						const backend = cheatedPair.backends.bob;
						const publish = backend.broadcastTransaction.bind(backend);
						backend.broadcastTransaction = async (
							txHex: string
						): Promise<string> => {
							if (away) throw new Error('not connected');
							return publish(txHex);
						};
					},
					kind
				);
				await chainWorld.mine(pair, 1);
				if (pair.chain.height < cltvExpiry - 1) {
					pair.chain.advance(cltvExpiry - 1 - pair.chain.height);
				}
				await mineUntil("the peer's HTLC-timeout is in a block", pair, () =>
					spent(receivedOutput(pair.bob, pair, txid))
				);
				const lost = receivedOutput(pair.bob, pair, txid)!;
				const child = trackedOutputs(pair.bob, pair.channelId).find(
					(output) => output.txid === lost.resolutionTxid
				);
				expect(child, 'the second-level output is tracked').to.not.equal(
					undefined
				);
				away = false;
				await mineUntil('the second-level output is taken', pair, () =>
					spent(
						trackedOutputs(pair.bob, pair.channelId).find(
							(output) => output.txid === lost.resolutionTxid
						)
					)
				);
				expect(
					pair.chain.confirmed.get(lost.resolutionTxid!)!.height,
					"the peer's timeout"
				).to.be.at.least(cltvExpiry);
				const taken = trackedOutputs(pair.bob, pair.channelId).find(
					(output) => output.txid === lost.resolutionTxid
				)!;
				const penalty = pair.chain.confirmed.get(taken.resolutionTxid!)!.tx;
				const input = penalty.ins.find(
					(candidate) =>
						Buffer.from(candidate.hash).reverse().toString('hex') ===
							taken.txid && candidate.index === taken.outputIndex
				)!;
				expect(input.witness, 'taken by the revocation key').to.have.length(1);
			});
		}
	});
});
