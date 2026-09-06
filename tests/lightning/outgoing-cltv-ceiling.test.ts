/**
 * The absolute outgoing HTLC expiry ceiling (issue #737, phase 2).
 *
 * A submarine swap provider pays a Lightning invoice against an on-chain
 * refund height: no HTLC it sends may expire past that height less its claim
 * margin, on any attempt, retry or MPP part. The router bound is advisory;
 * the dispatch gate in sendPaymentToRoute / sendPaymentMpp is the guarantee
 * and fails closed with no record, no mapping and no HTLC.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	LightningErrorCode,
	LightningPaymentError,
	PaymentStatus
} from '../../src/lightning/node/types';
import { HtlcState } from '../../src/lightning/channel/types';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import { findRouteToBlindedPath } from '../../src/lightning/gossip/pathfinding';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	buildGraph,
	connectNodes,
	createNode,
	makeExternalHash,
	openReadyChannel,
	scidForIndex
} from './helpers/loopback-nodes';

const TAG = 'cltv-ceiling';

/** Offered HTLCs on alice's side of a channel, any state. */
function offeredHtlcs(
	node: LightningNode,
	channelId: Buffer
): Array<{ cltvExpiry: number; state: HtlcState }> {
	const state = node.getChannelManager().getChannel(channelId)!.getFullState();
	const out: Array<{ cltvExpiry: number; state: HtlcState }> = [];
	for (const [key, htlc] of state.htlcs) {
		if (key.startsWith('offered-')) {
			out.push({ cltvExpiry: htlc.cltvExpiry, state: htlc.state });
		}
	}
	return out;
}

function codeOf(fn: () => unknown): string | undefined {
	try {
		fn();
		return undefined;
	} catch (err) {
		return err instanceof LightningPaymentError ? err.code : String(err);
	}
}

describe('Outgoing CLTV ceiling (issue #737 phase 2)', function () {
	describe('single path', function () {
		function pair(seed: number): {
			alice: LightningNode;
			bob: LightningNode;
			channelId: Buffer;
		} {
			const alice = createNode(TAG, seed);
			const bob = createNode(TAG, seed + 1);
			connectNodes(alice, bob);
			alice.handleNewBlock(1000);
			bob.handleNewBlock(1000);
			const channelId = openReadyChannel(alice, bob);
			buildGraph(alice, bob, [channelId]);
			return { alice, bob, channelId };
		}

		/** The absolute expiry a direct payment at height 1000 needs. */
		function needFor(
			alice: LightningNode,
			bob: LightningNode,
			channelId: Buffer
		): number {
			const { hash } = makeExternalHash();
			const inv = bob.createInvoice({
				amountMsat: 1_000_000n,
				description: 'probe',
				hold: true,
				paymentHash: hash
			});
			alice.sendPayment(inv.bolt11);
			const need = offeredHtlcs(alice, channelId)[0].cltvExpiry;
			bob.cancelHoldInvoice(hash);
			return need;
		}

		it('refuses a ceiling below what the route needs, leaving nothing behind', function () {
			const { alice, bob, channelId } = pair(1);
			const need = needFor(alice, bob, channelId);
			expect(need).to.equal(1000 + 40 + 3);

			const { hash } = makeExternalHash();
			const inv = bob.createInvoice({
				amountMsat: 1_000_000n,
				description: 'too-tight',
				hold: true,
				paymentHash: hash
			});
			const code = codeOf(() =>
				alice.sendPaymentWithOptions(inv.bolt11, {
					maxCltvExpiryHeight: need - 1
				})
			);
			expect(code).to.be.oneOf([
				LightningErrorCode.NO_ROUTE,
				LightningErrorCode.CLTV_EXCEEDS_MAX
			]);
			expect(alice.getPayment(hash)).to.equal(undefined);
			expect(alice.getOutgoingHtlcs(hash).htlcs).to.have.length(0);
			expect(
				offeredHtlcs(alice, channelId).filter(
					(h) => h.state !== HtlcState.FAILED && h.state !== HtlcState.FULFILLED
				)
			).to.have.length(0);
			expect(bob.getHeldInvoiceSnapshot(hash)!.parts).to.have.length(0);
		});

		it('sends under a ceiling equal to the need and never exceeds it', function () {
			const { alice, bob, channelId } = pair(3);
			const need = needFor(alice, bob, channelId);
			const { hash } = makeExternalHash();
			const inv = bob.createInvoice({
				amountMsat: 1_000_000n,
				description: 'fits',
				hold: true,
				paymentHash: hash
			});
			const payment = alice.sendPaymentWithOptions(inv.bolt11, {
				maxCltvExpiryHeight: need
			});
			expect(payment.status).to.equal(PaymentStatus.PENDING);
			const live = offeredHtlcs(alice, channelId).filter(
				(h) => h.state === HtlcState.COMMITTED
			);
			expect(live).to.have.length(1);
			expect(live[0].cltvExpiry).to.equal(need);
			expect(live[0].cltvExpiry).to.be.at.most(need);
			bob.cancelHoldInvoice(hash);
		});

		it('rejects a ceiling that is not above the current height', function () {
			const { alice, bob } = pair(5);
			const { hash } = makeExternalHash();
			const inv = bob.createInvoice({
				amountMsat: 1_000n,
				description: 'stale',
				hold: true,
				paymentHash: hash
			});
			expect(
				codeOf(() =>
					alice.sendPaymentWithOptions(inv.bolt11, {
						maxCltvExpiryHeight: 1000
					})
				)
			).to.equal(LightningErrorCode.CLTV_EXCEEDS_MAX);
			expect(
				codeOf(() =>
					alice.sendPaymentWithOptions(inv.bolt11, { maxCltvExpiryHeight: 1.5 })
				)
			).to.equal(LightningErrorCode.CLTV_EXCEEDS_MAX);
			expect(alice.getPayment(hash)).to.equal(undefined);
		});

		it('gates at dispatch even when the caller bypasses the router', function () {
			const { alice, bob, channelId } = pair(7);
			const { hash } = makeExternalHash();
			const inv = bob.createInvoice({
				amountMsat: 1_000_000n,
				description: 'route',
				hold: true,
				paymentHash: hash
			});
			// Seed the retry context the way sendPayment would, with a ceiling
			// one block short of what this route's expiry (1000 + 40) needs.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(alice as any).paymentRetryContexts.set(hash.toString('hex'), {
				invoiceStr: inv.bolt11,
				excludedChannels: new Set(),
				retryCount: 0,
				maxRetries: 3,
				maxCltvExpiryHeight: 1039
			});
			const code = codeOf(() =>
				alice.sendPaymentToRoute(
					{
						hops: [
							{
								pubkey: Buffer.from(bob.getNodeId(), 'hex'),
								shortChannelId: scidForIndex(0),
								amountToForwardMsat: 1_000_000n,
								outgoingCltvValue: 40
							}
						]
					},
					hash,
					40,
					inv.paymentSecret,
					1_000_000n
				)
			);
			expect(code).to.equal(LightningErrorCode.CLTV_EXCEEDS_MAX);
			expect(alice.getPayment(hash)).to.equal(undefined);
			expect(
				offeredHtlcs(alice, channelId).filter(
					(h) =>
						h.state === HtlcState.COMMITTED || h.state === HtlcState.PENDING
				)
			).to.have.length(0);
			// The mapping was never written either.
			expect(alice.getOutgoingHtlcs(hash).htlcs).to.have.length(0);
		});

		it('a height-skew retry honours the ceiling and fails closed instead of re-sending', function () {
			// Bob is five blocks ahead: he rejects the first attempt with his
			// height, alice raises her base height for the retry, and the
			// retry no longer fits under a ceiling that the first attempt did.
			const alice = createNode(TAG, 9);
			const bob = createNode(TAG, 10);
			connectNodes(alice, bob);
			alice.handleNewBlock(1000);
			bob.handleNewBlock(1005);
			const channelId = openReadyChannel(alice, bob);
			buildGraph(alice, bob, [channelId]);

			const { hash } = makeExternalHash();
			const inv = bob.createInvoice({
				amountMsat: 1_000_000n,
				description: 'skew',
				hold: true,
				paymentHash: hash
			});
			const need = 1000 + 40 + 3;
			const payment = alice.sendPaymentWithOptions(inv.bolt11, {
				maxCltvExpiryHeight: need
			});
			// The first attempt fit and was refused by bob for being too soon;
			// the retry (base 1005) could not fit and was never dispatched.
			expect(payment.status).to.equal(PaymentStatus.FAILED);
			expect(payment.retryCount ?? 0).to.equal(0);
			expect(payment.failureReason).to.match(/retry not dispatched/i);
			expect(payment.cltvBaseHeight).to.equal(1000);
			// The refused first attempt is irrevocably failed (and pruned from
			// the channel); nothing else was ever offered.
			expect(
				offeredHtlcs(alice, channelId).filter(
					(h) => h.state !== HtlcState.FAILED
				)
			).to.have.length(0);
			const view = alice.getOutgoingHtlcs(hash);
			expect(view.resolved).to.equal(true);
			expect(view.htlcs.every((h) => h.terminal)).to.equal(true);
			expect(view.latestOutstandingExpiry).to.equal(null);
		});
	});

	describe('MPP parts', function () {
		function split(seed: number): {
			alice: LightningNode;
			bob: LightningNode;
			channels: Buffer[];
		} {
			const alice = createNode(TAG, seed);
			const bob = createNode(TAG, seed + 1);
			connectNodes(alice, bob);
			alice.handleNewBlock(1000);
			bob.handleNewBlock(1000);
			const channels = [
				openReadyChannel(alice, bob, 100_000n),
				openReadyChannel(alice, bob, 100_000n)
			];
			// Two 100k sat channels: a 150k sat invoice must split across both
			// (the invoice's own hint makes a single 90k path routable, so the
			// amount, not the advertised maximum, is what forces the split).
			buildGraph(alice, bob, channels, 100_000_000n);
			return { alice, bob, channels };
		}

		it('every part respects a ceiling that fits', function () {
			const { alice, bob, channels } = split(20);
			const { hash } = makeExternalHash();
			const inv = bob.createInvoice({
				amountMsat: 150_000_000n,
				description: 'mpp-fits',
				hold: true,
				paymentHash: hash
			});
			const need = 1000 + 40 + 3;
			const payment = alice.sendPaymentWithOptions(inv.bolt11, {
				maxCltvExpiryHeight: need
			});
			expect(payment.status).to.equal(PaymentStatus.PENDING);
			const live = channels.flatMap((c) =>
				offeredHtlcs(alice, c).filter((h) => h.state === HtlcState.COMMITTED)
			);
			expect(live).to.have.length(2);
			for (const h of live) expect(h.cltvExpiry).to.be.at.most(need);
			const view = alice.getOutgoingHtlcs(hash);
			expect(view.htlcs).to.have.length(2);
			expect(view.resolved).to.equal(false);
			expect(view.latestOutstandingExpiry).to.equal(need);
			bob.cancelHoldInvoice(hash);
		});

		it('a ceiling the parts cannot meet sends no part at all', function () {
			const { alice, bob, channels } = split(22);
			const { hash } = makeExternalHash();
			const inv = bob.createInvoice({
				amountMsat: 150_000_000n,
				description: 'mpp-tight',
				hold: true,
				paymentHash: hash
			});
			const code = codeOf(() =>
				alice.sendPaymentWithOptions(inv.bolt11, {
					maxCltvExpiryHeight: 1000 + 40 + 2
				})
			);
			expect(code).to.be.oneOf([
				LightningErrorCode.NO_ROUTE,
				LightningErrorCode.CLTV_EXCEEDS_MAX
			]);
			expect(alice.getPayment(hash)).to.equal(undefined);
			for (const c of channels) {
				expect(
					offeredHtlcs(alice, c).filter(
						(h) =>
							h.state === HtlcState.COMMITTED || h.state === HtlcState.PENDING
					)
				).to.have.length(0);
			}
			expect(bob.getHeldInvoiceSnapshot(hash)!.parts).to.have.length(0);
		});

		it('the MPP dispatch gate refuses a part whose expiry exceeds the ceiling', function () {
			// Drive sendPaymentMpp directly with a hand-built multi-route whose
			// deltas exceed the budget, so the gate (not the router) is what
			// refuses: the payment ends FAILED and no HTLC leaves either channel.
			const { alice, bob, channels } = split(24);
			const { hash } = makeExternalHash();
			const inv = bob.createInvoice({
				amountMsat: 90_000_000n,
				description: 'mpp-gate',
				hold: true,
				paymentHash: hash
			});
			const bobPub = Buffer.from(bob.getNodeId(), 'hex');
			const part = (
				i: number
			): {
				hops: Array<{
					pubkey: Buffer;
					shortChannelId: Buffer;
					amountToForwardMsat: bigint;
					outgoingCltvValue: number;
					feeBaseMsat: number;
					feeProportionalMillionths: number;
					cltvExpiryDelta: number;
				}>;
				totalAmountMsat: bigint;
				totalCltvDelta: number;
				totalFeeMsat: bigint;
			} => ({
				hops: [
					{
						pubkey: bobPub,
						shortChannelId: scidForIndex(i),
						amountToForwardMsat: 45_000_000n,
						outgoingCltvValue: 60,
						feeBaseMsat: 0,
						feeProportionalMillionths: 0,
						cltvExpiryDelta: 0
					}
				],
				totalAmountMsat: 45_000_000n,
				totalCltvDelta: 60,
				totalFeeMsat: 0n
			});
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const payment = (alice as any).sendPaymentMpp(
				inv.bolt11,
				{
					paymentHash: hash,
					paymentSecret: inv.paymentSecret,
					amountMsat: 90_000_000n
				},
				{
					parts: [part(0), part(1)],
					totalAmountMsat: 90_000_000n,
					totalFeeMsat: 0n
				},
				43,
				undefined,
				1050
			);
			expect(payment.status).to.equal(PaymentStatus.FAILED);
			expect(payment.failureReason).to.match(/ceiling/);
			for (const c of channels) {
				expect(
					offeredHtlcs(alice, c).filter(
						(h) =>
							h.state === HtlcState.COMMITTED || h.state === HtlcState.PENDING
					)
				).to.have.length(0);
			}
			expect(alice.getOutgoingHtlcs(hash).htlcs).to.have.length(0);
		});
	});

	describe('findRouteToBlindedPath', function () {
		it('bounds the self-introduction tail by maxCltvExpiry', function () {
			const graph = new NetworkGraph();
			const source = getPublicKey(crypto.randomBytes(32));
			const blindedPath = {
				introductionNodeId: source,
				blindingPoint: getPublicKey(crypto.randomBytes(32)),
				blindedHops: [
					{
						blindedNodeId: getPublicKey(crypto.randomBytes(32)),
						encryptedData: Buffer.alloc(8, 1)
					},
					{
						blindedNodeId: getPublicKey(crypto.randomBytes(32)),
						encryptedData: Buffer.alloc(8, 2)
					}
				]
			};
			const payInfo = {
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				cltvExpiryDelta: 100,
				htlcMinimumMsat: 1n,
				htlcMaximumMsat: 1_000_000_000n
			};
			const route = findRouteToBlindedPath(
				graph,
				source,
				blindedPath,
				payInfo,
				1_000n,
				40
			);
			expect(route).to.not.equal(null);
			expect(route!.totalCltvDelta).to.equal(140);
			expect(
				findRouteToBlindedPath(
					graph,
					source,
					blindedPath,
					payInfo,
					1_000n,
					40,
					undefined,
					undefined,
					undefined,
					undefined,
					139
				)
			).to.equal(null);
			expect(
				findRouteToBlindedPath(
					graph,
					source,
					blindedPath,
					payInfo,
					1_000n,
					40,
					undefined,
					undefined,
					undefined,
					undefined,
					140
				)
			).to.not.equal(null);
		});
	});
});
