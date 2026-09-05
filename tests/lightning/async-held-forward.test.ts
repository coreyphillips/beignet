/**
 * Async held forwards (issue #708): authenticated per-part durable state and
 * real offline behaviour. The world (Alice -> LSP -> Carol, crash-injecting
 * storage, event wire) lives in helpers/async-world.ts, shared with the
 * async receive service suite (issue #709).
 *
 * One test per acceptance criterion of the issue:
 *  - an unauthorized peer that knows the payment hash cannot release;
 *  - parts sharing one hash stay distinct and each resolves exactly once;
 *  - duplicate add, release, fail and replay inputs are idempotent;
 *  - a real disconnect/reconnect succeeds while CLTV remains;
 *  - a crash at every lifecycle boundary recovers deterministically;
 *  - restart plus channel_reestablish never duplicates the downstream add;
 *  - a release racing the CLTV cutoff has exactly one durable winner;
 *  - partial MPP arrival, retry reuse and force-close-relevant timing.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { ChannelState, HtlcState } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { IHeldForwardRecord } from '../../src/lightning/async-payments/held-forward-ledger';
import { RELEASE_HELD_HTLC_TLV_TYPE } from '../../src/lightning/async-payments/types';
import {
	deriveHoldRegistrationId,
	encodeReleaseCapability,
	signReleaseCapability
} from '../../src/lightning/async-payments/release-capability';
import {
	ICrashPlan,
	IWorld,
	LSP_SEED,
	MALLORY_SEED,
	asyncInvoice,
	buildOnionFrom,
	channelSaveWithReceivedHtlcState,
	crashingStorage,
	createNode,
	destroyAll,
	disconnect,
	heldRecords,
	nodePrivkey,
	observe,
	payPart,
	readRow,
	receivedHtlcCount,
	reconnect,
	reconnectRestarted,
	rowInState,
	settle,
	setupWorld,
	tapOnion,
	tempDb,
	waitFor,
	wire
} from './helpers/async-world';

// ─────────────── Tests ───────────────

describe('Async held forwards (issue #708)', () => {
	describe('authorization', () => {
		it('an unauthorized peer that knows the payment hash cannot release a hold', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol } = w;
			// Mallory is a peer of the LSP (onion messages need no channel).
			const mallory = createNode(MALLORY_SEED);
			wire(mallory, lsp, { val: false });

			const invoice = asyncInvoice(carol, 5_000_000n);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [record] = heldRecords(lsp);
			expect(record.state).to.equal('HELD');
			const holdId = Buffer.from(record.id, 'hex');
			const lspId = Buffer.from(lsp.getNodeId(), 'hex');
			const carolId = Buffer.from(carol.getNodeId(), 'hex');
			const malloryId = Buffer.from(mallory.getNodeId(), 'hex');
			const chainHash = (
				lsp as unknown as { chainHash: () => Buffer }
			).chainHash();
			const sendFrom = (node: LightningNode, bytes: Buffer): void =>
				node
					.getOnionMessageManager()
					.sendOnionMessage(
						lspId,
						new Map([[RELEASE_HELD_HTLC_TLV_TYPE, bytes]])
					);

			// 1. The hash itself, the old protocol's whole token.
			sendFrom(mallory, invoice.paymentHash);
			// 2. A capability naming Carol as receiver, signed by Mallory.
			sendFrom(
				mallory,
				encodeReleaseCapability(
					signReleaseCapability(
						{
							chainHash,
							receiverNodeId: carolId,
							lspNodeId: lspId,
							registrationId: deriveHoldRegistrationId(carolId, lspId),
							amountMsat: BigInt(record.forwardAmountMsat),
							expiresAt: BigInt(Math.floor(Date.now() / 1000) + 600),
							nonce: crypto.randomBytes(32),
							holdIds: [holdId]
						},
						nodePrivkey(MALLORY_SEED)
					)
				)
			);
			// 3. A capability naming Mallory herself, correctly signed, for a
			//    hold that is Carol's.
			sendFrom(
				mallory,
				encodeReleaseCapability(
					signReleaseCapability(
						{
							chainHash,
							receiverNodeId: malloryId,
							lspNodeId: lspId,
							registrationId: deriveHoldRegistrationId(malloryId, lspId),
							amountMsat: BigInt(record.forwardAmountMsat),
							expiresAt: BigInt(Math.floor(Date.now() / 1000) + 600),
							nonce: crypto.randomBytes(32),
							holdIds: [holdId]
						},
						nodePrivkey(MALLORY_SEED)
					)
				)
			);
			// 4. Carol's genuine capability, obtained somehow, replayed by
			//    Mallory over her own connection.
			const genuine = carol
				.getAsyncPaymentManager()
				.buildRelease(lspId, [holdId], BigInt(record.forwardAmountMsat));
			sendFrom(mallory, encodeReleaseCapability(genuine));
			// 5. Carol herself, but with the wrong registration, amount, or an
			//    expired capability.
			sendFrom(
				carol,
				encodeReleaseCapability(
					carol
						.getAsyncPaymentManager()
						.buildRelease(lspId, [holdId], BigInt(record.forwardAmountMsat), {
							registrationId: Buffer.alloc(32, 1)
						})
				)
			);
			sendFrom(
				carol,
				encodeReleaseCapability(
					carol
						.getAsyncPaymentManager()
						.buildRelease(
							lspId,
							[holdId],
							BigInt(record.forwardAmountMsat) + 1n
						)
				)
			);
			sendFrom(
				carol,
				encodeReleaseCapability(
					carol
						.getAsyncPaymentManager()
						.buildRelease(lspId, [holdId], BigInt(record.forwardAmountMsat), {
							ttlSec: -100
						})
				)
			);
			await settle();

			expect(w.refusals).to.deep.equal([
				'malformed',
				'sender_mismatch',
				'unknown_hold',
				'sender_mismatch',
				'registration_mismatch',
				'amount_mismatch',
				'expired'
			]);
			expect(heldRecords(lsp)[0].state, 'still parked').to.equal('HELD');
			expect(w.forwards).to.equal(0);
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);

			// The genuine capability from Carol's own connection releases.
			sendFrom(carol, encodeReleaseCapability(genuine));
			await settle();
			expect(heldRecords(lsp)[0].state).to.equal('RELEASED');
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(w.forwards).to.equal(1);
			destroyAll(alice, lsp, carol, mallory);
		});
	});

	describe('per-part identity', () => {
		it('two parts with one payment hash stay distinct and each resolves exactly once', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol } = w;
			const total = 100_000_000n;
			const invoice = asyncInvoice(carol, total);
			const released: string[] = [];
			lsp.on('htlc:held-forward-released', (r: IHeldForwardRecord) =>
				released.push(r.id)
			);

			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total / 2n,
				total
			);
			await settle();
			expect(heldRecords(lsp), 'first part parked').to.have.length(1);
			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total / 2n,
				total
			);
			await settle();
			const records = heldRecords(lsp);
			expect(records, 'second part parked as its own row').to.have.length(2);
			expect(records[0].id).to.not.equal(records[1].id);
			expect(records[0].paymentHashHex).to.equal(records[1].paymentHashHex);
			expect(records[0].inHtlcId).to.not.equal(records[1].inHtlcId);
			expect(records.every((r) => r.state === 'HELD')).to.equal(true);
			// The payment-level index groups them; the second notice lists both.
			expect(w.notices).to.have.length(2);
			expect(w.notices[1].notice.entries).to.have.length(2);

			// Atomic set release: one capability over the complete set.
			const sum = records.reduce((s, r) => s + BigInt(r.forwardAmountMsat), 0n);
			carol.sendAsyncRelease(
				Buffer.from(lsp.getNodeId(), 'hex'),
				records.map((r) => Buffer.from(r.id, 'hex')),
				sum
			);
			await settle();
			const after = heldRecords(lsp);
			expect(after.map((r) => r.state)).to.deep.equal(['RELEASED', 'RELEASED']);
			expect(after[0].releaseNonceHex, 'released as ONE set').to.equal(
				after[1].releaseNonceHex
			);
			expect(released.sort()).to.deep.equal(records.map((r) => r.id).sort());
			expect(w.forwards, 'one add per part').to.equal(2);
			const carolPayment = carol.getPayment(invoice.paymentHash)!;
			expect(carolPayment.status).to.equal(PaymentStatus.COMPLETED);
			expect(Number(carolPayment.amountMsat)).to.equal(Number(total));
			destroyAll(alice, lsp, carol);
		});

		it('partial MPP arrival is never released; the set goes when the total is covered', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: true });
			const { alice, lsp, carol } = w;
			const total = 100_000_000n;
			const invoice = asyncInvoice(carol, total);

			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total / 2n,
				total
			);
			await settle();
			expect(w.notices, 'Carol was told about the first part').to.have.length(
				1
			);
			expect(heldRecords(lsp)[0].state, 'half a payment stays parked').to.equal(
				'HELD'
			);
			expect(w.forwards).to.equal(0);

			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total / 2n,
				total
			);
			await settle();
			const records = heldRecords(lsp);
			expect(records.map((r) => r.state)).to.deep.equal([
				'RELEASED',
				'RELEASED'
			]);
			expect(records[0].releaseNonceHex).to.equal(records[1].releaseNonceHex);
			expect(w.forwards).to.equal(2);
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			destroyAll(alice, lsp, carol);
		});

		it('an amount-less invoice releases each part independently', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: true });
			const { alice, lsp, carol } = w;
			const invoice = asyncInvoice(carol, undefined);
			alice.sendPayment(invoice.bolt11, undefined, undefined, 3_000_000n);
			await settle();
			const [record] = heldRecords(lsp);
			expect(record.state).to.equal('RELEASED');
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('idempotency', () => {
		it('duplicate add, release, fail and replay inputs are idempotent', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol, abChannelId } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);
			const carolToLsp = tapOnion(carol, lsp);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [record] = heldRecords(lsp);

			// Duplicate add: the restart redispatch and a replayed dispatch of
			// the same inbound HTLC both re-enter the hold path.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const priv = lsp as any;
			priv.redispatchUnresolvedReceivedHtlcs(abChannelId);
			priv.handleIncomingHtlc(
				abChannelId,
				BigInt(record.inHtlcId),
				BigInt(record.incomingAmountMsat),
				invoice.paymentHash
			);
			await settle();
			expect(heldRecords(lsp), 'one row for one HTLC').to.have.length(1);
			expect(heldRecords(lsp)[0].id, 'same hold id').to.equal(record.id);

			// Release, then replay the very same capability bytes.
			carol.sendAsyncRelease(
				Buffer.from(lsp.getNodeId(), 'hex'),
				[Buffer.from(record.id, 'hex')],
				BigInt(record.forwardAmountMsat)
			);
			await settle();
			expect(heldRecords(lsp)[0].state).to.equal('RELEASED');
			expect(w.forwards).to.equal(1);
			expect(carolToLsp, 'the release was captured').to.have.length(1);
			lsp.handlePeerMessage(
				carol.getNodeId(),
				MessageType.ONION_MESSAGE,
				carolToLsp[0]
			);
			lsp.handlePeerMessage(
				carol.getNodeId(),
				MessageType.ONION_MESSAGE,
				carolToLsp[0]
			);
			await settle();
			expect(w.forwards, 'a replayed release forwards nothing').to.equal(1);
			expect(
				w.refusals,
				'a replay is a silent duplicate, not a refusal'
			).to.deep.equal([]);
			expect(heldRecords(lsp)[0].state).to.equal('RELEASED');
			// A fresh capability for a resolved hold is stale, not an action.
			carol.sendAsyncRelease(
				Buffer.from(lsp.getNodeId(), 'hex'),
				[Buffer.from(record.id, 'hex')],
				BigInt(record.forwardAmountMsat)
			);
			await settle();
			expect(w.refusals).to.deep.equal(['stale']);
			expect(w.forwards).to.equal(1);

			// Duplicate fail on a second hold: the first fail acts, the second
			// is a no-op, and a release after the fail loses.
			const invoice2 = asyncInvoice(carol, 4_000_000n);
			alice.sendPayment(invoice2.bolt11);
			await settle();
			const second = heldRecords(lsp).find((r) => r.state === 'HELD')!;
			expect(lsp.failHeldForward(second.id)).to.equal(true);
			expect(lsp.failHeldForward(second.id)).to.equal(false);
			await settle();
			expect(
				lsp.listHeldForwards().find((r) => r.id === second.id)!.state
			).to.equal('FAILED');
			expect(alice.getPayment(invoice2.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			carol.sendAsyncRelease(
				Buffer.from(lsp.getNodeId(), 'hex'),
				[Buffer.from(second.id, 'hex')],
				BigInt(second.forwardAmountMsat)
			);
			await settle();
			expect(w.refusals).to.deep.equal(['stale', 'stale']);
			expect(w.forwards).to.equal(1);
			destroyAll(alice, lsp, carol);
		});

		it('a retry after a failed hold gets its own hold, and the old capability cannot touch it', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol } = w;
			const total = 5_000_000n;
			const invoice = asyncInvoice(carol, total);
			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total,
				total
			);
			await settle();
			const first = heldRecords(lsp)[0];
			const lspId = Buffer.from(lsp.getNodeId(), 'hex');
			const oldCap = carol
				.getAsyncPaymentManager()
				.buildRelease(lspId, [Buffer.from(first.id, 'hex')], total);
			expect(lsp.failHeldForward(first.id)).to.equal(true);
			await settle();
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);

			// The payer retries the same invoice: same hash, new HTLC, new hold.
			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total,
				total
			);
			await settle();
			const records = heldRecords(lsp);
			expect(records).to.have.length(2);
			const retry = records.find((r) => r.state === 'HELD')!;
			expect(retry.id).to.not.equal(first.id);
			expect(retry.paymentHashHex).to.equal(first.paymentHashHex);
			expect(retry.inHtlcId).to.not.equal(first.inHtlcId);

			carol
				.getOnionMessageManager()
				.sendOnionMessage(
					lspId,
					new Map([
						[RELEASE_HELD_HTLC_TLV_TYPE, encodeReleaseCapability(oldCap)]
					])
				);
			await settle();
			expect(w.refusals, 'the old hold is terminal').to.deep.equal(['stale']);
			expect(
				lsp.listHeldForwards().find((r) => r.id === retry.id)!.state
			).to.equal('HELD');
			carol.sendAsyncRelease(lspId, [Buffer.from(retry.id, 'hex')], total);
			await settle();
			expect(
				lsp.listHeldForwards().find((r) => r.id === retry.id)!.state
			).to.equal('RELEASED');
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(w.forwards).to.equal(1);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('offline receiver', () => {
		it('a real peer disconnect and reconnect succeeds when enough CLTV remains', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: true });
			const { alice, lsp, carol, bcChannelId } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);

			// Carol goes offline for real: the link is cut and both sides run
			// their disconnect handling, so the LSP's channel to her is
			// AWAITING_REESTABLISH and cannot carry an add.
			await disconnect(lsp, carol, w.cutBC);
			expect(
				lsp.getChannelManager().getChannel(bcChannelId)!.getState()
			).to.equal(ChannelState.AWAITING_REESTABLISH);

			alice.sendPayment(invoice.bolt11);
			await settle();
			const [record] = heldRecords(lsp);
			expect(record.state).to.equal('HELD');
			expect(w.notices, 'nothing reaches an offline receiver').to.have.length(
				0
			);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);

			// Carol comes back: channel_reestablish both ways, then the LSP's
			// notice, Carol's signed release, the add, and the fulfill.
			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					carol.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.COMPLETED,
				'Carol to be paid after reconnecting'
			);
			expect(w.notices).to.have.length(1);
			expect(heldRecords(lsp)[0].state).to.equal('RELEASED');
			expect(w.forwards).to.equal(1);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			destroyAll(alice, lsp, carol);
		});

		it('a release that arrives while the outgoing channel is still reestablishing is deferred, not refused', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol, bcChannelId } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [record] = heldRecords(lsp);
			const lspId = Buffer.from(lsp.getNodeId(), 'hex');
			const cap = carol
				.getAsyncPaymentManager()
				.buildRelease(
					lspId,
					[Buffer.from(record.id, 'hex')],
					BigInt(record.forwardAmountMsat)
				);

			await disconnect(lsp, carol, w.cutBC);
			// Reconnect, but deliver Carol's release BEFORE the reestablish
			// messages are drained: the LSP sees it on a channel that is not
			// yet usable.
			await reconnect(lsp, carol, w.cutBC, w.gateBC, () => {
				lsp.handlePeerMessage(
					carol.getNodeId(),
					MessageType.ONION_MESSAGE,
					buildOnionFrom(carol, lspId, encodeReleaseCapability(cap))
				);
				expect(
					lsp.getChannelManager().getChannel(bcChannelId)!.getState()
				).to.equal(ChannelState.AWAITING_REESTABLISH);
				expect(heldRecords(lsp)[0].state, 'release won, add deferred').to.equal(
					'RELEASING'
				);
				expect(w.forwards).to.equal(0);
			});
			await waitFor(
				() => heldRecords(lsp)[0].state === 'RELEASED',
				'the deferred add to be placed once the channel is usable'
			);
			expect(w.forwards).to.equal(1);
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('holding-node crash at every lifecycle boundary', () => {
		interface IBoundary {
			name: string;
			plan: ICrashPlan;
			/** What the restarted LSP must end at. */
			expect: 'paid-once' | 'failed';
			/** Whether the pre-crash hold id survives (the row landed). */
			sameHoldId: boolean;
			/** Drive the cutoff before the crash point (fail boundaries). */
			viaCutoff?: boolean;
		}
		const boundaries: IBoundary[] = [
			{
				name: 'before the HELD row commits',
				plan: { phase: 'before-commit', when: rowInState('HELD') },
				expect: 'paid-once',
				sameHoldId: false
			},
			{
				name: 'after the HELD row commits',
				plan: { phase: 'after-commit', when: rowInState('HELD') },
				expect: 'paid-once',
				sameHoldId: true
			},
			{
				name: 'after the RELEASING row commits, before the add',
				plan: { phase: 'after-commit', when: rowInState('RELEASING') },
				expect: 'paid-once',
				sameHoldId: true
			},
			{
				name: 'after the add commits, before the RELEASED row',
				plan: {
					phase: 'after-commit',
					when: (writes) => writes.some((x) => x.method === 'saveForwardedHtlc')
				},
				expect: 'paid-once',
				sameHoldId: true
			},
			{
				name: 'after the FAILING row commits, before the fail',
				plan: { phase: 'after-commit', when: rowInState('FAILING') },
				expect: 'failed',
				sameHoldId: true,
				viaCutoff: true
			},
			{
				name: 'after the fail commits, before the FAILED row',
				plan: {
					phase: 'after-commit',
					when: channelSaveWithReceivedHtlcState(HtlcState.FAILED)
				},
				expect: 'failed',
				sameHoldId: true,
				viaCutoff: true
			}
		];

		for (const b of boundaries) {
			it(`recovers deterministically from a crash ${b.name}`, async function () {
				this.timeout(30_000);
				const dbPath = tempDb('held-forward-crash');
				const raw = new SqliteStorage(dbPath);
				raw.open();
				const dead = { val: false };
				const w = await setupWorld({
					lspStorage: crashingStorage(raw, dead, b.plan),
					dead,
					carolAutoRelease: true
				});
				const { alice, lsp, carol, abChannelId, bcChannelId } = w;
				const invoice = asyncInvoice(carol, 5_000_000n);

				// Carol is offline while Alice pays, as an async receiver is.
				await disconnect(lsp, carol, w.cutBC);
				alice.sendPayment(invoice.bolt11);
				await settle();
				// The zombie's memory is not evidence (its writes stopped landing);
				// only the id it minted matters, and only when the row landed.
				const before: IHeldForwardRecord | undefined = heldRecords(lsp)[0];
				if (b.viaCutoff) {
					expect(dead.val, 'alive until the cutoff').to.equal(false);
					lsp.handleNewBlock(before!.cutoffHeight);
					await settle();
				} else if (!dead.val) {
					// Release boundaries: Carol reconnects and releases.
					await reconnect(lsp, carol, w.cutBC, w.gateBC);
					await settle();
				}
				expect(dead.val, `the LSP died ${b.name}`).to.equal(true);

				// The process is gone: peers notice, and the zombie is dropped.
				const lspId = lsp.getNodeId();
				lsp.destroy();
				alice.getChannelManager().handlePeerDisconnected(lspId);
				carol.getChannelManager().handlePeerDisconnected(lspId);
				alice.removeAllListeners('message:outbound');
				carol.removeAllListeners('message:outbound');
				const paidBeforeRestart =
					carol.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.COMPLETED;

				const disk = new SqliteStorage(dbPath);
				disk.open();
				const restored = createNode(LSP_SEED, disk, {
					asyncReceiveService: { enabled: true }
				});
				const w2: IWorld = { ...w, lsp: restored, refusals: [], forwards: 0 };
				observe(w2, restored, carol);
				// The payer's channel reestablishes first (its redispatch
				// re-parks or re-drives the hold), then the receiver's.
				await reconnectRestarted(restored, alice);
				await reconnectRestarted(restored, carol);
				await settle(10);

				const rows = heldRecords(restored);
				expect(rows, 'exactly one hold on disk after restart').to.have.length(
					1
				);
				if (b.sameHoldId) {
					expect(rows[0].id, 'the hold id survived').to.equal(before!.id);
				} else {
					expect(rows[0].id, 'a fresh hold id').to.not.equal(before?.id);
				}
				if (b.expect === 'paid-once') {
					await waitFor(
						() =>
							carol.getPayment(invoice.paymentHash)?.status ===
							PaymentStatus.COMPLETED,
						'Carol to be paid'
					);
					expect(heldRecords(restored)[0].state).to.equal('RELEASED');
					expect(readRow(dbPath, rows[0].id)!.state, 'durable').to.equal(
						'RELEASED'
					);
					expect(
						Number(carol.getPayment(invoice.paymentHash)!.amountMsat),
						'paid exactly the invoice amount, never twice'
					).to.equal(5_000_000);
					expect(
						receivedHtlcCount(carol, bcChannelId) + (paidBeforeRestart ? 1 : 0),
						'at most one add ever reached Carol'
					).to.be.at.most(1);
					await waitFor(
						() =>
							alice.getPayment(invoice.paymentHash)?.status ===
							PaymentStatus.COMPLETED,
						'Alice to settle'
					);
				} else {
					await waitFor(
						() =>
							alice.getPayment(invoice.paymentHash)?.status ===
							PaymentStatus.FAILED,
						'Alice to see the failure'
					);
					expect(heldRecords(restored)[0].state).to.equal('FAILED');
					expect(readRow(dbPath, rows[0].id)!.state, 'durable').to.equal(
						'FAILED'
					);
					expect(w2.forwards, 'nothing forwarded').to.equal(0);
					expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
						PaymentStatus.PENDING
					);
				}
				// No channel was lost to the crash.
				expect(
					restored.getChannelManager().getChannel(abChannelId)!.getState()
				).to.equal(ChannelState.NORMAL);
				expect(
					restored.getChannelManager().getChannel(bcChannelId)!.getState()
				).to.equal(ChannelState.NORMAL);
				destroyAll(alice, restored, carol);
			});
		}

		it('restart plus channel_reestablish never duplicates the downstream add', async function () {
			this.timeout(30_000);
			// The add landed and Carol had it, then the LSP died before it
			// could record RELEASED: the retransmission on reestablish and the
			// redispatch of the inbound leg must both leave one add.
			const dbPath = tempDb('held-forward-dup');
			const raw = new SqliteStorage(dbPath);
			raw.open();
			const dead = { val: false };
			const w = await setupWorld({
				lspStorage: crashingStorage(raw, dead, {
					phase: 'after-commit',
					when: (writes) => writes.some((x) => x.method === 'saveForwardedHtlc')
				}),
				dead,
				carolAutoRelease: true
			});
			const { alice, lsp, carol, bcChannelId } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);
			alice.sendPayment(invoice.bolt11);
			await settle();
			expect(dead.val, 'died right after the add committed').to.equal(true);
			const before = heldRecords(lsp)[0];

			const lspId = lsp.getNodeId();
			lsp.destroy();
			alice.getChannelManager().handlePeerDisconnected(lspId);
			carol.getChannelManager().handlePeerDisconnected(lspId);
			alice.removeAllListeners('message:outbound');
			carol.removeAllListeners('message:outbound');

			const disk = new SqliteStorage(dbPath);
			disk.open();
			expect(readRow(dbPath, before.id)!.state, 'RELEASING on disk').to.equal(
				'RELEASING'
			);
			const restored = createNode(LSP_SEED, disk, {
				asyncReceiveService: { enabled: true }
			});
			const w2: IWorld = { ...w, lsp: restored, refusals: [], forwards: 0 };
			observe(w2, restored, carol);
			let addsAfterRestart = 0;
			restored.on('message:outbound', (pk: string, t: number) => {
				if (pk === carol.getNodeId() && t === MessageType.UPDATE_ADD_HTLC) {
					addsAfterRestart++;
				}
			});
			await reconnectRestarted(restored, alice);
			await reconnectRestarted(restored, carol);
			await waitFor(
				() =>
					alice.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.COMPLETED,
				'the payment to complete after the restart'
			);
			expect(heldRecords(restored)[0].state).to.equal('RELEASED');
			expect(w2.forwards, 'the redispatch placed no second add').to.equal(0);
			expect(addsAfterRestart, 'only the BOLT 2 retransmission').to.be.at.most(
				1
			);
			expect(
				Number(carol.getPayment(invoice.paymentHash)!.amountMsat)
			).to.equal(5_000_000);
			expect(receivedHtlcCount(carol, bcChannelId)).to.be.at.most(1);
			destroyAll(alice, restored, carol);
		});
	});

	describe('CLTV cutoff', () => {
		it('fixes the cutoff on the row from the receiver headroom and the LSP margin', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [r] = heldRecords(lsp);
			// DEFAULT_MIN_FINAL_CLTV_EXPIRY = 40 (the receiver refuses less);
			// HELD_HTLC_EXPIRY_MARGIN = 18, htlcSafetyMargin default 6.
			expect(r.cutoffHeight).to.equal(
				Math.min(r.forwardCltv - 40, r.incomingCltvExpiry - 18)
			);
			expect(
				r.cutoffHeight,
				'well before the inbound leg goes on-chain'
			).to.be.below(r.incomingCltvExpiry - 18);
			// A block short of the cutoff changes nothing.
			lsp.handleNewBlock(r.cutoffHeight - 1);
			await settle();
			expect(heldRecords(lsp)[0].state).to.equal('HELD');
			destroyAll(alice, lsp, carol);
		});

		for (const releaseFirst of [true, false]) {
			it(`release racing the cutoff has one durable winner (${
				releaseFirst ? 'release' : 'cutoff'
			} lands first)`, async function () {
				this.timeout(20_000);
				const dbPath = tempDb('held-forward-race');
				const disk = new SqliteStorage(dbPath);
				disk.open();
				const w = await setupWorld({
					lspStorage: disk,
					carolAutoRelease: false
				});
				const { alice, lsp, carol, abChannelId } = w;
				const invoice = asyncInvoice(carol, 5_000_000n);
				alice.sendPayment(invoice.bolt11);
				await settle();
				const [r] = heldRecords(lsp);
				const lspId = Buffer.from(lsp.getNodeId(), 'hex');
				const cap = carol
					.getAsyncPaymentManager()
					.buildRelease(
						lspId,
						[Buffer.from(r.id, 'hex')],
						BigInt(r.forwardAmountMsat)
					);
				const release = (): void =>
					lsp.handlePeerMessage(
						carol.getNodeId(),
						MessageType.ONION_MESSAGE,
						buildOnionFrom(carol, lspId, encodeReleaseCapability(cap))
					);
				const cutoff = (): void => lsp.handleNewBlock(r.cutoffHeight);

				if (releaseFirst) {
					release();
					cutoff();
				} else {
					cutoff();
					release();
				}
				await settle();

				const final = heldRecords(lsp)[0];
				if (releaseFirst) {
					expect(final.state).to.equal('RELEASED');
					expect(w.forwards).to.equal(1);
					expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
						PaymentStatus.COMPLETED
					);
					expect(w.refusals).to.deep.equal([]);
				} else {
					expect(final.state).to.equal('FAILED');
					expect(final.failReason).to.equal('cutoff');
					expect(w.forwards).to.equal(0);
					expect(w.refusals).to.deep.equal(['past_cutoff']);
					expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
						PaymentStatus.FAILED
					);
					// Failed off-chain, while the inbound channel stays healthy:
					// the mandatory failure is what keeps this off the chain.
					const inbound = lsp.getChannelManager().getChannel(abChannelId)!;
					expect(inbound.getState()).to.equal(ChannelState.NORMAL);
					expect(
						[...inbound.getFullState().htlcs.values()].some(
							(h) => h.state === HtlcState.COMMITTED
						)
					).to.equal(false);
				}
				// The winner is on disk, not just in memory.
				expect(readRow(dbPath, r.id)!.state).to.equal(final.state);
				destroyAll(alice, lsp, carol);
			});
		}
	});
});

/**
 * Build the raw onion_message a node would send to `to` with this payload,
 * without sending it, so a test can deliver it at a chosen instant.
 */
describe('Async held forwards, review round 1 (issue #708)', () => {
	describe('release drive', () => {
		it('an atomic set release forwards every part or none', async function () {
			this.timeout(20_000);
			// "The LSP moves the set in one transaction or not at all": the
			// ledger transition was atomic, but the adds were placed one by
			// one and nothing checked the outgoing channel could carry the
			// whole set (in-flight ceiling, max_accepted_htlcs, balance). When
			// the second add was refused the first was already at the receiver:
			// one row RELEASED, one FAILED, half an MPP at the receiver until
			// its timeout and a refunded part at the payer. Now every unplaced
			// member is judged together before the first add leaves, and a set
			// that does not fit is failed back whole.
			const w = await setupWorld({ carolAutoRelease: true });
			const { alice, lsp, carol, bcChannelId } = w;
			const total = 5_000_000n;
			const invoice = asyncInvoice(carol, total);
			await disconnect(lsp, carol, w.cutBC);
			for (let i = 0; i < 2; i++) {
				payPart(
					alice,
					invoice.bolt11,
					invoice.paymentHash,
					invoice.paymentSecret,
					total / 2n,
					total
				);
				await settle();
			}
			expect(heldRecords(lsp).map((r) => r.state)).to.deep.equal([
				'HELD',
				'HELD'
			]);
			// The receiver's in-flight ceiling, as the LSP knows it, admits one
			// part but not both.
			lsp
				.getChannelManager()
				.getChannel(bcChannelId)!
				.getFullState().remoteConfig.maxHtlcValueInFlightMsat = 3_000_000n;
			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await settle();
			const states = heldRecords(lsp).map((r) => r.state);
			expect(new Set(states).size, `all or nothing, got ${states}`).to.equal(1);
			expect(states[0]).to.equal('FAILED');
			expect(w.forwards, 'no half-delivered payment').to.equal(0);
			expect(receivedHtlcCount(carol, bcChannelId)).to.equal(0);
			await waitFor(
				() =>
					alice.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the payer to be refunded both parts'
			);
			destroyAll(alice, lsp, carol);
		});

		it('a release whose add is refused while the inbound channel is reestablishing still resolves the inbound HTLC', async function () {
			this.timeout(20_000);
			// Exactly-once resolution of the incoming HTLC. The refusal path
			// called failIncoming, which the reestablishing inbound channel
			// refused; without a JIT engine the owed refund was dropped, yet
			// the row went FAILED (forward_refused) as if resolved. Nothing
			// owned the inbound HTLC until the generic expiry scan. Now the
			// refund is owed by the node and carried on the channel's
			// reestablish (and per block), and a restart's redispatch of a
			// FAILED row with a committed inbound HTLC owes it again.
			const w = await setupWorld({ carolAutoRelease: true });
			const { alice, lsp, carol, abChannelId, bcChannelId } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);
			await disconnect(lsp, carol, w.cutBC);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [row] = heldRecords(lsp);
			expect(row.state).to.equal('HELD');
			lsp
				.getChannelManager()
				.getChannel(bcChannelId)!
				.getFullState().remoteConfig.maxHtlcValueInFlightMsat = 1_000_000n;
			// The payer's link is down when the receiver comes back and releases.
			await disconnect(alice, lsp, w.cutAB);
			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await settle();
			expect(heldRecords(lsp)[0].state).to.equal('FAILED');
			expect(heldRecords(lsp)[0].failReason).to.equal('forward_refused');
			await reconnect(alice, lsp, w.cutAB, w.gateAB);
			await settle(10);
			const inbound = lsp
				.getChannelManager()
				.getChannel(abChannelId)!
				.getFullState()
				.htlcs.get(`received-${row.inHtlcId}`);
			expect(
				inbound?.state,
				'the inbound HTLC must be failed once the channel can carry it'
			).to.not.equal(HtlcState.COMMITTED);
			await waitFor(
				() =>
					alice.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the payer to be refunded',
				3_000
			);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('cutoff after a restart', () => {
		it('a restarted LSP does not release a hold its previous process had already judged past the cutoff', async function () {
			this.timeout(30_000);
			// The block height was persisted at the END of the per-block work,
			// so a process that died inside the cutoff scan (here: the FAILING
			// write rolled back) restarted at the height it had before that
			// block, and both handleRelease and scan skip the cutoff until a
			// block arrives. Carol's reconnect notice was answered with a
			// release the previous process had refused. The height is now
			// durable BEFORE the work judged at it.
			const dbPath = tempDb('held-forward-review-cutoff');
			const raw = new SqliteStorage(dbPath);
			raw.open();
			const dead = { val: false };
			const w = await setupWorld({
				lspStorage: crashingStorage(raw, dead, {
					phase: 'before-commit',
					when: rowInState('FAILING')
				}),
				dead,
				carolAutoRelease: true
			});
			const { alice, lsp, carol } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);
			await disconnect(lsp, carol, w.cutBC);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const before = heldRecords(lsp)[0];
			lsp.handleNewBlock(before.cutoffHeight);
			await settle();
			expect(dead.val, 'died at the cutoff scan').to.equal(true);

			const lspId = lsp.getNodeId();
			lsp.destroy();
			alice.getChannelManager().handlePeerDisconnected(lspId);
			carol.getChannelManager().handlePeerDisconnected(lspId);
			alice.removeAllListeners('message:outbound');
			carol.removeAllListeners('message:outbound');
			const disk = new SqliteStorage(dbPath);
			disk.open();
			const restored = createNode(LSP_SEED, disk, {
				asyncReceiveService: { enabled: true }
			});
			const w2: IWorld = { ...w, lsp: restored, refusals: [], forwards: 0 };
			observe(w2, restored, carol);
			await reconnectRestarted(restored, alice);
			await reconnectRestarted(restored, carol);
			await settle(10);
			expect(
				heldRecords(restored)[0].state,
				'a hold at its cutoff is never released'
			).to.not.equal('RELEASED');
			expect(w2.refusals).to.deep.equal(['past_cutoff']);
			expect(w2.forwards, 'no add past the cutoff').to.equal(0);
			restored.handleNewBlock(before.cutoffHeight);
			await waitFor(
				() =>
					alice.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the payer to be refunded at the cutoff',
				5_000
			);
			destroyAll(alice, restored, carol);
		});
	});
});

function buildOnionFrom(
	from: LightningNode,
	to: Buffer,
	payload: Buffer
): Buffer {
	let captured: Buffer | null = null;
	const om = from.getOnionMessageManager();
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const saved = (om as any).sendMessage;
	om.setSendFunction((_peer: string, _type: number, p: Buffer) => {
		captured = Buffer.from(p);
	});
	om.sendOnionMessage(to, new Map([[RELEASE_HELD_HTLC_TLV_TYPE, payload]]));
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(om as any).sendMessage = saved;
	expect(captured, 'onion message built').to.not.equal(null);
	return captured!;
}
