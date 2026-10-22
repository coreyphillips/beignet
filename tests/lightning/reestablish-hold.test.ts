/**
 * Reestablish hold (issue #1726).
 *
 * Alice -> LSP -> Carol over ordinary BOLT 11 invoices, no blinded path and
 * no grant. The LSP runs the JIT receive role and opened Carol's channel,
 * which makes Carol a liquidity client. When Carol's channel is awaiting
 * reestablish, a forward to her is held for a window measured from her
 * disconnect, placed when the channel comes back, and failed back with
 * temporary_channel_failure when the window or the CLTV cutoff ends.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IHeldForwardRecord } from '../../src/lightning/async-payments/held-forward-ledger';
import {
	DEFAULT_REESTABLISH_HOLD_MS,
	IReestablishHoldConfig,
	IReestablishHoldLimits,
	MAX_REESTABLISH_HOLD_MS,
	judgeReestablishHold,
	resolveReestablishHold
} from '../../src/lightning/async-payments/reestablish-hold';
import {
	IWorld,
	LSP_SEED,
	asyncInvoice,
	createNode,
	destroyAll,
	disconnect,
	nodePubkey,
	reconnect,
	reconnectRestarted,
	settle,
	setupWorld,
	tempDb,
	waitFor
} from './helpers/async-world';

const TEMPORARY_CHANNEL_FAILURE = 0x1007;

function lspExtra(
	hold: Partial<IReestablishHoldConfig> = {}
): Parameters<typeof setupWorld>[0]['lspExtra'] {
	return {
		jitReceive: { enabled: true },
		reestablishHold: { enabled: true, ...hold }
	};
}

/** A wallet's home channel is unannounced; the harness opens public ones. */
function makeUnannounced(w: IWorld): void {
	for (const node of [w.lsp, w.carol]) {
		node
			.getChannelManager()
			.getChannel(w.bcChannelId)!
			.getFullState().announceChannel = false;
	}
}

async function holdWorld(
	hold: Partial<IReestablishHoldConfig> = {},
	lspStorage?: SqliteStorage
): Promise<IWorld> {
	const w = await setupWorld({
		lspStorage,
		carolRegisters: false,
		lspService: { enabled: false },
		lspExtra: lspExtra(hold)
	});
	makeUnannounced(w);
	return w;
}

/** Restart the LSP over the same file, as a new process would. */
function restartLsp(w: IWorld, dbPath: string): LightningNode {
	const lspId = w.lsp.getNodeId();
	w.lsp.destroy();
	w.alice.getChannelManager().handlePeerDisconnected(lspId);
	w.carol.getChannelManager().handlePeerDisconnected(lspId);
	w.alice.removeAllListeners('message:outbound');
	w.carol.removeAllListeners('message:outbound');
	const reopened = new SqliteStorage(dbPath);
	reopened.open();
	return createNode(LSP_SEED, reopened, {
		asyncReceiveService: { enabled: false },
		...lspExtra()
	});
}

/* eslint-disable @typescript-eslint/no-explicit-any */
/** Move Carol's disconnect back in time, as if she had been away that long. */
function awayFor(w: IWorld, ms: number): void {
	const at = (w.lsp as any).peerDisconnectedAt as Map<string, number>;
	expect(at.has(w.carol.getNodeId()), 'the disconnect was recorded').to.equal(
		true
	);
	at.set(w.carol.getNodeId(), Date.now() - ms);
}
/* eslint-enable @typescript-eslint/no-explicit-any */

function holds(lsp: LightningNode): IHeldForwardRecord[] {
	return lsp.listHeldForwards().filter((r) => r.kind === 'reestablish');
}

interface IHtlcLog {
	action: string;
	data: { reason?: string };
}

/** Every structured htlc log the LSP writes, by action. */
function htlcLog(lsp: LightningNode): IHtlcLog[] {
	const out: IHtlcLog[] = [];
	lsp.on('log', (e: IHtlcLog & { category?: string }) => {
		if (e.category === 'htlc') out.push({ action: e.action, data: e.data });
	});
	return out;
}

/** Count the failures the LSP sends the payer. */
function failsToPayer(w: IWorld): () => number {
	let fails = 0;
	w.lsp.on('message:outbound', (pk: string, type: number) => {
		if (
			pk === w.alice.getNodeId() &&
			(type === MessageType.UPDATE_FAIL_HTLC ||
				type === MessageType.UPDATE_FAIL_MALFORMED_HTLC)
		) {
			fails++;
		}
	});
	return (): number => fails;
}

/**
 * Carol's JIT intent, registered the way the request handler does. Returns
 * its intercept SCID.
 */
function registerIntent(w: IWorld, acceptsSkimmedFee?: boolean): Buffer {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const ack = (w.lsp as any).jitReceiveManager.registerIntent(
		w.carol.getNodeId(),
		{
			requestId: crypto.randomBytes(8),
			maxAmountMsat: 10_000_000n,
			targetRemainingInboundSat: 0n,
			expirySeconds: 600,
			acceptsSkimmedFee
		}
	);
	expect(ack.accepted, ack.reason).to.equal(true);
	return ack.interceptScid;
}

/** Make the LSP's add onto Carol's channel refused for liquidity. */
function shrinkChannel(w: IWorld): () => void {
	const state = w.lsp
		.getChannelManager()
		.getChannel(w.bcChannelId)!
		.getFullState();
	const original = state.remoteConfig.maxHtlcValueInFlightMsat;
	state.remoteConfig.maxHtlcValueInFlightMsat = 1_000_000n;
	return (): void => {
		state.remoteConfig.maxHtlcValueInFlightMsat = original;
	};
}

function invoiceFor(
	w: IWorld,
	amountMsat = 5_000_000n
): ReturnType<LightningNode['createInvoice']> {
	return w.carol.createInvoice({ amountMsat, description: 'away' });
}

function paymentStatus(node: LightningNode, hash: Buffer): string | undefined {
	return node.getPayment(hash)?.status;
}

function channelsNormal(...nodes: LightningNode[]): boolean {
	return nodes.every((n) =>
		n
			.getChannelManager()
			.listChannels()
			.every((c) => c.getState() === ChannelState.NORMAL)
	);
}

describe('Reestablish hold (issue #1726)', () => {
	describe('limits and admission', () => {
		const limits: IReestablishHoldLimits = {
			holdMs: 180_000,
			maxPartsPerPeer: 2,
			maxHolds: 3
		};
		const row = (
			peer: string,
			channel: string,
			amount: bigint
		): IHeldForwardRecord =>
			({
				id: crypto.randomBytes(32).toString('hex'),
				state: 'RELEASING',
				kind: 'reestablish',
				receiverNodeIdHex: peer,
				outChannelIdHex: channel,
				forwardAmountMsat: amount.toString()
			}) as IHeldForwardRecord;
		const base = {
			peerHex: 'p1',
			outChannelIdHex: 'c1',
			forwardAmountMsat: 1_000n,
			cutoffHeight: 900_010,
			channelSendableMsat: 10_000n,
			disconnectedAt: 1_000_000,
			now: 1_010_000,
			height: 900_000
		};

		it('is off unless enabled, defaults to 180 s and never exceeds 300 s', () => {
			expect(resolveReestablishHold(undefined)).to.equal(null);
			expect(resolveReestablishHold({ enabled: false })).to.equal(null);
			expect(resolveReestablishHold({ enabled: true, holdMs: 0 })).to.equal(
				null
			);
			expect(resolveReestablishHold({ enabled: true })).to.deep.equal({
				holdMs: DEFAULT_REESTABLISH_HOLD_MS,
				maxPartsPerPeer: 10,
				maxHolds: 200
			});
			expect(
				resolveReestablishHold({ enabled: true, holdMs: 3_600_000 })!.holdMs
			).to.equal(MAX_REESTABLISH_HOLD_MS);
		});

		it('measures the window from the disconnect, not from the HTLC', () => {
			const ok = judgeReestablishHold(base, [], limits);
			expect(ok).to.deep.equal({ ok: true, holdUntil: 1_180_000 });
			expect(
				judgeReestablishHold({ ...base, now: 1_180_000 }, [], limits)
			).to.deep.equal({ ok: false, reason: 'peer_gone_too_long' });
			expect(
				judgeReestablishHold({ ...base, disconnectedAt: undefined }, [], limits)
			).to.deep.equal({ ok: false, reason: 'disconnect_unknown' });
		});

		it('refuses a part already at its cutoff', () => {
			expect(
				judgeReestablishHold({ ...base, height: 900_010 }, [], limits)
			).to.deep.equal({ ok: false, reason: 'past_cutoff' });
		});

		it('caps parts per peer, value per channel and holds overall, counting only unresolved reestablish rows', () => {
			const twoForPeer = [row('p1', 'c1', 1n), row('p1', 'c2', 1n)];
			expect(judgeReestablishHold(base, twoForPeer, limits)).to.deep.equal({
				ok: false,
				reason: 'peer_count'
			});
			const resolved = { ...row('p1', 'c1', 1n), state: 'RELEASED' as const };
			const asyncHold = { ...row('p1', 'c1', 1n), kind: undefined };
			expect(
				judgeReestablishHold(base, [resolved, resolved, asyncHold], limits).ok
			).to.equal(true);
			expect(
				judgeReestablishHold(base, [row('p1', 'c1', 9_001n)], limits)
			).to.deep.equal({ ok: false, reason: 'channel_value' });
			expect(
				judgeReestablishHold(
					base,
					[row('p2', 'c2', 1n), row('p3', 'c3', 1n), row('p4', 'c4', 1n)],
					limits
				)
			).to.deep.equal({ ok: false, reason: 'global_count' });
		});
	});

	describe('on a node', function () {
		this.timeout(30_000);

		for (const awayMs of [10_000, 45_000]) {
			it(`holds the forward and completes it when the wallet comes back ${
				awayMs / 1000
			} s after it left`, async () => {
				const w = await holdWorld();
				const { alice, lsp, carol } = w;
				const log = htlcLog(lsp);
				const fails = failsToPayer(w);
				const heldEvents: unknown[] = [];
				lsp.on('htlc:held-for-reestablish', (e) => heldEvents.push(e));
				const invoice = invoiceFor(w);

				await disconnect(lsp, carol, w.cutBC);
				awayFor(w, awayMs);
				alice.sendPayment(invoice.bolt11);
				await settle();

				const [row] = holds(lsp);
				expect(row, 'the part is held').to.not.equal(undefined);
				expect(row.state).to.equal('RELEASING');
				expect(row.outChannelIdHex).to.equal(w.bcChannelId.toString('hex'));
				expect(row.receiverNodeIdHex).to.equal(carol.getNodeId());
				const disconnectedAt = row.holdUntil! - DEFAULT_REESTABLISH_HOLD_MS;
				expect(Date.now() - disconnectedAt).to.be.at.least(awayMs);
				expect(heldEvents).to.have.length(1);
				expect(log.map((l) => l.action)).to.include('held_for_reestablish');
				expect(fails(), 'nothing failed back').to.equal(0);
				expect(paymentStatus(alice, invoice.paymentHash)).to.equal(
					PaymentStatus.PENDING
				);

				await reconnect(lsp, carol, w.cutBC, w.gateBC);
				await waitFor(
					() =>
						paymentStatus(alice, invoice.paymentHash) ===
						PaymentStatus.COMPLETED,
					'the payment to complete after the reestablish'
				);
				expect(paymentStatus(carol, invoice.paymentHash)).to.equal(
					PaymentStatus.COMPLETED
				);
				expect(holds(lsp)[0].state).to.equal('RELEASED');
				expect(log.map((l) => l.action)).to.include(
					'released_after_reestablish'
				);
				expect(fails()).to.equal(0);
				destroyAll(alice, lsp, carol);
			});
		}

		it('fails the part back with temporary_channel_failure when the window ends', async () => {
			const w = await holdWorld();
			const { alice, lsp, carol } = w;
			const log = htlcLog(lsp);
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			// 400 ms of the window left.
			awayFor(w, DEFAULT_REESTABLISH_HOLD_MS - 400);
			alice.sendPayment(invoice.bolt11);
			await settle();
			expect(holds(lsp)[0].state).to.equal('RELEASING');

			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.FAILED,
				'the payer to be refunded at the end of the window',
				5_000
			);
			expect(alice.getPayment(invoice.paymentHash)!.failureCode).to.equal(
				TEMPORARY_CHANNEL_FAILURE
			);
			const [row] = holds(lsp);
			expect(row.state).to.equal('FAILED');
			expect(row.failReason).to.equal('hold_expired');
			expect(
				log.find((l) => l.action === 'hold_expired')?.data.reason
			).to.equal('hold_expired');
			// The wallet coming back later finds nothing to place.
			const forwardsBefore = w.forwards;
			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await settle(10);
			expect(w.forwards).to.equal(forwardsBefore);
			expect(channelsNormal(alice, lsp, carol)).to.equal(true);
			destroyAll(alice, lsp, carol);
		});

		it('retries the end of the window when its write fails', async () => {
			const disk = new SqliteStorage(tempDb('reestablish-hold-expiry-write'));
			disk.open();
			const w = await holdWorld({}, disk);
			const { alice, lsp, carol } = w;
			const invoice = invoiceFor(w);
			const save = disk.saveMetadata.bind(disk);
			let failed = 0;
			disk.saveMetadata = (key: string, value: string): void => {
				if (
					failed === 0 &&
					key.startsWith('held_forward') &&
					value.includes('"FAILING"')
				) {
					failed++;
					throw new Error('disk full');
				}
				save(key, value);
			};
			await disconnect(lsp, carol, w.cutBC);
			awayFor(w, DEFAULT_REESTABLISH_HOLD_MS - 400);
			alice.sendPayment(invoice.bolt11);
			await settle();
			expect(holds(lsp)[0].state).to.equal('RELEASING');

			await waitFor(() => failed === 1, 'the expiry write to fail', 5_000);
			expect(holds(lsp)[0].state).to.equal('RELEASING');
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.FAILED,
				'the payer to be refunded on the retry'
			);
			expect(alice.getPayment(invoice.paymentHash)!.failureCode).to.equal(
				TEMPORARY_CHANNEL_FAILURE
			);
			expect(holds(lsp)[0].failReason).to.equal('hold_expired');
			destroyAll(alice, lsp, carol);
		});

		it('fails the part early, with the same code, when a block crosses its cutoff', async () => {
			const w = await holdWorld();
			const { alice, lsp, carol } = w;
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [held] = holds(lsp);
			expect(held.cutoffHeight).to.equal(
				Math.min(held.forwardCltv - 40 + 1, held.incomingCltvExpiry - 18)
			);

			lsp.handleNewBlock(held.cutoffHeight - 1);
			await settle();
			expect(holds(lsp)[0].state, 'a block short of it').to.equal('RELEASING');
			lsp.handleNewBlock(held.cutoffHeight);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.FAILED,
				'the payer to be refunded at the cutoff',
				5_000
			);
			expect(alice.getPayment(invoice.paymentHash)!.failureCode).to.equal(
				TEMPORARY_CHANNEL_FAILURE
			);
			expect(holds(lsp)[0].failReason).to.equal('cutoff_unplaced');
			destroyAll(alice, lsp, carol);
		});

		/** Alice pays Carol at height 1000 with exactly `finalDelta` blocks. */
		function payAtHeight1000(
			w: IWorld,
			invoice: ReturnType<LightningNode['createInvoice']>,
			finalDelta: number
		): void {
			for (const node of [w.alice, w.lsp, w.carol]) node.handleNewBlock(1000);
			const amountMsat = 5_000_000n;
			w.alice.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: nodePubkey(LSP_SEED),
							shortChannelId: w.scidAB,
							amountToForwardMsat: amountMsat + 100_000n,
							outgoingCltvValue: 400
						},
						{
							pubkey: Buffer.from(w.carol.getNodeId(), 'hex'),
							shortChannelId: w.scidBC,
							amountToForwardMsat: amountMsat,
							outgoingCltvValue: finalDelta
						}
					]
				},
				invoice.paymentHash,
				finalDelta,
				invoice.paymentSecret,
				amountMsat
			);
		}

		it('holds a part that carries exactly the invoice delta and places it at the same height', async () => {
			const w = await holdWorld();
			const { alice, lsp, carol } = w;
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			payAtHeight1000(w, invoice, 40);
			await settle();
			const [held] = holds(lsp);
			expect(held, 'the part is held').to.not.equal(undefined);
			expect(held.cutoffHeight).to.equal(1001);

			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.COMPLETED,
				'the payment to complete after the reestablish'
			);
			destroyAll(alice, lsp, carol);
		});

		it("fails a JIT client's part with temporary_channel_failure once a block leaves it under the JIT invoice delta", async () => {
			const w = await holdWorld();
			const { alice, lsp, carol } = w;
			registerIntent(w);
			// What createJitInvoice mints over an existing channel.
			const invoice = carol.createInvoice({
				amountMsat: 5_000_000n,
				description: 'away',
				minFinalCltvExpiry: 72
			});
			await disconnect(lsp, carol, w.cutBC);
			payAtHeight1000(w, invoice, 72);
			await settle();
			const [held] = holds(lsp);
			expect(held.cutoffHeight).to.equal(1001);

			for (const node of [alice, lsp, carol]) node.handleNewBlock(1001);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.FAILED,
				'the payer to be refunded at the cutoff',
				5_000
			);
			expect(alice.getPayment(invoice.paymentHash)!.failureCode).to.equal(
				TEMPORARY_CHANNEL_FAILURE
			);
			expect(holds(lsp)[0].failReason).to.equal('cutoff_unplaced');
			destroyAll(alice, lsp, carol);
		});

		it('fails at once a part for a wallet gone longer than the window', async () => {
			const w = await holdWorld();
			const { alice, lsp, carol } = w;
			// Nor does a live JIT intent queue it for a splice instead.
			registerIntent(w);
			const log = htlcLog(lsp);
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			awayFor(w, 60 * 60 * 1000);
			alice.sendPayment(invoice.bolt11);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.FAILED,
				'the payer to be refunded at once',
				2_000
			);
			expect(holds(lsp)).to.have.length(0);
			expect(
				log.find((l) => l.action === 'reestablish_hold_refused')?.data.reason
			).to.equal('peer_gone_too_long');
			destroyAll(alice, lsp, carol);
		});

		it('fails at once when the hold is not configured, as before', async () => {
			const w = await setupWorld({
				carolRegisters: false,
				lspService: { enabled: false },
				lspExtra: { jitReceive: { enabled: true } }
			});
			makeUnannounced(w);
			const { alice, lsp, carol } = w;
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			alice.sendPayment(invoice.bolt11);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.FAILED,
				'the payer to be refunded at once',
				2_000
			);
			expect(lsp.listHeldForwards()).to.have.length(0);
			destroyAll(alice, lsp, carol);
		});

		it('refuses the eleventh part for one wallet and holds the ten before it', async () => {
			const w = await holdWorld();
			const { alice, lsp, carol } = w;
			// Nor does a live JIT intent queue it for a splice instead.
			registerIntent(w);
			const log = htlcLog(lsp);
			const invoices = Array.from({ length: 11 }, () =>
				invoiceFor(w, 1_000_000n)
			);
			await disconnect(lsp, carol, w.cutBC);
			for (const invoice of invoices.slice(0, 10)) {
				alice.sendPayment(invoice.bolt11);
				await settle();
			}
			expect(holds(lsp)).to.have.length(10);

			const eleventh = invoices[10];
			alice.sendPayment(eleventh.bolt11);
			await waitFor(
				() =>
					paymentStatus(alice, eleventh.paymentHash) === PaymentStatus.FAILED,
				'the eleventh part to be refused',
				2_000
			);
			expect(holds(lsp)).to.have.length(10);
			expect(
				log.find((l) => l.action === 'reestablish_hold_refused')?.data.reason
			).to.equal('peer_count');

			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					invoices
						.slice(0, 10)
						.every(
							(i) =>
								paymentStatus(alice, i.paymentHash) === PaymentStatus.COMPLETED
						),
				'the ten held parts to complete'
			);
			destroyAll(alice, lsp, carol);
		});

		it('drops a resolved hold row a day later, and its inbound HTLC with it', async () => {
			const w = await holdWorld();
			const { alice, lsp, carol } = w;
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			alice.sendPayment(invoice.bolt11);
			await settle();
			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.COMPLETED,
				'the payment to complete'
			);
			const [row] = holds(lsp);
			expect(row.state).to.equal('RELEASED');
			/* eslint-disable @typescript-eslint/no-explicit-any */
			const ledger = (lsp as any).heldForwardLedger;
			lsp.handleNewBlock(1);
			expect(holds(lsp), 'kept for a day').to.have.length(1);

			ledger.ledger.records.get(row.id).resolvedAt =
				Date.now() - 25 * 60 * 60 * 1000;
			/* eslint-enable @typescript-eslint/no-explicit-any */
			lsp.handleNewBlock(2);
			expect(holds(lsp)).to.have.length(0);
			expect(
				ledger.byIncoming(row.inChannelIdHex, BigInt(row.inHtlcId))
			).to.equal(undefined);
			destroyAll(alice, lsp, carol);
		});

		it('resolves a hold across a restart of the LSP', async () => {
			const dbPath = tempDb('reestablish-hold-restart');
			const disk = new SqliteStorage(dbPath);
			disk.open();
			const w = await holdWorld({}, disk);
			const { alice, lsp, carol } = w;
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [before] = holds(lsp);
			expect(before.state).to.equal('RELEASING');

			const restored = restartLsp(w, dbPath);
			const [after] = holds(restored);
			expect(after.id, 'the row survived the restart').to.equal(before.id);
			expect(after.state).to.equal('RELEASING');

			// The payer's channel comes back first: its inbound HTLC is
			// redispatched and re-armed from the row, never forwarded around it.
			await reconnectRestarted(restored, alice);
			await settle(10);
			expect(holds(restored)[0].state).to.equal('RELEASING');
			expect(paymentStatus(alice, invoice.paymentHash)).to.equal(
				PaymentStatus.PENDING
			);

			await reconnectRestarted(restored, carol);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.COMPLETED,
				'the payment to complete once the wallet is back'
			);
			expect(holds(restored)[0].state).to.equal('RELEASED');
			destroyAll(alice, restored, carol);
		});

		it('fails a restored hold whose window ended before the payer came back', async () => {
			const dbPath = tempDb('reestablish-hold-expired-restart');
			const disk = new SqliteStorage(dbPath);
			disk.open();
			const w = await holdWorld({}, disk);
			const { alice, lsp, carol } = w;
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			awayFor(w, DEFAULT_REESTABLISH_HOLD_MS - 500);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [held] = holds(lsp);

			const restored = restartLsp(w, dbPath);
			await reconnectRestarted(restored, carol);
			await new Promise((r) =>
				setTimeout(r, Math.max(0, held.holdUntil! - Date.now()) + 50)
			);
			await reconnectRestarted(restored, alice);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.FAILED,
				'the payer to be refunded',
				5_000
			);
			expect(alice.getPayment(invoice.paymentHash)!.failureCode).to.equal(
				TEMPORARY_CHANNEL_FAILURE
			);
			const [row] = holds(restored);
			expect(row.state).to.equal('FAILED');
			expect(row.failReason).to.equal('hold_expired');
			destroyAll(alice, restored, carol);
		});

		it('never places a restored hold past its cutoff', async () => {
			const dbPath = tempDb('reestablish-hold-cutoff-restart');
			const disk = new SqliteStorage(dbPath);
			disk.open();
			const w = await holdWorld({}, disk);
			const { alice, lsp, carol } = w;
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			awayFor(w, DEFAULT_REESTABLISH_HOLD_MS - 3_000);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [held] = holds(lsp);
			// The block past the cutoff is stored, and the process dies before
			// its hold scan runs.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(lsp as any).asyncPaymentManager.scan = (): void => undefined;
			lsp.handleNewBlock(held.cutoffHeight + 1);

			const restored = restartLsp(w, dbPath);
			let forwards = 0;
			restored.on('htlc:forward', () => forwards++);
			await reconnectRestarted(restored, carol);
			await reconnectRestarted(restored, alice);
			await settle(10);
			expect(forwards, 'nothing placed past the cutoff').to.equal(0);
			expect(holds(restored)[0].state).to.equal('RELEASING');

			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.FAILED,
				'the payer to be refunded',
				5_000
			);
			expect(alice.getPayment(invoice.paymentHash)!.failureCode).to.equal(
				TEMPORARY_CHANNEL_FAILURE
			);
			expect(forwards).to.equal(0);
			destroyAll(alice, restored, carol);
		});

		it('never places a restored hold past its cutoff when the part also carries hold_htlc', async () => {
			const dbPath = tempDb('reestablish-hold-marker-restart');
			const disk = new SqliteStorage(dbPath);
			disk.open();
			// Carol registered while the LSP ran the async service; it has
			// since been turned off, so her path's marker is ignored.
			const w = await setupWorld({ lspStorage: disk, lspExtra: lspExtra() });
			makeUnannounced(w);
			const { alice, lsp, carol } = w;
			/* eslint-disable @typescript-eslint/no-explicit-any */
			(lsp as any).asyncReceiveService.isEnabled = (): boolean => false;
			const invoice = asyncInvoice(carol, 5_000_000n);
			await disconnect(lsp, carol, w.cutBC);
			awayFor(w, DEFAULT_REESTABLISH_HOLD_MS - 3_000);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [held] = holds(lsp);
			expect(held?.state).to.equal('RELEASING');
			(lsp as any).asyncPaymentManager.scan = (): void => undefined;
			/* eslint-enable @typescript-eslint/no-explicit-any */
			lsp.handleNewBlock(held.cutoffHeight + 1);

			const restored = restartLsp(w, dbPath);
			let forwards = 0;
			restored.on('htlc:forward', () => forwards++);
			await reconnectRestarted(restored, carol);
			await reconnectRestarted(restored, alice);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.FAILED,
				'the payer to be refunded',
				5_000
			);
			expect(forwards, 'nothing placed past the cutoff').to.equal(0);
			expect(holds(restored)[0].state).to.equal('FAILED');
			destroyAll(alice, restored, carol);
		});

		it('re-arms a held JIT part paid to its intercept SCID across a restart', async () => {
			const dbPath = tempDb('reestablish-hold-intercept-restart');
			const disk = new SqliteStorage(dbPath);
			disk.open();
			const w = await holdWorld({}, disk);
			const { alice, lsp, carol } = w;
			const interceptScid = registerIntent(w);
			// The funding completes as the wallet drops. Carol's existing
			// channel stands in for the one it would have opened.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(lsp as any).openZeroConfChannelAndWait = async (): Promise<Buffer> => {
				await disconnect(lsp, carol, w.cutBC);
				return w.bcChannelId;
			};
			const amountMsat = 5_000_000n;
			const invoice = invoiceFor(w, amountMsat);
			alice.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: nodePubkey(LSP_SEED),
							shortChannelId: w.scidAB,
							amountToForwardMsat: amountMsat + 100_000n,
							outgoingCltvValue: 400
						},
						{
							pubkey: Buffer.from(carol.getNodeId(), 'hex'),
							shortChannelId: interceptScid,
							amountToForwardMsat: amountMsat,
							outgoingCltvValue: 100
						}
					]
				},
				invoice.paymentHash,
				100,
				invoice.paymentSecret,
				amountMsat
			);
			await waitFor(() => holds(lsp).length === 1, 'the part to be held');

			const restored = restartLsp(w, dbPath);
			await reconnectRestarted(restored, carol);
			await reconnectRestarted(restored, alice);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.COMPLETED,
				'the payment to complete once both channels are back'
			);
			expect(holds(restored)[0].state).to.equal('RELEASED');
			destroyAll(alice, restored, carol);
		});

		it('a held JIT part keeps its opening fee across a restart', async () => {
			const dbPath = tempDb('reestablish-hold-jit-fee-restart');
			const disk = new SqliteStorage(dbPath);
			disk.open();
			const w = await setupWorld({
				lspStorage: disk,
				carolRegisters: false,
				lspService: { enabled: false },
				lspExtra: {
					jitReceive: { enabled: true, flatFeeSat: 100n },
					reestablishHold: { enabled: true }
				}
			});
			makeUnannounced(w);
			const { alice, lsp, carol } = w;
			registerIntent(w, true);
			const restoreCapacity = shrinkChannel(w);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(lsp as any).spliceInAndWait = async (): Promise<void> => {
				restoreCapacity();
				await disconnect(lsp, carol, w.cutBC);
			};
			const invoice = carol.createInvoice({
				amountMsat: 5_000_000n,
				description: 'away',
				jitFeeAllowance: { flatFeeSat: 100, feePpm: 0 }
			});
			alice.sendPayment(invoice.bolt11);
			await waitFor(() => holds(lsp).length === 1, 'the part to be held');
			expect(holds(lsp)[0].forwardAmountMsat).to.equal('4900000');

			const restored = restartLsp(w, dbPath);
			const forwarded: bigint[] = [];
			restored.on('htlc:forward', (_in, _out, amountMsat: bigint) =>
				forwarded.push(amountMsat)
			);
			await reconnectRestarted(restored, alice);
			await reconnectRestarted(restored, carol);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.COMPLETED,
				'the payment to complete once the wallet is back'
			);
			expect(forwarded).to.deep.equal([4_900_000n]);
			destroyAll(alice, restored, carol);
		});

		it('JIT, channel too small: the splice waits for the wallet to come back, then completes', async () => {
			// The hold is off here, so the refused add goes to the splice path.
			const w = await setupWorld({
				carolRegisters: false,
				lspService: { enabled: false },
				lspExtra: { jitReceive: { enabled: true, fundingRetryDelayMs: 1 } }
			});
			makeUnannounced(w);
			const { alice, lsp, carol } = w;
			registerIntent(w);
			const restoreCapacity = shrinkChannel(w);
			const spliceSawState: string[] = [];
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(lsp as any).spliceInAndWait = async (): Promise<void> => {
				spliceSawState.push(
					lsp.getChannelManager().getChannel(w.bcChannelId)!.getState()
				);
				restoreCapacity();
			};
			const failures: string[] = [];
			lsp.on('jit:failed', (d: { reason: string }) => failures.push(d.reason));
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			alice.sendPayment(invoice.bolt11);
			await new Promise((r) => setTimeout(r, 100));
			expect(
				spliceSawState,
				'no splice while the wallet is away'
			).to.deep.equal([]);
			expect(failures).to.deep.equal([]);

			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.COMPLETED,
				'the payment to complete over the spliced channel'
			);
			expect(spliceSawState).to.deep.equal([ChannelState.NORMAL]);
			expect(failures).to.deep.equal([]);
			destroyAll(alice, lsp, carol);
		});

		it('JIT, channel too small with the hold on: the part goes to the splice, not the hold', async () => {
			const w = await setupWorld({
				carolRegisters: false,
				lspService: { enabled: false },
				lspExtra: {
					jitReceive: { enabled: true, fundingRetryDelayMs: 1 },
					reestablishHold: { enabled: true }
				}
			});
			makeUnannounced(w);
			const { alice, lsp, carol } = w;
			registerIntent(w);
			const restoreCapacity = shrinkChannel(w);
			// Below the part, so the hold's value cap refuses it.
			const channel = lsp.getChannelManager().getChannel(w.bcChannelId)!;
			channel.getSpendableOutboundMsat = (): bigint => 1_000_000n;
			let splices = 0;
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(lsp as any).spliceInAndWait = async (): Promise<void> => {
				splices++;
				restoreCapacity();
				delete (channel as Partial<typeof channel>).getSpendableOutboundMsat;
			};
			const fails = failsToPayer(w);
			const invoice = invoiceFor(w);
			await disconnect(lsp, carol, w.cutBC);
			alice.sendPayment(invoice.bolt11);
			await new Promise((r) => setTimeout(r, 100));
			expect(holds(lsp), 'not held for reestablish').to.have.length(0);
			expect(fails(), 'nothing failed back').to.equal(0);

			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.COMPLETED,
				'the payment to complete over the spliced channel'
			);
			expect(splices).to.equal(1);
			destroyAll(alice, lsp, carol);
		});

		it('a JIT forward whose wallet drops right after the splice is held, not failed', async () => {
			const w = await holdWorld();
			const { alice, lsp, carol } = w;
			registerIntent(w);
			const restoreCapacity = shrinkChannel(w);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(lsp as any).spliceInAndWait = async (): Promise<void> => {
				restoreCapacity();
				await disconnect(lsp, carol, w.cutBC);
			};
			const fails = failsToPayer(w);
			const invoice = invoiceFor(w);
			alice.sendPayment(invoice.bolt11);
			await waitFor(() => holds(lsp).length === 1, 'the part to be held');
			expect(holds(lsp)[0].state).to.equal('RELEASING');
			expect(fails()).to.equal(0);

			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.COMPLETED,
				'the payment to complete after the reestablish'
			);
			expect(holds(lsp)[0].state).to.equal('RELEASED');
			destroyAll(alice, lsp, carol);
		});

		it('an MPP set split across the disconnect ends without a force close', async () => {
			const w = await holdWorld();
			const { alice, lsp, carol } = w;
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(carol as any).mppTimeoutMs = 200;
			const totalMsat = 10_000_000n;
			const part = totalMsat / 2n;
			const invoice = carol.createInvoice({
				amountMsat: totalMsat,
				description: 'split'
			});
			const sendPart = (): void => {
				alice.sendPaymentToRoute(
					{
						hops: [
							{
								pubkey: nodePubkey(LSP_SEED),
								shortChannelId: w.scidAB,
								amountToForwardMsat: part + 100_000n,
								outgoingCltvValue: 400
							},
							{
								pubkey: Buffer.from(carol.getNodeId(), 'hex'),
								shortChannelId: w.scidBC,
								amountToForwardMsat: part,
								outgoingCltvValue: 100
							}
						]
					},
					invoice.paymentHash,
					100,
					invoice.paymentSecret,
					totalMsat
				);
			};
			// One part reaches the wallet, which waits for the rest.
			sendPart();
			await settle(10);
			expect(paymentStatus(carol, invoice.paymentHash)).to.equal(
				PaymentStatus.PENDING
			);
			// The wallet goes quiet; the second part is held at the LSP.
			await disconnect(lsp, carol, w.cutBC);
			sendPart();
			await settle();
			expect(holds(lsp)).to.have.length(1);

			// The wallet's MPP clock ran while it was away: its first tick
			// after resume drops the set, and the held part then arrives alone.
			await new Promise((r) => setTimeout(r, 250));
			carol.failTimedOutMppPayments();
			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await settle(10);
			expect(holds(lsp)[0].state).to.equal('RELEASED');
			await new Promise((r) => setTimeout(r, 250));
			carol.failTimedOutMppPayments();
			await waitFor(
				() =>
					paymentStatus(alice, invoice.paymentHash) === PaymentStatus.FAILED,
				'the payer to be refunded'
			);
			await settle(10);
			expect(
				channelsNormal(alice, lsp, carol),
				'nothing force closed'
			).to.equal(true);
			destroyAll(alice, lsp, carol);
		});
	});
});
