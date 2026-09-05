/**
 * One owner for a refused held-forward part (issue #722).
 *
 * When a release's outgoing add is refused, two engines used to be able to
 * claim the part: the JIT engine (tryHoldForSplice, which then forwards it
 * after a splice or fails it upstream itself) and the held-forward driver
 * (which owed the upstream refund because holdsPart never looked at the
 * splice queue). Now the placement says which happened: `held` hands the
 * part to the JIT engine and the ledger records the row RELEASED with
 * `heldBySplice`; `refused` leaves the refund with the driver alone, and
 * the JIT engine registers no owed failure for a part whose caller owes it.
 *
 * Both orderings, with the inbound HTLC failed or fulfilled exactly once:
 *  - the JIT engine holds, the splice locks, the part is forwarded;
 *  - the JIT engine holds, the splice fails, the engine alone fails upstream;
 *  - the JIT engine cannot hold (no intent), the driver alone owes the refund
 *    across a reestablishing inbound channel.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { MessageType } from '../../src/lightning/message/types';
import { HtlcState } from '../../src/lightning/channel/types';
import {
	IWorld,
	asyncInvoice,
	destroyAll,
	disconnect,
	heldRecords,
	reconnect,
	settle,
	setupWorld,
	waitFor
} from './helpers/async-world';

/** Count the failures the LSP sends the payer for one inbound HTLC. */
function countFails(lsp: LightningNode, alice: LightningNode): () => number {
	let fails = 0;
	lsp.on('message:outbound', (pk: string, type: number) => {
		if (
			pk === alice.getNodeId() &&
			(type === MessageType.UPDATE_FAIL_HTLC ||
				type === MessageType.UPDATE_FAIL_MALFORMED_HTLC)
		) {
			fails++;
		}
	});
	return (): number => fails;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
function owedByDriver(lsp: LightningNode): number {
	return (lsp as any).owedHeldForwardFailures.size;
}
function owedByEngine(lsp: LightningNode): number {
	return (lsp as any).jitReceiveManager?.restoredToFail.length ?? 0;
}
function engineHolds(w: IWorld, inHtlcId: string): boolean {
	return (
		(w.lsp as any).jitReceiveManager?.holdsPart(
			w.abChannelId.toString('hex'),
			BigInt(inHtlcId)
		) ?? false
	);
}
/** Carol's JIT intent, registered on the LSP's engine the way the JIT
 * request handler does once it has verified the request over the wire. */
function registerIntent(w: IWorld): void {
	const ack = (w.lsp as any).jitReceiveManager.registerIntent(
		w.carol.getNodeId(),
		{
			requestId: crypto.randomBytes(8),
			maxAmountMsat: 10_000_000n,
			targetRemainingInboundSat: 0n,
			expirySeconds: 600
		}
	);
	expect(ack.accepted, ack.reason).to.equal(true);
}
/* eslint-enable @typescript-eslint/no-explicit-any */

async function jitWorld(): Promise<IWorld> {
	return setupWorld({
		carolAutoRelease: true,
		lspExtra: {
			jitReceive: {
				enabled: true,
				fundingAttempts: 1,
				fundingRetryDelayMs: 0,
				fundingAttemptTimeoutMs: 5_000
			}
		}
	});
}

/** Park a 5 msat-million hold, then make the outgoing channel refuse it. */
async function parkAndRefuse(w: IWorld): Promise<{
	paymentHash: Buffer;
	inHtlcId: string;
	restoreCapacity: () => void;
}> {
	const invoice = asyncInvoice(w.carol, 5_000_000n);
	await disconnect(w.lsp, w.carol, w.cutBC);
	w.alice.sendPayment(invoice.bolt11);
	await settle();
	const [row] = heldRecords(w.lsp);
	expect(row.state).to.equal('HELD');
	const state = w.lsp
		.getChannelManager()
		.getChannel(w.bcChannelId)!
		.getFullState();
	const original = state.remoteConfig.maxHtlcValueInFlightMsat;
	state.remoteConfig.maxHtlcValueInFlightMsat = 1_000_000n;
	return {
		paymentHash: invoice.paymentHash,
		inHtlcId: row.inHtlcId,
		restoreCapacity: (): void => {
			state.remoteConfig.maxHtlcValueInFlightMsat = original;
		}
	};
}

describe('A refused held-forward part has one owner (issue #722)', () => {
	it('held by the JIT engine and forwarded after the splice: RELEASED with heldBySplice, no refund owed anywhere', async function () {
		this.timeout(20_000);
		const w = await jitWorld();
		const { alice, lsp, carol } = w;
		registerIntent(w);
		const fails = countFails(lsp, alice);
		const parked = await parkAndRefuse(w);
		// The splice "locks" and, with it, the channel can take the add.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(lsp as any).spliceInAndWait = async (): Promise<void> => {
			parked.restoreCapacity();
		};
		const forwarded = new Promise<void>((resolve) => {
			lsp.once('jit:forwarded', () => resolve());
		});

		await reconnect(lsp, carol, w.cutBC, w.gateBC);
		await settle();
		await forwarded;
		await settle();

		const [row] = heldRecords(lsp);
		expect(row.state).to.equal('RELEASED');
		expect(row.heldBySplice, 'the ledger says who owns the part').to.equal(
			true
		);
		expect(row.failReason).to.equal(undefined);
		await waitFor(
			() =>
				alice.getPayment(parked.paymentHash)?.status ===
				PaymentStatus.COMPLETED,
			'the payer to complete over the spliced channel',
			5_000
		);
		expect(carol.getPayment(parked.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(fails(), 'nothing failed the inbound HTLC').to.equal(0);
		expect(owedByDriver(lsp), 'the driver owes no refund').to.equal(0);
		expect(owedByEngine(lsp), 'the engine owes no refund').to.equal(0);
		destroyAll(alice, lsp, carol);
	});

	it('held by the JIT engine and the splice fails: the engine alone fails upstream, exactly once', async function () {
		this.timeout(20_000);
		const w = await jitWorld();
		const { alice, lsp, carol } = w;
		registerIntent(w);
		const fails = countFails(lsp, alice);
		const parked = await parkAndRefuse(w);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(lsp as any).spliceInAndWait = async (): Promise<void> => {
			throw new Error('splice aborted by peer');
		};
		const failed = new Promise<void>((resolve) => {
			lsp.once('jit:failed', () => resolve());
		});

		await reconnect(lsp, carol, w.cutBC, w.gateBC);
		await settle();
		await failed;
		await settle();

		const [row] = heldRecords(lsp);
		expect(row.state).to.equal('RELEASED');
		expect(row.heldBySplice).to.equal(true);
		await waitFor(
			() =>
				alice.getPayment(parked.paymentHash)?.status === PaymentStatus.FAILED,
			'the payer to be refunded by the engine',
			5_000
		);
		expect(fails(), 'failed upstream exactly once').to.equal(1);
		expect(owedByDriver(lsp), 'the driver never owed it').to.equal(0);
		expect(owedByEngine(lsp), 'and the engine has nothing left').to.equal(0);
		expect(engineHolds(w, parked.inHtlcId)).to.equal(false);
		const inbound = lsp
			.getChannelManager()
			.getChannel(w.abChannelId)!
			.getFullState()
			.htlcs.get(`received-${parked.inHtlcId}`);
		expect(inbound?.state).to.not.equal(HtlcState.COMMITTED);
		destroyAll(alice, lsp, carol);
	});

	it('not held (no intent) with the inbound channel reestablishing: the driver alone owes the refund, carried once', async function () {
		this.timeout(20_000);
		const w = await jitWorld();
		const { alice, lsp, carol } = w;
		// Carol never registers a JIT intent, so the engine cannot hold.
		const fails = countFails(lsp, alice);
		const parked = await parkAndRefuse(w);
		// The payer's link is down when the receiver comes back and releases,
		// so the refusal cannot be carried at once and somebody must owe it.
		await disconnect(alice, lsp, w.cutAB);
		await reconnect(lsp, carol, w.cutBC, w.gateBC);
		await settle();

		const [row] = heldRecords(lsp);
		expect(row.state).to.equal('FAILED');
		expect(row.failReason).to.equal('forward_refused');
		expect(row.heldBySplice).to.equal(undefined);
		expect(owedByDriver(lsp), 'the driver owes the refund').to.equal(1);
		expect(owedByEngine(lsp), 'the engine registered none').to.equal(0);
		expect(engineHolds(w, parked.inHtlcId)).to.equal(false);

		await reconnect(alice, lsp, w.cutAB, w.gateAB);
		await settle(10);
		await waitFor(
			() =>
				alice.getPayment(parked.paymentHash)?.status === PaymentStatus.FAILED,
			'the payer to be refunded by the driver',
			5_000
		);
		expect(fails(), 'failed upstream exactly once').to.equal(1);
		expect(owedByDriver(lsp), 'and the debt is cleared').to.equal(0);
		destroyAll(alice, lsp, carol);
	});
});
