/**
 * FFOR M6: the crash matrix (spec §15 "crash matrix at every arrow in §6's
 * diagram"). One side is crashed + restarted from its last DURABLE state at
 * EVERY protocol arrow, alternating sides:
 *
 *   SETUP:      ff_init / ff_accept / ff_invoices / ff_escape_sigs / ff_begin
 *   SETTLEMENT: before package persist / after persist before tower send /
 *               after tower store before release / after release before
 *               upstream fulfill / after fulfill before commitment ack
 *   RECONCILE:  reestablish TLV / each replayed package / ff_reconcile /
 *               ff_reconcile_ack / ff_revoke_batch / ff_end / each voucher
 *               fulfillment
 *
 * After every crash+restart the flow is completed and the recovery invariants
 * hold: no fund loss, no duplicate settlement, epoch state consistent on both
 * sides, and the final balances EQUAL the uncrashed reference run.
 *
 * A "crash" restores the side from the persist-tracker mirror (exactly what a
 * real node's storage would hold), discards the live manager, and reconnects.
 */

import { expect } from 'chai';
import {
	ITriple,
	createTriple,
	goOffline,
	reconnectSR,
	reconnectPS,
	restartS,
	restartR,
	pay,
	flush,
	ILink,
	FUNDING_SATOSHIS
} from './ffor-m6-harness';
import { MessageType } from '../../src/lightning/message/types';
import { FforEpochState } from '../../src/lightning/ffor/types';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	IFforTowerProvisioning,
	LoopbackTowerClient
} from '../../src/lightning/ffor/tower';
import { serializeChannelState } from '../../src/lightning/storage/serialization';

// Two-settlement scenario used throughout; v = a - (1000 + 0.5% a).
const PAY_1 = 1_000_000n;
const PAY_2 = 50_000_000n;
const V_SUM = 994_000n + 49_749_000n;

/**
 * Arm a one-shot crash at a message arrow. timing 'before' = the message is
 * LOST (receiver crashed before processing); 'after' = the message was fully
 * processed, THEN the side crashed. Either way every subsequent message on
 * the link is dropped until the link is disarmed (the "wire" died with the
 * process).
 */
function armCrash(
	link: ILink,
	fromPub: string,
	msgType: MessageType,
	timing: 'before' | 'after',
	opts?: { skip?: number }
): { triggered: () => boolean } {
	let triggered = false;
	let toSkip = opts?.skip ?? 0;
	link.intercept = (from, type): 'deliver' | 'drop' => {
		if (triggered) return 'drop';
		if (from === fromPub && type === msgType) {
			if (toSkip > 0) {
				toSkip--;
				return 'deliver';
			}
			if (timing === 'before') {
				triggered = true;
				return 'drop';
			}
		}
		return 'deliver';
	};
	if (timing === 'after') {
		link.after = (from, type): void => {
			if (triggered) return;
			if (from === fromPub && type === msgType) {
				if (toSkip > 0) return; // consumed by intercept side
				triggered = true;
			}
		};
	}
	return { triggered: (): boolean => triggered };
}

function disarm(link: ILink): void {
	link.intercept = undefined;
	link.after = undefined;
}

/** Complete a (possibly re-initiated) epoch and assert the invariants. */
function completeAndAssert(t: ITriple, label: string): void {
	const errs = (): string =>
		`${label}: ${t.rErrors.concat(t.sErrors).join('; ')}`;
	// Reconcile if the epoch is still open.
	const sEpoch = t.sChannel.getFforEpoch();
	if (sEpoch && sEpoch.state !== FforEpochState.FF_CLOSED) {
		if (t.sChannel.getState() !== ChannelState.NORMAL) {
			reconnectSR(t);
		}
	}
	expect(t.sChannel.getState(), errs()).to.equal(ChannelState.NORMAL);
	expect(t.rChannel.getState(), errs()).to.equal(ChannelState.NORMAL);
	expect(t.sChannel.getFforEpoch()!.state, errs()).to.equal(
		FforEpochState.FF_CLOSED
	);
	expect(t.rChannel.getFforEpoch()!.state, errs()).to.equal(
		FforEpochState.FF_CLOSED
	);
	// No duplicate settlement: exactly 2 packages, 2 upstream fulfills.
	expect(t.sChannel.getFforEpoch()!.lastSeq, errs()).to.equal(2);
	expect(t.pFulfilled.length, errs()).to.equal(2);
	// Convert vouchers (idempotent if already converted).
	if (t.rChannel.getFullState().htlcs.size > 0) {
		expect(t.rManager.fforFulfillVouchers(t.srChannelId).ok, errs()).to.equal(
			true
		);
	}
	// FINAL BALANCES equal the uncrashed reference: R credited V_SUM on S-R,
	// P debited the raw amounts on P-S. No fund loss anywhere.
	expect(t.rChannel.getBalances().localMsat, errs()).to.equal(V_SUM);
	expect(t.sChannel.getBalances().localMsat, errs()).to.equal(
		FUNDING_SATOSHIS * 1000n - V_SUM
	);
	expect(t.pChannel.getBalances().localMsat, errs()).to.equal(
		FUNDING_SATOSHIS * 1000n - PAY_1 - PAY_2
	);
	expect(t.spChannel.getBalances().localMsat, errs()).to.equal(PAY_1 + PAY_2);
	expect(t.sChannel.getFullState().htlcs.size, errs()).to.equal(0);
	expect(t.rChannel.getFullState().htlcs.size, errs()).to.equal(0);
}

/** Settle both payments while R is offline. */
function settleBoth(t: ITriple): void {
	pay(t, t.hashes[0], PAY_1);
	pay(t, t.hashes[1], PAY_2);
	expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(2);
	expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(2);
}

// ───────────────────────── SETUP arrows ─────────────────────────

describe('FFOR M6 crash matrix: SETUP arrows', function () {
	interface ISetupCase {
		name: string;
		/** Arrow: message type + sender at which the crash happens. */
		msg: MessageType;
		from: 'R' | 'S';
		timing: 'before' | 'after';
		crash: 'R' | 'S';
	}
	// Nothing is durable pre-ff_begin (spec §7.5/§11.2): a crash at any setup
	// arrow aborts the epoch on restart; the epoch is then re-initiated fresh
	// (new epoch_id) and the whole flow completes to the reference balances.
	const cases: ISetupCase[] = [
		{
			name: 'ff_init lost, R crashes after sending it',
			msg: MessageType.FF_INIT,
			from: 'R',
			timing: 'before',
			crash: 'R'
		},
		{
			name: 'S crashes right after processing ff_init (ff_accept dies with it)',
			msg: MessageType.FF_ACCEPT,
			from: 'S',
			timing: 'before',
			crash: 'S'
		},
		{
			name: 'R crashes right after processing ff_accept (its reply batch dies)',
			msg: MessageType.FF_INVOICES,
			from: 'R',
			timing: 'before',
			crash: 'R'
		},
		{
			name: 'S crashes after processing ff_invoices (ff_escape_sigs lost)',
			msg: MessageType.FF_ESCAPE_SIGS,
			from: 'R',
			timing: 'before',
			crash: 'S'
		},
		{
			name: 'S crashes after processing ff_escape_sigs (ff_begin lost)',
			msg: MessageType.FF_BEGIN,
			from: 'R',
			timing: 'before',
			crash: 'S'
		},
		{
			name: 'S crashes right after ff_begin (epoch durable on BOTH sides)',
			msg: MessageType.FF_BEGIN,
			from: 'R',
			timing: 'after',
			crash: 'S'
		},
		{
			name: 'R crashes right after ff_begin (epoch durable on BOTH sides)',
			msg: MessageType.FF_BEGIN,
			from: 'R',
			timing: 'after',
			crash: 'R'
		}
	];

	for (const c of cases) {
		it(c.name, function () {
			const t = createTriple({ prefix: 'cm-setup', noEpoch: true });
			// Escapes ON so ff_escape_sigs is a real arrow.
			const arm = armCrash(
				t.srLink,
				c.from === 'R' ? t.rPub : t.sPub,
				c.msg,
				c.timing
			);
			const res = t.rManager.initiateFforEpoch(t.srChannelId, {
				variant: 1,
				budgetMsat: 100_000_000n,
				maxPayments: 3,
				minPaymentMsat: 600_000n,
				settlementDeadline: 1000,
				voucherExpiry: 2008,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 5000,
				escapeGranularityMsat: 50_000_000n
			});
			expect(res.ok).to.equal(true); // local send succeeded
			expect(arm.triggered(), 'crash point reached').to.equal(true);

			// The crash: restart the side from its last durable state.
			disarm(t.srLink);
			if (c.crash === 'S') restartS(t);
			else restartR(t);

			const epochDurable =
				c.timing === 'after' && c.msg === MessageType.FF_BEGIN;
			if (epochDurable) {
				// ff_begin persisted on both sides before the crash: the epoch
				// SURVIVES the restart.
				expect(t.sChannel.getFforEpoch()?.state).to.equal(
					FforEpochState.FF_EPOCH
				);
				expect(t.rChannel.getFforEpoch()?.state).to.equal(
					FforEpochState.FF_EPOCH
				);
			}

			// Reconnect (S also re-reestablishes with P after an S crash).
			if (c.crash === 'S') reconnectPS(t);
			reconnectSR(t);
			// During a live epoch the channel state IS FF_EPOCH (not NORMAL).
			const expectedState = epochDurable
				? ChannelState.FF_EPOCH
				: ChannelState.NORMAL;
			expect(t.sChannel.getState(), t.sErrors.join('; ')).to.equal(
				expectedState
			);
			expect(t.rChannel.getState(), t.rErrors.join('; ')).to.equal(
				expectedState
			);

			if (!epochDurable) {
				// Nothing durable pre-ff_begin: both sides come back with NO
				// active epoch; re-initiate a fresh one (new epoch_id).
				expect(
					t.sChannel.getFforEpoch()?.state ?? FforEpochState.FF_CLOSED
				).to.not.equal(FforEpochState.FF_EPOCH);
				const retry = t.rManager.initiateFforEpoch(t.srChannelId, {
					variant: 1,
					budgetMsat: 100_000_000n,
					maxPayments: 3,
					minPaymentMsat: 600_000n,
					settlementDeadline: 1000,
					voucherExpiry: 2008,
					feeBaseMsat: 1000,
					feeProportionalMillionths: 5000,
					escapeGranularityMsat: 50_000_000n
				});
				expect(retry.ok, t.rErrors.concat(t.sErrors).join('; ')).to.equal(true);
			}
			t.hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
			expect(t.sChannel.getFforEpoch()!.state).to.equal(
				FforEpochState.FF_EPOCH
			);

			// Complete the whole flow to the reference balances.
			goOffline(t);
			settleBoth(t);
			reconnectSR(t);
			completeAndAssert(t, c.name);
		});
	}
});

// ─────────────────────── SETTLEMENT arrows ───────────────────────

describe('FFOR M6 crash matrix: SETTLEMENT arrows', function () {
	it('S crashes AFTER the HTLC commits but BEFORE the package persists', function () {
		const t = createTriple({ prefix: 'cm-set-a' });
		goOffline(t);
		pay(t, t.hashes[0], PAY_1); // settles; P got the fulfill
		// Second payment: the HTLC becomes irrevocably committed on P-S (and
		// that commitment point persists), then S crashes BEFORE the FFOR
		// engine persists the package: no seq 2, no package 2, no fulfill.
		// The upstream channel record alone must drive the recovery.
		let snap: { sr: string; sp: string } | null = null;
		t.sManager.on('channel:persist', (cid: Buffer) => {
			if (!cid.equals(t.psChannelId) || snap) return;
			const entry = [...t.spChannel.getFullState().htlcs.values()].find((h) =>
				h.paymentHash.equals(t.hashes[1])
			);
			if (
				entry?.state === 'COMMITTED' &&
				t.sChannel.getFforEpoch()!.lastSeq === 1
			) {
				snap = {
					sp: JSON.stringify(serializeChannelState(t.spChannel.getFullState())),
					sr: JSON.stringify(serializeChannelState(t.sChannel.getFullState()))
				};
				t.psLink.down(); // nothing after this instant escapes S
			}
		});
		pay(t, t.hashes[1], PAY_2);
		expect(snap, 'crash window captured').to.not.equal(null);
		expect(t.pFulfilled).to.have.length(1); // fulfill #2 died with S
		restartS(t, snap!);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(1); // pre-persist
		reconnectPS(t);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(2);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(2); // exactly once
		reconnectSR(t);
		completeAndAssert(t, 'settlement pre-persist');
	});

	it('variant B: S crashes after package persist, BEFORE the tower send', async function () {
		const t = createTriple({ prefix: 'cm-set-b', variant: 'B' });
		goOffline(t);
		// First payment settles normally through the tower.
		pay(t, t.hashes[0], PAY_1);
		await flush();
		expect(t.pFulfilled).to.have.length(1);

		// Second payment: the tower client "dies" before the request leaves —
		// the package is already persisted; S hangs exactly as a crashed
		// process would.
		let hung = false;
		t.sManager.setFforTowerClient({
			provision: async (p: IFforTowerProvisioning): Promise<void> =>
				t.tower!.provision(p),
			requestRelease: (): Promise<never> => {
				hung = true;
				t.psLink.down();
				return new Promise<never>(() => {}); // the crash
			},
			fetch: async (
				req: Parameters<LoopbackTowerClient['fetch']>[0]
			): ReturnType<LoopbackTowerClient['fetch']> => t.tower!.handleFetch(req)
		});
		pay(t, t.hashes[1], PAY_2);
		await flush();
		expect(hung).to.equal(true);
		expect(t.pFulfilled).to.have.length(1);
		expect(t.tower!.lastReleased).to.equal(1); // never reached T

		// Restart S (fresh tower client), reconnect P: the persisted package
		// re-dispatches to the tower and the payment completes exactly once.
		restartS(t);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(2);
		reconnectPS(t);
		await flush(20);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(2);
		expect(t.tower!.lastReleased).to.equal(2);
		reconnectSR(t);
		await flush();
		// Variant B conversion (§11.1 step 6): R fetches the preimages from
		// the tower (S's replay never carries them — TLV 3 is variant A only).
		expect(
			(
				await t.rManager.fforRecoverFromTower(
					t.srChannelId,
					new LoopbackTowerClient(t.tower!)
				)
			).ok
		).to.equal(true);
		completeAndAssert(t, 'settlement pre-tower-send');
	});

	it('variant B: S crashes after the tower stored+released, BEFORE processing the release', async function () {
		const t = createTriple({ prefix: 'cm-set-c', variant: 'B' });
		goOffline(t);
		pay(t, t.hashes[0], PAY_1);
		await flush();
		expect(t.pFulfilled).to.have.length(1);

		// The tower request goes THROUGH (T verifies + durably stores +
		// releases), but S dies before its response lands.
		let stored = false;
		t.sManager.setFforTowerClient({
			provision: async (p: IFforTowerProvisioning): Promise<void> =>
				t.tower!.provision(p),
			requestRelease: (pkg: Buffer): Promise<never> => {
				const res = t.tower!.handleReleaseRequest(pkg);
				stored = res.ok;
				t.psLink.down();
				return new Promise<never>(() => {}); // the crash
			},
			fetch: async (
				req: Parameters<LoopbackTowerClient['fetch']>[0]
			): ReturnType<LoopbackTowerClient['fetch']> => t.tower!.handleFetch(req)
		});
		pay(t, t.hashes[1], PAY_2);
		await flush();
		expect(stored).to.equal(true);
		expect(t.tower!.lastReleased).to.equal(2); // T holds it
		expect(t.pFulfilled).to.have.length(1); // S never fulfilled

		// Restart: S re-requests seq 2; the tower re-release is idempotent.
		restartS(t);
		reconnectPS(t);
		await flush(20);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(2);
		expect(t.tower!.lastReleased).to.equal(2);
		reconnectSR(t);
		await flush();
		expect(
			(
				await t.rManager.fforRecoverFromTower(
					t.srChannelId,
					new LoopbackTowerClient(t.tower!)
				)
			).ok
		).to.equal(true);
		completeAndAssert(t, 'settlement post-tower-store');
	});

	it('S crashes after the release (preimage persisted), BEFORE the upstream fulfill', function () {
		const t = createTriple({ prefix: 'cm-set-d' });
		goOffline(t);
		pay(t, t.hashes[0], PAY_1);
		// Crash window (§9.2): package 2 persisted + preimage durable, fulfill
		// never leaves. Snapshot S's durable state AT that persist (the crash
		// instant) and cut P-S so the fulfill dies with S.
		let snap: { sr: string; sp: string } | null = null;
		t.sManager.on('channel:persist', (cid: Buffer) => {
			if (!cid.equals(t.srChannelId) || snap) return;
			const epoch = t.sChannel.getFforEpoch();
			if (epoch && epoch.lastSeq === 2 && !epoch.upstreamFulfilled[1]) {
				snap = {
					sr: JSON.stringify(serializeChannelState(t.sChannel.getFullState())),
					sp: JSON.stringify(serializeChannelState(t.spChannel.getFullState()))
				};
				t.psLink.down(); // the fulfill dies with S
			}
		});
		pay(t, t.hashes[1], PAY_2);
		expect(t.pFulfilled).to.have.length(1);
		expect(snap, 'crash window captured').to.not.equal(null);
		restartS(t, snap!);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(2);
		expect(t.sChannel.getFforEpoch()!.upstreamFulfilled[1] ?? false).to.equal(
			false
		);
		reconnectPS(t);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(2);
		reconnectSR(t);
		completeAndAssert(t, 'settlement pre-fulfill');
	});

	it('S crashes after the fulfill was MARKED durable but its round never was (fulfill lost with the connection)', function () {
		const t = createTriple({ prefix: 'cm-set-e' });
		goOffline(t);
		pay(t, t.hashes[0], PAY_1);
		// The nasty inconsistent-durability window: the epoch channel's
		// upstreamFulfilled flag hits disk (it persists right after the
		// fulfill is dispatched) but the upstream channel's fulfill round does
		// NOT (its record predates the fulfill), and the wire died before the
		// fulfill reached P. On restart S must NOT treat its own crash-replay
		// as a duplicate part: same upstream htlc id -> re-fulfill.
		let spPreFulfill: string | null = null;
		t.sManager.on('channel:persist', (cid: Buffer) => {
			if (!cid.equals(t.psChannelId)) return;
			const entry = [...t.spChannel.getFullState().htlcs.values()].find((h) =>
				h.paymentHash.equals(t.hashes[1])
			);
			// Keep the LAST persist where the HTLC is still merely COMMITTED
			// (the round-complete record, before the fulfill touches it).
			if (entry?.state === 'COMMITTED') {
				spPreFulfill = JSON.stringify(
					serializeChannelState(t.spChannel.getFullState())
				);
			}
		});
		// The connection dies just before the fulfill would reach P.
		const arm = armCrash(
			t.psLink,
			t.sPub,
			MessageType.UPDATE_FULFILL_HTLC,
			'before'
		);
		pay(t, t.hashes[1], PAY_2);
		expect(arm.triggered()).to.equal(true);
		expect(spPreFulfill, 'pre-fulfill upstream record captured').to.not.equal(
			null
		);
		expect(t.pFulfilled).to.have.length(1); // the fulfill never arrived
		disarm(t.psLink);
		// sr from the LATEST persist (flag true + htlc id recorded); sp from
		// the pre-fulfill record.
		expect(
			t.sChannel.getFforEpoch()!.upstreamFulfilled[1],
			'flag durable'
		).to.equal(true);
		restartS(t, { sp: spPreFulfill! });
		expect(t.sChannel.getFforEpoch()!.upstreamFulfilled[1]).to.equal(true);
		reconnectPS(t);
		// The FFOR re-scan re-fulfills the SAME upstream HTLC (id matches) —
		// P's payment completes; no duplicate credit anywhere.
		expect(t.pFulfilled, t.sErrors.concat(t.pErrors).join('; ')).to.have.length(
			2
		);
		expect(t.spChannel.getBalances().localMsat).to.equal(PAY_1 + PAY_2);
		reconnectSR(t);
		completeAndAssert(t, 'settlement post-fulfill-mark');
	});
});

// ─────────────────────── RECONCILIATION arrows ───────────────────────

describe('FFOR M6 crash matrix: RECONCILIATION arrows', function () {
	interface IReconCase {
		name: string;
		msg: MessageType;
		from: 'R' | 'S';
		timing: 'before' | 'after';
		crash: 'R' | 'S';
		skip?: number;
	}
	const cases: IReconCase[] = [
		{
			name: "R's reestablish processed by S, replay package 1 lost (S crashes mid-replay)",
			msg: MessageType.FF_SETTLEMENT,
			from: 'S',
			timing: 'before',
			crash: 'S'
		},
		{
			name: 'R crashes after replayed package 1 of 2 (package 2 lost)',
			msg: MessageType.FF_SETTLEMENT,
			from: 'S',
			timing: 'before',
			crash: 'R',
			skip: 1
		},
		{
			name: 'R crashes after both packages, ff_reconcile lost',
			msg: MessageType.FF_RECONCILE,
			from: 'R',
			timing: 'before',
			crash: 'R'
		},
		{
			name: 'S crashes after ff_reconcile, ff_reconcile_ack lost',
			msg: MessageType.FF_RECONCILE_ACK,
			from: 'S',
			timing: 'before',
			crash: 'S'
		},
		{
			name: 'R crashes after the ack, ff_revoke_batch lost',
			msg: MessageType.FF_REVOKE_BATCH,
			from: 'R',
			timing: 'before',
			crash: 'R'
		},
		{
			name: 'S crashes after the revoke batch, ff_end lost',
			msg: MessageType.FF_END,
			from: 'S',
			timing: 'before',
			crash: 'S'
		},
		{
			name: "R crashes right after S's ff_end (R's own ff_end lost)",
			msg: MessageType.FF_END,
			from: 'S',
			timing: 'after',
			crash: 'R'
		}
	];

	for (const c of cases) {
		it(c.name, function () {
			const t = createTriple({ prefix: 'cm-rec' });
			goOffline(t);
			settleBoth(t);

			const arm = armCrash(
				t.srLink,
				c.from === 'R' ? t.rPub : t.sPub,
				c.msg,
				c.timing,
				{ skip: c.skip }
			);
			reconnectSR(t);
			expect(arm.triggered(), 'crash point reached').to.equal(true);
			disarm(t.srLink);

			// The crash + restart from durable state.
			if (c.crash === 'S') {
				restartS(t);
				reconnectPS(t);
			} else {
				restartR(t);
			}
			// S may believe it is still connected (its reestablish flew before
			// the crash): force both ends to reestablish cleanly.
			if (t.sChannel.getState() === ChannelState.NORMAL) {
				t.sManager.handlePeerDisconnected(t.rPub);
			}
			if (t.rChannel.getState() === ChannelState.NORMAL) {
				t.rManager.handlePeerDisconnected(t.sPub);
			}
			reconnectSR(t);
			completeAndAssert(t, c.name);
		});
	}

	it("R crashes at the reestablish arrow itself (S's reestablish + ffor TLV lost)", function () {
		const t = createTriple({ prefix: 'cm-rec-re' });
		goOffline(t);
		settleBoth(t);
		// R dies at the exact moment of reconnect: S's reestablish (with the
		// ffor TLV + catch-up point) is never processed.
		restartR(t);
		reconnectSR(t);
		completeAndAssert(t, 'reestablish arrow');
	});

	it('R crashes after fulfilling voucher 1 of 2 (second fulfill lost)', function () {
		const t = createTriple({ prefix: 'cm-voucher' });
		goOffline(t);
		settleBoth(t);
		reconnectSR(t);
		expect(t.rChannel.getFforEpoch()!.state).to.equal(FforEpochState.FF_CLOSED);
		expect(t.rChannel.getFullState().htlcs.size).to.equal(2);

		// Voucher conversion: crash R after the FIRST update_fulfill_htlc.
		const arm = armCrash(
			t.srLink,
			t.rPub,
			MessageType.UPDATE_FULFILL_HTLC,
			'after'
		);
		t.rManager.fforFulfillVouchers(t.srChannelId);
		expect(arm.triggered()).to.equal(true);
		disarm(t.srLink);
		restartR(t);
		if (t.sChannel.getState() === ChannelState.NORMAL) {
			t.sManager.handlePeerDisconnected(t.rPub);
		}
		reconnectSR(t);
		expect(t.sChannel.getState(), t.sErrors.join('; ')).to.equal(
			ChannelState.NORMAL
		);
		// Finish converting whatever remains; the final balances are exact.
		if (t.rChannel.getFullState().htlcs.size > 0) {
			expect(
				t.rManager.fforFulfillVouchers(t.srChannelId).ok,
				t.rErrors.concat(t.sErrors).join('; ')
			).to.equal(true);
		}
		expect(t.rChannel.getBalances().localMsat).to.equal(V_SUM);
		expect(t.sChannel.getBalances().localMsat).to.equal(
			FUNDING_SATOSHIS * 1000n - V_SUM
		);
		expect(t.rChannel.getFullState().htlcs.size).to.equal(0);
		expect(t.sChannel.getFullState().htlcs.size).to.equal(0);
	});
});
