/**
 * Direct-funding outstanding-request store (issue #610, LFBW port #532 4A).
 *
 * Every envelope handed out is only payable while its record survives, so the
 * tests here are about durability across a restart, the two indexes, the
 * expiry sweep, the outstanding cap, and the tombstone that keeps a paid
 * request answerable until it expires.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	DF_MAX_RECEIVED_RECORDS,
	DF_RECEIVED_RETENTION_MS,
	DF_RECEIVED_STORAGE_KEY,
	DF_REQUESTS_STORAGE_KEY,
	DirectFundingErrorCode,
	DirectFundingRequestStore,
	IDfReceivedRecord,
	IDfRequestRecord,
	IDfRequestStoreDeps,
	encodeSealedFrame,
	openFrame,
	requestEncryptionPublicKey,
	sealFrame,
	senderLaneKeys,
	decodeSealedFrame
} from '../../src/lightning/direct-funding';
import { DirectFundingError } from '../../src/lightning/direct-funding/types';

const HOUR = 60 * 60 * 1000;
const OFFER_SUBTYPE = 16;

interface IHarness {
	store: DirectFundingRequestStore;
	wallet: Map<string, string>;
	clock: { now: number };
	deps: IDfRequestStoreDeps;
	failWrites: { value: boolean };
}

function harness(
	config: { maxOutstanding?: number; requestTtlMs?: number } = {},
	shared?: { wallet: Map<string, string>; clock: { now: number } }
): IHarness {
	const wallet = shared?.wallet ?? new Map<string, string>();
	const clock = shared?.clock ?? { now: 1_700_000_000_000 };
	const failWrites = { value: false };
	const deps: IDfRequestStoreDeps = {
		storage: {
			saveWalletData: (key, value): void => {
				if (failWrites.value) throw new Error('disk is full');
				wallet.set(key, value);
			},
			loadWalletData: (key): string | null => wallet.get(key) ?? null
		},
		now: () => clock.now
	};
	return {
		store: new DirectFundingRequestStore(deps, config),
		wallet,
		clock,
		deps,
		failWrites
	};
}

const errorCode = (fn: () => unknown): string | undefined => {
	try {
		fn();
	} catch (e) {
		return (e as DirectFundingError).code;
	}
	return undefined;
};

describe('Direct funding: outstanding requests', () => {
	it('mints a distinct secret set per request', () => {
		const { store } = harness();
		const a = store.mint();
		const b = store.mint();
		expect(a.requestId).to.not.equal(b.requestId);
		expect(a.receiptHash).to.not.equal(b.receiptHash);
		expect(a.preimageHex).to.not.equal(b.preimageHex);
		expect(a.encryptionPrivateKeyHex).to.not.equal(b.encryptionPrivateKeyHex);
		expect(a.onionPathSecretHex).to.not.equal(b.onionPathSecretHex);
		expect(
			crypto
				.createHash('sha256')
				.update(Buffer.from(a.preimageHex, 'hex'))
				.digest('hex')
		).to.equal(a.receiptHash);
		expect(requestEncryptionPublicKey(a)).to.have.length(33);
		expect(a.swarmSeedHex).to.equal(undefined);
	});

	/**
	 * The envelope's amount is the payer's copy, and the offer that arrives
	 * carries an amount of the payer's choosing. A fixed-amount request is only
	 * enforceable against a figure the receiver kept, so it has to be durable
	 * and it has to survive a restart intact or not at all.
	 */
	it('records a fixed amount and keeps it across a restart', () => {
		const first = harness();
		const record = first.store.mint({ amountSat: 100_000n });
		expect(record.amountSat).to.equal('100000');
		expect(first.store.mint().amountSat).to.equal(undefined);
		expect(errorCode(() => first.store.mint({ amountSat: 0n }))).to.equal(
			DirectFundingErrorCode.MALFORMED
		);

		const second = harness({}, { wallet: first.wallet, clock: first.clock });
		expect(second.store.restore()).to.equal(2);
		expect(second.store.byReceiptHash(record.receiptHash)?.amountSat).to.equal(
			'100000'
		);
	});

	it('drops a restored record whose fixed amount did not survive', () => {
		const first = harness();
		const record = first.store.mint({ amountSat: 100_000n });
		const rows = JSON.parse(first.wallet.get(DF_REQUESTS_STORAGE_KEY)!);
		rows[0].amountSat = 'not-a-number';
		first.wallet.set(DF_REQUESTS_STORAGE_KEY, JSON.stringify(rows));

		const second = harness({}, { wallet: first.wallet, clock: first.clock });
		// Unpayable beats payable at any amount.
		expect(second.store.restore()).to.equal(0);
		expect(second.store.byReceiptHash(record.receiptHash)).to.equal(null);
	});

	it('restores across a restart with both indexes rebuilt', () => {
		const first = harness();
		const record = first.store.mint();
		expect(first.wallet.has(DF_REQUESTS_STORAGE_KEY)).to.equal(true);

		const second = harness({}, { wallet: first.wallet, clock: first.clock });
		expect(second.store.restore()).to.equal(1);
		expect(second.store.byRequestId(record.requestId)).to.deep.equal(record);
		expect(
			second.store.byOnionPathSecret(record.onionPathSecretHex)
		).to.deep.equal(record);
		expect(second.store.byReceiptHash(record.receiptHash)).to.deep.equal(
			record
		);
		expect(second.store.receiptPreimage(record.receiptHash)).to.equal(
			record.preimageHex
		);
	});

	it('drops expired records on restore and on the sweep', () => {
		const first = harness({ requestTtlMs: HOUR });
		const stale = first.store.mint();
		first.clock.now += HOUR / 2;
		const live = first.store.mint();
		first.clock.now += HOUR / 2;

		const second = harness({}, { wallet: first.wallet, clock: first.clock });
		expect(second.store.restore()).to.equal(1);
		expect(second.store.byRequestId(stale.requestId)).to.equal(null);
		expect(second.store.byOnionPathSecret(stale.onionPathSecretHex)).to.equal(
			null
		);
		expect(second.store.byRequestId(live.requestId)).to.not.equal(null);
		// The drop is written back, so the expired secrets leave storage too.
		expect(second.wallet.get(DF_REQUESTS_STORAGE_KEY)).to.not.contain(
			stale.preimageHex
		);

		second.clock.now += 2 * HOUR;
		expect(second.store.sweep()).to.equal(1);
		expect(second.store.size()).to.equal(0);
		expect(second.wallet.get(DF_REQUESTS_STORAGE_KEY)).to.equal('[]');
	});

	it('sweeps on a timer rather than only when a request is minted', async () => {
		// The fork pruned only from its mint route, so a node that minted one
		// request and then idled kept it, and its secrets, past expiry.
		const h = harness({ requestTtlMs: 20 });
		h.deps.now = (): number => Date.now();
		const store = new DirectFundingRequestStore(h.deps, {
			requestTtlMs: 20,
			sweepIntervalMs: 10
		});
		store.mint();
		store.start();
		await new Promise((resolve) => setTimeout(resolve, 60));
		store.stop();
		expect(store.size()).to.equal(0);
	});

	it('refuses cleanly at the outstanding cap', () => {
		const { store } = harness({ maxOutstanding: 2 });
		store.mint();
		store.mint();
		let code: string | undefined;
		try {
			store.mint();
		} catch (e) {
			code = (e as DirectFundingError).code;
		}
		expect(code).to.equal(DirectFundingErrorCode.TOO_MANY_REQUESTS);
		expect(store.size()).to.equal(2);
	});

	it('makes room at the cap once entries expire', () => {
		const h = harness({ maxOutstanding: 1, requestTtlMs: HOUR });
		h.store.mint();
		h.clock.now += HOUR + 1;
		expect(() => h.store.mint()).to.not.throw();
		expect(h.store.size()).to.equal(1);
	});

	it('refuses a mint whose secrets did not reach storage', () => {
		// An envelope handed out for an unpersisted request is unpayable after
		// the next restart, so the mint has to fail rather than the request.
		const h = harness();
		h.failWrites.value = true;
		expect(errorCode(() => h.store.mint())).to.equal(
			DirectFundingErrorCode.NOT_PERSISTED
		);
		expect(h.store.size()).to.equal(0);
		expect(h.wallet.has(DF_REQUESTS_STORAGE_KEY)).to.equal(false);
	});

	it('runs in memory when the node has no wallet-data storage', () => {
		const store = new DirectFundingRequestStore({});
		const record = store.mint();
		expect(store.byRequestId(record.requestId)).to.deep.equal(record);
		expect(store.restore()).to.equal(0);
	});

	it('survives corrupt persisted state instead of refusing to start', () => {
		const h = harness();
		h.wallet.set(DF_REQUESTS_STORAGE_KEY, '{not json');
		expect(h.store.restore()).to.equal(0);
		h.wallet.set(
			DF_REQUESTS_STORAGE_KEY,
			JSON.stringify([{ requestId: 'ab' }])
		);
		expect(h.store.restore()).to.equal(0);
	});

	describe('tombstones', () => {
		it('keeps a paid request decryptable and replayable until it expires', () => {
			// The fork DELETED the request when the receipt was used, so the
			// encryption key went with it and a payer whose receipt frame was
			// lost could never re-request it: the re-sent offer was dropped as
			// unknown before the idempotent replay path was reached.
			const { store, clock } = harness({ requestTtlMs: HOUR });
			const record = store.mint();
			store.markReceiptRevealed(record.receiptHash);
			expect(store.isTombstoned(record.receiptHash)).to.equal(true);
			expect(store.receiptPreimage(record.receiptHash)).to.equal(
				record.preimageHex
			);
			expect(store.byRequestId(record.requestId)).to.not.equal(null);

			const requestId = Buffer.from(record.requestId, 'hex');
			const sender = senderLaneKeys(
				requestEncryptionPublicKey(record),
				requestId
			);
			const wire = encodeSealedFrame(
				sealFrame(
					sender.keys.sendKey,
					requestId,
					OFFER_SUBTYPE,
					Buffer.from('the same offer again')
				),
				{ requestId, ephemeralPublicKey: sender.ephemeralPublicKey }
			);
			const lane = store.laneKeysForFrame(decodeSealedFrame(wire)!);
			expect(lane).to.not.equal(null);
			expect(
				openFrame(
					lane!.keys.recvKey,
					requestId,
					OFFER_SUBTYPE,
					decodeSealedFrame(wire)!
				)
			).to.deep.equal(Buffer.from('the same offer again'));

			clock.now += HOUR + 1;
			expect(store.byRequestId(record.requestId)).to.equal(null);
		});

		it('persists the tombstone across a restart', () => {
			const first = harness();
			const record = first.store.mint();
			first.store.markReceiptRevealed(record.receiptHash);
			const second = harness({}, { wallet: first.wallet, clock: first.clock });
			second.store.restore();
			expect(second.store.isTombstoned(record.receiptHash)).to.equal(true);
		});

		it('reports a tombstone that did not reach storage, and retries', () => {
			// Swallowing the failed write leaves a paid request looking unpaid
			// after the next restart.
			const h = harness();
			const record = h.store.mint();
			h.failWrites.value = true;
			expect(
				errorCode(() => h.store.markReceiptRevealed(record.receiptHash))
			).to.equal(DirectFundingErrorCode.NOT_PERSISTED);

			h.failWrites.value = false;
			h.store.markReceiptRevealed(record.receiptHash);
			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			restarted.store.restore();
			expect(restarted.store.isTombstoned(record.receiptHash)).to.equal(true);
		});
	});

	describe('the funding an attempt leaves in flight (issue #635)', () => {
		const OFFER_A = 'a1'.repeat(16);
		const OFFER_B = 'b2'.repeat(16);
		const funding = {
			outpoint: `${'ab'.repeat(32)}:1`,
			channelId: 'cd'.repeat(32),
			splice: false,
			contentHash: 'ef'.repeat(32),
			payerEphemeralKey: `02${'ab'.repeat(32)}`
		};

		it('holds the busy mark to the request expiry and restores the binding', () => {
			const first = harness({ requestTtlMs: HOUR });
			const record = first.store.mint();
			const slotExpiresAt = first.clock.now + 15 * 60 * 1000;
			expect(
				first.store.beginAttempt(record.receiptHash, OFFER_A, slotExpiresAt)
			).to.equal(true);
			expect(
				first.store.markAttemptFunding(
					record.receiptHash,
					OFFER_A,
					funding,
					record.expiresAt
				)
			).to.equal(true);

			// Past the slot the attempt took, and still inside the request's life:
			// the funding can only be finished by the payer's witness, so the
			// request is not free for a second one.
			const second = harness({}, { wallet: first.wallet, clock: first.clock });
			second.store.restore();
			second.clock.now = slotExpiresAt + 1;
			const attempt = second.store.attemptsFor(record.receiptHash);
			expect(attempt.activeOfferId).to.equal(OFFER_A);
			expect(attempt.funding).to.deep.equal(funding);
			expect(second.store.activeFundings()).to.deep.equal([
				{
					receiptHash: record.receiptHash,
					offerIdHex: OFFER_A,
					expiresAt: record.expiresAt,
					funding
				}
			]);
		});

		it('names no funding for an attempt another offer holds', () => {
			const { store, clock } = harness();
			const record = store.mint();
			store.beginAttempt(record.receiptHash, OFFER_A, clock.now + 1000);
			expect(
				store.markAttemptFunding(
					record.receiptHash,
					OFFER_B,
					funding,
					clock.now
				)
			).to.equal(false);
			expect(store.attemptsFor(record.receiptHash).funding).to.equal(undefined);
		});

		it('lets the funding go when the attempt settles', () => {
			const { store, clock } = harness();
			const record = store.mint();
			store.beginAttempt(record.receiptHash, OFFER_A, clock.now + 1000);
			store.markAttemptFunding(
				record.receiptHash,
				OFFER_A,
				funding,
				record.expiresAt
			);
			store.endAttempt(record.receiptHash, OFFER_A);
			expect(store.attemptsFor(record.receiptHash).activeOfferId).to.equal(
				undefined
			);
			expect(store.activeFundings()).to.deep.equal([]);
		});

		it('drops a marker whose payer lane key did not come back', () => {
			const first = harness();
			const record = first.store.mint();
			first.store.beginAttempt(
				record.receiptHash,
				OFFER_A,
				first.clock.now + 1000
			);
			const { payerEphemeralKey: _dropped, ...noLane } = funding;
			first.store.markAttemptFunding(
				record.receiptHash,
				OFFER_A,
				noLane as typeof funding,
				record.expiresAt
			);
			const second = harness({}, { wallet: first.wallet, clock: first.clock });
			second.store.restore();
			// Without the lane key the witness the funding is waiting for can
			// never be opened, so the marker answers nothing it is trusted for.
			expect(second.store.attemptsFor(record.receiptHash)).to.deep.equal({
				attempts: 1
			});
		});

		it('drops a marker that did not come back intact', () => {
			const first = harness();
			const record = first.store.mint();
			first.store.beginAttempt(
				record.receiptHash,
				OFFER_A,
				first.clock.now + 1000
			);
			first.store.markAttemptFunding(
				record.receiptHash,
				OFFER_A,
				{ ...funding, channelId: 'cd' },
				record.expiresAt
			);
			const second = harness({}, { wallet: first.wallet, clock: first.clock });
			expect(second.store.restore()).to.equal(1);
			// The record itself is intact, so the request stays payable; only the
			// marker that would have answered with a truncated channel id goes.
			expect(second.store.byReceiptHash(record.receiptHash)).to.not.equal(null);
			expect(second.store.attemptsFor(record.receiptHash)).to.deep.equal({
				attempts: 1
			});
		});
	});

	describe('a request that expires under a live funding (issue #644)', () => {
		const OFFER_A = 'a1'.repeat(16);
		const HOLD_MS = 15 * 60 * 1000;
		const funding = {
			outpoint: `${'ab'.repeat(32)}:1`,
			channelId: 'cd'.repeat(32),
			splice: false,
			contentHash: 'ef'.repeat(32),
			payerEphemeralKey: `02${'ab'.repeat(32)}`
		};

		/**
		 * A request paid so late in its life that the funding it negotiated is
		 * held past its own expiry, which is what the receiver's session does:
		 * the hold is the later of the request's expiry and the session TTL.
		 */
		function fundedNearExpiry(): {
			harness: IHarness;
			record: IDfRequestRecord;
			heldUntil: number;
		} {
			const h = harness({ requestTtlMs: HOUR });
			const record = h.store.mint();
			h.clock.now = record.expiresAt - 1_000;
			const heldUntil = h.clock.now + HOLD_MS;
			expect(
				h.store.beginAttempt(record.receiptHash, OFFER_A, h.clock.now + 1_000)
			).to.equal(true);
			expect(
				h.store.markAttemptFunding(
					record.receiptHash,
					OFFER_A,
					funding,
					heldUntil
				)
			).to.equal(true);
			return { harness: h, record, heldUntil };
		}

		it('answers for the funding after the request itself has lapsed', () => {
			const { harness: first, record } = fundedNearExpiry();
			first.clock.now = record.expiresAt + 1;

			// The payer's witness rides a continuation frame opened with the lane
			// key this row holds, and the receipt is this row's preimage: swept on
			// the request's clock, the channel could be finished by no route.
			const second = harness({}, { wallet: first.wallet, clock: first.clock });
			expect(second.store.restore()).to.equal(1);
			expect(second.store.byRequestId(record.requestId)).to.not.equal(null);
			expect(second.store.receiptPreimage(record.receiptHash)).to.equal(
				record.preimageHex
			);
			expect(
				second.store.attemptsFor(record.receiptHash).funding
			).to.deep.equal(funding);
			expect(second.store.activeFundings()).to.have.length(1);
			expect(second.store.sweep()).to.equal(0);
			expect(second.store.lapsedFundings()).to.deep.equal([]);
		});

		it('holds the row through a negotiation the request expires under', () => {
			const h = harness({ requestTtlMs: HOUR });
			const record = h.store.mint();
			h.clock.now = record.expiresAt - 1_000;
			const heldUntil = h.clock.now + HOLD_MS;
			expect(
				h.store.beginAttempt(record.receiptHash, OFFER_A, heldUntil)
			).to.equal(true);

			// The funding is named only once the transaction is final, which is
			// minutes after the offer was admitted. A row taken in that window
			// refuses the binding, and the channel the peer has signed for by then
			// is stranded exactly as it is when the mark itself goes.
			h.clock.now = record.expiresAt + 1;
			expect(h.store.sweep()).to.equal(0);
			expect(
				h.store.markAttemptFunding(
					record.receiptHash,
					OFFER_A,
					funding,
					heldUntil
				)
			).to.equal(true);
			expect(h.store.attemptsFor(record.receiptHash).funding).to.deep.equal(
				funding
			);
		});

		it('lets the row go when that attempt lapses naming no funding', () => {
			const h = harness({ requestTtlMs: HOUR });
			const record = h.store.mint();
			h.clock.now = record.expiresAt - 1_000;
			h.store.beginAttempt(record.receiptHash, OFFER_A, record.expiresAt);
			h.clock.now = record.expiresAt + 1;
			expect(h.store.sweep()).to.equal(1);
		});

		it('refuses a fresh attempt on a request only its funding keeps alive', () => {
			const { harness: h, record } = fundedNearExpiry();
			h.clock.now = record.expiresAt + 1;
			// The mark this funding is held by is not one another offer may take.
			expect(
				h.store.beginAttempt(record.receiptHash, 'b2'.repeat(16), h.clock.now)
			).to.equal(false);
			expect(h.store.attemptsFor(record.receiptHash).activeOfferId).to.equal(
				OFFER_A
			);
		});

		it('hands the funding over rather than sweeping the row from under it', () => {
			const { harness: h, record, heldUntil } = fundedNearExpiry();
			h.clock.now = heldUntil + 1;

			// The store cannot abort the channel the funding names, so it holds the
			// row until the receiver has: the sweep dropping it here is what leaves
			// a pending channel nothing can finish and nothing retires.
			expect(h.store.sweep()).to.equal(0);
			expect(h.store.size()).to.equal(1);
			expect(h.store.activeFundings()).to.deep.equal([]);
			expect(h.store.lapsedFundings()).to.deep.equal([
				{ receiptHash: record.receiptHash, offerIdHex: OFFER_A, funding }
			]);

			h.store.endAttempt(record.receiptHash, OFFER_A);
			expect(h.store.lapsedFundings()).to.deep.equal([]);
			expect(h.store.sweep()).to.equal(1);
			expect(h.store.byRequestId(record.requestId)).to.equal(null);
			expect(h.wallet.get(DF_REQUESTS_STORAGE_KEY)).to.equal('[]');
		});

		it('keeps a lapsed funding across a restart, for the receiver to retire', () => {
			const { harness: first, record, heldUntil } = fundedNearExpiry();
			first.clock.now = heldUntil + 1;
			const second = harness({}, { wallet: first.wallet, clock: first.clock });
			expect(second.store.restore()).to.equal(1);
			expect(second.store.lapsedFundings()).to.deep.equal([
				{ receiptHash: record.receiptHash, offerIdHex: OFFER_A, funding }
			]);
		});
	});

	describe('payments received (issue #1893)', () => {
		const OFFER_A = 'a1'.repeat(16);
		const OFFER_B = 'b2'.repeat(16);
		const FUNDING_TXID = '9f'.repeat(32);
		const funding = {
			outpoint: `${'ab'.repeat(32)}:1`,
			channelId: 'cd'.repeat(32),
			splice: true,
			contentHash: 'ef'.repeat(32),
			payerEphemeralKey: `02${'ab'.repeat(32)}`,
			fundingTxid: FUNDING_TXID,
			amountSat: '60000'
		};

		/** Pay a request the way the receiver does: attempt, funding, receipt. */
		function pay(
			h: IHarness,
			record: IDfRequestRecord,
			opts: { amountSat?: string; withFunding?: boolean } = {}
		): void {
			h.store.beginAttempt(record.receiptHash, OFFER_A, h.clock.now + HOUR);
			if (opts.withFunding !== false) {
				h.store.markAttemptFunding(
					record.receiptHash,
					OFFER_A,
					funding,
					h.clock.now + HOUR
				);
			}
			h.store.markReceiptRevealed(record.receiptHash, {
				offerIdHex: OFFER_A,
				fundingTxidHex: FUNDING_TXID,
				...(opts.amountSat !== undefined ? { amountSat: opts.amountSat } : {})
			});
		}

		it('records the payment with its channel and amount, and keeps it past the request', () => {
			const h = harness({ requestTtlMs: HOUR });
			const record = h.store.mint();
			const paidAt = h.clock.now;
			pay(h, record, { amountSat: '60000' });
			const expected: IDfReceivedRecord = {
				receiptHash: record.receiptHash,
				requestId: record.requestId,
				offerId: OFFER_A,
				fundingTxid: FUNDING_TXID,
				channelId: funding.channelId,
				splice: true,
				amountSat: '60000',
				status: 'PAID',
				paidAt,
				updatedAt: paidAt
			};
			expect(h.store.receivedFor(record.receiptHash)).to.deep.equal(expected);

			// The request and its secrets go on schedule; the payment does not.
			h.clock.now += 2 * HOUR;
			h.store.sweep();
			expect(h.store.byReceiptHash(record.receiptHash)).to.equal(null);
			expect(h.store.received()).to.deep.equal([expected]);

			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			expect(restarted.store.restore()).to.equal(0);
			expect(restarted.store.received()).to.deep.equal([expected]);
		});

		it("takes the funding's amount, then the request's, and names no channel without a funding", () => {
			const h = harness();
			const open = h.store.mint();
			pay(h, open);
			expect(h.store.receivedFor(open.receiptHash)?.amountSat).to.equal(
				'60000'
			);

			const fixed = h.store.mint({ amountSat: 25_000n });
			pay(h, fixed, { withFunding: false });
			const received = h.store.receivedFor(fixed.receiptHash);
			expect(received?.amountSat).to.equal('25000');
			expect(received).to.not.have.property('channelId');
			expect(received).to.not.have.property('splice');

			const unknown = h.store.mint();
			pay(h, unknown, { withFunding: false });
			expect(h.store.receivedFor(unknown.receiptHash)).to.not.have.property(
				'amountSat'
			);
		});

		it("keeps the first payment's record", () => {
			const h = harness();
			const record = h.store.mint();
			pay(h, record, { amountSat: '60000' });
			h.store.markReceiptRevealed(record.receiptHash, {
				offerIdHex: OFFER_B,
				fundingTxidHex: '11'.repeat(32),
				amountSat: '1'
			});
			expect(h.store.received()).to.have.length(1);
			expect(h.store.receivedFor(record.receiptHash)).to.include({
				offerId: OFFER_A,
				fundingTxid: FUNDING_TXID,
				amountSat: '60000'
			});
		});

		it('writes no record for a tombstone that names no payment', () => {
			const h = harness();
			const record = h.store.mint();
			h.store.markReceiptRevealed(record.receiptHash);
			expect(h.store.received()).to.deep.equal([]);
			expect(h.wallet.has(DF_RECEIVED_STORAGE_KEY)).to.equal(false);
		});

		it('gives a request paid before these records were kept its record on restore', () => {
			// Even an expired one, which the same restore then drops: its tombstone
			// is the last trace of the payment.
			const h = harness({ requestTtlMs: HOUR });
			const record = h.store.mint({ amountSat: 60_000n });
			pay(h, record, { withFunding: false });
			h.wallet.delete(DF_RECEIVED_STORAGE_KEY);
			h.clock.now += 2 * HOUR;

			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			expect(restarted.store.restore()).to.equal(0);
			expect(restarted.store.receivedFor(record.receiptHash)).to.include({
				offerId: OFFER_A,
				fundingTxid: FUNDING_TXID,
				amountSat: '60000',
				status: 'PAID'
			});
			expect(h.wallet.has(DF_RECEIVED_STORAGE_KEY)).to.equal(true);
		});

		/** Fail every write of the received set until the returned switch is flipped. */
		function failReceivedWrites(h: IHarness): { heal: () => void } {
			const save = h.deps.storage!.saveWalletData;
			h.deps.storage!.saveWalletData = (key, value): void => {
				if (key === DF_RECEIVED_STORAGE_KEY) throw new Error('disk is full');
				save(key, value);
			};
			return {
				heal: (): void => {
					h.deps.storage!.saveWalletData = save;
				}
			};
		}

		it('reports a record that did not reach storage, and lands it with a later write', () => {
			// No caller retries the reveal, and the tombstone it writes has already
			// cleared the mark holding the channel and the amount.
			const h = harness({ requestTtlMs: HOUR });
			const record = h.store.mint();
			const disk = failReceivedWrites(h);
			expect(errorCode(() => pay(h, record, { amountSat: '60000' }))).to.equal(
				DirectFundingErrorCode.NOT_PERSISTED
			);
			expect(h.wallet.has(DF_RECEIVED_STORAGE_KEY)).to.equal(false);

			// Expired, but its tombstone is the only stored trace of the payment.
			h.clock.now += 2 * HOUR;
			expect(h.store.sweep()).to.equal(0);
			disk.heal();
			expect(h.store.sweep(), 'the paid request goes once it has').to.equal(1);
			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			restarted.store.restore();
			expect(restarted.store.receivedFor(record.receiptHash)).to.include({
				channelId: funding.channelId,
				splice: true,
				amountSat: '60000'
			});
		});

		it('keeps the channel and amount on the tombstone for a restart before the retry', () => {
			// The tombstone clears the mark that held them, so a received record
			// that never landed is rebuilt from what the tombstone kept.
			const h = harness();
			const record = h.store.mint();
			failReceivedWrites(h);
			expect(errorCode(() => pay(h, record, { amountSat: '60000' }))).to.equal(
				DirectFundingErrorCode.NOT_PERSISTED
			);
			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			restarted.store.restore();
			expect(restarted.store.receivedFor(record.receiptHash)).to.include({
				channelId: funding.channelId,
				splice: true,
				amountSat: '60000'
			});
			expect(restarted.store.paidOffer(record.receiptHash)).to.deep.equal({
				offerIdHex: OFFER_A,
				fundingTxidHex: FUNDING_TXID
			});
		});

		it('holds back from the sweep only a paid request whose record is unsaved', () => {
			const h = harness({ requestTtlMs: HOUR });
			const saved = h.store.mint();
			pay(h, saved);
			const disk = failReceivedWrites(h);
			const unsaved = h.store.mint();
			expect(errorCode(() => pay(h, unsaved))).to.equal(
				DirectFundingErrorCode.NOT_PERSISTED
			);
			h.clock.now += 2 * HOUR;
			const stored = (): string[] =>
				(
					JSON.parse(
						h.wallet.get(DF_REQUESTS_STORAGE_KEY)!
					) as IDfRequestRecord[]
				).map((r) => r.receiptHash);
			expect(h.store.sweep()).to.equal(1);
			expect(stored()).to.deep.equal([unsaved.receiptHash]);
			disk.heal();
			expect(h.store.sweep()).to.equal(1);
			expect(stored()).to.deep.equal([]);
		});

		it('keeps an expired paid request on restore until its backfilled record lands', () => {
			const h = harness({ requestTtlMs: HOUR });
			const record = h.store.mint({ amountSat: 60_000n });
			pay(h, record, { withFunding: false });
			h.wallet.delete(DF_RECEIVED_STORAGE_KEY);
			h.clock.now += 2 * HOUR;

			const failing = harness({}, { wallet: h.wallet, clock: h.clock });
			const disk = failReceivedWrites(failing);
			failing.store.restore();
			expect(failing.store.receivedFor(record.receiptHash)).to.not.equal(null);
			expect(failing.store.sweep()).to.equal(0);
			disk.heal();
			expect(failing.store.sweep()).to.equal(1);

			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			restarted.store.restore();
			expect(
				restarted.store.receivedFor(record.receiptHash)?.amountSat
			).to.equal('60000');
		});

		it('lands a REVERTED mark whose write failed with the next write', () => {
			const h = harness();
			const record = h.store.mint();
			pay(h, record);
			const disk = failReceivedWrites(h);
			expect(h.store.markReceivedReverted(FUNDING_TXID)).to.equal(1);
			disk.heal();
			h.store.mint();
			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			restarted.store.restore();
			expect(restarted.store.receivedFor(record.receiptHash)?.status).to.equal(
				'REVERTED'
			);
		});

		it('marks the payment a reverted splice carried, and keeps it marked', () => {
			const h = harness();
			const record = h.store.mint();
			pay(h, record);
			expect(h.store.markReceivedReverted('22'.repeat(32))).to.equal(0);
			h.clock.now += 1_000;
			expect(h.store.markReceivedReverted(FUNDING_TXID)).to.equal(1);
			expect(h.store.markReceivedReverted(FUNDING_TXID)).to.equal(0);
			expect(h.store.receivedFor(record.receiptHash)).to.include({
				status: 'REVERTED',
				updatedAt: h.clock.now
			});

			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			restarted.store.restore();
			expect(restarted.store.receivedFor(record.receiptHash)?.status).to.equal(
				'REVERTED'
			);
		});

		it('drops a restored row that did not come back whole', () => {
			const h = harness();
			const record = h.store.mint();
			pay(h, record);
			const good = JSON.parse(h.wallet.get(DF_RECEIVED_STORAGE_KEY)!)[0];
			h.wallet.set(
				DF_RECEIVED_STORAGE_KEY,
				JSON.stringify([
					good,
					{ ...good, receiptHash: '33'.repeat(32), amountSat: '-5' },
					{ ...good, receiptHash: '44'.repeat(32), status: 'MAYBE' },
					{ ...good, receiptHash: 'zz' }
				])
			);
			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			restarted.store.restore();
			expect(restarted.store.received()).to.deep.equal([good]);

			// Corrupt rows run from nothing, and the paid request still held gives
			// its record back whole: the tombstone keeps the channel and amount
			// the mark it cleared held.
			h.wallet.set(DF_RECEIVED_STORAGE_KEY, '{not json');
			const corrupt = harness({}, { wallet: h.wallet, clock: h.clock });
			corrupt.store.restore();
			expect(corrupt.store.received()).to.deep.equal([good]);
		});

		it('lets a record past retention go on the sweep and on restore, with no new payment', () => {
			const h = harness();
			const record = h.store.mint();
			pay(h, record);
			h.clock.now += DF_RECEIVED_RETENTION_MS + 1;
			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			restarted.store.restore();
			expect(restarted.store.received()).to.deep.equal([]);
			expect(JSON.parse(h.wallet.get(DF_RECEIVED_STORAGE_KEY)!)).to.deep.equal(
				[]
			);

			const running = harness();
			const other = running.store.mint();
			pay(running, other);
			running.clock.now += DF_RECEIVED_RETENTION_MS + 1;
			running.store.sweep();
			expect(running.store.received()).to.deep.equal([]);
		});

		it('lets a record go after the retention window, and the oldest at the ceiling', () => {
			const h = harness();
			const old = h.store.mint();
			pay(h, old);
			h.clock.now += DF_RECEIVED_RETENTION_MS + 1;
			const fresh = h.store.mint();
			pay(h, fresh);
			expect(h.store.received().map((r) => r.receiptHash)).to.deep.equal([
				fresh.receiptHash
			]);

			const row = JSON.parse(h.wallet.get(DF_RECEIVED_STORAGE_KEY)!)[0];
			const full = Array.from({ length: DF_MAX_RECEIVED_RECORDS }, (_, i) => ({
				...row,
				receiptHash: i.toString(16).padStart(64, '0'),
				paidAt: h.clock.now - DF_MAX_RECEIVED_RECORDS + i,
				updatedAt: h.clock.now - DF_MAX_RECEIVED_RECORDS + i
			}));
			h.wallet.set(DF_RECEIVED_STORAGE_KEY, JSON.stringify(full));
			// Without the paid request still held, which would be given its record
			// back on restore and take a slot of its own.
			h.wallet.delete(DF_REQUESTS_STORAGE_KEY);
			const restarted = harness({}, { wallet: h.wallet, clock: h.clock });
			restarted.store.restore();
			const next = restarted.store.mint();
			pay(restarted, next);
			const kept = restarted.store.received().map((r) => r.receiptHash);
			expect(kept).to.have.length(DF_MAX_RECEIVED_RECORDS);
			expect(kept[0]).to.equal(next.receiptHash);
			expect(kept).to.not.include(full[0].receiptHash);
			expect(kept).to.include(full[1].receiptHash);
		});
	});

	describe('frames for requests we did not mint', () => {
		it('yields silence rather than an error', () => {
			const { store } = harness();
			const record = store.mint();
			const unknownId = crypto.randomBytes(16);
			const sender = senderLaneKeys(
				requestEncryptionPublicKey(record),
				unknownId
			);
			expect(
				store.laneKeysForFrame({
					requestId: unknownId,
					ephemeralPublicKey: sender.ephemeralPublicKey,
					nonce: Buffer.alloc(12),
					ciphertext: Buffer.alloc(16)
				})
			).to.equal(null);
		});

		it('yields silence for a continuation frame with no request id', () => {
			const { store } = harness();
			expect(
				store.laneKeysForFrame({
					nonce: Buffer.alloc(12),
					ciphertext: Buffer.alloc(16)
				})
			).to.equal(null);
		});

		it('yields silence for an expired request and a junk ephemeral key', () => {
			const h = harness({ requestTtlMs: HOUR });
			const record = h.store.mint();
			const requestId = Buffer.from(record.requestId, 'hex');
			expect(
				h.store.laneKeysForFrame({
					requestId,
					ephemeralPublicKey: Buffer.alloc(33, 0x05),
					nonce: Buffer.alloc(12),
					ciphertext: Buffer.alloc(16)
				})
			).to.equal(null);
			h.clock.now += HOUR + 1;
			const sender = senderLaneKeys(
				requestEncryptionPublicKey(record),
				requestId
			);
			expect(
				h.store.laneKeysForFrame({
					requestId,
					ephemeralPublicKey: sender.ephemeralPublicKey,
					nonce: Buffer.alloc(12),
					ciphertext: Buffer.alloc(16)
				})
			).to.equal(null);
		});
	});
});
