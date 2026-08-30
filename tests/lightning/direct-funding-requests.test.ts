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
	DF_REQUESTS_STORAGE_KEY,
	DirectFundingErrorCode,
	DirectFundingRequestStore,
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
			contentHash: 'ef'.repeat(32)
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
