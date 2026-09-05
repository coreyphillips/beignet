/**
 * Held-forward ledger infrastructure (issue #708): the durable record store,
 * the compare-and-swap transition helper, the rehydrate-before-serve rule,
 * and the release capability construction. The node-level behaviour these
 * underpin lives in async-held-forward.test.ts.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	DurableLedger,
	ILedgerKeyValueStorage,
	ILedgerRecord,
	MemoryLedgerStore,
	MetadataLedgerStore
} from '../../src/lightning/storage/durable-ledger';
import {
	HeldForwardLedger,
	IHeldForwardRecord,
	heldForwardCodec
} from '../../src/lightning/async-payments/held-forward-ledger';
import {
	decodeReleaseCapability,
	deriveHoldRegistrationId,
	encodeReleaseCapability,
	signReleaseCapability,
	verifyReleaseCapability
} from '../../src/lightning/async-payments/release-capability';
import {
	decodeHeldForwardNotice,
	encodeHeldForwardNotice
} from '../../src/lightning/async-payments/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

interface IToyRecord extends ILedgerRecord {
	id: string;
	state: 'A' | 'B' | 'C';
	note?: string;
}

/** In-memory key/value storage with a transaction that rolls back on throw. */
class FakeKv implements ILedgerKeyValueStorage {
	rows = new Map<string, string>();
	failNext = false;
	saveMetadata(key: string, value: string): void {
		if (this.failNext) {
			this.failNext = false;
			throw new Error('disk full');
		}
		this.rows.set(key, value);
	}
	loadMetadata(key: string): string | null {
		return this.rows.get(key) ?? null;
	}
	transaction<T>(fn: () => T): T {
		const snapshot = new Map(this.rows);
		try {
			return fn();
		} catch (err) {
			this.rows = snapshot;
			throw err;
		}
	}
}

function toyLedger(store = new MemoryLedgerStore<IToyRecord>()): {
	ledger: DurableLedger<IToyRecord>;
	store: MemoryLedgerStore<IToyRecord>;
} {
	const ledger = new DurableLedger<IToyRecord>(store);
	ledger.rehydrate();
	return { ledger, store };
}

function holdFields(
	overrides: Partial<IHeldForwardRecord> = {}
): Parameters<HeldForwardLedger['register']>[0] {
	return {
		inChannelIdHex: 'aa'.repeat(32),
		inHtlcId: '0',
		paymentHashHex: 'bb'.repeat(32),
		outChannelIdHex: 'cc'.repeat(32),
		receiverNodeIdHex: '02' + 'dd'.repeat(32),
		registrationIdHex: 'ee'.repeat(32),
		incomingAmountMsat: '1001000',
		forwardAmountMsat: '1000000',
		forwardCltv: 143,
		incomingCltvExpiry: 183,
		cutoffHeight: 103,
		...overrides
	};
}

describe('DurableLedger (issue #708 infrastructure)', () => {
	it('refuses every transition until rehydrated', () => {
		const ledger = new DurableLedger<IToyRecord>(
			new MemoryLedgerStore<IToyRecord>()
		);
		expect(ledger.insert({ id: 'x', state: 'A' }).outcome).to.equal(
			'not_rehydrated'
		);
		expect(ledger.transition('x', ['A'], 'B').outcome).to.equal(
			'not_rehydrated'
		);
		expect(ledger.rehydrate()).to.equal(0);
		expect(ledger.insert({ id: 'x', state: 'A' }).outcome).to.equal('applied');
	});

	it('insert is idempotent on id: a second insert is stale, never an overwrite', () => {
		const { ledger } = toyLedger();
		ledger.insert({ id: 'x', state: 'A', note: 'first' });
		const dup = ledger.insert({ id: 'x', state: 'A', note: 'second' });
		expect(dup.outcome).to.equal('stale');
		expect(ledger.get('x')!.note).to.equal('first');
	});

	it('transition is compare-and-swap: wrong state is stale and leaves the row alone', () => {
		const { ledger } = toyLedger();
		ledger.insert({ id: 'x', state: 'A' });
		expect(ledger.transition('x', ['A'], 'B').outcome).to.equal('applied');
		const again = ledger.transition('x', ['A'], 'B');
		expect(again.outcome).to.equal('stale');
		expect(again.actualState).to.equal('B');
		expect(ledger.transition('nope', ['A'], 'B').outcome).to.equal('missing');
		expect(ledger.get('x')!.state).to.equal('B');
	});

	it('a set transition moves every member or none', () => {
		const { ledger } = toyLedger();
		ledger.insert({ id: 'x', state: 'A' });
		ledger.insert({ id: 'y', state: 'A' });
		ledger.insert({ id: 'z', state: 'B' });
		const mixed = ledger.transitionSet(['x', 'y', 'z'], ['A'], 'C');
		expect(mixed.outcome).to.equal('stale');
		expect(ledger.get('x')!.state, 'x untouched').to.equal('A');
		expect(ledger.get('y')!.state, 'y untouched').to.equal('A');
		const clean = ledger.transitionSet(['x', 'y'], ['A'], 'C', { note: 'set' });
		expect(clean.outcome).to.equal('applied');
		expect(ledger.get('x')!.state).to.equal('C');
		expect(ledger.get('y')!.note).to.equal('set');
	});

	it('the durable write lands before memory changes: a storage failure leaves memory as it was', () => {
		const kv = new FakeKv();
		const store = new MetadataLedgerStore<IToyRecord>(kv, 'toy', {
			encode: (r) => JSON.stringify(r),
			decode: (s) => JSON.parse(s) as IToyRecord
		});
		const ledger = new DurableLedger<IToyRecord>(store);
		ledger.rehydrate();
		ledger.insert({ id: 'x', state: 'A' });
		kv.failNext = true;
		const failed = ledger.transition('x', ['A'], 'B');
		expect(failed.outcome).to.equal('storage_failed');
		expect(ledger.get('x')!.state, 'memory unchanged').to.equal('A');
		expect(store.load('x')!.state, 'disk unchanged').to.equal('A');
		expect(ledger.transition('x', ['A'], 'B').outcome).to.equal('applied');
		expect(store.load('x')!.state).to.equal('B');
	});

	it('a set transition that fails mid-write rolls the whole set back', () => {
		const kv = new FakeKv();
		const store = new MetadataLedgerStore<IToyRecord>(kv, 'toy', {
			encode: (r) => JSON.stringify(r),
			decode: (s) => JSON.parse(s) as IToyRecord
		});
		const ledger = new DurableLedger<IToyRecord>(store);
		ledger.rehydrate();
		ledger.insert({ id: 'x', state: 'A' });
		ledger.insert({ id: 'y', state: 'A' });
		// The first row write of the set fails; the transaction rolls back.
		kv.failNext = true;
		expect(ledger.transitionSet(['x', 'y'], ['A'], 'B').outcome).to.equal(
			'storage_failed'
		);
		expect(store.load('x')!.state).to.equal('A');
		expect(store.load('y')!.state).to.equal('A');
		expect(ledger.get('x')!.state).to.equal('A');
		expect(ledger.get('y')!.state).to.equal('A');
	});

	it('MetadataLedgerStore keeps rows and index across instances, and delete tombstones', () => {
		const kv = new FakeKv();
		const codec = {
			encode: (r: IToyRecord): string => JSON.stringify(r),
			decode: (s: string): IToyRecord => JSON.parse(s) as IToyRecord
		};
		const first = new DurableLedger<IToyRecord>(
			new MetadataLedgerStore<IToyRecord>(kv, 'toy', codec)
		);
		first.rehydrate();
		first.insert({ id: 'x', state: 'A' });
		first.insert({ id: 'y', state: 'A' });
		first.remove('y');
		// A second record type over the SAME storage under its own prefix
		// neither sees nor disturbs the first: the witness ledger's shape.
		const other = new DurableLedger<IToyRecord>(
			new MetadataLedgerStore<IToyRecord>(kv, 'witness', codec)
		);
		other.rehydrate();
		other.insert({ id: 'x', state: 'B' });

		const second = new DurableLedger<IToyRecord>(
			new MetadataLedgerStore<IToyRecord>(kv, 'toy', codec)
		);
		expect(second.rehydrate()).to.equal(1);
		expect(second.get('x')!.state).to.equal('A');
		expect(second.get('y')).to.equal(undefined);
		const otherAgain = new DurableLedger<IToyRecord>(
			new MetadataLedgerStore<IToyRecord>(kv, 'witness', codec)
		);
		expect(otherAgain.rehydrate()).to.equal(1);
		expect(otherAgain.get('x')!.state).to.equal('B');
	});

	it('MetadataLedgerStore rides the real SQLite metadata table transactionally', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ledger-'));
		const db = new SqliteStorage(path.join(dir, 'node.db'));
		db.open();
		const store = new MetadataLedgerStore<IHeldForwardRecord>(
			db,
			'held_forward',
			heldForwardCodec
		);
		const ledger = new HeldForwardLedger(store);
		ledger.rehydrate();
		const reg = ledger.register(holdFields())!;
		expect(reg.created).to.equal(true);
		expect(
			ledger.beginRelease([reg.record.id], 'ff'.repeat(32)).outcome
		).to.equal('applied');
		db.close();

		const reopened = new SqliteStorage(path.join(dir, 'node.db'));
		reopened.open();
		const again = new HeldForwardLedger(
			new MetadataLedgerStore<IHeldForwardRecord>(
				reopened,
				'held_forward',
				heldForwardCodec
			)
		);
		expect(again.rehydrate()).to.equal(1);
		const row = again.get(reg.record.id)!;
		expect(row.state).to.equal('RELEASING');
		expect(row.releaseNonceHex).to.equal('ff'.repeat(32));
		reopened.close();
	});
});

describe('HeldForwardLedger', () => {
	function fresh(): HeldForwardLedger {
		const ledger = new HeldForwardLedger(
			new MemoryLedgerStore<IHeldForwardRecord>()
		);
		ledger.rehydrate();
		return ledger;
	}

	it('keys by random hold_id and indexes by payment hash: two parts, one hash, two rows', () => {
		const ledger = fresh();
		const a = ledger.register(holdFields({ inHtlcId: '0' }))!;
		const b = ledger.register(holdFields({ inHtlcId: '1' }))!;
		expect(a.record.id).to.not.equal(b.record.id);
		expect(a.record.id).to.have.length(64);
		expect(ledger.partsForPaymentHash('bb'.repeat(32))).to.have.length(2);
		expect(ledger.byIncoming('aa'.repeat(32), 1n)!.id).to.equal(b.record.id);
	});

	it('register is idempotent on the canonical (channel, htlc) identity', () => {
		const ledger = fresh();
		const first = ledger.register(holdFields())!;
		const again = ledger.register(holdFields())!;
		expect(again.created).to.equal(false);
		expect(again.record.id).to.equal(first.record.id);
		expect(ledger.list()).to.have.length(1);
	});

	it('walks HELD -> RELEASING -> RELEASED with every arrow a CAS', () => {
		const ledger = fresh();
		const { record } = ledger.register(holdFields())!;
		expect(ledger.markReleased(record.id).outcome, 'no skipping').to.equal(
			'stale'
		);
		expect(ledger.beginRelease([record.id], '00'.repeat(32)).outcome).to.equal(
			'applied'
		);
		expect(
			ledger.beginRelease([record.id], '11'.repeat(32)).outcome,
			'second release is stale'
		).to.equal('stale');
		expect(ledger.markReleased(record.id).outcome).to.equal('applied');
		expect(ledger.markReleased(record.id).outcome).to.equal('stale');
		expect(ledger.beginFail(record.id, 'late').outcome).to.equal('stale');
		expect(ledger.get(record.id)!.state).to.equal('RELEASED');
	});

	it('walks HELD -> FAILING -> FAILED, and a release after the fail loses', () => {
		const ledger = fresh();
		const { record } = ledger.register(holdFields())!;
		expect(ledger.beginFail(record.id, 'cutoff').outcome).to.equal('applied');
		expect(ledger.beginRelease([record.id], '00'.repeat(32)).outcome).to.equal(
			'stale'
		);
		expect(ledger.markFailed(record.id).outcome).to.equal('applied');
		expect(ledger.markFailed(record.id).outcome).to.equal('stale');
		expect(ledger.get(record.id)!.failReason).to.equal('cutoff');
	});

	it('the cutoff race has one durable winner whichever order the writes land', () => {
		for (const releaseFirst of [true, false]) {
			const ledger = fresh();
			const { record } = ledger.register(holdFields())!;
			const release = (): string =>
				ledger.beginRelease([record.id], '00'.repeat(32)).outcome;
			const cutoff = (): string =>
				ledger.beginFail(record.id, 'cutoff').outcome;
			const [first, second] = releaseFirst
				? [release(), cutoff()]
				: [cutoff(), release()];
			expect(first).to.equal('applied');
			expect(second).to.equal('stale');
			expect(ledger.get(record.id)!.state).to.equal(
				releaseFirst ? 'RELEASING' : 'FAILING'
			);
		}
	});

	it('a set release is atomic: one part already failed keeps every part where it was', () => {
		const ledger = fresh();
		const a = ledger.register(holdFields({ inHtlcId: '0' }))!.record;
		const b = ledger.register(holdFields({ inHtlcId: '1' }))!.record;
		ledger.beginFail(b.id, 'cutoff');
		expect(ledger.beginRelease([a.id, b.id], '00'.repeat(32)).outcome).to.equal(
			'stale'
		);
		expect(ledger.get(a.id)!.state).to.equal('HELD');
		expect(ledger.get(b.id)!.state).to.equal('FAILING');
	});

	it('forget drops only terminal rows', () => {
		const ledger = fresh();
		const { record } = ledger.register(holdFields())!;
		expect(ledger.forget(record.id)).to.equal(false);
		ledger.beginFail(record.id, 'operator');
		ledger.markFailed(record.id);
		expect(ledger.forget(record.id)).to.equal(true);
		expect(ledger.list()).to.have.length(0);
	});
});

describe('Release capability', () => {
	const receiverPriv = crypto.createHash('sha256').update('receiver').digest();
	const receiverPub = getPublicKey(receiverPriv);
	const lspPriv = crypto.createHash('sha256').update('lsp').digest();
	const lspPub = getPublicKey(lspPriv);
	const chainHash = Buffer.alloc(32, 7);

	function make(
		overrides: Partial<Parameters<typeof signReleaseCapability>[0]> = {}
	) {
		return signReleaseCapability(
			{
				chainHash,
				receiverNodeId: receiverPub,
				lspNodeId: lspPub,
				registrationId: deriveHoldRegistrationId(receiverPub, lspPub),
				amountMsat: 1_000_000n,
				expiresAt: 4_000_000_000n,
				nonce: crypto.randomBytes(32),
				holdIds: [Buffer.alloc(32, 9), Buffer.alloc(32, 2)],
				...overrides
			},
			receiverPriv
		);
	}

	it('round-trips the wire encoding with hold ids in canonical order', () => {
		const cap = make();
		const decoded = decodeReleaseCapability(encodeReleaseCapability(cap))!;
		expect(decoded).to.not.equal(null);
		expect(decoded.holdIds.map((h) => h[0])).to.deep.equal([2, 9]);
		expect(decoded.amountMsat).to.equal(1_000_000n);
		expect(decoded.receiverNodeId).to.deep.equal(receiverPub);
		expect(verifyReleaseCapability(decoded)).to.equal(true);
	});

	it('every bound field is load-bearing: changing one invalidates the signature', () => {
		const cap = make();
		const tampered: Array<Partial<typeof cap>> = [
			{ chainHash: Buffer.alloc(32, 8) },
			{ lspNodeId: receiverPub },
			{ registrationId: Buffer.alloc(32, 1) },
			{ amountMsat: 1_000_001n },
			{ expiresAt: 4_000_000_001n },
			{ nonce: Buffer.alloc(32, 0) },
			{ holdIds: [Buffer.alloc(32, 2)] }
		];
		for (const change of tampered) {
			expect(
				verifyReleaseCapability({ ...cap, ...change }),
				JSON.stringify(Object.keys(change))
			).to.equal(false);
		}
		// Naming a different receiver identity fails too: the signature is
		// checked against the identity the capability names.
		expect(
			verifyReleaseCapability({ ...cap, receiverNodeId: lspPub })
		).to.equal(false);
	});

	it('a capability signed by another key does not verify for the named receiver', () => {
		const forged = signReleaseCapability(
			{
				chainHash,
				receiverNodeId: receiverPub,
				lspNodeId: lspPub,
				registrationId: deriveHoldRegistrationId(receiverPub, lspPub),
				amountMsat: 1n,
				expiresAt: 4_000_000_000n,
				nonce: crypto.randomBytes(32),
				holdIds: [Buffer.alloc(32, 1)]
			},
			lspPriv
		);
		expect(verifyReleaseCapability(forged)).to.equal(false);
	});

	it('decode refuses unsorted or duplicated hold ids, bad versions and truncation', () => {
		const cap = make();
		const wire = encodeReleaseCapability(cap);
		expect(decodeReleaseCapability(wire.subarray(0, wire.length - 1))).to.equal(
			null
		);
		const badVersion = Buffer.from(wire);
		badVersion[0] = 2;
		expect(decodeReleaseCapability(badVersion)).to.equal(null);
		// Swap the two sorted ids in place: same bytes, wrong order.
		const idsOff = wire.length - 64 - 64;
		const swapped = Buffer.from(wire);
		wire.copy(swapped, idsOff, idsOff + 32, idsOff + 64);
		wire.copy(swapped, idsOff + 32, idsOff, idsOff + 32);
		expect(decodeReleaseCapability(swapped)).to.equal(null);
		const dup = Buffer.from(wire);
		wire.copy(dup, idsOff + 32, idsOff, idsOff + 32);
		expect(decodeReleaseCapability(dup)).to.equal(null);
		expect(decodeReleaseCapability(Buffer.alloc(32, 1))).to.equal(null);
	});

	it('the registration id binds the (receiver, LSP) pair', () => {
		expect(deriveHoldRegistrationId(receiverPub, lspPub)).to.deep.equal(
			deriveHoldRegistrationId(receiverPub, lspPub)
		);
		expect(deriveHoldRegistrationId(receiverPub, lspPub)).to.not.deep.equal(
			deriveHoldRegistrationId(lspPub, receiverPub)
		);
	});
});

describe('HELD_HTLC_NOTICE encoding', () => {
	it('round-trips and refuses malformed payloads', () => {
		const entry = {
			holdId: Buffer.alloc(32, 1),
			paymentHash: Buffer.alloc(32, 2),
			forwardAmountMsat: 123_456_789n,
			forwardCltv: 800_100,
			cutoffHeight: 800_060,
			registrationId: Buffer.alloc(32, 3)
		};
		const wire = encodeHeldForwardNotice({ entries: [entry, entry] });
		const back = decodeHeldForwardNotice(wire)!;
		expect(back.entries).to.have.length(2);
		expect(back.entries[1]).to.deep.equal(entry);
		expect(decodeHeldForwardNotice(wire.subarray(0, wire.length - 1))).to.equal(
			null
		);
		expect(decodeHeldForwardNotice(Buffer.alloc(0))).to.equal(null);
	});
});
