/**
 * Swap ledger and key derivation (issue #737, phase 2): codec, legal and
 * illegal arrows, the write-once preimage, storage failure atomicity, a
 * SqliteStorage rehydrate, and the node's own ledger wiring.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	IDurableLedgerStore,
	ILedgerKeyValueStorage,
	MemoryLedgerStore,
	MetadataLedgerStore
} from '../../src/lightning/storage/durable-ledger';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	ISwapRecord,
	ISwapRecordInput,
	SWAP_LEDGER_PREFIX,
	SwapLedger,
	SwapState,
	deriveSwapId,
	deriveSwapKey,
	isTerminalSwapState,
	swapCodec,
	swapSourcesFor
} from '../../src/lightning/swaps';
import { createNode } from './helpers/loopback-nodes';

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

function input(overrides: Partial<ISwapRecordInput> = {}): ISwapRecordInput {
	return {
		id: crypto.randomBytes(16).toString('hex'),
		direction: 'reverse',
		peerNodeIdHex: '02' + '11'.repeat(32),
		paymentHashHex: crypto.randomBytes(32).toString('hex'),
		claimPubkeyHex: '02' + '22'.repeat(32),
		refundPubkeyHex: '02' + '33'.repeat(32),
		refundHeight: 1000,
		outputScriptHex: '0020' + '44'.repeat(32),
		address: 'bcrt1q',
		network: 'regtest',
		onchainSat: '100000',
		invoiceMsat: '101000000',
		totalFeeSat: '1000',
		minerFeeSat: '300',
		createdAt: 1,
		createdHeight: 900,
		...overrides
	};
}

function ledgerOn(
	store: IDurableLedgerStore<ISwapRecord> = new MemoryLedgerStore<ISwapRecord>()
): SwapLedger {
	const ledger = new SwapLedger(store);
	ledger.rehydrate();
	return ledger;
}

describe('Swap ledger (issue #737 phase 2)', function () {
	describe('codec', function () {
		it('round-trips a record and rejects malformed rows', function () {
			const ledger = ledgerOn();
			const inserted = ledger.insert(input());
			expect(inserted.outcome).to.equal('applied');
			const record = inserted.record!;
			expect(swapCodec.decode(swapCodec.encode(record))).to.deep.equal(record);
			// A resolution read back is history: its session verification is
			// cleared, the rest round-trips.
			const resolved = {
				...record,
				resolution: {
					kind: 'refund' as const,
					txid: 'ab'.repeat(32),
					confirmations: 3,
					verifiedThisSession: true
				}
			};
			expect(swapCodec.decode(swapCodec.encode(resolved))).to.deep.equal({
				...resolved,
				resolution: { ...resolved.resolution, verifiedThisSession: false }
			});
			expect(swapCodec.decode('not json')).to.equal(null);
			expect(
				swapCodec.decode(JSON.stringify({ ...record, state: 'NOPE' }))
			).to.equal(null);
			expect(
				swapCodec.decode(JSON.stringify({ ...record, direction: 'sideways' }))
			).to.equal(null);
			expect(
				swapCodec.decode(JSON.stringify({ ...record, onchainSat: 100000 }))
			).to.equal(null);
			expect(
				swapCodec.decode(JSON.stringify({ ...record, paymentHashHex: 'ab' }))
			).to.equal(null);
			expect(
				swapCodec.decode(JSON.stringify({ ...record, preimageHex: 'zz' }))
			).to.equal(null);
			// A submarine state on a reverse row is malformed too.
			expect(
				swapCodec.decode(JSON.stringify({ ...record, state: 'PAYING' }))
			).to.equal(null);
		});
	});

	describe('arrows', function () {
		it('follows the reverse lifecycle and refuses everything else', function () {
			const ledger = ledgerOn();
			const id = ledger.insert(input()).record!.id;
			const path: SwapState[] = [
				'HELD',
				'FUNDING',
				'FUNDING_BROADCAST',
				'FUNDED',
				'REFUND_PENDING',
				'CLAIMED',
				'SETTLED'
			];
			for (const to of path) {
				const r = ledger.move(id, to);
				expect(r.outcome, to).to.equal('applied');
				expect(r.record!.state).to.equal(to);
			}
			expect(isTerminalSwapState(ledger.get(id)!.state)).to.equal(true);
			// Terminal: nothing moves, nothing patches state.
			for (const to of ['EXPOSED', 'REFUNDED', 'HELD', 'FAILED'] as const) {
				expect(ledger.move(id, to).outcome, to).to.equal('stale');
			}
			expect(ledger.get(id)!.state).to.equal('SETTLED');
		});

		it('refuses an illegal arrow without touching the row', function () {
			const ledger = ledgerOn();
			const id = ledger.insert(input()).record!.id;
			// CREATED cannot fund, settle or refund.
			for (const to of ['FUNDING', 'SETTLED', 'REFUNDED', 'EXPOSED'] as const) {
				const r = ledger.move(id, to);
				expect(r.outcome, to).to.equal('stale');
				expect(r.actualState).to.equal('CREATED');
			}
			expect(ledger.move('nope', 'HELD').outcome).to.equal('missing');
			expect(ledger.get(id)!.state).to.equal('CREATED');
		});

		it('exposes the sources of every arrow', function () {
			expect(swapSourcesFor('reverse', 'CLAIMED').sort()).to.deep.equal(
				['FUNDED', 'FUNDING_BROADCAST', 'REFUND_PENDING'].sort()
			);
			expect(swapSourcesFor('reverse', 'EXPOSED').sort()).to.deep.equal(
				[
					'CLAIMED',
					'FUNDED',
					'FUNDING',
					'FUNDING_BROADCAST',
					'REFUND_PENDING'
				].sort()
			);
			expect(swapSourcesFor('reverse', 'REFUNDED')).to.deep.equal([
				'REFUND_PENDING'
			]);
			expect(swapSourcesFor('reverse', 'CREATED')).to.deep.equal([]);
			expect(
				swapSourcesFor('submarine', 'PREIMAGE_KNOWN').sort()
			).to.deep.equal(['PAYING', 'PAYMENT_UNRESOLVED'].sort());
		});

		it('follows the submarine lifecycle including a funding reorg', function () {
			const ledger = ledgerOn();
			const id = ledger.insert(input({ direction: 'submarine' })).record!.id;
			for (const to of [
				'FUNDING_SEEN',
				'FUNDING_LOST',
				'FUNDING_SEEN',
				'FUNDED',
				'PAYING',
				'PAYMENT_UNRESOLVED',
				'PREIMAGE_KNOWN',
				'CLAIM_BROADCAST',
				'CLAIM_CONFIRMED'
			] as const) {
				expect(ledger.move(id, to).outcome, to).to.equal('applied');
			}
			expect(ledger.move(id, 'PAYMENT_FAILED').outcome).to.equal('stale');
		});

		it('inserting an existing id is stale, never an overwrite', function () {
			const ledger = ledgerOn();
			const first = input();
			expect(ledger.insert(first).outcome).to.equal('applied');
			ledger.move(first.id, 'HELD');
			const again = ledger.insert({ ...first, onchainSat: '1' });
			expect(again.outcome).to.equal('stale');
			expect(again.record!.state).to.equal('HELD');
			expect(ledger.get(first.id)!.onchainSat).to.equal('100000');
		});
	});

	describe('patch and preimage', function () {
		it('patches bookkeeping in place and keeps the state', function () {
			const ledger = ledgerOn();
			const id = ledger.insert(input()).record!.id;
			const r = ledger.patch(id, { bolt11: 'lnbcrt1...', invoiceExpiresAt: 5 });
			expect(r.outcome).to.equal('applied');
			expect(r.record!.state).to.equal('CREATED');
			expect(ledger.get(id)!.bolt11).to.equal('lnbcrt1...');
		});

		it('records a preimage from any non-terminal state, write once, retained through terminal', function () {
			const ledger = ledgerOn();
			const id = ledger.insert(input()).record!.id;
			ledger.move(id, 'HELD');
			ledger.move(id, 'FUNDING');
			ledger.move(id, 'FUNDING_BROADCAST');
			ledger.move(id, 'EXPOSED');
			const pre = 'aa'.repeat(32);
			expect(ledger.recordPreimage(id, pre, 'onchain-claim').outcome).to.equal(
				'applied'
			);
			expect(ledger.get(id)!.preimageHex).to.equal(pre);
			expect(ledger.get(id)!.preimageSource).to.equal('onchain-claim');
			// A second source does not replace it.
			ledger.recordPreimage(id, 'bb'.repeat(32), 'peer');
			expect(ledger.get(id)!.preimageHex).to.equal(pre);
			// Neither a patch nor a move can remove it.
			ledger.patch(id, { preimageHex: undefined, preimageSource: undefined });
			expect(ledger.get(id)!.preimageHex).to.equal(pre);

			const other = ledger.insert(input()).record!.id;
			ledger.move(other, 'CANCELLED');
			expect(ledger.recordPreimage(other, pre, 'peer').outcome).to.equal(
				'stale'
			);
			expect(ledger.recordPreimage('nope', pre, 'peer').outcome).to.equal(
				'missing'
			);
		});
	});

	describe('queries and housekeeping', function () {
		it('indexes by payment hash and funding outpoint and summarises exposure', function () {
			const ledger = ledgerOn();
			const a = ledger.insert(input({ paymentHashHex: 'ab'.repeat(32) }))
				.record!;
			const b = ledger.insert(input()).record!;
			ledger.move(b.id, 'HELD');
			ledger.move(b.id, 'FUNDING');
			ledger.patch(b.id, { fundingTxid: 'ff'.repeat(32), fundingVout: 1 });
			expect(
				ledger.byPaymentHash('ab'.repeat(32)).map((r) => r.id)
			).to.deep.equal([a.id]);
			expect(ledger.byFundingOutpoint('ff'.repeat(32), 1)!.id).to.equal(b.id);
			expect(ledger.byFundingOutpoint('ff'.repeat(32), 0)).to.equal(undefined);
			expect(ledger.unresolved()).to.have.length(2);
			const summary = SwapLedger.exposure(ledger.list());
			expect(summary).to.deep.equal({
				count: 2,
				exposedCount: 1,
				exposedSat: 100_000n
			});
		});

		it('forgets only terminal rows', function () {
			const ledger = ledgerOn();
			const id = ledger.insert(input()).record!.id;
			expect(ledger.forget(id)).to.equal(false);
			ledger.move(id, 'FAILED');
			expect(ledger.forget(id)).to.equal(true);
			expect(ledger.get(id)).to.equal(undefined);
			expect(ledger.forget(id)).to.equal(false);
		});
	});

	describe('durability', function () {
		it('a storage failure leaves memory and disk unchanged', function () {
			const kv = new FakeKv();
			const store = new MetadataLedgerStore<ISwapRecord>(
				kv,
				SWAP_LEDGER_PREFIX,
				swapCodec
			);
			const ledger = ledgerOn(store);
			const id = ledger.insert(input()).record!.id;
			kv.failNext = true;
			expect(ledger.move(id, 'HELD').outcome).to.equal('storage_failed');
			expect(ledger.get(id)!.state).to.equal('CREATED');
			const reloaded = new SwapLedger(
				new MetadataLedgerStore<ISwapRecord>(kv, SWAP_LEDGER_PREFIX, swapCodec)
			);
			reloaded.rehydrate();
			expect(reloaded.get(id)!.state).to.equal('CREATED');
			expect(ledger.move(id, 'HELD').outcome).to.equal('applied');
		});

		it('rehydrates from SqliteStorage', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const ledger = ledgerOn(
				new MetadataLedgerStore<ISwapRecord>(
					storage,
					SWAP_LEDGER_PREFIX,
					swapCodec
				)
			);
			const id = ledger.insert(input()).record!.id;
			ledger.move(id, 'HELD');
			ledger.recordPreimage(id, 'cc'.repeat(32), 'lightning');
			const again = new SwapLedger(
				new MetadataLedgerStore<ISwapRecord>(
					storage,
					SWAP_LEDGER_PREFIX,
					swapCodec
				)
			);
			expect(again.move(id, 'FUNDING').outcome).to.equal('not_rehydrated');
			expect(again.rehydrate()).to.equal(1);
			expect(again.get(id)!.state).to.equal('HELD');
			expect(again.get(id)!.preimageHex).to.equal('cc'.repeat(32));
			storage.close();
		});

		it('the node builds and rehydrates its ledger when swaps are enabled', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const first = createNode('swap-ledger', 1, storage, {
				swaps: { enabled: true }
			});
			const ledger = first.getSwapLedger()!;
			expect(ledger.isRehydrated()).to.equal(true);
			const id = ledger.insert(input()).record!.id;
			const second = createNode('swap-ledger', 1, storage, {
				swaps: { enabled: true }
			});
			expect(second.getSwapLedger()!.get(id)!.state).to.equal('CREATED');
			expect(() => second.swapChain()).to.throw(/chain backend/i);
			const deriver = second.getSwapKeyDeriver();
			const swapId = Buffer.from(id, 'hex');
			expect(deriver(swapId, 'refund')).to.deep.equal(
				deriver(swapId, 'refund')
			);
			expect(deriver(swapId, 'refund')).to.not.deep.equal(
				deriver(swapId, 'claim')
			);
			const disabled = createNode('swap-ledger', 2);
			expect(disabled.getSwapLedger()).to.equal(undefined);
			storage.close();
		});
	});

	describe('keys', function () {
		it('derives deterministic, role-distinct, valid keys and a stable swap id', function () {
			const nodeKey = crypto.randomBytes(32);
			const peer = getPublicKey(crypto.randomBytes(32));
			const hash = crypto.randomBytes(32);
			const id = deriveSwapId(peer, hash);
			expect(id).to.have.length(16);
			expect(deriveSwapId(peer, hash)).to.deep.equal(id);
			expect(
				deriveSwapId(getPublicKey(crypto.randomBytes(32)), hash)
			).to.not.deep.equal(id);
			const refund = deriveSwapKey(nodeKey, id, 'refund');
			expect(refund).to.have.length(32);
			expect(deriveSwapKey(nodeKey, id, 'refund')).to.deep.equal(refund);
			expect(deriveSwapKey(nodeKey, id, 'claim')).to.not.deep.equal(refund);
			expect(
				deriveSwapKey(crypto.randomBytes(32), id, 'refund')
			).to.not.deep.equal(refund);
			// A stored public key checks against the derivation.
			expect(getPublicKey(refund)).to.have.length(33);
			expect(() => deriveSwapKey(nodeKey, Buffer.alloc(8), 'refund')).to.throw(
				/16 bytes/
			);
			expect(() => deriveSwapId(Buffer.alloc(32), hash)).to.throw(/33-byte/);
		});
	});
});
