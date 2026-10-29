/**
 * Ranked receive primaries (issue #1922, step 1): the selection rule as a
 * table, and the store's validation and persistence.
 */

import { expect } from 'chai';
import {
	MAX_PRIMARIES,
	PRIMARIES_STORAGE_KEY,
	PrimariesError,
	PrimariesErrorCode,
	PrimariesStore,
	selectReceiveTargets
} from '../../src/lightning/liquidity/primaries';
import type { IPrimariesPolicy } from '../../src/lightning/liquidity/primaries';

const A = '02' + 'aa'.repeat(32);
const B = '03' + 'bb'.repeat(32);
const C = '02' + 'cc'.repeat(32);
const D = '03' + 'dd'.repeat(32);

function policy(
	keys: string[],
	fillThresholdSat: number | null
): IPrimariesPolicy {
	return { primaries: keys.map((pubkey) => ({ pubkey })), fillThresholdSat };
}

function order(
	keys: string[],
	threshold: number | null,
	balances: Record<string, number>
): string[] {
	return selectReceiveTargets(
		policy(keys, threshold),
		new Map(Object.entries(balances))
	).map((c) => c.pubkey);
}

function memoryStorage(): {
	data: Map<string, string>;
	saveWalletData(key: string, value: string): void;
	loadWalletData(key: string): string | null;
} {
	const data = new Map<string, string>();
	return {
		data,
		saveWalletData: (key, value): void => {
			data.set(key, value);
		},
		loadWalletData: (key): string | null => data.get(key) ?? null
	};
}

function codeOf(fn: () => unknown): string | undefined {
	try {
		fn();
	} catch (err) {
		expect(err).to.be.instanceOf(PrimariesError);
		return (err as PrimariesError).code;
	}
	return undefined;
}

describe('selectReceiveTargets (issue #1922)', () => {
	const T = 1_000_000;

	it('targets the first primary below the threshold', () => {
		expect(order([A, B], T, { [A]: 400_000 })).to.deep.equal([A, B]);
	});

	it('moves to the next primary, channel or not, once the first is full', () => {
		const ranked = selectReceiveTargets(
			policy([A, B], T),
			new Map([[A, 1_000_000]])
		);
		expect(ranked.map((c) => c.pubkey)).to.deep.equal([B, A]);
		expect(ranked[0]).to.deep.equal({
			pubkey: B,
			rank: 2,
			balanceSat: 0,
			belowThreshold: true
		});
		expect(ranked[1].belowThreshold).to.equal(false);
	});

	it('levels the full ones: lowest balance first, ties to the higher rank', () => {
		const balances = { [A]: 2_000_000, [B]: 1_000_000, [C]: 1_000_000 };
		expect(order([A, B, C], T, balances)).to.deep.equal([B, C, A]);
		// Once B pulls ahead, C is next.
		expect(order([A, B, C], T, { ...balances, [B]: 1_000_001 })).to.deep.equal([
			C,
			B,
			A
		]);
	});

	it('treats exactly the threshold as full and one sat under as not', () => {
		expect(order([A, B], T, { [A]: T, [B]: T })).to.deep.equal([A, B]);
		expect(order([A, B], T, { [A]: T, [B]: T - 1 })).to.deep.equal([B, A]);
		expect(order([A, B], T, { [A]: T - 1, [B]: 0 })).to.deep.equal([A, B]);
	});

	it('keeps rank order among the primaries still below the threshold', () => {
		expect(
			order([A, B, C, D], T, { [A]: T, [B]: 900_000, [C]: 0, [D]: 5 })
		).to.deep.equal([B, C, D, A]);
	});

	it('follows rank alone with no cap', () => {
		expect(order([B, A], null, { [A]: 0, [B]: 50_000_000 })).to.deep.equal([
			B,
			A
		]);
	});

	it('levels everything with a zero threshold', () => {
		expect(order([A, B, C], 0, { [A]: 10, [C]: 10 })).to.deep.equal([B, A, C]);
	});

	it('answers an empty list with no candidates', () => {
		expect(order([], T, { [A]: 5 })).to.deep.equal([]);
	});

	it('ignores balances with peers that are not primaries', () => {
		expect(order([A], T, { [B]: 5_000_000 })).to.deep.equal([A]);
	});
});

describe('PrimariesStore (issue #1922)', () => {
	it('adds, ranks, reorders and removes, persisting each change', () => {
		const storage = memoryStorage();
		const store = new PrimariesStore({ storage });
		store.add({ pubkey: A, host: '10.0.0.1', port: 9735 });
		store.add({ pubkey: C });
		store.add({ pubkey: B.toUpperCase() }, 1);
		expect(store.get().primaries.map((p) => p.pubkey)).to.deep.equal([B, A, C]);

		store.reorder([C, A, B]);
		store.setFillThreshold(250_000);
		store.remove(A);
		expect(store.get()).to.deep.equal({
			primaries: [{ pubkey: C }, { pubkey: B }],
			fillThresholdSat: 250_000
		});

		const reloaded = new PrimariesStore({ storage });
		expect(reloaded.restore()).to.equal(2);
		expect(reloaded.get()).to.deep.equal(store.get());
	});

	it('accepts a peer URI, iroh included, for the same node', () => {
		const store = new PrimariesStore({});
		store.add({ pubkey: A, uri: `${A}@ws://lsp.example:9736` });
		store.add({ pubkey: B, uri: `${B}@iroh:${'ef'.repeat(32)}` });
		expect(store.get().primaries.map((p) => p.uri)).to.deep.equal([
			`${A}@ws://lsp.example:9736`,
			`${B}@iroh:${'ef'.repeat(32)}`
		]);
	});

	it('refuses malformed entries', () => {
		const store = new PrimariesStore({});
		const bad: unknown[] = [
			null,
			'02aa',
			{ pubkey: '04' + 'aa'.repeat(32) },
			{ pubkey: A.slice(0, 64) },
			{ pubkey: A, host: 'h', port: 0 },
			{ pubkey: A, host: 'h', port: 65536 },
			{ pubkey: A, host: 'h', port: 9735.5 },
			{ pubkey: A, host: 'h', port: '9735' },
			{ pubkey: A, host: 'h' },
			{ pubkey: A, port: 9735 },
			{ pubkey: A, host: '', port: 9735 },
			{ pubkey: A, uri: 'not-a-uri' },
			{ pubkey: A, uri: `${B}@10.0.0.1:9735` }
		];
		for (const entry of bad) {
			expect(
				codeOf(() => store.add(entry)),
				JSON.stringify(entry)
			).to.equal(PrimariesErrorCode.INVALID_PRIMARY);
		}
		expect(store.get().primaries).to.deep.equal([]);
	});

	it('refuses a duplicate, case-insensitively', () => {
		const store = new PrimariesStore({});
		store.add({ pubkey: A });
		expect(codeOf(() => store.add({ pubkey: A.toUpperCase() }))).to.equal(
			PrimariesErrorCode.DUPLICATE_PRIMARY
		);
	});

	it('refuses a rank out of range and a list past the cap', () => {
		const store = new PrimariesStore({});
		expect(codeOf(() => store.add({ pubkey: A }, 0))).to.equal(
			PrimariesErrorCode.INVALID_PRIMARY
		);
		expect(codeOf(() => store.add({ pubkey: A }, 2))).to.equal(
			PrimariesErrorCode.INVALID_PRIMARY
		);
		for (let i = 0; i < MAX_PRIMARIES; i++) {
			store.add({ pubkey: '02' + i.toString(16).padStart(64, '0') });
		}
		expect(codeOf(() => store.add({ pubkey: A }))).to.equal(
			PrimariesErrorCode.TOO_MANY_PRIMARIES
		);
	});

	it('refuses a reorder that adds, drops or repeats a primary', () => {
		const store = new PrimariesStore({});
		store.add({ pubkey: A });
		store.add({ pubkey: B });
		for (const bad of [[A], [A, B, C], [A, A], [A, C], 'A,B', [A, 5]]) {
			expect(
				codeOf(() => store.reorder(bad)),
				JSON.stringify(bad)
			).to.equal(PrimariesErrorCode.INVALID_ORDER);
		}
		expect(store.get().primaries.map((p) => p.pubkey)).to.deep.equal([A, B]);
	});

	it('refuses removing a primary it does not hold', () => {
		const store = new PrimariesStore({});
		expect(codeOf(() => store.remove(A))).to.equal(
			PrimariesErrorCode.UNKNOWN_PRIMARY
		);
	});

	it('takes a non-negative integer threshold or null', () => {
		const store = new PrimariesStore({});
		for (const bad of [-1, 1.5, NaN, Infinity, '1000', 2 ** 53, undefined]) {
			expect(
				codeOf(() => store.setFillThreshold(bad)),
				String(bad)
			).to.equal(PrimariesErrorCode.INVALID_THRESHOLD);
		}
		expect(store.setFillThreshold(0).fillThresholdSat).to.equal(0);
		expect(store.setFillThreshold(null).fillThresholdSat).to.equal(null);
	});

	it('leaves the list unchanged when the write fails', () => {
		const store = new PrimariesStore({
			storage: {
				saveWalletData: (): void => {
					throw new Error('disk full');
				},
				loadWalletData: (): null => null
			}
		});
		expect(codeOf(() => store.add({ pubkey: A }))).to.equal(
			PrimariesErrorCode.PERSIST_FAILED
		);
		expect(store.get().primaries).to.deep.equal([]);
	});

	it('restores what it can from damaged storage', () => {
		const storage = memoryStorage();
		storage.data.set(PRIMARIES_STORAGE_KEY, '{not json');
		expect(new PrimariesStore({ storage }).restore()).to.equal(0);

		storage.data.set(
			PRIMARIES_STORAGE_KEY,
			JSON.stringify({
				primaries: [
					{ pubkey: A },
					{ pubkey: 'junk' },
					{ pubkey: A },
					{ pubkey: B }
				],
				fillThresholdSat: -5
			})
		);
		const store = new PrimariesStore({ storage });
		expect(store.restore()).to.equal(2);
		expect(store.get()).to.deep.equal({
			primaries: [{ pubkey: A }, { pubkey: B }],
			fillThresholdSat: null
		});
	});
});
