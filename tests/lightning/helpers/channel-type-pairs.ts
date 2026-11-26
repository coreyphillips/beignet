/**
 * Channel pairs for the #2151 step 2a tests: an asset channel of the
 * recovery profile, and a plain final channel whose terms fit the asset type
 * (dust 354 on both sides, at most 83 accepted HTLCs), each on two original
 * SQLite devices.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { setupAssetSplicePeerTransport } from './asset-splice-peer-transport';
import {
	assetRounds,
	plainRounds,
	type ITypeDevice
} from './channel-type-record';
import type { FinalGeneration } from './final-generation';
import {
	fundReadyPair,
	generateSide,
	type IReadyPairTerms,
	type Side
} from './final-update-pair';

/** Terms that fit both types: dust 354 on both sides and at most 83 accepted HTLCs. */
export const FIT_TERMS: IReadyPairTerms = {
	remoteDustLimitSatoshis: 354,
	maxAcceptedHtlcs: 83
};

/** Temporary directories and stores, released after each test. */
export function scratch(prefix: string) {
	const dirs: string[] = [];
	const closers: (() => void)[] = [];
	return {
		dir(): string {
			const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
			dirs.push(d);
			return d;
		},
		closing(close: () => void): void {
			closers.push(close);
		},
		release(): void {
			for (const close of closers.splice(0).reverse())
				try {
					close();
				} catch {
					// Already closed by the test.
				}
			for (const d of dirs.splice(0))
				fs.rmSync(d, { recursive: true, force: true });
		}
	};
}
export type Scratch = ReturnType<typeof scratch>;

export interface IAssetTypePair {
	p: ReturnType<typeof setupAssetSplicePeerTransport>;
	id: string;
	devices: ITypeDevice[];
	files: string[];
	bindings: Side['binding'][];
	/** Close device i and open it again from its file. */
	restart(i: number): SqliteStorage;
}
/** A funded, ready asset channel of the recovery profile after `rounds` asset rounds. */
export async function assetTypePair(
	s: Scratch,
	rounds = 0,
	generation: 5 | 6 = 6
): Promise<IAssetTypePair> {
	const p = setupAssetSplicePeerTransport(s.dir(), undefined, generation);
	s.closing(() => p.close());
	const devices = p.f.devices.map((d) => ({
		store: d.store,
		root: d.party.root
	}));
	await assetRounds(devices, p.id, rounds);
	return {
		p,
		id: p.id,
		devices,
		files: p.f.devices.map((d) => d.file),
		bindings: p.f.devices.map((d) => d.party.binding),
		restart(i: number): SqliteStorage {
			const d = p.f.devices[i];
			d.store.close();
			d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
			devices[i].store = d.store;
			return d.store;
		}
	};
}

export interface IPlainTypePair {
	id: string;
	sides: Side[];
	stores: SqliteStorage[];
	devices: ITypeDevice[];
	files: string[];
	restart(i: number): SqliteStorage;
}
/** A funded, ready plain final channel after `rounds` plain rounds. */
export function plainTypePair(
	s: Scratch,
	rounds = 0,
	generation: FinalGeneration = 6,
	terms: IReadyPairTerms = FIT_TERMS
): IPlainTypePair {
	const dir = s.dir();
	const sides = [generateSide(generation), generateSide(generation)];
	const files = sides.map((_, i) => path.join(dir, 'w' + i));
	const stores = sides.map((side, i) =>
		SqliteStorage.createFinalWallet(files[i], side.binding)
	);
	s.closing(() => stores.forEach((st) => st.close()));
	const id = fundReadyPair(stores[0], stores[1], sides[0], sides[1], terms);
	const devices = stores.map((store, i) => ({ store, root: sides[i].root }));
	plainRounds(devices, id, rounds);
	return {
		id,
		sides,
		stores,
		devices,
		files,
		restart(i: number): SqliteStorage {
			stores[i].close();
			stores[i] = SqliteStorage.openFinalWallet(files[i], sides[i].binding);
			devices[i].store = stores[i];
			return stores[i];
		}
	};
}
