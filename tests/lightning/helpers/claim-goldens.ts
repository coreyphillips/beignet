/**
 * Claim lists of channels with no channel-type record and no conversion
 * exit, built from fixed wallet seeds so their bytes repeat run to run. The
 * #2151 step 2b goldens (tests/lightning/fixtures/asset-conversion-claim-goldens.json)
 * were captured from this module on the step's base; the test compares the
 * same lists byte for byte.
 */
import { entropyToMnemonic } from 'bip39';
import { Transaction } from 'bitcoinjs-lib';
import { assetOpeningOutputClaims } from '../../../src/lightning/chain/asset-opening-claims';
import {
	finalChannelOutputClaims,
	finalOpeningOutputClaims,
	type IFinalOutputClaim
} from '../../../src/lightning/chain/final-output-claims';
import { sha256 } from '../../../src/lightning/crypto/provider';
import type { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import {
	assetTypePair,
	plainTypePair,
	type Scratch
} from './channel-type-pairs';
import {
	assetRounds,
	claimBytes,
	plainRounds,
	type ChannelKind,
	type ITypeDevice
} from './channel-type-record';

export const GOLDEN_DESTINATION = Buffer.from('0014' + 'cd'.repeat(20), 'hex');

/**
 * Run `fixture` with each newly generated wallet mnemonic taken from a fixed
 * sequence under `label`, so its keys, channel IDs and commitments repeat.
 */
export async function withFixedMnemonics<T>(
	label: string,
	fixture: () => Promise<T>
): Promise<T> {
	const bip39 = require('bip39') as { generateMnemonic: () => string };
	const original = bip39.generateMnemonic;
	let n = 0;
	bip39.generateMnemonic = (): string =>
		entropyToMnemonic(
			sha256(Buffer.from('beignet/claim-golden/' + label + '/' + n++))
				.subarray(0, 16)
				.toString('hex')
		);
	try {
		return await fixture();
	} finally {
		bip39.generateMnemonic = original;
	}
}

export interface IGoldenChannel {
	kind: ChannelKind;
	generation: 2 | 4 | 5 | 6;
}
export const GOLDEN_CHANNELS: Record<string, IGoldenChannel> = {
	'generation 6 plain': { kind: 'plain', generation: 6 },
	'generation 6 asset': { kind: 'asset', generation: 6 },
	'generation 5 asset': { kind: 'asset', generation: 5 },
	'generation 4 asset': { kind: 'asset', generation: 4 },
	'generation 2 plain': { kind: 'plain', generation: 2 }
};

/** The commitments a golden channel is claimed from, by device 0. */
export interface IGoldenFixture {
	id: string;
	devices: ITypeDevice[];
	kind: ChannelKind;
	parents: Record<'ours' | 'peer current' | 'peer revoked', Transaction>;
}
/**
 * A channel after one round: our current commitment, the peer's current one,
 * and the peer's commitment at height 0, which that round revoked.
 */
export async function goldenFixture(
	s: Scratch,
	name: string
): Promise<IGoldenFixture> {
	const { kind, generation } = GOLDEN_CHANNELS[name];
	return withFixedMnemonics(name, async () => {
		const exit = (store: SqliteStorage, id: string): Transaction =>
			Transaction.fromBuffer(store.loadFinalFundingExits(id)[0].exit);
		if (kind === 'plain') {
			const pair = plainTypePair(s, 0, generation);
			const revoked = exit(pair.stores[1], pair.id);
			plainRounds(pair.devices, pair.id, 1);
			return {
				id: pair.id,
				devices: pair.devices,
				kind,
				parents: {
					ours: exit(pair.stores[0], pair.id),
					'peer current': exit(pair.stores[1], pair.id),
					'peer revoked': revoked
				}
			};
		}
		const pair = await assetTypePair(s, 0, generation as 4 | 5 | 6);
		const revoked = exit(pair.devices[1].store, pair.id);
		await assetRounds(pair.devices, pair.id, 1);
		return {
			id: pair.id,
			devices: pair.devices,
			kind,
			parents: {
				ours: exit(pair.devices[0].store, pair.id),
				'peer current': exit(pair.devices[1].store, pair.id),
				'peer revoked': revoked
			}
		};
	});
}

/** Device 0's claims of each parent, from the dispatcher and from the kind's own builder. */
export function goldenClaims(f: IGoldenFixture): Record<string, unknown> {
	const { store, root } = f.devices[0];
	const runtime = { storage: store, root };
	const key = Buffer.from(f.id, 'hex');
	const out: Record<string, unknown> = {};
	for (const [name, parent] of Object.entries(f.parents)) {
		const direct: IFinalOutputClaim[] =
			f.kind === 'plain'
				? finalOpeningOutputClaims(runtime, key, parent, GOLDEN_DESTINATION, 1)
				: assetOpeningOutputClaims(runtime, key, parent, GOLDEN_DESTINATION, 1);
		const dispatched = finalChannelOutputClaims(
			runtime,
			key,
			parent,
			GOLDEN_DESTINATION,
			1,
			undefined,
			undefined,
			(cid) => store.loadFinalChannelKind(cid)
		);
		out[name] = {
			parent: parent.getId(),
			direct: claimBytes(direct),
			dispatched: claimBytes(dispatched)
		};
	}
	return out;
}
