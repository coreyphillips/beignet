/**
 * #2151 step 2a: a channel of a generation 6 wallet runs by its recorded
 * type. These tests pin the `channel-type` record's writer
 * (SqliteStorage.appendFinalChannelType), its reader
 * (loadFinalChannelTypeRecords), the current type (loadFinalChannelType)
 * and its memo, restore and backup, and the builders and signer by type.
 *
 * The step's names are reached through helpers/channel-type-record.ts, so
 * this file loads on a base without them. Where the step leaves a name or
 * a signature open, this file assumes, in one place each:
 * - the type-aware builders take a trailing `as` argument,
 *   `{ channelType, openingRoot? }`, after their last current argument
 *   (buildAs below);
 * - signFinalUpdate takes the type of the commitment being signed as a
 *   trailing argument after `spliceFunding` (signAs below).
 */
import { expect } from 'chai';
import Database from 'better-sqlite3';
import { payments, Transaction } from 'bitcoinjs-lib';
import path from 'path';
import sinon from 'sinon';
import { BeignetNode } from '../../src/cli/beignet-node';
import { deriveBackupMacKey, writeBackupMac } from '../../src/cli/backup-mac';
import { performAssetChannelRestore } from '../../src/cli/restore';
import {
	buildAssetSpliceCommitment,
	buildFinalCommitmentView,
	type IFinalCommitmentView
} from '../../src/lightning/channel/final-opening-commitment';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { deriveChannelKeys } from '../../src/lightning/keys/wallet-keys';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { encodeUpdateFeeMessage } from '../../src/lightning/message/channel-update';
import { MessageType as M } from '../../src/lightning/message/types';
import * as candidates from '../../src/lightning/storage/final-opening-candidate';
import {
	signFinalUpdate,
	spliceCommitmentNonceContext,
	updateVerificationNonce
} from '../../src/lightning/storage/final-update-signing';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';
import {
	assetTypePair,
	FIT_TERMS,
	plainTypePair,
	rootOf,
	scratch,
	type IAssetTypePair,
	type IPlainTypePair
} from './helpers/channel-type-pairs';
import {
	appendBoth,
	assetRounds,
	ASSET_TYPE_HEX,
	assetTwin,
	buildConversion,
	copyInput,
	deviceAuthority,
	expectRefusal,
	type IChannelTypeRecordInput,
	type IConversion,
	type IFinalAssetSeedInput,
	type IFinalPlainSeedInput,
	LEAVES,
	localPointsOf,
	openingParent,
	PLAIN_TYPE_HEX,
	plainTwin,
	step2a,
	TEXT,
	TWIN_ROOT,
	typed
} from './helpers/channel-type-record';
import { finalTestNode } from './helpers/asset-conversion-node';
import { generateFinalGeneration } from './helpers/final-generation';
import { signingFixture } from './helpers/final-opening-signing';
import { plainUpdates, plainWire } from './helpers/final-plain-wire';

const unknown = '77'.repeat(32);
const feeUpdate = (id: string): Buffer =>
	encodeUpdateFeeMessage({
		channelId: Buffer.from(id, 'hex'),
		feeratePerKw: 301
	});

/** The type-aware builders, with the assumed trailing `as` argument. */
function buildAs(
	kind: 'plain' | 'asset',
	args: unknown[],
	as: { channelType: string; openingRoot?: Buffer }
): IFinalCommitmentView {
	const build = (kind === 'plain'
		? buildFinalCommitmentView
		: buildAssetSpliceCommitment) as unknown as (
		...a: unknown[]
	) => ReturnType<typeof buildFinalCommitmentView>;
	return build(...args, as);
}
/** signFinalUpdate with the assumed trailing type argument. */
function signAs(
	args: Parameters<typeof signFinalUpdate>,
	channelType: string
): Buffer {
	return (signFinalUpdate as unknown as (...a: unknown[]) => Buffer)(
		...args,
		channelType
	);
}

function db(store: SqliteStorage): Database.Database {
	return (store as unknown as { db: Database.Database }).db;
}
function typeRows(store: SqliteStorage, id: string): unknown[] {
	return db(store)
		.prepare(
			"SELECT sequence, record FROM final_lifecycle_log WHERE scope='channel-type' AND channel_id=? ORDER BY sequence"
		)
		.all(id);
}
const txidOf = (hex: string): string => Transaction.fromHex(hex).getId();
/** The output the channel lives on, as loadFinalChannelType names it. */
const fundingOf = (c: IConversion): { txid: string; outputIndex: number } => ({
	txid: c.tx.getId(),
	outputIndex: 0
});
const parentOf = (c: IConversion): { tx: Transaction; index: number } => ({
	tx: c.tx,
	index: 0
});

/** The peer's per-commitment secret for height h, from its device root. */
function peerSecret(
	pair: {
		devices: { store: SqliteStorage; root: import('bip32').BIP32Interface }[];
	},
	id: string,
	peer: number,
	h: number
): Buffer {
	const index =
		pair.devices[peer].store.loadFinalOpeningSession(id)!.channelKeyIndex;
	const seed = deriveChannelKeys(
		pair.devices[peer].root,
		1,
		index
	).perCommitmentSeed;
	return generateFromSeed(seed, MAX_INDEX - BigInt(h));
}
/** The BOLT 3 buckets of secrets for heights 0 to n - 1, as rememberRevocation stores them. */
function buckets(
	secret: (h: number) => Buffer,
	n: number
): ({ height: number; secret: string } | null)[] {
	const out: ({ height: number; secret: string } | null)[] = [];
	for (let h = 0; h < n; h++) {
		const index = MAX_INDEX - BigInt(h);
		let bits = 0;
		while (bits < 48 && ((index >> BigInt(bits)) & 1n) === 0n) bits++;
		while (out.length < bits) out.push(null);
		out[bits] = { height: h, secret: secret(h).toString('hex') };
	}
	return out;
}

describe('Channel type record writer gates (#2151 step 2a, item 1)', function () {
	this.timeout(240000);
	const s = scratch('channel-type-writer-');
	afterEach(() => s.release());

	async function toPlain(
		rounds = 0,
		generation: 5 | 6 = 6
	): Promise<{ pair: IAssetTypePair; c: IConversion }> {
		const pair = await assetTypePair(s, rounds, generation);
		const c = buildConversion(pair.devices, pair.id, {
			type: 'plain',
			stateNumber: rounds,
			parent: openingParent(pair.devices[0].store, pair.id)
		});
		return { pair, c };
	}
	function toAsset(pair: IPlainTypePair, n = 0, extra = {}): IConversion {
		return buildConversion(pair.devices, pair.id, {
			type: 'asset',
			stateNumber: n,
			parent: openingParent(pair.stores[0], pair.id),
			...extra
		});
	}
	/** A refusal with its own text, by the device's root, storing nothing. */
	const refusesNothingStored = (
		store: SqliteStorage,
		id: string,
		input: IChannelTypeRecordInput,
		text: string
	): Error => {
		const e = expectRefusal(
			() => typed(store).appendFinalChannelType(id, input, rootOf(store)),
			text
		);
		expect(typed(store).loadFinalChannelTypeRecords(id)).to.deep.equal([]);
		return e;
	};

	it('accepts a valid record in each direction and stores it with its computed shachain', async () => {
		const { pair, c } = await toPlain(0);
		appendBoth(pair.devices, c);
		for (const [i, d] of pair.devices.entries()) {
			const [record] = typed(d.store).loadFinalChannelTypeRecords(pair.id);
			expect(record).to.deep.equal({
				...c.inputs[i],
				seed: {
					...c.inputs[i].seed,
					localPoints: localPointsOf(c, i),
					shachain: []
				}
			});
		}
		const plain = plainTypePair(s, 0);
		const a = toAsset(plain);
		appendBoth(plain.devices, a);
		for (const [i, d] of plain.devices.entries())
			expect(
				typed(d.store).loadFinalChannelTypeRecords(plain.id)
			).to.deep.equal([
				{
					...a.inputs[i],
					seed: {
						...a.inputs[i].seed,
						localPoints: localPointsOf(a, i),
						shachain: []
					}
				}
			]);
	});

	it('refuses every generation 1 to 5 wallet and a generation 6 copy first (rule 1)', async () => {
		const { pair, c } = await toPlain(0);
		for (const g of [1, 2, 3, 4, 5] as const) {
			const fresh = generateFinalGeneration(g);
			const store = SqliteStorage.createFinalWallet(
				path.join(s.dir(), 'g' + g),
				fresh.binding
			);
			s.closing(() => store.close());
			// Before the unknown channel and the canonical form are checked.
			expectRefusal(
				() =>
					typed(store).appendFinalChannelType(unknown, {
						bogus: true
					} as unknown as IChannelTypeRecordInput),
				TEXT.original
			);
			expect(typed(store).loadFinalChannelTypeRecords(unknown)).to.deep.equal(
				[]
			);
		}
		const g5 = await toPlain(0, 5);
		refusesNothingStored(
			g5.pair.devices[0].store,
			g5.pair.id,
			g5.c.inputs[0],
			TEXT.original
		);
		const g2 = plainTypePair(s, 0, 2);
		const g2c = toAsset(g2);
		refusesNothingStored(g2.stores[0], g2.id, g2c.inputs[0], TEXT.original);
		const copy = path.join(s.dir(), 'copy.db');
		await pair.devices[0].store.backup(copy);
		const backup = SqliteStorage.openFinalWallet(copy, pair.bindings[0]);
		s.closing(() => backup.close());
		expect(backup.canConvertAssetChannels).to.equal(false);
		refusesNothingStored(backup, pair.id, c.inputs[0], TEXT.original);
		expectRefusal(
			() =>
				typed(backup).appendFinalChannelType(pair.id, {
					...c.inputs[0],
					stateNumber: '01'
				}),
			TEXT.original
		);
	});

	it('refuses inside a transaction (rule 2)', async () => {
		const { pair, c } = await toPlain(0);
		const store = pair.devices[0].store;
		expectRefusal(
			() =>
				db(store).transaction(() =>
					typed(store).appendFinalChannelType(
						pair.id,
						c.inputs[0],
						rootOf(store)
					)
				)(),
			'Channel type records require a top-level commit'
		);
		expect(typed(store).loadFinalChannelTypeRecords(pair.id)).to.deep.equal([]);
	});

	it('refuses an unknown channel and one without a funded ready session (rule 3)', async () => {
		const { pair, c } = await toPlain(0);
		const store = pair.devices[0].store;
		refusesNothingStored(
			store,
			unknown,
			{ ...c.inputs[0] },
			'Channel type record requires a funded ready channel'
		);
		const unfunded = setupAssetSpliceProofs(s.dir(), undefined, 6);
		s.closing(() => unfunded.devices.forEach((d) => d.store.close()));
		expectRefusal(
			() =>
				typed(unfunded.devices[0].store).appendFinalChannelType(
					unfunded.id,
					c.inputs[0],
					pair.devices[0].root
				),
			'Channel type record requires a funded ready channel'
		);
	});

	it('refuses a record that is not in canonical form (rule 4), before the type is compared', async () => {
		const { pair, c } = await toPlain(0);
		const store = pair.devices[0].store;
		const base = c.inputs[0];
		const variants: Record<string, IChannelTypeRecordInput> = {
			'an extra field': { ...base, extra: 1 } as IChannelTypeRecordInput,
			'an extra seed field': {
				...base,
				seed: { ...base.seed, extra: 1 }
			} as unknown as IChannelTypeRecordInput,
			'a seed shachain supplied by the caller': {
				...base,
				seed: { ...base.seed, shachain: [] }
			} as unknown as IChannelTypeRecordInput,
			'seed local points supplied by the caller': {
				...base,
				seed: { ...base.seed, localPoints: localPointsOf(c, 0) }
			} as unknown as IChannelTypeRecordInput,
			'another kind': { ...base, kind: 'asset-splice' } as never,
			'an unknown type': { ...base, type: 'bitcoin' } as never,
			'a state number with a leading zero': { ...base, stateNumber: '00' },
			'a negative state number': { ...base, stateNumber: '-1' },
			'a state number of MAX_INDEX - 1': {
				...base,
				stateNumber: String(MAX_INDEX - 1n)
			},
			'a plain record with the asset hex': {
				...base,
				channelType: ASSET_TYPE_HEX
			},
			'a plain record with an alias bit its asset parent lacks': {
				...base,
				channelType: '0100000000400000000000'
			},
			'a negative parent index': {
				...base,
				parent: { ...base.parent, outputIndex: -1 }
			},
			'a fractional key index': {
				...base,
				funding: { ...base.funding, localFundingKeyIndex: 1.5 }
			},
			// The same type and malformed: the canonical form is checked first.
			'the same type with an extra field': {
				...base,
				type: 'asset',
				channelType: ASSET_TYPE_HEX,
				extra: 1
			} as IChannelTypeRecordInput
		};
		for (const [name, input] of Object.entries(variants)) {
			const e = expectRefusal(
				() =>
					typed(store).appendFinalChannelType(pair.id, input, rootOf(store)),
				'Invalid channel type record'
			);
			expect(e.message, name).to.not.equal(TEXT.sameType);
			expect(e.message, name).to.not.equal(TEXT.state);
		}
		expect(typed(store).loadFinalChannelTypeRecords(pair.id)).to.deep.equal([]);
	});

	it('refuses a record of the current type (rule 5), before the state number', async () => {
		const pair = await assetTypePair(s, 1);
		const same = buildConversion(pair.devices, pair.id, {
			type: 'asset',
			stateNumber: 1,
			parent: openingParent(pair.devices[0].store, pair.id)
		});
		refusesNothingStored(
			pair.devices[0].store,
			pair.id,
			same.inputs[0],
			TEXT.sameType
		);
		refusesNothingStored(
			pair.devices[0].store,
			pair.id,
			{ ...same.inputs[0], stateNumber: '7' },
			TEXT.sameType
		);
		const plain = plainTypePair(s, 0);
		const plainSame = buildConversion(plain.devices, plain.id, {
			type: 'plain',
			stateNumber: 0,
			parent: openingParent(plain.stores[0], plain.id)
		});
		refusesNothingStored(
			plain.stores[0],
			plain.id,
			plainSame.inputs[0],
			TEXT.sameType
		);
	});

	it('refuses a parent that is not the live funding (rule 6)', async () => {
		const { pair, c } = await toPlain(0);
		const store = pair.devices[0].store;
		const wrong = copyInput(c.inputs[0]);
		wrong.parent.txid = 'ab'.repeat(32);
		refusesNothingStored(
			store,
			pair.id,
			wrong,
			'Channel type record parent is not the live funding'
		);
		const index = copyInput(c.inputs[0]);
		index.parent.outputIndex += 1;
		refusesNothingStored(
			store,
			pair.id,
			index,
			'Channel type record parent is not the live funding'
		);
		// After an adopted asset splice, the opening is no longer the live funding.
		const spliced = await assetTypePair(s, 0);
		await spliced.p.start();
		await spliced.p.drain();
		await spliced.p.adopt();
		const stale = buildConversion(spliced.devices, spliced.id, {
			type: 'plain',
			stateNumber: 0,
			parent: openingParent(spliced.devices[0].store, spliced.id)
		});
		refusesNothingStored(
			spliced.devices[0].store,
			spliced.id,
			stale.inputs[0],
			'Channel type record parent is not the live funding'
		);
	});

	it('refuses a funding that does not spend the parent or reuses an earlier funding (rule 7)', async () => {
		const { pair, c } = await toPlain(0);
		const store = pair.devices[0].store;
		const elsewhere = copyInput(c.inputs[0]);
		const tx = Transaction.fromHex(elsewhere.funding.fundingTxHex);
		tx.ins[0].hash = Buffer.alloc(32, 9);
		elsewhere.funding.fundingTxHex = tx.toHex();
		refusesNothingStored(
			store,
			pair.id,
			elsewhere,
			'Channel type record funding must spend its parent and be new'
		);
		const opening = store.loadFinalDaemonOpening(pair.id)!;
		const reused = copyInput(c.inputs[0]);
		reused.funding = {
			fundingTxHex: opening.candidate.fundingTxHex,
			fundingOutputIndex: opening.candidate.fundingOutputIndex,
			localFundingPubkey: opening.candidate.localFundingPubkey,
			remoteFundingPubkey: opening.candidate.remoteFundingPubkey,
			localFundingKeyIndex: opening.session.channelKeyIndex
		};
		refusesNothingStored(
			store,
			pair.id,
			reused,
			'Channel type record funding must spend its parent and be new'
		);
	});

	it('refuses a plain ledger that is not quiescent at one height (rule 8)', () => {
		// Heights that differ: the opener's update is signed one way only.
		const differ = plainTypePair(s, 0);
		plainUpdates(differ.stores, differ.sides, differ.id).stage(
			0,
			M.UPDATE_FEE,
			feeUpdate(differ.id)
		);
		const sig = differ.stores[0].signFinalUpdateCommitment(
			differ.id,
			differ.sides[0].root
		);
		const ack = differ.stores[1].acceptFinalUpdateCommitment(
			differ.id,
			differ.sides[1].root,
			sig
		);
		differ.stores[0].acceptFinalUpdateRevocation(differ.id, ack);
		const status = differ.stores[1].loadFinalUpdateStatus(differ.id)!;
		expect(status.localHeight).to.not.equal(status.remoteHeight);
		const differInput = toAsset(differ, 0);
		for (const i of [0, 1])
			refusesNothingStored(
				differ.stores[i],
				differ.id,
				differInput.inputs[i],
				'Channel type record requires a quiescent channel'
			);

		// A staged update waiting to be signed.
		const waiting = plainTypePair(s, 0);
		plainUpdates(waiting.stores, waiting.sides, waiting.id).stage(
			0,
			M.UPDATE_FEE,
			feeUpdate(waiting.id)
		);
		const waitingInput = toAsset(waiting, 0);
		refusesNothingStored(
			waiting.stores[0],
			waiting.id,
			waitingInput.inputs[0],
			'Channel type record requires a quiescent channel'
		);

		// A commitment signed and not yet revoked by the peer.
		const inFlight = plainTypePair(s, 0);
		plainUpdates(inFlight.stores, inFlight.sides, inFlight.id).stage(
			0,
			M.UPDATE_FEE,
			feeUpdate(inFlight.id)
		);
		inFlight.stores[0].signFinalUpdateCommitment(
			inFlight.id,
			inFlight.sides[0].root
		);
		const inFlightInput = toAsset(inFlight, 0);
		refusesNothingStored(
			inFlight.stores[0],
			inFlight.id,
			inFlightInput.inputs[0],
			'Channel type record requires a quiescent channel'
		);

		// A locked-in HTLC: offered on side 0, received on side 1.
		const htlc = plainTypePair(s, 0);
		plainUpdates(htlc.stores, htlc.sides, htlc.id).add();
		const htlcInput = toAsset(htlc, 1);
		for (const i of [0, 1])
			refusesNothingStored(
				htlc.stores[i],
				htlc.id,
				htlcInput.inputs[i],
				'Channel type record requires a quiescent channel'
			);
	});

	it('refuses an asset ledger with an intent (rule 8)', async () => {
		const pair = await assetTypePair(s, 0);
		const { store, root } = pair.devices[0];
		store
			.assetSpliceUpdateBatch(
				pair.id,
				root,
				1n,
				[{ kind: 'fee', feeratePerKw: 1200 }],
				() => 600000
			)
			.offer();
		const c = buildConversion(pair.devices, pair.id, {
			type: 'plain',
			stateNumber: 0,
			parent: openingParent(store, pair.id)
		});
		refusesNothingStored(
			store,
			pair.id,
			c.inputs[0],
			'Channel type record requires a quiescent channel'
		);
	});

	it('refuses a pending splice of either kind (rule 9)', async () => {
		const plain = plainTypePair(s, 0);
		const wire = plainWire(plain.stores, plain.sides, plain.id);
		await wire.spliceOut();
		wire.destroy();
		const plainInput = toAsset(plain, 0);
		refusesNothingStored(
			plain.stores[0],
			plain.id,
			plainInput.inputs[0],
			'Channel type record requires no pending splice attempt'
		);
		const asset = await assetTypePair(s, 0);
		await asset.p.start();
		await asset.p.drain();
		expect(
			asset.devices[0].store.loadAssetSpliceFundingInfo(asset.id).pending
		).to.have.length(1);
		const assetInput = buildConversion(asset.devices, asset.id, {
			type: 'plain',
			stateNumber: 0,
			parent: openingParent(asset.devices[0].store, asset.id)
		});
		refusesNothingStored(
			asset.devices[0].store,
			asset.id,
			assetInput.inputs[0],
			'Channel type record requires no pending splice attempt'
		);
	});

	it('refuses an exit request and a started simple close (rule 10)', () => {
		const exit = plainTypePair(s, 0);
		const exitInput = toAsset(exit, 0);
		exit.stores[0].requestFinalOpeningExit(exit.id);
		refusesNothingStored(
			exit.stores[0],
			exit.id,
			exitInput.inputs[0],
			'Channel type record requires an open channel'
		);
		const close = plainTypePair(s, 0);
		const closeInput = toAsset(close, 0);
		close.stores[0].finalSimpleCloseStep(close.id, close.sides[0].root, {
			start: true,
			script: payments.p2wpkh({
				pubkey: close.sides[0].keys.channelBasepoints.paymentBasepoint
			}).output!,
			blockHeight: 200,
			feeratePerKw: 1000
		});
		refusesNothingStored(
			close.stores[0],
			close.id,
			closeInput.inputs[0],
			'Channel type record requires an open channel'
		);
	});

	it('refuses a state number that is not the current height (rule 11), before the seed is verified', async () => {
		const { pair, c } = await toPlain(1);
		const store = pair.devices[0].store;
		for (const n of ['0', '2'])
			refusesNothingStored(
				store,
				pair.id,
				{ ...c.inputs[0], stateNumber: n },
				TEXT.state
			);
		const badSeed = copyInput(c.inputs[0]);
		(badSeed.seed as IFinalPlainSeedInput).nextLocalId = '5';
		refusesNothingStored(
			store,
			pair.id,
			{ ...badSeed, stateNumber: '2' },
			TEXT.state
		);
	});

	it('refuses opening terms that do not fit the asset type (rule 12)', () => {
		const dust = plainTypePair(s, 0, 6, {});
		expect(
			dust.stores[0].loadFinalOpeningSession(dust.id)!.terms
				.remoteDustLimitSatoshis
		).to.equal(1000);
		const dustInput = toAsset(dust, 0);
		refusesNothingStored(
			dust.stores[0],
			dust.id,
			dustInput.inputs[0],
			'Channel opening terms do not fit the new type'
		);
		const htlcs = plainTypePair(s, 0, 6, {
			...FIT_TERMS,
			maxAcceptedHtlcs: 84
		});
		const htlcInput = toAsset(htlcs, 0);
		refusesNothingStored(
			htlcs.stores[0],
			htlcs.id,
			htlcInput.inputs[0],
			'Channel opening terms do not fit the new type'
		);
	});

	describe('a seed that does not verify (rule 13)', () => {
		type Mutation = (
			seed: never,
			c: IConversion,
			i: number,
			input: IChannelTypeRecordInput,
			isInitiator: boolean
		) => void;
		const dropRevocations = (seed: {
			localRevoke?: string;
			peerRevoke?: string;
		}): void => {
			delete seed.localRevoke;
			delete seed.peerRevoke;
		};
		const swapRevocations = (seed: {
			localRevoke?: string;
			peerRevoke?: string;
		}): void => {
			[seed.localRevoke, seed.peerRevoke] = [seed.peerRevoke, seed.localRevoke];
		};
		/** The check each mutation must fail, as "Channel type seed <check> does not verify". */
		const plainChecks: Record<string, string> = {
			'rebuilt bytes': 'rebuilt bytes',
			signature: 'signature',
			'local next nonce': 'local nonce',
			'remote next nonce': 'remote nonce',
			points: 'rebuilt bytes',
			'HTLC IDs': 'HTLC IDs',
			'peer HTLC ID': 'HTLC IDs',
			'a balance sum off by one msat': 'rebuilt bytes',
			'both revocations dropped': 'revocations',
			'a one-byte peer revocation': 'revocations',
			'swapped revocations': 'revocations'
		};
		const assetChecks: Record<string, string> = {
			'rebuilt bytes': 'rebuilt bytes',
			signature: 'signature',
			'local nonce': 'local nonce',
			'peer nonce': 'nonce',
			'the asset digest': 'digest',
			'the peer next point': 'points',
			'the peer current point': 'points',
			'HTLC IDs': 'HTLC IDs',
			'a balance sum off by one msat': 'rebuilt bytes',
			'both revocations dropped': 'revocations',
			'swapped revocations': 'revocations',
			'holders that disagree on balances': 'holder balances'
		};
		const witnessless = (hex: string): string => {
			const t = Transaction.fromHex(hex);
			t.setWitness(0, [Buffer.alloc(64, 1)]);
			return t.toHex();
		};
		const badNonce = '05' + '11'.repeat(32) + '05' + '11'.repeat(32);
		const plainMutations: Record<string, Mutation> = {
			'rebuilt bytes': (seed: IFinalPlainSeedInput, c, i) => {
				seed.remote.tx = c
					.view(i, 'remote', { feerate: seed.funds.feeratePerKw! + 1 })
					.tx.toHex();
			},
			signature: (seed: IFinalPlainSeedInput) => {
				seed.local.tx = witnessless(seed.local.tx);
			},
			'local next nonce': (seed: IFinalPlainSeedInput, c, i) => {
				seed.local.nextNonce.pub = c.nonceAt(i, c.stateNumber + 2);
			},
			'remote next nonce': (seed: IFinalPlainSeedInput) => {
				seed.remote.nextNonce.pub = badNonce;
			},
			points: (seed: IFinalPlainSeedInput, c, i) => {
				seed.remote.tx = c
					.view(i, 'remote', { point: c.point(1 - i, c.stateNumber + 1) })
					.tx.toHex();
			},
			'HTLC IDs': (seed: IFinalPlainSeedInput) => {
				seed.nextLocalId = '1';
			},
			'peer HTLC ID': (seed: IFinalPlainSeedInput) => {
				seed.nextPeerId = '1';
			},
			'a balance sum off by one msat': (seed: IFinalPlainSeedInput) => {
				seed.funds.local = String(BigInt(seed.funds.local) + 1n);
			},
			'both revocations dropped': dropRevocations,
			'a one-byte peer revocation': (seed: IFinalPlainSeedInput) => {
				seed.peerRevoke = '00';
			},
			'swapped revocations': swapRevocations
		};
		const assetMutations: Record<string, Mutation> = {
			'rebuilt bytes': (seed: IFinalAssetSeedInput, c, i) => {
				seed.members[0].remoteCommitment = c
					.view(i, 'remote', { feerate: seed.feerate + 1 })
					.tx.toHex();
			},
			signature: (seed: IFinalAssetSeedInput) => {
				seed.members[0].localCommitment = witnessless(
					seed.members[0].localCommitment
				);
			},
			'local nonce': (seed: IFinalAssetSeedInput, c, i) => {
				seed.localNonces[0] = c.nonceAt(i, c.stateNumber + 2);
			},
			'peer nonce': (seed: IFinalAssetSeedInput) => {
				seed.peerNonces[0] = badNonce;
			},
			'the asset digest': (seed: IFinalAssetSeedInput) => {
				seed.digest = 'ab'.repeat(32);
			},
			'the peer next point': (seed: IFinalAssetSeedInput, c, i) => {
				seed.peerNextPoint = c.point(1 - i, c.stateNumber + 2).toString('hex');
			},
			'the peer current point': (seed: IFinalAssetSeedInput, c, i) => {
				seed.members[0].remoteRecovery.point = c
					.point(1 - i, c.stateNumber + 1)
					.toString('hex');
			},
			'HTLC IDs': (seed: IFinalAssetSeedInput) => {
				seed.nextLocalId = '1';
			},
			'a balance sum off by one msat': (seed: IFinalAssetSeedInput) => {
				const m = seed.members[0];
				for (const r of [m.localRecovery, m.remoteRecovery])
					r.localBalanceMsat = String(BigInt(r.localBalanceMsat) + 1n);
			},
			'both revocations dropped': dropRevocations,
			'swapped revocations': swapRevocations,
			// The peer's commitment as rebuilt with 1000 sat moved to the peer, and
			// a digest recomputed over it: only the holders' agreement refuses it.
			'holders that disagree on balances': (
				seed: IFinalAssetSeedInput,
				c,
				i,
				input,
				isInitiator
			) => {
				const m = seed.members[0];
				const balances = {
					localBalanceMsat:
						BigInt(m.remoteRecovery.localBalanceMsat) - 1_000_000n,
					remoteBalanceMsat:
						BigInt(m.remoteRecovery.remoteBalanceMsat) + 1_000_000n
				};
				m.remoteRecovery.localBalanceMsat = String(balances.localBalanceMsat);
				m.remoteRecovery.remoteBalanceMsat = String(balances.remoteBalanceMsat);
				m.remoteCommitment = c.view(i, 'remote', { balances }).tx.toHex();
				seed.digest = step2a().finalAssetSeedDigest(c.id, isInitiator, input);
			}
		};
		function each(
			device: { store: SqliteStorage; root: import('bip32').BIP32Interface },
			c: IConversion,
			mutations: Record<string, Mutation>,
			checks: Record<string, string>
		): void {
			const { store, root } = device;
			const isInitiator = store.loadFinalOpening(c.id)!.isInitiator;
			expect(Object.keys(checks)).to.deep.equal(Object.keys(mutations));
			for (const [name, mutate] of Object.entries(mutations)) {
				const input = copyInput(c.inputs[0]);
				mutate(input.seed as never, c, 0, input, isInitiator);
				let error: Error | undefined;
				try {
					typed(store).appendFinalChannelType(c.id, input, root);
				} catch (e) {
					error = e as Error;
				}
				expect(error?.message, name).to.equal(
					'Channel type seed ' + checks[name] + ' does not verify'
				);
			}
			expect(typed(store).loadFinalChannelTypeRecords(c.id)).to.deep.equal([]);
		}

		it('refuses each failing check of a plain seed at N >= 1, and accepts it unchanged', async () => {
			const { pair, c } = await toPlain(1);
			each(pair.devices[0], c, plainMutations, plainChecks);
			appendBoth(pair.devices, c);
		});

		it('refuses each failing check of an asset seed at N >= 1, and accepts it unchanged', () => {
			const plain = plainTypePair(s, 1);
			const c = toAsset(plain, 1);
			each(plain.devices[0], c, assetMutations, assetChecks);
			appendBoth(plain.devices, c);
		});

		it('refuses a reserve that does not hold on the new funding', async () => {
			const pair = await assetTypePair(s, 0);
			const parent = openingParent(pair.devices[0].store, pair.id);
			const value = BigInt(parent.tx.outs[parent.index].value - 600);
			const poor = buildConversion(pair.devices, pair.id, {
				type: 'plain',
				stateNumber: 0,
				parent,
				balances: [
					{
						localBalanceMsat: (value - 500n) * 1000n,
						remoteBalanceMsat: 500_000n
					},
					{
						localBalanceMsat: 500_000n,
						remoteBalanceMsat: (value - 500n) * 1000n
					}
				]
			});
			for (const i of [0, 1])
				refusesNothingStored(
					pair.devices[i].store,
					pair.id,
					poor.inputs[i],
					'Channel type seed reserve does not verify'
				);
		});

		it('refuses revocations in a seed at N = 0', async () => {
			const { pair, c } = await toPlain(0);
			const input = copyInput(c.inputs[0]);
			// In the canonical field order, so only the revocation rule refuses it.
			const { local, remote, ...rest } = input.seed as IFinalPlainSeedInput;
			input.seed = { local, remote, peerRevoke: 'ab'.repeat(97), ...rest };
			refusesNothingStored(
				pair.devices[0].store,
				pair.id,
				input,
				'Channel type seed revocations does not verify'
			);
		});

		it('refuses an asset seed whose reserve does not hold on the new funding', () => {
			const plain = plainTypePair(s, 0);
			const parent = openingParent(plain.stores[0], plain.id);
			const value = BigInt(parent.tx.outs[parent.index].value - 600);
			const poor = toAsset(plain, 0, {
				balances: [
					{
						localBalanceMsat: (value - 500n) * 1000n,
						remoteBalanceMsat: 500_000n
					},
					{
						localBalanceMsat: 500_000n,
						remoteBalanceMsat: (value - 500n) * 1000n
					}
				]
			});
			for (const i of [0, 1])
				refusesNothingStored(
					plain.stores[i],
					plain.id,
					poor.inputs[i],
					'Channel type seed reserve does not verify'
				);
		});

		it('refuses a funding key index used by an earlier funding', async () => {
			const pair = await assetTypePair(s, 0);
			const index = pair.devices.map(
				(d) => d.store.loadFinalOpeningSession(pair.id)!.channelKeyIndex
			) as [number, number];
			const reused = buildConversion(pair.devices, pair.id, {
				type: 'plain',
				stateNumber: 0,
				parent: openingParent(pair.devices[0].store, pair.id),
				keyIndices: index
			});
			refusesNothingStored(
				pair.devices[0].store,
				pair.id,
				reused.inputs[0],
				'Channel type record reuses a funding key'
			);
		});
	});
});

describe('Channel type reader and memo (#2151 step 2a, item 2)', function () {
	this.timeout(240000);
	const s = scratch('channel-type-reader-');
	afterEach(() => {
		sinon.restore();
		s.release();
	});

	async function converted(
		rounds = 0
	): Promise<{ pair: IAssetTypePair; c: IConversion }> {
		const pair = await assetTypePair(s, rounds);
		const c = buildConversion(pair.devices, pair.id, {
			type: 'plain',
			stateNumber: rounds,
			parent: openingParent(pair.devices[0].store, pair.id)
		});
		appendBoth(pair.devices, c);
		return { pair, c };
	}

	it("reads the opening's kind and type with no record", async () => {
		const asset = await assetTypePair(s, 0);
		const plain = plainTypePair(s, 0);
		for (const [store, id, type] of [
			[asset.devices[0].store, asset.id, 'asset'],
			[plain.stores[0], plain.id, 'plain']
		] as const) {
			const opening = store.loadFinalOpening(id)!;
			expect(typed(store).loadFinalChannelType(id)).to.deep.equal({
				type,
				channelType: opening.channelType,
				source: 'opening',
				stateNumber: 0n,
				funding: {
					txid: txidOf(opening.fundingTxHex),
					outputIndex: opening.fundingOutputIndex
				}
			});
			expect(store.loadFinalChannelKind(id)).to.equal(type);
			expect(typed(store).loadFinalChannelTypeRecords(id)).to.deep.equal([]);
		}
		expect(typed(plain.stores[0]).loadFinalChannelType(unknown)).to.equal(null);
	});

	it('reads the type of one record', async () => {
		const { pair, c } = await converted(0);
		for (const [i, d] of pair.devices.entries()) {
			const current = typed(d.store).loadFinalChannelType(pair.id)!;
			expect(current).to.deep.equal({
				type: 'plain',
				channelType: PLAIN_TYPE_HEX,
				source: 'record',
				stateNumber: 0n,
				funding: fundingOf(c),
				record: typed(d.store).loadFinalChannelTypeRecords(pair.id)[0]
			});
			expect(current.record!.parent).to.deep.equal(c.inputs[i].parent);
			expect(d.store.loadFinalChannelKind(pair.id)).to.equal('plain');
			expect(
				txidOf(d.store.loadFinalActiveFunding(pair.id)!.fundingTxHex)
			).to.equal(c.tx.getId());
		}
	});

	it('reads asset to plain to asset, the second record at N with no plain rounds', async () => {
		const { pair, c } = await converted(1);
		const back = buildConversion(
			pair.devices,
			pair.id,
			{ type: 'asset', stateNumber: 1, parent: parentOf(c) },
			'plain'
		);
		appendBoth(pair.devices, back);
		for (const d of pair.devices) {
			const current = typed(d.store).loadFinalChannelType(pair.id)!;
			expect(current.type).to.equal('asset');
			expect(current.channelType).to.equal(ASSET_TYPE_HEX);
			expect(current.stateNumber).to.equal(1n);
			expect(current.funding).to.deep.equal(fundingOf(back));
			expect(
				typed(d.store)
					.loadFinalChannelTypeRecords(pair.id)
					.map((r) => [r.type, r.parent.txid])
			).to.deep.equal([
				['plain', openingParent(d.store, pair.id).tx.getId()],
				['asset', c.tx.getId()]
			]);
			expect(d.store.loadFinalChannelKind(pair.id)).to.equal('asset');
		}
	});

	it('reads plain to asset to plain at N > 0, whose shachain spans both eras', async () => {
		const plain = plainTypePair(s, 2);
		const toAsset = buildConversion(plain.devices, plain.id, {
			type: 'asset',
			stateNumber: 2,
			parent: openingParent(plain.stores[0], plain.id)
		});
		appendBoth(plain.devices, toAsset);
		await assetRounds(plain.devices, plain.id, 3);
		const back = buildConversion(
			plain.devices,
			plain.id,
			{ type: 'plain', stateNumber: 3, parent: parentOf(toAsset) },
			'asset'
		);
		appendBoth(plain.devices, back);
		for (const [i, d] of plain.devices.entries()) {
			const records = typed(d.store).loadFinalChannelTypeRecords(plain.id);
			expect(records.map((r) => r.type)).to.deep.equal(['asset', 'plain']);
			const secret = (h: number): Buffer =>
				peerSecret(plain, plain.id, 1 - i, h);
			expect(records[0].seed.shachain).to.deep.equal(buckets(secret, 2));
			expect(records[1].seed.shachain).to.deep.equal(buckets(secret, 3));
			expect(typed(d.store).loadFinalChannelType(plain.id)!.type).to.equal(
				'plain'
			);
		}
	});

	it("reads 'plain' before the asset session is stored and 'asset' after", () => {
		const f = setupAssetSpliceProofs(s.dir(), undefined, 6);
		s.closing(() => f.devices.forEach((d) => d.store.close()));
		const store = f.devices[0].store;
		// The opening row as it reads before its session is stored: the kind
		// reads 'plain' from the missing session, and the memo must not keep it.
		const view = store as unknown as {
			finalOpeningRecord(id: string): { nonces: object } | null;
		};
		const real = view.finalOpeningRecord.bind(store);
		const before = sinon
			.stub(view, 'finalOpeningRecord')
			.callsFake((id: string) => {
				const r = real(id);
				return r && { ...r, nonces: { ...r.nonces, session: undefined } };
			});
		expect(store.loadFinalChannelKind(f.id)).to.equal('plain');
		expect(typed(store).loadFinalChannelType(f.id)!.type).to.equal('plain');
		before.restore();
		expect(typed(store).loadFinalChannelType(f.id)!.type).to.equal('asset');
		expect(store.loadFinalChannelKind(f.id)).to.equal('asset');
	});

	it('makes no further opening read after the first, and refills when the opening row or the record count changes', async () => {
		const { pair } = await converted(0);
		const store = pair.devices[0].store;
		const spy = sinon.spy(
			store as unknown as { finalOpeningRecord(id: string): unknown },
			'finalOpeningRecord'
		);
		const first = typed(store).loadFinalChannelType(pair.id);
		spy.resetHistory();
		for (let n = 0; n < 3; n++) {
			expect(typed(store).loadFinalChannelType(pair.id)).to.deep.equal(first);
			expect(store.loadFinalChannelKind(pair.id)).to.equal('plain');
		}
		expect(spy.callCount, 'opening reads after the first').to.equal(0);
		// A record row the wallet lost is refilled from the device on the next read.
		db(store)
			.prepare(
				"DELETE FROM final_lifecycle_log WHERE scope='channel-type' AND channel_id=?"
			)
			.run(pair.id);
		expect(typed(store).loadFinalChannelType(pair.id)).to.deep.equal(first);
		expect(typeRows(store, pair.id)).to.have.length(1);
		// A changed opening row is read again through the authenticated path.
		db(store)
			.prepare(
				"UPDATE final_opening_candidates SET nonces_json = nonces_json || ' ' WHERE channel_id=?"
			)
			.run(pair.id);
		spy.resetHistory();
		try {
			typed(store).loadFinalChannelType(pair.id);
		} catch {
			// The authenticated read may refuse the changed row.
		}
		expect(spy.callCount, 'opening reads after a row change').to.be.greaterThan(
			0
		);
	});

	it('reads a record committed on the device whose wallet insert failed, also after a restart', async () => {
		const pair = await assetTypePair(s, 0);
		const c = buildConversion(pair.devices, pair.id, {
			type: 'plain',
			stateNumber: 0,
			parent: openingParent(pair.devices[0].store, pair.id)
		});
		const store = pair.devices[0].store;
		expect(typed(store).loadFinalChannelType(pair.id)!.type).to.equal('asset');
		const authority = deviceAuthority(store);
		const commit = authority.commitLifecycleEntry.bind(authority);
		sinon
			.stub(authority, 'commitLifecycleEntry')
			.callsFake((slot: string, encoded: string) => {
				commit(slot, encoded);
				if (slot.startsWith('channel-type/'))
					throw new Error('wallet insert failed');
			});
		expect(() =>
			typed(store).appendFinalChannelType(
				pair.id,
				c.inputs[0],
				pair.devices[0].root
			)
		).to.throw('wallet insert failed');
		sinon.restore();
		expect(typed(store).loadFinalChannelType(pair.id)!.type).to.equal('plain');
		const reopened = pair.restart(0);
		expect(typed(reopened).loadFinalChannelType(pair.id)!.type).to.equal(
			'plain'
		);
		expect(typeRows(reopened, pair.id)).to.have.length(1);
	});

	it("gives the opening's kind in generations 1 and 3 without touching final_lifecycle_log", () => {
		for (const g of [1, 3] as const) {
			const store = SqliteStorage.createFinalWallet(
				path.join(s.dir(), 'g' + g),
				generateFinalGeneration(g).binding
			);
			s.closing(() => store.close());
			const prepare = sinon.spy(db(store), 'prepare');
			expect(typed(store).loadFinalChannelType(unknown)).to.equal(null);
			expect(typed(store).loadFinalChannelTypeRecords(unknown)).to.deep.equal(
				[]
			);
			expect(
				prepare.args.filter((a: unknown[]) =>
					String(a[0]).includes('final_lifecycle_log')
				)
			).to.deep.equal([]);
			prepare.restore();
		}
		const g2 = plainTypePair(s, 0, 2);
		expect(typed(g2.stores[0]).loadFinalChannelType(g2.id)!.source).to.equal(
			'opening'
		);
	});

	it("binds the asset seed digest to the commitments, not to either host's proof bytes", () => {
		const pair = plainTypePair(s, 0);
		const c = buildConversion(pair.devices, pair.id, {
			type: 'asset',
			stateNumber: 0,
			parent: openingParent(pair.stores[0], pair.id)
		});
		const digestOf = (i: number, input: IChannelTypeRecordInput): string =>
			step2a().finalAssetSeedDigest(
				c.id,
				pair.stores[i].loadFinalOpening(c.id)!.isInitiator,
				input
			);
		const [d0, d1] = [digestOf(0, c.inputs[0]), digestOf(1, c.inputs[1])];
		expect(d0).to.equal(d1);
		const reproved = JSON.parse(
			JSON.stringify(c.inputs[1])
		) as IChannelTypeRecordInput;
		const m = (reproved.seed as IFinalAssetSeedInput).members[0];
		m.localProofs = 'ab'.repeat(40);
		m.remoteProofs = 'cd'.repeat(40);
		m.fundingProofs = 'ef'.repeat(40);
		expect(digestOf(1, reproved)).to.equal(d0);
		const moved = JSON.parse(
			JSON.stringify(c.inputs[1])
		) as IChannelTypeRecordInput;
		(moved.seed as IFinalAssetSeedInput).members[0].remoteCommitment =
			c.tx.toHex();
		expect(digestOf(1, moved)).to.not.equal(d0);
	});

	it('reads a funded channel of generations 1 and 3 as its opening, without the lifecycle journal', () => {
		for (const g of [1, 3] as const) {
			const pair = plainTypePair(s, 0, g);
			const read = typed(pair.stores[0]).loadFinalChannelType(pair.id)!;
			expect(read.source).to.equal('opening');
			expect(read.stateNumber).to.equal(0n);
			expect(
				typed(pair.stores[0]).loadFinalChannelTypeRecords(pair.id)
			).to.deep.equal([]);
		}
	});

	it("keeps a block's work going when one channel's type cannot be read", async () => {
		const { pair } = await converted(0);
		const d = pair.p.f.devices[0];
		const running = finalTestNode(6, {
			wallet: { db: d.store, mnemonic: d.mnemonic }
		});
		try {
			const manager = running.node.getChannelManager();
			const fields = manager as unknown as {
				assetCollateral: Map<string, unknown>;
			};
			const unreadable = '66'.repeat(32);
			const marker = { accepted: false, confirmed: false, present: false };
			fields.assetCollateral.set(unreadable, { ...marker });
			fields.assetCollateral.set(pair.id, { ...marker });
			const read = d.store.loadFinalChannelTypeRecords.bind(d.store);
			sinon
				.stub(d.store, 'loadFinalChannelTypeRecords')
				.callsFake((id: string) => {
					if (id === unreadable) throw new Error('unreadable channel type');
					return read(id);
				});
			// Every channel's HTLC deadline check follows the manager's block work.
			const deadlines = sinon.spy(manager, 'checkFinalHtlcDeadlines');
			const errors: string[] = [];
			manager.on('error', (_id: Buffer | null, message: string) => {
				errors.push(message);
			});
			expect(() => running.node.handleNewBlock(300)).to.not.throw();
			expect(deadlines.callCount).to.equal(1);
			expect(errors).to.include('unreadable channel type');
			// The readable recorded channel still loses its marker at this block.
			expect(fields.assetCollateral.has(pair.id)).to.equal(false);
		} finally {
			sinon.restore();
			running.close();
		}
	});

	it("reads a backup copy's plain channel and an asset channel inside a transaction as outside", async () => {
		const plain = plainTypePair(s, 1);
		const copy = path.join(s.dir(), 'plain-copy.db');
		await plain.stores[0].backup(copy);
		const backup = SqliteStorage.openFinalWallet(copy, plain.sides[0].binding);
		s.closing(() => backup.close());
		expect(backup.canSignFinalOpening).to.equal(false);
		expect(typed(backup).loadFinalChannelType(plain.id)).to.deep.equal(
			typed(plain.stores[0]).loadFinalChannelType(plain.id)
		);
		const spliced = await assetTypePair(s, 0);
		await spliced.p.start();
		await spliced.p.drain();
		await spliced.p.adopt();
		const store = spliced.devices[0].store;
		const outside = typed(store).loadFinalChannelType(spliced.id)!;
		expect(outside.funding.txid).to.not.equal(
			txidOf(store.loadFinalOpening(spliced.id)!.fundingTxHex)
		);
		const inside = db(store).transaction(() =>
			typed(store).loadFinalChannelType(spliced.id)
		)();
		expect(inside).to.deep.equal(outside);
	});

	it('opens and restarts with a record present', async () => {
		const { pair, c } = await converted(1);
		const before = pair.devices.map((d) =>
			typed(d.store).loadFinalChannelType(pair.id)
		);
		for (const i of [0, 1]) {
			const store = pair.restart(i);
			expect(typed(store).loadFinalChannelType(pair.id)).to.deep.equal(
				before[i]
			);
			expect(store.loadFinalChannelKind(pair.id)).to.equal('plain');
			expect(
				txidOf(store.loadFinalActiveFunding(pair.id)!.fundingTxHex)
			).to.equal(c.tx.getId());
		}
		// A node over the reopened wallet lists the channel by its current type
		// and arms no asset marker for it: the record's watch is Step 5's.
		const d = pair.p.f.devices[0];
		const running = finalTestNode(6, {
			wallet: { db: d.store, mnemonic: d.mnemonic }
		});
		try {
			const manager = running.node.getChannelManager();
			manager.restoreFinalOpeningBroadcasts();
			const listed = running.node
				.listChannels()
				.filter((ch) => Buffer.from(ch.channelId).toString('hex') === pair.id);
			expect(listed).to.have.length(1);
			expect((listed[0] as { auxiliary?: boolean }).auxiliary).to.not.equal(
				true
			);
			const markers = manager as unknown as {
				assetCollateral: Map<string, unknown>;
				assetFundingChannels: Map<string, string>;
			};
			expect(markers.assetCollateral.has(pair.id)).to.equal(false);
			expect([...markers.assetFundingChannels.values()]).to.not.include(
				pair.id
			);
			expect(running.errors).to.deep.equal([]);
		} finally {
			running.close();
		}
	});

	it('keeps the record byte for byte in a backup and reads the same type from it', async () => {
		const { pair } = await converted(0);
		const store = pair.devices[0].store;
		const copy = path.join(s.dir(), 'copy.db');
		await store.backup(copy);
		const backup = SqliteStorage.openFinalWallet(copy, pair.bindings[0]);
		s.closing(() => backup.close());
		expect(typeRows(backup, pair.id)).to.deep.equal(typeRows(store, pair.id));
		expect(typeRows(backup, pair.id)).to.have.length(1);
		expect(typed(backup).loadFinalChannelType(pair.id)).to.deep.equal(
			typed(store).loadFinalChannelType(pair.id)
		);
	});

	it('refuses restore and repair of a recorded channel, including a device-ahead record', async () => {
		const pair = await assetTypePair(s, 0);
		const { id } = pair;
		const dir = s.dir();
		const mac = Buffer.alloc(32, 79);
		const early = path.join(dir, 'early.db'),
			frame = path.join(dir, 'early.frame'),
			late = path.join(dir, 'late.db');
		await pair.devices[0].store.backup(early);
		await writeBackupMac(mac, early);
		const sdk = Object.create(BeignetNode.prototype) as BeignetNode;
		Object.assign(sdk, {
			sqlite: () => pair.p.f.devices[1].store,
			walletSeed: () => pair.p.f.devices[1].seed
		});
		await sdk.backupAssetChannelFrame(id, frame);
		const c = buildConversion(pair.devices, id, {
			type: 'plain',
			stateNumber: 0,
			parent: openingParent(pair.devices[0].store, id)
		});
		appendBoth(pair.devices, c);
		await pair.devices[0].store.backup(late);
		await writeBackupMac(mac, late);
		const sources = [
			{ side: 0, file: late, mac, why: 'the snapshot holds the record' },
			{ side: 0, file: early, mac, why: 'the device holds the record' },
			{
				side: 1,
				file: frame,
				mac: deriveBackupMacKey(pair.p.f.devices[1].seed),
				why: 'a frame from before the record'
			}
		];
		for (const source of sources) {
			const d = pair.p.f.devices[source.side];
			try {
				d.store.close();
			} catch {
				// Closed by an earlier source.
			}
			const raw = new Database(d.file);
			raw
				.prepare(
					"DELETE FROM final_lifecycle_log WHERE channel_id=? AND scope='channel-type'"
				)
				.run(id);
			raw.close();
			let error: Error | undefined;
			try {
				await performAssetChannelRestore(
					source.file,
					d.file,
					path.join(dir, 'restore.lock'),
					d.party.binding,
					id,
					source.mac
				);
			} catch (e) {
				error = e as Error;
			}
			expect(error?.message, source.why).to.equal(TEXT.restore);
		}
		for (const i of [0, 1]) {
			const store = pair.restart(i);
			expect(typed(store).loadFinalChannelType(id)!.type).to.equal('plain');
		}
	});
});

describe('Builders and signer by type (#2151 step 2a, item 7)', function () {
	this.timeout(120000);
	const s = scratch('channel-type-builders-');
	afterEach(() => s.release());

	function openings(): {
		f: ReturnType<typeof setupAssetSpliceProofs>;
		asset: NonNullable<ReturnType<SqliteStorage['loadFinalDaemonOpening']>>;
		plain: ReturnType<typeof signingFixture>;
	} {
		const f = setupAssetSpliceProofs(s.dir(), undefined, 6);
		s.closing(() => f.devices.forEach((d) => d.store.close()));
		const asset = f.devices[0].store.loadFinalDaemonOpening(f.id)!;
		const plain = signingFixture(false);
		return { f, asset, plain };
	}
	const point = (seed: Buffer): Buffer =>
		getPublicKey(generateFromSeed(seed, MAX_INDEX - 3n));

	it('builds on an asset opening by the plain type what a plain opening of the same terms builds', () => {
		const { f, asset } = openings();
		const keys = deriveChannelKeys(f.devices[0].party.root, 1, 2);
		const peer = deriveChannelKeys(f.devices[1].party.root, 1, 2);
		const tx = new Transaction();
		tx.version = 2;
		tx.addInput(Buffer.alloc(32, 3), 0);
		tx.addOutput(
			createTaprootFundingScript(
				keys.channelBasepoints.fundingPubkey,
				peer.channelBasepoints.fundingPubkey
			).p2trOutput,
			139_400
		);
		const ref = {
			fundingTxHex: tx.toHex(),
			fundingOutputIndex: 0,
			localFundingPubkey: keys.channelBasepoints.fundingPubkey.toString('hex'),
			remoteFundingPubkey: peer.channelBasepoints.fundingPubkey.toString('hex'),
			localFundingKeyIndex: 2
		};
		const root = Buffer.from(asset.session.assetEvidence!.fundingRoot, 'hex');
		const args = (c: typeof asset.candidate): unknown[] => [
			c,
			asset.session.terms,
			'local',
			point(keys.perCommitmentSeed),
			3n,
			{ localBalanceMsat: 89_400_000n, remoteBalanceMsat: 50_000_000n },
			[],
			ref
		];
		const twin = buildFinalCommitmentView(
			...(args(plainTwin(asset.candidate)) as Parameters<
				typeof buildFinalCommitmentView
			>)
		);
		// Today's builder refuses the asset opening.
		expect(() =>
			buildFinalCommitmentView(
				...(args(asset.candidate) as Parameters<
					typeof buildFinalCommitmentView
				>)
			)
		).to.throw();
		const typedView = buildAs('plain', args(asset.candidate), {
			channelType: PLAIN_TYPE_HEX,
			openingRoot: root
		});
		expect(typedView.tx.toHex()).to.equal(twin.tx.toHex());
		expectRefusal(() =>
			buildAs('plain', args(asset.candidate), {
				channelType: ASSET_TYPE_HEX,
				openingRoot: root
			})
		);
	});

	it('builds on a plain opening by the asset type what an asset opening of the same terms builds', () => {
		const { plain } = openings();
		const { candidate, terms } = plain;
		const local = Buffer.from(terms.localBasepoints.fundingPubkey, 'hex');
		const remote = Buffer.from(terms.remoteBasepoints.fundingPubkey, 'hex');
		const root = Buffer.alloc(32, 0x3c);
		const tx = new Transaction();
		tx.version = 2;
		tx.addInput(Buffer.alloc(32, 4), 0);
		tx.addOutput(
			createTaprootFundingScript(local, remote, undefined, root).p2trOutput,
			139_400
		);
		// The new funding reuses the opening keys here: the builder checks the script only.
		const ref = {
			fundingTxHex: tx.toHex(),
			fundingOutputIndex: 0,
			localFundingPubkey: local.toString('hex'),
			remoteFundingPubkey: remote.toString('hex'),
			localFundingKeyIndex: 2
		};
		const args = (
			c: typeof candidate,
			openingRoot: Buffer | undefined
		): unknown[] => [
			c,
			terms,
			'remote',
			Buffer.from(terms.remoteBasepoints.firstPerCommitmentPoint, 'hex'),
			0n,
			{ localBalanceMsat: 89_400_000n, remoteBalanceMsat: 50_000_000n },
			[],
			ref,
			openingRoot,
			{ fundingRoot: root, ...LEAVES }
		];
		const twin = buildAssetSpliceCommitment(
			...(args(assetTwin(candidate), TWIN_ROOT) as Parameters<
				typeof buildAssetSpliceCommitment
			>)
		);
		expect(() =>
			buildAssetSpliceCommitment(
				...(args(candidate, TWIN_ROOT) as Parameters<
					typeof buildAssetSpliceCommitment
				>)
			)
		).to.throw();
		const typedView = buildAs('asset', args(candidate, undefined), {
			channelType: ASSET_TYPE_HEX
		});
		expect(typedView.tx.toHex()).to.equal(twin.tx.toHex());
		expectRefusal(() =>
			buildAs('asset', args(candidate, undefined), {
				channelType: PLAIN_TYPE_HEX
			})
		);
	});

	it('validates an opening as another type by its fixed fields, and keeps the validators without a type unchanged', () => {
		const { asset, plain } = openings();
		const root = Buffer.from(asset.session.assetEvidence!.fundingRoot, 'hex');
		const as = candidates as unknown as {
			validateFinalOpeningAs(
				c: unknown,
				channelType: string,
				openingRoot?: Buffer
			): unknown;
			validateAssetOpeningAs(
				c: unknown,
				channelType: string,
				openingRoot?: Buffer
			): unknown;
		};
		// Unchanged without a type.
		expect(() => candidates.validateFinalOpening(asset.candidate)).to.throw();
		expect(() =>
			candidates.validateAssetOpening(plain.candidate, TWIN_ROOT)
		).to.throw();
		const oneSided = signingFixture(true);
		expect(() =>
			candidates.validateAssetOpening(assetTwin(oneSided.candidate), TWIN_ROOT)
		).to.throw(/two contributors/);
		// By type.
		expect(() =>
			as.validateFinalOpeningAs(asset.candidate, PLAIN_TYPE_HEX, root)
		).to.not.throw();
		expectRefusal(() =>
			as.validateFinalOpeningAs(asset.candidate, ASSET_TYPE_HEX, root)
		);
		expectRefusal(() =>
			as.validateFinalOpeningAs(asset.candidate, PLAIN_TYPE_HEX)
		);
		expect(() =>
			as.validateAssetOpeningAs(plain.candidate, ASSET_TYPE_HEX)
		).to.not.throw();
		expect(
			() => as.validateAssetOpeningAs(oneSided.candidate, ASSET_TYPE_HEX),
			'a one-sided plain opening'
		).to.not.throw();
		expectRefusal(() =>
			as.validateAssetOpeningAs(plain.candidate, PLAIN_TYPE_HEX)
		);
	});

	it('signs by the passed type and refuses a type that disagrees with the asset payload', async () => {
		const pair = await assetTypePair(s, 0);
		const c = buildConversion(pair.devices, pair.id, {
			type: 'plain',
			stateNumber: 0,
			parent: openingParent(pair.devices[0].store, pair.id)
		});
		const [d0, d1] = pair.devices;
		const opening = d1.store.loadFinalDaemonOpening(pair.id)!;
		const keys = deriveChannelKeys(d1.root, 1, opening.session.channelKeyIndex);
		const fundingKey = deriveChannelKeys(d1.root, 1, c.keyIndices[1]);
		const nonceKey = spliceCommitmentNonceContext(pair.id, c.tx.getHash(), 0);
		// A fresh height so the device has made no promise for it.
		const height = 5;
		const promise = Buffer.from(
			updateVerificationNonce(
				deviceAuthority(d0.store).nonceContext(nonceKey),
				deriveChannelKeys(d0.root, 1, c.keyIndices[0]).fundingPrivkey,
				height,
				{ pub: '', source: 'splice' }
			)
		).toString('hex');
		const args = (asset?: {
			fundingRoot: Buffer;
			transcriptDigest: Buffer;
		}): Parameters<typeof signFinalUpdate> => [
			opening.candidate,
			c.view(1, 'remote'),
			c.point(0, 0),
			height,
			{ pub: promise },
			keys,
			deviceAuthority(d1.store),
			nonceKey,
			[],
			undefined,
			{
				reference: c.refs[1],
				privateKey: fundingKey.fundingPrivkey,
				...(asset && { asset })
			}
		];
		// Unchanged without a type: the asset opening needs the asset payload.
		expect(() => signFinalUpdate(...args())).to.throw(
			'Asset commitment signing requires its funding root and transcript'
		);
		expectRefusal(() =>
			signAs(
				args({
					fundingRoot: Buffer.alloc(32, 1),
					transcriptDigest: Buffer.alloc(32, 2)
				}),
				PLAIN_TYPE_HEX
			)
		);
		expectRefusal(() => signAs(args(), ASSET_TYPE_HEX));
		expect(signAs(args(), PLAIN_TYPE_HEX)).to.be.instanceOf(Buffer);
	});
});
