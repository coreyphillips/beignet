/**
 * #2151 step 2a: the ledger a recorded type change seeds at its state
 * number N, pure (the peer shachain and seedFinalLedger) and on real SQLite
 * devices, to plain from an asset channel and to asset from a plain one.
 *
 * The record inputs come from helpers/channel-type-record.ts, which builds
 * the first commitments at N with today's builders on a twin of the opening
 * and has both devices sign them through signFinalUpdate. The step's names
 * are reached loosely there, so this file loads on a base without them.
 * Pure names the contract leaves open are assumed in that helper
 * (finalSeedShachain, finalAssetSeedDigest).
 *
 * No watch is armed for a record's funding in 2a, so the exit tests inject
 * the record's txid into the manager's observed funding, as Step 5's watch
 * will.
 */
import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import {
	finalChannelOutputClaims,
	type IFinalOutputClaim
} from '../../src/lightning/chain/final-output-claims';
import {
	AssetSpliceTransport,
	type AssetSpliceHost
} from '../../src/lightning/channel/asset-splice-transport';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { deriveChannelKeys } from '../../src/lightning/keys/wallet-keys';
import { decodeRevokeAndAckMessage } from '../../src/lightning/message/channel-commitment';
import {
	decodeChannelReestablishMessage,
	encodeChannelReestablishMessage
} from '../../src/lightning/message/channel-reestablish';
import { encodeUpdateFeeMessage } from '../../src/lightning/message/channel-update';
import { MessageType as M } from '../../src/lightning/message/types';
import { acceptAssetSpliceReestablish } from '../../src/lightning/storage/asset-splice-reestablish';
import {
	assetSpliceUpdateHead,
	assetUpdateHistory
} from '../../src/lightning/storage/asset-update-history';
import type { IFinalOpeningNonces } from '../../src/lightning/storage/final-opening-nonces';
import type { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { loadVectors, hexToBuffer } from './conformance/helpers';
import { assetTypePair, scratch } from './helpers/channel-type-pairs';
import {
	assetReporting,
	assetRounds,
	buildConversion,
	expectRefusal,
	type IChannelTypeRecord,
	localPointsOf,
	type IConversion,
	type IFinalPlainSeedInput,
	openingParent,
	type Shachain,
	step2a,
	TEXT,
	typed,
	toAsset as toAssetOf,
	toPlain as toPlainOf,
	type IToAsset,
	type IToPlain,
	type ITypeDevice
} from './helpers/channel-type-record';
import {
	closeCooperatively,
	plainUpdates,
	plainWire
} from './helpers/final-plain-wire';

const destination = Buffer.from('0014' + 'cd'.repeat(20), 'hex');
const zero = Buffer.alloc(32);

interface ISecretVectors {
	generation: { name: string; seed: string; index: string; output: string }[];
	storage: {
		name: string;
		inserts: { index: string; secret: string; output: 'OK' | 'ERROR' }[];
	}[];
}
const vectors = loadVectors<ISecretVectors>(
	'bolt03/per-commitment-secrets.json'
);
const sequence = (
	name: string
): { height: number; secret: Buffer; point: Buffer }[] =>
	vectors.storage
		.find((c) => c.name === name)!
		.inserts.map((i) => {
			const height = Number(MAX_INDEX - BigInt(i.index));
			const secret = hexToBuffer(i.secret);
			return { height, secret, point: getPublicKey(secret) };
		});
const correct = sequence('insert_secret correct sequence');
const derivedSeed = hexToBuffer(
	vectors.generation.find((g) => g.name === 'generate_from_seed FF final node')!
		.seed
);
const derived = (
	h: number
): { height: number; secret: Buffer; point: Buffer } => {
	const secret = generateFromSeed(derivedSeed, MAX_INDEX - BigInt(h));
	return { height: h, secret, point: getPublicKey(secret) };
};
const heights = (
	from: number,
	to: number
): { height: number; secret: Buffer; point: Buffer }[] =>
	Array.from({ length: to - from }, (_, i) => derived(from + i));

/** The BOLT 3 buckets of the given secrets, as rememberRevocation stores them. */
function buckets(secrets: { height: number; secret: Buffer }[]): Shachain {
	const out: Shachain = [];
	for (const { height, secret } of secrets) {
		const index = MAX_INDEX - BigInt(height);
		let bits = 0;
		while (bits < 48 && ((index >> BigInt(bits)) & 1n) === 0n) bits++;
		while (out.length < bits) out.push(null);
		out[bits] = { height, secret: secret.toString('hex') };
	}
	return out;
}

/** The secret device `peer` reveals for height h. */
function secretOf(
	devices: readonly ITypeDevice[],
	id: string,
	peer: number,
	h: number
): Buffer {
	const index =
		devices[peer].store.loadFinalOpeningSession(id)!.channelKeyIndex;
	return generateFromSeed(
		deriveChannelKeys(devices[peer].root, 1, index).perCommitmentSeed,
		MAX_INDEX - BigInt(h)
	);
}
const recordOf = (
	c: IConversion,
	i: number,
	shachain: Shachain
): IChannelTypeRecord => ({
	...c.inputs[i],
	seed: { ...c.inputs[i].seed, localPoints: localPointsOf(c, i), shachain }
});

describe('The peer shachain and the seeded plain ledger, pure (#2151 step 2a, item 4)', function () {
	this.timeout(120000);
	const s = scratch('channel-type-pure-');
	afterEach(() => s.release());
	const pure = (): ReturnType<typeof step2a> => step2a();

	it('computes the BOLT 3 buckets of the spec sequence at N = 0, 1, 2 and 7', () => {
		for (const n of [0, 1, 2, 7, 8])
			expect(
				pure().finalSeedShachain({
					secrets: correct.slice(0, n),
					stateNumber: n
				}),
				'N = ' + n
			).to.deep.equal(buckets(correct.slice(0, n)));
	});

	it('computes the buckets at N = 64 and across a bucket boundary, also from an earlier record', () => {
		expect(
			pure().finalSeedShachain({ secrets: heights(0, 64), stateNumber: 64 })
		).to.deep.equal(buckets(heights(0, 64)));
		// Height 15 fills bucket 4 and checks buckets 0 to 3, which the earlier record holds.
		const prior = pure().finalSeedShachain({
			secrets: heights(0, 13),
			stateNumber: 13
		});
		expect(prior).to.deep.equal(buckets(heights(0, 13)));
		const crossing = pure().finalSeedShachain({
			prior,
			secrets: heights(13, 17),
			stateNumber: 17
		});
		expect(crossing).to.deep.equal(buckets(heights(0, 17)));
		expect(crossing[4]).to.deep.equal({
			height: 15,
			secret: derived(15).secret.toString('hex')
		});
		expect(
			pure().finalSeedShachain({
				prior: pure().finalSeedShachain({
					secrets: heights(0, 5),
					stateNumber: 5
				}),
				secrets: heights(5, 64),
				stateNumber: 64
			})
		).to.deep.equal(buckets(heights(0, 64)));
	});

	it('refuses a missing height, also one that no bucket check would notice', () => {
		const run = (
			input: Parameters<ReturnType<typeof step2a>['finalSeedShachain']>[0]
		): Error =>
			expectRefusal(() => pure().finalSeedShachain(input), TEXT.missing);
		// Height 2 is derivable from height 3, so its bucket check alone passes.
		run({ secrets: [derived(0), derived(1), derived(3)], stateNumber: 4 });
		run({ secrets: heights(0, 3), stateNumber: 4 });
		run({ secrets: heights(1, 4), stateNumber: 4 });
		run({
			prior: buckets(heights(0, 4)),
			secrets: heights(5, 8),
			stateNumber: 8
		});
	});

	it('refuses a secret whose point is not the one recorded for its height', () => {
		const secrets = heights(0, 4);
		secrets[2] = { ...secrets[2], point: derived(3).point };
		expectRefusal(
			() => pure().finalSeedShachain({ secrets, stateNumber: 4 }),
			TEXT.mismatch
		);
	});

	it('refuses an inconsistent chain (the spec vectors)', () => {
		for (const name of [
			'insert_secret #1 incorrect',
			'insert_secret #3 incorrect'
		]) {
			const secrets = sequence(name);
			expectRefusal(
				() =>
					pure().finalSeedShachain({ secrets, stateNumber: secrets.length }),
				TEXT.inconsistent
			);
		}
	});

	it('bounds the state number below MAX_INDEX - 1 in the canonical form', async () => {
		const pair = await assetTypePair(s, 0);
		const c = buildConversion(pair.devices, pair.id, {
			type: 'plain',
			stateNumber: 0,
			parent: openingParent(pair.devices[0].store, pair.id)
		});
		const record = recordOf(c, 0, []);
		expect(pure().canonicalFinalChannelTypeRecord(record)).to.deep.equal(
			record
		);
		for (const n of [MAX_INDEX - 1n, MAX_INDEX, -1n])
			expectRefusal(() =>
				pure().canonicalFinalChannelTypeRecord({
					...record,
					stateNumber: String(n)
				})
			);
	});

	it('seeds the plain ledger at N from the record and the peer points', async () => {
		const pair = await assetTypePair(s, 1);
		const { id, devices } = pair;
		const c = buildConversion(devices, id, {
			type: 'plain',
			stateNumber: 1,
			parent: openingParent(devices[0].store, id)
		});
		const record = recordOf(
			c,
			0,
			buckets([{ height: 0, secret: secretOf(devices, id, 1, 0) }])
		);
		const seed = record.seed as IFinalPlainSeedInput & { shachain: Shachain };
		const opening = (
			devices[0].store as unknown as {
				finalOpeningRecord(id: string): {
					candidate: import('../../src/lightning/storage/final-opening-candidate').IFinalOpeningCandidate;
					nonces: IFinalOpeningNonces;
				};
			}
		).finalOpeningRecord(id);
		const state = pure().seedFinalLedger({
			candidate: opening.candidate,
			nonces: opening.nonces,
			record,
			peerPoints: [c.point(1, 1), c.point(1, 2)]
		});
		expect(state.funding).to.deep.equal(record.funding);
		expect(state.local).to.deep.include({
			height: 1,
			point: c.point(0, 1).toString('hex'),
			nextPoint: c.point(0, 2).toString('hex'),
			tx: seed.local.tx,
			signed: seed.local.signed,
			revoke: seed.localRevoke
		});
		expect(state.local.nextNonce).to.deep.equal(seed.local.nextNonce);
		expect(state.local.funds).to.deep.equal(seed.funds);
		expect(state.remote).to.deep.include({
			height: 1,
			point: c.point(1, 1).toString('hex'),
			nextPoint: c.point(1, 2).toString('hex'),
			tx: seed.remote.tx,
			revoke: seed.peerRevoke
		});
		expect(state.remote.nextNonce).to.deep.equal(seed.remote.nextNonce);
		expect(state.initialRemote).to.deep.equal(state.remote);
		expect(state.shachain).to.deep.equal(seed.shachain);
		expect(state.locked).to.deep.equal(seed.funds);
		expect(state).to.deep.include({
			waiting: [],
			deliveries: [],
			nextUpdate: 1,
			wireSequence: 0,
			nextLocalId: seed.nextLocalId,
			nextPeerId: seed.nextPeerId
		});
		expect(state.openingRecovery).to.equal(undefined);
		expect(state.inFlight).to.equal(undefined);
	});
});

/** A minimal manager over one device, enough for the exit and deadline paths. */
function exitManager(
	store: SqliteStorage,
	side: ITypeDevice,
	id: string,
	txid: string
): { manager: ChannelManager; broadcasts: Transaction[]; errors: string[] } {
	const manager = Object.assign(Object.create(ChannelManager.prototype), {
		config: { finalOpening: { storage: store, root: side.root } },
		assetCollateral: new Map(),
		// No watch is armed in 2a: the record's txid is injected as observed.
		finalObservedFunding: new Map([
			[id, new Map([[txid, { height: 101, parentAtDepth: true }]])]
		]),
		finalDepthByChannel: new Map([[id, new Set([txid])]]),
		finalObservedClose: new Map(),
		finalTransport: { closed: () => {} }
	}) as ChannelManager;
	const broadcasts: Transaction[] = [],
		errors: string[] = [];
	manager.on('broadcast:tx', (raw: Buffer) =>
		broadcasts.push(Transaction.fromBuffer(raw))
	);
	manager.on('error', (_id: Buffer | null, message: string) => {
		errors.push(message);
	});
	return { manager, broadcasts, errors };
}
/** The dispatcher's claims alone, as the node's chain watcher asks for them. */
function dispatchedOf(
	store: SqliteStorage,
	root: ITypeDevice['root'],
	id: string,
	parent: Transaction
): IFinalOutputClaim[] {
	return finalChannelOutputClaims(
		{ storage: store, root },
		Buffer.from(id, 'hex'),
		parent,
		destination,
		1,
		undefined,
		undefined,
		(cid) => store.loadFinalChannelKind(cid)
	);
}
async function assetSpliceRefusal(
	store: SqliteStorage,
	root: ITypeDevice['root'],
	id: string
): Promise<string> {
	const reported: string[] = [];
	const transport = new AssetSpliceTransport(
		{ storage: store, root },
		{} as AssetSpliceHost,
		() => true,
		() => true,
		() => 0,
		() => {},
		async () => 'unspent',
		() => {},
		() => {},
		(_id, reason) => {
			reported.push(reason);
		}
	);
	let message: string | undefined;
	try {
		await transport.start(id, { fundingFeeratePerkw: 253, minimumDepth: 3 });
	} catch (e) {
		message = (e as Error).message;
	}
	transport.destroy();
	return message ?? reported[0];
}
const feeUpdate = (id: string, feeratePerKw: number): Buffer =>
	encodeUpdateFeeMessage({ channelId: Buffer.from(id, 'hex'), feeratePerKw });
const txidOf = (raw: Buffer): Buffer => Transaction.fromBuffer(raw).ins[0].hash;

describe('A conversion to plain on real SQLite devices (#2151 step 2a, item 5)', function () {
	this.timeout(240000);
	const s = scratch('channel-type-to-plain-');
	afterEach(() => s.release());

	const toPlain = (k: number): Promise<IToPlain> => toPlainOf(s, k);
	/** One plain round at N + 1 each way, returning each revoke_and_ack. */
	function roundEachWay(t: Awaited<ReturnType<typeof toPlain>>): Buffer[] {
		const st = t.stores();
		const opener = st[0].loadFinalOpening(t.id)!.isInitiator ? 0 : 1;
		const wire = feeUpdate(t.id, 400);
		st[opener].stageFinalHtlcUpdate(t.id, 'local', M.UPDATE_FEE, wire);
		st[1 - opener].stageFinalHtlcUpdate(t.id, 'peer', M.UPDATE_FEE, wire);
		const acks: Buffer[] = [];
		for (const from of [opener, 1 - opener]) {
			const sig = st[from].signFinalUpdateCommitment(
				t.id,
				t.devices[from].root
			);
			const ack = st[1 - from].acceptFinalUpdateCommitment(
				t.id,
				t.devices[1 - from].root,
				sig
			);
			acks[1 - from] = ack;
			st[from].acceptFinalUpdateRevocation(t.id, ack);
		}
		for (const store of st)
			for (const event of store.loadFinalUpdateDeliveries(t.id))
				store.ackFinalUpdateDelivery(t.id, event.id);
		return acks;
	}

	it('runs as plain: takes plain updates and refuses asset updates and both kinds of splice', async () => {
		const t = await toPlain(1);
		for (const store of t.stores()) {
			expect(typed(store).loadFinalChannelType(t.id)!.type).to.equal('plain');
			const status = store.loadFinalUpdateStatus(t.id)!;
			expect([status.localHeight, status.remoteHeight]).to.deep.equal([1n, 1n]);
		}
		roundEachWay(t);
		const status = t.stores()[0].loadFinalUpdateStatus(t.id)!;
		expect([status.localHeight, status.remoteHeight]).to.deep.equal([2n, 2n]);
		const { store, root } = t.devices[0];
		expectRefusal(() =>
			store.assetSpliceUpdateBatch(
				t.id,
				root,
				3n,
				[{ kind: 'fee', feeratePerKw: 1300 }],
				() => 600000
			)
		);
		expectRefusal(() => store.finalSpliceSession(t.id, root), TEXT.splice);
		expect(await assetSpliceRefusal(store, root, t.id)).to.equal(TEXT.splice);
	});

	for (const k of [0, 2])
		it('reestablishes right after the record at N = ' + k, async () => {
			const t = await toPlain(k);
			const st = t.stores();
			const fields = st.map((store, i) =>
				store.finalUpdateReestablish(t.id, t.devices[i].root)
			);
			for (const [i, f] of fields.entries()) {
				expect(f.nextCommitmentNumber).to.equal(BigInt(k + 1));
				expect(f.nextRevocationNumber).to.equal(BigInt(k));
				expect(f.myCurrentPerCommitmentPoint).to.deep.equal(t.c.point(i, k));
				expect(f.yourLastPerCommitmentSecret).to.deep.equal(
					k ? secretOf(t.devices, t.id, 1 - i, k - 1) : zero
				);
				expect(f.nextLocalNonces![0].fundingTxid).to.deep.equal(
					t.c.tx.getHash()
				);
			}
			for (const i of [0, 1])
				expect(
					st[i].acceptFinalUpdateReestablish(
						t.id,
						t.devices[i].root,
						fields[1 - i]
					)
				).to.deep.equal([]);
			// Through the transports: the plain path, the live funding and no channel_ready.
			const wire = plainWire(st, t.sides, t.id);
			const seen: number[] = [];
			const push = wire.messages.push.bind(wire.messages);
			wire.messages.push = (...items): number => {
				seen.push(...items.map((m) => m.type));
				return push(...items);
			};
			for (const i of [0, 1]) {
				const peer = t.sides[1 - i].binding.nodeId;
				wire.sockets[i].disconnected(peer);
				wire.sockets[i].opened(peer, t.id, true);
			}
			const sent = wire.messages.filter(
				(m) => m.type === M.CHANNEL_REESTABLISH
			);
			expect(sent).to.have.length(2);
			for (const m of sent)
				expect(
					decodeChannelReestablishMessage(m.payload, { finalTaproot: true })
						.myCurrentFundingLocked?.txid
				).to.deep.equal(t.c.tx.getHash());
			await wire.drain();
			expect(wire.errors).to.deep.equal([]);
			expect(seen.filter((type) => type === M.CHANNEL_READY)).to.deep.equal([]);
			wire.destroy();
			roundEachWay(t);
		});

	it('completes a plain round at N + 1 each way, each revoke_and_ack on the seed points, and reestablishes after it', async () => {
		const k = 1;
		const t = await toPlain(k);
		const acks = roundEachWay(t);
		for (const i of [0, 1]) {
			const r = decodeRevokeAndAckMessage(acks[i], { finalTaproot: true });
			expect(getPublicKey(r.perCommitmentSecret)).to.deep.equal(
				t.c.point(i, k)
			);
			expect(r.nextPerCommitmentPoint).to.deep.equal(t.c.point(i, k + 2));
			expect(r.nextLocalNonces![0].fundingTxid).to.deep.equal(t.c.tx.getHash());
		}
		const st = t.stores();
		const fields = st.map((store, i) =>
			store.finalUpdateReestablish(t.id, t.devices[i].root)
		);
		for (const [i, f] of fields.entries()) {
			expect(f.nextCommitmentNumber).to.equal(BigInt(k + 2));
			expect(f.nextRevocationNumber).to.equal(BigInt(k + 1));
			expect(f.yourLastPerCommitmentSecret).to.deep.equal(
				secretOf(t.devices, t.id, 1 - i, k)
			);
		}
		for (const i of [0, 1])
			expect(
				st[i].acceptFinalUpdateReestablish(
					t.id,
					t.devices[i].root,
					fields[1 - i]
				)
			).to.deep.equal([]);
	});

	it('walks the resolution states from N', async () => {
		const k = 1;
		const t = await toPlain(k);
		const store = t.stores()[0];
		const at = store.loadFinalResolutionStates(t.id)!;
		expect(at.local.height).to.equal(BigInt(k));
		expect(at.revoked).to.deep.equal([]);
		roundEachWay(t);
		const after = store.loadFinalResolutionStates(t.id)!;
		expect(after.local.height).to.equal(BigInt(k + 1));
		expect(after.remote.map((r) => r.height)).to.deep.equal([BigInt(k + 1)]);
		expect(after.revoked.map((r) => r.height)).to.deep.equal([BigInt(k)]);
		expect(after.revoked[0].secret).to.deep.equal(
			secretOf(t.devices, t.id, 1, k)
		);
		expect(txidOf(after.revoked[0].tx)).to.deep.equal(t.c.tx.getHash());
	});

	it('exits by the plain commitment on the new funding, never by the opening or the asset parent', async () => {
		const t = await toPlain(0);
		const { store } = t.devices[0];
		const exit = store.loadFinalOpeningExit(t.id)!;
		expect(txidOf(exit)).to.deep.equal(t.c.tx.getHash());
		expect(Transaction.fromBuffer(exit).toHex()).to.equal(
			(t.c.inputs[0].seed as IFinalPlainSeedInput).local.tx
		);
		expect(
			store.loadFinalFundingExits(t.id).map((e) => e.fundingTxid)
		).to.deep.equal([t.c.tx.getHash()]);
		const { manager } = exitManager(store, t.devices[0], t.id, t.c.tx.getId());
		expect(
			(
				manager as unknown as {
					observedFinalExit(id: string): Buffer | undefined;
				}
			).observedFinalExit(t.id)
		).to.deep.equal(t.c.tx.getHash());
		expect(txidOf(store.requestFinalOpeningExit(t.id))).to.deep.equal(
			t.c.tx.getHash()
		);
	});

	it('force closes on the new funding at an HTLC deadline', async () => {
		const t = await toPlain(1);
		plainUpdates(t.stores(), t.sides, t.id).add(1100);
		const { store } = t.devices[0];
		const { manager, broadcasts, errors } = exitManager(
			store,
			t.devices[0],
			t.id,
			t.c.tx.getId()
		);
		manager.checkFinalHtlcDeadlines(1099, 10, 0);
		expect(broadcasts, 'before the deadline').to.deep.equal([]);
		manager.checkFinalHtlcDeadlines(1100, 10, 0);
		expect(errors).to.deep.equal([]);
		expect(broadcasts).to.have.length(1);
		expect(broadcasts[0].ins[0].hash).to.deep.equal(t.c.tx.getHash());
	});

	it("keeps the deadline exit after the parent is spent by the record's funding", async () => {
		const t = await toPlain(1);
		plainUpdates(t.stores(), t.sides, t.id).add(1100);
		const { store } = t.devices[0];
		const { manager, broadcasts, errors } = exitManager(
			store,
			t.devices[0],
			t.id,
			t.c.tx.getId()
		);
		Object.assign(
			(manager as unknown as { finalTransport: object }).finalTransport,
			{ fundingDepth: (): void => {}, assetFundingSpendable: (): void => {} }
		);
		// The conversion transaction spends the asset parent: a type change, not a close.
		expect(
			manager.handleFundingSpent(
				Buffer.from(t.id, 'hex'),
				t.c.tx,
				101,
				destination
			)
		).to.deep.equal([]);
		manager.checkFinalHtlcDeadlines(1100, 10, 0);
		expect(errors).to.deep.equal([]);
		expect(broadcasts).to.have.length(1);
		expect(broadcasts[0].ins[0].hash).to.deep.equal(t.c.tx.getHash());
	});

	it('refuses a peer reestablish one revocation behind the record', async () => {
		const k = 2;
		const t = await toPlain(k);
		const wire = plainWire(t.stores(), t.sides, t.id);
		for (const i of [0, 1]) {
			const peer = t.sides[1 - i].binding.nodeId;
			wire.sockets[i].disconnected(peer);
			wire.sockets[i].opened(peer, t.id, true);
		}
		const packet = wire.messages.find(
			(m) => m.from === 1 && m.type === M.CHANNEL_REESTABLISH
		)!;
		const msg = decodeChannelReestablishMessage(packet.payload, {
			finalTaproot: true
		});
		packet.payload = encodeChannelReestablishMessage({
			...msg,
			nextRevocationNumber: BigInt(k - 1),
			yourLastPerCommitmentSecret: secretOf(t.devices, t.id, 0, k - 2)
		});
		await wire.drain();
		expect(
			wire.errors.some((e) => e.includes(TEXT.behind)),
			wire.errors.join('; ')
		).to.equal(true);
		wire.destroy();
	});

	// Flipped by #2151 step 2b: a recorded channel is claimed by branch.
	it('claims the new exit by the plain builder and the asset parent by the asset builder (#2151 step 2b)', async () => {
		const t = await toPlain(1);
		const { store, root } = t.devices[0];
		const exits = store
			.loadFinalFundingExits(t.id)
			.map((e) => Transaction.fromBuffer(e.exit));
		expect(exits.map((e) => e.ins[0].hash)).to.deep.equal([t.c.tx.getHash()]);
		// Our plain commitment at N: to_local after its delay, with no asset reporting.
		const [plain] = exits.map((e) => dispatchedOf(store, root, t.id, e));
		expect(plain).to.have.length(1);
		expect(plain[0].tx, 'a signed to_local sweep').to.not.equal(null);
		expect(plain[0].relativeDelay).to.be.greaterThan(1);
		expect(plain[0].tx!.ins[0].hash).to.deep.equal(exits[0].getHash());
		expect(plain.some(assetReporting)).to.equal(false);
		// Our asset commitment of the parent at N: the asset builder's balance output.
		expect(t.parentExits).to.have.length(1);
		for (const exit of t.parentExits) {
			const claims = dispatchedOf(store, root, t.id, exit);
			expect(claims).to.have.length(1);
			expect(claims[0].assetBalanceOutput).to.equal(true);
			expect(claims[0].relativeDelay).to.be.greaterThan(1);
		}
	});

	it('closes cooperatively by spending the new funding', async () => {
		const t = await toPlain(1);
		const txs = closeCooperatively(t.stores(), t.sides, t.id);
		for (const raw of txs) expect(txidOf(raw)).to.deep.equal(t.c.tx.getHash());
	});
});

describe('A conversion to asset on real SQLite devices (#2151 step 2a, item 6)', function () {
	this.timeout(240000);
	const s = scratch('channel-type-to-asset-');
	afterEach(() => s.release());

	const toAsset = (k: number): IToAsset => toAssetOf(s, k);

	it('runs as asset: refuses plain updates and both kinds of splice', async () => {
		const t = toAsset(1);
		const { store, root } = t.devices[0];
		expect(typed(store).loadFinalChannelType(t.id)!.type).to.equal('asset');
		expect(store.loadFinalChannelKind(t.id)).to.equal('asset');
		expect(store.loadFinalUpdateStatus(t.id)).to.equal(null);
		expectRefusal(() =>
			store.stageFinalHtlcUpdate(
				t.id,
				'local',
				M.UPDATE_FEE,
				feeUpdate(t.id, 400)
			)
		);
		expectRefusal(() => store.signFinalUpdateCommitment(t.id, root));
		expectRefusal(() => store.finalSpliceSession(t.id, root), TEXT.splice);
		expect(await assetSpliceRefusal(store, root, t.id)).to.equal(TEXT.splice);
	});

	it('starts the asset history and head at N', () => {
		const k = 2;
		const t = toAsset(k);
		for (const { store } of t.devices) {
			const head = assetSpliceUpdateHead(store, t.id);
			expect(head.nextNumber).to.equal(BigInt(k + 1));
			expect(head.committed?.height).to.equal(String(k));
			const history = assetUpdateHistory(store, t.id);
			expect(history.latest?.height).to.equal(String(k));
			expect(history.stages.has(k + '/local-revoke')).to.equal(true);
			expect(history.stages.has(k + '/peer-revoke')).to.equal(true);
			expect([...history.states.keys()]).to.deep.equal([BigInt(k)]);
		}
	});

	for (const k of [0, 2])
		it('reestablishes right after the record at N = ' + k, () => {
			const t = toAsset(k);
			const fields = t.devices.map((d) =>
				d.store.assetSpliceReconnect(t.id, d.root, false)
			);
			for (const [i, f] of fields.entries()) {
				expect(f.nextCommitmentNumber).to.equal(BigInt(k + 1));
				expect(f.nextRevocationNumber).to.equal(BigInt(k));
				expect(f.yourLastPerCommitmentSecret).to.deep.equal(
					k ? secretOf(t.devices, t.id, 1 - i, k - 1) : zero
				);
				expect(
					f.nextLocalNonces?.map((n) => n.fundingTxid.toString('hex'))
				).to.deep.equal([t.c.tx.getHash().toString('hex')]);
			}
			for (const [i, d] of t.devices.entries())
				acceptAssetSpliceReestablish(d.store, t.id, d.root, fields[1 - i]);
		});

	it('completes an asset round at N + 1 with its revocation', async () => {
		const k = 1;
		const t = toAsset(k);
		await assetRounds(t.devices, t.id, k + 1);
		for (const [i, { store }] of t.devices.entries()) {
			expect(assetSpliceUpdateHead(store, t.id).committed?.height).to.equal(
				String(k + 1)
			);
			const revoke = assetUpdateHistory(store, t.id).stages.get(
				k + 1 + '/peer-revoke'
			)!;
			const r = decodeRevokeAndAckMessage(Buffer.from(revoke, 'hex'), {
				finalTaproot: true
			});
			expect(r.perCommitmentSecret).to.deep.equal(
				secretOf(t.devices, t.id, 1 - i, k)
			);
			expect(r.nextPerCommitmentPoint).to.deep.equal(t.c.point(1 - i, k + 2));
		}
	});

	it('exits by the asset commitment on the new funding', () => {
		const t = toAsset(0);
		const { store } = t.devices[0];
		const exit = store.loadFinalOpeningExit(t.id)!;
		expect(txidOf(exit)).to.deep.equal(t.c.tx.getHash());
		expect(
			store.loadFinalFundingExits(t.id).map((e) => e.fundingTxid)
		).to.deep.equal([t.c.tx.getHash()]);
	});

	// Flipped by #2151 step 2b: a recorded channel is claimed by branch.
	it('claims the new exit by the asset builder (#2151 step 2b)', () => {
		const t = toAsset(1);
		const { store, root } = t.devices[0];
		const [exit] = store
			.loadFinalFundingExits(t.id)
			.map((e) => Transaction.fromBuffer(e.exit));
		expect(exit.ins[0].hash).to.deep.equal(t.c.tx.getHash());
		const claims = dispatchedOf(store, root, t.id, exit);
		expect(claims).to.have.length(1);
		expect(claims[0].assetBalanceOutput).to.equal(true);
		expect(claims[0].relativeDelay).to.be.greaterThan(1);
	});
});
