/**
 * #2151 step 2b: claims and recovery by branch. A commitment published on
 * any funding output a channel has had is claimed by the rules of that
 * output's type and era: the opening, a record's funding, a splice's parent
 * and candidate, and a pending conversion's parent and candidate.
 *
 * The step's names are reached through `step2b()` in
 * helpers/channel-type-record.ts, so this file loads on a base without them.
 * The fixtures are 2a's (buildConversion, appendBoth) with the HTLC rounds
 * of this step (assetHtlcRound, plainHtlcRound), which add an HTLC in one
 * round and settle it in the next, so a revoked commitment holds the HTLC
 * and the ledger is quiescent when the record is appended. The asset
 * builder's host arguments are pinned against recordingHost(), whose
 * recoverOutput and recoverHtlc record their arguments and recover nothing.
 *
 * Every claim here is device 0's, of a commitment the peer (device 1) or
 * device 0 published.
 */
import { expect } from 'chai';
import type Database from 'better-sqlite3';
import path from 'path';
import { Transaction } from 'bitcoinjs-lib';
import {
	finalChannelOutputClaims,
	type IFinalOutputClaim
} from '../../src/lightning/chain/final-output-claims';
import type {
	IAssetOpeningPayout,
	IAuxiliaryDualFunding
} from '../../src/lightning/channel/asset-opening-provider';
import { encodeUpdateFeeMessage } from '../../src/lightning/message/channel-update';
import { MessageType as M } from '../../src/lightning/message/types';
import { assetUpdateFundingMembers } from '../../src/lightning/storage/asset-splice-exit-proofs';
import { assetUpdateHistory } from '../../src/lightning/storage/asset-update-history';
import { FinalDeviceJournal } from '../../src/lightning/storage/final-device-journal';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import sinon from 'sinon';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';
import {
	assetTypePair,
	plainTypePair,
	scratch,
	type IAssetTypePair,
	type IPlainTypePair
} from './helpers/channel-type-pairs';
import {
	appendBoth,
	assetHtlcRound,
	assetParentBranch,
	assetReporting,
	assetRounds,
	buildConversion,
	claimBytes,
	CONVERSION_DIGEST,
	conversionExits,
	exitOf,
	expectRefusal,
	openingParent,
	outpoint,
	plainHtlcRound,
	plainParentBranch,
	plainRounds,
	recordingHost,
	retainBoth,
	step2b,
	typed,
	valueOutputs,
	type IConversion,
	type IConversionExits,
	type IFinalAssetSeedInput,
	type IFinalChannelFunding,
	type IFinalExitBranch,
	type IFinalPlainSeedInput,
	type ITypeDevice
} from './helpers/channel-type-record';
import { plainWire } from './helpers/final-plain-wire';

const destination = Buffer.from('0014' + 'cd'.repeat(20), 'hex');

/** Device 0's claims through the dispatcher, as the node's chain watcher asks for them. */
function claimsOf(
	devices: readonly ITypeDevice[],
	id: string,
	parent: Transaction,
	provider?: IAuxiliaryDualFunding
): IFinalOutputClaim[] {
	const { store, root } = devices[0];
	return finalChannelOutputClaims(
		{ storage: store, root },
		Buffer.from(id, 'hex'),
		parent,
		destination,
		1,
		provider,
		undefined,
		(cid) => store.loadFinalChannelKind(cid)
	);
}
/** Run every recover a claim list carries, so a recording host sees its arguments. */
async function recoverAll(claims: readonly IFinalOutputClaim[]): Promise<void> {
	for (const c of claims) if (c.recover) await c.recover();
}
/** A plain-branch claim list: signed sweeps and no asset reporting. */
function expectPlain(claims: readonly IFinalOutputClaim[]): void {
	expect(claims.filter(assetReporting), 'asset reporting').to.deep.equal([]);
	for (const c of claims)
		if (c.paymentHash === undefined)
			expect(c.tx, 'output ' + c.outputIndex).to.not.equal(null);
}
/** An asset-branch claim list: every balance output carries the asset reporting. */
function expectAsset(claims: readonly IFinalOutputClaim[]): void {
	expect(claims.length).to.be.greaterThan(0);
	for (const c of claims)
		expect(assetReporting(c), 'output ' + c.outputIndex).to.equal(true);
}
/** Our output of the peer's current commitment, and nothing else. */
function expectOurOutput(
	claims: readonly IFinalOutputClaim[],
	parent: Transaction
): void {
	expect(claims).to.have.length(1);
	expect(claims[0].relativeDelay).to.equal(1);
	expect(valueOutputs(parent)).to.include(claims[0].outputIndex);
}
/** Our to_local of our own commitment, after its delay. */
function expectToLocal(
	claims: readonly IFinalOutputClaim[],
	parent: Transaction
): void {
	expect(claims).to.have.length(1);
	expect(claims[0].relativeDelay).to.be.greaterThan(1);
	expect(valueOutputs(parent)).to.include(claims[0].outputIndex);
	if (claims[0].tx) {
		expect(claims[0].tx.ins[0].hash).to.deep.equal(parent.getHash());
		expect(claims[0].tx.ins[0].sequence).to.equal(claims[0].relativeDelay);
	}
}
/** A penalty: every output that carries value is claimed, the peer's own ones at once. */
function expectPenalty(
	claims: readonly IFinalOutputClaim[],
	parent: Transaction
): void {
	expect(
		claims.map((c) => c.outputIndex).sort((a, b) => a - b),
		'every value output'
	).to.deep.equal(valueOutputs(parent));
	expect(
		claims.filter((c) => c.relativeDelay === 0).length,
		'claims of the peer outputs'
	).to.equal(claims.length - 1);
}
const tx = (hex: string): Transaction => Transaction.fromHex(hex);
const plainSeed = (c: IConversion, i: number): IFinalPlainSeedInput =>
	c.inputs[i].seed as IFinalPlainSeedInput;
const assetSeed = (c: IConversion, i: number): IFinalAssetSeedInput =>
	c.inputs[i].seed as IFinalAssetSeedInput;
/** The lineage entry an adopted asset splice's states receive today: the funding as an edge from its parent. */
function lineageOf(
	funding: Transaction,
	parent: { txid: string; outputIndex: number }
): unknown[] {
	return [
		{
			parentTxid: parent.txid,
			parentOutputIndex: parent.outputIndex,
			fundingTxid: funding.getId(),
			fundingOutputIndex: 0,
			fundingTxHex: funding.toHex()
		}
	];
}
function fundingOf(
	store: SqliteStorage,
	id: string,
	txid: string
): IFinalChannelFunding {
	const entry = step2b()
		.finalChannelFundings(store, id)
		.find((f) => f.txid === txid);
	expect(entry, 'a funding ' + txid).to.not.equal(undefined);
	return entry!;
}
function db(store: SqliteStorage): Database.Database {
	return (store as unknown as { db: Database.Database }).db;
}

describe('Fundings and branches (#2151 step 2b, item 1)', function () {
	this.timeout(240000);
	const s = scratch('branch-fundings-');
	afterEach(() => sinon.restore());
	afterEach(() => s.release());

	it("gives the opening's and a record's fundings their type, era and parent, and matches a spend to its branch", async () => {
		const pair = await assetTypePair(s, 1);
		const { id, devices } = pair;
		const opening = openingParent(devices[0].store, id);
		const parentPeer = exitOf(devices[1], id);
		const c = buildConversion(devices, id, {
			type: 'plain',
			stateNumber: 1,
			parent: opening
		});
		appendBoth(devices, c);
		const store = devices[0].store;
		const fundings = step2b().finalChannelFundings(store, id);
		expect(fundings).to.have.length(2);
		const first = fundingOf(store, id, opening.tx.getId());
		expect(first).to.deep.include({
			outputIndex: opening.index,
			type: 'asset',
			era: 0,
			source: 'opening'
		});
		expect(first.parent).to.equal(undefined);
		expect(fundingOf(store, id, c.tx.getId())).to.deep.include({
			outputIndex: 0,
			type: 'plain',
			era: 1,
			source: 'record',
			parent: outpoint(opening.tx, opening.index)
		});
		expect(step2b().finalSpendBranch(store, id, parentPeer)).to.deep.equal(
			first
		);
		expect(
			step2b().finalSpendBranch(store, id, tx(plainSeed(c, 1).local.tx))
		).to.deep.equal(fundingOf(store, id, c.tx.getId()));
		const unknown = new Transaction();
		unknown.addInput(Buffer.alloc(32, 0x42), 0);
		unknown.addOutput(destination, 1000);
		expect(step2b().finalSpendBranch(store, id, unknown)).to.equal(null);
	});

	it('gives a plain splice candidate the era and type of the funding it spends, before and after a record', async () => {
		const pair = plainTypePair(s, 0);
		const { id, devices, stores, sides } = pair;
		const opening = openingParent(stores[0], id);
		const wire = plainWire(stores, sides, id);
		const child = await wire.spliceOut();
		const candidate = (): IFinalChannelFunding =>
			fundingOf(stores[0], id, child.getId());
		expect(candidate()).to.deep.include({
			type: 'plain',
			era: 0,
			source: 'plain-splice',
			parent: outpoint(opening.tx, opening.index)
		});
		wire.adopt(child);
		wire.destroy();
		const live = stores[0].loadFinalActiveFunding(id)!;
		const c = buildConversion(devices, id, {
			type: 'asset',
			stateNumber: 0,
			parent: { tx: child, index: live.fundingOutputIndex }
		});
		appendBoth(devices, c);
		expect(candidate()).to.deep.include({
			outputIndex: live.fundingOutputIndex,
			type: 'plain',
			era: 0,
			source: 'plain-splice'
		});
		expect(fundingOf(stores[0], id, c.tx.getId())).to.deep.include({
			type: 'asset',
			era: 1,
			source: 'record',
			parent: outpoint(child, live.fundingOutputIndex)
		});
	});

	it("gives an asset splice's parent and candidate the opening's era and type", () => {
		const f = setupAssetSpliceProofs(s.dir(), undefined, 6);
		s.closing(() => f.devices.forEach((d) => d.store.close()));
		f.retain(0);
		const store = f.devices[0].store;
		const { parent, candidate } = f.evidence(0);
		expect(fundingOf(store, f.id, parent.fundingTxid)).to.deep.include({
			outputIndex: parent.outputIndex,
			type: 'asset',
			era: 0,
			source: 'opening'
		});
		expect(fundingOf(store, f.id, candidate.fundingTxid)).to.deep.include({
			outputIndex: candidate.outputIndex,
			type: 'asset',
			era: 0,
			source: 'asset-splice',
			parent: { txid: parent.fundingTxid, outputIndex: parent.outputIndex }
		});
		expect(
			step2b().finalSpendBranch(store, f.id, tx(candidate.remoteCommitment))
		).to.deep.include({ source: 'asset-splice', era: 0 });
	});

	it('gives a conversion candidate its own type and its digest in place of an era', async () => {
		const t = await pendingToPlain(s);
		retainBoth(t.devices, t.id, t.exits);
		const store = t.devices[0].store;
		const entry = fundingOf(store, t.id, t.c.tx.getId());
		expect(entry).to.deep.include({
			outputIndex: 0,
			type: 'plain',
			source: 'conversion',
			digest: CONVERSION_DIGEST,
			parent: outpoint(t.opening.tx, t.opening.index)
		});
		expect(entry.era).to.equal(undefined);
		expect(
			step2b().finalSpendBranch(
				store,
				t.id,
				tx(t.exits[1].candidate.localCommitment)
			)
		).to.deep.equal(entry);
	});

	it('takes the fast path with no decrypting read for a channel with no record or conversion row', async () => {
		const channels: (IAssetTypePair | IPlainTypePair)[] = [
			plainTypePair(s, 1),
			await assetTypePair(s, 1)
		];
		for (const pair of channels) {
			const parent = exitOf(pair.devices[1], pair.id);
			const read = sinon.spy(FinalDeviceJournal.prototype, 'read');
			const proto = SqliteStorage.prototype as unknown as Record<
				string,
				unknown
			>;
			const fundings =
				typeof proto.finalChannelFundings === 'function'
					? sinon.spy(
							proto as { finalChannelFundings(): unknown },
							'finalChannelFundings'
					  )
					: undefined;
			try {
				expect(claimsOf(pair.devices, pair.id, parent)).to.have.length(1);
				const scopes: string[] = read
					.getCalls()
					.map((c: { args: unknown[] }) => String(c.args[0]));
				expect(scopes.filter((x) => x === 'channel-type')).to.deep.equal([]);
				expect(scopes.filter((x) => x === 'conversion')).to.deep.equal([]);
				expect(fundings?.callCount ?? 0).to.equal(0);
			} finally {
				read.restore();
				fundings?.restore();
			}
		}
	});
});

/** An asset channel with an add-then-settle HTLC round, recorded to plain at N. */
async function recordedToPlain(s: ReturnType<typeof scratch>): Promise<{
	pair: IAssetTypePair;
	id: string;
	devices: ITypeDevice[];
	c: IConversion;
	n: number;
	opening: ReturnType<typeof openingParent>;
	parentPeer: Transaction;
	revokedHtlc: Transaction;
	digestAtN: string;
	paymentHash: Buffer;
}> {
	const pair = await assetTypePair(s, 0);
	const { id, devices } = pair;
	let revokedHtlc: Transaction | undefined;
	const htlc = await assetHtlcRound(devices, id, {
		added: () => {
			revokedHtlc = exitOf(devices[1], id);
		}
	});
	const n = Number(htlc.settled);
	const opening = openingParent(devices[0].store, id);
	const parentPeer = exitOf(devices[1], id);
	const digestAtN = assetUpdateHistory(devices[0].store, id).states.get(
		BigInt(n)
	)!.digest;
	const c = buildConversion(devices, id, {
		type: 'plain',
		stateNumber: n,
		parent: opening
	});
	appendBoth(devices, c);
	return {
		pair,
		id,
		devices,
		c,
		n,
		opening,
		parentPeer,
		revokedHtlc: revokedHtlc!,
		digestAtN,
		paymentHash: htlc.paymentHash
	};
}

describe('To plain, after a record at N (#2151 step 2b, item 3)', function () {
	this.timeout(300000);
	const s = scratch('branch-to-plain-');
	afterEach(() => s.release());

	it('claims our output of the peer plain commitment at N and our to_local of ours, by the plain builder', async () => {
		const t = await recordedToPlain(s);
		const recorded = recordingHost();
		const peer = tx(plainSeed(t.c, 1).local.tx);
		const theirs = claimsOf(t.devices, t.id, peer, recorded.host);
		expectOurOutput(theirs, peer);
		expectPlain(theirs);
		const ours = tx(plainSeed(t.c, 0).local.tx);
		const own = claimsOf(t.devices, t.id, ours, recorded.host);
		expectToLocal(own, ours);
		expectPlain(own);
		expect(recorded.outputs).to.deep.equal([]);
		expect(recorded.htlcs).to.deep.equal([]);
	});

	it("punishes the peer's asset commitment of the parent at N with the plain era's secret, by the asset builder", async () => {
		const t = await recordedToPlain(s);
		// Before the plain round at N + 1 the peer has not revealed N: our output only.
		const before = claimsOf(t.devices, t.id, t.parentPeer);
		expectOurOutput(before, t.parentPeer);
		expectAsset(before);
		plainRounds(t.devices, t.id, 1, () => 400);
		const recorded = recordingHost();
		const claims = claimsOf(t.devices, t.id, t.parentPeer, recorded.host);
		expectPenalty(claims, t.parentPeer);
		expectAsset(claims);
		await recoverAll(claims);
		expect(recorded.outputs).to.have.length(2);
		// Today's arguments for the old asset era: the opening's lineage and its round at N.
		for (const ctx of recorded.outputs) {
			expect(ctx.walletGeneration).to.equal(5);
			expect(ctx.holder).to.equal('remote');
			expect(ctx.fundingLineage).to.deep.equal([]);
			expect(ctx.splice).to.equal(undefined);
			expect(ctx.update).to.deep.equal({
				roundDigest: t.digestAtN,
				stateNumber: String(t.n),
				fundingTxid: t.opening.tx.getId(),
				fundingOutputIndex: t.opening.index
			});
		}
		expect(recorded.outputs.filter((o) => o.revocation)).to.have.length(1);
	});

	it('punishes a revoked asset commitment below N that holds the HTLC, its HTLC output included', async () => {
		const t = await recordedToPlain(s);
		const recorded = recordingHost();
		const claims = claimsOf(t.devices, t.id, t.revokedHtlc, recorded.host);
		expectPenalty(claims, t.revokedHtlc);
		expectAsset(claims);
		expect(
			claims.filter((c) => c.paymentHash?.equals(t.paymentHash)),
			'the HTLC output'
		).to.have.length(1);
		await recoverAll(claims);
		expect(recorded.htlcs.map((h) => h.kind)).to.deep.equal([
			'htlc_revocation'
		]);
		expect(recorded.outputs.filter((o) => o.revocation)).to.have.length(1);
	});
});

/** A plain channel with an add-then-settle HTLC round, recorded to asset at N. */
function recordedToAsset(s: ReturnType<typeof scratch>): {
	pair: IPlainTypePair;
	id: string;
	devices: ITypeDevice[];
	c: IConversion;
	n: number;
	opening: ReturnType<typeof openingParent>;
	parentPeer: Transaction;
	revokedHtlc: Transaction;
} {
	const pair = plainTypePair(s, 0);
	const { id, devices } = pair;
	let revokedHtlc: Transaction | undefined;
	const htlc = plainHtlcRound(devices, id, {
		added: () => {
			revokedHtlc = exitOf(devices[1], id);
		}
	});
	const n = Number(htlc.settled);
	const opening = openingParent(devices[0].store, id);
	const parentPeer = exitOf(devices[1], id);
	const c = buildConversion(devices, id, {
		type: 'asset',
		stateNumber: n,
		parent: opening
	});
	appendBoth(devices, c);
	return {
		pair,
		id,
		devices,
		c,
		n,
		opening,
		parentPeer,
		revokedHtlc: revokedHtlc!
	};
}
/** The host arguments of a seeded asset era's commitment held by the peer (section 5, A5). */
function expectSeededEra(
	ctx: IAssetOpeningPayout,
	t: ReturnType<typeof recordedToAsset>,
	update: { roundDigest: string; stateNumber: string }
): void {
	const member = assetSeed(t.c, 0).members[0];
	expect(ctx.walletGeneration).to.equal(5);
	expect(ctx.holder).to.equal('remote');
	expect(ctx.fundingLineage).to.deep.equal(
		lineageOf(t.c.tx, outpoint(t.opening.tx, t.opening.index))
	);
	expect(ctx.fundingProofs.toString('hex')).to.equal(member.fundingProofs);
	expect(ctx.exitProofs.toString('hex')).to.equal(member.remoteProofs);
	expect(ctx.splice).to.equal(undefined);
	expect(ctx.update).to.deep.equal({
		...update,
		fundingTxid: t.c.tx.getId(),
		fundingOutputIndex: 0
	});
	expect(ctx.virtualPayout).to.deep.include({
		channelId: t.id,
		fundingTxid: t.c.tx.getId(),
		fundingOutputIndex: 0,
		stateNumber: update.stateNumber
	});
	expect(ctx.candidate).to.deep.equal(
		t.devices[0].store.loadFinalOpening(t.id)
	);
}

describe('To asset, after a record at N (#2151 step 2b, item 4)', function () {
	this.timeout(300000);
	const s = scratch('branch-to-asset-');
	afterEach(() => s.release());

	it('claims the peer asset commitment at N by the asset builder, with the seeded era host arguments', async () => {
		const t = recordedToAsset(s);
		const recorded = recordingHost();
		const peer = tx(assetSeed(t.c, 1).members[0].localCommitment);
		const claims = claimsOf(t.devices, t.id, peer, recorded.host);
		expectOurOutput(claims, peer);
		expectAsset(claims);
		await recoverAll(claims);
		expect(recorded.outputs).to.have.length(1);
		expectSeededEra(recorded.outputs[0], t, {
			roundDigest: assetSeed(t.c, 0).digest,
			stateNumber: String(t.n)
		});
		const ours = tx(assetSeed(t.c, 0).members[0].localCommitment);
		const own = claimsOf(t.devices, t.id, ours);
		expectToLocal(own, ours);
		expectAsset(own);
	});

	it('after an asset round at N + 1, claims that round as the seeded era and punishes the plain parent and a revoked HTLC commitment', async () => {
		const t = recordedToAsset(s);
		await assetRounds(t.devices, t.id, t.n + 1);
		const recorded = recordingHost();
		const current = exitOf(t.devices[1], t.id);
		const claims = claimsOf(t.devices, t.id, current, recorded.host);
		expectOurOutput(claims, current);
		await recoverAll(claims);
		expectSeededEra(recorded.outputs[0], t, {
			roundDigest: assetUpdateHistory(t.devices[0].store, t.id).states.get(
				BigInt(t.n + 1)
			)!.digest,
			stateNumber: String(t.n + 1)
		});
		// The plain parent commitment at N, revoked by the asset era's secret for N.
		const parent = claimsOf(t.devices, t.id, t.parentPeer);
		expectPenalty(parent, t.parentPeer);
		expectPlain(parent);
		// The plain commitment that held the HTLC, below N.
		const htlc = claimsOf(t.devices, t.id, t.revokedHtlc);
		expectPenalty(htlc, t.revokedHtlc);
		expectPlain(htlc);
		expect(htlc.filter((c) => c.paymentHash)).to.have.length(1);
	});
});

describe('Two records back (#2151 step 2b, item 5)', function () {
	this.timeout(300000);
	const s = scratch('branch-two-records-');
	afterEach(() => s.release());

	it('punishes a revoked era-0 asset commitment and revoked era-1 plain commitments, each by its own builder and views', async () => {
		const pair = await assetTypePair(s, 0);
		const { id, devices } = pair;
		const era0 = exitOf(devices[1], id);
		await assetRounds(devices, id, 1);
		const first = buildConversion(devices, id, {
			type: 'plain',
			stateNumber: 1,
			parent: openingParent(devices[0].store, id)
		});
		appendBoth(devices, first);
		const era1AtN = tx(plainSeed(first, 1).local.tx);
		plainRounds(devices, id, 1, () => 400);
		const era1Last = exitOf(devices[1], id);
		const second = buildConversion(
			devices,
			id,
			{ type: 'asset', stateNumber: 2, parent: { tx: first.tx, index: 0 } },
			'plain'
		);
		appendBoth(devices, second);
		await assetRounds(devices, id, 3);

		const asset = claimsOf(devices, id, era0);
		expectPenalty(asset, era0);
		expectAsset(asset);
		for (const plain of [era1AtN, era1Last]) {
			const claims = claimsOf(devices, id, plain);
			expectPenalty(claims, plain);
			expectPlain(claims);
		}
		// Each era's views: the plain era from its seed to its last state on its own funding.
		const store = devices[0].store;
		const era1 = step2b().loadFinalEraResolutionStates(store, id, 1)!;
		expect(era1.local.height).to.equal(2n);
		expect(Transaction.fromBuffer(era1.local.tx).ins[0].hash).to.deep.equal(
			first.tx.getHash()
		);
		expect([
			...step2b().assetEraHistory(store, id, 0).states.keys()
		]).to.deep.equal([1n]);
		expect([
			...step2b().assetEraHistory(store, id, 2).states.keys()
		]).to.deep.equal([2n, 3n]);
	});
});

interface IPending {
	pair: IAssetTypePair | IPlainTypePair;
	id: string;
	devices: ITypeDevice[];
	c: IConversion;
	n: number;
	opening: ReturnType<typeof openingParent>;
	parents: IFinalExitBranch[];
	exits: [IConversionExits, IConversionExits];
	/** Device 0's signed exit of the parent before the conversion was retained. */
	parentOurs: Transaction;
	/** The peer's current commitment of the parent, and device 0's claims of it before the retain. */
	parentPeer: Transaction;
	parentClaims: unknown[];
}
/** An asset channel at k = 1 with a pending conversion to plain on its opening. */
async function pendingToPlain(
	s: ReturnType<typeof scratch>
): Promise<IPending> {
	const pair = await assetTypePair(s, 1);
	return pending(pair, 'plain', (d) => assetParentBranch(d.store, pair.id, 1));
}
/** A plain channel at k = 1 with a pending conversion to asset on its opening. */
function pendingToAsset(s: ReturnType<typeof scratch>): IPending {
	const pair = plainTypePair(s, 1);
	return pending(pair, 'asset', (d) => plainParentBranch(d.store, pair.id));
}
function pending(
	pair: IAssetTypePair | IPlainTypePair,
	type: 'plain' | 'asset',
	parentOf: (d: ITypeDevice) => IFinalExitBranch
): IPending {
	const { id, devices } = pair;
	const n = 1;
	const opening = openingParent(devices[0].store, id);
	const parentPeer = exitOf(devices[1], id);
	const parentOurs = exitOf(devices[0], id);
	const parentClaims = claimBytes(claimsOf(devices, id, parentPeer));
	const c = buildConversion(devices, id, {
		type,
		stateNumber: n,
		parent: opening
	});
	const parents = devices.map(parentOf);
	return {
		pair,
		id,
		devices,
		c,
		n,
		opening,
		parents,
		exits: conversionExits(devices, c, parents),
		parentOurs,
		parentPeer,
		parentClaims
	};
}
const copy = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** What the asset readers see of a channel, which the conversion rows must not change. */
function assetView(store: SqliteStorage, id: string): Record<string, unknown> {
	const attempt = (f: () => unknown): unknown => {
		try {
			return f();
		} catch (e) {
			return 'throws: ' + (e as Error).message;
		}
	};
	return {
		history: attempt(() => assetUpdateHistory(store, id)),
		fundingInfo: attempt(() => store.loadAssetSpliceFundingInfo(id)),
		journal: attempt(() => store.readAssetSpliceJournal(id).records),
		members: attempt(() => {
			const latest = assetUpdateHistory(store, id).latest;
			return latest ? assetUpdateFundingMembers(store, id, latest) : null;
		})
	};
}

for (const direction of ['to plain', 'to asset'] as const)
	describe(
		'A pending conversion ' + direction + ' (#2151 step 2b, item 6)',
		function () {
			this.timeout(300000);
			const s = scratch('branch-pending-');
			afterEach(() => s.release());
			const setup = async (): Promise<IPending> =>
				direction === 'to plain' ? pendingToPlain(s) : pendingToAsset(s);
			const candidateType = direction === 'to plain' ? 'plain' : 'asset';

			it('retains the exits once, a second retain of the same bytes being a no-op, and a release once', async () => {
				const t = await setup();
				retainBoth(t.devices, t.id, t.exits);
				const { store, root } = t.devices[0];
				step2b().retainFinalConversionExits(
					store,
					t.id,
					copy(t.exits[0]),
					root
				);
				step2b().releaseFinalConversionExits(store, t.id, CONVERSION_DIGEST);
				step2b().releaseFinalConversionExits(store, t.id, CONVERSION_DIGEST);
			});

			it('refuses each exit the contract names', async () => {
				const t = await setup();
				const { store, root } = t.devices[0];
				const retain = (exits: IConversionExits): void => {
					step2b().retainFinalConversionExits(store, t.id, exits, root);
				};
				const plainBranch = (e: IConversionExits): IFinalExitBranch =>
					e.parent.type === 'plain' ? e.parent : e.candidate;
				const assetBranch = (e: IConversionExits): IFinalExitBranch =>
					e.parent.type === 'asset' ? e.parent : e.candidate;
				const cases: [string, (e: IConversionExits) => IConversionExits][] = [
					[
						'a parent of another type than the current one',
						(e): IConversionExits => ({
							...e,
							parent: e.candidate,
							candidate: e.parent
						})
					],
					[
						'a candidate of the same type',
						(e): IConversionExits => ({ ...e, candidate: e.parent })
					],
					[
						'a parent that is not the live funding',
						(e): IConversionExits => ({
							...e,
							parent: { ...e.parent, fundingTxid: 'ab'.repeat(32) }
						})
					],
					[
						'another state number',
						(e): IConversionExits => ({ ...e, stateNumber: String(t.n + 1) })
					],
					[
						'a plain commitment the plain builder does not rebuild',
						(e): IConversionExits => {
							const b = plainBranch(e);
							const changed = {
								...b,
								remoteCommitment:
									b === e.candidate
										? t.c.view(0, 'remote', { feerate: 999 }).tx.toHex()
										: e.candidate.remoteCommitment
							};
							return b === e.parent
								? { ...e, parent: changed }
								: { ...e, candidate: changed };
						}
					],
					[
						'an asset branch failing the asset branch checks',
						(e): IConversionExits => {
							const b = assetBranch(e);
							const changed = { ...b, fundingRoot: '00' };
							return b === e.parent
								? { ...e, parent: changed }
								: { ...e, candidate: changed };
						}
					],
					[
						"parent commitments other than the current ledger's",
						(e): IConversionExits => ({
							...e,
							parent: {
								...e.parent,
								localCommitment: e.parent.remoteCommitment
							}
						})
					]
				];
				if (direction === 'to plain')
					cases.push([
						'a plain candidate whose local witness does not verify',
						(e): IConversionExits => ({
							...e,
							candidate: {
								...e.candidate,
								localCommitment: t.c.view(0, 'local').tx.toHex()
							}
						})
					]);
				for (const [why, change] of cases) {
					let refused: Error | undefined;
					try {
						retain(change(copy(t.exits[0])));
					} catch (e) {
						refused = e as Error;
					}
					expect(refused, why).to.be.instanceOf(Error);
					expect(refused!.message, why).to.not.match(
						/is not a function|Cannot read propert|is not defined/
					);
				}
				// A candidate that does not spend the parent.
				const elsewhere = new Transaction();
				elsewhere.addInput(Buffer.alloc(32, 7), 0);
				const out = t.opening.tx.outs[t.opening.index];
				elsewhere.addOutput(out.script, out.value);
				const stray = buildConversion(t.devices, t.id, {
					type: candidateType,
					stateNumber: t.n,
					parent: { tx: elsewhere, index: 0 }
				});
				expectRefusal(() =>
					retain(conversionExits(t.devices, stray, t.parents)[0])
				);
				// A candidate funding on an unallocated key index.
				const unallocated = buildConversion(t.devices, t.id, {
					type: candidateType,
					stateNumber: t.n,
					parent: t.opening,
					keyIndices: [9999, 9999]
				});
				expectRefusal(() =>
					retain(conversionExits(t.devices, unallocated, t.parents)[0])
				);
				// A candidate funding equal to an earlier funding of the channel: the opening.
				const reused = copy(t.exits[0]);
				reused.candidate = {
					...reused.candidate,
					funding: copy(reused.parent.funding),
					fundingTxid: reused.parent.fundingTxid,
					outputIndex: reused.parent.outputIndex
				};
				expectRefusal(() => retain(reused));
				// Inside a transaction.
				expectRefusal(() =>
					db(store).transaction(() => retain(copy(t.exits[0])))()
				);
				// The same digest with other bytes, a second pending conversion, an unknown release.
				retain(copy(t.exits[0]));
				const other = copy(t.exits[0]);
				other.candidate.minimumDepth += 1;
				expectRefusal(() => retain(other));
				expectRefusal(() =>
					retain({ ...copy(t.exits[0]), digest: 'd2'.repeat(32) })
				);
				expectRefusal(() =>
					step2b().releaseFinalConversionExits(store, t.id, 'd3'.repeat(32))
				);
			});

			it('refuses a ledger that is not quiescent', async () => {
				const t = await setup();
				const { store, root } = t.devices[0];
				if (direction === 'to plain')
					store
						.assetSpliceUpdateBatch(
							t.id,
							root,
							BigInt(t.n + 1),
							[{ kind: 'fee', feeratePerKw: 1300 }],
							() => 600000
						)
						.offer();
				else
					store.stageFinalHtlcUpdate(
						t.id,
						'local',
						M.UPDATE_FEE,
						encodeUpdateFeeMessage({
							channelId: Buffer.from(t.id, 'hex'),
							feeratePerKw: 400
						})
					);
				expectRefusal(() =>
					step2b().retainFinalConversionExits(store, t.id, t.exits[0], root)
				);
			});

			it('refuses generations 1 to 5 and a generation 6 copy', async () => {
				const t = await setup();
				const backupFile = path.join(s.dir(), 'copy.db');
				await t.devices[0].store.backup(backupFile);
				const binding =
					'bindings' in t.pair ? t.pair.bindings[0] : t.pair.sides[0].binding;
				const backup = SqliteStorage.openFinalWallet(backupFile, binding);
				s.closing(() => backup.close());
				expectRefusal(() =>
					step2b().retainFinalConversionExits(
						backup,
						t.id,
						t.exits[0],
						t.devices[0].root
					)
				);
				const older =
					direction === 'to plain'
						? await assetTypePair(s, 1, 5)
						: plainTypePair(s, 1, 2);
				const c = buildConversion(older.devices, older.id, {
					type: candidateType,
					stateNumber: 1,
					parent: openingParent(older.devices[0].store, older.id)
				});
				const parents = older.devices.map((d) =>
					direction === 'to plain'
						? assetParentBranch(d.store, older.id, 1)
						: plainParentBranch(d.store, older.id)
				);
				expectRefusal(() =>
					retainBoth(
						older.devices,
						older.id,
						conversionExits(older.devices, c, parents)
					)
				);
			});

			it('offers only the parent exit before release and both after, selected by outpoint', async () => {
				const t = await setup();
				const { store } = t.devices[0];
				retainBoth(t.devices, t.id, t.exits);
				const txids = (): string[] =>
					store
						.loadFinalFundingExits(t.id)
						.map((e) => Buffer.from(e.fundingTxid).reverse().toString('hex'))
						.sort();
				expect(txids()).to.deep.equal([t.opening.tx.getId()]);
				for (const d of t.devices)
					step2b().releaseFinalConversionExits(
						d.store,
						t.id,
						CONVERSION_DIGEST
					);
				expect(txids()).to.deep.equal(
					[t.opening.tx.getId(), t.c.tx.getId()].sort()
				);
				const candidateExit = store
					.loadFinalFundingExits(t.id)
					.find((e) => e.fundingTxid.equals(t.c.tx.getHash()))!;
				expect(candidateExit.exit.toString('hex')).to.equal(
					t.exits[0].candidate.localCommitment
				);
				expect(
					step2b().selectedFinalExit(store, t.id, t.c.tx.getHash(), 0)
				).to.equal(t.exits[0].candidate.localCommitment);
				expect(
					step2b().selectedFinalExit(
						store,
						t.id,
						t.opening.tx.getHash(),
						t.opening.index
					)
				).to.equal(t.parentOurs.toHex());
			});

			it('claims a commitment on either outpoint by its own type, released or not, the parent byte for byte as without a branch', async () => {
				const t = await setup();
				retainBoth(t.devices, t.id, t.exits);
				const peerCandidate = tx(t.exits[1].candidate.localCommitment);
				const ourCandidate = tx(t.exits[0].candidate.localCommitment);
				for (const released of [false, true]) {
					if (released)
						for (const d of t.devices)
							step2b().releaseFinalConversionExits(
								d.store,
								t.id,
								CONVERSION_DIGEST
							);
					const why = released ? 'released' : 'pending';
					const recorded = recordingHost();
					const theirs = claimsOf(
						t.devices,
						t.id,
						peerCandidate,
						recorded.host
					);
					const own = claimsOf(t.devices, t.id, ourCandidate);
					expectOurOutput(theirs, peerCandidate);
					expectToLocal(own, ourCandidate);
					if (candidateType === 'plain') {
						expectPlain(theirs);
						expectPlain(own);
					} else {
						expectAsset(theirs);
						expectAsset(own);
						await recoverAll(theirs);
						expect(recorded.outputs, why).to.have.length(1);
						const ctx = recorded.outputs[0];
						const branch = t.exits[0].candidate as IFinalExitBranch & {
							fundingProofs: string;
							remoteProofs: string;
						};
						expect(ctx.walletGeneration).to.equal(5);
						expect(ctx.fundingLineage, why).to.deep.equal(
							lineageOf(t.c.tx, outpoint(t.opening.tx, t.opening.index))
						);
						expect(ctx.fundingProofs.toString('hex')).to.equal(
							branch.fundingProofs
						);
						expect(ctx.exitProofs.toString('hex')).to.equal(
							branch.remoteProofs
						);
						expect(ctx.update).to.equal(undefined);
						expect(ctx.splice, why).to.deep.equal({
							finalDigest: CONVERSION_DIGEST,
							stateNumber: String(t.n),
							generation: 'candidate',
							fundingTxid: t.c.tx.getId(),
							fundingOutputIndex: 0
						});
						expect(ctx.candidate).to.deep.equal(
							t.devices[0].store.loadFinalOpening(t.id)
						);
					}
					expect(
						claimBytes(claimsOf(t.devices, t.id, t.parentPeer)),
						why + ' parent'
					).to.deep.equal(t.parentClaims);
				}
			});

			it('keeps the conversion rows out of every asset reader, and a later record of the candidate admissible', async () => {
				const t = await setup();
				const before = t.devices.map((d) => assetView(d.store, t.id));
				retainBoth(t.devices, t.id, t.exits);
				expect(t.devices.map((d) => assetView(d.store, t.id))).to.deep.equal(
					before
				);
				for (const i of [0, 1]) t.pair.restart(i);
				expect(t.devices.map((d) => assetView(d.store, t.id))).to.deep.equal(
					before
				);
				appendBoth(t.devices, t.c);
				for (const d of t.devices)
					expect(typed(d.store).loadFinalChannelType(t.id)!.type).to.equal(
						candidateType
					);
			});
		}
	);
