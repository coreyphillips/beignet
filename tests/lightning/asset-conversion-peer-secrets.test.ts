/**
 * #2151 step 2b, item 2: the peer's revocation secrets, looked up per height
 * in one reader over the records' shachains, the plain log and the asset
 * journal.
 *
 * The readers are private SqliteStorage methods (amendment v2.1), reached
 * through the loose view `step2b()` of helpers/channel-type-record.ts:
 * loadFinalPeerSecret(channelId, height, point) gives { secret, conflict }
 * and loadFinalPeerSecrets(channelId) the whole map. Heights are passed as
 * bigint.
 *
 * A disagreement between sources cannot be written through a public path,
 * since the record's writer checks its shachain. The test makes one by
 * changing the single shachain bucket of a record at N = 1 as the device
 * journal hands it out, so the record's secret for height 0 differs from the
 * asset journal's.
 */
import { expect } from 'chai';
import sinon from 'sinon';
import { Transaction } from 'bitcoinjs-lib';
import { finalChannelOutputClaims } from '../../src/lightning/chain/final-output-claims';
import { decodeRevokeAndAckMessage } from '../../src/lightning/message/channel-commitment';
import { assetUpdateHistory } from '../../src/lightning/storage/asset-update-history';
import { FinalDeviceJournal } from '../../src/lightning/storage/final-device-journal';
import type { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { finalTestNode } from './helpers/asset-conversion-node';
import {
	assetTypePair,
	plainTypePair,
	scratch,
	type IAssetTypePair
} from './helpers/channel-type-pairs';
import {
	appendBoth,
	assetRounds,
	buildConversion,
	exitOf,
	expectRefusal,
	openingParent,
	plainRounds,
	revealedSecret,
	step2b,
	valueOutputs,
	type IChannelTypeRecord,
	type ITypeDevice
} from './helpers/channel-type-record';

const destination = Buffer.from('0014' + 'cd'.repeat(20), 'hex');
const other = Buffer.from(
	'02' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	'hex'
);

/** Today's peer secrets of a plain channel: its resolution states' revoked heights. */
function plainSecrets(store: SqliteStorage, id: string): Map<bigint, Buffer> {
	const states = store.loadFinalResolutionStates(id)!;
	return new Map(states.revoked.map((r) => [r.height, r.secret!]));
}
/** Today's peer secrets of an asset channel: each `h/peer-revoke` stage reveals height h - 1. */
function assetSecrets(store: SqliteStorage, id: string): Map<bigint, Buffer> {
	const out = new Map<bigint, Buffer>();
	for (const [stage, wire] of assetUpdateHistory(store, id).stages) {
		const [height, kind] = stage.split('/');
		if (kind !== 'peer-revoke') continue;
		const msg = decodeRevokeAndAckMessage(Buffer.from(wire, 'hex'), {
			finalTaproot: true
		});
		out.set(BigInt(height) - 1n, msg.perCommitmentSecret);
	}
	return out;
}
/** Every height below `to` resolves to the peer's secret for it, from device 0. */
function expectResolved(
	devices: readonly ITypeDevice[],
	id: string,
	to: number
): void {
	const store = devices[0].store;
	for (let h = 0; h < to; h++) {
		const { secret, point } = revealedSecret(devices, id, 1, h);
		expect(
			step2b().loadFinalPeerSecret(store, id, BigInt(h), point),
			'height ' + h
		).to.deep.equal({ secret, conflict: false });
		expect(
			step2b().loadFinalPeerSecret(store, id, BigInt(h), other).secret,
			'height ' + h + ' under another point'
		).to.equal(null);
	}
	const current = revealedSecret(devices, id, 1, to);
	expect(
		step2b().loadFinalPeerSecret(store, id, BigInt(to), current.point).secret,
		'the unrevealed height ' + to
	).to.equal(null);
	expect(
		[...step2b().loadFinalPeerSecrets(store, id).entries()].sort((a, b) =>
			a[0] < b[0] ? -1 : 1
		)
	).to.deep.equal(
		Array.from({ length: to }, (_, h) => [
			BigInt(h),
			revealedSecret(devices, id, 1, h).secret
		])
	);
}
/** Counts the device-journal reads by scope while `run` runs. */
function journalReads(run: () => void): string[] {
	const read = sinon.spy(FinalDeviceJournal.prototype, 'read');
	try {
		run();
		return read.getCalls().map((c: { args: unknown[] }) => String(c.args[0]));
	} finally {
		read.restore();
	}
}

describe("The peer secret store keeps today's secrets (#2151 step 2b, item 2)", function () {
	this.timeout(240000);
	const s = scratch('peer-secrets-guard-');
	afterEach(() => s.release());

	for (const g of [2, 6] as const)
		it('gives a generation ' + g + " plain channel's revoked heights", () => {
			const pair = plainTypePair(s, 2, g);
			const store = pair.stores[0];
			const today = plainSecrets(store, pair.id);
			expect([...today.keys()]).to.deep.equal([0n, 1n]);
			for (const [h, secret] of today)
				expect(secret).to.deep.equal(
					revealedSecret(pair.devices, pair.id, 1, h).secret
				);
			expectResolved(pair.devices, pair.id, 2);
		});

	for (const g of [4, 5, 6] as const)
		it(
			'gives a generation ' + g + " asset channel's peer-revoke stages",
			async () => {
				const pair = await assetTypePair(s, 2, g);
				const today = assetSecrets(pair.devices[0].store, pair.id);
				expect([...today.keys()].sort()).to.deep.equal([0n, 1n]);
				for (const [h, secret] of today)
					expect(secret).to.deep.equal(
						revealedSecret(pair.devices, pair.id, 1, h).secret
					);
				expectResolved(pair.devices, pair.id, 2);
			}
		);

	for (const g of [1, 3] as const)
		it(
			'gives null in generation ' +
				g +
				' without reading the lifecycle journal',
			() => {
				const pair = plainTypePair(s, 0, g);
				const { point } = revealedSecret(pair.devices, pair.id, 1, 0);
				const scopes = journalReads(() => {
					expect(
						step2b().loadFinalPeerSecret(pair.stores[0], pair.id, 0n, point)
					).to.deep.equal({ secret: null, conflict: false });
					expect(
						step2b().loadFinalPeerSecrets(pair.stores[0], pair.id).size
					).to.equal(0);
				});
				expect(scopes).to.deep.equal([]);
			}
		);
});

describe('The peer secret store across eras (#2151 step 2b, item 2)', function () {
	this.timeout(300000);
	const s = scratch('peer-secrets-eras-');
	afterEach(() => s.release());

	it('resolves every height after asset to plain to asset', async () => {
		const pair = await assetTypePair(s, 1);
		const { id, devices } = pair;
		const first = buildConversion(devices, id, {
			type: 'plain',
			stateNumber: 1,
			parent: openingParent(devices[0].store, id)
		});
		appendBoth(devices, first);
		plainRounds(devices, id, 1, () => 400);
		const second = buildConversion(
			devices,
			id,
			{ type: 'asset', stateNumber: 2, parent: { tx: first.tx, index: 0 } },
			'plain'
		);
		appendBoth(devices, second);
		await assetRounds(devices, id, 3);
		expectResolved(devices, id, 3);
	});

	it('resolves every height after plain to asset to plain', async () => {
		const pair = plainTypePair(s, 1);
		const { id, devices } = pair;
		const first = buildConversion(devices, id, {
			type: 'asset',
			stateNumber: 1,
			parent: openingParent(devices[0].store, id)
		});
		appendBoth(devices, first);
		await assetRounds(devices, id, 2);
		const second = buildConversion(
			devices,
			id,
			{ type: 'plain', stateNumber: 2, parent: { tx: first.tx, index: 0 } },
			'asset'
		);
		appendBoth(devices, second);
		plainRounds(devices, id, 1, () => 400);
		expectResolved(devices, id, 3);
	});

	it("resolves a height below a record's N from the record's shachain", async () => {
		const pair = await assetTypePair(s, 2);
		const { id, devices } = pair;
		const c = buildConversion(devices, id, {
			type: 'plain',
			stateNumber: 2,
			parent: openingParent(devices[0].store, id)
		});
		appendBoth(devices, c);
		const store = pair.restart(0);
		// The asset journal, the only other source below N, reads as empty.
		const read = FinalDeviceJournal.prototype.read;
		const hidden = sinon
			.stub(FinalDeviceJournal.prototype, 'read')
			.callsFake(function (
				this: FinalDeviceJournal,
				...args: Parameters<typeof read>
			) {
				const out = read.apply(this, args);
				return args[0] === 'asset-splice' ? { ...out, records: [] } : out;
			});
		try {
			for (const h of [0, 1]) {
				const { secret, point } = revealedSecret(devices, id, 1, h);
				expect(
					step2b().loadFinalPeerSecret(store, id, BigInt(h), point),
					'height ' + h
				).to.deep.equal({ secret, conflict: false });
			}
			expect(hidden.called, 'the asset journal was consulted').to.equal(true);
		} finally {
			hidden.restore();
		}
	});
});

describe('Disagreeing peer secrets (#2151 step 2b, item 2)', function () {
	this.timeout(300000);
	const s = scratch('peer-secrets-conflict-');
	afterEach(() => sinon.restore());
	afterEach(() => s.release());

	/** An asset channel recorded to plain at N = 1, whose record's secret for height 0 reads wrong. */
	async function disagreeing(): Promise<{
		pair: IAssetTypePair;
		revoked: Transaction;
		truth: { secret: Buffer; point: Buffer };
	}> {
		const pair = await assetTypePair(s, 0);
		const { id, devices } = pair;
		// The peer's commitment at height 0, which the round below revokes.
		const revoked = exitOf(devices[1], id);
		await assetRounds(devices, id, 1);
		const c = buildConversion(devices, id, {
			type: 'plain',
			stateNumber: 1,
			parent: openingParent(devices[0].store, id)
		});
		appendBoth(devices, c);
		const truth = revealedSecret(devices, id, 1, 0);
		const wrong = revealedSecret(devices, id, 1, 5).secret.toString('hex');
		const read = FinalDeviceJournal.prototype.read;
		sinon.stub(FinalDeviceJournal.prototype, 'read').callsFake(function (
			this: FinalDeviceJournal,
			...args: Parameters<typeof read>
		) {
			const out = read.apply(this, args);
			if (args[0] !== 'channel-type') return out;
			return {
				...out,
				records: (out.records as IChannelTypeRecord[]).map((r) => ({
					...r,
					seed: {
						...r.seed,
						shachain: r.seed.shachain.map((b) =>
							b && b.height === 0 ? { ...b, secret: wrong } : b
						)
					}
				}))
			};
		});
		pair.restart(0);
		return { pair, revoked, truth };
	}

	it('makes loadFinalPeerSecrets throw', async () => {
		const { pair } = await disagreeing();
		expectRefusal(
			() => step2b().loadFinalPeerSecrets(pair.devices[0].store, pair.id),
			/Inconsistent peer revocation secrets/
		);
	});

	it('returns the secret that matches the point, with the conflict, and never throws', async () => {
		const { pair, truth } = await disagreeing();
		const store = pair.devices[0].store;
		for (let i = 0; i < 2; i++)
			expect(
				step2b().loadFinalPeerSecret(store, pair.id, 0n, truth.point)
			).to.deep.equal({ secret: truth.secret, conflict: true });
	});

	it('still builds the penalty over that height, and the chain watcher reports the conflict once', async () => {
		const { pair, revoked } = await disagreeing();
		const d = pair.p.f.devices[0];
		const store = pair.devices[0].store;
		const claims = finalChannelOutputClaims(
			{ storage: store, root: pair.devices[0].root },
			Buffer.from(pair.id, 'hex'),
			revoked,
			destination,
			1,
			undefined,
			undefined,
			(cid) => store.loadFinalChannelKind(cid)
		);
		expect(claims.map((c) => c.outputIndex).sort()).to.deep.equal(
			valueOutputs(revoked)
		);
		expect(claims.some((c) => c.relativeDelay === 0)).to.equal(true);
		const running = finalTestNode(6, {
			wallet: { db: store, mnemonic: d.mnemonic }
		});
		try {
			const watcher = (
				running.node as unknown as {
					chainWatcher: {
						backend: { listUnspent?: unknown };
						on(event: 'error', f: (e: Error) => void): void;
						claimFinalOutputs(
							id: Buffer,
							parent: Transaction,
							height: number,
							superseded: () => boolean
						): Promise<void>;
					};
				}
			).chainWatcher;
			watcher.backend.listUnspent ??= async (): Promise<never[]> => [];
			const errors: string[] = [];
			watcher.on('error', (e) => errors.push(e.message));
			for (let i = 0; i < 2; i++)
				await watcher.claimFinalOutputs(
					Buffer.from(pair.id, 'hex'),
					revoked,
					0,
					() => false
				);
			expect(errors, 'one report for the channel and height').to.have.length(1);
			expect(errors[0]).to.not.match(/is not a function|Cannot read propert/);
			expect(errors[0]).to.match(/Inconsistent peer revocation secrets/);
		} finally {
			running.close();
		}
	});
});
