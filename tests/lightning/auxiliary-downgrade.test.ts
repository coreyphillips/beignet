/**
 * A released build over a database that holds an asset channel (issue
 * #2093).
 *
 * An asset channel's row is stored inside an envelope (IStoredAssetChannelRow)
 * that a release from before asset channels cannot decode. This suite drives
 * the published beignet 0.42.0 itself over a database written by this build
 * and holds it to what the envelope is for: the release skips the row as
 * corrupt, says so, starts and runs the channels it knows, and leaves the row
 * as it was, byte for byte, so this build has the channel whole again
 * afterwards. A channel without asset state is stored as the bytes the
 * release itself writes.
 *
 * The released build is not a dependency of this repository. The suite runs
 * when BEIGNET_RELEASED_0_42_0 names an installed copy of it, and is skipped
 * without it:
 *
 *   npm install --prefix "$DIR" beignet@0.42.0
 *   BEIGNET_RELEASED_0_42_0="$DIR/node_modules/beignet" \
 *     npx mocha -r ts-node/register tests/lightning/auxiliary-downgrade.test.ts
 */

import Database from 'better-sqlite3';
import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { IChannelInfo, INodeConfig } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { amountRecord } from './helpers/auxiliary-pair';
import {
	IAssetHost,
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens
} from './helpers/auxiliary-nodes';
import { makeNodeConfig, openReadyChannel } from './helpers/loopback-nodes';

const RELEASED = process.env.BEIGNET_RELEASED_0_42_0;

/** What this suite uses of the released build's storage. */
interface IReleasedStorage {
	open(): void;
	close(): void;
	corruptRowCount(): number;
	loadAllChannels(): Array<{
		channelId: string;
		state: unknown;
		peerPubkey: string;
	}>;
}

/** What this suite uses of the released build's node. */
interface IReleasedNode {
	listChannels(): Array<{ channelId: Buffer; state: string }>;
	handleNewBlock(height: number): void;
	setChannelPolicy(channelId: Buffer, policy: { feeBaseMsat: number }): void;
	destroy(): void;
}

interface IReleased {
	SqliteStorage: new (
		file: string,
		onCorruptRow?: (error: unknown) => void
	) => IReleasedStorage;
	LightningNode: new (config: unknown) => IReleasedNode;
	serializeChannelState: (
		state: unknown,
		options: { htlcHistory: 'none' }
	) => unknown;
}

const released = (): IReleased => {
	const from = (file: string): Record<string, unknown> =>
		// eslint-disable-next-line @typescript-eslint/no-var-requires
		require(path.join(RELEASED as string, 'dist', 'lightning', file));
	return {
		SqliteStorage: from('storage/sqlite-storage.js')
			.SqliteStorage as IReleased['SqliteStorage'],
		LightningNode: from('node/lightning-node.js')
			.LightningNode as IReleased['LightningNode'],
		serializeChannelState: from('storage/serialization.js')
			.serializeChannelState as IReleased['serializeChannelState']
	};
};

/** Every row of every table, as text, by table. */
const tables = (file: string): Map<string, string[]> => {
	const db = new Database(file, { readonly: true });
	const out = new Map<string, string[]>();
	const names = db
		.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
		.all() as Array<{ name: string }>;
	for (const { name } of names) {
		const rows = db.prepare(`SELECT * FROM "${name}"`).all() as object[];
		out.set(
			name,
			rows.map((row) =>
				JSON.stringify(row, (_key, value: unknown) =>
					Buffer.isBuffer(value) ? value.toString('hex') : value
				)
			)
		);
	}
	db.close();
	return out;
};

const channelRow = (
	file: string,
	channelId: Buffer
): { state_json: string; peer_pubkey: string } => {
	const db = new Database(file, { readonly: true });
	const row = db
		.prepare(
			'SELECT state_json, peer_pubkey FROM channels WHERE channel_id = ?'
		)
		.get(channelId.toString('hex')) as {
		state_json: string;
		peer_pubkey: string;
	};
	db.close();
	return row;
};

/** A channel's state as this build reads it from the file, with no node running. */
const storedState = (file: string, channelId: Buffer): IChannelState => {
	const storage = new SqliteStorage(file);
	storage.open();
	const state = storage.loadChannel(channelId.toString('hex'))!.state;
	storage.close();
	return state;
};

const settle = async (): Promise<void> => {
	for (let i = 0; i < 40; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

const summary = (rows: IChannelInfo[]): Array<[string, boolean]> =>
	rows
		.map((row): [string, boolean] => [
			row.channelId.toString('hex'),
			row.auxiliary === true
		])
		.sort(([a], [b]) => a.localeCompare(b));

describe('The released 0.42.0 over a database that holds an asset channel (#2093)', function () {
	this.timeout(120_000);
	withAssetOpens();

	const directories: string[] = [];
	const hosts: IAssetHost[] = [];

	before(function () {
		if (!RELEASED) this.skip();
		const manifest = JSON.parse(
			fs.readFileSync(path.join(RELEASED as string, 'package.json'), 'utf8')
		) as { name: string; version: string };
		expect([manifest.name, manifest.version]).to.deep.equal([
			'beignet',
			'0.42.0'
		]);
	});

	afterEach(() => {
		for (const host of hosts.splice(0)) {
			try {
				host.node.destroy();
			} catch {
				// Already destroyed by the test.
			}
			try {
				host.storage?.close();
			} catch {
				// Already closed by the test.
			}
		}
		for (const directory of directories.splice(0)) {
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});

	/**
	 * Alice, on a database file, with an asset channel that has carried a
	 * payment and an ordinary channel beside it, both to Bob. Returns after
	 * Alice has stopped and closed her database.
	 */
	async function written(
		tag: string,
		extra: Partial<INodeConfig> = {}
	): Promise<{
		file: string;
		assetId: Buffer;
		ordinaryId: Buffer;
		assetState: IChannelState;
		units: [bigint, bigint];
		extra: Partial<INodeConfig>;
	}> {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-downgrade-'));
		directories.push(directory);
		const file = path.join(directory, 'alice.sqlite');
		const alice = assetHost(tag, 1, {}, { sqlitePath: file, extra });
		const bob = assetHost(tag, 2, {
			valueIncomingHtlc: (context) =>
				context.auxiliaryAmount === undefined
					? undefined
					: context.auxiliaryAmount * 1000n
		});
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const assetId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		const ordinaryId = openReadyChannel(alice.node, bob.node);
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'before the downgrade'
		});
		alice.node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						shortChannelId: Buffer.alloc(8, 9),
						amountToForwardMsat: 5_000_000n,
						outgoingCltvValue: 40
					}
				]
			},
			invoice.paymentHash,
			40,
			invoice.paymentSecret,
			undefined,
			undefined,
			undefined,
			undefined,
			{
				assetPayment: {
					channelId: assetId,
					wireAmountMsat: 354_000n,
					customRecords: amountRecord(5000n)
				}
			}
		);
		await settle();
		const info = alice.node.getAuxiliaryChannelInfo(assetId)!;
		const units: [bigint, bigint] = [
			info.localAssetBalance,
			info.remoteAssetBalance
		];
		expect(units).to.deep.equal([4000n, 6000n]);
		alice.node.destroy();
		const assetState = storedState(file, assetId);
		return { file, assetId, ordinaryId, assetState, units, extra };
	}

	/** The released build's node over `file`, and what its storage reported. */
	function downgraded(
		tag: string,
		file: string,
		extra: Partial<INodeConfig>
	): {
		storage: IReleasedStorage;
		node: IReleasedNode;
		reported: string[];
	} {
		const build = released();
		const reported: string[] = [];
		const storage = new build.SqliteStorage(file, (error) =>
			reported.push(error instanceof Error ? error.message : String(error))
		);
		storage.open();
		const node = new build.LightningNode({
			...makeNodeConfig(tag, 1),
			storage,
			...extra
		});
		return { storage, node, reported };
	}

	/** Back on this build: the channel is whole. */
	function expectWhole(
		tag: string,
		wrote: Awaited<ReturnType<typeof written>>
	): void {
		expect(storedState(wrote.file, wrote.assetId)).to.deep.equal(
			wrote.assetState
		);
		const again = assetHost(
			tag,
			1,
			{},
			{ sqlitePath: wrote.file, extra: wrote.extra }
		);
		hosts.push(again);
		expect(again.errors).to.deep.equal([]);
		expect(summary(again.node.listChannels())).to.deep.equal(
			[
				[wrote.assetId.toString('hex'), true] as [string, boolean],
				[wrote.ordinaryId.toString('hex'), false] as [string, boolean]
			].sort(([a], [b]) => a.localeCompare(b))
		);
		const info = again.node.getAuxiliaryChannelInfo(wrote.assetId)!;
		expect([info.localAssetBalance, info.remoteAssetBalance]).to.deep.equal(
			wrote.units
		);
	}

	it('skips the asset channel row and says so, starts and runs the ordinary channel, removes nothing, and leaves the row as it was', async () => {
		const tag = 'aux-downgrade';
		const wrote = await written(tag);
		const before = tables(wrote.file);
		const assetBefore = channelRow(wrote.file, wrote.assetId);
		const ordinaryBefore = channelRow(wrote.file, wrote.ordinaryId);
		expect(Object.keys(JSON.parse(assetBefore.state_json))).to.deep.equal([
			'assetChannelRow',
			'channel'
		]);

		const old = downgraded(tag, wrote.file, {});
		// It starts, with the ordinary channel and without the asset channel.
		expect(
			old.node.listChannels().map((row) => row.channelId.toString('hex'))
		).to.deep.equal([wrote.ordinaryId.toString('hex')]);
		// It reports the row it could not decode, once, and counts it.
		expect(old.reported).to.have.length(1);
		expect(old.storage.corruptRowCount()).to.equal(1);

		// The ordinary channel is stored as the bytes the release writes for
		// what it loaded.
		const loaded = old.storage
			.loadAllChannels()
			.find((row) => row.channelId === wrote.ordinaryId.toString('hex'))!;
		expect(
			JSON.stringify(
				released().serializeChannelState(loaded.state, {
					htlcHistory: 'none'
				})
			)
		).to.equal(ordinaryBefore.state_json);

		// It works: a block arrives and the ordinary channel's policy changes.
		old.node.handleNewBlock(200);
		old.node.setChannelPolicy(wrote.ordinaryId, { feeBaseMsat: 1234 });
		await settle();
		old.node.destroy();
		old.storage.close();

		// The asset channel's row is the row it was.
		expect(channelRow(wrote.file, wrote.assetId)).to.deep.equal(assetBefore);
		// Nothing stored was removed or rewritten, in any table, but two
		// counters the release advances at every start.
		const after = tables(wrote.file);
		const advanced = (row: string): boolean =>
			row.includes('"channel_key_index_floor"') ||
			row.includes('"name":"action_log"');
		for (const [table, rows] of before) {
			const kept = new Set(after.get(table) ?? []);
			const gone = rows.filter((row) => !kept.has(row) && !advanced(row));
			expect(gone, `rows of ${table} the release removed`).to.deep.equal([]);
		}

		expectWhole(tag, wrote);
	});

	it('with the recovery journal on, starts, says its journal cannot take a snapshot, and writes no frame over the ones stored', async () => {
		const tag = 'aux-downgrade-journal';
		const recovery = {
			recovery: { enabled: true, durability: 'local' }
		} as Partial<INodeConfig>;
		const wrote = await written(tag, recovery);
		const before = tables(wrote.file);
		const assetBefore = channelRow(wrote.file, wrote.assetId);
		expect(before.get('recovery_frames')!.length).to.be.greaterThan(0);

		const old = downgraded(tag, wrote.file, recovery);
		expect(
			old.node.listChannels().map((row) => row.channelId.toString('hex'))
		).to.deep.equal([wrote.ordinaryId.toString('hex')]);
		expect(old.storage.corruptRowCount()).to.be.at.least(1);
		old.node.handleNewBlock(200);
		old.node.setChannelPolicy(wrote.ordinaryId, { feeBaseMsat: 1234 });
		await settle();
		old.node.destroy();
		old.storage.close();

		const after = tables(wrote.file);
		expect(channelRow(wrote.file, wrote.assetId)).to.deep.equal(assetBefore);
		// The frames are the frames this build wrote: none replaced, none
		// added by a build that cannot say what the database holds.
		expect(after.get('recovery_frames')).to.deep.equal(
			before.get('recovery_frames')
		);
		expect(
			after
				.get('action_log')!
				.some((row) => row.includes('recovery_capsule_rebase_failed'))
		).to.equal(true);

		expectWhole(tag, wrote);
	});
});
