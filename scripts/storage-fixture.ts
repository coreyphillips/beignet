/**
 * Writes a SqliteStorage fixture for tests/lightning/sqlite-schema-upgrade
 * using the storage code of whichever source tree it is pointed at, and
 * dumps the database as SQL.
 *
 * A fixture must come from the code that wrote that schema, so before
 * bumping CURRENT_SCHEMA_VERSION, write one from the current master:
 *
 *   mkdir /tmp/old && git archive master src types tsconfig.json package.json \
 *     | tar -x -C /tmp/old && ln -s "$PWD/node_modules" /tmp/old/node_modules
 *   FIXTURE_SOURCE=$(git rev-parse --short master) \
 *   TS_NODE_TRANSPILE_ONLY=1 node --no-strip-types -r ts-node/register \
 *     scripts/storage-fixture.ts /tmp/old \
 *     tests/lightning/fixtures/sqlite-schema/schema-NN.sql
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import Database from 'better-sqlite3';
import {
	FIXTURE,
	fixtureHex
} from '../tests/lightning/fixtures/sqlite-schema/values';

/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-var-requires */

function main(): void {
	const [rootArg, outArg] = process.argv.slice(2);
	if (!rootArg || !outArg) {
		throw new Error('usage: storage-fixture.ts <source root> <output .sql>');
	}
	const root = path.resolve(rootArg);
	const load = (module: string): any =>
		require(path.join(root, 'src/lightning', module));
	const { SqliteStorage } = load('storage/sqlite-storage');
	const { createOpenerState } = load('channel/channel-state');
	const { DEFAULT_CHANNEL_CONFIG, ChannelState } = load('channel/types');
	const { MAX_INDEX, generateFromSeed } = load('keys/shachain');
	const { perCommitmentPointFromSecret } = load('keys/derivation');
	const { getPublicKey } = load('crypto/ecdh');

	const bytes = (label: string): Buffer =>
		Buffer.from(fixtureHex(label), 'hex');
	const basepoints = (side: string): any => ({
		fundingPubkey: getPublicKey(bytes(`${side}-funding`)),
		revocationBasepoint: getPublicKey(bytes(`${side}-revocation`)),
		paymentBasepoint: getPublicKey(bytes(`${side}-payment`)),
		delayedPaymentBasepoint: getPublicKey(bytes(`${side}-delayed`)),
		htlcBasepoint: getPublicKey(bytes(`${side}-htlc`)),
		firstPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(bytes(`${side}-commitment-seed`), MAX_INDEX)
		)
	});
	const channel = createOpenerState({
		temporaryChannelId: Buffer.from(FIXTURE.temporaryChannelId, 'hex'),
		fundingSatoshis: FIXTURE.fundingSatoshis,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: basepoints('local'),
		localPerCommitmentSeed: bytes('local-commitment-seed')
	});
	channel.state = ChannelState.NORMAL;
	channel.channelId = Buffer.from(FIXTURE.channelId, 'hex');
	channel.fundingTxid = Buffer.from(FIXTURE.fundingTxid, 'hex');
	channel.fundingOutputIndex = 0;
	channel.localCommitmentNumber = FIXTURE.localCommitmentNumber;
	channel.remoteCommitmentNumber = FIXTURE.remoteCommitmentNumber;
	channel.localBalanceMsat = FIXTURE.localBalanceMsat;
	channel.remoteBalanceMsat = FIXTURE.remoteBalanceMsat;
	channel.remoteBasepoints = basepoints('remote');
	channel.remoteCurrentPerCommitmentPoint =
		channel.remoteBasepoints.firstPerCommitmentPoint;

	const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'storage-fixture-'));
	try {
		const file = path.join(directory, 'fixture.db');
		const storage = new SqliteStorage(file);
		storage.open();
		const version: number = storage.getSchemaVersion();
		storage.saveChannel(FIXTURE.channelId, channel, FIXTURE.peerPubkey);
		storage.saveChannelKeyIndex(FIXTURE.channelId, FIXTURE.channelIndex);
		storage.savePeerAddress(
			FIXTURE.peerPubkey,
			FIXTURE.peerHost,
			FIXTURE.peerPort
		);
		storage.savePayment(FIXTURE.paymentHash, {
			paymentHash: Buffer.from(FIXTURE.paymentHash, 'hex'),
			preimage: Buffer.from(FIXTURE.paymentPreimage, 'hex'),
			amountMsat: FIXTURE.paymentAmountMsat,
			status: 'COMPLETED',
			direction: 'OUTGOING',
			createdAt: FIXTURE.paymentCreatedAt,
			completedAt: FIXTURE.paymentCompletedAt,
			metadata: { ...FIXTURE.paymentMetadata }
		});
		storage.savePreimage(
			FIXTURE.paymentHash,
			Buffer.from(FIXTURE.paymentPreimage, 'hex')
		);
		storage.savePaymentSecret(
			FIXTURE.invoiceHash,
			Buffer.from(FIXTURE.invoiceSecret, 'hex')
		);
		storage.saveInvoice(FIXTURE.invoiceHash, {
			paymentHash: FIXTURE.invoiceHash,
			bolt11: FIXTURE.invoiceBolt11,
			amountMsat: FIXTURE.invoiceAmountMsat,
			description: FIXTURE.invoiceDescription,
			expiry: FIXTURE.invoiceExpiry,
			createdAt: FIXTURE.invoiceCreatedAt
		});
		storage.saveMetadata(FIXTURE.metadataKey, FIXTURE.metadataValue);
		storage.saveWalletData?.(FIXTURE.walletDataKey, FIXTURE.walletDataValue);
		storage.saveOffer?.(
			FIXTURE.offerId,
			FIXTURE.offerEncoded,
			Buffer.from(FIXTURE.offerPathId, 'hex'),
			FIXTURE.offerCreatedAt
		);
		if (storage.saveWatchtowerSession) {
			storage.saveWatchtowerSession(
				{
					towerUri: FIXTURE.towerUri,
					towerPubkey: FIXTURE.towerPubkey,
					sessionId: FIXTURE.sessionId,
					blobType: FIXTURE.sessionBlobType,
					maxUpdates: FIXTURE.sessionMaxUpdates,
					sweepFeeRate: FIXTURE.sessionSweepFeeRate,
					seqNum: 1,
					lastApplied: 0,
					createdAt: FIXTURE.sessionCreatedAt
				},
				Buffer.from(FIXTURE.sessionKey, 'hex')
			);
			storage.addWatchtowerUpdate({
				towerUri: FIXTURE.towerUri,
				channelId: FIXTURE.channelId,
				blobType: FIXTURE.sessionBlobType,
				hint: FIXTURE.updateHint,
				encryptedBlob: FIXTURE.updateBlob,
				seqNum: 1,
				acked: false,
				createdAt: FIXTURE.updateCreatedAt
			});
		}
		storage.close();

		const pkg = JSON.parse(
			fs.readFileSync(path.join(root, 'package.json'), 'utf8')
		) as { version: string };
		const header = [
			`-- SqliteStorage schema ${version}, written by beignet ${pkg.version}`,
			`-- (${sourceRevision(root)}) with scripts/storage-fixture.ts.`
		];
		fs.writeFileSync(
			path.resolve(outArg),
			[...header, ...dump(file)].join('\n') + '\n'
		);
	} finally {
		fs.rmSync(directory, { recursive: true, force: true });
	}
}

/** FIXTURE_SOURCE (a git archive has no history), else the tree's HEAD. */
function sourceRevision(root: string): string {
	if (process.env.FIXTURE_SOURCE) return process.env.FIXTURE_SOURCE;
	try {
		return execFileSync('git', ['-C', root, 'rev-parse', '--short', 'HEAD'], {
			encoding: 'utf8',
			stdio: ['ignore', 'pipe', 'ignore']
		}).trim();
	} catch {
		return 'unknown source';
	}
}

/** Schema and rows as SQL, using SQLite's quote() for every value. */
function dump(file: string): string[] {
	const db = new Database(file, { readonly: true });
	try {
		const objects = db
			.prepare(
				"SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, name"
			)
			.all() as Array<{ type: string; name: string; sql: string }>;
		const tables = objects.filter((o) => o.type === 'table');
		const lines: string[] = [];
		for (const table of tables) {
			if (table.name !== 'sqlite_sequence') lines.push(`${table.sql};`);
		}
		for (const table of tables) {
			const columns = (
				db.pragma(`table_info("${table.name}")`) as Array<{ name: string }>
			).map((c) => `quote("${c.name}")`);
			const order = table.name === 'sqlite_sequence' ? 'name' : 'rowid';
			const rows = db
				.prepare(
					`SELECT ${columns.join(" || ',' || ")} AS v FROM "${
						table.name
					}" ORDER BY ${order}`
				)
				.all() as Array<{ v: string }>;
			for (const row of rows) {
				lines.push(`INSERT INTO "${table.name}" VALUES(${row.v});`);
			}
		}
		for (const object of objects) {
			if (object.type !== 'table') lines.push(`${object.sql};`);
		}
		return lines;
	} finally {
		db.close();
	}
}

main();
