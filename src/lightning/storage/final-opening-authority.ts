import type { IFinalReestablishNonce } from './final-opening-nonces';
import type Database from 'better-sqlite3';
import path from 'path';
import { nodeFs } from '../../utils/node-builtins';
import { hmacSha256, randomBytes, sha256 } from '../crypto/provider';
import { hkdfKey, encryptValue, decryptValue } from './encryption';
import { loadBetterSqlite3 } from './sqlite-binding';

export const SIGNER_SUFFIX = '.opening-signer';
export const SIGNER_TABLE = 'final_opening_signer';
const AUTHORITY_INFO = 'beignet-opening-authority-v1';
const REPLAY_ONLY = 'replay-only';

function descriptor(file: string, canonicalFile = file): string {
	const fs = nodeFs();
	const info = fs.lstatSync(file, { bigint: true });
	if (!info.isFile() || info.ino === 0n)
		throw new Error('Invalid original wallet file');
	const location = path.join(
		fs.realpathSync(path.dirname(canonicalFile)),
		path.basename(canonicalFile)
	);
	return sha256(
		Buffer.from(
			JSON.stringify([
				location,
				String(info.dev),
				String(info.ino),
				String(info.birthtimeNs)
			])
		)
	).toString('hex');
}

function bindingKey(key: Buffer, identity: string): Buffer {
	return hkdfKey(key, AUTHORITY_INFO + '/' + identity);
}

function claimCountTag(secret: Buffer, count: number): string {
	return hmacSha256(
		secret,
		Buffer.from('beignet-opening-claim-count-v1/' + count)
	).toString('hex');
}

/** The authenticated count detects missing claims even when the device row survives. */
function readClaimCount(
	db: Database.Database,
	secret: Buffer,
	added = 0
): void {
	const { count, tag } = db
		.prepare(
			`SELECT (SELECT COUNT(*) FROM claims) AS count, claim_count_tag AS tag FROM ${SIGNER_TABLE} WHERE id=1`
		)
		.get() as { count: number; tag: string };
	if (tag !== claimCountTag(secret, count - added))
		throw new Error('Incomplete opening signer journal');
	if (added) {
		const next = claimCountTag(secret, count);
		if (
			db
				.prepare(
					`UPDATE ${SIGNER_TABLE} SET claim_count_tag=? WHERE id=1 AND claim_count_tag=?`
				)
				.run(next, tag).changes !== 1
		)
			throw new Error('Could not authenticate opening signer claim count');
		readClaimCount(db, secret);
	}
}

export function installOpeningAuthority(
	stageWallet: string,
	canonical: string,
	db: Database.Database,
	key: Buffer,
	identity: string,
	daemonGenerated: boolean
): void {
	const fs = nodeFs();
	const stagedSigner = stageWallet + SIGNER_SUFFIX;
	fs.closeSync(fs.openSync(stagedSigner, 'wx', 0o600));
	const Sqlite = loadBetterSqlite3();
	const signer = new Sqlite(stagedSigner, { fileMustExist: true });
	try {
		signer.pragma('synchronous = EXTRA');
		const generation = JSON.parse(identity)[0];
		if (generation === 3 || generation === 4 || generation === 5)
			signer.pragma('auto_vacuum = FULL');
		const secret = randomBytes(32);
		const origin = JSON.stringify([
			descriptor(stageWallet, canonical),
			descriptor(stagedSigner, canonical + SIGNER_SUFFIX),
			sha256(secret).toString('hex')
		]);
		const seal = bindingKey(key, identity);
		signer.transaction(() => {
			signer.exec(`
				CREATE TABLE ${SIGNER_TABLE} (id INTEGER PRIMARY KEY CHECK (id = 1), device TEXT NOT NULL, claim_count_tag TEXT NOT NULL);
				CREATE TABLE claims (slot TEXT NOT NULL PRIMARY KEY, claim TEXT NOT NULL);
			`);
			signer
				.prepare(
					`INSERT INTO ${SIGNER_TABLE} (id, device, claim_count_tag) VALUES (1, ?, ?)`
				)
				.run(
					encryptValue(
						seal,
						JSON.stringify([origin, secret.toString('hex'), daemonGenerated])
					),
					claimCountTag(secret, 0)
				);
		})();
		db.transaction(() => {
			db.exec('ALTER TABLE final_wallet_format ADD COLUMN signer_binding TEXT');
			db.prepare(
				'UPDATE final_wallet_format SET signer_binding = ? WHERE id = 1'
			).run(encryptValue(seal, origin));
		})();
	} finally {
		signer.close();
	}
}

interface WalletOrigin {
	encoded: string;
	lineage: string | null;
	files?: [string, string];
}

function getOrigin(
	db: Database.Database,
	key: Buffer,
	identity: string
): WalletOrigin {
	const cols = db.pragma('table_info(final_wallet_format)') as {
		name: string;
	}[];
	const untracked = { encoded: REPLAY_ONLY, lineage: null };
	if (!cols.some((col) => col.name === 'signer_binding')) return untracked;
	const row = db
		.prepare('SELECT signer_binding FROM final_wallet_format WHERE id=1')
		.get() as { signer_binding: string };
	const encoded = decryptValue(bindingKey(key, identity), row.signer_binding);
	if (encoded === REPLAY_ONLY) return untracked;
	const fields: unknown = JSON.parse(encoded);
	const fingerprint = (v: unknown): v is string =>
		typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
	if (Array.isArray(fields)) {
		if (
			fields.length === 2 &&
			fields[0] === REPLAY_ONLY &&
			fingerprint(fields[1])
		)
			return { encoded, lineage: fields[1] };
		if (fields.length === 3 && fields.every(fingerprint))
			return { encoded, files: [fields[0], fields[1]], lineage: fields[2] };
	}
	throw new Error('Invalid final wallet original device binding');
}

function decodeDevice(
	encrypted: string,
	key: Buffer,
	identity: string,
	origin: WalletOrigin
): {
	secret: Buffer;
	daemonGenerated: boolean;
} {
	const [claimedOrigin, deviceHex, daemonGenerated] = JSON.parse(
		decryptValue(bindingKey(key, identity), encrypted)
	);
	if (
		claimedOrigin !== origin.encoded ||
		(daemonGenerated !== undefined && typeof daemonGenerated !== 'boolean') ||
		typeof deviceHex !== 'string' ||
		!/^[a-f0-9]{64}$/.test(deviceHex)
	)
		throw new Error('Wrong opening signer');
	const secret = Buffer.from(deviceHex, 'hex');
	if (sha256(secret).toString('hex') !== origin.lineage)
		throw new Error('Wrong opening signer');
	return { secret, daemonGenerated: daemonGenerated === true };
}

/** Validate an interrupted, unused installation before publishing its missing wallet link. */
export function verifyStagedDaemonDevice(
	wallet: Database.Database,
	signer: Database.Database,
	staged: string,
	canonical: string,
	key: Buffer,
	identity: string
): void {
	const origin = getOrigin(wallet, key, identity);
	if (
		!origin.files ||
		origin.files[0] !== descriptor(staged, canonical) ||
		origin.files[1] !==
			descriptor(staged + SIGNER_SUFFIX, canonical + SIGNER_SUFFIX) ||
		origin.files[1] !== descriptor(canonical + SIGNER_SUFFIX)
	)
		throw new Error(
			'Staged wallet does not match its installed opening signer'
		);
	const row = signer
		.prepare(`SELECT device FROM ${SIGNER_TABLE} WHERE id=1`)
		.get() as { device: string };
	const { secret, daemonGenerated } = decodeDevice(
		row.device,
		key,
		identity,
		origin
	);
	try {
		if (
			!daemonGenerated ||
			signer.prepare('SELECT 1 FROM claims LIMIT 1').get()
		)
			throw new Error('Expected an unused daemon-enrolled original signer');
		readClaimCount(signer, secret);
	} finally {
		secret.fill(0);
	}
}

export function protectOriginalBackupDestination(
	db: Database.Database,
	file: string,
	key: Buffer,
	identity: string,
	sourceLineage: string | null
): void {
	const origin = getOrigin(db, key, identity);
	if (
		origin.files ||
		nodeFs().lstatSync(file + SIGNER_SUFFIX, { throwIfNoEntry: false })
	)
		throw new Error('Cannot replace an original final wallet with a backup');
	if (!sourceLineage || sourceLineage !== origin.lineage)
		throw new Error(
			'Cannot replace a backup from another or unknown wallet lineage'
		);
}

/** Preserve public lineage and remove signing authority before publishing the backup. */
export function markOpeningBackup(
	db: Database.Database,
	key: Buffer,
	identity: string
): string | null {
	const origin = getOrigin(db, key, identity);
	if (!origin.files) return origin.lineage;
	const encoded = JSON.stringify([REPLAY_ONLY, origin.lineage]);
	db.prepare(
		'UPDATE final_wallet_format SET signer_binding = ? WHERE id=1'
	).run(encryptValue(bindingKey(key, identity), encoded));
	if (getOrigin(db, key, identity).encoded !== encoded)
		throw new Error('Could not mark final wallet backup');
	return origin.lineage;
}

interface Claim {
	transcript: string;
	result: string | null;
}

/** An original wallet's separate device journal. Its key and claims never enter a wallet backup. */
export class FinalOpeningAuthority {
	private constructor(
		private readonly db: Database.Database,
		private readonly secret: Buffer,
		private readonly wallet: string,
		private readonly walletFile: string,
		private readonly signerFile: string,
		private readonly daemonGenerated: boolean
	) {}

	static open(
		walletDb: Database.Database,
		file: string,
		key: Buffer,
		identity: string
	): FinalOpeningAuthority | null {
		const origin = getOrigin(walletDb, key, identity);
		if (!origin.files) return null;
		const [walletFile, signerFile] = origin.files;
		const signerPath = file + SIGNER_SUFFIX;
		if (descriptor(file) !== walletFile) return null;
		const stat = nodeFs().lstatSync(signerPath, { throwIfNoEntry: false });
		if (!stat?.isFile() || descriptor(signerPath) !== signerFile) return null;
		const Sqlite = loadBetterSqlite3();
		let db: Database.Database | undefined;
		try {
			for (const suffix of ['-journal', '-shm', '-wal']) {
				const sidecar = nodeFs().lstatSync(signerPath + suffix, {
					throwIfNoEntry: false
				});
				if (sidecar && !sidecar.isFile()) return null;
			}
			const opened = new Sqlite(signerPath, {
				fileMustExist: true,
				timeout: 0
			});
			db = opened;
			db.pragma('locking_mode = EXCLUSIVE');
			db.pragma('synchronous = EXTRA');
			const encrypted = db
				.transaction(() => {
					const row = opened
						.prepare(`SELECT device FROM ${SIGNER_TABLE} WHERE id = 1`)
						.get() as { device: string };
					// An empty or replaced device journal never creates the missing schema here.
					opened.prepare('SELECT claim FROM claims WHERE slot=?');
					return row.device;
				})
				.exclusive();
			const { secret, daemonGenerated } = decodeDevice(
				encrypted,
				key,
				identity,
				origin
			);
			readClaimCount(db, secret);
			const authority = new FinalOpeningAuthority(
				db,
				secret,
				file,
				walletFile,
				signerFile,
				daemonGenerated === true
			);
			for (const row of db
				.prepare('SELECT slot, claim FROM claims')
				.iterate() as Iterable<{ slot: string; claim: string }>) {
				authority.decodeClaim(row.slot, row.claim);
			}
			return authority;
		} catch {
			// Public replay and an already signed exit survive a lost or damaged signer.
			db?.close();
			return null;
		}
	}

	close(): void {
		this.secret.fill(0);
		this.db.close();
	}

	private verifyFiles(): void {
		if (
			descriptor(this.wallet) !== this.walletFile ||
			descriptor(this.wallet + SIGNER_SUFFIX) !== this.signerFile
		)
			throw new Error('Original opening signer files have changed');
	}

	assertDaemonEnrollment(): void {
		this.verifyFiles();
		if (!this.daemonGenerated)
			throw new Error('Final wallet lacks fresh daemon enrollment');
	}

	/** Match the replay-only snapshot and its funded opening to existing claims without creating a signing reservation. */
	verifyAssetOpeningBackup(
		source: Database.Database,
		key: Buffer,
		identity: string,
		id: string,
		outpoint: string,
		candidate: string,
		session: string,
		exit: string
	): void {
		this.assertDaemonEnrollment();
		const origin = getOrigin(source, key, identity);
		if (origin.files || origin.lineage !== sha256(this.secret).toString('hex'))
			throw new Error('Expected a replay-only backup from this wallet lineage');
		const candidateHash = sha256(Buffer.from(candidate)).toString('hex');
		const claims = [
			['channel/' + id, candidateHash],
			['funding/' + outpoint, candidateHash],
			['opening/session/' + id, sha256(Buffer.from(session)).toString('hex')],
			[
				'enforceable-exit/' + id,
				sha256(Buffer.from(exit, 'hex')).toString('hex')
			]
		];
		for (const [slot, transcript] of claims) {
			if (this.read(slot)?.transcript !== transcript)
				throw new Error('Backup opening differs from the original device');
		}
	}

	nonceContext(candidateKey: Buffer): Buffer {
		this.verifyFiles();
		return hmacSha256(this.secret, candidateKey);
	}

	private claimKey(slot: string): Buffer {
		return hkdfKey(this.secret, 'beignet-opening-transcript-v1/' + slot);
	}

	private read(slot: string): Claim | null {
		const row = this.db
			.prepare('SELECT claim FROM claims WHERE slot=?')
			.get(slot) as { claim: string } | undefined;
		return row ? this.decodeClaim(slot, row.claim) : null;
	}

	private decodeClaim(slot: string, sealed: string): Claim {
		const value: Claim = JSON.parse(decryptValue(this.claimKey(slot), sealed));
		if (
			!value ||
			typeof value.transcript !== 'string' ||
			(value.result !== null &&
				(typeof value.result !== 'string' ||
					value.result.length % 2 !== 0 ||
					!/^[0-9a-f]+$/.test(value.result)))
		)
			throw new Error('Invalid opening signer transcript');
		return value;
	}

	private lock(slot: string, transcript: string): Buffer | null {
		const record = this.read(slot);
		if (record) {
			if (record.transcript !== transcript)
				throw new Error('Opening signer transcript changed');
			return record.result === null ? null : Buffer.from(record.result, 'hex');
		}
		this.db
			.prepare('INSERT INTO claims (slot, claim) VALUES (?,?)')
			.run(
				slot,
				encryptValue(
					this.claimKey(slot),
					JSON.stringify({ transcript, result: null })
				)
			);
		readClaimCount(this.db, this.secret, 1);
		if (this.read(slot)?.transcript !== transcript)
			throw new Error('Could not claim opening signer transcript');
		return null;
	}

	/** Commit the one allowed challenge before generating any signature for this nonce. */
	claim(slot: string, transcript: string): Buffer | null {
		this.verifyFiles();
		return this.db.transaction(() => this.lock(slot, transcript)).immediate();
	}

	fundingWitnessResult(
		id: string,
		field: 'fundingLocal' | 'fundingPeer'
	): Buffer | null {
		this.verifyFiles();
		const result = this.read('funding-witness/' + field + '/' + id)?.result;
		return result ? Buffer.from(result, 'hex') : null;
	}

	/** Advance the device high-water mark before the wallet releases a reconnect nonce.
	 * Replacing one authenticated slot bounds storage across repeated disconnects.
	 */
	advanceReestablishNonce(
		slot: string,
		transcript: string,
		wallet: IFinalReestablishNonce | undefined,
		generate: (generation: number) => Buffer
	): IFinalReestablishNonce {
		this.verifyFiles();
		return this.db
			.transaction(() => {
				const current = this.lock(slot, transcript);
				const previous: IFinalReestablishNonce | null =
					current && JSON.parse(current.toString());
				if (
					previous &&
					(!Number.isSafeInteger(previous.generation) ||
						previous.generation < 1 ||
						typeof previous.nonce !== 'string' ||
						!/^[0-9a-f]{132}$/.test(previous.nonce))
				)
					throw new Error('Invalid device reconnect nonce');
				if (
					wallet &&
					(!previous ||
						wallet.generation > previous.generation ||
						(wallet.generation === previous.generation &&
							wallet.nonce !== previous.nonce))
				)
					throw new Error('Reconnect nonce disagrees with original device');
				const generation = (previous?.generation ?? 0) + 1;
				if (!Number.isSafeInteger(generation))
					throw new Error('Reconnect nonce counter exhausted');
				const nonce = generate(generation).toString('hex');
				// A deterministic peer can repeat its unused nonce for the same commitment height.
				if (previous?.nonce === nonce) return previous;
				const next = { generation, nonce };
				const result = Buffer.from(JSON.stringify(next)).toString('hex');
				this.db
					.prepare('UPDATE claims SET claim=? WHERE slot=?')
					.run(
						encryptValue(
							this.claimKey(slot),
							JSON.stringify({ transcript, result })
						),
						slot
					);
				if (this.read(slot)?.result !== result)
					throw new Error('Could not save reconnect nonce on device');
				return next;
			})
			.immediate();
	}

	requireReconnectPromise(
		slot: string,
		promise: IFinalReestablishNonce | undefined
	): void {
		this.verifyFiles();
		const result = this.read(slot)?.result;
		if (
			(result ? Buffer.from(result, 'hex').toString() : undefined) !==
			(promise ? JSON.stringify(promise) : undefined)
		)
			throw new Error(
				'Wallet requires a fresh authenticated reconnect before its first update'
			);
	}

	/** Burn a key before its basepoints leave this device, even if the wallet rolls back. */
	lifecycleEntry(slot: string): string | null {
		this.verifyFiles();
		const existing = this.read('lifecycle/' + slot);
		if (!existing) return null;
		if (!existing.result) throw new Error('Incomplete final lifecycle entry');
		const data = Buffer.from(existing.result, 'hex');
		if (sha256(data).toString('hex') !== existing.transcript)
			throw new Error('Invalid final lifecycle entry');
		return data.toString('utf8');
	}

	commitLifecycleEntry(slot: string, value: string): void {
		this.verifyFiles();
		const name = 'lifecycle/' + slot,
			raw = Buffer.from(value),
			digest = sha256(raw).toString('hex');
		this.db
			.transaction(() => {
				this.lock(name, digest);
				this.finish(name, digest, raw);
			})
			.immediate();
	}

	listAssetOpenStages(): string[] {
		this.verifyFiles();
		const rows = this.db
			.prepare(
				`
			SELECT substr(slot, 15) AS id FROM claims AS started
			WHERE slot GLOB 'asset-attempt/*'
			AND NOT EXISTS (SELECT 1 FROM claims WHERE slot =
				'asset-packet/' || substr(started.slot, 15) || '/finished')
			ORDER BY slot LIMIT 9
		`
			)
			.all() as { id: string }[];
		if (rows.length > 8) throw new Error('Too many pending asset openings');
		return rows.map((row) => row.id);
	}

	private assetStageName(id: string, field: string): string {
		if (
			typeof id !== 'string' ||
			!/^[0-9a-f]{64}$/.test(id) ||
			typeof field !== 'string' ||
			!/^[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,79}$/.test(field)
		)
			throw new Error('Invalid asset opening stage');
		return id + '/' + field;
	}

	loadAssetOpenStage(id: string, field: string): Buffer | null {
		this.verifyFiles();
		const name = this.assetStageName(id, field);
		const record = this.read('asset-packet/' + name);
		if (!record) return null;
		if (
			record.result === '00' &&
			field !== 'finished' &&
			this.read('asset-packet/' + id + '/finished')
		)
			return null;
		if (!record.result?.startsWith('01'))
			throw new Error('Incomplete asset opening stage');
		const bytes = Buffer.from(record.result.slice(2), 'hex');
		if (record.transcript !== sha256(bytes).toString('hex'))
			throw new Error('Invalid stored asset opening stage');
		return bytes;
	}

	/** An unfinished attempt has at most 128 named packets/reservations and 40 MiB of packet data. */
	private admitAssetStage(
		id: string,
		field: string,
		additionalBytes: number
	): void {
		if (this.read('asset-packet/' + id + '/finished'))
			throw new Error('Asset opening stage is finished');
		if (!this.read('asset-attempt/' + id)) {
			if (field === 'finished' || this.listAssetOpenStages().length >= 8)
				throw new Error('Cannot start an asset opening stage');
			this.lock('asset-attempt/' + id, id);
		}
		const prefix = 'asset-size/' + id + '/';
		const rows = this.db
			.prepare('SELECT slot,claim FROM claims WHERE slot GLOB ? LIMIT 129')
			.all(prefix + '*') as { slot: string; claim: string }[];
		if (rows.length >= (field === 'finished' ? 128 : 127))
			throw new Error('Too many asset opening fields');
		let total = additionalBytes;
		for (const row of rows) {
			const size = Number(this.decodeClaim(row.slot, row.claim).transcript);
			if (!Number.isSafeInteger(size) || size < 0 || size > 4 * 1024 * 1024)
				throw new Error('Invalid asset opening record size');
			total += size;
		}
		if (total > 40 * 1024 * 1024 - (field === 'finished' ? 0 : 1))
			throw new Error('Asset opening byte limit exceeded');
	}

	/** Retain the authenticated packet digest and signing reservations, releasing completed proof bodies. */
	private compactAssetStage(id: string): void {
		const prefix = 'asset-packet/' + id + '/';
		const slots = this.db
			.prepare('SELECT slot FROM claims WHERE slot GLOB ?')
			.all(prefix + '*') as { slot: string }[];
		const update = this.db.prepare('UPDATE claims SET claim=? WHERE slot=?');
		for (const { slot } of slots) {
			const field = slot.slice(prefix.length);
			if (field === 'finished') continue;
			const record = this.read(slot)!;
			if (record.result === '00') continue;
			if (
				!record.result?.startsWith('01') ||
				!/^[0-9a-f]{64}$/.test(record.transcript)
			)
				throw new Error('Invalid asset opening packet at retirement');
			// The public session can be interrupted between admission and nonce persistence.
			if (field === 'peerNonce' && record.result.length <= 514) continue;
			const receipt = encryptValue(
				this.claimKey(slot),
				JSON.stringify({ transcript: record.transcript, result: '00' })
			);
			update.run(receipt, slot);
			const saved = this.read(slot);
			if (saved?.result !== '00' || saved.transcript !== record.transcript)
				throw new Error('Could not compact the retired asset opening');
		}
		this.lock('asset-compacted/' + id, id);
	}

	compactRetiredAssetStages(): void {
		this.verifyFiles();
		const rows = this.db
			.prepare(
				`SELECT substr(slot,14,64) AS id FROM claims AS done
			WHERE slot GLOB 'asset-packet/*/finished' AND length(slot)=86
			AND NOT EXISTS(SELECT 1 FROM claims WHERE slot='asset-compacted/'||substr(done.slot,14,64))`
			)
			.all() as { id: string }[];
		for (const { id } of rows)
			this.db.transaction(() => this.compactAssetStage(id)).immediate();
	}

	saveAssetOpenStage(id: string, field: string, bytes: Buffer): void {
		this.verifyFiles();
		const name = this.assetStageName(id, field);
		if (
			!Buffer.isBuffer(bytes) ||
			bytes.length > 4 * 1024 * 1024 ||
			(field === 'finished' && bytes.length > 1)
		)
			throw new Error('Invalid asset opening stage size');
		const digest = sha256(bytes).toString('hex');
		this.db
			.transaction(() => {
				const old = this.loadAssetOpenStage(id, field);
				if (old) {
					if (!old.equals(bytes))
						throw new Error('Asset opening stage changed');
					return;
				}
				this.admitAssetStage(id, field, bytes.length);
				this.lock(
					'asset-size/' + id + '/packet/' + field,
					String(bytes.length)
				);
				const slot = 'asset-packet/' + name;
				this.lock(slot, digest);
				this.finish(slot, digest, Buffer.concat([Buffer.of(1), bytes]));
				if (field === 'finished') this.compactAssetStage(id);
			})
			.immediate();
	}

	reserveAssetOpenSignature(
		id: string,
		field: string,
		digest: string | Buffer
	): void {
		this.verifyFiles();
		const name = this.assetStageName(id, field);
		const hex = Buffer.isBuffer(digest) ? digest.toString('hex') : digest;
		if (
			field === 'finished' ||
			typeof hex !== 'string' ||
			!/^[0-9a-f]{64}$/.test(hex)
		)
			throw new Error('Invalid asset opening signature reservation');
		const slot = 'asset-reservation/' + name;
		this.db
			.transaction(() => {
				if (!this.read(slot)) {
					this.admitAssetStage(id, field, 0);
					this.lock('asset-size/' + id + '/signature/' + field, '0');
				} else if (this.read('asset-packet/' + id + '/finished')) {
					throw new Error('Asset opening stage is finished');
				}
				this.lock(slot, hex);
			})
			.immediate();
	}

	requireAllocatedChannelKey(index: number): void {
		this.verifyFiles();
		if (
			this.read('key-allocation/' + String(index).padStart(10, '0'))
				?.transcript !== String(index)
		)
			throw new Error('Opening must use a previously allocated device key');
	}

	allocateChannelKey(minimum: number): number {
		this.verifyFiles();
		return this.db
			.transaction(() => {
				const previous = this.db
					.prepare(
						"SELECT slot FROM claims WHERE slot GLOB 'key-allocation/*' ORDER BY slot DESC LIMIT 1"
					)
					.get() as { slot: string } | undefined;
				let highest = 0;
				if (previous) {
					const value = previous.slot.slice('key-allocation/'.length);
					highest = Number(value);
					if (
						!/^[0-9]{10}$/.test(value) ||
						this.read(previous.slot)?.transcript !== String(highest)
					)
						throw new Error('Invalid original wallet channel key allocation');
				}
				const index = Math.max(highest + 1, minimum);
				if (!Number.isSafeInteger(index) || index < 1 || index > 0x7fffffff)
					throw new Error('Channel key index exhausted');
				this.lock(
					'key-allocation/' + String(index).padStart(10, '0'),
					String(index)
				);
				return index;
			})
			.immediate();
	}

	/** Retain this exact enforceable exit before a peer can acquire spend authority. */
	requireEnforceableExit(channelId: string, exit: string): void {
		this.claim(
			'enforceable-exit/' + channelId,
			sha256(Buffer.from(exit, 'hex')).toString('hex')
		);
	}

	/** An operator or protocol failure has irrevocably selected the existing signed exit. */
	recordExitRequest(channelId: string, exit: string): void {
		this.claim(
			'exit-request/' + channelId,
			sha256(Buffer.from(exit, 'hex')).toString('hex')
		);
	}

	/** A chain observer may select another retained unrevoked funding generation after a reorg. */
	recordFundingExitChoice(channelId: string, digest: string): void {
		const anchor = this.exitRequest(channelId);
		if (!anchor || !/^[a-f0-9]{64}$/.test(digest))
			throw new Error('Original close decision is missing');
		const slot = 'funding-exit-choice/' + channelId;
		this.db
			.transaction(() => {
				const result = Buffer.from(digest).toString('hex');
				const previous = this.lock(slot, anchor);
				if (previous?.toString() === digest) return;
				this.db
					.prepare('UPDATE claims SET claim=? WHERE slot=?')
					.run(
						encryptValue(
							this.claimKey(slot),
							JSON.stringify({ transcript: anchor, result })
						),
						slot
					);
				if (this.chosenFundingExit(channelId) !== digest)
					throw new Error('Could not persist current funding exit');
			})
			.immediate();
	}

	chosenFundingExit(channelId: string): string | null {
		const anchor = this.exitRequest(channelId);
		if (!anchor) return null;
		const claim = this.read('funding-exit-choice/' + channelId);
		if (!claim) return anchor;
		const result = claim.result && Buffer.from(claim.result, 'hex').toString();
		if (
			claim.transcript !== anchor ||
			!result ||
			!/^[a-f0-9]{64}$/.test(result)
		)
			throw new Error('Invalid current funding exit selection');
		return result;
	}

	exitRequest(channelId: string): string | null {
		this.verifyFiles();
		return this.read('exit-request/' + channelId)?.transcript ?? null;
	}

	assertEnforceableExits(load: (channelId: string) => Buffer | null): void {
		this.verifyFiles();
		for (const row of this.db
			.prepare(
				"SELECT slot, claim FROM claims WHERE slot GLOB 'enforceable-exit/*'"
			)
			.iterate() as Iterable<{ slot: string; claim: string }>) {
			const id = row.slot.slice('enforceable-exit/'.length);
			const exit = /^[a-f0-9]{64}$/.test(id) && load(id);
			const { transcript } = this.decodeClaim(row.slot, row.claim);
			if (!exit || sha256(exit).toString('hex') !== transcript)
				throw new Error(
					'Original wallet is missing its authorized opening exit'
				);
		}
	}

	/** Reserve all wallet inputs together before the signer can release any funding witness. */
	bindFundingInputs(outpoints: readonly string[], transcript: string): void {
		if (!outpoints.length) return;
		this.verifyFiles();
		this.db
			.transaction(() => {
				for (const outpoint of outpoints)
					this.lock('wallet-input/' + outpoint, transcript);
			})
			.immediate();
	}

	bindCandidate(channelId: string, outpoint: string, transcript: string): void {
		this.verifyFiles();
		this.db
			.transaction(() => {
				this.lock('channel/' + channelId, transcript);
				this.lock('funding/' + outpoint, transcript);
			})
			.immediate();
	}

	finish(slot: string, transcript: string, result: Buffer): Buffer {
		this.verifyFiles();
		return this.db
			.transaction(() => {
				const held = this.read(slot);
				const encoded = result.toString('hex');
				if (
					!held ||
					held.transcript !== transcript ||
					(held.result !== null && held.result !== encoded)
				)
					throw new Error('Opening signer result does not match its claim');
				if (!held.result) {
					this.db
						.prepare('UPDATE claims SET claim=? WHERE slot=?')
						.run(
							encryptValue(
								this.claimKey(slot),
								JSON.stringify({ transcript, result: encoded })
							),
							slot
						);
					if (this.read(slot)?.result !== encoded)
						throw new Error('Could not store opening signer result');
				}
				return Buffer.from(result);
			})
			.immediate();
	}
}
