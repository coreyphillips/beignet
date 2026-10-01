/**
 * Authentication for database backups (issue #1228).
 *
 * Storage encryption only hides the sensitive columns: a plaintext row is
 * still read, and encrypted on open, and the lookup tables are never
 * encrypted at all. So a backup is authenticated as a whole file, with an
 * HMAC-SHA256 under a key derived from the wallet seed, kept next to it in
 * `<backup>.hmac`. The backup stays an ordinary SQLite file.
 */

import { createHmac } from 'crypto';
import * as fs from 'fs';
import { hkdfKey } from '../lightning/storage/encryption';
import { writeFileAtomic } from './fs-utils';

const BACKUP_MAC_INFO = 'beignet-db-backup-mac-v1';
const BACKUP_MAC_PREFIX = 'beignet-db-mac-v1:';

/** Where the MAC of the backup at `backupPath` is kept. */
export function backupMacPath(backupPath: string): string {
	return `${backupPath}.hmac`;
}

/** The backup MAC key for a wallet seed (bip39 mnemonicToSeed output). */
export function deriveBackupMacKey(seed: Buffer): Buffer {
	return hkdfKey(seed, BACKUP_MAC_INFO);
}

/** HMAC-SHA256 of a file's bytes. */
export async function fileMac(key: Buffer, filePath: string): Promise<Buffer> {
	const hmac = createHmac('sha256', key);
	for await (const chunk of fs.createReadStream(filePath)) {
		hmac.update(chunk as Buffer);
	}
	return hmac.digest();
}

/** Write the MAC of the backup at `backupPath` to its sidecar. */
export async function writeBackupMac(
	key: Buffer,
	backupPath: string
): Promise<void> {
	const mac = await fileMac(key, backupPath);
	writeFileAtomic(
		backupMacPath(backupPath),
		`${BACKUP_MAC_PREFIX}${mac.toString('hex')}\n`
	);
}

/**
 * The MAC recorded for the backup at `backupPath`, or null when it has no
 * sidecar. Throws when the sidecar is not a MAC this release wrote.
 */
export function readBackupMac(backupPath: string): Buffer | null {
	const macPath = backupMacPath(backupPath);
	let text: string;
	try {
		text = fs.readFileSync(macPath, 'utf8').trim();
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
		throw err;
	}
	const hex = text.startsWith(BACKUP_MAC_PREFIX)
		? text.slice(BACKUP_MAC_PREFIX.length)
		: '';
	if (!/^[0-9a-f]{64}$/.test(hex)) {
		throw new Error(`Malformed backup MAC file: ${macPath}`);
	}
	return Buffer.from(hex, 'hex');
}
