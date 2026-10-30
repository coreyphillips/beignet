import * as fs from 'fs';
import * as path from 'path';
import { createHash, randomBytes } from 'crypto';
import type { DirectFundingStorage } from './client';

/**
 * Single-writer, atomic, fsynced storage for one wallet. Contents include payment
 * signatures and receipts, but no wallet keys. Use an encrypted disk if needed.
 * After a process crash, verify that the old process is stopped before removing
 * the .writer-lock directory. Never remove a live writer's lock.
 */
export class FileDirectFundingStorage implements DirectFundingStorage {
	private readonly lock: string;
	private closed = false;

	constructor(private readonly directory: string) {
		this.directory = path.resolve(directory);
		fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
		this.lock = path.join(this.directory, '.writer-lock');
		try {
			fs.mkdirSync(this.lock, { mode: 0o700 });
		} catch (err) {
			if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
				throw new Error(
					`storage is locked: ${this.lock}; verify the previous writer has stopped before removing a stale lock`
				);
			}
			throw err;
		}
	}

	loadWalletData(key: string): string | null {
		this.assertOpen();
		let raw: string;
		try {
			raw = fs.readFileSync(this.file(key), 'utf8');
		} catch (err) {
			if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
			throw err;
		}
		const entry = JSON.parse(raw) as { key?: unknown; value?: unknown };
		if (entry?.key !== key || typeof entry.value !== 'string') {
			throw new Error('invalid direct-funding storage entry');
		}
		return entry.value;
	}

	saveWalletData(key: string, value: string): void {
		this.assertOpen();
		const destination = this.file(key);
		const temporary = `${destination}.${randomBytes(12).toString('hex')}.tmp`;
		try {
			const fd = fs.openSync(temporary, 'wx', 0o600);
			try {
				fs.writeFileSync(fd, JSON.stringify({ key, value }));
				fs.fsyncSync(fd);
			} finally {
				fs.closeSync(fd);
			}
			fs.renameSync(temporary, destination);
			const dir = fs.openSync(this.directory, 'r');
			try {
				fs.fsyncSync(dir);
			} finally {
				fs.closeSync(dir);
			}
		} finally {
			if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
		}
	}

	/** Call only after all payments and reconciliation work have finished. */
	close(): void {
		if (this.closed) return;
		fs.rmdirSync(this.lock);
		this.closed = true;
	}

	private file(key: string): string {
		return path.join(
			this.directory,
			`${createHash('sha256').update(key).digest('hex')}.json`
		);
	}

	private assertOpen(): void {
		if (this.closed) throw new Error('direct-funding storage is closed');
	}
}

export { NodePeerMessaging } from './peer-messaging';
export type { INodePeerMessagingOptions } from './peer-messaging';
export type {
	TransportConnectFn,
	IDuplexTransport
} from '../lightning/transport/duplex-transport';
