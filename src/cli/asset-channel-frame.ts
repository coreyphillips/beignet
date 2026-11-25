import path from 'path';
import { nodeFs } from '../utils/node-builtins';
import { hkdfKey } from '../lightning/storage/encryption';
import {
	encodeFrame,
	decodeFrame,
	hashFrame
} from '../lightning/recovery/frame-codec';
import { deriveFrameIv } from '../lightning/recovery/guardian-wire';
import {
	encryptFrame,
	decryptFrame,
	deriveFrameKey,
	frameAad
} from '../lightning/recovery/journal';
import type { RecoveryFrame } from '../lightning/recovery/types';

const MAGIC = Buffer.from('BGNACRF1', 'ascii');
// Magic, uint64 sequence, predecessor hash and canonical plaintext hash.
const HEADER = 80;
// Bound memory before decrypting an untrusted backup containing opening proof histories.
const MAX_FILE_BYTES = 128 * 1024 * 1024;

function channelKey(macKey: Buffer, channel: Buffer): Buffer {
	return deriveFrameKey(
		hkdfKey(macKey, 'beignet-original-asset-channel-frame-v1'),
		channel,
		1n
	);
}

export function writeAssetChannelFrame(
	dest: string,
	macKey: Buffer,
	createFrame: () => RecoveryFrame
): void {
	const fs = nodeFs();
	if (fs.lstatSync(dest, { throwIfNoEntry: false }))
		throw Error('Recovery frame destination already exists');
	const parent = path.dirname(dest);
	const dir = fs.mkdtempSync(path.join(parent, '.asset-channel-frame-'));
	try {
		const staged = path.join(dir, 'frame');
		const frame = createFrame();
		if (frame.version !== 6 || !frame.originalDeviceChannel)
			throw Error('Expected original-device recovery frame');
		const plaintext = encodeFrame(frame);
		if (HEADER + 28 + plaintext.length > MAX_FILE_BYTES)
			throw Error('Asset channel recovery frame exceeds size limit');
		const hash = hashFrame(plaintext);
		const channel = Buffer.from(frame.originalDeviceChannel.channelId, 'hex');
		const header = Buffer.alloc(HEADER);
		MAGIC.copy(header);
		header.writeBigUInt64BE(frame.sequence, 8);
		frame.previousFrameHash.copy(header, 16);
		hash.copy(header, 48);
		const sealed = encryptFrame(
			channelKey(macKey, channel),
			plaintext,
			frameAad(channel, 1n, frame.sequence, frame.previousFrameHash),
			deriveFrameIv(channel, 1n, frame.sequence, hash)
		);
		const fd = fs.openSync(staged, 'wx', 0o600);
		try {
			fs.writeFileSync(fd, header);
			fs.writeFileSync(fd, sealed);
			fs.fsyncSync(fd);
		} finally {
			fs.closeSync(fd);
		}
		// link is exclusive even when another writer created the destination during capture.
		fs.linkSync(staged, dest);
		if (process.platform !== 'win32') {
			const directory = fs.openSync(parent, 'r');
			try {
				fs.fsyncSync(directory);
			} finally {
				fs.closeSync(directory);
			}
		}
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
}

/** An ordinary database backup continues through the existing SQLite authentication path. */
export function readAssetChannelFrame(
	file: string,
	id: string,
	macKey: Buffer
): RecoveryFrame | undefined {
	const fs = nodeFs();
	const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
	try {
		const stat = fs.fstatSync(fd);
		if (!stat.isFile()) throw Error('Recovery backup must be a regular file');
		const magic = Buffer.alloc(MAGIC.length);
		if (
			fs.readSync(fd, magic, 0, magic.length, 0) !== magic.length ||
			!magic.equals(MAGIC)
		)
			return undefined;
		if (
			!/^[0-9a-f]{64}$/.test(id) ||
			stat.size <= HEADER + 28 ||
			stat.size > MAX_FILE_BYTES
		)
			throw Error('Invalid asset channel recovery frame');
		const bytes = Buffer.allocUnsafe(stat.size);
		let offset = 0;
		while (offset < bytes.length) {
			const n = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
			if (!n) throw Error('Asset channel recovery frame is truncated');
			offset += n;
		}
		const sequence = bytes.readBigUInt64BE(8),
			previous = bytes.subarray(16, 48),
			hash = bytes.subarray(48, 80);
		const channel = Buffer.from(id, 'hex');
		const plain = decryptFrame(
			channelKey(macKey, channel),
			bytes.subarray(HEADER),
			frameAad(channel, 1n, sequence, previous)
		);
		if (!bytes.subarray(0, 8).equals(MAGIC) || !hashFrame(plain).equals(hash))
			throw Error('Asset channel recovery frame hash does not match');
		const frame = decodeFrame(plain, { originalDevice: true });
		if (
			frame.version !== 6 ||
			frame.originalDeviceChannel?.channelId !== id ||
			frame.sequence !== sequence ||
			!frame.previousFrameHash.equals(previous)
		)
			throw Error(
				'Asset channel recovery frame header differs from its checkpoint'
			);
		return frame;
	} finally {
		fs.closeSync(fd);
	}
}
