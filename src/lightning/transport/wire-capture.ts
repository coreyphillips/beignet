/**
 * Wire-message capture for protocol debugging (SPLICE_CAPTURE=1).
 *
 * When the SPLICE_CAPTURE environment variable is set, every non-gossip wire
 * message (both directions) plus connection lifecycle events are appended as
 * JSONL to a capture file, so an interop failure (e.g. a peer disconnecting
 * during splice reestablish) can be reconstructed message-by-message.
 *
 * SPLICE_CAPTURE=1        → ~/.beignet/splice-capture-<YYYY-MM-DD>.jsonl
 * SPLICE_CAPTURE=/a/path  → that file
 *
 * Writes are synchronous appends: capture is a debugging aid and ordering of
 * records matters more than throughput. Gossip and ping/pong are skipped to
 * keep the file readable.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { MessageType } from '../message/types';

/** High-volume message types that would drown the capture. */
const SKIPPED_TYPES = new Set<number>([
	MessageType.PING,
	MessageType.PONG,
	MessageType.CHANNEL_ANNOUNCEMENT,
	MessageType.NODE_ANNOUNCEMENT,
	MessageType.CHANNEL_UPDATE,
	MessageType.QUERY_SHORT_CHANNEL_IDS,
	MessageType.REPLY_SHORT_CHANNEL_IDS_END,
	MessageType.QUERY_CHANNEL_RANGE,
	MessageType.REPLY_CHANNEL_RANGE,
	MessageType.GOSSIP_TIMESTAMP_FILTER
]);

let capturePath: string | null | undefined;

function resolveCapturePath(): string | null {
	if (capturePath !== undefined) return capturePath;
	const env = process.env.SPLICE_CAPTURE;
	if (!env || env === '0' || env.toLowerCase() === 'false') {
		capturePath = null;
		return capturePath;
	}
	if (env === '1' || env.toLowerCase() === 'true') {
		const dir = path.join(os.homedir(), '.beignet');
		try {
			fs.mkdirSync(dir, { recursive: true });
		} catch {
			// fall through; append below will fail and disable capture
		}
		const date = new Date().toISOString().slice(0, 10);
		capturePath = path.join(dir, `splice-capture-${date}.jsonl`);
	} else {
		capturePath = path.resolve(env);
	}
	return capturePath;
}

export function isWireCaptureEnabled(): boolean {
	return resolveCapturePath() !== null;
}

function append(record: Record<string, unknown>): void {
	const file = resolveCapturePath();
	if (!file) return;
	try {
		fs.appendFileSync(
			file,
			JSON.stringify({ ts: new Date().toISOString(), ...record }) + '\n'
		);
	} catch {
		capturePath = null; // unwritable destination: disable for the session
	}
}

/** Record a wire message. `dir` is relative to us: 'in' = received. */
export function captureWireMessage(
	dir: 'in' | 'out',
	peerPubkey: string,
	type: number,
	payload: Buffer
): void {
	if (!isWireCaptureEnabled() || SKIPPED_TYPES.has(type)) return;
	append({
		dir,
		peer: peerPubkey,
		type,
		name: MessageType[type] ?? `unknown_${type}`,
		len: payload.length,
		payload: payload.toString('hex')
	});
}

/** Record a connection lifecycle event (connect/close/error) with a reason. */
export function captureWireEvent(
	event: string,
	peerPubkey: string,
	detail?: string
): void {
	if (!isWireCaptureEnabled()) return;
	append({
		dir: 'event',
		event,
		peer: peerPubkey,
		...(detail ? { detail } : {})
	});
}
