import {
	encodeStartBatchMessage,
	decodeStartBatchMessage
} from '../message/splice';
import { assetUpdateHistory } from '../storage/asset-update-history';
import { sha256 } from '../crypto/provider';
import { decodeCommitmentSignedMessage } from '../message/channel-commitment';
import {
	ASSET_OPEN_OBJECT_LIMIT,
	ASSET_OPEN_CHUNK_SIZE,
	AssetOpenObjectReceiver,
	decodeAssetOpenFrame,
	encodeAssetOpenFrame
} from '../message/asset-open';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	encodeCustomMessage
} from '../message/custom';
import { MessageType as M } from '../message/types';
import type { AssetSpliceUpdateBatch } from './asset-splice-update-batch';
import type { IFinalOpeningRuntime } from './final-opening-runtime';
import {
	decodeAssetUpdateIntent,
	encodeAssetUpdateIntent
} from './asset-splice-update-intent';
import type {
	IAssetSpliceUpdateHost,
	AssetUpdateChange
} from './asset-splice-update-provider';

type Phase = 'layout' | 'layout_ack' | 'authorization' | 'exit' | 'final';
type Entry = {
	kind: 'asset-update-peer';
	height: string;
	attempt: string;
	origin: boolean;
	bytes: string;
};
type Session = {
	id: string;
	peer: string;
	entry: Entry;
	changes: AssetUpdateChange[];
	ack: boolean;
	batch?: AssetSpliceUpdateBatch;
	sent: Set<string>;
	received: Map<Phase, Buffer>;
	chunks: Map<Phase, AssetOpenObjectReceiver>;
	peerFrames: Buffer[];
	sentBatch?: Buffer[];
	retained: boolean;
	completed: boolean;
};
interface Params {
	peer: string;
	originalInitiator: boolean;
}
const limit = 20;
const phaseLimit = (phase: Phase) =>
	phase === 'layout'
		? 65536
		: phase === 'authorization'
		? 8192
		: ASSET_OPEN_OBJECT_LIMIT;
const heightBytes = (n: bigint) => {
	const b = Buffer.alloc(8);
	b.writeBigUInt64BE(n);
	return b;
};
function attempt(id: string, height: bigint, intent: Buffer) {
	return sha256(
		Buffer.concat([
			Buffer.from('asset-update-peer/v1\0'),
			Buffer.from(id, 'hex'),
			heightBytes(height),
			intent
		])
	);
}
export function hasAssetUpdateHost(h: unknown): h is IAssetSpliceUpdateHost {
	const a = h as Partial<IAssetSpliceUpdateHost> | undefined;
	return (
		!!a &&
		typeof a.signAssetUpdateViews === 'function' &&
		typeof a.signAssetUpdateHtlcs === 'function' &&
		typeof a.verifyAssetUpdateViews === 'function' &&
		typeof a.retainAssetUpdateViews === 'function'
	);
}
function checkAuthor(
	changes: readonly AssetUpdateChange[],
	local: boolean,
	originalInitiator: boolean
) {
	const author = local ? 'local' : 'peer';
	for (const v of changes) {
		if (
			v.kind === 'fee'
				? local !== originalInitiator
				: v.kind === 'add'
				? v.htlc.offeredBy !== author
				: v.offeredBy === author
		)
			throw Error('Peer cannot authorize another wallet commitment change');
	}
}

/** Peer-authenticated private control messages precede a standard ordered commitment_signed batch and revoke_and_ack. */
export class AssetSpliceUpdateTransport {
	private sessions = new Map<string, Session>();
	private intents = new Map<
		string,
		{ height: bigint; attempt: string; receiver: AssetOpenObjectReceiver }
	>();
	private early = new Map<
		string,
		{ peer: string; frames: Buffer[]; bytes: number }
	>();
	private batches = new Map<
		string,
		{ id: string; size: number; parts: Buffer[] }
	>();
	private queues = new Map<string, { tail: Promise<void>; pending: number }>();
	constructor(
		private readonly runtime: IFinalOpeningRuntime,
		private readonly host: IAssetSpliceUpdateHost,
		private readonly channel: (id: string) => Params | undefined,
		private readonly currentHeight: (id: string) => number | undefined,
		private readonly send: (peer: string, type: number, raw: Buffer) => void,
		private readonly settled: (id: string) => Promise<void>,
		private readonly report: (id: string, error: string) => void,
		private readonly knownPeer: (id: string, peer: string) => boolean = () =>
			false
	) {}
	private run(id: string, action: () => Promise<void>) {
		const q = this.queues.get(id) ?? { tail: Promise.resolve(), pending: 0 };
		if (q.pending >= 160)
			return Promise.reject(new Error('Too many queued asset update frames'));
		q.pending++;
		this.queues.set(id, q);
		const result = q.tail.then(action);
		q.tail = result
			.catch(() => undefined)
			.finally(() => {
				if (--q.pending === 0 && this.queues.get(id) === q)
					this.queues.delete(id);
			});
		return result;
	}
	private head(id: string) {
		return this.runtime.storage.assetSpliceUpdateHead(id);
	}
	private remembered(id: string, height: bigint) {
		return this.runtime.storage
			.readAssetSpliceJournal<Entry>(id)
			.records.filter(
				(r) => r.kind === 'asset-update-peer' && r.height === String(height)
			)
			.pop();
	}
	private session(id: string, p: Params, entry: Entry) {
		const existing = this.sessions.get(id);
		if (existing?.entry.attempt === entry.attempt) return existing;
		const changes = decodeAssetUpdateIntent(
			id,
			p.originalInitiator,
			Buffer.from(entry.bytes, 'hex')
		);
		checkAuthor(changes, entry.origin, p.originalInitiator);
		const s: Session = {
			id,
			peer: p.peer,
			entry,
			changes,
			ack: false,
			sent: new Set(),
			received: new Map(),
			chunks: new Map(),
			peerFrames: [],
			retained: false,
			completed: false
		};
		this.sessions.set(id, s);
		return s;
	}
	private remember(
		id: string,
		p: Params,
		height: bigint,
		origin: boolean,
		bytes: Buffer
	) {
		const digest = attempt(id, height, bytes).toString('hex'),
			existing = this.remembered(id, height);
		const e: Entry = {
			kind: 'asset-update-peer',
			height: String(height),
			attempt: digest,
			origin,
			bytes: bytes.toString('hex')
		};
		const changes = decodeAssetUpdateIntent(id, p.originalInitiator, bytes);
		checkAuthor(changes, origin, p.originalInitiator);
		const batch = this.runtime.storage.assetSpliceUpdateBatch(
			id,
			this.runtime.root,
			height,
			changes,
			() => this.currentHeight(id)
		);
		if (existing?.attempt !== digest) {
			// Crossed unsigned requests are sequenced by the original channel opener. Published offers can only replay.
			if (
				existing &&
				(this.head(id).inProgress || existing.origin === p.originalInitiator)
			)
				throw Error('Another asset update has priority at this height');
			this.runtime.storage.appendAssetSpliceEvent(
				id,
				this.runtime.storage.readAssetSpliceJournal(id),
				e
			);
		}
		const session = this.session(
			id,
			p,
			existing?.attempt === digest ? existing : e
		);
		session.batch ??= batch;
		return session;
	}
	private emit(s: Session, k: string, type: number, wire: Buffer) {
		if (this.sessions.get(s.id) !== s || s.sent.has(k)) return;
		this.send(s.peer, type, wire);
		s.sent.add(k);
	}
	private object(s: Session, phase: Phase, bytes: Buffer) {
		if (s.sent.has(phase)) return;
		const ack = phase === 'layout_ack',
			digest = ack ? bytes : sha256(bytes),
			total = ack ? 0 : bytes.length;
		if (total > phaseLimit(phase) || !bytes.length)
			throw Error('Invalid asset update object size');
		const header = Buffer.concat([
			Buffer.from(s.id, 'hex'),
			heightBytes(BigInt(s.entry.height))
		]);
		for (
			let offset = 0;
			offset < Math.max(total, 1);
			offset += ASSET_OPEN_CHUNK_SIZE
		) {
			const frame = encodeAssetOpenFrame({
				phase,
				attempt: Buffer.from(s.entry.attempt, 'hex'),
				digest,
				total,
				offset,
				bytes: ack
					? Buffer.alloc(0)
					: bytes.subarray(offset, offset + ASSET_OPEN_CHUNK_SIZE)
			});
			this.emit(
				s,
				phase + '/' + offset,
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				encodeCustomMessage(
					BeignetCustomSubtype.ASSET_UPDATE,
					Buffer.concat([header, frame])
				)
			);
		}
		s.sent.add(phase);
	}
	async start(id: string, changes: readonly AssetUpdateChange[]) {
		const p = this.channel(id);
		if (!p || !this.currentHeight(id))
			throw Error('Asset update requires an authenticated funded channel');
		checkAuthor(changes, true, p.originalInitiator);
		const raw = encodeAssetUpdateIntent(id, p.originalInitiator, changes);
		await this.run(id, async () => {
			const h = this.head(id);
			if (h.inProgress)
				throw Error('Another asset update is awaiting settlement');
			const s = this.remember(id, p, h.nextNumber, true, raw);
			await this.drive(s, p);
		});
	}
	private sendCommitments(s: Session, wires: Buffer[]) {
		this.emit(
			s,
			'start-batch',
			M.START_BATCH,
			encodeStartBatchMessage({
				channelId: Buffer.from(s.id, 'hex'),
				batchSize: wires.length,
				messageType: M.COMMITMENT_SIGNED
			})
		);
		for (const [i, wire] of wires.entries())
			this.emit(s, 'commit/' + i, M.COMMITMENT_SIGNED, wire);
	}
	private async drive(s: Session, p: Params) {
		if (
			this.sessions.get(s.id) !== s ||
			!this.channel(s.id) ||
			!this.currentHeight(s.id)
		)
			return;
		if (s.entry.origin)
			this.object(s, 'layout', Buffer.from(s.entry.bytes, 'hex'));
		else this.object(s, 'layout_ack', Buffer.from(s.entry.attempt, 'hex'));
		if (s.entry.origin && !s.ack) return;
		s.batch ??= this.runtime.storage.assetSpliceUpdateBatch(
			s.id,
			this.runtime.root,
			BigInt(s.entry.height),
			s.changes,
			() =>
				this.sessions.get(s.id) === s ? this.currentHeight(s.id) : undefined
		);
		const b = s.batch;
		this.object(s, 'authorization', b.offer());
		const peerOffer = s.received.get('authorization');
		if (!peerOffer) return;
		b.acceptOffer(peerOffer);
		const own = await b.signAssetShares(this.host);
		if (this.sessions.get(s.id) !== s) return;
		this.object(s, 'exit', own);
		const peer = s.received.get('exit');
		if (!peer) return;
		const ordered = (local: Buffer, remote: Buffer) =>
			p.originalInitiator
				? ([local, remote] as const)
				: ([remote, local] as const);
		const joint = ordered(own, peer);
		const signature = await b.signAssetHtlcs(this.host, joint);
		if (this.sessions.get(s.id) !== s) return;
		this.object(s, 'final', signature);
		const peerChild = s.received.get('final');
		if (!peerChild) return;
		if (!s.sentBatch) {
			await b.verifyAssetShares(
				this.host,
				joint,
				ordered(signature, peerChild)
			);
			if (this.sessions.get(s.id) !== s) return;
			s.sentBatch = b.commitments();
		}
		this.sendCommitments(s, s.sentBatch);
		if (!s.retained) {
			if (s.peerFrames.length !== s.sentBatch.length) return;
			try {
				await b.acceptCommitments(this.host, s.peerFrames);
			} catch (e) {
				s.peerFrames = [];
				throw e;
			}
			s.retained = true;
		}
		if (this.sessions.get(s.id) === s)
			this.emit(s, 'revocation', M.REVOKE_AND_ACK, b.revocation());
	}
	private replaySettled(id: string, p: Params, height: bigint, digest: Buffer) {
		const head = this.head(id);
		if (head.inProgress || head.nextNumber !== height + 1n) return false;
		const entry = this.remembered(id, height);
		if (!entry || entry.attempt !== digest.toString('hex')) return false;
		const history = assetUpdateHistory(this.runtime.storage, id),
			state = history.states.get(height);
		const stage = (name: string) => history.stages.get(height + '/' + name);
		const revoke = stage('local-revoke');
		if (!state || !revoke || !stage('peer-revoke')) return false;
		const s = this.session(id, p, entry);
		if (s.sent.has('history')) return true;
		if (entry.origin) this.object(s, 'layout', Buffer.from(entry.bytes, 'hex'));
		else this.object(s, 'layout_ack', digest);
		for (const [field, name] of [
			['authorization', 'offer'],
			['exit', 'local-shares'],
			['final', 'local-htlcs']
		] as const) {
			const raw = stage(name);
			if (!raw) throw Error('Incomplete historic asset commitment exchange');
			this.object(s, field, Buffer.from(raw, 'hex'));
		}
		this.sendCommitments(
			s,
			state.localCommitments.map((wire) => Buffer.from(wire, 'hex'))
		);
		this.emit(s, 'revocation', M.REVOKE_AND_ACK, Buffer.from(revoke, 'hex'));
		s.completed = true;
		s.sent.add('history');
		return true;
	}

	custom(peer: string, raw: Buffer) {
		if (raw.length < 114) return;
		const id = raw.subarray(0, 32).toString('hex'),
			p = this.channel(id);
		if (p?.peer !== peer) {
			// Authenticated Noise peers can send immediately after their own reestablish finishes.
			if (!p && this.knownPeer(id, peer)) {
				const pending = this.early.get(id) ?? { peer, frames: [], bytes: 0 };
				if (
					pending.peer !== peer ||
					pending.frames.length >= 160 ||
					pending.bytes + raw.length > ASSET_OPEN_OBJECT_LIMIT
				) {
					this.report(
						id,
						'Too many asset update frames before reestablishment'
					);
					return;
				}
				pending.frames.push(Buffer.from(raw));
				pending.bytes += raw.length;
				this.early.set(id, pending);
			}
			return;
		}
		const height = raw.readBigUInt64BE(32),
			f = decodeAssetOpenFrame(raw.subarray(40));
		void this.run(id, async () => {
			if (this.channel(id)?.peer !== peer) return;
			if (this.replaySettled(id, p, height, f.attempt)) return;
			if (
				f.phase !== 'layout' &&
				f.phase !== 'layout_ack' &&
				f.phase !== 'authorization' &&
				f.phase !== 'exit' &&
				f.phase !== 'final'
			)
				throw Error('Unknown splice update phase');
			let s = this.sessions.get(id);
			if (f.phase === 'layout') {
				if (f.total > 65533)
					throw Error('Asset update intent exceeds its wire limit');
				const identity = f.attempt.toString('hex');
				let assembled = this.intents.get(id);
				if (!assembled) {
					assembled = {
						height,
						attempt: identity,
						receiver: new AssetOpenObjectReceiver(f.attempt, 'layout', 65533)
					};
					this.intents.set(id, assembled);
				}
				if (assembled.height !== height || assembled.attempt !== identity)
					throw Error('Overlapping asset update intents');
				let intent: Buffer | undefined;
				try {
					intent = assembled.receiver.receive(f);
				} catch (err) {
					this.intents.delete(id);
					throw err;
				}
				if (!intent) return;
				this.intents.delete(id);
				if (!attempt(id, height, intent).equals(f.attempt))
					throw Error('Unmatched asset update digest');
				const head = this.head(id),
					known = this.remembered(id, height);
				if (
					height !== head.nextNumber &&
					height !== head.inProgress?.stateNumber
				) {
					if (known?.attempt === f.attempt.toString('hex')) return;
					throw Error('Invalid asset update height');
				}
				const decoded = decodeAssetUpdateIntent(
					id,
					p.originalInitiator,
					intent
				);
				checkAuthor(decoded, false, p.originalInitiator);
				s = this.remember(id, p, height, false, Buffer.from(intent));
			}
			if (
				!s ||
				s.entry.height !== String(height) ||
				s.entry.attempt !== f.attempt.toString('hex')
			)
				return;
			if (f.phase === 'layout_ack') {
				if (!s.entry.origin || !f.digest.equals(f.attempt))
					throw Error('Unmatched asset update acknowledgement');
				s.ack = true;
			} else if (f.phase !== 'layout') {
				const previous = s.received.get(f.phase);
				if (previous) {
					if (
						f.total !== previous.length ||
						!f.digest.equals(sha256(previous)) ||
						!previous
							.subarray(f.offset, f.offset + f.bytes.length)
							.equals(f.bytes)
					)
						throw Error('Changed asset update proof replay');
				} else {
					let chunks = s.chunks.get(f.phase);
					if (!chunks) {
						chunks = new AssetOpenObjectReceiver(
							f.attempt,
							f.phase,
							phaseLimit(f.phase)
						);
						s.chunks.set(f.phase, chunks);
					}
					const full = chunks.receive(f);
					if (!full) return;
					s.chunks.delete(f.phase);
					s.received.set(f.phase, full);
				}
			}
			await this.drive(s, p);
		}).catch((e) => this.report(id, String(e)));
	}
	/** Called for every peer frame, before channel routing can hide an interleaved message. */
	collect(peer: string, type: number, raw: Buffer): boolean {
		const active = this.batches.get(peer);
		if (active) {
			const id = active.id;
			if (
				type !== M.COMMITMENT_SIGNED ||
				raw.length < 32 ||
				raw.subarray(0, 32).toString('hex') !== id
			) {
				this.batches.delete(peer);
				this.report(id, 'Unexpected message inside asset commitment batch');
				return true;
			}
			active.parts.push(Buffer.from(raw));
			if (active.parts.length === active.size) {
				this.batches.delete(peer);
				const s = this.sessions.get(id);
				void this.run(id, async () => {
					if (!s || this.sessions.get(id) !== s || s.completed) return;
					if (!s.batch || active.size !== s.batch.fundingCount)
						throw Error(
							'Asset commitment batch does not cover the elected funding set'
						);
					if (
						s.peerFrames.length &&
						!s.peerFrames.every((wire, i) => wire.equals(active.parts[i]))
					)
						throw Error('Conflicting asset commitment batch replay');
					s.peerFrames = active.parts;
					const p = this.channel(id);
					if (p?.peer === peer) await this.drive(s, p);
				}).catch((err) => this.report(id, String(err)));
			}
			return true;
		}
		if (type !== M.START_BATCH || raw.length < 32) return false;
		const id = raw.subarray(0, 32).toString('hex');
		if (this.channel(id)?.peer !== peer || !this.sessions.has(id)) return false;
		try {
			const m = decodeStartBatchMessage(raw);
			if (
				m.messageType !== M.COMMITMENT_SIGNED ||
				m.batchSize < 1 ||
				m.batchSize > limit
			)
				throw Error('Invalid asset commitment batch header');
			this.batches.set(peer, { id, size: m.batchSize, parts: [] });
		} catch (err) {
			this.report(id, String(err));
		}
		return true;
	}
	handle(peer: string, type: number, raw: Buffer) {
		if (this.collect(peer, type, raw)) return true;
		if (
			(type !== M.COMMITMENT_SIGNED && type !== M.REVOKE_AND_ACK) ||
			raw.length < 32
		)
			return false;
		const id = raw.subarray(0, 32).toString('hex'),
			s = this.sessions.get(id),
			p = this.channel(id);
		if (!s || p?.peer !== peer) return false;
		// A reconnect also replays prior opening and splice signatures. Only update members carry the wallet's HTLC record.
		if (
			type === M.COMMITMENT_SIGNED &&
			!decodeCommitmentSignedMessage(raw, {
				customRecords: true
			}).customRecords?.has(65537n)
		)
			return false;
		const msg = Buffer.from(raw);
		void this.run(id, async () => {
			if (this.sessions.get(id) !== s || !s.batch) return;
			if (type === M.REVOKE_AND_ACK) {
				if (!s.retained)
					throw Error(
						'Asset update revocation preceded the complete peer batch'
					);
				s.batch.receiveRevocation(msg);
				s.completed = true;
				await this.settled(id);
				return;
			}
			if (!s.completed)
				throw Error(
					'Asset commitment signature arrived outside its declared batch'
				);
		}).catch((e) => this.report(id, String(e)));
		return true;
	}
	disconnected(peer: string) {
		this.batches.delete(peer);
		for (const [id, p] of this.early)
			if (p.peer === peer) this.early.delete(id);
		for (const [id, s] of this.sessions)
			if (s.peer === peer) {
				this.sessions.delete(id);
				this.intents.delete(id);
			}
	}
	resume(peer: string, id: string) {
		const p = this.channel(id);
		if (p?.peer !== peer) return;
		void this.run(id, async () => {
			const head = this.head(id),
				e = this.remembered(
					id,
					head.inProgress?.stateNumber ?? head.nextNumber
				);
			if (e) await this.drive(this.session(id, p, e), p);
			const early = this.early.get(id);
			if (early?.peer === peer) {
				this.early.delete(id);
				for (const frame of early.frames) this.custom(peer, frame);
			}
		}).catch((e) => this.report(id, String(e)));
	}
}
