import { Transaction } from 'bitcoinjs-lib';
import { isValidPublicKey } from '../crypto/ecdh';
import {
	decodeTxCompleteMessage,
	encodeTxAddInputMessage,
	encodeTxAddOutputMessage,
	encodeTxCompleteMessage,
	type ITxCompleteMessage
} from '../message/interactive-tx';
import { MAX_LIGHTNING_PAYLOAD } from '../message/custom-records';
import { MessageType as M } from '../message/types';
import type { SqliteStorage } from '../storage/sqlite-storage';
import {
	alternatingConstructionTurns,
	type IAssetConstructionTurn
} from './asset-opening-construction';
import {
	assetSpliceConstructionView,
	type IAssetSpliceLayout,
	type verifyAssetSpliceCandidate
} from './asset-splice-manifest';
import {
	freshSplicePublicNonce,
	spliceConstruction
} from './final-splice-transcript';
import type {
	IFinalSpliceCandidate,
	IFinalSpliceTerms
} from './final-splice-candidate';
import type { FinalSpliceEvent } from './final-splice-state';

interface Frame {
	type: M;
	payload: Buffer;
}
type Nonces = Required<ITxCompleteMessage>;
interface Binding {
	attempt: string;
	finalDigest: string;
	txid: string;
	initiator: boolean;
}
type Wire = Extract<FinalSpliceEvent, { kind: 'wire' }>;
type Entry = Binding &
	(
		| { kind: 'construction-start'; localComplete: string }
		| { kind: 'construction-frame'; local: boolean; type: M; payload: string }
	);
function complete(raw: Buffer, id: Buffer): Nonces {
	const m = decodeTxCompleteMessage(raw, { taproot: true });
	if (
		!m.channelId.equals(id) ||
		!m.commitNonces ||
		!m.fundingInputNonce ||
		!encodeTxCompleteMessage(m).equals(raw)
	)
		throw new Error('Incomplete or noncanonical asset splice nonce promise');
	const keys = [
		m.commitNonces.current,
		m.commitNonces.next,
		m.fundingInputNonce
	];
	if (
		keys.some(
			(n) =>
				n.length !== 66 ||
				!isValidPublicKey(n.subarray(0, 33)) ||
				!isValidPublicKey(n.subarray(33))
		) ||
		new Set(keys.map((n) => n.toString('hex'))).size !== 3
	)
		throw new Error('Invalid or repeated asset splice nonce');
	return {
		channelId: m.channelId,
		commitNonces: m.commitNonces,
		fundingInputNonce: m.fundingInputNonce
	};
}
const nonceKeys = (n: Nonces): string[] =>
	[n.commitNonces.current, n.commitNonces.next, n.fundingInputNonce].map((b) =>
		b.toString('hex')
	);

/** Validate and persist each BOLT construction frame before the caller sends or acts on it. */
export class AssetSpliceConstruction {
	private readonly id: Buffer;
	private readonly idHex: string;
	private readonly binding: Binding;
	private readonly terms: IFinalSpliceTerms;
	private readonly frozen: string;
	private readonly localComplete: Buffer;
	private readonly turns: IAssetConstructionTurn[];
	constructor(
		layout: IAssetSpliceLayout,
		verified: ReturnType<typeof verifyAssetSpliceCandidate>,
		localComplete: Buffer,
		private readonly store: SqliteStorage
	) {
		const view = assetSpliceConstructionView(layout, verified);
		if (!store.canSpliceDualFundedAssets)
			throw new Error('Asset splice construction requires the original device');
		this.id = Buffer.from(layout.channelId);
		this.idHex = this.id.toString('hex');
		this.terms = view.terms;
		this.frozen = view.transaction;
		const tx = Transaction.fromHex(this.frozen);
		this.binding = {
			attempt: layout.attempt.toString('hex'),
			finalDigest: view.finalDigest,
			txid: tx.getId(),
			initiator: view.terms.localIsSpliceInitiator
		};
		this.localComplete = Buffer.from(localComplete);
		complete(this.localComplete, this.id);
		const sides: IAssetConstructionTurn[][] = [[], []];
		for (const x of layout.inputs) {
			const side = Number(x.serialId & 1n);
			sides[side].push({
				initiator: side === 0,
				type: M.TX_ADD_INPUT,
				payload: encodeTxAddInputMessage({
					channelId: this.id,
					serialId: x.serialId,
					prevTx: x.isShared ? Buffer.alloc(0) : x.prevTx!,
					prevTxVout: x.prevOutputIndex,
					sequence: x.sequence,
					...(x.isShared && { sharedInputTxid: x.prevTxid })
				})
			});
		}
		for (const [i, o] of layout.outputs.entries()) {
			const side = Number(o.serialId & 1n);
			sides[side].push({
				initiator: side === 0,
				type: M.TX_ADD_OUTPUT,
				payload: encodeTxAddOutputMessage({
					channelId: this.id,
					serialId: o.serialId,
					amountSats: o.amountSats,
					scriptPubkey: tx.outs[i].script
				})
			});
		}
		this.turns = alternatingConstructionTurns(sides);
		if (this.turns.some(t => t.payload && t.payload.length > MAX_LIGHTNING_PAYLOAD))
			throw new Error('Asset splice construction exceeds the BOLT payload limit');
		const head = store.readAssetSpliceJournal<Entry>(this.idHex);
		const saved = head.records.find(
			(r) =>
				r.kind === 'construction-start' && r.attempt === this.binding.attempt
		);
		if (!saved) {
			if (head.records.some(r => r.kind === 'construction-frame' && r.attempt === this.binding.attempt))
				throw new Error('Asset splice frames lack their initial reservation');
			const localKeys = new Set(
				nonceKeys(complete(this.localComplete, this.id))
			);
			for (const r of head.records) {
				if (
					r.kind !== 'construction-start' &&
					!(r.kind === 'construction-frame' && r.type === M.TX_COMPLETE)
				)
					continue;
				const other = Buffer.from(
					r.kind === 'construction-start' ? r.localComplete : r.payload,
					'hex'
				);
				if (nonceKeys(complete(other, this.id)).some((k) => localKeys.has(k)))
					throw new Error(
						'Asset splice nonce already belongs to another construction'
					);
			}
			store.appendAssetSpliceEvent(this.idHex, head, {
				kind: 'construction-start',
				...this.binding,
				localComplete: this.localComplete.toString('hex')
			} satisfies Entry);
		}
		this.state();
	}
	private state() {
		const head = this.store.readAssetSpliceJournal<Entry>(this.idHex);
		const frames: Wire[] = [];
		const used = new Set(nonceKeys(complete(this.localComplete, this.id)));
		let started = false;
		for (const entry of head.records) {
			if (
				entry.kind !== 'construction-start' &&
				entry.kind !== 'construction-frame'
			)
				continue;
			if (entry.attempt !== this.binding.attempt) {
				if (
					entry.kind === 'construction-start' ||
					entry.type === M.TX_COMPLETE
				) {
					const prior = complete(
						Buffer.from(
							entry.kind === 'construction-start'
								? entry.localComplete
								: entry.payload,
							'hex'
						),
						this.id
					);
					for (const k of nonceKeys(prior)) used.add(k);
				}
				continue;
			}
			if (
				entry.finalDigest !== this.binding.finalDigest ||
				entry.initiator !== this.binding.initiator ||
				entry.txid !== this.binding.txid
			)
				throw new Error('Asset splice construction binding changed');
			if (entry.kind === 'construction-start') {
				if (
					started ||
					entry.localComplete !== this.localComplete.toString('hex')
				)
					throw new Error('Asset splice nonce reservation changed');
				started = true;
				continue;
			}
			if (!started)
				throw new Error('Missing initial asset splice nonce reservation');
			const raw = Buffer.from(entry.payload, 'hex');
			if (raw.toString('hex') !== entry.payload)
				throw new Error('Invalid asset splice wire bytes');
			this.validate(frames.length, entry.local, entry.type, raw, used);
			frames.push({
				kind: 'wire',
				local: entry.local,
				type: entry.type,
				payload: entry.payload
			});
		}
		if (!started) throw new Error('Missing asset splice construction');
		return { head, frames, used };
	}
	private validate(
		position: number,
		local: boolean,
		type: M,
		raw: Buffer,
		used: Set<string>
	): void {
		const turn = this.turns[position];
		if (
			!turn ||
			turn.type !== type ||
			local !== (turn.initiator === this.binding.initiator) ||
			(turn.payload && !turn.payload.equals(raw))
		)
			throw new Error(
				'Unexpected asset splice construction turn or contribution'
			);
		if (type !== M.TX_COMPLETE) return;
		const keys = nonceKeys(complete(raw, this.id));
		if (local && position >= this.turns.length - 2) {
			if (!raw.equals(this.localComplete))
				throw new Error('Final asset splice nonce promise changed');
		} else if (keys.some((k) => used.has(k)))
			throw new Error('Asset splice verification nonce already used');
		for (const k of keys) used.add(k);
	}
	private write(
		s: ReturnType<AssetSpliceConstruction['state']>,
		local: boolean,
		type: M,
		payload: Buffer
	): void {
		this.validate(s.frames.length, local, type, payload, s.used);
		this.store.appendAssetSpliceEvent(this.idHex, s.head, {
			kind: 'construction-frame',
			...this.binding,
			local,
			type,
			payload: payload.toString('hex')
		} satisfies Entry);
	}
	next(): Frame | undefined {
		const s = this.state(),
			turn = this.turns[s.frames.length];
		if (!turn || turn.initiator !== this.binding.initiator) return;
		let payload = turn.payload;
		if (!payload)
			payload =
				s.frames.length >= this.turns.length - 2
					? this.localComplete
					: encodeTxCompleteMessage({
							channelId: this.id,
							commitNonces: {
								current: freshSplicePublicNonce(),
								next: freshSplicePublicNonce()
							},
							fundingInputNonce: freshSplicePublicNonce()
					  });
		this.write(s, true, turn.type, payload);
		return { type: turn.type, payload: Buffer.from(payload) };
	}
	replay(): Frame | undefined {
		const { frames } = this.state(),
			last = frames[frames.length - 1];
		return last?.local
			? { type: last.type, payload: Buffer.from(last.payload, 'hex') }
			: undefined;
	}
	receive(type: M, payload: Buffer): void {
		if (payload.length > MAX_LIGHTNING_PAYLOAD) throw new Error('Oversize asset splice frame');
		const s = this.state(),
			raw = payload.toString('hex');
		if (s.frames.some((m) => !m.local && m.type === type && m.payload === raw))
			return;
		this.write(s, false, type, payload);
	}
	agreement():
		| { candidate: IFinalSpliceCandidate; local: Nonces; peer: Nonces }
		| undefined {
		const { frames } = this.state();
		if (frames.length !== this.turns.length) return;
		const built = spliceConstruction(
			{ intent: { initiator: this.binding.initiator }, messages: frames },
			this.terms
		);
		const candidate = built.build();
		if (
			!built.localComplete ||
			!built.peerComplete ||
			candidate.tx.toHex() !== this.frozen
		)
			throw new Error(
				'Interactive asset splice differs from its verified transaction'
			);
		return {
			candidate,
			local: complete(built.localComplete, this.id),
			peer: complete(built.peerComplete, this.id)
		};
	}
}
