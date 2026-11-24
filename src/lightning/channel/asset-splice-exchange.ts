import { Transaction } from 'bitcoinjs-lib';
import { sha256 } from '../crypto/provider';
import {
	ASSET_OPEN_CHUNK_SIZE,
	ASSET_OPEN_OBJECT_LIMIT,
	AssetOpenObjectReceiver,
	decodeAssetOpenConsent,
	decodeAssetOpenFrame,
	encodeAssetOpenConsent,
	encodeAssetOpenFrame
} from '../message/asset-open';
import {
	BeignetCustomSubtype as Sub,
	encodeCustomMessage
} from '../message/custom';
import type { SqliteStorage } from '../storage/sqlite-storage';
import type { AssetOpenPair } from './asset-opening-provider';
import {
	prepareAssetSpliceAgreement,
	type IAssetSpliceContext,
	type IAssetSpliceChannelTerms,
	type IAssetSplicePlanner
} from './asset-splice-agreement';

type Field =
	| 'layout'
	| 'layout_ack'
	| 'consent'
	| 'authorization'
	| 'final_ack'
	| 'construction_checkpoint'
	| 'exit';
type Entry = {
	kind: 'exchange';
	attempt: string;
	local: boolean;
	field: Field;
	bytes: string;
};
type Agreement = Awaited<ReturnType<typeof prepareAssetSpliceAgreement>>;
type Completed = Awaited<ReturnType<Agreement['finalize']>>;
export interface IAssetSpliceExchangeResult {
	layout: Agreement['layout'];
	funding: Completed['funding'];
	verified: ReturnType<Completed['verifyFrozen']>;
}

/** Reuse the approved contribution for splice_init or splice_ack and the later layout exchange. */
export async function localAssetSpliceProposal(
	store: SqliteStorage,
	host: IAssetSplicePlanner,
	ctx: IAssetSpliceContext
): Promise<Buffer> {
	const attempt = ctx.attempt.toString('hex');
	const lookup = () =>
		store
			.readAssetSpliceJournal<Entry>(ctx.channelId)
			.records.find(
				(e) =>
					e.kind === 'exchange' &&
					e.attempt === attempt &&
					e.local &&
					e.field === 'layout'
			);
	const existing = lookup();
	if (existing) return Buffer.from(existing.bytes, 'hex');
	const bytes = await host.proposeSplice(ctx);
	if (
		!Buffer.isBuffer(bytes) ||
		!bytes.length ||
		bytes.length > ASSET_OPEN_OBJECT_LIMIT
	)
		throw Error('Invalid local asset splice proposal size');
	const peer = lookup();
	if (peer && peer.bytes !== bytes.toString('hex'))
		throw Error('Local splice proposal changed during approval');
	if (!peer)
		store.appendAssetSpliceEvent(
			ctx.channelId,
			store.readAssetSpliceJournal(ctx.channelId),
			{
				kind: 'exchange',
				local: true,
				field: 'layout',
				bytes: bytes.toString('hex'),
				attempt
			} satisfies Entry
		);
	return Buffer.from(bytes);
}
/** A caller serializes receive and advance for one channel and connection. */
export class AssetSpliceExchange {
	private readonly sent = new Set<Field>();
	private readonly values = new Map<string, Buffer>();
	private readonly receivers = new Map<Field, AssetOpenObjectReceiver>();
	private plan?: Agreement;
	private completed?: Completed;
	private final?: IAssetSpliceExchangeResult;
	private constructionAgreed = false;
	constructor(
		private readonly host: IAssetSplicePlanner,
		private readonly ctx: IAssetSpliceContext,
		private readonly terms: IAssetSpliceChannelTerms,
		private readonly init: Buffer,
		private readonly ack: Buffer,
		private readonly store: SqliteStorage,
		private readonly send: (envelope: Buffer) => void
	) {
		for (const r of this.entries().records) {
			if (
				r.kind === 'exchange' &&
				r.attempt === this.ctx.attempt.toString('hex')
			)
				this.values.set(
					this.key(r.local, r.field),
					Buffer.from(r.bytes, 'hex')
				);
		}
	}
	private key(local: boolean, field: Field) {
		return (local ? 'local/' : 'peer/') + field;
	}
	private entries() {
		return this.store.readAssetSpliceJournal<Entry>(this.ctx.channelId);
	}
	private value(local: boolean, field: Field): Buffer | undefined {
		const stored = this.values.get(this.key(local, field));
		return stored && Buffer.from(stored);
	}
	private save(local: boolean, field: Field, bytes: Buffer): void {
		if (!bytes.length || bytes.length > ASSET_OPEN_OBJECT_LIMIT)
			throw new Error('Invalid splice exchange object size');
		const stored = this.value(local, field);
		if (stored) {
			if (!stored.equals(bytes))
				throw new Error('Conflicting asset splice exchange replay');
			return;
		}
		const head = this.entries();
		const previous = head.records.find(
			(e) =>
				e.kind === 'exchange' &&
				e.attempt === this.ctx.attempt.toString('hex') &&
				e.field === field &&
				e.local === local
		);
		if (previous) {
			if (previous.bytes !== bytes.toString('hex'))
				throw Error('Conflicting asset splice exchange replay');
			this.values.set(this.key(local, field), Buffer.from(bytes));
			return;
		}
		this.store.appendAssetSpliceEvent(this.ctx.channelId, head, {
			kind: 'exchange',
			attempt: this.ctx.attempt.toString('hex'),
			local,
			field,
			bytes: bytes.toString('hex')
		} satisfies Entry);
		this.values.set(this.key(local, field), Buffer.from(bytes));
	}
	private both(field: Field): AssetOpenPair<Buffer> | undefined {
		const local = this.value(true, field),
			peer = this.value(false, field);
		if (local && peer)
			return this.ctx.isInitiator ? [local, peer] : [peer, local];
		return undefined;
	}
	private async publish(
		field: Field,
		build: () => Buffer | Promise<Buffer>
	): Promise<void> {
		if (this.sent.has(field)) return;
		const bytes = this.value(true, field) ?? (await build());
		this.save(true, field, bytes);
		if (field === 'consent') {
			const sig = encodeAssetOpenConsent({
				attempt: this.ctx.attempt,
				digest: this.plan!.agreement,
				signature: bytes
			});
			this.send(encodeCustomMessage(Sub.ASSET_SPLICE_CONSENT, sig));
		} else {
			const ack =
				field === 'layout_ack' ||
				field === 'final_ack' ||
				field === 'construction_checkpoint';
			const total = ack ? 0 : bytes.length,
				digest = ack ? bytes : sha256(bytes);
			for (
				let offset = 0;
				offset < Math.max(total, 1);
				offset += ASSET_OPEN_CHUNK_SIZE
			) {
				const frame = encodeAssetOpenFrame({
					phase: field,
					attempt: this.ctx.attempt,
					digest,
					total,
					offset,
					bytes: ack
						? Buffer.alloc(0)
						: bytes.subarray(offset, offset + ASSET_OPEN_CHUNK_SIZE)
				});
				this.send(encodeCustomMessage(Sub.ASSET_SPLICE, frame));
			}
		}
		this.sent.add(field);
	}
	async advance(): Promise<void> {
		if (this.final) return;
		await this.publish('layout', () => this.host.proposeSplice(this.ctx));
		const blobs = this.both('layout');
		if (!blobs) return;
		this.plan ??= await prepareAssetSpliceAgreement(
			this.host,
			this.ctx,
			this.terms,
			this.init,
			this.ack,
			blobs
		);
		const plan = this.plan;
		await this.publish('layout_ack', () => plan.agreement);
		const peerLayout = this.value(false, 'layout_ack');
		if (!peerLayout) return;
		if (!peerLayout.equals(plan.agreement))
			throw new Error('Peers disagree on asset splice terms');
		await this.publish('consent', () => plan.consent(peerLayout));
		const consents = this.both('consent');
		if (!consents) return;
		await this.publish('authorization', async () => {
			const head = this.store.readAssetSpliceJournal<{
				kind: string;
				attempt?: string;
			}>(this.ctx.channelId);
			const attempt = this.ctx.attempt.toString('hex');
			if (
				!head.records.some(
					(r) =>
						r.kind === 'splice-authorization-start' && r.attempt === attempt
				)
			)
				this.store.appendAssetSpliceEvent(this.ctx.channelId, head, {
					kind: 'splice-authorization-start',
					attempt
				});
			return plan.authorize(peerLayout, consents);
		});
		const auth = this.both('authorization');
		if (!auth) return;
		this.completed ??= await plan.finalize(consents, auth);
		const funding = this.completed.funding;
		const verified = this.completed.verifyFrozen(
			Transaction.fromBuffer(funding.transaction)
		);
		await this.publish('final_ack', () => verified.digest);
		const peerFinal = this.value(false, 'final_ack');
		if (!peerFinal) return;
		if (!peerFinal.equals(verified.digest))
			throw new Error('Peers disagree on final asset splice funding');
		this.final = { layout: plan.layout, funding, verified };
	}
	result() {
		return this.final;
	}
	async checkpoint(
		transaction: Transaction,
		nonces: AssetOpenPair<Buffer>
	): Promise<boolean> {
		if (!this.final || !this.completed)
			throw Error('Missing bilateral splice agreement');
		const frozen = this.completed.verifyFrozen(transaction);
		const digest = sha256(
			Buffer.concat([
				Buffer.from('asset-splice-construction/v1\0'),
				frozen.digest,
				transaction.getHash(),
				sha256(nonces[0]),
				sha256(nonces[1])
			])
		);
		const saved = this.value(true, 'construction_checkpoint');
		if (saved && !saved.equals(digest))
			throw Error('Frozen asset splice checkpoint changed');
		await this.publish('construction_checkpoint', () => digest);
		const peer = this.value(false, 'construction_checkpoint');
		if (!peer) return false;
		if (!peer.equals(digest))
			throw Error(
				'Splice peers disagree on the frozen transaction or signing nonces'
			);
		this.constructionAgreed = true;
		return true;
	}
	async exitShares(
		ours: () => Promise<Buffer>
	): Promise<AssetOpenPair<Buffer> | undefined> {
		if (!this.final || !this.constructionAgreed)
			throw new Error('Splice exit shares require bilateral final agreement');
		await this.publish('exit', ours);
		return this.both('exit');
	}
	async receive(subtype: number, raw: Buffer): Promise<void> {
		let field: Field, bytes: Buffer;
		if (subtype === Sub.ASSET_SPLICE_CONSENT) {
			const consent = decodeAssetOpenConsent(raw);
			if (
				!consent.attempt.equals(this.ctx.attempt) ||
				!this.plan?.agreement.equals(consent.digest) ||
				!this.value(true, 'layout_ack')
			)
				throw new Error('Splice consent references unknown terms');
			field = 'consent';
			bytes = consent.signature;
		} else if (subtype === Sub.ASSET_SPLICE) {
			const frame = decodeAssetOpenFrame(raw);
			if (!frame.attempt.equals(this.ctx.attempt))
				throw new Error('Wrong splice attempt');
			switch (frame.phase) {
				case 'layout_ack':
				case 'final_ack':
				case 'construction_checkpoint':
					field = frame.phase;
					bytes = frame.digest;
					if (
						!this.value(
							true,
							field === 'layout_ack'
								? 'layout'
								: field === 'construction_checkpoint'
								? 'final_ack'
								: 'authorization'
						)
					)
						throw new Error('Premature splice acknowledgement');
					break;
				case 'layout':
				case 'authorization':
				case 'exit': {
					field = frame.phase;
					if (
						(field === 'authorization' && !this.value(true, 'consent')) ||
						(field === 'exit' && !this.value(true, 'construction_checkpoint'))
					)
						throw new Error('Premature splice proof object');
					const saved = this.value(false, field);
					if (saved) {
						if (
							frame.total !== saved.length ||
							!frame.digest.equals(sha256(saved)) ||
							!saved
								.subarray(frame.offset, frame.offset + frame.bytes.length)
								.equals(frame.bytes)
						)
							throw new Error('Conflicting asset splice chunk replay');
						return;
					}
					let receiver = this.receivers.get(field);
					if (!receiver) {
						receiver = new AssetOpenObjectReceiver(
							this.ctx.attempt,
							field,
							ASSET_OPEN_OBJECT_LIMIT
						);
						this.receivers.set(field, receiver);
					}
					const complete = receiver.receive(frame);
					if (!complete) return;
					this.receivers.delete(field);
					bytes = complete;
					break;
				}
				default:
					throw new Error('Unexpected splice object phase');
			}
		} else throw new Error('Invalid splice envelope');
		this.save(false, field, bytes);
		await this.advance();
	}
}
