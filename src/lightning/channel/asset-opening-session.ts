import {
	finalFundingReserveSats,
	finalHtlcLimits
} from './final-commitment-reserve';
import { Transaction } from 'bitcoinjs-lib';
import { MAX_PEER_PREVTX_BYTES_PER_SESSION } from '../interactive-tx/validation';
import { MAX_LIGHTNING_PAYLOAD } from '../message/custom-records';
import { REGTEST_CHAIN_HASH } from '../chain/hashes';
import { sha256 } from '../crypto/provider';
import { deriveChannelKeys } from '../keys/wallet-keys';
import {
	ASSET_OPEN_CHUNK_SIZE,
	ASSET_OPEN_OBJECT_LIMIT,
	AssetOpenObjectReceiver,
	decodeAssetOpenFrame,
	decodeAssetOpenConsent,
	encodeAssetOpenConsent,
	encodeAssetOpenFrame,
	type IAssetOpenFrame
} from '../message/asset-open';
import {
	BeignetCustomSubtype,
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	encodeCustomMessage
} from '../message/custom';
import {
	decodeAcceptChannel2Message,
	decodeOpenChannel2Message,
	encodeAcceptChannel2Message,
	encodeOpenChannel2Message
} from '../message/dual-funding';
import { MessageType } from '../message/types';
import { recordPeerTxComplete } from '../storage/final-opening-nonces';
import { assetOpeningConstruction } from './asset-opening-construction';
import {
	finalManifestDigest,
	layoutDigest,
	type IAssetOpenLayout
} from './asset-opening-manifest';
import type {
	IAssetOpenContext,
	IAssetOpenDescription,
	IAssetOpenFunding,
	IAssetOpenPlan,
	IAuxiliaryDualFunding,
	AssetOpenPair
} from './asset-opening-provider';
import { buildAssetOpeningCommitment } from './final-opening-commitment';
import { openingTerms } from './final-opening-negotiation';
import type { IFinalOpeningRuntime } from './final-opening-runtime';
import { deriveV2ChannelId } from './validation';
import {
	ASSET_OPENING_TYPE_HEX,
	ASSET_SPLICE_RECOVERY_TYPE_HEX
} from '../features/asset-opening';
import type { IFinalOpeningCandidate } from '../storage/final-opening-candidate';

type Phase = IAssetOpenFrame['phase'] | 'consent';
type ObjectPhase = 'layout' | 'authorization' | 'final' | 'exit';
type Sender = (peer: string, type: number, payload: Buffer) => void;
export interface IAssetOpeningStart {
	peer: string;
	index: number;
	initiator: boolean;
	open: string;
	accept: string;
	deadline: number;
}

type Frozen = ReturnType<typeof assetOpeningConstruction> & {
	funding: IAssetOpenFunding;
	digest: Buffer;
};

/** Drives exactly one pre-authorized opening on its authenticated connection. */
export class AssetOpeningSession {
	readonly ctx: IAssetOpenContext;
	readonly id: string;
	private readonly chunks = new Map<ObjectPhase, AssetOpenObjectReceiver>();
	private readonly sent = new Set<Phase>();
	private tail: Promise<void> = Promise.resolve();
	private queued = 0;
	private stopped = false;
	private detached = false;
	private releasing = false;
	private paused = false;
	private generation = 0;
	private ready = false;
	private peerReestablish?: Buffer;
	private reconnected = false;
	private timer?: ReturnType<typeof setTimeout>;
	private peerCheckpoint?: Buffer;
	private readonly hashes = new Map<Phase, Buffer>();
	private position = 0;
	private plan?: IAssetOpenPlan;
	private layout?: IAssetOpenLayout;
	private description?: IAssetOpenDescription;
	private frozen?: Frozen;
	private peerNonce?: Buffer;
	private readonly receivedTurns = new Set<string>();
	private readonly stageCache = new Map<string, Buffer>();
	constructor(
		readonly start: IAssetOpeningStart,
		private readonly runtime: IFinalOpeningRuntime,
		private readonly provider: IAuxiliaryDualFunding,
		private readonly send: Sender,
		private readonly unspent: (
			tx: Transaction,
			index: number
		) => Promise<boolean>,
		private readonly admitted: (
			candidate: IFinalOpeningCandidate,
			nonce: Buffer,
			early?: Buffer,
			reestablish?: Buffer,
			reconnected?: boolean
		) => void,
		private readonly refuse: (reason: string) => void,
		private readonly retired: () => void
	) {
		const open = decodeOpenChannel2Message(Buffer.from(start.open, 'hex')),
			accept = decodeAcceptChannel2Message(Buffer.from(start.accept, 'hex'));
		const channelId = deriveV2ChannelId(
			open.revocationBasepoint,
			accept.revocationBasepoint
		);
		if (
			!open.chainHash?.equals(REGTEST_CHAIN_HASH) ||
			open.channelFlags !== 0 ||
			accept.minimumDepth < 1 ||
			open.channelType?.toString('hex') !==
				(runtime.storage.canRecoverAssetSplice
					? ASSET_SPLICE_RECOVERY_TYPE_HEX
					: ASSET_OPENING_TYPE_HEX) ||
			!accept.channelType?.equals(open.channelType) ||
			!open.channelId.equals(accept.channelId) ||
			open.requestFunds ||
			accept.willFund ||
			open.disableChannelReserve ||
			accept.disableChannelReserve ||
			encodeOpenChannel2Message(open).toString('hex') !== start.open ||
			encodeAcceptChannel2Message(accept).toString('hex') !== start.accept
		)
			throw new Error('Invalid asset opening negotiation');
		this.ctx = {
			...(runtime.storage.canSpliceDualFundedAssets && {
				walletGeneration: runtime.storage.canRecoverAssetSplice
					? (5 as const)
					: (4 as const)
			}),
			peer: start.peer,
			isInitiator: start.initiator,
			open,
			accept,
			attempt: channelId,
			channelId
		};
		this.id = channelId.toString('hex');
	}

	private read(field: string): Buffer | null {
		let value = this.stageCache.get(field);
		if (!value) {
			value =
				this.runtime.storage.loadAssetOpenStage(this.id, field) ?? undefined;
			if (value) this.stageCache.set(field, value);
		}
		return value ? Buffer.from(value) : null;
	}

	private save(field: string, bytes: Buffer): void {
		const previous = this.stageCache.get(field);
		if (previous) {
			if (!previous.equals(bytes))
				throw new Error('Changed asset opening stage ' + field);
			return;
		}
		this.runtime.storage.saveAssetOpenStage(this.id, field, bytes);
		this.stageCache.set(field, Buffer.from(bytes));
	}

	private both(phase: Phase): AssetOpenPair<Buffer> | null {
		const ours = this.read('our/' + phase),
			theirs = this.read('peer/' + phase);
		return ours && theirs
			? this.ctx.isInitiator
				? [ours, theirs]
				: [theirs, ours]
			: null;
	}
	private assertLive(g: number): void {
		if (this.stopped || this.paused || g !== this.generation)
			throw new Error('Asset opening connection changed');
		if (!this.ready && Date.now() > this.start.deadline)
			throw new Error('Asset opening approval expired');
	}
	private enqueue(fn: (g: number) => Promise<void>): void {
		if (this.paused || this.stopped) return;
		const g = this.generation;
		if (++this.queued > 32) {
			this.stop('Asset opening peer exceeded its pending message limit');
			return;
		}
		this.tail = this.tail.then(async () => {
			try {
				this.assertLive(g);
				await fn(g);
			} catch (e) {
				if (g === this.generation && !this.paused)
					this.stop(e instanceof Error ? e.message : String(e));
			} finally {
				this.queued--;
			}
		});
	}
	private stop(reason: string): void {
		if (this.stopped) return;
		this.stopped = true;
		this.generation++;
		this.chunks.clear();
		clearTimeout(this.timer);
		if (!this.runtime.storage.loadFinalOpeningSession(this.id)) {
			this.save('abandoned', Buffer.of(1));
			this.cleanup();
		}
		if (!this.paused) this.refuse(reason);
	}
	private cleanup(): void {
		if (this.releasing || this.detached) return;
		this.releasing = true;
		this.tail = this.tail
			.then(async () => {
				if (this.detached) return;
				await this.provider.abandon(this.ctx);
				if (this.detached) return;
				this.save('finished', Buffer.alloc(0));
				this.retired();
			})
			.catch(() => {
				// The node can restore before its asset wallet is available.
				if (!this.detached) {
					this.timer = setTimeout(() => this.cleanup(), 5000);
					this.timer.unref?.();
				}
			})
			.finally(() => {
				this.releasing = false;
			});
	}

	abort(reason: string): void {
		this.stop(reason);
	}
	detach(): void {
		this.detached = true;
		clearTimeout(this.timer);
		this.pause();
	}
	recordReestablish(payload: Buffer): void {
		this.peerReestablish = Buffer.from(payload);
	}
	pause(): void {
		this.peerReestablish = undefined;
		this.paused = true;
		this.generation++;
		this.chunks.clear();
	}
	resume(): void {
		this.reconnected = true;
		this.paused = false;
		this.stopped = false;
		this.generation++;
		this.peerCheckpoint = undefined;
		this.sent.clear();
		this.position = 0;
		this.receivedTurns.clear();
		this.ready = false;
		this.begin();
	}
	/** Restore the expiry clock without starting a signing turn or contacting an offline peer. */
	waitForPeer(): void {
		this.pause();
		this.watchExpiry();
	}
	private watchExpiry(): void {
		if (this.read('abandoned')) {
			this.stopped = true;
			this.cleanup();
			return;
		}
		if (!this.runtime.storage.loadFinalOpeningSession(this.id)) {
			clearTimeout(this.timer);
			this.timer = setTimeout(
				() => this.stop('Asset opening approval expired'),
				Math.max(0, this.start.deadline - Date.now())
			);
			this.timer.unref?.();
		}
	}
	begin(): void {
		this.watchExpiry();
		if (!this.stopped) this.enqueue((g) => this.drive(g));
	}

	/** The peer can miss our final exit share even though its own share reached us. */
	replayAdmitted(): void {
		this.sent.clear();
		for (const phase of [
			'layout',
			'layout_ack',
			'consent',
			'authorization',
			'construction_checkpoint',
			'final',
			'final_ack',
			'exit'
		] as const) {
			const bytes = this.read(
				phase === 'construction_checkpoint' ? 'constructed' : 'our/' + phase
			);
			if (!bytes) throw new Error('Incomplete admitted asset opening');
			this.emitStage(phase, bytes);
		}
	}

	private emitStage(phase: Phase, value: Buffer): void {
		if (this.sent.has(phase)) return;
		this.sent.add(phase);
		const id = this.ctx.attempt;
		if (phase === 'consent') {
			const planDigest = this.plan?.digest ?? this.read('ourConsentDigest');
			if (value.length !== 64 || !planDigest)
				throw new Error('Invalid asset opening consent');
			this.send(
				this.start.peer,
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				encodeCustomMessage(
					BeignetCustomSubtype.ASSET_OPEN_CONSENT,
					encodeAssetOpenConsent({
						attempt: id,
						digest: planDigest,
						signature: value
					})
				)
			);
			return;
		}
		const ack =
			phase === 'layout_ack' ||
			phase === 'final_ack' ||
			phase === 'construction_checkpoint';
		const digest = ack ? value : sha256(value);
		const total = ack ? 0 : value.length;
		for (
			let offset = 0;
			offset < Math.max(total, 1);
			offset += ASSET_OPEN_CHUNK_SIZE
		) {
			const frame = {
				phase,
				attempt: id,
				digest,
				total,
				offset,
				bytes: ack
					? Buffer.alloc(0)
					: value.subarray(offset, offset + ASSET_OPEN_CHUNK_SIZE)
			};
			this.send(
				this.start.peer,
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				encodeCustomMessage(
					BeignetCustomSubtype.ASSET_OPEN,
					encodeAssetOpenFrame(frame)
				)
			);
		}
	}

	private async stage(
		phase: Phase,
		build: () => Promise<Buffer>,
		g: number,
		bind?: Buffer
	): Promise<Buffer> {
		let bytes = this.read('our/' + phase);
		if (!bytes) {
			if (Date.now() > this.start.deadline)
				throw new Error('Asset opening approval expired');
			if (bind)
				this.runtime.storage.reserveAssetOpenSignature(this.id, phase, bind);
			bytes = await build();
			this.assertLive(g);
			if (
				!Buffer.isBuffer(bytes) ||
				!bytes.length ||
				bytes.length > ASSET_OPEN_OBJECT_LIMIT
			)
				throw new Error('Invalid host asset opening object');
			this.save('our/' + phase, bytes);
		}
		this.emitStage(phase, bytes);
		return bytes;
	}
	custom(subtype: number, raw: Buffer): void {
		if (this.stopped || this.paused) return;
		try {
			if (subtype === BeignetCustomSubtype.ASSET_OPEN_CONSENT) {
				const consent = decodeAssetOpenConsent(raw);
				if (!consent.attempt.equals(this.ctx.attempt))
					throw new Error('Asset opening consent attempt mismatch');
				if (!this.read('our/layout_ack'))
					throw new Error('Asset consent before layout agreement');
				this.save('peerConsentDigest', consent.digest);
				this.save('peer/consent', consent.signature);
			} else {
				const f = decodeAssetOpenFrame(raw);
				if (!f.attempt.equals(this.ctx.attempt))
					throw new Error('Asset opening attempt mismatch');
				// The conversion phases (#2151) belong to subtype 98 alone.
				if (f.phase === 'conversion_terms' || f.phase === 'conversion_reply')
					throw new Error('Unexpected asset opening phase');
				if (f.phase === 'construction_checkpoint') {
					if (!this.read('our/authorization'))
						throw new Error('Unexpected asset construction checkpoint');
					if (this.peerCheckpoint && !this.peerCheckpoint.equals(f.digest))
						throw new Error('Changed asset construction checkpoint');
					if (!this.peerCheckpoint) {
						this.peerCheckpoint = Buffer.from(f.digest);
						this.enqueue((g) => this.drive(g));
					}
					return;
				}
				const prerequisite = {
					layout: undefined,
					layout_ack: 'layout',
					authorization: 'consent',
					final: 'authorization',
					final_ack: 'final',
					exit: 'final_ack'
				}[f.phase];
				if (prerequisite && !this.read('our/' + prerequisite))
					throw new Error('Premature asset opening phase');
				const ack = f.phase === 'layout_ack' || f.phase === 'final_ack';
				const prior = this.read('peer/' + f.phase);
				if (prior) {
					if (!ack && !this.hashes.has(f.phase))
						this.hashes.set(f.phase, sha256(prior));
					const same = ack
						? prior.equals(f.digest)
						: f.total === prior.length &&
						  f.bytes.equals(
								prior.subarray(f.offset, f.offset + f.bytes.length)
						  ) &&
						  this.hashes.get(f.phase)!.equals(f.digest);
					if (!same) throw new Error('Conflicting asset opening object replay');
					return;
				}
				if (ack) this.save('peer/' + f.phase, f.digest);
				else {
					const phase = f.phase as ObjectPhase;
					let receiver = this.chunks.get(phase);
					if (!receiver) {
						receiver = new AssetOpenObjectReceiver(
							this.ctx.attempt,
							phase,
							ASSET_OPEN_OBJECT_LIMIT
						);
						this.chunks.set(phase, receiver);
					}
					const bytes = receiver.receive(f);
					if (!bytes) return;
					this.save('peer/' + phase, bytes);
					this.chunks.delete(phase);
				}
			}
			this.enqueue((g) => this.drive(g));
		} catch (e) {
			this.stop(e instanceof Error ? e.message : String(e));
		}
	}

	interactive(type: number, payload: Buffer): void {
		// The exit verification already queued can admit the candidate before
		// the next queue item runs. Retain a crossing peer signature at receipt.
		if (type === MessageType.COMMITMENT_SIGNED && this.read('our/exit')) {
			try {
				this.save('earlyCommitment', payload);
			} catch (err) {
				this.stop(String(err));
			}
			return;
		}
		this.enqueue(async (g) => {
			const turn = this.frozen?.turns[this.position];
			const token = type + '/' + sha256(payload).toString('hex');
			if (
				!turn ||
				turn.initiator === this.ctx.isInitiator ||
				turn.type !== type ||
				(turn.payload && !turn.payload.equals(payload))
			) {
				if (this.receivedTurns.has(token)) return;
				throw new Error(
					'Unexpected item in authorized asset funding transaction'
				);
			}
			if (type === MessageType.TX_COMPLETE) {
				recordPeerTxComplete({}, this.id, payload);
				this.save('peerNonce', payload);
				this.peerNonce = Buffer.from(payload);
			}
			this.receivedTurns.add(token);
			this.position++;
			await this.drive(g);
		});
	}
	private async drive(g: number): Promise<void> {
		if (this.ready) return;
		const { ctx, provider, runtime } = this;
		await this.stage('layout', () => provider.propose(ctx), g);
		const proposals = this.both('layout');
		if (!proposals) return;
		if (!this.layout || !this.description || !this.plan) {
			const d = await provider.describe(ctx, proposals);
			this.assertLive(g);
			const layout = {
				...d,
				attempt: ctx.attempt,
				chainHash: ctx.open.chainHash!,
				channelId: ctx.channelId,
				openHash: sha256(Buffer.from(this.start.open, 'hex')),
				acceptHash: sha256(Buffer.from(this.start.accept, 'hex')),
				initiatorProposalHash: sha256(proposals[0]),
				acceptorProposalHash: sha256(proposals[1]),
				locktime: ctx.open.locktime
			};
			const hash = layoutDigest(layout);
			const prevBytes = [0, 0];
			for (const input of layout.inputs) {
				const side = Number(input.serialId & 1n);
				// tx_add_input adds the channel id, serial, length, vout and sequence.
				if (
					!Buffer.isBuffer(input.prevTx) ||
					input.prevTx.length + 50 > MAX_LIGHTNING_PAYLOAD ||
					(prevBytes[side] += input.prevTx.length) >
						MAX_PEER_PREVTX_BYTES_PER_SESSION
				)
					throw new Error(
						'Asset opening exceeds its previous transaction byte limit'
					);
			}
			for (const i of layout.inputs) {
				const prev = Transaction.fromBuffer(i.prevTx);
				if (
					!prev.getHash().equals(i.txid) ||
					!prev.outs[i.vout] ||
					!(await this.unspent(prev, i.vout))
				)
					throw new Error('Asset opening input is not verified unspent');
				this.assertLive(g);
			}
			const plan = await provider.prepare(ctx, proposals, hash);
			this.assertLive(g);
			if (!Buffer.isBuffer(plan.digest) || plan.digest.length !== 32)
				throw new Error('Invalid provider layout digest');
			this.plan = plan;
			this.description = d;
			this.layout = layout;
		}
		const plan = this.plan,
			layout = this.layout;
		const agreement = sha256(
			Buffer.concat([layoutDigest(layout), plan.digest])
		);
		const layoutAck = await this.stage('layout_ack', async () => agreement, g);
		if (!agreement.equals(layoutAck))
			throw new Error('Stored asset opening layout changed');
		const peerLayout = this.read('peer/layout_ack');
		if (!peerLayout) return;
		if (!peerLayout.equals(agreement))
			throw new Error('Asset opening layouts differ');
		this.save('ourConsentDigest', plan.digest);
		await this.stage('consent', () => plan.consent(), g, agreement);
		const consents = this.both('consent');
		if (!consents) return;
		if (!this.read('peerConsentDigest')?.equals(plan.digest))
			throw new Error('Asset opening consent digest differs');
		await this.stage(
			'authorization',
			() => plan.authorize(consents),
			g,
			sha256(Buffer.concat([agreement, ...consents]))
		);
		const auth = this.both('authorization');
		if (!auth) return;
		if (!this.frozen) {
			const f = await plan.finalize(consents, auth);
			this.assertLive(g);
			const tx = Transaction.fromBuffer(f.transaction);
			const digest = finalManifestDigest(
				layout,
				tx,
				f.fundingRoot,
				[sha256(auth[0]), sha256(auth[1])],
				f.proofDigest
			);
			this.frozen = {
				...assetOpeningConstruction(ctx, this.description, f),
				funding: f,
				digest
			};
		}
		const { candidate, turns, funding, digest } = this.frozen;
		const keys = deriveChannelKeys(runtime.root, 1, this.start.index);
		const constructed = this.read('constructed');
		if (constructed && !constructed.equals(digest))
			throw new Error('Stored funding construction changed');
		this.emitStage('construction_checkpoint', constructed ?? Buffer.alloc(32));
		if (!this.peerCheckpoint) return;
		if (!this.peerCheckpoint.equals(Buffer.alloc(32))) {
			if (!this.peerCheckpoint.equals(digest))
				throw new Error('Peer funding construction changed');
			if (constructed) this.position = turns.length;
		}
		const turn = turns[this.position];
		if (turn) {
			if (turn.initiator !== ctx.isInitiator) return;
			const payload =
				turn.payload ??
				runtime.storage.previewAssetOpeningTxComplete(
					candidate,
					funding.fundingRoot,
					keys.fundingPrivkey,
					this.start.index
				);
			this.position++;
			this.send(this.start.peer, turn.type, payload);
			if (this.position < turns.length) return;
		}
		const peerNonce = this.peerNonce ?? this.read('peerNonce');
		if (!peerNonce) throw new Error('Missing peer completion');
		this.save('constructed', digest);
		await this.stage('final', async () => digest, g);
		const peerFinal = this.read('peer/final');
		if (!peerFinal) return;
		if (!peerFinal.equals(digest))
			throw new Error('Asset opening final manifests differ');
		await this.stage('final_ack', async () => digest, g);
		const ack = this.read('peer/final_ack');
		if (!ack) return;
		if (!ack.equals(digest))
			throw new Error('Asset opening final acknowledgement differs');
		const terms = openingTerms(ctx.open, ctx.accept, ctx.isInitiator);
		const bare = { fundingRoot: funding.fundingRoot };
		const exitContext = {
			opening: ctx,
			funding,
			candidate,
			terms,
			local: buildAssetOpeningCommitment(candidate, terms, 'local', bare),
			remote: buildAssetOpeningCommitment(candidate, terms, 'remote', bare)
		};
		await this.stage('exit', () => provider.signExits(exitContext), g, digest);
		const shares = this.both('exit');
		if (!shares) return;
		const exits = await provider.verifyExits(exitContext, shares);
		this.assertLive(g);
		const capacity = ctx.open.fundingSatoshis + ctx.accept.fundingSatoshis;
		const updateLimits =
			ctx.walletGeneration !== undefined
				? {
						local: finalHtlcLimits(
							ctx.isInitiator ? ctx.open : ctx.accept,
							finalFundingReserveSats(capacity, terms, false)
						),
						remote: finalHtlcLimits(
							ctx.isInitiator ? ctx.accept : ctx.open,
							finalFundingReserveSats(capacity, terms, true)
						)
				  }
				: undefined;
		runtime.storage.rememberAssetOpeningSession(
			candidate,
			ctx.peer,
			terms,
			this.start.index,
			(ctx.isInitiator
				? ctx.accept
				: ctx.open
			).secondPerCommitmentPoint.toString('hex'),
			{
				fundingRoot: funding.fundingRoot.toString('hex'),
				layoutDigest: agreement.toString('hex'),
				finalDigest: digest.toString('hex'),
				fundingProofs: funding.fundingProofs.toString('hex'),
				local: exits.local,
				remote: exits.remote
			},
			updateLimits
		);
		runtime.storage.finalOpeningTxComplete(this.id, keys.fundingPrivkey);
		runtime.storage.rememberFinalPeerTxComplete(this.id, peerNonce);
		this.ready = true;
		clearTimeout(this.timer);
		this.admitted(
			candidate,
			peerNonce,
			this.read('earlyCommitment') ?? undefined,
			this.peerReestablish,
			this.reconnected
		);
	}
}
