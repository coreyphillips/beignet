import { Transaction } from 'bitcoinjs-lib';
import type { BIP32Interface } from 'bip32';
import { isValidPublicKey } from '../crypto/ecdh';
import { deriveChannelKeys, deriveLightningKeys } from '../keys/wallet-keys';
import { MessageType as M } from '../message/types';
import { encodeStfuMessage, decodeStfuMessage } from '../message/stfu';
import {
	encodeSpliceMessage,
	decodeSpliceMessage,
	encodeSpliceAckMessage,
	decodeSpliceAckMessage,
	encodeSpliceLockedMessage
} from '../message/splice';
import {
	decodeTxCompleteMessage,
	encodeTxCompleteMessage,
	encodeTxAbortMessage
} from '../message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../message/channel-commitment';
import { validateFinalSpliceReserves } from './final-commitment-reserve';
import { buildFinalCommitmentView } from './final-opening-commitment';
import {
	finalSpliceSharedNonce,
	signFinalSpliceFunding,
	assembleFinalSplice,
	verifyFinalSpliceContribution
} from './final-splice-funding';
import {
	lastSpliceWire,
	spliceConstruction,
	freshSplicePublicNonce,
	spliceTerms,
	localSpliceContributions
} from './final-splice-transcript';
import {
	finalSpliceAttempts,
	type FinalSpliceEvent,
	type IFinalSpliceAttempt,
	type IFinalSpliceIntent
} from './final-splice-state';
import type {
	IFinalSpliceCandidate,
	IFinalSpliceTerms,
	IFinalFundingReference
} from './final-splice-candidate';
import type { FinalOpeningAuthority } from '../storage/final-opening-authority';
import type { FinalDeviceJournal } from '../storage/final-device-journal';
import type { FinalFundingWitnessSigner } from '../storage/final-opening-funding';
import {
	spliceCommitmentNonceContext,
	updateVerificationNonce,
	signFinalUpdate
} from '../storage/final-update-signing';
import type { SqliteStorage } from '../storage/sqlite-storage';
import type { IFinalOpeningMessage } from './final-opening-runtime';
import { MAX_SPLICE_FEERATE_PERKW } from './splice-weight';

export type FinalSplicePlan = Pick<
	IFinalSpliceIntent,
	'localDelta' | 'feeBudget' | 'feerate' | 'locktime' | 'inputs' | 'outputs'
>;
export interface ISpliceSignatureRequest {
	candidate: IFinalSpliceCandidate;
	intent: IFinalSpliceIntent;
}
export class FinalSpliceSession {
	private readonly id: Buffer;
	constructor(
		private readonly idHex: string,
		private readonly store: SqliteStorage,
		private readonly root: BIP32Interface,
		private readonly journal: FinalDeviceJournal,
		private readonly authority: FinalOpeningAuthority,
		private readonly read: () => IFinalSpliceAttempt | undefined
	) {
		this.id = Buffer.from(idHex, 'hex');
	}
	private get opening() {
		const s = this.store.loadFinalOpeningSession(this.idHex);
		if (!s) throw new Error('Missing final channel opening');
		return s;
	}
	private get snapshot() {
		const s = this.store.loadFinalCommitmentSnapshot(this.idHex);
		if (!s || !s.quiescent)
			throw new Error('Splice requires a quiescent commitment ledger');
		return s;
	}
	private append(event: FinalSpliceEvent) {
		const head = this.journal.read<FinalSpliceEvent>('splice', this.idHex);
		finalSpliceAttempts(this.idHex, [...head.records, event]);
		this.journal.append('splice', this.idHex, head, event);
	}
	begin(initiator: boolean, plan: FinalSplicePlan): void {
		const previous = this.read();
		if (
			previous?.aborted !== undefined &&
			(!previous.inputsReleased || previous.awaitingAbortEcho)
		)
			throw new Error('Previous splice abort is incomplete');
		const parent = this.store.loadFinalActiveFunding(this.idHex);
		if (
			!parent ||
			this.store.finalSimpleCloseStarted(this.idHex) ||
			this.store.loadFinalDaemonOpening(this.idHex)?.exitToBroadcast
		)
			throw new Error('Channel is busy or closing');
		const snapshot = this.snapshot;
		if (
			!Number.isSafeInteger(plan.feerate) ||
			plan.feerate < 1 ||
			plan.feerate > MAX_SPLICE_FEERATE_PERKW ||
			!Number.isInteger(plan.locktime) ||
			plan.locktime < 0 ||
			plan.locktime > 0xffffffff ||
			BigInt(plan.feeBudget) < 0n ||
			snapshot.localBalanceMsat + BigInt(plan.localDelta) * 1000n < 0n
		)
			throw new Error('Invalid splice contribution');
		const index = this.store.allocateFinalChannelKeyIndex(1);
		const pub = deriveChannelKeys(this.root, 1, index).channelBasepoints
			.fundingPubkey;
		this.append({
			kind: 'begin',
			intent: {
				...plan,
				initiator,
				parent,
				localFundingKeyIndex: index,
				localFundingPubkey: pub.toString('hex')
			}
		});
	}
	private terms(a: IFinalSpliceAttempt) {
		const o = this.opening.terms;
		return spliceTerms(
			a,
			BigInt(Math.max(546, o.localDustLimitSatoshis, o.remoteDustLimitSatoshis))
		);
	}
	private refs(
		a: IFinalSpliceAttempt,
		c: IFinalSpliceCandidate,
		t: IFinalSpliceTerms
	) {
		const funding: IFinalFundingReference = {
			fundingTxHex: c.tx.toHex(),
			fundingOutputIndex: c.fundingIndex,
			localFundingPubkey: t.newLocalKey.toString('hex'),
			remoteFundingPubkey: t.newPeerKey.toString('hex'),
			localFundingKeyIndex: a.intent.localFundingKeyIndex
		};
		const context = spliceCommitmentNonceContext(
			this.idHex,
			c.tx.getHash(),
			c.fundingIndex
		);
		const key = deriveChannelKeys(
			this.root,
			1,
			a.intent.localFundingKeyIndex
		).fundingPrivkey;
		const oldKey = deriveChannelKeys(
			this.root,
			1,
			a.intent.parent.localFundingKeyIndex
		).fundingPrivkey;
		return { funding, context, key, oldKey };
	}
	private balances(
		s: FinalSpliceSession['snapshot'],
		t: IFinalSpliceTerms,
		c: IFinalSpliceCandidate
	) {
		const balances = {
			localBalanceMsat: s.localBalanceMsat + t.localDelta * 1000n,
			remoteBalanceMsat: s.remoteBalanceMsat + t.peerDelta * 1000n
		};
		validateFinalSpliceReserves(
			BigInt(c.tx.outs[c.fundingIndex].value),
			s.terms,
			balances,
			s.htlcs,
			s.candidate.isInitiator,
			c.outputOwners
		);
		return balances;
	}
	private promise(
		a: IFinalSpliceAttempt,
		t: IFinalSpliceTerms,
		c?: IFinalSpliceCandidate
	): Buffer {
		if (!c)
			return encodeTxCompleteMessage({
				channelId: this.id,
				commitNonces: {
					current: freshSplicePublicNonce(),
					next: freshSplicePublicNonce()
				},
				fundingInputNonce: freshSplicePublicNonce()
			});
		const { context, key, oldKey } = this.refs(a, c, t);
		const snapshot = this.snapshot;
		this.balances(snapshot, t, c);
		const height = Number(snapshot.localHeight);
		const nonce = (n: number) =>
			Buffer.from(
				updateVerificationNonce(this.authority.nonceContext(context), key, n, {
					pub: '',
					source: 'splice'
				})
			);
		return encodeTxCompleteMessage({
			channelId: this.id,
			commitNonces: { current: nonce(height), next: nonce(height + 1) },
			fundingInputNonce: finalSpliceSharedNonce(c, oldKey, this.authority)
		});
	}
	private commitment(
		a: IFinalSpliceAttempt,
		t: IFinalSpliceTerms,
		c: IFinalSpliceCandidate,
		nonce: Buffer,
		peerPayload?: Buffer
	) {
		const s = this.snapshot;
		const { funding, context, key } = this.refs(a, c, t);
		const height = peerPayload ? s.localHeight : s.remoteHeight,
			point = peerPayload ? s.localPoint : s.remotePoint;
		if (
			peerPayload &&
			!decodeCommitmentSignedMessage(peerPayload).fundingTxid?.equals(
				c.tx.getHash()
			)
		)
			throw new Error('Wrong splice commitment funding tag');
		const balances = this.balances(s, t, c);
		const view = buildFinalCommitmentView(
			s.candidate,
			s.terms,
			peerPayload ? 'local' : 'remote',
			point,
			height,
			balances,
			s.htlcs,
			funding
		);
		const keys = deriveChannelKeys(this.root, 1, this.opening.channelKeyIndex);
		return signFinalUpdate(
			s.candidate,
			view,
			point,
			Number(height),
			{ pub: nonce.toString('hex'), source: 'splice' },
			keys,
			this.authority,
			context,
			[],
			peerPayload,
			{ reference: funding, privateKey: key }
		);
	}
	private localSignsFirst(
		a: IFinalSpliceAttempt,
		c: IFinalSpliceCandidate
	): boolean {
		const amount = (indices: number[]) =>
			indices.reduce((sum, i) => sum + BigInt(c.values[i]), 0n);
		const shared = BigInt(c.values[c.sharedIndex]);
		const local = amount(c.localInputs) + (a.intent.initiator ? shared : 0n);
		const peer = amount(c.peerInputs) + (a.intent.initiator ? 0n : shared);
		return (
			local < peer ||
			(local === peer &&
				Buffer.compare(
					deriveLightningKeys(this.root, 1).nodePublicKey,
					Buffer.from(this.opening.peer, 'hex')
				) < 0)
		);
	}
	private agreement(a: IFinalSpliceAttempt, t: IFinalSpliceTerms) {
		const turns = spliceConstruction(a, t);
		if (!turns.localComplete || !turns.peerComplete) return undefined;
		const c = turns.build();
		if (!a.candidate && !this.promise(a, t, c).equals(turns.localComplete))
			throw new Error('Agreed splice differs from local nonce promise');
		const local = decodeTxCompleteMessage(turns.localComplete, {
			taproot: true
		});
		const peer = decodeTxCompleteMessage(turns.peerComplete, { taproot: true });
		return { c, local, peer };
	}
	private wire(
		a: IFinalSpliceAttempt,
		local: boolean,
		message: IFinalOpeningMessage,
		prevTx?: Buffer
	) {
		const event = {
			kind: 'wire' as const,
			local,
			type: message.type,
			payload: message.payload.toString('hex'),
			...(prevTx && { resolvedPrevTx: prevTx.toString('hex') })
		};
		const proposed = { ...a, messages: [...a.messages, event] };
		const t = this.terms(proposed);
		if (t && message.type >= M.TX_ADD_INPUT && message.type <= M.TX_COMPLETE) {
			const turns = spliceConstruction(proposed, t);
			if (turns.localComplete && turns.peerComplete)
				this.agreement(proposed, t);
		}
		this.append(event);
	}
	receive(msg: IFinalOpeningMessage, resolvedPrevTx?: Buffer): void {
		const a = this.read();
		if (!a || !msg.payload.subarray(0, 32).equals(this.id))
			throw new Error('Unknown splice negotiation');
		if (
			a.adopted &&
			msg.type === M.SPLICE_LOCKED &&
			lastSpliceWire(a, false, msg.type)?.payload ===
				msg.payload.toString('hex')
		)
			return;
		if (a.adopted || a.aborted !== undefined)
			throw new Error('Splice already finished');
		const old = lastSpliceWire(a, false, msg.type);
		if (
			old?.payload === msg.payload.toString('hex') &&
			(msg.type < M.TX_ADD_INPUT || msg.type > M.TX_COMPLETE || !!a.candidate)
		)
			return;
		const t = this.terms(a);
		switch (msg.type) {
			case M.STFU:
				if (
					old ||
					msg.payload.length !== 33 ||
					msg.payload[32] > 1 ||
					(decodeStfuMessage(msg.payload).initiator === a.intent.initiator &&
						!(a.intent.initiator && this.snapshot.candidate.isInitiator))
				)
					throw new Error('Unexpected splice quiescence initiator');
				break;
			case M.SPLICE: {
				const p = decodeSpliceMessage(msg.payload);
				if (
					old ||
					a.intent.initiator ||
					!lastSpliceWire(a, true, M.STFU) ||
					!p.fundingFeeratePerkw ||
					p.fundingFeeratePerkw > MAX_SPLICE_FEERATE_PERKW ||
					p.lockDepth ||
					p.requireConfirmedInputs ||
					// An asset conversion (#2151) is the conversion transport's.
					p.conversion ||
					!isValidPublicKey(p.fundingPubkey)
				)
					throw new Error('Unsupported splice proposal');
				break;
			}
			case M.SPLICE_ACK: {
				const ack = decodeSpliceAckMessage(msg.payload);
				if (
					old ||
					!a.intent.initiator ||
					!lastSpliceWire(a, true, M.SPLICE) ||
					ack.conversion ||
					!isValidPublicKey(ack.fundingPubkey)
				)
					throw new Error('Unexpected splice acknowledgment');
				break;
			}
			case M.COMMITMENT_SIGNED: {
				const agreed = t && this.agreement(a, t);
				if (!t || !agreed || old)
					throw new Error('Unexpected splice commitment');
				this.commitment(
					a,
					t,
					agreed.c,
					agreed.local.commitNonces!.current,
					msg.payload
				);
				break;
			}
			case M.TX_SIGNATURES: {
				const g = t && a.candidate && this.agreement(a, t);
				if (
					!g ||
					!t ||
					old ||
					(this.localSignsFirst(a, g.c) &&
						!lastSpliceWire(a, true, M.TX_SIGNATURES))
				)
					throw new Error('Unexpected splice input signatures');
				verifyFinalSpliceContribution(
					g.c,
					t,
					this.id,
					msg.payload,
					false,
					g.local.fundingInputNonce!,
					g.peer.fundingInputNonce!
				);
				break;
			}
			case M.SPLICE_LOCKED:
				if (old || !a.funded) throw new Error('Unexpected splice lock');
				break;
			default:
				if (!t || msg.type < M.TX_ADD_INPUT || msg.type > M.TX_COMPLETE)
					throw new Error('Unexpected final splice message');
		}
		this.wire(a, false, msg, resolvedPrevTx);
	}
	/** Return one durably recorded packet. The caller transmits before asking for the next. */
	next(
		signWallet?: FinalFundingWitnessSigner,
		atDepthTxid?: string
	):
		| {
				wire?: IFinalOpeningMessage;
				verify?: ISpliceSignatureRequest;
				watch?: IFinalFundingReference;
				broadcast?: Buffer;
				adopted?: string;
		  }
		| undefined {
		const a = this.read();
		if (!a || a.adopted || a.aborted !== undefined) return;
		const get = (local: boolean, type: M) => lastSpliceWire(a, local, type);
		const send = (type: M, payload: Buffer) => {
			const wire = { type, payload };
			this.wire(a, true, wire);
			return { wire };
		};
		if (!get(true, M.STFU)) {
			if (!a.intent.initiator && !get(false, M.STFU)) return;
			return send(
				M.STFU,
				encodeStfuMessage({ channelId: this.id, initiator: a.intent.initiator })
			);
		}
		if (!get(false, M.STFU)) return;
		const intent = a.intent;
		const offer = {
			channelId: this.id,
			relativeSatoshis: BigInt(intent.localDelta),
			fundingPubkey: Buffer.from(intent.localFundingPubkey, 'hex')
		};
		if (a.intent.initiator && !get(true, M.SPLICE))
			return send(
				M.SPLICE,
				encodeSpliceMessage({
					...offer,
					fundingFeeratePerkw: intent.feerate,
					locktime: intent.locktime
				})
			);
		if (!a.intent.initiator && get(false, M.SPLICE) && !get(true, M.SPLICE_ACK))
			return send(M.SPLICE_ACK, encodeSpliceAckMessage(offer));
		const t = this.terms(a);
		if (!t) return;
		const turns = spliceConstruction(a, t);
		if (!turns.localComplete || !turns.peerComplete) {
			if (!turns.localTurn) return;
			const own = localSpliceContributions(this.id, a, t);
			const pending = own.find(
				(m) =>
					!a.messages.some(
						(old) =>
							old.local &&
							old.type === m.type &&
							old.payload === m.payload.toString('hex')
					)
			);
			if (pending) return send(pending.type, pending.payload);
			let c: IFinalSpliceCandidate | undefined;
			try {
				c = turns.build();
			} catch (err) {
				if (turns.peerComplete) throw err;
			}
			return send(M.TX_COMPLETE, this.promise(a, t, c));
		}
		const g = this.agreement(a, t)!;
		const { funding, oldKey } = this.refs(a, g.c, t);
		const ours = get(true, M.COMMITMENT_SIGNED),
			theirs = get(false, M.COMMITMENT_SIGNED);
		if (!ours)
			return send(
				M.COMMITMENT_SIGNED,
				this.commitment(a, t, g.c, g.peer.commitNonces!.current)
			);
		if (!theirs) return;
		if (!a.candidate) {
			const s = this.snapshot;
			const exit = this.commitment(
				a,
				t,
				g.c,
				g.local.commitNonces!.current,
				Buffer.from(theirs.payload, 'hex')
			);
			this.append({
				kind: 'candidate',
				funding,
				localDelta: intent.localDelta,
				peerDelta: t.peerDelta.toString(),
				localExit: exit.toString('hex'),
				ourCommitment: ours.payload,
				peerCommitment: theirs.payload,
				localHeight: Number(s.localHeight),
				remoteHeight: Number(s.remoteHeight),
				localNextNonce: g.local.commitNonces!.next.toString('hex'),
				peerNextNonce: g.peer.commitNonces!.next.toString('hex')
			});
			return { watch: funding };
		}
		const localSig = get(true, M.TX_SIGNATURES),
			peerSig = get(false, M.TX_SIGNATURES);
		if (!localSig) {
			if (!this.localSignsFirst(a, g.c) && !peerSig) return;
			if (!signWallet) return { verify: { candidate: g.c, intent } };
			const s = this.snapshot,
				oldExit = this.store.loadFinalResolutionStates(this.idHex)?.local.tx;
			if (!oldExit) throw new Error('Missing current parent exit');
			const parent = buildFinalCommitmentView(
				s.candidate,
				s.terms,
				'local',
				s.localPoint,
				s.localHeight,
				s,
				s.htlcs,
				intent.parent
			);
			const child = buildFinalCommitmentView(
				s.candidate,
				s.terms,
				'local',
				s.localPoint,
				s.localHeight,
				{
					localBalanceMsat: s.localBalanceMsat + t.localDelta * 1000n,
					remoteBalanceMsat: s.remoteBalanceMsat + t.peerDelta * 1000n
				},
				s.htlcs,
				funding
			);
			const payload = signFinalSpliceFunding(
				g.c,
				t,
				this.id,
				oldKey,
				g.local.fundingInputNonce!,
				g.peer.fundingInputNonce!,
				this.authority,
				{
					parent: {
						expected: parent.tx,
						signed: Transaction.fromBuffer(oldExit)
					},
					candidate: {
						expected: child.tx,
						signed: Transaction.fromHex(a.candidate.localExit)
					}
				},
				signWallet
			);
			return send(M.TX_SIGNATURES, payload);
		}
		if (peerSig && !a.funded) {
			const full = assembleFinalSplice(
				g.c,
				t,
				this.id,
				g.local.fundingInputNonce!,
				g.peer.fundingInputNonce!,
				Buffer.from(localSig.payload, 'hex'),
				Buffer.from(peerSig.payload, 'hex')
			);
			this.append({ kind: 'funded', transaction: full.toHex() });
			return { broadcast: full.toBuffer() };
		}
		if (
			a.localLock &&
			a.localLock === a.peerLock &&
			a.localLock === atDepthTxid
		) {
			this.append({ kind: 'adopt', txid: a.localLock });
			return { adopted: a.localLock };
		}
		return undefined;
	}
	replacement(phase: 'quiescent' | 'refused' | 'finished'): void {
		const a = this.read();
		if (!a?.funded || a.adopted)
			throw new Error('Replacement requires an unlocked signed funding');
		if (a.rbf !== phase) this.append({ kind: 'rbf', phase });
	}
	currentNonce(local = true): Buffer | undefined {
		const a = this.read();
		const w = a && lastSpliceWire(a, local, M.TX_COMPLETE);
		return w
			? decodeTxCompleteMessage(Buffer.from(w.payload, 'hex'), {
					taproot: true
			  }).commitNonces?.current
			: undefined;
	}
	lock(txid: string): IFinalOpeningMessage | undefined {
		const a = this.read();
		if (
			!a?.funded ||
			a.adopted ||
			a.localLock ||
			Transaction.fromHex(a.funded).getId() !== txid
		)
			return;
		const msg = {
			type: M.SPLICE_LOCKED,
			payload: encodeSpliceLockedMessage({
				channelId: this.id,
				fundingTxid: Transaction.fromHex(a.funded).getHash()
			})
		};
		this.wire(a, true, msg);
		return msg;
	}
	agreedFundingTxid(): Buffer | undefined {
		const a = this.read(),
			t = a && this.terms(a);
		return t && this.agreement(a, t)?.c.tx.getHash();
	}
	continueCrossedQuiescence(): void {
		const a = this.read();
		if (
			!a ||
			a.intent.initiator ||
			a.messages.length ||
			this.snapshot.candidate.isInitiator
		)
			throw new Error('Unexpected crossed splice quiescence');
		this.wire(a, true, {
			type: M.STFU,
			payload: encodeStfuMessage({ channelId: this.id, initiator: true })
		});
	}
	acknowledgeAbort(): void {
		if (this.read()?.awaitingAbortEcho) this.append({ kind: 'abort-ack' });
	}
	releasedInputs(): void {
		if (!this.read()?.inputsReleased) this.append({ kind: 'inputs-released' });
	}
	abort(reason: string, awaitingEcho = false): IFinalOpeningMessage {
		this.append({ kind: 'abort', reason, awaitingEcho });
		return {
			type: M.TX_ABORT,
			payload: encodeTxAbortMessage({
				channelId: this.id,
				data: Buffer.from(reason).subarray(0, 240)
			})
		};
	}
}
