import { Transaction } from 'bitcoinjs-lib';
import { encodeStfuMessage } from '../message/stfu';
import { MessageType as M } from '../message/types';
import {
	decodeTxAbortMessage,
	decodeTxAddInputMessage,
	encodeTxAbortMessage,
	decodeTxSignaturesMessage
} from '../message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../message/channel-commitment';
import type { IChannelReestablishMessage } from '../message/channel-reestablish';
import type { IFundingProvider } from '../node/types';
import type { IFinalSpliceAttempt } from './final-splice-state';
import { lastSpliceWire } from './final-splice-transcript';
import type {
	IFinalOpeningRuntime,
	IFinalOpeningMessage
} from './final-opening-runtime';
import type {
	FinalSplicePlan,
	ISpliceSignatureRequest
} from './final-splice-session';
import type { IFinalFundingReference } from './final-splice-candidate';
import type { FinalFundingWitnessSigner } from '../storage/final-opening-funding';
import type { IChannelManagerConfig } from './channel-manager';

export class FinalSpliceTransport {
	constructor(
		private readonly runtime: IFinalOpeningRuntime,
		private readonly wallet: () => Pick<
			IFundingProvider,
			'releaseInputPledges' | 'resolveFinalSpliceInputs'
		> | null,
		private readonly verify: NonNullable<
			IChannelManagerConfig['verifyRemoteFundingInput']
		>,
		private readonly fetchPrevious:
			| ((txid: string) => Promise<Buffer>)
			| undefined,
		private readonly send: (peer: string, type: M, payload: Buffer) => void,
		private readonly watch: (
			id: string,
			funding: IFinalFundingReference
		) => void,
		private readonly broadcast: (raw: Buffer) => void,
		private readonly adopted: (id: string, txid: string) => void,
		private readonly atDepth: (id: string, txid: string) => boolean,
		private readonly aborted: (id: string, reason: string) => void
	) {}
	// A fresh object distinguishes depth returning while an earlier prevout lookup was in flight.
	private readonly fundingEvidence = new Map<string, object>();
	private readonly paused = new Set<string>();

	fundingDepth(id: string, confirmed: boolean): void {
		if (confirmed) {
			if (!this.fundingEvidence.has(id)) this.fundingEvidence.set(id, {});
		} else this.fundingEvidence.delete(id);
	}
	awaitingDepth(id: string): boolean {
		return this.paused.has(id);
	}
	forget(id: string): void {
		this.fundingEvidence.delete(id);
		this.paused.delete(id);
	}
	requiresDepth(id: string, type: M): boolean {
		if (type === M.TX_ABORT) return false;
		const a = this.latest(id);
		// A peer may already have broadcast the child after we released our witnesses.
		// Its matching witnesses can still be received and assembled to recover the funding watch.
		return !!a && a.aborted === undefined && !a.adopted && this.unsigned(a);
	}
	private session(id: string) {
		return this.runtime.storage.finalSpliceSession(id, this.runtime.root);
	}
	private latest(id: string) {
		return this.runtime.storage.loadFinalSpliceAttempts(id).slice(-1)[0];
	}
	private sendFor(id: string, m: IFinalOpeningMessage) {
		this.send(
			this.runtime.storage.loadFinalOpeningSession(id)!.peer,
			m.type,
			m.payload
		);
	}
	start(id: string, plan: FinalSplicePlan): void {
		if (!this.fundingEvidence.has(id))
			throw new Error('Starting a splice requires live funding depth');
		const session = this.session(id);
		session.begin(true, plan);
		const first = session.next();
		if (first?.wire) this.sendFor(id, first.wire);
	}
	handles(id: string, type: M, payload: Buffer): boolean {
		if (!this.runtime.storage.canUpdateFinalCommitments) return false;
		if (
			[
				M.STFU,
				M.SPLICE,
				M.SPLICE_ACK,
				M.SPLICE_LOCKED,
				M.TX_INIT_RBF,
				M.TX_ACK_RBF
			].includes(type)
		)
			return true;
		const a = this.latest(id);
		if (!a) return false;
		if (a.aborted !== undefined) return type === M.TX_ABORT;
		if (
			type === M.TX_ABORT &&
			a.funded &&
			!a.adopted &&
			(a.rbf === 'refused' || a.rbf === 'finished')
		)
			return true;
		if (type === M.COMMITMENT_SIGNED || type === M.TX_SIGNATURES) {
			if (!a.funded && !a.adopted) return true;
			const old = lastSpliceWire(a, false, type);
			if (old?.payload === payload.toString('hex')) return true;
			if (type === M.TX_SIGNATURES && a.candidate)
				return decodeTxSignaturesMessage(payload, {
					taproot: true
				}).txid.equals(
					Transaction.fromHex(a.candidate.funding.fundingTxHex).getHash()
				);
			return false;
		}
		return (
			!a.funded &&
			!a.adopted &&
			((type >= M.TX_ADD_INPUT && type <= M.TX_COMPLETE) || type === M.TX_ABORT)
		);
	}
	private async resolve(
		request: ISpliceSignatureRequest
	): Promise<FinalFundingWitnessSigner> {
		const { candidate: c } = request;
		for (const [index, v] of c.tx.ins.entries()) {
			const verdict = await this.verify({
				txid: v.hash,
				vout: v.index,
				scriptPubKey: c.scripts[index]
			});
			if (verdict !== 'unspent')
				throw new Error('Splice input is not verified unspent');
		}
		const wallet = this.wallet();
		if (!wallet?.resolveFinalSpliceInputs)
			throw new Error('Missing original splice wallet input verifier');
		return wallet.resolveFinalSpliceInputs(request);
	}
	async drive(id: string, current: () => boolean): Promise<void> {
		const session = this.session(id);
		const a = this.latest(id);
		this.paused.delete(id);
		if (!a || a.aborted !== undefined || a.adopted || !current()) return;
		const funded = a.funded;
		const txid = funded && Transaction.fromHex(funded).getId();
		const depth = () => (txid && this.atDepth(id, txid) ? txid : undefined);
		const next = (signer?: FinalFundingWitnessSigner) => {
			if (this.unsigned(a) && !this.fundingEvidence.has(id)) {
				this.paused.add(id);
				return;
			}
			return session.next(signer, depth());
		};
		let result = next();
		while (result && current()) {
			if (result.verify) {
				const before = this.fundingEvidence.get(id);
				if (!before) {
					this.paused.add(id);
					return;
				}
				let signer: FinalFundingWitnessSigner;
				try {
					signer = await this.resolve(result.verify);
				} catch (error) {
					if (!current()) return;
					if (this.fundingEvidence.get(id) !== before) continue;
					throw error;
				}
				if (!current()) return;
				if (this.fundingEvidence.get(id) !== before) continue;
				result = next(signer);
				continue;
			}
			if (result.wire) this.sendFor(id, result.wire);
			if (result.watch) this.watch(id, result.watch);
			if (result.broadcast) {
				this.broadcast(result.broadcast);
				const assembledTxid = Transaction.fromBuffer(result.broadcast).getId();
				// A peer may already have confirmed the child before we recover its witness message.
				if (current() && this.atDepth(id, assembledTxid))
					this.depth(id, assembledTxid, true);
			}
			if (result.adopted) this.adopted(id, result.adopted);
			if (!current()) return;
			result = next();
		}
	}
	private unsigned(
		a: Pick<IFinalSpliceAttempt, 'messages' | 'funded'>
	): boolean {
		return !a.funded && !lastSpliceWire(a, true, M.TX_SIGNATURES);
	}
	private async release(id: string): Promise<void> {
		const a = this.latest(id);
		if (!a || a.aborted === undefined || a.inputsReleased) return;
		const inputs = a.intent.inputs.map((i) => ({
			txid: Transaction.fromHex(i.prevTxHex).getId(),
			vout: i.vout
		}));
		if (inputs.length) {
			const wallet = this.wallet();
			if (!wallet?.releaseInputPledges)
				throw new Error(
					'Original wallet is unavailable to release splice inputs'
				);
			await wallet.releaseInputPledges(inputs);
		}
		this.session(id).releasedInputs();
	}
	private async retire(
		id: string,
		reason: string,
		wire: 'send' | 'echo' | 'none'
	): Promise<void> {
		const response = this.session(id).abort(reason, wire === 'send');
		this.paused.delete(id);
		if (wire !== 'none') this.sendFor(id, response);
		await this.release(id);
		this.aborted(id, reason);
	}
	async receive(
		id: string,
		msg: IFinalOpeningMessage,
		live: boolean,
		current: () => boolean
	): Promise<void> {
		const session = this.session(id);
		let prior = this.latest(id);
		if (msg.type === M.TX_ABORT && prior?.aborted !== undefined) {
			decodeTxAbortMessage(msg.payload);
			session.acknowledgeAbort();
			await this.release(id);
			return;
		}
		if (msg.type === M.TX_ABORT && prior && this.unsigned(prior)) {
			decodeTxAbortMessage(msg.payload);
			await this.retire(id, 'Peer aborted splice', 'echo');
			return;
		}
		if (
			msg.type === M.STFU &&
			prior?.intent.initiator &&
			prior.aborted === undefined &&
			!prior.adopted &&
			!lastSpliceWire(prior, false, M.STFU) &&
			lastSpliceWire(prior, true, M.STFU) &&
			msg.payload.length === 33 &&
			msg.payload[32] === 1 &&
			!this.runtime.storage.loadFinalOpening(id)!.isInitiator
		) {
			await this.retire(
				id,
				'Original channel opener won simultaneous quiescence',
				'none'
			);
			session.begin(false, {
				localDelta: '0',
				feeBudget: '0',
				feerate: 1,
				locktime: 0,
				inputs: [],
				outputs: []
			});
			session.continueCrossedQuiescence();
			prior = this.latest(id);
		}
		if (
			msg.type === M.STFU &&
			prior?.funded &&
			!prior.adopted &&
			msg.payload.length === 33 &&
			msg.payload[32] === 1
		) {
			if (!this.runtime.storage.loadFinalCommitmentSnapshot(id)?.quiescent)
				throw new Error('Splice replacement requires a quiescent channel');
			session.replacement('quiescent');
			this.sendFor(id, {
				type: M.STFU,
				payload: encodeStfuMessage({
					channelId: Buffer.from(id, 'hex'),
					initiator: false
				})
			});
			return;
		}
		if (
			msg.type === M.TX_ABORT &&
			prior?.funded &&
			!prior.adopted &&
			(prior.rbf === 'refused' || prior.rbf === 'finished')
		) {
			session.replacement('finished');
			return;
		}
		if (
			msg.type === M.TX_INIT_RBF ||
			msg.type === M.TX_ACK_RBF ||
			(msg.type === M.SPLICE &&
				prior?.funded &&
				!prior.adopted &&
				prior.rbf === 'quiescent')
		) {
			if (prior?.rbf === 'quiescent') session.replacement('refused');
			this.sendFor(id, {
				type: M.TX_ABORT,
				payload: encodeTxAbortMessage({
					channelId: Buffer.from(id, 'hex'),
					data: Buffer.from('Splice fee replacement is unavailable')
				})
			});
			return;
		}
		if (
			msg.type === M.STFU &&
			(!prior || prior.adopted || prior.aborted !== undefined)
		) {
			if (!live || msg.payload.length !== 33 || msg.payload[32] !== 1)
				throw new Error('New splice requires a live, quiescent channel');
			session.begin(false, {
				localDelta: '0',
				feeBudget: '0',
				feerate: 1,
				locktime: 0,
				inputs: [],
				outputs: []
			});
		}
		if (
			prior?.adopted &&
			[M.TX_SIGNATURES, M.COMMITMENT_SIGNED].includes(msg.type) &&
			lastSpliceWire(prior, false, msg.type)?.payload ===
				msg.payload.toString('hex')
		)
			return;
		try {
			let previous: Buffer | undefined;
			if (msg.type === M.TX_ADD_INPUT) {
				const input = decodeTxAddInputMessage(msg.payload, { taproot: true });
				if (input.prevTxOut) {
					if (!this.fetchPrevious)
						throw new Error('Cannot resolve a compact splice input');
					previous = await this.fetchPrevious(
						Buffer.from(input.prevTxOut.txid).reverse().toString('hex')
					);
					if (!current()) return;
					if (previous.length > 65535)
						throw new Error(
							'Resolved splice prevout exceeds transaction budget'
						);
				}
			}
			session.receive(msg, previous);
			await this.drive(id, current);
		} catch (error) {
			if (!current()) return;
			const a = this.latest(id);
			if (!a || !this.unsigned(a) || a.adopted || a.aborted !== undefined)
				throw error;
			// Re-read the durable witness record after asynchronous wallet and chain checks.
			await this.retire(id, 'Refused splice negotiation', 'send');
		}
	}
	reconnectFields(id: string): Partial<IChannelReestablishMessage> {
		const a = this.latest(id);
		if (!a || a.aborted !== undefined || a.adopted) return {};
		const fields: Partial<IChannelReestablishMessage> = {};
		if (a.localLock && a.funded && this.atDepth(id, a.localLock))
			fields.myCurrentFundingLocked = {
				txid: Transaction.fromHex(a.funded).getHash(),
				retransmitFlags: 0
			};
		const raw = lastSpliceWire(a, true, M.COMMITMENT_SIGNED);
		if (!a.funded && raw) {
			const signature = decodeCommitmentSignedMessage(
				Buffer.from(raw.payload, 'hex')
			);
			fields.nextFundingTxid = signature.fundingTxid;
			fields.nextFundingRetransmitFlags = lastSpliceWire(
				a,
				false,
				M.COMMITMENT_SIGNED
			)
				? 0
				: 1;
			if (fields.nextFundingRetransmitFlags)
				fields.currentCommitNonce = this.session(id).currentNonce();
		}
		return fields;
	}
	validateReconnect(id: string, msg: IChannelReestablishMessage): void {
		if (!msg.nextFundingTxid) return;
		const a = this.latest(id);
		if (!a || a.aborted !== undefined)
			throw new Error('Peer retained an unknown splice candidate');
		const ours = lastSpliceWire(a, true, M.COMMITMENT_SIGNED);
		const txid = a.candidate
			? Transaction.fromHex(a.candidate.funding.fundingTxHex).getHash()
			: ours
			? decodeCommitmentSignedMessage(Buffer.from(ours.payload, 'hex'))
					.fundingTxid
			: this.session(id).agreedFundingTxid();
		if (
			!txid?.equals(msg.nextFundingTxid) ||
			(msg.nextFundingRetransmitFlags ?? 0) > 1
		)
			throw new Error('Different splice candidate on reconnect');
		if (msg.nextFundingRetransmitFlags) {
			if (
				!this.session(id)
					.currentNonce(false)
					?.equals(msg.currentCommitNonce ?? Buffer.alloc(0))
			)
				throw new Error('Peer changed in-flight splice verification nonce');
		}
	}
	async reestablished(
		id: string,
		msg: IChannelReestablishMessage,
		current: () => boolean
	): Promise<void> {
		const a = this.latest(id);
		if (!a) return;
		if (a.aborted !== undefined) {
			this.session(id).acknowledgeAbort();
			await this.release(id);
			return;
		}
		if (
			a.funded &&
			!a.adopted &&
			(a.rbf === 'quiescent' || a.rbf === 'refused')
		)
			this.session(id).replacement('finished');
		const resend = (type: M) => {
			const w = lastSpliceWire(a, true, type);
			if (w) this.sendFor(id, { type, payload: Buffer.from(w.payload, 'hex') });
		};
		if (msg.nextFundingTxid) {
			if (msg.nextFundingRetransmitFlags) {
				resend(M.COMMITMENT_SIGNED);
			}
			resend(M.TX_SIGNATURES);
		} else if (this.unsigned(a)) {
			await this.retire(
				id,
				'Peer discarded unsigned splice on reconnect',
				'none'
			);
			return;
		} else if (!a.funded) resend(M.TX_SIGNATURES);
		if (a.localLock && this.atDepth(id, a.localLock)) resend(M.SPLICE_LOCKED);
		await this.drive(id, current);
	}
	depth(id: string, txid: string, connected: boolean): void {
		const a = this.latest(id);
		if (
			!a?.funded ||
			a.adopted ||
			Transaction.fromHex(a.funded).getId() !== txid
		)
			return;
		const wire = this.session(id).lock(txid);
		if (connected) {
			const saved = lastSpliceWire(a, true, M.SPLICE_LOCKED);
			if (wire) this.sendFor(id, wire);
			else if (saved)
				this.sendFor(id, {
					type: M.SPLICE_LOCKED,
					payload: Buffer.from(saved.payload, 'hex')
				});
		}
		const result = this.session(id).next(undefined, txid);
		if (result?.adopted) this.adopted(id, result.adopted);
	}
}
