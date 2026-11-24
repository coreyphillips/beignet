import { Transaction } from 'bitcoinjs-lib';
import type { IFinalFundingReference } from './final-splice-candidate';
import { MessageType } from '../message/types';
import { decodeSpliceLockedMessage } from '../message/splice';

export interface IFinalSpliceIntent {
	initiator: boolean;
	parent: IFinalFundingReference;
	localFundingKeyIndex: number;
	localFundingPubkey: string;
	localDelta: string;
	feeBudget: string;
	feerate: number;
	locktime: number;
	inputs: Array<{ prevTxHex: string; vout: number; sequence: number }>;
	outputs: Array<{ value: string; script: string }>;
}
export type FinalSpliceEvent =
	| { kind: 'begin'; intent: IFinalSpliceIntent }
	| {
			kind: 'wire';
			local: boolean;
			type: MessageType;
			payload: string;
			resolvedPrevTx?: string;
	  }
	| {
			kind: 'candidate';
			funding: IFinalFundingReference;
			localDelta: string;
			peerDelta: string;
			localExit: string;
			peerCommitment: string;
			ourCommitment: string;
			localHeight: number;
			remoteHeight: number;
			localNextNonce: string;
			peerNextNonce: string;
	  }
	| { kind: 'rbf'; phase: 'quiescent' | 'refused' | 'finished' }
	| { kind: 'funded'; transaction: string }
	| { kind: 'adopt'; txid: string }
	| { kind: 'abort'; reason: string; awaitingEcho?: boolean }
	| { kind: 'abort-ack' }
	| { kind: 'inputs-released' };

export interface IFinalSpliceAttempt {
	intent: IFinalSpliceIntent;
	messages: Array<Extract<FinalSpliceEvent, { kind: 'wire' }>>;
	candidate?: Extract<FinalSpliceEvent, { kind: 'candidate' }>;
	funded?: string;
	rbf?: 'quiescent' | 'refused' | 'finished';
	localLock?: string;
	peerLock?: string;
	adopted?: string;
	aborted?: string;
	awaitingAbortEcho?: boolean;
	inputsReleased?: boolean;
}

/** A candidate can appear on chain after our funding witnesses leave, even if the peer's reply was lost. */
export function releasedFinalSpliceFunding(
	attempt?: Pick<IFinalSpliceAttempt, 'aborted' | 'funded' | 'messages'> & {
		candidate?: { funding: IFinalFundingReference };
	}
): IFinalFundingReference | undefined {
	if (!attempt?.candidate || attempt.aborted !== undefined) return;
	if (
		attempt.funded ||
		attempt.messages.some(
			(m) => m.local && m.type === MessageType.TX_SIGNATURES
		)
	)
		return attempt.candidate.funding;
	return undefined;
}
export function finalSpliceAttempts(
	id: string,
	records: readonly FinalSpliceEvent[]
): IFinalSpliceAttempt[] {
	const attempts: IFinalSpliceAttempt[] = [];
	let active: IFinalSpliceAttempt | undefined;
	for (const record of records) {
		if (record.kind === 'begin') {
			if (
				active &&
				!active.adopted &&
				(active.aborted === undefined ||
					active.awaitingAbortEcho ||
					!active.inputsReleased)
			)
				throw new Error('Overlapping final splice negotiations');
			active = { intent: record.intent, messages: [] };
			attempts.push(active);
			continue;
		}
		if (record.kind === 'abort-ack' || record.kind === 'inputs-released') {
			if (!active || active.aborted === undefined)
				throw new Error('Splice cleanup requires a retired attempt');
			if (record.kind === 'abort-ack') active.awaitingAbortEcho = false;
			else active.inputsReleased = true;
			continue;
		}
		if (!active || active.aborted !== undefined || active.adopted)
			throw new Error('Final splice event outside an active negotiation');
		switch (record.kind) {
			case 'wire': {
				const raw = Buffer.from(record.payload, 'hex');
				if (
					raw.length < 32 ||
					raw.subarray(0, 32).toString('hex') !== id ||
					raw.toString('hex') !== record.payload
				)
					throw new Error('Wrong channel in splice journal');
				if (record.type === MessageType.SPLICE_LOCKED) {
					const lock = decodeSpliceLockedMessage(raw);
					if (
						raw.length !== 64 ||
						!lock.fundingTxid ||
						!active.candidate ||
						!active.funded
					)
						throw new Error('Splice lock requires explicit signed funding');
					const tx = Transaction.fromHex(active.funded);
					if (!lock.fundingTxid.equals(tx.getHash()))
						throw new Error(
							'Splice lock names a different funding transaction'
						);
					if (record.local) active.localLock = tx.getId();
					else active.peerLock = tx.getId();
				}
				active.messages.push(record);
				break;
			}
			case 'candidate': {
				if (active.candidate || active.funded || !record.funding)
					throw new Error('Unexpected splice commitment candidate');
				active.candidate = record;
				break;
			}
			case 'rbf':
				if (
					!active.funded ||
					(record.phase === 'refused' && active.rbf !== 'quiescent') ||
					(record.phase === 'finished' &&
						active.rbf !== 'refused' &&
						active.rbf !== 'quiescent')
				)
					throw new Error('Unexpected splice replacement negotiation');
				active.rbf = record.phase;
				break;
			case 'funded': {
				const tx = Transaction.fromHex(record.transaction);
				if (
					!active.candidate ||
					active.funded ||
					tx.getId() !==
						Transaction.fromHex(
							active.candidate.funding.fundingTxHex
						).getId() ||
					!tx.hasWitnesses()
				)
					throw new Error('Invalid assembled splice transaction');
				active.funded = record.transaction;
				break;
			}
			case 'adopt':
				if (
					!active.funded ||
					active.localLock !== record.txid ||
					active.peerLock !== record.txid
				)
					throw new Error('Final splice adoption requires matching locks');
				active.adopted = record.txid;
				break;
			case 'abort':
				if (
					active.funded ||
					active.messages.some(
						(m) => m.type === MessageType.TX_SIGNATURES && m.local
					)
				)
					throw new Error('Cannot discard a publishable splice');
				active.aborted = record.reason;
				active.awaitingAbortEcho = record.awaitingEcho;
				break;
			default:
				throw new Error('Unknown final splice event');
		}
	}
	return attempts;
}

export function selectFinalFunding(
	original: IFinalFundingReference,
	attempts: readonly IFinalSpliceAttempt[]
): IFinalFundingReference | null {
	let selected = original;
	for (const a of attempts) {
		if (a.aborted !== undefined) continue;
		if (!a.adopted) return null;
		selected = a.candidate!.funding;
	}
	return selected;
}
