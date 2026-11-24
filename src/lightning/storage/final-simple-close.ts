import { Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import type { BIP32Interface } from 'bip32';
import { deriveChannelKeys } from '../keys/wallet-keys';
import type { IFinalOpeningNonces } from './final-opening-nonces';
import type { FinalOpeningAuthority } from './final-opening-authority';
import { readyKeys } from './final-opening-ready';
import { isValidShutdownScript } from '../channel/validation';
import { getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import { generateNonce } from '../crypto/musig';
import { hmacSha256, sha256 } from '../crypto/provider';
import { estimateSimpleCloseFee } from '../chain/closing';
import { MessageType } from '../message/types';
import {
	decodeClosingCompleteMessage,
	decodeClosingSigMessage,
	decodeShutdownMessage,
	encodeShutdownMessage
} from '../message/channel-close';
import {
	acceptFinalSimpleClose,
	completeFinalSimpleClose,
	proposeFinalSimpleClose,
	finalSimpleCloseProposalTxids,
	type IFinalSimpleCloseParams
} from '../channel/final-simple-close';
import type { IFinalOpeningMessage } from '../channel/final-opening-runtime';

/** Public wire bytes and fully signed transactions. Nonce secrets stay on the original. */
export interface IFinalSimpleCloseState {
	requestedScript?: string;
	locked?: true;
	localShutdown?: string;
	peerShutdown?: string;
	localProposal?: string;
	localProposalTxids?: string[];
	funding?: { txid: string; index: number; script: string; value: number };
	peerProposal?: string;
	localReply?: string;
	peerReply?: string;
	localTransaction?: string;
	peerTransaction?: string;
	answered?: number;
	priorTransactions?: string[];
}

export interface IFinalCloseView {
	localHeight: bigint;
	remoteHeight: bigint;
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	pending: unknown;
	htlcs: readonly unknown[];
}

export interface IFinalCloseFunding {
	fundingTxHex: string;
	fundingOutputIndex: number;
	localFundingPubkey: string;
	remoteFundingPubkey: string;
	localFundingKeyIndex: number;
}

export interface IFinalCloseRequest {
	script: Buffer;
	blockHeight: number;
	feeratePerKw: number;
	message?: IFinalOpeningMessage;
	start?: boolean;
}

export class FinalCloseProtocolError extends Error {}

function peerNonce(bytes?: Buffer): Buffer {
	if (
		!bytes ||
		bytes.length !== 66 ||
		!isValidPublicKey(bytes.subarray(0, 33)) ||
		!isValidPublicKey(bytes.subarray(33))
	)
		throw new FinalCloseProtocolError('Invalid simple close nonce');
	return bytes;
}

/** Persist all results in the caller before delivering the returned wire messages. */
export function driveFinalSimpleClose(
	id: string,
	candidate: IFinalCloseFunding,
	opening: IFinalOpeningNonces,
	context: Buffer,
	authority: FinalOpeningAuthority,
	root: BIP32Interface,
	identity: string,
	close: IFinalSimpleCloseState,
	view: IFinalCloseView,
	req: IFinalCloseRequest
): { messages: IFinalOpeningMessage[]; transaction?: Buffer } {
	const cid = Buffer.from(id, 'hex');
	readyKeys(root, opening, identity);
	const key = deriveChannelKeys(
		root,
		1,
		candidate.localFundingKeyIndex
	).fundingPrivkey;
	if (getPublicKey(key).toString('hex') !== candidate.localFundingPubkey)
		throw new Error('Active final funding key belongs to another derivation');
	const nonce = (purpose: string, msg?: Buffer): Uint8Array =>
		generateNonce({
			publicKey: getPublicKey(key),
			secretKey: key,
			msg,
			sessionId: hmacSha256(
				context,
				Buffer.from('final-simple-close/' + purpose)
			),
			extraInput: Buffer.from('final-simple-close-v1')
		});
	const wire = req.message;
	const messages: IFinalOpeningMessage[] = [];
	if (wire && !wire.payload.subarray(0, 32).equals(cid))
		throw new FinalCloseProtocolError('Simple close channel id changed');
	if (wire?.type === MessageType.SHUTDOWN) {
		const peer = decodeShutdownMessage(wire.payload);
		if (!isValidShutdownScript(peer.scriptPubkey, true, true))
			throw new FinalCloseProtocolError('Invalid peer shutdown script');
		peerNonce(peer.shutdownNonce);
		if (
			close.peerShutdown &&
			close.peerShutdown !== wire.payload.toString('hex')
		)
			throw new Error('Peer changed an outstanding final shutdown');
		close.peerShutdown = wire.payload.toString('hex');
	}
	if (req.start) {
		if (!isValidShutdownScript(req.script, true, false))
			throw new Error('Invalid local simple close destination');
		const hex = req.script.toString('hex');
		if (close.requestedScript && close.requestedScript !== hex)
			throw new Error('Local shutdown destination already chosen');
		close.requestedScript = hex;
	}
	if (
		!close.localShutdown &&
		!view.pending &&
		(close.requestedScript || close.peerShutdown)
	) {
		const destination = close.requestedScript
			? Buffer.from(close.requestedScript, 'hex')
			: req.script;
		if (!isValidShutdownScript(destination, true, false))
			throw new Error('Invalid local simple close destination');
		const shut = encodeShutdownMessage({
			channelId: cid,
			scriptPubkey: destination,
			shutdownNonce: Buffer.from(nonce('closee/0'))
		});
		if (
			close.peerShutdown &&
			decodeShutdownMessage(
				Buffer.from(close.peerShutdown, 'hex')
			).shutdownNonce?.equals(decodeShutdownMessage(shut).shutdownNonce!)
		)
			throw new FinalCloseProtocolError('Reflected simple close nonce');
		close.localShutdown = shut.toString('hex');
		messages.push({ type: MessageType.SHUTDOWN, payload: shut });
	} else if (req.start && close.localShutdown) {
		const retained = Buffer.from(close.localShutdown, 'hex');
		if (!decodeShutdownMessage(retained).scriptPubkey.equals(req.script))
			throw new Error('Local shutdown destination already chosen');
		messages.push({ type: MessageType.SHUTDOWN, payload: retained });
	}
	if (
		!close.localShutdown ||
		!close.peerShutdown ||
		view.pending ||
		view.htlcs.length
	) {
		if (wire && wire.type !== MessageType.SHUTDOWN)
			throw new Error(
				'Simple close requires both shutdowns and settled commitments'
			);
		return { messages };
	}
	const ours = decodeShutdownMessage(Buffer.from(close.localShutdown, 'hex'));
	const theirs = decodeShutdownMessage(Buffer.from(close.peerShutdown, 'hex'));
	if (theirs.shutdownNonce!.equals(ours.shutdownNonce!))
		throw new FinalCloseProtocolError('Reflected shutdown nonce');
	const funds = Buffer.from(candidate.fundingTxHex, 'hex');
	const params: IFinalSimpleCloseParams = {
		channelId: cid,
		fundingTx: funds,
		fundingOutputIndex: candidate.fundingOutputIndex,
		localFundingPrivkey: key,
		remoteFundingPubkey: Buffer.from(candidate.remoteFundingPubkey, 'hex'),
		localBalanceMsat: view.localBalanceMsat,
		remoteBalanceMsat: view.remoteBalanceMsat,
		localScriptPubkey: ours.scriptPubkey,
		remoteScriptPubkey: theirs.scriptPubkey,
		localIsCloser: true,
		blockHeight: req.blockHeight,
		locktime: 0,
		feeSatoshis: estimateSimpleCloseFee(
			req.feeratePerKw,
			ours.scriptPubkey.length,
			theirs.scriptPubkey.length
		)
	};
	const binding = sha256(
		Buffer.from(
			JSON.stringify([
				id,
				candidate.fundingTxHex,
				candidate.fundingOutputIndex,
				view.localHeight.toString(),
				view.remoteHeight.toString(),
				view.localBalanceMsat.toString(),
				view.remoteBalanceMsat.toString(),
				close.localShutdown,
				close.peerShutdown
			])
		)
	).toString('hex');
	authority.commitLifecycleEntry('simple-close-lock/' + id, binding);
	close.locked = true;
	const funding = Transaction.fromBuffer(funds);
	const output = funding.outs[candidate.fundingOutputIndex];
	close.funding = {
		txid: funding.getHash().toString('hex'),
		index: candidate.fundingOutputIndex,
		script: output.script.toString('hex'),
		value: output.value
	};
	if (
		!close.localProposal &&
		(!wire || wire.type === MessageType.SHUTDOWN) &&
		params.feeSatoshis <= view.localBalanceMsat / 1000n
	) {
		const purpose = 'proposal/' + binding + '/' + params.feeSatoshis;
		const proposal = proposeFinalSimpleClose(
			params,
			theirs.shutdownNonce!,
			(variant, sighash) => nonce(purpose + '/' + variant, sighash)
		).proposal;
		close.localProposalTxids = finalSimpleCloseProposalTxids(params, proposal);
		close.localProposal = proposal.toString('hex');
		messages.push({ type: MessageType.CLOSING_COMPLETE, payload: proposal });
	}
	if (!wire || wire.type === MessageType.SHUTDOWN) return { messages };
	if (wire.type === MessageType.CLOSING_COMPLETE) {
		const proposal = wire.payload.toString('hex');
		if (close.peerProposal === proposal && close.localReply)
			return {
				messages: [
					{
						type: MessageType.CLOSING_SIG,
						payload: Buffer.from(close.localReply, 'hex')
					}
				],
				transaction: Buffer.from(close.peerTransaction!, 'hex')
			};
		const decoded = decodeClosingCompleteMessage(wire.payload, {
			finalTaproot: true
		});
		const generation = close.answered ?? 0;
		if (generation >= 256)
			throw new Error('Simple close proposal history is full');
		const challenge = sha256(
			Buffer.concat([Buffer.from(binding, 'hex'), wire.payload])
		).toString('hex');
		const slot = 'final-simple-close-answer/' + id + '/' + generation;
		const saved = authority.claim(slot, challenge);
		const response = saved
			? (JSON.parse(saved.toString()) as { reply: string; transaction: string })
			: ((): { reply: string; transaction: string } => {
					const result = acceptFinalSimpleClose(
						{
							...params,
							localIsCloser: false,
							feeSatoshis: decoded.feeSatoshis,
							locktime: decoded.locktime
						},
						wire.payload,
						nonce('closee/' + generation),
						Buffer.from(nonce('closee/' + (generation + 1)))
					);
					const value = {
						reply: result.reply.toString('hex'),
						transaction: result.transaction.toString('hex')
					};
					authority.finish(slot, challenge, Buffer.from(JSON.stringify(value)));
					return value;
			  })();
		if (close.peerTransaction)
			(close.priorTransactions ??= []).push(close.peerTransaction);
		close.peerProposal = proposal;
		close.localReply = response.reply;
		close.peerTransaction = response.transaction;
		close.answered = generation + 1;
		return {
			messages: [
				{
					type: MessageType.CLOSING_SIG,
					payload: Buffer.from(response.reply, 'hex')
				}
			],
			transaction: Buffer.from(response.transaction, 'hex')
		};
	}
	if (wire.type !== MessageType.CLOSING_SIG || !close.localProposal)
		throw new FinalCloseProtocolError('Unexpected final simple close message');
	const p = Buffer.from(close.localProposal, 'hex');
	const original = decodeClosingCompleteMessage(p, { finalTaproot: true });
	decodeClosingSigMessage(wire.payload, { finalTaproot: true });
	const signed = completeFinalSimpleClose(
		{
			...params,
			feeSatoshis: original.feeSatoshis,
			locktime: original.locktime
		},
		p,
		wire.payload,
		theirs.shutdownNonce!
	);
	close.peerReply = wire.payload.toString('hex');
	close.localTransaction = signed.toString('hex');
	return { messages, transaction: signed };
}

export function matchFinalSimpleCloseSpend(
	close: IFinalSimpleCloseState | null,
	raw: Buffer
): boolean {
	if (!close?.funding) return false;
	const tx = Transaction.fromBuffer(raw);
	const id = tx.getId();
	const saved = [
		close.localTransaction,
		close.peerTransaction,
		...(close.priorTransactions ?? [])
	];
	if (
		!close.localProposalTxids?.includes(id) &&
		!saved.some((hex) => hex && Transaction.fromHex(hex).getId() === id)
	)
		return false;
	const input = tx.ins[0];
	const { txid, index, script, value } = close.funding;
	if (
		tx.ins.length !== 1 ||
		input.index !== index ||
		input.hash.toString('hex') !== txid ||
		input.script.length ||
		input.witness.length !== 1 ||
		input.witness[0].length !== 64
	)
		return false;
	const prev = Buffer.from(script, 'hex');
	return ecc.verifySchnorr(
		tx.hashForWitnessV1(0, [prev], [value], Transaction.SIGHASH_DEFAULT),
		prev.subarray(2),
		input.witness[0]
	);
}
