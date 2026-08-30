/**
 * Harness for the direct-funding receiver engine tests (issue #612).
 *
 * One payer, one stub node. The payer half is real: real request envelopes
 * (4A), real sealed frames, real ownership proofs over the real digest, so an
 * offer that the engine accepts is one a real payer could have sent. The node
 * half is a stub with knobs, because the point of these tests is the engine's
 * decisions, not the channel state machine's (which has suites of its own).
 */

import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

import { getPublicKey, sign } from '../../../src/lightning/crypto/ecdh';
import { schnorrSign } from '../../../src/lightning/offer/schnorr';
import { BeignetCustomSubtype } from '../../../src/lightning/message/custom';
import {
	decodeSealedFrame,
	encodeSealedFrame,
	openFrame,
	sealFrame,
	senderLaneKeys,
	IDfSenderLane
} from '../../../src/lightning/direct-funding/frames';
import {
	deriveOfferId,
	encodeDfOffer,
	encodeDfWitness,
	ownershipDigest,
	IDfOffer
} from '../../../src/lightning/direct-funding/messages';
import {
	DirectFundingRequestStore,
	requestEncryptionPublicKey
} from '../../../src/lightning/direct-funding/requests';
import { IDfRequestRecord } from '../../../src/lightning/direct-funding/types';
import {
	IDfChannelHandle,
	IDfOpenParams,
	IDfPendingSpliceTx,
	IDfPendingV2FundingTx,
	IDfReceiverDeps,
	IDfSpliceTxSigsNeeded,
	IDfTxSigsNeeded
} from '../../../src/lightning/direct-funding/receiver/types';
import {
	IDfInboundFrame,
	IDfLaneSender
} from '../../../src/lightning/direct-funding/transport/types';
import { ISpliceWalletInput } from '../../../src/lightning/channel/channel';

export const LSP_PUBKEY = getPublicKey(
	crypto.createHash('sha256').update('df-lsp').digest()
).toString('hex');

/** Let every pending microtask and zero-delay timer run. */
export async function flush(times = 4): Promise<void> {
	for (let i = 0; i < times; i++) {
		await new Promise((resolve) => setTimeout(resolve, 0));
	}
}

// ─────────────── Coins ───────────────

export interface IDfTestCoin {
	prevTx: bitcoin.Transaction;
	txidHex: string;
	vout: number;
	valueSat: bigint;
	script: Buffer;
	privkey: Buffer;
	pubkey: Buffer;
	kind: 'p2wpkh' | 'p2tr' | 'p2wsh';
}

export function makeCoin(
	kind: 'p2wpkh' | 'p2tr' | 'p2wsh' = 'p2wpkh',
	valueSat = 100_000
): IDfTestCoin {
	const privkey = crypto.randomBytes(32);
	const pubkey = getPublicKey(privkey);
	const script =
		kind === 'p2wpkh'
			? bitcoin.payments.p2wpkh({ pubkey }).output!
			: kind === 'p2tr'
			? Buffer.concat([Buffer.from([0x51, 0x20]), pubkey.subarray(1, 33)])
			: Buffer.concat([
					Buffer.from([0x00, 0x20]),
					crypto.createHash('sha256').update(pubkey).digest()
			  ]);
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(script, valueSat);
	return {
		prevTx,
		txidHex: prevTx.getId(),
		vout: 0,
		valueSat: BigInt(valueSat),
		script,
		privkey,
		pubkey,
		kind
	};
}

// ─────────────── Offers ───────────────

export interface IDfOfferOverrides {
	amountSat?: bigint;
	sequence?: number;
	changeScript?: Buffer;
	maxTotalFeeSat?: bigint;
	receiptHash?: Buffer;
	offerId?: Buffer;
	ownershipSignature?: Buffer;
	ownershipPubkey?: Buffer;
}

export function buildOffer(
	record: IDfRequestRecord,
	coin: IDfTestCoin,
	overrides: IDfOfferOverrides = {}
): IDfOffer {
	const amountSat = overrides.amountSat ?? 50_000n;
	const txid = Buffer.from(coin.txidHex, 'hex');
	const offerId =
		overrides.offerId ?? deriveOfferId(txid, coin.vout, amountSat);
	const digest = ownershipDigest(offerId, txid, coin.vout, amountSat);
	const isTaproot = coin.kind === 'p2tr';
	const signature =
		overrides.ownershipSignature ??
		(isTaproot
			? schnorrSign(digest, coin.privkey)
			: sign(digest, coin.privkey));
	return {
		offerId,
		amountSat,
		txid,
		vout: coin.vout,
		valueSat: coin.valueSat,
		sequence: overrides.sequence ?? 0xfffffffd,
		changeScript:
			overrides.changeScript ??
			bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) }).output!,
		maxTotalFeeSat: overrides.maxTotalFeeSat ?? 2_000n,
		receiptHash:
			overrides.receiptHash ?? Buffer.from(record.receiptHash, 'hex'),
		ownership: {
			pubkey:
				overrides.ownershipPubkey ??
				(isTaproot ? coin.pubkey.subarray(1, 33) : coin.pubkey),
			signature
		}
	};
}

// ─────────────── The payer's lane ───────────────

export class FakePayerLane {
	readonly sent: Array<{ subtype: number; payload: Buffer }> = [];
	readonly lane: IDfSenderLane;
	readonly requestId: Buffer;
	/** Every message the receiver sent us, opened and by subtype. */
	readonly received: Array<{ subtype: number; body: Buffer }> = [];

	constructor(
		private readonly record: IDfRequestRecord,
		readonly laneKey = 'payer-lane',
		readonly authenticatedPeer?: string
	) {
		this.requestId = Buffer.from(record.requestId, 'hex');
		this.lane = senderLaneKeys(
			requestEncryptionPublicKey(record),
			this.requestId
		);
	}

	get reply(): IDfLaneSender {
		return {
			type: 1,
			send: (subtype, payload): void => {
				this.capture(subtype, payload);
			},
			trySend: (subtype, payload): boolean => {
				this.capture(subtype, payload);
				return true;
			}
		};
	}

	private capture(subtype: number, payload: Buffer): void {
		this.sent.push({ subtype, payload });
		const wire = decodeSealedFrame(payload);
		if (!wire) return;
		const body = openFrame(
			this.lane.keys.recvKey,
			this.requestId,
			subtype,
			wire
		);
		if (!body) return;
		this.received.push({ subtype, body });
		// Fires INSIDE the receiver's send, which is what a payer and a receiver
		// in one process actually do to each other.
		this.onReceive?.(subtype, body);
	}

	/** Answer synchronously, the way a same-process payer would. */
	onReceive?: (subtype: number, body: Buffer) => void;

	bodiesOf(subtype: number): Buffer[] {
		return this.received
			.filter((r) => r.subtype === subtype)
			.map((r) => r.body);
	}

	/** An OPENING frame carrying one offer, exactly as a payer sends it. */
	offerFrame(offer: IDfOffer): IDfInboundFrame {
		return this.frame(
			BeignetCustomSubtype.DIRECT_FUNDING_OFFER,
			encodeDfOffer(offer),
			true
		);
	}

	witnessFrame(offerId: Buffer, witness: Buffer[]): IDfInboundFrame {
		return this.frame(
			BeignetCustomSubtype.DIRECT_FUNDING_WITNESS,
			encodeDfWitness({ offerId, witness }),
			false
		);
	}

	frame(subtype: number, body: Buffer, opening: boolean): IDfInboundFrame {
		const sealed = sealFrame(
			this.lane.keys.sendKey,
			this.requestId,
			subtype,
			body
		);
		const payload = encodeSealedFrame(
			sealed,
			opening
				? {
						requestId: this.requestId,
						ephemeralPublicKey: this.lane.ephemeralPublicKey
				  }
				: undefined
		);
		return {
			type: 1,
			laneKey: this.laneKey,
			subtype,
			payload,
			reply: this.reply,
			...(this.authenticatedPeer
				? { authenticatedPeer: this.authenticatedPeer }
				: {})
		};
	}

	get requestRecord(): IDfRequestRecord {
		return this.record;
	}
}

// ─────────────── The stub node ───────────────

export interface IDfOpenCall {
	peerHex: string;
	params: IDfOpenParams;
	channelId: Buffer;
}

export interface IDfSpliceCall {
	channelId: Buffer;
	amountSats: bigint;
	inputs: ISpliceWalletInput[];
	changeScript: Buffer;
	feeratePerKw: number;
}

/** A wallet-data store two FakeDfNodes can share, i.e. survive a restart. */
export function memoryStorage(): {
	saveWalletData(key: string, value: string): void;
	loadWalletData(key: string): string | null;
} {
	const rows = new Map<string, string>();
	return {
		saveWalletData: (key, value): void => {
			rows.set(key, value);
		},
		loadWalletData: (key): string | null => rows.get(key) ?? null
	};
}

export class FakeDfNode implements IDfReceiverDeps {
	readonly requests: DirectFundingRequestStore;
	readonly transactions = new Map<string, Buffer>();
	readonly unspent = new Map<
		string,
		Array<{
			txid: string;
			outputIndex: number;
			valueSat: number;
			height: number;
		}>
	>();
	readonly history = new Map<string, Array<{ txid: string; height: number }>>();
	readonly opens: IDfOpenCall[] = [];
	readonly splices: IDfSpliceCall[] = [];
	readonly aborts: Array<{ kind: 'open' | 'splice'; channelId: string }> = [];
	readonly witnesses: Array<{ kind: 'open' | 'splice'; witness: Buffer[] }> =
		[];
	/** Set to make the channel refuse a delivered witness. */
	witnessError: string | null = null;
	/** Set to make the channel take the witness and withhold its tx_signatures. */
	witnessSendsWithheld = false;
	/** Set to make abortDualFundedOpen report a refusal. */
	abortError: string | null = null;
	/** Set to make abortDualFundedOpen report a tx_abort awaiting its echo. */
	abortPending = false;
	/** Set to make abortSplice report a refusal (the peer signed first). */
	spliceAbortError: string | null = null;
	spliceError: string | null = null;
	openThrows: Error | null = null;
	lspPubkey: string | null = LSP_PUBKEY;
	spliceChannel: Buffer | null = null;
	trustedPayers = new Set<string>();
	zeroConfPeers = new Set<string>();
	pubkeysAvailable = true;
	/** Fired inside openChannelV2 when set, i.e. a fully synchronous transport. */
	onOpenSideEffect: (() => void) | null = null;

	private txSigsListeners: Array<(e: IDfTxSigsNeeded) => void> = [];
	private spliceListeners: Array<(e: IDfSpliceTxSigsNeeded) => void> = [];
	private pendingV2 = new Map<string, IDfPendingV2FundingTx>();
	private pendingSplice = new Map<string, IDfPendingSpliceTx>();

	readonly chain = {
		getTransaction: async (txid: string): Promise<Buffer> => {
			const raw = this.transactions.get(txid);
			if (!raw) throw new Error(`no such transaction ${txid}`);
			return raw;
		},
		listUnspent: async (
			scriptHash: string
		): Promise<
			Array<{
				txid: string;
				outputIndex: number;
				valueSat: number;
				height: number;
			}>
		> => this.unspent.get(scriptHash) ?? [],
		getScriptHashHistory: async (
			scriptHash: string
		): Promise<Array<{ txid: string; height: number }>> =>
			this.history.get(scriptHash) ?? []
	};

	// ─── setup ───

	constructor(
		storage?: {
			saveWalletData(key: string, value: string): void;
			loadWalletData(key: string): string | null;
		},
		now?: () => number
	) {
		this.requests = new DirectFundingRequestStore({
			...(storage ? { storage } : {}),
			...(now ? { now } : {})
		});
		this.requests.restore();
	}

	mintRequest(ttlMs?: number, amountSat?: bigint): IDfRequestRecord {
		return this.requests.mint({
			...(ttlMs === undefined ? {} : { ttlMs }),
			...(amountSat === undefined ? {} : { amountSat })
		});
	}

	/** Make a coin resolvable, unspent and confirmed, from our chain source. */
	publish(coin: IDfTestCoin, height = 100): void {
		this.transactions.set(coin.txidHex, coin.prevTx.toBuffer());
		const scriptHash = Buffer.from(
			crypto.createHash('sha256').update(coin.script).digest()
		)
			.reverse()
			.toString('hex');
		this.unspent.set(scriptHash, [
			{
				txid: coin.txidHex,
				outputIndex: coin.vout,
				valueSat: Number(coin.valueSat),
				height
			}
		]);
		this.history.set(scriptHash, [{ txid: coin.txidHex, height }]);
	}

	/** Make a published coin look provably spent (confirmed, not unspent). */
	markSpent(coin: IDfTestCoin): void {
		const scriptHash = Buffer.from(
			crypto.createHash('sha256').update(coin.script).digest()
		)
			.reverse()
			.toString('hex');
		this.unspent.set(scriptHash, []);
		this.history.set(scriptHash, [{ txid: coin.txidHex, height: 100 }]);
	}

	// ─── IDfReceiverDeps ───

	signMessage(): string {
		// zbase32 of 65 zero bytes: the engine only checks the width.
		return 'y'.repeat(104);
	}

	liquidityPeer(): string | null {
		return this.lspPubkey;
	}

	usableChannelWith(): Buffer | null {
		return this.spliceChannel;
	}

	fundingPubkeys(): { local: Buffer; remote: Buffer } | null {
		if (!this.pubkeysAvailable) return null;
		return {
			local: getPublicKey(crypto.createHash('sha256').update('local').digest()),
			remote: getPublicKey(
				crypto.createHash('sha256').update('remote').digest()
			)
		};
	}

	canOpenZeroConfTo(peerHex: string): boolean {
		return this.zeroConfPeers.has(peerHex);
	}

	isTrustedPayer(peerHex: string): boolean {
		return this.trustedPayers.has(peerHex);
	}

	openChannelV2(peerHex: string, params: IDfOpenParams): IDfChannelHandle {
		if (this.openThrows) throw this.openThrows;
		const channelId = crypto.randomBytes(32);
		this.opens.push({ peerHex, params, channelId });
		this.onOpenSideEffect?.();
		return { channelId: (): Buffer => channelId };
	}

	abortDualFundedOpen(channelId: Buffer): {
		ok: boolean;
		error?: string;
		pending?: boolean;
	} {
		this.aborts.push({ kind: 'open', channelId: channelId.toString('hex') });
		return this.abortError
			? { ok: false, error: this.abortError }
			: { ok: true, pending: this.abortPending };
	}

	spliceInWithInputs(
		channelId: Buffer,
		amountSats: bigint,
		inputs: ISpliceWalletInput[],
		changeScript: Buffer,
		feeratePerKw: number
	): { ok: boolean; error?: string } {
		this.splices.push({
			channelId,
			amountSats,
			inputs,
			changeScript,
			feeratePerKw
		});
		return this.spliceError
			? { ok: false, error: this.spliceError }
			: { ok: true };
	}

	abortSplice(channelId: Buffer): { ok: boolean; error?: string } {
		this.aborts.push({ kind: 'splice', channelId: channelId.toString('hex') });
		return this.spliceAbortError
			? { ok: false, error: this.spliceAbortError }
			: { ok: true };
	}

	getPendingV2FundingTx(channelId: Buffer): IDfPendingV2FundingTx | null {
		return this.pendingV2.get(channelId.toString('hex')) ?? null;
	}

	getPendingSpliceTx(channelId: Buffer): IDfPendingSpliceTx | null {
		return this.pendingSplice.get(channelId.toString('hex')) ?? null;
	}

	provideV2ExternalWitness(
		_channelId: Buffer,
		_prevTxid: Buffer,
		_prevOutputIndex: number,
		witness: Buffer[]
	): { ok: boolean; error?: string; sendsWithheld?: boolean } {
		this.witnesses.push({ kind: 'open', witness });
		return this.deliveryResult();
	}

	provideSpliceExternalWitness(
		_channelId: Buffer,
		_prevTxid: Buffer,
		_prevOutputIndex: number,
		witness: Buffer[]
	): { ok: boolean; error?: string; sendsWithheld?: boolean } {
		this.witnesses.push({ kind: 'splice', witness });
		return this.deliveryResult();
	}

	private deliveryResult(): {
		ok: boolean;
		error?: string;
		sendsWithheld?: boolean;
	} {
		if (this.witnessError) return { ok: false, error: this.witnessError };
		return { ok: true, sendsWithheld: this.witnessSendsWithheld };
	}

	onTxSigsNeeded(cb: (e: IDfTxSigsNeeded) => void): () => void {
		this.txSigsListeners.push(cb);
		return () => {
			this.txSigsListeners = this.txSigsListeners.filter((l) => l !== cb);
		};
	}

	onSpliceTxSigsNeeded(cb: (e: IDfSpliceTxSigsNeeded) => void): () => void {
		this.spliceListeners.push(cb);
		return () => {
			this.spliceListeners = this.spliceListeners.filter((l) => l !== cb);
		};
	}

	// ─── driving the negotiation ───

	/**
	 * Publish a negotiated funding transaction for the most recent open and
	 * fire channel:txsigs-needed for it, the way a real channel does once its
	 * commitment round has completed.
	 */
	completeNegotiation(
		coin: IDfTestCoin,
		offer: IDfOffer,
		opts: {
			feeSat?: bigint;
			fundingValueSat?: bigint;
			changeScript?: Buffer;
			witnessesFilled?: boolean;
			channelId?: Buffer;
			extraOutputs?: number;
			/** The real 2-of-2, when a payer on the other end will check it. */
			fundingScript?: Buffer;
		} = {}
	): { channelId: Buffer; tx: bitcoin.Transaction } {
		const channelId =
			opts.channelId ?? this.opens[this.opens.length - 1].channelId;
		const built = this.buildNegotiatedTx(coin, offer, opts);
		this.pendingV2.set(channelId.toString('hex'), {
			tx: built,
			fundingTxid: Buffer.from(built.getHash()),
			fundingOutputIndex: 0,
			prevouts: { scripts: [coin.script], values: [coin.valueSat] },
			owedExternalInputs: [
				{
					inputIndex: 0,
					prevTxid: Buffer.from(coin.prevTx.getHash()),
					prevOutputIndex: coin.vout
				}
			]
		});
		for (const cb of [...this.txSigsListeners]) {
			cb({ channelId, externalInputIndices: [0] });
		}
		return { channelId, tx: built };
	}

	completeSpliceNegotiation(
		coin: IDfTestCoin,
		offer: IDfOffer,
		preCapacitySat: bigint,
		opts: {
			feeSat?: bigint;
			fundingValueSat?: bigint;
			/** The real 2-of-2; the shared input spends it too. */
			fundingScript?: Buffer;
		} = {}
	): { channelId: Buffer; tx: bitcoin.Transaction } {
		const channelId = this.splices[this.splices.length - 1].channelId;
		const built = this.buildNegotiatedTx(coin, offer, {
			...opts,
			fundingValueSat: opts.fundingValueSat ?? preCapacitySat + offer.amountSat,
			sharedInput: preCapacitySat
		});
		this.pendingSplice.set(channelId.toString('hex'), {
			tx: built,
			spliceTxid: Buffer.from(built.getHash()),
			sharedInputIndex: 1,
			newFundingOutputIndex: 0,
			prevouts: {
				scripts: [coin.script, opts.fundingScript ?? Buffer.alloc(34, 2)],
				values: [coin.valueSat, preCapacitySat]
			},
			owedExternalInputs: [
				{
					inputIndex: 0,
					prevTxid: Buffer.from(coin.prevTx.getHash()),
					prevOutputIndex: coin.vout
				}
			]
		});
		for (const cb of [...this.spliceListeners]) {
			cb({ channelId, externalInputIndices: [0] });
		}
		return { channelId, tx: built };
	}

	/**
	 * The transaction the channel would have negotiated: the payer's input, the
	 * funding output, the payer's change. `sharedInput` adds the splice's shared
	 * old-funding input behind the payer's, `extraOutputs` pads it past rev 2's
	 * shape cap.
	 */
	buildNegotiatedTx(
		coin: IDfTestCoin,
		offer: IDfOffer,
		opts: {
			feeSat?: bigint;
			fundingValueSat?: bigint;
			changeScript?: Buffer;
			witnessesFilled?: boolean;
			sharedInput?: bigint;
			extraOutputs?: number;
			/** The real 2-of-2, when a payer on the other end will check it. */
			fundingScript?: Buffer;
		} = {}
	): bitcoin.Transaction {
		const fee = opts.feeSat ?? 500n;
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(Buffer.from(coin.prevTx.getHash()), coin.vout, offer.sequence);
		if (opts.sharedInput !== undefined) {
			tx.addInput(crypto.randomBytes(32), 0, 0xfffffffd);
		}
		tx.addOutput(
			opts.fundingScript ?? Buffer.alloc(34, 1),
			Number(opts.fundingValueSat ?? offer.amountSat)
		);
		const change = offer.valueSat - offer.amountSat - fee;
		if (change > 0n) {
			tx.addOutput(opts.changeScript ?? offer.changeScript, Number(change));
		}
		for (let i = 0; i < (opts.extraOutputs ?? 0); i++) {
			tx.addOutput(Buffer.alloc(34, 0x80 + i), 1_000);
		}
		if (opts.witnessesFilled) {
			tx.ins.forEach((_, i) => tx.setWitness(i, [Buffer.alloc(64, 7)]));
		}
		return tx;
	}
}
