/**
 * Harness for the direct-funding payer tests (issue #613).
 *
 * The receiver half is a stub with knobs; the payer half is entirely real, down
 * to the sealed frames and the ownership proofs, because what these tests are
 * about is what the payer refuses to sign. The envelope is minted with a real
 * node key so the attestation check has something to recover to.
 */

import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	signMessageWithKey,
	zbase32Decode
} from '../../../src/lightning/crypto/message-signing';
import { schnorrSign } from '../../../src/lightning/offer/schnorr';
import { createFundingScript } from '../../../src/lightning/script/funding';
import { BeignetCustomSubtype } from '../../../src/lightning/message/custom';
import {
	decodeSealedFrame,
	encodeSealedFrame,
	openFrame,
	receiverLaneKeys,
	sealFrame
} from '../../../src/lightning/direct-funding/frames';
import {
	attestationMessage,
	decodeDfOffer,
	decodeDfWitness,
	encodeDfOfferAck,
	encodeDfReceipt,
	encodeDfSignRequest,
	IDfOffer,
	IDfPrevout
} from '../../../src/lightning/direct-funding/messages';
import {
	encodeRequestEnvelope,
	mintRequestEnvelope
} from '../../../src/lightning/direct-funding/envelope';
import { mintRequestEncryptionKeys } from '../../../src/lightning/direct-funding/frames';
import {
	chainHashForNetwork,
	DfTransportType,
	DfTransportDescriptor
} from '../../../src/lightning/direct-funding/types';
import { DfTransportRegistry } from '../../../src/lightning/direct-funding/transport/registry';
import {
	DfFrameHandler,
	IDfInboundFrame,
	IDfLaneFactory,
	IDfTransport
} from '../../../src/lightning/direct-funding/transport/types';
import {
	IDfCoinSigner,
	IDfSenderCoin,
	IDfSenderWallet
} from '../../../src/lightning/direct-funding/sender/types';
import { Network } from '../../../src/lightning/invoice/types';
import { taprootTweakPrivateKey } from '../../../src/lightning/wallet/wallet-funding-provider';

export const PAYER_SEQUENCE = 0xfffffffd;

/** Let every pending microtask and zero-delay timer run. */
export async function flush(times = 6): Promise<void> {
	for (let i = 0; i < times; i++) {
		await new Promise((resolve) => setTimeout(resolve, 0));
	}
}

// ─────────────── The payer's coins ───────────────

export interface ITestCoin extends IDfSenderCoin {
	prevTx: bitcoin.Transaction;
	privkey: Buffer;
	pubkey: Buffer;
	kind: 'p2wpkh' | 'p2tr';
}

export function makeCoin(
	valueSat = 200_000,
	kind: 'p2wpkh' | 'p2tr' = 'p2wpkh',
	/** Derive the whole coin, so a second life rebuilds the same outpoint. */
	seed?: Buffer
): ITestCoin {
	const from = (label: string): Buffer =>
		crypto.createHash('sha256').update(seed!).update(label).digest();
	const privkey = seed ? from('key') : crypto.randomBytes(32);
	const pubkey = getPublicKey(privkey);
	const script =
		kind === 'p2wpkh'
			? bitcoin.payments.p2wpkh({ pubkey }).output!
			: bitcoin.payments.p2tr({ internalPubkey: pubkey.subarray(1, 33) })
					.output!;
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(seed ? from('prevout') : crypto.randomBytes(32), 0);
	prevTx.addOutput(script, valueSat);
	return {
		prevTx,
		txidHex: prevTx.getId(),
		vout: 0,
		valueSat: BigInt(valueSat),
		script,
		height: 100,
		privkey,
		pubkey,
		kind
	};
}

// ─────────────── The payer's wallet ───────────────

/** Somewhere a freeze can outlive the process, as the real wallet's does. */
export interface IFreezeStore {
	load(): string[];
	save(outpoints: string[]): void;
}

export class FakeSenderWallet implements IDfSenderWallet {
	coins: ITestCoin[] = [];
	readonly frozen = new Set<string>();
	readonly changeScript_: Buffer;
	/** Held before the freeze resolves, to open a window mid-honor. */
	freezeDelayMs = 0;
	/** Transactions this wallet knows, txid -> confirmed. */
	readonly known = new Map<string, boolean>();
	/** Outpoint key -> the confirmed txid that spent it. */
	readonly conflicts = new Map<string, string>();
	freezeFails = false;
	changeScriptThrows = false;
	/** The chain tip the locktime check is judged against; 0 means unsynced. */
	tipHeight = 800_000;
	/** Answer no signer for any coin, whatever the wallet still holds. */
	signerMissing = false;
	/** Prevouts a chain lookup will answer with, txid -> raw transaction. */
	readonly chain = new Map<string, Buffer>();
	chainFails = false;

	constructor(
		coins: ITestCoin[] = [],
		/** Persist freezes, so a second life sees the one a crash left behind. */
		private readonly freezes?: IFreezeStore
	) {
		this.coins = coins;
		this.changeScript_ = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20)
		}).output!;
		for (const coin of coins)
			this.chain.set(coin.txidHex, coin.prevTx.toBuffer());
		for (const outpoint of freezes?.load() ?? []) this.frozen.add(outpoint);
	}

	listSpendable(): IDfSenderCoin[] {
		return this.coins.filter((c) => !this.frozen.has(`${c.txidHex}:${c.vout}`));
	}

	findCoin(txidHex: string, vout: number): IDfSenderCoin | null {
		// Frozen coins included, as the real wallet's does: a freeze is the payer's
		// own reservation, not a coin that left.
		return (
			this.coins.find((c) => c.txidHex === txidHex && c.vout === vout) ?? null
		);
	}

	ownsOutpoint(txidHex: string, vout: number): boolean {
		return this.coins.some((c) => c.txidHex === txidHex && c.vout === vout);
	}

	async getTransaction(txidHex: string): Promise<Buffer> {
		if (this.chainFails) throw new Error('chain unavailable');
		const raw = this.chain.get(txidHex);
		if (!raw) throw new Error(`no such transaction ${txidHex}`);
		return raw;
	}

	async changeScript(): Promise<Buffer> {
		if (this.changeScriptThrows) throw new Error('no change address');
		return this.changeScript_;
	}

	signerFor(coin: IDfSenderCoin): IDfCoinSigner | null {
		// A watch-only restore: the coin is still findable, the key is not there.
		if (this.signerMissing) return null;
		const known = this.coins.find(
			(c) => c.txidHex === coin.txidHex && c.vout === coin.vout
		);
		if (!known) return null;
		if (known.kind === 'p2tr') {
			const tweaked = taprootTweakPrivateKey(known.privkey, known.pubkey);
			return {
				kind: 'p2tr',
				// The x-only OUTPUT key: what the receiver lifts from the scriptPubKey
				// and verifies the Schnorr proof under.
				ownershipPubkey: getPublicKey(tweaked).subarray(1, 33),
				signOwnership: (digest): Buffer => schnorrSign(digest, tweaked),
				signInput: (tx, index, prevouts): Buffer[] => [
					schnorrSign(
						tx.hashForWitnessV1(
							index,
							prevouts.scripts,
							prevouts.values.map((v) => Number(v)),
							bitcoin.Transaction.SIGHASH_DEFAULT
						),
						tweaked
					)
				]
			};
		}
		const scriptCode = bitcoin.payments.p2pkh({ pubkey: known.pubkey }).output!;
		return {
			kind: 'p2wpkh',
			ownershipPubkey: known.pubkey,
			signOwnership: (digest): Buffer =>
				Buffer.from(ecc.sign(digest, known.privkey)),
			signInput: (tx, index): Buffer[] => [
				bitcoin.script.signature.encode(
					Buffer.from(
						ecc.sign(
							tx.hashForWitnessV0(
								index,
								scriptCode,
								Number(known.valueSat),
								bitcoin.Transaction.SIGHASH_ALL
							),
							known.privkey
						)
					),
					bitcoin.Transaction.SIGHASH_ALL
				),
				known.pubkey
			]
		};
	}

	async freezeUtxo(txidHex: string, vout: number): Promise<boolean> {
		if (this.freezeFails) return false;
		// The write lands first, exactly like the real wallet: a crash in the
		// delay leaves the freeze behind with no record of why.
		this.frozen.add(`${txidHex}:${vout}`);
		this.freezes?.save([...this.frozen]);
		if (this.freezeDelayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, this.freezeDelayMs));
		}
		return true;
	}

	async unfreezeUtxo(txidHex: string, vout: number): Promise<boolean> {
		this.frozen.delete(`${txidHex}:${vout}`);
		this.freezes?.save([...this.frozen]);
		return true;
	}

	blockHeight(): number {
		return this.tipHeight;
	}

	txStatus(txidHex: string): { known: boolean; confirmed: boolean } | null {
		const confirmed = this.known.get(txidHex);
		if (confirmed === undefined) return null;
		return { known: true, confirmed };
	}

	confirmedSpendOf(txidHex: string, vout: number): string | null {
		return this.conflicts.get(`${txidHex}:${vout}`) ?? null;
	}
}

/** A wallet-data store two stores can share, i.e. survive a restart. */
export function memoryStorage(): {
	saveWalletData(key: string, value: string): void;
	loadWalletData(key: string): string | null;
	rows: Map<string, string>;
	failWrites: boolean;
	failWhen: null | ((value: string) => boolean);
} {
	const rows = new Map<string, string>();
	const store = {
		rows,
		failWrites: false,
		/** Fail only the writes whose value this matches, e.g. the commit. */
		failWhen: null as null | ((value: string) => boolean),
		saveWalletData: (key: string, value: string): void => {
			if (store.failWrites || store.failWhen?.(value)) {
				throw new Error('storage is unavailable');
			}
			rows.set(key, value);
		},
		loadWalletData: (key: string): string | null => rows.get(key) ?? null
	};
	return store;
}

// ─────────────── The receiver's request ───────────────

export interface ITestRequest {
	encoded: string;
	requestId: Buffer;
	receiptHash: Buffer;
	preimage: Buffer;
	nodeId: Buffer;
	nodePrivkey: Buffer;
	encryptionPrivateKey: Buffer;
	transports: DfTransportDescriptor[];
}

export function mintRequest(
	opts: {
		amountSat?: bigint;
		ttlMs?: number;
		transports?: DfTransportDescriptor[];
		network?: Network;
		nodePrivkey?: Buffer;
		/**
		 * Pin the identity a lane's sealing depends on. A second life against a
		 * persisted envelope has to rebuild the SAME receiver, or its lane cannot
		 * open a frame the payer sealed for the first one.
		 */
		requestId?: Buffer;
		preimage?: Buffer;
		encryptionPrivateKey?: Buffer;
	} = {}
): ITestRequest {
	const nodePrivkey = opts.nodePrivkey ?? crypto.randomBytes(32);
	const nodeId = getPublicKey(nodePrivkey);
	const preimage = opts.preimage ?? crypto.randomBytes(32);
	const receiptHash = crypto.createHash('sha256').update(preimage).digest();
	const requestId = opts.requestId ?? crypto.randomBytes(16);
	const encryption = opts.encryptionPrivateKey
		? {
				privateKey: opts.encryptionPrivateKey,
				publicKey: getPublicKey(opts.encryptionPrivateKey)
		  }
		: mintRequestEncryptionKeys();
	const transports = opts.transports ?? [
		{ type: DfTransportType.DIRECT_PEER, host: '127.0.0.1', port: 9735 }
	];
	const env = mintRequestEnvelope(
		{
			requestId,
			chainHash: chainHashForNetwork(opts.network ?? Network.REGTEST),
			receiverNodeId: nodeId,
			expiresAt: Date.now() + (opts.ttlMs ?? 3_600_000),
			...(opts.amountSat !== undefined ? { amountSat: opts.amountSat } : {}),
			receiptHash,
			encryptionKey: encryption.publicKey,
			transports
		},
		(message) => signMessageWithKey(message, nodePrivkey)
	);
	return {
		encoded: encodeRequestEnvelope(env),
		requestId,
		receiptHash,
		preimage,
		nodeId,
		nodePrivkey,
		encryptionPrivateKey: encryption.privateKey,
		transports
	};
}

// ─────────────── A lane and the receiver behind it ───────────────

/**
 * One lane, wired to a scripted receiver. Every frame the payer sends is opened
 * with the request's real keys, so the receiver sees exactly what a real one
 * would, and everything it answers is sealed the same way.
 */
export class ScriptedReceiverLane implements IDfTransport {
	readonly type = DfTransportType.DIRECT_PEER;
	readonly sent: Array<{ subtype: number; body: Buffer }> = [];
	readonly handlers = new Set<DfFrameHandler>();
	exchanged = 0;
	closed = false;
	/** Set to make the first send throw, i.e. a lane that never established. */
	sendThrows: Error | null = null;
	/** Narrow `sendThrows` to one subtype, i.e. a lane that dies mid-exchange. */
	sendThrowsFor: number | null = null;
	private keys: { sendKey: Buffer; recvKey: Buffer } | null = null;

	constructor(
		private readonly request: ITestRequest,
		/** Called with each opened message the payer sent. */
		readonly onMessageFromPayer: (
			lane: ScriptedReceiverLane,
			subtype: number,
			body: Buffer
		) => void
	) {}

	send(subtype: number, payload: Buffer): void {
		if (
			this.sendThrows &&
			(this.sendThrowsFor === null || this.sendThrowsFor === subtype)
		) {
			throw this.sendThrows;
		}
		this.exchanged++;
		this.deliverToReceiver(subtype, payload);
	}

	trySend(subtype: number, payload: Buffer): boolean {
		try {
			this.send(subtype, payload);
			return true;
		} catch {
			return false;
		}
	}

	onMessage(cb: DfFrameHandler): () => void {
		this.handlers.add(cb);
		return () => {
			this.handlers.delete(cb);
		};
	}

	framesExchanged(): number {
		return this.exchanged;
	}

	close(): void {
		this.closed = true;
		this.handlers.clear();
	}

	/** Seal and hand a message back to the payer, as the receiver would. */
	reply(subtype: number, body: Buffer): void {
		if (!this.keys) throw new Error('the payer has not opened the lane yet');
		const sealed = sealFrame(
			this.keys.sendKey,
			this.request.requestId,
			subtype,
			body
		);
		const frame: IDfInboundFrame = {
			type: DfTransportType.DIRECT_PEER,
			laneKey: 'receiver',
			subtype,
			payload: encodeSealedFrame(sealed),
			reply: this
		};
		this.exchanged++;
		for (const handler of [...this.handlers]) handler(frame);
	}

	/** Hand the payer raw bytes, i.e. something it must not be able to open. */
	replyRaw(subtype: number, payload: Buffer): void {
		const frame: IDfInboundFrame = {
			type: DfTransportType.DIRECT_PEER,
			laneKey: 'receiver',
			subtype,
			payload,
			reply: this
		};
		for (const handler of [...this.handlers]) handler(frame);
	}

	private deliverToReceiver(subtype: number, payload: Buffer): void {
		const wire = decodeSealedFrame(payload);
		if (!wire) return;
		if (wire.ephemeralPublicKey && wire.requestId) {
			this.keys = receiverLaneKeys(
				this.request.encryptionPrivateKey,
				wire.ephemeralPublicKey,
				wire.requestId
			);
		}
		if (!this.keys) return;
		const body = openFrame(
			this.keys.recvKey,
			this.request.requestId,
			subtype,
			wire
		);
		if (!body) return;
		this.sent.push({ subtype, body });
		this.onMessageFromPayer(this, subtype, body);
	}
}

/** A registry serving exactly one lane, so `registry.run` is exercised for real. */
export function registryWith(lane: IDfTransport): DfTransportRegistry {
	const registry = new DfTransportRegistry();
	const factory: IDfLaneFactory = {
		type: DfTransportType.DIRECT_PEER,
		open: async () => lane,
		attachInbound: () => (): void => undefined
	};
	registry.register({
		type: DfTransportType.DIRECT_PEER,
		enabled: true,
		load: () => factory
	});
	return registry;
}

/** A registry that hands each request its own lane, by request id. */
export function registryRouting(
	lanes: Map<string, IDfTransport>
): DfTransportRegistry {
	const registry = new DfTransportRegistry();
	registry.register({
		type: DfTransportType.DIRECT_PEER,
		enabled: true,
		load: () => ({
			type: DfTransportType.DIRECT_PEER,
			open: async (_descriptor, ctx) =>
				lanes.get(ctx.requestId.toString('hex')) ?? null,
			attachInbound: () => (): void => undefined
		})
	});
	return registry;
}

/** A registry with no usable lane at all. */
export function unreachableRegistry(): DfTransportRegistry {
	const registry = new DfTransportRegistry();
	registry.register({
		type: DfTransportType.DIRECT_PEER,
		enabled: true,
		load: () => ({
			type: DfTransportType.DIRECT_PEER,
			open: async () => null,
			attachInbound: () => (): void => undefined
		})
	});
	return registry;
}

// ─────────────── Building what the receiver sends back ───────────────

export interface ISignRequestOptions {
	/** Fee the transaction pays out of the payer's coin. */
	feeSat?: bigint;
	/** Override the funding output's value. */
	fundingValueSat?: bigint;
	/** Pay change to something other than the payer's change script. */
	changeScript?: Buffer;
	/** Drop the change output outright (the dust arm). */
	noChange?: boolean;
	version?: number;
	locktime?: number;
	sequence?: number;
	/** Extra inputs, each with its own prevout. */
	extraInputs?: Array<{ txid: Buffer; vout: number; prevout: IDfPrevout }>;
	extraOutputs?: number;
	/** Splice: the shared old-funding input, at index 1. */
	sharedInput?: { valueSat: bigint; script?: Buffer };
	/** Sign the attestation with this key instead of the receiver's node key. */
	attestWith?: Buffer;
	/** Corrupt the attestation signature. */
	forgeAttestation?: boolean;
	/** Point the attestation at a different output index. */
	fundingOutputIndex?: number;
	/** Lie about a prevout's value or script. */
	manglePrevout?: (prevouts: IDfPrevout[]) => void;
	/** Send fewer prevouts than inputs. */
	dropPrevouts?: boolean;
	/** Claim a different offer id. */
	offerId?: Buffer;
}

export interface IBuiltSignRequest {
	body: Buffer;
	tx: bitcoin.Transaction;
	fundingScript: Buffer;
	localFundingPubkey: Buffer;
	remoteFundingPubkey: Buffer;
}

/**
 * The transaction and sign request a receiver would produce for this offer:
 * the payer's input, the 2-of-2 funding output, the payer's change.
 */
export function buildSignRequest(
	request: ITestRequest,
	offer: IDfOffer,
	opts: ISignRequestOptions = {}
): IBuiltSignRequest {
	const localFundingPubkey = getPublicKey(
		crypto.createHash('sha256').update('df-local').digest()
	);
	const remoteFundingPubkey = getPublicKey(
		crypto.createHash('sha256').update('df-remote').digest()
	);
	const fundingScript = createFundingScript(
		localFundingPubkey,
		remoteFundingPubkey
	).p2wshOutput;

	const tx = new bitcoin.Transaction();
	tx.version = opts.version ?? 2;
	tx.locktime = opts.locktime ?? 0;
	const prevouts: IDfPrevout[] = [];
	tx.addInput(
		Buffer.from(offer.txid).reverse(),
		offer.vout,
		opts.sequence ?? offer.sequence
	);
	prevouts.push({ valueSat: offer.valueSat, script: payerScriptOf(offer) });

	const sharedBase = opts.sharedInput?.valueSat ?? 0n;
	if (opts.sharedInput) {
		tx.addInput(crypto.randomBytes(32), 0, PAYER_SEQUENCE);
		prevouts.push({
			valueSat: opts.sharedInput.valueSat,
			script: opts.sharedInput.script ?? fundingScript
		});
	}
	for (const extra of opts.extraInputs ?? []) {
		tx.addInput(Buffer.from(extra.txid).reverse(), extra.vout, PAYER_SEQUENCE);
		prevouts.push(extra.prevout);
	}

	const fee = opts.feeSat ?? 500n;
	tx.addOutput(
		fundingScript,
		Number(opts.fundingValueSat ?? sharedBase + offer.amountSat)
	);
	const change = offer.valueSat - offer.amountSat - fee;
	if (!opts.noChange && change > 0n) {
		tx.addOutput(opts.changeScript ?? offer.changeScript, Number(change));
	}
	for (let i = 0; i < (opts.extraOutputs ?? 0); i++) {
		tx.addOutput(Buffer.alloc(34, 0x80 + i), 1_000);
	}

	opts.manglePrevout?.(prevouts);
	const rawTx = tx.toBuffer();
	const fundingOutputIndex = opts.fundingOutputIndex ?? 0;
	const signer = opts.attestWith ?? request.nodePrivkey;
	let signature = zbase32Decode(
		signMessageWithKey(
			attestationMessage(
				opts.offerId ?? offer.offerId,
				rawTx,
				fundingOutputIndex,
				localFundingPubkey
			),
			signer
		)
	)!;
	if (opts.forgeAttestation) {
		signature = Buffer.from(signature);
		signature[10] ^= 0xff;
	}
	return {
		body: encodeDfSignRequest({
			offerId: opts.offerId ?? offer.offerId,
			rawTx,
			prevouts: opts.dropPrevouts ? prevouts.slice(0, -1) : prevouts,
			attestation: {
				fundingOutputIndex,
				localFundingPubkey,
				remoteFundingPubkey,
				signature
			},
			...(opts.sharedInput ? { sharedInputIndex: 1 } : {})
		}),
		tx,
		fundingScript,
		localFundingPubkey,
		remoteFundingPubkey
	};
}

/**
 * The payer's own scriptPubKey, rebuilt from the offer's ownership proof so the
 * prevout the receiver claims matches what the wallet holds.
 */
function payerScriptOf(offer: IDfOffer): Buffer {
	if (offer.ownership.pubkey.length === 32) {
		return Buffer.concat([Buffer.from([0x51, 0x20]), offer.ownership.pubkey]);
	}
	return bitcoin.payments.p2wpkh({ pubkey: offer.ownership.pubkey }).output!;
}

/**
 * A receiver that accepts every offer, answers with a sign request built from
 * `opts`, and (unless told otherwise) sends the receipt once the witness lands.
 */
export function acceptingReceiver(
	request: ITestRequest,
	opts: ISignRequestOptions & {
		/** Withhold the receipt: the payer must still resolve. */
		noReceipt?: boolean;
		/** Send a receipt whose preimage does not open the request's hash. */
		forgeReceipt?: boolean;
		/** Include the fully signed transaction in the receipt. */
		includeRawTx?: boolean;
		/** Decline the offer instead of serving it. */
		decline?: string;
		/** Called with the payer's witness stack. */
		onWitness?: (witness: Buffer[]) => void;
		/** Send the sign request twice, i.e. an idempotent replay. */
		duplicateSignRequest?: boolean;
	} = {}
): (lane: ScriptedReceiverLane, subtype: number, body: Buffer) => void {
	let built: IBuiltSignRequest | null = null;
	let offer: IDfOffer | null = null;
	return (lane, subtype, body): void => {
		if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER) {
			offer = decodeDfOffer(body);
			if (opts.decline !== undefined) {
				lane.reply(
					BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK,
					encodeDfOfferAck({
						offerId: offer.offerId,
						accepted: false,
						reason: opts.decline
					})
				);
				return;
			}
			lane.reply(
				BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK,
				encodeDfOfferAck({ offerId: offer.offerId, accepted: true })
			);
			built = buildSignRequest(request, offer, opts);
			lane.reply(BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST, built.body);
			if (opts.duplicateSignRequest) {
				lane.reply(
					BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST,
					built.body
				);
			}
			return;
		}
		if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_WITNESS) {
			const witness = decodeDfWitness(body);
			opts.onWitness?.(witness.witness);
			if (opts.noReceipt || !built || !offer) return;
			const preimage = opts.forgeReceipt
				? crypto.randomBytes(32)
				: request.preimage;
			lane.reply(
				BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
				encodeDfReceipt({
					offerId: offer.offerId,
					preimage,
					fundingTxid: Buffer.from(built.tx.getHash()).reverse(),
					...(opts.includeRawTx ? { rawTx: built.tx.toBuffer() } : {})
				})
			);
		}
	};
}
