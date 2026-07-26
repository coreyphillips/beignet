import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as crypto from 'crypto';
import { ECPairFactory } from 'ecpair';
import { BeignetNode } from './beignet-node';
import { BeignetCustomSubtype } from '../lightning/message/custom';
import { ISpliceWalletInput } from '../lightning/channel/channel';
import { buildSpliceTx } from '../lightning/channel/splice-tx';
import {
	scriptKind,
	taprootTweakPrivateKey
} from '../lightning/wallet/wallet-funding-provider';
import { createFundingScript } from '../lightning/script/funding';
import { verifyMessageSignature } from '../lightning/crypto/message-signing';
import { ILeaseRates } from '../lightning/gossip/types';
// Envelope helpers loaded lazily: df-envelope imports our DfTransport TYPE
// only, so the runtime dependency is one-directional.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const envelope = require('./df-envelope') as typeof import('./df-envelope');

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

/**
 * Beignet-native 1-tx direct funding: a beignet-aware sender's onchain
 * payment IS the recipient's channel-funding transaction — the intermediate
 * deposit tx disappears.
 *
 *   Sender                Recipient                    LSP
 *     │ FUNDING_OFFER        │                          │
 *     ├─────────────────────>│ validate, ack            │
 *     │<─── OFFER_ACK ───────┤                          │
 *     │                      │ openChannelV2 with the   │
 *     │                      │ SENDER's input (external)│
 *     │                      ├─ interactive tx ────────>│  (LSP unchanged,
 *     │                      │<─────────────────────────┤   sells will_fund)
 *     │<── SIGN_REQUEST ─────┤ negotiated raw tx        │
 *     │  verify + sign       │                          │
 *     ├──── WITNESS ────────>│ merge → tx_signatures    │
 *     │<──── RECEIPT ────────┤ broadcast — ONE chain tx │
 *
 * Trust stance: the sender verifies, in the EXACT transaction it signs, that
 * (a) its own input and change are honest, and (b) the funding output is the
 * 2-of-2 attested by the recipient's NODE key — which must be the node the
 * payment request named. Delivery is then chain-atomic: the transaction
 * either confirms with the sats inside the recipient's channel, or nothing
 * moves. The receipt preimage (revealed after broadcast, against the hash
 * the request carried) is a provable delivery receipt on top.
 *
 * All payloads are JSON over the single odd custom message type (or a swarm
 * socket carrying the same frames), so non-beignet peers ignore the whole
 * protocol and legacy senders just pay the plain address.
 */

/**
 * A duplex lane for direct-funding frames. Lightning custom messages when
 * the peers share a connection; a hyperswarm socket when the sender only
 * knows the recipient's pubkey from the payment request.
 */
export interface DfTransport {
	send(subtype: number, payload: object): void;
	/** Subscribe to inbound frames; returns the unsubscribe. */
	onMessage(cb: (subtype: number, payload: Buffer) => void): () => void;
}

/** Direct-funding frames over an existing Lightning peer connection. */
export function lnTransport(node: BeignetNode, peerPubkey: string): DfTransport {
	return {
		send: (subtype, payload) =>
			node.lightningNode.sendCustomMessage(
				peerPubkey,
				subtype,
				Buffer.from(JSON.stringify(payload), 'utf8')
			),
		onMessage: (cb) => {
			const onMsg = (msg: {
				peerPubkey: string;
				subtype: number;
				payload: Buffer;
			}): void => {
				if (msg.peerPubkey !== peerPubkey) return;
				cb(msg.subtype, msg.payload);
			};
			node.lightningNode.on('custom-message', onMsg);
			return () => node.lightningNode.removeListener('custom-message', onMsg);
		}
	};
}

/**
 * Direct-funding frames relayed BLIND through a shared Lightning peer (the
 * receiver's LSP). Outbound frames ride RELAY envelopes `{to, t, p}` to the
 * relay; inbound frames arrive from the relay as `{from, t, p}` where `from`
 * was stamped by the relay itself from its authenticated connection, so
 * neither endpoint can claim to be someone it is not. Payloads stay sealed
 * to the per-request key: the relay moves bytes it cannot read.
 */
export function relayTransport(
	node: BeignetNode,
	viaPubkey: string,
	counterpartyPubkey: string
): DfTransport {
	return {
		send: (subtype, payload) =>
			node.lightningNode.sendCustomMessage(
				viaPubkey,
				BeignetCustomSubtype.DIRECT_FUNDING_RELAY,
				Buffer.from(
					JSON.stringify({ to: counterpartyPubkey, t: subtype, p: payload }),
					'utf8'
				)
			),
		onMessage: (cb) => {
			const onMsg = (msg: {
				peerPubkey: string;
				subtype: number;
				payload: Buffer;
			}): void => {
				if (msg.peerPubkey !== viaPubkey) return;
				if (msg.subtype !== BeignetCustomSubtype.DIRECT_FUNDING_RELAY) return;
				try {
					const frame = JSON.parse(msg.payload.toString('utf8'));
					if (frame?.from !== counterpartyPubkey) return;
					if (typeof frame.t !== 'number') return;
					cb(frame.t, Buffer.from(JSON.stringify(frame.p), 'utf8'));
				} catch {
					/* malformed relay frame: drop */
				}
			};
			node.lightningNode.on('custom-message', onMsg);
			return () => node.lightningNode.removeListener('custom-message', onMsg);
		}
	};
}

/**
 * Make this node a blind direct-funding relay. Any connected peer may hand
 * it a RELAY envelope `{to, t, p}`; if `to` is also a connected peer the
 * frame is forwarded as `{from, t, p}` with `from` stamped from the
 * authenticated sending connection. The relay never parses `p`: it is
 * sealed to a request key only the endpoints hold. Frames whose target is
 * not connected are dropped silently, which is all a store-nothing relay
 * can honestly do. The forwarder logs NOTHING per frame: the relay's
 * unavoidable metadata view (who talked to whom, when) is not additionally
 * written to disk.
 */
export function attachRelayForwarder(node: BeignetNode): void {
	node.lightningNode.on(
		'custom-message',
		(msg: { peerPubkey: string; subtype: number; payload: Buffer }) => {
			if (msg.subtype !== BeignetCustomSubtype.DIRECT_FUNDING_RELAY) return;
			try {
				const frame = JSON.parse(msg.payload.toString('utf8'));
				// Only originator frames carry `to`; forwarded frames carry `from`
				// instead, so a forwarded frame can never be forwarded again.
				if (typeof frame?.to !== 'string' || frame.from !== undefined) return;
				const target = node.lightningNode
					.listPeers()
					.find((p) => p.pubkey === frame.to);
				if (!target) return;
				node.lightningNode.sendCustomMessage(
					frame.to,
					BeignetCustomSubtype.DIRECT_FUNDING_RELAY,
					Buffer.from(
						JSON.stringify({ from: msg.peerPubkey, t: frame.t, p: frame.p }),
						'utf8'
					)
				);
			} catch {
				/* malformed relay frame: drop */
			}
		}
	);
}

/** Message payloads (JSON over custom subtypes 16-21). */
interface OfferMsg {
	offerId: string;
	amountSat: number;
	/** Display-order txid of the transaction holding the offered output. The
	 *  receiver fetches the full transaction from its OWN chain source, which
	 *  both keeps offers small (onion-message friendly) and verifies the
	 *  offer against chain truth instead of sender-supplied bytes. */
	txidHex: string;
	vout: number;
	valueSat: number;
	sequence: number;
	/** Sender's change script (hex) — change from its input returns here. */
	changeScriptHex: string;
	/** The sender's fee ceiling: its cost above amountSat must not exceed
	 *  this. Enforced by the sender at sign time; declared here so the
	 *  receiver can build a transaction that will pass. */
	maxTotalFeeSat?: number;
	/** Input-ownership proof: the UTXO's key signs the offer context. */
	ownership: {
		pubkeyHex: string;
		sigHex: string;
	};
	/** Hash from the payment request; the receiver must hold its preimage
	 *  and reveals it after broadcast as the delivery receipt. */
	receiptHashHex?: string;
}

interface AckMsg {
	offerId: string;
	accepted: boolean;
	reason?: string;
}

interface SignRequestMsg {
	offerId: string;
	rawTxHex: string;
	/** Prevout script+value per input (tx order) — required for P2TR (BIP 341). */
	prevouts: Array<{ scriptHex: string; valueSat: number }>;
	/**
	 * Present when the negotiated tx is a SPLICE of an existing channel: the
	 * input index spending the old funding outpoint. The sender then checks
	 * that input against the attested 2-of-2 and requires the new funding
	 * output to carry the old value plus the amount.
	 */
	sharedInputIndex?: number;
	/**
	 * Recipient attestation: binds the recipient's NODE identity to the
	 * funding output the sender is asked to pay into.
	 */
	attestation: {
		fundingOutputIndex: number;
		localFundingPubkeyHex: string;
		remoteFundingPubkeyHex: string;
		sigHex: string;
	};
}

interface WitnessMsg {
	offerId: string;
	witnessHex: string[];
}

interface ReceiptMsg {
	offerId: string;
	preimageHex: string;
	fundingTxidHex: string;
	/** The complete broadcast transaction when the receiver could fetch it,
	 *  so the sender can rebroadcast independently. */
	rawTxHex?: string;
}

/** The exact string a recipient's node key signs for an attestation. */
function attestationMessage(
	offerId: string,
	rawTxHex: string,
	fundingOutputIndex: number,
	localFundingPubkeyHex: string
): string {
	const txHash = bitcoin.crypto.sha256(Buffer.from(rawTxHex, 'hex'));
	return `lfbw-direct-funding-attest:${offerId}:${txHash.toString('hex')}:${fundingOutputIndex}:${localFundingPubkeyHex}`;
}

/** The exact string a sender's UTXO key signs for an ownership proof. */
function ownershipMessage(
	offerId: string,
	txid: string,
	vout: number,
	amountSat: number
): Buffer {
	return bitcoin.crypto.sha256(
		Buffer.from(
			`lfbw-direct-funding-offer:${offerId}:${txid}:${vout}:${amountSat}`,
			'utf8'
		)
	);
}

const OFFER_TIMEOUT_MS = 60_000;
const RECEIPT_TIMEOUT_MS = 20_000;
const OFFER_RESEND_DELAYS_MS = [7_000, 14_000];
// Terminal offer records (tombstones) live as long as a request can: a
// duplicate offer inside the request's lifetime replays the recorded
// responses instead of re-executing effects.
const OFFER_SESSION_TTL_MS = 60 * 60 * 1000;
const OUTPOINT_RESERVATION_TTL_MS = 10 * 60 * 1000;
const MAX_INFLIGHT_OFFER_SESSIONS = 4;
/** Absolute floor for direct-funding offers, comfortably above dust,
 *  channel reserve mechanics, and commitment fee overhead. Operator
 *  minimums below this (including 0) clamp up to it; the DEFAULT is the
 *  floor itself, the most permissive safe setting. */
export const HARD_MIN_OFFER_AMOUNT_SAT = 5_000;
const MAX_REQUEST_ATTEMPTS = 3;

/**
 * Receiver-side offer idempotence. Offers are AT-LEAST-ONCE: a sender whose
 * ack or sign request was lost re-sends the same offer, and a duplicate must
 * replay the recorded responses instead of opening a second channel session.
 * Keyed by offer id; the payload hash pins the id to one exact offer.
 */
interface IOfferSession {
	payloadHash: string;
	outbound: Array<[number, object]>;
	inflight: boolean;
	expiresAt: number;
}
const offerSessions = new Map<string, IOfferSession>();

/**
 * One outpoint funds one session at a time: an attacker holding a single
 * UTXO cannot fan it into many concurrent channel-open sessions, which is
 * what prices session DoS at one real coin per concurrent session.
 */
const outpointReservations = new Map<
	string,
	{ offerId: string; expiresAt: number }
>();

/**
 * Per-request throttles: one active funding attempt at a time and a
 * bounded number of attempts over the request's life. A UTXO owner can
 * prove ownership endlessly at no cost; what it cannot do is grief the
 * receiver through unbounded sequential sessions against one request.
 */
const requestAttempts = new Map<
	string,
	{ attempts: number; activeOfferId?: string; expiresAt: number }
>();

function pruneOfferState(): void {
	const now = Date.now();
	for (const [k, v] of offerSessions) {
		if (v.expiresAt <= now) offerSessions.delete(k);
	}
	for (const [k, v] of outpointReservations) {
		if (v.expiresAt <= now) outpointReservations.delete(k);
	}
	for (const [k, v] of requestAttempts) {
		if (v.expiresAt <= now) requestAttempts.delete(k);
	}
}

/** Buyer-side price ceiling used when the receiver buys inbound alongside. */
export const DEFAULT_MAX_LEASE_RATES: ILeaseRates = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100,
	leaseFeeBaseSat: 10000,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 3
};

// ─────────────── Sender side ───────────────

export interface IDirectFundingSendResult {
	offerId: string;
	spentTxid: string;
	fundingTxid?: string;
	/** True once the recipient's node-key attestation over the funding output
	 *  verified against the pubkey the payment request named. */
	attested: boolean;
	/** The delivery receipt: preimage of the request's receipt hash, revealed
	 *  by the receiver after broadcast. Null when no hash was in play or the
	 *  receipt did not arrive in time (delivery is still chain-atomic). */
	receiptPreimageHex: string | null;
	/** The negotiated funding transaction we signed (unsigned form). */
	rawTxHex?: string;
	/** The fully signed funding transaction, when the receipt carried it:
	 *  lets the sender rebroadcast independently. */
	broadcastTxHex?: string;
}

/**
 * Fund the recipient's channel directly from one of our UTXOs. Resolves once
 * our witness is delivered and the receipt (when requested) arrives. Throws
 * when we lack a single UTXO covering the amount, the recipient declines or
 * times out, or the sign request fails verification — in every throw path
 * nothing was signed or spent.
 */
export async function sendDirectFunding(
	node: BeignetNode,
	network: bitcoin.Network,
	transport: DfTransport,
	opts: {
		/** Node the payment request named; the attestation MUST verify to it. */
		recipientPubkey: string;
		amountSat: number;
		feeHeadroomSat: number;
		receiptHashHex?: string;
	}
): Promise<IDirectFundingSendResult> {
	const { recipientPubkey, amountSat, feeHeadroomSat } = opts;
	const wallet = node.onchainWallet;
	let fundingTxid: string | undefined;
	let attested = false;
	let rawTxHex: string | undefined;
	let broadcastTxHex: string | undefined;

	// One UTXO covering amount + our fee share (no multi-input offers).
	const utxo = (wallet.listUtxos() ?? [])
		.filter((u) => {
			try {
				return (
					scriptKind(bitcoin.address.toOutputScript(u.address, network)) !==
					null
				);
			} catch {
				return false;
			}
		})
		.sort((a, b) => b.value - a.value)
		.find((u) => u.value >= amountSat + feeHeadroomSat);
	if (!utxo) {
		throw new Error(
			`direct funding needs a single UTXO of at least ${amountSat + feeHeadroomSat} sats`
		);
	}

	const txsRes = await wallet.electrum.getTransactions({
		txHashes: [{ tx_hash: utxo.tx_hash }]
	});
	if (txsRes.isErr()) throw new Error('failed to fetch prev tx');
	const prevTxHex = (txsRes.value.data?.[0]?.result?.hex ?? '') as string;
	if (!prevTxHex) throw new Error('prev tx unavailable');

	const changeRes = await wallet.getChangeAddress();
	if (changeRes.isErr()) throw new Error('no change address');
	const changeScript = bitcoin.address.toOutputScript(
		changeRes.value.address,
		network
	);

	// Deterministic over the offer's full content: the same logical payment
	// retries under the same id (idempotent at the receiver), while any
	// change of amount or coin is a different offer. A string prefix would
	// truncate before the amount; hash the whole context.
	const offerId = crypto
		.createHash('sha256')
		.update(`${utxo.tx_hash}:${utxo.tx_pos}:${amountSat}`)
		.digest('hex')
		.slice(0, 32);

	// Signing materials for later.
	const keyPair = ECPair.fromWIF(wallet.getPrivateKey(utxo.path), network);
	const pubkey = Buffer.from(keyPair.publicKey);
	const privKey = Buffer.from(keyPair.privateKey!);
	const ourScript = bitcoin.address.toOutputScript(utxo.address, network);
	const kind = scriptKind(ourScript)!;
	const scriptCode = bitcoin.payments.p2pkh({ pubkey, network }).output!;
	const prevTxid = bitcoin.Transaction.fromHex(prevTxHex).getHash();

	// Input-ownership proof: sign the offer context with the key that
	// controls the offered UTXO, so the recipient never starts a channel
	// open for a coin the sender cannot actually spend.
	const ownMsg = ownershipMessage(offerId, utxo.tx_hash, utxo.tx_pos, amountSat);
	const ownership =
		kind === 'p2tr'
			? {
					pubkeyHex: pubkey.toString('hex'),
					sigHex: Buffer.from(
						ecc.signSchnorr(ownMsg, taprootTweakPrivateKey(privKey, pubkey))
					).toString('hex')
			  }
			: {
					pubkeyHex: pubkey.toString('hex'),
					sigHex: Buffer.from(ecc.sign(ownMsg, privKey)).toString('hex')
			  };
	const sendOffer = (): void =>
		transport.send(BeignetCustomSubtype.DIRECT_FUNDING_OFFER, {
			offerId,
			amountSat,
			txidHex: utxo.tx_hash,
			vout: utxo.tx_pos,
			valueSat: utxo.value,
			sequence: 0xfffffffd,
			changeScriptHex: changeScript.toString('hex'),
			maxTotalFeeSat: feeHeadroomSat,
			ownership,
			...(opts.receiptHashHex ? { receiptHashHex: opts.receiptHashHex } : {})
		} as OfferMsg);

	// Sender-side safety invariant: once the witness has left this device,
	// this promise NEVER rejects. Every later problem (lost receipt, junk
	// frame, timeout) resolves with what is known, because the funding may
	// already be broadcast and an error here could prompt the caller into a
	// SECOND payment for the same request.
	const done = new Promise<string | null>((resolve, reject) => {
		let witnessSent = false;
		let signRequestSeen = false;
		const resendTimers: NodeJS.Timeout[] = [];
		const failUnlessCommitted = (err: Error): void => {
			cleanup();
			if (witnessSent) resolve(null);
			else reject(err);
		};
		const timer = setTimeout(() => {
			failUnlessCommitted(new Error('direct funding timed out'));
		}, OFFER_TIMEOUT_MS);
		let receiptTimer: NodeJS.Timeout | undefined;
		const unsubscribe = transport.onMessage((subtype, payload) => {
			void (async () => {
			try {
				if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK) {
					const ack = JSON.parse(payload.toString('utf8')) as AckMsg;
					if (ack.offerId !== offerId) return;
					if (!ack.accepted) {
						cleanup();
						reject(new Error(`recipient declined: ${ack.reason ?? ''}`));
					}
					// Accepted: stop re-sending the offer, wait for the sign
					// request.
					while (resendTimers.length) clearTimeout(resendTimers.pop()!);
					return;
				}
				if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT) {
					const r = JSON.parse(payload.toString('utf8')) as ReceiptMsg;
					if (r.offerId !== offerId || !opts.receiptHashHex) return;
					const hash = bitcoin.crypto
						.sha256(Buffer.from(r.preimageHex, 'hex'))
						.toString('hex');
					if (hash !== opts.receiptHashHex) return; // forged receipt: ignore
					if (r.rawTxHex) broadcastTxHex = r.rawTxHex;
					cleanup();
					resolve(r.preimageHex);
					return;
				}
				if (subtype !== BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST) {
					return;
				}
				const req = JSON.parse(payload.toString('utf8')) as SignRequestMsg;
				if (req.offerId !== offerId) return;
				if (signRequestSeen) return; // duplicate: witness already handled
				signRequestSeen = true;
				const tx = bitcoin.Transaction.fromHex(req.rawTxHex);

				// Verify OUR input is spent by this exact tx, exactly once, with
				// exactly the sequence the offer committed to, in a transaction
				// whose shape is bounded and sane. Every check runs against the
				// exact bytes we would sign; nothing is taken on trust.
				const ourMatches = tx.ins.filter(
					(i) =>
						Buffer.from(i.hash).equals(prevTxid) && i.index === utxo.tx_pos
				);
				const ourIndex = tx.ins.findIndex(
					(i) =>
						Buffer.from(i.hash).equals(prevTxid) && i.index === utxo.tx_pos
				);
				if (ourMatches.length !== 1) {
					failUnlessCommitted(
						new Error('negotiated tx does not spend our input exactly once')
					);
					return;
				}
				if (tx.ins[ourIndex].sequence !== 0xfffffffd) {
					failUnlessCommitted(
						new Error('negotiated tx changes our input sequence')
					);
					return;
				}
				if (tx.version !== 2) {
					failUnlessCommitted(
						new Error('unexpected funding transaction version')
					);
					return;
				}
				if (tx.locktime >= 500_000_000) {
					failUnlessCommitted(
						new Error('time-based locktime refused in direct funding')
					);
					return;
				}
				if (tx.ins.length > 16 || tx.outs.length > 8) {
					failUnlessCommitted(
						new Error('funding transaction exceeds direct funding bounds')
					);
					return;
				}
				// …our change comes back: everything above amount + a bounded
				// fee must return to our change script…
				const changeValue = tx.outs
					.filter((o) => o.script.equals(changeScript))
					.reduce((s, o) => s + Number(o.value), 0);
				const minChange = utxo.value - amountSat - feeHeadroomSat;
				if (minChange > 294 && changeValue < minChange) {
					failUnlessCommitted(
						new Error(
							`negotiated tx shorts our change: got ${changeValue}, expected >= ${minChange}`
						)
					);
					return;
				}
				// …and the funding output is the recipient's channel: the exact
				// 2-of-2 built from the attested funding pubkeys, holding at
				// least the amount we are paying, signed by the NODE the payment
				// request named. Without this, "delivery" would be a claim; with
				// it, the transaction we sign is delivery by construction.
				const att = req.attestation;
				if (!att) {
					failUnlessCommitted(
						new Error('sign request carries no recipient attestation')
					);
					return;
				}
				const fundingOut = tx.outs[att.fundingOutputIndex];
				const expected = createFundingScript(
					Buffer.from(att.localFundingPubkeyHex, 'hex'),
					Buffer.from(att.remoteFundingPubkeyHex, 'hex'),
					network
				);
				if (
					!fundingOut ||
					!Buffer.from(fundingOut.script).equals(expected.p2wshOutput)
				) {
					failUnlessCommitted(
						new Error('funding output does not match the attested 2-of-2')
					);
					return;
				}
				if (typeof req.sharedInputIndex === 'number') {
					// Splice of an existing channel: the shared input must itself
					// be the attested 2-of-2 (the OLD channel funding), and the
					// new funding output must carry its value plus our amount, so
					// the receiver's prior balance and our payment both land in
					// the channel we verified.
					const shared = (req.prevouts ?? [])[req.sharedInputIndex];
					if (
						!shared ||
						!Buffer.from(shared.scriptHex, 'hex').equals(
							expected.p2wshOutput
						)
					) {
						failUnlessCommitted(
							new Error(
								'shared input is not the attested channel funding'
							)
						);
						return;
					}
					if (
						Number(fundingOut.value) <
						shared.valueSat + amountSat - feeHeadroomSat
					) {
						failUnlessCommitted(
							new Error('new funding output shorts the spliced amount')
						);
						return;
					}
				} else if (Number(fundingOut.value) < amountSat) {
					failUnlessCommitted(
						new Error('funding output holds less than the amount paid')
					);
					return;
				}
				const verdict = verifyMessageSignature(
					attestationMessage(
						offerId,
						req.rawTxHex,
						att.fundingOutputIndex,
						att.localFundingPubkeyHex
					),
					att.sigHex
				);
				if (!verdict.valid || !verdict.pubkey) {
					failUnlessCommitted(
						new Error('recipient attestation signature is invalid')
					);
					return;
				}
				if (verdict.pubkey.toString('hex') !== recipientPubkey) {
					failUnlessCommitted(
						new Error(
							'attestation signed by a different node than the payment request named'
						)
					);
					return;
				}
				attested = true;
				fundingTxid = tx.getId();

				let witnessHex: string[];
				if (kind === 'p2tr') {
					// BIP 341 SIGHASH_DEFAULT commits to the amounts and scripts
					// of EVERY input, so every supplied prevout is signing input,
					// not metadata. Verify each one against our own chain source;
					// a receiver feeding false prevouts would otherwise make us
					// compute a signature that can never validate.
					const prevouts = req.prevouts ?? [];
					if (
						prevouts.length !== tx.ins.length ||
						prevouts[ourIndex]?.scriptHex !== ourScript.toString('hex') ||
						prevouts[ourIndex]?.valueSat !== utxo.value
					) {
						failUnlessCommitted(
							new Error('sign request prevouts do not match our input')
						);
						return;
					}
					const foreignHashes = tx.ins
						.map((inp, i) => ({ i, inp }))
						.filter(({ i }) => i !== ourIndex)
						.map(({ inp }) => ({
							tx_hash: Buffer.from(inp.hash).reverse().toString('hex')
						}));
					if (foreignHashes.length > 0) {
						const chainRes = await wallet.electrum
							.getTransactions({ txHashes: foreignHashes })
							.catch(() => null);
						if (!chainRes || chainRes.isErr()) {
							failUnlessCommitted(
								new Error('could not verify prevouts against the chain')
							);
							return;
						}
						const byId = new Map<string, bitcoin.Transaction>();
						for (const item of chainRes.value.data ?? []) {
							const hex = (item?.result?.hex ?? '') as string;
							if (hex) {
								const t = bitcoin.Transaction.fromHex(hex);
								byId.set(t.getId(), t);
							}
						}
						for (let i = 0; i < tx.ins.length; i++) {
							if (i === ourIndex) continue;
							const txid = Buffer.from(tx.ins[i].hash)
								.reverse()
								.toString('hex');
							const chainTx = byId.get(txid);
							const chainOut = chainTx?.outs[tx.ins[i].index];
							if (
								!chainOut ||
								Buffer.from(chainOut.script).toString('hex') !==
									prevouts[i]?.scriptHex ||
								Number(chainOut.value) !== prevouts[i]?.valueSat
							) {
								failUnlessCommitted(
									new Error(
										'sign request prevouts do not match chain truth'
									)
								);
								return;
							}
						}
					}
					const sighash = tx.hashForWitnessV1(
						ourIndex,
						prevouts.map((o) => Buffer.from(o.scriptHex, 'hex')),
						prevouts.map((o) => o.valueSat),
						bitcoin.Transaction.SIGHASH_DEFAULT
					);
					const tweaked = taprootTweakPrivateKey(privKey, pubkey);
					witnessHex = [
						Buffer.from(ecc.signSchnorr(sighash, tweaked)).toString('hex')
					];
				} else {
					const sighash = tx.hashForWitnessV0(
						ourIndex,
						scriptCode,
						utxo.value,
						bitcoin.Transaction.SIGHASH_ALL
					);
					const der = bitcoin.script.signature.encode(
						Buffer.from(ecc.sign(sighash, privKey)),
						bitcoin.Transaction.SIGHASH_ALL
					);
					witnessHex = [der.toString('hex'), pubkey.toString('hex')];
				}
				transport.send(BeignetCustomSubtype.DIRECT_FUNDING_WITNESS, {
					offerId,
					witnessHex
				} as WitnessMsg);
				witnessSent = true;
				rawTxHex = req.rawTxHex;
				// The witness is out: the funding may broadcast at any moment.
				// Freeze the offered UTXO so this wallet's own coin selection
				// cannot accidentally double-spend it while the funding is
				// unconfirmed. If the funding confirms the coin is gone anyway;
				// if the payment is abandoned, unfreezing is a deliberate act.
				void node
					.freezeUtxo(utxo.tx_hash, utxo.tx_pos)
					.catch(() => {
						/* freezing is protective, not critical */
					});
				if (!opts.receiptHashHex) {
					cleanup();
					resolve(null);
					return;
				}
				// Witness delivered; give the receipt its own (shorter) window.
				clearTimeout(timer);
				receiptTimer = setTimeout(() => {
					cleanup();
					resolve(null); // delivery already chain-atomic; receipt is bonus
				}, RECEIPT_TIMEOUT_MS);
			} catch (e) {
				failUnlessCommitted(e as Error);
			}
			})();
		});
		const cleanup = (): void => {
			clearTimeout(timer);
			if (receiptTimer) clearTimeout(receiptTimer);
			while (resendTimers.length) clearTimeout(resendTimers.pop()!);
			unsubscribe();
		};
		// Offers are idempotent at the receiver, so re-sending one lost in
		// transit is safe: a duplicate replays the recorded responses and
		// opens nothing twice. This is what makes the fire-and-forget onion
		// lane reliable in practice: at-least-once delivery of the offer,
		// exactly-once effects behind it.
		for (const delay of OFFER_RESEND_DELAYS_MS) {
			const t = setTimeout(() => {
				if (!signRequestSeen && !witnessSent) sendOffer();
			}, delay);
			t.unref?.();
			resendTimers.push(t);
		}
	});

	sendOffer();

	const receiptPreimageHex = await done;
	return {
		offerId,
		spentTxid: utxo.tx_hash,
		fundingTxid,
		attested,
		receiptPreimageHex,
		// The negotiated transaction (and, when the receipt carried it, the
		// fully signed broadcast form): everything a caller needs to persist
		// for post-witness monitoring and independent rebroadcast.
		rawTxHex,
		broadcastTxHex
	};
}

// ─────────────── Recipient side ───────────────

export interface IDirectFundingReceiverDeps {
	getLspPubkey: () => string | undefined;
	/** Hex secp256k1 private key of a request, for sealed offers. */
	getRequestEncryptionKey?: (requestId: string) => string | undefined;
	/** Map a blinded-path path_id (the request's PRIVATE path secret, never
	 *  present in the envelope) to its request id. BOLT 4: path_id content
	 *  must be unknowable to the payer, or anyone holding the request could
	 *  mint their own blinded route that passes the issued-path check. */
	resolveOnionPathSecret?: (pathSecretHex: string) => string | undefined;
	/** Inbound to BUY from the LSP alongside (0 = plain v2, nothing bought). */
	getTargetInboundSat: () => number;
	/** Receiver's minimum offer amount (sats); clamped to the hard floor. */
	getMinAmountSat?: () => number;
	/** Negotiate option_zeroconf into the open (LSP must trust this node). */
	getTrusted: () => boolean;
	/** Preimage (hex) for a receipt hash this node handed out, if any. */
	getReceiptPreimage: (hashHex: string) => string | undefined;
	onReceiptUsed?: (hashHex: string) => void;
	network: bitcoin.Network;
	maxLeaseRates?: ILeaseRates;
	onEvent?: (kind: string, detail: string) => void;
}

/**
 * Handle inbound FUNDING_OFFERs arriving over the Lightning peer transport.
 * Call once at daemon startup; swarm connections route into the same
 * handleOffer with their own transport.
 */
export function attachDirectFundingReceiver(
	node: BeignetNode,
	deps: IDirectFundingReceiverDeps
): void {
	// Offers arriving over blinded onion paths. The path_id IS the request
	// id, and the onion layer authenticated it (decrypted recipient data of
	// a path this node minted), so an unknown id is silence, as everywhere.
	// Onion senders are anonymous by construction: that is the transport's
	// point, and the trust policy follows.
	const onion = require('./df-onion');
	const onionDispatcher = onion.onionDfDispatcher(node);
	onionDispatcher.offerSink = (
		pathIdHex: string,
		sealedOffer: object,
		replyPath?: unknown
	): void => {
		// The path_id is a per-request secret the payer never sees; only a
		// path THIS node minted can carry it. It must also name the same
		// request the offer is sealed to, or the frame is mismatched noise.
		const requestId = deps.resolveOnionPathSecret?.(pathIdHex);
		if (!requestId) return;
		const sealedRequestId = (sealedOffer as { requestId?: string }).requestId;
		if (sealedRequestId !== requestId) return;
		if (!replyPath) return;
		const lane = onion.createOnionLane(node, onionDispatcher, pathIdHex, {
			initialPeerReplyPath: replyPath
		});
		void dispatchOffer(
			node,
			deps,
			lane,
			Buffer.from(JSON.stringify(sealedOffer), 'utf8'),
			{ senderAnonymous: true }
		).catch((e) => {
			deps.onEvent?.('direct-funding-failed', e.message);
		});
	};
	node.lightningNode.on(
		'custom-message',
		(msg: { peerPubkey: string; subtype: number; payload: Buffer }) => {
			if (msg.subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER) {
				// A Lightning connection AUTHENTICATES the sender; it does not
				// make them trusted. Zero-conf usability and home-channel
				// splices are reserved for PAIRED senders: node ids the
				// operator explicitly placed in this wallet's trusted set.
				// Every other sender, however it connected, gets the anonymous
				// policy (plain v2 open, confirmations required).
				const paired = node.lightningNode.isTrustedPeer(msg.peerPubkey);
				void dispatchOffer(
					node,
					deps,
					lnTransport(node, msg.peerPubkey),
					msg.payload,
					{ senderAnonymous: !paired }
				).catch((e) => {
					deps.onEvent?.('direct-funding-failed', e.message);
				});
				return;
			}
			if (msg.subtype === BeignetCustomSubtype.DIRECT_FUNDING_RELAY) {
				try {
					const frame = JSON.parse(msg.payload.toString('utf8'));
					// Only forwarded frames (relay-stamped `from`) are offers for us;
					// frames still carrying `to` belong to the forwarder, not here.
					if (typeof frame?.from !== 'string' || frame.to !== undefined) {
						return;
					}
					if (frame.t !== BeignetCustomSubtype.DIRECT_FUNDING_OFFER) return;
					void dispatchOffer(
						node,
						deps,
						relayTransport(node, msg.peerPubkey, frame.from),
						Buffer.from(JSON.stringify(frame.p), 'utf8'),
						// The relay stamps the sender's node id, but that identity is
						// vouched for by the relay, not observed by this node, so the
						// sender gets the anonymous trust policy: no zero-conf, no
						// splice into the home channel, confirmations required.
						{ senderAnonymous: true }
					).catch((e) => {
						deps.onEvent?.('direct-funding-failed', e.message);
					});
				} catch {
					/* malformed relay frame: drop */
				}
			}
		}
	);
}

/**
 * Route an inbound offer, transparently unsealing envelope-v1 traffic.
 * A sealed first frame carries the request id and the sender's ephemeral
 * X25519 key in the clear; the request's private key derives the shared
 * key, the offer decrypts, and the rest of the exchange rides an
 * encrypted wrapper over the same transport. An offer sealed to a request
 * this node never minted is dropped without an answer.
 */
export async function dispatchOffer(
	node: BeignetNode,
	deps: IDirectFundingReceiverDeps,
	transport: DfTransport,
	rawPayload: Buffer,
	opts: { senderAnonymous: boolean }
): Promise<void> {
	let payload: Buffer;
	let lane: DfTransport;
	try {
		const frame = JSON.parse(rawPayload.toString('utf8'));
		if (
			!frame ||
			typeof frame.requestId !== 'string' ||
			typeof frame.eph !== 'string' ||
			typeof frame.c !== 'string'
		) {
			return; // every offer is sealed to a request; anything else is noise
		}
		const priv = deps.getRequestEncryptionKey?.(frame.requestId);
		if (!priv) return; // not our request: say nothing
		const keys = envelope.receiverDeriveKey(priv, frame.eph, frame.requestId);
		payload = envelope.open(
			keys.recvKey,
			frame.requestId,
			BeignetCustomSubtype.DIRECT_FUNDING_OFFER,
			{ n: frame.n, c: frame.c }
		);
		lane = envelope.encryptedTransport(transport, keys, frame.requestId);
	} catch {
		return; // undecryptable: tampered or foreign, drop
	}
	return handleOffer(node, deps, lane, payload, opts);
}

/**
 * Turn a sender's offered UTXO into our channel funding via a v2 open to the
 * LSP (sender's input marked external), relay the sign request/witness, and
 * reveal the receipt preimage after broadcast.
 */
export async function handleOffer(
	node: BeignetNode,
	deps: IDirectFundingReceiverDeps,
	transport: DfTransport,
	payload: Buffer,
	opts: {
		/** True when the sender arrived over the DHT and has no identity we
		 *  can hold anything against. Zero-conf usability is NEVER extended
		 *  to a channel funded by an anonymous sender's unconfirmed input:
		 *  the double-spend risk zero-conf trust accepts is the FUNDER's,
		 *  and here the funder is the sender, not the trusted LSP. */
		senderAnonymous: boolean;
	}
): Promise<void> {
	const offer = JSON.parse(payload.toString('utf8')) as OfferMsg;
	const lsp = deps.getLspPubkey();
	pruneOfferState();

	// Duplicate of an offer already being (or already) served: replay the
	// recorded responses on this transport and do nothing else. Same id with
	// DIFFERENT content is refused outright.
	const payloadHash = crypto
		.createHash('sha256')
		.update(payload)
		.digest('hex');
	const existing = offerSessions.get(offer.offerId);
	if (existing) {
		if (existing.payloadHash !== payloadHash) {
			transport.send(BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK, {
				offerId: offer.offerId,
				accepted: false,
				reason: 'offer id reused with different content'
			} as AckMsg);
			return;
		}
		for (const [subtype, frame] of existing.outbound) {
			transport.send(subtype, frame);
		}
		return;
	}

	const offerSession: IOfferSession = {
		payloadHash,
		outbound: [],
		inflight: true,
		expiresAt: Date.now() + OFFER_SESSION_TTL_MS
	};
	// Record everything we send so a duplicate offer replays it verbatim,
	// including the receipt if the exchange already completed.
	const rawSend = transport.send.bind(transport);
	transport = {
		send: (subtype, frame) => {
			offerSession.outbound.push([subtype, frame]);
			rawSend(subtype, frame);
		},
		onMessage: transport.onMessage.bind(transport)
	};
	const ack = (accepted: boolean, reason?: string): void =>
		transport.send(BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK, {
			offerId: offer.offerId,
			accepted,
			...(reason ? { reason } : {})
		} as AckMsg);
	const declineWithoutSession = (reason: string): void => {
		// Declines are not sessions: forget them so a corrected retry with
		// the same offer id is judged fresh.
		offerSessions.delete(offer.offerId);
		ack(false, reason);
	};
	offerSessions.set(offer.offerId, offerSession);

	const inflightCount = [...offerSessions.values()].filter(
		(o) => o.inflight
	).length;
	if (inflightCount > MAX_INFLIGHT_OFFER_SESSIONS) {
		return declineWithoutSession('too many concurrent funding sessions');
	}
	if (!lsp) return declineWithoutSession('no liquidity peer');
	// A receipt hash we never handed out means the sender is paying a request
	// that is not ours (or a stale one): decline before any channel work.
	const receiptPreimage = offer.receiptHashHex
		? deps.getReceiptPreimage(offer.receiptHashHex)
		: undefined;
	if (!offer.receiptHashHex) {
		// Envelope-only world: every offer pays a minted request. An offer
		// with no receipt hash is not paying anything this node issued.
		return declineWithoutSession('missing receipt hash');
	}
	if (!receiptPreimage) {
		return declineWithoutSession('unknown receipt hash');
	}
	const minAmount = Math.max(
		deps.getMinAmountSat?.() ?? HARD_MIN_OFFER_AMOUNT_SAT,
		HARD_MIN_OFFER_AMOUNT_SAT
	);
	if (offer.amountSat < minAmount) {
		return declineWithoutSession(
			`amount below this receiver's ${minAmount} sat direct funding minimum`
		);
	}
	const reqTrack = requestAttempts.get(offer.receiptHashHex) ?? {
		attempts: 0,
		expiresAt: Date.now() + OFFER_SESSION_TTL_MS
	};
	if (reqTrack.activeOfferId && reqTrack.activeOfferId !== offer.offerId) {
		return declineWithoutSession('request already has an active funding attempt');
	}
	if (reqTrack.attempts >= MAX_REQUEST_ATTEMPTS) {
		return declineWithoutSession('too many attempts for this request');
	}
	// The offer names only an outpoint; the transaction comes from OUR chain
	// source, so the values below are chain truth rather than sender claims.
	const prevTxRes = await node.onchainWallet.electrum
		.getTransactions({ txHashes: [{ tx_hash: offer.txidHex }] })
		.catch(() => null);
	const prevTxHex =
		prevTxRes && !prevTxRes.isErr()
			? ((prevTxRes.value.data?.[0]?.result?.hex ?? '') as string)
			: '';
	if (!prevTxHex) {
		return declineWithoutSession('offered transaction not found on chain');
	}
	const prevTx = bitcoin.Transaction.fromHex(prevTxHex);
	const out = prevTx.outs[offer.vout];
	if (!out || Number(out.value) !== offer.valueSat) {
		return declineWithoutSession('offer value does not match prev tx');
	}
	// Input-ownership proof: the offered UTXO's key must have signed the
	// offer context AND control the UTXO's script — otherwise we would burn a
	// whole channel-open session on a coin the sender cannot spend.
	const ownErr = ((): string | null => {
		if (!offer.ownership) return 'missing ownership proof';
		const script = Buffer.from(out.script);
		const kind = scriptKind(script);
		if (!kind) return 'unsupported input script';
		const proofPub = Buffer.from(offer.ownership.pubkeyHex, 'hex');
		const sig = Buffer.from(offer.ownership.sigHex, 'hex');
		const msg = ownershipMessage(
			offer.offerId,
			prevTx.getId(),
			offer.vout,
			offer.amountSat
		);
		if (kind === 'p2tr') {
			// Key-path: the script's x-only key is the TWEAKED key; verify the
			// schnorr sig against it directly.
			const outputKey = script.subarray(2, 34);
			if (!ecc.verifySchnorr(msg, outputKey, sig)) {
				return 'invalid taproot ownership signature';
			}
			return null;
		}
		// P2WPKH: pubkey must hash to the program, sig must verify.
		const program = script.subarray(2, 22);
		if (!bitcoin.crypto.hash160(proofPub).equals(program)) {
			return 'ownership pubkey does not control the UTXO';
		}
		if (!ecc.verify(msg, proofPub, sig)) {
			return 'invalid ownership signature';
		}
		return null;
	})();
	if (ownErr) return declineWithoutSession(ownErr);

	// One session per outpoint: reserve it for this offer id before any
	// channel work. A duplicate offer never reaches here (replayed above),
	// so a conflicting reservation means a DIFFERENT offer wants the coin.
	const outpoint = `${prevTx.getId()}:${offer.vout}`;
	const reserved = outpointReservations.get(outpoint);
	if (reserved && reserved.offerId !== offer.offerId) {
		return declineWithoutSession('input already committed to another offer');
	}
	outpointReservations.set(outpoint, {
		offerId: offer.offerId,
		expiresAt: Date.now() + OUTPOINT_RESERVATION_TTL_MS
	});
	reqTrack.attempts += 1;
	reqTrack.activeOfferId = offer.offerId;
	requestAttempts.set(offer.receiptHashHex, reqTrack);

	// Everything past this point counts against the in-flight session cap
	// until it settles, succeeds or fails, so a stalled or failed session
	// cannot pin a slot for its whole TTL.
	try {

	// Our "wallet input" IS the sender's input; its change returns to the
	// sender. Our contribution equals the amount they are paying us.
	const externalInput: ISpliceWalletInput = {
		prevTx: prevTx.toBuffer(),
		prevOutputIndex: offer.vout,
		value: BigInt(offer.valueSat),
		sequence: offer.sequence,
		confirmed: true,
		external: true,
		signWitness: () => {
			throw new Error('external input — witness comes from the sender');
		}
	};

	// ONE home channel: when a usable channel with the LSP already exists and
	// the sender is identified, the payment SPLICES it bigger instead of
	// stacking a second channel. Anonymous senders keep the open path: a
	// zero-conf home channel would lock their splice at broadcast, and the
	// double-spend risk of an unconfirmed third-party input is theirs to
	// carry, not the channel's.
	if (!opts.senderAnonymous) {
		const home = node
			.listChannels()
			.find(
				(c) =>
					c.peerPubkey === lsp &&
					(c.htlcUsable != null ? c.htlcUsable : c.state === 'NORMAL')
			);
		if (home) {
			ack(true);
			deps.onEvent?.(
				'channelizing',
				`incoming direct funding (${offer.amountSat.toLocaleString('en-US')} sats) — splicing the home channel bigger from the sender's transaction`
			);
			try {
				await handleSpliceOffer(
					node,
					deps,
					transport,
					offer,
					receiptPreimage,
					externalInput,
					prevTx,
					home.channelId,
					lsp
				);
			} finally {
				offerSession.inflight = false;
				if (reqTrack.activeOfferId === offer.offerId) {
					reqTrack.activeOfferId = undefined;
				}
			}
			return;
		}
	}

	ack(true);
	deps.onEvent?.(
		'channelizing',
		`incoming direct funding (${offer.amountSat.toLocaleString('en-US')} sats) — opening channel from the sender's transaction`
	);

	const targetInboundSat = deps.getTargetInboundSat();
	const channel = node.lightningNode.openChannelV2(lsp, {
		fundingSatoshis: BigInt(offer.amountSat),
		// Zero-conf is explicit opt-in (upstream semantics): negotiated into
		// the channel type only when the LSP trusts this node AND the funder
		// is not anonymous. An anonymous sender's input could be double-spent
		// before it confirms, so their channel waits for a confirmation.
		...(deps.getTrusted() && !opts.senderAnonymous ? { trusted: true } : {}),
		// Buying inbound alongside is optional: a primary that does not sell
		// leases still accepts the plain v2 open.
		...(targetInboundSat > 0
			? {
					requestFunds: {
						requestedSats: BigInt(targetInboundSat),
						blockheight: node.getInfo().blockHeight
					},
					maxLeaseRates: deps.maxLeaseRates ?? DEFAULT_MAX_LEASE_RATES
			  }
			: {})
	});
	channel.setV2FundingInputs(
		[externalInput],
		Buffer.from(offer.changeScriptHex, 'hex')
	);

	// Wait for the negotiated funding tx, then ask the sender to sign it.
	const deadline = Date.now() + OFFER_TIMEOUT_MS;
	while (Date.now() < deadline) {
		if (channel.getFullState().fundingTxid) break;
		await new Promise((r) => setTimeout(r, 250));
	}
	const session = channel.getDualFundingSession();
	const built = session?.buildTransaction();
	if (!channel.getFullState().fundingTxid || !built) {
		throw new Error('direct funding negotiation did not complete');
	}
	const rawTx = rebuildTx(built);
	// Attest: bind OUR node identity to the funding output the sender is
	// being asked to pay into (funding pubkeys + output index + exact tx).
	const chanState = channel.getFullState();
	const localFundingPubkeyHex =
		chanState.localBasepoints.fundingPubkey.toString('hex');
	const remoteFundingPubkeyHex = (
		channel.getDualFundingSession()?.getRemoteBasepoints()?.fundingPubkey ??
		chanState.remoteBasepoints!.fundingPubkey
	).toString('hex');
	const fundingOutputIndex = chanState.fundingOutputIndex;
	// Prevout script+value per input (tx order) so a taproot sender can build
	// its BIP 341 sighash. Every v2 input carries its prevTx.
	const prevouts = rawTx.ins.map((input) => {
		const source = built.inputs.find(
			(i) =>
				i.prevTx &&
				i.prevTx.length >= 32 &&
				bitcoin.Transaction.fromBuffer(i.prevTx)
					.getHash()
					.equals(Buffer.from(input.hash)) &&
				(i.prevTxVout ?? i.prevOutputIndex) === input.index
		);
		if (!source) throw new Error('direct funding: missing prevout for input');
		const sourceOut = bitcoin.Transaction.fromBuffer(source.prevTx!).outs[
			input.index
		];
		return {
			scriptHex: Buffer.from(sourceOut.script).toString('hex'),
			valueSat: Number(sourceOut.value)
		};
	});
	transport.send(BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST, {
		offerId: offer.offerId,
		rawTxHex: rawTx.toHex(),
		prevouts,
		attestation: {
			fundingOutputIndex,
			localFundingPubkeyHex,
			remoteFundingPubkeyHex,
			sigHex: node.signMessage(
				attestationMessage(
					offer.offerId,
					rawTx.toHex(),
					fundingOutputIndex,
					localFundingPubkeyHex
				)
			).signature
		}
	} as SignRequestMsg);

	// Merge the sender's witness when it arrives.
	await new Promise<void>((resolve, reject) => {
		const timer = setTimeout(() => {
			cleanup();
			reject(new Error('sender never delivered its witness'));
		}, OFFER_TIMEOUT_MS);
		const unsubscribe = transport.onMessage((subtype, msgPayload) => {
			if (subtype !== BeignetCustomSubtype.DIRECT_FUNDING_WITNESS) return;
			try {
				const w = JSON.parse(msgPayload.toString('utf8')) as WitnessMsg;
				if (w.offerId !== offer.offerId) return;
				node.lightningNode.provideV2ExternalWitness(
					lsp,
					channel,
					prevTx.getHash(),
					offer.vout,
					w.witnessHex.map((h) => Buffer.from(h, 'hex'))
				);
				cleanup();
				resolve();
			} catch (e) {
				cleanup();
				reject(e);
			}
		});
		const cleanup = (): void => {
			clearTimeout(timer);
			unsubscribe();
		};
	});

	// Broadcast is on its way; reveal the receipt preimage — the sender's
	// provable delivery receipt against the hash its payment request carried.
	if (offer.receiptHashHex && receiptPreimage) {
		const fundingTxidHex = Buffer.from(chanState.fundingTxid!)
			.reverse()
			.toString('hex');
		let receiptRawTxHex: string | undefined;
		try {
			const bres = await node.onchainWallet.electrum.getTransactions({
				txHashes: [{ tx_hash: fundingTxidHex }]
			});
			if (!bres.isErr()) {
				receiptRawTxHex =
					((bres.value.data?.[0]?.result?.hex ?? '') as string) || undefined;
			}
		} catch {
			/* receipt still valid without the raw tx */
		}
		transport.send(BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT, {
			offerId: offer.offerId,
			preimageHex: receiptPreimage,
			fundingTxidHex,
			...(receiptRawTxHex ? { rawTxHex: receiptRawTxHex } : {})
		} as ReceiptMsg);
		deps.onReceiptUsed?.(offer.receiptHashHex);
	}
	deps.onEvent?.(
		'channelized',
		'direct funding complete — one transaction, funds are lightning-ready'
	);
	} finally {
		offerSession.inflight = false;
		if (reqTrack.activeOfferId === offer.offerId) {
			reqTrack.activeOfferId = undefined;
		}
	}
}

const DEFAULT_SPLICE_FEERATE_PERKW = 500;

/**
 * Splice variant of the offer: the sender's UTXO funds a splice-in on the
 * existing home channel. Wire legs (sign request, witness, receipt) are the
 * ones the open path uses; only the channel operation differs.
 */
async function handleSpliceOffer(
	node: BeignetNode,
	deps: IDirectFundingReceiverDeps,
	transport: DfTransport,
	offer: OfferMsg,
	receiptPreimage: string | undefined,
	externalInput: ISpliceWalletInput,
	prevTx: bitcoin.Transaction,
	channelIdHex: string,
	lsp: string
): Promise<void> {
	const channelId = Buffer.from(channelIdHex, 'hex');
	const channel = node.lightningNode.getRawChannel(channelId);
	if (!channel) throw new Error('home channel disappeared');

	const res = node.lightningNode.spliceInWithInputs(
		channelId,
		BigInt(offer.amountSat),
		DEFAULT_SPLICE_FEERATE_PERKW,
		[externalInput],
		Buffer.from(offer.changeScriptHex, 'hex')
	);
	if (!res.ok) {
		throw new Error(`splice initiation failed: ${res.error}`);
	}

	// Wait for the negotiated splice tx. buildAndSignSpliceTx is idempotent
	// and, with an unsigned external input, simply leaves that witness slot
	// for the sender; premature calls fail harmlessly until the interactive
	// round completes.
	const deadline = Date.now() + OFFER_TIMEOUT_MS;
	let pending = channel.getPendingSpliceTx();
	while (!pending && Date.now() < deadline) {
		await new Promise((r) => setTimeout(r, 250));
		try {
			channel.buildAndSignSpliceTx();
		} catch {
			/* interactive round not complete yet */
		}
		pending = channel.getPendingSpliceTx();
	}
	if (!pending) throw new Error('splice negotiation did not complete');

	const rawTx = pending.tx;
	const chanState = channel.getFullState();
	const localFundingPubkeyHex =
		chanState.localBasepoints.fundingPubkey.toString('hex');
	const remoteFundingPubkeyHex =
		chanState.remoteBasepoints!.fundingPubkey.toString('hex');
	const oldFundingScript = createFundingScript(
		chanState.localBasepoints.fundingPubkey,
		chanState.remoteBasepoints!.fundingPubkey,
		deps.network
	);

	// Prevout script+value per input (tx order): the sender's from its own
	// offer, the shared old-funding input from the channel state.
	const senderTxid = prevTx.getHash();
	const prevouts = rawTx.ins.map((input, i) => {
		if (i === pending!.sharedInputIndex) {
			return {
				scriptHex: oldFundingScript.p2wshOutput.toString('hex'),
				valueSat: Number(chanState.fundingSatoshis)
			};
		}
		if (
			Buffer.from(input.hash).equals(senderTxid) &&
			input.index === offer.vout
		) {
			const out = prevTx.outs[offer.vout];
			return {
				scriptHex: Buffer.from(out.script).toString('hex'),
				valueSat: Number(out.value)
			};
		}
		throw new Error('direct-funded splice: unexpected extra input');
	});

	transport.send(BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST, {
		offerId: offer.offerId,
		rawTxHex: rawTx.toHex(),
		prevouts,
		sharedInputIndex: pending.sharedInputIndex,
		attestation: {
			fundingOutputIndex: pending.newFundingOutputIndex,
			localFundingPubkeyHex,
			remoteFundingPubkeyHex,
			sigHex: node.signMessage(
				attestationMessage(
					offer.offerId,
					rawTx.toHex(),
					pending.newFundingOutputIndex,
					localFundingPubkeyHex
				)
			).signature
		}
	} as SignRequestMsg);

	// Merge the sender's witness when it arrives; this releases our held
	// tx_signatures and the splice completes.
	await new Promise<void>((resolve, reject) => {
		const timer = setTimeout(() => {
			cleanup();
			reject(new Error('sender never delivered its witness'));
		}, OFFER_TIMEOUT_MS);
		const unsubscribe = transport.onMessage((subtype, msgPayload) => {
			if (subtype !== BeignetCustomSubtype.DIRECT_FUNDING_WITNESS) return;
			try {
				const w = JSON.parse(msgPayload.toString('utf8')) as WitnessMsg;
				if (w.offerId !== offer.offerId) return;
				node.lightningNode.provideSpliceExternalWitness(
					lsp,
					channel,
					prevTx.getHash(),
					offer.vout,
					w.witnessHex.map((h) => Buffer.from(h, 'hex'))
				);
				cleanup();
				resolve();
			} catch (e) {
				cleanup();
				reject(e);
			}
		});
		const cleanup = (): void => {
			clearTimeout(timer);
			unsubscribe();
		};
	});

	if (offer.receiptHashHex && receiptPreimage) {
		let receiptRawTxHex: string | undefined;
		try {
			const bres = await node.onchainWallet.electrum.getTransactions({
				txHashes: [{ tx_hash: rawTx.getId() }]
			});
			if (!bres.isErr()) {
				receiptRawTxHex =
					((bres.value.data?.[0]?.result?.hex ?? '') as string) || undefined;
			}
		} catch {
			/* receipt still valid without the raw tx */
		}
		transport.send(BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT, {
			offerId: offer.offerId,
			preimageHex: receiptPreimage,
			fundingTxidHex: rawTx.getId(),
			...(receiptRawTxHex ? { rawTxHex: receiptRawTxHex } : {})
		} as ReceiptMsg);
		deps.onReceiptUsed?.(offer.receiptHashHex);
	}
	deps.onEvent?.(
		'channelized',
		'direct-funded splice complete — one transaction, the home channel grew'
	);
}

/**
 * Per-request DHT topic from a dedicated random rendezvous secret carried in
 * the payment request. Unpredictable to anyone without the request, unlinkable
 * to the node identity, and single-use: the receiver leaves the topic when
 * the request is used or expires.
 */
export function rendezvousTopic(rendezvousSecretHex: string): Buffer {
	return crypto
		.createHash('sha256')
		.update(
			Buffer.concat([
				Buffer.from('beignet/direct-funding/topic/v1', 'utf8'),
				Buffer.from(rendezvousSecretHex, 'hex')
			])
		)
		.digest();
}

/** Rebuild the negotiated tx exactly as the channel does (serial-id order). */
function rebuildTx(built: {
	inputs: Array<{
		serialId: bigint;
		prevTxid: Buffer;
		prevOutputIndex: number;
		prevTx?: Buffer;
		prevTxVout?: number;
		sequence: number;
	}>;
	outputs: Array<{
		serialId: bigint;
		scriptPubkey: Buffer;
		amountSats: bigint;
	}>;
	locktime: number;
}): bitcoin.Transaction {
	return buildSpliceTx(
		built.inputs.map((i) => ({
			serialId: i.serialId,
			prevTxid:
				i.prevTx && i.prevTx.length >= 32
					? Buffer.from(bitcoin.Transaction.fromBuffer(i.prevTx).getHash())
					: i.prevTxid,
			prevOutputIndex: i.prevTxVout ?? i.prevOutputIndex,
			sequence: i.sequence
		})),
		built.outputs.map((o) => ({
			serialId: o.serialId,
			script: o.scriptPubkey,
			valueSats: o.amountSats
		})),
		built.locktime
	);
}
