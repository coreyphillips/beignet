import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { BeignetNode } from './beignet-node';
import { BeignetCustomSubtype } from '../lightning/message/custom';
import { ISpliceWalletInput } from '../lightning/channel/channel';
import { buildSpliceTx } from '../lightning/channel/splice-tx';
import {
	scriptKind,
	taprootTweakPrivateKey
} from '../lightning/wallet/wallet-funding-provider';
import { ILeaseRates } from '../lightning/gossip/types';

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
 *     │                      │ broadcast — ONE chain tx │
 *
 * Trust stance (beignet↔beignet only): the sender verifies its own input and
 * change in the exact tx it signs, and checks the recipient's node-key
 * attestation over the funding output; witness withholding just times the
 * session out. All payloads are JSON over the single odd custom message type,
 * so non-beignet peers silently ignore the whole protocol.
 */

/** Message payloads (JSON over custom subtypes 16-19). */
interface OfferMsg {
	offerId: string;
	amountSat: number;
	prevTxHex: string;
	vout: number;
	valueSat: number;
	sequence: number;
	/** Sender's change script (hex) — change from its input returns here. */
	changeScriptHex: string;
	/** Input-ownership proof: the UTXO's key signs the offer context. */
	ownership: {
		pubkeyHex: string;
		sigHex: string;
	};
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

/** Buyer-side price ceiling used when the receiver buys inbound alongside. */
export const DEFAULT_MAX_LEASE_RATES: ILeaseRates = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100,
	leaseFeeBaseSat: 10000,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 3
};

function send(
	node: BeignetNode,
	peer: string,
	subtype: number,
	payload: object
): void {
	node.lightningNode.sendCustomMessage(
		peer,
		subtype,
		Buffer.from(JSON.stringify(payload), 'utf8')
	);
}

// ─────────────── Sender side ───────────────

/**
 * Fund the recipient's channel directly from one of our UTXOs. Resolves once
 * our witness is delivered (the recipient broadcasts). Throws when we lack a
 * single UTXO covering the amount, or the recipient declines/times out.
 */
export async function sendDirectFunding(
	node: BeignetNode,
	network: bitcoin.Network,
	recipientPubkey: string,
	amountSat: number,
	feeHeadroomSat: number
): Promise<{ offerId: string; spentTxid: string }> {
	const wallet = node.onchainWallet;

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

	const offerId = Buffer.from(`${utxo.tx_hash}:${utxo.tx_pos}:${amountSat}`)
		.toString('hex')
		.slice(0, 32);

	// Signing materials for later.
	const keyPair = ECPair.fromWIF(wallet.getPrivateKey(utxo.path), network);
	const pubkey = Buffer.from(keyPair.publicKey);
	const privKey = Buffer.from(keyPair.privateKey!);
	const ourScript = bitcoin.address.toOutputScript(utxo.address, network);
	const kind = scriptKind(ourScript)!;
	const scriptCode = bitcoin.payments.p2pkh({ pubkey, network }).output!;
	const prevTxid = bitcoin.Transaction.fromHex(prevTxHex).getHash();

	const done = new Promise<void>((resolve, reject) => {
		const timer = setTimeout(() => {
			cleanup();
			reject(new Error('direct funding timed out'));
		}, OFFER_TIMEOUT_MS);
		const onMsg = (msg: {
			peerPubkey: string;
			subtype: number;
			payload: Buffer;
		}): void => {
			if (msg.peerPubkey !== recipientPubkey) return;
			try {
				if (msg.subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK) {
					const ack = JSON.parse(msg.payload.toString('utf8')) as AckMsg;
					if (ack.offerId !== offerId) return;
					if (!ack.accepted) {
						cleanup();
						reject(new Error(`recipient declined: ${ack.reason ?? ''}`));
					}
					return; // accepted — wait for the sign request
				}
				if (msg.subtype === BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST) {
					const req = JSON.parse(
						msg.payload.toString('utf8')
					) as SignRequestMsg;
					if (req.offerId !== offerId) return;
					const tx = bitcoin.Transaction.fromHex(req.rawTxHex);

					// Verify OUR input is spent by this exact tx…
					const ourIndex = tx.ins.findIndex(
						(i) =>
							Buffer.from(i.hash).equals(prevTxid) && i.index === utxo.tx_pos
					);
					if (ourIndex < 0) {
						cleanup();
						reject(new Error('negotiated tx does not spend our input'));
						return;
					}
					// …and our change comes back: everything above amount + a bounded
					// fee must return to our change script.
					const changeValue = tx.outs
						.filter((o) => o.script.equals(changeScript))
						.reduce((s, o) => s + Number(o.value), 0);
					const minChange = utxo.value - amountSat - feeHeadroomSat;
					if (minChange > 294 && changeValue < minChange) {
						cleanup();
						reject(
							new Error(
								`negotiated tx shorts our change: got ${changeValue}, expected >= ${minChange}`
							)
						);
						return;
					}

					let witnessHex: string[];
					if (kind === 'p2tr') {
						// BIP 341 sighash needs every input's prevout — the recipient
						// supplied them; verify OUR entry against our own UTXO before
						// trusting the rest.
						const prevouts = req.prevouts ?? [];
						if (
							prevouts.length !== tx.ins.length ||
							prevouts[ourIndex]?.scriptHex !== ourScript.toString('hex') ||
							prevouts[ourIndex]?.valueSat !== utxo.value
						) {
							cleanup();
							reject(new Error('sign request prevouts do not match our input'));
							return;
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
					send(
						node,
						recipientPubkey,
						BeignetCustomSubtype.DIRECT_FUNDING_WITNESS,
						{
							offerId,
							witnessHex
						} as WitnessMsg
					);
					cleanup();
					resolve();
				}
			} catch (e) {
				cleanup();
				reject(e);
			}
		};
		const cleanup = (): void => {
			clearTimeout(timer);
			node.lightningNode.removeListener('custom-message', onMsg);
		};
		node.lightningNode.on('custom-message', onMsg);
	});

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

	send(node, recipientPubkey, BeignetCustomSubtype.DIRECT_FUNDING_OFFER, {
		offerId,
		amountSat,
		prevTxHex,
		vout: utxo.tx_pos,
		valueSat: utxo.value,
		sequence: 0xfffffffd,
		changeScriptHex: changeScript.toString('hex'),
		ownership
	} as OfferMsg);

	await done;
	return { offerId, spentTxid: utxo.tx_hash };
}

// ─────────────── Recipient side ───────────────

export interface IDirectFundingReceiverDeps {
	getLspPubkey: () => string | undefined;
	/** Inbound to BUY from the LSP alongside (0 = plain v2, nothing bought). */
	getTargetInboundSat: () => number;
	network: bitcoin.Network;
	maxLeaseRates?: ILeaseRates;
	onEvent?: (kind: string, detail: string) => void;
}

/**
 * Handle inbound FUNDING_OFFERs: turn the sender's UTXO into our channel
 * funding via a v2 open to the LSP (sender's input marked external), then
 * relay the sign request/witness. Call once at daemon startup.
 */
export function attachDirectFundingReceiver(
	node: BeignetNode,
	deps: IDirectFundingReceiverDeps
): void {
	node.lightningNode.on(
		'custom-message',
		(msg: { peerPubkey: string; subtype: number; payload: Buffer }) => {
			if (msg.subtype !== BeignetCustomSubtype.DIRECT_FUNDING_OFFER) return;
			void handleOffer(node, deps, msg.peerPubkey, msg.payload).catch((e) => {
				deps.onEvent?.('direct-funding-failed', e.message);
			});
		}
	);
}

async function handleOffer(
	node: BeignetNode,
	deps: IDirectFundingReceiverDeps,
	senderPubkey: string,
	payload: Buffer
): Promise<void> {
	const offer = JSON.parse(payload.toString('utf8')) as OfferMsg;
	const lsp = deps.getLspPubkey();
	const ack = (accepted: boolean, reason?: string): void =>
		send(node, senderPubkey, BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK, {
			offerId: offer.offerId,
			accepted,
			...(reason ? { reason } : {})
		} as AckMsg);

	if (!lsp) return ack(false, 'no liquidity peer');
	const prevTx = bitcoin.Transaction.fromHex(offer.prevTxHex);
	const out = prevTx.outs[offer.vout];
	if (!out || Number(out.value) !== offer.valueSat) {
		return ack(false, 'offer value does not match prev tx');
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
	if (ownErr) return ack(false, ownErr);
	ack(true);
	deps.onEvent?.(
		'channelizing',
		`incoming direct funding (${offer.amountSat.toLocaleString('en-US')} sats) — opening channel from the sender's transaction`
	);

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

	const targetInboundSat = deps.getTargetInboundSat();
	const channel = node.lightningNode.openChannelV2(lsp, {
		fundingSatoshis: BigInt(offer.amountSat),
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
	send(node, senderPubkey, BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST, {
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
		const onMsg = (msg: {
			peerPubkey: string;
			subtype: number;
			payload: Buffer;
		}): void => {
			if (msg.peerPubkey !== senderPubkey) return;
			if (msg.subtype !== BeignetCustomSubtype.DIRECT_FUNDING_WITNESS) return;
			try {
				const w = JSON.parse(msg.payload.toString('utf8')) as WitnessMsg;
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
		};
		const cleanup = (): void => {
			clearTimeout(timer);
			node.lightningNode.removeListener('custom-message', onMsg);
		};
		node.lightningNode.on('custom-message', onMsg);
	});
	deps.onEvent?.(
		'channelized',
		'direct funding complete — one transaction, funds are lightning-ready'
	);
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
