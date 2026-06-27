/**
 * BOLT 3: Commitment transaction builder.
 *
 * Builds commitment transactions with the exact format required by the
 * Lightning specification, including obscured commitment numbers,
 * to_local/to_remote outputs, trimming, and BIP 69 output ordering.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';
import {
	buildAnchorOutput,
	buildToRemoteAnchorOutput,
	ANCHOR_OUTPUT_VALUE
} from './anchor';

bitcoin.initEccLib(ecc);

const DUST_LIMIT_P2WSH = 546;
const DUST_LIMIT_P2WPKH = 294;

/**
 * Calculate the obscured commitment number.
 *
 * mask = SHA256(open_basepoint || accept_basepoint) → last 6 bytes
 * obscured = commitment_number XOR mask
 *
 * @param openPaymentBasepoint - 33-byte opener's payment basepoint
 * @param acceptPaymentBasepoint - 33-byte accepter's payment basepoint
 * @param commitmentNumber - The commitment number (0-indexed)
 * @returns 6-byte obscured commitment number as bigint
 */
export function calculateObscuredCommitmentNumber(
	openPaymentBasepoint: Buffer,
	acceptPaymentBasepoint: Buffer,
	commitmentNumber: bigint
): bigint {
	const hash = crypto
		.createHash('sha256')
		.update(openPaymentBasepoint)
		.update(acceptPaymentBasepoint)
		.digest();

	// Take last 6 bytes as mask
	let mask = 0n;
	for (let i = 26; i < 32; i++) {
		mask = (mask << 8n) | BigInt(hash[i]);
	}

	return commitmentNumber ^ mask;
}

/**
 * Build the to_local output script.
 *
 * OP_IF
 *   <revocationpubkey>
 * OP_ELSE
 *   <to_self_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
 *   <local_delayedpubkey>
 * OP_ENDIF
 * OP_CHECKSIG
 *
 * @param revocationPubkey - 33-byte revocation public key
 * @param localDelayedPubkey - 33-byte local delayed payment key
 * @param toSelfDelay - CSV delay in blocks
 * @returns The witness script
 */
export function buildToLocalScript(
	revocationPubkey: Buffer,
	localDelayedPubkey: Buffer,
	toSelfDelay: number
): Buffer {
	return bitcoin.script.compile([
		bitcoin.opcodes.OP_IF,
		revocationPubkey,
		bitcoin.opcodes.OP_ELSE,
		bitcoin.script.number.encode(toSelfDelay),
		bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
		bitcoin.opcodes.OP_DROP,
		localDelayedPubkey,
		bitcoin.opcodes.OP_ENDIF,
		bitcoin.opcodes.OP_CHECKSIG
	]);
}

/**
 * Parameters for building a commitment transaction.
 */
export interface ICommitmentTxParams {
	/** Funding transaction outpoint */
	fundingTxid: string;
	fundingOutputIndex: number;
	fundingAmount: bigint;

	/** Obscured commitment number */
	obscuredCommitmentNumber: bigint;

	/** to_local output */
	localAmount: bigint;
	revocationPubkey: Buffer;
	localDelayedPubkey: Buffer;
	toSelfDelay: number;

	/** to_remote output (P2WPKH with static_remote_key) */
	remoteAmount: bigint;
	remotePaymentPubkey: Buffer;

	/** HTLC outputs (pre-built scripts and amounts) */
	htlcOutputs?: IHtlcOutput[];

	/** Fee rate in satoshis per kilo-weight (for weight calculation reference) */
	feeRatePerKw?: bigint;

	/**
	 * The commitment holder's negotiated dust_limit_satoshis. Outputs below this
	 * are trimmed (BOLT 3). When omitted, falls back to the legacy P2WSH/P2WPKH
	 * standardness constants for backward compatibility.
	 */
	dustLimitSatoshis?: bigint;

	/** Enable anchor outputs (BOLT 3 option_anchors) */
	useAnchors?: boolean;
	/** Local funding pubkey (for local anchor output, required when useAnchors=true) */
	localFundingPubkey?: Buffer;
	/** Remote funding pubkey (for remote anchor output, required when useAnchors=true) */
	remoteFundingPubkey?: Buffer;
}

export interface IHtlcOutput {
	script: Buffer; // The HTLC witness script
	amount: bigint; // Amount in satoshis
	cltvExpiry: number; // CLTV expiry (for sorting)
	paymentHash: Buffer; // Payment hash (for sorting)
}

export interface ICommitmentTxResult {
	tx: bitcoin.Transaction;
	toLocalScript?: Buffer;
	toRemoteScript?: Buffer;
	outputMap: {
		toLocal?: number;
		toRemote?: number;
		htlcs: number[];
		/** Maps each entry in htlcs[] back to its index in the original htlcOutputs[] array */
		htlcOriginalIndices: number[];
		/** Anchor output indices (when useAnchors=true) */
		anchorLocal?: number;
		anchorRemote?: number;
	};
}

/**
 * Build a commitment transaction following BOLT 3.
 */
export function buildCommitmentTx(
	params: ICommitmentTxParams
): ICommitmentTxResult {
	const {
		fundingTxid,
		fundingOutputIndex,
		obscuredCommitmentNumber,
		localAmount,
		revocationPubkey,
		localDelayedPubkey,
		toSelfDelay,
		remoteAmount,
		remotePaymentPubkey,
		htlcOutputs,
		useAnchors,
		localFundingPubkey,
		remoteFundingPubkey
	} = params;

	// BOLT 3: trim outputs below the holder's negotiated dust_limit_satoshis.
	// When the negotiated limit isn't supplied, fall back to the legacy
	// standardness constants so existing callers are unaffected.
	const dustWsh = params.dustLimitSatoshis ?? BigInt(DUST_LIMIT_P2WSH);
	const dustWpkh = params.dustLimitSatoshis ?? BigInt(DUST_LIMIT_P2WPKH);

	const tx = new bitcoin.Transaction();
	tx.version = 2;

	// Set locktime: upper bits signal, lower 24 bits from obscured number
	tx.locktime = 0x20000000 | Number(obscuredCommitmentNumber & 0xffffffn);

	// Set input sequence: upper bits signal, remaining from obscured upper bits
	// Use >>> 0 to convert from signed to unsigned 32-bit integer
	const sequence =
		(0x80000000 | Number((obscuredCommitmentNumber >> 24n) & 0xffffffn)) >>> 0;

	// Add funding input (fundingTxid is in internal byte order per BOLT 2)
	const fundingTxidBuf = Buffer.from(fundingTxid, 'hex');
	tx.addInput(fundingTxidBuf, fundingOutputIndex, sequence);

	// Build outputs
	type OutputKind =
		| 'to_local'
		| 'to_remote'
		| 'htlc'
		| 'anchor_local'
		| 'anchor_remote';
	interface IOutputEntry {
		script: Buffer;
		value: bigint;
		sortKey: Buffer;
		type: OutputKind;
		htlcIndex?: number;
	}
	const outputs: IOutputEntry[] = [];

	// to_local output (if above dust)
	let toLocalScript: Buffer | undefined;
	if (localAmount >= dustWsh) {
		toLocalScript = buildToLocalScript(
			revocationPubkey,
			localDelayedPubkey,
			toSelfDelay
		);
		const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: toLocalScript } });
		outputs.push({
			script: p2wsh.output!,
			value: localAmount,
			sortKey: p2wsh.output!,
			type: 'to_local'
		});
	}

	// to_remote output
	let toRemoteScript: Buffer | undefined;
	if (useAnchors) {
		// Anchor mode: to_remote is P2WSH with 1-block CSV delay
		if (remoteAmount >= dustWsh) {
			const { script, witnessScript } =
				buildToRemoteAnchorOutput(remotePaymentPubkey);
			toRemoteScript = witnessScript;
			outputs.push({
				script,
				value: remoteAmount,
				sortKey: script,
				type: 'to_remote'
			});
		}
	} else {
		// Non-anchor: to_remote is plain P2WPKH
		if (remoteAmount >= dustWpkh) {
			const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: remotePaymentPubkey });
			outputs.push({
				script: p2wpkh.output!,
				value: remoteAmount,
				sortKey: p2wpkh.output!,
				type: 'to_remote'
			});
		}
	}

	// HTLC outputs
	if (htlcOutputs) {
		for (let i = 0; i < htlcOutputs.length; i++) {
			const htlc = htlcOutputs[i];
			if (htlc.amount >= dustWsh) {
				const p2wsh = bitcoin.payments.p2wsh({
					redeem: { output: htlc.script }
				});
				outputs.push({
					script: p2wsh.output!,
					value: htlc.amount,
					sortKey: p2wsh.output!,
					type: 'htlc',
					htlcIndex: i
				});
			}
		}
	}

	// Anchor outputs (when useAnchors=true)
	// BOLT 3: anchor output for a party is included only if that party has a
	// non-dust main output (to_local / to_remote) OR there are untrimmed HTLCs.
	if (useAnchors && localFundingPubkey && remoteFundingPubkey) {
		const hasUntrimmedHtlcs = outputs.some((o) => o.type === 'htlc');
		const hasToLocal = outputs.some((o) => o.type === 'to_local');
		const hasToRemote = outputs.some((o) => o.type === 'to_remote');

		if (hasToLocal || hasUntrimmedHtlcs) {
			const localAnchor = buildAnchorOutput(localFundingPubkey);
			outputs.push({
				script: localAnchor.script,
				value: ANCHOR_OUTPUT_VALUE,
				sortKey: localAnchor.script,
				type: 'anchor_local'
			});
		}

		if (hasToRemote || hasUntrimmedHtlcs) {
			const remoteAnchor = buildAnchorOutput(remoteFundingPubkey);
			outputs.push({
				script: remoteAnchor.script,
				value: ANCHOR_OUTPUT_VALUE,
				sortKey: remoteAnchor.script,
				type: 'anchor_remote'
			});
		}
	}

	// Sort outputs: BIP 69 — by value, then by scriptPubKey
	outputs.sort((a, b) => {
		if (a.value !== b.value) {
			return a.value < b.value ? -1 : 1;
		}
		return Buffer.compare(a.sortKey, b.sortKey);
	});

	// Add sorted outputs to transaction
	const outputMap: ICommitmentTxResult['outputMap'] = {
		htlcs: [],
		htlcOriginalIndices: []
	};
	for (let i = 0; i < outputs.length; i++) {
		tx.addOutput(outputs[i].script, Number(outputs[i].value));

		switch (outputs[i].type) {
			case 'to_local':
				outputMap.toLocal = i;
				break;
			case 'to_remote':
				outputMap.toRemote = i;
				break;
			case 'htlc':
				outputMap.htlcs.push(i);
				outputMap.htlcOriginalIndices.push(outputs[i].htlcIndex!);
				break;
			case 'anchor_local':
				outputMap.anchorLocal = i;
				break;
			case 'anchor_remote':
				outputMap.anchorRemote = i;
				break;
		}
	}

	return { tx, toLocalScript, toRemoteScript, outputMap };
}

/**
 * Sort commitment outputs following BOLT 3 rules.
 * Sorts by value first, then by scriptPubKey.
 */
export function sortCommitmentOutputs(
	outputs: Array<{ script: Buffer; value: bigint }>
): Array<{ script: Buffer; value: bigint }> {
	return [...outputs].sort((a, b) => {
		if (a.value !== b.value) {
			return a.value < b.value ? -1 : 1;
		}
		return Buffer.compare(a.script, b.script);
	});
}

export { DUST_LIMIT_P2WSH, DUST_LIMIT_P2WPKH };
