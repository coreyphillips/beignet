import * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import { sha256 } from '../crypto/provider';

export function validateFundingWitness(
	tx: bitcoin.Transaction,
	index: number,
	stack: Buffer[],
	prevouts: { scripts: Buffer[]; values: bigint[] }
): string | null {
	const script = prevouts.scripts[index];
	const value = prevouts.values[index];
	if (stack.length === 0) return 'empty witness stack';
	// bitcoinjs sighash APIs take number values; above 2^53 the
	// narrowing would silently compute a wrong sighash and fail the
	// verify for the wrong reason. No real prevout gets there (21M BTC
	// in sats fits), so refuse loudly instead of narrowing quietly.
	if (prevouts.values.some((v) => v > BigInt(Number.MAX_SAFE_INTEGER))) {
		return 'prevout value exceeds the safe integer range';
	}
	const isP2wpkh =
		script.length === 22 && script[0] === 0x00 && script[1] === 0x14;
	const isP2wsh =
		script.length === 34 && script[0] === 0x00 && script[1] === 0x20;
	const isP2tr =
		script.length === 34 && script[0] === 0x51 && script[1] === 0x20;
	if (isP2wpkh) {
		if (stack.length !== 2) {
			return 'P2WPKH witness must be [signature, pubkey]';
		}
		const decoded = decodeDerSighashAll(stack[0]);
		if (typeof decoded === 'string') return `P2WPKH ${decoded}`;
		const pubkey = stack[1];
		if (pubkey.length !== 33 || (pubkey[0] !== 0x02 && pubkey[0] !== 0x03)) {
			return 'P2WPKH witness pubkey is malformed';
		}
		if (!bitcoin.crypto.hash160(pubkey).equals(script.subarray(2))) {
			return 'P2WPKH witness pubkey does not match the prevout program';
		}
		const scriptCode = bitcoin.payments.p2pkh({
			hash: script.subarray(2)
		}).output!;
		const sighash = tx.hashForWitnessV0(
			index,
			scriptCode,
			Number(value),
			bitcoin.Transaction.SIGHASH_ALL
		);
		let valid = false;
		try {
			// strict: high-S signatures are refused (BIP 62 standardness).
			valid = ecc.verify(sighash, pubkey, decoded, true);
		} catch {
			// A malformed peer-controlled point must fail the negotiation,
			// not escape the validator as an exception.
			valid = false;
		}
		if (!valid) {
			return 'P2WPKH signature does not verify against its prevout';
		}
		return null;
	}
	if (isP2tr) {
		if (stack.length === 1) {
			const sig = stack[0];
			// BOLT 2 names SIGHASH_ALL for tx_signatures, but BIP 341's
			// 64-byte SIGHASH_DEFAULT shorthand commits to exactly the
			// same transaction data, and common signers (Bitcoin Core,
			// libwally, and so eclair and CLN) emit it for taproot
			// inputs: both forms are accepted. A 65-byte signature with
			// any other trailing byte stays refused, including 0x00,
			// which BIP 341 forbids in the explicit form.
			const isDefaultForm = sig.length === 64;
			if (!isDefaultForm && (sig.length !== 65 || sig[64] !== 0x01)) {
				return 'P2TR key-spend signature must be the 64-byte SIGHASH_DEFAULT form or carry an explicit SIGHASH_ALL byte';
			}
			// The hash type byte is part of the BIP 341 message, so the
			// sighash must be computed for the form the witness carries.
			const sighash = tx.hashForWitnessV1(
				index,
				prevouts.scripts,
				prevouts.values.map((v) => Number(v)),
				isDefaultForm
					? bitcoin.Transaction.SIGHASH_DEFAULT
					: bitcoin.Transaction.SIGHASH_ALL
			);
			let valid = false;
			try {
				valid = ecc.verifySchnorr(
					sighash,
					script.subarray(2),
					sig.subarray(0, 64)
				);
			} catch {
				valid = false;
			}
			if (!valid) {
				return 'P2TR signature does not verify against its prevout';
			}
			return null;
		}
		// Script-path spends cannot be verified generically (the leaf
		// semantics are the script's own): fail closed rather than accept
		// a witness this validator cannot judge. The negotiation-time
		// check keeps P2TR prevouts acceptable, because a KEY-spend of
		// them is fully verifiable; only the path choice is refused here.
		return 'P2TR script-path spends are not supported for funding inputs';
	}
	if (isP2wsh) {
		// A general P2WSH witness cannot be verified without executing the
		// script (a hash-matched OP_FALSE spend would pass any structural
		// check), so exactly one form is admitted (issue #1922): the bare
		// 2-of-2 of a channel funding output, OP_2 <key> <key> OP_2
		// OP_CHECKMULTISIG, spent as [<>, sig, sig, script], whose
		// semantics are fully known: both signatures must verify under
		// BIP 143 against the key in the same position. Everything else
		// stays refused here, which is where a splice session defers the
		// judgment to (_v2CheckInputSpendable admits the program at
		// tx_complete, where only the 32-byte hash is visible).
		return validateBare2of2Witness(tx, index, stack, script, value);
	}
	return 'peer funding input is not a supported segwit output';
}

/**
 * The one P2WSH witness form a funding input may carry (issue #1922): a
 * bare 2-of-2 multisig in the canonical BOLT 3 funding form, with both
 * signatures present, SIGHASH_ALL, low-S, each verifying against the key
 * at its position. Returns the problem, or null when acceptable.
 */
function validateBare2of2Witness(
	tx: bitcoin.Transaction,
	index: number,
	stack: Buffer[],
	prevoutScript: Buffer,
	value: bigint
): string | null {
	if (stack.length !== 4 || stack[0].length !== 0) {
		return 'P2WSH witness must be [<>, signature, signature, script] (bare 2-of-2)';
	}
	const script = stack[3];
	if (!sha256(script).equals(prevoutScript.subarray(2))) {
		return 'P2WSH witness script does not match the prevout program';
	}
	const chunks = bitcoin.script.decompile(script);
	const isKey = (c: unknown): c is Buffer =>
		Buffer.isBuffer(c) && c.length === 33 && (c[0] === 0x02 || c[0] === 0x03);
	if (
		!chunks ||
		chunks.length !== 5 ||
		chunks[0] !== bitcoin.opcodes.OP_2 ||
		!isKey(chunks[1]) ||
		!isKey(chunks[2]) ||
		chunks[3] !== bitcoin.opcodes.OP_2 ||
		chunks[4] !== bitcoin.opcodes.OP_CHECKMULTISIG ||
		!bitcoin.script.compile(chunks).equals(script)
	) {
		return 'P2WSH witness script is not a bare 2-of-2 (OP_2 <key> <key> OP_2 OP_CHECKMULTISIG)';
	}
	const keys = [chunks[1], chunks[2]];
	const sighash = tx.hashForWitnessV0(
		index,
		script,
		Number(value),
		bitcoin.Transaction.SIGHASH_ALL
	);
	for (let k = 0; k < 2; k++) {
		const decoded = decodeDerSighashAll(stack[1 + k]);
		if (typeof decoded === 'string') return `2-of-2 ${decoded}`;
		let valid = false;
		try {
			// strict: high-S signatures are refused (BIP 62 standardness).
			valid = ecc.verify(sighash, keys[k], decoded, true);
		} catch {
			valid = false;
		}
		if (!valid) {
			return `2-of-2 signature ${k + 1} does not verify against its key`;
		}
	}
	return null;
}

/**
 * Decode a DER-encoded signature-with-sighash element; returns the raw
 * 64-byte signature when it is structurally valid AND carries an explicit
 * SIGHASH_ALL byte, or the problem as a string.
 */
function decodeDerSighashAll(el: Buffer): Buffer | string {
	let decoded: { signature: Buffer; hashType: number };
	try {
		decoded = bitcoin.script.signature.decode(el);
	} catch {
		return 'signature is not a valid DER signature';
	}
	if (decoded.hashType !== bitcoin.Transaction.SIGHASH_ALL) {
		return 'signature is not SIGHASH_ALL';
	}
	return decoded.signature;
}
