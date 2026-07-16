/**
 * BOLT 5: Sweep transaction builders.
 *
 * Builds transactions to sweep commitment outputs: to_local (CSV delay),
 * HTLC success/timeout witnesses, second-level sweeps, and to_remote claims.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { sign } from '../crypto/ecdh';

import { OutputType } from './types';
import type { ISpliceWalletInput } from '../channel/channel';
import { P2WPKH_DUST_LIMIT } from '../channel/splice-weight';
import { tweakTaprootKeyPathPrivkey } from '../script/commitment-taproot';
import { signTaprootHtlcLeaf } from '../script/htlc-taproot';

bitcoin.initEccLib(ecc);

// ─────────────── Sweep Size Estimation ───────────────

/**
 * Estimated virtual bytes for each sweep transaction type.
 * These are based on typical witness sizes for each output type:
 * - TO_LOCAL: ~113 vbytes (1-in/1-out P2WSH with CSV delay witness)
 * - TO_REMOTE: ~110 vbytes (1-in/1-out P2WPKH claim)
 * - HTLC-timeout (OFFERED_HTLC): ~166 vbytes (HTLC-timeout second-level tx)
 * - HTLC-success (RECEIVED_HTLC): ~176 vbytes (HTLC-success second-level tx with preimage)
 */
const SWEEP_VBYTES: Record<OutputType, number> = {
	[OutputType.TO_LOCAL]: 113,
	[OutputType.TO_REMOTE]: 110,
	[OutputType.OFFERED_HTLC]: 166,
	[OutputType.RECEIVED_HTLC]: 176
};

/**
 * Get the estimated virtual byte size for sweeping a given output type.
 * `leased` marks a lease-locked (liquidity ads) to_remote claim, whose
 * witness script carries an extra CLTV clause: +7 WU (LND's lease
 * script-size overhead), ~+2 vbytes.
 */
export function estimateSweepVbytes(
	outputType: OutputType,
	leased = false
): number {
	const base = SWEEP_VBYTES[outputType];
	return leased && outputType === OutputType.TO_REMOTE ? base + 2 : base;
}

// ─────────────── To-Local Sweep ───────────────

export interface IToLocalSweepParams {
	/** Commitment transaction ID */
	commitmentTxid: string;
	/** Output index of the to_local output */
	outputIndex: number;
	/** Amount of the to_local output in satoshis */
	amount: bigint;
	/** The to_local witness script */
	witnessScript: Buffer;
	/** CSV delay in blocks */
	toSelfDelay: number;
	/** Destination scriptPubKey for swept funds */
	destinationScript: Buffer;
	/** Fee in satoshis */
	feeSatoshis: bigint;
	/**
	 * Liquidity ads (bLIP-0051): absolute lease-expiry height. When the to_local
	 * is a lessor output (CLTV-locked), the sweep must set nLockTime to this; the
	 * input sequence (toSelfDelay, not 0xffffffff) keeps locktime enforced.
	 */
	leaseExpiry?: number;
}

/**
 * Build a transaction to sweep the to_local output after CSV delay.
 * Uses the OP_ELSE (delayed) path of the to_local script.
 */
export function buildToLocalSweepTx(
	params: IToLocalSweepParams
): bitcoin.Transaction {
	const {
		commitmentTxid,
		outputIndex,
		amount,
		toSelfDelay,
		destinationScript,
		feeSatoshis,
		leaseExpiry
	} = params;

	const tx = new bitcoin.Transaction();
	tx.version = 2;
	// Lessor to_local outputs are CLTV-locked until lease_expiry; the input
	// sequence (toSelfDelay) is not 0xffffffff, so locktime stays enforced.
	tx.locktime = leaseExpiry && leaseExpiry > 0 ? leaseExpiry : 0;

	const txidBuf = Buffer.from(commitmentTxid, 'hex').reverse();
	tx.addInput(txidBuf, outputIndex, toSelfDelay);

	const outputAmount = amount - feeSatoshis;
	if (outputAmount <= 0n) {
		throw new Error('Fee exceeds available value for to_local sweep');
	}
	tx.addOutput(destinationScript, Number(outputAmount));

	return tx;
}

/**
 * Build the witness for spending the to_local output via the delayed path.
 * Witness: <sig> 0 <witnessScript>
 * The 0 selects the OP_ELSE branch (delayed payment, not revocation).
 */
export function buildToLocalDelayedWitness(
	signature: Buffer,
	witnessScript: Buffer
): Buffer[] {
	return [
		signature,
		Buffer.alloc(0), // OP_FALSE for the OP_ELSE branch
		witnessScript
	];
}

// ─────────────── HTLC Witnesses ───────────────

/**
 * Build the witness for an HTLC-success spend (claiming a received HTLC with preimage).
 * Per BOLT 3: witness = 0 <remotesig> <localsig> <payment_preimage> <witnessScript>
 */
export function buildHtlcSuccessWitness(
	remoteSig: Buffer,
	localSig: Buffer,
	preimage: Buffer,
	witnessScript: Buffer
): Buffer[] {
	return [
		Buffer.alloc(0), // OP_0 dummy for CHECKMULTISIG
		remoteSig,
		localSig,
		preimage,
		witnessScript
	];
}

/**
 * Build the witness for an HTLC-timeout spend (claiming an offered HTLC after timeout).
 * Per BOLT 3: witness = 0 <remotesig> <localsig> 0 <witnessScript>
 */
export function buildHtlcTimeoutWitness(
	remoteSig: Buffer,
	localSig: Buffer,
	witnessScript: Buffer
): Buffer[] {
	return [
		Buffer.alloc(0), // OP_0 dummy for CHECKMULTISIG
		remoteSig,
		localSig,
		Buffer.alloc(0), // OP_0 to select the timeout path
		witnessScript
	];
}

// ─────────────── Second-Level Sweep ───────────────

export interface ISecondLevelSweepParams {
	/** HTLC-success or HTLC-timeout transaction ID */
	htlcTxid: string;
	/** Output index (always 0 for second-level txs) */
	outputIndex: number;
	/** Amount of the second-level output in satoshis */
	amount: bigint;
	/** The output script of the second-level tx (same format as to_local) */
	witnessScript: Buffer;
	/** CSV delay in blocks */
	toSelfDelay: number;
	/** Destination scriptPubKey for swept funds */
	destinationScript: Buffer;
	/** Fee in satoshis */
	feeSatoshis: bigint;
	/**
	 * Liquidity ads (bLIP-0051): absolute lease-expiry height. When the lessor's
	 * second-level output is CLTV-locked, the sweep must set nLockTime to this.
	 */
	leaseExpiry?: number;
}

/**
 * Build a transaction to sweep the output of an HTLC second-level tx.
 * These outputs have the same script format as to_local (CSV delay).
 */
export function buildSecondLevelSweepTx(
	params: ISecondLevelSweepParams
): bitcoin.Transaction {
	const {
		htlcTxid,
		outputIndex,
		amount,
		toSelfDelay,
		destinationScript,
		feeSatoshis,
		leaseExpiry
	} = params;

	const tx = new bitcoin.Transaction();
	tx.version = 2;
	// Lessor second-level outputs are CLTV-locked until lease_expiry.
	tx.locktime = leaseExpiry && leaseExpiry > 0 ? leaseExpiry : 0;

	const txidBuf = Buffer.from(htlcTxid, 'hex').reverse();
	tx.addInput(txidBuf, outputIndex, toSelfDelay);

	const outputAmount = amount - feeSatoshis;
	if (outputAmount <= 0n) {
		throw new Error('Fee exceeds available value for second-level sweep');
	}
	tx.addOutput(destinationScript, Number(outputAmount));

	return tx;
}

// ─────────────── To-Remote Claim ───────────────

export interface IToRemoteClaimParams {
	/** Commitment transaction ID */
	commitmentTxid: string;
	/** Output index of the to_remote (P2WPKH) output */
	outputIndex: number;
	/** Amount of the to_remote output in satoshis */
	amount: bigint;
	/** Destination scriptPubKey for claimed funds */
	destinationScript: Buffer;
	/** Fee in satoshis */
	feeSatoshis: bigint;
}

/**
 * Build a transaction to claim the to_remote P2WPKH output from
 * the counterparty's commitment transaction. No delay required.
 */
export function buildToRemoteClaimTx(
	params: IToRemoteClaimParams
): bitcoin.Transaction {
	const {
		commitmentTxid,
		outputIndex,
		amount,
		destinationScript,
		feeSatoshis
	} = params;

	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 0;

	const txidBuf = Buffer.from(commitmentTxid, 'hex').reverse();
	tx.addInput(txidBuf, outputIndex, 0xffffffff);

	const outputAmount = amount - feeSatoshis;
	if (outputAmount <= 0n) {
		throw new Error('Fee exceeds available value for to_remote claim');
	}
	tx.addOutput(destinationScript, Number(outputAmount));

	return tx;
}

/**
 * Build the P2WPKH witness for claiming a to_remote output.
 * Witness: <sig> <pubkey>
 */
export function buildToRemoteWitness(
	signature: Buffer,
	pubkey: Buffer
): Buffer[] {
	return [signature, pubkey];
}

/**
 * Build the P2WSH witness for claiming an anchor-channel to_remote output.
 * The script is `<remotepubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY`,
 * so only the signature is needed on the witness stack (the 1-block CSV is
 * satisfied by the spending input's nSequence).
 * Witness: <sig> <witnessScript>
 */
export function buildToRemoteAnchorWitness(
	signature: Buffer,
	witnessScript: Buffer
): Buffer[] {
	return [signature, witnessScript];
}

// ─────────────── Remote HTLC Preimage Claim ───────────────

export interface IRemoteHtlcPreimageClaimParams {
	/** Commitment transaction ID (remote force-close) */
	commitmentTxid: string;
	/** Output index of the HTLC output */
	outputIndex: number;
	/** Amount of the HTLC output in satoshis */
	amount: bigint;
	/** The HTLC witness script */
	witnessScript: Buffer;
	/** Destination scriptPubKey for claimed funds */
	destinationScript: Buffer;
	/** Fee in satoshis */
	feeSatoshis: bigint;
	/**
	 * nSequence for the input. Anchor channels add a 1-block CSV to the HTLC
	 * output's remote-claim path, so the claim must use sequence 1 (not the
	 * default 0xffffffff, whose disable bit would make OP_CSV fail).
	 */
	inputSequence?: number;
}

/**
 * Build a transaction to claim a remote offered HTLC output via the preimage path.
 * On the remote's commitment, their "offered HTLC" is our received payment.
 * We spend it directly (no second-level tx) using the preimage.
 */
export function buildRemoteHtlcPreimageClaimTx(
	params: IRemoteHtlcPreimageClaimParams
): bitcoin.Transaction {
	const {
		commitmentTxid,
		outputIndex,
		amount,
		destinationScript,
		feeSatoshis,
		inputSequence = 0xffffffff
	} = params;

	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 0;

	const txidBuf = Buffer.from(commitmentTxid, 'hex').reverse();
	tx.addInput(txidBuf, outputIndex, inputSequence);

	const outputAmount = amount - feeSatoshis;
	if (outputAmount <= 0n) {
		throw new Error('Fee exceeds available value for HTLC preimage claim');
	}
	tx.addOutput(destinationScript, Number(outputAmount));

	return tx;
}

/**
 * Build the witness for claiming a remote offered HTLC with preimage.
 * The offered HTLC script's preimage path: <remoteHtlcSig> <preimage> <witnessScript>
 */
export function buildRemoteHtlcPreimageWitness(
	signature: Buffer,
	preimage: Buffer,
	witnessScript: Buffer
): Buffer[] {
	return [signature, preimage, witnessScript];
}

// ─────────────── Remote HTLC Timeout Claim ───────────────

/**
 * Build a transaction to reclaim OUR offered HTLC from the remote's commitment
 * after its CLTV expiry. On the remote's commitment our offered HTLC uses the
 * received-HTLC script; the timeout path (taken when the success element is not
 * a 32-byte preimage) is a single signature by the offerer (us). The claim must
 * set nLockTime = cltv_expiry and the input nSequence must NOT be 0xffffffff so
 * OP_CHECKLOCKTIMEVERIFY is enforced. Anchor channels add a 1-block CSV, so the
 * caller passes inputSequence = 1; non-anchor uses 0xfffffffd.
 */
export function buildRemoteHtlcTimeoutClaimTx(
	params: IRemoteHtlcPreimageClaimParams & { cltvExpiry: number }
): bitcoin.Transaction {
	const {
		commitmentTxid,
		outputIndex,
		amount,
		destinationScript,
		feeSatoshis,
		cltvExpiry,
		inputSequence = 0xfffffffd
	} = params;

	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = cltvExpiry;

	const txidBuf = Buffer.from(commitmentTxid, 'hex').reverse();
	tx.addInput(txidBuf, outputIndex, inputSequence);

	const outputAmount = amount - feeSatoshis;
	if (outputAmount <= 0n) {
		throw new Error('Fee exceeds available value for HTLC timeout claim');
	}
	tx.addOutput(destinationScript, Number(outputAmount));

	return tx;
}

/**
 * Witness for the received-HTLC script timeout path: a single offerer signature,
 * then an empty element so `OP_SIZE 32 OP_EQUAL` is false and the timeout branch
 * is selected: [signature, <empty>, witnessScript].
 */
export function buildRemoteHtlcTimeoutWitness(
	signature: Buffer,
	witnessScript: Buffer
): Buffer[] {
	return [signature, Buffer.alloc(0), witnessScript];
}

// ─────────────── Generic Signing ───────────────

/**
 * Sign a sweep transaction input with witness v0 SIGHASH_ALL.
 *
 * @param tx - The sweep transaction
 * @param inputIndex - Which input to sign
 * @param witnessScript - The witness script for the output being spent
 * @param value - The value of the output being spent in satoshis
 * @param privateKey - The private key to sign with
 * @returns DER-encoded signature with SIGHASH_ALL byte
 */
export function signSweepInput(
	tx: bitcoin.Transaction,
	inputIndex: number,
	witnessScript: Buffer,
	value: number,
	privateKey: Buffer,
	sighashType: number = bitcoin.Transaction.SIGHASH_ALL
): Buffer {
	const sigHash = tx.hashForWitnessV0(
		inputIndex,
		witnessScript,
		value,
		sighashType
	);

	const sig = sign(sigHash, privateKey);

	return Buffer.concat([encodeDerSignature(sig), Buffer.from([sighashType])]);
}

/**
 * Encode a counterparty's 64-byte compact signature into the DER + sighash-byte
 * form required inside a witness stack. The remote HTLC signatures received in
 * commitment_signed are compact; they must be re-encoded before being placed in
 * a second-level HTLC witness.
 */
export function encodeWitnessSignature(
	compactSig: Buffer,
	sighashType: number = bitcoin.Transaction.SIGHASH_ALL
): Buffer {
	return Buffer.concat([
		encodeDerSignature(compactSig),
		Buffer.from([sighashType])
	]);
}

/**
 * Sign a P2WPKH input (for to_remote claims).
 * The "witness script" for P2WPKH signing is the implied P2PKH script.
 */
export function signP2wpkhInput(
	tx: bitcoin.Transaction,
	inputIndex: number,
	pubkey: Buffer,
	value: number,
	privateKey: Buffer
): Buffer {
	// For P2WPKH, the script used for signing is:
	// OP_DUP OP_HASH160 <pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
	const p2pkh = bitcoin.payments.p2pkh({ pubkey });
	const sigHash = tx.hashForWitnessV0(
		inputIndex,
		p2pkh.output!,
		value,
		bitcoin.Transaction.SIGHASH_ALL
	);

	const sig = sign(sigHash, privateKey);

	return Buffer.concat([
		encodeDerSignature(sig),
		Buffer.from([bitcoin.Transaction.SIGHASH_ALL])
	]);
}

/**
 * Encode a 64-byte compact signature to DER format.
 */
function encodeDerSignature(sig: Buffer): Buffer {
	if (sig.length !== 64) {
		throw new Error(`Signature must be 64 bytes, got ${sig.length}`);
	}

	const r = sig.subarray(0, 32);
	const s = sig.subarray(32, 64);

	function encodeInteger(val: Buffer): Buffer {
		let v = val;
		let start = 0;
		while (start < v.length - 1 && v[start] === 0) start++;
		v = v.subarray(start);
		if (v[0] & 0x80) {
			v = Buffer.concat([Buffer.from([0x00]), v]);
		}
		return Buffer.concat([Buffer.from([0x02, v.length]), v]);
	}

	const rDer = encodeInteger(r);
	const sDer = encodeInteger(s);

	return Buffer.concat([
		Buffer.from([0x30, rDer.length + sDer.length]),
		rDer,
		sDer
	]);
}

// ─────────────── Anchor Fee Bumping ───────────────

/**
 * A dummy witness stack (max-size DER sig + compressed pubkey) used only to
 * measure a transaction's virtual size before the real signatures exist.
 * Witness data is not covered by the signature hash, so replacing these with
 * real witnesses afterwards never invalidates a signature.
 */
const DUMMY_P2WPKH_WITNESS: Buffer[] = [Buffer.alloc(72), Buffer.alloc(33)];

/** Internal-byte-order txid hash of a previous transaction (for addInput). */
function prevTxHash(prevTx: Buffer): Buffer {
	return bitcoin.Transaction.fromBuffer(prevTx).getHash();
}

export interface IAttachFeeInputsParams {
	/** The pre-signed zero-fee second-level HTLC tx (1 input, 1 output). */
	htlcTx: bitcoin.Transaction;
	/**
	 * The witness for the HTLC input (input 0), pre-signed by the counterparty
	 * with SIGHASH_SINGLE|SIGHASH_ANYONECANPAY. Untouched here — appending inputs
	 * and a change output does not invalidate it.
	 */
	htlcWitness: Buffer[];
	/** Wallet fee inputs (P2WPKH) with their signWitness closures. */
	walletInputs: ISpliceWalletInput[];
	/** scriptPubKey for the change output. */
	changeScript: Buffer;
	/** Target fee rate in sat/vByte for the whole bumped transaction. */
	feeratePerVbyte: number;
}

/**
 * Attach wallet fee inputs (and a change output) to a zero-fee anchor
 * second-level HTLC transaction so it pays its own fee and can confirm.
 *
 * The HTLC input keeps its SIGHASH_SINGLE|ANYONECANPAY witness (which only
 * commits to input 0 and output 0); the appended wallet inputs are signed
 * SIGHASH_ALL over the finalised transaction. The result is a self-funding
 * single transaction — not a parent/child package — so it needs no package
 * relay. The HTLC tx's txid changes; callers must re-track the returned txid.
 */
export function attachFeeInputsToZeroFeeHtlcTx(
	params: IAttachFeeInputsParams
): { tx: bitcoin.Transaction; txid: string } {
	const { htlcTx, htlcWitness, walletInputs, changeScript, feeratePerVbyte } =
		params;
	if (walletInputs.length === 0) {
		throw new Error(
			'attachFeeInputsToZeroFeeHtlcTx requires at least one wallet input'
		);
	}
	const walletTotal = walletInputs.reduce((sum, w) => sum + w.value, 0n);

	const build = (
		includeChange: boolean,
		changeValue: bigint
	): bitcoin.Transaction => {
		const tx = new bitcoin.Transaction();
		tx.version = htlcTx.version;
		tx.locktime = htlcTx.locktime;
		// input 0: the HTLC output (its pre-signed witness is re-applied below)
		tx.addInput(
			Buffer.from(htlcTx.ins[0].hash),
			htlcTx.ins[0].index,
			htlcTx.ins[0].sequence
		);
		// output 0: the second-level to-self output — SIGHASH_SINGLE commits to it,
		// so it must stay at index 0 with its original value.
		tx.addOutput(htlcTx.outs[0].script, htlcTx.outs[0].value);
		for (const w of walletInputs) {
			tx.addInput(prevTxHash(w.prevTx), w.prevOutputIndex, w.sequence);
		}
		if (includeChange) {
			tx.addOutput(changeScript, Number(changeValue));
		}
		return tx;
	};

	// Size the candidate (with change) using dummy witnesses, then derive change.
	const sizing = build(true, walletTotal);
	sizing.setWitness(0, htlcWitness);
	walletInputs.forEach((_, i) =>
		sizing.setWitness(1 + i, DUMMY_P2WPKH_WITNESS)
	);
	const fee = BigInt(Math.ceil(sizing.virtualSize() * feeratePerVbyte));
	const change = walletTotal - fee;
	if (change < 0n) {
		throw new Error(
			`insufficient wallet input value to fund HTLC fee bump: have ${walletTotal} sats, need ${fee} sats fee`
		);
	}
	// Below dust: fold the change into the fee (drop the change output).
	const includeChange = change >= P2WPKH_DUST_LIMIT;

	const tx = build(includeChange, includeChange ? change : 0n);
	tx.setWitness(0, htlcWitness);
	walletInputs.forEach((w, i) => {
		tx.setWitness(1 + i, w.signWitness(tx, 1 + i, w.value));
	});

	return { tx, txid: tx.getId() };
}

export interface IAnchorCpfpParams {
	/** Commitment txid in display (big-endian) hex. */
	commitmentTxid: string;
	/** Output index of our local anchor output. */
	anchorOutputIndex: number;
	/** Anchor output value in satoshis (330 per BOLT 3). */
	anchorAmount: bigint;
	/** The anchor witness script (`<funding_pubkey> OP_CHECKSIG OP_IFDUP ...`). */
	anchorWitnessScript: Buffer;
	/**
	 * The private key that owns the anchor and spends it immediately. For legacy
	 * anchor channels this is the funding privkey (witness-v0 owner path); for a
	 * taproot anchor (taprootAnchorMerkleRoot set) it is the local delayed
	 * payment privkey for the broadcast commitment (BIP341 key-path).
	 */
	localFundingPrivkey: Buffer;
	/** Virtual size of the parent (commitment) tx being bumped. */
	parentVbytes: number;
	/** Fee already paid by the parent (commitment) tx, in satoshis. */
	parentFeeSats: bigint;
	/** Wallet fee inputs (P2WPKH) with their signWitness closures. */
	walletInputs: ISpliceWalletInput[];
	/** scriptPubKey for the single change output. */
	changeScript: Buffer;
	/** Target fee rate in sat/vByte the whole package must clear. */
	feeratePerVbyte: number;
	/**
	 * Simple-taproot anchor: the P2TR anchor scriptPubKey. When set, the anchor
	 * input is spent via a BIP341 key-path (Schnorr) spend rather than the legacy
	 * witness-v0 owner path, and anchorWitnessScript is ignored.
	 */
	taprootAnchorScript?: Buffer;
	/**
	 * Simple-taproot anchor: merkle root of the anchor's single-leaf (16-CSV)
	 * tree, used to tweak localFundingPrivkey (the delayed privkey) for the spend.
	 */
	taprootAnchorMerkleRoot?: Buffer;
}

/**
 * Build a CPFP child that spends a commitment's local anchor output (plus
 * wallet inputs) to raise the effective fee rate of the commitment package.
 *
 * The anchor owner path is spendable immediately (no CSV), so the child can be
 * broadcast alongside the commitment as a 1-parent-1-child package. The child
 * pays enough that (parentFee + childFee) / (parentVbytes + childVbytes) clears
 * the target rate, while never paying less than its own way.
 */
export function buildAnchorCpfpTx(params: IAnchorCpfpParams): {
	tx: bitcoin.Transaction;
	txid: string;
} {
	const {
		commitmentTxid,
		anchorOutputIndex,
		anchorAmount,
		anchorWitnessScript,
		localFundingPrivkey,
		parentVbytes,
		parentFeeSats,
		walletInputs,
		changeScript,
		feeratePerVbyte
	} = params;
	if (walletInputs.length === 0) {
		throw new Error('buildAnchorCpfpTx requires at least one wallet input');
	}
	const isTaproot = !!params.taprootAnchorMerkleRoot;
	const totalIn =
		anchorAmount + walletInputs.reduce((sum, w) => sum + w.value, 0n);

	const build = (changeValue: bigint): bitcoin.Transaction => {
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.locktime = 0;
		// input 0: the local anchor (owner path — no CSV, spendable immediately)
		const anchorTxidBuf = Buffer.from(commitmentTxid, 'hex').reverse();
		tx.addInput(anchorTxidBuf, anchorOutputIndex, 0xffffffff);
		for (const w of walletInputs) {
			tx.addInput(prevTxHash(w.prevTx), w.prevOutputIndex, w.sequence);
		}
		tx.addOutput(changeScript, Number(changeValue));
		return tx;
	};

	// Size the child with dummy witnesses to derive the package fee. A taproot
	// key-path spend is a single 64-byte Schnorr signature (no witness script).
	const sizing = build(totalIn);
	sizing.setWitness(
		0,
		isTaproot ? [Buffer.alloc(64)] : [Buffer.alloc(72), anchorWitnessScript]
	);
	walletInputs.forEach((_, i) =>
		sizing.setWitness(1 + i, DUMMY_P2WPKH_WITNESS)
	);
	const childVbytes = sizing.virtualSize();

	const requiredPackageFee = BigInt(
		Math.ceil(feeratePerVbyte * (parentVbytes + childVbytes))
	);
	const childMinFee = BigInt(Math.ceil(feeratePerVbyte * childVbytes));
	let childFee = requiredPackageFee - parentFeeSats;
	if (childFee < childMinFee) childFee = childMinFee;

	const change = totalIn - childFee;
	if (change < P2WPKH_DUST_LIMIT) {
		throw new Error(
			`insufficient funds for anchor CPFP: change ${change} sats below dust (need fee ${childFee} sats from ${totalIn} sats in)`
		);
	}

	const tx = build(change);
	if (isTaproot) {
		// BIP341 key-path spend of the P2TR anchor. The taproot sighash commits to
		// every input's prevout script and value, so gather them across the anchor
		// and the P2WPKH wallet inputs.
		const prevScripts: Buffer[] = [
			params.taprootAnchorScript!,
			...walletInputs.map(
				(w) =>
					bitcoin.Transaction.fromBuffer(w.prevTx).outs[w.prevOutputIndex]
						.script
			)
		];
		const prevValues: number[] = [
			Number(anchorAmount),
			...walletInputs.map((w) => Number(w.value))
		];
		const sighash = tx.hashForWitnessV1(
			0,
			prevScripts,
			prevValues,
			bitcoin.Transaction.SIGHASH_DEFAULT
		);
		const tweaked = tweakTaprootKeyPathPrivkey(
			localFundingPrivkey,
			params.taprootAnchorMerkleRoot!
		);
		tx.setWitness(0, [signTaprootHtlcLeaf(sighash, tweaked)]);
	} else {
		const anchorSig = signSweepInput(
			tx,
			0,
			anchorWitnessScript,
			Number(anchorAmount),
			localFundingPrivkey
		);
		tx.setWitness(0, [anchorSig, anchorWitnessScript]);
	}
	walletInputs.forEach((w, i) => {
		tx.setWitness(1 + i, w.signWitness(tx, 1 + i, w.value));
	});

	return { tx, txid: tx.getId() };
}
