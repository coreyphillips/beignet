/**
 * BOLT 3, Section 3.4: Cooperative closing transaction builder.
 *
 * Builds the closing transaction that both parties sign when
 * cooperatively closing a channel.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';

bitcoin.initEccLib(ecc);

const DUST_LIMIT_P2WPKH = 294;
const DUST_LIMIT_P2WSH = 546;

export interface IClosingTxParams {
	fundingTxid: string;
	fundingOutputIndex: number;
	fundingAmount: bigint;
	localScriptPubkey: Buffer;
	remoteScriptPubkey: Buffer;
	localAmount: bigint;
	remoteAmount: bigint;
	feeAmount: bigint;
}

export interface IClosingTxResult {
	tx: bitcoin.Transaction;
	outputMap: {
		local?: number;
		remote?: number;
	};
}

/**
 * Build a cooperative closing transaction per BOLT 3.
 *
 * - version: 2
 * - locktime: 0
 * - sequence: 0xFFFFFFFF
 * - outputs sorted by BIP 69 (value, then scriptPubKey)
 * - dust outputs omitted
 */
export function buildClosingTx(params: IClosingTxParams): IClosingTxResult {
	const {
		fundingTxid,
		fundingOutputIndex,
		localScriptPubkey,
		remoteScriptPubkey,
		localAmount,
		remoteAmount
	} = params;

	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 0;

	// fundingTxid is in internal byte order per BOLT 2
	const fundingTxidBuf = Buffer.from(fundingTxid, 'hex');
	tx.addInput(fundingTxidBuf, fundingOutputIndex, 0xffffffff);

	interface IOutputEntry {
		script: Buffer;
		value: bigint;
		type: 'local' | 'remote';
	}
	const outputs: IOutputEntry[] = [];

	// Determine dust limit based on script type
	const localDust = getDustLimit(localScriptPubkey);
	const remoteDust = getDustLimit(remoteScriptPubkey);

	if (localAmount >= BigInt(localDust)) {
		outputs.push({
			script: localScriptPubkey,
			value: localAmount,
			type: 'local'
		});
	}

	if (remoteAmount >= BigInt(remoteDust)) {
		outputs.push({
			script: remoteScriptPubkey,
			value: remoteAmount,
			type: 'remote'
		});
	}

	// BIP 69: sort by value, then scriptPubKey
	outputs.sort((a, b) => {
		if (a.value !== b.value) {
			return a.value < b.value ? -1 : 1;
		}
		return Buffer.compare(a.script, b.script);
	});

	const outputMap: IClosingTxResult['outputMap'] = {};
	for (let i = 0; i < outputs.length; i++) {
		tx.addOutput(outputs[i].script, Number(outputs[i].value));
		if (outputs[i].type === 'local') {
			outputMap.local = i;
		} else {
			outputMap.remote = i;
		}
	}

	return { tx, outputMap };
}

/**
 * Calculate the closing fee for a cooperative close.
 *
 * Weight estimation for closing tx:
 * - Header: 10 vbytes (version 4 + locktime 4 + input/output counts)
 * - Input: ~68 vbytes (outpoint 36 + sequence 4 + witness ~110/4)
 * - Each output: 8 (value) + 1 (script len) + scriptLen
 *
 * @param feeratePerKw - Fee rate in satoshis per kilo-weight
 * @param localScriptLen - Length of local scriptPubkey
 * @param remoteScriptLen - Length of remote scriptPubkey
 * @returns Fee in satoshis
 */
export function calculateClosingFee(
	feeratePerKw: number,
	localScriptLen: number,
	remoteScriptLen: number
): bigint {
	// Base weight: header (40) + 1 input (164 witness-adjusted) + segwit marker (2)
	// = 206 weight units for base + input
	const baseWeight = 206;

	// Output weight: 4 * (8 + 1 + scriptLen) per output
	const localOutputWeight = 4 * (8 + 1 + localScriptLen);
	const remoteOutputWeight = 4 * (8 + 1 + remoteScriptLen);

	// Witness: multisig witness (OP_0 + 2 sigs + redeemScript) ≈ 220 weight units
	const witnessWeight = 220;

	const totalWeight =
		baseWeight + localOutputWeight + remoteOutputWeight + witnessWeight;

	// fee = weight * feeRatePerKw / 1000
	return BigInt(Math.ceil((totalWeight * feeratePerKw) / 1000));
}

/**
 * Get the dust limit for a given script type.
 */
function getDustLimit(scriptPubkey: Buffer): number {
	// P2WPKH is 22 bytes (OP_0 <20-byte-hash>)
	if (
		scriptPubkey.length === 22 &&
		scriptPubkey[0] === 0x00 &&
		scriptPubkey[1] === 0x14
	) {
		return DUST_LIMIT_P2WPKH;
	}
	// P2WSH is 34 bytes (OP_0 <32-byte-hash>)
	if (
		scriptPubkey.length === 34 &&
		scriptPubkey[0] === 0x00 &&
		scriptPubkey[1] === 0x20
	) {
		return DUST_LIMIT_P2WSH;
	}
	// Default to P2WSH dust limit for safety
	return DUST_LIMIT_P2WSH;
}
