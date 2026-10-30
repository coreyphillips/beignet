import * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../utils/ecc';
import { ownershipProbeTransaction } from '../lightning/direct-funding/messages';
import type {
	IDfCoinSigner,
	IDfSenderCoin
} from '../lightning/direct-funding/sender/types';

bitcoin.initEccLib(ecc);

/** The wallet must sign only inputIndex and must not broadcast the PSBT. */
export interface IPsbtSigningContext {
	inputIndex: number;
	purpose: 'ownership' | 'funding';
}

export interface IPsbtCoinSignerOptions {
	/** Return a partially signed or finalized PSBT without broadcasting it. */
	signPsbt(psbtBase64: string, context: IPsbtSigningContext): Promise<string>;
	/** Raw previous transaction, addressed by its display-order transaction ID. */
	getTransaction(txidHex: string): Promise<Buffer>;
	/**
	 * Add derivation paths or other wallet metadata. Changing the transaction,
	 * previous outputs, or sighash mode is refused before signPsbt is called.
	 */
	decoratePsbt?(
		psbt: bitcoin.Psbt,
		context: IPsbtSigningContext
	): void | Promise<void>;
}

interface IPrevouts {
	scripts: Buffer[];
	values: bigint[];
}

const MAX_MONEY = 21_000_000n * 100_000_000n;

function satoshis(value: bigint): number {
	if (value < 0n || value > MAX_MONEY) {
		throw new Error('PSBT previous output value is out of range');
	}
	return Number(value);
}

/**
 * The two supported witnesses contain at most two items, each under 253 bytes.
 * Restricting the encoding also rejects noncanonical CompactSize values.
 */
function readWitness(bytes: Buffer): Buffer[] {
	if (bytes.length === 0 || bytes[0] < 1 || bytes[0] > 2) {
		throw new Error('PSBT has an unsupported final witness');
	}
	const stack: Buffer[] = [];
	let offset = 1;
	for (let i = 0; i < bytes[0]; i++) {
		if (offset >= bytes.length || bytes[offset] >= 0xfd) {
			throw new Error('PSBT has a malformed final witness');
		}
		const length = bytes[offset++];
		if (offset + length > bytes.length) {
			throw new Error('PSBT has a truncated final witness');
		}
		stack.push(Buffer.from(bytes.subarray(offset, offset + length)));
		offset += length;
	}
	if (offset !== bytes.length) {
		throw new Error('PSBT final witness has trailing bytes');
	}
	return stack;
}

/**
 * Adapt a PSBT-only wallet to the payer's narrow signing interface. Ownership
 * uses the protocol's deliberately unspendable probe, never a funding witness.
 * The caller still verifies funding terms and reserves the coin through the
 * payer engine; this function verifies the wallet's signing response.
 */
export function createPsbtCoinSigner(
	coin: IDfSenderCoin,
	options: IPsbtCoinSignerOptions
): IDfCoinSigner {
	// Snapshot before any wallet callback can mutate caller-owned objects.
	const script = Buffer.from(coin.script);
	const txid = coin.txidHex.toLowerCase();
	const vout = coin.vout;
	const value = coin.valueSat;
	if (
		!/^[0-9a-f]{64}$/.test(txid) ||
		!Number.isInteger(vout) ||
		vout < 0 ||
		vout > 0xffffffff ||
		value <= 0n
	) {
		throw new Error('Invalid PSBT signer coin');
	}
	satoshis(value);
	const kind =
		script.length === 22 && script[0] === 0 && script[1] === 20
			? 'p2wpkh'
			: script.length === 34 &&
			  script[0] === 0x51 &&
			  script[1] === 32 &&
			  ecc.isXOnlyPoint(script.subarray(2))
			? 'p2tr'
			: null;
	if (!kind) throw new Error('PSBT signer requires P2WPKH or P2TR key path');
	const hashType =
		kind === 'p2wpkh'
			? bitcoin.Transaction.SIGHASH_ALL
			: bitcoin.Transaction.SIGHASH_DEFAULT;
	const hash = Buffer.from(txid, 'hex').reverse();

	async function sign(
		original: bitcoin.Transaction,
		inputIndex: number,
		originalPrevouts: IPrevouts,
		purpose: IPsbtSigningContext['purpose']
	): Promise<Buffer[]> {
		// bitcoinjs-lib's clone shares script and hash buffers with the source.
		const tx = bitcoin.Transaction.fromBuffer(original.toBuffer());
		const prevouts = {
			scripts: originalPrevouts.scripts.map((s) => Buffer.from(s)),
			values: [...originalPrevouts.values]
		};
		if (
			!Number.isInteger(inputIndex) ||
			inputIndex < 0 ||
			inputIndex >= tx.ins.length ||
			prevouts.scripts.length !== tx.ins.length ||
			prevouts.values.length !== tx.ins.length
		) {
			throw new Error('PSBT signing input or previous outputs are invalid');
		}
		const target = tx.ins[inputIndex];
		if (
			!target.hash.equals(hash) ||
			target.index !== vout ||
			!prevouts.scripts[inputIndex].equals(script) ||
			prevouts.values[inputIndex] !== value ||
			tx.ins.filter((i) => i.hash.equals(hash) && i.index === vout).length !== 1
		) {
			throw new Error('PSBT signing input does not match the selected coin');
		}
		for (const input of tx.ins) {
			if (input.script.length !== 0) {
				throw new Error('PSBT signer requires empty input scriptSigs');
			}
		}
		const values = prevouts.values.map(satoshis);
		// PSBT's unsigned transaction omits all witnesses. Existing witnesses
		// from other parties are not needed to produce our own signature.
		for (let i = 0; i < tx.ins.length; i++) tx.setWitness(i, []);
		if (purpose === 'ownership') validateProbe(tx, prevouts);
		const expectedTx = tx.toBuffer();
		const previous = bitcoin.Transaction.fromBuffer(
			Buffer.from(await options.getTransaction(txid))
		);
		const output = previous.outs[vout];
		if (
			previous.getId() !== txid ||
			!output ||
			!output.script.equals(script) ||
			BigInt(output.value) !== value
		) {
			throw new Error('PSBT previous transaction does not match the coin');
		}
		const psbt = new bitcoin.Psbt();
		psbt.setVersion(tx.version);
		psbt.setLocktime(tx.locktime);
		for (let i = 0; i < tx.ins.length; i++) {
			psbt.addInput({
				hash: Buffer.from(tx.ins[i].hash),
				index: tx.ins[i].index,
				sequence: tx.ins[i].sequence,
				witnessUtxo: {
					script: Buffer.from(prevouts.scripts[i]),
					value: values[i]
				},
				...(i === inputIndex
					? {
							nonWitnessUtxo: previous.toBuffer(),
							// Omission is SIGHASH_DEFAULT for taproot. bip174 v2's
							// updater rejects an explicitly zero-valued sighash field.
							...(kind === 'p2wpkh' ? { sighashType: hashType } : {})
					  }
					: {})
			});
		}
		for (const out of tx.outs) {
			psbt.addOutput({ script: Buffer.from(out.script), value: out.value });
		}
		const context: IPsbtSigningContext = { inputIndex, purpose };

		function checkResponse(candidate: bitcoin.Psbt): void {
			if (!candidate.data.globalMap.unsignedTx.toBuffer().equals(expectedTx)) {
				throw new Error('PSBT signer changed the unsigned transaction');
			}
			for (let i = 0; i < tx.ins.length; i++) {
				const input = candidate.data.inputs[i];
				const prevout = input.witnessUtxo;
				if (
					!prevout ||
					!prevout.script.equals(prevouts.scripts[i]) ||
					prevout.value !== values[i]
				) {
					throw new Error('PSBT signer changed a previous output');
				}
				if (input.nonWitnessUtxo) {
					const parent = bitcoin.Transaction.fromBuffer(input.nonWitnessUtxo);
					const parentOutput = parent.outs[tx.ins[i].index];
					if (
						!parent.getHash().equals(tx.ins[i].hash) ||
						!parentOutput ||
						!parentOutput.script.equals(prevouts.scripts[i]) ||
						parentOutput.value !== values[i]
					) {
						throw new Error('PSBT signer changed a previous transaction');
					}
				}
			}
			const input = candidate.data.inputs[inputIndex];
			if (input.sighashType !== undefined && input.sighashType !== hashType) {
				throw new Error('PSBT signer changed the sighash mode');
			}
			if (input.finalScriptSig?.length) {
				throw new Error('PSBT signer returned a nonempty scriptSig');
			}
		}

		await options.decoratePsbt?.(psbt, { ...context });
		checkResponse(psbt);
		const encoded = await options.signPsbt(psbt.toBase64(), { ...context });
		const signed = bitcoin.Psbt.fromBase64(encoded);
		checkResponse(signed);
		const input = signed.data.inputs[inputIndex];
		let witness: Buffer[];
		if (input.finalScriptWitness) {
			witness = readWitness(input.finalScriptWitness);
		} else if (kind === 'p2wpkh' && input.partialSig?.length === 1) {
			witness = [input.partialSig[0].signature, input.partialSig[0].pubkey];
		} else if (kind === 'p2tr' && input.tapKeySig) {
			witness = [input.tapKeySig];
		} else {
			throw new Error('PSBT signer did not return a supported input signature');
		}
		if (kind === 'p2wpkh') {
			if (
				witness.length !== 2 ||
				witness[1].length !== 33 ||
				!bitcoin.crypto.hash160(witness[1]).equals(script.subarray(2))
			) {
				throw new Error('PSBT witness does not match the selected P2WPKH coin');
			}
			const signature = bitcoin.script.signature.decode(witness[0]);
			if (signature.hashType !== bitcoin.Transaction.SIGHASH_ALL) {
				throw new Error('PSBT signer must use SIGHASH_ALL for P2WPKH');
			}
			const scriptCode = bitcoin.payments.p2pkh({
				hash: script.subarray(2)
			}).output!;
			const digest = tx.hashForWitnessV0(
				inputIndex,
				scriptCode,
				Number(value),
				hashType
			);
			if (!ecc.verify(digest, witness[1], signature.signature, true)) {
				throw new Error('PSBT signer returned an invalid P2WPKH signature');
			}
		} else {
			if (witness.length !== 1 || witness[0].length !== 64) {
				throw new Error(
					'PSBT signer must use SIGHASH_DEFAULT for P2TR key path'
				);
			}
			const digest = tx.hashForWitnessV1(
				inputIndex,
				prevouts.scripts,
				values,
				hashType
			);
			if (!ecc.verifySchnorr(digest, script.subarray(2), witness[0])) {
				throw new Error('PSBT signer returned an invalid P2TR signature');
			}
		}
		return witness.map((item) => Buffer.from(item));
	}

	function validateProbe(tx: bitcoin.Transaction, prevouts: IPrevouts): void {
		const commitment = tx.outs[0]?.script;
		if (
			tx.ins.length !== 2 ||
			tx.outs.length !== 1 ||
			!commitment ||
			commitment.length !== 84 ||
			!commitment.subarray(0, 3).equals(Buffer.from([0x6a, 0x4c, 81]))
		) {
			throw new Error('Invalid direct-funding ownership probe');
		}
		const expected = ownershipProbeTransaction(
			commitment.subarray(3, 19),
			Buffer.from(txid, 'hex'),
			vout,
			tx.ins[0].sequence,
			script,
			value,
			commitment.subarray(19, 51),
			commitment.subarray(51)
		);
		if (
			!expected.tx.toBuffer().equals(tx.toBuffer()) ||
			prevouts.values[1] !== 0n ||
			!expected.prevouts.scripts[1].equals(prevouts.scripts[1])
		) {
			throw new Error('Invalid direct-funding ownership probe');
		}
	}

	return {
		kind,
		// The probe returns the compressed P2WPKH key learned from the wallet.
		ownershipPubkey:
			kind === 'p2tr' ? Buffer.from(script.subarray(2)) : Buffer.alloc(33),
		signOwnership(): never {
			throw new Error('PSBT wallets prove ownership with a transaction probe');
		},
		async signOwnershipProbe(
			tx,
			prevouts
		): Promise<{ pubkey: Buffer; signature: Buffer }> {
			const witness = await sign(tx, 0, prevouts, 'ownership');
			return kind === 'p2wpkh'
				? {
						pubkey: witness[1],
						signature: bitcoin.script.signature.decode(witness[0]).signature
				  }
				: { pubkey: Buffer.from(script.subarray(2)), signature: witness[0] };
		},
		signInput: (tx, inputIndex, prevouts) =>
			sign(tx, inputIndex, prevouts, 'funding')
	};
}
