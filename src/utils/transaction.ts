import * as bitcoin from 'bitcoinjs-lib';
import { Psbt } from 'bitcoinjs-lib';
import { err, ok, Result } from './result';
import {
	EAddressType,
	EAvailableNetworks,
	IOutput,
	ISendTransaction,
	TDecodeRawTx,
	TGetByteCountInputs,
	TGetByteCountOutputs
} from '../types';
import { availableNetworks, reduceValue } from './wallet';
import validate, { getAddressInfo } from 'bitcoin-address-validation';
import * as bip21 from 'bip21';
import { TRANSACTION_DEFAULTS } from '../wallet/constants';
import { getBitcoinJsNetwork, validateAddress } from './helpers';
import { btcToSats } from './conversion';

/**
 * Sets RBF for the provided psbt.
 * @param {Psbt} psbt
 * @param {boolean} setRbf
 * @returns {void}
 */
export const setReplaceByFee = ({
	psbt,
	setRbf = true
}: {
	psbt: Psbt;
	setRbf: boolean;
}): void => {
	try {
		const defaultSequence = bitcoin.Transaction.DEFAULT_SEQUENCE;
		//Cannot set replace-by-fee on transaction without inputs.
		// eslint-disable-next-line @typescript-eslint/ban-ts-comment
		// @ts-ignore type for Psbt is wrong
		const ins = psbt.data.globalMap.unsignedTx.tx.ins;
		if (ins.length !== 0) {
			ins.forEach((x) => {
				if (setRbf) {
					if (x.sequence >= defaultSequence - 1) {
						x.sequence = 0;
					}
				} else {
					if (x.sequence < defaultSequence - 1) {
						x.sequence = defaultSequence;
					}
				}
			});
		}
	} catch {}
};

export interface IEncodeBip21 {
	address: string;
	amountSats?: number;
	label?: string;
	message?: string;
}

/**
 * Encodes a BIP21 payment URI (bitcoin:<address>?amount=&label=&message=).
 * The amount is expressed in BTC decimal as the spec requires; it is passed
 * as a fixed-notation string so sub-1e-6 amounts never serialize in exponent
 * form (e.g. "1e-8").
 * @param {IEncodeBip21} params
 * @returns {Result<string>}
 */
export const encodeBip21 = ({
	address,
	amountSats,
	label,
	message
}: IEncodeBip21): Result<string> => {
	try {
		if (!address) {
			return err('No address provided.');
		}
		const options: { [key: string]: string } = {};
		if (amountSats !== undefined) {
			if (!Number.isInteger(amountSats) || amountSats < 0) {
				return err('amountSats must be a non-negative integer.');
			}
			if (amountSats > 0) {
				options.amount = (amountSats / 1e8)
					.toFixed(8)
					.replace(/0+$/, '')
					.replace(/\.$/, '');
			}
		}
		if (label) options.label = label;
		if (message) options.message = message;
		return ok(bip21.encode(address, options));
	} catch (e) {
		return err(e);
	}
};

/*
 * Attempts to parse any given string as an on-chain payment request.
 * Returns an error if invalid.
 * @param {string} data
 * @param {EAvailableNetworks} [network]
 * @returns {Result<{address: string; network: EAvailableNetworks; sats: number; message: string;}>}
 */
export const parseOnChainPaymentRequest = (
	data: string,
	network?: EAvailableNetworks
): Result<{
	address: string;
	network: EAvailableNetworks;
	sats: number;
	message: string;
}> => {
	try {
		if (!data) {
			return err('No data provided to parseOnChainPaymentRequest.');
		}

		let validateAddressResult = validateAddress({ address: data, network });

		if (
			validateAddressResult.isValid &&
			!data.includes(':' || '?' || '&' || '//')
		) {
			return ok({
				address: data,
				network: validateAddressResult.network,
				sats: 0,
				message: ''
			});
		}

		//Determine if we need to parse any invoice data.
		if (data.includes(':' || '?' || '&' || '//')) {
			try {
				//Remove slashes
				if (data.includes('//')) {
					data = data.replace('//', '');
				}
				//bip21.decode will throw if anything other than "bitcoin" is passed to it.
				//Replace any instance of "testnet" or "litecoin" with "bitcoin"
				if (data.includes(':')) {
					data = data.substring(data.indexOf(':') + 1);
					data = `bitcoin:${data}`;
				}

				// types are wrong for package 'bip21'
				const result = bip21.decode(data) as {
					address: string;
					options: { [key: string]: string };
				};
				const address = result.address;
				validateAddressResult = validateAddress({ address, network });
				//Ensure address is valid
				if (!validateAddressResult.isValid) {
					return err(`Invalid address: ${data}`);
				}
				let amount = 0;
				let message = '';
				try {
					amount = Number(result.options.amount) || 0;
				} catch (e) {}
				try {
					message = result.options.message || '';
				} catch (e) {}
				return ok({
					address,
					network: validateAddressResult.network,
					sats: btcToSats(amount),
					message
				});
			} catch {
				return err(data);
			}
		}
		return err(data);
	} catch {
		return err(data);
	}
};

/**
 * Constructs the parameter for getByteCount via an array of addresses.
 * @param {string[]} addresses
 * @param increaseAddressCount
 * @returns {TGetByteCountInputs | TGetByteCountOutputs}y
 */
export const constructByteCountParam = (
	addresses: string[],
	increaseAddressCount: { addrType: EAddressType; count: number }[] = []
): TGetByteCountInputs | TGetByteCountOutputs => {
	try {
		const param: TGetByteCountOutputs = {};
		addresses.forEach((address) => {
			if (validate(address)) {
				const addressType = getAddressInfo(address).type.toUpperCase();
				param[addressType] = (param[addressType] ?? 0) + 1;
			}
		});
		// Applied even when there are no addresses. That is precisely when a caller
		// asks for an assumed output, and returning early on an empty list dropped
		// the request on the floor: sendMax works out its amount before it knows the
		// destination, so it priced a sweep with no outputs at all and went out
		// below the fee rate it was given.
		//
		// The key is upper-cased and a zero count is not written. Writing `p2wpkh: 0`
		// next to `P2WPKH: n`, as this did, left getByteCount holding both spellings
		// of the same type, which it then counted twice.
		increaseAddressCount.forEach(({ addrType, count }) => {
			if (count <= 0) return;
			const key = String(addrType).toUpperCase();
			param[key] = (param[key] ?? 0) + count;
		});
		return Object.keys(param).length ? param : { P2WPKH: 0 };
	} catch {
		return { P2WPKH: 0 };
	}
};

// Patch for https://github.com/coreyphillips/moonshine/issues/52: an OP_RETURN
// payload shorter than this is padded out with spaces.
const MIN_OP_RETURN_PAYLOAD_BYTES = 5;

/**
 * Builds the OP_RETURN script for a message, or undefined when there is no
 * message to embed. Both the PSBT builder and getByteCount go through this, so
 * the fee estimate cannot drift from the script that actually gets built.
 * @param {string} [message]
 * @returns {Buffer | undefined}
 */
export const createOpReturnScript = (message?: string): Buffer | undefined => {
	if (!message || message.trim() === '') {
		return undefined;
	}
	let payload = Buffer.from(message, 'utf8');
	if (payload.length < MIN_OP_RETURN_PAYLOAD_BYTES) {
		payload = Buffer.concat([
			payload,
			Buffer.alloc(MIN_OP_RETURN_PAYLOAD_BYTES - payload.length, 0x20)
		]);
	}
	return bitcoin.payments.embed({ data: [payload] }).output;
};

/*
	Adapted from: https://gist.github.com/junderw/b43af3253ea5865ed52cb51c200ac19c
	Usage:
	getByteCount({'MULTISIG-P2SH:2-4':45},{'P2PKH':1}) Means "45 inputs of P2SH Multisig and 1 output of P2PKH"
	getByteCount({'P2PKH':1,'MULTISIG-P2SH:2-3':2},{'P2PKH':2}) means "1 P2PKH input and 2 Multisig P2SH (2 of 3) inputs along with 2 P2PKH outputs"
	@param {TGetByteCountInputs} inputs
	@param {TGetByteCountOutputs} outputs
	@param {string} [message]
	@param {number} [minByteCount=166] - The minimum byte count to return. Often helpful when calculating fees for a transaction that has not yet been constructed.
	@returns {number}
*/
export const getByteCount = (
	inputs: TGetByteCountInputs,
	outputs: TGetByteCountOutputs,
	message?: string,
	minByteCount = 166
): number => {
	try {
		let totalWeight = 0;
		let hasWitness = false;
		let inputCount = 0;
		let outputCount = 0;
		// assumes compressed pubkeys in all cases.
		const types = {
			// MULTISIG-* do not include pubkeys or signatures yet (this is calculated at runtime)
			// sigs = 73 and pubkeys = 34 (these include pushdata byte)
			inputs: {
				// Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:3(max))
				//   + (script_bytes(OP_0,PUSHDATA(max:3),m,n,CHECK_MULTISIG):5)
				'MULTISIG-P2SH': 51 * 4,
				// Segwit: (push_count:1) + (script_bytes(OP_0,PUSHDATA(max:3),m,n,CHECK_MULTISIG):5)
				// Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1)
				'MULTISIG-P2WSH': 8 + 41 * 4,
				// Segwit: (push_count:1) + (script_bytes(OP_0,PUSHDATA(max:3),m,n,CHECK_MULTISIG):5)
				// Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1) + (p2wsh:35)
				'MULTISIG-P2SH-P2WSH': 8 + 76 * 4,
				// Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1) + (sig:73) + (pubkey:34)
				P2PKH: 148 * 4,
				P2SH: 108 + 64 * 4,
				// Segwit: (push_count:1) + (sig:73) + (pubkey:34)
				// Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1)
				P2WPKH: 108 + 41 * 4,
				// Segwit: (push_count:1) + (sig:73) + (pubkey:34)
				// Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1) + (p2wpkh:23)
				'P2SH-P2WPKH': 108 + 64 * 4,
				// Taproot key-path spend. Witness: (push_count:1) + (schnorr sig:65
				// incl. length) = 66 WU. Non-witness: (txid:32)+(vout:4)+(sequence:4)
				// +(script_len:1) = 41 bytes * 4 = 164 WU. Total ~230 WU = 57.5 vB.
				// It was priced at 138*4 = 552 WU (138 vB), a ~2.4x fee overpay on
				// every taproot spend (and sendMax paid the recipient correspondingly
				// less).
				P2TR: 66 + 41 * 4
			},
			outputs: {
				// (p2sh:24) + (amount:8)
				P2SH: 32 * 4,
				// (p2pkh:26) + (amount:8)
				P2PKH: 34 * 4,
				// (p2wpkh:23) + (amount:8)
				P2WPKH: 31 * 4,
				// (p2wsh:35) + (amount:8)
				P2WSH: 43 * 4,
				// (p2tr:35) + (amount:8). The script is OP_1 <32-byte program>, so 34
				// bytes plus its length prefix, the same size as a P2WSH output. It was
				// counted as (8 + 1 + 32), which omits the two opcode bytes and
				// under-priced every taproot output by 2 vB.
				P2TR: 43 * 4
			}
		};

		const checkUInt53 = (n): void => {
			if (n < 0 || n > Number.MAX_SAFE_INTEGER || n % 1 !== 0)
				throw new RangeError('value out of range');
		};

		const varIntLength = (number): number => {
			checkUInt53(number);

			return number < 0xfd
				? 1
				: number <= 0xffff
				? 3
				: number <= 0xffffffff
				? 5
				: 9;
		};

		// Read each count from the key it was given under, then upper-case the key
		// only to look the type up. Upper-casing first and re-reading the object
		// with the upper-cased key makes a lower-case entry ("p2wpkh") read the
		// value of its upper-case twin ("P2WPKH") and count it a second time, so a
		// param carrying both forms was double-counted. constructByteCountParam
		// emits exactly that pair, which inflated every fee getTotalFeeObj quoted.
		Object.keys(inputs).forEach(function (originalKey) {
			const count = inputs[originalKey];
			const key = originalKey.toUpperCase();
			checkUInt53(count);
			if (key.slice(0, 8) === 'MULTISIG') {
				// ex. "MULTISIG-P2SH:2-3" would mean 2 of 3 P2SH MULTISIG
				const keyParts = key.split(':');
				if (keyParts.length !== 2) throw new Error('invalid input: ' + key);
				const newKey = keyParts[0];
				const mAndN = keyParts[1].split('-').map(function (item) {
					return parseInt(item);
				});

				const multisigWeight = types.inputs[newKey];
				if (multisigWeight === undefined)
					throw new Error('invalid input: ' + key);
				totalWeight += multisigWeight * count;
				const multiplyer = newKey === 'MULTISIG-P2SH' ? 4 : 1;
				totalWeight += (73 * mAndN[0] + 34 * mAndN[1]) * multiplyer * count;
			} else {
				// An unknown key used to make totalWeight NaN, and NaN fails the
				// minByteCount comparison below, so the function returned NaN
				// instead of the fallback its catch provides. types.inputs has no
				// plain P2WSH entry, which is the reachable case.
				const weight = types.inputs[key];
				if (weight === undefined) throw new Error('invalid input: ' + key);
				totalWeight += weight * count;
			}
			inputCount += count;
			// Any segwit input needs the 2-WU marker+flag. P2TR is segwit (v1) but
			// has no 'W' in its name, so it was missed here and every taproot-only
			// tx under-counted the witness overhead by 2 WU.
			if (count > 0 && (key.indexOf('W') >= 0 || key === 'P2TR'))
				hasWitness = true;
		});

		Object.keys(outputs).forEach(function (originalKey) {
			const count = outputs[originalKey];
			const key = originalKey.toUpperCase();
			checkUInt53(count);
			const weight = types.outputs[key];
			if (weight === undefined) throw new Error('invalid output: ' + key);
			totalWeight += weight * count;
			outputCount += count;
		});

		if (hasWitness) totalWeight += 2;
		// Price the exact script the PSBT builder will embed, rather than a second
		// copy of its serialization rules. The message was previously added as
		// message.length * 2 weight units, which is half the payload in vbytes
		// once totalWeight is divided by 4, and nothing for the output itself.
		const opReturnScript = createOpReturnScript(message);
		if (opReturnScript) {
			totalWeight +=
				(8 + varIntLength(opReturnScript.length) + opReturnScript.length) * 4;
			outputCount += 1;
		}

		totalWeight += 8 * 4;
		totalWeight += varIntLength(inputCount) * 4;
		totalWeight += varIntLength(outputCount) * 4;

		const totalVsize = Math.ceil(totalWeight / 4);
		return totalVsize < minByteCount ? minByteCount : totalVsize;
	} catch {
		return minByteCount;
	}
};

// Bitcoin Core prices dust at three sats per vbyte (the default dust relay
// fee) over the serialized output plus the cost of spending it: 67 vbytes for
// a witness program, 148 for anything else. See GetDustThreshold in
// src/policy/policy.cpp.
const DUST_RELAY_SATS_PER_VBYTE = 3;
const WITNESS_SPEND_VBYTES = 67;
const LEGACY_SPEND_VBYTES = 148;
// 8 byte value + 1 byte script length prefix.
const OUTPUT_SERIALIZE_OVERHEAD = 9;

/**
 * Returns the dust threshold in sats for the given address. An output below it
 * is non-standard and will not relay. The value depends on the output script:
 * 294 for P2WPKH, 330 for P2TR and P2WSH, 540 for P2SH and 546 for P2PKH.
 * @param {string} address
 * @returns {number}
 */
export const getDustThreshold = (address: string): number => {
	try {
		// OP_<witness version> + push byte + witness program.
		const { data } = bitcoin.address.fromBech32(address);
		return (
			DUST_RELAY_SATS_PER_VBYTE *
			(OUTPUT_SERIALIZE_OVERHEAD + 2 + data.length + WITNESS_SPEND_VBYTES)
		);
	} catch {
		// Not a segwit address. Fall through to base58.
	}
	try {
		const { version } = bitcoin.address.fromBase58Check(address);
		const isP2sh = availableNetworks().some(
			(network) => getBitcoinJsNetwork(network).scriptHash === version
		);
		// P2SH is OP_HASH160 <20 bytes> OP_EQUAL. P2PKH wraps the same hash in
		// OP_DUP, OP_HASH160, OP_EQUALVERIFY and OP_CHECKSIG.
		const scriptSize = isP2sh ? 23 : 25;
		return (
			DUST_RELAY_SATS_PER_VBYTE *
			(OUTPUT_SERIALIZE_OVERHEAD + scriptSize + LEGACY_SPEND_VBYTES)
		);
	} catch {
		// Unrecognized format. Fall back to the most conservative threshold.
		return TRANSACTION_DEFAULTS.dustLimit;
	}
};

/**
 * Removes outputs that are below the dust threshold of their address type.
 * @param {IOutput[]} outputs
 * @returns {IOutput[]}
 */
export const removeDustOutputs = (outputs: IOutput[]): IOutput[] => {
	return outputs.filter((output) => {
		return output.value >= getDustThreshold(output.address);
	});
};

/**
 * Used to validate transaction form data.
 * @param {ISendTransaction} transaction
 * @return {Result<string>}
 */
export const validateTransaction = (
	transaction: ISendTransaction
): Result<string> => {
	try {
		if (!transaction.fee) {
			return err('No transaction fee provided.');
		}
		if (transaction.outputs.length < 1 || !transaction.outputs[0].address) {
			return err('Please provide an address to send funds to.');
		}
		if (transaction.outputs.length > 0 && !transaction.outputs[0].value) {
			return err('Please provide an amount to send.');
		}
		const inputs = transaction.inputs;
		const outputs = transaction.outputs;
		for (let i = 0; i < outputs.length; i++) {
			const address = outputs[i]?.address ?? '';
			const value = outputs[i]?.value ?? 0;
			const { isValid } = validateAddress({ address });
			if (!isValid) {
				return err(`Invalid Address: ${address}`);
			}
			// Erring here keeps a sub-dust output from reaching the PSBT, where it
			// would make the transaction unrelayable. Dropping it instead would
			// hand the caller's payment to the miner as fee.
			const dustThreshold = getDustThreshold(address);
			if (value < dustThreshold) {
				return err(
					`Output value for ${address} must be greater than or equal to the dust threshold of ${dustThreshold} sats`
				);
			}
			if (!Number.isInteger(value)) {
				return err(`Output value for ${address} should be an integer`);
			}
		}

		const inputsReduce = reduceValue({
			arr: inputs,
			value: 'value'
		});
		if (inputsReduce.isErr()) {
			return err(inputsReduce.error.message);
		}
		//Remove the change address from the outputs array, if any.
		let filteredOutputs = outputs;
		if (transaction.changeAddress) {
			filteredOutputs = outputs.filter((output) => {
				return output.address !== transaction.changeAddress;
			});
		}
		const outputsReduce = reduceValue({
			arr: filteredOutputs,
			value: 'value'
		});
		if (outputsReduce.isErr()) {
			return err(outputsReduce.error.message);
		}

		return ok('Transaction is valid.');
	} catch (e) {
		return err(e);
	}
};

/**
 * Attempts to decode a raw tx hex.
 * Source: https://github.com/bitcoinjs/bitcoinjs-lib/issues/1606#issuecomment-664740672
 * @param {string} hex
 * @param {EAvailableNetworks} [_network]
 * @returns {Result<TDecodeRawTx>}
 */
export const decodeRawTransaction = (
	hex: string,
	_network: EAvailableNetworks
): Result<TDecodeRawTx> => {
	try {
		const network = getBitcoinJsNetwork(_network);
		const tx = bitcoin.Transaction.fromHex(hex);
		return ok({
			txid: tx.getId(),
			tx_hash: tx.getHash(true).toString('hex'),
			size: tx.byteLength(),
			vsize: tx.virtualSize(),
			weight: tx.weight(),
			version: tx.version,
			locktime: tx.locktime,
			vin: tx.ins.map((input) => ({
				txid: Buffer.from(input.hash).reverse().toString('hex'),
				vout: input.index,
				scriptSig: {
					asm: bitcoin.script.toASM(input.script),
					hex: input.script.toString('hex')
				},
				txinwitness: input.witness.map((b) => b.toString('hex')),
				sequence: input.sequence
			})),
			vout: tx.outs.map((output, i) => {
				let address;
				try {
					address = bitcoin.address.fromOutputScript(output.script, network);
				} catch (e) {}
				return {
					value: output.value,
					n: i,
					scriptPubKey: {
						asm: bitcoin.script.toASM(output.script),
						hex: output.script.toString('hex'),
						address
					}
				};
			})
		});
	} catch (e) {
		return err(e);
	}
};

/**
 * Quickly attempts to determine if the provided address is a valid p2tr/taproot address prefix.
 * For a more robust check, use isValidBech32mEncodedString.
 * @param {string} address
 * @returns {boolean}
 */
export const isP2trPrefix = (address: string): boolean => {
	try {
		return (
			address.startsWith('bc1p') ||
			address.startsWith('tb1p') ||
			address.startsWith('bcrt1p')
		);
	} catch {
		return false;
	}
};
