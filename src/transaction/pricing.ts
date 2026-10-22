import type { ILogger } from '../logger';
import type {
	EAddressType,
	IAddressTypesIO,
	ICoinSelectResponse,
	IOutput,
	ISendTransaction,
	IUtxo,
	TGetByteCountInputs,
	TGetByteCountOutputs,
	TGetTotalFeeObj
} from '../types';
import { EBoostType, ECoinSelectPreference } from '../types';
import type { Result } from '../utils';
import {
	ok,
	err,
	reduceValue,
	constructByteCountParam,
	getByteCount,
	getDustThreshold
} from '../utils';
import { TRANSACTION_DEFAULTS } from '../wallet/constants';
import { getAddressInfo } from 'bitcoin-address-validation';

/**
 * Coin selection and fee pricing. These read nothing but their arguments and
 * leave those as they were. Transaction's autoCoinSelect, getTotalFee and
 * getTotalFeeObj fill in the defaults from the staged send and the wallet,
 * then call these.
 */

/** A multisig wallet's m-of-n, which sizes its P2WSH inputs. */
export type TMultisigWeights = { threshold: number; totalCosigners: number };

/** What pricing reads from the wallet. */
export interface IPricingWallet {
	/** The type of the output assumed for a send that names none yet. */
	readonly addressType: EAddressType;
	readonly multisig?: TMultisigWeights;
	/**
	 * The change address the builder adds to a send staged without one, or
	 * undefined when there is none to add.
	 */
	readonly changeAddress?: string;
	readonly logger?: Pick<ILogger, 'error'>;
}

export interface ISelectCoins {
	inputs: IUtxo[];
	outputs: IOutput[];
	changeAddress?: string;
	satsPerByte?: number;
	message?: string;
	coinSelectPreference?: ECoinSelectPreference;
	multisig?: TMultisigWeights;
}

export interface IPriceTransaction {
	satsPerByte: number;
	message: string;
	transaction: Partial<ISendTransaction>;
	fundingLightning: boolean;
	coinSelectPreference: ECoinSelectPreference;
	/** Prices what the builder does with the leftover when no change address is staged: a change output, or dust added to the fee. */
	generatesChange: boolean;
	wallet: IPricingWallet;
}

export type TQuoteTransaction = Omit<IPriceTransaction, 'generatesChange'>;

/**
 * The total value of `items`, or 0 when one has no numeric value.
 * @param {{ value: number }[]} items
 * @param {'inputs' | 'outputs'} kind
 * @param {IPricingWallet} wallet
 * @returns {number}
 */
const totalValue = (
	items: { value: number }[],
	kind: 'inputs' | 'outputs',
	wallet: IPricingWallet
): number => {
	const response = reduceValue({ arr: items, value: 'value' });
	if (response.isOk()) return response.value;
	// 0 is also what an empty set totals, so a failure here is invisible to
	// the caller. Say so rather than only returning it.
	wallet.logger?.error(
		`Failed to total the transaction ${kind}.`,
		response.error
	);
	return 0;
};

/**
 * The highest whole fee rate, in sat/vB, whose fee is at most half of `balance`.
 * @param {number} transactionByteCount
 * @param {number} balance
 * @returns {number}
 */
export const maxSatsPerByte = (
	transactionByteCount: number,
	balance: number
): number => Math.floor(balance / (2 * transactionByteCount));

/**
 * Whether a send below 2 sat/vB is priced at getByteCount's size instead
 * of at least 256 vB. A max send pays its fee out of its one output, so
 * padding only shrinks what the recipient gets and can push a small sweep
 * below dust. getByteCount counts every key as compressed, 32 vB short
 * for an uncompressed one, so those keep the padding.
 * @param {Partial<ISendTransaction>} transaction
 * @param {IUtxo[]} inputs
 * @returns {boolean}
 */
const skipsSizeFloor = (
	transaction: Partial<ISendTransaction>,
	inputs: IUtxo[]
): boolean =>
	!!transaction.max &&
	!inputs.some((input) => input.keyPair?.publicKey.length === 65);

/**
 * The vbytes getByteCount leaves out for inputs signed with an
 * uncompressed key. It prices a P2PKH scriptSig with a 33 byte key, and
 * an uncompressed one is 65 bytes.
 * @param {IUtxo[]} inputs
 * @returns {number}
 */
const uncompressedKeyBytes = (inputs: IUtxo[]): number =>
	inputs.filter(
		(input) =>
			input.keyPair?.publicKey.length === 65 &&
			getAddressInfo(input.address).type === 'p2pkh'
	).length * 32;

/**
 * Rewrites plain P2WSH input counts to the weight-accurate
 * MULTISIG-P2WSH:m-n key for multisig wallets. getByteCount has no
 * generic P2WSH input weight; without this the byte count is unusable.
 * @param {TGetByteCountInputs} param
 * @param {TMultisigWeights} [multisig]
 * @returns {TGetByteCountInputs}
 */
const applyMultisigInputWeights = (
	param: TGetByteCountInputs,
	multisig?: TMultisigWeights
): TGetByteCountInputs => {
	if (!multisig) return param;
	const record = { ...param } as Record<string, number>;
	const count = record.P2WSH ?? record.p2wsh ?? 0;
	if (count > 0) {
		delete record.P2WSH;
		delete record.p2wsh;
		record[`MULTISIG-P2WSH:${multisig.threshold}-${multisig.totalCosigners}`] =
			count;
	}
	return record as TGetByteCountInputs;
};

/**
 * The change address createPsbtFromTransactionData fetches for a
 * transaction staged without one, and what the inputs leave after the
 * outputs and `fee`. Undefined for a staged change address or a max send.
 * @param {Partial<ISendTransaction>} transaction
 * @param {IUtxo[]} inputs
 * @param {number} fee
 * @param {IPricingWallet} wallet
 * @returns {{ address: string; leftover: number } | undefined}
 */
const unstagedChange = ({
	transaction,
	inputs,
	fee,
	wallet
}: {
	transaction: Partial<ISendTransaction>;
	inputs: IUtxo[];
	fee: number;
	wallet: IPricingWallet;
}): { address: string; leftover: number } | undefined => {
	if (transaction.changeAddress || transaction.max) return undefined;
	const address = wallet.changeAddress;
	if (!address) return undefined;
	const leftover =
		totalValue(inputs, 'inputs', wallet) -
		totalValue(transaction.outputs ?? [], 'outputs', wallet) -
		fee;
	return { address, leftover };
};

/**
 * Returns the change address createPsbtFromTransactionData will add to a
 * transaction staged without one, or undefined when it adds none. The
 * builder adds it for any leftover at or above dust and does not reprice
 * the fee, so the estimate has to count it. The leftover is measured at the
 * fee without change, as the builder would see it. Measuring it after the
 * change's own cost leaves out change the builder still adds.
 * @param {Parameters<typeof unstagedChange>[0]} args
 * @returns {string | undefined}
 */
const generatedChangeAddress = (
	args: Parameters<typeof unstagedChange>[0]
): string | undefined => {
	const change = unstagedChange(args);
	return change && change.leftover >= getDustThreshold(change.address)
		? change.address
		: undefined;
};

/**
 * The leftover createPsbtFromTransactionData adds to `fee` for a
 * transaction staged without a change address: all of it when it is under
 * the dust threshold of the change the builder would add, otherwise none.
 * @param {Parameters<typeof unstagedChange>[0]} args
 * @returns {number}
 */
const droppedDust = (args: Parameters<typeof unstagedChange>[0]): number => {
	const change = unstagedChange(args);
	return change &&
		change.leftover >= 0 &&
		change.leftover < getDustThreshold(change.address)
		? change.leftover
		: 0;
};

/**
 * Selects coins for transaction construction based on provided parameters.
 * Sorts a copy of `inputs`.
 * @param {ISelectCoins} args
 * @returns {Result<ICoinSelectResponse>}
 */
export const selectCoins = ({
	inputs = [],
	outputs = [],
	changeAddress,
	satsPerByte = 1,
	message = '',
	coinSelectPreference = ECoinSelectPreference.small,
	multisig
}: ISelectCoins): Result<ICoinSelectResponse> => {
	try {
		if (!inputs || !inputs?.length) {
			return err('No inputs provided');
		}
		if (!outputs || !outputs?.length) {
			return err('No outputs provided');
		}
		// A malformed output value must not become 0. amountToSend being falsy
		// takes the consolidate branch below, which selects every UTXO in the
		// wallet, and applyAutoCoinSelect stages that selection before
		// validateTransaction ever sees the transaction. reduceValue tells a
		// genuine 0, which legitimately means "spend everything", apart from
		// non-numeric data, which does not.
		const amountToSendRes = reduceValue({ arr: outputs, value: 'value' });
		if (amountToSendRes.isErr()) {
			return err(amountToSendRes.error);
		}
		const amountToSend = amountToSendRes.value;

		// Sorted as a copy: callers pass the staged transaction's inputs, and a
		// fee quote must not reorder what the send will spend.
		inputs = [...inputs];
		switch (coinSelectPreference) {
			case 'large':
				// Sort by the largest UTXO amount (Lowest fee, but reveals your largest UTXO's)
				inputs.sort((a, b) => Number(b.value) - Number(a.value));
				break;
			case 'firstInFirstOut':
				// Sort by oldest UTXOs first (lowest height), treating unconfirmed (height = 0 or undefined) as newest
				inputs.sort((a, b) => {
					const heightA = !a.height
						? Number.MAX_SAFE_INTEGER
						: Number(a.height);
					const heightB = !b.height
						? Number.MAX_SAFE_INTEGER
						: Number(b.height);
					return heightA - heightB;
				});
				break;
			case 'lastInFirstOut':
				// Sort by newest UTXOs first (highest height), treating unconfirmed (height = 0 or undefined) as newest
				inputs.sort((a, b) => {
					const heightA = !a.height
						? Number.MAX_SAFE_INTEGER
						: Number(a.height);
					const heightB = !b.height
						? Number.MAX_SAFE_INTEGER
						: Number(b.height);
					return heightB - heightA;
				});
				break;
			case 'small':
			default:
				// Sort by the smallest UTXO amount (Highest fee, but hides your largest UTXO's)
				inputs.sort((a, b) => Number(a.value) - Number(b.value));
				break;
		}

		//Add UTXO's until we have more than the target amount to send.
		let inputAmount = 0;
		let newInputs: IUtxo[] = [];
		const oldInputs: IUtxo[] = [];

		//Consolidate UTXO's if unable to determine the amount to send.
		if (coinSelectPreference === 'consolidate' || !amountToSend) {
			//Add all inputs
			newInputs = [...inputs];
			inputAmount = newInputs.reduce((acc, cur) => {
				return acc + Number(cur.value);
			}, 0);
		} else {
			//Add only the necessary inputs based on the amountToSend.
			inputs.forEach((input) => {
				if (inputAmount < amountToSend) {
					inputAmount += input.value;
					newInputs.push(input);
				} else {
					oldInputs.push(input);
				}
			});

			//The provided UTXO's do not have enough to cover the transaction.
			if ((amountToSend && inputAmount < amountToSend) || !newInputs?.length) {
				return err('Not enough funds.');
			}
		}

		// Output address types for the fee calculation, with and without the
		// change output. Input types are counted below, as the selection grows.
		const countOutputTypes = (
			addresses: string[]
		): IAddressTypesIO['outputs'] => {
			const types = {} as IAddressTypesIO['outputs'];
			addresses.forEach((address) => {
				if (!address) {
					return;
				}
				const validateResponse = getAddressInfo(address);
				if (!validateResponse) {
					return;
				}
				const type = validateResponse.type.toUpperCase() as EAddressType;
				if (type in types) {
					types[type] = types[type] + 1;
				} else {
					types[type] = 1;
				}
			});
			return types;
		};
		const paymentAddresses = outputs.map(({ address }) => address);
		const noChangeOutputTypes = countOutputTypes(paymentAddresses);
		const outputTypes = changeAddress
			? countOutputTypes([...paymentAddresses, changeAddress])
			: noChangeOutputTypes;

		// A selection is priced from its count of inputs per script type, and
		// each coin's address is decoded once. The top-up below reprices after
		// every coin it adds, so walking the whole selection each time is
		// quadratic in the number of coins.
		const addressTypes = new Map<IUtxo, string>();
		const typeOf = (input: IUtxo): string => {
			let type = addressTypes.get(input);
			if (type === undefined) {
				type = getAddressInfo(input.address).type.toUpperCase();
				addressTypes.set(input, type);
			}
			return type;
		};
		type TSelection = { types: Record<string, number>; uncompressed: number };
		// Adds `input` to the counts, or with -1 takes it out. A type with none
		// left is dropped, as a fresh count would have it. A zero P2WSH count
		// is not rewritten by applyMultisigInputWeights, and getByteCount has
		// no plain P2WSH input weight.
		const count = (
			selection: TSelection,
			input: IUtxo,
			by: 1 | -1 = 1
		): TSelection => {
			const type = typeOf(input);
			const left = (selection.types[type] ?? 0) + by;
			if (left) selection.types[type] = left;
			else delete selection.types[type];
			// See uncompressedKeyBytes.
			if (type === 'P2PKH' && input.keyPair?.publicKey.length === 65) {
				selection.uncompressed += by;
			}
			return selection;
		};
		const countAll = (selected: IUtxo[]): TSelection => {
			const selection: TSelection = { types: {}, uncompressed: 0 };
			selected.forEach((input) => count(selection, input));
			return selection;
		};
		const copyOf = (selection: TSelection): TSelection => ({
			types: { ...selection.types },
			uncompressed: selection.uncompressed
		});

		//Price a selection. Every input added costs weight, so this has to be
		//recomputed whenever the selection changes.
		const calculateFee = (
			selection: TSelection,
			types = outputTypes
		): number => {
			// See priceTransaction: priced at its size, without the 166 vB floor.
			let baseFee =
				getByteCount(
					applyMultisigInputWeights(
						selection.types as TGetByteCountInputs,
						multisig
					),
					types,
					message,
					0
				) +
				selection.uncompressed * 32;
			if (satsPerByte < 2) {
				const minByteCount = TRANSACTION_DEFAULTS.recommendedBaseFee;
				if (baseFee < minByteCount) baseFee = minByteCount;
			}
			return baseFee * satsPerByte;
		};

		const selection = countAll(newInputs);
		let fee = calculateFee(selection);
		// The top-up below can add a coin worth less than its own weight costs,
		// leaving a selection that no longer pays the rate even without change.
		// The last one that did is kept to fall back on. The top-up only
		// appends, so that selection is a prefix of newInputs.
		let noChangeLength: number | undefined;
		let noChangeAmount = 0;

		//Ensure we can still cover the transaction with the previously selected UTXO's. Add more UTXO's if not.
		//Repricing after each addition matters: the fee the top-up is measured
		//against used to be the one calculated before any of these inputs
		//existed, so their weight (~68 vB each for P2WPKH) went unpaid.
		if (amountToSend) {
			for (const input of oldInputs) {
				if (inputAmount >= amountToSend + fee) break;
				if (
					inputAmount >=
					amountToSend + calculateFee(selection, noChangeOutputTypes)
				) {
					noChangeLength = newInputs.length;
					noChangeAmount = inputAmount;
				}
				inputAmount += input.value;
				newInputs.push(input);
				fee = calculateFee(count(selection, input));
			}
		}

		//The provided UTXO's do not have enough to cover the transaction.
		if (!newInputs?.length) {
			return err('Not enough funds');
		}
		if (inputAmount < amountToSend + fee) {
			// The payment can still meet the rate without its change output.
			// priceTransaction then quotes the whole leftover as the fee, and the
			// builder finds no change to add.
			const noChangeFee = calculateFee(selection, noChangeOutputTypes);
			if (inputAmount < amountToSend + noChangeFee) {
				if (noChangeLength === undefined) {
					if (coinSelectPreference === 'consolidate' || !amountToSend) {
						return err('Not enough funds');
					}
					// Every input is selected by now. A coin the first pass picked
					// stays in every shorter selection too, so one worth less than
					// what it adds to the fee is left out by selecting again.
					// Inputs of one type and key size add the same, so each kind is
					// priced once.
					const kindOf = (input: IUtxo): string =>
						`${typeOf(input)}:${input.keyPair?.publicKey.length}`;
					const added = new Map<string, number>();
					const economic: IUtxo[] = [];
					const dropped: IUtxo[] = [];
					newInputs.forEach((input) => {
						const kind = kindOf(input);
						let cost = added.get(kind);
						if (cost === undefined) {
							cost = fee - calculateFee(count(copyOf(selection), input, -1));
							added.set(kind, cost);
						}
						(input.value > cost ? economic : dropped).push(input);
					});
					if (!economic.length || !dropped.length) {
						return err('Not enough funds');
					}
					// Dropping coins can bring the selection down to the size floor,
					// where a coin adds less than it did to the whole selection. Each
					// dropped coin is offered back, largest first, at what it adds to
					// the coins kept. Keeping coins only moves the selection away
					// from the floor, so once one of a kind is refused the smaller
					// ones of that kind are too.
					dropped.sort((a, b) => b.value - a.value);
					const refused = new Set<string>();
					const kept = countAll(economic);
					let keptFee = calculateFee(kept);
					for (const input of dropped) {
						const kind = kindOf(input);
						if (refused.has(kind)) continue;
						const withInput = calculateFee(count(copyOf(kept), input));
						if (input.value > withInput - keptFee) {
							economic.push(input);
							count(kept, input);
							keptFee = withInput;
						} else {
							refused.add(kind);
						}
					}
					if (economic.length === newInputs.length) {
						return err('Not enough funds');
					}
					return selectCoins({
						inputs: economic,
						outputs,
						changeAddress,
						satsPerByte,
						message,
						coinSelectPreference,
						multisig
					});
				}
				newInputs = newInputs.slice(0, noChangeLength);
				inputAmount = noChangeAmount;
			}
			fee = inputAmount - amountToSend;
		}
		return ok({ inputs: newInputs, outputs, fee });
	} catch (e) {
		return err(e);
	}
};

/**
 * The fee a transaction pays at `satsPerByte`, on the coins selectCoins picks
 * for it unless it consolidates or sends the max.
 * @param {IPriceTransaction} args
 * @returns {Result<number>}
 */
export const priceTransaction = ({
	satsPerByte,
	message,
	transaction,
	fundingLightning,
	coinSelectPreference,
	generatesChange,
	wallet
}: IPriceTransaction): Result<number> => {
	try {
		let inputs = transaction.inputs || [];
		if (
			coinSelectPreference !== ECoinSelectPreference.consolidate &&
			!transaction.max
		) {
			const coinSelectRes = selectCoins({
				inputs: transaction.inputs || [],
				outputs: transaction.outputs || [],
				changeAddress: transaction.changeAddress,
				satsPerByte,
				message,
				coinSelectPreference,
				multisig: wallet.multisig
			});
			if (coinSelectRes.isOk()) {
				inputs = coinSelectRes.value.inputs;
			}
		}
		const outputs = transaction.outputs || [];
		const changeAddress = transaction.changeAddress;
		//No need for a change address when draining the wallet
		const pricesChange = !!changeAddress && !transaction.max;

		//Determine the address type of each address and construct the object for fee calculation
		const inputAddresses = inputs.map((input) => input.address);
		const inputParam = applyMultisigInputWeights(
			constructByteCountParam(inputAddresses),
			wallet.multisig
		);

		const feeFor = (withChange: boolean): number => {
			const outputAddresses = outputs.map((output) => output.address);
			if (withChange && changeAddress) {
				outputAddresses.push(changeAddress);
			}

			// Every transaction pays to at least one output, even when the caller has
			// not named it yet. sendMax works out the amount before it knows where it
			// is going, so the outputs are still empty here; counting none of them
			// priced the sweep one output short and it went out below the rate that
			// was asked for. quoteTransaction already assumes the output. Assume it
			// here too, or the two disagree about the same transaction.
			let increaseAddressCount = 0;
			if (!outputAddresses.length) {
				increaseAddressCount++;
			}

			const outputParam = constructByteCountParam(outputAddresses, [
				{ addrType: wallet.addressType, count: increaseAddressCount }
			]);
			// A channel funding output is a 2-of-2 P2WSH (43 vB), not the P2WPKH
			// (31 vB) an ordinary send pays to. Counting it as P2WPKH understates
			// every channel funding transaction by 12 vB, which is a real shortfall
			// at the fee rates a funding transaction is actually broadcast at.
			if (fundingLightning) {
				const fundingOutputs = outputParam as TGetByteCountOutputs;
				fundingOutputs.P2WSH = (fundingOutputs.P2WSH || 0) + 1;
			}

			// The inputs and outputs are known, so the transaction is priced at
			// its size, not at getByteCount's default 166 vB floor.
			let transactionByteCount =
				getByteCount(inputParam, outputParam, message, 0) +
				uncompressedKeyBytes(inputs);
			if (satsPerByte < 2 && !skipsSizeFloor(transaction, inputs)) {
				const minByteCount = TRANSACTION_DEFAULTS.recommendedBaseFee;
				if (transactionByteCount < minByteCount)
					transactionByteCount = minByteCount;
			}
			// Outputs are whole sats, so a fractional rate rounds the fee up.
			return Math.ceil(transactionByteCount * satsPerByte);
		};

		const fee = feeFor(pricesChange);
		if (pricesChange) {
			// The change output can cost more than the inputs have left over,
			// or leave less than dust, which the builder adds to the fee. The
			// payment may still meet the rate without it, and quoting the whole
			// leftover as the fee leaves the builder nothing to pay change from.
			const available =
				totalValue(inputs, 'inputs', wallet) -
				totalValue(outputs, 'outputs', wallet);
			if (
				available - fee < getDustThreshold(changeAddress) &&
				feeFor(false) <= available
			) {
				return ok(available);
			}
		}
		const generatedChange =
			generatesChange &&
			generatedChangeAddress({ transaction, inputs, fee, wallet });
		if (generatedChange) {
			// Consolidate keeps the inputs already selected above.
			return priceTransaction({
				satsPerByte,
				message,
				transaction: {
					...transaction,
					inputs,
					changeAddress: generatedChange
				},
				fundingLightning,
				coinSelectPreference: ECoinSelectPreference.consolidate,
				generatesChange: true,
				wallet
			});
		}
		return ok(
			generatesChange
				? fee + droppedDust({ transaction, inputs, fee, wallet })
				: fee
		);
	} catch (e) {
		return err(e);
	}
};

/**
 * priceTransaction's fee, or 256 vB at `satsPerByte` when it cannot price
 * the transaction.
 * @param {IPriceTransaction} args
 * @returns {number}
 */
export const estimateFee = (args: IPriceTransaction): number => {
	const priced = priceTransaction(args);
	return priced.isOk()
		? priced.value
		: TRANSACTION_DEFAULTS.recommendedBaseFee * args.satsPerByte;
};

/**
 * The fee at `satsPerByte`, its size, and the highest rate updateFee accepts
 * for the transaction. A rate it refuses is capped to that maximum. A
 * transaction with no inputs is quoted at nothing.
 * @param {TQuoteTransaction} args
 * @returns {Result<TGetTotalFeeObj>}
 */
export const quoteTransaction = (
	args: TQuoteTransaction
): Result<TGetTotalFeeObj> => quote(args, new Map());

/**
 * quoteTransaction, given the fees coin selection has already priced for
 * this quote. Its searches and its quote at a capped rate ask for the same
 * rates more than once, and each one selects coins again.
 * @param {TQuoteTransaction} args
 * @param {Map<string, number>} selectedFees estimateFee by rate and generatesChange.
 * @returns {Result<TGetTotalFeeObj>}
 */
const quote = (
	{
		satsPerByte,
		message,
		transaction,
		fundingLightning,
		coinSelectPreference,
		wallet
	}: TQuoteTransaction,
	selectedFees: Map<string, number>
): Result<TGetTotalFeeObj> => {
	try {
		let changeAddress = transaction.changeAddress;

		let inputs = transaction.inputs || [];
		const outputs = transaction.outputs || [];

		// A replacement spends every input of the original, so coin selection
		// must not price a subset of them.
		const selectsCoins =
			coinSelectPreference !== ECoinSelectPreference.consolidate &&
			!transaction.max &&
			transaction.boostType !== EBoostType.rbf;
		if (selectsCoins) {
			const coinSelectRes = selectCoins({
				inputs,
				outputs,
				changeAddress,
				satsPerByte,
				message,
				coinSelectPreference,
				multisig: wallet.multisig
			});
			if (coinSelectRes.isErr()) {
				return err(coinSelectRes.error);
			}
			inputs = coinSelectRes.value.inputs;
		}

		if (!inputs.length) {
			return ok({
				totalFee: 0,
				transactionByteCount: 0,
				satsPerByte: 0,
				maxSatPerByte: 0
			});
		}

		//No need for a change address when draining the wallet
		let pricesChange = !!changeAddress && !transaction.max;

		//Determine the address type of each address and construct the object for fee calculation
		const inputAddresses = inputs.map((input) => input.address);
		const inputParam = applyMultisigInputWeights(
			constructByteCountParam(inputAddresses),
			wallet.multisig
		);

		const byteCountFor = (withChange: boolean, rate = satsPerByte): number => {
			const outputAddresses = outputs.map((output) => output.address);

			// Always assume we're sending to at least one output for a proper base calculation.
			let increaseAddressCount = 0;
			if (!outputAddresses.length) {
				increaseAddressCount++;
			}
			if (withChange && changeAddress) {
				outputAddresses.push(changeAddress);
			}

			const outputParam = constructByteCountParam(outputAddresses, [
				{ addrType: wallet.addressType, count: increaseAddressCount }
			]);
			// A channel funding output is a 2-of-2 P2WSH (43 vB), not the P2WPKH
			// (31 vB) an ordinary send pays to. Counting it as P2WPKH understates
			// every channel funding transaction by 12 vB, which is a real shortfall
			// at the fee rates a funding transaction is actually broadcast at.
			if (fundingLightning) {
				const fundingOutputs = outputParam as TGetByteCountOutputs;
				fundingOutputs.P2WSH = (fundingOutputs.P2WSH || 0) + 1;
			}

			// See priceTransaction: priced at its size, without the 166 vB floor.
			const size = getByteCount(inputParam, outputParam, message, 0);
			// For a type it has no weight for, such as a P2WSH input outside a
			// multisig wallet, getByteCount returns the minimum it is given, 0
			// here. Every rate fits a transaction of no size, so the rate
			// searches below would never end, and under 2 sat/vB the size floor
			// would hide it instead. The catch below returns this as the error.
			if (!size) {
				throw new Error(
					'Unable to size the transaction for its fee. A P2WSH input is only sized in a multisig wallet.'
				);
			}
			let transactionByteCount = size + uncompressedKeyBytes(inputs);
			if (rate < 2 && !skipsSizeFloor(transaction, inputs)) {
				const minByteCount = TRANSACTION_DEFAULTS.recommendedBaseFee;
				if (transactionByteCount < minByteCount)
					transactionByteCount = minByteCount;
			}
			return transactionByteCount;
		};

		let transactionByteCount = byteCountFor(pricesChange);
		const generatedChange = generatedChangeAddress({
			transaction,
			inputs,
			fee: Math.ceil(transactionByteCount * satsPerByte),
			wallet
		});
		if (generatedChange) {
			// Priced on the inputs already selected above. Recursing with
			// consolidate would hide from the half-balance guard below that a
			// lower rate selects its own coins.
			changeAddress = generatedChange;
			pricesChange = true;
		}
		const inputAmount = totalValue(inputs, 'inputs', wallet);
		const outputAmount = totalValue(outputs, 'outputs', wallet);
		// To prevent the user from spending more in fees than their output, use the output amount if available.
		const txBalance =
			outputAmount && outputAmount < inputAmount ? outputAmount : inputAmount;
		// See priceTransaction: a payment that cannot also pay for its change
		// output, or would leave it below dust, goes without it, with the whole
		// leftover as the fee. updateFee refuses a fee of half the balance, so a
		// leftover that large keeps change it cannot pay for. Dust change cannot
		// stay: the fee with it looks payable, and updateFee prices the leftover.
		const available = inputAmount - outputAmount;
		const quoteAt = (
			rate: number
		): { totalFee: number; transactionByteCount: number } => {
			// A rate capped below 2 sat/vB takes the size floor that updateFee
			// prices it with.
			const byteCount = byteCountFor(pricesChange, rate);
			const fee = Math.ceil(byteCount * rate);
			const leftover = available - fee;
			if (
				pricesChange &&
				changeAddress &&
				leftover < getDustThreshold(changeAddress) &&
				(leftover >= 0 || available < txBalance / 2)
			) {
				const noChangeByteCount = byteCountFor(false, rate);
				if (Math.ceil(noChangeByteCount * rate) <= available) {
					return {
						totalFee: available,
						transactionByteCount: noChangeByteCount
					};
				}
			}
			// Without a change address staged, the builder adds dust to the fee.
			return {
				totalFee: pricesChange
					? fee
					: fee + droppedDust({ transaction, inputs, fee, wallet }),
				transactionByteCount: byteCount
			};
		};
		const atRate = quoteAt(satsPerByte);
		transactionByteCount = atRate.transactionByteCount;
		let maxSatPerByte = maxSatsPerByte(transactionByteCount, txBalance);
		// updateFee refuses a fee of exactly half the balance. A rate that drops
		// the change output pays only the leftover, which is under half. A
		// lower rate can also select fewer coins than this quote did.
		const feeAt = (rate: number, generatesChange = true): number => {
			if (!selectsCoins) return quoteAt(rate).totalFee;
			const key = `${rate}:${generatesChange}`;
			let fee = selectedFees.get(key);
			if (fee === undefined) {
				fee = estimateFee({
					satsPerByte: rate,
					message,
					transaction,
					fundingLightning,
					coinSelectPreference,
					generatesChange,
					wallet
				});
				selectedFees.set(key, fee);
			}
			return fee;
		};
		// The highest rate below `over` that fits.
		const highestFitting = (
			over: number,
			fits: (rate: number) => boolean
		): number => {
			let fit = 0;
			while (over - fit > 1) {
				const mid = Math.floor((fit + over) / 2);
				if (fits(mid)) fit = mid;
				else over = mid;
			}
			return fit;
		};
		// The highest rate below `over` whose fee is under half.
		const highestUnderHalf = (
			over: number,
			fee: (rate: number) => number
		): number => highestFitting(over, (rate) => fee(rate) < txBalance / 2);
		// A higher rate can select more coins than this quote did, so the
		// size-based maximum can be many rates over half. Coin selection only
		// adds coins as the rate rises, so the fee does not fall with it,
		// except where the leftover becomes dust and generated change goes.
		// The fee without generated change never falls and is never above the
		// real one, so the highest rate it fits at bounds the search. If that
		// rate still prices change, every lower rate where change goes is
		// already under half, and a plain search below it is safe.
		const fitUnderHalf = (rate: number): number => {
			if (!rate || feeAt(rate) < txBalance / 2) return rate;
			const withoutChange = (r: number): number => feeAt(r, false);
			const top =
				withoutChange(rate) < txBalance / 2
					? rate
					: highestUnderHalf(rate, withoutChange);
			return feeAt(top) < txBalance / 2 ? top : highestUnderHalf(top, feeAt);
		};
		maxSatPerByte = fitUnderHalf(maxSatPerByte);
		// updateFee refuses a fee the staged inputs cannot pay on top of the
		// outputs. A max send is exempt, since it sizes its output from the fee.
		// A rate that leaves no room for the change output drops it, so a
		// replacement, whose inputs are fixed, is capped on the size without it.
		if (transaction.boostType === EBoostType.rbf && !transaction.max) {
			const remaining = Math.max(0, inputAmount - outputAmount);
			maxSatPerByte = Math.min(
				maxSatPerByte,
				Math.floor(remaining / byteCountFor(false))
			);
		} else if (!transaction.max) {
			// An ordinary send can select more coins at a higher rate. A selection
			// that pays one rate pays every lower one too, so the rates the staged
			// inputs cover end at a single highest one.
			const stagedAmount = totalValue(
				transaction.inputs ?? [],
				'inputs',
				wallet
			);
			const covers = (rate: number): boolean =>
				outputAmount + feeAt(rate) <= stagedAmount;
			if (!covers(maxSatPerByte)) {
				maxSatPerByte = highestFitting(maxSatPerByte, covers);
			}
		}
		// Lowering the maximum can put the remainder above dust. The builder
		// then adds change, which needs its own fee. Below 2 sat/vB the size
		// floor can keep the remainder under dust, so size at the maximum.
		if (!pricesChange) {
			const changeAtMax = generatedChangeAddress({
				transaction,
				inputs,
				fee: Math.ceil(byteCountFor(false, maxSatPerByte) * maxSatPerByte),
				wallet
			});
			if (changeAtMax) {
				changeAddress = changeAtMax;
				pricesChange = true;
				maxSatPerByte = fitUnderHalf(
					Math.min(
						maxSatPerByte,
						maxSatsPerByte(byteCountFor(true, maxSatPerByte), txBalance)
					)
				);
			}
		}
		// The maximum is a whole rate, but updateFee takes any rate whose fee
		// fits its limits, so a fractional rate just past the maximum can too.
		const paysRequested =
			atRate.totalFee < txBalance / 2 &&
			(!!transaction.max || atRate.totalFee <= available);
		// Below 2 sat/vB the size floor can leave dust change that a higher
		// rate keeps, so a maximum above the request does not mean it fits.
		if (!paysRequested && maxSatPerByte >= satsPerByte) {
			maxSatPerByte = fitUnderHalf(Math.ceil(satsPerByte) - 1);
			if (!transaction.max && feeAt(maxSatPerByte) > available) {
				maxSatPerByte = highestFitting(
					maxSatPerByte,
					(rate) => feeAt(rate) <= available
				);
			}
		}
		if (maxSatPerByte < satsPerByte && !paysRequested) {
			// quoteAt prices the coins selected at the requested rate. The capped
			// rate can select fewer, and their change can be dust.
			if (selectsCoins && maxSatPerByte) {
				const atMax = quote(
					{
						satsPerByte: maxSatPerByte,
						message,
						transaction,
						fundingLightning,
						coinSelectPreference,
						wallet
					},
					selectedFees
				);
				if (atMax.isErr()) return atMax;
				return ok({
					totalFee: atMax.value.totalFee,
					transactionByteCount: atMax.value.transactionByteCount,
					satsPerByte: maxSatPerByte,
					maxSatPerByte
				});
			}
			const capped = quoteAt(maxSatPerByte);
			return ok({
				totalFee: capped.totalFee,
				transactionByteCount: maxSatPerByte ? capped.transactionByteCount : 0,
				satsPerByte: maxSatPerByte,
				maxSatPerByte
			});
		}
		return ok({
			totalFee: atRate.totalFee,
			transactionByteCount,
			satsPerByte,
			maxSatPerByte
		});
	} catch (e) {
		return err(e);
	}
};
