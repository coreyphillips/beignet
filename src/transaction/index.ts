import type {
	ICoinSelectResponse,
	IOutput,
	ISendTransaction,
	IUtxo,
	TGetTotalFeeObj
} from '../types';
import {
	EAddressType,
	EBoostType,
	ECoinSelectPreference,
	EFeeId
} from '../types';
import { getDefaultSendTransaction } from '../shapes';
import type { Wallet } from '../wallet';
import type { Result } from '../utils';
import {
	ok,
	err,
	EWalletErrorCode,
	validateTransaction,
	getTapRootAddressFromPublicKey,
	isP2trPrefix
} from '../utils';
import { getBitcoinJsNetwork, reduceValue, shuffleArray } from '../utils';
import { btcToSats } from '../utils/conversion';
import { derivePathCached } from '../utils/derive-path-cached';
import { TRANSACTION_DEFAULTS } from '../wallet/constants';
import { liveWalletData } from '../wallet/live-data';
import {
	createOpReturnScript,
	getDustThreshold,
	setReplaceByFee
} from '../utils';
import type {
	IAddInput,
	ICreateTransaction,
	ISetupTransaction,
	ITargets,
	TSetupTransactionResponse
} from '../types';
import type { Psbt } from 'bitcoinjs-lib';
import type { BIP32Interface } from 'bip32';
import { ecc } from '../utils/ecc';
import * as bitcoin from 'bitcoinjs-lib';
import { getAddressInfo } from 'bitcoin-address-validation';
import type { ECPairInterface } from 'ecpair';
import { toXOnly } from 'bitcoinjs-lib/src/psbt/bip371';
import type { IPricingWallet, TMultisigWeights } from './pricing';
import {
	estimateFee,
	maxSatsPerByte,
	quoteTransaction,
	selectCoins
} from './pricing';

bitcoin.initEccLib(ecc);

/**
 * The staged send lives in memory only and is never written to wallet
 * storage. Nothing reads a stored copy, and one has replayed recipients after
 * a restart (#1002) and leaked swept key pairs (#1011).
 */
export class Transaction {
	private _data: ISendTransaction;
	private readonly _wallet: Wallet;

	constructor({ wallet }: { wallet: Wallet }) {
		this._wallet = wallet;
		this._data = getDefaultSendTransaction();
	}

	public get data(): ISendTransaction {
		return this._data;
	}

	/**
	 * Sets up a transaction for a given wallet by gathering inputs, setting the next available change address as an output and sets up the baseline fee structure.
	 * This function will not override previously set transaction data. To do that you'll need to call resetSendTransaction.
	 * Outputs come only from the outputs argument, so a restart cannot replay
	 * an earlier call's recipients (#1002).
	 * @param {string[]} [inputTxHashes] Errs when none of them has a spendable UTXO.
	 * @param {IUtxo[]} [utxos]
	 * @param {boolean} [rbf]
	 * @param {number} [satsPerByte]
	 * @param {IUtxo[]} [outputs]
	 * @returns {Promise<Result<Partial<ISendTransaction>>>}
	 */
	public async setupTransaction({
		inputTxHashes,
		utxos,
		rbf = false,
		satsPerByte = 1,
		outputs
	}: ISetupTransaction = {}): Promise<TSetupTransactionResponse> {
		try {
			const addressType = this._wallet.addressType;

			const currentWallet = liveWalletData(this._wallet);

			// The live staged send, never currentWallet.transaction: that is the
			// copy loaded from storage at boot, and nothing updates it after.
			const transaction = this._data;

			// Gather required inputs. Frozen (blacklisted) UTXOs are excluded
			// from every wallet-driven selection path; only an explicit utxos
			// argument (internal RBF/CPFP flows) bypasses the filter.
			let inputs: IUtxo[] = [];
			if (inputTxHashes) {
				// If specified, filter for the desired tx_hash and push the utxo as an input.
				inputs = this.removeBlackListedUtxos(
					currentWallet.utxos.filter((utxo) => {
						return inputTxHashes.includes(utxo.tx_hash);
					})
				);
				// The fallback below would spend every coin in the wallet instead.
				// For a CPFP that is a full-wallet self-send at the boost rate,
				// which need not even descend from the parent (#1026).
				if (!inputs.length) {
					return err(
						`No spendable UTXOs found for the requested transactions: ${inputTxHashes.join(
							', '
						)}.`
					);
				}
			} else if (utxos) {
				inputs = utxos;
			} else {
				inputs = this.removeBlackListedUtxos(currentWallet.utxos);
			}

			if (!inputs.length) {
				// If inputs were previously selected, leave them.
				if (transaction.inputs.length > 0) {
					inputs = transaction.inputs;
				} else {
					// Otherwise, lets use our available utxo's.
					inputs = this.removeBlackListedUtxos(currentWallet.utxos);
				}
			}

			if (!inputs.length) {
				return err('No inputs specified in setupTransaction.');
			}

			const changeAddressIndexContent =
				currentWallet.changeAddressIndex[addressType];
			// Set the current change address.
			const changeAddress = changeAddressIndexContent.address;
			if (!changeAddress) {
				return err('Unable to successfully generate a change address.');
			}

			const lightningInvoice = transaction.lightningInvoice;

			// Only the caller's outputs are staged. Seeding them from the stored
			// copy replayed a persisted multi-recipient send into every later
			// send after a restart (#1002).
			outputs = outputs ?? [];
			if (!lightningInvoice) {
				//Remove any potential change address that may have been included from a previous tx attempt.
				outputs = outputs.filter((output) => {
					return !!(
						output.address && !this._wallet.isChangeAddress(output.address)
					);
				});
			}

			// Set the minimum fee.
			const fee = this.getTotalFee({
				satsPerByte,
				message: '',
				transaction: {
					...transaction,
					inputs,
					outputs
				}
			});

			const payload = {
				inputs,
				changeAddress,
				fee,
				outputs,
				rbf,
				satsPerByte
			};

			this._data = {
				...this._data,
				...payload
			};

			return ok(payload);
		} catch (e) {
			return err(e);
		}
	}

	public async applyAutoCoinSelect({
		coinSelectRes
	}: {
		coinSelectRes: ICoinSelectResponse;
	}): Promise<Result<ISendTransaction>> {
		const data = {
			...this._data,
			inputs: coinSelectRes.inputs
		};
		this._data = data;

		return ok(data);
	}

	/**
	 * This completely resets the send transaction state.
	 * @returns {Promise<Result<string>>}
	 */
	async resetSendTransaction(): Promise<Result<string>> {
		this._data = getDefaultSendTransaction();
		return ok('Transaction reset.');
	}

	/**
	 * Removes blacklisted UTXO's from the UTXO array.
	 * @param utxos
	 */
	removeBlackListedUtxos(utxos?: IUtxo[]): IUtxo[] {
		if (!utxos) {
			utxos = liveWalletData(this._wallet).utxos;
		}
		const blacklistedUtxos = liveWalletData(this._wallet).blacklistedUtxos;
		// Match by outpoint only: height changes when a frozen UTXO confirms
		// and must not silently unfreeze it.
		return utxos.filter((utxo) => {
			return !blacklistedUtxos.find(
				(blacklistedUtxo) =>
					utxo.tx_hash === blacklistedUtxo.tx_hash &&
					utxo.tx_pos === blacklistedUtxo.tx_pos
			);
		});
	}

	/**
	 * An address of the type getChangeAddress derives, for a wallet that has
	 * not set its change index yet. getChangeAddress derives one on the fly
	 * there and the builder pays change to it. The estimate only needs the
	 * output's size and dust threshold, which the script type alone sets, so
	 * an all-zero program stands in.
	 * @private
	 * @returns {string | undefined}
	 */
	private changeAddressStandIn(): string | undefined {
		const network = getBitcoinJsNetwork(this._wallet.network);
		const hash = Buffer.alloc(20);
		switch (this._wallet.addressType) {
			case EAddressType.p2wpkh:
				return bitcoin.payments.p2wpkh({ hash, network }).address;
			case EAddressType.p2sh:
				return bitcoin.payments.p2sh({ hash, network }).address;
			case EAddressType.p2pkh:
				return bitcoin.payments.p2pkh({ hash, network }).address;
			case EAddressType.p2wsh:
				return bitcoin.address.toBech32(Buffer.alloc(32), 0, network.bech32);
			case EAddressType.p2tr:
				return bitcoin.address.toBech32(Buffer.alloc(32), 1, network.bech32);
		}
	}

	/**
	 * What pricing reads from the wallet. A getter reads the wallet only when
	 * pricing asks, so a send with change staged never looks up the wallet's.
	 * @private
	 * @returns {IPricingWallet}
	 */
	private pricingWallet(): IPricingWallet {
		const wallet = this._wallet;
		const changeAddressStandIn = (): string | undefined =>
			this.changeAddressStandIn();
		return {
			get addressType(): EAddressType {
				return wallet.addressType;
			},
			get multisig(): TMultisigWeights | undefined {
				return wallet?.multisigInfo;
			},
			get changeAddress(): string | undefined {
				return (
					liveWalletData(wallet).changeAddressIndex[wallet.addressType]
						?.address || changeAddressStandIn()
				);
			},
			get logger(): IPricingWallet['logger'] {
				return wallet?.logger;
			}
		};
	}

	/**
	 * Attempt to estimate the current fee for a given transaction and its UTXO's
	 * @param {number} [satsPerByte]
	 * @param {string} [message]
	 * @param {Partial<ISendTransaction>} [transaction]
	 * @param {boolean} [fundingLightning]
	 * @param {ECoinSelectPreference} [coinSelectPreference]
	 * @param {boolean} [generatesChange] Prices what the builder does with the leftover when no change address is staged: a change output, or dust added to the fee.
	 * @returns {number} The fee priceTransaction prices, or 256 vB at the rate when it cannot price the transaction.
	 */
	getTotalFee = ({
		satsPerByte,
		message = '',
		transaction = this.data,
		fundingLightning = false,
		coinSelectPreference = this._wallet.coinSelectPreference,
		generatesChange = true
	}: {
		satsPerByte: number;
		message?: string;
		transaction?: Partial<ISendTransaction>;
		fundingLightning?: boolean;
		coinSelectPreference?: ECoinSelectPreference;
		generatesChange?: boolean;
	}): number =>
		estimateFee({
			satsPerByte,
			message,
			transaction,
			fundingLightning,
			coinSelectPreference,
			generatesChange,
			wallet: this.pricingWallet()
		});

	/**
	 * Attempt to estimate the current fee for a given transaction and its UTXO's
	 * @param {number} [amount]
	 * @param {number} [satsPerByte]
	 * @param {string} [message]
	 * @param {Partial<ISendTransaction>} [transaction]
	 * @param {boolean} [fundingLightning]
	 * @returns {Result<TGetTotalFeeObj>}
	 */
	getTotalFeeObj = ({
		satsPerByte = this._wallet.feeEstimates.normal,
		transaction = this.data,
		// updateFee prices the staged message, so the quote must too.
		message = transaction.message ?? '',
		fundingLightning = false,
		coinSelectPreference = this._wallet.coinSelectPreference
	}: {
		satsPerByte?: number;
		message?: string;
		transaction?: Partial<ISendTransaction>;
		fundingLightning?: boolean;
		coinSelectPreference?: ECoinSelectPreference;
	} = {}): Result<TGetTotalFeeObj> => {
		try {
			// With no inputs, price the transaction against every spendable UTXO, as
			// setupTransaction would gather them, but in memory. Staging them here
			// would replace the caller's staged outputs.
			if (!transaction.inputs?.length) {
				transaction = {
					...transaction,
					inputs: this.removeBlackListedUtxos(
						liveWalletData(this._wallet).utxos
					),
					changeAddress:
						transaction.changeAddress ||
						liveWalletData(this._wallet).changeAddressIndex[
							this._wallet.addressType
						]?.address
				};
			}
			return quoteTransaction({
				satsPerByte,
				message,
				transaction,
				fundingLightning,
				coinSelectPreference,
				wallet: this.pricingWallet()
			});
		} catch (e) {
			return err(e);
		}
	};

	/**
	 * Returns the maximum fee rate, in sat/vB, that can be used for a given transaction.
	 * @param {number} transactionByteCount
	 * @param {number} [balance]
	 * @returns {number}
	 */
	getMaxSatsPerByte = ({
		transactionByteCount,
		balance = this._wallet.getBalance()
	}: {
		transactionByteCount: number;
		balance?: number;
	}): number => maxSatsPerByte(transactionByteCount, balance);

	/**
	 * Creates complete signed transaction using the transaction data store
	 * @param {ISendTransaction} [transactionData]
	 * @param {boolean} [shuffleOutputs]
	 * @param {coinSelectPreference} [ECoinSelectPreference]
	 * @param {boolean} [spendFrozen] Signs staged inputs that are frozen, for a caller that froze them to reserve them for this send.
	 * @returns {Promise<Result<{id: string, hex: string}>>}
	 */
	createTransaction = async ({
		transactionData = this.data,
		shuffleOutputs = true,
		runCoinSelect = false,
		spendFrozen = false
	}: ICreateTransaction = {}): Promise<Result<{ id: string; hex: string }>> => {
		let transaction = transactionData;
		if (runCoinSelect) {
			const coinSelectRes = this.autoCoinSelect({
				inputs: transactionData.inputs,
				outputs: transactionData.outputs,
				satsPerByte: transactionData.satsPerByte,
				changeAddress: transactionData.changeAddress,
				message: transactionData.message,
				coinSelectPreference: this._wallet.coinSelectPreference
			});
			if (coinSelectRes.isErr()) {
				return err(coinSelectRes.error);
			}
			const coinSelectApplyRes = await this.applyAutoCoinSelect({
				coinSelectRes: coinSelectRes.value
			});
			if (coinSelectApplyRes.isErr()) {
				return err(coinSelectApplyRes.error);
			}
			transaction = {
				...coinSelectApplyRes.value,
				outputs: transactionData.outputs
			};
		}

		const inputValue = this.getTransactionInputValue({
			inputs: transaction.inputs
		});
		const outputValue = this.getTransactionOutputValue({
			outputs: transaction.outputs
		});
		if (inputValue === 0) {
			const message = 'No inputs to spend.';
			return err(message);
		}

		// Staging leaves frozen coins out, but a coin frozen since stays staged
		// until something restages, and sendMax turning max off does not.
		if (!spendFrozen) {
			const frozen = transaction.inputs.find((input) =>
				this._wallet.isUtxoFrozen({ txid: input.tx_hash, vout: input.tx_pos })
			);
			if (frozen) {
				return err(
					`Staged input ${frozen.tx_hash}:${frozen.tx_pos} is frozen.`
				);
			}
		}

		const fee = inputValue - outputValue;

		//Refuse tx if the fee is greater than the amount we're attempting to send.
		if (fee > inputValue) {
			const message = 'Fee is larger than the intended payment.';
			return err(message);
		}

		const validateRes = validateTransaction(transaction);
		if (validateRes.isErr()) return err(validateRes.error);

		try {
			const bip32InterfaceRes = await this._wallet.getBip32Interface();
			if (bip32InterfaceRes.isErr()) {
				return err(bip32InterfaceRes.error);
			}
			// The build fills it and the signer reads it, so each input's key is
			// derived once.
			const keys = new Map<string, BIP32Interface>();

			//Create PSBT before signing inputs
			const psbtRes = await this.createPsbtFromTransactionData({
				transactionData: transaction,
				bip32Interface: bip32InterfaceRes.value,
				shuffleTargets: shuffleOutputs,
				keys
			});

			if (psbtRes.isErr()) {
				return err(psbtRes.error);
			}

			const psbt = psbtRes.value;

			// A freeze can land while the awaits above derive keys and load
			// prevouts, so check what is about to be signed. No await may sit
			// between this check and signPsbt.
			if (!spendFrozen) {
				for (const { hash, index } of psbt.txInputs) {
					const txid = Buffer.from(hash).reverse().toString('hex');
					if (this._wallet.isUtxoFrozen({ txid, vout: index })) {
						return err(`Staged input ${txid}:${index} is frozen.`);
					}
				}
			}

			const signedPsbtRes = await this.signPsbt({
				psbt,
				bip32Interface: bip32InterfaceRes.value,
				keys
			});

			if (signedPsbtRes.isErr()) {
				return err(signedPsbtRes.error);
			}

			const tx = signedPsbtRes.value.extractTransaction();
			const id = tx.getId();
			const hex = tx.toHex();
			return ok({ id, hex });
		} catch (e) {
			return err(e);
		}
	};

	/**
	 * Returns total value of all utxos.
	 * @param {IUtxo[]} [inputs]
	 */
	getTransactionInputValue = ({ inputs }: { inputs?: IUtxo[] }): number => {
		try {
			if (!inputs) {
				const transaction = this.data;
				inputs = transaction.inputs;
			}
			if (inputs) {
				const response = reduceValue({ arr: inputs, value: 'value' });
				if (response.isOk()) {
					return response.value;
				}
				// 0 is also what an empty input set returns, so a failure here is
				// invisible to the caller. Say so rather than only returning it.
				this._wallet?.logger?.error(
					'Failed to total the transaction inputs.',
					response.error
				);
			}
			return 0;
		} catch (e) {
			this._wallet?.logger?.error('Failed to total the transaction inputs.', e);
			return 0;
		}
	};

	/**
	 * The key at an input's path, read from `keys` or derived into it along
	 * with the branch nodes above it.
	 * @param {BIP32Interface} root
	 * @param {string} path
	 * @param {Map<string, BIP32Interface>} keys Nodes derived from root only.
	 * @returns {BIP32Interface}
	 * @private
	 */
	private inputKey(
		root: BIP32Interface,
		path: string,
		keys: Map<string, BIP32Interface>
	): BIP32Interface {
		let key = keys.get(path);
		if (!key) {
			key = derivePathCached(root, path, keys);
			keys.set(path, key);
		}
		return key;
	}

	/**
	 * Loops through inputs and signs them
	 * @param {Psbt} psbt
	 * @param {BIP32Interface} bip32Interface
	 * @param {Map<string, BIP32Interface>} [keys] Keys createPsbtFromTransactionData derived from the same bip32Interface.
	 * @returns {Promise<Result<Psbt>>}
	 */
	signPsbt = async ({
		psbt,
		bip32Interface,
		keys = new Map()
	}: {
		psbt: Psbt;
		bip32Interface: BIP32Interface;
		keys?: Map<string, BIP32Interface>;
	}): Promise<Result<Psbt>> => {
		const transactionDataRes = this.data;

		const { inputs } = transactionDataRes;
		for (const [index, input] of inputs.entries()) {
			try {
				let keyPair = input?.keyPair;
				if (!keyPair && input?.path) {
					keyPair = this.inputKey(bip32Interface, input.path, keys);
				}
				if (!keyPair) return err('Unable to derive keyPair.');
				if (isP2trPrefix(input.address)) {
					const tapRootAddress = getTapRootAddressFromPublicKey({
						publicKey: keyPair.publicKey,
						network: getBitcoinJsNetwork(this._wallet.network)
					});
					if (tapRootAddress.isErr()) return err(tapRootAddress.error);
					const childNodeXOnlyPubkey = tapRootAddress.value.internalPubkey;
					const tweakedChildNode = keyPair.tweak(
						bitcoin.crypto.taggedHash('TapTweak', childNodeXOnlyPubkey)
					);
					psbt.signInput(index, tweakedChildNode);
				} else {
					psbt.signInput(index, keyPair);
				}
			} catch (e) {
				return err(e);
			}
		}

		psbt.finalizeAllInputs();

		return ok(psbt);
	};

	/**
	 * Returns a PSBT that includes unsigned funding inputs.
	 * @param {ISendTransaction} transactionData
	 * @param {BIP32Interface} bip32Interface
	 * @param shuffleTargets
	 * @param {Map<string, BIP32Interface>} [keys] Filled with the input keys derived from bip32Interface, for signPsbt to reuse.
	 * @returns {Promise<Result<Psbt>>}
	 */
	createPsbtFromTransactionData = async ({
		transactionData,
		bip32Interface,
		shuffleTargets = true,
		keys = new Map()
	}: {
		transactionData: ISendTransaction;
		bip32Interface?: BIP32Interface;
		shuffleTargets?: boolean;
		keys?: Map<string, BIP32Interface>;
	}): Promise<Result<Psbt>> => {
		const { inputs, outputs, fee, rbf, message } = transactionData;
		let { changeAddress } = transactionData;

		//Get balance of current inputs.
		const balance = this.getTransactionInputValue({
			inputs
		});

		//Get value of current outputs.
		const outputValue = this.getTransactionOutputValue({
			outputs
		});

		// The built transaction pays whatever the outputs leave over, so a staged
		// fee the inputs cannot cover would be silently cut, possibly below the
		// relay floor. addOutput and removeTxInput do not reprice the fee.
		if (outputValue + fee > balance) {
			return err(
				`Inputs of ${balance} sats cannot cover outputs of ${outputValue} sats plus the staged fee of ${fee} sats.`
			);
		}

		const network = getBitcoinJsNetwork(this._wallet.network);

		//Collect all outputs.
		let targets: ITargets[] = outputs.concat();

		//Change address and amount to send back to wallet.
		if (changeAddress) {
			const changeAddressValue = balance - (outputValue + fee);
			// Change below its own script's dust threshold would not relay, so it
			// goes to the fee. The flat 546 is only P2PKH's threshold and gave
			// away relayable segwit change.
			if (changeAddressValue >= getDustThreshold(changeAddress)) {
				targets.push({
					address: changeAddress,
					value: changeAddressValue,
					index: targets.length
				});
			}
			// Looks like we don't need a change address.
			// Double check we don't have any spare sats hanging around.
		} else if (outputValue + fee < balance) {
			// The threshold depends on the change script, so fetch the address
			// before deciding whether the spare sats are worth an output.
			const diffValue = balance - (outputValue + fee);
			const changeAddressRes = await this._wallet.getChangeAddress();
			if (changeAddressRes.isErr()) {
				return err(changeAddressRes.error);
			}
			if (diffValue >= getDustThreshold(changeAddressRes.value.address)) {
				changeAddress = changeAddressRes.value.address;
				targets.push({
					address: changeAddress,
					value: diffValue,
					index: targets.length
				});
			}
		}

		//Embed any OP_RETURN messages. getByteCount prices this same script, so
		//the padding and push rules live in one place.
		const opReturnScript = createOpReturnScript(message);
		if (opReturnScript) {
			targets.push({
				script: opReturnScript,
				value: 0,
				index: targets.length
			});
		}

		// Watch-only wallets cannot produce a signing root; inputs only need
		// public keys here, which derivePublicNode provides in both modes.
		if (!bip32Interface && !this._wallet.isWatchOnly) {
			const bip32InterfaceRes = await this._wallet.getBip32Interface();
			if (bip32InterfaceRes.isErr()) {
				return err(bip32InterfaceRes.error);
			}
			bip32Interface = bip32InterfaceRes.value;
		}

		const root = bip32Interface;
		const psbt = new bitcoin.Psbt({ network });
		const prevTxs = await this.fetchPrevTxs(inputs);

		//Add Inputs from inputs array
		try {
			for (const input of inputs) {
				if (this._wallet.isMultisig) {
					// Multisig inputs are built from the sortedmulti script, not a
					// single key pair (watch-only multisig has no derivable key).
					const addRes = await this.addInput({ psbt, input, prevTxs });
					if (addRes.isErr()) return err(addRes.error);
					continue;
				}
				let keyPair: BIP32Interface | ECPairInterface | undefined =
					input?.keyPair;
				if (!keyPair && input?.path) {
					if (root) {
						keyPair = this.inputKey(root, input.path, keys);
					} else {
						const publicNodeRes = this._wallet.derivePublicNode(input.path);
						if (publicNodeRes.isErr()) {
							return err(publicNodeRes.error);
						}
						keyPair = publicNodeRes.value;
					}
				}
				if (!keyPair) {
					return err('Unable to derive keyPair.');
				}
				const addRes = await this.addInput({
					psbt,
					keyPair,
					input,
					prevTxs
				});
				if (addRes.isErr()) return err(addRes.error);
			}
		} catch (e) {
			return err(e);
		}

		//Set RBF if supported and prompted via rbf in Settings.
		setReplaceByFee({ psbt, setRbf: !!rbf });

		// Shuffle targets if not run from unit test and add outputs.
		if (shuffleTargets) {
			targets = shuffleArray(targets);
		}

		targets.forEach((target) => {
			//Check if OP_RETURN
			let isOpReturn = false;
			try {
				isOpReturn = !!target.script;
			} catch (e) {}
			if (isOpReturn) {
				if (target.script) {
					psbt.addOutput({
						script: target.script,
						value: target.value ?? 0
					});
				}
			} else {
				if (target.address && target.value) {
					psbt.addOutput({
						address: target.address,
						value: target.value
					});
				}
			}
		});

		return ok(psbt);
	};

	/**
	 * Builds an UNSIGNED PSBT from the current (or provided) transaction data
	 * and attaches the metadata an external signer needs
	 * (bip32Derivation/tapBip32Derivation). Mirrors createTransaction but
	 * stops before signing.
	 * @param {ISendTransaction} [transactionData]
	 * @param {boolean} [shuffleOutputs]
	 * @param {boolean} [spendFrozen] Keeps staged inputs that are frozen, for a caller that froze them to reserve them for this send.
	 * @returns {Promise<Result<Psbt>>}
	 */
	createUnsignedPsbt = async ({
		transactionData = this.data,
		shuffleOutputs = true,
		spendFrozen = false
	}: {
		transactionData?: ISendTransaction;
		shuffleOutputs?: boolean;
		spendFrozen?: boolean;
	} = {}): Promise<Result<Psbt>> => {
		const inputValue = this.getTransactionInputValue({
			inputs: transactionData.inputs
		});
		const outputValue = this.getTransactionOutputValue({
			outputs: transactionData.outputs
		});
		if (inputValue === 0) {
			return err('No inputs to spend.');
		}
		const fee = inputValue - outputValue;
		if (fee > inputValue) {
			return err('Fee is larger than the intended payment.');
		}

		const validateRes = validateTransaction(transactionData);
		if (validateRes.isErr()) return err(validateRes.error);

		try {
			const psbtRes = await this.createPsbtFromTransactionData({
				transactionData,
				shuffleTargets: shuffleOutputs
			});
			if (psbtRes.isErr()) return err(psbtRes.error);
			const psbt = psbtRes.value;
			const metadataRes = this.addSignerMetadata({
				psbt,
				inputs: transactionData.inputs
			});
			if (metadataRes.isErr()) return err(metadataRes.error);
			const changeRes = await this.addChangeOutputMetadata(psbt);
			if (changeRes.isErr()) return err(changeRes.error);
			// A coin frozen since staging, or during the awaits above, must not
			// reach an external signer. No await may sit between this and return.
			if (!spendFrozen) {
				for (const { hash, index } of psbt.txInputs) {
					const txid = Buffer.from(hash).reverse().toString('hex');
					if (this._wallet.isUtxoFrozen({ txid, vout: index })) {
						return err(`Staged input ${txid}:${index} is frozen.`);
					}
				}
			}
			return ok(psbt);
		} catch (e) {
			return err(e);
		}
	};

	/**
	 * Attaches the key derivation (and redeemScript, witnessScript or
	 * tapInternalKey) to every output paying one of this wallet's change
	 * addresses. A hardware signer shows an output it cannot derive as a
	 * payment, so without this the change looks like a second recipient and
	 * a change output rewritten in transit looks no different.
	 * @param {Psbt} psbt
	 * @returns {Promise<Result<string>>}
	 * @private
	 */
	private async addChangeOutputMetadata(psbt: Psbt): Promise<Result<string>> {
		try {
			const { changeAddresses, changeAddressIndex } = liveWalletData(
				this._wallet
			);
			const changePaths = new Map<string, string>();
			for (const addresses of Object.values(changeAddresses)) {
				for (const { address, path } of Object.values(addresses ?? {})) {
					changePaths.set(address, path);
				}
			}
			for (const { address, path } of Object.values(changeAddressIndex)) {
				if (address && path) changePaths.set(address, path);
			}
			// A wallet that has not set a type's change index yet gets that
			// type's change address generated on the fly, and neither map above
			// holds it.
			for (const type of this._wallet.addressTypesToMonitor) {
				const fallbackRes = await this._wallet.getChangeAddress(type);
				if (fallbackRes.isErr()) return err(fallbackRes.error);
				changePaths.set(fallbackRes.value.address, fallbackRes.value.path);
			}
			const network = getBitcoinJsNetwork(this._wallet.network);
			const masterFingerprint = this._wallet.getMasterFingerprint();
			psbt.txOutputs.forEach((output, index) => {
				const path = changePaths.get(output.address ?? '');
				if (!output.address || !path) return;
				const mismatch = new Error(
					`Change output ${index} does not match the key at ${path}.`
				);
				const { type } = getAddressInfo(output.address);
				if (type === 'p2wsh') {
					const paymentRes = this._wallet.getMultisigPayment(path);
					if (paymentRes.isErr()) throw paymentRes.error;
					if (!paymentRes.value.output.equals(output.script)) throw mismatch;
					psbt.updateOutput(index, {
						witnessScript: paymentRes.value.witnessScript,
						bip32Derivation: paymentRes.value.derivations
					});
					return;
				}
				const publicNodeRes = this._wallet.derivePublicNode(path);
				if (publicNodeRes.isErr()) throw publicNodeRes.error;
				const pubkey = publicNodeRes.value.publicKey;
				const originPath = this._wallet.mapPathToKeyOrigin(path);
				if (type === 'p2tr') {
					const p2tr = getTapRootAddressFromPublicKey({
						publicKey: pubkey,
						network
					});
					if (p2tr.isErr()) throw new Error(p2tr.error.message);
					if (!p2tr.value.output.equals(output.script)) throw mismatch;
					psbt.updateOutput(index, {
						tapInternalKey: p2tr.value.internalPubkey,
						tapBip32Derivation: [
							{
								masterFingerprint,
								path: originPath,
								pubkey: toXOnly(pubkey),
								leafHashes: []
							}
						]
					});
					return;
				}
				const p2wpkh = bitcoin.payments.p2wpkh({ pubkey, network });
				const payment =
					type === 'p2sh'
						? bitcoin.payments.p2sh({ redeem: p2wpkh, network })
						: type === 'p2pkh'
						? bitcoin.payments.p2pkh({ pubkey, network })
						: p2wpkh;
				if (!payment.output?.equals(output.script)) throw mismatch;
				psbt.updateOutput(index, {
					...(type === 'p2sh' ? { redeemScript: p2wpkh.output } : {}),
					bip32Derivation: [{ masterFingerprint, path: originPath, pubkey }]
				});
			});
			return ok('Change output metadata added.');
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Attaches bip32Derivation (tapBip32Derivation for p2tr) to each PSBT
	 * input so external signers can locate their keys. PSBT inputs are added
	 * in the order of the inputs array, so indexes line up.
	 * @param {Psbt} psbt
	 * @param {IUtxo[]} inputs
	 * @returns {Result<string>}
	 * @private
	 */
	private addSignerMetadata({
		psbt,
		inputs
	}: {
		psbt: Psbt;
		inputs: IUtxo[];
	}): Result<string> {
		try {
			if (this._wallet.isMultisig) {
				// Multisig inputs carry one bip32Derivation entry PER COSIGNER so
				// every signer can locate its key.
				inputs.forEach((input, index) => {
					if (!input.path) return;
					const paymentRes = this._wallet.getMultisigPayment(input.path);
					if (paymentRes.isErr()) throw paymentRes.error;
					psbt.updateInput(index, {
						bip32Derivation: paymentRes.value.derivations
					});
				});
				return ok('Signer metadata added.');
			}
			const masterFingerprint = this._wallet.getMasterFingerprint();
			inputs.forEach((input, index) => {
				// External inputs (e.g. swept keys) have no wallet path; an
				// external signer cannot be pointed at them.
				if (!input.path) return;
				let pubkey: Buffer | undefined;
				if (input.publicKey) {
					pubkey = Buffer.from(input.publicKey, 'hex');
				} else if (input.keyPair) {
					pubkey = input.keyPair.publicKey;
				} else {
					const publicNodeRes = this._wallet.derivePublicNode(input.path);
					if (publicNodeRes.isErr()) throw publicNodeRes.error;
					pubkey = publicNodeRes.value.publicKey;
				}
				// Watch-only wallets with a supplied key origin pair the master
				// fingerprint with the path that master actually derives.
				const originPath = this._wallet.mapPathToKeyOrigin(input.path);
				if (isP2trPrefix(input.address)) {
					psbt.updateInput(index, {
						tapBip32Derivation: [
							{
								masterFingerprint,
								path: originPath,
								pubkey: toXOnly(pubkey),
								leafHashes: []
							}
						]
					});
				} else {
					psbt.updateInput(index, {
						bip32Derivation: [
							{
								masterFingerprint,
								path: originPath,
								pubkey
							}
						]
					});
				}
			});
			return ok('Signer metadata added.');
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Fetches the raw previous transaction of every input that attaches one
	 * (all but p2tr) in one batched lookup rather than a round trip per input,
	 * once per distinct parent. Answers are keyed by the txid Electrum tags
	 * them with, since a batch may be answered in any order.
	 * @param {IUtxo[]} inputs
	 * @returns {Promise<Result<Map<string, string>>>} hex by txid
	 * @private
	 */
	private async fetchPrevTxs(
		inputs: IUtxo[]
	): Promise<Result<Map<string, string>>> {
		const txHashes = [
			...new Set(
				inputs
					.filter(({ address }) => !isP2trPrefix(address))
					.map(({ tx_hash }) => tx_hash)
			)
		].map((tx_hash) => ({ tx_hash }));
		const hexes = new Map<string, string>();
		if (!txHashes.length) return ok(hexes);
		try {
			const res = await this._wallet.electrum.getTransactions({ txHashes });
			if (res.isErr()) return err(res.error);
			for (const { data, result } of res.value.data) {
				if (data?.tx_hash && result?.hex) hexes.set(data.tx_hash, result.hex);
			}
			return ok(hexes);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Looks up the full previous transaction for a PSBT input, as a spreadable
	 * { nonWitnessUtxo } field. Segwit v0 signers postdating CVE-2020-14199
	 * (Ledger 2.x, Trezor >= 2.3.5) require non_witness_utxo alongside
	 * witness_utxo to verify input amounts. Returns {} when the backend
	 * cannot supply it (witness_utxo alone remains BIP 174-valid), so
	 * offline builds still succeed. Errs when the transaction it supplies
	 * contradicts the input (see checkPrevTx).
	 * @param {IUtxo} input
	 * @param {Buffer} script
	 * @param {Result<Map<string, string>>} prevTxs from fetchPrevTxs
	 * @returns {Result<{ nonWitnessUtxo: Buffer } | Record<string, never>>}
	 * @private
	 */
	private nonWitnessUtxoField(
		input: IUtxo,
		script: Buffer,
		prevTxs: Result<Map<string, string>>
	): Result<{ nonWitnessUtxo: Buffer } | Record<string, never>> {
		if (prevTxs.isErr()) return ok({});
		const hex = prevTxs.value.get(input.tx_hash);
		if (!hex) return ok({});
		const prevTxRes = this.checkPrevTx({ hex, input, script });
		if (prevTxRes.isErr()) return err(prevTxRes.error);
		return ok({ nonWitnessUtxo: prevTxRes.value });
	}

	/**
	 * Refuses a previous transaction unless it is the one the input spends and
	 * its output at tx_pos pays input.value to script. Fee and change are
	 * computed from input.value, which the server reported, but once
	 * non_witness_utxo is attached the signature commits to the value in this
	 * transaction. A server that under-reported a coin would otherwise get a
	 * valid transaction that pays the difference as fee.
	 * @param {string} hex
	 * @param {IUtxo} input
	 * @param {Buffer} script
	 * @returns {Result<Buffer>} the raw previous transaction
	 * @private
	 */
	private checkPrevTx({
		hex,
		input,
		script
	}: {
		hex: string;
		input: IUtxo;
		script: Buffer;
	}): Result<Buffer> {
		const outpoint = `${input.tx_hash}:${input.tx_pos}`;
		let prevTx: bitcoin.Transaction;
		try {
			prevTx = bitcoin.Transaction.fromHex(hex);
		} catch {
			return err(`Previous transaction for ${outpoint} could not be parsed.`);
		}
		if (prevTx.getId() !== input.tx_hash) {
			return err(`Previous transaction for ${outpoint} has a different txid.`);
		}
		const prevOut = prevTx.outs[input.tx_pos];
		if (!prevOut || !prevOut.script.equals(script)) {
			return err(`Output ${outpoint} does not pay this input's address.`);
		}
		if (prevOut.value !== input.value) {
			return err(
				`Output ${outpoint} holds ${prevOut.value} sats, not the ${input.value} the server reported.`
			);
		}
		return ok(Buffer.from(hex, 'hex'));
	}

	addInput = async ({
		psbt,
		keyPair,
		input,
		prevTxs
	}: IAddInput): Promise<Result<string>> => {
		try {
			const network = getBitcoinJsNetwork(this._wallet.network);
			const { type } = getAddressInfo(input.address);

			if (!input.value) {
				return err('No input provided.');
			}

			if (input.value < getDustThreshold(input.address)) {
				return err('Input value is below dust limit.');
			}

			// Use the provided input keyPair if available.
			if (input?.keyPair) {
				keyPair = input.keyPair;
			}

			prevTxs = prevTxs ?? (await this.fetchPrevTxs([input]));

			if (type === 'p2wsh') {
				// Sorted-multisig input: the witnessScript comes from the wallet's
				// multisig configuration, keyed by the input's BIP 48 path.
				const paymentRes = this._wallet.getMultisigPayment(input.path);
				if (paymentRes.isErr()) return err(paymentRes.error);
				const { address, output, witnessScript } = paymentRes.value;
				if (address !== input.address) {
					return err(
						`Multisig script for path ${input.path} does not produce address ${input.address}.`
					);
				}
				const prevTxRes = this.nonWitnessUtxoField(input, output, prevTxs);
				if (prevTxRes.isErr()) return err(prevTxRes.error);
				psbt.addInput({
					hash: input.tx_hash,
					index: input.tx_pos,
					witnessUtxo: {
						script: output,
						value: input.value
					},
					witnessScript,
					...prevTxRes.value
				});
				return ok('Success');
			}

			if (!keyPair) {
				return err('Unable to derive keyPair.');
			}

			if (type === 'p2wpkh') {
				const p2wpkh = bitcoin.payments.p2wpkh({
					pubkey: keyPair.publicKey,
					network
				});
				if (!p2wpkh?.output) {
					return err('p2wpkh.output is undefined.');
				}
				const prevTxRes = this.nonWitnessUtxoField(
					input,
					p2wpkh.output,
					prevTxs
				);
				if (prevTxRes.isErr()) return err(prevTxRes.error);
				psbt.addInput({
					hash: input.tx_hash,
					index: input.tx_pos,
					witnessUtxo: {
						script: p2wpkh.output,
						value: input.value
					},
					...prevTxRes.value
				});
			}

			if (type === 'p2sh') {
				const p2wpkh = bitcoin.payments.p2wpkh({
					pubkey: keyPair.publicKey,
					network
				});
				const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network });
				if (!p2sh?.output) {
					return err('p2sh.output is undefined.');
				}
				if (!p2sh?.redeem) {
					return err('p2sh.redeem.output is undefined.');
				}
				const prevTxRes = this.nonWitnessUtxoField(input, p2sh.output, prevTxs);
				if (prevTxRes.isErr()) return err(prevTxRes.error);
				psbt.addInput({
					hash: input.tx_hash,
					index: input.tx_pos,
					witnessUtxo: {
						script: p2sh.output,
						value: input.value
					},
					redeemScript: p2sh.redeem.output,
					...prevTxRes.value
				});
			}

			if (type === 'p2pkh') {
				const p2pkh = bitcoin.payments.p2pkh({
					pubkey: keyPair.publicKey,
					network
				});
				if (!p2pkh?.output) {
					return err('p2pkh.output is undefined.');
				}
				if (prevTxs.isErr()) return err(prevTxs.error);
				const hex = prevTxs.value.get(input.tx_hash);
				if (!hex) {
					return err(
						`Previous transaction for ${input.tx_hash}:${input.tx_pos} is unavailable.`
					);
				}
				const prevTxRes = this.checkPrevTx({
					hex,
					input,
					script: p2pkh.output
				});
				if (prevTxRes.isErr()) return err(prevTxRes.error);
				psbt.addInput({
					hash: input.tx_hash,
					index: input.tx_pos,
					nonWitnessUtxo: prevTxRes.value
				});
			}

			if (type === 'p2tr') {
				if (!keyPair && input?.path) {
					const bip32Interface = await this._wallet.getBip32Interface();
					if (bip32Interface.isErr()) return err(bip32Interface.error);
					keyPair = bip32Interface.value.derivePath(input.path);
				}
				if (!keyPair) return err('No keyPair provided for p2tr input.');
				const p2trAddress = getTapRootAddressFromPublicKey({
					publicKey: keyPair.publicKey,
					network
				});
				if (p2trAddress.isErr()) return err(p2trAddress.error);
				psbt.addInput({
					hash: input.tx_hash,
					index: input.tx_pos,
					witnessUtxo: {
						script: p2trAddress.value.output,
						value: input.value
					},
					tapInternalKey: p2trAddress.value.internalPubkey
				});
			}
			return ok('Success');
		} catch {
			return err('Unable to add input.');
		}
	};

	/**
	 * Adds external inputs to the current transaction.
	 * @param {IUtxo[]} inputs
	 * @param {BIP32Interface | ECPairInterface} keyPair
	 * @returns {Result<IUtxo[]>}
	 */
	public addExternalInputs({
		inputs,
		keyPair
	}: {
		inputs: IUtxo[];
		keyPair: BIP32Interface | ECPairInterface;
	}): Result<IUtxo[]> {
		if (!inputs || !inputs.length) return err('No inputs provided.');
		const transaction = this.data;
		const satsPerByte = transaction.satsPerByte;
		const newInputs = inputs.map((input) => {
			return {
				...input,
				keyPair
			};
		});
		const _inputs = [...transaction.inputs, ...newInputs];
		const feeInfo = this.getTotalFeeObj({
			satsPerByte,
			transaction: {
				...transaction,
				inputs: _inputs
			}
		});
		if (feeInfo.isErr()) return err(feeInfo.error);
		const feeUpdateRes = this.updateFee({
			satsPerByte,
			transaction: {
				...transaction,
				inputs: _inputs
			}
		});
		if (feeUpdateRes.isErr()) return err(feeUpdateRes.error);
		const updateSendRes = this.updateSendTransaction({
			transaction: {
				inputs: _inputs
			}
		});
		if (updateSendRes.isErr()) return err(updateSendRes.error);
		return ok(_inputs);
	}

	/**
	 * Adds an output at the specified index to the current transaction.
	 * @param {string} address
	 * @param {number} value
	 * @param {number} [index]
	 * @returns {IOutput}
	 */
	addOutput = async ({
		address,
		value,
		index = 0
	}: IOutput): Promise<Result<string>> => {
		const dustThreshold = getDustThreshold(address);
		if (value < dustThreshold) {
			return err(
				`Output value is below the dust threshold of ${dustThreshold} sats.`
			);
		}
		if (!this.data.inputs?.length) {
			const setupRes = await this.setupTransaction();
			if (setupRes.isErr()) return err(setupRes.error);
		}
		return this.updateSendTransaction({
			transaction: {
				outputs: [{ address, value, index }]
			}
		});
	};

	/**
	 * Returns total value of all outputs. Excludes any value that would be sent to the change address.
	 * @param {IOutput[]} [outputs]
	 * @returns {number}
	 */
	getTransactionOutputValue = ({
		outputs
	}: {
		outputs?: IOutput[];
	} = {}): number => {
		try {
			if (!outputs) {
				const transaction = this.data;
				outputs = transaction.outputs;
			}
			const response = reduceValue({ arr: outputs, value: 'value' });
			if (response.isOk()) {
				return response.value;
			}
			// See getTransactionInputValue: 0 is a legitimate total, so a silent 0
			// on failure is indistinguishable from an empty output set.
			this._wallet?.logger?.error(
				'Failed to total the transaction outputs.',
				response.error
			);
			return 0;
		} catch (e) {
			this._wallet?.logger?.error(
				'Failed to total the transaction outputs.',
				e
			);
			return 0;
		}
	};

	/**
	 * This updates the transaction state used for sending.
	 * @param {Partial<ISendTransaction>} transaction
	 * @return {Promise<Result<string>>}
	 */
	updateSendTransaction = ({
		transaction
	}: {
		transaction: Partial<ISendTransaction>;
	}): Result<string> => {
		try {
			//Add output if specified
			let { outputs } = transaction;
			if (outputs) {
				const staged = this._data.outputs.concat();
				outputs.forEach((output) => {
					//if (output.value > TRANSACTION_DEFAULTS.dustLimit)
					staged[output.index] = output;
				});
				outputs = staged;
			}

			this._data = {
				...this._data,
				...transaction,
				...(outputs && { outputs })
			};

			return ok('Transaction updated');
		} catch (e) {
			return err(e);
		}
	};

	/**
	 * Updates the fee for the current transaction by the specified amount.
	 * @param {number} [satsPerByte]
	 * @param {EFeeId} [selectedFeeId]
	 * @param {number} [index]
	 * @param {ISendTransaction} [transaction]
	 * @returns {Result<{ fee: number }>}
	 */
	public updateFee({
		satsPerByte,
		selectedFeeId = EFeeId.custom,
		index = 0,
		transaction = this.data
	}: {
		satsPerByte: number;
		selectedFeeId?: EFeeId;
		index?: number;
		transaction?: ISendTransaction;
	}): Result<{ fee: number }> {
		// setupRbf sets minFee no lower than the rate at which the replacement
		// outbids the original. Nodes reject anything under it.
		if (
			transaction.boostType === EBoostType.rbf &&
			satsPerByte < transaction.minFee
		) {
			return err(
				EWalletErrorCode.REPLACEMENT_FEE_TOO_LOW,
				`A replacement needs at least ${transaction.minFee} sats/vbyte to outbid the original transaction.`
			);
		}

		const inputTotal = this.getTransactionInputValue({
			inputs: transaction.inputs
		});

		const { max, message, outputs } = transaction;
		let address = '';
		if (outputs.length > index) {
			address = outputs[index]?.address ?? '';
		}

		// A replacement spends every input of the original, so coin selection
		// must not price a subset of them.
		const newFee = this.getTotalFee({
			satsPerByte,
			transaction,
			message,
			coinSelectPreference:
				transaction.boostType === EBoostType.rbf
					? ECoinSelectPreference.consolidate
					: undefined
		});

		//Return if the new fee exceeds half of the user's input balance
		if (newFee >= inputTotal / 2) {
			return err(
				EWalletErrorCode.FEE_EXCEEDS_HALF_INPUTS,
				'Unable to increase the fee any further. Otherwise, it will exceed half the current input balance.'
			);
		}

		const totalTransactionValue = this.getTransactionOutputValue({
			outputs
		});

		//Return if the new fee exceeds half of the user's output amount
		if (newFee >= totalTransactionValue / 2) {
			return err(
				EWalletErrorCode.FEE_EXCEEDS_HALF_OUTPUTS,
				'Unable to increase the fee any further. Otherwise, it will exceed half the current sending/output amount.'
			);
		}

		const newTotalAmount = totalTransactionValue + newFee;
		const _transaction: Partial<ISendTransaction> = {
			satsPerByte,
			fee: newFee,
			selectedFeeId
		};

		if (max) {
			// Update the tx value with the new fee to continue sending the max amount.
			_transaction.outputs = [{ address, value: inputTotal - newFee, index }];
		}

		// Check that the user has enough funds
		if (max || newTotalAmount <= inputTotal) {
			this.updateSendTransaction({
				transaction: _transaction
			});
			return ok({ fee: newFee });
		}

		return err(
			'New total amount exceeds the available balance. Unable to update the transaction fee.'
		);
	}

	/**
	 * Toggles the max amount to the provided output index.
	 * @param {string} [address] If left undefined, the current receiving address will be provided.
	 * @param {ISendTransaction} [transaction]
	 * @param {number} [index]
	 * @param satsPerByte
	 * @param rbf
	 * @param {boolean} [spendFrozen] Keeps staged inputs that are frozen, for a caller that froze them to reserve them for this send.
	 */
	sendMax = async ({
		address,
		transaction,
		index = 0,
		satsPerByte,
		rbf = false,
		spendFrozen = false
	}: {
		address?: string;
		transaction?: ISendTransaction;
		index?: number;
		satsPerByte?: number;
		rbf?: boolean;
		spendFrozen?: boolean;
	} = {}): Promise<Result<string>> => {
		try {
			if (!transaction) {
				transaction = this.data;
			}
			if (!transaction.inputs?.length) {
				const setupRes = await this.setupTransaction({ rbf });
				if (setupRes.isErr()) return err(setupRes.error);
				// Setup stages the inputs on a new _data, not on the transaction read
				// above. Only the inputs are taken, since setup also resets the staged
				// outputs and rate that the address and rate below fall back to.
				transaction = { ...transaction, inputs: this._data.inputs };
			}
			if (!satsPerByte) {
				satsPerByte = transaction?.satsPerByte ?? 1;
			}
			const outputs = transaction.outputs ?? [];
			// No address specified, attempt to assign the address currently specified in the current output index.
			if (!address) {
				address = outputs[index]?.address ?? '';
			}

			// setupTransaction leaves frozen coins out, but a coin frozen since is
			// still staged, and createTransaction signs what is staged.
			const unfrozen = (utxos: IUtxo[]): IUtxo[] =>
				spendFrozen ? utxos : this.removeBlackListedUtxos(utxos);
			const stagedInputs = transaction.inputs ?? [];
			const inputs = unfrozen(stagedInputs);
			if (stagedInputs.length && !inputs.length) {
				return err('Every staged input is frozen.');
			}

			// Priced as the one output staged below. With no outputs, getTotalFee
			// assumes one of the wallet's own type, which is 12 vB short for a p2wpkh
			// wallet sweeping to a p2tr or p2wsh address.
			const maxAmountResponse = this.getMaxSendAmount({
				satsPerByte,
				selectedFeeId: transaction.selectedFeeId,
				transaction: {
					...transaction,
					inputs,
					outputs: address ? [{ address, value: 0, index }] : []
				}
			});
			if (maxAmountResponse.isErr()) {
				return err(maxAmountResponse.error);
			}
			const { amount, fee } = maxAmountResponse.value;

			if (!transaction.max) {
				this.updateSendTransaction({
					transaction: {
						satsPerByte,
						max: true,
						inputs: unfrozen(this._data.inputs),
						outputs: [{ address, value: amount, index }],
						fee
					}
				});
			} else {
				this.updateSendTransaction({
					transaction: {
						max: false
					}
				});
			}

			return ok('Successfully setup max send transaction.');
		} catch (e) {
			return err(e);
		}
	};

	/**
	 * Calculates the max amount able to send for onchain/lightning
	 * @param {ISendTransaction} [transaction]
	 * @param {number} [index]
	 */
	//TODO: Double check the transactionSpeed and customFeeRate are being used correctly.
	estimateTransactionCosts = ({
		transaction,
		customFeeRate
	}: {
		transaction?: ISendTransaction;
		customFeeRate?: number;
	}): Result<{ amount: number; fee: number; satsPerByte: number }> => {
		try {
			if (!transaction) {
				transaction = this.data;
			}

			const currentWallet = liveWalletData(this._wallet);
			// The coins sendMax spends. The stored balance is not: it also counts
			// frozen coins.
			const spendableUtxos = this.removeBlackListedUtxos(currentWallet.utxos);
			const onchainBalance = this.getTransactionInputValue({
				inputs: spendableUtxos
			});

			// A coin frozen after it was staged is still among the inputs, and
			// sendMax restages without it.
			const stagedInputs = this.removeBlackListedUtxos(transaction.inputs);
			const inputValue = this.getTransactionInputValue({
				inputs: stagedInputs
			});
			const amount = onchainBalance > inputValue ? onchainBalance : inputValue;

			let utxos: IUtxo[] = [];
			//Ensure we add the larger utxo set for a more accurate fee.
			if (stagedInputs.length > spendableUtxos.length) {
				utxos = stagedInputs;
			} else {
				utxos = spendableUtxos;
			}
			const fees = this._wallet.feeEstimates;
			const selectedFeeId = this._wallet.selectedFeeId;
			const satsPerByte =
				customFeeRate ??
				(fees as Partial<Record<EFeeId, number>>)[selectedFeeId] ??
				1;
			const fee = this.getTotalFee({
				satsPerByte,
				message: transaction.message,
				transaction: {
					...transaction,
					max: true,
					inputs: utxos,
					selectedFeeId,
					satsPerByte
				}
			});

			if (amount <= fee) {
				return err(
					`An amount of ${amount} is too low to spend with an expected fee of ${fee} at ${satsPerByte} satsPerVByte.`
				);
			}

			const maxAmount = {
				amount: amount - fee,
				fee,
				satsPerByte
			};

			return ok(maxAmount);
		} catch (e) {
			return err(e);
		}
	};

	/**
	 * Calculates the max amount able to send for the provided/current onchain transaction.
	 * @param {number} satsPerByte
	 * @param {EFeeId} [selectedFeeId]
	 * @param {ISendTransaction} [transaction]
	 * @returns {Result<{ amount: number; fee?: number }>}
	 */
	getMaxSendAmount({
		satsPerByte,
		selectedFeeId = EFeeId.none,
		transaction = this.data
	}: {
		satsPerByte: number;
		selectedFeeId?: EFeeId;
		transaction?: ISendTransaction;
	}): Result<{ amount: number; fee: number }> {
		try {
			const inputValue = this.getTransactionInputValue({
				inputs: transaction.inputs
			});
			const amount = inputValue;

			const inputs = transaction.inputs ?? [];

			const fee = this.getTotalFee({
				satsPerByte,
				message: transaction.message,
				transaction: {
					...transaction,
					max: true,
					inputs,
					selectedFeeId,
					satsPerByte
				}
			});

			if (amount <= fee) {
				return err(
					`An amount of ${amount} is too low to spend with an expected fee of ${fee} at ${satsPerByte} satsPerVByte.`
				);
			}

			const maxAmount = {
				amount: amount - fee,
				fee
			};

			return ok(maxAmount);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Sets up a CPFP transaction.
	 * @param {string} [txid]
	 * @param {number} [satsPerByte]
	 */
	async setupCpfp({
		txid,
		satsPerByte
	}: {
		txid?: string; // txid of utxo to include in the CPFP tx. Undefined will gather all utxo's.
		satsPerByte?: number;
	}): Promise<Result<ISendTransaction>> {
		try {
			if (txid) {
				// canBoost only reads the height stored at the last refresh, and a
				// child of a parent that has since confirmed is a pointless self-send
				// at the boost rate. An unanswered lookup leaves that stored height as
				// the only gate, as before.
				const parentRes = await this._wallet.electrum.getTransactions({
					txHashes: [{ tx_hash: txid }]
				});
				const confirmations = parentRes.isOk()
					? parentRes.value.data[0]?.result?.confirmations ?? 0
					: 0;
				if (confirmations > 0) {
					return err('Transaction is already confirmed. Unable to CPFP.');
				}
			}
			let minFee = this._wallet.feeEstimates.fast;
			await this.resetSendTransaction();
			const setupTransactionRes = await this.setupTransaction({
				inputTxHashes: txid ? [txid] : undefined,
				rbf: this._wallet.rbf
			});
			if (setupTransactionRes.isErr()) {
				return err(setupTransactionRes.error);
			}
			const receiveAddress = await this._wallet.getReceiveAddress({});
			if (receiveAddress.isErr()) {
				return err(receiveAddress.error);
			}
			const child = {
				...this.data,
				...setupTransactionRes.value,
				boostType: EBoostType.cpfp
			};

			// try to calculate satsPerByte if not provided.
			// child + parent combined fee rate should be higher than fastest.
			// TODO: take all possible unconfirmed parent UTXOs into account.
			if (!satsPerByte && txid) {
				const parent = liveWalletData(this._wallet).transactions[txid];
				if (parent) {
					const parentVsize = parent.vsize;
					// The child spends every output of the parent that pays us, so it
					// is sized as the max send that sendMax prices below. Below 2
					// sat/vB getTotalFee can floor the size at 256 vB, so the size is
					// read at 2.
					const childVsize =
						this.getTotalFee({
							satsPerByte: 2,
							message: child.message,
							transaction: {
								...child,
								max: true,
								outputs: [{ address: receiveAddress.value, value: 0, index: 0 }]
							}
						}) / 2;
					const { fast, normal } = this._wallet.feeEstimates;
					// IFormattedTransaction.fee is denominated in BTC. Subtracting it
					// from a sat figure took roughly 0.00001 off where it meant to take
					// 1000, so the parent's paid fee was effectively ignored and the
					// child overpaid by that fee spread across its own vsize.
					const parentFeeSats = btcToSats(parent.fee);
					// A parent that already paid above the target rate can drive these
					// below 1 sat/vB, which is not a broadcastable rate.
					satsPerByte = Math.max(
						1,
						Math.ceil(
							(fast * (parentVsize + childVsize) - parentFeeSats) / childVsize
						)
					);
					minFee = Math.max(
						1,
						Math.ceil(
							(normal * (parentVsize + childVsize) - parentFeeSats) / childVsize
						)
					);
				}
			}

			// if we still don't have a satsPerByte, use 1.5x fastest.
			if (!satsPerByte) {
				satsPerByte = Math.ceil(this._wallet.feeEstimates.fast * 1.5);
			}

			const sendMaxRes = await this.sendMax({
				transaction: child,
				address: receiveAddress.value,
				satsPerByte,
				rbf: this._wallet.rbf
			});
			if (sendMaxRes.isErr()) {
				return err(sendMaxRes.error);
			}

			this.updateSendTransaction({ transaction: { minFee } });

			return ok(this.data);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Sets up a transaction for RBF.
	 * @param {string} txid
	 */
	async setupRbf({
		txid
	}: {
		txid: string;
	}): Promise<Result<ISendTransaction>> {
		try {
			await this.resetSendTransaction();
			const setupTransactionRes = await this.setupTransaction({
				rbf: true
			});
			if (setupTransactionRes.isErr()) {
				return err(setupTransactionRes.error);
			}

			const response = await this._wallet.fetchRbfData({ txid });
			if (response.isErr()) {
				return err(response.error);
			}
			const transaction = response.value;

			// filter out change address, otherwise getTransactionOutputValue will include it
			const outputs = transaction.outputs
				.filter((output) => output.address !== transaction.changeAddress)
				.map((output, index) => ({ ...output, index }));

			// getTotalFee prices the change output from changeAddress, so it is
			// given the outputs without it. The replacement spends every input of
			// the original, so coin selection must not price a subset of them.
			const priceAt = (rate: number): number =>
				this.getTotalFee({
					transaction: { ...transaction, outputs },
					satsPerByte: rate,
					message: transaction.message,
					coinSelectPreference: ECoinSelectPreference.consolidate
				});
			// Nodes only relay a replacement that pays the original fee plus its
			// own size at the incremental relay rate, and estimates can have
			// fallen below what the original paid. Below 2 sat/vB getTotalFee
			// floors the size at 256 vB, so the size is read at 2.
			const vsize = priceAt(2) / 2;
			const relayFloor = Math.ceil(
				(transaction.fee + vsize * TRANSACTION_DEFAULTS.incrementalRelayFee) /
					vsize
			);
			const minFee = Math.max(this._wallet.feeEstimates.slow, relayFloor);
			const satsPerByte = Math.max(this._wallet.feeEstimates.fast, minFee);
			const newFee = priceAt(satsPerByte);

			const inputTotal = this.getTransactionInputValue({
				inputs: transaction.inputs
			});
			// Ensure we have enough funds to perform an RBF transaction.
			const outputTotal = this.getTransactionOutputValue({
				outputs
			});
			// The relay floor is a rate on the size with change. A replacement that
			// drops its change pays the leftover, the same at every rate, on the
			// smaller size, so the leftover must outbid the original at that size.
			// A fee that keeps the change already clears this.
			const noChangeVsize =
				this.getTotalFee({
					transaction: { ...transaction, outputs, changeAddress: '' },
					satsPerByte: 2,
					message: transaction.message,
					coinSelectPreference: ECoinSelectPreference.consolidate,
					generatesChange: false
				}) / 2;
			const outbidsOriginal =
				newFee >=
				transaction.fee +
					noChangeVsize * TRANSACTION_DEFAULTS.incrementalRelayFee;

			// A replacement that drops its change pays the whole leftover as fee,
			// so its outputs and fee add up to exactly the inputs.
			if (
				outputTotal + newFee > inputTotal ||
				newFee >= inputTotal / 2 ||
				!outbidsOriginal
			) {
				/*
				 * We could always pull the fee from the output total,
				 * but this may negatively impact the transaction made by the user.
				 * (Ex: Reducing the amount paid to the recipient).
				 * We could always include additional unconfirmed utxo's to cover the fee as well,
				 * but this may negatively impact the user's privacy by including sensitive utxos.
				 * Instead of allowing either scenario, we attempt a CPFP instead.
				 */
				return err('Not enough sats to support an RBF transaction.');
			}
			const newTransaction: Partial<ISendTransaction> = {
				...transaction,
				outputs,
				minFee,
				fee: newFee,
				satsPerByte,
				rbf: true,
				boostType: EBoostType.rbf
			};

			this.updateSendTransaction({
				transaction: newTransaction
			});

			return ok(this.data);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Selects coins for transaction construction based on provided parameters.
	 * @param {IUtxo[]} inputs
	 * @param {IOutput[]} outputs
	 * @param {number} [satsPerByte]
	 * @param {string} [message]
	 * @param ECoinSelectPreference [coinSelectPreference]
	 */
	public autoCoinSelect({
		inputs = [],
		outputs = [],
		changeAddress,
		satsPerByte = 1,
		message = '',
		coinSelectPreference = ECoinSelectPreference.small
	}: {
		inputs: IUtxo[];
		outputs: IOutput[];
		changeAddress?: string;
		satsPerByte?: number;
		message?: string;
		coinSelectPreference?: ECoinSelectPreference;
	}): Result<ICoinSelectResponse> {
		// No wallet is needed: a Transaction with none attached still selects.
		return selectCoins({
			inputs,
			outputs,
			changeAddress,
			satsPerByte,
			message,
			coinSelectPreference,
			multisig: this._wallet?.multisigInfo
		});
	}
}
