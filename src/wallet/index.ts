import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';
import { Network } from 'bitcoinjs-lib';
import BIP32Factory, { BIP32Interface } from 'bip32';
import * as ecc from '@bitcoinerlab/secp256k1';
import cloneDeep from 'lodash.clonedeep';

import {
	EAddressType,
	EAvailableNetworks,
	EBoostType,
	ECoinSelectPreference,
	EFeeId,
	EPaymentType,
	EScanningStrategy,
	IAddress,
	IAddresses,
	IBalanceBreakdown,
	IBoostedTransaction,
	IBoostedTransactions,
	IBtInfo,
	IBuildPsbtArgs,
	IBuildPsbtResponse,
	IImportSignedPsbtResponse,
	ICanBoostResponse,
	ICustomGetAddress,
	ICustomGetScriptHash,
	IExportDescriptorsResponse,
	IExportedDescriptor,
	IFormattedTransaction,
	IFormattedTransactions,
	IGenerateAddresses,
	IGenerateAddressesResponse,
	IGetAddress,
	IGetAddressBalanceRes,
	IGetAddressByPath,
	IGetAddressesFromPrivateKey,
	IGetAddressResponse,
	IGetFeeEstimatesResponse,
	IGetNextAvailableAddressResponse,
	IGetUtxosResponse,
	IHeader,
	IKeyDerivationPath,
	IMultisigCosigner,
	IMultisigOptions,
	IMultisigWallet,
	InputData,
	IOnchainFees,
	IOutput,
	IPrivateKeyInfo,
	IRbfData,
	ISendTransaction,
	ISendTx,
	ISetupTransaction,
	ISweepPrivateKey,
	ISweepPrivateKeyRes,
	ITransaction,
	ITxHash,
	IUtxo,
	IVout,
	IWallet,
	IWalletData,
	IWatchOnlyWallet,
	Net,
	TAddressIndexInfo,
	TAddressLabels,
	TAddressTypeContent,
	TAvailableNetworks,
	TFeeEstimationSource,
	TGapLimitOptions,
	TGetData,
	TGetTotalFeeObj,
	Tls,
	TMessageDataMap,
	TOnMessage,
	TProcessUnconfirmedTransactions,
	TServer,
	TSetData,
	TSetupTransactionResponse,
	TTransactionMessage,
	TTxDetails,
	TTxResult,
	TUnspentAddressScriptHashData,
	TWalletDataKeys
} from '../types';
import {
	appendDescriptorChecksum,
	buildSortedMultisigPayment,
	clampFeeRate,
	decodeOpReturnMessage,
	err,
	filterAddressesObjForGapLimit,
	formatKeyDerivationPath,
	generateWalletId,
	getAddressesFromPrivateKey,
	getAddressFromKeyPair,
	getAddressIndexDiff,
	getAddressTypeFromPath,
	getDataFallback,
	getDefaultWalletData,
	getDefaultWalletDataKeys,
	getBitcoinJsNetwork,
	getElectrumNetwork,
	getHighestUsedIndexFromTxHashes,
	getKeyDerivationPath,
	getKeyDerivationPathObject,
	getKeyDerivationPathString,
	getScriptHash,
	getSeed,
	getWalletDataStorageKey,
	IKeyOrigin,
	isPositive,
	MultisigSpendError,
	normalizeKeyOrigin,
	objectKeys,
	objectsMatch,
	ok,
	parseBip48Path,
	parseExtendedPublicKey,
	removeDustUtxos,
	Result,
	shuffleArray,
	validateAddress,
	validateMnemonic,
	validatePsbtSignature,
	WatchOnlySigningError
} from '../utils';
import {
	addressTypes,
	defaultFeesShape,
	getAddressTypeContent,
	getAddressTypes
} from '../shapes';
import { Electrum } from '../electrum';
import { Transaction } from '../transaction';
import { GAP_LIMIT, GAP_LIMIT_CHANGE, TRANSACTION_DEFAULTS } from './constants';
import { btcToSats } from '../utils/conversion';
import { ILogger, createConsoleLogger } from '../logger';

const bip32 = BIP32Factory(ecc);

export class Wallet {
	private _network: EAvailableNetworks;
	private readonly _mnemonic?: string;
	private readonly _passphrase: string;
	private readonly _seed?: Buffer;
	private readonly _root?: BIP32Interface;
	// Account-level xpub node for watch-only wallets (no private keys).
	private readonly _accountNode?: BIP32Interface;
	// True key origin of the watch-only account xpub (master fingerprint +
	// path from that master), when the caller supplied it.
	private readonly _keyOrigin?: IKeyOrigin;
	// Sorted-multisig configuration: threshold + account-level PUBLIC nodes
	// for every cosigner (ours included when a mnemonic was provided), plus
	// each cosigner's true key origin when supplied.
	private readonly _multisig?: {
		threshold: number;
		cosigners: {
			node: BIP32Interface;
			isOurs: boolean;
			keyOrigin?: IKeyOrigin;
		}[];
	};
	private _data: IWalletData;
	private _getData: TGetData;
	private _setData?: TSetData;
	private _customGetAddress?: (
		data: ICustomGetAddress
	) => Promise<Result<IGetAddressResponse>>; // For use with Bitkit.
	private _customGetScriptHash?: (
		data: ICustomGetScriptHash
	) => Promise<string>; // For use with Bitkit.
	private _pendingRefreshPromises: Array<
		(result: Result<IWalletData>) => void
	> = [];
	private _disableMessagesOnCreate: boolean;
	// BIP32 account index as a path segment string ('0' by default).
	private readonly _account: string;
	// Requested at create time; merged with the stored value in setWalletData.
	private readonly _birthdayHeightOption?: number;

	public addressTypesToMonitor: EAddressType[];
	public coinSelectPreference: ECoinSelectPreference;
	public readonly isWatchOnly: boolean;
	public isRefreshing: boolean;
	public isSwitchingNetworks: boolean;
	public readonly id: string;
	public readonly name: string;
	public electrumOptions?: {
		net: Net;
		tls: Tls;
		servers?: TServer | TServer[];
		batchLimit?: number; // Maximum number of requests to be sent in a single batch
		batchDelay?: number; // Delay (in milliseconds) between each batch of requests
	};
	public electrum: Electrum;
	public addressType: EAddressType;
	public sendMessage: TOnMessage;
	public transaction: Transaction;
	public feeEstimates: IOnchainFees;
	public rbf: boolean;
	public selectedFeeId: EFeeId;
	public feeEstimationSource: TFeeEstimationSource;
	public disableMessages: boolean;
	public gapLimitOptions: TGapLimitOptions;
	// Leveled diagnostic logger. Defaults to a console-backed logger at
	// 'info' (preserving historical console output); injectable via IWallet.
	public readonly logger: ILogger;
	private constructor({
		mnemonic,
		xpub,
		masterFingerprint,
		originPath,
		passphrase,
		name,
		network = EAvailableNetworks.mainnet,
		addressType,
		account = 0,
		birthdayHeight,
		coinSelectPreference = ECoinSelectPreference.consolidate,
		storage,
		electrumOptions,
		onMessage = (): null => null,
		customGetAddress,
		customGetScriptHash,
		rbf = false,
		selectedFeeId = EFeeId.normal,
		feeEstimationSource = 'auto',
		disableMessages = false,
		disableMessagesOnCreate = false,
		logger,
		addressTypesToMonitor = Object.values(EAddressType),
		gapLimitOptions = {
			lookBehind: GAP_LIMIT,
			lookAhead: GAP_LIMIT,
			lookBehindChange: GAP_LIMIT_CHANGE,
			lookAheadChange: GAP_LIMIT_CHANGE
		},
		multisig
	}: IWallet) {
		if (!mnemonic && !xpub && !multisig) {
			throw new Error('No mnemonic specified.');
		}
		if (name && name.includes('-'))
			throw new Error('Wallet name cannot include a hyphen (-).');
		if (!Number.isInteger(account) || account < 0) {
			throw new Error('account must be a non-negative integer.');
		}
		if (
			birthdayHeight !== undefined &&
			(!Number.isInteger(birthdayHeight) || birthdayHeight < 0)
		) {
			throw new Error('birthdayHeight must be a non-negative integer.');
		}
		this._account = String(account);
		this._birthdayHeightOption = birthdayHeight;
		this._network = network;
		this._passphrase = passphrase ?? '';
		this.isWatchOnly = !mnemonic;
		if (mnemonic) {
			if (!validateMnemonic(mnemonic)) throw new Error('Invalid mnemonic.');
			this._mnemonic = mnemonic;
			this._seed = getSeed(this._mnemonic, this._passphrase);
			this._root = bip32.fromSeed(
				this._seed,
				this.getBitcoinNetwork(this._network)
			);
		}
		if (multisig) {
			if (addressType && addressType !== EAddressType.p2wsh) {
				throw new Error(
					'Multisig wallets only support the p2wsh address type.'
				);
			}
			const setup = this._initMultisig(multisig);
			this._multisig = setup.config;
			this.id = setup.id;
			this.addressType = EAddressType.p2wsh;
			// Multisig wallets derive exactly one script type.
			addressTypesToMonitor = [EAddressType.p2wsh];
		} else if (mnemonic) {
			if (addressType === EAddressType.p2wsh) {
				throw new Error(
					'p2wsh is a multisig address type. Use Wallet.createMultisig.'
				);
			}
			this.id = generateWalletId(this._seed!);
			this.addressType = addressType ?? EAddressType.p2wpkh;
		} else {
			const parseRes = parseExtendedPublicKey(xpub!, this._network);
			if (parseRes.isErr()) throw parseRes.error;
			const { node, addressType: inferredType } = parseRes.value;
			if (addressType && inferredType && addressType !== inferredType) {
				throw new Error(
					`The provided xpub prefix implies ${inferredType}, but addressType ${addressType} was requested.`
				);
			}
			const resolvedType = addressType ?? inferredType ?? EAddressType.p2wpkh;
			if (resolvedType === EAddressType.p2wsh) {
				throw new Error(
					'p2wsh is a multisig address type. Use Wallet.createMultisig with every cosigner xpub.'
				);
			}
			if (masterFingerprint) {
				const originRes = normalizeKeyOrigin(masterFingerprint, originPath);
				if (originRes.isErr()) throw originRes.error;
				this._keyOrigin = originRes.value;
			} else if (originPath) {
				throw new Error(
					'originPath requires masterFingerprint (a path is meaningless without the fingerprint it starts from).'
				);
			}
			this._accountNode = node;
			this.addressType = resolvedType;
			// Deterministic id across SLIP-132 encodings of the same account key.
			this.id = generateWalletId(
				Buffer.concat([node.publicKey, node.chainCode])
			);
			// A single account-level xpub only yields one address type.
			addressTypesToMonitor = [this.addressType];
		}
		if (!this._multisig) {
			// Sorted multisig cannot be derived without cosigner keys; it never
			// belongs in a single-sig wallet's monitor set.
			addressTypesToMonitor = addressTypesToMonitor.filter(
				(type) => type !== EAddressType.p2wsh
			);
		}
		this.logger = logger ?? createConsoleLogger('info');
		this._data = getDefaultWalletData();
		this._getData = storage?.getData ?? getDataFallback;
		this._setData = storage?.setData;
		this._disableMessagesOnCreate = disableMessagesOnCreate;
		if (customGetAddress) this._customGetAddress = customGetAddress;
		if (customGetScriptHash) this._customGetScriptHash = customGetScriptHash;
		this.name = name ?? this.id;
		this.coinSelectPreference = coinSelectPreference;
		this.transaction = new Transaction({
			wallet: this
		});
		this.feeEstimates = cloneDeep(defaultFeesShape);
		this.disableMessages = disableMessages;
		this.sendMessage = <K extends keyof TMessageDataMap>(
			key: K,
			data: TMessageDataMap[K]
		): void => {
			if (this.disableMessages) return;
			onMessage(key, data);
		};
		this.electrumOptions = electrumOptions;
		this.electrum = new Electrum({
			wallet: this,
			network: this.network,
			...electrumOptions
		});
		this.rbf = rbf;
		this.selectedFeeId = selectedFeeId;
		this.feeEstimationSource = feeEstimationSource;
		this.isRefreshing = false;
		this.isSwitchingNetworks = false;
		this.addressTypesToMonitor = addressTypesToMonitor;
		if (!this.addressTypesToMonitor.includes(this.addressType)) {
			this.addressTypesToMonitor.push(this.addressType);
		}
		// Remove duplicates
		this.addressTypesToMonitor = [...new Set(this.addressTypesToMonitor)];
		this.gapLimitOptions = {
			lookBehind: isPositive(gapLimitOptions.lookBehind)
				? gapLimitOptions.lookBehind
				: 1,
			lookAhead: isPositive(gapLimitOptions.lookAhead)
				? gapLimitOptions.lookAhead
				: 1,
			lookBehindChange: isPositive(gapLimitOptions.lookBehindChange)
				? gapLimitOptions.lookBehindChange
				: 1,
			lookAheadChange: isPositive(gapLimitOptions.lookAheadChange)
				? gapLimitOptions.lookAheadChange
				: 1
		};
	}

	public get data(): IWalletData {
		return this._data;
	}

	public get transactions(): IFormattedTransactions {
		return this._data.transactions;
	}

	public get unconfirmedTransactions(): IFormattedTransactions {
		return this._data.unconfirmedTransactions;
	}

	public get utxos(): IUtxo[] {
		return this._data.utxos;
	}

	public get balance(): number {
		return this._data.balance;
	}

	public get network(): EAvailableNetworks {
		return this._network;
	}

	/** BIP32 account index this wallet derives from (default 0). */
	public get account(): number {
		return Number(this._account);
	}

	/**
	 * Wallet creation height (0 = unknown). HONEST SCOPE: the Electrum
	 * protocol addresses history by scripthash, not by height, so a birthday
	 * cannot reduce Electrum scan work today. The value is persisted
	 * (earliest provided value wins), included in exportDescriptors() output,
	 * and recorded for future backends (bitcoind RPC / compact filters) and
	 * external tooling that CAN bound scans by height.
	 */
	public get birthdayHeight(): number {
		return this._data.birthdayHeight ?? 0;
	}

	/** True when this wallet is a sorted-multisig (p2wsh) wallet. */
	public get isMultisig(): boolean {
		return !!this._multisig;
	}

	/** Threshold and cosigner count for multisig wallets. */
	public get multisigInfo():
		| { threshold: number; totalCosigners: number }
		| undefined {
		if (!this._multisig) return undefined;
		return {
			threshold: this._multisig.threshold,
			totalCosigners: this._multisig.cosigners.length
		};
	}

	static async create(params: IWallet): Promise<Result<Wallet>> {
		try {
			const wallet = new Wallet(params);
			if (wallet._disableMessagesOnCreate) wallet.disableMessages = true;
			const res = await wallet.setWalletData();
			if (res.isErr()) return err(res.error.message);
			wallet.updateFeeEstimates(true);
			wallet.refreshWallet({});
			return ok(wallet);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Creates a watch-only wallet from an account-level extended public key
	 * (xpub/ypub/zpub/tpub/upub/vpub). The key is assumed to sit at the
	 * account level (m/purpose'/coin'/account', e.g. m/84'/0'/0' for p2wpkh),
	 * so receive and change addresses are derived publicly as xpub/0/i and
	 * xpub/1/i. All read-only functionality works; anything that requires
	 * private keys fails with WatchOnlySigningError.
	 * The account option does not affect derivation here (the xpub already
	 * encodes its account); it only namespaces the storage keys so two
	 * watch-only wallets over different account xpubs can share storage.
	 * @param {IWatchOnlyWallet} params
	 * @returns {Promise<Result<Wallet>>}
	 */
	static async createWatchOnly(
		params: IWatchOnlyWallet
	): Promise<Result<Wallet>> {
		if (!params?.xpub) return err('No xpub provided.');
		return await Wallet.create(params);
	}

	/**
	 * Creates a sorted-multisig (BIP 48 / BIP 67) P2WSH wallet:
	 * wsh(sortedmulti(threshold, cosigner keys...)), derived at
	 * m/48'/coin'/account'/2'/{0,1}/index. Cosigners are provided as
	 * account-level extended public keys (xpub/tpub or SLIP-132 Zpub/Vpub).
	 * When a mnemonic is provided we are one of the cosigners: our BIP 48
	 * account xpub is derived and included automatically. Without a mnemonic
	 * the wallet is a watch-only multisig (full read-only surface, no
	 * signing). Spending is PSBT-only: buildPsbt -> signPsbtWithOurKey ->
	 * combinePsbts -> importSignedPsbt -> broadcastTransaction.
	 * @param {IMultisigWallet} params
	 * @returns {Promise<Result<Wallet>>}
	 */
	static async createMultisig(
		params: IMultisigWallet
	): Promise<Result<Wallet>> {
		if (!params) return err('No multisig parameters provided.');
		const { threshold, cosigners, ourXpub, ...walletParams } = params;
		return await Wallet.create({
			...walletParams,
			addressType: EAddressType.p2wsh,
			multisig: { threshold, cosigners, ourXpub }
		});
	}

	/**
	 * Validates the multisig options and resolves every cosigner to an
	 * account-level PUBLIC node. Requires _network/_account/_root to be set.
	 * The cosigner list is stored sorted by account public key so every
	 * instance of the same quorum is deterministic (BIP 67 ordering of the
	 * DERIVED child keys happens per address in buildSortedMultisigPayment).
	 * @private
	 * @param {IMultisigOptions} multisig
	 * @returns {{ config; id }}
	 */
	private _initMultisig(multisig: IMultisigOptions): {
		config: {
			threshold: number;
			cosigners: {
				node: BIP32Interface;
				isOurs: boolean;
				keyOrigin?: IKeyOrigin;
			}[];
		};
		id: string;
	} {
		const { threshold, cosigners, ourXpub } = multisig;
		if (!Number.isInteger(threshold) || threshold < 1) {
			throw new Error('Multisig threshold must be a positive integer.');
		}
		const keyId = (node: BIP32Interface): string =>
			Buffer.concat([node.publicKey, node.chainCode]).toString('hex');
		const entries: {
			node: BIP32Interface;
			isOurs: boolean;
			keyOrigin?: IKeyOrigin;
		}[] = [];
		const addCosigner = (cosigner: string | IMultisigCosigner): void => {
			const info: IMultisigCosigner =
				typeof cosigner === 'string' ? { xpub: cosigner } : cosigner;
			const { xpub, masterFingerprint, originPath } = info;
			const res = parseExtendedPublicKey(xpub, this._network);
			if (res.isErr()) throw res.error;
			const node = res.value.node;
			if (entries.some((e) => keyId(e.node) === keyId(node))) {
				throw new Error(`Duplicate cosigner xpub provided: ${xpub}`);
			}
			let keyOrigin: IKeyOrigin | undefined;
			if (masterFingerprint) {
				const originRes = normalizeKeyOrigin(masterFingerprint, originPath);
				if (originRes.isErr()) throw originRes.error;
				keyOrigin = originRes.value;
			} else if (originPath) {
				throw new Error(
					`Cosigner ${xpub} has an originPath but no masterFingerprint.`
				);
			}
			entries.push({ node, isOurs: false, keyOrigin });
		};
		for (const cosigner of cosigners ?? []) addCosigner(cosigner);
		if (this._root) {
			// We are a cosigner: derive our BIP 48 account xpub and include it.
			const coinType = this._network === EAvailableNetworks.bitcoin ? '0' : '1';
			const ourNode = this._root
				.derivePath(`m/48'/${coinType}'/${this._account}'/2'`)
				.neutered();
			if (ourXpub) {
				const parsed = parseExtendedPublicKey(ourXpub, this._network);
				if (parsed.isErr()) throw parsed.error;
				if (keyId(parsed.value.node) !== keyId(ourNode)) {
					throw new Error(
						`ourXpub does not match the account xpub derived from the mnemonic at m/48'/${coinType}'/${this._account}'/2'.`
					);
				}
			}
			const existing = entries.find((e) => keyId(e.node) === keyId(ourNode));
			if (existing) {
				existing.isOurs = true;
			} else {
				entries.push({ node: ourNode, isOurs: true });
			}
		} else if (ourXpub) {
			// Watch-only multisig: ourXpub is just another cosigner key.
			addCosigner(ourXpub);
		}
		const n = entries.length;
		if (threshold > n) {
			throw new Error(
				`Multisig threshold (${threshold}) exceeds the number of cosigners (${n}).`
			);
		}
		if (n > 15) {
			throw new Error(`Multisig supports at most 15 cosigners, received ${n}.`);
		}
		entries.sort((a, b) => a.node.publicKey.compare(b.node.publicKey));
		// Deterministic id for the quorum, independent of input order and of
		// which cosigner (or watch-only coordinator) instantiates it.
		const id = generateWalletId(
			Buffer.concat([
				Buffer.from('sortedmulti'),
				Buffer.from([threshold, n]),
				...entries.map((e) =>
					Buffer.concat([e.node.publicKey, e.node.chainCode])
				)
			])
		);
		return { config: { threshold, cosigners: entries }, id };
	}

	/**
	 * Builds the sorted-multisig payment data for a full BIP 48 path
	 * (m/48'/coin'/account'/2'/change/index): the P2WSH address/output, the
	 * m-of-n witnessScript and one bip32Derivation entry per cosigner
	 * (ordered by BIP 67 derived-key order). publicKey is OUR derived child
	 * key when a mnemonic is present, '' for watch-only multisig.
	 * @param {string} path
	 * @returns {Result}
	 */
	public getMultisigPayment(path: string): Result<{
		address: string;
		output: Buffer;
		witnessScript: Buffer;
		publicKey: string;
		derivations: { masterFingerprint: Buffer; path: string; pubkey: Buffer }[];
	}> {
		try {
			if (!this._multisig) {
				return err('This wallet is not a multisig wallet.');
			}
			const parsed = parseBip48Path(path);
			if (parsed.isErr()) return err(parsed.error.message);
			const { coinType, account, change, index } = parsed.value;
			const expectedCoin =
				this._network === EAvailableNetworks.bitcoin ? '0' : '1';
			if (coinType !== expectedCoin || account !== this._account) {
				return err(
					`Path ${path} does not match this wallet (expected m/48'/${expectedCoin}'/${this._account}'/2'/change/index).`
				);
			}
			const payment = buildSortedMultisigPayment({
				threshold: this._multisig.threshold,
				cosignerNodes: this._multisig.cosigners.map((c) => c.node),
				change,
				index,
				network: this.getBitcoinNetwork()
			});
			if (payment.isErr()) return err(payment.error.message);
			const perCosigner = this._multisig.cosigners
				.map((c) => {
					let masterFingerprint: Buffer;
					let cosignerPath = path;
					if (c.isOurs && this._root) {
						masterFingerprint = Buffer.from(this._root.fingerprint);
					} else if (c.keyOrigin) {
						// The cosigner's true origin was supplied: pair its master
						// fingerprint with the path THAT device derives, so hardware
						// cosigners recognize the entry (BIP 174).
						masterFingerprint = Buffer.from(c.keyOrigin.fingerprint);
						if (c.keyOrigin.path) {
							cosignerPath = `m/${c.keyOrigin.path}/${change}/${index}`;
						}
					} else {
						// Only the account xpub is known for this cosigner; expose
						// its parent fingerprint (watch-only single-sig convention).
						masterFingerprint = Buffer.alloc(4);
						masterFingerprint.writeUInt32BE(c.node.parentFingerprint ?? 0, 0);
					}
					return {
						masterFingerprint,
						path: cosignerPath,
						pubkey: c.node.derive(change).derive(index).publicKey,
						isOurs: c.isOurs
					};
				})
				.sort((a, b) => a.pubkey.compare(b.pubkey));
			const ours = perCosigner.find((d) => d.isOurs);
			return ok({
				address: payment.value.address,
				output: payment.value.output,
				witnessScript: payment.value.witnessScript,
				publicKey: ours && this._root ? ours.pubkey.toString('hex') : '',
				derivations: perCosigner.map((d) => ({
					masterFingerprint: d.masterFingerprint,
					path: d.path,
					pubkey: d.pubkey
				}))
			});
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Stops the wallet. Use this method to prepare the wallet to be de
	 * @returns {Promise<Result<string>>}
	 */
	public async stop(): Promise<Result<string>> {
		try {
			// if we are refreshing, we need to wait for it to finish
			if (this.isRefreshing) {
				await this.refreshWallet();
			}
			// disable onMessage callback
			this.disableMessages = true;
			// disable saving to storage
			this._setData = undefined;
			// disconnect from Electrum
			await this.electrum.disconnect();
			return ok('Wallet stopped.');
		} catch (e) {
			return err(e);
		}
	}

	public updateCoinSelectPreference(
		coinSelectPreference: ECoinSelectPreference
	): void {
		this.coinSelectPreference = coinSelectPreference;
	}

	public async switchNetwork(
		network: EAvailableNetworks,
		servers?: TServer | TServer[]
	): Promise<Result<Wallet>> {
		if (this._multisig) {
			// Cosigner xpub version bytes encode the network; a new multisig
			// wallet must be created from keys for the target network.
			return err(
				'Multisig wallets cannot switch networks. Create a new multisig wallet with cosigner xpubs for the target network.'
			);
		}
		if (this.isWatchOnly) {
			// The xpub version bytes encode the network; a new watch-only wallet
			// must be created from a key that matches the target network.
			return err(
				'Watch-only wallets cannot switch networks. Create a new watch-only wallet with an xpub for the target network.'
			);
		}
		this.isSwitchingNetworks = true;
		// Disconnect from Electrum.
		await this.electrum.disconnect();

		this._network = network;
		this._data = getDefaultWalletData();
		const params: IWallet = {
			...this,
			mnemonic: this._mnemonic,
			passphrase: this._passphrase,
			account: Number(this._account),
			birthdayHeight: this._birthdayHeightOption,
			network,
			electrumOptions: {
				servers,
				tls: this.electrumOptions?.tls,
				net: this.electrumOptions?.net
			},
			storage: {
				getData: this._getData,
				setData: this._setData
			},
			data: getDefaultWalletData(),
			onMessage: this.sendMessage
		};
		const createRes = await Wallet.create(params);
		if (createRes.isErr()) return err(createRes.error.message);
		Object.assign(this, createRes.value);
		await this.updateFeeEstimates(true);
		this.isSwitchingNetworks = false;
		return ok(this);
	}

	/**
	 * Updates the address type for the current wallet.
	 * @param {EAddressType} addressType
	 * @returns {Promise<void>}
	 */
	async updateAddressType(addressType: EAddressType): Promise<void> {
		if (addressType === EAddressType.p2wsh && !this._multisig) {
			throw new Error(
				'p2wsh is a multisig address type. Use Wallet.createMultisig.'
			);
		}
		if (this._multisig && addressType !== EAddressType.p2wsh) {
			throw new Error('Multisig wallets only support the p2wsh address type.');
		}
		this.addressType = addressType;
		if (!this.addressTypesToMonitor.includes(this.addressType)) {
			this.addressTypesToMonitor.push(this.addressType);
		}
		await this.saveWalletData('addressType', addressType);
		await this.refreshWallet({});
	}

	/**
	 * Refreshes/Syncs the wallet data.
	 * @param {boolean} [scanAllAddresses]
	 * @param {string[]} [additionalAddresses]
	 * @returns {Promise<Result<IWalletData>>}
	 */
	public async refreshWallet({
		scanAllAddresses = false,
		additionalAddresses = [],
		force = false
	}: {
		scanAllAddresses?: boolean;
		additionalAddresses?: string[];
		force?: boolean;
	} = {}): Promise<Result<IWalletData>> {
		if (this.isRefreshing && !force) {
			return new Promise((resolve) => {
				this._pendingRefreshPromises.push(resolve);
			});
		}
		this.isRefreshing = true;
		this.updateFeeEstimates();
		try {
			await this.setZeroIndexAddresses();
			const r1 = await this.updateAddressIndexes();
			if (r1.isErr()) {
				return this._handleRefreshError(r1.error.message);
			}
			const r2 = await this.getUtxos({
				scanningStrategy: scanAllAddresses ? EScanningStrategy.all : undefined,
				additionalAddresses
			});
			if (r2.isErr()) {
				return this._handleRefreshError(r2.error.message);
			}
			const r3 = await this.updateTransactions({ scanAllAddresses });
			if (r3.isErr()) {
				return this._handleRefreshError(r3.error.message);
			}
			await this.electrum.subscribeToAddresses();
			if (!force) {
				this._resolveAllPendingRefreshPromises(ok(this.data));
			}
			return ok(this.data);
		} catch (e) {
			if (force) {
				return err(e);
			} else {
				return this._handleRefreshError(e);
			}
		} finally {
			if (this._disableMessagesOnCreate) this.disableMessages = false;
		}
	}

	private _resolveAllPendingRefreshPromises(result: Result<IWalletData>): void {
		this.isRefreshing = false;
		while (this._pendingRefreshPromises.length > 0) {
			const resolve = this._pendingRefreshPromises.shift();
			if (resolve) {
				resolve(result);
			}
		}
	}

	private _handleRefreshError(errorMessage: string): Result<IWalletData> {
		this.isRefreshing = false;
		this._resolveAllPendingRefreshPromises(err(errorMessage));
		return err(errorMessage);
	}

	/**
	 * Sets the wallet data object.
	 * @returns {Promise<Result<boolean>>}
	 * @private
	 */
	private async setWalletData(): Promise<Result<boolean>> {
		try {
			const storageIdCheckRes = await this.storageIdCheck(this.id);
			if (storageIdCheckRes.isErr())
				return err(storageIdCheckRes.error.message);
			this._data = getDefaultWalletData();
			const walletDataResponse = await this.getWalletData();
			if (walletDataResponse.isErr())
				return err(walletDataResponse.error.message);
			this._data = walletDataResponse.value;
			await this._applyBirthdayHeightOption();
			return ok(true);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Ensure we are not overwriting wallet data of a different wallet by checking that the wallet id's match.
	 * @private
	 * @async
	 * @param {string} id
	 * @returns {Promise<Result<string>>}
	 */
	private async storageIdCheck(id: string): Promise<Result<string>> {
		const storageKey = this.getWalletDataKey('id');
		const res = await this._getData(storageKey);
		// No id found, it is safe to save to storage.
		if (res.isErr() || !res.value) {
			// Save id to storage.
			this._data.id = id;
			await this.saveWalletData('id', id);
			return ok('Saved ID to storage.');
		}
		// If the ID saved in storage does not match return an error and notify the developer.
		if (res.value !== id) {
			const msg =
				'Mismatched id found in storage. Change the wallet name or delete the old wallet from storage and try again.';
			this.logger.warn(msg);
			return err(msg);
		}
		return ok("ID's match, it's safe to continue.");
	}

	/**
	 * Returns the key used for storing wallet data in the key/value pair.
	 * @returns {string}
	 * @param key
	 */
	public getWalletDataKey(key: keyof IWalletData): string {
		return getWalletDataStorageKey(
			this.name,
			this._network,
			key,
			Number(this._account)
		);
	}

	/**
	 * Merges a birthdayHeight passed to Wallet.create with the stored value.
	 * The EARLIEST non-zero value wins: moving a birthday later could let a
	 * future height-bounded backend skip real history, so it is never allowed.
	 * @private
	 * @returns {Promise<void>}
	 */
	private async _applyBirthdayHeightOption(): Promise<void> {
		if (this._birthdayHeightOption === undefined) return;
		const stored = this._data.birthdayHeight ?? 0;
		const next =
			stored > 0
				? Math.min(stored, this._birthdayHeightOption)
				: this._birthdayHeightOption;
		if (next !== stored) {
			this._data.birthdayHeight = next;
			await this.saveWalletData('birthdayHeight', next);
		}
	}

	/**
	 * Gets the wallet data object from storage if able.
	 * Otherwise, it falls back to the default wallet data object.
	 * @returns {Promise<Result<IWalletData>>}
	 */
	public async getWalletData(): Promise<Result<IWalletData>> {
		try {
			const walletDataKeys = getDefaultWalletDataKeys();
			const walletData: IWalletData = getDefaultWalletData();
			await Promise.all(
				walletDataKeys.map(async (key) => {
					let dataResult;
					try {
						const walletDataKey = this.getWalletDataKey(key);
						const getDataRes = await this._getData(walletDataKey);
						if (getDataRes.isErr()) {
							//dataResult = getDataRes?.value ?? walletData[key];
							return err(
								dataResult?.error?.message ?? 'Error getting wallet data'
							);
						}
						dataResult = getDataRes?.value;
					} catch (e) {
						this.logger.error('Failed to read wallet data from storage.', e);
					}
					const data = dataResult ?? walletData[key];
					switch (key) {
						case 'id':
							walletData[key] = data as string;
							break;
						case 'addressType':
							walletData[key] = data as EAddressType;
							break;
						case 'addresses':
						case 'changeAddresses':
							walletData[key] = data as TAddressTypeContent<IAddresses>;
							break;
						case 'addressIndex':
						case 'changeAddressIndex':
							walletData[key] = data as TAddressTypeContent<IAddress>;
							break;
						case 'lastUsedAddressIndex':
						case 'lastUsedChangeAddressIndex':
							walletData[key] = data as TAddressTypeContent<IAddress>;
							break;
						case 'utxos':
							walletData[key] = data as IUtxo[];
							break;
						case 'blacklistedUtxos':
							walletData[key] = data as IUtxo[];
							break;
						case 'unconfirmedTransactions':
						case 'transactions':
							walletData[key] = data as IFormattedTransactions;
							break;
						case 'transaction':
							walletData[key] = data as ISendTransaction;
							break;
						case 'balance':
							walletData[key] = data as number;
							break;
						case 'header':
							walletData[key] = data as IHeader;
							break;
						case 'boostedTransactions':
							walletData[key] = data as IBoostedTransactions;
							break;
						case 'selectedFeeId':
							walletData[key] = data as EFeeId;
							break;
						case 'feeEstimates':
							walletData[key] = data as IOnchainFees;
							break;
						case 'addressLabels':
							walletData[key] = data as TAddressLabels;
							break;
						case 'birthdayHeight':
							walletData[key] = data as number;
							break;
						default:
							this.logger.warn(`Unhandled key in getWalletData: ${key}`);
							break;
					}
				})
			);
			return ok(walletData);
		} catch (e) {
			this.logger.error('Failed to get wallet data.', e);
			return err(e);
		}
	}

	/**
	 * Returns the Network object of the currently selected network (bitcoin or testnet).
	 * @param {TAvailableNetworks} [network]
	 * @returns {Network}
	 */
	private getBitcoinNetwork(network?: TAvailableNetworks): Network {
		if (!network) network = this._network;
		return getBitcoinJsNetwork(network);
	}

	/**
	 * Ensures the provided mnemonic matches the one stored in the wallet and is valid.
	 * @param mnemonic
	 * @returns {boolean}
	 */
	isValid(mnemonic): boolean {
		return (
			!!this._mnemonic &&
			mnemonic === this._mnemonic &&
			validateMnemonic(mnemonic)
		);
	}

	/**
	 * Derives the key pair (public only for watch-only wallets) for a given
	 * full derivation path.
	 * @param {string} path
	 * @returns {BIP32Interface}
	 * @private
	 */
	private _derivePathKeyPair(path: string): BIP32Interface {
		if (this._root) return this._root.derivePath(path);
		return this._deriveWatchOnlyNode(path);
	}

	/**
	 * Watch-only wallets hold the account-level xpub, so only the public
	 * change/index segments of a full path can be derived. The path's purpose
	 * must match the wallet's address type.
	 * @param {string} path
	 * @returns {BIP32Interface}
	 * @private
	 */
	private _deriveWatchOnlyNode(path: string): BIP32Interface {
		if (!this._accountNode) {
			throw new Error('Watch-only account node is unavailable.');
		}
		const segments = path.replace(/'/g, '').split('/');
		if (segments.length !== 6) {
			throw new Error(
				`Watch-only wallets require a full path (m/purpose'/coin'/account'/change/index): ${path}`
			);
		}
		const expectedPathRes = getKeyDerivationPathObject({
			path: addressTypes[this.addressType].path,
			network: this._network
		});
		if (expectedPathRes.isErr()) throw expectedPathRes.error;
		if (segments[1] !== expectedPathRes.value.purpose) {
			throw new Error(
				`This watch-only wallet only derives ${this.addressType} paths (purpose ${expectedPathRes.value.purpose}'), received: ${path}`
			);
		}
		const change = Number(segments[4]);
		const index = Number(segments[5]);
		if (
			!Number.isInteger(change) ||
			!Number.isInteger(index) ||
			change < 0 ||
			index < 0
		) {
			throw new Error(`Invalid change/index segments in path: ${path}`);
		}
		return this._accountNode.derive(change).derive(index);
	}

	/**
	 * Returns a public-only BIP32 node for the given full derivation path.
	 * @param {string} path
	 * @returns {Result<BIP32Interface>}
	 */
	public derivePublicNode(path: string): Result<BIP32Interface> {
		try {
			if (this._root) return ok(this._root.derivePath(path).neutered());
			return ok(this._deriveWatchOnlyNode(path));
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns the fingerprint external signers should match against. For full
	 * wallets this is the master fingerprint. Watch-only wallets use the
	 * caller-supplied masterFingerprint when one was provided at creation;
	 * otherwise they fall back to the xpub's parent fingerprint (which
	 * hardware signers will refuse to match, but is all that is derivable
	 * from the xpub alone).
	 * @returns {Buffer}
	 */
	public getMasterFingerprint(): Buffer {
		if (this._root) return Buffer.from(this._root.fingerprint);
		if (this._keyOrigin) return Buffer.from(this._keyOrigin.fingerprint);
		const fingerprint = Buffer.alloc(4);
		fingerprint.writeUInt32BE(this._accountNode?.parentFingerprint ?? 0, 0);
		return fingerprint;
	}

	/**
	 * Rewrites a wallet-derived full path (m/purpose'/coin'/account'/change/
	 * index) onto the watch-only key's true origin path, so PSBT
	 * bip32_derivation entries pair the supplied master fingerprint with the
	 * path that fingerprint's device actually uses. Returns the path
	 * unchanged for full wallets or when no origin path was supplied.
	 * @param {string} path
	 * @returns {string}
	 */
	public mapPathToKeyOrigin(path: string): string {
		if (this._root || !this._keyOrigin?.path) return path;
		const segments = path.replace(/^m\//i, '').split('/');
		// The account xpub derives change/index only; keep the last two
		// (non-hardened) segments and graft them onto the true origin.
		if (segments.length < 2) return path;
		const suffix = segments.slice(-2).join('/');
		return `m/${this._keyOrigin.path}/${suffix}`;
	}

	/**
	 * Returns the address for the specified path and address type.
	 * @param {string} path
	 * @param {EAddressType} addressType
	 * @returns {IGetAddressResponse}
	 * @private
	 */
	private async _getAddress(
		path: string,
		addressType: EAddressType
	): Promise<Result<IGetAddressResponse>> {
		try {
			if (addressType === EAddressType.p2wsh) {
				if (!this._multisig) {
					return err(
						'p2wsh addresses require a multisig wallet (Wallet.createMultisig).'
					);
				}
				const payment = this.getMultisigPayment(path);
				if (payment.isErr()) return err(payment.error.message);
				return ok({
					address: payment.value.address,
					publicKey: payment.value.publicKey,
					path
				});
			}
			if (this._customGetAddress) {
				const data = {
					path,
					type: addressType,
					selectedNetwork: getElectrumNetwork(this._network)
				};
				const res = await this._customGetAddress(data);
				if (res.isErr()) return err(res.error.message);
			}
			const keyPair = this._derivePathKeyPair(path);
			const network = this.getBitcoinNetwork(this._network);
			const addressInfo = getAddressFromKeyPair({
				keyPair,
				addressType,
				network
			});
			if (addressInfo.isErr()) return err(addressInfo.error.message);
			return ok({
				...addressInfo.value,
				path
			});
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns a single Bitcoin address based on the provided address type,
	 * index and whether it is a change address.
	 * @param {TKeyDerivationIndex} [index]
	 * @param {boolean} [changeAddress]
	 * @param {EAddressType} [addressType]
	 * @returns {string}
	 */
	public async getAddress({
		index,
		changeAddress = false,
		addressType = this.addressType
	}: IGetAddress = {}): Promise<string> {
		try {
			if (index === undefined) {
				const addressIndex = this.data.addressIndex[addressType];
				index = addressIndex.index >= 0 ? String(addressIndex.index) : '0';
			}
			const pathRes = getKeyDerivationPathString({
				addressType,
				changeAddress,
				index,
				accountType: this._account,
				network: this._network
			});
			if (pathRes.isErr()) {
				return '';
			}
			const path = pathRes.value;
			const res = await this._getAddress(path, addressType);
			if (res.isErr()) return '';
			return res.value.address;
		} catch {
			return '';
		}
	}

	/**
	 * Get address for a given keyPair, network and type.
	 * @param {string} path
	 * @param {EAddressType} addressType
	 * @returns {Promise<Result<string>>}
	 */
	public async getAddressByPath({
		path,
		addressType
	}: IGetAddressByPath): Promise<Result<IGetAddressResponse>> {
		if (!path) {
			return err('No path specified');
		}
		if (!addressType) {
			const res = getAddressTypeFromPath(path);
			if (res.isErr()) return err(res.error.message);
			addressType = res.value;
		}
		try {
			const getAddressRes = await this._getAddress(path, addressType);
			if (getAddressRes.isErr()) return err('Unable to get address.');
			return ok(getAddressRes.value);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Attempts to connect to the specified Electrum server(s).
	 * @param {TServer | TServer[]} servers
	 * @returns {Promise<Result<string>>}
	 */
	public async connectToElectrum(
		servers?: TServer | TServer[]
	): Promise<Result<string>> {
		const res = await this.electrum.connectToElectrum({
			network: this._network,
			servers: servers ?? this.electrumOptions?.servers
		});
		let msg = 'Unable to connect to Electrum server.';
		if (res.isErr()) {
			this.logger.warn(msg);
			return err(msg);
		}
		msg = 'Connected to Electrum server.';
		return ok(msg);
	}

	/**
	 * Returns the address balance for the specified address.
	 * @param {string} address
	 * @returns {Promise<Result<IGetAddressBalanceRes>>}
	 */
	public async getAddressBalance(
		address: string
	): Promise<Result<IGetAddressBalanceRes>> {
		const scriptHash = await this.getScriptHash({
			address,
			network: this._network
		});
		const res = await this.electrum.getAddressBalance(scriptHash);
		if (res.error) return err('Unable to get address balance at this time.');
		return ok({ unconfirmed: res.unconfirmed, confirmed: res.confirmed });
	}

	/**
	 * Returns combined balance of provided addresses.
	 * @async
	 * @param {string[]} addresses
	 * @returns {Promise<Result<number>>}
	 */
	public async getAddressesBalance(
		addresses: string[] = []
	): Promise<Result<number>> {
		try {
			const network = this._network;
			const scriptHashes = await Promise.all(
				addresses.map(async (address) => {
					return await this.getScriptHash({ address, network });
				})
			);
			const res =
				await this.electrum.getAddressScriptHashBalances(scriptHashes);
			if (res.error || typeof res.data === 'string') {
				return err(JSON.stringify(res.data));
			}
			return ok(
				res.data.reduce((acc, cur) => {
					return (
						acc +
						Number(cur.result?.confirmed ?? 0) +
						Number(cur.result?.unconfirmed ?? 0)
					);
				}, 0) || 0
			);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Get scriptHash for a given address
	 * @param {string} address
	 * @param {EAvailableNetworks} network
	 * @returns {Promise<string>}
	 */
	public async getScriptHash({
		address,
		network
	}: {
		address: string;
		network: EAvailableNetworks;
	}): Promise<string> {
		if (this._customGetScriptHash) {
			const selectedNetwork = getElectrumNetwork(network);
			return await this._customGetScriptHash({ address, selectedNetwork });
		}
		return getScriptHash({ address, network });
	}

	/**
	 * Returns private key for the provided path.
	 * @param path
	 * @returns {string}
	 */
	getPrivateKey(path: string): string {
		if (!this._root) throw new WatchOnlySigningError();
		const keyPair = this._root.derivePath(path);
		return keyPair.toWIF();
	}

	/**
	 * Returns the balance for the specified scriptHash.
	 * @param {string} scriptHash
	 * @returns {Promise<Result<IGetAddressBalanceRes>>}
	 */
	public async getScriptHashBalance(
		scriptHash: string
	): Promise<Result<IGetAddressBalanceRes>> {
		const res = await this.electrum.getAddressBalance(scriptHash);
		if (res.error) return err('Unable to get address balance at this time.');
		return ok({ unconfirmed: res.unconfirmed, confirmed: res.confirmed });
	}

	/**
	 * Returns the known balance from storage.
	 * @returns {number}
	 */
	public getBalance(): number {
		return this?.data?.balance ?? 0;
	}

	/**
	 * Generates a series of addresses based on the specified params.
	 * @async
	 * @param {string} selectedWallet - Wallet ID
	 * @param {number} [addressAmount] - Number of addresses to generate.
	 * @param {number} [changeAddressAmount] - Number of changeAddresses to generate.
	 * @param {number} [addressIndex] - What index to start generating addresses at.
	 * @param {number} [changeAddressIndex] - What index to start generating changeAddresses at.
	 * @param {string} [keyDerivationPath] - The path to generate addresses from.
	 * @param {string} [addressType] - Determines what type of address to generate (p2pkh, p2sh, p2wpkh).
	 * @returns {Promise<Result<IGenerateAddressesResponse>>}
	 */
	public async generateAddresses({
		addressAmount = 10,
		changeAddressAmount = 10,
		addressIndex = 0,
		changeAddressIndex = 0,
		keyDerivationPath,
		addressType = this.addressType
	}: IGenerateAddresses): Promise<Result<IGenerateAddressesResponse>> {
		const network = this._network;
		try {
			if (!keyDerivationPath) {
				// Set derivation path accordingly based on address type.
				const keyDerivationPathResponse = getKeyDerivationPath({
					network,
					addressType
				});
				if (keyDerivationPathResponse.isErr())
					return err(keyDerivationPathResponse.error.message);
				keyDerivationPath = keyDerivationPathResponse.value;
				keyDerivationPath.account = this._account;
			}

			const addresses = {} as IAddresses;
			const changeAddresses = {} as IAddresses;
			const addressArray = new Array(addressAmount).fill(null);
			const changeAddressArray = new Array(changeAddressAmount).fill(null);

			await Promise.all(
				addressArray.map(async (_item, i) => {
					const index = i + addressIndex;
					const path = { ...keyDerivationPath };
					path.index = `${index}`;
					const addressPath = formatKeyDerivationPath({
						path,
						network,
						changeAddress: false,
						index: `${index}`
					});
					if (addressPath.isErr()) {
						throw addressPath.error;
					}
					const address = await this.getAddressByPath({
						path: addressPath.value.pathString
					});
					if (address.isErr()) {
						throw address.error;
					}
					const scriptHash = await this.getScriptHash({
						address: address.value.address,
						network
					});
					if (!scriptHash) {
						throw new Error('Unable to get script hash.');
					}
					addresses[scriptHash] = {
						...address.value,
						index,
						scriptHash
					};
				})
			);

			await Promise.all(
				changeAddressArray.map(async (_item, i) => {
					const index = i + changeAddressIndex;
					const path = { ...keyDerivationPath };
					path.index = `${index}`;
					const changeAddressPath = formatKeyDerivationPath({
						path,
						network,
						changeAddress: true,
						index: `${index}`
					});
					if (changeAddressPath.isErr()) {
						throw changeAddressPath.error;
					}

					const address = await this.getAddressByPath({
						path: changeAddressPath.value.pathString
					});
					if (address.isErr()) {
						throw address.error;
					}
					const scriptHash = await this.getScriptHash({
						address: address.value.address,
						network
					});
					if (!scriptHash) {
						throw new Error('Unable to get script hash.');
					}
					changeAddresses[scriptHash] = {
						...address.value,
						index,
						scriptHash
					};
				})
			);

			return ok({ addresses, changeAddresses });
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Ensures the connection to Electrum is still available.
	 * Will attempt to reconnect if not initially available.
	 * @returns {Promise<Result<string>>}
	 */
	public async checkElectrumConnection(): Promise<Result<string>> {
		const isConnected = this.electrum.connectedToElectrum;
		if (!isConnected) {
			return await this.connectToElectrum();
		}
		// Ensure we're connected by pinging the server.
		const pingRes = await this.electrum.isConnected();
		if (pingRes) return ok('Is connected to Electrum.Z');
		return err('Failed Electrum connection check.');
	}

	/**
	 * Returns the next available address for the given addresstype.
	 * @param {EAddressType} addressType
	 * @returns {Promise<Result<IGetNextAvailableAddressResponse>>}
	 */
	public async getNextAvailableAddress(
		addressType?: EAddressType
	): Promise<Result<IGetNextAvailableAddressResponse>> {
		const checkRes = await this.checkElectrumConnection();
		if (checkRes.isErr()) return err(checkRes.error.message);
		try {
			const network = this._network;
			addressType = addressType ?? this.addressType;
			const currentWallet = this.data;
			const { path } = addressTypes[addressType]; // Assuming addressTypes is globally defined.
			const result = formatKeyDerivationPath({ path, network });

			if (result.isErr()) {
				return err(result.error.message);
			}

			const { pathObject: keyDerivationPath } = result.value;
			keyDerivationPath.account = this._account;

			//The currently known/stored address index.
			let addressIndex = currentWallet.addressIndex[addressType];
			let lastUsedAddressIndex =
				currentWallet.lastUsedAddressIndex[addressType];
			let changeAddressIndex = currentWallet.changeAddressIndex[addressType];
			let lastUsedChangeAddressIndex =
				currentWallet.lastUsedChangeAddressIndex[addressType];

			const originalHighestStoredIndexes = this.getHighestStoredAddressIndex({
				addressType
			});
			if (originalHighestStoredIndexes.isErr()) {
				return err(originalHighestStoredIndexes.error.message);
			}
			const originalHighestStoredIndex =
				originalHighestStoredIndexes.value.addressIndex;
			const originalHighestStoredChangeIndex =
				originalHighestStoredIndexes.value.changeAddressIndex;

			const addressIndexDiff = getAddressIndexDiff(
				originalHighestStoredIndex.index,
				lastUsedAddressIndex.index
			);
			const addressesToGenerate =
				this.gapLimitOptions.lookAhead - addressIndexDiff;
			let shouldSaveAddresses = false;
			let shouldSaveChangeAddresses = false;
			if (addressesToGenerate > 0) {
				const generatedAddresses = await this.addAddresses({
					addressAmount: addressesToGenerate,
					addressIndex: 0,
					changeAddressAmount: 0,
					keyDerivationPath,
					addressType,
					saveAddresses: false
				});
				if (generatedAddresses.isErr()) {
					return err(generatedAddresses.error);
				}
				shouldSaveAddresses = true;
				if (addressIndex.index < 0) {
					const addresses = generatedAddresses.value.addresses;
					const sorted = Object.values(addresses).sort(
						(a, b) => a.index - b.index
					);
					if (sorted.length >= 1 && sorted[0].index >= 0)
						addressIndex = sorted[0];
				}
			}

			const changeAddressIndexDiff = getAddressIndexDiff(
				originalHighestStoredChangeIndex.index,
				lastUsedChangeAddressIndex.index
			);
			const changeAddressesToGenerate =
				this.gapLimitOptions.lookAheadChange - changeAddressIndexDiff;

			if (changeAddressesToGenerate > 0) {
				const generatedAddresses = await this.addAddresses({
					addressAmount: 0,
					changeAddressAmount: changeAddressesToGenerate,
					changeAddressIndex: 0,
					keyDerivationPath,
					addressType,
					saveAddresses: false
				});
				if (generatedAddresses.isErr()) {
					return err(generatedAddresses.error);
				}
				shouldSaveChangeAddresses = true;
				if (changeAddressIndex.index < 0) {
					const changeAddresses = generatedAddresses.value.changeAddresses;
					const sorted = Object.values(changeAddresses).sort(
						(a, b) => a.index - b.index
					);
					if (sorted.length >= 1 && sorted[0].index >= 0)
						changeAddressIndex = sorted[0];
				}
			}

			// Save any addresses that have been created thus far if necessary.
			const promises: Promise<string>[] = [];
			if (shouldSaveAddresses) {
				promises.push(this.saveWalletData('addresses', this._data.addresses));
			}
			if (shouldSaveChangeAddresses) {
				promises.push(
					this.saveWalletData('changeAddresses', this._data.changeAddresses)
				);
			}
			await Promise.all(promises);

			let addresses = filterAddressesObjForGapLimit({
				addresses: this._data.addresses[addressType],
				index: addressIndex.index,
				gapLimitOptions: this.gapLimitOptions,
				change: false
			});
			let changeAddresses = filterAddressesObjForGapLimit({
				addresses: this._data.changeAddresses[addressType],
				index: changeAddressIndex.index,
				gapLimitOptions: this.gapLimitOptions,
				change: true
			});

			//Store all addresses that are to be searched and used in this method.
			let allAddresses = Object.values(addresses).filter(
				({ index }) => index >= addressIndex.index
			);

			let addressesToScan = allAddresses;

			//Store all change addresses that are to be searched and used in this method.
			let allChangeAddresses = Object.values(changeAddresses).filter(
				({ index }) => index >= changeAddressIndex.index
			);
			let changeAddressesToScan = allChangeAddresses;

			//Prep for batch request
			let combinedAddressesToScan = [
				...addressesToScan,
				...changeAddressesToScan
			];

			let foundLastUsedAddress = false;
			let foundLastUsedChangeAddress = false;
			let addressHasBeenUsed = false;
			let changeAddressHasBeenUsed = false;

			// If an error occurs, return last known/available indexes.
			const lastKnownIndexes = ok({
				addressIndex,
				lastUsedAddressIndex,
				changeAddressIndex,
				lastUsedChangeAddressIndex
			});

			while (!foundLastUsedAddress || !foundLastUsedChangeAddress) {
				//Check if transactions are pending in the mempool.
				const addressHistory = await this.electrum.getAddressHistory({
					scriptHashes: combinedAddressesToScan
				});

				if (addressHistory.isErr()) {
					this.logger.warn(addressHistory.error.message);
					return lastKnownIndexes;
				}

				const txHashes = addressHistory.value;

				const highestUsedIndex = getHighestUsedIndexFromTxHashes({
					txHashes,
					addresses,
					changeAddresses,
					addressIndex: lastUsedAddressIndex,
					changeAddressIndex: lastUsedChangeAddressIndex
				});

				if (highestUsedIndex.isErr()) {
					this.logger.warn(highestUsedIndex.error.message);
					return lastKnownIndexes;
				}

				if (highestUsedIndex.value.foundAddressIndex) {
					lastUsedAddressIndex = highestUsedIndex.value.addressIndex;
					addressIndex = highestUsedIndex.value.addressIndex;
					addressHasBeenUsed = true;
				}
				if (highestUsedIndex.value.foundChangeAddressIndex) {
					lastUsedChangeAddressIndex =
						highestUsedIndex.value.changeAddressIndex;
					changeAddressIndex = highestUsedIndex.value.changeAddressIndex;
					changeAddressHasBeenUsed = true;
				}

				const highestStoredIndex = this.getHighestStoredAddressIndex({
					addressType
				});

				if (highestStoredIndex.isErr()) {
					this.logger.warn(highestStoredIndex.error.message);
					return lastKnownIndexes;
				}

				const {
					addressIndex: highestUsedAddressIndex,
					changeAddressIndex: highestUsedChangeAddressIndex
				} = highestUsedIndex.value;
				const {
					addressIndex: highestStoredAddressIndex,
					changeAddressIndex: highestStoredChangeAddressIndex
				} = highestStoredIndex.value;

				if (
					getAddressIndexDiff(
						highestUsedAddressIndex.index,
						highestStoredAddressIndex.index
					) >= this.gapLimitOptions.lookAhead
				) {
					foundLastUsedAddress = true;
				}

				if (
					getAddressIndexDiff(
						highestUsedChangeAddressIndex.index,
						highestStoredChangeAddressIndex.index
					) >= this.gapLimitOptions.lookAheadChange
				) {
					foundLastUsedChangeAddress = true;
				}

				if (foundLastUsedAddress && foundLastUsedChangeAddress) {
					//Increase index by one if the current index was found in a txHash or is greater than the previous index.
					let newAddressIndex = addressIndex.index;
					if (
						highestUsedAddressIndex.index > addressIndex.index ||
						addressHasBeenUsed
					) {
						const index = highestUsedAddressIndex.index;
						if (highestUsedAddressIndex && index >= 0) {
							lastUsedAddressIndex = highestUsedAddressIndex;
						}
						newAddressIndex = index >= 0 ? index + 1 : index;
					}

					let newChangeAddressIndex = changeAddressIndex.index;
					if (
						highestUsedChangeAddressIndex.index > changeAddressIndex.index ||
						changeAddressHasBeenUsed
					) {
						const index = highestUsedChangeAddressIndex.index;
						if (highestUsedChangeAddressIndex && index >= 0) {
							lastUsedChangeAddressIndex = highestUsedChangeAddressIndex;
						}
						newChangeAddressIndex = index >= 0 ? index + 1 : index;
					}

					//Find and return the new address index.
					const nextAvailableAddress = Object.values(allAddresses).find(
						({ index }) => index === newAddressIndex
					);
					//Find and return the new change address index.
					const nextAvailableChangeAddress = Object.values(
						allChangeAddresses
					).find(({ index }) => index === newChangeAddressIndex);
					if (!nextAvailableAddress || !nextAvailableChangeAddress) {
						return lastKnownIndexes;
					}
					await Promise.all([
						this.saveWalletData('addresses', this._data.addresses),
						this.saveWalletData('changeAddresses', this._data.changeAddresses)
					]);
					return ok({
						addressIndex: nextAvailableAddress,
						lastUsedAddressIndex,
						changeAddressIndex: nextAvailableChangeAddress,
						lastUsedChangeAddressIndex
					});
				}

				//Create receiving addresses for the next round
				if (!foundLastUsedAddress) {
					const addressAmount =
						this.gapLimitOptions.lookAhead -
						getAddressIndexDiff(
							highestUsedAddressIndex.index,
							highestStoredAddressIndex.index
						);
					const newAddresses = await this.addAddresses({
						addressAmount,
						changeAddressAmount: 0,
						addressIndex: highestStoredIndex.value.addressIndex.index + 1,
						changeAddressIndex: 0,
						keyDerivationPath,
						addressType,
						saveAddresses: false
					});
					if (newAddresses.isOk()) {
						addresses = newAddresses.value.addresses || {};
					}
				}
				//Create change addresses for the next round
				if (!foundLastUsedChangeAddress) {
					const changeAddressAmount =
						this.gapLimitOptions.lookAheadChange -
						getAddressIndexDiff(
							highestUsedChangeAddressIndex.index,
							highestStoredChangeAddressIndex.index
						);
					const newChangeAddresses = await this.addAddresses({
						addressAmount: 0,
						changeAddressAmount,
						addressIndex: 0,
						changeAddressIndex:
							highestStoredIndex.value.changeAddressIndex.index + 1,
						keyDerivationPath,
						addressType,
						saveAddresses: false
					});
					if (newChangeAddresses.isOk()) {
						changeAddresses = newChangeAddresses.value.changeAddresses || {};
					}
				}

				// Store newly created addresses to scan in the next round.
				addressesToScan = Object.values(addresses);
				changeAddressesToScan = Object.values(changeAddresses);
				combinedAddressesToScan = [
					...addressesToScan,
					...changeAddressesToScan
				];
				// Store the newly created addresses used for this method.
				allAddresses = [...allAddresses, ...addressesToScan];
				allChangeAddresses = [...allChangeAddresses, ...changeAddressesToScan];
				// Check UTXO's as we generate addresses.
				await this.getUtxos({
					addressIndex: addressIndex.index,
					changeAddressIndex: changeAddressIndex.index,
					addressTypesToCheck: [addressType]
				});
			}

			await Promise.all([
				this.saveWalletData('addresses', this._data.addresses),
				this.saveWalletData('changeAddresses', this._data.changeAddresses)
			]);

			return lastKnownIndexes;
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns the highest address and change address index stored in the app for the specified wallet and network.
	 * Retrives the highest stored address index for the provided address type.
	 * @param {EAddressType} addressType
	 * @returns {Result<{ addressIndex: IAddress; changeAddressIndex: IAddress }>}
	 */
	public getHighestStoredAddressIndex({
		addressType
	}: {
		addressType: EAddressType;
	}): Result<{
		addressIndex: IAddress;
		changeAddressIndex: IAddress;
	}> {
		try {
			const currentWallet = this.data;
			const addresses = currentWallet.addresses[addressType];
			const changeAddresses = currentWallet.changeAddresses[addressType];

			const addressIndex = Object.values(addresses).reduce((prev, current) => {
				return prev.index > current.index ? prev : current;
			});

			const changeAddressIndex = Object.values(changeAddresses).reduce(
				(prev, current) => (prev.index > current.index ? prev : current)
			);

			return ok({ addressIndex, changeAddressIndex });
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * This method will generate addresses as specified and return an object of filtered addresses to ensure no duplicates are returned.
	 * @async
	 * @private
	 * @param {number} [addressAmount]
	 * @param {number} [changeAddressAmount]
	 * @param {number} [addressIndex]
	 * @param {number} [changeAddressIndex]
	 * @param {IKeyDerivationPath} [keyDerivationPath]
	 * @param {EAddressType} [addressType]
	 * @param {boolean} [saveAddresses] If true (default), will save new addresses to storage. When batching address-saves false is used.
	 * @returns {Promise<Result<IGenerateAddressesResponse>>}
	 */
	private async addAddresses({
		addressAmount = 5,
		changeAddressAmount = 5,
		addressIndex = 0,
		changeAddressIndex = 0,
		addressType = this.addressType,
		keyDerivationPath,
		saveAddresses = true
	}: IGenerateAddresses): Promise<Result<IGenerateAddressesResponse>> {
		const network = this._network;
		const { path, type } = addressTypes[addressType];
		if (!keyDerivationPath) {
			const keyDerivationPathResponse = getKeyDerivationPathObject({
				path,
				network
			});
			if (keyDerivationPathResponse.isErr()) {
				return err(keyDerivationPathResponse.error.message);
			}
			keyDerivationPath = keyDerivationPathResponse.value;
			keyDerivationPath.account = this._account;
		}
		const generatedAddresses = await this.generateAddresses({
			addressAmount,
			changeAddressAmount,
			addressIndex,
			changeAddressIndex,
			keyDerivationPath,
			addressType: type
		});
		if (generatedAddresses.isErr()) {
			return err(generatedAddresses.error);
		}

		const removeDuplicateResponse = await this.removeDuplicateAddresses({
			addresses: generatedAddresses.value.addresses,
			changeAddresses: generatedAddresses.value.changeAddresses
		});
		if (removeDuplicateResponse.isErr()) {
			return err(removeDuplicateResponse.error.message);
		}

		const addresses = removeDuplicateResponse.value.addresses;
		const changeAddresses = removeDuplicateResponse.value.changeAddresses;
		if (Object.keys(addresses).length) {
			this._data.addresses[addressType] = {
				...this.data.addresses[addressType],
				...addresses
			};
			if (saveAddresses)
				await this.saveWalletData('addresses', this._data.addresses);
		}
		if (Object.keys(changeAddresses).length) {
			this._data.changeAddresses[addressType] = {
				...this.data.changeAddresses[addressType],
				...changeAddresses
			};
			if (saveAddresses)
				await this.saveWalletData(
					'changeAddresses',
					this._data.changeAddresses
				);
		}

		return ok({ ...generatedAddresses.value, addressType: type });
	}

	/**
	 * This method will compare a set of specified addresses to the currently stored addresses and remove any duplicates.
	 * @private
	 * @async
	 * @param {IAddresses} addresses
	 * @param {IAddresses} changeAddresses
	 * @returns {Promise<Result<IGenerateAddressesResponse>>}
	 */
	private async removeDuplicateAddresses({
		addresses = {},
		changeAddresses = {}
	}: {
		addresses?: IAddresses;
		changeAddresses?: IAddresses;
	}): Promise<Result<IGenerateAddressesResponse>> {
		try {
			const currentWallet: IWalletData = this.data;
			const currentAddressTypeContent: TAddressTypeContent<IAddresses> =
				currentWallet.addresses;
			const currentChangeAddressTypeContent: TAddressTypeContent<IAddresses> =
				currentWallet.changeAddresses;

			//Remove any duplicate addresses.
			await Promise.all([
				objectKeys(currentAddressTypeContent).map(async (addressType) => {
					await Promise.all(
						objectKeys(addresses).map((scriptHash) => {
							if (scriptHash in currentAddressTypeContent[addressType]) {
								delete addresses[scriptHash];
							}
						})
					);
				}),

				objectKeys(currentChangeAddressTypeContent).map(async (addressType) => {
					await Promise.all(
						objectKeys(changeAddresses).map((scriptHash) => {
							if (scriptHash in currentChangeAddressTypeContent[addressType]) {
								delete changeAddresses[scriptHash];
							}
						})
					);
				})
			]);

			return ok({ addresses, changeAddresses });
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * This method updates the next available (zero-balance) address & changeAddress index.
	 * @private
	 * @async
	 * @returns {Promise<Result<string>>}
	 */
	private async updateAddressIndexes(): Promise<Result<string>> {
		const checkRes = await this.checkElectrumConnection();
		if (checkRes.isErr()) return err(checkRes.error.message);
		const currentWallet = this.data;

		let updated = false;

		const promises = this.addressTypesToMonitor.map(async (addressTypeKey) => {
			const response = await this.getNextAvailableAddress(addressTypeKey);
			if (response.isErr()) {
				throw response.error;
			}
			const result = response.value;
			let addressIndex = currentWallet.addressIndex[addressTypeKey];
			let changeAddressIndex = currentWallet.changeAddressIndex[addressTypeKey];
			let lastUsedAddressIndex =
				currentWallet.lastUsedAddressIndex[addressTypeKey];
			let lastUsedChangeAddressIndex =
				currentWallet.lastUsedChangeAddressIndex[addressTypeKey];
			if (
				addressIndex.index < 0 ||
				changeAddressIndex.index < 0 ||
				result.addressIndex.index > addressIndex.index ||
				result.changeAddressIndex.index > changeAddressIndex.index ||
				result.lastUsedAddressIndex.index > lastUsedAddressIndex.index ||
				result.lastUsedChangeAddressIndex.index >
					lastUsedChangeAddressIndex?.index
			) {
				if (result.addressIndex) {
					addressIndex = result.addressIndex;
				}

				if (result.changeAddressIndex) {
					changeAddressIndex = result.changeAddressIndex;
				}

				if (result.lastUsedAddressIndex) {
					lastUsedAddressIndex = result.lastUsedAddressIndex;
				}

				if (result.lastUsedChangeAddressIndex) {
					lastUsedChangeAddressIndex = result.lastUsedChangeAddressIndex;
				}

				//Final check to ensure that both addresses and change addresses do not exceed the gap limit/scanning threshold.
				//If either does, we generate a new addresses and/or change address at +1 the last used index.
				const lastUsedIndex =
					lastUsedAddressIndex.index > 0 ? lastUsedAddressIndex.index : 0;
				const currentGap = Math.abs(addressIndex.index - lastUsedIndex);
				if (currentGap > this.gapLimitOptions.lookBehind) {
					const excessAmount = currentGap - this.gapLimitOptions.lookBehind;
					const newIndex = addressIndex.index - excessAmount;
					const _addressIndex = await this.generateAddresses({
						addressType: addressTypeKey,
						addressAmount: 1,
						changeAddressAmount: 0,
						addressIndex: newIndex
					});
					if (_addressIndex.isErr()) {
						return err(_addressIndex.error.message);
					}
					addressIndex = Object.values(_addressIndex.value.addresses)[0];
				}

				const lastUsedChangeIndex =
					lastUsedChangeAddressIndex.index > 0
						? lastUsedChangeAddressIndex.index
						: 0;
				const currentChangeAddressGap = Math.abs(
					changeAddressIndex.index - lastUsedChangeIndex
				);
				if (currentChangeAddressGap > this.gapLimitOptions.lookBehindChange) {
					// Clamp the CHANGE chain using the change gap/index, not the receive
					// chain's currentGap / addressIndex.index. The copy-pasted receive
					// variables here could place change past the gap (undiscoverable by
					// a standard restore) or reuse an address.
					const excessAmount =
						currentChangeAddressGap - this.gapLimitOptions.lookBehindChange;
					const newIndex = changeAddressIndex.index - excessAmount;
					const _changeAddressIndex = await this.generateAddresses({
						addressType: addressTypeKey,
						addressAmount: 0,
						changeAddressAmount: 1,
						changeAddressIndex: newIndex
					});
					if (_changeAddressIndex.isErr()) {
						return err(_changeAddressIndex.error.message);
					}
					changeAddressIndex = Object.values(
						_changeAddressIndex.value.changeAddresses
					)[0];
				}

				this._data.addressIndex[addressTypeKey] = addressIndex;
				this._data.changeAddressIndex[addressTypeKey] = changeAddressIndex;
				this._data.lastUsedAddressIndex[addressTypeKey] = lastUsedAddressIndex;
				this._data.lastUsedChangeAddressIndex[addressTypeKey] =
					lastUsedChangeAddressIndex;
				updated = true;
			}
		});
		try {
			await Promise.all(promises);
			if (updated) {
				await Promise.all([
					this.saveWalletData('addressIndex', this._data.addressIndex),
					this.saveWalletData(
						'changeAddressIndex',
						this._data.changeAddressIndex
					),
					this.saveWalletData(
						'lastUsedAddressIndex',
						this._data.lastUsedAddressIndex
					),
					this.saveWalletData(
						'lastUsedChangeAddressIndex',
						this._data.lastUsedChangeAddressIndex
					)
				]);
			}
			return ok(
				updated ? 'Successfully updated indexes.' : 'No update needed.'
			);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Resets address indexes back to the app's default/original state.
	 * @private
	 * @returns {void}
	 */
	public async resetAddressIndexes(): Promise<void> {
		const defaultWalletShape = getDefaultWalletData();
		this._data.addressIndex = defaultWalletShape.addressIndex;
		this._data.changeAddressIndex = defaultWalletShape.changeAddressIndex;
		this._data.lastUsedAddressIndex = defaultWalletShape.lastUsedAddressIndex;
		this._data.lastUsedChangeAddressIndex =
			defaultWalletShape.lastUsedChangeAddressIndex;
		await Promise.all([
			this.saveWalletData('addressIndex', this._data.addressIndex),
			this.saveWalletData('changeAddressIndex', this._data.changeAddressIndex),
			this.saveWalletData(
				'lastUsedAddressIndex',
				this._data.lastUsedAddressIndex
			),
			this.saveWalletData(
				'lastUsedChangeAddressIndex',
				this._data.lastUsedChangeAddressIndex
			)
		]);
	}

	/**
	 * Generate a new receive address for the provided addresstype up to the set gap limit.
	 * @async
	 * @param {EAddressType} addressType
	 * @param {boolean} [overrideGapLimit] WARNING: Only set to true if you understand what you're doing. This can result in other wallets not seeing your funds as this will override the previously set/standard gap limit.
	 * @param {IKeyDerivationPath} keyDerivationPath
	 * @returns {Promise<Result<IAddress>>}
	 */
	public async generateNewReceiveAddress({
		addressType = this.addressType,
		overrideGapLimit = false, // WARNING: Only set to true if you understand what you're doing. This can result in other wallets not seeing your funds as this will override the previously set/standard gap limit.
		keyDerivationPath
	}: {
		addressType?: EAddressType;
		overrideGapLimit?: boolean; // WARNING: Only set to true if you understand what you're doing. This can result in other wallets not seeing your funds as this will override the previously set/standard gap limit.
		keyDerivationPath?: IKeyDerivationPath;
	} = {}): Promise<Result<IAddress>> {
		try {
			const network = this._network;
			const currentWallet = this.data;

			const getGapLimitResponse = this.getGapLimit({
				addressType
			});
			if (getGapLimitResponse.isErr()) {
				return err(getGapLimitResponse.error.message);
			}
			const { addressDelta } = getGapLimitResponse.value;

			// If the address delta exceeds the default gap limit, only return the current address index.
			if (
				addressDelta >= this.gapLimitOptions.lookBehind &&
				!overrideGapLimit
			) {
				const addressIndex = currentWallet.addressIndex;
				const receiveAddress = addressIndex[addressType];
				return ok(receiveAddress);
			}

			const { path } = addressTypes[addressType];
			if (!keyDerivationPath) {
				const keyDerivationPathResponse = getKeyDerivationPathObject({
					network,
					path
				});
				if (keyDerivationPathResponse.isErr()) {
					return err(keyDerivationPathResponse.error.message);
				}
				keyDerivationPath = keyDerivationPathResponse.value;
				keyDerivationPath.account = this._account;
			}
			const addresses: IAddresses = currentWallet.addresses[addressType];
			const currentAddressIndex: number =
				currentWallet.addressIndex[addressType].index;
			const nextAddressIndex = Object.values(addresses).find((address) => {
				return address.index === currentAddressIndex + 1;
			});

			// Check if the next address index already exists or if it needs to be generated.
			if (nextAddressIndex) {
				// Update addressIndex and return the address content.
				this._data.addressIndex[addressType] = nextAddressIndex;
				await this.saveWalletData('addressIndex', this._data.addressIndex);
				return ok(nextAddressIndex);
			}

			// We need to generate, save and return the new address.
			const addAddressesRes = await this.addAddresses({
				addressAmount: 1,
				changeAddressAmount: 0,
				addressIndex: currentAddressIndex + 1,
				changeAddressIndex: 0,
				keyDerivationPath,
				addressType
			});
			if (addAddressesRes.isErr()) {
				return err(addAddressesRes.error.message);
			}
			const addressIndex = Object.values(this.data.addresses[addressType]).find(
				(addr) => addr.index === currentAddressIndex + 1
			);

			// If for any reason we're unable to generate the new address, return error.
			if (!addressIndex) {
				return err('Unable to generate addresses at this time.');
			}
			if (overrideGapLimit) {
				this.updateGapLimit({
					lookBehind:
						addressDelta > this.gapLimitOptions.lookBehind
							? addressDelta
							: this.gapLimitOptions.lookBehind,
					lookAhead:
						addressDelta > this.gapLimitOptions.lookAhead
							? addressDelta
							: this.gapLimitOptions.lookAhead,
					lookBehindChange:
						addressDelta > this.gapLimitOptions.lookBehindChange
							? addressDelta
							: this.gapLimitOptions.lookBehindChange,
					lookAheadChange:
						addressDelta > this.gapLimitOptions.lookAheadChange
							? addressDelta
							: this.gapLimitOptions.lookAheadChange
				});
			}
			this._data.addressIndex[addressType] = addressIndex;
			await this.saveWalletData('addressIndex', this._data.addressIndex);
			return ok(addressIndex);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns the difference between the current address index and the last used address index.
	 * @private
	 * @param {EAddressType} [addressType]
	 * @returns {Result<{ addressDelta: number; changeAddressDelta: number }>}
	 */
	public getGapLimit({
		addressType = this.addressType
	}: {
		addressType?: EAddressType;
	}): Result<{ addressDelta: number; changeAddressDelta: number }> {
		try {
			const currentWallet = this.data;
			const addressIndex = currentWallet.addressIndex[addressType].index;
			const lastUsedAddressIndex =
				currentWallet.lastUsedAddressIndex[addressType].index;
			const changeAddressIndex =
				currentWallet.changeAddressIndex[addressType].index;
			const lastUsedChangeAddressIndex =
				currentWallet.lastUsedChangeAddressIndex[addressType].index;
			const addressDelta = Math.abs(
				addressIndex - (lastUsedAddressIndex > 0 ? lastUsedAddressIndex : 0)
			);
			const changeAddressDelta = Math.abs(
				changeAddressIndex -
					(lastUsedChangeAddressIndex > 0 ? lastUsedChangeAddressIndex : 0)
			);

			return ok({ addressDelta, changeAddressDelta });
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Retrieves and sets UTXO's for the current wallet from Electrum.
	 * @param {EScanningStrategy} [scanningStrategy]
	 * @param {number} addressIndex
	 * @param {number} changeAddressIndex
	 * @param {EAddressType[]} [addressTypesToCheck]
	 * @returns {Promise<Result<IGetUtxosResponse>>}
	 */
	public async getUtxos({
		scanningStrategy = EScanningStrategy.gapLimit,
		addressIndex,
		changeAddressIndex,
		addressTypesToCheck,
		additionalAddresses = []
	}: {
		scanningStrategy?: EScanningStrategy;
		addressIndex?: number;
		changeAddressIndex?: number;
		addressTypesToCheck?: EAddressType[];
		additionalAddresses?: string[];
	}): Promise<Result<IGetUtxosResponse>> {
		const checkRes = await this.checkElectrumConnection();
		if (checkRes.isErr()) return err(checkRes.error.message);
		const getUtxosRes = await this.electrum.getUtxos({
			scanningStrategy,
			addressIndex,
			changeAddressIndex,
			addressTypesToCheck,
			additionalAddresses
		});
		if (getUtxosRes.isErr()) {
			return err(getUtxosRes.error.message);
		}
		const utxos = removeDustUtxos(getUtxosRes.value?.utxos ?? []);
		const balance = getUtxosRes.value?.balance ?? 0;
		this._data.utxos = utxos;
		this._data.balance = balance;
		await Promise.all([
			this.saveWalletData('utxos', this._data.utxos),
			this.saveWalletData('balance', this._data.balance)
		]);
		return ok({ utxos, balance });
	}

	/**
	 * Returns the current wallet's UTXO's from storage.
	 * @returns {IUtxo[]}
	 */
	listUtxos(): IUtxo[] {
		return this.data.utxos;
	}

	/**
	 * Returns true when the given outpoint is currently frozen (blacklisted).
	 * @param {string} txid
	 * @param {number} index
	 * @returns {boolean}
	 */
	public isUtxoFrozen(txid: string, index: number): boolean {
		return this.data.blacklistedUtxos.some(
			(frozen) => frozen.tx_hash === txid && frozen.tx_pos === index
		);
	}

	/**
	 * Freezes a wallet UTXO: it is excluded from every wallet-driven coin
	 * selection path (send/sendMany/sendMax/consolidate/buildPsbt) until
	 * unfrozen, while still counting toward getBalance(). Persists through
	 * the existing blacklistedUtxos wallet data. Matching is by outpoint
	 * (txid + index) so confirmation height changes cannot unfreeze it.
	 * @param {string} txid
	 * @param {number} index
	 * @returns {Promise<Result<string>>}
	 */
	public async freezeUtxo({
		txid,
		index,
		tag
	}: {
		txid: string;
		index: number;
		/** Optional origin marker (e.g. 'funding-pledge') persisted with the
		 *  entry so automated freezers can recognize, and recover, their own
		 *  freezes after a restart without touching user-frozen coins. */
		tag?: string;
	}): Promise<Result<string>> {
		if (typeof txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(txid)) {
			return err('txid must be a 64-character hex string.');
		}
		if (!Number.isInteger(index) || index < 0) {
			return err('index must be a non-negative integer.');
		}
		const utxo = this.data.utxos.find(
			(u) => u.tx_hash === txid && u.tx_pos === index
		);
		if (!utxo) {
			return err(`UTXO ${txid}:${index} is not known to this wallet.`);
		}
		if (this.isUtxoFrozen(txid, index)) {
			return ok(`UTXO ${txid}:${index} is already frozen.`);
		}
		// keyPair must never be persisted with the frozen entry.
		const { keyPair, ...frozen } = utxo;
		void keyPair;
		this._data.blacklistedUtxos.push({
			...frozen,
			...(tag !== undefined ? { freezeTag: tag, frozenAt: Date.now() } : {})
		});
		await this.saveWalletData('blacklistedUtxos', this._data.blacklistedUtxos);
		return ok(`UTXO ${txid}:${index} frozen.`);
	}

	/**
	 * Unfreezes a previously frozen UTXO, making it spendable again.
	 * @param {string} txid
	 * @param {number} index
	 * @returns {Promise<Result<string>>}
	 */
	public async unfreezeUtxo({
		txid,
		index
	}: {
		txid: string;
		index: number;
	}): Promise<Result<string>> {
		const before = this._data.blacklistedUtxos.length;
		this._data.blacklistedUtxos = this._data.blacklistedUtxos.filter(
			(frozen) => !(frozen.tx_hash === txid && frozen.tx_pos === index)
		);
		if (this._data.blacklistedUtxos.length === before) {
			return err(`UTXO ${txid}:${index} is not frozen.`);
		}
		await this.saveWalletData('blacklistedUtxos', this._data.blacklistedUtxos);
		return ok(`UTXO ${txid}:${index} unfrozen.`);
	}

	/**
	 * Returns the frozen (blacklisted) UTXO entries. Entries are kept even
	 * when the underlying outpoint has been spent or is not currently in the
	 * UTXO set; matching against live UTXOs is by txid + index.
	 * @returns {IUtxo[]}
	 */
	public listFrozenUtxos(): IUtxo[] {
		return this.data.blacklistedUtxos;
	}

	/**
	 * Splits the stored balance into spendable and frozen portions.
	 * getBalance() keeps returning the total.
	 * @returns {IBalanceBreakdown}
	 */
	public getBalanceBreakdown(): IBalanceBreakdown {
		const total = this.getBalance();
		const frozen = this.data.utxos.reduce((acc, utxo) => {
			return this.isUtxoFrozen(utxo.tx_hash, utxo.tx_pos)
				? acc + utxo.value
				: acc;
		}, 0);
		return { total, spendable: total - frozen, frozen };
	}

	/**
	 * Sets (or clears, when label is empty) a user label for an address.
	 * Stored in its own addressLabels map; the pre-existing
	 * IAddressData.label field (the address-type name) is untouched.
	 * @param {string} address
	 * @param {string} label
	 * @returns {Promise<Result<string>>}
	 */
	public async setAddressLabel(
		address: string,
		label: string
	): Promise<Result<string>> {
		if (!address || !this.validateAddress(address)) {
			return err(`Invalid ${this._network} address: ${address}`);
		}
		if (typeof label !== 'string') {
			return err('label must be a string.');
		}
		if (label.length > 255) {
			return err('label must be 255 characters or fewer.');
		}
		if (label === '') {
			delete this._data.addressLabels[address];
		} else {
			this._data.addressLabels[address] = label;
		}
		await this.saveWalletData('addressLabels', this._data.addressLabels);
		return ok(label === '' ? 'Label removed.' : 'Label saved.');
	}

	/**
	 * Returns the user label for an address, if any.
	 * @param {string} address
	 * @returns {string | undefined}
	 */
	public getAddressLabel(address: string): string | undefined {
		return this.data.addressLabels[address];
	}

	/**
	 * Returns all user address labels keyed by address.
	 * @returns {TAddressLabels}
	 */
	public listAddressLabels(): TAddressLabels {
		return { ...this.data.addressLabels };
	}

	/**
	 * Exports BIP 380 output descriptors (with checksums) for this wallet.
	 * Full wallets export all four address types with key origin info
	 * ([fingerprint/purpose'/coin'/account']). Watch-only wallets and
	 * external multisig cosigners include a full key origin when a
	 * masterFingerprint + originPath were supplied at creation; otherwise
	 * origins are omitted (watch-only) or fingerprint-only (cosigners),
	 * since a true origin cannot be derived from an xpub alone.
	 * NO PRIVATE KEYS are ever included.
	 * @returns {Result<IExportDescriptorsResponse>}
	 */
	public exportDescriptors(): Result<IExportDescriptorsResponse> {
		try {
			const fingerprint = this.getMasterFingerprint().toString('hex');
			const descriptors: IExportedDescriptor[] = [];
			const wrap = (addressType: EAddressType, keyExpr: string): string => {
				switch (addressType) {
					case EAddressType.p2pkh:
						return `pkh(${keyExpr})`;
					case EAddressType.p2sh:
						return `sh(wpkh(${keyExpr}))`;
					case EAddressType.p2wpkh:
						return `wpkh(${keyExpr})`;
					case EAddressType.p2tr:
						return `tr(${keyExpr})`;
					case EAddressType.p2wsh:
						// Multisig descriptors are assembled in the multisig branch
						// below; p2wsh is filtered out of the single-sig loop.
						return `wsh(${keyExpr})`;
				}
			};
			if (this._multisig) {
				// wsh(sortedmulti(k, key1, key2, ...)): our key carries the full
				// origin (master fingerprint + BIP 48 path); cosigners known only
				// as xpubs carry a fingerprint-only origin (the account key's
				// parent fingerprint, the watch-only single-sig convention).
				const coinType =
					this._network === EAvailableNetworks.bitcoin ? '0' : '1';
				const keyExpr = (chain: 0 | 1): string => {
					const keys = this._multisig!.cosigners.map((cosigner) => {
						const xpub = this._toStandardBase58(cosigner.node);
						let origin: string;
						if (cosigner.isOurs && this._root) {
							origin = `[${fingerprint}/48h/${coinType}h/${this._account}h/2h]`;
						} else if (cosigner.keyOrigin?.path) {
							// BIP 380 key origin: the cosigner's own master fingerprint
							// followed by the full path from that master to the xpub.
							const fp = cosigner.keyOrigin.fingerprint.toString('hex');
							const originPath = cosigner.keyOrigin.path.replace(/'/g, 'h');
							origin = `[${fp}/${originPath}]`;
						} else {
							const parentFp = Buffer.alloc(4);
							parentFp.writeUInt32BE(cosigner.node.parentFingerprint ?? 0, 0);
							origin = `[${parentFp.toString('hex')}]`;
						}
						return `${origin}${xpub}/${chain}/*`;
					});
					return `sortedmulti(${this._multisig!.threshold},${keys.join(',')})`;
				};
				descriptors.push({
					addressType: EAddressType.p2wsh,
					external: appendDescriptorChecksum(`wsh(${keyExpr(0)})`),
					internal: appendDescriptorChecksum(`wsh(${keyExpr(1)})`)
				});
			} else if (this.isWatchOnly) {
				if (!this._accountNode) {
					return err('Watch-only account node is unavailable.');
				}
				const xpub = this._toStandardBase58(this._accountNode);
				// With a supplied key origin the descriptor carries the full
				// BIP 380 origin; without one it stays origin-less as before.
				const origin = this._keyOrigin?.path
					? `[${this._keyOrigin.fingerprint.toString(
							'hex'
					  )}/${this._keyOrigin.path.replace(/'/g, 'h')}]`
					: '';
				descriptors.push({
					addressType: this.addressType,
					external: appendDescriptorChecksum(
						wrap(this.addressType, `${origin}${xpub}/0/*`)
					),
					internal: appendDescriptorChecksum(
						wrap(this.addressType, `${origin}${xpub}/1/*`)
					)
				});
			} else {
				if (!this._root) return err('Wallet root is unavailable.');
				const coinType =
					this._network === EAvailableNetworks.bitcoin ? '0' : '1';
				// p2wsh is multisig-only and has no single-key descriptor.
				const singleSigTypes = Object.values(EAddressType).filter(
					(type) => type !== EAddressType.p2wsh
				);
				for (const addressType of singleSigTypes) {
					const pathRes = getKeyDerivationPathObject({
						path: addressTypes[addressType].path,
						network: this._network
					});
					if (pathRes.isErr()) return err(pathRes.error.message);
					const purpose = pathRes.value.purpose;
					const accountPath = `m/${purpose}'/${coinType}'/${this._account}'`;
					// neutered(): the exported node carries public material only.
					const accountXpub = this._toStandardBase58(
						this._root.derivePath(accountPath).neutered()
					);
					const origin = `[${fingerprint}/${purpose}h/${coinType}h/${this._account}h]`;
					descriptors.push({
						addressType,
						external: appendDescriptorChecksum(
							wrap(addressType, `${origin}${accountXpub}/0/*`)
						),
						internal: appendDescriptorChecksum(
							wrap(addressType, `${origin}${accountXpub}/1/*`)
						)
					});
				}
			}
			const birthdayHeight = this.birthdayHeight;
			return ok({
				fingerprint,
				network: this._network,
				account: Number(this._account),
				...(birthdayHeight > 0 ? { birthdayHeight } : {}),
				watchOnly: this.isWatchOnly,
				descriptors
			});
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Re-encodes a public BIP32 node with the network's standard version
	 * bytes (xpub/tpub). Watch-only account nodes parsed from SLIP-132
	 * encodings (ypub/zpub/upub/vpub) otherwise serialize with their
	 * non-standard prefix, which descriptor parsers reject.
	 * @param {BIP32Interface} node
	 * @returns {string}
	 * @private
	 */
	private _toStandardBase58(node: BIP32Interface): string {
		const standard = this.getBitcoinNetwork(this._network);
		if (node.network?.bip32?.public === standard.bip32.public) {
			return node.toBase58();
		}
		// Property-descriptor clone: swaps only the version bytes used by
		// toBase58 while preserving depth/parentFingerprint/index metadata.
		const clone = Object.create(
			Object.getPrototypeOf(node),
			Object.getOwnPropertyDescriptors(node)
		) as BIP32Interface;
		(clone as { network: Network }).network = standard;
		return clone.toBase58();
	}

	/**
	 * Saves the wallet data object to storage if able.
	 * @private
	 * @async
	 * @param {TWalletDataKeys} key
	 * @param {IWalletData[K]} data
	 * @returns {Promise<void>}
	 */
	private savingOperations: Record<string, Promise<string>> = {};
	public async saveWalletData<K extends keyof IWalletData>(
		key: TWalletDataKeys,
		data: IWalletData[K]
	): Promise<string> {
		if (!this._setData) return 'No setData method has been provided';

		// Check if there's an ongoing save operation for the same key
		if (key in this.savingOperations) {
			// Wait for the ongoing operation to complete
			await this.savingOperations[key];
		}

		const walletDataKey = this.getWalletDataKey(key);
		// Create a new save operation
		this.savingOperations[key] = this._setData(walletDataKey, data)
			.then(() => {
				return `${walletDataKey} data saved successfully`;
			})
			.catch((error) => {
				return `Error saving wallet data for ${walletDataKey}: ${error}`;
			})
			.finally(() => {
				// Remove the operation once it's completed
				delete this.savingOperations[key];
			});

		// Wait for the save operation to complete
		return await this.savingOperations[key];
	}

	//TODO: Implement this as a way to better update and save state so we can consolidate this.data[key] updates.
	// @ts-ignore
	private async updateAndSaveWalletData(
		key: TWalletDataKeys,
		data: IWalletData,
		addressType?: EAddressType
	): Promise<void> {
		if (addressType) {
			this.data[key][addressType] = data;
			await this.saveWalletData(key, this._data[key]);
		} else {
			// @ts-ignore
			this.data[key] = data;
			await this.saveWalletData(key, this._data[key]);
		}
	}

	/**
	 * Retrieves, formats & stores the transaction history for the selected wallet/network.
	 * @param {boolean} [scanAllAddresses]
	 * @param {boolean} [replaceStoredTransactions] Setting this to true will set scanAllAddresses to true as well.
	 * @returns {Promise<Result<string | undefined>>}
	 */
	public async updateTransactions({
		scanAllAddresses = false,
		replaceStoredTransactions = false
	}: {
		scanAllAddresses?: boolean;
		replaceStoredTransactions?: boolean;
	}): Promise<Result<string | undefined>> {
		//Check existing unconfirmed transactions and remove any that are confirmed.
		//If the tx is reorg'd or bumped from the mempool and no longer exists, the transaction will be removed from the store and updated in the activity list.
		await this.checkUnconfirmedTransactions();

		const history = await this.electrum.getAddressHistory({
			scanAllAddresses: scanAllAddresses || replaceStoredTransactions
		});
		if (history.isErr()) {
			return err(history.error.message);
		}
		if (!history.value.length) {
			return ok(undefined);
		}

		// Filter out transactions that are already confirmed.
		let filteredTxHashes = history.value;
		if (!replaceStoredTransactions) {
			filteredTxHashes = history.value.filter((tx) => {
				return !((this.data.transactions[tx.tx_hash]?.height ?? 0) >= 6);
			});
		}

		const getTransactionsResponse = await this.electrum.getTransactions({
			txHashes: filteredTxHashes
		});
		if (getTransactionsResponse.isErr()) {
			return err(getTransactionsResponse.error.message);
		}

		const formatTransactionsResponse = await this.formatTransactions({
			transactions: getTransactionsResponse.value.data
		});
		if (formatTransactionsResponse.isErr()) {
			return err(formatTransactionsResponse.error.message);
		}
		const transactions = formatTransactionsResponse.value;

		// Add unconfirmed transactions.
		// No need to wait for this to finish.
		this.addUnconfirmedTransactions({
			transactions
		});

		if (replaceStoredTransactions) {
			// No need to check the existing txs since we're replacing them. Update with the returned formatTransactionsResponse.
			this._data.transactions = transactions;
			await this.saveWalletData('transactions', this._data.transactions);
			return ok(undefined);
		}

		// Handle new or updated transactions.
		const formattedTransactions: IFormattedTransactions = {};

		let notificationTxid: string | undefined;
		const storedTransactions = this.data.transactions;
		const confirmedTxs: TTransactionMessage[] = [];
		const receivedTxs: TTransactionMessage[] = [];
		const sentTxs: TTransactionMessage[] = [];

		Object.keys(transactions).forEach((txid) => {
			//If the tx is new or the tx now has a block height (state changed to confirmed)
			if (
				!storedTransactions[txid] ||
				storedTransactions[txid].height !== transactions[txid].height
			) {
				formattedTransactions[txid] = {
					...transactions[txid],
					// Keep the previous timestamp if the tx is not new.
					timestamp:
						storedTransactions[txid]?.timestamp ??
						transactions[txid]?.timestamp ??
						Date.now()
				};
				if ((formattedTransactions[txid]?.height ?? 0) > 0)
					confirmedTxs.push({ transaction: formattedTransactions[txid] });
			}

			// if the tx is new, incoming but not from a transfer - show notification
			if (!(txid in storedTransactions)) {
				if (transactions[txid].type === EPaymentType.received) {
					receivedTxs.push({ transaction: transactions[txid] });
				} else if (transactions[txid].type === EPaymentType.sent) {
					sentTxs.push({ transaction: transactions[txid] });
				}
				notificationTxid = txid;
			}
		});

		//No new or updated transactions
		if (!Object.keys(formattedTransactions).length) {
			return ok(undefined);
		}

		this._data.transactions = {
			...this._data.transactions,
			...formattedTransactions
		};
		await this.saveWalletData('transactions', this._data.transactions);

		confirmedTxs.forEach((tx) => {
			this.sendMessage('transactionConfirmed', tx);
		});

		sentTxs.forEach((tx) => {
			this.sendMessage('transactionSent', tx);
		});

		const addresses = this.data.addresses;
		const utxoScriptHashes = new Set(
			this.data.utxos.map((utxo) => utxo.scriptHash)
		);
		const outsideGapLimitAddresses: {
			[key: string]: number[];
		} = {};
		for (const tx of receivedTxs) {
			// No need to scan an address with a saved UTXO.
			if (utxoScriptHashes.has(tx.transaction.scriptHash)) continue;
			for (const addressType in addresses) {
				const addressData: IAddresses = addresses[addressType];
				if (tx.transaction.scriptHash in addressData) {
					const address = addressData[tx.transaction.scriptHash];
					const index = address.index;
					const currentIndex = this.data.addressIndex[addressType].index;
					const diff = getAddressIndexDiff(index, currentIndex);
					if (diff > this.gapLimitOptions.lookBehind) {
						outsideGapLimitAddresses[addressType] = [
							...(outsideGapLimitAddresses[addressType] ?? []),
							index
						];
					}
					break;
				}
			}
		}
		if (receivedTxs.length > 0) {
			// Scan for received transactions to addresses out of the specified gap limit that we may still be subscribed to from the current session.
			for (const type of Object.keys(outsideGapLimitAddresses)) {
				const indexes = outsideGapLimitAddresses[type];
				if (indexes.length <= 0) continue;
				const lowestIndex = Math.min(...indexes);
				const addressType = type as EAddressType;
				await this.getUtxos({
					scanningStrategy: EScanningStrategy.startingIndex,
					addressIndex: lowestIndex - this.gapLimitOptions.lookBehind,
					changeAddressIndex:
						lowestIndex - this.gapLimitOptions.lookBehindChange,
					addressTypesToCheck: [addressType]
				});
			}
		}

		for (const tx of receivedTxs) {
			this.sendMessage('transactionReceived', tx);
		}

		return ok(notificationTxid);
	}

	/**
	 * Checks existing unconfirmed transactions that have been received and removes any that have >= 6 confirmations.
	 * If the tx is reorg'd or bumped from the mempool and no longer exists, the transaction
	 * will be removed from the store and updated in the activity list.
	 * @private
	 * @async
	 * @returns {Promise<Result<string>>}
	 */
	async checkUnconfirmedTransactions(
		reorgDetected = false
	): Promise<Result<string>> {
		try {
			const processRes = await this.processUnconfirmedTransactions();
			if (processRes.isErr()) {
				return err(processRes.error.message);
			}

			const { unconfirmedTxs, outdatedTxs, ghostTxs } = processRes.value;
			if (outdatedTxs.length > 0 || reorgDetected) {
				this.sendMessage('reorg', outdatedTxs);
				//We need to update the height of the transactions that were reorg'd out.
				await this.updateTransactionHeights(outdatedTxs);
			}
			if (ghostTxs.length > 0) {
				this.sendMessage('rbf', ghostTxs);
				//We need to update the ghost transactions in the store & activity-list and rescan the addresses to get the correct balance.
				await this.updateGhostTransactions({
					txIds: ghostTxs
				});
			} else {
				this._data.unconfirmedTransactions = unconfirmedTxs;
				await this.saveWalletData(
					'unconfirmedTransactions',
					this._data.unconfirmedTransactions
				);
			}
			return ok('Successfully updated unconfirmed transactions.');
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * This method processes all transactions with less than 6 confirmations and returns the following:
	 * 1. Transactions that still have less than 6 confirmations and can be considered unconfirmed. (unconfirmedTxs)
	 * 2. Transactions that have fewer confirmations than before due to a reorg. (outdatedTxs)
	 * 3. Transactions that have been removed from the mempool. (ghostTxs)
	 * @private
	 * @async
	 * @returns {Promise<Result<TProcessUnconfirmedTransactions>>}
	 */
	private async processUnconfirmedTransactions(): Promise<
		Result<TProcessUnconfirmedTransactions>
	> {
		try {
			//Retrieve all unconfirmed transactions (tx less than 6 confirmations in this case) from the store
			const oldUnconfirmedTxs = this.getUnconfirmedTransactions();

			//Use electrum to check if the transaction was removed/bumped from the mempool or if it still exists.
			const tx_hashes: ITxHash[] = Object.values(oldUnconfirmedTxs).map(
				(transaction: IFormattedTransaction) => {
					return { tx_hash: transaction.txid };
				}
			);
			const txs = await this.electrum.getTransactions({
				txHashes: tx_hashes
			});
			if (txs.isErr()) {
				return err(txs.error);
			}

			const unconfirmedTxs: IFormattedTransactions = {};
			const outdatedTxs: IUtxo[] = []; //Transactions that have been pushed back into the mempool due to a reorg. We need to update the height.
			const ghostTxs: string[] = []; //Transactions that have been removed from the mempool and are no longer in the blockchain.
			txs.value.data.forEach((txData: ITransaction<IUtxo>) => {
				// Check if the transaction has been removed from the mempool/still exists.
				if (!this.electrum.transactionExists(txData)) {
					//Transaction may have been removed/bumped from the mempool or potentially reorg'd out.
					ghostTxs.push(txData.data.tx_hash);
					return;
				}

				const newHeight = this.confirmationsToBlockHeight({
					confirmations: txData.result?.confirmations ?? 0
				});

				if (!txData.result?.confirmations) {
					const oldHeight = oldUnconfirmedTxs[txData.data.tx_hash]?.height ?? 0;
					if (oldHeight > newHeight) {
						//Transaction was reorg'd back to zero confirmations. Add it to the outdatedTxs array.
						outdatedTxs.push(txData.data);
					}
					unconfirmedTxs[txData.data.tx_hash] = {
						...oldUnconfirmedTxs[txData.data.tx_hash],
						height: newHeight
					};
					return;
				}

				//Check if the transaction has been confirmed.
				if (txData.result?.confirmations < 6) {
					unconfirmedTxs[txData.data.tx_hash] = {
						...oldUnconfirmedTxs[txData.data.tx_hash],
						height: newHeight
					};
				}
			});
			return ok({
				unconfirmedTxs,
				outdatedTxs,
				ghostTxs
			});
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns the current wallet's unconfirmed transactions from storage.
	 * @returns {Promise<Result<IFormattedTransactions>>}
	 */
	public getUnconfirmedTransactions(): IFormattedTransactions {
		const currentWallet = this.data;
		return currentWallet?.unconfirmedTransactions ?? {};
	}

	/**
	 * Returns the block height for a given number of confirmations from storage.
	 * @param {number} confirmations
	 * @param {number} [currentHeight]
	 * @param {TAvailableNetworks} [selectedNetwork]
	 * @returns {number}
	 */
	public confirmationsToBlockHeight({
		confirmations,
		currentHeight
	}: {
		confirmations: number;
		currentHeight?: number;
	}): number {
		if (!currentHeight) {
			const header = this.data.header;
			currentHeight = header.height;
		}
		if (confirmations > currentHeight) {
			return 0;
		}
		return currentHeight - confirmations;
	}

	/**
	 * Updates & Saves header information to storage.
	 * @param headerData
	 * @returns {Promise<void>}
	 */
	public async updateHeader(headerData: IHeader): Promise<void> {
		this._data.header = headerData;
		await this.saveWalletData('header', headerData);
	}

	/**
	 * Removes transactions from the store and activity list.
	 * @private
	 * @async
	 * @param {string[]} txIds
	 * @returns {Promise<Result<string>>}
	 */
	private async updateGhostTransactions({
		txIds
	}: {
		txIds: string[];
	}): Promise<Result<string>> {
		try {
			const transactions = this.data.transactions;
			const unconfirmedTransactions = this.data.unconfirmedTransactions;
			txIds.forEach((txId) => {
				if (txId in transactions) {
					transactions[txId]['exists'] = false;
				}
				if (txId in unconfirmedTransactions) {
					delete unconfirmedTransactions[txId];
				}
			});
			this._data.transactions = transactions;
			await this.saveWalletData('transactions', transactions);
			this._data.unconfirmedTransactions = unconfirmedTransactions;
			await this.saveWalletData(
				'unconfirmedTransactions',
				unconfirmedTransactions
			);

			//Rescan the addresses to get the correct balance.
			await this.rescanAddresses({
				shouldClearAddresses: false // No need to clear addresses since we are only updating the balance.
			});
			return ok('Successfully deleted transactions.');
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * This method will clear the utxo array for each address type and reset the
	 * address indexes back to the original/default app values. Once cleared & reset
	 * the app will rescan the wallet's addresses from index zero at the standard gap
	 * limit or higher (if previously set higher by the user).
	 * @async
	 * @param {boolean} [shouldClearAddresses] - Clears and re-generates all addresses when true.
	 * @param shouldClearTransactions
	 * @returns {Promise<Result<string>>}
	 */
	public async rescanAddresses({
		shouldClearAddresses = true, // It's assumed we want to clear addresses in this method unless explicitly set to false.
		shouldClearTransactions = false // We'll lose some timestamp information about the transactions if we clear them. So it's set to false by default.
	}: {
		shouldClearAddresses?: boolean;
		shouldClearTransactions?: boolean;
	}): Promise<Result<IWalletData>> {
		// If the gap limit settings are less than the standard, ensure we set the standard gap limit before rescanning.
		const currentGapLimitOptions = this.gapLimitOptions;
		if (
			currentGapLimitOptions.lookBehind < GAP_LIMIT ||
			currentGapLimitOptions.lookAhead < GAP_LIMIT ||
			currentGapLimitOptions.lookBehindChange < GAP_LIMIT_CHANGE ||
			currentGapLimitOptions.lookAheadChange < GAP_LIMIT_CHANGE
		) {
			this.updateGapLimit({
				lookBehind:
					currentGapLimitOptions.lookBehind < GAP_LIMIT
						? GAP_LIMIT
						: currentGapLimitOptions.lookBehind,
				lookAhead:
					currentGapLimitOptions.lookAhead < GAP_LIMIT
						? GAP_LIMIT
						: currentGapLimitOptions.lookAhead,
				lookBehindChange:
					currentGapLimitOptions.lookBehindChange < GAP_LIMIT_CHANGE
						? GAP_LIMIT_CHANGE
						: currentGapLimitOptions.lookBehindChange,
				lookAheadChange:
					currentGapLimitOptions.lookAheadChange < GAP_LIMIT_CHANGE
						? GAP_LIMIT_CHANGE
						: currentGapLimitOptions.lookAheadChange
			});
		}
		if (shouldClearAddresses) {
			await this.clearAddresses();
		}
		if (shouldClearTransactions) {
			await this.clearTransactions();
		}
		await this.clearUtxos();
		await this.resetAddressIndexes();
		// Wait to generate our zero index addresses.
		await this.setZeroIndexAddresses();
		const refreshWalletRes = await this.refreshWallet({
			scanAllAddresses: true,
			force: true
		});
		// Revert gap limit options to the original settings.
		this.updateGapLimit(currentGapLimitOptions);
		return refreshWalletRes;
	}

	/**
	 * Clears the UTXO array and balance from storage.
	 * @public
	 * @async
	 * @returns {Promise<string>}
	 */
	public async clearUtxos(): Promise<string> {
		this._data.balance = 0;
		this._data.utxos = [];
		await Promise.all([
			this.saveWalletData('balance', this._data.balance),
			this.saveWalletData('utxos', this._data.utxos)
		]);
		return "Successfully cleared UTXO's.";
	}

	/**
	 * Clears the transactions object for a given wallet and network from storage.
	 * @private
	 * @returns {string}
	 */
	private async clearTransactions(): Promise<string> {
		this._data.transactions = getDefaultWalletData().transactions;
		await this.saveWalletData('transactions', this._data.transactions);
		return 'Successfully reset transactions.';
	}

	/**
	 * Clears the addresses and changeAddresses object for a given wallet and network.
	 * @private
	 * @async
	 * @returns {Promise<string>}
	 */
	private async clearAddresses(): Promise<string> {
		this._data.addresses = getAddressTypeContent<IAddresses>({});
		this._data.changeAddresses = getAddressTypeContent<IAddresses>({});
		await Promise.all([
			this.saveWalletData('addresses', this._data.addresses),
			this.saveWalletData('changeAddresses', this._data.changeAddresses)
		]);
		return 'Successfully reset transactions.';
	}

	/**
	 * Updates the confirmation state of activity item transactions that were reorg'd out.
	 * @private
	 * @async
	 * @param {IUtxo[]} txs
	 * @returns {Promise<string>}
	 */
	private async updateTransactionHeights(txs: IUtxo[]): Promise<string> {
		let needsSave = false;
		const transactions = this.data.transactions;
		txs.forEach((tx) => {
			const txId = tx.tx_hash;
			if (txId in transactions) {
				transactions[txId].confirmTimestamp = 0;
				needsSave = true;
			}
		});
		if (needsSave) {
			await this.saveWalletData('transactions', transactions);
		}
		return 'Successfully updated reorg transactions.';
	}

	/**
	 * Parses and adds unconfirmed transactions to the store.
	 * @private
	 * @async
	 * @param {IFormattedTransactions} transactions
	 * @returns {Result<string>}
	 */
	private async addUnconfirmedTransactions({
		transactions
	}: {
		transactions: IFormattedTransactions;
	}): Promise<Result<string>> {
		try {
			const unconfirmedTransactions: IFormattedTransactions = {};
			Object.keys(transactions).forEach((key) => {
				const confirmations = this.blockHeightToConfirmations({
					blockHeight: transactions[key]?.height ?? 0
				});
				if (confirmations < 6) {
					unconfirmedTransactions[key] = transactions[key];
				}
			});

			if (!Object.keys(unconfirmedTransactions).length) {
				return ok('No unconfirmed transactions found.');
			}

			this._data.unconfirmedTransactions = {
				...this.data.unconfirmedTransactions,
				...unconfirmedTransactions
			};

			await this.saveWalletData(
				'unconfirmedTransactions',
				this._data.unconfirmedTransactions
			);
			return ok('Successfully updated unconfirmed transactions.');
		} catch (e) {
			this.logger.error('Failed to update unconfirmed transactions.', e);
			return err(e);
		}
	}

	/**
	 * Returns the number of confirmations for a given block height.
	 * @param {number} height
	 * @param {number} [currentHeight]
	 * @returns {number}
	 */
	public blockHeightToConfirmations({
		blockHeight,
		currentHeight
	}: {
		blockHeight?: number;
		currentHeight?: number;
	}): number {
		if (!blockHeight || blockHeight <= 0) {
			return 0;
		}
		if (!currentHeight) {
			const header = this.electrum.getBlockHeader();
			currentHeight = header.height;
		}
		if (currentHeight < blockHeight) {
			return 0;
		}
		return currentHeight - blockHeight + 1;
	}

	/**
	 * Formats the provided transaction.
	 * @async
	 * @param {ITransaction<IUtxo>[]} transactions
	 * @returns {Promise<Result<IFormattedTransactions>>}
	 */
	public async formatTransactions({
		transactions
	}: {
		transactions: ITransaction<IUtxo>[];
	}): Promise<Result<IFormattedTransactions>> {
		if (transactions.length < 1) {
			return ok({});
		}
		const currentWallet = this.data;

		// Batch and pre-fetch input data.
		const inputs: { tx_hash: string; vout: number }[] = [];
		transactions.forEach(({ result }) => {
			if (result?.vin) {
				result.vin.forEach((v) =>
					inputs.push({ tx_hash: v.txid, vout: v.vout })
				);
			}
		});
		const inputDataResponse = await this.getInputData({
			inputs
		});
		if (inputDataResponse.isErr()) {
			return err(
				inputDataResponse.error?.message ?? 'Unable to get input data.'
			);
		}
		const addressTypeKeys = Object.values(EAddressType);
		const inputData = inputDataResponse.value;
		const currentAddresses = currentWallet.addresses;
		const currentChangeAddresses = currentWallet.changeAddresses;

		let addresses = {} as IAddresses;
		let changeAddresses = {} as IAddresses;
		let rbf = false;

		addressTypeKeys.map((addressType) => {
			// Check if addresses of this type have been generated. If not, skip.
			if (Object.keys(currentAddresses[addressType])?.length > 0) {
				addresses = {
					...addresses,
					...currentAddresses[addressType]
				};
			}
			// Check if change addresses of this type have been generated. If not, skip.
			if (Object.keys(currentChangeAddresses[addressType])?.length > 0) {
				changeAddresses = {
					...changeAddresses,
					...currentChangeAddresses[addressType]
				};
			}
		});

		// Create combined address/change-address object for easier/faster reference later on.
		const combinedAddressObj: { [key: string]: IAddress } = {};
		[...Object.values(addresses), ...Object.values(changeAddresses)].map(
			(data) => {
				combinedAddressObj[data.address] = data;
			}
		);

		const formattedTransactions: IFormattedTransactions = {};
		transactions.map(async ({ data, result }) => {
			if (!result.txid) {
				return;
			}

			let totalInputValue = 0; // Total value of all inputs.
			let matchedInputValue = 0; // Total value of all inputs with addresses that belong to this wallet.
			let totalOutputValue = 0; // Total value of all outputs.
			let matchedOutputValue = 0; // Total value of all outputs with addresses that belong to this wallet.
			let messages: string[] = []; // Array of OP_RETURN messages.

			//Iterate over each input
			result.vin.map(({ txid, scriptSig, vout, sequence }) => {
				//Push any OP_RETURN messages to messages array
				try {
					const asm = scriptSig.asm;
					if (asm !== '' && asm.includes('OP_RETURN')) {
						const OpReturnMessages = decodeOpReturnMessage(asm);
						messages = messages.concat(OpReturnMessages);
					}
				} catch {}

				try {
					// Check if rbf was enabled for this transaction.
					if (sequence < 0xffffffff - 1) rbf = true;
				} catch {}

				const key = `${txid}${vout}`;
				if (key in inputData) {
					const { addresses: _addresses, value } = inputData[key];
					totalInputValue = totalInputValue + value;
					_addresses.map((address) => {
						if (address in combinedAddressObj) {
							matchedInputValue = matchedInputValue + value;
						}
					});
				}
			});

			//Iterate over each output
			result.vout.map(({ scriptPubKey, value }) => {
				const _addresses = scriptPubKey.addresses
					? scriptPubKey.addresses
					: scriptPubKey.address
					? [scriptPubKey.address]
					: [];
				totalOutputValue = totalOutputValue + value;
				_addresses.map((address) => {
					if (address in combinedAddressObj) {
						matchedOutputValue = matchedOutputValue + value;
					}
				});
			});

			const txid = result.txid;
			const type =
				matchedInputValue > matchedOutputValue
					? EPaymentType.sent
					: EPaymentType.received;
			const totalMatchedValue = matchedOutputValue - matchedInputValue;
			const value = Number(totalMatchedValue.toFixed(8));
			const totalValue = totalInputValue - totalOutputValue;
			const fee = Number(Math.abs(totalValue).toFixed(8));
			const vsize = result.vsize;
			const satsPerByte = Math.round(btcToSats(fee) / vsize);
			const { address, height, scriptHash } = data;
			let timestamp = Date.now();
			let confirmTimestamp: number | undefined;
			const blockhash = result.blockhash;

			if (height > 0 && result.blocktime) {
				confirmTimestamp = result.blocktime * 1000;
				//In the event we're recovering, set the older timestamp.
				if (confirmTimestamp < timestamp) {
					timestamp = confirmTimestamp;
				}
			}

			formattedTransactions[txid] = {
				address,
				blockhash,
				height,
				scriptHash,
				totalInputValue,
				matchedInputValue,
				totalOutputValue,
				matchedOutputValue,
				fee,
				satsPerByte,
				type,
				value,
				txid,
				messages,
				timestamp,
				confirmTimestamp,
				vin: result.vin,
				rbf,
				exists: true,
				vsize
			};
		});

		return ok(formattedTransactions);
	}

	/**
	 * Returns formatted input data from the inputs array.
	 * @async
	 * @param {{tx_hash: string, vout: number}[]} inputs
	 * @returns {Promise<Result<InputData>>}
	 */
	public async getInputData({
		inputs
	}: {
		inputs: { tx_hash: string; vout: number }[];
	}): Promise<Result<InputData>> {
		try {
			const inputData: InputData = {};
			const failedRequests: { tx_hash: string; vout: number }[] = [];

			const batchLimit = this.electrum.batchLimit;
			for (let i = 0; i < inputs.length; i += batchLimit) {
				const chunk = inputs.slice(i, i + batchLimit);

				const getTransactionsResponse =
					await this.electrum.getTransactionsFromInputs({
						txHashes: chunk
					});
				if (getTransactionsResponse.isErr()) {
					return err(
						getTransactionsResponse.error?.message ??
							// @ts-ignore
							getTransactionsResponse.error?.data
					);
				}
				getTransactionsResponse.value.data.map(({ data, result, error }) => {
					if (result && result?.vout) {
						const { addresses, value, key } = this._extractVoutData(
							result.vout[data.vout],
							data
						);
						inputData[key] = { addresses, value };
					} else if (error) {
						if (
							error?.message &&
							error.message.includes('response too large')
						) {
							// No point in re-running this tx_hash since Electrum considers the tx too large, just log the error.
							this._logGetInputDataError(error, data);
						} else {
							failedRequests.push(data);
						}
					}
				});
			}

			// Attempt to retrieve the data for any failed getTransactionsFromInputs request.
			for (const input of failedRequests) {
				const getTransactionsResponse =
					await this.electrum.getTransactionsFromInputs({
						txHashes: [input]
					});
				if (getTransactionsResponse.isErr()) {
					return err(
						getTransactionsResponse.error?.message ??
							// @ts-ignore
							getTransactionsResponse.error?.data
					);
				}
				getTransactionsResponse.value.data.map(({ data, result, error }) => {
					if (result && result?.vout) {
						const { addresses, value, key } = this._extractVoutData(
							result.vout[data.vout],
							data
						);
						inputData[key] = { addresses, value };
					} else if (error) {
						this._logGetInputDataError(error, data);
					}
				});
			}
			return ok(inputData);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Extracts data from the provided vout.
	 * @private
	 * @param {IVout} vout
	 * @param { tx_hash: string; vout: number } data
	 * @returns { addresses: string[]; value: number; key: string }
	 */
	private _extractVoutData(
		vout: IVout,
		data: { tx_hash: string; vout: number }
	): { addresses: string[]; value: number; key: string } {
		const addresses = vout.scriptPubKey.addresses
			? vout.scriptPubKey.addresses
			: vout.scriptPubKey.address
			? [vout.scriptPubKey.address]
			: [];
		const value = vout.value;
		const key = `${data.tx_hash}${vout.n}`;
		return { addresses, value, key };
	}

	/*
	 * Logs an error message when getInputData fails to retrieve getTransactionsFromInputs data.
	 * @private
	 * @param { code?: number; message?: string } error
	 * @param { tx_hash: string; vout: number } data
	 * @returns {void}
	 */
	private _logGetInputDataError(
		error: { code?: number; message?: string },
		data: { tx_hash: string; vout: number }
	): void {
		this.logger.error('\nError:', error);
		if (data) {
			this.logger.warn('Unable to retrieve input data for:', data);
		}
		if (error?.code && error.code === -32600)
			this.logger.info(
				'Suggestion: Please increase the response limit on your Electrum server.'
			);
	}

	/**
	 * Attempts to validate a given address.
	 * @param {string} address
	 * @returns {boolean}
	 */
	public validateAddress(address: string): boolean {
		return validateAddress({ address, network: this._network }).isValid;
	}

	/**
	 * Retrieves the next available change address data.
	 * @async
	 * @param {EAddressType} [addressType]
	 * @returns {Promise<Result<IAddress>>}
	 */
	public async getChangeAddress(
		addressType = this.addressType
	): Promise<Result<IAddress>> {
		const currentWallet = this.data;

		const changeAddressIndexContent =
			currentWallet.changeAddressIndex[addressType];

		if (
			changeAddressIndexContent?.address &&
			changeAddressIndexContent.index >= 0
		) {
			return ok(changeAddressIndexContent);
		}

		// It's possible we haven't set the change address index yet. Generate one on the fly.
		const generateAddressResponse = await this.generateAddresses({
			addressAmount: 0,
			changeAddressAmount: 1,
			addressType
		});
		if (generateAddressResponse.isErr()) {
			this.logger.warn(generateAddressResponse.error.message);
			return err('Unable to successfully generate a change address.');
		}
		return ok(generateAddressResponse.value.changeAddresses[0]);
	}

	/**
	 * Returns the current fee estimates for the provided network, honoring
	 * feeEstimationSource ('electrum' | 'http' | 'auto'):
	 * - 'electrum': connected Electrum server only; on failure the previous
	 *   estimates are returned rather than leaking the request to clearnet HTTP.
	 * - 'http': mempool.space with a blocktank fallback.
	 * - 'auto' (default): Electrum first, HTTP only when Electrum is
	 *   disconnected or returns unusable values.
	 * All remote-sourced rates are clamped to [1, MAX_FEE_RATE_SAT_PER_VBYTE].
	 * @async
	 * @returns {Promise<IOnchainFees>}
	 */
	public async getFeeEstimates(network = this._network): Promise<IOnchainFees> {
		if (network === EAvailableNetworks.bitcoinRegtest) {
			return { ...defaultFeesShape, timestamp: Date.now() };
		}
		if (this.feeEstimationSource !== 'http') {
			const electrumFees = await this.getFeeEstimatesFromElectrum();
			if (electrumFees.isOk()) {
				return electrumFees.value;
			}
			if (this.feeEstimationSource === 'electrum') {
				return this.feeEstimates;
			}
		}
		return this.getFeeEstimatesFromHttp(network);
	}

	/**
	 * Queries the connected Electrum server (blockchain.estimatefee) for fee
	 * estimates at the fast/normal/slow/minimum confirmation targets. Errs when
	 * disconnected or when any target returns an unusable value (-1).
	 * @async
	 * @returns {Promise<Result<IOnchainFees>>}
	 */
	public async getFeeEstimatesFromElectrum(): Promise<Result<IOnchainFees>> {
		if (!this.electrum.connectedToElectrum) {
			return err('Not connected to an Electrum server.');
		}
		// Confirmation targets (blocks) for fast/normal/slow/minimum.
		const targets = [2, 6, 24, 144];
		const results = await Promise.all(
			targets.map((blocks) => this.electrum.getFeeEstimate(blocks))
		);
		const [fast, normal, slow, minimum] = results;
		if (fast.isErr() || normal.isErr() || slow.isErr() || minimum.isErr()) {
			return err('Electrum returned unusable fee estimates.');
		}
		return ok({
			fast: fast.value,
			normal: normal.value,
			slow: slow.value,
			minimum: minimum.value,
			timestamp: Date.now()
		});
	}

	/**
	 * Fetches fee estimates over HTTP from mempool.space, falling back to
	 * blocktank if mempool.space is down.
	 * @async
	 * @param {EAvailableNetworks} network
	 * @returns {Promise<IOnchainFees>}
	 */
	public async getFeeEstimatesFromHttp(
		network = this._network
	): Promise<IOnchainFees> {
		try {
			let urlModifier = '';
			if (network !== EAvailableNetworks.bitcoinMainnet) {
				urlModifier =
					network === EAvailableNetworks.bitcoinSignet ? 'signet/' : 'testnet/';
			}
			const response = await fetch(
				`https://mempool.space/${urlModifier}api/v1/fees/recommended`
			);
			const res: IGetFeeEstimatesResponse = await response.json();
			const fast = clampFeeRate(res.fastestFee);
			const normal = clampFeeRate(res.halfHourFee);
			const slow = clampFeeRate(res.hourFee);
			const minimum = clampFeeRate(res.minimumFee);
			// clampFeeRate returns 0 for unusable (non-finite or <= 0) values.
			if (!(fast > 0 && normal > 0 && slow > 0 && minimum > 0)) {
				throw new Error('Unexpected response from mempool.space');
			}

			return {
				fast,
				normal,
				slow,
				minimum,
				timestamp: Date.now()
			};
		} catch {
			// Falls back to using blocktank for fee estimates if mempool.space is down.
			return this.getFallbackFeeEstimates(network);
		}
	}

	/**
	 * Fallback method to use blocktank for fee estimates if mempool.space is down.
	 * @param {EAvailableNetworks} network
	 * @returns {Promise<IOnchainFees>}
	 */
	public async getFallbackFeeEstimates(
		network = this._network
	): Promise<IOnchainFees> {
		try {
			if (network !== EAvailableNetworks.bitcoinMainnet) {
				return defaultFeesShape;
			}
			const url = 'https://api1.blocktank.to/api/info';
			const response = await fetch(url);
			const res: IBtInfo = await response.json();
			// check the response for the expected properties
			if (
				!(
					res?.onchain?.feeRates?.fast > 0 &&
					res?.onchain?.feeRates?.mid > 0 &&
					res?.onchain?.feeRates?.slow > 0
				)
			) {
				throw new Error('Unexpected response from blocktank');
			}
			const fast = clampFeeRate(res.onchain.feeRates.fast);
			const normal = clampFeeRate(res.onchain.feeRates.mid);
			const slow = clampFeeRate(res.onchain.feeRates.slow);
			// clampFeeRate returns 0 for unusable (non-finite or <= 0) values.
			if (!(fast > 0 && normal > 0 && slow > 0)) {
				throw new Error('Unexpected response from blocktank');
			}
			return {
				fast,
				normal,
				slow,
				minimum: slow,
				timestamp: Date.now()
			};
		} catch (e) {
			this.logger.warn('Unable to fetch fee estimates.', e);
			return this.feeEstimates;
		}
	}

	/**
	 * Sets up the transaction object with existing inputs and change address information
	 * @async.
	 * @param {ISetupTransaction} params
	 * @returns {TSetupTransactionResponse}
	 */
	public async setupTransaction(
		params: ISetupTransaction = {}
	): Promise<TSetupTransactionResponse> {
		return await this.transaction.setupTransaction(params);
	}

	/**
	 * Returns a fee object for the current transaction.
	 * @param {number} [satsPerByte]
	 * @param {string} [message]
	 * @param {Partial<ISendTransaction>} [transaction]
	 * @param {boolean} [fundingLightning]
	 * @param {coinSelectPreference} [ECoinSelectPreference]
	 * @returns {Result<TGetTotalFeeObj>}
	 */
	public getFeeInfo({
		satsPerByte = this.feeEstimates.normal,
		message = '',
		transaction,
		fundingLightning = false,
		coinSelectPreference = this.coinSelectPreference
	}: {
		satsPerByte?: number;
		message?: string;
		transaction?: Partial<ISendTransaction>;
		fundingLightning?: boolean;
		coinSelectPreference?: ECoinSelectPreference;
	} = {}): Result<TGetTotalFeeObj> {
		return this.transaction.getTotalFeeObj({
			satsPerByte,
			message,
			transaction,
			fundingLightning,
			coinSelectPreference
		});
	}

	/**
	 * Sets up and creates a transaction to multiple outputs.
	 * @param {ISendTx[]} txs
	 * @param {number} [satsPerByte]
	 * @param {boolean} [rbf]
	 * @param {false} [broadcast]
	 * @param {boolean} [shuffleOutputs]
	 * @returns {Promise<Result<string>>}
	 */
	public async sendMany({
		txs = [],
		satsPerByte = this.feeEstimates.normal,
		rbf,
		broadcast = true,
		shuffleOutputs = true
	}: {
		txs: ISendTx[];
		satsPerByte?: number;
		rbf?: boolean;
		broadcast?: boolean;
		shuffleOutputs?: boolean;
	}): Promise<Result<string>> {
		if (this._multisig) return err(new MultisigSpendError());
		if (this.isWatchOnly) return err(new WatchOnlySigningError());
		if (!this.data.utxos.length) {
			return err('No UTXOs available.');
		}
		const setupTransactionRes = await this.transaction.setupTransaction({
			rbf
		});
		if (setupTransactionRes.isErr()) {
			return err(setupTransactionRes.error.message);
		}

		if (!Array.isArray(txs)) txs = [txs];

		const shuffledTxs = shuffleOutputs ? shuffleArray(txs) : txs;
		let index = 0;
		for (const tx of shuffledTxs) {
			const updateSendTransactionRes = this.transaction.updateSendTransaction({
				transaction: {
					label: tx.message,
					outputs: [{ address: tx.address, value: tx.amount, index }]
				}
			});
			if (updateSendTransactionRes.isErr())
				err(updateSendTransactionRes.error.message);
			index++;
		}

		const updateFeeRes = this.transaction.updateFee({ satsPerByte });
		if (updateFeeRes.isErr()) {
			if (updateFeeRes.error.message.includes('Unable to increase the fee')) {
				const feeInfo = this.getFeeInfo({ satsPerByte: 1 });
				if (feeInfo.isOk()) {
					return err(
						`Fee is too high. The maximum fee for this transaction is ${feeInfo.value.maxSatPerByte}`
					);
				}
			} else {
				return err(updateFeeRes.error.message);
			}
		}

		const createRes = await this.transaction.createTransaction({
			shuffleOutputs
		});
		if (createRes.isErr()) return err(createRes.error.message);
		const { hex } = createRes.value;
		if (!broadcast) {
			return ok(hex);
		}
		const broadcastRes = await this.electrum.broadcastTransaction({
			rawTx: hex
		});
		if (broadcastRes.isErr()) return err(broadcastRes.error.message);
		return ok(broadcastRes.value);
	}

	/**
	 * Sends the maximum amount of sats to a given address at the specified satsPerByte.
	 * @param {string} address
	 * @param {number} satsPerByte
	 * @param [rbf]
	 * @param {boolean} [broadcast]
	 * @returns {Promise<Result<string>>}
	 */
	public async sendMax({
		address,
		satsPerByte,
		rbf = false,
		broadcast = true
	}: {
		address?: string;
		satsPerByte?: number;
		rbf?: boolean;
		broadcast?: boolean;
	} = {}): Promise<Result<string>> {
		if (this._multisig) return err(new MultisigSpendError());
		if (this.isWatchOnly) return err(new WatchOnlySigningError());
		if (!this.data.utxos.length) {
			return err('No UTXOs available.');
		}
		await this.resetSendTransaction();
		const setupTransactionRes = await this.transaction.setupTransaction();
		if (setupTransactionRes.isErr()) {
			return err(setupTransactionRes.error.message);
		}
		const sendMaxRes = await this.transaction.sendMax({
			address,
			satsPerByte,
			rbf
		});

		if (sendMaxRes.isErr()) {
			return err(sendMaxRes.error.message);
		}

		const createRes = await this.transaction.createTransaction({
			shuffleOutputs: true
		});
		if (createRes.isErr()) return err(createRes.error.message);
		const { hex } = createRes.value;
		if (!broadcast) {
			return ok(hex);
		}
		const broadcastRes = await this.electrum.broadcastTransaction({
			rawTx: hex
		});
		if (broadcastRes.isErr()) return err(broadcastRes.error.message);
		return ok(broadcastRes.value);
	}

	/**
	 * Sets up and creates a transaction to a single output/recipient.
	 * @async
	 * @param {string} address
	 * @param {number} amount
	 * @param {string} [message]
	 * @param {number} [satsPerByte]
	 * @param {boolean} [rbf]
	 * @param {boolean} [broadcast]
	 * @param {boolean} [shuffleOutputs]
	 * @returns {Promise<Result<string>>}
	 */
	public async send({
		address,
		amount,
		message = '',
		satsPerByte = this.feeEstimates.normal,
		rbf,
		broadcast = true,
		shuffleOutputs = true
	}: {
		address: string;
		amount: number; // sats
		message?: string;
		satsPerByte?: number;
		rbf?: boolean;
		broadcast?: boolean;
		shuffleOutputs?: boolean;
	}): Promise<Result<string>> {
		return await this.sendMany({
			txs: [{ address, amount, message }],
			satsPerByte,
			rbf,
			broadcast,
			shuffleOutputs
		});
	}

	/**
	 * Builds an UNSIGNED PSBT for an external signer (e.g. a hardware wallet).
	 * Runs the same setup, coin selection and fee logic as send/sendMany but
	 * stops before signing. Each input carries witnessUtxo (nonWitnessUtxo for
	 * legacy p2pkh), redeemScript for p2sh-p2wpkh, tapInternalKey for p2tr and
	 * bip32Derivation/tapBip32Derivation metadata. Works on both full and
	 * watch-only wallets.
	 * @param {IBuildPsbtArgs} args
	 * @returns {Promise<Result<IBuildPsbtResponse>>}
	 */
	public async buildPsbt({
		txs,
		address,
		amount,
		message = '',
		satsPerByte = this.feeEstimates.normal,
		rbf = false,
		shuffleOutputs = true
	}: IBuildPsbtArgs): Promise<Result<IBuildPsbtResponse>> {
		try {
			let sendTxs: ISendTx[] = txs ?? [];
			if (!sendTxs.length) {
				if (!address || !amount) {
					return err('No outputs provided. Specify txs or address and amount.');
				}
				sendTxs = [{ address, amount, message }];
			}
			if (!this.data.utxos.length) {
				return err('No UTXOs available.');
			}
			await this.resetSendTransaction();
			const setupTransactionRes = await this.transaction.setupTransaction({
				rbf,
				satsPerByte
			});
			if (setupTransactionRes.isErr()) {
				return err(setupTransactionRes.error.message);
			}
			let index = 0;
			for (const tx of sendTxs) {
				const updateSendTransactionRes = this.transaction.updateSendTransaction(
					{
						transaction: {
							label: tx.message,
							outputs: [{ address: tx.address, value: tx.amount, index }]
						}
					}
				);
				if (updateSendTransactionRes.isErr()) {
					return err(updateSendTransactionRes.error.message);
				}
				index++;
			}
			const updateFeeRes = this.transaction.updateFee({ satsPerByte });
			if (updateFeeRes.isErr()) return err(updateFeeRes.error.message);
			const psbtRes = await this.transaction.createUnsignedPsbt({
				shuffleOutputs
			});
			if (psbtRes.isErr()) return err(psbtRes.error.message);
			const psbt = psbtRes.value;
			const txData = this.transaction.data;
			const inputValue = this.transaction.getTransactionInputValue({
				inputs: txData.inputs
			});
			const outputValue = psbt.txOutputs.reduce((acc, o) => acc + o.value, 0);
			const fee = inputValue - outputValue;
			// The fee was computed as byteCount * satsPerByte by updateFee, so the
			// byte count it used is recoverable from the fee itself.
			const effectiveSatsPerByte = txData.satsPerByte || satsPerByte;
			const vsizeEstimate =
				effectiveSatsPerByte > 0 ? Math.round(fee / effectiveSatsPerByte) : 0;
			const network = this.getBitcoinNetwork();
			const outputs = psbt.txOutputs.map((output, i) => {
				let outputAddress: string | undefined = output.address;
				if (!outputAddress) {
					try {
						outputAddress = bitcoin.address.fromOutputScript(
							output.script,
							network
						);
					} catch {
						outputAddress = undefined;
					}
				}
				return { address: outputAddress, value: output.value, index: i };
			});
			const inputs = txData.inputs.map((input) => ({
				tx_hash: input.tx_hash,
				tx_pos: input.tx_pos,
				address: input.address,
				value: input.value,
				path: input.path
			}));
			return ok({
				psbtBase64: psbt.toBase64(),
				fee,
				vsizeEstimate,
				satsPerByte: effectiveSatsPerByte,
				inputs,
				outputs
			});
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Imports an externally signed PSBT, validates that EVERY input carries a
	 * valid signature, finalizes and extracts the transaction WITHOUT
	 * broadcasting it. Broadcast separately via broadcastTransaction.
	 * Multisig (P2WSH m-of-n witnessScript) inputs finalize only when at
	 * least m VALID partial signatures from script keys are present; below
	 * the threshold the error names how many signatures it has and needs.
	 * @param {string} psbtBase64
	 * @returns {Result<IImportSignedPsbtResponse>}
	 */
	public importSignedPsbt(
		psbtBase64: string
	): Result<IImportSignedPsbtResponse> {
		try {
			if (!psbtBase64) return err('No PSBT provided.');
			const network = this.getBitcoinNetwork();
			const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network });
			if (psbt.inputCount === 0) return err('PSBT has no inputs.');
			for (let i = 0; i < psbt.inputCount; i++) {
				const input = psbt.data.inputs[i];
				// Inputs already finalized by the signer carry their signature in
				// the final script and cannot be re-validated via partialSig.
				const finalized = !!(input.finalScriptSig || input.finalScriptWitness);
				if (finalized) continue;
				const hasSignature =
					(input.partialSig?.length ?? 0) > 0 ||
					!!input.tapKeySig ||
					(input.tapScriptSig?.length ?? 0) > 0;
				if (!hasSignature) {
					return err(`Input ${i} is missing a signature.`);
				}
				const multisigCheck = this._enforceMultisigThreshold(psbt, i);
				if (multisigCheck.isErr()) return err(multisigCheck.error.message);
				let valid = false;
				try {
					valid = psbt.validateSignaturesOfInput(i, validatePsbtSignature);
				} catch (e) {
					return err(
						`Unable to validate the signature for input ${i}: ${
							e instanceof Error ? e.message : String(e)
						}`
					);
				}
				if (!valid) return err(`Input ${i} has an invalid signature.`);
				psbt.finalizeInput(i);
			}
			const tx = psbt.extractTransaction();
			return ok({ txHex: tx.toHex(), txid: tx.getId() });
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Threshold gate for multisig PSBT inputs. When input i carries an m-of-n
	 * OP_CHECKMULTISIG witnessScript, this verifies (fail-closed):
	 * - the witnessUtxo commits to that witnessScript (P2WSH match),
	 * - every partial signature comes from a key IN the script,
	 * - at least m distinct script keys signed (else err naming have/need).
	 * Extra signatures beyond m (all still validated by the caller) are
	 * trimmed in script-key order so the finalizer can build the witness.
	 * Non-multisig inputs pass through untouched.
	 * @private
	 * @param {bitcoin.Psbt} psbt
	 * @param {number} i
	 * @returns {Result<string>}
	 */
	private _enforceMultisigThreshold(
		psbt: bitcoin.Psbt,
		i: number
	): Result<string> {
		const input = psbt.data.inputs[i];
		const witnessScript = input.witnessScript;
		if (!witnessScript) return ok('Not a multisig input.');
		let m: number | undefined;
		let pubkeys: Buffer[] | undefined;
		try {
			const p2ms = bitcoin.payments.p2ms({ output: witnessScript });
			m = p2ms.m;
			pubkeys = p2ms.pubkeys;
		} catch {
			return ok('Not a multisig witnessScript.');
		}
		if (!m || !pubkeys?.length) return ok('Not a multisig witnessScript.');
		const p2wsh = bitcoin.payments.p2wsh({
			redeem: { output: witnessScript }
		});
		if (
			!input.witnessUtxo ||
			!p2wsh.output ||
			!input.witnessUtxo.script.equals(p2wsh.output)
		) {
			return err(
				`Input ${i}: witnessScript does not match the witnessUtxo script.`
			);
		}
		const partials = input.partialSig ?? [];
		for (const ps of partials) {
			if (!pubkeys.some((pk) => pk.equals(ps.pubkey))) {
				return err(
					`Input ${i} carries a signature from a key that is not in the multisig script.`
				);
			}
		}
		const signedKeys = new Set(partials.map((ps) => ps.pubkey.toString('hex')));
		const have = signedKeys.size;
		if (have < m) {
			return err(
				`Input ${i} is below the multisig threshold: have ${have} signature(s), need ${m}.`
			);
		}
		if (have > m) {
			// Keep the first m signatures in script-key order; the multisig
			// finalizer requires exactly m.
			const keep: typeof partials = [];
			for (const pk of pubkeys) {
				if (keep.length >= m) break;
				const ps = partials.find((p) => p.pubkey.equals(pk));
				if (ps) keep.push(ps);
			}
			input.partialSig = keep;
		}
		return ok('Multisig threshold satisfied.');
	}

	/**
	 * Adds OUR partial signature(s) to a PSBT without finalizing it (multisig
	 * cosigner flow). Inputs are matched through their bip32Derivation
	 * entries: any entry whose pubkey equals the key this wallet derives at
	 * that path gets signed. Inputs we already signed are skipped. Requires
	 * the mnemonic; watch-only wallets get the typed WatchOnlySigningError.
	 * @param {string} psbtBase64
	 * @returns {Result<string>} The PSBT (base64) including our signatures.
	 */
	public signPsbtWithOurKey(psbtBase64: string): Result<string> {
		try {
			if (!this._root) return err(new WatchOnlySigningError());
			if (!psbtBase64) return err('No PSBT provided.');
			const network = this.getBitcoinNetwork();
			const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network });
			if (psbt.inputCount === 0) return err('PSBT has no inputs.');
			let matched = 0;
			for (let i = 0; i < psbt.inputCount; i++) {
				const input = psbt.data.inputs[i];
				if (input.finalScriptSig || input.finalScriptWitness) continue;
				for (const derivation of input.bip32Derivation ?? []) {
					let keyPair: BIP32Interface;
					try {
						keyPair = this._root.derivePath(derivation.path);
					} catch {
						continue;
					}
					if (!keyPair.publicKey.equals(derivation.pubkey)) continue;
					matched++;
					const alreadySigned = (input.partialSig ?? []).some((ps) =>
						ps.pubkey.equals(keyPair.publicKey)
					);
					if (!alreadySigned) psbt.signInput(i, keyPair);
					break;
				}
			}
			if (matched === 0) {
				return err(
					'No PSBT input carries a bip32Derivation this wallet can sign for.'
				);
			}
			return ok(psbt.toBase64());
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Combines multiple partially signed copies of the same PSBT (multi-party
	 * signing flows) into one.
	 * @param {string[]} psbts base64-encoded PSBTs.
	 * @returns {Result<string>} The combined PSBT in base64.
	 */
	public combinePsbts(psbts: string[]): Result<string> {
		try {
			if (!psbts || psbts.length < 2) {
				return err('Provide at least two PSBTs to combine.');
			}
			const network = this.getBitcoinNetwork();
			const parsed = psbts.map((psbtBase64) =>
				bitcoin.Psbt.fromBase64(psbtBase64, { network })
			);
			const [base, ...rest] = parsed;
			base.combine(...rest);
			return ok(base.toBase64());
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Broadcasts a raw transaction via Electrum and returns the txid.
	 * @param {string} txHex
	 * @returns {Promise<Result<string>>}
	 */
	public async broadcastTransaction(txHex: string): Promise<Result<string>> {
		if (!txHex) return err('No transaction hex provided.');
		return await this.electrum.broadcastTransaction({
			rawTx: txHex,
			subscribeToOutputAddress: false
		});
	}

	/**
	 * Returns the address from a provided script hash in storage.
	 * @param {string} scriptHash
	 * @returns {IAddress | undefined}
	 */
	public getAddressFromScriptHash(scriptHash: string): IAddress | undefined {
		const addresses: TAddressTypeContent<IAddresses> = this.data.addresses;
		const changeAddresses: TAddressTypeContent<IAddresses> =
			this.data.changeAddresses;
		const combinedAddresses: IAddress[] = [
			...Object.values(addresses),
			...Object.values(changeAddresses)
		].flatMap((addressGroup: IAddresses) => Object.values(addressGroup));
		return combinedAddresses.find(
			(addressObj: IAddress) => addressObj.scriptHash === scriptHash
		);
	}

	/**
	 * Will ensure that both address and change address indexes are set at index 0.
	 * Will also generate and store address and changeAddress at index 0.
	 * @private
	 * @async
	 * @returns {Promise<Result<string>>}
	 */
	private async setZeroIndexAddresses(): Promise<Result<string>> {
		const currentWallet = this.data;
		let saveAddressIndexes = false;
		let saveChangeAddressIndexes = false;

		await Promise.all(
			this.addressTypesToMonitor.map(async (addressType) => {
				const addressIndex = currentWallet.addressIndex[addressType];
				const changeAddressIndex =
					currentWallet.changeAddressIndex[addressType];

				if (addressIndex?.index < 0) {
					await this.updateAddressIndex(addressType, false);
					saveAddressIndexes = true;
				}
				if (changeAddressIndex?.index < 0) {
					await this.updateAddressIndex(addressType, true);
					saveChangeAddressIndexes = true;
				}
			})
		);

		if (saveAddressIndexes) {
			await Promise.all([
				this.saveWalletData('addressIndex', this._data.addressIndex),
				this.saveWalletData('addresses', this._data.addresses)
			]);
		}
		if (saveChangeAddressIndexes) {
			await Promise.all([
				this.saveWalletData(
					'changeAddressIndex',
					this._data.changeAddressIndex
				),
				this.saveWalletData('changeAddresses', this._data.changeAddresses)
			]);
		}

		return ok('Set Zero Index Addresses.');
	}

	/**
	 * Updates the address index for a given address type.
	 * @private
	 * @async
	 * @param {EAddressType} addressType
	 * @param {boolean} isChangeAddress
	 * @param {number} [index]
	 * @returns {Promise<void>}
	 */
	private async updateAddressIndex(
		addressType: EAddressType,
		isChangeAddress: boolean,
		index = 0
	): Promise<void> {
		const address = await this.generateAddresses({
			addressAmount: isChangeAddress ? 0 : 1,
			addressIndex: index,
			changeAddressAmount: isChangeAddress ? 1 : 0,
			changeAddressIndex: index,
			addressType
		});
		const indexToUpdate = isChangeAddress
			? 'changeAddressIndex'
			: 'addressIndex';
		if (address.isOk()) {
			const key = isChangeAddress ? 'changeAddresses' : 'addresses';
			this._data[indexToUpdate][addressType] =
				address.value[key][Object.keys(address.value[key])[0]];
		}
		// Ensure we have addresses to pull from.
		let addresses = {};
		if (indexToUpdate === 'addressIndex') {
			addresses = this.data.addresses[addressType];
		} else {
			addresses = this.data.changeAddresses[addressType];
		}
		if (!Object.keys(addresses).length) {
			await this.addAddresses({
				addressAmount:
					indexToUpdate === 'addressIndex' ? this.gapLimitOptions.lookAhead : 0,
				addressIndex: index,
				changeAddressAmount:
					indexToUpdate === 'changeAddressIndex'
						? this.gapLimitOptions.lookAheadChange
						: 0,
				changeAddressIndex: index,
				addressType,
				saveAddresses: false
			});
		}
	}

	/**
	 * Returns current address index information.
	 * @returns {TAddressIndexInfo}
	 */
	public getAddressIndexInfo(): TAddressIndexInfo {
		const addressType = this.addressType;
		const currentWallet = this.data;
		const addressIndex = currentWallet.addressIndex[addressType];
		const changeAddressIndex = currentWallet.addressIndex[addressType];
		const lastUsedAddressIndex =
			currentWallet.lastUsedAddressIndex[addressType];
		const lastUsedChangeAddressIndex =
			currentWallet.lastUsedChangeAddressIndex[addressType];
		return {
			addressIndex,
			changeAddressIndex,
			lastUsedAddressIndex,
			lastUsedChangeAddressIndex
		};
	}

	/**
	 * Returns the next available receive address.
	 * @param {EAddressType} [addressType]
	 * @returns {Promise<Result<string>>}
	 */
	getReceiveAddress = async ({
		addressType = this.addressType
	}: {
		addressType?: EAddressType;
	}): Promise<Result<string>> => {
		try {
			const wallet = this.data;
			const addressIndex = wallet.addressIndex;
			const receiveAddress = addressIndex[addressType].address;
			if (receiveAddress) {
				return ok(receiveAddress);
			}
			const addresses = wallet?.addresses[addressType];

			// Check if addresses were generated, but the index has not been set yet.
			if (
				Object.keys(addresses).length > 0 &&
				addressIndex[addressType].index < 0
			) {
				// Grab and return the address at index 0.
				const address = Object.values(addresses).find(
					({ index }) => index === 0
				);
				if (address) {
					return ok(address.address);
				}
			}
			// Fallback to generating a new receive address on the fly.
			const generatedAddress = await this.generateNewReceiveAddress({
				addressType
			});
			if (generatedAddress.isOk()) {
				return ok(generatedAddress.value.address);
			} else {
				this.logger.warn(generatedAddress.error.message);
			}
			return err('No receive address available.');
		} catch (e) {
			return err(e);
		}
	};

	/**
	 * Using a tx_hash this method will return the necessary data to create a
	 * replace-by-fee transaction for any 0-conf, RBF-enabled tx.
	 * @param {ITxHash} txHash
	 * @returns {Promise<Result<IRbfData>>}
	 */
	public async getRbfData({
		txHash
	}: {
		txHash: ITxHash;
	}): Promise<Result<IRbfData>> {
		const txResponse = await this.electrum.getTransactions({
			txHashes: [txHash]
		});
		if (txResponse.isErr()) {
			return err(txResponse.error.message);
		}
		const txData = txResponse.value.data;

		const wallet = this.data;
		const addressTypeKeys = objectKeys(EAddressType);
		const addresses = wallet.addresses;
		const changeAddresses = wallet.changeAddresses;

		let allAddresses = {} as IAddresses;
		let allChangeAddresses = {} as IAddresses;

		await Promise.all(
			addressTypeKeys.map((addressType) => {
				allAddresses = {
					...allAddresses,
					...addresses[addressType],
					...changeAddresses[addressType]
				};
				allChangeAddresses = {
					...allChangeAddresses,
					...changeAddresses[addressType]
				};
			})
		);

		let changeAddressData: IOutput = {
			address: '',
			value: 0,
			index: 0
		};
		const inputs: IUtxo[] = [];
		let address = '';
		let scriptHash = '';
		let path = '';
		let value = 0;
		const addressType = EAddressType.p2wpkh;
		const outputs: IOutput[] = [];
		let message = '';
		let inputTotal = 0;
		let outputTotal = 0;
		let fee = 0;

		const insAndOuts = await Promise.all(
			txData.map(({ result }) => {
				const vin = result.vin ?? [];
				const vout = result.vout ?? [];
				return { vins: vin, vouts: vout };
			})
		);
		const { vins, vouts } = insAndOuts[0];
		for (let i = 0; i < vins.length; i++) {
			try {
				const input = vins[i];
				const txId = input.txid;
				const tx = await this.electrum.getTransactions({
					txHashes: [{ tx_hash: txId }]
				});
				if (tx.isErr()) {
					return err(tx.error.message);
				}
				if (tx.value.data[0].data.height > 0) {
					return err('Transaction is already confirmed. Unable to RBF.');
				}
				const txVout = tx.value.data[0].result.vout[input.vout];
				if (txVout.scriptPubKey?.address) {
					address = txVout.scriptPubKey.address;
				} else if (
					txVout.scriptPubKey?.addresses &&
					txVout.scriptPubKey.addresses.length
				) {
					address = txVout.scriptPubKey.addresses[0];
				}
				if (!address) {
					continue;
				}
				scriptHash = getScriptHash({ address, network: this._network });
				// Check that we are in possession of this scriptHash.
				if (!(scriptHash in allAddresses)) {
					// This output did not come from us.
					continue;
				}
				path = allAddresses[scriptHash].path;
				value = btcToSats(txVout.value);
				const publicKey = allAddresses[scriptHash].publicKey;
				inputs.push({
					tx_hash: input.txid,
					index: input.vout,
					tx_pos: input.vout,
					height: 0,
					address,
					scriptHash,
					path,
					value,
					publicKey
				});
				if (value) {
					inputTotal = inputTotal + value;
				}
			} catch (e) {
				this.logger.error('Failed to get input value.', e);
			}
		}
		for (let i = 0; i < vouts.length; i++) {
			const vout = vouts[i];
			const voutValue = btcToSats(vout.value);
			if (vout.scriptPubKey?.addresses) {
				address = vout.scriptPubKey.addresses[0];
			} else if (vout.scriptPubKey?.address) {
				address = vout.scriptPubKey.address;
			} else {
				try {
					if (vout.scriptPubKey.asm.includes('OP_RETURN')) {
						message = decodeOpReturnMessage(vout.scriptPubKey.asm)[0] || '';
					}
				} catch {}
			}
			if (!address) {
				continue;
			}
			const changeAddressScriptHash = getScriptHash({
				address,
				network: this._network
			});

			// If the address scripthash matches one of our address scripthashes, add it accordingly. Otherwise, add it as another output.
			if (Object.keys(allAddresses).includes(changeAddressScriptHash)) {
				changeAddressData = {
					address,
					value: voutValue,
					index: i
				};
			}
			const index = outputs?.length ?? 0;
			outputs.push({
				address,
				value: voutValue,
				index
			});
			outputTotal = outputTotal + voutValue;
		}

		if (!changeAddressData?.address && outputs.length >= 2) {
			/*
			 * Unable to determine change address.
			 * Performing an RBF could divert funds from the incorrect output.
			 *
			 * It's very possible that this tx sent the max amount of sats to a foreign/unknown address.
			 * Instead of pulling sats from that output to accommodate the higher fee (reducing how much the recipient receives)
			 * suggest a CPFP transaction.
			 */
			return err('Unable to determine change address.');
		}

		if (outputTotal > inputTotal) {
			return err('Outputs should not be greater than the inputs.');
		}
		fee = Math.abs(Number(inputTotal - outputTotal));

		return ok({
			changeAddress: changeAddressData.address,
			inputs,
			balance: inputTotal,
			outputs,
			fee,
			message,
			addressType,
			rbf: true
		});
	}

	/**
	 * Deletes a given on-chain transaction by id.
	 * @param {string} txid
	 */
	async deleteOnChainTransactionById({
		txid
	}: {
		txid: string;
	}): Promise<void> {
		const transactions = this._data.transactions;
		const unconfirmed = this._data.unconfirmedTransactions;
		if (txid in transactions) {
			delete transactions[txid];
		}
		if (txid in unconfirmed) {
			delete unconfirmed[txid];
		}
		await this.saveWalletData('transactions', transactions);
		await this.saveWalletData('unconfirmedTransactions', unconfirmed);
	}

	/**
	 * Sets "exists" to false for a given on-chain transaction id.
	 * @param {string} txid
	 */
	async addGhostTransaction({ txid }: { txid: string }): Promise<void> {
		if (txid in this._data.transactions) {
			this._data.transactions[txid].exists = false;
		}
		await this.saveWalletData('transactions', this._data.transactions);
	}

	/**
	 * Adds a boosted transaction id to the boostedTransactions object.
	 * @param {string} newTxId
	 * @param {string} oldTxId
	 * @param {EBoostType} [type]
	 * @param {number} fee
	 * @returns {Promise<Result<IBoostedTransaction>>}
	 */
	async addBoostedTransaction({
		newTxId,
		oldTxId,
		type,
		fee
	}: {
		newTxId: string;
		oldTxId: string;
		type: EBoostType;
		fee: number;
	}): Promise<Result<IBoostedTransaction>> {
		try {
			const boostedTransactions = this.data.boostedTransactions;
			const parentTransactions = this.getBoostedTransactionParents({
				txid: oldTxId,
				boostedTransactions
			});
			parentTransactions.push(oldTxId);
			const boostedTx: IBoostedTransaction = {
				parentTransactions: parentTransactions,
				childTransaction: newTxId,
				type,
				fee
			};
			const boostedTransaction: IBoostedTransactions = {
				[oldTxId]: boostedTx
			};
			this._data.boostedTransactions = {
				...this.data.boostedTransactions,
				...boostedTransaction
			};

			// Only delete the old transaction if it was an RBF
			if (type === EBoostType.rbf) {
				await this.deleteOnChainTransactionById({ txid: oldTxId });
			}

			await this.saveWalletData(
				'boostedTransactions',
				this._data.boostedTransactions
			);
			return ok(boostedTx);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns an array of parents for a boosted transaction id.
	 * @param {string} txid
	 * @param {IBoostedTransactions} [boostedTransactions]
	 * @returns {string[]}
	 */
	getBoostedTransactionParents = ({
		txid,
		boostedTransactions
	}: {
		txid: string;
		boostedTransactions?: IBoostedTransactions;
	}): string[] => {
		if (!boostedTransactions) {
			boostedTransactions = this.getBoostedTransactions();
		}
		const boostObj = Object.values(boostedTransactions).find((boostObject) => {
			return boostObject.childTransaction === txid;
		});

		return boostObj?.parentTransactions ?? [];
	};

	/**
	 * Returns boosted transactions object.
	 * @returns {IBoostedTransactions}
	 */
	getBoostedTransactions = (): IBoostedTransactions => {
		return this.data.boostedTransactions;
	};

	/**
	 * This completely resets the send transaction state.
	 * @returns {Promise<Result<string>>}
	 */
	async resetSendTransaction(): Promise<Result<string>> {
		return await this.transaction.resetSendTransaction();
	}

	/**
	 * Returns an array of transactions that can be boosted with cpfp and rbf.
	 * @returns {{cpfp: IFormattedTransaction[], rbf: IFormattedTransaction[]}}
	 */
	getBoostableTransactions(): {
		cpfp: IFormattedTransaction[];
		rbf: IFormattedTransaction[];
	} {
		const cpfp: IFormattedTransaction[] = [];
		const rbf: IFormattedTransaction[] = [];
		Object.values(this.data.unconfirmedTransactions).map((tx) => {
			if (tx.rbf) rbf.push(tx);
			cpfp.push(tx); // All unconfirmed transactions can be cpfp'd.
		});
		return { cpfp, rbf };
	}

	/**
	 * Creates a BIP32Interface from the selected wallet's mnemonic and passphrase
	 * @returns {Promise<Result<BIP32Interface>>}
	 */
	getBip32Interface = async (): Promise<Result<BIP32Interface>> => {
		try {
			if (!this._mnemonic) return err(new WatchOnlySigningError());
			const network = getBitcoinJsNetwork(this._network);
			const seed = await bip39.mnemonicToSeed(this._mnemonic, this._passphrase);
			const root = bip32.fromSeed(seed, network);
			return ok(root);
		} catch (e) {
			return err(e);
		}
	};

	/**
	 * Adds a specified input to the current transaction.
	 * @param {IUtxo} input
	 * @returns {Result<IUtxo[]>}
	 */
	public addTxInput({ input }: { input: IUtxo }): Result<IUtxo[]> {
		try {
			if (input.value < TRANSACTION_DEFAULTS.dustLimit) {
				return err('Input value is below dust limit.');
			}
			const txData = this.transaction.data;
			const inputs = txData?.inputs ?? [];
			const newInputs = [...inputs, input];
			this.transaction.updateSendTransaction({
				transaction: {
					inputs: newInputs
				}
			});
			return ok(newInputs);
		} catch (e) {
			this.logger.error('Failed to add transaction input.', e);
			return err(e);
		}
	}

	/**
	 * Removes the specified input from the current transaction.
	 * @param {IUtxo} input
	 * @returns {Result<IUtxo[]>}
	 */
	public removeTxInput({ input }: { input: IUtxo }): Result<IUtxo[]> {
		try {
			const txData = this.transaction.data;
			const txInputs = txData?.inputs ?? [];
			const newInputs = txInputs.filter((txInput) => {
				if (!objectsMatch(input, txInput)) {
					return txInput;
				}
			});
			this.transaction.updateSendTransaction({
				transaction: {
					inputs: newInputs
				}
			});
			return ok(newInputs);
		} catch (e) {
			this.logger.error('Failed to remove transaction input.', e);
			return err(e);
		}
	}

	/**
	 * Adds a specified tag to the current transaction.
	 * @param {string} tag
	 * @returns {Result<string>}
	 */
	addTxTag({ tag }: { tag: string }): Result<string> {
		try {
			const txData = this.transaction.data;
			let tags = [...txData.tags, tag];
			tags = [...new Set(tags)]; // remove duplicates
			this.transaction.updateSendTransaction({
				transaction: {
					...txData,
					tags
				}
			});
			return ok('Tag successfully added');
		} catch (e) {
			this.logger.error('Failed to add transaction tag.', e);
			return err(e);
		}
	}

	/**
	 * Removes a specified tag from the current transaction.
	 * @param {string} tag
	 * @returns {Result<string>}
	 */
	removeTxTag({ tag }: { tag: string }): Result<string> {
		try {
			const txData = this.transaction.data;
			const tags = txData.tags;
			const newTags = tags.filter((t) => t !== tag);

			this.transaction.updateSendTransaction({
				transaction: {
					...txData,
					tags: newTags
				}
			});
			return ok('Tag successfully added');
		} catch (e) {
			this.logger.error('Failed to remove transaction tag.', e);
			return err(e);
		}
	}

	/**
	 * Updates the fee rate for the current transaction to the preferred value if none set.
	 * @param {number} [satsPerByte]
	 * @param {EFeeId} [selectedFeeId]
	 * @returns {Result<string>}
	 */
	setupFeeForOnChainTransaction({
		satsPerByte,
		selectedFeeId
	}: {
		satsPerByte?: number;
		selectedFeeId?: EFeeId;
	}): Result<string> {
		try {
			const transactionData = this.transaction.data;
			if (!satsPerByte) {
				satsPerByte = transactionData?.satsPerByte ?? 1;
				satsPerByte =
					this.selectedFeeId === EFeeId.none
						? satsPerByte
						: this.feeEstimates[this.selectedFeeId];
			}
			const res = this.transaction.updateFee({
				satsPerByte: satsPerByte ?? 1,
				selectedFeeId
			});
			if (res.isErr()) {
				this.logger.warn(res.error.message);
				return err(res.error.message);
			}

			return ok('Fee has been changed successfully');
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Used to temporarily update the balance until the Electrum server catches up after sending a transaction.
	 * @param {number} balance
	 * @returns {Result<string>}
	 */
	public updateWalletBalance({ balance }: { balance: number }): Result<string> {
		try {
			this._data.balance = balance;
			this.saveWalletData('balance', balance);
			return ok('Successfully updated balance.');
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Updates the fee estimates for the current network.
	 * @public
	 * @async
	 * @param {boolean} [forceUpdate] Ignores the timestamp if set true and forces the update
	 * @returns {Promise<Result<IOnchainFees>>}
	 */
	public async updateFeeEstimates(
		forceUpdate = false
	): Promise<Result<IOnchainFees>> {
		const timestamp = this.feeEstimates.timestamp;
		const difference = Math.floor((Date.now() - timestamp) / 1000);
		if (!forceUpdate && difference < 60) {
			return ok(this.feeEstimates);
		}
		const feeEstimates = await this.getFeeEstimates();
		this.feeEstimates = feeEstimates;
		await this.saveWalletData('feeEstimates', feeEstimates);
		return ok(feeEstimates);
	}

	/**
	 * Get addresses from a given private key.
	 * @param {string} privateKey
	 * @param {EAddressType[]} [_addressTypes]
	 * @returns {Result<IGetAddressesFromPrivateKey>}
	 */
	public getAddressesFromPrivateKey(
		privateKey: string,
		// p2wsh is excluded: a single private key cannot form a multisig script.
		_addressTypes = getAddressTypes().filter((t) => t !== EAddressType.p2wsh)
	): Result<IGetAddressesFromPrivateKey> {
		try {
			const network = this.getBitcoinNetwork();
			return getAddressesFromPrivateKey({
				privateKey,
				addrTypes: _addressTypes,
				network
			});
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns the balance, utxos, and keyPair info for a given private key.
	 * @async
	 * @param {string} privateKey
	 * @returns {Promise<Result<IPrivateKeyInfo>>}
	 */
	public async getPrivateKeyInfo(
		privateKey: string
	): Promise<Result<IPrivateKeyInfo>> {
		if (!privateKey) return err('No private key provided.');
		const addressesRes = this.getAddressesFromPrivateKey(privateKey);
		if (addressesRes.isErr()) {
			return err(addressesRes.error.message);
		}
		const { addresses, keyPair } = addressesRes.value;
		const addressData: TUnspentAddressScriptHashData = {};
		addresses.map(({ address, publicKey }) => {
			const scriptHash = getScriptHash({ address, network: this._network });
			addressData[scriptHash] = {
				scriptHash,
				address,
				index: 0,
				path: '',
				publicKey
			};
		});

		const getUtxoRes = await this.electrum.listUnspentAddressScriptHashes({
			addresses: addressData
		});
		if (getUtxoRes.isErr()) {
			return err(getUtxoRes.error.message);
		}
		const { balance, utxos } = getUtxoRes.value;
		if (balance < TRANSACTION_DEFAULTS.dustLimit) {
			return err('Balance is below dust limit.');
		}
		return ok({ balance, utxos, keyPair, addresses });
	}

	/**
	 * Sweeps a private key to a given address.
	 * @async
	 * @param {string} privateKey
	 * @param {string} toAddress
	 * @param {number} [satsPerByte]
	 * @param {boolean} [broadcast]
	 * @param {boolean} [combineWithWalletUtxos]
	 * @returns {Promise<Result<ISweepPrivateKeyRes>>}
	 */
	public async sweepPrivateKey({
		privateKey,
		toAddress,
		satsPerByte = this.feeEstimates.normal,
		broadcast = true,
		combineWithWalletUtxos = false
	}: ISweepPrivateKey): Promise<Result<ISweepPrivateKeyRes>> {
		// The sweep transaction is signed through the wallet signing path, which
		// requires the wallet's own keys even for an externally provided key.
		if (this._multisig) return err(new MultisigSpendError());
		if (this.isWatchOnly) return err(new WatchOnlySigningError());
		const privateKeyInfo = await this.getPrivateKeyInfo(privateKey);
		if (privateKeyInfo.isErr()) {
			return err(privateKeyInfo.error.message);
		}
		const { balance, keyPair } = privateKeyInfo.value;
		let utxos = privateKeyInfo.value.utxos;
		utxos = utxos.map((utxo) => {
			return { ...utxo, keyPair };
		});
		if (combineWithWalletUtxos) {
			const walletUtxos = this.data.utxos;
			utxos = [...walletUtxos, ...utxos];
		}
		await this.transaction.resetSendTransaction();
		await this.transaction.setupTransaction({
			satsPerByte,
			utxos,
			outputs: [{ address: toAddress, value: balance, index: 0 }]
		});
		const sendMaxRes = await this.transaction.sendMax({
			address: toAddress,
			satsPerByte,
			transaction: {
				...this.transaction.data,
				outputs: [{ address: toAddress, value: balance, index: 0 }],
				inputs: utxos,
				satsPerByte
			}
		});
		if (sendMaxRes.isErr()) {
			return err(sendMaxRes.error.message);
		}
		const createRes = await this.transaction.createTransaction({});
		if (createRes.isErr()) {
			return err(createRes.error.message);
		}
		const response = {
			...createRes.value,
			balance
		};
		if (!broadcast) {
			return ok(response);
		}
		const broadcastResponse = await this.electrum.broadcastTransaction({
			rawTx: response.hex,
			subscribeToOutputAddress: false
		});
		if (broadcastResponse.isErr()) {
			return err(broadcastResponse.error.message);
		}
		response.id = broadcastResponse.value;
		return ok(response);
	}

	public getAddressInfoFromScriptHash(scriptHash: string): Result<{
		address: IAddress;
		addressType: EAddressType;
	}> {
		const addresses = this.data.addresses;
		let address: { address: IAddress; addressType: EAddressType } | undefined;
		for (const addressType in addresses) {
			if (scriptHash in addresses[addressType]) {
				address = {
					address: addresses[addressType][scriptHash],
					addressType: addressType as EAddressType
				};
				break; // Exit the loop once the address is found
			}
		}
		return address ? ok(address) : err('Address not found');
	}

	/**
	 * Allows the user to update the gap limit options.
	 * @param gapLimitOptions
	 * @returns {Promise<Result<TGapLimitOptions>>}
	 */
	public updateGapLimit(
		gapLimitOptions: TGapLimitOptions
	): Result<TGapLimitOptions> {
		if (!gapLimitOptions) {
			return err('No gap limit options provided.');
		}
		if (
			!isPositive(gapLimitOptions.lookAhead) ||
			!isPositive(gapLimitOptions.lookBehind) ||
			!isPositive(gapLimitOptions.lookAheadChange) ||
			!isPositive(gapLimitOptions.lookBehindChange)
		) {
			return err('All gap limit options must be positive.');
		}
		this.gapLimitOptions = gapLimitOptions;
		return ok(this.gapLimitOptions);
	}

	/**
	 * Returns an array of tx_hashes and their height for a given address.
	 * @param {string} address
	 * @returns {Promise<Result<TTxResult[]>>}
	 */
	public async getAddressHistory(
		address: string
	): Promise<Result<TTxResult[]>> {
		try {
			const scriptHash = getScriptHash({ address, network: this._network });
			const response = await this.electrum.getAddressScriptHashesHistory([
				scriptHash
			]);
			if (response.isErr()) {
				return err(response.error.message);
			}
			if (response.value.data[0].error?.message) {
				return err(response.value.data[0].error.message);
			}
			return ok(response.value.data[0].result);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns the transaction details for a given tx_hash.
	 * @param {string} tx_hash
	 * @returns {Promise<Result<TTxDetails>>}
	 */
	public async getTransactionDetails(
		tx_hash: string
	): Promise<Result<TTxDetails>> {
		try {
			const details = await this.electrum.getTransactions({
				txHashes: [{ tx_hash }]
			});
			if (details.isErr()) {
				return err(details.error.message);
			}
			if (details.value.data[0]?.error?.message) {
				return err(details.value.data[0].error.message);
			}
			return ok(details.value.data[0].result);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Used to determine if we're able to boost a transaction either by RBF or CPFP.
	 * @param {string} txid
	 */
	public canBoost(txid: string): ICanBoostResponse {
		const failure = { canBoost: false, rbf: false, cpfp: false };
		try {
			const t =
				this._data.unconfirmedTransactions[txid] ??
				this._data.transactions[txid];

			// transaction not found
			if (!t) {
				return failure;
			}

			// transaction already confirmed
			if (t.height && t.height > 0) {
				return failure;
			}

			// balance is below the recommended base fee
			if (this.getBalance() < TRANSACTION_DEFAULTS.recommendedBaseFee) {
				return failure;
			}

			/*
			 * For an RBF, technically we can reduce the output value and apply it to the fee,
			 * but this might cause issues when paying a merchant that requested a specific amount.
			 */
			const rbf =
				this.rbf &&
				(t.rbf ?? false) &&
				t.type === EPaymentType.sent &&
				t.matchedOutputValue > t.fee &&
				btcToSats(t.matchedOutputValue) >
					TRANSACTION_DEFAULTS.recommendedBaseFee;

			// Performing a CPFP tx requires a new tx and higher fee.
			const cpfp =
				btcToSats(t.matchedOutputValue) >=
				TRANSACTION_DEFAULTS.recommendedBaseFee * 3;

			return { canBoost: rbf || cpfp, rbf, cpfp };
		} catch (e) {
			return failure;
		}
	}
}
