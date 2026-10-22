import type { Result } from '../utils/result';
import type { Sats } from '../utils/conversion';
import type {
	EElectrumNetworks,
	IElectrumOptions,
	IHeader,
	INewBlock,
	TTxResult
} from './electrum';
import type {
	ECoinSelectPreference,
	EFeeId,
	TGapLimitOptions
} from './transaction';
import type { ECPairInterface } from 'ecpair';
import type { BIP32Interface } from 'bip32';
import type { ILogger } from '../logger';
import { Network } from '../network';

/**
 * @deprecated Use {@link Network}. Removed in the next major release.
 */
export type TAvailableNetworks = `${Network}`;
export type TAddressType = 'p2wpkh' | 'p2sh' | 'p2pkh';
export type TAddressLabel = 'bech32' | 'segwit' | 'legacy';
export type TKeyDerivationPurpose = '84' | '49' | '44' | string; //"p2wpkh" | "p2sh" | "p2pkh";
export type TKeyDerivationCoinType = '0' | '1' | string; //"mainnet" | "testnet";
export type TKeyDerivationAccount = '0' | string;
export type TKeyDerivationChange = '0' | '1'; //"Receiving Address" | "Change Address";
export type TKeyDerivationIndex = string;
export type TAddressTypes = {
	[key in EAddressType]: Readonly<IAddressTypeData>;
};
// A namespace rather than an object so the alias still behaves like the enum
// it replaced: its const members widen to Network where an enum member would,
// and its type members keep `EAvailableNetworks.mainnet` usable as a type.
/**
 * @deprecated Use {@link Network}. The extra member names are spellings of
 * its four values. Removed in the next major release.
 */
// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace EAvailableNetworks {
	export const bitcoin = Network.bitcoin;
	export const mainnet = Network.bitcoin;
	export const bitcoinMainnet = Network.bitcoin;
	export const testnet = Network.testnet;
	export const bitcoinTestnet = Network.testnet;
	export const regtest = Network.regtest;
	export const bitcoinRegtest = Network.regtest;
	export const signet = Network.signet;
	export const bitcoinSignet = Network.signet;
	export type bitcoin = Network.bitcoin;
	export type mainnet = Network.bitcoin;
	export type bitcoinMainnet = Network.bitcoin;
	export type testnet = Network.testnet;
	export type bitcoinTestnet = Network.testnet;
	export type regtest = Network.regtest;
	export type bitcoinRegtest = Network.regtest;
	export type signet = Network.signet;
	export type bitcoinSignet = Network.signet;
}
/**
 * @deprecated Use {@link Network}. Removed in the next major release.
 */
export type EAvailableNetworks = Network;

/**
 * Where getFeeEstimates sources its data:
 * - 'electrum': the connected Electrum server only (no clearnet HTTP leak).
 * - 'http': mempool.space with a blocktank fallback (legacy behavior).
 * - 'auto' (default): Electrum first, HTTP only when Electrum is unavailable
 *   or returns unusable values.
 */
export type TFeeEstimationSource = 'electrum' | 'http' | 'auto';
export enum EAddressType {
	p2wpkh = 'p2wpkh',
	p2sh = 'p2sh',
	p2pkh = 'p2pkh',
	p2tr = 'p2tr',
	// Sorted-multisig P2WSH (BIP 48 script type 2). Only available on wallets
	// created via Wallet.createMultisig; single-sig wallets reject it.
	p2wsh = 'p2wsh'
}

export enum EPaymentType {
	sent = 'sent',
	received = 'received'
}

export type TAddressTypeContent<T> = {
	[key in EAddressType]: T;
};

export interface IAddressTypeData {
	type: EAddressType;
	path: string;
	name: string;
	shortName: string;
	description: string;
	example: string;
}

export interface IUtxo {
	address: string;
	index: number;
	path: string;
	scriptHash: string;
	height: number;
	tx_hash: string;
	tx_pos: number;
	value: number;
	publicKey: string;
	keyPair?: BIP32Interface | ECPairInterface;
	/** Set on frozen (blacklisted) entries created with a tag: who froze the
	 *  coin (e.g. 'funding-pledge') and when, so automated freezers can
	 *  recover their own stale freezes after a restart. */
	freezeTag?: string;
	frozenAt?: number;
}

export interface IVin {
	scriptSig: {
		asm: string;
		hex: string;
	};
	sequence: number;
	txid: string;
	txinwitness: string[];
	vout: number;
}

/**
 * A coinbase input: no previous output exists, so bitcoind reports the
 * coinbase script instead of txid/vout/scriptSig. Mining directly to a
 * wallet address (regtest) puts these into the wallet's transaction flow
 * (issue #548), so the vin type models them rather than promising fields
 * the runtime value does not carry. Narrow with `'txid' in vin`.
 */
export interface ICoinbaseVin {
	coinbase: string;
	sequence: number;
	txinwitness?: string[];
}

export type TVin = IVin | ICoinbaseVin;

/**
 * An input as a formatted transaction stores it: the outpoint it spends, or
 * the coinbase marker. The scriptSig and witness are dropped, since nothing
 * reads them and they made up most of the stored history. Narrow with
 * `'txid' in vin`.
 */
export type TFormattedVin =
	| Pick<IVin, 'txid' | 'vout' | 'sequence'>
	| Pick<ICoinbaseVin, 'coinbase' | 'sequence'>;

export interface IFormattedTransaction {
	address: string;
	blockhash?: string;
	height?: number;
	scriptHash: string;
	// Each amount is held in sats (the *Sats fields) and in BTC, as decoded
	// from the raw transaction. The BTC fields are deprecated and go in the
	// next major release. Until then the sats fields are optional, so code
	// that builds or stores records without them still compiles. The wallet
	// sets them on every record it formats or loads.
	/** @deprecated BTC: use totalInputSats. */
	totalInputValue: number;
	/** The sum of the outputs the inputs spend. */
	totalInputSats?: Sats;
	/** @deprecated BTC: use matchedInputSats. */
	matchedInputValue: number;
	/** The part of totalInputSats this wallet's addresses held. */
	matchedInputSats?: Sats;
	/** @deprecated BTC: use totalOutputSats. */
	totalOutputValue: number;
	totalOutputSats?: Sats;
	/** @deprecated BTC: use matchedOutputSats. */
	matchedOutputValue: number;
	/** The part of totalOutputSats paid to this wallet's addresses. */
	matchedOutputSats?: Sats;
	/** @deprecated BTC: use feeSats. */
	fee: number;
	/** 0 for a coinbase, which pays no fee. */
	feeSats?: Sats;
	/** The fee rate in sat/vB, rounded to a whole number. */
	satsPerByte: number;
	type: EPaymentType;
	/** @deprecated BTC: use valueSats. */
	value: number;
	/**
	 * matchedOutputSats minus matchedInputSats: negative for a send, and then
	 * it includes the fee.
	 */
	valueSats?: Sats;
	txid: string;
	messages: string[];
	vin: TFormattedVin[];
	timestamp: number;
	confirmTimestamp?: number;
	exists?: boolean;
	rbf?: boolean;
	vsize: number;
}

export interface IFormattedTransactions {
	[key: string]: IFormattedTransaction;
}

export interface IOutput {
	address: string; // Address to send to.
	value: number; // Amount denominated in sats.
	index: number; // Used to specify which output to update or edit when using updateSendTransaction.
}

export enum EBoostType {
	rbf = 'rbf',
	cpfp = 'cpfp'
}

export interface ISendTransaction {
	outputs: IOutput[];
	inputs: IUtxo[];
	changeAddress: string;
	fiatAmount: number;
	fee: number; //Total fee in sats
	satsPerByte: number; // sat/vB
	selectedFeeId: EFeeId;
	message: string; // OP_RETURN data for a given transaction.
	label: string; // User set label for a given transaction.
	rbf: boolean;
	boostType: EBoostType;
	minFee: number; // (sats/vbyte) Lowest fee rate to offer for an RBF/CPFP boost. A rate like satsPerByte, not a total like fee.
	max: boolean; // If the user intends to send the max amount.
	tags: string[];
	slashTagsUrl?: string; // TODO: Remove after migration.
	lightningInvoice?: string; // TODO: Remove after migration.
}

export interface IAddresses {
	[scriptHash: string]: IAddress;
}

export interface IAddress {
	index: number;
	path: string;
	address: string;
	scriptHash: string;
	publicKey: string;
}

export interface IWalletData {
	id: string;
	addressType: EAddressType;
	header: IHeader;
	addresses: TAddressTypeContent<IAddresses>;
	changeAddresses: TAddressTypeContent<IAddresses>;
	addressIndex: TAddressTypeContent<IAddress>;
	changeAddressIndex: TAddressTypeContent<IAddress>;
	lastUsedAddressIndex: TAddressTypeContent<IAddress>;
	lastUsedChangeAddressIndex: TAddressTypeContent<IAddress>;
	utxos: IUtxo[];
	blacklistedUtxos: IUtxo[];
	unconfirmedTransactions: IFormattedTransactions;
	transactions: IFormattedTransactions;
	boostedTransactions: IBoostedTransactions;
	transaction: ISendTransaction;
	balance: number;
	selectedFeeId: EFeeId;
	feeEstimates: IOnchainFees;
	// User-set labels keyed by address. Separate from IAddressData.label,
	// which holds the address-type name and is kept for back-compat.
	addressLabels: TAddressLabels;
	// Wallet creation height (0 = unknown). Metadata only on Electrum; see
	// Wallet.birthdayHeight docs.
	birthdayHeight: number;
}

export type TAddressLabels = { [address: string]: string };

export type TWalletDataKeys = keyof IWalletData;

// Must return ok(undefined) for a key the storage does not hold, and err only
// when the read itself fails. Wallet.create refuses to start on an err (see
// IWallet.resetOnReadFailure), since a wallet loaded from defaults would save
// them over the data it could not read.
export type TGetData = <K extends keyof IWalletData>(
	key: string
) => Promise<Result<IWalletData[K]>>;
export type TSetData = <K extends keyof IWalletData>(
	key: string,
	value: IWalletData[K]
) => Promise<Result<boolean>>;

export interface IWallet {
	mnemonic?: string;
	// Account-level extended public key (xpub/ypub/zpub/tpub/upub/vpub) for
	// watch-only wallets. Used only when no mnemonic is provided.
	xpub?: string;
	id?: string;
	name?: string;
	passphrase?: string;
	// The BIP39 seed of mnemonic + passphrase, for a host that already holds
	// it (BeignetNode derives it once per boot): the constructor then skips
	// its PBKDF2 pass. It is not checked against the mnemonic, so it must be
	// that mnemonic's seed. Ignored without a mnemonic.
	seed?: Buffer;
	network?: Network;
	addressType?: EAddressType;
	// BIP32 account index (m/purpose'/coin'/ACCOUNT'/change/index). Defaults
	// to 0. Non-zero accounts use distinct storage keys so instances over the
	// same mnemonic and storage never collide. For watch-only wallets the
	// account is already encoded in the xpub; the option only namespaces
	// storage.
	account?: number;
	// Block height at wallet creation. Stored (earliest value wins) and
	// exposed for backends/tools that can bound scans by height; the Electrum
	// protocol cannot, see Wallet.birthdayHeight docs.
	birthdayHeight?: number;
	coinSelectPreference?: ECoinSelectPreference;
	data?: IWalletData;
	storage?: TStorage;
	// Treat a storage read that fails as a missing key and start from the
	// default for it. Off by default: the wallet's next save then overwrites
	// whatever the storage could not read, frozen coins and labels included.
	resetOnReadFailure?: boolean;
	electrumOptions: IElectrumOptions;
	remainOffline?: boolean;
	onMessage?: TOnMessage;
	// Answers every single-key address in place of the wallet's own
	// derivation. The answer is used as given, so it must be the address
	// and public key at the path asked for.
	customGetAddress?: (
		data: ICustomGetAddress
	) => Promise<Result<IGetAddressResponse>>;
	customGetScriptHash?: (data: ICustomGetScriptHash) => Promise<string>;
	rbf?: boolean;
	selectedFeeId?: EFeeId;
	feeEstimationSource?: TFeeEstimationSource;
	disableMessages?: boolean;
	/** Hold onMessage until the first refresh ends, so stored history does not
	 *  replay as news. A storageWriteFailed message still passes: it is the
	 *  only word a host gets of a write that storage refused at startup. */
	disableMessagesOnCreate?: boolean;
	/** Skip the refreshWallet Wallet.create fires in the background, for a
	 *  host that owns the startup refresh itself and needs to hold the ONE
	 *  refresh promise (issue #548; BeignetNode's waitForInitialSync). */
	disableRefreshOnCreate?: boolean;
	// Leveled diagnostic logger (debug/info/warn/error). Defaults to a
	// console-backed logger at 'info' so existing console output is
	// preserved; inject your own to reroute or silence diagnostics.
	// Independent of disableMessages, which only gates onMessage callbacks.
	logger?: ILogger;
	addressTypesToMonitor?: EAddressType[];
	gapLimitOptions?: TGapLimitOptions;
	addressLookBehind?: number;
	addressLookAhead?: number;
	// Sorted-multisig configuration. Prefer Wallet.createMultisig over
	// passing this directly.
	multisig?: IMultisigOptions;
	// Watch-only only: the true BIP 32 master fingerprint (8 hex chars) of
	// the device that holds the xpub's private key, and the derivation path
	// from that master to the xpub (e.g. "m/84'/0'/0'"). When provided, PSBT
	// bip32_derivation entries and exported descriptors carry a correct
	// BIP 174/380 key origin that hardware signers accept. Without them the
	// xpub's parent fingerprint is used as before, which most hardware
	// signers refuse to match.
	masterFingerprint?: string;
	originPath?: string;
}

export interface IAddressData {
	path: string;
	type: 'p2wpkh' | 'p2sh' | 'p2pkh';
	label: string;
}

export interface IAddressType {
	[key: string]: IAddressData;
}

// m / purpose' / coin_type' / account' / change / index
export interface IKeyDerivationPath {
	purpose?: TKeyDerivationPurpose;
	coinType?: TKeyDerivationCoinType;
	account?: TKeyDerivationAccount;
	change?: TKeyDerivationChange;
	index?: TKeyDerivationIndex;
}

export interface IGetDerivationPath extends IKeyDerivationPath {
	addressType?: EAddressType;
}

export interface IGetAddress {
	index?: TKeyDerivationIndex;
	changeAddress?: boolean;
	addressType?: EAddressType;
}

export interface ICustomGetAddress {
	path: string;
	type: EAddressType;
	selectedNetwork: EElectrumNetworks;
}

export interface ICustomGetScriptHash {
	address: string;
	selectedNetwork: EElectrumNetworks;
}

export interface IGetAddressByPath {
	path: string;
	addressType?: EAddressType;
}

export interface IGetAddressBalanceRes {
	confirmed: number;
	unconfirmed: number;
}

export interface IGenerateAddresses {
	addressAmount?: number;
	changeAddressAmount?: number;
	addressIndex?: number;
	changeAddressIndex?: number;
	keyDerivationPath?: IKeyDerivationPath;
	addressType?: EAddressType;
	saveAddresses?: boolean;
}

export interface IKeyDerivationPathData {
	pathString: string;
	pathObject: IKeyDerivationPath;
}

export interface IGenerateAddressesResponse {
	addresses: IAddresses;
	changeAddresses: IAddresses;
}

export interface IGetAddressResponse {
	address: string;
	path: string;
	publicKey: string;
}

export interface IGetAddressesFromPrivateKey {
	keyPair: BIP32Interface | ECPairInterface;
	addresses: IGetAddressesFromKeyPair[];
}

export interface IGetAddressesFromKeyPair {
	address: string;
	publicKey: string;
}

export interface IGetNextAvailableAddressResponse {
	addressIndex: IAddress;
	lastUsedAddressIndex: IAddress;
	changeAddressIndex: IAddress;
	lastUsedChangeAddressIndex: IAddress;
}

/**
 * What a refresh's gap-limit scan hands the steps after it, so each script
 * hash's history is asked for once and the UTXOs are listed once.
 */
export type TAddressScan = {
	/** The history answered so far, by script hash. */
	history: Map<string, TTxResult[]>;
	/**
	 * Whether those answers can stand in for a new lookup: the wallet is on
	 * the network that gave them, and no stored transaction has been cleared
	 * or repaired since the first was asked for.
	 */
	current: () => boolean;
	/** What the UTXO scan of each extension round would have listed. */
	utxoAddresses: IAddresses;
};

export interface ITxHashes extends TTxResult {
	scriptHash: string;
}

export interface IIndexes {
	addressIndex: IAddress;
	changeAddressIndex: IAddress;
	foundAddressIndex: boolean;
	foundChangeAddressIndex: boolean;
}

export interface ITxHash {
	tx_hash: string;
}

export interface IGetTransactions {
	error: boolean;
	id: number;
	method: string;
	network: string;
	data: ITransaction<IUtxo>[];
}

export interface ITransaction<T> {
	id: number;
	jsonrpc: string;
	param: string;
	data: T;
	result: TTxDetails;
	error?: { code: number; message: string };
}

export type TTxDetails = {
	blockhash?: string;
	confirmations?: number;
	hash: string;
	hex: string;
	locktime: number;
	size: number;
	txid: string;
	version: number;
	vin: TVin[];
	vout: IVout[];
	vsize: number;
	weight: number;
	blocktime?: number;
	time?: number;
};

export interface IVout {
	n: number; //0
	scriptPubKey: {
		addresses?: string[];
		address?: string;
		asm: string;
		hex: string;
		reqSigs?: number;
		type?: string;
	};
	value: number;
}

export type TProcessUnconfirmedTransactions = {
	unconfirmedTxs: IFormattedTransactions; // zero-conf transactions
	outdatedTxs: IUtxo[]; // Transactions that are no longer confirmed.
	ghostTxs: string[]; // Transactions that have been removed from the mempool.
};

export enum EUnit {
	satoshi = 'satoshi',
	BTC = 'BTC',
	fiat = 'fiat'
}

export type InputData = {
	[key: string]: {
		addresses: string[];
		value: number;
	};
};

export type TGetByteCountInputs = {
	[key in TGetByteCountInput]?: number;
};

export type TGetByteCountOutputs = {
	[key in TGetByteCountOutput]?: number;
};

export type TGetByteCountInput =
	| `MULTISIG-P2SH:${number}-${number}`
	| `MULTISIG-P2WSH:${number}-${number}`
	| `MULTISIG-P2SH-P2WSH:${number}-${number}`
	| 'P2SH-P2WPKH'
	| 'P2PKH'
	| 'p2pkh'
	| 'P2WPKH'
	| 'p2wpkh'
	| 'P2SH'
	| 'p2sh'
	| 'P2TR'
	| 'p2tr';

export type TGetByteCountOutput =
	| 'P2SH'
	| 'P2PKH'
	| 'P2WPKH'
	| 'P2WSH'
	| 'p2wpkh'
	| 'p2sh'
	| 'p2pkh'
	| 'P2TR'
	| 'p2tr';

export interface IGetFeeEstimatesResponse {
	fastestFee: number;
	halfHourFee: number;
	hourFee: number;
	minimumFee: number;
}

//On-chain fee estimates in sats/vbyte
export interface IOnchainFees {
	fast: number; // 10-20 mins
	normal: number; // 20-60 mins
	slow: number; // 1-2 hrs
	minimum: number;
	timestamp: number;
}

export type TMessageDataMap = {
	newBlock: INewBlock;
	transactionReceived: TTransactionMessage;
	transactionConfirmed: TTransactionMessage;
	transactionSent: TTransactionMessage;
	reorg: IUtxo[];
	rbf: string[];
	connectedToElectrum: boolean; // True if connected, false if disconnected.
	storageWriteFailed: TStorageWriteFailure;
};

/**
 * A write the storage adapter refused or threw on. Sent for every such write,
 * including those whose method also returns the error: storage still holds
 * the value from before, and the next start loads it.
 */
export type TStorageWriteFailure = {
	key: TWalletDataKeys;
	/** The key handed to setData, which names the wallet and network. */
	storageKey: string;
	error: string;
};

export type TTransactionMessage = {
	transaction: IFormattedTransaction;
};

// MIT License
// Copyright (c) Sindre Sorhus <sindresorhus@gmail.com> (https://sindresorhus.com)
// https://github.com/sindresorhus/ts-extras
export type ObjectKeys<T extends object> = `${Exclude<keyof T, symbol>}`;

// Define the type of the onMessage function
export type TOnMessage = <K extends keyof TMessageDataMap>(
	key: K,
	data: TMessageDataMap[K]
) => void;

export type TMessageKeys = keyof TMessageDataMap;

export interface ISendTx {
	address: string;
	amount: number;
	message?: string;
}

export interface ISend {
	txs: ISendTx | ISendTx[];
	satsPerByte?: number; // sat/vB
}

// Watch-only wallets are constructed from an account-level xpub; mnemonic,
// passphrase and key-dependent options do not apply.
export type IWatchOnlyWallet = Omit<
	IWallet,
	'mnemonic' | 'passphrase' | 'seed' | 'xpub'
> & {
	xpub: string;
};

// A multisig cosigner known by more than a bare xpub: the cosigner device's
// true master fingerprint (8 hex chars) and the path from that master to the
// account xpub (e.g. "m/48'/0'/0'/2'"). Supplying them lets PSBTs and
// exported descriptors carry the BIP 174/380 key origin hardware cosigners
// (Coldcard/Ledger/BitBox) and coordinators (Sparrow) require.
export interface IMultisigCosigner {
	xpub: string;
	masterFingerprint?: string;
	originPath?: string;
}

// Sorted-multisig (BIP 48 / BIP 67) wallet configuration.
export interface IMultisigOptions {
	// Signatures required to spend (m of n).
	threshold: number;
	// Account-level extended public keys (BIP 48 m/48'/coin'/account'/2')
	// for the cosigners, either as bare strings or as IMultisigCosigner
	// objects carrying key-origin metadata. SLIP-132 Zpub/Vpub encodings are
	// normalized. When a mnemonic is provided, our own derived account xpub
	// is added automatically if it is not already present.
	cosigners: (string | IMultisigCosigner)[];
	// Optional explicit statement of OUR account xpub. With a mnemonic it
	// must match the derived key; provided without a mnemonic it is simply
	// included as a cosigner.
	ourXpub?: string;
}

// createMultisig params: a multisig wallet is always p2wsh and never uses a
// single account xpub. Omitting the mnemonic creates a watch-only multisig.
export type IMultisigWallet = Omit<IWallet, 'xpub' | 'addressType'> &
	IMultisigOptions;

export interface IBuildPsbtArgs {
	txs?: ISendTx[];
	address?: string;
	amount?: number; // sats
	message?: string;
	satsPerByte?: number; // sat/vB
	rbf?: boolean;
	shuffleOutputs?: boolean;
}

export interface IBuildPsbtInputSummary {
	tx_hash: string;
	tx_pos: number;
	address: string;
	value: number;
	path: string;
}

export interface IBuildPsbtOutputSummary {
	address?: string; // Undefined for non-address outputs (e.g. OP_RETURN).
	value: number;
	index: number;
}

export interface IBuildPsbtResponse {
	psbtBase64: string;
	fee: number; // sats
	vsizeEstimate: number; // vbytes
	satsPerByte: number; // sat/vB
	inputs: IBuildPsbtInputSummary[];
	outputs: IBuildPsbtOutputSummary[];
}

export interface IImportSignedPsbtResponse {
	txHex: string;
	txid: string;
}

/**
 * A transaction output: the txid of the transaction that created it, in
 * display order, and the output's position in that transaction.
 */
export interface IOutpoint {
	txid: string;
	vout: number;
}

/** The outpoint shape the freeze methods took before {@link IOutpoint}. */
export interface IIndexedOutpoint {
	txid: string;
	/** @deprecated Use `vout`. Removed in the next major release. */
	index: number;
}

export interface ICreateSignedTransactionArgs extends IBuildPsbtArgs {
	/**
	 * Spend every unfrozen coin to `address`, less the fee, as sendMax does.
	 * Refused alongside `amount` or `txs`.
	 */
	max?: boolean;
}

/** A signed transaction that has not been broadcast. */
export interface ISignedTransaction {
	txHex: string;
	txid: string;
}

export type TAddressIndexInfo = {
	addressIndex: IAddress;
	changeAddressIndex: IAddress;
	lastUsedAddressIndex: IAddress;
	lastUsedChangeAddressIndex: IAddress;
};

export type TStorage = {
	getData?: TGetData;
	setData?: TSetData;
};

export interface IRbfData {
	outputs: IOutput[];
	balance: number;
	addressType: EAddressType;
	fee: number; // Total fee in sats.
	inputs: IUtxo[];
	message: string;
	changeAddress: string;
}

export interface IBoostedTransaction {
	parentTransactions: string[]; // Array of parent txids to the currently boosted transaction.
	childTransaction: string; // Child txid of the currently boosted transaction.
	type: EBoostType;
	fee: number;
}

export interface IBoostedTransactions {
	[txId: string]: IBoostedTransaction;
}

export interface IBoost {
	txid: string;
	type: EBoostType;
	/** In sat/vB. Defaults to the rate setupRbf or setupCpfp picks. */
	satsPerByte?: number;
}

export interface IBoostRes {
	/** Txid of the replacement (RBF) or child (CPFP) transaction. */
	id: string;
	hex: string;
	/** Total fee paid by the new transaction, in sats. */
	fee: number;
}

export interface IPrivateKeyInfo {
	balance: number;
	utxos: IUtxo[];
	keyPair: ECPairInterface | BIP32Interface;
	addresses: IGetAddressesFromKeyPair[];
}

export interface ISweepPrivateKey {
	privateKey: string;
	toAddress: string;
	satsPerByte?: number; // sat/vB
	broadcast?: boolean;
	combineWithWalletUtxos?: boolean;
}

export interface ISweepPrivateKeyRes {
	balance: number;
	id: string;
	hex: string;
}

export interface IBtInfo {
	/**
	 * @deprecated Use the `versions` object instead.
	 */
	version: number;
	/**
	 * Available nodes.
	 */
	nodes: ILspNode[];
	options: {
		/**
		 * Minimum channel size
		 */
		minChannelSizeSat: number;
		/**
		 * Maximum channel size
		 */
		maxChannelSizeSat: number;
		/**
		 * Minimum channel lease time in weeks.
		 */
		minExpiryWeeks: number;
		/**
		 * Maximum channel lease time in weeks.
		 */
		maxExpiryWeeks: number;
		/**
		 * Minimum payment confirmation for safe payments.
		 */
		minPaymentConfirmations: number;
		/**
		 * Minimum payment confirmations for high value payments.
		 */
		minHighRiskPaymentConfirmations: number;
		/**
		 * Maximum clientBalanceSat that is accepted as 0conf/turbochannel.
		 */
		max0ConfClientBalanceSat: number;
		/**
		 * Maximum clientBalanceSat in general.
		 */
		maxClientBalanceSat: number;
	};
	/**
	 * SemVer versions of the micro services.
	 */
	versions: {
		/**
		 * SemVer versions of the http micro services.
		 */
		http: string;
		/**
		 * SemVer versions of the btc micro services.
		 */
		btc: string;
		/**
		 * SemVer versions of the ln2 micro services.
		 */
		ln2: string;
	};
	onchain: {
		network: Network;
		feeRates: {
			/**
			 * Fast fee in sat/vbyte.
			 */
			fast: number;
			/**
			 * Mid fee in sat/vbyte.
			 */
			mid: number;
			/**
			 * Slow fee in sat/vbyte.
			 */
			slow: number;
		};
	};
}

interface ILspNode {
	alias: string;
	pubkey: string;
	connectionStrings: string[];
}

export interface ICanBoostResponse {
	canBoost: boolean;
	rbf: boolean;
	cpfp: boolean;
}

// Balance split by frozen (blacklisted) UTXOs. total always equals
// spendable + frozen; getBalance() keeps returning total.
export interface IBalanceBreakdown {
	total: number;
	spendable: number;
	frozen: number;
}

// One output descriptor pair for a single address type.
export interface IExportedDescriptor {
	addressType: EAddressType;
	external: string; // .../0/* receive chain
	internal: string; // .../1/* change chain
}

export interface IExportDescriptorsResponse {
	fingerprint: string; // Master fingerprint hex (see getMasterFingerprint)
	network: Network;
	account: number;
	// Present when a birthday was recorded; helps a restore bound its scan.
	birthdayHeight?: number;
	watchOnly: boolean;
	descriptors: IExportedDescriptor[];
}
