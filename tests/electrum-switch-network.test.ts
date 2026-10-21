/**
 * switchNetwork against an unreachable target: the real switching lifecycle
 * (fresh wallet built for the target network, background refresh failing
 * offline). Runs in its OWN mocha process: rn-electrum-client keeps
 * module-global client state without request timeouts, and any other
 * wallet's failed-connect residue in the same process can wedge the awaited
 * calls in this lifecycle.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import { networks, payments } from 'bitcoinjs-lib';
import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	EPaymentType,
	EProtocol,
	Electrum,
	IFormattedTransaction,
	IFormattedTransactions,
	IGetAddressHistoryResponse,
	IGetNextAvailableAddressResponse,
	IGetTransactions,
	IGetUtxosResponse,
	IOnchainFees,
	ITransaction,
	IUtxo,
	IWalletData,
	err,
	ok,
	Result,
	TStorage,
	Wallet
} from '../src';
import { getWalletDataStorageKey } from '../src/utils/wallet';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: this test must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65528,
		tcp: 65528,
		protocol: EProtocol.tcp
	}
};

const otherServer = {
	host: '127.0.0.1',
	ssl: 65527,
	tcp: 65527,
	protocol: EProtocol.tcp
};

const network = EAvailableNetworks.regtest;

// Valid curve points (G, 2G), so bitcoinjs will encode them.
const address = (pubkey: string): string =>
	payments.p2wpkh({
		pubkey: Buffer.from(pubkey, 'hex'),
		network: networks.regtest
	}).address as string;
const PAYEE = address(
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
);
const CHANGE = address(
	'02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
);

const utxo = (value: number, index: number): IUtxo => ({
	address: PAYEE,
	index,
	path: `m/84'/1'/0'/0/${index}`,
	scriptHash: '00'.repeat(32),
	height: 1,
	tx_hash: 'ab'.repeat(32),
	tx_pos: index,
	value,
	publicKey: '02'.repeat(33)
});

const makeStorage = (store: Map<string, unknown>): TStorage => ({
	getData: async <K extends keyof IWalletData>(
		key: string
	): Promise<Result<IWalletData[K]>> => ok(store.get(key) as IWalletData[K]),
	setData: async <K extends keyof IWalletData>(
		key: string,
		value: IWalletData[K]
	): Promise<Result<boolean>> => {
		store.set(key, value);
		return ok(true);
	}
});

/** Whether the promise settles within five seconds. */
const settles = async (pending: Promise<unknown>): Promise<boolean> => {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const settled = await Promise.race([
		pending.then(() => true),
		new Promise<boolean>((resolve) => {
			timer = setTimeout(() => resolve(false), 5000);
		})
	]);
	clearTimeout(timer);
	return settled;
};

/** A gate a stub can hold a call at, reporting when the call is held. */
const holdable = (): {
	held: Promise<void>;
	hold: () => Promise<void>;
	release: () => void;
} => {
	let release = (): void => {};
	const open = new Promise<void>((resolve) => {
		release = resolve;
	});
	let arrived = (): void => {};
	const held = new Promise<void>((resolve) => {
		arrived = resolve;
	});
	return {
		held,
		hold: async (): Promise<void> => {
			arrived();
			await open;
		},
		release
	};
};

/** Answers every call the rest of a refresh makes without reaching a server. */
const offline = (electrum: Electrum): void => {
	electrum.getUtxos = async (): Promise<Result<IGetUtxosResponse>> =>
		ok({ utxos: [], balance: 0 });
	electrum.getAddressHistory = async (): Promise<
		Result<IGetAddressHistoryResponse[]>
	> => ok([]);
	electrum.subscribeToAddresses = async (): Promise<Result<string>> => ok('');
};

/** A received payment to PAYEE, last seen at `height`. */
const payment = (txid: string, height: number): IFormattedTransaction => ({
	address: PAYEE,
	scriptHash: '00'.repeat(32),
	height,
	totalInputValue: 0.002,
	matchedInputValue: 0,
	totalOutputValue: 0.0019,
	matchedOutputValue: 0.001,
	fee: 0.0001,
	satsPerByte: 10,
	type: EPaymentType.received,
	value: 0.001,
	txid,
	messages: [],
	vin: [],
	timestamp: 1,
	vsize: 100
});

/** A getTransactions answer with one entry per txid. */
const answer = (entries: {
	[txid: string]: {
		result?: { confirmations: number };
		error?: { code: number; message: string };
	};
}): Result<IGetTransactions> =>
	ok({
		error: false,
		id: 0,
		method: 'getTransactions',
		network,
		data: Object.entries(entries).map(
			([txid, entry]) =>
				({
					...entry,
					data: { tx_hash: txid }
				}) as unknown as ITransaction<IUtxo>
		)
	});

/** makeStorage, holding the next write to the key passed to holdNext. */
const holdingStorage = (
	store: Map<string, unknown>
): ReturnType<typeof holdable> & {
	storage: TStorage;
	holdNext: (key: string) => void;
} => {
	const gate = holdable();
	let at: string | undefined;
	return {
		...gate,
		holdNext: (key: string): void => {
			at = key;
		},
		storage: {
			getData: makeStorage(store).getData,
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				if (key === at) {
					at = undefined;
					await gate.hold();
				}
				store.set(key, value);
				return ok(true);
			}
		}
	};
};

describe('switchNetwork against an unreachable target', function () {
	this.timeout(60000);

	it('switchNetwork to an unreachable network completes with the connection reported down', async function () {
		// The real switching lifecycle: a fresh wallet is built for the target
		// network, its background refresh fails offline, and the switch still
		// completes; the connection must be reported down, not up.
		// feeEstimationSource electrum keeps the awaited fee refresh offline.
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			electrumOptions,
			feeEstimationSource: 'electrum'
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		try {
			// The target stays regtest: it is the only network with NO bundled
			// public fallback servers, so the new wallet's background refresh
			// cannot nondeterministically reach a real host and flip the
			// connection state mid-assertion. The network-field movement to a
			// DIFFERENT network is pinned by the stubbed field-update test in
			// electrum-connect-failure.test.ts.
			const switched = await w.switchNetwork(
				EAvailableNetworks.regtest,
				otherServer
			);
			expect(switched.isOk()).to.equal(true);
			expect(w.network).to.equal(EAvailableNetworks.regtest);
			expect(w.electrum.network).to.equal(EAvailableNetworks.regtest);
			expect([w.electrum.servers].flat()).to.deep.equal([otherServer]);
			expect(w.electrum.connectedToElectrum).to.equal(false);
		} finally {
			await w.stop();
		}
	});

	it('leaves nothing bound to the wallet the switch built (#1595)', async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			electrumOptions,
			feeEstimationSource: 'electrum'
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		try {
			const switched = await w.switchNetwork(
				EAvailableNetworks.regtest,
				otherServer
			);
			if (switched.isErr()) throw switched.error;
			const transaction = w.transaction as unknown as { _wallet: Wallet };
			expect(
				transaction._wallet === w,
				'Transaction reads this wallet'
			).to.equal(true);
			expect(w.electrum.wallet === w, 'Electrum reads this wallet').to.equal(
				true
			);

			// The refresh the switch starts runs on this wallet, so it is this
			// wallet's flag that comes down and a later refresh is answered.
			let timer: ReturnType<typeof setTimeout> | undefined;
			const refreshed = await Promise.race([
				w.refreshWallet().then(() => true),
				new Promise<boolean>((resolve) => {
					timer = setTimeout(() => resolve(false), 20000);
				})
			]);
			clearTimeout(timer);
			expect(refreshed, 'a refresh after the switch settles').to.equal(true);
			expect(w.isRefreshing).to.equal(false);

			// Quotes default to the preference and fee estimate set afterwards.
			w.data.utxos = [utxo(100000, 0), utxo(20000, 1)];
			const quote = (
				options: {
					satsPerByte?: number;
					coinSelectPreference?: ECoinSelectPreference;
				} = {}
			): { transactionByteCount: number; satsPerByte: number } => {
				const quoted = w.transaction.getTotalFeeObj({
					transaction: {
						outputs: [{ address: PAYEE, value: 10000, index: 0 }],
						changeAddress: CHANGE
					},
					...options
				});
				if (quoted.isErr()) throw quoted.error;
				return quoted.value;
			};
			w.updateCoinSelectPreference(ECoinSelectPreference.large);
			const large = quote({
				satsPerByte: 10,
				coinSelectPreference: ECoinSelectPreference.large
			});
			const consolidate = quote({
				satsPerByte: 10,
				coinSelectPreference: ECoinSelectPreference.consolidate
			});
			expect(large.transactionByteCount).to.be.below(
				consolidate.transactionByteCount
			);
			expect(quote({ satsPerByte: 10 })).to.deep.equal(large);
			w.feeEstimates = { ...w.feeEstimates, normal: 23 };
			expect(quote().satsPerByte).to.equal(23);

			// getReceiveAddress is an arrow method: it reads the address type of
			// the wallet whose constructor bound it.
			w.addressType = EAddressType.p2tr;
			const receive = await w.getReceiveAddress({});
			if (receive.isErr()) throw receive.error;
			expect(receive.value.startsWith('bcrt1p')).to.equal(true);
		} finally {
			await w.stop();
		}
	});

	it('keeps later refreshes answered when a refresh spans the switch (#1595)', async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			electrumOptions,
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		let release = (): void => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		(
			w as unknown as { _runRefresh: () => Promise<Result<IWalletData>> }
		)._runRefresh = async (): Promise<Result<IWalletData>> => {
			await gate;
			return ok(w.data);
		};
		try {
			const spanning = w.refreshWallet();
			const switched = await w.switchNetwork(
				EAvailableNetworks.regtest,
				otherServer
			);
			if (switched.isErr()) throw switched.error;
			release();
			expect(await settles(spanning)).to.equal(true);
			expect(await settles(w.refreshWallet())).to.equal(true);
			expect(await settles(w.refreshWallet())).to.equal(true);
			expect(w.isRefreshing).to.equal(false);
		} finally {
			release();
			await w.stop();
		}
	});

	it('drops a UTXO answer from the network the wallet switched away from (#1614)', async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			electrumOptions,
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		const stubs = w as unknown as {
			_scanSeq: number;
			_appliedScanSeq: number;
			_runRefresh: () => Promise<Result<IWalletData>>;
		};
		w.checkElectrumConnection = async (): Promise<Result<string>> =>
			ok('connected');
		w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(w.feeEstimates);
		stubs._runRefresh = async (): Promise<Result<IWalletData>> => ok(w.data);
		let release = (): void => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		w.electrum.getUtxos = async (): Promise<Result<IGetUtxosResponse>> => {
			await gate;
			return ok({ utxos: [utxo(100000, 0)], balance: 100000 });
		};
		try {
			stubs._scanSeq = 100;
			const stale = w.getUtxos({});
			const switched = await w.switchNetwork(
				EAvailableNetworks.signet,
				otherServer
			);
			if (switched.isErr()) throw switched.error;
			release();
			expect((await stale).isErr()).to.equal(true);
			expect(w.network).to.equal(EAvailableNetworks.signet);
			expect(w.data.utxos).to.deep.equal([]);
			expect(w.data.balance).to.equal(0);
			expect(stubs._appliedScanSeq).to.equal(0);

			w.electrum.getUtxos = async (): Promise<Result<IGetUtxosResponse>> =>
				ok({ utxos: [utxo(30000, 1)], balance: 30000 });
			const fresh = await w.getUtxos({});
			if (fresh.isErr()) throw fresh.error;
			expect(stubs._appliedScanSeq).to.equal(1);
			expect(w.data.utxos).to.deep.equal([utxo(30000, 1)]);
			expect(w.data.balance).to.equal(30000);
		} finally {
			release();
			await w.stop();
		}
	});

	it('keeps the mark of a scan started after the switch when one from before it lands (#1635)', async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			electrumOptions,
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		const stubs = w as unknown as {
			_scanMarks: number[];
			_runRefresh: () => Promise<Result<IWalletData>>;
		};
		w.checkElectrumConnection = async (): Promise<Result<string>> =>
			ok('connected');
		w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(w.feeEstimates);
		stubs._runRefresh = async (): Promise<Result<IWalletData>> => ok(w.data);
		// Each stub answers once released, and reports when its query is out,
		// since getUtxos registers the mark only after a connection check.
		const held = (): {
			issued: Promise<void>;
			release: () => void;
			getUtxos: () => Promise<Result<IGetUtxosResponse>>;
		} => {
			let release = (): void => {};
			const gate = new Promise<void>((resolve) => {
				release = resolve;
			});
			let issue = (): void => {};
			const issued = new Promise<void>((resolve) => {
				issue = resolve;
			});
			return {
				issued,
				release,
				getUtxos: async (): Promise<Result<IGetUtxosResponse>> => {
					issue();
					await gate;
					return ok({ utxos: [utxo(30000, 1)], balance: 30000 });
				}
			};
		};
		const before = held();
		const after = held();
		w.electrum.getUtxos = before.getUtxos;
		try {
			const stale = w.getUtxos({});
			await before.issued;
			const switched = await w.switchNetwork(
				EAvailableNetworks.signet,
				otherServer
			);
			if (switched.isErr()) throw switched.error;
			w.electrum.getUtxos = after.getUtxos;
			const later = w.getUtxos({});
			await after.issued;
			// Both generations number their marks from zero.
			expect(stubs._scanMarks).to.deep.equal([0]);

			before.release();
			expect((await stale).isErr()).to.equal(true);
			expect(stubs._scanMarks).to.deep.equal([0]);

			after.release();
			const laterRes = await later;
			if (laterRes.isErr()) throw laterRes.error;
			expect(stubs._scanMarks).to.deep.equal([]);
			expect(w.data.utxos).to.deep.equal([utxo(30000, 1)]);
			expect(w.data.balance).to.equal(30000);
		} finally {
			before.release();
			after.release();
			await w.stop();
		}
	});

	it('writes a pending UTXO pair under the network it was scanned on (#1623)', async function () {
		const name = 'switchsave';
		const store = new Map<string, unknown>();
		const key = (on: EAvailableNetworks, field: keyof IWalletData): string =>
			getWalletDataStorageKey(name, on, field);
		let release = (): void => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		let held = (): void => {};
		const holding = new Promise<void>((resolve) => {
			held = resolve;
		});
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name,
			network,
			electrumOptions,
			storage: {
				...makeStorage(store),
				setData: async <K extends keyof IWalletData>(
					at: string,
					value: IWalletData[K]
				): Promise<Result<boolean>> => {
					if (at === key(network, 'utxos')) {
						held();
						await gate;
					}
					store.set(at, value);
					return ok(true);
				}
			},
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		w.checkElectrumConnection = async (): Promise<Result<string>> =>
			ok('connected');
		w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(w.feeEstimates);
		(
			w as unknown as { _runRefresh: () => Promise<Result<IWalletData>> }
		)._runRefresh = async (): Promise<Result<IWalletData>> => ok(w.data);
		w.electrum.getUtxos = async (): Promise<Result<IGetUtxosResponse>> =>
			ok({ utxos: [utxo(100000, 0)], balance: 100000 });
		try {
			const scan = w.getUtxos({});
			await holding;
			const switched = await w.switchNetwork(
				EAvailableNetworks.signet,
				otherServer
			);
			if (switched.isErr()) throw switched.error;
			release();
			if ((await scan).isErr()) throw new Error('the scan failed');

			expect(w.data.utxos).to.deep.equal([]);
			expect(w.data.balance).to.equal(0);
			expect(store.has(key(EAvailableNetworks.signet, 'utxos'))).to.equal(
				false
			);
			expect(store.has(key(EAvailableNetworks.signet, 'balance'))).to.equal(
				false
			);
			expect(store.get(key(network, 'utxos'))).to.deep.equal([utxo(100000, 0)]);
			expect(store.get(key(network, 'balance'))).to.equal(100000);
		} finally {
			release();
			await w.stop();
		}
	});

	it('keeps a pending write ahead of a newer one after switching back (#1631)', async function () {
		const name = 'switchback';
		const store = new Map<string, unknown>();
		const key = (field: keyof IWalletData): string =>
			getWalletDataStorageKey(name, network, field);
		let release = (): void => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		let held = (): void => {};
		const holding = new Promise<void>((resolve) => {
			held = resolve;
		});
		let holds = 1;
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name,
			network,
			electrumOptions,
			storage: {
				...makeStorage(store),
				setData: async <K extends keyof IWalletData>(
					at: string,
					value: IWalletData[K]
				): Promise<Result<boolean>> => {
					if (at === key('utxos') && holds-- > 0) {
						held();
						await gate;
					}
					store.set(at, value);
					return ok(true);
				}
			},
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		w.checkElectrumConnection = async (): Promise<Result<string>> =>
			ok('connected');
		w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(w.feeEstimates);
		(
			w as unknown as { _runRefresh: () => Promise<Result<IWalletData>> }
		)._runRefresh = async (): Promise<Result<IWalletData>> => ok(w.data);
		w.electrum.getUtxos = async (): Promise<Result<IGetUtxosResponse>> =>
			ok({ utxos: [utxo(100000, 0)], balance: 100000 });
		try {
			const older = w.getUtxos({});
			await holding;
			const away = await w.switchNetwork(
				EAvailableNetworks.signet,
				otherServer
			);
			if (away.isErr()) throw away.error;
			// Nothing in this process connected to signet, so there is no client
			// for the switch back to stop.
			w.electrum.disconnect = async (): Promise<void> => {};
			const back = await w.switchNetwork(network, otherServer);
			if (back.isErr()) throw back.error;
			w.electrum.getUtxos = async (): Promise<Result<IGetUtxosResponse>> =>
				ok({ utxos: [], balance: 0 });
			const newer = w.getUtxos({});
			// The newer scan runs as far as it can: unordered, its pair is already
			// stored when the older write lands on top of it.
			await new Promise<void>((resolve) => setImmediate(resolve));
			release();
			if ((await older).isErr()) throw new Error('the older scan failed');
			if ((await newer).isErr()) throw new Error('the newer scan failed');

			expect(w.data.utxos).to.deep.equal([]);
			expect(w.data.balance).to.equal(0);
			expect(store.get(key('utxos'))).to.deep.equal([]);
			expect(store.get(key('balance'))).to.equal(0);
		} finally {
			release();
			await w.stop();
		}
	});

	it('keeps the Electrum batch options and the create-time flags across a switch (#1637)', async function () {
		const heard: string[] = [];
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			electrumOptions: { ...electrumOptions, batchLimit: 5, batchDelay: 1 },
			feeEstimationSource: 'electrum',
			disableMessagesOnCreate: true,
			disableRefreshOnCreate: true,
			onMessage: (key): void => {
				heard.push(key);
			}
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		const stubs = w as unknown as {
			_quietUntilFirstRefresh: boolean;
			_disableRefreshOnCreate: boolean;
			_runRefresh: () => Promise<Result<IWalletData>>;
		};
		w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(w.feeEstimates);
		// The switch starts a refresh, and the first refresh to end lowers the
		// message hold. Holding it keeps the flags as the switch left them.
		let release = (): void => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		stubs._runRefresh = async (): Promise<Result<IWalletData>> => {
			await gate;
			return ok(w.data);
		};
		try {
			expect(w.electrum.batchLimit).to.equal(5);
			expect(w.electrum.batchDelay).to.equal(1);
			expect(stubs._quietUntilFirstRefresh).to.equal(true);
			expect(stubs._disableRefreshOnCreate).to.equal(true);

			const switched = await w.switchNetwork(
				EAvailableNetworks.signet,
				otherServer
			);
			if (switched.isErr()) throw switched.error;
			expect([w.electrum.servers].flat()).to.deep.equal([otherServer]);
			expect(w.electrum.batchLimit).to.equal(5);
			expect(w.electrum.batchDelay).to.equal(1);
			// A later switch builds from these, so they have to be complete too.
			expect(w.electrumOptions).to.include({
				batchLimit: 5,
				batchDelay: 1,
				servers: otherServer
			});
			expect(stubs._disableRefreshOnCreate).to.equal(true);
			expect(stubs._quietUntilFirstRefresh).to.equal(true);
			w.sendMessage('reorg', []);
			expect(heard).to.not.include('reorg');

			// The hold still ends with the first refresh, which is the switch's.
			const later = w.refreshWallet();
			release();
			await later;
			expect(stubs._quietUntilFirstRefresh).to.equal(false);
			w.sendMessage('reorg', []);
			expect(heard).to.include('reorg');
		} finally {
			release();
			await w.stop();
		}
	});

	it('waits for a send in flight before replacing what it stages on and broadcasts with (#1636)', async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		const stubs = w as unknown as {
			_runRefresh: () => Promise<Result<IWalletData>>;
			setZeroIndexAddresses: () => Promise<Result<string>>;
		};
		w.checkElectrumConnection = async (): Promise<Result<string>> =>
			ok('connected');
		w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(w.feeEstimates);
		stubs._runRefresh = async (): Promise<Result<IWalletData>> => ok(w.data);
		// Index-0 addresses, derived offline: a coin to spend and change to pay.
		await stubs.setZeroIndexAddresses();
		const source = w.data.addressIndex[EAddressType.p2wpkh];
		w.data.utxos = [
			{
				...source,
				height: 1,
				tx_hash: '11'.repeat(32),
				tx_pos: 0,
				value: 60000
			}
		];
		w.data.balance = 60000;
		const electrum = w.electrum;
		const transaction = w.transaction;
		// Segwit inputs build from witnessUtxo when the previous transaction
		// cannot be fetched.
		electrum.getTransactions = async (): Promise<Result<IGetTransactions>> =>
			err('offline');
		const broadcast: string[] = [];
		electrum.broadcastTransaction = async ({
			rawTx
		}: {
			rawTx: string;
		}): Promise<Result<string>> => {
			broadcast.push(rawTx);
			return ok('ff'.repeat(32));
		};
		// The send pauses at signing, its inputs staged.
		const signing = holdable();
		const createTransaction = transaction.createTransaction;
		transaction.createTransaction = async (
			args
		): ReturnType<typeof createTransaction> => {
			await signing.hold();
			return createTransaction(args);
		};
		const order: string[] = [];
		const send = (): Promise<Result<string>> =>
			w.send({ address: PAYEE, amount: 15000, satsPerByte: 2 });
		try {
			const sent = send().then((r) => {
				order.push('send');
				return r;
			});
			await signing.held;
			const switched = w
				.switchNetwork(EAvailableNetworks.signet, otherServer)
				.then((r) => {
					order.push('switch');
					return r;
				});
			// A send that arrives while the switch waits runs once it is done.
			const later = send().then((r) => {
				order.push('later');
				return r;
			});
			await new Promise((resolve) => setTimeout(resolve, 200));
			expect(order).to.deep.equal([]);
			expect(w.isSwitchingNetworks).to.equal(false);
			expect(w.network).to.equal(network);
			expect(w.electrum).to.equal(electrum);
			expect(w.transaction).to.equal(transaction);

			signing.release();
			const sentRes = await sent;
			if (sentRes.isErr()) throw sentRes.error;
			expect(sentRes.value).to.equal('ff'.repeat(32));
			expect(broadcast).to.have.length(1);
			const switchedRes = await switched;
			if (switchedRes.isErr()) throw switchedRes.error;
			expect(w.network).to.equal(EAvailableNetworks.signet);
			expect(w.electrum).to.not.equal(electrum);
			// Nothing to spend on the network switched to.
			const laterRes = await later;
			expect(laterRes.isErr()).to.equal(true);
			if (laterRes.isErr()) {
				expect(laterRes.error.message).to.equal('No UTXOs available.');
			}
			expect(order).to.deep.equal(['send', 'switch', 'later']);
		} finally {
			signing.release();
			await w.stop();
		}
	});

	it('drops the index scan of a refresh held across the switch (#1636)', async function () {
		const name = 'switchindex';
		const store = new Map<string, unknown>();
		const key = (on: EAvailableNetworks, field: keyof IWalletData): string =>
			getWalletDataStorageKey(name, on, field);
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name,
			network,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			storage: makeStorage(store),
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		w.checkElectrumConnection = async (): Promise<Result<string>> =>
			ok('connected');
		w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(w.feeEstimates);
		offline(w.electrum);
		// The scan the refresh is held at finds regtest's index 5 used once it
		// is released. Every later scan finds nothing new.
		const generated = await w.generateAddresses({
			addressAmount: 1,
			changeAddressAmount: 1,
			addressIndex: 5,
			changeAddressIndex: 5,
			addressType: EAddressType.p2wpkh
		});
		if (generated.isErr()) throw generated.error;
		const used = Object.values(generated.value.addresses)[0];
		const usedChange = Object.values(generated.value.changeAddresses)[0];
		const scanning = holdable();
		let first = true;
		w.getNextAvailableAddress = async (
			addressType = EAddressType.p2wpkh
		): Promise<Result<IGetNextAvailableAddressResponse>> => {
			if (first) {
				first = false;
				await scanning.hold();
				return ok({
					addressIndex: used,
					lastUsedAddressIndex: used,
					changeAddressIndex: usedChange,
					lastUsedChangeAddressIndex: usedChange
				});
			}
			return ok({
				addressIndex: w.data.addressIndex[addressType],
				lastUsedAddressIndex: w.data.lastUsedAddressIndex[addressType],
				changeAddressIndex: w.data.changeAddressIndex[addressType],
				lastUsedChangeAddressIndex:
					w.data.lastUsedChangeAddressIndex[addressType]
			});
		};
		try {
			const spanning = w.refreshWallet();
			await scanning.held;
			const switched = await w.switchNetwork(
				EAvailableNetworks.signet,
				otherServer
			);
			if (switched.isErr()) throw switched.error;
			offline(w.electrum);
			scanning.release();
			expect(await settles(spanning)).to.equal(true);
			expect(w.isRefreshing).to.equal(false);

			// The refresh the switch started set signet's index 0; regtest's
			// index 5 reached neither memory nor storage.
			const index = w.data.addressIndex[EAddressType.p2wpkh];
			expect(index.index).to.equal(0);
			expect(index.address.startsWith('tb1q')).to.equal(true);
			expect(
				w.data.changeAddressIndex[EAddressType.p2wpkh].address.startsWith(
					'tb1q'
				)
			).to.equal(true);
			const stored = store.get(
				key(EAvailableNetworks.signet, 'addressIndex')
			) as IWalletData['addressIndex'];
			expect(stored[EAddressType.p2wpkh]).to.deep.equal(index);
			const signetValues = [...store.entries()]
				.filter(([at]) => at.includes(EAvailableNetworks.signet))
				.map(([, value]) => JSON.stringify(value));
			expect(signetValues.some((value) => value.includes('bcrt1'))).to.equal(
				false
			);
		} finally {
			scanning.release();
			await w.stop();
		}
	});

	it('drops the history a refresh held across the switch read (#1636)', async function () {
		const name = 'switchhistory';
		const store = new Map<string, unknown>();
		const key = (on: EAvailableNetworks, field: keyof IWalletData): string =>
			getWalletDataStorageKey(name, on, field);
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name,
			network,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			storage: makeStorage(store),
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		const stubs = w as unknown as {
			updateAddressIndexes: () => Promise<Result<string>>;
		};
		w.checkElectrumConnection = async (): Promise<Result<string>> =>
			ok('connected');
		w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(w.feeEstimates);
		stubs.updateAddressIndexes = async (): Promise<Result<string>> =>
			ok('No update needed.');
		offline(w.electrum);
		// The history the refresh is held at answers with a regtest payment
		// once it is released.
		const txid = 'cc'.repeat(32);
		const payee = utxo(100000, 0);
		const received: IFormattedTransaction = {
			address: payee.address,
			scriptHash: payee.scriptHash,
			height: 1,
			totalInputValue: 0.002,
			matchedInputValue: 0,
			totalOutputValue: 0.0019,
			matchedOutputValue: 0.001,
			fee: 0.0001,
			satsPerByte: 10,
			type: EPaymentType.received,
			value: 0.001,
			txid,
			messages: [],
			vin: [],
			timestamp: 1,
			vsize: 100
		};
		const reading = holdable();
		w.electrum.getAddressHistory = async (): Promise<
			Result<IGetAddressHistoryResponse[]>
		> => {
			await reading.hold();
			return ok([{ ...payee, tx_hash: txid }]);
		};
		w.electrum.getTransactions = async (): Promise<Result<IGetTransactions>> =>
			ok({ error: false, id: 0, method: 'getTransactions', network, data: [] });
		w.formatTransactions = async (): Promise<Result<IFormattedTransactions>> =>
			ok({ [txid]: received });
		try {
			const spanning = w.refreshWallet();
			await reading.held;
			const switched = await w.switchNetwork(
				EAvailableNetworks.signet,
				otherServer
			);
			if (switched.isErr()) throw switched.error;
			offline(w.electrum);
			reading.release();
			expect(await settles(spanning)).to.equal(true);
			expect(w.isRefreshing).to.equal(false);

			expect(w.data.transactions).to.deep.equal({});
			expect(w.data.unconfirmedTransactions).to.deep.equal({});
			expect(
				store.has(key(EAvailableNetworks.signet, 'transactions'))
			).to.equal(false);
			expect(
				store.get(key(EAvailableNetworks.signet, 'unconfirmedTransactions'))
			).to.deep.equal({});
			expect(store.has(key(network, 'transactions'))).to.equal(false);
		} finally {
			reading.release();
			await w.stop();
		}
	});

	// Index 0 is the address the refresh moves the receive index to. Index 1
	// is in the lookahead it then fills the address map with.
	for (const heldIndex of [0, 1]) {
		it(`drops the zero index addresses a refresh derived across the switch, held at index ${heldIndex} (#1754)`, async function () {
			const name = `switchzero${heldIndex}`;
			const store = new Map<string, unknown>();
			const res = await Wallet.create({
				mnemonic: MNEMONIC,
				name,
				network,
				addressType: EAddressType.p2wpkh,
				electrumOptions,
				storage: makeStorage(store),
				feeEstimationSource: 'electrum',
				disableRefreshOnCreate: true
			});
			if (res.isErr()) throw res.error;
			const w = res.value;
			w.checkElectrumConnection = async (): Promise<Result<string>> =>
				ok('connected');
			w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
				ok(w.feeEstimates);
			offline(w.electrum);
			const generated = await w.generateAddresses({
				addressAmount: 1,
				changeAddressAmount: 0,
				addressIndex: heldIndex,
				addressType: EAddressType.p2wpkh
			});
			if (generated.isErr()) throw generated.error;
			const held = Object.values(generated.value.addresses)[0].address;
			const deriving = holdable();
			const getScriptHash = w.getScriptHash.bind(w);
			w.getScriptHash = async (options): Promise<string> => {
				const scriptHash = await getScriptHash(options);
				if (options.address === held) await deriving.hold();
				return scriptHash;
			};
			try {
				const spanning = w.refreshWallet();
				await deriving.held;
				const switched = await w.switchNetwork(
					EAvailableNetworks.signet,
					otherServer
				);
				if (switched.isErr()) throw switched.error;
				offline(w.electrum);
				deriving.release();
				expect(await settles(spanning)).to.equal(true);
				expect(w.isRefreshing).to.equal(false);

				// The refresh the switch started set signet's own index 0.
				const index = w.data.addressIndex[EAddressType.p2wpkh];
				expect(index.index).to.equal(0);
				expect(index.address.startsWith('tb1q')).to.equal(true);
				expect(JSON.stringify(w.data)).not.to.include('bcrt1');
				const stored = store.get(
					getWalletDataStorageKey(
						name,
						EAvailableNetworks.signet,
						'addressIndex'
					)
				) as IWalletData['addressIndex'];
				expect(stored[EAddressType.p2wpkh]).to.deep.equal(index);
				const signetValues = [...store.entries()]
					.filter(([at]) => at.includes(EAvailableNetworks.signet))
					.map(([, value]) => JSON.stringify(value));
				expect(signetValues.some((value) => value.includes('bcrt1'))).to.equal(
					false
				);
			} finally {
				deriving.release();
				await w.stop();
			}
		});
	}

	it('drops a reorg repair a switch lands in the write of (#1754)', async function () {
		const name = 'switchreorg';
		const store = new Map<string, unknown>();
		const key = (on: EAvailableNetworks, field: keyof IWalletData): string =>
			getWalletDataStorageKey(name, on, field);
		const saving = holdingStorage(store);
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name,
			network,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			storage: saving.storage,
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		w.checkElectrumConnection = async (): Promise<Result<string>> =>
			ok('connected');
		w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(w.feeEstimates);
		offline(w.electrum);
		// Seen in block 100, and back in the mempool once the refresh asks.
		const txid = 'ee'.repeat(32);
		w.data.transactions = { [txid]: payment(txid, 100) };
		w.data.unconfirmedTransactions = { [txid]: payment(txid, 100) };
		w.data.header.height = 101;
		w.electrum.getTransactions = async (): Promise<Result<IGetTransactions>> =>
			answer({ [txid]: { result: { confirmations: 0 } } });
		try {
			// Nothing in the refresh writes regtest's transactions before the
			// repair does.
			saving.holdNext(key(network, 'transactions'));
			const spanning = w.refreshWallet();
			await saving.held;
			const switched = await w.switchNetwork(
				EAvailableNetworks.signet,
				otherServer
			);
			if (switched.isErr()) throw switched.error;
			offline(w.electrum);
			saving.release();
			expect(await settles(spanning)).to.equal(true);
			expect(w.isRefreshing).to.equal(false);

			expect(w.data.transactions).to.deep.equal({});
			expect(w.data.unconfirmedTransactions).to.deep.equal({});
			const signetValues = [...store.entries()]
				.filter(([at]) => at.includes(EAvailableNetworks.signet))
				.map(([, value]) => JSON.stringify(value));
			expect(signetValues.some((value) => value.includes(txid))).to.equal(
				false
			);
			// The repair still landed on the network it was made for.
			const repaired = store.get(
				key(network, 'transactions')
			) as IFormattedTransactions;
			expect(repaired[txid].height).to.equal(0);
		} finally {
			saving.release();
			await w.stop();
		}
	});

	// The ghost repair writes the transactions map, then the unconfirmed map,
	// then rescans the addresses. A switch can land in either write.
	for (const field of ['transactions', 'unconfirmedTransactions'] as const) {
		it(`drops a ghost repair a switch lands in the ${field} write of (#1754)`, async function () {
			const name = `switchghost${field}`;
			const store = new Map<string, unknown>();
			const key = (on: EAvailableNetworks, at: keyof IWalletData): string =>
				getWalletDataStorageKey(name, on, at);
			const saving = holdingStorage(store);
			const res = await Wallet.create({
				mnemonic: MNEMONIC,
				name,
				network,
				addressType: EAddressType.p2wpkh,
				electrumOptions,
				storage: saving.storage,
				feeEstimationSource: 'electrum',
				disableRefreshOnCreate: true
			});
			if (res.isErr()) throw res.error;
			const w = res.value;
			w.checkElectrumConnection = async (): Promise<Result<string>> =>
				ok('connected');
			w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
				ok(w.feeEstimates);
			offline(w.electrum);
			// One transaction gone from both the chain and the mempool, and one
			// still in the mempool.
			const ghost = 'ee'.repeat(32);
			const pending = 'ef'.repeat(32);
			w.data.transactions = {
				[ghost]: payment(ghost, 100),
				[pending]: payment(pending, 0)
			};
			w.data.unconfirmedTransactions = { ...w.data.transactions };
			w.data.header.height = 101;
			w.electrum.getTransactions = async (): Promise<
				Result<IGetTransactions>
			> =>
				answer({
					[ghost]: {
						error: {
							code: 2,
							message: 'No such mempool or blockchain transaction'
						}
					},
					[pending]: { result: { confirmations: 0 } }
				});
			let rescans = 0;
			const rescanAddresses = w.rescanAddresses.bind(w);
			w.rescanAddresses = async (options): Promise<Result<IWalletData>> => {
				rescans += 1;
				return rescanAddresses(options);
			};
			try {
				// Nothing in the refresh writes either map on regtest before the
				// repair does.
				saving.holdNext(key(network, field));
				const spanning = w.refreshWallet();
				await saving.held;
				const switched = await w.switchNetwork(
					EAvailableNetworks.signet,
					otherServer
				);
				if (switched.isErr()) throw switched.error;
				offline(w.electrum);
				saving.release();
				expect(await settles(spanning)).to.equal(true);
				expect(w.isRefreshing).to.equal(false);

				expect(w.data.transactions).to.deep.equal({});
				expect(w.data.unconfirmedTransactions).to.deep.equal({});
				const signetValues = [...store.entries()]
					.filter(([at]) => at.includes(EAvailableNetworks.signet))
					.map(([, value]) => JSON.stringify(value));
				expect(
					signetValues.some(
						(value) => value.includes(ghost) || value.includes(pending)
					)
				).to.equal(false);
				// Signet's indexes and UTXOs are left alone: the rescan was for
				// regtest's balance.
				expect(rescans).to.equal(0);
				// The ghost is still cleared on the network it was found on.
				const repaired = store.get(
					key(network, 'transactions')
				) as IFormattedTransactions;
				expect(repaired[ghost].exists).to.equal(false);
			} finally {
				saving.release();
				await w.stop();
			}
		});
	}

	it('keeps what the session remembers across sends and refreshes (#1636)', async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			electrumOptions,
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		const stubs = w as unknown as {
			_runRefresh: () => Promise<Result<IWalletData>>;
			_spentOutpoints: Map<string, number>;
			_spendSeq: number;
			_builtPsbts: Map<string, unknown[]>;
			_ghostClearings: Map<string, number>;
			_noTxindexMisses: Map<string, number>;
		};
		w.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(w.feeEstimates);
		stubs._runRefresh = async (): Promise<Result<IWalletData>> => ok(w.data);
		const txid = 'dd'.repeat(32);
		const { _spentOutpoints, _builtPsbts, _ghostClearings, _noTxindexMisses } =
			stubs;
		_spentOutpoints.set(`${txid}:0`, 2);
		stubs._spendSeq = 2;
		_builtPsbts.set('unsigned', []);
		_ghostClearings.set(txid, 3);
		_noTxindexMisses.set(txid, 100);
		try {
			const switched = await w.switchNetwork(
				EAvailableNetworks.signet,
				otherServer
			);
			if (switched.isErr()) throw switched.error;
			expect(stubs._spentOutpoints).to.equal(_spentOutpoints);
			expect(stubs._spentOutpoints.get(`${txid}:0`)).to.equal(2);
			expect(stubs._spendSeq).to.equal(2);
			expect(stubs._builtPsbts).to.equal(_builtPsbts);
			expect(stubs._builtPsbts.has('unsigned')).to.equal(true);
			expect(stubs._ghostClearings).to.equal(_ghostClearings);
			expect(stubs._ghostClearings.get(txid)).to.equal(3);
			expect(stubs._noTxindexMisses).to.equal(_noTxindexMisses);
			expect(stubs._noTxindexMisses.get(txid)).to.equal(100);
		} finally {
			await w.stop();
		}
	});

	it('leaves the wallet untouched when the target network fails to load (#1595)', async function () {
		const name = 'switchfail';
		const store = new Map<string, unknown>();
		// Another wallet's id under the target network's key fails the load.
		store.set(
			getWalletDataStorageKey(name, EAvailableNetworks.testnet, 'id'),
			'another-wallet'
		);
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name,
			network,
			electrumOptions,
			storage: makeStorage(store),
			feeEstimationSource: 'electrum'
		});
		if (res.isErr()) throw res.error;
		const w = res.value;
		try {
			const { data, electrum, transaction } = w;
			const switched = await w.switchNetwork(
				EAvailableNetworks.testnet,
				otherServer
			);
			expect(switched.isErr()).to.equal(true);
			if (switched.isErr()) {
				expect(switched.error.message).to.include('Mismatched id');
			}
			expect(w.isSwitchingNetworks).to.equal(false);
			expect(w.network).to.equal(network);
			expect(w.data).to.equal(data);
			expect(w.transaction).to.equal(transaction);
			expect(w.electrum).to.equal(electrum);
			expect(electrum.isDisconnected).to.equal(false);
		} finally {
			await w.stop();
		}
	});
});
