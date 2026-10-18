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
	EProtocol,
	IGetUtxosResponse,
	IOnchainFees,
	IUtxo,
	IWalletData,
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
		const settles = async (refresh: Promise<unknown>): Promise<boolean> => {
			let timer: ReturnType<typeof setTimeout> | undefined;
			const settled = await Promise.race([
				refresh.then(() => true),
				new Promise<boolean>((resolve) => {
					timer = setTimeout(() => resolve(false), 5000);
				})
			]);
			clearTimeout(timer);
			return settled;
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
