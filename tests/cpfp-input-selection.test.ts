/**
 * CPFP input selection (#1026). Fully OFFLINE: the wallet points at an
 * unreachable Electrum port and UTXOs are injected into wallet data.
 *
 * setupTransaction filtered the wallet's UTXOs by inputTxHashes and, when
 * nothing matched, fell back to every unfrozen coin. setupCpfp passes the
 * parent's txid there, so boosting a parent whose output was frozen, already
 * spent or not yet scanned sent the whole wallet to itself at the boost rate.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	EAddressType,
	EAvailableNetworks,
	EBoostType,
	EProtocol,
	IUtxo,
	IWalletData,
	Result,
	TStorage,
	Wallet,
	ok
} from '../src';
import { IFormattedTransaction } from '../src/types/wallet';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: this test must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65529,
		tcp: 65529,
		protocol: EProtocol.tcp
	}
};

const PARENT_TXID = 'aa'.repeat(32);
const OTHER_TXID_1 = '11'.repeat(32);
const OTHER_TXID_2 = '22'.repeat(32);

/** An in-memory TStorage, so freezeUtxo has somewhere to persist. */
const memoryStorage = (): TStorage => {
	const store = new Map<string, unknown>();
	return {
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
	};
};

describe('CPFP input selection (#1026)', function () {
	this.timeout(60000);

	let wallet: Wallet;

	/** Fabricates a UTXO paying to the wallet's own index-0 address. */
	const injectUtxo = (txid: string, value: number): IUtxo => {
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		if (!source?.address) throw new Error('No derived address available.');
		const utxo: IUtxo = {
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height: 0,
			tx_hash: txid,
			tx_pos: 0,
			value,
			publicKey: source.publicKey
		};
		wallet.data.utxos.push(utxo);
		wallet.data.balance += value;
		return utxo;
	};

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'cpfpinputs',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			storage: memoryStorage(),
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		wallet.feeEstimates = { ...wallet.feeEstimates, fast: 50, normal: 20 };
		// The unconfirmed parent: 200 vB, 1000 sats of fee.
		wallet.data.transactions[PARENT_TXID] = {
			fee: 0.00001,
			vsize: 200
		} as IFormattedTransaction;
		injectUtxo(OTHER_TXID_1, 1_000_000);
		injectUtxo(OTHER_TXID_2, 2_000_000);
	});

	afterEach(async function () {
		await wallet?.stop();
	});

	const expectNothingStaged = (): void => {
		expect(wallet.transaction.data.inputs).to.have.length(0);
		expect(wallet.transaction.data.outputs).to.have.length(0);
	};

	it('refuses when the parent has no UTXO of ours', async () => {
		// Already spent by another pending transaction, or not yet scanned.
		const res = await wallet.transaction.setupCpfp({ txid: PARENT_TXID });
		expect(res.isErr(), 'setupCpfp refused').to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.include(PARENT_TXID);
		expectNothingStaged();
	});

	it("refuses when the parent's only output to us is frozen", async () => {
		injectUtxo(PARENT_TXID, 50_000);
		const frozen = await wallet.freezeUtxo({ txid: PARENT_TXID, index: 0 });
		if (frozen.isErr()) throw frozen.error;

		const res = await wallet.transaction.setupCpfp({ txid: PARENT_TXID });
		expect(res.isErr(), 'setupCpfp refused').to.equal(true);
		expectNothingStaged();
	});

	it('setupTransaction errs rather than selecting every coin when inputTxHashes matches nothing', async () => {
		const res = await wallet.transaction.setupTransaction({
			inputTxHashes: [PARENT_TXID]
		});
		expect(res.isErr(), 'setupTransaction refused').to.equal(true);
		expectNothingStaged();
	});

	it("spends only the parent's output when it is spendable", async () => {
		injectUtxo(PARENT_TXID, 50_000);

		const res = await wallet.transaction.setupCpfp({ txid: PARENT_TXID });
		if (res.isErr()) throw res.error;
		expect(res.value.boostType).to.equal(EBoostType.cpfp);
		expect(
			res.value.inputs.map((input) => input.tx_hash),
			'only the parent is spent'
		).to.deep.equal([PARENT_TXID]);
		expect(res.value.outputs).to.have.length(1);
	});
});
