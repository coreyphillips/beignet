/**
 * Two on-chain wallet defects (#1038). Fully OFFLINE: the wallet points at an
 * unreachable Electrum port, UTXOs are injected into wallet data, and the
 * transaction lookups a boost makes are stubbed.
 *
 *  1. sendMax priced its single output as the wallet's own address type, so a
 *     p2wpkh wallet sweeping to a p2tr or p2wsh address paid for 31 vB of
 *     output and built 43 (visible once the sweep is above the 166 vB floor).
 *  2. getRbfData's "already confirmed" guard read the request echo Electrum
 *     tags each result with, so it never fired, and setupCpfp had no fresh
 *     check at all. Both relied on the height stored at the last refresh.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';
import {
	address as bitcoinAddress,
	Transaction as BitcoinTransaction
} from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IUtxo,
	IWalletData,
	Result,
	TStorage,
	Wallet,
	ok
} from '../src';
import {
	IFormattedTransaction,
	ITxHash,
	TTxDetails
} from '../src/types/wallet';

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

const P2TR = bitcoinAddress.toBech32(Buffer.alloc(32, 1), 1, 'bcrt');
const P2WSH = bitcoinAddress.toBech32(Buffer.alloc(32, 2), 0, 'bcrt');
const P2WPKH = bitcoinAddress.toBech32(Buffer.alloc(20, 3), 0, 'bcrt');

const BOOSTED_TXID = 'bb'.repeat(32);
const FUNDING_TXID = 'aa'.repeat(32);

/** An in-memory TStorage, so the wallet has somewhere to persist. */
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

describe('sweep output pricing and boost confirmation guard (#1038)', function () {
	this.timeout(60000);

	let wallet: Wallet;

	const receiveAddress = (): string =>
		wallet.data.addressIndex[EAddressType.p2wpkh].address;
	const changeAddress = (): string =>
		wallet.data.changeAddressIndex[EAddressType.p2wpkh].address;

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

	/**
	 * Answers getTransactions from a fixed set of verbose results, each tagged
	 * with the request it answers, the way rn-electrum-client tags them.
	 */
	const stubLookups = (results: Record<string, Partial<TTxDetails>>): void => {
		sinon
			.stub(wallet.electrum, 'getTransactions')
			.callsFake(async ({ txHashes }: { txHashes: ITxHash[] }) =>
				ok({
					error: false,
					id: 0,
					method: 'getTransactions',
					network: 'regtest',
					data: txHashes.map(({ tx_hash }) => ({
						id: 0,
						jsonrpc: '2.0',
						param: tx_hash,
						data: { tx_hash } as unknown as IUtxo,
						result: { txid: tx_hash, ...results[tx_hash] } as TTxDetails
					}))
				})
			);
	};

	/**
	 * The boosted transaction spends a confirmed output of ours, pays 40k sats
	 * away and 50k back to change.
	 */
	const stubBoostedTransaction = (confirmations?: number): void => {
		stubLookups({
			[BOOSTED_TXID]: {
				confirmations,
				vin: [{ txid: FUNDING_TXID, vout: 0 }] as TTxDetails['vin'],
				vout: [
					{ value: 0.0004, n: 0, scriptPubKey: { address: P2WPKH } },
					{ value: 0.0005, n: 1, scriptPubKey: { address: changeAddress() } }
				] as unknown as TTxDetails['vout']
			},
			[FUNDING_TXID]: {
				confirmations: 10,
				vout: [
					{ value: 0.001, n: 0, scriptPubKey: { address: receiveAddress() } }
				] as unknown as TTxDetails['vout']
			}
		});
	};

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'sweeppricing',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			rbf: true,
			storage: memoryStorage(),
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		wallet.feeEstimates = { ...wallet.feeEstimates, fast: 10, normal: 5 };
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	describe('sendMax', function () {
		[
			{ name: 'p2tr', to: P2TR },
			{ name: 'p2wsh', to: P2WSH },
			{ name: 'p2wpkh', to: P2WPKH }
		].forEach(({ name, to }) => {
			it(`pays the requested rate on a sweep to ${name}`, async function () {
				const satsPerByte = 10;
				// Two inputs, because getByteCount floors every estimate at 166 vB and
				// a 1-in-1-out sweep sits under that floor whatever its output type.
				injectUtxo(FUNDING_TXID, 100_000);
				injectUtxo(BOOSTED_TXID, 100_000);

				const res = await wallet.sendMax({
					address: to,
					satsPerByte,
					broadcast: false
				});
				if (res.isErr()) throw res.error;

				const tx = BitcoinTransaction.fromHex(res.value);
				expect(tx.ins).to.have.length(2);
				expect(tx.outs, 'a sweep needs no change output').to.have.length(1);
				const fee = 200_000 - tx.outs[0].value;
				// A 2-in-1-out p2wpkh-to-p2tr sweep is about 190 vB. Priced as p2wpkh
				// it paid for 178.
				expect(fee).to.be.at.least(tx.virtualSize() * satsPerByte);
				expect(fee).to.equal(wallet.transaction.data.fee);
			});
		});
	});

	describe('setupRbf', function () {
		beforeEach(function () {
			injectUtxo(FUNDING_TXID, 100_000);
		});

		it('refuses a transaction that has confirmed since the last refresh', async function () {
			stubBoostedTransaction(1);

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

			expect(res.isErr(), 'setupRbf refused').to.equal(true);
			if (res.isOk()) return;
			expect(res.error.message).to.include('already confirmed');
		});

		it('replaces an unconfirmed transaction that spends a confirmed coin', async function () {
			// The old guard sat in the input loop, where the transaction looked up
			// is the one funding the input. That one is normally confirmed, so the
			// check belongs on the transaction being replaced.
			stubBoostedTransaction(undefined);

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

			if (res.isErr()) throw res.error;
			expect(res.value.inputs.map((input) => input.tx_hash)).to.deep.equal([
				FUNDING_TXID
			]);
			expect(res.value.changeAddress).to.equal(changeAddress());
		});
	});

	describe('setupCpfp', function () {
		beforeEach(function () {
			// The unconfirmed parent as stored at the last refresh: 200 vB, 1000
			// sats of fee, and an output of ours the child can spend.
			wallet.data.transactions[BOOSTED_TXID] = {
				fee: 0.00001,
				vsize: 200
			} as IFormattedTransaction;
			injectUtxo(BOOSTED_TXID, 50_000);
		});

		it('refuses a parent that has confirmed since the last refresh', async function () {
			stubLookups({ [BOOSTED_TXID]: { confirmations: 1 } });
			const sendMax = sinon.spy(wallet.transaction, 'sendMax');

			const res = await wallet.transaction.setupCpfp({ txid: BOOSTED_TXID });

			expect(res.isErr(), 'setupCpfp refused').to.equal(true);
			if (res.isOk()) return;
			expect(res.error.message).to.include('already confirmed');
			expect(sendMax.called, 'no child was set up').to.equal(false);
			expect(wallet.transaction.data.outputs).to.have.length(0);
		});

		it('sets up a child for a parent that is still unconfirmed', async function () {
			stubLookups({ [BOOSTED_TXID]: {} });

			const res = await wallet.transaction.setupCpfp({ txid: BOOSTED_TXID });

			if (res.isErr()) throw res.error;
			expect(
				res.value.inputs.map((input) => input.tx_hash),
				'only the parent is spent'
			).to.deep.equal([BOOSTED_TXID]);
		});
	});
});
