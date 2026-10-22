/**
 * Regression test for issue #1657: a wallet refresh asked get_mempool beside
 * every get_history batch, although get_history already lists unconfirmed
 * entries, and fetched a transaction, and the parents of its inputs, once for
 * every history entry naming it.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port and the
 * client helpers are a counting fake server.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	createMemoryStorage,
	EAddressType,
	EAvailableNetworks,
	EPaymentType,
	EProtocol,
	IAddress,
	IAddresses,
	TTxDetails,
	Wallet
} from '../../src';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: this test must work offline. Not remainOffline,
// which refuses each request before it reaches the fake server.
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

/** A stranger's transaction, funding T. */
const P = '1a'.repeat(32);
/** Unconfirmed: pays three of the wallet's addresses from P:0. */
const T = '2b'.repeat(32);

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

const details = (
	txid: string,
	vin: Array<{ txid: string; vout: number }>,
	vout: Array<[string, number]>
): TTxDetails =>
	({
		txid,
		hash: txid,
		hex: '00',
		locktime: 0,
		size: 222,
		vsize: 141,
		weight: 561,
		version: 2,
		vin: vin.map((v) => ({
			...v,
			scriptSig: { asm: '', hex: '' },
			txinwitness: [],
			sequence: 0xfffffffd
		})),
		vout: vout.map(([address, value], n) => ({
			n,
			value,
			scriptPubKey: { asm: '', hex: '', address }
		}))
	}) as TTxDetails;

type TBatch<T> = { key: string; data: T[] };

describe('wallet refresh Electrum requests (#1657)', function () {
	this.timeout(60000);

	let wallet: Wallet;

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			addressTypesToMonitor: [EAddressType.p2wpkh, EAddressType.p2tr],
			electrumOptions,
			feeEstimationSource: 'electrum',
			// The test drives the refresh itself; nothing may scan behind it.
			disableRefreshOnCreate: true,
			storage: createMemoryStorage()
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		wallet.electrum.stopConnectionPolling();
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	it('asks get_history once per script hash, never get_mempool, and fetches each transaction once', async function () {
		const book: Record<string, { addresses: IAddresses; change: IAddresses }> =
			{};
		for (const addressType of [EAddressType.p2wpkh, EAddressType.p2tr]) {
			const gen = await wallet.generateAddresses({
				addressAmount: 3,
				changeAddressAmount: 3,
				addressType
			});
			if (gen.isErr()) throw gen.error;
			const stored = await wallet.updateData({
				addresses: {
					...wallet.data.addresses,
					[addressType]: gen.value.addresses
				},
				changeAddresses: {
					...wallet.data.changeAddresses,
					[addressType]: gen.value.changeAddresses
				}
			});
			if (stored.isErr()) throw stored.error;
			book[addressType] = {
				addresses: gen.value.addresses,
				change: gen.value.changeAddresses
			};
		}
		const at = (addresses: IAddresses, index: number): IAddress =>
			Object.values(addresses).find((a) => a.index === index) as IAddress;
		const receive = at(book[EAddressType.p2wpkh].addresses, 0);
		const change = at(book[EAddressType.p2wpkh].change, 1);
		const taproot = at(book[EAddressType.p2tr].addresses, 2);
		// T's coin on the first address, as the UTXO scan saved it.
		const utxos = await wallet.updateData({
			utxos: [
				{
					...receive,
					height: 0,
					tx_hash: T,
					tx_pos: 0,
					value: 10_000_000
				}
			]
		});
		if (utxos.isErr()) throw utxos.error;

		const transactions: Record<string, TTxDetails> = {
			[P]: details(P, [{ txid: 'ee'.repeat(32), vout: 0 }], [[EXTERNAL, 1]]),
			[T]: details(
				T,
				[{ txid: P, vout: 0 }],
				[
					[receive.address, 0.1],
					[change.address, 0.2],
					[taproot.address, 0.3],
					[EXTERNAL, 0.3999]
				]
			)
		};
		const touched = new Set([
			receive.scriptHash,
			change.scriptHash,
			taproot.scriptHash
		]);
		const scanned: string[] = [];
		const history = sinon
			.stub(electrumHelpers, 'getAddressScriptHashesHistory')
			.callsFake(
				async ({ scriptHashes }: { scriptHashes: TBatch<IAddress> }) => {
					scanned.push(...scriptHashes.data.map((a) => a.scriptHash));
					return {
						error: false,
						data: scriptHashes.data.map((a) => ({
							data: a,
							param: a.scriptHash,
							result: touched.has(a.scriptHash)
								? [{ tx_hash: T, height: 0 }]
								: []
						}))
					};
				}
			);
		const mempool = sinon
			.stub(electrumHelpers, 'getAddressScriptHashesMempool')
			.callsFake(
				async ({ scriptHashes }: { scriptHashes: TBatch<IAddress> }) => ({
					error: false,
					data: scriptHashes.data.map((a) => ({
						data: a,
						param: a.scriptHash,
						result: touched.has(a.scriptHash)
							? [{ tx_hash: T, height: 0, fee: 100 }]
							: []
					}))
				})
			);
		const fetched: string[] = [];
		sinon
			.stub(electrumHelpers, 'getTransactions')
			.callsFake(
				async ({ txHashes }: { txHashes: TBatch<{ tx_hash: string }> }) => {
					fetched.push(...txHashes.data.map((h) => h.tx_hash));
					return {
						error: false,
						data: txHashes.data.map((h) => ({
							id: 0,
							jsonrpc: '2.0',
							param: h.tx_hash,
							data: h,
							result: transactions[h.tx_hash]
						}))
					};
				}
			);
		wallet.electrum.connectedToElectrum = true;
		wallet.electrum.batchLimit = 4;
		wallet.electrum.batchDelay = 0;

		const res = await wallet.updateTransactions({});
		expect(res.isOk(), res.isErr() ? res.error.message : '').to.equal(true);

		const walletScriptHashes = Object.values(book).flatMap((entry) =>
			[...Object.values(entry.addresses), ...Object.values(entry.change)].map(
				(a) => a.scriptHash
			)
		);
		expect(walletScriptHashes).to.have.length(12);
		expect(
			[...scanned].sort(),
			'each address once, the UTXO address included'
		).to.deep.equal([...walletScriptHashes].sort());
		expect(history.callCount, 'one request per batch of four').to.equal(3);
		expect(mempool.callCount).to.equal(0);
		expect(
			fetched.filter((h) => h === T),
			'T is fetched once'
		).to.have.length(1);
		expect(
			fetched.filter((h) => h === P),
			'and so is the parent of its input'
		).to.have.length(1);

		const record = wallet.data.transactions[T];
		expect(record?.type).to.equal(EPaymentType.received);
		expect(record?.value).to.equal(0.6);
		expect(record?.height).to.equal(0);
		expect(record?.address, 'its last history entry').to.equal(taproot.address);
	});
});
