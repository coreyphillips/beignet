/**
 * Regression test for issue #1617: BeignetNode.sendOnchain let go of the
 * wallet's send lock once wallet.send returned, then broadcast and reset the
 * staged send outside it. A direct wallet.send that took the lock in that gap
 * lost its staged inputs to the reset and failed to sign.
 *
 * Issue #1626: BeignetNode.prepareOnchainSweep reset and staged the wallet's
 * transaction under the node's lock alone, wiping a direct send the same way.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port, UTXOs are
 * injected into wallet data, and the broadcast is stubbed.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';
import {
	address as bitcoinAddress,
	networks,
	Transaction as BitcoinTransaction
} from 'bitcoinjs-lib';

import { BeignetNode } from '../../src/cli/beignet-node';
import { ONCHAIN_SWEEPS_KEY } from '../../src/cli/onchain-sweep';
import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	EProtocol,
	IWalletData,
	Result,
	TStorage,
	Wallet,
	err,
	ok
} from '../../src';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

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

const network = networks.regtest;
const CLI_PAYEE = bitcoinAddress.toBech32(Buffer.alloc(20, 3), 0, 'bcrt');
const DIRECT_PAYEE = bitcoinAddress.toBech32(Buffer.alloc(20, 4), 0, 'bcrt');
const SWEEP_PAYEE = bitcoinAddress.toBech32(Buffer.alloc(20, 5), 0, 'bcrt');
const LARGE_COIN = '11'.repeat(32);
const SMALL_COIN = '22'.repeat(32);

/**
 * An in-memory TStorage that answers each write on a later tick, as a real
 * adapter does.
 */
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
			await new Promise((resolve) => setImmediate(resolve));
			store.set(key, value);
			return ok(true);
		}
	};
};

const spends = (hex: string): string[] =>
	BitcoinTransaction.fromHex(hex).ins.map(
		(input) =>
			`${Buffer.from(input.hash).reverse().toString('hex')}:${input.index}`
	);

const pays = (hex: string): string[] =>
	BitcoinTransaction.fromHex(hex).outs.map(
		(out) =>
			`${bitcoinAddress.fromOutputScript(out.script, network)}:${out.value}`
	);

/** A promise and the function that resolves it. */
const gate = (): { opened: Promise<void>; open: () => void } => {
	let open!: () => void;
	const opened = new Promise<void>((resolve) => (open = resolve));
	return { opened, open };
};

describe('CLI on-chain sends hold the wallet send lock (#1617, #1626)', function () {
	this.timeout(60000);

	let wallet: Wallet;

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'clisendlock',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			rbf: true,
			// Each send spends one coin, so the two sends fund independently.
			coinSelectPreference: ECoinSelectPreference.large,
			storage: memoryStorage(),
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		for (const [txid, value] of [
			[LARGE_COIN, 60_000],
			[SMALL_COIN, 30_000]
		] as const) {
			wallet.data.utxos.push({
				address: source.address,
				index: source.index,
				path: source.path,
				scriptHash: source.scriptHash,
				height: 1,
				tx_hash: txid,
				tx_pos: 0,
				value,
				publicKey: source.publicKey
			});
			wallet.data.balance += value;
		}
		sinon
			.stub(electrumHelpers, 'subscribeAddress')
			.resolves({ error: false, data: '' });
		// Segwit inputs build from witnessUtxo when the previous transaction
		// cannot be fetched.
		sinon.stub(wallet.electrum, 'getTransactions').resolves(err('offline'));
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	it('a direct send overlapping a CLI broadcast keeps its staged inputs', async () => {
		const atBroadcast = gate();
		const broadcastGate = gate();
		sinon
			.stub(electrumHelpers, 'broadcastTransaction')
			.callsFake(async ({ rawTx }: { rawTx: string }) => {
				atBroadcast.open();
				await broadcastGate.opened;
				return {
					error: false,
					data: BitcoinTransaction.fromHex(rawTx).getId()
				};
			});
		// Object.create skips field initializers, so the send lock is set here.
		const node = Object.assign(Object.create(BeignetNode.prototype), {
			wallet,
			_onchainSendLock: Promise.resolve()
		}) as BeignetNode;

		const cli = node.sendOnchain(CLI_PAYEE, 20_000, 2);
		await atBroadcast.opened;

		// Hold the direct send at key derivation, after it has staged its inputs
		// and before it signs them.
		const atSigning = gate();
		const signingGate = gate();
		const derive = wallet.getBip32Interface;
		sinon.stub(wallet, 'getBip32Interface').callsFake(async () => {
			atSigning.open();
			await signingGate.opened;
			return derive();
		});
		const direct = wallet.send({
			address: DIRECT_PAYEE,
			amount: 10_000,
			satsPerByte: 2,
			broadcast: false
		});
		// Under the lock the direct send cannot get this far until the CLI send
		// is done, so this waits a moment rather than on it.
		await Promise.race([
			atSigning.opened,
			new Promise((resolve) => setTimeout(resolve, 100))
		]);

		broadcastGate.open();
		const sent = await cli;
		signingGate.open();
		const built = await direct;
		if (built.isErr()) expect.fail(built.error.message);

		expect(spends(sent.hex)).to.deep.equal([`${LARGE_COIN}:0`]);
		expect(pays(sent.hex)).to.include(`${CLI_PAYEE}:20000`);
		expect(spends(built.value)).to.deep.equal([`${SMALL_COIN}:0`]);
		expect(pays(built.value)).to.include(`${DIRECT_PAYEE}:10000`);
	});

	it('a sweep prepared while a direct send signs leaves its staged inputs alone', async () => {
		const journal = new Map<string, string>();
		const node = Object.assign(Object.create(BeignetNode.prototype), {
			wallet,
			_onchainSendLock: Promise.resolve(),
			storage: {
				loadWalletData: (key: string) => journal.get(key) ?? null,
				saveWalletData: (key: string, value: string) => {
					journal.set(key, value);
				}
			},
			getBitcoinNetwork: () => network
		}) as BeignetNode;

		// Hold only the direct send at key derivation, after it has staged its
		// inputs and before it signs them. The sweep signs on a later call.
		const atSigning = gate();
		const signingGate = gate();
		const derive = wallet.getBip32Interface;
		const stub = sinon.stub(wallet, 'getBip32Interface').callThrough();
		stub.onFirstCall().callsFake(async () => {
			atSigning.open();
			await signingGate.opened;
			return derive();
		});
		const direct = wallet.send({
			address: DIRECT_PAYEE,
			amount: 20_000,
			satsPerByte: 2,
			broadcast: false
		});
		await atSigning.opened;

		const sweep = node.prepareOnchainSweep({
			requestId: 'overlapping-sweep',
			address: SWEEP_PAYEE,
			satsPerVbyte: 2,
			inputOutpoints: [{ txid: SMALL_COIN, vout: 0 }],
			debitSats: 30_000,
			maxFeeSats: 1_000
		});
		// Under the lock the sweep cannot finish until the direct send is done,
		// so this waits a moment rather than on it.
		await Promise.race([
			sweep,
			new Promise((resolve) => setTimeout(resolve, 100))
		]);

		signingGate.open();
		const built = await direct;
		if (built.isErr()) expect.fail(built.error.message);
		const prepared = await sweep;

		expect(spends(built.value)).to.deep.equal([`${LARGE_COIN}:0`]);
		expect(pays(built.value)).to.include(`${DIRECT_PAYEE}:20000`);
		expect(prepared.status).to.equal('prepared');
		const [record] = JSON.parse(journal.get(ONCHAIN_SWEEPS_KEY)!);
		expect(spends(record.hex)).to.deep.equal([`${SMALL_COIN}:0`]);
		expect(pays(record.hex)).to.deep.equal([
			`${SWEEP_PAYEE}:${prepared.amountSats}`
		]);
	});
});
