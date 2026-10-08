/**
 * Issue #1361: the low-level staging calls (addOutput, removeTxInput) do not
 * reprice the staged fee. When the outputs plus that fee came to more than the
 * inputs, the builder dropped the negative change and the transaction paid
 * whatever was left, down to a few sats, while the staged fee still read as
 * the reviewed figure. The build is now refused instead.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum server, UTXOs
 * are fabricated and the previous-transaction fetch is stubbed.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	getScriptHash,
	IUtxo,
	ok,
	Wallet
} from '../src';

bitcoin.initEccLib(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const regtest = bitcoin.networks.regtest;
const network = EAvailableNetworks.regtest;
const PATH = "m/84'/1'/0'/0/0";

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

/** Previous transactions paying `values` to `script`, one output each. */
const makePrevTxs = (script: Buffer, values: number[]): bitcoin.Transaction[] =>
	values.map((value, i) => {
		const prevTx = new bitcoin.Transaction();
		prevTx.addInput(Buffer.alloc(32, i + 1), 0);
		prevTx.addOutput(script, value);
		return prevTx;
	});

describe('Staged fee the inputs cannot cover (#1361)', function () {
	this.timeout(120000);

	let wallet: Wallet;

	/** Gives the wallet one coin per value and serves their previous txs. */
	const fund = async (values: number[]): Promise<IUtxo[]> => {
		const address = await wallet.getAddress({
			index: '0',
			addressType: EAddressType.p2wpkh
		});
		const node = wallet.derivePublicNode(PATH);
		if (node.isErr()) throw node.error;
		const prevTxs = makePrevTxs(
			bitcoin.address.toOutputScript(address, regtest),
			values
		);
		const utxos: IUtxo[] = prevTxs.map((prevTx, i) => ({
			address,
			index: 0,
			path: PATH,
			scriptHash: getScriptHash({ address, network }),
			height: 100,
			tx_hash: prevTx.getId(),
			tx_pos: 0,
			value: values[i],
			publicKey: node.value.publicKey.toString('hex')
		}));
		wallet.data.utxos = utxos;
		const electrum = wallet.electrum as unknown as {
			getTransactions: (args: {
				txHashes: { tx_hash: string }[];
			}) => Promise<unknown>;
		};
		electrum.getTransactions = async ({ txHashes }): Promise<unknown> =>
			ok({
				data: txHashes.map(({ tx_hash }) => ({
					result: {
						hex: prevTxs.find((tx) => tx.getId() === tx_hash)?.toHex()
					}
				}))
			});
		return utxos;
	};

	before(async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			name: 'stagedfeeshortfall'
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// Populates the change address setupTransaction needs; the Electrum sync
		// fails harmlessly offline.
		await wallet.refreshWallet({});
	});

	beforeEach(async () => {
		await wallet.resetSendTransaction();
	});

	after(async () => {
		await wallet?.stop();
	});

	it('refuses to sign when addOutput leaves less than the staged fee', async () => {
		await fund([10_000]);
		const setup = await wallet.transaction.setupTransaction({});
		if (setup.isErr()) throw setup.error;
		const added = await wallet.transaction.addOutput({
			address: RECIPIENT,
			value: 9_990,
			index: 0
		});
		if (added.isErr()) throw added.error;
		const stagedFee = wallet.transaction.data.fee;
		expect(stagedFee).to.be.greaterThan(10);

		const res = await wallet.transaction.createTransaction();
		expect(res.isErr(), 'the build is refused').to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.contain(
			`plus the staged fee of ${stagedFee} sats`
		);
	});

	it('refuses to build the unsigned PSBT for the same staging', async () => {
		await fund([10_000]);
		const setup = await wallet.transaction.setupTransaction({});
		if (setup.isErr()) throw setup.error;
		const added = await wallet.transaction.addOutput({
			address: RECIPIENT,
			value: 9_990,
			index: 0
		});
		if (added.isErr()) throw added.error;

		const res = await wallet.transaction.createUnsignedPsbt();
		expect(res.isErr(), 'the PSBT is refused').to.equal(true);
	});

	it('refuses to sign after removeTxInput takes away the fee', async () => {
		const [first, second] = await fund([10_000, 10_000]);
		const setup = await wallet.transaction.setupTransaction({
			utxos: [first, second]
		});
		if (setup.isErr()) throw setup.error;
		const added = await wallet.transaction.addOutput({
			address: RECIPIENT,
			value: 9_900,
			index: 0
		});
		if (added.isErr()) throw added.error;
		const fee = wallet.transaction.updateFee({ satsPerByte: 2 });
		if (fee.isErr()) throw fee.error;
		const removed = wallet.removeTxInput({ input: second });
		if (removed.isErr()) throw removed.error;

		const res = await wallet.transaction.createTransaction();
		expect(res.isErr(), 'the build is refused').to.equal(true);
	});

	it('still pays exactly the staged fee when the inputs cover it', async () => {
		await fund([10_000]);
		const setup = await wallet.transaction.setupTransaction({});
		if (setup.isErr()) throw setup.error;
		const added = await wallet.transaction.addOutput({
			address: RECIPIENT,
			value: 5_000,
			index: 0
		});
		if (added.isErr()) throw added.error;

		const res = await wallet.transaction.createTransaction();
		if (res.isErr()) throw res.error;
		const tx = bitcoin.Transaction.fromHex(res.value.hex);
		const outputs = tx.outs.reduce((sum, out) => sum + out.value, 0);
		expect(10_000 - outputs).to.equal(wallet.transaction.data.fee);
	});
});
