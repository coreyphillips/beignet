/**
 * Issue #1010: fee and change are computed from the UTXO value the Electrum
 * server reports, while the signature on a segwit v0 input commits to the
 * value in the attached previous transaction. A server that under-reports a
 * coin got a valid transaction that paid the difference as fee. Inputs are
 * now refused unless the previous transaction agrees with the reported coin.
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
	Result,
	Wallet
} from '../src';

bitcoin.initEccLib(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const regtest = bitcoin.networks.regtest;
const network = EAvailableNetworks.regtest;

const REAL_VALUE = 1_000_000;
const REPORTED_VALUE = 500_000;
const SEND_AMOUNT = 200_000;
const SATS_PER_BYTE = 10;

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

const PURPOSE: Partial<Record<EAddressType, number>> = {
	p2pkh: 44,
	p2sh: 49,
	p2wpkh: 84
};

const createdWallets: Wallet[] = [];

const createWallet = async (addressType: EAddressType): Promise<Wallet> => {
	const res = await Wallet.create({
		mnemonic: MNEMONIC,
		network,
		addressType,
		electrumOptions,
		name: `prevout${addressType}${createdWallets.length}`
	});
	if (res.isErr()) throw res.error;
	createdWallets.push(res.value);
	// Populates the index-0 addresses, including the change address
	// setupTransaction needs; the Electrum sync fails harmlessly offline.
	await res.value.refreshWallet({});
	return res.value;
};

/** A previous transaction paying `value` to `script` at output 0. */
const makePrevTx = (script: Buffer, value: number): bitcoin.Transaction => {
	const prevTx = new bitcoin.Transaction();
	prevTx.addInput(Buffer.alloc(32, 7), 0);
	prevTx.addOutput(script, value);
	return prevTx;
};

/**
 * Funds the wallet with one coin the server reports as `reportedValue`, and
 * makes the previous-transaction fetch return `servedTx`.
 */
const fund = async ({
	wallet,
	addressType,
	txHash,
	reportedValue,
	servedTx
}: {
	wallet: Wallet;
	addressType: EAddressType;
	txHash: string;
	reportedValue: number;
	servedTx: bitcoin.Transaction;
}): Promise<void> => {
	const address = await wallet.getAddress({ index: '0', addressType });
	const path = `m/${PURPOSE[addressType]}'/1'/0'/0/0`;
	const node = wallet.derivePublicNode(path);
	if (node.isErr()) throw node.error;
	const utxo: IUtxo = {
		address,
		index: 0,
		path,
		scriptHash: getScriptHash({ address, network }),
		height: 100,
		tx_hash: txHash,
		tx_pos: 0,
		value: reportedValue,
		publicKey: node.value.publicKey.toString('hex')
	};
	wallet.data.utxos = [utxo];
	const electrum = wallet.electrum as unknown as {
		getTransactions: () => Promise<unknown>;
	};
	electrum.getTransactions = async (): Promise<unknown> =>
		ok({ data: [{ result: { hex: servedTx.toHex() } }] });
};

/** Stages and signs a send the way send() does, without broadcasting it. */
const createSend = async (
	wallet: Wallet
): Promise<Result<{ id: string; hex: string }>> => {
	const setup = await wallet.transaction.setupTransaction({
		satsPerByte: SATS_PER_BYTE
	});
	if (setup.isErr()) throw setup.error;
	const staged = wallet.transaction.updateSendTransaction({
		transaction: {
			outputs: [{ address: RECIPIENT, value: SEND_AMOUNT, index: 0 }]
		}
	});
	if (staged.isErr()) throw staged.error;
	const fee = wallet.transaction.updateFee({ satsPerByte: SATS_PER_BYTE });
	if (fee.isErr()) throw fee.error;
	return await wallet.transaction.createTransaction({});
};

const outputScript = async (
	wallet: Wallet,
	addressType: EAddressType
): Promise<Buffer> => {
	const address = await wallet.getAddress({ index: '0', addressType });
	return bitcoin.address.toOutputScript(address, regtest);
};

describe('Previous transaction checks on wallet inputs (#1010)', function () {
	this.timeout(120000);

	after(async () => {
		await Promise.all(createdWallets.map((w) => w?.stop()));
	});

	for (const addressType of [
		EAddressType.p2wpkh,
		EAddressType.p2sh,
		EAddressType.p2pkh
	]) {
		describe(addressType, () => {
			let wallet: Wallet;

			before(async () => {
				wallet = await createWallet(addressType);
			});

			it('refuses to sign a send from an under-reported coin', async () => {
				const prevTx = makePrevTx(
					await outputScript(wallet, addressType),
					REAL_VALUE
				);
				await fund({
					wallet,
					addressType,
					txHash: prevTx.getId(),
					reportedValue: REPORTED_VALUE,
					servedTx: prevTx
				});
				const res = await createSend(wallet);
				expect(res.isErr(), 'the send is refused').to.equal(true);
				if (res.isOk()) return;
				expect(res.error.message).to.contain(
					`holds ${REAL_VALUE} sats, not the ${REPORTED_VALUE}`
				);
			});

			it('refuses to build a PSBT from an under-reported coin', async () => {
				const prevTx = makePrevTx(
					await outputScript(wallet, addressType),
					REAL_VALUE
				);
				await fund({
					wallet,
					addressType,
					txHash: prevTx.getId(),
					reportedValue: REPORTED_VALUE,
					servedTx: prevTx
				});
				const res = await wallet.buildPsbt({
					address: RECIPIENT,
					amount: SEND_AMOUNT,
					satsPerByte: SATS_PER_BYTE,
					shuffleOutputs: false
				});
				expect(res.isErr(), 'the PSBT is refused').to.equal(true);
				if (res.isOk()) return;
				expect(res.error.message).to.contain(`holds ${REAL_VALUE} sats`);
			});

			it('pays exactly the staged fee when the coin is reported truthfully', async () => {
				const prevTx = makePrevTx(
					await outputScript(wallet, addressType),
					REAL_VALUE
				);
				await fund({
					wallet,
					addressType,
					txHash: prevTx.getId(),
					reportedValue: REAL_VALUE,
					servedTx: prevTx
				});
				const res = await createSend(wallet);
				if (res.isErr()) throw res.error;
				const tx = bitcoin.Transaction.fromHex(res.value.hex);
				const outputs = tx.outs.reduce((sum, out) => sum + out.value, 0);
				expect(REAL_VALUE - outputs).to.equal(wallet.transaction.data.fee);
				expect(wallet.transaction.data.fee).to.be.lessThan(
					SATS_PER_BYTE * tx.virtualSize() * 2
				);
			});
		});
	}

	describe('previous transaction that does not match the input', () => {
		let wallet: Wallet;

		before(async () => {
			wallet = await createWallet(EAddressType.p2wpkh);
		});

		it('refuses a previous transaction with a different txid', async () => {
			const script = await outputScript(wallet, EAddressType.p2wpkh);
			const claimed = makePrevTx(script, REAL_VALUE);
			// Pays the reported value, but is not the transaction the input spends.
			const served = makePrevTx(script, REPORTED_VALUE);
			await fund({
				wallet,
				addressType: EAddressType.p2wpkh,
				txHash: claimed.getId(),
				reportedValue: REPORTED_VALUE,
				servedTx: served
			});
			const res = await createSend(wallet);
			expect(res.isErr()).to.equal(true);
			if (res.isOk()) return;
			expect(res.error.message).to.contain('has a different txid');
		});

		it('refuses an output that does not pay the input address', async () => {
			const foreign = bitcoin.payments.p2wpkh({ hash: Buffer.alloc(20, 1) });
			const prevTx = makePrevTx(foreign.output!, REAL_VALUE);
			await fund({
				wallet,
				addressType: EAddressType.p2wpkh,
				txHash: prevTx.getId(),
				reportedValue: REAL_VALUE,
				servedTx: prevTx
			});
			const res = await createSend(wallet);
			expect(res.isErr()).to.equal(true);
			if (res.isOk()) return;
			expect(res.error.message).to.contain("does not pay this input's address");
		});
	});
});
