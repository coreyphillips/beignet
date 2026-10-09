/**
 * Issue #1432: the PSBT builder dropped change below a flat 546 sats, which is
 * only P2PKH's dust threshold. Relayable P2WPKH change of 294 to 545 sats went
 * to the miner as fee. Change is now kept at its own script's threshold.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum server, the UTXO
 * is fabricated and the previous-transaction fetch is stubbed.
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
import { getDefaultSendTransaction } from '../src/shapes';

bitcoin.initEccLib(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const regtest = bitcoin.networks.regtest;
const network = EAvailableNetworks.regtest;
const PATH = "m/84'/1'/0'/0/0";
const INPUT_VALUE = 10_000;
const FEE = 200;
const P2WPKH_DUST = 294;

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

describe('Relayable segwit change (#1432)', function () {
	this.timeout(120000);

	let wallet: Wallet;
	let input: IUtxo;
	let changeAddress: string;

	before(async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			name: 'relayablechange'
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// Populates the change address; the Electrum sync fails harmlessly
		// offline.
		await wallet.refreshWallet({});
		changeAddress = wallet.data.changeAddressIndex[EAddressType.p2wpkh].address;
		expect(changeAddress).to.match(/^bcrt1q/);

		const address = await wallet.getAddress({
			index: '0',
			addressType: EAddressType.p2wpkh
		});
		const node = wallet.derivePublicNode(PATH);
		if (node.isErr()) throw node.error;
		const prevTx = new bitcoin.Transaction();
		prevTx.addInput(Buffer.alloc(32, 1), 0);
		prevTx.addOutput(
			bitcoin.address.toOutputScript(address, regtest),
			INPUT_VALUE
		);
		input = {
			address,
			index: 0,
			path: PATH,
			scriptHash: getScriptHash({ address, network }),
			height: 100,
			tx_hash: prevTx.getId(),
			tx_pos: 0,
			value: INPUT_VALUE,
			publicKey: node.value.publicKey.toString('hex')
		};
		const electrum = wallet.electrum as unknown as {
			getTransactions: () => Promise<unknown>;
		};
		electrum.getTransactions = async (): Promise<unknown> =>
			ok({ data: [{ result: { hex: prevTx.toHex() } }] });
	});

	after(async () => {
		await wallet?.stop();
	});

	/** Builds the PSBT for a payment that leaves `change` after FEE. */
	const build = async (
		change: number,
		withChangeAddress: boolean
	): Promise<{ address?: string; value: number }[]> => {
		const res = await wallet.transaction.createPsbtFromTransactionData({
			transactionData: {
				...getDefaultSendTransaction(),
				inputs: [input],
				outputs: [
					{ address: RECIPIENT, value: INPUT_VALUE - FEE - change, index: 0 }
				],
				fee: FEE,
				satsPerByte: 1,
				changeAddress: withChangeAddress ? changeAddress : ''
			},
			shuffleTargets: false
		});
		if (res.isErr()) throw res.error;
		return res.value.txOutputs.map(({ address, value }) => ({
			address,
			value
		}));
	};

	[true, false].forEach((withChangeAddress) => {
		const label = withChangeAddress
			? 'with a change address'
			: 'without a change address';

		it(`keeps 400 sats of P2WPKH change ${label}`, async () => {
			const outputs = await build(400, withChangeAddress);
			expect(outputs).to.deep.equal([
				{ address: RECIPIENT, value: INPUT_VALUE - FEE - 400 },
				{ address: changeAddress, value: 400 }
			]);
		});

		it(`keeps change at the P2WPKH threshold and drops it below ${label}`, async () => {
			const kept = await build(P2WPKH_DUST, withChangeAddress);
			expect(kept.map((o) => o.value)).to.deep.equal([
				INPUT_VALUE - FEE - P2WPKH_DUST,
				P2WPKH_DUST
			]);

			const dropped = await build(P2WPKH_DUST - 1, withChangeAddress);
			expect(dropped).to.deep.equal([
				{ address: RECIPIENT, value: INPUT_VALUE - FEE - (P2WPKH_DUST - 1) }
			]);
		});
	});
});
