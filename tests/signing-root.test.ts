/**
 * Signing uses the root key the wallet derived when it was constructed
 * (#1598). Fully OFFLINE: wallets point at an unreachable Electrum port and
 * UTXOs are fabricated for the wallet's own derived addresses.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';
import * as bip39 from 'bip39';
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
import { bip32 } from '../src/utils/ecc-apis';
import { ecc } from '../src/utils/ecc';

bitcoin.initEccLib(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const regtest = bitcoin.networks.regtest;
const network = EAvailableNetworks.regtest;

// Unreachable on purpose: these tests must work offline.
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
	p2wpkh: 84,
	p2tr: 86
};

const createWallet = async (addressType: EAddressType): Promise<Wallet> => {
	const res = await Wallet.create({
		mnemonic: MNEMONIC,
		network,
		addressType,
		electrumOptions
	});
	if (res.isErr()) throw res.error;
	// The failed (offline) refresh still generates the index-0 addresses,
	// including the change address a send needs.
	await res.value.refreshWallet({});
	return res.value;
};

/** Fabricates a UTXO paying the wallet's receive address at `index`. */
const addUtxo = async (
	wallet: Wallet,
	addressType: EAddressType,
	index: number,
	value: number
): Promise<IUtxo> => {
	const address = await wallet.getAddress({
		index: String(index),
		addressType,
		changeAddress: false
	});
	const path = `m/${PURPOSE[addressType]}'/1'/0'/0/${index}`;
	const node = wallet.derivePublicNode(path);
	if (node.isErr()) throw node.error;
	const utxo: IUtxo = {
		address,
		index,
		path,
		scriptHash: getScriptHash({ address, network }),
		height: 100,
		tx_hash: Buffer.from(
			bitcoin.crypto.sha256(Buffer.from(`utxo-${addressType}-${index}`))
		).toString('hex'),
		tx_pos: 0,
		value,
		publicKey: node.value.publicKey.toString('hex')
	};
	wallet.data.utxos.push(utxo);
	wallet.data.balance += value;
	return utxo;
};

// 100k needs all three coins.
const sendAll = async (wallet: Wallet): Promise<string> => {
	const res = await wallet.send({
		address: RECIPIENT,
		amount: 100000,
		satsPerByte: 2,
		broadcast: false,
		shuffleOutputs: false
	});
	if (res.isErr()) throw res.error;
	return res.value;
};

describe('Signing root (#1598)', function () {
	this.timeout(60000);

	for (const addressType of [EAddressType.p2wpkh, EAddressType.p2tr]) {
		describe(addressType, () => {
			let wallet: Wallet;
			let utxos: IUtxo[];

			before(async () => {
				wallet = await createWallet(addressType);
				utxos = [
					await addUtxo(wallet, addressType, 0, 40000),
					await addUtxo(wallet, addressType, 1, 35000),
					await addUtxo(wallet, addressType, 2, 30000)
				];
			});

			afterEach(async () => {
				sinon.restore();
				await wallet.resetSendTransaction();
			});

			after(async () => {
				await wallet?.stop();
			});

			it('send and buildPsbt never re-derive the seed', async () => {
				const seedAsync = sinon.spy(bip39, 'mnemonicToSeed');
				const seedSync = sinon.spy(bip39, 'mnemonicToSeedSync');
				await sendAll(wallet);
				const built = await wallet.buildPsbt({
					address: RECIPIENT,
					amount: 100000,
					satsPerByte: 2
				});
				if (built.isErr()) throw built.error;
				expect(seedAsync.callCount).to.equal(0);
				expect(seedSync.callCount).to.equal(0);
			});

			it("signs the same bytes as the mnemonic's own root", async () => {
				const signed = await sendAll(wallet);
				await wallet.resetSendTransaction();
				sinon
					.stub(wallet, 'getBip32Interface')
					.resolves(
						ok(bip32.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC), regtest))
					);
				expect(await sendAll(wallet)).to.equal(signed);
			});

			it('signs every input', async () => {
				const tx = bitcoin.Transaction.fromHex(await sendAll(wallet));
				expect(tx.ins).to.have.length(utxos.length);
				const prevouts = tx.ins.map((vin) => {
					const txid = Buffer.from(vin.hash).reverse().toString('hex');
					const utxo = utxos.find(
						(u) => u.tx_hash === txid && u.tx_pos === vin.index
					);
					if (!utxo) throw new Error(`Unknown input ${txid}:${vin.index}`);
					return utxo;
				});
				const scripts = prevouts.map((u) =>
					bitcoin.address.toOutputScript(u.address, regtest)
				);
				const values = prevouts.map((u) => u.value);
				tx.ins.forEach((vin, i) => {
					if (addressType === EAddressType.p2tr) {
						// Key-path spend, SIGHASH_DEFAULT: one 64-byte signature by
						// the output key.
						expect(vin.witness).to.have.length(1);
						const hash = tx.hashForWitnessV1(
							i,
							scripts,
							values,
							bitcoin.Transaction.SIGHASH_DEFAULT
						);
						expect(
							ecc.verifySchnorr(hash, scripts[i].subarray(2), vin.witness[0])
						).to.equal(true);
					} else {
						expect(vin.witness).to.have.length(2);
						const pubkey = vin.witness[1];
						const { signature, hashType } = bitcoin.script.signature.decode(
							vin.witness[0]
						);
						const scriptCode = bitcoin.payments.p2pkh({ pubkey }).output!;
						const hash = tx.hashForWitnessV0(
							i,
							scriptCode,
							values[i],
							hashType
						);
						expect(ecc.verify(hash, pubkey, signature)).to.equal(true);
						expect(
							bitcoin.payments.p2wpkh({ pubkey, network: regtest }).output
						).to.deep.equal(scripts[i]);
					}
				});
			});
		});
	}
});
