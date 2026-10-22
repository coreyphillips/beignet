/**
 * Issue #1659: building a PSBT fetched each input's previous transaction with
 * a lookup of its own, so N inputs cost N sequential round trips, and inputs
 * spending the same parent fetched it again. getRbfData did the same for the
 * transaction it rebuilds. Both now fetch every distinct parent in one
 * batched lookup, and the bytes built from them are unchanged.
 *
 * Fully OFFLINE: the wallet is created with remainOffline, UTXOs are
 * fabricated and the previous-transaction fetch is a counting fake.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import { createHash } from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

import { EAddressType, EAvailableNetworks, IUtxo, ok, Wallet } from '../src';
import { ITxHash } from '../src/types/wallet';

bitcoin.initEccLib(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const regtest = bitcoin.networks.regtest;
const network = EAvailableNetworks.regtest;
const PARENTS = 3;
const COINS_PER_PARENT = 10;
const SEND_AMOUNT = 200_000;
const SATS_PER_BYTE = 2;

// Digests of what master built from the same staging, before the fetch was
// batched.
const P2PKH_SIGNED_HEX_SHA256 =
	'149530a01e4613c7eddbdc6d9dd1a34bffb622d272c9e2d771191fcd8cf2ef4a';
const P2WPKH_UNSIGNED_PSBT_SHA256 =
	'9120151897537c9a49df6895915ecfab56225862289c4bb2e4c3376a7c48beae';

const electrumOptions = { net, tls };

const sha256 = (data: string | Buffer): string =>
	createHash('sha256').update(data).digest('hex');

describe('Previous transactions fetched in one batch (#1659)', function () {
	this.timeout(120000);

	const wallets: Wallet[] = [];

	after(async () => {
		await Promise.all(wallets.map((w) => w?.stop()));
	});

	const createWallet = async (addressType: EAddressType): Promise<Wallet> => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			addressType,
			electrumOptions,
			remainOffline: true,
			name: `prevtxbatch${addressType}`
		});
		if (res.isErr()) throw res.error;
		wallets.push(res.value);
		// Populates the index-0 addresses, including the change address
		// setupTransaction needs; the Electrum sync fails harmlessly offline.
		await res.value.refreshWallet({});
		return res.value;
	};

	/**
	 * Three parents, each paying ten coins to the wallet's index-0 address.
	 * getTransactions answers any of them, plus the verbose results `extra`
	 * builds from the coins, and records every request it receives.
	 */
	const fund = async (
		wallet: Wallet,
		addressType: EAddressType,
		extra: (utxos: IUtxo[]) => Record<string, unknown> = () => ({})
	): Promise<{
		parents: bitcoin.Transaction[];
		utxos: IUtxo[];
		requests: string[][];
	}> => {
		const source = wallet.data.addressIndex[addressType];
		const script = bitcoin.address.toOutputScript(source.address, regtest);
		const parents = Array.from({ length: PARENTS }, (_, p) => {
			const parent = new bitcoin.Transaction();
			parent.addInput(Buffer.alloc(32, p + 1), 0);
			for (let i = 0; i < COINS_PER_PARENT; i++) {
				parent.addOutput(script, 10_000 + p * 100 + i);
			}
			return parent;
		});
		const utxos: IUtxo[] = parents.flatMap((parent) =>
			parent.outs.map((out, txPos) => ({
				address: source.address,
				index: source.index,
				path: source.path,
				scriptHash: source.scriptHash,
				height: 100,
				tx_hash: parent.getId(),
				tx_pos: txPos,
				value: out.value,
				publicKey: source.publicKey
			}))
		);
		const funded = await wallet.updateData({ utxos });
		if (funded.isErr()) throw funded.error;

		const verbose = (parent: bitcoin.Transaction): Record<string, unknown> => ({
			txid: parent.getId(),
			hex: parent.toHex(),
			confirmations: 10,
			vout: parent.outs.map((out, n) => ({
				value: out.value / 1e8,
				n,
				scriptPubKey: { address: source.address }
			}))
		});
		const results: Record<string, unknown> = extra(utxos);
		for (const parent of parents) results[parent.getId()] = verbose(parent);

		const requests: string[][] = [];
		const electrum = wallet.electrum as unknown as {
			getTransactions: (args: { txHashes: ITxHash[] }) => Promise<unknown>;
		};
		electrum.getTransactions = async ({ txHashes }): Promise<unknown> => {
			requests.push(txHashes.map(({ tx_hash }) => tx_hash));
			return ok({
				error: false,
				id: 0,
				method: 'getTransactions',
				network: 'regtest',
				data: txHashes.map(({ tx_hash }) => ({
					id: 0,
					jsonrpc: '2.0',
					param: tx_hash,
					data: { tx_hash },
					result: results[tx_hash]
				}))
			});
		};
		return { parents, utxos, requests };
	};

	/** Stages every coin in one payment to RECIPIENT. */
	const stage = async (wallet: Wallet, utxos: IUtxo[]): Promise<void> => {
		await wallet.resetSendTransaction();
		const setup = await wallet.transaction.setupTransaction({
			utxos,
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
	};

	it('signs 30 legacy inputs from 3 parents after one lookup of the 3', async () => {
		const wallet = await createWallet(EAddressType.p2pkh);
		const { parents, utxos, requests } = await fund(wallet, EAddressType.p2pkh);
		await stage(wallet, utxos);

		const res = await wallet.transaction.createTransaction({
			shuffleOutputs: false
		});
		if (res.isErr()) throw res.error;

		expect(requests).to.have.length(1);
		expect(requests[0]).to.have.members(parents.map((p) => p.getId()));
		const tx = bitcoin.Transaction.fromHex(res.value.hex);
		expect(tx.ins).to.have.length(PARENTS * COINS_PER_PARENT);
		expect(sha256(res.value.hex)).to.equal(P2PKH_SIGNED_HEX_SHA256);
	});

	it('attaches every segwit nonWitnessUtxo from one lookup of the 3', async () => {
		const wallet = await createWallet(EAddressType.p2wpkh);
		const { parents, utxos, requests } = await fund(
			wallet,
			EAddressType.p2wpkh
		);
		await stage(wallet, utxos);

		const res = await wallet.transaction.createUnsignedPsbt({
			shuffleOutputs: false
		});
		if (res.isErr()) throw res.error;

		expect(requests).to.have.length(1);
		expect(requests[0]).to.have.members(parents.map((p) => p.getId()));
		const byTxid = new Map(parents.map((p) => [p.getId(), p.toHex()]));
		res.value.data.inputs.forEach((input, i) => {
			expect(input.nonWitnessUtxo?.toString('hex')).to.equal(
				byTxid.get(utxos[i].tx_hash)
			);
		});
		expect(sha256(res.value.toBase64())).to.equal(P2WPKH_UNSIGNED_PSBT_SHA256);
	});

	it('reads the inputs of a transaction to replace from one lookup of the 3', async () => {
		const wallet = await createWallet(EAddressType.p2wpkh);
		const replacedTxid = 'bb'.repeat(32);
		const change = wallet.data.changeAddressIndex[EAddressType.p2wpkh].address;
		const { parents, utxos, requests } = await fund(
			wallet,
			EAddressType.p2wpkh,
			(coins) => ({
				// Spends all thirty coins.
				[replacedTxid]: {
					txid: replacedTxid,
					confirmations: 0,
					vin: coins.map(({ tx_hash, tx_pos }) => ({
						txid: tx_hash,
						vout: tx_pos
					})),
					vout: [
						{ value: 0.002, n: 0, scriptPubKey: { address: RECIPIENT } },
						{ value: 0.001, n: 1, scriptPubKey: { address: change } }
					]
				}
			})
		);

		const res = await wallet.getRbfData({ txHash: { tx_hash: replacedTxid } });
		if (res.isErr()) throw res.error;

		expect(requests).to.have.length(2);
		expect(requests[0]).to.deep.equal([replacedTxid]);
		expect(requests[1]).to.have.members(parents.map((p) => p.getId()));
		expect(
			res.value.inputs.map(({ tx_hash, tx_pos, value }) => ({
				tx_hash,
				tx_pos,
				value
			}))
		).to.deep.equal(
			utxos.map(({ tx_hash, tx_pos, value }) => ({ tx_hash, tx_pos, value }))
		);
	});
});
