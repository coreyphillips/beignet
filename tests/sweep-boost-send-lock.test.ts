/**
 * Regression tests for issue #1597: sweepPrivateKey and the boost flow staged
 * on the shared send transaction without taking the send lock, so either one
 * overlapping a send reset or read the other's inputs, outputs and fee.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port, UTXOs are
 * injected into wallet data, and the lookups and broadcast are stubbed.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';
import ecc from '@bitcoinerlab/secp256k1';
import {
	address as bitcoinAddress,
	networks,
	payments,
	Transaction as BitcoinTransaction
} from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';

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
	err,
	ok
} from '../src';
import { ITxHash, TTxDetails } from '../src/types/wallet';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const ECPair = ECPairFactory(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

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

const network = networks.regtest;
const RECIPIENT = bitcoinAddress.toBech32(Buffer.alloc(20, 3), 0, 'bcrt');
const SWEEP_TO = bitcoinAddress.toBech32(Buffer.alloc(20, 4), 0, 'bcrt');
const BOOST_PAYEE = bitcoinAddress.toBech32(Buffer.alloc(20, 5), 0, 'bcrt');

const WALLET_TXID = '11'.repeat(32);
const KEY_TXID = '22'.repeat(32);
const FUNDING_TXID = 'aa'.repeat(32);
const BOOSTED_TXID = 'bb'.repeat(32);

const keyPair = ECPair.fromPrivateKey(Buffer.alloc(32, 0x5a), { network });
const KEY_ADDRESS = payments.p2wpkh({ pubkey: keyPair.publicKey, network })
	.address as string;

/**
 * An in-memory TStorage that answers each write on a later tick, as a real
 * adapter does. A write that settles at once leaves no gap between staging
 * steps for an overlapping call to land in.
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

describe('Sweeps and boosts queue behind sends (#1597)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	/** Value of every coin a transaction here can spend, by outpoint. */
	const coinValues = new Map<string, number>([
		[`${WALLET_TXID}:0`, 60_000],
		[`${KEY_TXID}:0`, 10_000],
		[`${FUNDING_TXID}:0`, 100_000]
	]);

	/** What a signed transaction spends and pays, and the fee that leaves. */
	const summary = (
		hex: string
	): { inputs: string[]; outputs: string[]; fee: number } => {
		const tx = BitcoinTransaction.fromHex(hex);
		const inputs = tx.ins.map(
			(input) =>
				`${Buffer.from(input.hash).reverse().toString('hex')}:${input.index}`
		);
		const inputTotal = inputs.reduce((sum, outpoint) => {
			const value = coinValues.get(outpoint);
			if (value === undefined) throw new Error(`Unknown input ${outpoint}.`);
			return sum + value;
		}, 0);
		return {
			inputs: inputs.sort(),
			outputs: tx.outs
				.map(
					(out) =>
						`${bitcoinAddress.fromOutputScript(out.script, network)}:${
							out.value
						}`
				)
				.sort(),
			fee: inputTotal - tx.outs.reduce((sum, out) => sum + out.value, 0)
		};
	};

	const send = async (): Promise<string> => {
		const res = await wallet.send({
			address: RECIPIENT,
			amount: 15_000,
			satsPerByte: 2,
			broadcast: false,
			shuffleOutputs: false
		});
		if (res.isErr()) throw res.error;
		return res.value;
	};

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'sendlock',
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
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		wallet.data.utxos.push({
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height: 1,
			tx_hash: WALLET_TXID,
			tx_pos: 0,
			value: 60_000,
			publicKey: source.publicKey
		});
		wallet.data.balance += 60_000;
		sinon
			.stub(electrumHelpers, 'broadcastTransaction')
			.resolves({ error: false, data: 'ff'.repeat(32) });
		sinon
			.stub(electrumHelpers, 'subscribeAddress')
			.resolves({ error: false, data: '' });
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	/** Starts the send and the other call without awaiting either. */
	const overlap = async (
		other: () => Promise<string>,
		otherFirst: boolean
	): Promise<[string, string]> => {
		if (!otherFirst) return Promise.all([send(), other()]);
		const [otherHex, sendHex] = await Promise.all([other(), send()]);
		return [sendHex, otherHex];
	};

	for (const otherFirst of [false, true]) {
		const order = otherFirst ? 'started first' : 'started second';

		it(`builds a send and an overlapping sweep ${order} as each would alone`, async () => {
			const keyCoin: IUtxo = {
				address: KEY_ADDRESS,
				index: 0,
				path: '',
				scriptHash: '00'.repeat(32),
				height: 1,
				tx_hash: KEY_TXID,
				tx_pos: 0,
				value: 10_000,
				publicKey: keyPair.publicKey.toString('hex')
			};
			sinon
				.stub(wallet.electrum, 'listUnspentAddressScriptHashes')
				.resolves(ok({ utxos: [keyCoin], balance: keyCoin.value }));
			// Segwit inputs build from witnessUtxo when the previous transaction
			// cannot be fetched.
			sinon.stub(wallet.electrum, 'getTransactions').resolves(err('offline'));
			const sweep = async (): Promise<string> => {
				const res = await wallet.sweepPrivateKey({
					privateKey: keyPair.toWIF(),
					toAddress: SWEEP_TO,
					satsPerByte: 2,
					broadcast: false
				});
				if (res.isErr()) throw res.error;
				return res.value.hex;
			};

			const sendAlone = summary(await send());
			const sweepAlone = summary(await sweep());
			const [sendHex, sweepHex] = await overlap(sweep, otherFirst);

			expect(sendAlone.inputs).to.deep.equal([`${WALLET_TXID}:0`]);
			expect(sweepAlone.inputs).to.deep.equal([`${KEY_TXID}:0`]);
			expect(summary(sendHex)).to.deep.equal(sendAlone);
			expect(summary(sweepHex)).to.deep.equal(sweepAlone);
		});

		it(`builds a send and an overlapping RBF boost ${order} as each would alone`, async () => {
			const receiveAddress =
				wallet.data.addressIndex[EAddressType.p2wpkh].address;
			const changeAddress =
				wallet.data.changeAddressIndex[EAddressType.p2wpkh].address;
			// The boosted transaction spends a confirmed 100k coin of ours, pays 40k
			// away and 50k back to change. Any other lookup has no details.
			const lookups: Record<string, Partial<TTxDetails>> = {
				[BOOSTED_TXID]: {
					vin: [{ txid: FUNDING_TXID, vout: 0 }] as TTxDetails['vin'],
					vout: [
						{ value: 0.0004, n: 0, scriptPubKey: { address: BOOST_PAYEE } },
						{ value: 0.0005, n: 1, scriptPubKey: { address: changeAddress } }
					] as unknown as TTxDetails['vout']
				},
				[FUNDING_TXID]: {
					confirmations: 10,
					vout: [
						{ value: 0.001, n: 0, scriptPubKey: { address: receiveAddress } }
					] as unknown as TTxDetails['vout']
				}
			};
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
							result: { txid: tx_hash, ...lookups[tx_hash] } as TTxDetails
						}))
					})
				);
			const boost = async (): Promise<string> => {
				const res = await wallet.boost({
					txid: BOOSTED_TXID,
					type: EBoostType.rbf
				});
				if (res.isErr()) throw res.error;
				expect(res.value.fee).to.equal(summary(res.value.hex).fee);
				return res.value.hex;
			};

			const sendAlone = summary(await send());
			const boostAlone = summary(await boost());
			const [sendHex, boostHex] = await overlap(boost, otherFirst);

			expect(sendAlone.inputs).to.deep.equal([`${WALLET_TXID}:0`]);
			expect(boostAlone.inputs).to.deep.equal([`${FUNDING_TXID}:0`]);
			expect(boostAlone.outputs).to.include(`${BOOST_PAYEE}:40000`);
			expect(summary(sendHex)).to.deep.equal(sendAlone);
			expect(summary(boostHex)).to.deep.equal(boostAlone);
			expect(wallet.getBoostedTransactions()[BOOSTED_TXID]).to.deep.include({
				childTransaction: BitcoinTransaction.fromHex(boostHex).getId(),
				type: EBoostType.rbf,
				fee: boostAlone.fee
			});
		});
	}
});
