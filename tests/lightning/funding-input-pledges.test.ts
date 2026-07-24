/**
 * Funding input pledges.
 *
 * Concurrent fundings draw coins from one wallet through two uncoordinated
 * paths (wallet.send inside buildFundingTransaction, and direct UTXO
 * selection in gatherWalletInputs). Every coin a funding selects must be
 * pledged (frozen) until its spend is observed or a TTL passes, so a second
 * funding can never pick the same coin and RBF-replace the first.
 */
import { expect } from 'chai';
import * as crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { WalletFundingProvider } from '../../src/lightning/wallet/wallet-funding-provider';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

function ok<T>(value: T) {
	return { isErr: () => false, value };
}

interface IFrozenEntry {
	tx_hash: string;
	tx_pos: number;
	freezeTag?: string;
	frozenAt?: number;
}

/**
 * A mock wallet with N P2WPKH coins and real freeze bookkeeping: frozen
 * entries are tracked with their tag and timestamp exactly like the real
 * wallet's blacklist, and listUtxos does NOT filter them (matching the real
 * wallet, where exclusion happens at selection time).
 */
function makeWallet(values: number[]) {
	const key = ECPair.makeRandom({ network });
	const pubkey = Buffer.from(key.publicKey);
	const payment = bitcoin.payments.p2wpkh({ pubkey, network });

	const fundingTxs = values.map((v) => {
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(crypto.randomBytes(32), 0);
		tx.addOutput(payment.output!, v);
		return tx;
	});
	const utxos = fundingTxs.map((tx, i) => ({
		address: payment.address!,
		path: "m/84'/0/0",
		tx_hash: tx.getId(),
		tx_pos: 0,
		value: values[i],
		height: 100 + i,
		publicKey: pubkey.toString('hex')
	}));
	const hexByTxid = new Map(fundingTxs.map((tx) => [tx.getId(), tx.toHex()]));

	const frozen = new Map<string, IFrozenEntry>();
	const unfrozenLog: string[] = [];

	const wallet = {
		network: 'regtest',
		send: async () => ok(''),
		listUtxos: () => utxos,
		getPrivateKey: () => key.toWIF(),
		getChangeAddress: async () => ok({ address: payment.address! }),
		isUtxoFrozen: (txid: string, index: number) =>
			frozen.has(`${txid}:${index}`),
		freezeUtxo: async (p: { txid: string; index: number; tag?: string }) => {
			frozen.set(`${p.txid}:${p.index}`, {
				tx_hash: p.txid,
				tx_pos: p.index,
				...(p.tag !== undefined
					? { freezeTag: p.tag, frozenAt: Date.now() }
					: {})
			});
			return ok('frozen');
		},
		unfreezeUtxo: async (p: { txid: string; index: number }) => {
			frozen.delete(`${p.txid}:${p.index}`);
			unfrozenLog.push(`${p.txid}:${p.index}`);
			return ok('unfrozen');
		},
		listFrozenUtxos: () => [...frozen.values()],
		electrum: {
			getTransactions: async (params: {
				txHashes: Array<{ tx_hash: string }>;
			}) =>
				ok({
					data: params.txHashes.map((t) => ({
						data: { tx_hash: t.tx_hash },
						result: { txid: t.tx_hash, hex: hexByTxid.get(t.tx_hash) }
					}))
				})
		}
	};
	return { wallet, utxos, frozen, unfrozenLog, payment };
}

const outpoints = (
	inputs: Array<{ prevTx: Buffer; prevOutputIndex: number }>
) =>
	inputs.map((i) => {
		const tx = bitcoin.Transaction.fromBuffer(i.prevTx);
		return `${tx.getId()}:${i.prevOutputIndex}`;
	});

describe('Funding input pledges', function () {
	it('a coin selected by one funding is never selected by a concurrent one', async function () {
		const { wallet } = makeWallet([100_000, 100_000, 100_000]);
		const provider = new WalletFundingProvider(wallet as never);

		const first = await provider.selectSpliceInputs!(80_000n, 1000);
		const second = await provider.selectSpliceInputs!(80_000n, 1000);

		const a = outpoints(first.inputs);
		const b = outpoints(second.inputs);
		expect(a.length).to.be.greaterThan(0);
		expect(b.length).to.be.greaterThan(0);
		for (const op of b) {
			expect(a, 'no outpoint reused across concurrent fundings').to.not.include(
				op
			);
		}
	});

	it('truly concurrent selections (Promise.all) never share a coin', async function () {
		// Force interleaving: the prev-tx fetch yields to the event loop, so
		// without serialization both selections would pick the same coins
		// before either pledge lands.
		const { wallet } = makeWallet([100_000, 100_000, 100_000]);
		const slowGet = wallet.electrum.getTransactions;
		wallet.electrum.getTransactions = async (params) => {
			await new Promise((resolve) => setTimeout(resolve, 20));
			return slowGet(params);
		};
		const provider = new WalletFundingProvider(wallet as never);

		const [first, second] = await Promise.all([
			provider.selectSpliceInputs!(80_000n, 1000),
			provider.selectSpliceInputs!(80_000n, 1000)
		]);

		const a = outpoints(first.inputs);
		const b = outpoints(second.inputs);
		expect(a.length).to.be.greaterThan(0);
		expect(b.length).to.be.greaterThan(0);
		for (const op of b) {
			expect(a, 'no outpoint shared by interleaved fundings').to.not.include(
				op
			);
		}
	});

	it('exhausting the wallet with pledges fails the next funding instead of double-spending', async function () {
		const { wallet } = makeWallet([100_000, 100_000]);
		const provider = new WalletFundingProvider(wallet as never);

		await provider.selectSpliceInputs!(80_000n, 1000);
		await provider.selectSpliceInputs!(80_000n, 1000);
		let error = '';
		try {
			await provider.selectSpliceInputs!(80_000n, 1000);
		} catch (e) {
			error = (e as Error).message;
		}
		expect(error).to.contain('insufficient wallet funds');
	});

	it('buildFundingTransaction pledges the inputs of the built tx', async function () {
		const { wallet, utxos, payment } = makeWallet([200_000, 200_000]);

		// The "wallet" builds a funding tx spending coin 0 exactly.
		const fundingDest = payment.address!;
		const spend = new bitcoin.Transaction();
		spend.version = 2;
		spend.addInput(
			Buffer.from(utxos[0].tx_hash, 'hex').reverse(),
			utxos[0].tx_pos
		);
		spend.addOutput(payment.output!, 150_000);
		wallet.send = async () => ok(spend.toHex());

		const provider = new WalletFundingProvider(wallet as never);
		await provider.buildFundingTransaction(fundingDest, 150_000n);

		// Coin 0 is pledged now: a follow-up selection must draw on coin 1 only.
		const next = await provider.selectSpliceInputs!(150_000n, 1000);
		const ops = outpoints(next.inputs);
		expect(ops).to.deep.equal([`${utxos[1].tx_hash}:${utxos[1].tx_pos}`]);
	});

	it('adopts stale tagged pledges after a restart and prunes them by TTL', async function () {
		const { wallet, utxos, frozen, unfrozenLog } = makeWallet([
			100_000, 100_000
		]);
		// A pledge freeze from a previous run, 11 minutes old (TTL is 10).
		frozen.set(`${utxos[0].tx_hash}:0`, {
			tx_hash: utxos[0].tx_hash,
			tx_pos: 0,
			freezeTag: 'funding-pledge',
			frozenAt: Date.now() - 11 * 60_000
		});

		const provider = new WalletFundingProvider(wallet as never);
		const { inputs } = await provider.selectSpliceInputs!(150_000n, 1000);

		// The stale pledge was adopted, expired, unfrozen, and the coin is
		// selectable again in the very same call.
		expect(unfrozenLog).to.include(`${utxos[0].tx_hash}:0`);
		expect(outpoints(inputs)).to.include(`${utxos[0].tx_hash}:0`);
	});

	it('never adopts or unfreezes a user freeze (no tag)', async function () {
		const { wallet, utxos, unfrozenLog } = makeWallet([100_000, 100_000]);
		// User froze coin 0 with no tag.
		await wallet.freezeUtxo({ txid: utxos[0].tx_hash, index: 0 });

		const provider = new WalletFundingProvider(wallet as never);
		const { inputs } = await provider.selectSpliceInputs!(80_000n, 1000);

		expect(unfrozenLog).to.deep.equal([]);
		expect(outpoints(inputs)).to.not.include(`${utxos[0].tx_hash}:0`);
	});
});
