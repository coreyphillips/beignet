/**
 * WalletFundingProvider caller-directed UTXO selection (issue #572): the
 * IUtxoSelectionOpts trailing argument on selectDualFundingInputs and
 * selectSpliceInputs.
 *
 * Semantics under test: every named outpoint is contributed (never silently
 * skipped); a named coin the wallet cannot spend fails the selection naming
 * it; named coins short of amount + fee fail as insufficient unless
 * allowTopUp permits completing from the remaining spendable coins; and an
 * unrestricted selection is untouched.
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

function ok<T>(value: T): { isErr: () => boolean; value: T } {
	return { isErr: () => false, value };
}

interface IFrozenEntry {
	tx_hash: string;
	tx_pos: number;
	freezeTag?: string;
	frozenAt?: number;
}

interface IMadeWallet {
	// The provider constructor takes the full wallet type; the stub carries
	// exactly what the selection paths consume.
	wallet: unknown;
	utxos: Array<{ tx_hash: string; tx_pos: number; value: number }>;
	freeze: (txid: string, index: number) => void;
}

/** A mock wallet with N confirmed P2WPKH coins and freeze bookkeeping. */
function makeWallet(values: number[]): IMadeWallet {
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
	const wallet = {
		network: 'regtest',
		send: async () => ok(''),
		listUtxos: () => utxos,
		getPrivateKey: () => key.toWIF(),
		getChangeAddress: async () => ok({ address: payment.address! }),
		isUtxoFrozen: (txid: string, index: number) =>
			frozen.has(`${txid}:${index}`),
		freezeUtxo: async (p: {
			txid: string;
			index: number;
			tag?: string;
		}): Promise<ReturnType<typeof ok<string>>> => {
			frozen.set(`${p.txid}:${p.index}`, {
				tx_hash: p.txid,
				tx_pos: p.index,
				...(p.tag !== undefined
					? { freezeTag: p.tag, frozenAt: Date.now() }
					: {})
			});
			return ok('frozen');
		},
		unfreezeUtxo: async (p: {
			txid: string;
			index: number;
		}): Promise<ReturnType<typeof ok<string>>> => {
			frozen.delete(`${p.txid}:${p.index}`);
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
	return {
		wallet,
		utxos,
		freeze: (txid, index) =>
			frozen.set(`${txid}:${index}`, { tx_hash: txid, tx_pos: index })
	};
}

function selectedOutpoints(
	inputs: Array<{ prevTx: Buffer; prevOutputIndex: number }>
): string[] {
	return inputs.map((i) => {
		const tx = bitcoin.Transaction.fromBuffer(i.prevTx);
		return `${tx.getId()}:${i.prevOutputIndex}`;
	});
}

describe('WalletFundingProvider directed UTXO selection (issue #572)', function () {
	it('selects exactly the named coin even when the greedy order differs', async function () {
		const w = makeWallet([100_000, 50_000, 30_000]);
		const provider = new WalletFundingProvider(w.wallet as never);
		const named = w.utxos[2]; // the smallest; greedy would pick 100k first

		const result = await provider.selectDualFundingInputs(
			10_000n,
			1000,
			true,
			false,
			{ utxos: [{ txid: named.tx_hash, vout: named.tx_pos }] }
		);
		expect(selectedOutpoints(result.inputs)).to.deep.equal([
			`${named.tx_hash}:${named.tx_pos}`
		]);
	});

	it('a named outpoint the wallet does not hold fails the selection naming it', async function () {
		const w = makeWallet([100_000]);
		const provider = new WalletFundingProvider(w.wallet as never);
		const bogus = crypto.randomBytes(32).toString('hex');

		let error = '';
		try {
			await provider.selectDualFundingInputs(10_000n, 1000, true, false, {
				utxos: [{ txid: bogus, vout: 0 }]
			});
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal(`requested funding utxo not spendable: ${bogus}:0`);
	});

	it('a frozen named outpoint fails the same way, never silently skipped', async function () {
		const w = makeWallet([100_000, 50_000]);
		const provider = new WalletFundingProvider(w.wallet as never);
		const named = w.utxos[1];
		w.freeze(named.tx_hash, named.tx_pos);

		let error = '';
		try {
			await provider.selectDualFundingInputs(10_000n, 1000, true, false, {
				utxos: [{ txid: named.tx_hash, vout: named.tx_pos }]
			});
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal(
			`requested funding utxo not spendable: ${named.tx_hash}:${named.tx_pos}`
		);
	});

	it('named coins short of the target fail as insufficient without allowTopUp', async function () {
		const w = makeWallet([100_000, 30_000]);
		const provider = new WalletFundingProvider(w.wallet as never);
		const named = w.utxos[1];

		let error = '';
		try {
			await provider.selectDualFundingInputs(50_000n, 1000, true, false, {
				utxos: [{ txid: named.tx_hash, vout: named.tx_pos }]
			});
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.match(/^insufficient wallet funds/);
	});

	it('allowTopUp completes a short directed selection from the remaining coins', async function () {
		const w = makeWallet([100_000, 30_000]);
		const provider = new WalletFundingProvider(w.wallet as never);
		const named = w.utxos[1];

		const result = await provider.selectDualFundingInputs(
			50_000n,
			1000,
			true,
			false,
			{
				utxos: [{ txid: named.tx_hash, vout: named.tx_pos }],
				allowTopUp: true
			}
		);
		const picked = selectedOutpoints(result.inputs);
		expect(picked).to.include(`${named.tx_hash}:${named.tx_pos}`);
		const total = result.inputs.reduce((s, i) => s + i.value, 0n);
		expect(total >= 50_000n).to.equal(true);
	});

	it('selectSpliceInputs honors the same opts', async function () {
		const w = makeWallet([100_000, 50_000, 30_000]);
		const provider = new WalletFundingProvider(w.wallet as never);
		const named = w.utxos[2];

		const result = await provider.selectSpliceInputs(10_000n, 1000, {
			utxos: [{ txid: named.tx_hash, vout: named.tx_pos }]
		});
		expect(selectedOutpoints(result.inputs)).to.deep.equal([
			`${named.tx_hash}:${named.tx_pos}`
		]);
	});

	it('an unrestricted selection is untouched by the new parameter', async function () {
		const w = makeWallet([100_000, 50_000]);
		const provider = new WalletFundingProvider(w.wallet as never);

		const result = await provider.selectDualFundingInputs(60_000n, 1000, true);
		// Confirmed-first, largest-first greedy: the 100k coin alone covers.
		expect(selectedOutpoints(result.inputs)).to.deep.equal([
			`${w.utxos[0].tx_hash}:0`
		]);
	});
});
