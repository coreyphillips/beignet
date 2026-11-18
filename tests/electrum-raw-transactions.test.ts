/**
 * A server that answers transactions only in raw form. electrs-esplora, which
 * Blockstream's and Bitkit's public servers run, refuses
 * `blockchain.transaction.get` with `verbose: true` ("verbose transactions are
 * currently unsupported"). The wallet asks for the verbose form first. From a
 * server that refuses it and answers the raw form, it takes the raw answer
 * and decodes it: inputs, outputs and sizes from the hex, and the block from
 * the history of a script the transaction pays and that block's header. A
 * server that answers verbose lookups is never asked twice.
 *
 * Fully OFFLINE: the wallet never connects, and the client helpers answer as
 * the server would.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';
import * as bitcoin from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EPaymentType,
	IFormattedTransaction,
	ITransaction,
	IUtxo,
	TTxDetails,
	Wallet,
	ok
} from '../src';
import { ElectrumBackend } from '../src/lightning/chain/electrum-backend';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const TIP = 300;
const REFUSAL = {
	code: -32603,
	message: 'verbose transactions are currently unsupported'
};
const MISS = { code: 2, message: 'No such mempool or blockchain transaction' };
/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

type TMode = 'verbose' | 'esplora' | 'silent';

describe('Electrum: a server that answers transactions only in raw form', function () {
	this.timeout(60000);

	let wallet: Wallet;
	/** The chain the fake server knows: each transaction's hex and height. */
	let chain: Map<string, { hex: string; height: number }>;
	/** The history of each script hash, as get_history answers it. */
	let histories: Map<string, Array<{ tx_hash: string; height: number }>>;
	/** verbose: answers verbose lookups; esplora: refuses them as electrs-esplora does; silent: refuses them with no message. */
	let mode: TMode;
	let verboseAsked: string[];
	let rawAsked: string[];

	const regtest = bitcoin.networks.regtest;
	const scriptHashOf = (script: Buffer): string =>
		Buffer.from(bitcoin.crypto.sha256(script)).reverse().toString('hex');

	/** An 80-byte header for a height, with a time of its own. */
	const headerAt = (height: number): string => {
		const block = new bitcoin.Block();
		block.version = 0x20000000;
		block.prevHash = Buffer.alloc(32, height % 251);
		block.merkleRoot = Buffer.alloc(32, 7);
		block.timestamp = 1_700_000_000 + height * 600;
		block.bits = 0x207fffff;
		block.nonce = height;
		return block.toHex(true);
	};

	/** The wallet's first receive address and its script. */
	const own = (): { address: string; scriptHash: string; script: Buffer } => {
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		return {
			address: source.address,
			scriptHash: source.scriptHash,
			script: bitcoin.address.toOutputScript(source.address, regtest)
		};
	};

	/** A payment of 100,000 sat to the wallet beside 40,000 to someone else, spending a witness input. */
	const payment = (): bitcoin.Transaction => {
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(Buffer.alloc(32, 0xee), 0, 0xfffffffd);
		tx.setWitness(0, [Buffer.alloc(71, 0x30), Buffer.alloc(33, 0x02)]);
		tx.addOutput(bitcoin.address.toOutputScript(EXTERNAL, regtest), 40_000);
		tx.addOutput(own().script, 100_000);
		return tx;
	};

	const coinbase = (): bitcoin.Transaction => {
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(
			Buffer.alloc(32, 0),
			0xffffffff,
			0xffffffff,
			Buffer.from('03fa0000', 'hex')
		);
		tx.addOutput(own().script, 5_000_000_000);
		return tx;
	};

	/** Puts a transaction in the fake chain, listed in the history of every script it pays. */
	const place = (
		tx: bitcoin.Transaction,
		height: number,
		listed = true
	): string => {
		const txid = tx.getId();
		chain.set(txid, { hex: tx.toHex(), height });
		if (listed) {
			for (const output of tx.outs) {
				const hash = scriptHashOf(output.script);
				histories.set(hash, [
					...(histories.get(hash) ?? []),
					{ tx_hash: txid, height }
				]);
			}
		}
		return txid;
	};

	const entry = (
		item: { tx_hash: string },
		extra: object
	): ITransaction<IUtxo> =>
		({
			id: 0,
			jsonrpc: '2.0',
			param: item.tx_hash,
			data: item,
			...extra
		}) as unknown as ITransaction<IUtxo>;

	const lookup = async (
		txid: string,
		scriptHash?: string
	): Promise<ITransaction<IUtxo>> => {
		const res = await wallet.electrum.getTransactions({
			txHashes: [{ tx_hash: txid, ...(scriptHash ? { scriptHash } : {}) }]
		});
		if (res.isErr()) throw res.error;
		expect(res.value.data).to.have.length(1);
		return res.value.data[0];
	};

	beforeEach(async function () {
		chain = new Map();
		histories = new Map();
		mode = 'esplora';
		verboseAsked = [];
		rawAsked = [];
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'electrumraw',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions: { net, tls },
			remainOffline: true,
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		await wallet.refreshWallet({});
		await wallet.updateHeader({ height: TIP, hash: '', hex: headerAt(TIP) });
		// A wallet made with remainOffline marks its instance disconnected, which
		// every lookup checks first. The helpers below answer as the server would.
		(wallet.electrum as unknown as { _disconnected: boolean })._disconnected =
			false;

		sinon
			.stub(electrumHelpers, 'getConnectedPeer')
			.returns({ host: 'esplora.example', port: 50002, protocol: 'ssl' });
		sinon
			.stub(electrumHelpers, 'getTransactions')
			.callsFake(
				async ({
					txHashes
				}: {
					txHashes: { data: Array<{ tx_hash: string }> };
				}) => {
					const items = txHashes.data;
					verboseAsked.push(...items.map((item) => item.tx_hash));
					return {
						error: false,
						id: 0,
						method: 'getTransactions',
						network: 'bitcoinRegtest',
						data: items.map((item) => {
							if (mode === 'esplora') return entry(item, { error: REFUSAL });
							if (mode === 'silent')
								return entry(item, { error: { code: -32600 } });
							const known = chain.get(item.tx_hash);
							if (!known) return entry(item, { error: MISS });
							const result: Partial<TTxDetails> = {
								txid: item.tx_hash,
								hex: known.hex,
								vin: [],
								vout: [],
								...(known.height > 0
									? { confirmations: TIP - known.height + 1 }
									: {})
							};
							return entry(item, { result });
						})
					};
				}
			);
		sinon.stub(electrumHelpers, 'getClient').resolves({
			error: false,
			data: {
				blockchainTransaction_getBatch: async (
					params: { key: string; data: Array<{ tx_hash: string }> },
					verbose: boolean
				): Promise<ITransaction<IUtxo>[]> => {
					expect(verbose, 'the fallback asks for the raw form').to.equal(false);
					rawAsked.push(...params.data.map((item) => item.tx_hash));
					return params.data.map((item) => {
						const known = chain.get(item.tx_hash);
						return known
							? entry(item, { result: known.hex })
							: entry(item, { error: MISS });
					});
				}
			}
		});
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashesHistory')
			.callsFake(async ({ scriptHashes }: { scriptHashes: string[] }) => ({
				error: false,
				data: scriptHashes.map((hash) => ({
					param: hash,
					result: histories.get(hash) ?? []
				}))
			}));
		sinon
			.stub(electrumHelpers, 'getHeader')
			.callsFake(async ({ height }: { height: number }) => ({
				error: false,
				data: headerAt(height)
			}));
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	it('asks for the verbose form first, takes the raw answer from a server that refuses it, and decodes it into the verbose shape', async () => {
		const tx = payment();
		const txid = place(tx, 298);

		const answered = await lookup(txid);
		expect(
			answered.error,
			'the refusal is gone once the raw answer is decoded'
		).to.equal(undefined);
		const result = answered.result;
		expect(result.txid).to.equal(txid);
		expect(result.hex).to.equal(tx.toHex());
		expect(result.hash, 'the witness hash').to.equal(
			Buffer.from(tx.getHash(true)).reverse().toString('hex')
		);
		expect(result.hash).to.not.equal(txid);
		expect(result.size).to.equal(tx.byteLength());
		expect(result.vsize).to.equal(tx.virtualSize());
		expect(result.vsize).to.be.below(result.size);
		expect(result.weight).to.equal(tx.weight());
		expect(result.version).to.equal(2);
		expect(result.locktime).to.equal(0);
		expect(result.vin).to.deep.equal([
			{
				txid: 'ee'.repeat(32),
				vout: 0,
				scriptSig: { asm: '', hex: '' },
				txinwitness: ['30'.repeat(71), '02'.repeat(33)],
				sequence: 0xfffffffd
			}
		]);
		expect(
			result.vout.map((output) => output.value),
			'values in BTC, as the verbose form gives them'
		).to.deep.equal([0.0004, 0.001]);
		expect(result.vout.map((output) => output.n)).to.deep.equal([0, 1]);
		expect(result.vout[0].scriptPubKey.address).to.equal(EXTERNAL);
		expect(result.vout[1].scriptPubKey.address).to.equal(own().address);
		expect(result.vout[1].scriptPubKey.hex).to.equal(
			own().script.toString('hex')
		);
		const block = bitcoin.Block.fromHex(headerAt(298));
		expect(result.blockhash).to.equal(block.getId());
		expect(result.blocktime).to.equal(block.timestamp);
		expect(result.confirmations).to.equal(TIP - 298 + 1);
		expect(verboseAsked).to.deep.equal([txid]);
		expect(rawAsked).to.deep.equal([txid]);
	});

	it('asks such a server for the raw form at once after that', async () => {
		const first = place(payment(), 298);
		const second = place(coinbase(), 299);
		await lookup(first);

		const answered = await lookup(second);
		expect(answered.result.txid).to.equal(second);
		expect(
			verboseAsked,
			'no verbose lookup after the first refusal'
		).to.deep.equal([first]);
		expect(rawAsked).to.deep.equal([first, second]);
	});

	it('finds a server whose refusal carries no message the same way', async () => {
		mode = 'silent';
		const txid = place(payment(), 298);

		const answered = await lookup(txid);
		expect(answered.error).to.equal(undefined);
		expect(answered.result.confirmations).to.equal(3);
		expect(rawAsked).to.deep.equal([txid]);
	});

	it('never asks a server that answers verbose lookups for the raw form', async () => {
		mode = 'verbose';
		const txid = place(payment(), 298);

		const answered = await lookup(txid);
		expect(answered.result.confirmations).to.equal(3);
		await lookup(txid);
		expect(rawAsked).to.deep.equal([]);
		expect(verboseAsked).to.deep.equal([txid, txid]);
	});

	it('reads a transaction in the mempool as unconfirmed', async () => {
		const txid = place(payment(), 0);

		const answered = await lookup(txid);
		expect(answered.result.txid).to.equal(txid);
		expect(answered.result.confirmations).to.equal(undefined);
		expect(answered.result.blockhash).to.equal(undefined);
	});

	it('marks a coinbase input as one', async () => {
		const txid = place(coinbase(), 250);

		const answered = await lookup(txid);
		expect(answered.result.vin).to.deep.equal([
			{ coinbase: '03fa0000', sequence: 0xffffffff }
		]);
		expect(answered.result.vout[0].value).to.equal(50);
	});

	it('leaves a transaction it cannot place in a block as an answer that says nothing, never as unconfirmed', async () => {
		const txid = place(payment(), 298, false);

		const answered = await lookup(txid);
		expect(answered.result).to.equal(undefined);
		expect(answered.error?.message).to.match(/only in raw form/);
		expect(wallet.electrum.transactionExists(answered), 'not a miss').to.equal(
			true
		);
	});

	it('reads the place of a transaction from the script hash the caller names first', async () => {
		const tx = payment();
		const txid = tx.getId();
		chain.set(txid, { hex: tx.toHex(), height: 297 });
		// Listed only in the history of the wallet's own script.
		histories.set(own().scriptHash, [{ tx_hash: txid, height: 297 }]);
		const asked: string[] = [];
		(
			electrumHelpers.getAddressScriptHashesHistory as sinon.SinonStub
		).callsFake(async ({ scriptHashes }: { scriptHashes: string[] }) => {
			asked.push(...scriptHashes);
			return {
				error: false,
				data: scriptHashes.map((hash) => ({
					param: hash,
					result: histories.get(hash) ?? []
				}))
			};
		});

		const answered = await lookup(txid, own().scriptHash);
		expect(answered.result.confirmations).to.equal(TIP - 297 + 1);
		expect(asked).to.deep.equal([own().scriptHash]);
	});

	it('still reads a transaction the server does not have as a miss', async () => {
		place(payment(), 298);
		const missing = 'ab'.repeat(32);

		const answered = await lookup(missing);
		expect(answered.result).to.equal(undefined);
		expect(answered.error).to.deep.equal(MISS);
		expect(wallet.electrum.transactionExists(answered)).to.equal(false);
	});

	it('gives the Lightning chain backend the hex', async () => {
		const tx = payment();
		const txid = place(tx, 298);

		const backend = new ElectrumBackend(wallet.electrum);
		const hex = await backend.getTransaction(txid);
		expect(hex.toString('hex')).to.equal(tx.toHex());
	});

	it('answers a lookup of inputs with output values in BTC', async () => {
		const txid = place(payment(), 298);

		const res = await wallet.electrum.getTransactionsFromInputs({
			txHashes: [{ tx_hash: txid }]
		});
		if (res.isErr()) throw res.error;
		expect(
			res.value.data[0].result.vout.map((output) => output.value)
		).to.deep.equal([0.0004, 0.001]);
	});

	it('lets the wallet see a received coin confirmed at its first confirmation, and still holds back an immature coinbase', async () => {
		const received = payment();
		const receivedTxid = place(received, TIP);
		const mined = coinbase();
		const minedTxid = place(mined, 250);
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		const coinOf = (
			txid: string,
			pos: number,
			value: number,
			height: number
		): IUtxo => ({
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height,
			tx_hash: txid,
			tx_pos: pos,
			value,
			publicKey: source.publicKey
		});
		const coin = coinOf(receivedTxid, 1, 100_000, TIP);
		const immature = coinOf(minedTxid, 0, 5_000_000_000, 250);
		sinon.stub(wallet, 'checkElectrumConnection').resolves(ok('connected'));
		sinon
			.stub(wallet.electrum, 'getUtxos')
			.resolves(ok({ utxos: [coin, immature], balance: 5_000_100_000 }));

		const scanned = await wallet.refreshUtxos({});
		if (scanned.isErr()) throw scanned.error;
		expect(wallet.listUtxos()).to.deep.equal([coin]);
		expect(
			wallet.listUtxos()[0].height,
			'confirmed at its first confirmation'
		).to.equal(TIP);
		expect(wallet.listImmatureUtxos().map((u) => u.tx_hash)).to.deep.equal([
			minedTxid
		]);
	});

	it("lets the wallet's check of its unconfirmed transactions see a receive confirm", async () => {
		const tx = payment();
		const txid = place(tx, 299);
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		const record: IFormattedTransaction = {
			address: source.address,
			height: 0,
			scriptHash: source.scriptHash,
			totalInputValue: 0.00141,
			totalInputSats: 141_000,
			matchedInputValue: 0,
			matchedInputSats: 0,
			totalOutputValue: 0.0014,
			totalOutputSats: 140_000,
			matchedOutputValue: 0.001,
			matchedOutputSats: 100_000,
			fee: 0.00001,
			feeSats: 1_000,
			satsPerByte: 7,
			type: EPaymentType.received,
			value: 0.001,
			valueSats: 100_000,
			txid,
			messages: [],
			vin: [],
			timestamp: 1_700_000_000_000,
			exists: true,
			vsize: 141
		};
		const seeded = await wallet.updateData({
			transactions: { ...wallet.data.transactions, [txid]: record },
			unconfirmedTransactions: {
				...wallet.data.unconfirmedTransactions,
				[txid]: record
			}
		});
		if (seeded.isErr()) throw seeded.error;

		const checked = await wallet.checkUnconfirmedTransactions();
		if (checked.isErr()) throw checked.error;
		// The copy under observation is what the check updates; a refresh
		// rewrites the main record. The raw answer gives the confirmations a
		// verbose one would (bitcoind's: tip - height + 1), and the check turns
		// them into a height as it does for a verbose answer.
		expect(wallet.data.unconfirmedTransactions[txid].height).to.equal(
			wallet.confirmationsToBlockHeight({ confirmations: TIP - 299 + 1 })
		);
		expect(wallet.data.unconfirmedTransactions[txid].height).to.be.above(0);
	});
});
