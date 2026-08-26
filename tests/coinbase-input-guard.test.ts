/**
 * Coinbase transaction handling (issue #548, LFBW port #532 workstream 1F).
 *
 * A coinbase input has no previous output: its vin carries `coinbase`
 * instead of txid/vout. Mining directly to a wallet address on regtest puts
 * such transactions into the wallet's flow, where they used to (a) make the
 * input prefetch ask Electrum for prevouts named undefined:undefined, one
 * invalid-params error per block, and (b) make the formatter read the ENTIRE
 * block reward as the transaction "fee" (|0 - outputs|) at an absurd
 * feerate (issue #548 review). The vin mapping skips coinbase entries,
 * getInputData filters them again at the request boundary, and the
 * formatter prices a coinbase at fee 0.
 *
 * Offline-proof: regtest network (no public Electrum peer lists), the
 * 'electrum' fee source (no Blocktank/mempool.space HTTP), the create-time
 * refresh disabled, and an unreachable local server.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import { EAvailableNetworks, EProtocol, Wallet } from '../src';
import { ICoinbaseVin, ITransaction, IUtxo } from '../src/types/wallet';
import { TTxDetails } from '../src/types/wallet';

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

describe('Coinbase transaction handling (issue #548)', function () {
	this.timeout(30_000);

	let wallet: Wallet;

	before(async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			feeEstimationSource: 'electrum',
			disableMessagesOnCreate: true,
			disableRefreshOnCreate: true,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
	});

	after(async () => {
		await wallet.stop();
	});

	it('getInputData drops coinbase-shaped inputs instead of querying them', async () => {
		const coinbaseShaped = [
			{
				tx_hash: undefined as unknown as string,
				vout: undefined as unknown as number
			},
			{
				tx_hash: undefined as unknown as string,
				vout: 0
			}
		];
		const res = await wallet.getInputData({ inputs: coinbaseShaped });
		// Unfiltered, these would go to the (unreachable) server and fail;
		// filtered, there is nothing to fetch and the result is an empty ok.
		expect(res.isOk(), res.isErr() ? res.error.message : 'ok').to.equal(true);
		if (res.isOk()) {
			expect(Object.keys(res.value)).to.have.length(0);
		}
	});

	it('formatTransactions prices a coinbase at fee 0, not the block reward', async () => {
		// A synthetic 50 BTC coinbase paying a random address. Unfixed, the
		// formatter reported fee = |0 - 50| = 50 BTC at millions of sat/vB
		// (issue #548 review).
		const coinbaseVin: ICoinbaseVin = {
			coinbase: '03a08601',
			sequence: 0xffffffff
		};
		const tx: ITransaction<IUtxo> = {
			id: 1,
			jsonrpc: '2.0',
			param: 'cb',
			data: {
				address: 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080',
				height: 101,
				scriptHash: 'ab'.repeat(32),
				index: 0,
				path: "m/84'/1'/0'/0/0",
				tx_hash: 'cd'.repeat(32),
				tx_pos: 0,
				value: 50,
				publicKey: ''
			} as unknown as IUtxo,
			result: {
				txid: 'cd'.repeat(32),
				hash: 'cd'.repeat(32),
				version: 2,
				size: 100,
				vsize: 100,
				weight: 400,
				locktime: 0,
				vin: [coinbaseVin],
				vout: [
					{
						value: 50,
						n: 0,
						scriptPubKey: {
							asm: '',
							hex: '',
							address: 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'
						}
					}
				],
				hex: '',
				blockhash: 'ee'.repeat(32),
				confirmations: 1,
				time: 1_700_000_000,
				blocktime: 1_700_000_000
			} as unknown as TTxDetails
		};
		const res = await wallet.formatTransactions({ transactions: [tx] });
		expect(res.isOk(), res.isErr() ? res.error.message : 'ok').to.equal(true);
		if (res.isOk()) {
			const formatted = res.value['cd'.repeat(32)];
			expect(formatted, 'coinbase tx formatted').to.exist;
			// A coinbase pays no fee; it collects the block's fees.
			expect(formatted.fee).to.equal(0);
			expect(formatted.satsPerByte).to.equal(0);
			// The output value is intact and the coinbase vin rides through
			// under its own union member.
			expect(formatted.totalOutputValue).to.equal(50);
			expect('coinbase' in formatted.vin[0]).to.equal(true);
		}
	});
});
