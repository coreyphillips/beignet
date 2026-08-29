/**
 * The payer's wallet adapter (issue #613, LFBW port #532 workstream 4D).
 *
 * Two things the wallet API cannot say for itself, and that the engine leans on
 * for fund safety: a freeze belongs to whoever took it, and a transaction with a
 * height is not therefore mined.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { directFundingWallet, IDfWallet } from '../../src/cli/direct-funding';
import { IUtxo } from '../../src/types';
import { ok, err, Result } from '../../src/utils';

const NETWORK = bitcoin.networks.regtest;
const TXID = 'aa'.repeat(32);
const CONFLICT = 'bb'.repeat(32);

interface IStubWallet extends IDfWallet {
	frozen: IUtxo[];
	freezes: Array<{ txid: string; index: number; tag?: string }>;
}

/** A wallet holding one coin, with whatever freezes and transactions a test sets. */
function stubWallet(
	opts: {
		frozen?: IUtxo[];
		transactions?: Record<string, { txid: string; height?: number; vin: [] }>;
	} = {}
): IStubWallet {
	const utxo = {
		address: 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080',
		tx_hash: TXID,
		tx_pos: 0,
		value: 200_000,
		height: 100,
		path: "m/84'/1'/0'/0/0",
		scriptHash: 'ff'.repeat(32)
	} as unknown as IUtxo;
	const stub = {
		frozen: opts.frozen ?? [],
		freezes: [] as Array<{ txid: string; index: number; tag?: string }>,
		listUtxos: (): IUtxo[] => [utxo],
		listFrozenUtxos: (): IUtxo[] => stub.frozen,
		isUtxoFrozen: (txid: string, index: number): boolean =>
			stub.frozen.some((f) => f.tx_hash === txid && f.tx_pos === index),
		freezeUtxo: async (args: {
			txid: string;
			index: number;
			tag?: string;
		}): Promise<Result<string>> => {
			stub.freezes.push(args);
			stub.frozen.push({
				...utxo,
				...(args.tag !== undefined ? { freezeTag: args.tag } : {})
			});
			return ok('frozen');
		},
		unfreezeUtxo: async (args: {
			txid: string;
			index: number;
		}): Promise<Result<string>> => {
			const before = stub.frozen.length;
			stub.frozen = stub.frozen.filter(
				(f) => !(f.tx_hash === args.txid && f.tx_pos === args.index)
			);
			return stub.frozen.length === before ? err('not frozen') : ok('unfrozen');
		},
		transactions: opts.transactions ?? {}
	};
	return stub as unknown as IStubWallet;
}

describe('direct funding wallet: whose freeze is it', () => {
	it('will not adopt a freeze the operator put on the coin', async () => {
		// The wallet answers Ok for a coin that is already frozen, so without the
		// tag the engine would read the operator's reservation as its own and sign
		// a coin somebody withheld.
		const wallet = stubWallet({
			frozen: [{ tx_hash: TXID, tx_pos: 0 } as unknown as IUtxo]
		});
		const df = directFundingWallet(wallet, NETWORK);
		expect(await df.freezeUtxo(TXID, 0)).to.equal(false);
		expect(wallet.freezes).to.have.length(0);
	});

	it('leaves the operator entry in place when the payment settles', async () => {
		const wallet = stubWallet({
			frozen: [{ tx_hash: TXID, tx_pos: 0 } as unknown as IUtxo]
		});
		const df = directFundingWallet(wallet, NETWORK);
		expect(await df.unfreezeUtxo(TXID, 0)).to.equal(false);
		expect(wallet.frozen).to.have.length(1);
	});

	it('takes, re-adopts and releases its own', async () => {
		const wallet = stubWallet();
		const df = directFundingWallet(wallet, NETWORK);
		expect(await df.freezeUtxo(TXID, 0)).to.equal(true);
		expect(wallet.freezes[0].tag).to.equal('direct-funding');
		// A resumed attempt meets the freeze its own earlier run left behind.
		expect(await df.freezeUtxo(TXID, 0)).to.equal(true);
		expect(wallet.freezes, 'no second write').to.have.length(1);
		expect(await df.unfreezeUtxo(TXID, 0)).to.equal(true);
		expect(wallet.frozen).to.have.length(0);
	});
});

describe('direct funding wallet: what counts as confirmed', () => {
	const tx = (
		txid: string,
		height: number
	): { txid: string; height: number; vin: [] } => ({ txid, height, vin: [] });

	it('reads an Electrum mempool height as unconfirmed', () => {
		// -1 is an unconfirmed transaction with an unconfirmed parent, and a
		// truthiness test reads it as mined: the payer would call the funding
		// CONFIRMED and release the coin while it is still in a mempool.
		for (const height of [-1, 0]) {
			const df = directFundingWallet(
				stubWallet({ transactions: { [TXID]: tx(TXID, height) } }),
				NETWORK
			);
			expect(df.txStatus(TXID)).to.deep.equal({
				known: true,
				confirmed: false
			});
		}
		const mined = directFundingWallet(
			stubWallet({ transactions: { [TXID]: tx(TXID, 100) } }),
			NETWORK
		);
		expect(mined.txStatus(TXID)?.confirmed).to.equal(true);
		expect(mined.txStatus(CONFLICT)).to.equal(null);
	});

	it('does not call a conflict won until it has actually confirmed', () => {
		const spend = (height: number): Record<string, never> =>
			({
				[CONFLICT]: {
					txid: CONFLICT,
					height,
					vin: [{ txid: TXID, vout: 0 }]
				}
			}) as unknown as Record<string, never>;
		const mempool = directFundingWallet(
			stubWallet({ transactions: spend(-1) }),
			NETWORK
		);
		// A FAILED here releases the payer's coin against a spend that may yet be
		// evicted, and rev 2 makes the conflict terminal only once it is mined.
		expect(mempool.confirmedSpendOf(TXID, 0)).to.equal(null);
		const mined = directFundingWallet(
			stubWallet({ transactions: spend(200) }),
			NETWORK
		);
		expect(mined.confirmedSpendOf(TXID, 0)).to.equal(CONFLICT);
	});
});
