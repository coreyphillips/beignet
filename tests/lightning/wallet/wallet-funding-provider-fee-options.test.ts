import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { getECPair } from '../../../src/utils/ecc-apis';
import { ecc } from '../../../src/utils/ecc';
import { EAddressType } from '../../../src/types';
import {
	WalletFundingProvider,
	IWalletLike,
	ISpliceUtxo
} from '../../../src/lightning/wallet/wallet-funding-provider';
import {
	fixedOutputHtlcFeeActionId,
	parseFixedOutputHtlcFeeActionId
} from '../../../src/lightning/chain/types';

bitcoin.initEccLib(ecc);

/**
 * A provider built without fixed-output fees, asked without fee options,
 * selects and reserves fee coins as it did before those existed. The sweep
 * behaviours (a wallet refresh on a shortfall, P2WPKH change, replacement
 * inputs) belong to a caller that passes fee options.
 */

const ok = <T>(value: T): { isErr(): boolean; isOk(): boolean; value: T } => ({
	isErr: () => false,
	isOk: () => true,
	value
});
const refused = (
	message: string
): { isErr(): boolean; isOk(): boolean; error: { message: string } } => ({
	isErr: () => true,
	isOk: () => false,
	error: { message }
});

function fixture(values: number[] = [50000]): {
	wallet: IWalletLike;
	coins: () => ISpliceUtxo[];
	setCoins: (next: ISpliceUtxo[]) => void;
	transactions: Map<string, bitcoin.Transaction>;
	frozen: Map<string, { freezeTag?: string; frozenAt: number }>;
	payment: bitcoin.payments.Payment;
	calls: {
		refreshes: number;
		changeArgs: unknown[][];
		freezes: string[];
	};
	onRefresh: (fn: () => void) => void;
} {
	const key = getECPair().fromPrivateKey(Buffer.alloc(32, 61), {
			network: bitcoin.networks.regtest
		}),
		pubkey = Buffer.from(key.publicKey),
		payment = bitcoin.payments.p2wpkh({
			pubkey,
			network: bitcoin.networks.regtest
		});
	const transactions = new Map<string, bitcoin.Transaction>();
	const owned = {
		address: payment.address!,
		path: 'owned',
		publicKey: pubkey.toString('hex')
	};
	let coins: ISpliceUtxo[] = values.map((value, index) => {
		const tx = new bitcoin.Transaction();
		tx.addInput(Buffer.alloc(32, 20 + index), 0);
		tx.addOutput(payment.output!, value);
		transactions.set(tx.getId(), tx);
		return { ...owned, tx_hash: tx.getId(), tx_pos: 0, value, height: 100 };
	});
	const frozen = new Map<string, { freezeTag?: string; frozenAt: number }>();
	const calls = {
		refreshes: 0,
		changeArgs: [] as unknown[][],
		freezes: [] as string[]
	};
	let refresh: () => void = () => undefined;
	const wallet: IWalletLike = {
		network: 'regtest',
		send: async () => ok(''),
		listUtxos: () => coins,
		refreshWallet: async () => {
			calls.refreshes++;
			refresh();
			return ok('refreshed');
		},
		getPrivateKey: (path) => {
			if (path !== 'owned') throw new Error('Unknown path');
			return key.toWIF();
		},
		getAddressFromScriptHash: (hash) =>
			hash ===
			Buffer.from(bitcoin.crypto.sha256(payment.output!))
				.reverse()
				.toString('hex')
				? owned
				: undefined,
		getChangeAddress: async (...args: unknown[]) => {
			calls.changeArgs.push(args);
			return ok({ address: payment.address! });
		},
		isUtxoFrozen: (id, index) => frozen.has(`${id}:${index}`),
		listFrozenUtxos: () =>
			[...frozen].map(([id, value]) => ({
				tx_hash: id.split(':')[0],
				tx_pos: Number(id.split(':')[1]),
				...value
			})),
		// As the wallet's coin control does it: a coin the wallet does not
		// list is refused, whether or not a freeze already stands on it.
		freezeUtxoIfUnfrozen: async ({ txid, index, tag }) => {
			const id = `${txid}:${index}`;
			calls.freezes.push(id);
			if (!coins.some((c) => c.tx_hash === txid && c.tx_pos === index))
				return refused(`UTXO ${id} is not known to this wallet.`);
			if (frozen.has(id)) return ok({ created: false });
			frozen.set(id, { freezeTag: tag, frozenAt: Date.now() });
			return ok({ created: true });
		},
		unfreezeUtxoIfTagged: async ({ txid, index, tag }) => {
			const id = `${txid}:${index}`;
			if (frozen.get(id)?.freezeTag !== tag) return ok({ unfrozen: false });
			frozen.delete(id);
			return ok({ unfrozen: true });
		},
		electrum: {
			broadcastTransaction: async () => ok(''),
			getTransactions: async ({ txHashes }) =>
				ok({
					data: txHashes.map(({ tx_hash }) => ({
						data: { tx_hash },
						result: { txid: tx_hash, hex: transactions.get(tx_hash)?.toHex() }
					}))
				})
		}
	};
	return {
		wallet,
		coins: () => coins,
		setCoins: (next): void => {
			coins = next;
		},
		transactions,
		frozen,
		payment,
		calls,
		onRefresh: (fn): void => {
			refresh = fn;
		}
	};
}

async function failure(promise: Promise<unknown>): Promise<string> {
	try {
		await promise;
	} catch (error) {
		return (error as Error).message;
	}
	return '';
}

describe('fee options on the wallet funding provider', () => {
	it('a provider without fixed-output fees says it cannot prepare them', () => {
		const f = fixture();
		const provider = new WalletFundingProvider(f.wallet);
		expect(provider.supportsFixedOutputFees()).equal(false);
		expect(provider.getFixedOutputFeeActionIds(Buffer.alloc(32, 1))).deep.equal(
			[]
		);
	});

	it('a fixed-output selection on a provider without the option is refused', async () => {
		const f = fixture();
		const provider = new WalletFundingProvider(f.wallet);
		expect(
			await failure(
				provider.selectFeeBumpInputs(1000n, 253, {
					fixedOutputs: true,
					feeActionId: 'asset-htlc:x'
				})
			)
		).contains('not configured');
		expect(f.calls.freezes).deep.equal([]);
	});

	it('without fee options a shortfall is refused in the old words and the wallet is not refreshed', async () => {
		const f = fixture([]);
		const provider = new WalletFundingProvider(f.wallet);
		expect(await failure(provider.selectFeeBumpInputs(1000n, 253))).equal(
			'insufficient wallet funds for fee-bump: need 0 sats (amount + fee), have 0 sats in spendable P2WPKH UTXOs'
		);
		expect(f.calls.refreshes).equal(0);
	});

	it('without fee options the change address is asked for with no arguments', async () => {
		const f = fixture();
		const provider = new WalletFundingProvider(f.wallet);
		const selected = await provider.selectFeeBumpInputs(1000n, 253);
		expect(selected.inputs).length(1);
		expect(selected).not.have.property('maxFeeSatoshis');
		expect(f.calls.changeArgs).deep.equal([[]]);
		expect(f.calls.refreshes).equal(0);
	});

	it('with fee options a shortfall refreshes the wallet once and takes the coin that appeared', async () => {
		const f = fixture([]);
		const tx = new bitcoin.Transaction();
		tx.addInput(Buffer.alloc(32, 77), 0);
		tx.addOutput(f.payment.output!, 49000);
		f.transactions.set(tx.getId(), tx);
		f.onRefresh(() =>
			f.setCoins([
				{
					address: f.payment.address!,
					path: 'owned',
					publicKey: Buffer.from(
						getECPair().fromPrivateKey(Buffer.alloc(32, 61), {
							network: bitcoin.networks.regtest
						}).publicKey
					).toString('hex'),
					tx_hash: tx.getId(),
					tx_pos: 0,
					value: 49000,
					height: 101
				}
			])
		);
		const provider = new WalletFundingProvider(f.wallet);
		const selected = await provider.selectFeeBumpInputs(1000n, 253, {});
		expect(f.calls.refreshes).equal(1);
		expect(selected.inputs).length(1);
		expect(
			bitcoin.Transaction.fromBuffer(selected.inputs[0].prevTx).getId()
		).equal(tx.getId());
	});

	it('with fee options the change of a fee bump is asked for as P2WPKH', async () => {
		const f = fixture();
		const provider = new WalletFundingProvider(f.wallet);
		await provider.selectFeeBumpInputs(1000n, 253, {});
		expect(f.calls.changeArgs).deep.equal([[EAddressType.p2wpkh]]);
	});

	it('with fee options an unconfirmed coin is left out when only confirmed ones are asked for', async () => {
		const f = fixture([50000]);
		f.setCoins(f.coins().map((c) => ({ ...c, height: 0 })));
		const provider = new WalletFundingProvider(f.wallet);
		expect(
			await failure(
				provider.selectFeeBumpInputs(1000n, 253, { confirmedOnly: true })
			)
		).contains('insufficient wallet funds for fee-bump');
		const plain = await provider.selectFeeBumpInputs(1000n, 253);
		expect(plain.inputs).length(1);
	});

	it('a pledge on a fee coin the wallet no longer lists is renewed without asking the wallet to freeze it again', async () => {
		const f = fixture();
		const coin = f.coins()[0];
		const provider = new WalletFundingProvider(f.wallet);
		const first = await provider.selectFeeBumpInputs(1000n, 253, {});
		expect(first.inputs).length(1);
		expect(f.frozen.has(`${coin.tx_hash}:0`)).equal(true);
		// A published sweep spent the coin: the wallet no longer lists it, and
		// its freeze still stands.
		f.setCoins([]);
		const before = f.calls.freezes.length;
		const restored = await provider.restoreFeeBumpInputs([
			{
				prevTx: f.transactions.get(coin.tx_hash)!.toBuffer(),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			}
		]);
		expect(restored).length(1);
		expect(restored[0].value).equal(50000n);
		expect(f.calls.freezes.length).equal(before);
		expect(f.frozen.get(`${coin.tx_hash}:0`)?.freezeTag).equal(
			'funding-pledge'
		);
	});

	it('a spent fee coin frozen under another owner is not taken over', async () => {
		const f = fixture();
		const coin = f.coins()[0];
		const provider = new WalletFundingProvider(f.wallet);
		await provider.selectFeeBumpInputs(1000n, 253, {});
		f.setCoins([]);
		f.frozen.set(`${coin.tx_hash}:0`, {
			freezeTag: 'someone-else',
			frozenAt: Date.now()
		});
		expect(
			await failure(
				provider.restoreFeeBumpInputs([
					{
						prevTx: f.transactions.get(coin.tx_hash)!.toBuffer(),
						prevOutputIndex: 0,
						sequence: 0xfffffffd
					}
				])
			)
		).contains('not an owned pledge');
		expect(f.frozen.get(`${coin.tx_hash}:0`)?.freezeTag).equal('someone-else');
	});

	it('two providers without the option do not wait on each other', async () => {
		const f = fixture([50000, 40000]);
		let release!: () => void;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const slow: IWalletLike = {
			...f.wallet,
			getChangeAddress: async () => {
				await gate;
				return ok({ address: f.payment.address! });
			}
		};
		const held = new WalletFundingProvider(slow).selectFeeBumpInputs(
			1000n,
			253
		);
		const free = await new WalletFundingProvider(f.wallet).selectFeeBumpInputs(
			1000n,
			253
		);
		expect(free.inputs).length(1);
		release();
		expect((await held).inputs).length(1);
	});
});

describe('the identity of a fixed-output HTLC fee action', () => {
	const channel = Buffer.alloc(32, 9);
	const txid = 'ab'.repeat(32);

	it('is written and read back as one canonical string', () => {
		const id = fixedOutputHtlcFeeActionId(channel, txid.toUpperCase(), 3);
		expect(id).equal(`asset-htlc:${'09'.repeat(32)}:${txid}:3`);
		const parsed = parseFixedOutputHtlcFeeActionId(id)!;
		expect(parsed.channelId.equals(channel)).equal(true);
		expect(parsed.txid).equal(txid);
		expect(parsed.outputIndex).equal(3);
	});

	it('refuses a short channel id, a malformed transaction id and an output index out of range', () => {
		expect(() => fixedOutputHtlcFeeActionId(Buffer.alloc(31), txid, 0)).throw(
			'Invalid fixed-output HTLC fee identity'
		);
		expect(() => fixedOutputHtlcFeeActionId(channel, 'zz', 0)).throw(
			'Invalid fixed-output HTLC fee identity'
		);
		expect(() => fixedOutputHtlcFeeActionId(channel, txid, -1)).throw(
			'Invalid fixed-output HTLC fee identity'
		);
		expect(() => fixedOutputHtlcFeeActionId(channel, txid, 2 ** 32)).throw(
			'Invalid fixed-output HTLC fee identity'
		);
	});

	it('reads nothing but a complete canonical identity', () => {
		const id = fixedOutputHtlcFeeActionId(channel, txid, 3);
		expect(parseFixedOutputHtlcFeeActionId(id + ':1')).equal(undefined);
		expect(parseFixedOutputHtlcFeeActionId(id.replace(':3', ':03'))).equal(
			undefined
		);
		expect(parseFixedOutputHtlcFeeActionId('asset-htlc:')).equal(undefined);
		expect(
			parseFixedOutputHtlcFeeActionId(id.replace(':3', ':4294967296'))
		).equal(undefined);
	});
});
