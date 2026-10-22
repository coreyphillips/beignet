/**
 * Issue #1694: a wallet method's name did not say whether it asks the
 * network. getUtxos scanned Electrum while listUtxos read the cache,
 * getGapLimit returned the current gap rather than the limit, outpoints came
 * as `{ txid, index }`, `(txid, index)` and `{ tx_hash, vout }`, and send
 * returned a txid or raw hex depending on a flag. The new names are tested
 * here beside the deprecated ones, which forward to them.
 *
 * Fully OFFLINE: the wallet never connects to Electrum, UTXOs are injected
 * into its data, and nothing is broadcast.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';
import * as bitcoin from 'bitcoinjs-lib';

import {
	createMemoryStorage,
	EAddressType,
	EScanningStrategy,
	IUtxo,
	Network,
	Wallet
} from '../../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';
const TXID_A = '1a'.repeat(32);
const TXID_B = '2b'.repeat(32);

/** A UTXO paying to the wallet's receive address at `addressIndex`. */
const injectUtxo = async (
	wallet: Wallet,
	txid: string,
	value: number,
	addressIndex: number
): Promise<IUtxo> => {
	const source = Object.values(wallet.data.addresses[EAddressType.p2wpkh]).find(
		(a) => a.index === addressIndex
	);
	if (!source) throw new Error('No derived address available.');
	const utxo: IUtxo = {
		address: source.address,
		index: source.index,
		path: source.path,
		scriptHash: source.scriptHash,
		height: 0,
		tx_hash: txid,
		tx_pos: 0,
		value,
		publicKey: source.publicKey
	};
	const injected = await wallet.updateData({
		utxos: [...wallet.data.utxos, utxo],
		balance: wallet.data.balance + value
	});
	if (injected.isErr()) throw injected.error;
	return utxo;
};

/** The display-order txid each input of `hex` spends. */
const spentTxids = (hex: string): string[] =>
	bitcoin.Transaction.fromHex(hex).ins.map((input) =>
		Buffer.from(input.hash).reverse().toString('hex')
	);

/** Each output of `hex` as [address, value]. */
const outputsOf = (hex: string): Array<[string, number]> =>
	bitcoin.Transaction.fromHex(hex).outs.map((out) => [
		bitcoin.address.fromOutputScript(out.script, bitcoin.networks.regtest),
		out.value
	]);

describe('Wallet method names (issue #1694)', function () {
	this.timeout(60000);

	let wallet: Wallet;

	before(async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'methodnames',
			network: Network.regtest,
			storage: createMemoryStorage(),
			remainOffline: true,
			electrumOptions: { net, tls }
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still derives the first addresses.
		await wallet.refreshWallet({});
		await injectUtxo(wallet, TXID_A, 60_000, 0);
		await injectUtxo(wallet, TXID_B, 40_000, 1);
	});

	after(async () => {
		await wallet?.stop();
	});

	afterEach(async () => {
		sinon.restore();
		await wallet.resetSendTransaction();
	});

	describe('each deprecated name forwards to its replacement', () => {
		const CASES: Array<{
			old: string;
			replacement: string;
			args: unknown[];
			/** What the replacement receives, when not args as given. */
			forwarded?: unknown[];
		}> = [
			{
				old: 'getUtxos',
				replacement: 'refreshUtxos',
				args: [{ scanningStrategy: EScanningStrategy.all }]
			},
			{
				old: 'getGapLimit',
				replacement: 'getAddressGap',
				args: [{ addressType: EAddressType.p2tr }]
			},
			{
				old: 'getNextAvailableAddress',
				replacement: 'fetchNextAvailableAddress',
				args: [EAddressType.p2tr],
				forwarded: [EAddressType.p2tr, undefined]
			},
			{
				old: 'getAddressBalance',
				replacement: 'fetchAddressBalance',
				args: [EXTERNAL]
			},
			{
				old: 'getAddressesBalance',
				replacement: 'fetchAddressesBalance',
				args: [[EXTERNAL]]
			},
			{
				old: 'getScriptHashBalance',
				replacement: 'fetchScriptHashBalance',
				args: ['ab'.repeat(32)]
			},
			{
				old: 'getAddressHistory',
				replacement: 'fetchAddressHistory',
				args: [EXTERNAL]
			},
			{
				old: 'getTransactionDetails',
				replacement: 'fetchTransactionDetails',
				args: [TXID_A]
			},
			{
				old: 'getFeeEstimates',
				replacement: 'fetchFeeEstimates',
				args: [Network.signet]
			},
			{
				old: 'getFeeEstimatesFromElectrum',
				replacement: 'fetchFeeEstimatesFromElectrum',
				args: []
			},
			{
				old: 'getFeeEstimatesFromHttp',
				replacement: 'fetchFeeEstimatesFromHttp',
				args: [Network.signet]
			},
			{
				old: 'getFallbackFeeEstimates',
				replacement: 'fetchFallbackFeeEstimates',
				args: [Network.signet]
			},
			{
				old: 'getPrivateKeyInfo',
				replacement: 'fetchPrivateKeyInfo',
				args: ['not-a-key']
			},
			{
				old: 'getInputData',
				replacement: 'fetchInputData',
				args: [{ inputs: [{ tx_hash: TXID_A, vout: 1 }] }],
				forwarded: [{ inputs: [{ txid: TXID_A, vout: 1 }] }]
			},
			{
				old: 'getRbfData',
				replacement: 'fetchRbfData',
				args: [{ txHash: { tx_hash: TXID_A } }],
				forwarded: [{ txid: TXID_A }]
			}
		];

		for (const { old, replacement, args, forwarded } of CASES) {
			it(`${old} calls ${replacement}`, () => {
				const answer = { from: replacement };
				const stub = sinon.stub(wallet, replacement as keyof Wallet);
				stub.returns(answer);
				const callable = wallet as unknown as Record<
					string,
					(...a: unknown[]) => unknown
				>;
				expect(callable[old](...args)).to.equal(answer);
				expect(stub.callCount).to.equal(1);
				expect(stub.firstCall.args).to.deep.equal(forwarded ?? args);
			});
		}
	});

	describe('getAddressGap', () => {
		it('returns how far each index is past the last used one', async () => {
			const type = EAddressType.p2wpkh;
			const data = wallet.data;
			const saved = {
				addressIndex: data.addressIndex,
				lastUsedAddressIndex: data.lastUsedAddressIndex,
				changeAddressIndex: data.changeAddressIndex,
				lastUsedChangeAddressIndex: data.lastUsedChangeAddressIndex
			};
			try {
				const moved = await wallet.updateData({
					addressIndex: {
						...saved.addressIndex,
						[type]: { ...saved.addressIndex[type], index: 7 }
					},
					lastUsedAddressIndex: {
						...saved.lastUsedAddressIndex,
						[type]: { ...saved.lastUsedAddressIndex[type], index: 3 }
					},
					changeAddressIndex: {
						...saved.changeAddressIndex,
						[type]: { ...saved.changeAddressIndex[type], index: 5 }
					},
					lastUsedChangeAddressIndex: {
						...saved.lastUsedChangeAddressIndex,
						[type]: { ...saved.lastUsedChangeAddressIndex[type], index: 4 }
					}
				});
				if (moved.isErr()) throw moved.error;
				const gap = wallet.getAddressGap({ addressType: type });
				if (gap.isErr()) throw gap.error;
				expect(gap.value).to.deep.equal({
					addressDelta: 4,
					changeAddressDelta: 1
				});
				const old = wallet.getGapLimit({ addressType: type });
				if (old.isErr()) throw old.error;
				expect(old.value).to.deep.equal(gap.value);
			} finally {
				await wallet.updateData(saved);
			}
		});
	});

	describe('outpoints', () => {
		afterEach(async () => {
			for (const frozen of [...wallet.listFrozenUtxos()]) {
				await wallet.unfreezeUtxo({
					txid: frozen.tx_hash,
					vout: frozen.tx_pos
				});
			}
		});

		it('freezes, reads and unfreezes by { txid, vout }', async () => {
			const frozen = await wallet.freezeUtxo({ txid: TXID_A, vout: 0 });
			if (frozen.isErr()) throw frozen.error;
			expect(frozen.value).to.equal(`UTXO ${TXID_A}:0 frozen.`);
			expect(wallet.isUtxoFrozen({ txid: TXID_A, vout: 0 })).to.equal(true);
			expect(wallet.isUtxoFrozen({ txid: TXID_B, vout: 0 })).to.equal(false);

			const lifted = await wallet.unfreezeUtxo({ txid: TXID_A, vout: 0 });
			if (lifted.isErr()) throw lifted.error;
			expect(wallet.isUtxoFrozen({ txid: TXID_A, vout: 0 })).to.equal(false);
		});

		it('still takes the deprecated { txid, index } and (txid, index) forms', async () => {
			const frozen = await wallet.freezeUtxo({ txid: TXID_A, index: 0 });
			if (frozen.isErr()) throw frozen.error;
			expect(wallet.isUtxoFrozen(TXID_A, 0)).to.equal(true);
			expect(wallet.isUtxoFrozen({ txid: TXID_A, vout: 0 })).to.equal(true);

			const lifted = await wallet.unfreezeUtxo({ txid: TXID_A, index: 0 });
			if (lifted.isErr()) throw lifted.error;
			expect(wallet.isUtxoFrozen(TXID_A, 0)).to.equal(false);
		});

		it('takes { txid, vout } in the tagged freeze and release', async () => {
			const tag = 'naming-test';
			const frozen = await wallet.freezeUtxoIfUnfrozen({
				txid: TXID_B,
				vout: 0,
				tag
			});
			if (frozen.isErr()) throw frozen.error;
			expect(frozen.value.created).to.equal(true);
			expect(wallet.listFrozenUtxos()[0].freezeTag).to.equal(tag);

			const lifted = await wallet.unfreezeUtxoIfTagged({
				txid: TXID_B,
				vout: 0,
				tag
			});
			if (lifted.isErr()) throw lifted.error;
			expect(lifted.value.unfrozen).to.equal(true);
			expect(wallet.isUtxoFrozen({ txid: TXID_B, vout: 0 })).to.equal(false);
		});

		it('refuses an argument whose vout and index name different outputs', async () => {
			const both = { txid: TXID_A, vout: 0, index: 1 };
			for (const res of [
				await wallet.freezeUtxo(both),
				await wallet.freezeUtxoIfUnfrozen(both),
				await wallet.unfreezeUtxo(both),
				await wallet.unfreezeUtxoIfTagged({ ...both, tag: 'x' })
			]) {
				expect(res.isErr()).to.equal(true);
				if (res.isErr()) {
					expect(res.error.message).to.equal(
						'vout 0 and index 1 name different outputs.'
					);
				}
			}
			expect(wallet.listFrozenUtxos()).to.have.length(0);
		});
	});

	describe('createSignedTransaction', () => {
		it('signs a payment without broadcasting it', async () => {
			const broadcast = sinon.spy(wallet.electrum, 'broadcastTransaction');
			const res = await wallet.createSignedTransaction({
				address: EXTERNAL,
				amount: 30_000,
				satsPerByte: 2
			});
			if (res.isErr()) throw res.error;
			const { txHex, txid } = res.value;
			expect(bitcoin.Transaction.fromHex(txHex).getId()).to.equal(txid);
			expect(outputsOf(txHex)).to.deep.include([EXTERNAL, 30_000]);
			for (const spent of spentTxids(txHex)) {
				expect([TXID_A, TXID_B]).to.include(spent);
			}
			expect(broadcast.callCount).to.equal(0);
			expect(wallet.listUtxos()).to.have.length(2);
		});

		it('builds what send with broadcast: false built', async () => {
			const args = {
				address: EXTERNAL,
				amount: 30_000,
				satsPerByte: 2,
				shuffleOutputs: false
			};
			const res = await wallet.createSignedTransaction(args);
			if (res.isErr()) throw res.error;
			await wallet.resetSendTransaction();
			const old = await wallet.send({ ...args, broadcast: false });
			if (old.isErr()) throw old.error;
			expect(res.value.txHex).to.equal(old.value);
		});

		it('pays every recipient in txs', async () => {
			const own = wallet.data.addressIndex[EAddressType.p2wpkh].address;
			const res = await wallet.createSignedTransaction({
				txs: [
					{ address: EXTERNAL, amount: 20_000 },
					{ address: own, amount: 10_000 }
				],
				satsPerByte: 2
			});
			if (res.isErr()) throw res.error;
			const outputs = outputsOf(res.value.txHex);
			expect(outputs).to.deep.include([EXTERNAL, 20_000]);
			expect(outputs).to.deep.include([own, 10_000]);
		});

		it('spends every unfrozen coin with max', async () => {
			const res = await wallet.createSignedTransaction({
				address: EXTERNAL,
				max: true,
				satsPerByte: 2
			});
			if (res.isErr()) throw res.error;
			expect(spentTxids(res.value.txHex)).to.have.members([TXID_A, TXID_B]);
			const outputs = outputsOf(res.value.txHex);
			expect(outputs).to.have.length(1);
			expect(outputs[0][0]).to.equal(EXTERNAL);
			expect(outputs[0][1]).to.be.lessThan(100_000);
		});

		it('leaves a frozen coin out of a max spend', async () => {
			const frozen = await wallet.freezeUtxo({ txid: TXID_B, vout: 0 });
			if (frozen.isErr()) throw frozen.error;
			try {
				const res = await wallet.createSignedTransaction({
					address: EXTERNAL,
					max: true,
					satsPerByte: 2
				});
				if (res.isErr()) throw res.error;
				expect(spentTxids(res.value.txHex)).to.deep.equal([TXID_A]);
			} finally {
				await wallet.unfreezeUtxo({ txid: TXID_B, vout: 0 });
			}
		});

		it('refuses max alongside an amount, and a call with no outputs', async () => {
			const withAmount = await wallet.createSignedTransaction({
				address: EXTERNAL,
				amount: 1_000,
				max: true
			});
			expect(withAmount.isErr()).to.equal(true);
			const noOutputs = await wallet.createSignedTransaction({});
			expect(noOutputs.isErr()).to.equal(true);
			const maxNoAddress = await wallet.createSignedTransaction({ max: true });
			expect(maxNoAddress.isErr()).to.equal(true);
		});

		it('is in the session withSendLock hands out', async () => {
			const res = await wallet.withSendLock((locked) =>
				locked.createSignedTransaction({
					address: EXTERNAL,
					amount: 30_000,
					satsPerByte: 2
				})
			);
			if (res.isErr()) throw res.error;
			expect(outputsOf(res.value.txHex)).to.deep.include([EXTERNAL, 30_000]);
		});
	});
});
