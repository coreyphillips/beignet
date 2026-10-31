import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { getECPair } from '../../../src/utils/ecc-apis';
import { ecc } from '../../../src/utils/ecc';
import {
	WalletFundingProvider,
	IWalletLike,
	ISpliceUtxo
} from '../../../src/lightning/wallet/wallet-funding-provider';
bitcoin.initEccLib(ecc);
const ok = <T>(value: T) => ({ isErr: () => false, isOk: () => true, value });
function fixture() {
	const key = getECPair().fromPrivateKey(Buffer.alloc(32, 25), {
			network: bitcoin.networks.regtest
		}),
		pubkey = Buffer.from(key.publicKey),
		payment = bitcoin.payments.p2wpkh({
			pubkey,
			network: bitcoin.networks.regtest
		});
	const original = new bitcoin.Transaction();
	original.addInput(Buffer.alloc(32, 12), 0);
	original.addOutput(payment.output!, 50000);
	const coin: ISpliceUtxo = {
		tx_hash: original.getId(),
		tx_pos: 0,
		address: payment.address!,
		path: 'owned',
		publicKey: pubkey.toString('hex'),
		value: 50000,
		height: 100
	};
	let coins = [coin],
		unfreezes = 0;
	const frozen = new Map<string, { freezeTag?: string; frozenAt: number }>(),
		transactions = new Map([[original.getId(), original]]);
	const wallet: IWalletLike = {
		network: 'regtest',
		send: async () => ok(''),
		listUtxos: () => coins,
		getPrivateKey: (path) => {
			if (path !== 'owned') throw new Error('Unknown path');
			return key.toWIF();
		},
		getAddressFromScriptHash: (hash) =>
			hash ===
			Buffer.from(bitcoin.crypto.sha256(payment.output!))
				.reverse()
				.toString('hex')
				? coin
				: undefined,
		getChangeAddress: async () => ok({ address: payment.address! }),
		isUtxoFrozen: (id, index) => frozen.has(`${id}:${index}`),
		listFrozenUtxos: () =>
			[...frozen].map(([id, value]) => ({
				tx_hash: id.split(':')[0],
				tx_pos: Number(id.split(':')[1]),
				...value
			})),
		freezeUtxo: async ({ txid, index, tag }) => {
			const id = `${txid}:${index}`;
			if (!frozen.has(id))
				frozen.set(id, { freezeTag: tag, frozenAt: Date.now() });
			return ok('');
		},
		unfreezeUtxo: async ({ txid, index }) => {
			unfreezes++;
			frozen.delete(`${txid}:${index}`);
			return ok('');
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
		original,
		coin,
		key,
		payment,
		frozen,
		transactions,
		unfreezes: () => unfreezes,
		setCoins: (value: ISpliceUtxo[]) => {
			coins = value;
		}
	};
}
async function rejection(promise: Promise<unknown>, part: string) {
	let failure = '';
	try {
		await promise;
	} catch (error) {
		failure = (error as Error).message;
	}
	expect(failure).contains(part);
}
describe('pledged fee replacement inputs', () => {
	it('restores the same absent wallet coin after restart and never selects its candidate change', async () => {
		const f = fixture(),
			provider = new WalletFundingProvider(f.wallet),
			first = await provider.selectFeeBumpInputs(1000n, 2500);
		const candidate = new bitcoin.Transaction();
		candidate.version = 2;
		candidate.addInput(Buffer.alloc(32, 35), 0, 0xfffffffd);
		candidate.addInput(f.original.getHash(), 0, 0xfffffffd);
		candidate.addOutput(Buffer.from('5120' + '11'.repeat(32), 'hex'), 355);
		candidate.addOutput(f.payment.output!, 48000);
		candidate.setWitness(1, first.inputs[0].signWitness!(candidate, 1, 50000n));
		f.transactions.set(candidate.getId(), candidate);
		f.setCoins([
			{
				...f.coin,
				tx_hash: candidate.getId(),
				tx_pos: 1,
				value: 48000,
				height: 0
			}
		]);
		const restarted = new WalletFundingProvider(f.wallet),
			second = await restarted.selectFeeBumpInputs(4000n, 3000, {
				excludeTxids: [candidate.getId()],
				confirmedOnly: true,
				replacementInputs: [
					{ txid: f.original.getId(), vout: 0, sequence: 0xfffffffd }
				]
			});
		expect(second.inputs).length(1);
		expect(second.inputs[0].prevTx).deep.equal(f.original.toBuffer());
		expect(f.unfreezes()).equal(0);
		expect(f.frozen.has(`${f.original.getId()}:0`)).equal(true);
		const replacement = candidate.clone();
		replacement.outs[1].value = 44000;
		const witness = second.inputs[0].signWitness!(replacement, 1, 50000n),
			signature = bitcoin.script.signature.decode(witness[0]);
		const digest = replacement.hashForWitnessV0(
			1,
			bitcoin.payments.p2pkh({ pubkey: Buffer.from(f.key.publicKey) }).output!,
			50000,
			signature.hashType
		);
		expect(ecc.verify(digest, f.key.publicKey, signature.signature)).equal(
			true
		);
		expect(signature.hashType).equal(bitcoin.Transaction.SIGHASH_ALL);
	});
	it('adds only confirmed top-ups while keeping the original reservation', async () => {
		const f = fixture(),
			provider = new WalletFundingProvider(f.wallet);
		await provider.selectFeeBumpInputs(1000n, 2500);
		const topup = f.original.clone();
		topup.ins[0].hash = Buffer.alloc(32, 90);
		topup.outs[0].value = 10000;
		const unconfirmed = f.original.clone();
		unconfirmed.ins[0].hash = Buffer.alloc(32, 91);
		unconfirmed.outs[0].value = 1000000;
		f.transactions.set(topup.getId(), topup);
		f.transactions.set(unconfirmed.getId(), unconfirmed);
		f.setCoins([
			{ ...f.coin, tx_hash: unconfirmed.getId(), value: 1000000, height: 0 },
			{ ...f.coin, tx_hash: topup.getId(), value: 10000, height: 101 }
		]);
		const result = await provider.selectFeeBumpInputs(57000n, 2500, {
			confirmedOnly: false,
			replacementInputs: [
				{ txid: f.original.getId(), vout: 0, sequence: 0xfffffffd }
			]
		});
		expect(
			result.inputs.map((input) =>
				bitcoin.Transaction.fromBuffer(input.prevTx).getId()
			)
		).deep.equal([f.original.getId(), topup.getId()]);
		expect(f.unfreezes()).equal(0);
	});
	it('rejects a replacement previous transaction returned under a false identity', async () => {
		const f = fixture(),
			provider = new WalletFundingProvider(f.wallet);
		await provider.selectFeeBumpInputs(1000n, 2500);
		const forged = f.original.clone();
		forged.outs[0].value--;
		f.transactions.set(f.original.getId(), forged);
		await rejection(
			provider.selectFeeBumpInputs(1000n, 2500, {
				replacementInputs: [
					{ txid: f.original.getId(), vout: 0, sequence: 0xfffffffd }
				]
			}),
			'identity mismatch'
		);
		expect(f.unfreezes()).equal(0);
	});

	it('filters forbidden transactions and unconfirmed fresh top-ups', async () => {
		const f = fixture(),
			provider = new WalletFundingProvider(f.wallet);
		f.setCoins([{ ...f.coin, height: 0 }]);
		await rejection(
			provider.selectFeeBumpInputs(1000n, 2500, { confirmedOnly: true }),
			'insufficient wallet funds'
		);
		f.setCoins([f.coin]);
		await rejection(
			provider.selectFeeBumpInputs(1000n, 2500, {
				excludeTxids: [f.original.getId().toUpperCase()]
			}),
			'insufficient wallet funds'
		);
		expect(f.frozen.size).equal(0);
	});
	it('refuses unowned freezes, altered prevouts, duplicate inputs and wrong wallet derivations', async () => {
		const f = fixture(),
			provider = new WalletFundingProvider(f.wallet),
			input = {
				prevTx: f.original.toBuffer(),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			};
		await rejection(
			provider.restoreFeeBumpInputs([input]),
			'not an owned pledge'
		);
		await provider.selectFeeBumpInputs(1000n, 2500);
		await rejection(provider.restoreFeeBumpInputs([input, input]), 'Duplicate');
		const altered = f.original.clone();
		altered.outs[0].value--;
		await rejection(
			provider.restoreFeeBumpInputs([{ ...input, prevTx: altered.toBuffer() }]),
			'not an owned pledge'
		);
		const metadata = f.wallet.getAddressFromScriptHash!;
		f.wallet.getAddressFromScriptHash = (hash) => {
			const result = metadata(hash);
			return result
				? { ...result, publicKey: '02' + '00'.repeat(32) }
				: undefined;
		};
		await rejection(
			provider.restoreFeeBumpInputs([input]),
			'derived key mismatch'
		);
		f.wallet.getAddressFromScriptHash = metadata;
		f.frozen.set(`${f.original.getId()}:0`, { frozenAt: Date.now() });
		await rejection(
			provider.restoreFeeBumpInputs([input]),
			'not an owned pledge'
		);
		expect(f.unfreezes()).equal(0);
	});
	it('restores an unsigned persisted fee intent without selecting another coin', async () => {
		const f = fixture(),
			provider = new WalletFundingProvider(f.wallet);
		await provider.selectFeeBumpInputs(1000n, 2500);
		f.setCoins([]);
		const restored = await new WalletFundingProvider(
			f.wallet
		).restoreFeeBumpInputs([
			{
				prevTx: f.original.toBuffer(),
				prevOutputIndex: 0,
				sequence: 0xfffffffd
			}
		]);
		expect(restored).length(1);
		expect(f.unfreezes()).equal(0);
	});
});
