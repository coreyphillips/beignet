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

function errResult(message: string) {
	return { isErr: () => true, isOk: () => false, error: { message } };
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

	it('a renewed pledge outlives the TTL while the broadcast is still owed', async function () {
		const { wallet, utxos, frozen, unfrozenLog, payment } = makeWallet([
			100_000, 100_000
		]);
		// The pledge for coin 0 is 11 minutes old (TTL is 10) because the funding
		// tx that spends it has not confirmed yet: an electrum outage, a fee
		// spike, or a restart in the middle of either.
		frozen.set(`${utxos[0].tx_hash}:0`, {
			tx_hash: utxos[0].tx_hash,
			tx_pos: 0,
			freezeTag: 'funding-pledge',
			frozenAt: Date.now() - 11 * 60_000
		});
		const retained = new bitcoin.Transaction();
		retained.version = 2;
		retained.addInput(
			Buffer.from(utxos[0].tx_hash, 'hex').reverse(),
			utxos[0].tx_pos
		);
		retained.addOutput(payment.output!, 90_000);

		const provider = new WalletFundingProvider(wallet as never);
		await provider.pledgeTransactionInputs(retained.toHex());
		// Renewals arrive with the blocks, and this gap is already longer than
		// the session TTL: the renewed reservation has to outlast it or the
		// coin is unfrozen for most of every long interval.
		(provider as unknown as { pledged: Map<string, number> }).pledged.set(
			`${utxos[0].tx_hash}:0`,
			Date.now() - 11 * 60_000
		);

		// The next selection still cannot draw on the coin the retained
		// transaction spends.
		const { inputs } = await provider.selectSpliceInputs!(80_000n, 1000);
		expect(unfrozenLog).to.deep.equal([]);
		expect(outpoints(inputs)).to.not.include(`${utxos[0].tx_hash}:0`);
		expect(outpoints(inputs)).to.deep.equal([`${utxos[1].tx_hash}:0`]);
	});

	it('a renewed pledge still ages out once nothing renews it', async function () {
		const { wallet, utxos, unfrozenLog, payment } = makeWallet([
			100_000, 100_000
		]);
		const retained = new bitcoin.Transaction();
		retained.version = 2;
		retained.addInput(
			Buffer.from(utxos[0].tx_hash, 'hex').reverse(),
			utxos[0].tx_pos
		);
		retained.addOutput(payment.output!, 90_000);

		const provider = new WalletFundingProvider(wallet as never);
		await provider.pledgeTransactionInputs(retained.toHex());

		// The obligation retired (channel voided) and the renewals stopped an
		// hour ago. A reservation nothing stands behind must release the coin.
		const pledged = (provider as unknown as { pledged: Map<string, number> })
			.pledged;
		pledged.set(`${utxos[0].tx_hash}:0`, Date.now() - 61 * 60_000);

		const { inputs } = await provider.selectSpliceInputs!(150_000n, 1000);
		expect(unfrozenLog).to.include(`${utxos[0].tx_hash}:0`);
		expect(outpoints(inputs)).to.include(`${utxos[0].tx_hash}:0`);
	});

	it('re-freezes an input a mempool eviction handed back', async function () {
		const { wallet, utxos, frozen, payment } = makeWallet([100_000, 100_000]);
		const key = `${utxos[0].tx_hash}:0`;
		const spend = new bitcoin.Transaction();
		spend.version = 2;
		spend.addInput(
			Buffer.from(utxos[0].tx_hash, 'hex').reverse(),
			utxos[0].tx_pos
		);
		spend.addOutput(payment.output!, 90_000);
		wallet.send = async () => ok(spend.toHex());

		const provider = new WalletFundingProvider(wallet as never);
		await provider.buildFundingTransaction(payment.address!, 90_000n);
		expect(frozen.has(key), 'the built tx pledged its input').to.equal(true);

		// The broadcast landed: the wallet stops listing the coin and the next
		// selection prunes the pledge as spent.
		const evicted = utxos.splice(0, 1)[0];
		await provider.selectSpliceInputs!(50_000n, 1000);
		expect(frozen.has(key)).to.equal(false);

		// The funding tx is evicted from the mempool: the coin comes back
		// unspent AND unfrozen, with the broadcast still owed.
		utxos.unshift(evicted);
		await provider.pledgeTransactionInputs(spend.toHex());
		expect(
			frozen.has(key),
			'the renewal re-froze the resurrected coin'
		).to.equal(true);

		let error = '';
		try {
			await provider.selectSpliceInputs!(80_000n, 1000);
		} catch (e) {
			error = (e as Error).message;
		}
		expect(error, 'nothing can double-spend the retained tx').to.contain(
			'insufficient wallet funds'
		);
	});

	it('a renewal never re-freezes a coin the transaction already spent', async function () {
		const { wallet, utxos, frozen, payment } = makeWallet([100_000, 100_000]);
		const key = `${utxos[0].tx_hash}:0`;
		const spend = new bitcoin.Transaction();
		spend.version = 2;
		spend.addInput(
			Buffer.from(utxos[0].tx_hash, 'hex').reverse(),
			utxos[0].tx_pos
		);
		spend.addOutput(payment.output!, 90_000);

		const provider = new WalletFundingProvider(wallet as never);
		// The spend is in the mempool: the wallet no longer lists the coin, and
		// re-freezing an outpoint the wallet does not hold is rejected anyway.
		utxos.splice(0, 1);
		await provider.pledgeTransactionInputs(spend.toHex());
		expect(frozen.has(key)).to.equal(false);
	});

	it('an unreadable transaction renews nothing instead of throwing', async function () {
		const { wallet, frozen } = makeWallet([100_000]);
		const provider = new WalletFundingProvider(wallet as never);
		await provider.pledgeTransactionInputs('not-a-transaction');
		expect(frozen.size).to.equal(0);
	});

	it('a freeze the wallet refuses aborts the selection (issue #626)', async function () {
		// The wallet rejects a freeze it cannot persist. Handing the inputs back
		// anyway would sign a funding against coins the next coin selection, in
		// this process or the next one, is free to spend.
		const { wallet, frozen } = makeWallet([100_000, 100_000]);
		(wallet as { freezeUtxo: unknown }).freezeUtxo = async () => ({
			isErr: () => true,
			isOk: () => false,
			error: { message: 'storage is down' }
		});
		const provider = new WalletFundingProvider(wallet as never);

		let error = '';
		try {
			await provider.selectSpliceInputs!(80_000n, 1000);
		} catch (e) {
			error = (e as Error).message;
		}
		expect(error).to.include('Failed to reserve funding input');
		expect(frozen.size).to.equal(0);
		// And no phantom reservation is left behind claiming the coin is held.
		const pledged = (provider as unknown as { pledged: Map<string, number> })
			.pledged;
		expect(pledged.size).to.equal(0);
	});

	it('a refused renewal attempts every input and keeps the reservation (issue #626)', async function () {
		// A renewal has nothing to abort: the transaction exists and the node
		// still owes its broadcast. One input the wallet will not freeze says
		// nothing about the next, and forgetting the reservation would hand the
		// coin to the very selection that must not have it.
		const { wallet, utxos, payment } = makeWallet([100_000, 100_000]);
		const retained = new bitcoin.Transaction();
		retained.version = 2;
		for (const u of utxos) {
			retained.addInput(Buffer.from(u.tx_hash, 'hex').reverse(), u.tx_pos);
		}
		retained.addOutput(payment.output!, 190_000);

		const attempted: string[] = [];
		(wallet as { freezeUtxo: unknown }).freezeUtxo = async (p: {
			txid: string;
			index: number;
		}) => {
			attempted.push(`${p.txid}:${p.index}`);
			return errResult('storage is down');
		};

		const provider = new WalletFundingProvider(wallet as never);
		let error = '';
		try {
			await provider.pledgeTransactionInputs(retained.toHex());
		} catch (e) {
			error = (e as Error).message;
		}
		// Reported, so the node logs it and the next block renews again.
		expect(error).to.include('Failed to reserve retained transaction inputs');
		expect(attempted).to.deep.equal([
			`${utxos[0].tx_hash}:0`,
			`${utxos[1].tx_hash}:0`
		]);

		const pledged = (provider as unknown as { pledged: Map<string, number> })
			.pledged;
		expect([...pledged.keys()].sort()).to.deep.equal(
			[`${utxos[0].tx_hash}:0`, `${utxos[1].tx_hash}:0`].sort()
		);
		let selectError = '';
		try {
			await provider.selectSpliceInputs!(50_000n, 1000);
		} catch (e) {
			selectError = (e as Error).message;
		}
		expect(selectError).to.include('insufficient wallet funds');
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

	describe('releaseInputPledges (issue #311)', function () {
		const asOutpoint = (op: string): { txid: string; vout: number } => {
			const sep = op.lastIndexOf(':');
			return { txid: op.slice(0, sep), vout: Number(op.slice(sep + 1)) };
		};

		it('releases a selection pledge so the coin is selectable at once', async function () {
			const { wallet, unfrozenLog } = makeWallet([100_000, 100_000]);
			const provider = new WalletFundingProvider(wallet as never);

			const { inputs } = await provider.selectSpliceInputs!(150_000n, 1000);
			const pledgedOps = outpoints(inputs);
			expect(pledgedOps.length).to.equal(2);
			// The wallet is exhausted while the pledges stand.
			let error = '';
			try {
				await provider.selectSpliceInputs!(80_000n, 1000);
			} catch (e) {
				error = (e as Error).message;
			}
			expect(error).to.contain('insufficient wallet funds');

			// The open died before anything was signed: release returns the
			// coins to the pool immediately, no TTL wait.
			await provider.releaseInputPledges(pledgedOps.map(asOutpoint));
			expect(unfrozenLog.sort()).to.deep.equal([...pledgedOps].sort());
			const next = await provider.selectSpliceInputs!(80_000n, 1000);
			expect(next.inputs.length).to.be.greaterThan(0);
		});

		it('releasing one open leaves a concurrent open pledged', async function () {
			const { wallet } = makeWallet([100_000, 100_000, 100_000, 100_000]);
			const provider = new WalletFundingProvider(wallet as never);

			const first = await provider.selectSpliceInputs!(80_000n, 1000);
			const second = await provider.selectSpliceInputs!(80_000n, 1000);
			const firstOps = outpoints(first.inputs);
			const secondOps = outpoints(second.inputs);

			await provider.releaseInputPledges(firstOps.map(asOutpoint));

			// A follow-up selection may reuse the released coins but never the
			// still-pledged ones.
			const next = await provider.selectSpliceInputs!(80_000n, 1000);
			for (const op of outpoints(next.inputs)) {
				expect(secondOps, 'concurrent pledge survived').to.not.include(op);
			}
		});

		it('ignores unknown outpoints, tolerates a double release, never touches user freezes', async function () {
			const { wallet, utxos, frozen, unfrozenLog } = makeWallet([
				100_000, 100_000
			]);
			// User froze coin 1 with no tag.
			await wallet.freezeUtxo({ txid: utxos[1].tx_hash, index: 0 });

			const provider = new WalletFundingProvider(wallet as never);
			const { inputs } = await provider.selectSpliceInputs!(80_000n, 1000);
			const pledgedOps = outpoints(inputs).map(asOutpoint);

			const releaseAll = [
				...pledgedOps,
				{ txid: utxos[1].tx_hash, vout: 0 },
				{ txid: crypto.randomBytes(32).toString('hex'), vout: 7 }
			];
			await provider.releaseInputPledges(releaseAll);
			await provider.releaseInputPledges(releaseAll);

			expect(unfrozenLog).to.deep.equal(
				pledgedOps.map((o) => `${o.txid}:${o.vout}`)
			);
			expect(
				frozen.has(`${utxos[1].tx_hash}:0`),
				'user freeze untouched'
			).to.equal(true);
		});

		it('a renewal after a racing release re-freezes the coin', async function () {
			const { wallet, utxos, frozen, payment } = makeWallet([100_000, 100_000]);
			const key = `${utxos[0].tx_hash}:0`;
			const spend = new bitcoin.Transaction();
			spend.version = 2;
			spend.addInput(
				Buffer.from(utxos[0].tx_hash, 'hex').reverse(),
				utxos[0].tx_pos
			);
			spend.addOutput(payment.output!, 90_000);
			wallet.send = async () => ok(spend.toHex());

			const provider = new WalletFundingProvider(wallet as never);
			await provider.buildFundingTransaction(payment.address!, 90_000n);
			await provider.releaseInputPledges([asOutpoint(key)]);
			expect(frozen.has(key)).to.equal(false);

			// The broadcast obligation still stands: the per-block renewal wins.
			await provider.pledgeTransactionInputs(spend.toHex());
			expect(frozen.has(key)).to.equal(true);
		});

		it('releases a stale tagged pledge persisted by a previous run', async function () {
			const { wallet, utxos, frozen, unfrozenLog } = makeWallet([
				100_000, 100_000
			]);
			const key = `${utxos[0].tx_hash}:0`;
			// A pledge freeze from a crashed run, still fresh (2 minutes old).
			frozen.set(key, {
				tx_hash: utxos[0].tx_hash,
				tx_pos: 0,
				freezeTag: 'funding-pledge',
				frozenAt: Date.now() - 2 * 60_000
			});

			const provider = new WalletFundingProvider(wallet as never);
			await provider.releaseInputPledges([asOutpoint(key)]);
			expect(unfrozenLog).to.deep.equal([key]);
			expect(frozen.has(key)).to.equal(false);
		});

		it('a refused release keeps the pledge so a retry can lift it (issue #626)', async function () {
			const { wallet, frozen, unfrozenLog } = makeWallet([100_000, 100_000]);
			const provider = new WalletFundingProvider(wallet as never);
			const { inputs } = await provider.selectSpliceInputs!(150_000n, 1000);
			const pledgedOps = outpoints(inputs).map(asOutpoint);
			expect(pledgedOps.length).to.equal(2);

			const realUnfreeze = wallet.unfreezeUtxo;
			(wallet as { unfreezeUtxo: unknown }).unfreezeUtxo = async () =>
				errResult('storage is down');
			await provider.releaseInputPledges(pledgedOps);

			// Nothing was released, so nothing may be forgotten: only this map
			// knows the freezes still holding the coins are ours to lift.
			const pledged = (provider as unknown as { pledged: Map<string, number> })
				.pledged;
			expect(pledged.size).to.equal(2);
			expect(frozen.size).to.equal(2);
			expect(unfrozenLog).to.deep.equal([]);

			// Storage recovers and the next prune finishes the release without a
			// second call from the caller.
			(wallet as { unfreezeUtxo: unknown }).unfreezeUtxo = realUnfreeze;
			await provider.selectSpliceInputs!(80_000n, 1000);
			expect(unfrozenLog.sort()).to.deep.equal(
				pledgedOps.map((o) => `${o.txid}:${o.vout}`).sort()
			);
		});

		it('a refused prune unfreeze retries on the next prune (issue #626)', async function () {
			const { wallet, utxos, frozen, payment } = makeWallet([
				100_000, 100_000, 100_000
			]);
			const key = `${utxos[0].tx_hash}:0`;
			const spend = new bitcoin.Transaction();
			spend.version = 2;
			spend.addInput(
				Buffer.from(utxos[0].tx_hash, 'hex').reverse(),
				utxos[0].tx_pos
			);
			spend.addOutput(payment.output!, 90_000);
			wallet.send = async () => ok(spend.toHex());

			const provider = new WalletFundingProvider(wallet as never);
			await provider.buildFundingTransaction(payment.address!, 90_000n);
			expect(frozen.has(key)).to.equal(true);

			// The funding confirmed, so the pledge is due to be pruned, but the
			// wallet refuses the write that would lift it.
			utxos.splice(0, 1);
			const realUnfreeze = wallet.unfreezeUtxo;
			(wallet as { unfreezeUtxo: unknown }).unfreezeUtxo = async () =>
				errResult('storage is down');
			await provider.selectSpliceInputs!(50_000n, 1000);
			const pledged = (provider as unknown as { pledged: Map<string, number> })
				.pledged;
			expect(frozen.has(key), 'the coin is still frozen').to.equal(true);
			expect(pledged.has(key), 'kept for the retry').to.equal(true);

			(wallet as { unfreezeUtxo: unknown }).unfreezeUtxo = realUnfreeze;
			await provider.selectSpliceInputs!(50_000n, 1000);
			expect(frozen.has(key)).to.equal(false);
			expect(pledged.has(key)).to.equal(false);
		});
	});
});
