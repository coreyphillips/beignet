import { strict as assert } from 'assert';
import sinon from 'sinon';
import { walletSigner } from './helpers/final-update-pair';
import {
	classifyRemoteFundingInput,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';
import type { Electrum } from '../../src/electrum';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Transaction } from 'bitcoinjs-lib';
import type { IAssetSpliceSigningHost } from '../../src/lightning/channel/asset-splice-signature-round';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

import { signatureRoundFixture as setup } from './helpers/asset-splice-signature-round';
describe('asset splice Bitcoin commit and funding signature round', () => {
	let dir: string, t: ReturnType<typeof setup>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-round-'));
		t = setup(dir);
	});
	afterEach(() => {
		for (const d of t?.f.devices ?? []) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	async function commits(checkReceipt = false) {
		t.construct();
		const [a, b] = [t.round(0), t.round(1)];
		const shares = (await Promise.all([
			a.signExitShares(t.hosts[0], t.ctx(0)),
			b.signExitShares(t.hosts[1], t.ctx(1))
		])) as [Buffer, Buffer];
		const left = await a.verifyExitShares(t.hosts[0], t.ctx(0), shares),
			right = await b.verifyExitShares(t.hosts[1], t.ctx(1), shares);
		assert.throws(() => a.commitmentSigned(right));
		const ours = a.commitmentSigned(left),
			theirs = b.commitmentSigned(right);
		const corrupt = Buffer.from(theirs);
		corrupt[corrupt.length - 1] ^= 1;
		assert.throws(() => a.acceptCommitmentSigned(left, corrupt));
		const as = a.acceptCommitmentSigned(left, theirs),
			bs = b.acceptCommitmentSigned(right, ours);
		assert.equal(as.length > 0 && bs.length > 0, true);
		if (checkReceipt)
			for (const change of ['depth', 'proof'] as const) {
				const host = {
					...t.hosts[0],
					async retainSpliceExits(
						...args: Parameters<IAssetSpliceSigningHost['retainSpliceExits']>
					) {
						const receipt = await t.hosts[0].retainSpliceExits(...args);
						if (change === 'depth')
							receipt.minimumDepth = receipt.candidate.minimumDepth = 1;
						else receipt.candidate.fundingProofs = 'cc';
						return receipt;
					}
				};
				await assert.rejects(() => a.retainExits(host, t.ctx(0), left));
			}
		const receipts = await Promise.all([
			a.retainExits(t.hosts[0], t.ctx(0), left),
			b.retainExits(t.hosts[1], t.ctx(1), right)
		]);
		assert.equal(receipts[0].candidate.localCommitment, as.toString('hex'));
		assert.equal(receipts[1].candidate.localCommitment, bs.toString('hex'));
		return { a, b, left, right };
	}
	it('builds both original-device enforceable exits, enforces input value ordering and verifies a fully witnessed splice after restart', async () => {
		const { a, b } = await commits(true);
		const unspent = async () => 'unspent' as const;
		assert.equal(await a.nextFunding(t.hosts[0], t.ctx(0), unspent), undefined);
		const first = await b.nextFunding(t.hosts[1], t.ctx(1), unspent);
		assert(first);
		a.receiveFunding(first);
		const queries: string[] = [];
		const second = await a.nextFunding(t.hosts[0], t.ctx(0), async (coin) => {
			queries.push(coin.txid.toString('hex'));
			return 'unspent';
		});
		assert(second);
		b.receiveFunding(second);
		b.receiveFunding(second);
		assert.equal(queries.length, t.s.tx.ins.length);
		assert.deepEqual(t.f.calls, [1]);
		const signed = a.transaction() as Transaction;
		assert.equal(signed.toHex(), b.transaction()?.toHex());
		assert.equal(signed.getId(), t.s.tx.getId());
		assert(signed.ins.every((v) => v.witness.length > 0));
		const independent = a.transaction()!;
		independent.outs[0].script.fill(0);
		assert.equal(a.transaction()?.toHex(), signed.toHex());
		const device = t.f.devices[0];
		device.store.close();
		device.store = SqliteStorage.openFinalWallet(
			device.file,
			device.party.binding
		);
		const restored = t.round(0);
		assert.equal(restored.transaction()?.toHex(), signed.toHex());
		assert.deepEqual(
			await restored.nextFunding(t.hosts[0], t.ctx(0), async () => {
				throw Error('unexpected fresh signature');
			}),
			second
		);
	});
	it('recovers the already released witness and the peer response after the funding output has been spent', async () => {
		const { a, b } = await commits();
		const attempt = t.s.layout.attempt.toString('hex');
		const device = t.f.devices[1];
		assert.equal(device.store.releasedAssetSplice(t.f.id, attempt), undefined);
		const first = await b.nextFunding(
			t.hosts[1],
			t.ctx(1),
			async () => 'unspent'
		);
		assert(first);
		a.receiveFunding(first);
		const second = await a.nextFunding(
			t.hosts[0],
			t.ctx(0),
			async () => 'unspent'
		);
		assert(second);
		device.store.close();
		device.store = SqliteStorage.openFinalWallet(
			device.file,
			device.party.binding
		);
		assert.equal(
			device.store.releasedAssetSplice(t.f.id, '01'.repeat(32)),
			undefined
		);
		const resumed = device.store.releasedAssetSplice(t.f.id, attempt);
		assert(resumed);
		assert.deepEqual(resumed.wire, first);
		assert.equal(resumed.transaction(), undefined);
		assert.throws(() => resumed.receive(first));
		const altered = Buffer.from(second);
		altered[altered.length - 1] ^= 1;
		assert.throws(() => resumed.receive(altered));
		resumed.receive(second);
		resumed.receive(second);
		assert.deepEqual(resumed.transaction()?.toHex(), a.transaction()?.toHex());
		assert.equal(
			device.store.releasedAssetSplice(t.f.id, attempt)?.transaction()?.getId(),
			t.s.tx.getId()
		);
	});
	it('declines a verified exit handle when the live generation changes before a Bitcoin commitment share', async () => {
		t.construct();
		const a = t.round(0),
			initial = t.ctx(0);
		let available = true;
		const ctx = {
			...initial,
			currentParent: () => (available ? initial.currentParent() : undefined)
		};
		const checked = await a.verifyExitShares(t.hosts[0], ctx, t.raw);
		available = false;
		assert.throws(() => a.commitmentSigned(checked));
	});
	for (const outcome of [
		'unspent',
		'spent',
		'unknown',
		'parent changed'
	] as const) {
		it(
			'rechecks the funding input set after a lost Electrum read on restart: ' +
				outcome,
			async () => {
				const { a, b } = await commits();
				const first = await b.nextFunding(
					t.hosts[1],
					t.ctx(1),
					async () => 'unspent'
				);
				assert(first);
				a.receiveFunding(first);
				const device = t.f.devices[0];
				device.store.close();
				device.store = SqliteStorage.openFinalWallet(
					device.file,
					device.party.binding
				);
				const round = t.round(0),
					initial = t.ctx(0);
				const candidate = t.s.verified[0].candidate;
				const coins = candidate.tx.ins.map((coin, i) => ({
					script: computeScriptHash(candidate.scripts[i]),
					txid: Buffer.from(coin.hash).reverse().toString('hex'),
					vout: coin.index,
					value: candidate.values[i]
				}));
				assert(coins.length >= 2);
				assert.notEqual(coins[0].script, coins[1].script);
				const reads: string[] = [];
				const calls = (script: string) =>
					reads.filter((s) => s === script).length;
				let connected = true;
				const source = {
					connectedToElectrum: true,
					async listUnspentAddressScriptHashes({
						addresses,
						rejectFailedEntries
					}: {
						addresses: Record<string, unknown>;
						rejectFailedEntries: boolean;
					}) {
						assert.equal(rejectFailedEntries, true);
						const [script] = Object.keys(addresses);
						reads.push(script);
						const owned = coins.filter((c) => c.script === script);
						assert(owned.length);
						if (
							script === coins[1].script &&
							(calls(script) === 1 || outcome === 'unknown')
						) {
							if (outcome === 'parent changed')
								setTimeout(() => {
									connected = false;
								}, 1);
							return {
								isErr: () => true,
								error: new Error('Connection to server lost, please retry')
							};
						}
						const spent =
							outcome === 'spent' &&
							script === coins[0].script &&
							calls(script) > 1;
						return {
							isErr: () => false,
							value: {
								utxos: spent
									? []
									: owned.map((c) => ({
											tx_hash: c.txid,
											tx_pos: c.vout,
											value: c.value,
											height: 831
									  }))
							}
						};
					},
					async getAddressScriptHashesHistory([script]: string[]) {
						return {
							isErr: () => false,
							value: {
								data: [
									{
										result: coins
											.filter((c) => c.script === script)
											.map((c) => ({ tx_hash: c.txid, height: 831 }))
									}
								]
							}
						};
					}
				};
				const backend = new ElectrumBackend(source as unknown as Electrum);
				const before = device.store.readAssetSpliceJournal(t.f.id);
				const ctx = {
					...initial,
					currentParent: () => (connected ? initial.currentParent() : undefined)
				};
				let signed = false;
				const host = {
					...t.hosts[0],
					async signSpliceFunding(
						...args: Parameters<IAssetSpliceSigningHost['signSpliceFunding']>
					) {
						signed = true;
						const [, , tx, indices, prevouts] = args;
						return walletSigner(device.party.keys.fundingPrivkey, 1, t.f.calls)(
							tx,
							indices,
							prevouts
						);
					}
				};
				const clock = sinon.useFakeTimers({
					toFake: ['setTimeout', 'clearTimeout']
				});
				try {
					const funding = round.nextFunding(host, ctx, (coin) =>
						classifyRemoteFundingInput(backend, {
							txidDisplayHex: Buffer.from(coin.txid).reverse().toString('hex'),
							vout: coin.vout,
							scriptPubKey: coin.scriptPubKey
						})
					);
					const result =
						outcome === 'unspent'
							? funding.then((wire) => assert(wire))
							: assert.rejects(funding);
					await Promise.all([result, clock.runAllAsync()]);
					assert.equal(signed, outcome === 'unspent');
					if (outcome === 'unspent') {
						assert.equal(calls(coins[1].script), 2);
						assert.deepEqual(
							reads.slice(-coins.length),
							coins.map((c) => c.script)
						);
					} else {
						assert.deepEqual(
							device.store.readAssetSpliceJournal(t.f.id),
							before
						);
						if (outcome === 'spent')
							assert.equal(reads.at(-1), coins[0].script);
						if (outcome === 'parent changed')
							assert.equal(calls(coins[1].script), 1);
						if (outcome === 'unknown')
							assert(calls(coins[1].script) > 1 && calls(coins[1].script) <= 5);
					}
				} finally {
					clock.restore();
				}
			}
		);
	}
	it('declines early, conflicting and spent inputs without releasing wallet signatures', async () => {
		const original = t.round(0);
		await assert.rejects(() => original.signExitShares(t.hosts[0], t.ctx(0)));
		const { a, b } = await commits();
		const before = t.f.devices[1].store.readAssetSpliceJournal(t.f.id);
		await assert.rejects(() =>
			b.nextFunding(t.hosts[1], t.ctx(1), async () => 'spent')
		);
		assert.deepEqual(
			t.f.devices[1].store.readAssetSpliceJournal(t.f.id),
			before
		);
		const first = await b.nextFunding(
			t.hosts[1],
			t.ctx(1),
			async () => 'unspent'
		);
		assert(first);
		const changed = Buffer.from(first);
		changed[changed.length - 1] ^= 1;
		assert.throws(() => a.receiveFunding(changed));
		a.receiveFunding(first);
		const clock = sinon.useFakeTimers({
			toFake: ['setTimeout', 'clearTimeout']
		});
		try {
			await Promise.all([
				assert.rejects(() =>
					a.nextFunding(t.hosts[0], t.ctx(0), async () => 'unknown')
				),
				clock.runAllAsync()
			]);
		} finally {
			clock.restore();
		}
		assert.deepEqual(t.f.calls, []);
	});
});
