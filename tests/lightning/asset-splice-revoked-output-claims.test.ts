import { strict as assert } from 'assert';
import { Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ecc } from '../../src/utils/ecc';
import {
	assetPayoutRevocationKey,
	type IAssetOpeningPayout,
	type IAuxiliaryDualFunding
} from '../../src/lightning/channel';
import { assetOpeningOutputClaims } from '../../src/lightning/chain/asset-opening-claims';
import {
	setupFundedAssetUpdatePair,
	assetUpdateTestHost
} from './helpers/asset-splice-update';

describe('observed balance outputs on either live splice funding', function () {
	this.timeout(90000);
	it('offers the defender two separately bound claims only after the peer discloses the matching secret', async () => {
		const dir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'splice-protective-claims-')
		);
		const { f } = await setupFundedAssetUpdatePair(dir, 5);
		const id = Buffer.from(f.id, 'hex');
		const destination = Buffer.from('0014' + 'cd'.repeat(20), 'hex');
		const assetId = '4c'.repeat(32);
		const digest = Buffer.alloc(32, 31);
		try {
			const runtime = {
				storage: f.devices[0].store,
				root: f.devices[0].party.root
			};
			const observe = (parent: Transaction, provider?: IAuxiliaryDualFunding) =>
				assetOpeningOutputClaims(runtime, id, parent, destination, 1, provider);
			const previous = f.views[1];
			for (const branch of ['parent', 'candidate'] as const)
				assert.equal(observe(previous[branch].expected).length, 1);

			const batch = f.devices.map(({ store, party }, i) =>
				store.assetSpliceUpdateBatch(
					f.id,
					party.root,
					1n,
					[
						{
							kind: 'add',
							htlc: {
								offeredBy: i === 0 ? 'local' : 'peer',
								id: 0n,
								amountMsat: 5000000n,
								cltvExpiry: 601000,
								paymentHash: Buffer.alloc(32, 17),
								allocations: [{ assetId, units: 3n }]
							}
						}
					],
					() => 600900
				)
			);
			const hosts = [assetUpdateTestHost(0), assetUpdateTestHost(1)];
			const offers = batch.map((b) => b.offer());
			batch.forEach((b, i) => b.acceptOffer(offers[1 - i]));
			const shares = (await Promise.all(
				batch.map((b, i) => b.signAssetShares(hosts[i]))
			)) as [Buffer, Buffer];
			const htlcs = (await Promise.all(
				batch.map((b, i) => b.signAssetHtlcs(hosts[i], shares))
			)) as [Buffer, Buffer];
			await Promise.all(
				batch.map((b, i) => b.verifyAssetShares(hosts[i], shares, htlcs))
			);
			const commits = batch.map((b) => b.commitments());
			await Promise.all(
				batch.map((b, i) => b.acceptCommitments(hosts[i], commits[1 - i]))
			);
			assert.equal(observe(previous.candidate.expected).length, 1);
			const revocations = batch.map((b) => b.revocation());
			batch.forEach((b, i) => b.receiveRevocation(revocations[1 - i]));

			for (const branch of ['parent', 'candidate'] as const) {
				const record = previous[branch];
				const observed = record.expected;
				assert(!observed.hasWitnesses());
				const mismatch = observed.clone();
				mismatch.ins[0].index++;
				assert.deepEqual(observe(mismatch), []);
				assert.deepEqual(observe(f.views[0][branch].expected), []);
				const calls: number[] = [];
				let signer: NonNullable<IAssetOpeningPayout['revocation']> | undefined;
				const provider = {
					assetSpliceRecoveryVersion: 1,
					outputRecoveryReceipt(
						channelId: string,
						parentTxid: string,
						outputIndex: number,
						payout: Transaction
					) {
						assert.equal(channelId, f.id);
						assert.equal(parentTxid, observed.getId());
						assert.equal(payout.ins[0].index, outputIndex);
						return Buffer.from(payout.getId(), 'hex');
					},
					async restoreOutputReceipt(
						channelId: string,
						parentTxid: string,
						outputIndex: number,
						payout: Transaction,
						receipt: Buffer
					) {
						assert.equal(channelId, f.id);
						assert.equal(parentTxid, observed.getId());
						assert.equal(payout.ins[0].index, outputIndex);
						assert.equal(receipt.toString('hex'), payout.getId());
					},
					async recoverOutput(ctx: IAssetOpeningPayout) {
						calls.push(ctx.outputIndex);
						assert.notStrictEqual(ctx.parent.ins[0].hash, observed.ins[0].hash);
						assert.notStrictEqual(
							ctx.parent.ins[0].witness,
							observed.ins[0].witness
						);
						assert.notStrictEqual(
							ctx.parent.outs[ctx.outputIndex].script,
							observed.outs[ctx.outputIndex].script
						);
						assert.equal(ctx.walletGeneration, 5);
						assert.equal(ctx.holder, 'remote');
						const scope = ctx.virtualPayout;
						assert(scope);
						assert.equal(scope.channelId, f.id);
						assert.equal(scope.stateNumber, '0');
						assert.equal(
							scope.fundingTxid,
							Buffer.from(observed.ins[0].hash).reverse().toString('hex')
						);
						assert.equal(scope.fundingOutputIndex, observed.ins[0].index);
						if (ctx.outputIndex === record.outputMap.toLocal) {
							signer = ctx.revocation;
							assert(signer);
							const signature = signer.signVirtual(assetId, digest);
							assert(
								ecc.verifySchnorr(
									digest,
									assetPayoutRevocationKey(scope, assetId).subarray(1),
									signature
								)
							);
							assert(
								!ecc.verifySchnorr(
									digest,
									scope.revocationPubkey.subarray(1),
									signature
								)
							);
							assert.throws(() =>
								signer!.signVirtual(assetId, Buffer.alloc(31))
							);
						} else {
							assert.equal(ctx.outputIndex, record.outputMap.toRemote);
							assert.equal(ctx.revocation, undefined);
						}
						const sweep = new Transaction();
						sweep.version = 2;
						sweep.addInput(observed.getHash(), ctx.outputIndex, ctx.delay);
						sweep.addOutput(
							destination,
							observed.outs[ctx.outputIndex].value - 400
						);
						sweep.setWitness(0, ctx.signSweep(sweep, [observed]));
						return sweep;
					}
				} as unknown as IAuxiliaryDualFunding;
				const claims = observe(observed, provider);
				assert.equal(claims.length, 2);
				const txs = await Promise.all(claims.map((c) => c.recover!()));
				assert.deepEqual(
					calls.sort(),
					[record.outputMap.toLocal!, record.outputMap.toRemote!].sort()
				);
				assert.equal(new Set(txs.map((tx) => tx!.getId())).size, 2);
				assert(signer);
				assert.throws(() => signer!.signVirtual(assetId, digest));
				const replayed = await Promise.all(
					observe(observed, provider).map((c) => c.recover!())
				);
				assert.deepEqual(
					replayed.map((tx) => tx!.toHex()),
					txs.map((tx) => tx!.toHex())
				);
				assert.equal(calls.length, 2);
			}
		} finally {
			for (const d of f.devices) d.store.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
