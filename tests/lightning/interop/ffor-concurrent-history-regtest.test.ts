import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import { CommitmentType } from '../../../src/lightning/chain/types';
import {
	FF_RECONCILE_MARGIN_BLOCKS,
	FforState
} from '../../../src/lightning/ffor/types';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../../src/lightning/node/types';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { record, REGTEST } from '../helpers/ffor-world';
import { bitcoinRpc } from './shared-helpers';
import {
	bitcoindUp,
	regtestWorld,
	taps,
	spends,
	waitFor
} from './ffor-concurrent-helpers';

describe('Concurrent historical claim package qualification on regtest', function () {
	this.timeout(600000);
	before(async () => {
		if (!(await bitcoindUp())) throw Error('Bitcoin Core regtest is required');
	});
	for (const version of [1, 2] as const)
		for (const owner of ['S', 'R'] as const)
			for (const generation of ['activation', 'mixed'] as const) {
				it(`version ${version}, ${owner} ${generation}: cold history reconstructs valid protective claims without publication`, async () => {
					const directory = fs.mkdtempSync(
						path.join(os.tmpdir(), 'ffor-history-regtest-')
					);
					const file = path.join(directory, 'observer.sqlite');
					let storage = new SqliteStorage(file);
					storage.open();
					const rw = await regtestWorld({
						concurrent: true,
						srPushMsat: 200000000n,
						feeInputs: 0,
						...(owner === 'S' ? { rStorage: storage } : { sStorage: storage })
					});
					const { w, chain } = rw;
					let restored: LightningNode | undefined;
					try {
						expect(
							w.r.startFforEpoch(w.srHex, {
								voucherAmountsMsat: [100000000n, 100000000n],
								minPaymentMsat: 100000000n,
								settlementDeadline: chain.height + 200,
								voucherExpiry: chain.height + 200 + FF_RECONCILE_MARGIN_BLOCKS,
								feeBaseMsat: 1000,
								feeProportionalMillionths: 5000,
								concurrent: true,
								concurrentVersion: version
							}).ok
						).to.be.true;
						for (const node of [w.s, w.r]) {
							const epoch = record(node, w.srHex);
							expect(epoch.state).to.equal(FforState.ACTIVE);
							expect(epoch.concurrentVersion).to.equal(version);
							expect(epoch.paymentHashes).to.have.length(2);
						}
						const voucherHashes = record(w.r, w.srHex).paymentHashes.map(
							(hash) => hash.toString('hex')
						);
						const source = owner === 'S' ? w.s : w.r;
						const observer = owner === 'S' ? w.r : w.s;
						const config = owner === 'S' ? w.rConfig : w.sConfig;
						const destination = owner === 'S' ? rw.rDest : rw.sDest;
						const ordinary = w.r.createInvoice({
							amountMsat: 5000000n,
							description: 'historical ordinary payment',
							hold: true
						});
						if (generation === 'mixed')
							expect(w.s.sendPayment(ordinary.bolt11).status).to.equal(
								PaymentStatus.PENDING
							);
						const sourceChannel = source
							.getChannelManager()
							.getChannel(w.srChannelId)!;
						const plan = sourceChannel.prepareForceClose(
							sourceChannel.getSigner()!,
							{}
						);
						expect(plan.ok).to.be.true;
						if (!plan.ok) throw Error(plan.error);
						const historical = bitcoin.Transaction.fromBuffer(
							plan.commitmentTx
						);
						const hashes = [
							...observer
								.getChannelManager()
								.getChannel(w.srChannelId)!
								.getFullState()
								.htlcs.values()
						].map((htlc) => htlc.paymentHash.toString('hex'));
						expect(hashes).to.have.members(
							generation === 'mixed'
								? [...voucherHashes, ordinary.paymentHash.toString('hex')]
								: voucherHashes
						);
						if (generation === 'mixed')
							expect(w.r.settleHeldHtlc(ordinary.paymentHash)).to.be.true;
						else {
							const advance = w.r.createInvoice({
								amountMsat: 1000000n,
								description: 'advance past activation'
							});
							expect(w.s.sendPayment(advance.bolt11).status).to.equal(
								PaymentStatus.COMPLETED
							);
						}
						w.ps.disconnect();
						w.sr.disconnect();
						w.p.destroy();
						w.s.destroy();
						w.r.destroy();
						storage.close();
						storage = new SqliteStorage(file);
						storage.open();
						restored = new LightningNode({ ...config, storage });
						expect(
							restored.getChannelManager().getMonitor(w.srChannelId)
						).to.equal(undefined);
						const claims = taps(restored);
						// Only the local monitor observes this archived fixture. The parent and
						// protective children go through Core's read-only package validation.
						restored
							.getChannelManager()
							.handleFundingSpent(
								w.srChannelId,
								historical,
								chain.height + 1,
								destination,
								10,
								undefined,
								undefined,
								REGTEST
							);
						restored.handleNewBlock(chain.height + 2);
						const monitor = restored
							.getChannelManager()
							.getMonitor(w.srChannelId)!;
						expect(
							monitor.getFullState().commitmentBroadcast?.commitmentType
						).to.equal(CommitmentType.THEIR_REVOKED_COMMITMENT);
						const outputs = monitor
							.getTrackedOutputs()
							.filter(
								(output) =>
									output.paymentHash &&
									hashes.includes(output.paymentHash.toString('hex'))
							);
						expect(
							outputs.map((output) => output.paymentHash!.toString('hex'))
						).to.have.members(hashes);
						const validated = new Set<string>();
						for (const output of outputs) {
							const claim = await waitFor(
								() =>
									claims.find((tx) =>
										spends(tx, historical, output.outputIndex)
									),
								'protective archived HTLC claim'
							);
							if (validated.has(claim.getId())) continue;
							expect(claim.outs).to.have.length(1);
							expect(Buffer.from(claim.outs[0].script).equals(destination)).to
								.be.true;
							const protectedValue = claim.ins
								.filter((input) =>
									Buffer.from(input.hash).equals(historical.getHash())
								)
								.reduce(
									(total, input) =>
										total + BigInt(historical.outs[input.index].value),
									0n
								);
							expect(BigInt(claim.outs[0].value) > protectedValue - 10000n).to
								.be.true;
							const results = (await bitcoinRpc('testmempoolaccept', [
								[historical.toHex(), claim.toHex()]
							])) as {
								allowed?: boolean;
								'reject-reason'?: string;
								'package-error'?: string;
							}[];
							expect(results).to.have.length(2);
							for (const result of results)
								expect(result.allowed, JSON.stringify(result)).to.be.true;
							validated.add(claim.getId());
						}
						expect(validated.size).to.be.greaterThan(0);
						console.log(
							JSON.stringify({
								version,
								owner,
								generation,
								fundingTxid: rw.fundingTx.getId(),
								historicalTxid: historical.getId(),
								protectedHtlcs: outputs.length,
								validatedClaims: validated.size,
								published: false
							})
						);
					} finally {
						restored?.destroy();
						w.p.destroy();
						w.s.destroy();
						w.r.destroy();
						storage.close();
						fs.rmSync(directory, { recursive: true, force: true });
					}
				});
			}
});
