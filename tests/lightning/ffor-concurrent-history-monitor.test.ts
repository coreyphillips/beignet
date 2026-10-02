import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import { CommitmentType, OutputType } from '../../src/lightning/chain/types';
import { HtlcDirection } from '../../src/lightning/channel/types';
import { FforState } from '../../src/lightning/ffor/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import { record, REGTEST, TIP } from './helpers/ffor-world';

describe('Concurrent archived history reaches a fresh monitor', function () {
	this.timeout(60000);
	for (const version of [1, 2] as const)
		for (const owner of ['S', 'R'] as const)
			for (const generation of ['activation', 'mixed'] as const) {
				it(`version ${version}, ${owner} ${generation} history retains exact outputs after retirement and cold reload`, () => {
					const directory = fs.mkdtempSync(
						path.join(os.tmpdir(), 'ffor-history-monitor-')
					);
					const file = path.join(directory, 'observer.sqlite');
					let storage = new SqliteStorage(file);
					storage.open();
					const w = createConcurrentWorld(
						owner === 'S' ? { rStorage: storage } : { sStorage: storage }
					);
					let restored: LightningNode | undefined;
					try {
						activateWorld(w, true, [10000000n, 20000000n], version);
						const source = owner === 'S' ? w.s : w.r;
						const observer = owner === 'S' ? w.r : w.s;
						const config = owner === 'S' ? w.rConfig : w.sConfig;
						const ordinary = w.r.createInvoice({
							amountMsat: 5000000n,
							description: 'archived ordinary output',
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
						const expected = [
							...observer
								.getChannelManager()
								.getChannel(w.srChannelId)!
								.getFullState()
								.htlcs.values()
						].map((htlc) => ({
							hash: htlc.paymentHash.toString('hex'),
							amount: htlc.amountMsat / 1000n,
							expiry: htlc.cltvExpiry,
							direction: htlc.direction
						}));
						expect(expected).to.have.length(generation === 'mixed' ? 3 : 2);
						if (generation === 'mixed')
							expect(w.r.settleHeldHtlc(ordinary.paymentHash)).to.be.true;
						else {
							const invoice = w.r.createInvoice({
								amountMsat: 1000000n,
								description: 'advance commitment history'
							});
							expect(w.s.sendPayment(invoice.bolt11).status).to.equal(
								PaymentStatus.COMPLETED
							);
						}
						const proofs = record(w.s, w.srHex).preimages.map((proof) =>
							Buffer.from(proof)
						);
						expect(w.r.fforAddPreimage(w.srHex, proofs[0]).ok).to.be.true;
						expect(w.r.closeFforEpoch(w.srHex).ok).to.be.true;
						if (version === 2)
							expect(w.r.fforAddPreimage(w.srHex, proofs[1]).ok).to.be.true;
						expect(record(w.r, w.srHex).state).to.equal(FforState.CLOSED);
						activateWorld(w, false, [3000000n]);
						const history = observer
							.getChannelManager()
							.getChannel(w.srChannelId)!
							.getFullState().revokedHtlcSnapshots!;
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
							restored
								.getChannelManager()
								.getChannel(w.srChannelId)!
								.getFullState().revokedHtlcSnapshots
						).to.deep.equal(history);
						expect(
							restored.getChannelManager().getMonitor(w.srChannelId)
						).to.equal(undefined);
						// This checks local archive-to-monitor reconstruction only. No transaction is published.
						restored
							.getChannelManager()
							.handleFundingSpent(
								w.srChannelId,
								historical,
								TIP + 1,
								Buffer.concat([Buffer.from([0, 20]), Buffer.alloc(20, 7)]),
								10,
								undefined,
								undefined,
								REGTEST
							);
						const monitor = restored
							.getChannelManager()
							.getMonitor(w.srChannelId)!;
						expect(
							monitor.getFullState().commitmentBroadcast?.commitmentType
						).to.equal(CommitmentType.THEIR_REVOKED_COMMITMENT);
						const actual = monitor
							.getTrackedOutputs()
							.filter((output) => output.paymentHash)
							.map((output) => ({
								hash: output.paymentHash!.toString('hex'),
								amount: output.amount,
								expiry: output.cltvExpiry,
								direction:
									output.outputType === OutputType.RECEIVED_HTLC
										? HtlcDirection.RECEIVED
										: HtlcDirection.OFFERED
							}));
						expect(actual).to.have.deep.members(expected);
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
