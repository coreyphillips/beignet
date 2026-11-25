import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Transaction } from 'bitcoinjs-lib';
import type {
	IAssetOpeningHtlcPayout,
	IAssetOpeningPayout,
	IAuxiliaryDualFunding
} from '../../src/lightning/channel';
import type {
	IAssetSpliceUpdateHost,
	IAssetUpdatePeerMember
} from '../../src/lightning/channel/asset-splice-update-provider';
import { assetOpeningOutputClaims } from '../../src/lightning/chain/asset-opening-claims';
import { matchedAssetPayoutViews } from '../../src/lightning/chain/asset-splice-output-view';
import { assetUpdateHistory } from '../../src/lightning/storage/asset-update-history';
import {
	setupFundedAssetUpdatePair,
	assetUpdateTestHost
} from './helpers/asset-splice-update';

describe('a peer commitment signed by this device in a round it has not secured', function () {
	this.timeout(90000);
	it('is matched as the peer current state on either live funding output', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-inflight-peer-'));
		const { f } = await setupFundedAssetUpdatePair(dir, 5);
		const id = Buffer.from(f.id, 'hex');
		const destination = Buffer.from('0014' + 'cd'.repeat(20), 'hex');
		const assetId = '4c'.repeat(32);
		try {
			const runtime = {
				storage: f.devices[0].store,
				root: f.devices[0].party.root
			};
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
			const retained: IAssetUpdatePeerMember[][] = [[], []];
			const hosts = [0, 1].map(
				(i): IAssetSpliceUpdateHost => ({
					...assetUpdateTestHost(i),
					async retainAssetUpdatePeerViews(round, exact) {
						assert.equal(round.members.length, exact.length);
						for (const x of exact) assert(!x.remote.hasWitnesses());
						retained[i].push(...exact);
					}
				})
			);
			const offers = batch.map((b) => b.offer());
			batch.forEach((b, i) => b.acceptOffer(offers[1 - i]));
			const shares = (await Promise.all(
				batch.map((b, i) => b.signAssetShares(hosts[i]))
			)) as [Buffer, Buffer];
			const htlcs = (await Promise.all(
				batch.map((b, i) => b.signAssetHtlcs(hosts[i], shares))
			)) as [Buffer, Buffer];
			// A host that cannot keep the peer's side stops the round before any signature.
			await assert.rejects(
				batch[0].verifyAssetShares(
					{
						...hosts[0],
						async retainAssetUpdatePeerViews() {
							throw Error('Host storage is unavailable');
						}
					},
					shares,
					htlcs
				),
				/Host storage is unavailable/
			);
			assert.throws(
				() => batch[0].commitments(),
				/peer exits must be retained before signing/
			);
			assert.equal(retained[0].length, 0);
			await Promise.all(
				batch.map((b, i) => b.verifyAssetShares(hosts[i], shares, htlcs))
			);
			// The host kept the peer's exact commitments before any signature left.
			assert.equal(retained[0].length, 2);
			const commits = batch.map((b) => b.commitments());
			// Only the peer has our commitment_signed; this device has nothing back.
			await batch[1].acceptCommitments(hosts[1], commits[0]);
			const peerState = assetUpdateHistory(f.devices[1].store, f.id).states.get(
				1n
			)!;
			assert(peerState);
			assert.equal(
				assetUpdateHistory(f.devices[0].store, f.id).states.get(1n),
				undefined
			);
			assert.equal(peerState.members.length, 2);
			for (const m of peerState.members) {
				const published = Transaction.fromHex(m.localCommitment);
				assert.equal(published.ins[0].witness[0]?.length, 64);
				const kept = retained[0].find(
					(x) => x.outpoint === m.fundingTxid + ':' + m.outputIndex
				);
				assert(kept);
				assert.equal(kept.remote.getId(), published.getId());
				const [match] = matchedAssetPayoutViews(
					f.devices[0].store,
					f.id,
					published
				);
				assert(match, 'The peer commitment we signed must be recognized');
				assert.equal(match.holder, 'remote');
				assert.equal(match.state, 1n);
				assert.equal(match.revoked, undefined);
				assert.equal(match.splice, undefined);
				assert.equal(match.update?.stateNumber, '1');
				assert.equal(match.update?.fundingTxid, m.fundingTxid);
				assert.equal(match.update?.fundingOutputIndex, m.outputIndex);
				assert.equal(match.exitProofs, m.remoteProofs);

				const outputs: IAssetOpeningPayout[] = [];
				const htlcClaims: IAssetOpeningHtlcPayout[] = [];
				const provider = {
					assetSpliceRecoveryVersion: 1,
					outputRecoveryReceipt: (
						_c: string,
						_p: string,
						_o: number,
						payout: Transaction
					) => Buffer.from(payout.getId(), 'hex'),
					async restoreOutputReceipt() {},
					async recoverOutput(c: IAssetOpeningPayout) {
						outputs.push(c);
						const sweep = new Transaction();
						sweep.version = 2;
						sweep.addInput(published.getHash(), c.outputIndex, c.delay);
						sweep.addOutput(
							destination,
							published.outs[c.outputIndex].value - 400
						);
						sweep.setWitness(0, c.signSweep(sweep, [published]));
						return sweep;
					},
					async recoverHtlc(c: IAssetOpeningHtlcPayout) {
						htlcClaims.push(c);
						return null;
					}
				} as unknown as IAuxiliaryDualFunding;
				const claims = assetOpeningOutputClaims(
					runtime,
					id,
					published,
					destination,
					1,
					provider
				);
				// Our balance, and the HTLC we offered, which we take back by timeout.
				assert.equal(claims.length, 2);
				await Promise.all(claims.map((c) => c.recover?.()));
				assert.equal(outputs.length, 1);
				assert.equal(outputs[0].holder, 'remote');
				assert.equal(outputs[0].revocation, undefined);
				assert.equal(outputs[0].update?.stateNumber, '1');
				assert.equal(outputs[0].exitProofs.toString('hex'), m.remoteProofs);
				assert.equal(htlcClaims.length, 1);
				assert.equal(htlcClaims[0].kind, 'htlc_timeout');
				assert.equal(htlcClaims[0].holder, 'remote');
				assert.equal(htlcClaims[0].htlc.offeredBy, 'local');
				assert.equal(htlcClaims[0].virtualPayout.stateNumber, '1');
				assert.equal(htlcClaims[0].exitProofs.toString('hex'), m.remoteProofs);
			}
			// Once secured, the same transactions come from the secured round.
			await batch[0].acceptCommitments(hosts[0], commits[1]);
			for (const m of peerState.members) {
				const [match] = matchedAssetPayoutViews(
					f.devices[0].store,
					f.id,
					Transaction.fromHex(m.localCommitment)
				);
				assert.equal(match?.holder, 'remote');
				assert.equal(match?.state, 1n);
			}
		} finally {
			for (const d of f.devices) d.store.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
