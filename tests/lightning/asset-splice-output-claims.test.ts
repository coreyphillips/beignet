import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { assetOpeningOutputClaims } from '../../src/lightning/chain/asset-opening-claims';
import type {
	IAssetOpeningPayout,
	IAuxiliaryDualFunding
} from '../../src/lightning/channel/asset-opening-provider';
import {
	loadAssetSpliceExitProofs,
	recordAssetSpliceFundingPhase
} from '../../src/lightning/storage/asset-splice-exit-proofs';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';

describe('Watched asset commitment payouts after a splice', () => {
	let dir: string, f: ReturnType<typeof setupAssetSpliceProofs>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-claims-'));
		f = setupAssetSpliceProofs(dir);
		f.fundOpening();
	});
	afterEach(() => {
		for (const d of f.devices) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	const destination = Buffer.from('0014' + 'cd'.repeat(20), 'hex');
	it('matches each actual funding outpoint and commitment holder before supplying its exact proofs to the payout wallet', async () => {
		for (const [i, d] of f.devices.entries()) {
			const runtime = { storage: d.store, root: d.party.root };
			f.retain(i);
			const e = loadAssetSpliceExitProofs(
				d.store,
				f.id,
				f.evidence(i).finalDigest
			)!;
			recordAssetSpliceFundingPhase(d.store, e);
			for (const name of ['parent', 'candidate'] as const) {
				for (const holder of ['local', 'remote'] as const) {
					const commitment =
						f.views[holder === 'local' ? i : 1 - i][name].signed;
					let supplied: IAssetOpeningPayout | undefined;
					const provider = {
						async recoverOutput(ctx: IAssetOpeningPayout) {
							supplied = ctx;
							const tx = new Transaction();
							tx.version = 2;
							tx.addInput(commitment.getHash(), ctx.outputIndex, ctx.delay);
							tx.addOutput(
								destination,
								commitment.outs[ctx.outputIndex].value - 400
							);
							tx.setWitness(0, ctx.signSweep(tx, [commitment]));
							return tx;
						}
					} as unknown as IAuxiliaryDualFunding;
					const claims = assetOpeningOutputClaims(
						runtime,
						Buffer.from(f.id, 'hex'),
						commitment,
						destination,
						1,
						provider
					);
					expect(claims, name + '/' + holder).to.have.length(1);
					const sweep = await claims[0].recover!();
					expect(sweep!.ins[0].hash).to.deep.equal(commitment.getHash());
					expect(supplied!.fundingProofs.toString('hex')).to.equal(
						e[name].fundingProofs
					);
					expect(supplied!.exitProofs.toString('hex')).to.equal(
						holder === 'local' ? e[name].localProofs : e[name].remoteProofs
					);
					expect(supplied!.splice).to.deep.equal({
						finalDigest: e.finalDigest,
						stateNumber: e.stateNumber,
						generation: name,
						fundingTxid: e[name].fundingTxid,
						fundingOutputIndex: e[name].outputIndex
					});
					const wrong = commitment.clone();
					wrong.ins[0].index++;
					expect(
						assetOpeningOutputClaims(
							runtime,
							Buffer.from(f.id, 'hex'),
							wrong,
							destination,
							1,
							provider
						)
					).to.be.empty;
				}
			}
		}
	});
	it('refuses a missing recovery descriptor before any funding witness can be reserved', () => {
		for (const branch of ['parent', 'candidate'] as const)
			for (const key of ['localRecovery', 'remoteRecovery'] as const) {
				const e = f.evidence(0);
				delete (e[branch] as Partial<typeof e.parent>)[key];
				expect(() => f.retain(0, e)).to.throw();
			}
	});
});
