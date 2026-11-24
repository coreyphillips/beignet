import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { AssetSpliceConfirmationCoordinator } from '../../src/lightning/channel/asset-splice-confirmation';
import { encodeSpliceLockedMessage } from '../../src/lightning/message/splice';
import {
	loadAssetSpliceExitProofs,
	recordAssetSpliceFundingPhase
} from '../../src/lightning/storage/asset-splice-exit-proofs';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';

describe('Splice lock, confirmed wallet receipt and offline recovery', () => {
	let dir: string, f: ReturnType<typeof setupAssetSpliceProofs>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-confirmation-'));
		f = setupAssetSpliceProofs(dir);
	});
	afterEach(() => {
		for (const d of f.devices) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	it('restores each publishable funding watch and requires fresh inclusion, both locks and confirmed wallet receipts before reporting adoption', async () => {
		const d = f.devices[0],
			peer = f.devices[1].party.binding.nodeId,
			id = f.id;
		const e = f.evidence(0);
		f.retain(0);
		recordAssetSpliceFundingPhase(
			d.store,
			loadAssetSpliceExitProofs(d.store, id, e.finalDigest)!
		);
		const sent: Buffer[] = [],
			watched: string[] = [],
			calls: string[] = [];
		let confirmWorks = false;
		const make = () =>
			new AssetSpliceConfirmationCoordinator(
				d.store,
				{
					verifySpliceFunding: async (ctx) => {
						calls.push('verify');
						expect(ctx.currentLock()!.fundingTxid).to.equal(
							e.candidate.fundingTxid
						);
					},
					confirmSpliceFunding: async (ctx) => {
						calls.push('confirm');
						expect(ctx.currentLock()!.adopted).to.equal(true);
						if (!confirmWorks) throw Error('wallet temporarily unavailable');
					},
					retractSpliceFunding: async (ctx) => {
						calls.push('retract');
						expect(ctx.currentLock()!.needsReconciliation).to.equal(true);
					}
				},
				(_id, ref, depth) => {
					watched.push(ref.fundingTxHex);
					expect(depth).to.equal(3);
				},
				(_peer, raw) => sent.push(raw)
			);
		let c = make();
		c.restore(id);
		expect(watched).to.deep.equal([e.candidate.funding.fundingTxHex]);
		const wire = encodeSpliceLockedMessage({
			channelId: Buffer.from(id, 'hex'),
			fundingTxid: Buffer.from(e.candidate.fundingTxid, 'hex').reverse()
		});
		expect(await c.receive('02' + '01'.repeat(32), wire)).to.equal(false);
		expect(await c.receive(peer, wire)).to.equal(true);
		expect(sent).to.be.empty;
		d.store.close();
		d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		c = make();
		c.restore(id);
		expect(c.status(id, e.candidate.fundingTxid)!.available).to.equal(false);
		const prove = async () => ({
			txid: e.candidate.fundingTxid,
			blockHash: 'ba'.repeat(32),
			confirmations: 3
		});
		await c
			.observe(id, e.candidate.fundingTxid, 4, prove, () => true)
			.catch(() => {});
		expect(c.status(id, e.candidate.fundingTxid)!.available).to.equal(false);
		confirmWorks = true;
		await c.observe(id, e.candidate.fundingTxid, 4, prove, () => true);
		expect(c.status(id, e.candidate.fundingTxid)!.available).to.equal(true);
		expect(sent.some((raw) => raw.equals(wire))).to.equal(true);
		const successful = calls.filter((v) => v === 'confirm').length;
		await c.observe(id, e.candidate.fundingTxid, 4, prove, () => true);
		expect(calls.filter((v) => v === 'confirm')).to.have.length(successful);
		await c.observe(id, e.candidate.fundingTxid, undefined, prove, () => true);
		expect(c.status(id, e.candidate.fundingTxid)!.available).to.equal(false);
		expect(calls.at(-1)).to.equal('retract');
	});
});
