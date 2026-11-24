import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import {
	ChannelManager,
	type IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { ChannelState } from '../../src/lightning/channel/types';
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

describe('Splice lock, confirmed wallet receipt and offline recovery', function () {
	this.timeout(30000);
	let dir: string, f: ReturnType<typeof setupAssetSpliceProofs>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-confirmation-'));
		f = setupAssetSpliceProofs(dir);
		f.fundOpening();
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
		expect(() => d.store.loadAdoptedAssetSpliceReceipt(id)).to.throw(
			/wallet proof/
		);
		confirmWorks = true;
		await c.observe(id, e.candidate.fundingTxid, 4, prove, () => true);
		expect(c.status(id, e.candidate.fundingTxid)!.available).to.equal(true);
		expect(sent.some((raw) => raw.equals(wire))).to.equal(true);
		expect(d.store.loadAdoptedAssetSpliceReceipt(id)?.finalDigest).to.equal(
			e.finalDigest
		);
		const inPoint = e.candidate.fundingTxid + ':' + e.candidate.outputIndex;
		d.store.reserveAssetSpliceWalletInputs(id, '19'.repeat(32), inPoint, []);
		expect(() =>
			d.store.reserveAssetSpliceWalletInputs(
				id,
				'20'.repeat(32),
				e.parent.fundingTxid + ':' + e.parent.outputIndex,
				[]
			)
		).to.throw(/active funding/);
		const successful = calls.filter((v) => v === 'confirm').length;
		await c.observe(id, e.candidate.fundingTxid, 4, prove, () => true);
		expect(calls.filter((v) => v === 'confirm')).to.have.length(successful);
		await c.observe(id, e.candidate.fundingTxid, undefined, prove, () => true);
		expect(c.status(id, e.candidate.fundingTxid)!.available).to.equal(false);
		expect(calls.at(-1)).to.equal('retract');
		expect(() => d.store.loadAdoptedAssetSpliceReceipt(id)).to.throw(
			/reconciliation/
		);
	});
	it('tracks both possible commitments, rejects conflicting lock winners, and ignores a stale inclusion lookup', async () => {
		const store = f.devices[0].store,
			id = f.id,
			peer = f.devices[1].party.binding.nodeId;
		const first = f.evidence(0),
			second = { ...f.otherCandidate(0), finalDigest: 'ca'.repeat(32) };
		for (const e of [first, second]) {
			f.retain(0, e);
			recordAssetSpliceFundingPhase(
				store,
				loadAssetSpliceExitProofs(store, id, e.finalDigest)
			);
		}
		const c = new AssetSpliceConfirmationCoordinator(
			store,
			{
				verifySpliceFunding: async () => {},
				confirmSpliceFunding: async () => {},
				retractSpliceFunding: async () => {}
			},
			() => {},
			() => {}
		);
		c.restore(id);
		const parent = first.parent.fundingTxid + ':' + first.parent.outputIndex;
		expect(c.fundingSpend(id, first.candidate.fundingTxid, [parent])).to.equal(
			'splice'
		);
		expect(c.fundingSpend(id, second.candidate.fundingTxid, [parent])).to.equal(
			'splice'
		);
		expect(c.fundingSpend(id, '01'.repeat(32), [parent])).to.equal('close');
		expect(
			c.fundingSpend(id, '01'.repeat(32), [
				first.candidate.fundingTxid + ':' + first.candidate.outputIndex
			])
		).to.equal('close');
		expect(
			c.fundingSpend(id, '01'.repeat(32), ['19'.repeat(32) + ':0'])
		).to.equal(undefined);
		const wire = (txid: string) =>
			encodeSpliceLockedMessage({
				channelId: Buffer.from(id, 'hex'),
				fundingTxid: Buffer.from(txid, 'hex').reverse()
			});
		const anchor = (txid: string, depth: number) => ({
			txid,
			blockHash: 'de'.repeat(32),
			confirmations: depth
		});
		const txid = first.candidate.fundingTxid;
		let current = true;
		await c.observe(
			id,
			txid,
			10,
			async () => {
				current = false;
				return anchor(txid, 3);
			},
			() => current
		);
		expect(c.hasCurrentInclusion(id, txid)).to.equal(false);
		await c.observe(
			id,
			txid,
			10,
			async () => anchor(txid, 1),
			() => true
		);
		expect(c.hasCurrentInclusion(id, txid)).to.equal(true);
		expect(c.status(id, txid)?.available).to.equal(false);
		await c.receive(peer, wire(txid));
		await c.observe(
			id,
			txid,
			10,
			async () => anchor(txid, 3),
			() => true
		);
		expect(c.status(id, txid)?.available).to.equal(true);
		c.disconnected(peer);
		expect(c.hasCurrentInclusion(id, txid)).to.equal(true);
		const alternate = second.candidate.fundingTxid;
		await c.receive(peer, wire(alternate));
		let error: unknown;
		try {
			await c.observe(
				id,
				alternate,
				10,
				async () => anchor(alternate, 3),
				() => true
			);
		} catch (e) {
			error = e;
		}
		expect(String(error)).to.match(/competing/);
		expect(c.status(id, alternate)?.available).to.equal(false);
		expect(store.loadAdoptedAssetSpliceReceipt(id)?.finalDigest).to.equal(
			first.finalDigest
		);
	});
	it('treats an observed splice as funding and force closes the proven unspent candidate below lock depth', async () => {
		const { store, party } = f.devices[0],
			e = f.evidence(0);
		f.retain(0);
		f.sign(0, f.context(0));
		const manager = new ChannelManager({
			finalOpening: { storage: store, root: party.root },
			persistence: { persist: () => 'committed' }
		} as unknown as IChannelManagerConfig);
		const id = Buffer.from(f.id, 'hex');
		manager.restoreAssetSpliceWatches(f.id);
		const spending = Transaction.fromHex(e.candidate.funding.fundingTxHex);
		manager.handleFundingSpent(id, spending, 20, Buffer.alloc(0));
		expect(manager.finalOpeningInfo(id)[0].state).not.to.equal(
			ChannelState.FORCE_CLOSED
		);
		expect(manager.forceClose(id, Buffer.alloc(0)).ok).to.equal(false);
		await manager.observeAssetSpliceFunding(
			f.id,
			spending.getId(),
			20,
			async () => ({
				txid: spending.getId(),
				blockHash: 'b0'.repeat(32),
				confirmations: 1
			}),
			() => true
		);
		manager.observeFinalFunding(f.id, spending.getId(), 20, false);
		const sent: Buffer[] = [];
		manager.on('broadcast:tx', (raw: Buffer) => sent.push(raw));
		expect(manager.forceClose(id, Buffer.alloc(0)).ok).to.equal(true);
		expect(Transaction.fromBuffer(sent[0]).getId()).to.equal(
			Transaction.fromHex(e.candidate.localCommitment).getId()
		);
		manager.handleFundingSpent(
			id,
			Transaction.fromHex(e.candidate.remoteCommitment),
			22,
			Buffer.alloc(0)
		);
		expect(manager.finalOpeningInfo(id)[0].state).to.equal(
			ChannelState.FORCE_CLOSED
		);
	});
});
