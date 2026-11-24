import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	loadAssetSpliceExitProofs,
	recordAssetSpliceFundingPhase,
	type IAssetSpliceExitProofs
} from '../../src/lightning/storage/asset-splice-exit-proofs';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';

describe('Unilateral exits for multiple live asset funding outpoints', () => {
	let dir: string, f: ReturnType<typeof setupAssetSpliceProofs>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-choice-'));
		f = setupAssetSpliceProofs(dir);
		f.fundOpening();
	});
	afterEach(() => {
		for (const d of f.devices) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	function reserve(e = f.evidence(0)): IAssetSpliceExitProofs {
		f.retain(0, e);
		const db = f.devices[0].store;
		const saved = loadAssetSpliceExitProofs(db, f.id, e.finalDigest)!;
		recordAssetSpliceFundingPhase(db, saved);
		return saved;
	}

	it('keeps the original sole exit when another view has proofs but no funding reservation', () => {
		const db = f.devices[0].store;
		const initial = db.loadFinalOpeningExit(f.id)!;
		f.retain(0);
		expect(db.loadFinalFundingExits(f.id).map((r) => r.exit)).to.deep.equal([
			initial
		]);
		expect(db.requestFinalOpeningExit(f.id)).to.deep.equal(initial);
	});

	it('withholds an ambiguous default while a funding share may have escaped and replays the selected outpoint after restart', () => {
		const d = f.devices[0];
		const saved = reserve();
		const views = [saved.parent, saved.candidate];
		expect(
			d.store
				.loadFinalFundingExits(f.id)
				.map((r) => r.exit.toString('hex'))
				.sort()
		).to.deep.equal(views.map((v) => v.localCommitment).sort());
		expect(() => d.store.loadFinalOpeningExit(f.id)).to.throw();
		expect(() => d.store.requestFinalOpeningExit(f.id)).to.throw();
		expect(d.store.loadFinalDaemonOpening(f.id)!.exitToBroadcast).to.be
			.undefined;
		const peerTx = Transaction.fromHex(saved.candidate.remoteCommitment);
		const [input] = peerTx.ins;
		expect(() =>
			d.store.requestFinalOpeningExit(f.id, input.hash, input.index + 1)
		).to.throw();
		expect(() =>
			d.store.requestFinalOpeningExit(f.id, Buffer.alloc(32, 55))
		).to.throw();
		const selected = d.store.requestFinalOpeningExit(
			f.id,
			input.hash,
			input.index
		);
		expect(selected.toString('hex')).to.equal(saved.candidate.localCommitment);
		d.store.close();
		d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		expect(d.store.loadFinalDaemonOpening(f.id)!.exitToBroadcast).to.deep.equal(
			selected
		);
		expect(d.store.requestFinalOpeningExit(f.id)).to.deep.equal(selected);
		const parent = Transaction.fromHex(saved.parent.localCommitment);
		expect(
			d.store.requestFinalOpeningExit(f.id, parent.ins[0].hash).toString('hex')
		).to.equal(saved.parent.localCommitment);
		expect(d.store.loadFinalFundingExits(f.id)).to.have.length(2);
		d.store.close();
		d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		expect(
			d.store.loadFinalDaemonOpening(f.id)!.exitToBroadcast?.toString('hex')
		).to.equal(saved.parent.localCommitment);
	});

	it('repairs a candidate close from the original signer after a rollback to before its selection', () => {
		const d = f.devices[0];
		const saved = reserve();
		d.store.close();
		const earlier = path.join(dir, 'before-exit');
		fs.copyFileSync(d.file, earlier);
		d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		const tx = Transaction.fromHex(saved.candidate.localCommitment);
		const selection = d.store.requestFinalOpeningExit(
			f.id,
			tx.ins[0].hash,
			tx.ins[0].index
		);
		d.store.close();
		fs.copyFileSync(earlier, d.file);
		d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		expect(d.store.loadFinalDaemonOpening(f.id)!.exitToBroadcast).to.deep.equal(
			selection
		);
		expect(d.store.requestFinalOpeningExit(f.id)).to.deep.equal(selection);
	});

	it('requires the exact enrolled joint root and original state-zero commitment before selecting the first splice', () => {
		const first = f.evidence(0);
		const db = f.devices[0].store;
		const signed = Transaction.fromHex(first.parent.localCommitment);
		const prev = Transaction.fromHex(
			db.loadFinalOpeningExit(f.id)!.toString('hex')
		);
		expect(signed.getId()).to.equal(prev.getId());
		expect(() =>
			reserve({
				...first,
				parent: { ...first.parent, fundingRoot: 'ca'.repeat(32) }
			})
		).to.throw();
		expect(db.loadFinalFundingExits(f.id)).to.have.length(1);
	});

	it('keeps competing same-height candidates while refusing to advance a partial logical round', () => {
		const db = f.devices[0].store;
		reserve();
		const second = reserve({
			...f.otherCandidate(0),
			finalDigest: 'bb'.repeat(32)
		});
		expect(db.loadFinalFundingExits(f.id)).to.have.length(3);
		reserve({ ...f.evidence(0, 1n), finalDigest: 'ea'.repeat(32) });
		expect(() => db.loadFinalFundingExits(f.id)).to.throw();
		expect(() =>
			db.requestFinalOpeningExit(
				f.id,
				Transaction.fromHex(second.candidate.localCommitment).ins[0].hash
			)
		).to.throw();
	});

	it('refuses to retain a contradictory commitment for the same outpoint and logical height', () => {
		const db = f.devices[0].store;
		const first = reserve();
		const other = f.otherCandidate(0);
		const altered = Transaction.fromHex(first.parent.localCommitment);
		altered.outs[0].value--;
		expect(() =>
			reserve({
				...other,
				finalDigest: 'ba'.repeat(32),
				parent: { ...other.parent, localCommitment: altered.toHex() }
			})
		).to.throw();
		expect(db.loadFinalFundingExits(f.id)).to.have.length(2);
		expect(() => db.requestFinalOpeningExit(f.id)).to.throw();
	});
});
