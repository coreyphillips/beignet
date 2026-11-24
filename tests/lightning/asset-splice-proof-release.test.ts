import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { assembleFinalSplice } from '../../src/lightning/channel/final-splice-funding';
import { validateFundingWitness } from '../../src/lightning/interactive-tx/funding-witness';
import {
	loadAssetSpliceExitProofs,
	type IAssetSpliceExitProofs
} from '../../src/lightning/storage/asset-splice-exit-proofs';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	branchNames,
	finalDigest,
	setupAssetSpliceProofs as setup
} from './helpers/asset-splice-proof-release';

describe('Durable asset splice proofs before funding witness release', () => {
	let dir: string, f: ReturnType<typeof setup>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-proof-release-'));
		f = setup(dir);
	});
	afterEach(() => {
		for (const d of f?.devices ?? []) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('withholds the wallet witness and shared partial until both proof-backed generations have been retained', () => {
		expect(() => f.sign(0, undefined)).to.throw();
		expect(f.calls).to.deep.equal([]);
		expect(() => f.sign(0, f.context(0))).to.throw();
		expect(f.calls).to.deep.equal([]);
	});

	it('refuses a splice after the original device has committed to a unilateral exit', () => {
		f.retain(0);
		const store = f.devices[0].store;
		store['openingAuthority']!.recordExitRequest(
			f.id,
			f.evidence(0).parent.localCommitment
		);
		expect(() => f.sign(0, f.context(0))).to.throw();
		expect(f.calls).to.deep.equal([]);
	});

	it('rejects missing funding or either holder proof on each generation without consuming its nonce', () => {
		for (const name of branchNames) {
			for (const field of [
				'fundingProofs',
				'localProofs',
				'remoteProofs'
			] as const) {
				const missing = f.evidence(0);
				missing[name][field] = '';
				expect(() => f.retain(0, missing)).to.throw();
				expect(() => f.sign(0, f.context(0))).to.throw();
				expect(f.calls).to.deep.equal([]);
			}
			const incomplete: Partial<IAssetSpliceExitProofs> = f.evidence(0);
			delete incomplete[name];
			expect(() =>
				f.retain(0, incomplete as IAssetSpliceExitProofs)
			).to.throw();
		}
		f.retain(0);
		expect(f.sign(0, f.context(0))).to.be.instanceOf(Buffer);
		expect(f.calls).to.deep.equal([1]);
	});

	it('matches the retained local and remote commitments, state number and agreement before invoking the wallet', () => {
		f.retain(0);
		const ctx = f.context(0);
		for (const bad of [
			{ ...ctx, parentRemote: f.views[0].parent.expected },
			{ ...ctx, candidateRemote: f.views[0].candidate.expected },
			{ ...ctx, stateNumber: 1n },
			{ ...ctx, finalDigest: Buffer.alloc(32, 81) }
		])
			expect(() => f.sign(0, bad)).to.throw();
		for (const name of branchNames) {
			const bad = f.views[0][name].signed.clone();
			bad.setWitness(0, [Buffer.alloc(64)]);
			expect(() =>
				f.sign(0, ctx, {
					...f.views[0],
					[name]: { ...f.views[0][name], signed: bad }
				})
			).to.throw();
			expect(() =>
				f.sign(0, ctx, { ...f.views[0], [name]: f.views[1][name] })
			).to.throw();
		}
		expect(f.calls).to.deep.equal([]);
		expect(f.sign(0, ctx)).to.be.instanceOf(Buffer);
	});

	it('refuses a substituted funding outpoint, root, or candidate holder proofs under a retained digest', () => {
		const original = f.evidence(0);
		f.retain(0, original);
		for (const name of branchNames) {
			for (const replacement of [
				{ fundingTxid: '81'.repeat(32) },
				{ outputIndex: original[name].outputIndex + 1 },
				{ fundingRoot: '82'.repeat(32) },
				{ fundingProofs: '83' },
				{ localProofs: '84' },
				{ remoteProofs: '85' }
			])
				expect(() =>
					f.retain(0, {
						...original,
						[name]: { ...original[name], ...replacement }
					})
				).to.throw();
		}
		expect(
			loadAssetSpliceExitProofs(f.devices[0].store, f.id, finalDigest)
		).to.deep.equal(original);
	});

	it('withholds witnesses when a complete proof set belongs to another valid candidate with the same funding keys, output index and root', () => {
		const other = f.otherCandidate(0);
		expect(other.candidate.fundingTxid).not.to.equal(
			f.evidence(0).candidate.fundingTxid
		);
		f.retain(0, other);
		expect(() => f.sign(0, f.context(0))).to.throw();
		expect(f.calls).to.deep.equal([]);
	});

	it('requires the receipt and signer to belong to the same original device', () => {
		f.retain(0);
		f.retain(1);
		const ctx = { ...f.context(0), store: f.devices[1].store };
		expect(() => f.sign(0, ctx)).to.throw();
		expect(f.calls).to.deep.equal([]);
	});

	it('recovers exact proof bytes after a split write and replays identical funding packets once from the original devices', async () => {
		for (const i of [0, 1]) f.retain(i);
		const d = f.devices[0],
			original = f.evidence(0);
		const initial = f.sign(0, f.context(0));
		expect(f.calls).to.deep.equal([1]);
		d.store['db']
			.prepare(
				"DELETE FROM final_lifecycle_log WHERE scope='asset-splice' AND channel_id=?"
			)
			.run(f.id);
		d.store.close();
		d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		expect(loadAssetSpliceExitProofs(d.store, f.id, finalDigest)).to.deep.equal(
			original
		);
		expect(f.sign(0, f.context(0))).to.deep.equal(initial);
		expect(f.calls).to.deep.equal([1]);
		const remote = f.sign(1, f.context(1));
		const paid = assembleFinalSplice(
			f.candidates[0],
			f.terms[0],
			Buffer.from(f.id, 'hex'),
			f.nonces[0],
			f.nonces[1],
			initial,
			remote
		);
		for (const index of [
			f.candidates[0].sharedIndex,
			...f.candidates[0].localInputs
		])
			expect(
				validateFundingWitness(paid, index, paid.ins[index].witness, {
					scripts: f.candidates[0].scripts,
					values: f.candidates[0].values.map(BigInt)
				})
			).to.equal(null);
		const backupFile = path.join(dir, 'copied');
		await d.store.backup(backupFile);
		const copy = SqliteStorage.openFinalWallet(backupFile, d.party.binding);
		try {
			expect(loadAssetSpliceExitProofs(copy, f.id, finalDigest)).to.deep.equal(
				original
			);
			expect(() => f.sign(0, { ...f.context(0), store: copy })).to.throw();
		} finally {
			copy.close();
		}
		expect(f.calls).to.deep.equal([1]);
	});

	it('withholds a cached release if its retained journal changes', () => {
		f.retain(0);
		f.sign(0, f.context(0));
		const d = f.devices[0];
		d.store['db']
			.prepare(
				"UPDATE final_lifecycle_log SET record='damaged' WHERE scope='asset-splice' AND channel_id=?"
			)
			.run(f.id);
		expect(() => f.sign(0, f.context(0))).to.throw();
		expect(f.calls).to.deep.equal([1]);
	});
});
