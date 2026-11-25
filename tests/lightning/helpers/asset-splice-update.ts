import { strict as assert } from 'assert';
import type { IAssetSpliceUpdateHost } from '../../../src/lightning/channel/asset-splice-update-provider';
import { signatureRoundFixture } from './asset-splice-signature-round';

/** Real peer devices and Bitcoin signatures, with a deterministic wallet proof test double. */
export async function setupFundedAssetUpdatePair(dir: string) {
	const s = signatureRoundFixture(dir);
	s.construct();
	const rounds = [s.round(0), s.round(1)];
	const shares = (await Promise.all(
		rounds.map((r, i) => r.signExitShares(s.hosts[i], s.ctx(i)))
	)) as [Buffer, Buffer];
	const leaves = await Promise.all(
		rounds.map((r, i) => r.verifyExitShares(s.hosts[i], s.ctx(i), shares))
	);
	const wire = rounds.map((r, i) => r.commitmentSigned(leaves[i]));
	for (const [i, r] of rounds.entries()) {
		r.acceptCommitmentSigned(leaves[i], wire[1 - i]);
		await r.retainExits(s.hosts[i], s.ctx(i), leaves[i]);
	}
	const first = await rounds[1].nextFunding(
		s.hosts[1],
		s.ctx(1),
		async () => 'unspent'
	);
	rounds[0].receiveFunding(first!);
	const second = await rounds[0].nextFunding(
		s.hosts[0],
		s.ctx(0),
		async () => 'unspent'
	);
	rounds[1].receiveFunding(second!);
	return s;
}
export const assetUpdateTestHost = (
	i: number,
	counts: number[] = [],
	expectedMembers = 2
): IAssetSpliceUpdateHost => ({
	async signAssetUpdateViews(round) {
		assert.equal(round.members.length, expectedMembers);
		return Buffer.from([1 + i]);
	},
	async signAssetUpdateHtlcs(round, shares) {
		assert.deepEqual(shares, [Buffer.from([1]), Buffer.from([2])]);
		return Buffer.from([3 + i]);
	},
	async verifyAssetUpdateViews(round, shares, children) {
		assert.deepEqual(children, [Buffer.from([3]), Buffer.from([4])]);
		assert.deepEqual(shares, [Buffer.from([1]), Buffer.from([2])]);
		return round.members.map((m) => {
			const side = (holder: 'local' | 'remote') => ({
				toLocal: { script: Buffer.from('6a01aa', 'hex') },
				toRemote: { script: Buffer.from('6a01bb', 'hex') },
				htlcs: m[holder].htlcs
					.filter((h) => h.allocations.length)
					.map((h) => ({
						id: h.id,
						offeredBy: h.offeredBy,
						output: { script: Buffer.from('6a01cc', 'hex') },
						secondLevel: { script: Buffer.from('6a01dd', 'hex') }
					})),
				proofs: Buffer.from([m.funding.fundingOutputIndex + 11]),
				htlcSignatures: Buffer.from([0x12, m.funding.fundingOutputIndex])
			});
			return {
				outpoint: m.outpoint,
				local: side('local'),
				remote: side('remote')
			};
		});
	},
	async retainAssetUpdateViews(round, exact) {
		assert.equal(round.members.length, exact.length);
		for (const x of exact) {
			assert.equal(x.local.ins[0].witness[0]?.length, 64);
			assert(!x.remote.hasWitnesses());
		}
		counts.push(i);
	}
});
