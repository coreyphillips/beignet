import { strict as assert } from 'assert';
import { AssetSpliceConstruction } from '../../../src/lightning/channel/asset-splice-construction';
import type { IAssetSpliceSigningHost } from '../../../src/lightning/channel/asset-splice-signature-round';
import { constructionFixture } from './asset-splice-construction';
import { walletSigner } from './final-update-pair';

export function signatureRoundFixture(
	dir: string,
	transportAllocatesKeys = false,
	generation: 4 | 5 = 4
) {
	const s = constructionFixture(dir, generation),
		{ f, layout } = s;
	f.fundOpening();
	const pending = f.devices.map((d) =>
		transportAllocatesKeys ? 2 : d.store.allocateFinalChannelKeyIndex(2)
	);
	const retainedDigests: Buffer[] = [];
	const round = (i: number) =>
		f.devices[i].store.assetSpliceSignatureRound(
			f.devices[i].party.root,
			layout,
			s.verified[i],
			pending[i]
		);
	const ctx = (i: number) => ({
		channelId: f.id,
		peer: f.devices[1 - i].party.binding.nodeId,
		attempt: layout.attempt,
		isInitiator: i === 0,
		walletGeneration: generation,
		stateNumber: 0n,
		oldOutpoint: { hash: layout.parent.getHash(), index: layout.parentIndex },
		currentParent: () => ({
			stateNumber: 0n,
			walletGeneration: generation,
			oldOutpoint: { hash: layout.parent.getHash(), index: layout.parentIndex }
		})
	});
	const raw = [Buffer.from('aa', 'hex'), Buffer.from('bb', 'hex')] as const;
	const hosts = f.devices.map(
		({ store, party }, i): IAssetSpliceSigningHost => ({
			async signSpliceExits(_ctx, views) {
				assert.equal(
					views.parent.local.tx.ins[0].hash.toString('hex'),
					layout.parent.getHash().toString('hex')
				);
				assert.equal(
					views.candidate.local.tx.ins[0].hash.toString('hex'),
					s.tx.getHash().toString('hex')
				);
				assert.equal(
					views.candidate.local.localBalanceMsat,
					i ? 50000000n : 100000000n
				);
				return raw[i];
			},
			async verifySpliceExits(_ctx, _views, shares) {
				assert.deepEqual(shares, raw);
				const e = f.evidence(i);
				const leaves = (b: typeof e.parent, h: 'local' | 'remote') => ({
					toLocal: b.localRecovery.toLocal!,
					toRemote: b.localRecovery.toRemote!,
					proofs: h === 'local' ? b.localProofs : b.remoteProofs
				});
				return {
					parent: {
						local: leaves(e.parent, 'local'),
						remote: leaves(e.parent, 'remote')
					},
					candidate: {
						local: leaves(e.candidate, 'local'),
						remote: leaves(e.candidate, 'remote')
					}
				};
			},
			async retainSpliceExits(_ctx, views, exact) {
				const e = f.evidence(i);
				retainedDigests[i] = Buffer.from(views.finalDigest);
				e.finalDigest = views.finalDigest.toString('hex');
				for (const name of ['parent', 'candidate'] as const) {
					e[name].localCommitment = exact[name].local.toHex();
					e[name].remoteCommitment = exact[name].remote.toHex();
				}
				return e;
			},
			async signSpliceFunding(_ctx, digest, tx, indices, prevouts) {
				assert.deepEqual(digest, retainedDigests[i]);
				assert(
					store
						.readAssetSpliceJournal<{ kind: string }>(f.id)
						.records.some((r) => r.kind === 'funding-reserved')
				);
				if (i === 1) {
					assert.deepEqual(indices, []);
					return [];
				}
				return walletSigner(party.keys.fundingPrivkey, 1, f.calls)(
					tx,
					indices,
					prevouts
				);
			}
		})
	);
	function construct() {
		const sides = [0, 1].map(
			(i) =>
				new AssetSpliceConstruction(
					layout,
					s.verified[i],
					round(i).txComplete(),
					f.devices[i].store
				)
		);
		for (let j = 0; j < 16; j++) {
			const i = j % 2,
				frame = sides[i].next();
			if (!frame) break;
			sides[1 - i].receive(frame.type, frame.payload);
		}
		assert(sides.every((v) => !!v.agreement()));
	}
	return { s, f, ctx, hosts, round, construct, raw };
}
