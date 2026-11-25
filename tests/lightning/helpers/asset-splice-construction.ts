import { REGTEST_CHAIN_HASH } from '../../../src/lightning/chain/hashes';
import { AssetSpliceConstruction } from '../../../src/lightning/channel/asset-splice-construction';
import {
	assetSpliceLayoutDigest,
	verifyAssetSpliceCandidate,
	type IAssetSpliceLayout
} from '../../../src/lightning/channel/asset-splice-manifest';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { encodeTxCompleteMessage } from '../../../src/lightning/message/interactive-tx';
import {
	encodeSpliceMessage,
	encodeSpliceAckMessage
} from '../../../src/lightning/message/splice';
import { setupAssetSpliceProofs } from './asset-splice-proof-release';

const tag = (n: number) => Buffer.alloc(32, n);
export function localPromise(channelId: Buffer, i: number) {
	const nonce = (j: number) =>
		Buffer.concat([
			getPublicKey(tag(1 + i * 10 + j * 2)),
			getPublicKey(tag(2 + i * 10 + j * 2))
		]);
	return encodeTxCompleteMessage({
		channelId,
		commitNonces: { current: nonce(0), next: nonce(1) },
		fundingInputNonce: nonce(2)
	});
}
export function constructionFixture(dir: string) {
	const f = setupAssetSpliceProofs(dir),
		t = f.terms[0],
		channelId = Buffer.from(f.id, 'hex');
	const layout: IAssetSpliceLayout = {
		channelId,
		chainHash: REGTEST_CHAIN_HASH,
		attempt: tag(73),
		stateNumber: 0n,
		parent: t.parent,
		parentIndex: t.parentIndex,
		parentRoot: t.assetFundingRoots!.parent,
		parentKeys: [t.oldLocalKey, t.oldPeerKey],
		init: encodeSpliceMessage({
			channelId,
			fundingPubkey: t.newLocalKey,
			relativeSatoshis: t.localDelta,
			fundingFeeratePerkw: t.feerate,
			locktime: t.locktime,
			lockDepth: 3
		}),
		ack: encodeSpliceAckMessage({
			channelId,
			fundingPubkey: t.newPeerKey,
			relativeSatoshis: t.peerDelta,
			lockDepth: 3
		}),
		feeBudgets: [t.localFeeBudget, 0n],
		maxAcceptedHtlcs: [3, 3],
		commitmentRecordLimits: [
			[{ type: 65537n, maxBytes: 900 }],
			[{ type: 65537n, maxBytes: 900 }]
		],
		dust: t.dust,
		parentBalances: {
			issuances: [
				{
					assetId: tag(76).toString('hex'),
					funding: 20n,
					initiator: 11n,
					acceptor: 9n
				}
			],
			htlcs: []
		},
		movements: [],
		proposalDigests: [tag(77), tag(78)],
		inputs: f.inputs,
		outputs: f.outputs.map((o, i) => ({
			serialId: o.serialId,
			role: i === f.candidates[0].fundingIndex ? 'funding' : 'change',
			amountSats: o.amountSats,
			descriptorHash: tag(79 + i)
		}))
	};
	const tx = f.candidates[0].tx,
		digest = assetSpliceLayoutDigest(layout);
	const verified = [0, 1].map((i) =>
		verifyAssetSpliceCandidate(
			layout,
			digest,
			i === 0,
			tx,
			{
				layoutDigest: digest,
				transaction: tx.toBuffer(),
				fundingRoot: t.assetFundingRoots!.candidate,
				proofDigest: tag(85),
				fundingProofs: Buffer.from('b0c1', 'hex')
			},
			[tag(86), tag(87)]
		)
	);
	const payloads = [0, 1].map((i) => localPromise(channelId, i));
	const open = (i: number) =>
		new AssetSpliceConstruction(
			layout,
			verified[i],
			payloads[i],
			f.devices[i].store
		);
	return { f, tx, layout, verified, payloads, open };
}
