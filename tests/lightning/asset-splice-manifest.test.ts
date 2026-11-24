import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import { REGTEST_CHAIN_HASH } from '../../src/lightning/chain/hashes';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import {
	encodeSpliceMessage,
	encodeSpliceAckMessage
} from '../../src/lightning/message/splice';
import {
	assetSpliceLayoutDigest,
	verifyAssetSpliceCandidate,
	type IAssetSpliceLayout
} from '../../src/lightning/channel/asset-splice-manifest';

const hash = (n: number) => Buffer.alloc(32, n);
const key = (n: number) => getPublicKey(hash(n));
const sats = 600000;
const id = hash(1).toString('hex');

function fixture() {
	const parent = new Transaction();
	parent.version = 2;
	parent.addInput(hash(9), 1);
	const root = hash(22),
		newRoot = hash(23);
	const output = (a: number, b: number, r: Buffer) =>
		createTaprootFundingScript(key(a), key(b), undefined, r).p2trOutput;
	parent.addOutput(output(2, 3, root), sats);
	const init = {
		channelId: hash(4),
		fundingPubkey: key(5),
		relativeSatoshis: -3000n,
		fundingFeeratePerkw: 1000,
		locktime: 0,
		lockDepth: 3
	};
	const ack = {
		channelId: init.channelId,
		fundingPubkey: key(6),
		relativeSatoshis: 0n,
		lockDepth: 3
	};
	const layout: IAssetSpliceLayout = {
		attempt: hash(7),
		chainHash: REGTEST_CHAIN_HASH,
		channelId: init.channelId,
		init: encodeSpliceMessage(init),
		ack: encodeSpliceAckMessage(ack),
		parent,
		parentIndex: 0,
		parentKeys: [key(2), key(3)],
		parentRoot: root,
		stateNumber: 0n,
		feeBudgets: [1000n, 0n],
		maxAcceptedHtlcs: [8, 8],
		commitmentRecordLimits: [
			[{ type: 65537n, maxBytes: 2000 }],
			[{ type: 65537n, maxBytes: 2000 }]
		],
		dust: 546n,
		parentBalances: {
			issuances: [{ assetId: id, funding: 60n, initiator: 40n, acceptor: 20n }],
			htlcs: []
		},
		movements: [
			{
				assetId: id,
				owner: 'initiator',
				inputs: 0n,
				change: 0n,
				withdrawals: 10n,
				delta: -10n
			}
		],
		proposalDigests: [hash(11), hash(12)],
		inputs: [
			{
				serialId: 0n,
				prevTxid: parent.getHash(),
				prevOutputIndex: 0,
				sequence: 0xfffffffd,
				isShared: true
			}
		],
		outputs: [
			{
				serialId: 2n,
				role: 'funding',
				amountSats: BigInt(sats) - 3000n,
				descriptorHash: hash(13)
			},
			{
				serialId: 4n,
				role: 'withdrawal',
				amountSats: 2000n,
				descriptorHash: hash(14)
			}
		]
	};
	const tx = new Transaction();
	tx.version = 2;
	tx.addInput(parent.getHash(), 0, 0xfffffffd);
	tx.addOutput(output(5, 6, newRoot), sats - 3000);
	tx.addOutput(output(7, 8, hash(15)), 2000);
	const verified = {
		layoutDigest: assetSpliceLayoutDigest(layout),
		transaction: tx.toBuffer(),
		fundingRoot: newRoot,
		proofDigest: hash(16)
	};
	return { layout, tx, verified, auth: [hash(17), hash(18)] as const };
}

describe('Asset splice manifests', () => {
	it('pins a candidate when input buffers, including an external prevout, change after verification', () => {
		const { layout, tx, verified, auth } = fixture();
		const external = new Transaction();
		external.addInput(hash(41), 1);
		external.addOutput(
			Buffer.concat([Buffer.of(0, 20), Buffer.alloc(20, 42)]),
			1000
		);
		const input = {
			serialId: 1n,
			prevTxid: external.getHash(),
			prevOutputIndex: 0,
			sequence: 0xfffffffd,
			prevTx: external.toBuffer()
		};
		layout.inputs = [...layout.inputs, input];
		layout.feeBudgets = [1000n, 1000n];
		tx.addInput(input.prevTxid, 0, input.sequence);
		verified.transaction = tx.toBuffer();
		verified.layoutDigest = assetSpliceLayoutDigest(layout);
		const final = verifyAssetSpliceCandidate(
			layout,
			verified.layoutDigest,
			true,
			tx,
			verified,
			auth
		);
		const expected = (value: typeof final) =>
			JSON.stringify(value, (_key, n: unknown) =>
				typeof n === 'bigint' ? n.toString() : n
			);
		const before = expected(final);
		for (const raw of [
			tx.outs[0].script,
			tx.outs[1].script,
			input.prevTxid,
			input.prevTx,
			layout.inputs[0].prevTxid,
			layout.parent.outs[0].script,
			layout.parentRoot,
			...layout.parentKeys,
			layout.init,
			layout.ack,
			verified.fundingRoot,
			verified.transaction,
			verified.layoutDigest,
			verified.proofDigest,
			...auth
		])
			raw.fill(0);
		layout.parentBalances.issuances[0].initiator = 0n;
		expect(expected(final)).to.equal(before);
	});

	it('rejects a verified provider result from another state even after both parties acknowledge the new layout', () => {
		const { layout, tx, verified, auth } = fixture();
		const revised = { ...layout, stateNumber: 1n };
		const agreed = assetSpliceLayoutDigest(revised);
		expect(() =>
			verifyAssetSpliceCandidate(revised, agreed, true, tx, verified, auth)
		).to.throw();
	});

	it('authenticates the maximum tagged commitment budget of both holders before construction', () => {
		const { layout } = fixture();
		const agreed = assetSpliceLayoutDigest(layout);
		const revised = { ...layout, maxAcceptedHtlcs: [7, 8] as const };
		expect(assetSpliceLayoutDigest(revised)).not.to.deep.equal(agreed);
		const wide = [
			{ type: 65537n, maxBytes: 54615 },
			{ type: 65553n, maxBytes: 66 }
		];
		for (const pair of [
			[wide, layout.commitmentRecordLimits[1]],
			[layout.commitmentRecordLimits[0], wide]
		] as const)
			expect(() =>
				assetSpliceLayoutDigest({
					...layout,
					maxAcceptedHtlcs: [83, 83],
					commitmentRecordLimits: pair
				})
			).to.throw(/65551/);
	});

	it('matches the initiator-order wire and manifest vectors', () => {
		const { layout, tx, verified, auth } = fixture();
		expect(layout.init.toString('hex')).to.equal(
			'0404040404040404040404040404040404040404040404040404040404040404fffffffffffff448000003e8000000000362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7fe00010001020003'
		);
		expect(layout.ack.toString('hex')).to.equal(
			'0404040404040404040404040404040404040404040404040404040404040404000000000000000003f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0afe00010001020003'
		);
		const agreed = assetSpliceLayoutDigest(layout);
		expect(agreed.toString('hex')).to.equal(
			'30a1ab020fd20f4e5c48915fab741c7fae11097c46f388ace915959dc729a1b5'
		);
		expect(
			verifyAssetSpliceCandidate(
				layout,
				agreed,
				false,
				tx,
				verified,
				auth
			).digest.toString('hex')
		).to.equal(
			'136536a2646c9908e2844772204a272619b440f4667e3f5944256e0cb871269b'
		);
	});

	it('authenticates directional HTLC identity and exact allocations in canonical order', () => {
		const { layout } = fixture();
		const offered = {
			offeredBy: 'initiator' as const,
			id: 3n,
			paymentHash: hash(28).toString('hex'),
			cltvExpiry: 550,
			amountMsat: 1110000n,
			allocations: [{ assetId: id, units: 4n }]
		};
		const received = {
			...offered,
			offeredBy: 'acceptor' as const,
			allocations: []
		};
		const state = {
			issuances: [{ assetId: id, funding: 60n, initiator: 36n, acceptor: 20n }],
			htlcs: [offered, received]
		};
		const agreed = assetSpliceLayoutDigest({
			...layout,
			parentBalances: state
		});
		expect(
			assetSpliceLayoutDigest({
				...layout,
				parentBalances: { ...state, htlcs: [received, offered] }
			})
		).to.deep.equal(agreed);
		for (const change of [
			{ id: 5n },
			{ paymentHash: hash(29).toString('hex') },
			{ cltvExpiry: 551 },
			{ amountMsat: 1110001n }
		]) {
			expect(
				assetSpliceLayoutDigest({
					...layout,
					parentBalances: {
						...state,
						htlcs: [{ ...offered, ...change }, received]
					}
				})
			).not.to.deep.equal(agreed);
		}
		const switched = [
			{ ...offered, allocations: [] },
			{ ...received, allocations: offered.allocations }
		];
		expect(
			assetSpliceLayoutDigest({
				...layout,
				parentBalances: { ...state, htlcs: switched }
			})
		).not.to.deep.equal(agreed);
	});

	it('agrees on the ordered transaction, per-issuance move and both fee caps from either peer', () => {
		const { layout, tx, verified, auth } = fixture();
		const agreed = assetSpliceLayoutDigest(layout);
		const a = verifyAssetSpliceCandidate(
			layout,
			agreed,
			true,
			tx,
			verified,
			auth
		);
		const b = verifyAssetSpliceCandidate(
			layout,
			agreed,
			false,
			tx,
			verified,
			auth
		);
		expect(a.digest.equals(b.digest)).to.equal(true);
		expect(a.candidate.tx.toHex()).to.equal(tx.toHex());
		expect(a.balances.candidate.issuances[0]).to.deep.equal({
			assetId: id,
			funding: 50n,
			initiator: 30n,
			acceptor: 20n
		});
		expect(
			verifyAssetSpliceCandidate(
				layout,
				agreed,
				false,
				tx,
				{ ...verified, proofDigest: hash(24) },
				auth
			).digest.equals(a.digest)
		).to.equal(false);
	});

	it('binds the acknowledged attempt, state, per-owner allocation, descriptors and both Bitcoin fee limits', () => {
		const { layout, tx, verified, auth } = fixture();
		const agreed = assetSpliceLayoutDigest(layout);
		const changed = [
			{ ...layout, attempt: hash(31) },
			{ ...layout, stateNumber: 1n },
			{ ...layout, feeBudgets: [1001n, 0n] as const },
			{
				...layout,
				parentBalances: {
					issuances: [
						{ assetId: id, funding: 60n, initiator: 41n, acceptor: 19n }
					],
					htlcs: []
				}
			},
			{
				...layout,
				outputs: [
					layout.outputs[0],
					{ ...layout.outputs[1], descriptorHash: hash(32) }
				]
			},
			{
				...layout,
				proposalDigests: [hash(33), layout.proposalDigests[1]] as const
			}
		];
		for (const terms of changed)
			expect(() =>
				verifyAssetSpliceCandidate(terms, agreed, true, tx, verified, auth)
			).to.throw();
	});

	it('checks the initiator fee cap when the acceptor verifies the fully authorized layout', () => {
		const { layout, tx, verified, auth } = fixture();
		const terms = { ...layout, feeBudgets: [999n, 0n] as const };
		expect(() =>
			verifyAssetSpliceCandidate(
				terms,
				assetSpliceLayoutDigest(terms),
				false,
				tx,
				verified,
				auth
			)
		).to.throw();
	});

	it('refuses disagreement with the provider or with the exact accepted serial-to-vout layout', () => {
		const { layout, tx, verified, auth } = fixture();
		const agreed = assetSpliceLayoutDigest(layout);
		const changed = tx.clone();
		changed.outs.reverse();
		expect(() =>
			verifyAssetSpliceCandidate(layout, agreed, true, changed, verified, auth)
		).to.throw();
		expect(() =>
			verifyAssetSpliceCandidate(
				layout,
				agreed,
				true,
				changed,
				{ ...verified, transaction: changed.toBuffer() },
				auth
			)
		).to.throw();
		const different = tx.clone();
		different.outs[1].script = Buffer.concat([Buffer.of(0x51, 32), hash(19)]);
		expect(() =>
			verifyAssetSpliceCandidate(
				layout,
				agreed,
				true,
				different,
				verified,
				auth
			)
		).to.throw();
		expect(() =>
			verifyAssetSpliceCandidate(
				layout,
				agreed,
				true,
				tx,
				{ ...verified, fundingRoot: hash(25) },
				auth
			)
		).to.throw();
	});

	it('requires a single exact parent, fresh funding keys, positive matching locks and a private regtest chain', () => {
		const { layout } = fixture();
		const ack = {
			channelId: layout.channelId,
			fundingPubkey: key(6),
			relativeSatoshis: 0n,
			lockDepth: 3
		};
		for (const terms of [
			{
				...layout,
				ack: encodeSpliceAckMessage({ ...ack, lockDepth: undefined })
			},
			{ ...layout, ack: encodeSpliceAckMessage({ ...ack, lockDepth: 2 }) },
			{
				...layout,
				ack: encodeSpliceAckMessage({ ...ack, fundingPubkey: key(2) })
			},
			{ ...layout, chainHash: hash(30) },
			{ ...layout, parentRoot: hash(21) },
			{ ...layout, inputs: [{ ...layout.inputs[0], prevOutputIndex: 1 }] },
			{
				...layout,
				inputs: [layout.inputs[0], { ...layout.inputs[0], serialId: 6n }]
			}
		])
			expect(() => assetSpliceLayoutDigest(terms)).to.throw();
	});
});
