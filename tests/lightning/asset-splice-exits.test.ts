import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import {
	buildAssetSpliceCommitment as build,
	buildFinalCommitmentView,
	type IFinalCommitmentHtlc
} from '../../src/lightning/channel/final-opening-commitment';
import type { IFinalFundingReference } from '../../src/lightning/channel/final-splice-candidate';
import {
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootSecondLevelOutput,
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	type ITaprootAuxLeaf
} from '../../src/lightning/script/commitment-taproot';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';
import { channelType } from './helpers/final-opening';
import {
	commitmentFixture,
	openingPoints
} from './helpers/final-opening-commitment';

type Holder = 'local' | 'remote';
const openingRoot = Buffer.alloc(32, 37);
const fundingRoot = Buffer.alloc(32, 72);
const leaf = (n: number): ITaprootAuxLeaf => ({
	script: Buffer.concat([Buffer.from([0x6a, 0x20]), Buffer.alloc(32, n)]),
	leafVersion: 0xc0
});
const assets = {
	fundingRoot,
	toLocal: leaf(1),
	toRemote: leaf(2),
	htlcs: [
		{
			offeredBy: 'local' as const,
			id: 7n,
			output: leaf(3),
			secondLevel: leaf(4)
		},
		{
			offeredBy: 'peer' as const,
			id: 7n,
			output: leaf(5),
			secondLevel: leaf(6)
		}
	]
};
const htlcs: IFinalCommitmentHtlc[] = [
	{
		offeredBy: 'local',
		id: 7n,
		amountMsat: 3000000n,
		paymentHash: Buffer.alloc(32, 10),
		cltvExpiry: 600144
	},
	{
		offeredBy: 'peer',
		id: 7n,
		amountMsat: 3000000n,
		paymentHash: Buffer.alloc(32, 11),
		cltvExpiry: 600150
	},
	{
		offeredBy: 'peer',
		id: 8n,
		amountMsat: 4000000n,
		paymentHash: Buffer.alloc(32, 12),
		cltvExpiry: 600160
	}
];
const balances = { localBalanceMsat: 75000000n, remoteBalanceMsat: 42000000n };
const height = 3n;
function fundingScript(
	localKey: string,
	remoteKey: string,
	root?: Buffer
): Buffer {
	return createTaprootFundingScript(
		Buffer.from(localKey, 'hex'),
		Buffer.from(remoteKey, 'hex'),
		undefined,
		root
	).p2trOutput;
}
function fixture() {
	const { candidate: plainOpening, terms } = commitmentFixture();
	const parent = Transaction.fromHex(plainOpening.fundingTxHex);
	parent.outs[plainOpening.fundingOutputIndex].script = fundingScript(
		plainOpening.localFundingPubkey,
		plainOpening.remoteFundingPubkey,
		openingRoot
	);
	const opening = {
		...plainOpening,
		channelType: channelType(456, 2026),
		fundingTxHex: parent.toHex()
	};
	const localFundingPubkey = openingPoints(181).fundingPubkey;
	const remoteFundingPubkey = openingPoints(182).fundingPubkey;
	const tx = new Transaction();
	tx.version = 2;
	tx.addInput(parent.getHash(), opening.fundingOutputIndex, 0xfffffffd);
	tx.addOutput(
		Buffer.concat([Buffer.from([0, 20]), Buffer.alloc(20, 19)]),
		12500
	);
	tx.addOutput(
		fundingScript(localFundingPubkey, remoteFundingPubkey, fundingRoot),
		127000
	);
	const ref: IFinalFundingReference = {
		fundingTxHex: tx.toHex(),
		fundingOutputIndex: 1,
		localFundingPubkey,
		remoteFundingPubkey,
		localFundingKeyIndex: 9
	};
	const plain = tx.clone();
	plain.outs[1].script = fundingScript(localFundingPubkey, remoteFundingPubkey);
	const plainRef = { ...ref, fundingTxHex: plain.toHex() };
	const point = (holder: Holder) =>
		Buffer.from(
			openingPoints(holder === 'local' ? 184 : 185).firstPerCommitmentPoint,
			'hex'
		);
	return { opening, plainOpening, terms, parent, tx, ref, plainRef, point };
}

describe('Asset splice commitment exits', function () {
	for (const holder of ['local', 'remote'] as const) {
		it(`constructs the ${holder} holder's payout, HTLC trees and second-level transactions at the candidate outpoint`, function () {
			const { opening, plainOpening, terms, point, tx, ref, plainRef } =
				fixture();
			const base = buildFinalCommitmentView(
				plainOpening,
				terms,
				holder,
				point(holder),
				height,
				balances,
				htlcs,
				plainRef
			);
			const view = build(
				opening,
				terms,
				holder,
				point(holder),
				height,
				balances,
				htlcs,
				ref,
				openingRoot,
				assets
			);
			expect(view.tx.ins).to.have.length(1);
			expect(view.tx.ins[0].hash).to.deep.equal(tx.getHash());
			expect(view.tx.ins[0].index).to.equal(1);
			expect(view.tx.ins[0].sequence).to.equal(base.tx.ins[0].sequence);
			expect(view.tx.locktime).to.equal(base.tx.locktime);
			expect(view.outputMap).to.deep.equal(base.outputMap);
			expect(view.tx.outs.map((out) => out.value)).to.deep.equal(
				base.tx.outs.map((out) => out.value)
			);
			const peer =
				holder === 'local' ? terms.remoteBasepoints : terms.localBasepoints;
			expect(view.tx.outs[view.outputMap.toRemote!].script).to.deep.equal(
				buildTaprootToRemoteOutput(
					Buffer.from(peer.paymentBasepoint, 'hex'),
					undefined,
					{ finalLeaf: assets.toRemote }
				).output
			);
			expect(view.tx.outs[view.outputMap.toLocal!].script).to.deep.equal(
				buildTaprootToLocalOutput(
					view.keys.revocationPubkey,
					view.keys.localDelayedPubkey,
					view.toSelfDelay,
					undefined,
					{ finalLeaf: assets.toLocal }
				).output
			);
			expect(view.htlcs).to.have.length(3);
			for (const child of view.htlcs) {
				const h = child.htlc;
				const leaves = assets.htlcs.find(
					(a) => a.offeredBy === h.offeredBy && a.id === h.id
				);
				const offered = (holder === 'local') === (h.offeredBy === 'local');
				const args = [
					view.keys.revocationPubkey,
					view.keys.localHtlcPubkey,
					view.keys.remoteHtlcPubkey,
					h.paymentHash
				] as const;
				const format = leaves ? { finalLeaf: leaves.output } : 'final';
				const expectedTree = offered
					? buildTaprootOfferedHtlcOutput(...args, undefined, format)
					: buildTaprootReceivedHtlcOutput(
							...args,
							h.cltvExpiry,
							undefined,
							format
					  );
				expect(child.offered).to.equal(offered);
				expect(child.tree.output).to.deep.equal(expectedTree.output);
				expect(view.tx.outs[child.outputIndex].script).to.deep.equal(
					expectedTree.output
				);
				const spend = offered ? expectedTree.timeout : expectedTree.success;
				expect(child.leaf).to.deep.equal(spend);
				const second = child.secondLevelTx;
				expect(second.ins).to.have.length(1);
				expect(second.ins[0].hash).to.deep.equal(view.tx.getHash());
				expect(second.ins[0].index).to.equal(child.outputIndex);
				expect(second.ins[0].sequence).to.equal(1);
				expect(second.locktime).to.equal(offered ? h.cltvExpiry : 0);
				const secondTree = buildTaprootSecondLevelOutput(
					view.keys.revocationPubkey,
					view.keys.localDelayedPubkey,
					view.toSelfDelay,
					undefined,
					leaves ? { finalLeaf: leaves.secondLevel } : 'final'
				);
				const sats = Number(h.amountMsat / 1000n);
				expect(second.outs).to.deep.equal([
					{ value: sats, script: secondTree.output }
				]);
				expect(child.digest).to.deep.equal(
					second.hashForWitnessV1(
						0,
						[expectedTree.output],
						[sats],
						Transaction.SIGHASH_SINGLE | Transaction.SIGHASH_ANYONECANPAY,
						tapleafHash(spend.script, spend.leafVersion)
					)
				);
			}
		});
	}
	it('keeps the Bitcoin-sorted indexes even if the asset leaves reverse equal-value HTLC script order', function () {
		const { opening, plainOpening, terms, point, ref, plainRef } = fixture();
		const base = buildFinalCommitmentView(
			plainOpening,
			terms,
			'local',
			point('local'),
			height,
			balances,
			htlcs,
			plainRef
		);
		const tied = base.htlcs
			.filter((h) => h.htlc.id === 7n)
			.map((h) => h.outputIndex);
		expect(tied).to.have.length(2);
		const [i, j] = tied;
		expect(base.tx.outs[i].value).to.equal(base.tx.outs[j].value);
		expect(
			base.tx.outs[i].script.compare(base.tx.outs[j].script)
		).to.be.lessThan(0);
		let reversed = false;
		for (let n = 0; n < 32 && !reversed; n++) {
			const leaves = {
				...assets,
				htlcs: [{ ...assets.htlcs[0], output: leaf(n) }, assets.htlcs[1]]
			};
			const view = build(
				opening,
				terms,
				'local',
				point('local'),
				height,
				balances,
				htlcs,
				ref,
				openingRoot,
				leaves
			);
			expect(view.outputMap).to.deep.equal(base.outputMap);
			reversed = view.tx.outs[i].script.compare(view.tx.outs[j].script) > 0;
		}
		expect(reversed).to.equal(true);
	});

	it('checks the original enrollment and funding root separately from the selected generation', function () {
		const { opening, plainOpening, terms, parent, point, ref, plainRef } =
			fixture();
		const zero = { localBalanceMsat: 90000000n, remoteBalanceMsat: 50000000n };
		const parentRef = {
			...ref,
			fundingTxHex: parent.toHex(),
			fundingOutputIndex: opening.fundingOutputIndex,
			localFundingPubkey: opening.localFundingPubkey,
			remoteFundingPubkey: opening.remoteFundingPubkey,
			localFundingKeyIndex: 0
		};
		const exit = build(
			opening,
			terms,
			'local',
			point('local'),
			height,
			zero,
			[],
			parentRef,
			openingRoot,
			{
				fundingRoot: openingRoot,
				toLocal: assets.toLocal,
				toRemote: assets.toRemote
			}
		);
		expect(exit.tx.ins[0].hash).to.deep.equal(parent.getHash());
		expect(exit.tx.ins[0].index).to.equal(opening.fundingOutputIndex);
		for (const [enrolled, oldRoot, selected, root, current] of [
			[plainOpening, openingRoot, ref, fundingRoot, balances],
			[opening, fundingRoot, ref, fundingRoot, balances],
			[opening, openingRoot, ref, openingRoot, balances],
			[opening, openingRoot, plainRef, fundingRoot, balances],
			[
				opening,
				openingRoot,
				{ ...ref, fundingOutputIndex: 0 },
				fundingRoot,
				balances
			],
			[
				opening,
				openingRoot,
				ref,
				fundingRoot,
				{ ...balances, localBalanceMsat: balances.localBalanceMsat + 1n }
			]
		] as const) {
			expect(() =>
				build(
					enrolled,
					terms,
					'local',
					point('local'),
					height,
					current,
					htlcs,
					selected,
					oldRoot,
					{ ...assets, fundingRoot: root }
				)
			).to.throw();
		}
	});

	it('requires a selected funding reference even when the balances fit the enrolled opening', function () {
		const { opening, terms, point } = fixture();
		const openingBalances = {
			localBalanceMsat: 90000000n,
			remoteBalanceMsat: 50000000n
		};
		expect(() =>
			build(
				opening,
				terms,
				'local',
				point('local'),
				height,
				openingBalances,
				[],
				undefined!,
				openingRoot,
				{ fundingRoot, toLocal: assets.toLocal, toRemote: assets.toRemote }
			)
		).to.throw();
	});

	it('rejects malformed HTLC identifiers and empty persisted leaves', function () {
		const { opening, terms, point, ref } = fixture();
		const run = (hs: typeof htlcs, leafRows: typeof assets.htlcs) =>
			build(
				opening,
				terms,
				'local',
				point('local'),
				height,
				balances,
				hs,
				ref,
				openingRoot,
				{ ...assets, htlcs: leafRows }
			);
		const malformed = '7' as unknown as bigint;
		expect(() =>
			run(htlcs, [{ ...assets.htlcs[0], id: malformed }])
		).to.throw();
		expect(() =>
			run([{ ...htlcs[0], id: malformed }, ...htlcs.slice(1)], assets.htlcs)
		).to.throw();
		for (const output of [
			{ script: Buffer.alloc(0) },
			{ script: Buffer.alloc(10001) },
			{ ...leaf(1), leafVersion: 193 }
		]) {
			expect(() => run(htlcs, [{ ...assets.htlcs[0], output }])).to.throw();
			expect(() =>
				run(htlcs, [{ ...assets.htlcs[0], secondLevel: output }])
			).to.throw();
		}
	});

	it('refuses unknown, repeated or trimmed HTLC leaves and incomplete second-level claims', function () {
		const { opening, terms, point, ref } = fixture();
		const run = (leaves: typeof assets) =>
			build(
				opening,
				terms,
				'remote',
				point('remote'),
				height,
				balances,
				htlcs,
				ref,
				openingRoot,
				leaves
			);
		expect(() => run(assets)).not.to.throw();
		for (const invalid of [
			[...assets.htlcs, assets.htlcs[0]],
			[{ ...assets.htlcs[0], id: 99n }],
			[{ ...assets.htlcs[0], output: undefined! }],
			[{ ...assets.htlcs[0], secondLevel: undefined! }]
		])
			expect(() => run({ ...assets, htlcs: invalid })).to.throw();
		const small = htlcs.map((h, i) =>
			i === 0 ? { ...h, amountMsat: 700000n } : h
		);
		const adjusted = {
			...balances,
			localBalanceMsat: balances.localBalanceMsat + 2300000n
		};
		expect(() =>
			build(
				opening,
				terms,
				'local',
				point('local'),
				height,
				adjusted,
				small,
				ref,
				openingRoot,
				assets
			)
		).not.to.throw();
		expect(() =>
			build(
				opening,
				terms,
				'remote',
				point('remote'),
				height,
				adjusted,
				small,
				ref,
				openingRoot,
				assets
			)
		).to.throw();
	});
});
