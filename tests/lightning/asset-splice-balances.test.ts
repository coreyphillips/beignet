import { expect } from 'chai';
import {
	planAssetSpliceBalances,
	type IAssetSpliceUnitMovement
} from '../../src/lightning/channel/asset-splice-balances';

const A = '11'.repeat(32);
const B = '22'.repeat(32);
const C = '33'.repeat(32);
const hash = 'ab'.repeat(32);
const maxUnits = (1n << 64n) - 1n;

function balances() {
	return {
		issuances: [
			{ assetId: A, funding: 60n, initiator: 30n, acceptor: 20n },
			{ assetId: B, funding: 40n, initiator: 10n, acceptor: 25n }
		],
		htlcs: [
			{
				offeredBy: 'initiator' as const,
				id: 4n,
				paymentHash: hash,
				cltvExpiry: 550,
				amountMsat: 3_000_000n,
				allocations: [
					{ assetId: A, units: 10n },
					{ assetId: B, units: 5n }
				]
			},
			{
				offeredBy: 'acceptor' as const,
				id: 4n,
				paymentHash: hash,
				cltvExpiry: 553,
				amountMsat: 1_001_000n,
				allocations: []
			}
		]
	};
}

function movement(
	assetId: string,
	owner: IAssetSpliceUnitMovement['owner'],
	inputs: bigint,
	change: bigint,
	withdrawals: bigint,
	delta: bigint
): IAssetSpliceUnitMovement {
	return { assetId, owner, inputs, change, withdrawals, delta };
}

describe('Asset splice balances across the old and candidate funding outputs', () => {
	it('credits peer inputs by issuance and excludes wallet change and pending deposits from spendable units', () => {
		const parent = balances();
		const plan = planAssetSpliceBalances(parent, [
			movement(B, 'acceptor', 19n, 7n, 0n, 12n),
			movement(A, 'initiator', 14n, 3n, 0n, 11n),
			movement(A, 'acceptor', 17n, 1n, 0n, 16n)
		]);
		expect(plan.parent).to.deep.equal(parent);
		expect(plan.candidate.issuances).to.deep.equal([
			{ assetId: A, funding: 87n, initiator: 41n, acceptor: 36n },
			{ assetId: B, funding: 52n, initiator: 10n, acceptor: 37n }
		]);
		expect(plan.candidate.htlcs).to.deep.equal(parent.htlcs);
		expect(plan.spendable).to.deep.equal([
			{ assetId: A, initiator: 30n, acceptor: 20n },
			{ assetId: B, initiator: 10n, acceptor: 25n }
		]);
	});

	it('withdraws 20 A out of 60 A and 40 B and immediately reserves the withdrawn units', () => {
		const parent = balances();
		const plan = planAssetSpliceBalances(parent, [
			movement(A, 'initiator', 0n, 0n, 20n, -20n)
		]);
		expect(plan.parent).to.deep.equal(parent);
		expect(plan.candidate.issuances).to.deep.equal([
			{ assetId: A, funding: 40n, initiator: 10n, acceptor: 20n },
			parent.issuances[1]
		]);
		expect(plan.candidate.htlcs).to.deep.equal(parent.htlcs);
		expect(plan.spendable).to.deep.equal([
			{ assetId: A, initiator: 10n, acceptor: 20n },
			{ assetId: B, initiator: 10n, acceptor: 25n }
		]);
	});

	it('carries every unit and both HTLC identities into a Bitcoin-only splice', () => {
		const parent = balances();
		const plan = planAssetSpliceBalances(parent, []);
		expect(plan.candidate).to.deep.equal(parent);
		expect(plan.spendable).to.deep.equal([
			{ assetId: A, initiator: 30n, acceptor: 20n },
			{ assetId: B, initiator: 10n, acceptor: 25n }
		]);
	});

	it('reserves a gross withdrawal when the same owner also deposits that issuance', () => {
		const plan = planAssetSpliceBalances(balances(), [
			movement(A, 'initiator', 20n, 0n, 20n, 0n)
		]);
		expect(plan.candidate.issuances).to.deep.equal(plan.parent.issuances);
		expect(plan.spendable[0]).to.deep.equal({
			assetId: A,
			initiator: 10n,
			acceptor: 20n
		});
	});

	it('takes the union of issuance IDs when a deposit introduces one and a withdrawal removes another', () => {
		const parent = {
			issuances: [
				{ assetId: B, funding: 3n, initiator: 0n, acceptor: 3n },
				{ assetId: A, funding: 1n, initiator: 1n, acceptor: 0n }
			],
			htlcs: []
		};
		const plan = planAssetSpliceBalances(parent, [
			movement(C, 'initiator', 5n, 1n, 0n, 4n),
			movement(B, 'acceptor', 0n, 0n, 3n, -3n)
		]);
		expect(plan.parent.issuances.map((i) => i.assetId)).to.deep.equal([A, B]);
		expect(plan.candidate.issuances).to.deep.equal([
			{ assetId: A, funding: 1n, initiator: 1n, acceptor: 0n },
			{ assetId: C, funding: 4n, initiator: 4n, acceptor: 0n }
		]);
		expect(plan.spendable).to.deep.equal([
			{ assetId: A, initiator: 1n, acceptor: 0n },
			{ assetId: B, initiator: 0n, acceptor: 0n },
			{ assetId: C, initiator: 0n, acceptor: 0n }
		]);
	});

	it('pins a mixed HTLC and its allocations independently of later caller mutations', () => {
		const parent = balances();
		const plan = planAssetSpliceBalances(parent, []);
		parent.issuances[0].initiator = 0n;
		parent.htlcs[0].paymentHash = 'cd'.repeat(32);
		parent.htlcs[0].allocations[0].units = 1n;
		expect(plan.parent).to.deep.equal(balances());
		expect(plan.candidate).to.deep.equal(balances());
	});

	it('refuses ambiguous movements, missing ownership consent and cross-issuance substitutions', () => {
		const bad: IAssetSpliceUnitMovement[][] = [
			[movement(C, 'acceptor', 0n, 0n, 0n, 0n)],
			[movement(A, 'acceptor', 0n, 0n, 21n, -21n)],
			[movement(B, 'initiator', 5n, 0n, 11n, -6n)],
			[movement(A, 'initiator', 5n, 6n, 0n, -1n)],
			[movement(A, 'initiator', 10n, 1n, 0n, 10n)],
			[
				movement(A, 'initiator', 1n, 0n, 0n, 1n),
				movement(A, 'initiator', 1n, 0n, 0n, 1n)
			],
			[
				movement(A, 'acceptor', 12n, 0n, 0n, 0n),
				movement(B, 'acceptor', 0n, 0n, 0n, 12n)
			],
			[
				movement(A, 'initiator', 3n, 0n, 0n, 0n),
				movement(A, 'acceptor', 0n, 0n, 0n, 3n)
			]
		];
		for (const moves of bad)
			expect(() => planAssetSpliceBalances(balances(), moves)).to.throw();
	});

	it('refuses a parent with per-ID totals that offset, a repeated issuance or an unknown HTLC issuance', () => {
		const switched = balances();
		switched.issuances[0].funding -= 5n;
		switched.issuances[1].funding += 5n;
		const repeated = balances();
		repeated.issuances.push({ ...repeated.issuances[0] });
		const unknown = balances();
		unknown.htlcs[0].allocations[0].assetId = C;
		for (const parent of [switched, repeated, unknown])
			expect(() => planAssetSpliceBalances(parent, [])).to.throw();
	});

	it('refuses duplicated directional HTLC IDs, repeated ID allocations and malformed immutable HTLC terms', () => {
		const duplicate = balances();
		duplicate.htlcs.push({ ...duplicate.htlcs[1] });
		const repeated = balances();
		repeated.htlcs[0].allocations.splice(
			0,
			1,
			{ assetId: A, units: 9n },
			{ assetId: A, units: 1n }
		);
		const wrongHash = balances();
		wrongHash.htlcs[0].paymentHash = hash.toUpperCase();
		const wrongHeight = balances();
		wrongHeight.htlcs[1].cltvExpiry = 0x1_0000_0000;
		const wrongId = balances();
		wrongId.htlcs[1].id = -1n;
		const overflowMsat = balances();
		overflowMsat.htlcs[1].amountMsat = maxUnits + 1n;
		for (const parent of [
			duplicate,
			repeated,
			wrongHash,
			wrongHeight,
			wrongId,
			overflowMsat
		])
			expect(() => planAssetSpliceBalances(parent, [])).to.throw();
	});

	it('enforces unsigned 64-bit units on the actual balances and a nonempty channel inventory', () => {
		const max = {
			issuances: [
				{ assetId: A, funding: maxUnits, initiator: maxUnits, acceptor: 0n }
			],
			htlcs: []
		};
		expect(planAssetSpliceBalances(max, []).candidate).to.deep.equal(max);
		for (const m of [
			movement(A, 'acceptor', 1n, 0n, 0n, 1n),
			movement(A, 'initiator', 0n, 0n, maxUnits, -maxUnits),
			movement(A, 'acceptor', maxUnits + 1n, maxUnits + 1n, 0n, 0n),
			movement(A, 'acceptor', -1n, 0n, 0n, -1n),
			movement('FF'.repeat(32), 'acceptor', 1n, 0n, 0n, 1n),
			movement('1', 'acceptor', 1n, 0n, 0n, 1n)
		]) {
			expect(() => planAssetSpliceBalances(max, [m])).to.throw();
		}
	});
});
