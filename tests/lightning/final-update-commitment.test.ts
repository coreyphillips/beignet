import { expect } from 'chai';
import { buildFinalCommitmentView } from '../../src/lightning/channel/final-opening-commitment';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { alice, bob, signingFixture } from './helpers/final-opening-signing';

describe('Final Taproot commitment updates', () => {
	it('both sides derive the same holder transaction and ordered child digests with asymmetric dust limits', () => {
		const { candidate, counterpart, terms } = signingFixture();
		const p = getPublicKey(
			generateFromSeed(alice.keys.perCommitmentSeed, MAX_INDEX - 1n)
		);
		const invoice = Buffer.alloc(32, 42);
		const htlcs = [
			{
				id: 0n,
				offeredBy: 'local' as const,
				amountMsat: 1499999n,
				paymentHash: invoice,
				cltvExpiry: 123
			}
		];
		const a =
			BigInt(candidate.localContributionSats) * 1000n - htlcs[0].amountMsat;
		const b = BigInt(candidate.remoteContributionSats) * 1000n;
		const ours = buildFinalCommitmentView(
			candidate,
			terms,
			'local',
			p,
			1n,
			{ localBalanceMsat: a, remoteBalanceMsat: b },
			htlcs
		);
		const theirs = buildFinalCommitmentView(
			counterpart.candidate,
			counterpart.terms,
			'remote',
			p,
			1n,
			{ localBalanceMsat: b, remoteBalanceMsat: a },
			[{ ...htlcs[0], offeredBy: 'peer' }]
		);
		expect(ours.tx.toHex()).to.equal(theirs.tx.toHex());
		expect(ours.htlcs[0].digest).to.deep.equal(theirs.htlcs[0].digest);
		expect(ours.htlcs[0].secondLevelTx.locktime).to.equal(123);
		expect(ours.tx.outs[ours.htlcs[0].outputIndex].value).to.equal(1499);
		const bpoint = getPublicKey(
			generateFromSeed(bob.keys.perCommitmentSeed, MAX_INDEX - 1n)
		);
		const small = { ...htlcs[0], amountMsat: 900999n };
		const balances = {
			localBalanceMsat: a + htlcs[0].amountMsat - small.amountMsat,
			remoteBalanceMsat: b
		};
		expect(
			buildFinalCommitmentView(
				candidate,
				terms,
				'remote',
				bpoint,
				1n,
				balances,
				[small]
			).htlcs
		).to.be.empty;
		expect(
			buildFinalCommitmentView(candidate, terms, 'local', p, 1n, balances, [
				small
			]).htlcs
		).to.have.length(1);
		expect(() =>
			buildFinalCommitmentView(candidate, terms, 'local', p, 1n, balances, [])
		).to.throw();
	});
});
