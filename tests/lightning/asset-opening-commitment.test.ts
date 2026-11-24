import { expect } from 'chai';
import { payments, Transaction } from 'bitcoinjs-lib';
import {
	buildAssetOpeningCommitment as build,
	buildFinalOpeningCommitment,
	type IFinalCommitmentView
} from '../../src/lightning/channel/final-opening-commitment';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	TAPROOT_NUMS_KEY,
	type ITaprootAuxLeaf
} from '../../src/lightning/script/commitment-taproot';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { validateFinalOpening } from '../../src/lightning/storage/final-opening-candidate';
import {
	channelType,
	inputTransaction,
	type Candidate
} from './helpers/final-opening';
import {
	commitmentFixture,
	otherOpeningView
} from './helpers/final-opening-commitment';

const fundingRoot = Buffer.alloc(32, 0x71);
const profile = channelType(456, 2026);
const leaf = (tag: number): ITaprootAuxLeaf => ({
	script: Buffer.concat([Buffer.of(0x6a, 0x20), Buffer.alloc(32, tag)])
});
const leaves = { fundingRoot, toLocal: leaf(1), toRemote: leaf(2) };

function assetCandidate(c: Candidate): Candidate {
	const tx = Transaction.fromHex(c.fundingTxHex);
	tx.outs[c.fundingOutputIndex].script = createTaprootFundingScript(
		Buffer.from(c.localFundingPubkey, 'hex'),
		Buffer.from(c.remoteFundingPubkey, 'hex'),
		undefined,
		fundingRoot
	).p2trOutput;
	return { ...c, channelType: profile, fundingTxHex: tx.toHex() };
}

function withAmounts(c: Candidate, local: number, remote: number): Candidate {
	const tx = Transaction.fromHex(c.fundingTxHex);
	const prevs = [
		inputTransaction(175, local + 120),
		inputTransaction(176, remote + 80)
	];
	tx.outs[c.fundingOutputIndex].value = local + remote;
	prevs.forEach((prev, index) => {
		tx.ins[index].hash = prev.getHash();
	});
	return {
		...c,
		fundingTxHex: tx.toHex(),
		localContributionSats: local,
		remoteContributionSats: remote,
		inputs: c.inputs.map((v, i) => ({ ...v, prevTxHex: prevs[i].toHex() }))
	};
}

// Construct the two spending trees with bitcoinjs from the original final
// scripts. The asset leaf is a sibling of the complete Bitcoin subtree.
function scripts(
	view: IFinalCommitmentView,
	peerPayment: Buffer,
	local: ITaprootAuxLeaf,
	remote: ITaprootAuxLeaf
) {
	const delayed = buildTaprootToLocalOutput(
		view.keys.revocationPubkey,
		view.keys.localDelayedPubkey,
		view.toSelfDelay,
		undefined,
		'final'
	);
	const direct = buildTaprootToRemoteOutput(peerPayment, undefined, 'final');
	const localOutput = payments.p2tr({
		internalPubkey: TAPROOT_NUMS_KEY,
		scriptTree: [
			[{ output: delayed.delay.script }, { output: delayed.revoke.script }],
			{ output: local.script, version: local.leafVersion }
		],
		redeem: { output: delayed.delay.script }
	});
	const remoteOutput = payments.p2tr({
		internalPubkey: TAPROOT_NUMS_KEY,
		scriptTree: [
			{ output: direct.spend.script },
			{ output: remote.script, version: remote.leafVersion }
		],
		redeem: { output: direct.spend.script }
	});
	return { localOutput, remoteOutput, delayed, direct };
}

describe('Dual-funded asset opening commitment zero', function () {
	for (const owner of ['local', 'remote'] as const) {
		it(`binds the ${owner} exit and both final CSV spend paths to the asset outpoint`, function () {
			const { candidate, terms } = commitmentFixture();
			const c = assetCandidate(candidate);
			const other = otherOpeningView(c, terms);
			const view = build(c, terms, owner, leaves);
			expect(view.tx.toHex()).to.equal(
				build(
					other.candidate,
					other.terms,
					owner === 'local' ? 'remote' : 'local',
					leaves
				).tx.toHex()
			);
			const funding = Transaction.fromHex(c.fundingTxHex);
			expect(view.tx.ins).to.have.length(1);
			expect(view.tx.ins[0].hash).to.deep.equal(funding.getHash());
			expect(view.tx.ins[0].index).to.equal(c.fundingOutputIndex);
			const payment = Buffer.from(
				(owner === 'local' ? terms.remoteBasepoints : terms.localBasepoints)
					.paymentBasepoint,
				'hex'
			);
			const { localOutput, remoteOutput, delayed, direct } = scripts(
				view,
				payment,
				leaves.toLocal,
				leaves.toRemote
			);
			for (const [output, index, spend, size] of [
				[localOutput, view.outputMap.toLocal!, delayed.delay.script, 97],
				[remoteOutput, view.outputMap.toRemote!, direct.spend.script, 65]
			] as const) {
				expect(view.tx.outs[index].script).to.deep.equal(output.output);
				const witness = output.witness!;
				const block = witness[witness.length - 1];
				expect(block).to.have.length(size);
				expect(
					payments.p2tr({
						output: view.tx.outs[index].script,
						witness: [spend, block]
					}).redeem!.output
				).to.deep.equal(spend);
			}
			expect(view.tx.outs.map((o) => o.value)).to.deep.equal(
				buildFinalOpeningCommitment(candidate, terms, owner).outs.map(
					(o) => o.value
				)
			);
		});
	}

	it('accepts only its exact channel type and the negotiated funding root', function () {
		const { candidate, terms } = commitmentFixture();
		const c = assetCandidate(candidate);
		expect(() => build(c, terms, 'local', leaves)).not.to.throw();
		for (const type of [
			channelType(80),
			channelType(80, 2026),
			channelType(457, 2026),
			channelType(80, 456, 2026),
			channelType(80, 46, 456, 2026)
		]) {
			expect(() =>
				build({ ...c, channelType: type }, terms, 'local', leaves)
			).to.throw();
		}
		for (const root of [Buffer.alloc(31), Buffer.alloc(32, 0x72)]) {
			expect(() =>
				build(c, terms, 'local', { ...leaves, fundingRoot: root })
			).to.throw();
		}
		expect(() =>
			build({ ...candidate, channelType: profile }, terms, 'local', leaves)
		).to.throw();
		expect(() => validateFinalOpening(c)).to.throw();
		expect(() => buildFinalOpeningCommitment(c, terms, 'local')).to.throw();
	});

	it('preserves the Bitcoin output order when asset leaves reverse the tie between equal payouts', function () {
		const { candidate, terms } = commitmentFixture();
		// 244 sats commitment fee plus two 330 sat anchors.
		const plain = withAmounts(candidate, 50_904, 50_000);
		const base = buildFinalOpeningCommitment(plain, terms, 'local');
		const c = assetCandidate(plain);
		const view = build(c, terms, 'local', leaves);
		const peer = Buffer.from(terms.remoteBasepoints.paymentBasepoint, 'hex');
		const original = scripts(view, peer, leaves.toLocal, leaves.toRemote);
		const i = base.outs.findIndex((o) =>
			o.script.equals(original.delayed.output)
		);
		const j = base.outs.findIndex((o) =>
			o.script.equals(original.direct.output)
		);
		expect(i).to.be.at.least(0);
		expect(j).to.be.at.least(0);
		expect(base.outs[i].value).to.equal(base.outs[j].value);
		const chosen = { ...leaves, toLocal: leaf(6) };
		const expected = scripts(view, peer, chosen.toLocal, chosen.toRemote);
		const order = expected.localOutput.output!.compare(
			expected.remoteOutput.output!
		);
		expect(Math.sign(order)).to.equal(-Math.sign(i - j));
		const result = build(c, terms, 'local', chosen);
		expect(result.outputMap.toLocal).to.equal(i);
		expect(result.outputMap.toRemote).to.equal(j);
		expect(result.tx.outs[i].script).to.deep.equal(expected.localOutput.output);
		expect(result.tx.outs[j].script).to.deep.equal(
			expected.remoteOutput.output
		);
	});

	it('refuses a leaf for a trimmed payout in the holder view that trims it', function () {
		const { candidate, terms } = commitmentFixture();
		const c = assetCandidate(withAmounts(candidate, 90_000, 700));
		expect(() => build(c, terms, 'local', leaves)).not.to.throw();
		expect(() => build(c, terms, 'remote', leaves)).to.throw();
		// The remote holder is below its 1,000 sat dust limit. Its peer retains a payout.
		const v = build(c, terms, 'remote', {
			fundingRoot,
			toRemote: leaves.toRemote
		});
		expect(v.outputMap.toLocal).to.equal(undefined);
		expect(v.outputMap.toRemote).to.be.a('number');
	});
});
