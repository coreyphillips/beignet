/**
 * What a provider of asset channels builds with (issue #2093 step 6): the
 * four taproot builders are reachable by name as `script.<name>` from the
 * package's `lightning` entry, and they are the very functions the engine's
 * commitment builder and funding code call, so what a provider computes
 * cannot drift from what the node signs. The on-chain HTLC tests compare
 * them with transactions a chain accepted.
 */

import { expect } from 'chai';
import * as lightning from '../../src/lightning';
import * as commitmentTaproot from '../../src/lightning/script/commitment-taproot';
import * as fundingTaproot from '../../src/lightning/script/funding-taproot';
import { ecc } from '../../src/utils/ecc';
import { hash } from './helpers/auxiliary-pair';

const key = (tag: string): Buffer =>
	Buffer.from(ecc.pointFromScalar(hash(`script export ${tag}`), true)!);

describe('the script builders a provider of asset channels uses (issue #2093 step 6)', () => {
	const { script } = lightning;
	const leaf = { script: Buffer.from('51', 'hex') };

	it('are reachable by name from the lightning entry, and nothing else of their modules is', () => {
		const taproot = Object.keys(script).filter((name) => /Taproot/.test(name));
		expect(taproot.sort()).to.deep.equal([
			'buildTaprootOfferedHtlcOutput',
			'buildTaprootReceivedHtlcOutput',
			'buildTaprootSecondLevelOutput',
			'createTaprootFundingScript'
		]);
		for (const name of taproot) {
			expect(typeof (script as Record<string, unknown>)[name]).to.equal(
				'function'
			);
		}
	});

	it('are the functions the engine builds its own commitments and funding with', () => {
		expect(script.createTaprootFundingScript).to.equal(
			fundingTaproot.createTaprootFundingScript
		);
		expect(script.buildTaprootOfferedHtlcOutput).to.equal(
			commitmentTaproot.buildTaprootOfferedHtlcOutput
		);
		expect(script.buildTaprootReceivedHtlcOutput).to.equal(
			commitmentTaproot.buildTaprootReceivedHtlcOutput
		);
		expect(script.buildTaprootSecondLevelOutput).to.equal(
			commitmentTaproot.buildTaprootSecondLevelOutput
		);
	});

	it('give the output key of a funding with a merkle root, and the leaf scripts and control blocks of each HTLC output and of a second-level output, with and without an asset leaf', () => {
		const root = hash('script export funding root');
		const plain = script.createTaprootFundingScript(key('a'), key('b'));
		const rooted = script.createTaprootFundingScript(
			key('a'),
			key('b'),
			undefined,
			root
		);
		// The same aggregate key, tweaked by the root: another output key.
		expect(rooted.internalKey.equals(plain.internalKey)).to.equal(true);
		expect(rooted.outputKey.equals(plain.outputKey)).to.equal(false);
		expect(rooted.outputKey).to.have.length(32);
		expect(
			rooted.p2trOutput.equals(
				Buffer.concat([Buffer.from('5120', 'hex'), rooted.outputKey])
			)
		).to.equal(true);
		// The order of the two keys does not matter.
		expect(
			script
				.createTaprootFundingScript(key('b'), key('a'), undefined, root)
				.outputKey.equals(rooted.outputKey)
		).to.equal(true);

		const paymentHash = hash('script export payment');
		const offered = script.buildTaprootOfferedHtlcOutput(
			key('revocation'),
			key('local htlc'),
			key('remote htlc'),
			paymentHash
		);
		const offeredWithLeaf = script.buildTaprootOfferedHtlcOutput(
			key('revocation'),
			key('local htlc'),
			key('remote htlc'),
			paymentHash,
			undefined,
			leaf
		);
		const received = script.buildTaprootReceivedHtlcOutput(
			key('revocation'),
			key('local htlc'),
			key('remote htlc'),
			paymentHash,
			500
		);
		const receivedWithLeaf = script.buildTaprootReceivedHtlcOutput(
			key('revocation'),
			key('local htlc'),
			key('remote htlc'),
			paymentHash,
			500,
			undefined,
			leaf
		);
		for (const [bare, carrying] of [
			[offered, offeredWithLeaf],
			[received, receivedWithLeaf]
		]) {
			// An asset leaf leaves the two HTLC leaves as they are and
			// lengthens the path that proves each: another output key.
			expect(carrying.success.script.equals(bare.success.script)).to.equal(
				true
			);
			expect(carrying.timeout.script.equals(bare.timeout.script)).to.equal(
				true
			);
			expect(carrying.success.controlBlock.length).to.equal(
				bare.success.controlBlock.length + 32
			);
			expect(carrying.timeout.controlBlock.length).to.equal(
				bare.timeout.controlBlock.length + 32
			);
			expect(carrying.outputKey.equals(bare.outputKey)).to.equal(false);
			expect(carrying.internalKey.equals(bare.internalKey)).to.equal(true);
		}
		expect(offered.outputKey.equals(received.outputKey)).to.equal(false);

		const second = script.buildTaprootSecondLevelOutput(
			key('revocation'),
			key('delayed'),
			144
		);
		const secondWithLeaf = script.buildTaprootSecondLevelOutput(
			key('revocation'),
			key('delayed'),
			144,
			undefined,
			leaf
		);
		expect(secondWithLeaf.delay.script.equals(second.delay.script)).to.equal(
			true
		);
		expect(secondWithLeaf.delay.controlBlock.length).to.equal(
			second.delay.controlBlock.length + 32
		);
		expect(secondWithLeaf.outputKey.equals(second.outputKey)).to.equal(false);
	});
});
