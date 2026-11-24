/**
 * Simple Taproot test vectors from the BOLT extension linked below.
 * The JSON selects public keys, lock parameters and script trees from its
 * embedded fixture (SHA-256 7b40d067528c1e8a85e673e0170780d053a8999bd52b7f6eef457578004a4830).
 * Source: https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/bolt-simple-taproot.md
 * Lightning BOLTs contributors, https://creativecommons.org/licenses/by/4.0/.
 *
 * Eclair v0.14.0 independently matches the funding, main outputs, anchors,
 * offered local HTLC and both second-level output scripts. Its standalone
 * accepted local HTLC exchanges the keys, and its remote cases repeat the
 * local cases. Use the BOLT's holder-specific vectors for those scripts.
 * https://github.com/ACINQ/eclair/blob/ec8c63b215b98148887237e3f050342a6ca61f4c/eclair-core/src/test/resources/bolt3-tx-test-vectors-simple-taproot-commitment-format.json
 * SHA-256 f0ff6d1f6b646b875ca4922da297a2fa7da86ed6857b1450f56788c42ea5a16e.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	buildTaprootAnchorOutput,
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootSecondLevelOutput,
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput
} from '../../../src/lightning/script/commitment-taproot';
import type {
	ITaprootCommitOutput,
	ITaprootHtlcOutput,
	ITaprootLeafSpend
} from '../../../src/lightning/script/commitment-taproot';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import {
	buildTaprootHtlcSuccessTx,
	buildTaprootHtlcTimeoutTx,
	tapleafHash
} from '../../../src/lightning/script/htlc-taproot';
import { hexToBuffer, loadVectors } from './helpers';

interface IScriptTree {
	scripts: Record<string, string>;
	leaf_hashes: Record<string, string>;
	tapscript_root: string;
	internal_key: string;
	output_key: string;
	pkscript: string;
}

interface IScriptVectors {
	keys: Record<string, string>;
	csv_delay: number;
	htlc: { preimage: string; expiry: number };
	scripts: Record<string, IScriptTree> & {
		funding: {
			combined_funding_key: string;
			funding_key: string;
			pkscript: string;
		};
	};
}

const v = loadVectors<IScriptVectors>('bolt03/simple-taproot-scripts.json');
const key = (name: string): Buffer => hexToBuffer(v.keys[name]);
const delayed = key('derived_local_delayed_pubkey');
const revocation = key('derived_revocation_pubkey');
const payment = key('derived_remote_payment_pubkey');
const paymentHash = bitcoin.crypto.sha256(hexToBuffer(v.htlc.preimage));
const network = bitcoin.networks.regtest;

function expectTree(
	vector: IScriptTree,
	output: ITaprootCommitOutput & { merkleRoot?: Buffer },
	leaves: Record<string, ITaprootLeafSpend>
): void {
	expect(output.output.toString('hex')).to.equal(vector.pkscript);
	expect(output.outputKey.toString('hex')).to.equal(vector.output_key.slice(2));
	if (output.merkleRoot) {
		expect(output.merkleRoot.toString('hex')).to.equal(vector.tapscript_root);
	}
	expect(Object.keys(leaves)).to.have.members(Object.keys(vector.scripts));
	for (const [name, leaf] of Object.entries(leaves)) {
		expect(leaf.script.toString('hex'), name).to.equal(vector.scripts[name]);
		expect(leaf.leafVersion, name).to.equal(0xc0);
		expect(tapleafHash(leaf.script).toString('hex'), name).to.equal(
			vector.leaf_hashes[name]
		);
		// BIP 341 encodes output key parity, x-only internal key, then the
		// hash of the sibling (absent for a single-leaf tree).
		const parityByte = vector.output_key.startsWith('03') ? 'c1' : 'c0';
		const proof = Object.entries(vector.leaf_hashes)
			.filter(([other]) => other !== name)
			.map(([, hash]) => hash)
			.join('');
		expect(leaf.controlBlock.toString('hex'), name).to.equal(
			parityByte + vector.internal_key.slice(2) + proof
		);
	}
}

describe('Final simple Taproot commitment output scripts', function () {
	it('aggregates and tweaks the funding key', function () {
		const funding = createTaprootFundingScript(
			key('local_funding_pubkey'),
			key('remote_funding_pubkey'),
			network
		);
		expect(funding.internalKey.toString('hex')).to.equal(
			v.scripts.funding.combined_funding_key
		);
		expect(funding.outputKey.toString('hex')).to.equal(
			v.scripts.funding.funding_key
		);
		expect(funding.p2trOutput.toString('hex')).to.equal(
			v.scripts.funding.pkscript
		);
	});

	it('builds the delay and revocation paths of to_local', function () {
		const out = buildTaprootToLocalOutput(
			revocation,
			delayed,
			v.csv_delay,
			network,
			'final'
		);
		expectTree(v.scripts.to_local, out, {
			settle: out.delay,
			revocation: out.revoke
		});
	});

	it('builds the single CSV path of to_remote', function () {
		const out = buildTaprootToRemoteOutput(payment, network, 'final');
		expectTree(v.scripts.to_remote, out, { settle: out.spend });
	});

	for (const [name, pubkey] of [
		['local_anchor', delayed],
		['remote_anchor', payment]
	] as const) {
		it(`builds ${name} with the matching commitment key`, function () {
			const out = buildTaprootAnchorOutput(pubkey, network);
			expectTree(v.scripts[name], out, { sweep: out.anyone });
		});
	}

	for (const name of [
		'second_level_htlc_success',
		'second_level_htlc_timeout'
	]) {
		it(`builds ${name} with a revocation key path`, function () {
			const out = buildTaprootSecondLevelOutput(
				revocation,
				delayed,
				v.csv_delay,
				network,
				'final'
			);
			expectTree(v.scripts[name], out, { delay: out.delay });
		});
	}

	const holders = [
		{
			name: 'local_commit',
			revocation,
			holder: key('derived_local_htlc_pubkey'),
			peer: key('derived_remote_htlc_pubkey')
		},
		{
			name: 'remote_commit',
			revocation: key('remote_commit_revocation_pubkey'),
			holder: key('remote_commit_remote_htlc_pubkey'),
			peer: key('remote_commit_local_htlc_pubkey')
		}
	];
	for (const side of holders) {
		it(`builds an offered HTLC on the ${side.name}`, function () {
			const out = buildTaprootOfferedHtlcOutput(
				side.revocation,
				side.holder,
				side.peer,
				paymentHash,
				network,
				'final'
			);
			expectTree(v.scripts[`offered_htlc_${side.name}`], out, {
				success: out.success,
				timeout: out.timeout
			});
		});

		it(`builds an accepted HTLC on the ${side.name}`, function () {
			const out = buildTaprootReceivedHtlcOutput(
				side.revocation,
				side.holder,
				side.peer,
				paymentHash,
				v.htlc.expiry,
				network,
				'final'
			);
			expectTree(v.scripts[`accepted_htlc_${side.name}`], out, {
				success: out.success,
				timeout: out.timeout
			});
		});
	}

	it('accepts positive uint16 CSV delays and refuses unusable delay paths', function () {
		for (const build of [
			buildTaprootToLocalOutput,
			buildTaprootSecondLevelOutput
		]) {
			for (const delay of [1, 0xffff]) {
				expect(() =>
					build(revocation, delayed, delay, network, 'final')
				).not.to.throw();
			}
			for (const delay of [-1, 0, 1.5, 0x10000, NaN, Infinity]) {
				expect(() =>
					build(revocation, delayed, delay, network, 'final')
				).to.throw();
			}
		}
	});

	it('accepts positive block heights and refuses unusable HTLC timeout paths', function () {
		const received = (expiry: number): ITaprootHtlcOutput =>
			buildTaprootReceivedHtlcOutput(
				revocation,
				holders[0].holder,
				holders[0].peer,
				paymentHash,
				expiry,
				network,
				'final'
			);
		const txid = '01'.repeat(32);
		const timeout = (expiry: number): bitcoin.Transaction =>
			buildTaprootHtlcTimeoutTx(
				txid,
				0,
				1_000n,
				expiry,
				revocation,
				delayed,
				v.csv_delay,
				network,
				'final'
			);
		for (const expiry of [1, 499_999_999]) {
			expect(() => received(expiry)).not.to.throw();
			expect(timeout(expiry).locktime).to.equal(expiry);
		}
		for (const expiry of [0, 500_000_000, -1, 1.5, NaN, Infinity]) {
			expect(() => received(expiry)).to.throw();
			expect(() => timeout(expiry)).to.throw();
		}
		expect(
			buildTaprootHtlcSuccessTx(
				txid,
				0,
				1_000n,
				revocation,
				delayed,
				v.csv_delay,
				network,
				'final'
			).locktime
		).to.equal(0);
	});
});
