import { expect } from 'chai';
import { payments, Transaction } from 'bitcoinjs-lib';
import {
	buildFinalSpliceCandidate,
	finalSpliceFeeError,
	type IFinalSpliceTerms
} from '../../src/lightning/channel/final-splice-candidate';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { deriveChannelKeys } from '../../src/lightning/keys/wallet-keys';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { alice, bob } from './helpers/final-opening-signing';

const oldKeys = [alice.keys, bob.keys].map((keys) => keys.fundingPrivkey);
const newKeys = [alice, bob].map(
	(side) => deriveChannelKeys(side.root, 1, 9).fundingPrivkey
);
const parentRoot = Buffer.alloc(32, 17);
const candidateRoot = Buffer.alloc(32, 34);
const roots = { parent: parentRoot, candidate: candidateRoot };
const withdrawal = payments.p2wpkh({
	pubkey: alice.keys.channelBasepoints.paymentBasepoint
}).output!;

function script(keys: Buffer[], root?: Buffer): Buffer {
	return createTaprootFundingScript(
		getPublicKey(keys[0]),
		getPublicKey(keys[1]),
		undefined,
		root
	).p2trOutput;
}

function fixture(parentTree?: Buffer, candidateTree?: Buffer) {
	const parent = new Transaction();
	parent.addInput(Buffer.alloc(32, 1), 0);
	parent.addOutput(script(oldKeys, parentTree), 250000);
	const terms: IFinalSpliceTerms = {
		parent,
		parentIndex: 0,
		oldLocalKey: getPublicKey(oldKeys[0]),
		oldPeerKey: getPublicKey(oldKeys[1]),
		newLocalKey: getPublicKey(newKeys[0]),
		newPeerKey: getPublicKey(newKeys[1]),
		localIsSpliceInitiator: true,
		localDelta: -10500n,
		peerDelta: 0n,
		localFeeBudget: 500n,
		feerate: 253,
		dust: 354n,
		locktime: 0
	};
	const inputs = [
		{
			serialId: 0n,
			prevTxid: parent.getHash(),
			prevOutputIndex: 0,
			sequence: 0xfffffffd,
			isShared: true
		}
	];
	const outputs = [
		{ serialId: 2n, amountSats: 10000n, scriptPubkey: withdrawal },
		{
			serialId: 4n,
			amountSats: 239500n,
			scriptPubkey: script(newKeys, candidateTree)
		}
	];
	return { terms, inputs, outputs };
}

describe('asset roots in splice funding', () => {
	it('derives the shared script and the candidate script with their own roots and keys', () => {
		for (const candidate of [candidateRoot, parentRoot]) {
			const { terms, inputs, outputs } = fixture(parentRoot, candidate);
			const tx = buildFinalSpliceCandidate(
				{ ...terms, assetFundingRoots: { parent: parentRoot, candidate } },
				inputs,
				outputs
			);
			expect(tx.scripts[tx.sharedIndex]).to.deep.equal(
				script(oldKeys, parentRoot)
			);
			expect(tx.fundingIndex).to.equal(1);
			expect(tx.tx.outs[tx.fundingIndex].script).to.deep.equal(
				script(newKeys, candidate)
			);
			expect(tx.tx.outs[tx.fundingIndex].value).to.equal(239500);
			expect(tx.tx.outs[0].script).to.deep.equal(withdrawal);
		}
	});

	it('accepts ordinary funding when no asset roots were negotiated', () => {
		const { terms, inputs, outputs } = fixture();
		const tx = buildFinalSpliceCandidate(terms, inputs, outputs);
		expect(tx.scripts[tx.sharedIndex]).to.deep.equal(script(oldKeys));
		expect(tx.tx.outs[tx.fundingIndex].script).to.deep.equal(script(newKeys));
	});

	it('requires both roots as 32-byte buffers even if ordinary scripts otherwise match', () => {
		const { terms, inputs, outputs } = fixture();
		for (const malformed of [
			null,
			{},
			{ parent: parentRoot },
			{ candidate: candidateRoot },
			{ parent: Buffer.alloc(31), candidate: candidateRoot },
			{ parent: parentRoot, candidate: Buffer.alloc(33) },
			{ parent: parentRoot.toString('hex'), candidate: candidateRoot }
		]) {
			const invalid = {
				...terms,
				assetFundingRoots: malformed
			} as unknown as IFinalSpliceTerms;
			expect(() =>
				buildFinalSpliceCandidate(invalid, inputs, outputs)
			).to.throw();
		}
	});

	it('rejects a stripped or substituted root in either funding script', () => {
		for (const [parentTree, candidateTree] of [
			[undefined, candidateRoot],
			[parentRoot, undefined],
			[candidateRoot, candidateRoot],
			[parentRoot, parentRoot],
			[candidateRoot, parentRoot],
			[undefined, undefined]
		]) {
			const { terms, inputs, outputs } = fixture(parentTree, candidateTree);
			const agreed = { ...terms, assetFundingRoots: roots };
			expect(() =>
				buildFinalSpliceCandidate(agreed, inputs, outputs)
			).to.throw();
		}
		const { terms, inputs, outputs } = fixture(parentRoot, candidateRoot);
		expect(() => buildFinalSpliceCandidate(terms, inputs, outputs)).to.throw();
	});

	it('uses the full shared-input weight for an asset splice on both participants', () => {
		const { terms } = fixture(parentRoot, candidateRoot);
		const remoteWithdrawal = {
			...terms,
			localIsSpliceInitiator: false,
			localDelta: 0n,
			peerDelta: -5000n,
			localFeeBudget: 0n,
			feerate: 1000
		};
		expect(finalSpliceFeeError(998n, 1000, remoteWithdrawal, true)).to.equal(
			null
		);
		expect(
			finalSpliceFeeError(
				998n,
				1000,
				{ ...remoteWithdrawal, assetFundingRoots: roots },
				true
			)
		).to.be.a('string');
	});

	it('requires independent fee consent when the candidate moves asset funding', () => {
		const { terms, inputs, outputs } = fixture(parentRoot, candidateRoot);
		const agreed = { ...terms, assetFundingRoots: roots, localFeeBudget: 499n };
		expect(() => buildFinalSpliceCandidate(agreed, inputs, outputs)).to.throw(
			/contribution|fee/i
		);
	});
});
