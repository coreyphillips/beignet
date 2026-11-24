import { expect } from 'chai';
import { payments, Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	buildFinalSpliceCandidate,
	finalSpliceFeeError,
	type IFinalSpliceTerms
} from '../../src/lightning/channel/final-splice-candidate';
import {
	assembleFinalSplice,
	finalSpliceSharedNonce,
	signFinalSpliceFunding,
	verifyFinalSpliceContribution
} from '../../src/lightning/channel/final-splice-funding';
import {
	aggregateCommitmentSig,
	partialSignCommitment,
	startCommitmentSigningSession
} from '../../src/lightning/channel/commitment-musig';
import { deriveCommitmentKeys } from '../../src/lightning/channel/commitment-builder';
import {
	buildCommitmentTx,
	calculateObscuredCommitmentNumber
} from '../../src/lightning/script/commitment';
import {
	buildTaprootAnchorOutput,
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput
} from '../../src/lightning/script/commitment-taproot';
import { generateNonce } from '../../src/lightning/crypto/musig';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { deriveChannelKeys } from '../../src/lightning/keys/wallet-keys';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { validateFundingWitness } from '../../src/lightning/interactive-tx/funding-witness';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import type { FinalOpeningAuthority } from '../../src/lightning/storage/final-opening-authority';
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

function signExit(
	source: Transaction,
	index: number,
	keys: Buffer[],
	root: Buffer,
	holder: number
) {
	const prev = source.outs[index];
	const parties = [alice, bob];
	const basepoints = parties.map((p) => p.keys.channelBasepoints);
	const peerKey = basepoints[1 - holder].paymentBasepoint;
	const commitment = deriveCommitmentKeys(
		basepoints[0],
		basepoints[1],
		Buffer.from(parties[holder].points.firstPerCommitmentPoint, 'hex'),
		holder === 0
	);
	const balances = [BigInt(prev.value) - 100000n - 1000n - 660n, 100000n];
	const { tx: expected } = buildCommitmentTx({
		fundingTxid: source.getHash().toString('hex'),
		fundingOutputIndex: index,
		fundingAmount: BigInt(prev.value),
		obscuredCommitmentNumber: calculateObscuredCommitmentNumber(
			basepoints[0].paymentBasepoint,
			basepoints[1].paymentBasepoint,
			0n
		),
		localAmount: balances[holder],
		remoteAmount: balances[1 - holder],
		revocationPubkey: commitment.revocationPubkey,
		localDelayedPubkey: commitment.localDelayedPubkey,
		remotePaymentPubkey: peerKey,
		toSelfDelay: 144,
		useAnchors: true,
		localFundingPubkey: getPublicKey(keys[holder]),
		remoteFundingPubkey: getPublicKey(keys[1 - holder]),
		taprootToLocalScript: buildTaprootToLocalOutput(
			commitment.revocationPubkey,
			commitment.localDelayedPubkey,
			144,
			undefined,
			'final'
		).output,
		taprootToRemoteScript: buildTaprootToRemoteOutput(
			peerKey,
			undefined,
			'final'
		).output,
		taprootAnchorLocalScript: buildTaprootAnchorOutput(
			commitment.localDelayedPubkey
		).output,
		taprootAnchorRemoteScript: buildTaprootAnchorOutput(peerKey).output
	});
	const signed = expected.clone();
	const digest = signed.hashForWitnessV1(
		0,
		[prev.script],
		[prev.value],
		Transaction.SIGHASH_DEFAULT
	);
	const nonces = keys.map((secretKey) =>
		generateNonce({
			secretKey,
			publicKey: getPublicKey(secretKey),
			msg: digest
		})
	);
	const session = startCommitmentSigningSession(
		digest,
		getPublicKey(keys[0]),
		getPublicKey(keys[1]),
		nonces[0],
		Buffer.from(nonces[1]),
		root
	);
	const shares = keys.map((key, i) =>
		partialSignCommitment(session, key, nonces[i])
	);
	signed.setWitness(0, [aggregateCommitmentSig(session, shares[0], shares[1])]);
	return { expected, signed };
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

	it('requires signed exits on both generations before issuing shares that spend the old asset key', () => {
		const { terms, inputs, outputs } = fixture(parentRoot, candidateRoot);
		const ours = { ...terms, assetFundingRoots: roots };
		const theirs = {
			...ours,
			localIsSpliceInitiator: false,
			oldLocalKey: ours.oldPeerKey,
			oldPeerKey: ours.oldLocalKey,
			newLocalKey: ours.newPeerKey,
			newPeerKey: ours.newLocalKey,
			localDelta: 0n,
			peerDelta: ours.localDelta,
			localFeeBudget: 0n
		};
		const local = buildFinalSpliceCandidate(ours, inputs, outputs);
		const peer = buildFinalSpliceCandidate(theirs, inputs, outputs);
		expect(local.digest).to.deep.equal(peer.digest);
		const id = Buffer.alloc(32, 57);
		const dir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'asset-splice-candidate-')
		);
		const stores: SqliteStorage[] = [];
		try {
			for (const [name, side] of [
				['alice', alice],
				['bob', bob]
			] as const) {
				stores.push(
					SqliteStorage.createFinalWallet(path.join(dir, name), side.binding)
				);
			}
			const auth = stores.map(
				(store) =>
					(store as unknown as { openingAuthority: FinalOpeningAuthority })
						.openingAuthority
			);
			const nonces = [local, peer].map((c, i) =>
				finalSpliceSharedNonce(c, oldKeys[i], auth[i])
			);
			const shares = [local, peer].map((c, i) => {
				const exits = {
					parent: signExit(
						ours.parent,
						ours.parentIndex,
						oldKeys,
						parentRoot,
						i
					),
					candidate: signExit(c.tx, c.fundingIndex, newKeys, candidateRoot, i)
				};
				const sign = (views: typeof exits) =>
					signFinalSpliceFunding(
						c,
						i === 0 ? ours : theirs,
						id,
						oldKeys[i],
						nonces[i],
						nonces[1 - i],
						auth[i],
						views,
						() => {
							throw new Error('No external wallet input');
						}
					);
				for (const side of ['parent', 'candidate'] as const) {
					const bad = exits[side].signed.clone();
					bad.setWitness(0, [Buffer.alloc(64)]);
					expect(() =>
						sign({ ...exits, [side]: { ...exits[side], signed: bad } })
					).to.throw(/exit signature/);
				}
				const wire = sign(exits);
				expect(sign(exits)).to.deep.equal(wire);
				return wire;
			});
			for (const [i, wire] of shares.entries()) {
				expect(
					verifyFinalSpliceContribution(
						local,
						ours,
						id,
						wire,
						i === 0,
						nonces[0],
						nonces[1]
					).share
				).to.have.length(32);
			}
			const signed = assembleFinalSplice(
				local,
				ours,
				id,
				nonces[0],
				nonces[1],
				shares[0],
				shares[1]
			);
			expect(
				validateFundingWitness(
					signed,
					local.sharedIndex,
					signed.ins[local.sharedIndex].witness,
					{ scripts: local.scripts, values: local.values.map(BigInt) }
				)
			).to.equal(null);
		} finally {
			for (const store of stores) store.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
