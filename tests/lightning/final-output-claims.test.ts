import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../src/utils/ecc';
import {
	buildFinalCommitmentView,
	type IFinalCommitmentView
} from '../../src/lightning/channel/final-opening-commitment';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { derivePrivateKey } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { sha256 } from '../../src/lightning/crypto/provider';
import {
	tapleafHash,
	signTaprootHtlcLeaf
} from '../../src/lightning/script/htlc-taproot';
import { encodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import type { IFinalOpeningRuntime } from '../../src/lightning/channel/final-opening-runtime';
import { finalOpeningOutputClaims } from '../../src/lightning/chain/final-output-claims';
import { alice, bob, signingFixture } from './helpers/final-opening-signing';

function fixture(
	owner: 'local' | 'remote' | 'revoked',
	trimOffer = false,
	rate = 1
): {
	view: IFinalCommitmentView;
	claims: ReturnType<typeof finalOpeningOutputClaims>;
	trimmed: bigint[];
	preimage: Buffer;
} {
	const { candidate, terms, id } = signingFixture();
	const preimage = Buffer.alloc(32, 19),
		hash = sha256(preimage);
	const htlcs = [
		{
			id: 0n,
			offeredBy: 'local' as const,
			amountMsat: trimOffer ? 300000n : 5500000n,
			paymentHash: hash,
			cltvExpiry: 150
		},
		{
			id: 0n,
			offeredBy: 'peer' as const,
			amountMsat: 7000000n,
			paymentHash: hash,
			cltvExpiry: 200
		}
	];
	const balances = {
		localBalanceMsat:
			BigInt(candidate.localContributionSats) * 1000n - htlcs[0].amountMsat,
		remoteBalanceMsat:
			BigInt(candidate.remoteContributionSats) * 1000n - htlcs[1].amountMsat
	};
	const make = (
		side: 'local' | 'remote'
	): {
		v: IFinalCommitmentView;
		s: typeof balances & {
			point: Buffer;
			height: bigint;
			feeratePerKw: number;
			secret: Buffer | undefined;
			htlcs: typeof htlcs;
			tx: Buffer;
			commitmentSigned: Buffer;
		};
	} => {
		const secret = generateFromSeed(
			(side === 'local' ? alice : bob).keys.perCommitmentSeed,
			MAX_INDEX - 3n
		);
		const point = getPublicKey(secret);
		const v = buildFinalCommitmentView(
			candidate,
			terms,
			side,
			point,
			3n,
			balances,
			htlcs
		);
		const key = derivePrivateKey(
			bob.keys.htlcBasepointSecret,
			point,
			bob.keys.channelBasepoints.htlcBasepoint
		);
		const sig = encodeCommitmentSignedMessage({
			channelId: Buffer.from(id, 'hex'),
			signature: Buffer.alloc(64),
			htlcSignatures: v.htlcs.map((h) => signTaprootHtlcLeaf(h.digest, key))
		});
		return {
			v,
			s: {
				...balances,
				point,
				height: 3n,
				feeratePerKw: terms.commitmentFeeratePerKw,
				secret: owner === 'revoked' && side === 'remote' ? secret : undefined,
				htlcs,
				tx: v.tx.toBuffer(),
				commitmentSigned: sig
			}
		};
	};
	const local = make('local'),
		remote = make('remote'),
		view = owner === 'local' ? local.v : remote.v;
	const runtime = {
		root: alice.root,
		storage: {
			canUpdateFinalCommitments: true,
			loadFinalOpeningSession: () => ({ channelKeyIndex: alice.index }),
			loadFinalResolutionStates: () => ({
				local: local.s,
				remote: owner === 'revoked' ? [] : [remote.s],
				revoked: owner === 'revoked' ? [remote.s] : [],
				candidate,
				terms,
				preimages: [preimage]
			})
		}
	} as unknown as IFinalOpeningRuntime;
	const destination = Buffer.from('0014' + 'ac'.repeat(20), 'hex');
	const trimmed: bigint[] = [];
	const claims = finalOpeningOutputClaims(
		runtime,
		Buffer.from(id, 'hex'),
		view.tx,
		destination,
		rate,
		(_hash, htlcId) => {
			trimmed.push(htlcId);
		}
	);
	return { view, claims, trimmed, preimage };
}

describe('final commitment on-chain claims', () => {
	it('identifies a trimmed outgoing HTLC only on the authenticated parent', () => {
		expect(fixture('local', true).trimmed).to.deep.equal([0n]);
		expect(fixture('remote', true).trimmed).to.deep.equal([0n]);
		expect(fixture('local').trimmed).to.deep.equal([]);
	});

	it('uses both presigned holder HTLC children, then waits for the second-level delayed outputs', () => {
		const { view, claims, preimage } = fixture('local');
		for (const h of view.htlcs) {
			const claim = claims.find((c) => c.outputIndex === h.outputIndex)!;
			expect(claim.sponsor).to.equal(true);
			expect(claim.tx!.ins[0].witness[1].length).to.equal(65);
			expect(
				ecc.verifySchnorr(
					h.digest,
					view.keys.localHtlcPubkey.subarray(1),
					claim.tx!.ins[0].witness[1].subarray(0, 64)
				)
			).to.equal(true);
			if (!h.offered)
				expect(claim.tx!.ins[0].witness[2]).to.deep.equal(preimage);
			const second = claim.child!(claim.tx!, 0)!;
			expect(second.relativeDelay).to.equal(view.toSelfDelay);
			expect(second.tx!.ins[0].hash).to.deep.equal(claim.tx!.getHash());
		}
	});
	it('sweeps breached HTLCs and their observed delayed children by key path', () => {
		const { view, claims } = fixture('revoked');
		for (const h of view.htlcs) {
			const claim = claims.find((c) => c.outputIndex === h.outputIndex)!;
			const witness = claim.tx!.ins[0].witness;
			expect(witness).to.have.length(1);
			expect(
				ecc.verifySchnorr(
					claim.tx!.hashForWitnessV1(
						0,
						[h.tree.output],
						[view.tx.outs[h.outputIndex].value],
						Transaction.SIGHASH_DEFAULT
					),
					h.tree.outputKey,
					witness[0]
				)
			).to.equal(true);
			const second = claim.child!(h.secondLevelTx, 0)!;
			expect(second.relativeDelay).to.equal(0);
			expect(second.tx!.ins[0].witness).to.have.length(1);
		}
	});
	it('retains a watched peer offer when sweeping it at the current rate would consume the output', () => {
		const { view, claims } = fixture('remote', false, 200);
		const offered = view.htlcs.find((h) => h.htlc.offeredBy === 'local')!;
		const watch = claims.find((c) => c.outputIndex === offered.outputIndex);
		expect(watch?.tx).to.equal(null);
		expect(watch?.htlcId).to.equal(offered.htlc.id);
		expect(watch?.paymentHash).to.deep.equal(offered.htlc.paymentHash);
	});

	it('rebuilds the peer success and timeout leaves for a current peer commitment', () => {
		const { view, claims } = fixture('remote');
		for (const h of view.htlcs) {
			const c = claims.find((v) => v.outputIndex === h.outputIndex)!;
			const w = c.tx!.ins[0].witness,
				script = w[w.length - 2];
			expect(script).to.deep.equal(
				h.offered ? h.tree.success.script : h.tree.timeout.script
			);
			const digest = c.tx!.hashForWitnessV1(
				0,
				[h.tree.output],
				[view.tx.outs[h.outputIndex].value],
				Transaction.SIGHASH_DEFAULT,
				tapleafHash(script)
			);
			expect(
				ecc.verifySchnorr(digest, view.keys.remoteHtlcPubkey.subarray(1), w[0])
			).to.equal(true);
		}
	});
});
