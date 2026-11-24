import { expect } from 'chai';
import { crypto, Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../src/utils/ecc';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateNonce } from '../../src/lightning/crypto/musig';
import {
	startCommitmentSigningSession,
	partialSignCommitment,
	aggregateCommitmentSig
} from '../../src/lightning/channel/commitment-musig';
import {
	derivePrivateKey,
	deriveRevocationPrivkey
} from '../../src/lightning/keys/derivation';
import {
	buildTaprootAnchorOutput,
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput
} from '../../src/lightning/script/commitment-taproot';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';
import {
	Candidate,
	inputTransaction,
	localFundingSecret,
	remoteFundingSecret
} from './helpers/final-opening';
import {
	commitmentFixture,
	otherOpeningView,
	openingPoints
} from './helpers/final-opening-commitment';
import { privAt, seedFor } from './helpers/taproot-revoked-fixture';
import {
	buildFinalOpeningCommitment as build,
	type IFinalOpeningTerms
} from '../../src/lightning/channel/final-opening-commitment';

function expectedExit(
	candidate: Candidate,
	terms: IFinalOpeningTerms,
	owner: 'local' | 'remote'
): {
	tx: Transaction;
	toLocal: ReturnType<typeof buildTaprootToLocalOutput>;
	delayed: Buffer;
	delay: number;
} {
	const local = owner === 'local';
	const seed = seedFor(local ? 171 : 172);
	const peer = seedFor(local ? 172 : 171);
	const point = getPublicKey(privAt(seed, 5));
	const delayed = derivePrivateKey(
		privAt(seed, 3),
		point,
		getPublicKey(privAt(seed, 3))
	);
	const revocation = deriveRevocationPrivkey(
		privAt(peer, 1),
		privAt(seed, 5),
		getPublicKey(privAt(peer, 1)),
		point
	);
	const delay = local ? terms.remoteToSelfDelay : terms.localToSelfDelay;
	const payment = getPublicKey(privAt(peer, 2));
	const toLocal = buildTaprootToLocalOutput(
		getPublicKey(revocation),
		getPublicKey(delayed),
		delay,
		undefined,
		'final'
	);
	const toRemote = buildTaprootToRemoteOutput(payment, undefined, 'final');
	const fee = Math.floor((968 * terms.commitmentFeeratePerKw) / 1000);
	const openerBalance = candidate.localContributionSats - fee - 2 * 330;
	const payouts = [
		{
			value: local ? openerBalance : candidate.remoteContributionSats,
			script: toLocal.output,
			anchor: buildTaprootAnchorOutput(getPublicKey(delayed)).output
		},
		{
			value: local ? candidate.remoteContributionSats : openerBalance,
			script: toRemote.output,
			anchor: buildTaprootAnchorOutput(payment).output
		}
	];
	const dust = local
		? terms.localDustLimitSatoshis
		: terms.remoteDustLimitSatoshis;
	const outputs = payouts
		.filter((p) => p.value >= dust)
		.flatMap((p) => [
			{ value: p.value, script: p.script },
			{ value: 330, script: p.anchor }
		])
		.sort((a, b) => a.value - b.value || a.script.compare(b.script));
	const mask = crypto.sha256(
		Buffer.concat([
			getPublicKey(privAt(seedFor(171), 2)),
			getPublicKey(privAt(seedFor(172), 2))
		])
	);
	const tx = new Transaction();
	tx.version = 2;
	tx.locktime = 0x20000000 + mask.readUIntBE(29, 3);
	tx.addInput(
		Transaction.fromHex(candidate.fundingTxHex).getHash(),
		candidate.fundingOutputIndex,
		0x80000000 + mask.readUIntBE(26, 3)
	);
	for (const output of outputs) tx.addOutput(output.script, output.value);
	return { tx, toLocal, delayed, delay };
}

describe('Final opening commitment zero', () => {
	for (const owner of ['local', 'remote'] as const) {
		it(
			'matches the counterparty view and an independently constructed ' +
				owner +
				' commitment, including its delayed spend',
			() => {
				const { candidate, terms } = commitmentFixture();
				const other = otherOpeningView(candidate, terms);
				const tx = build(candidate, terms, owner);
				expect(
					build(
						other.candidate,
						other.terms,
						owner === 'local' ? 'remote' : 'local'
					).toHex()
				).to.equal(tx.toHex());
				const expected = expectedExit(candidate, terms, owner);
				expect(tx.toHex()).to.equal(expected.tx.toHex());
				const funding = Transaction.fromHex(candidate.fundingTxHex).outs[
					candidate.fundingOutputIndex
				];
				const digest = tx.hashForWitnessV1(
					0,
					[funding.script],
					[funding.value],
					Transaction.SIGHASH_DEFAULT
				);
				const secrets = [localFundingSecret, remoteFundingSecret];
				const keys = secrets.map(getPublicKey);
				const nonces = secrets.map((secretKey, i) =>
					generateNonce({ secretKey, publicKey: keys[i], msg: digest })
				);
				const signing = startCommitmentSigningSession(
					digest,
					keys[0],
					keys[1],
					Buffer.from(nonces[0]),
					Buffer.from(nonces[1])
				);
				const shares = secrets.map((secret, i) =>
					partialSignCommitment(signing, secret, nonces[i])
				);
				const signature = aggregateCommitmentSig(signing, shares[0], shares[1]);
				tx.setWitness(0, [signature]);
				expect(
					ecc.verifySchnorr(
						digest,
						funding.script.subarray(2),
						Transaction.fromHex(tx.toHex()).ins[0].witness[0]
					)
				).to.equal(true);

				const index = tx.outs.findIndex((out) =>
					out.script.equals(expected.toLocal.output)
				);
				const payout = tx.outs[index];
				const child = new Transaction();
				child.version = 2;
				child.addInput(tx.getHash(), index, expected.delay);
				child.addOutput(
					Buffer.concat([Buffer.of(0, 20), Buffer.alloc(20, 3)]),
					payout.value - 200
				);
				const leaf = expected.toLocal.delay;
				const leafDigest = child.hashForWitnessV1(
					0,
					[payout.script],
					[payout.value],
					Transaction.SIGHASH_DEFAULT,
					tapleafHash(leaf.script)
				);
				const childSig = Buffer.from(
					ecc.signSchnorr(leafDigest, expected.delayed)
				);
				child.setWitness(0, [childSig, leaf.script, leaf.controlBlock]);
				expect(
					ecc.verifySchnorr(
						leafDigest,
						getPublicKey(expected.delayed).subarray(1),
						child.ins[0].witness[0]
					)
				).to.equal(true);
			}
		);
	}

	it('uses the commitment holder dust limit for each balance and anchor', () => {
		const { candidate, terms } = commitmentFixture();
		const prev = inputTransaction(176, 780);
		const funding = Transaction.fromHex(candidate.fundingTxHex);
		funding.ins[1].hash = prev.getHash();
		funding.outs[0].value = 90_700;
		candidate.remoteContributionSats = 700;
		candidate.fundingTxHex = funding.toHex();
		candidate.inputs[1].prevTxHex = prev.toHex();
		for (const owner of ['local', 'remote'] as const) {
			const tx = build(candidate, terms, owner);
			expect(tx.outs).to.have.length(owner === 'local' ? 4 : 2);
			expect(tx.toHex()).to.equal(
				expectedExit(candidate, terms, owner).tx.toHex()
			);
		}
	});

	it('binds the funding outpoint index even when the channel output is not first', () => {
		const { candidate, terms } = commitmentFixture();
		const prev = inputTransaction(175, 91_220);
		const funding = Transaction.fromHex(candidate.fundingTxHex);
		funding.ins[0].hash = prev.getHash();
		funding.outs.unshift({
			script: Buffer.concat([Buffer.of(0, 20), Buffer.alloc(20, 2)]),
			value: 1000
		});
		candidate.fundingTxHex = funding.toHex();
		candidate.inputs[0].prevTxHex = prev.toHex();
		candidate.outputSerialIds = ['2', '4'];
		candidate.fundingOutputIndex = 1;
		expect(build(candidate, terms, 'local').toHex()).to.equal(
			expectedExit(candidate, terms, 'local').tx.toHex()
		);
	});

	it('refuses inconsistent channel IDs, basepoints, channel terms, and funding candidates', () => {
		const { candidate, terms } = commitmentFixture();
		for (const changed of [
			{ ...candidate, channelId: '11'.repeat(32) },
			{ ...candidate, minimumDepth: 0 },
			{ ...candidate, fundingOutputIndex: 1 }
		])
			expect(() => build(changed, terms, 'local')).to.throw();
		for (const changed of [
			{
				...terms,
				localBasepoints: {
					...terms.localBasepoints,
					revocationBasepoint: openingPoints(188).revocationBasepoint
				}
			},
			{
				...terms,
				remoteBasepoints: {
					...terms.remoteBasepoints,
					fundingPubkey: terms.localBasepoints.fundingPubkey
				}
			},
			{
				...terms,
				localBasepoints: {
					...terms.localBasepoints,
					firstPerCommitmentPoint: '02' + 'ff'.repeat(32)
				}
			},
			{ ...terms, remoteToSelfDelay: 0 },
			{ ...terms, localDustLimitSatoshis: 0 },
			{ ...terms, commitmentFeeratePerKw: 0 }
		])
			expect(() => build(candidate, changed, 'local')).to.throw();
	});

	it('refuses both commitment orientations when the opener cannot afford fee plus anchors', () => {
		const { candidate, terms } = commitmentFixture();
		const funding = Transaction.fromHex(candidate.fundingTxHex);
		candidate.localContributionSats = 800;
		funding.outs[0].value = candidate.remoteContributionSats + 800;
		candidate.fundingTxHex = funding.toHex();
		for (const owner of ['local', 'remote'] as const)
			expect(() => build(candidate, terms, owner)).to.throw();
	});
});
