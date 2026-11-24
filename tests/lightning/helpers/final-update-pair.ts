import { expect } from 'chai';
import { payments, script, Transaction } from 'bitcoinjs-lib';
import { mnemonicToSeedSync } from 'bip39';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	generateFromSeed,
	MAX_INDEX
} from '../../../src/lightning/keys/shachain';
import { bip32RootFromSeed } from '../../../src/lightning/keys/wallet-keys';
import { generateFinalDaemonWallet } from '../../../src/lightning/storage/final-wallet-generation';
import type { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { ecc } from '../../../src/utils/ecc';
import { boundParticipant, signingFixture } from './final-opening-signing';
import { otherOpeningView } from './final-opening-commitment';
export type Side = ReturnType<typeof boundParticipant>;
export function generateSide() {
	const { binding, mnemonic } = generateFinalDaemonWallet(true);
	return boundParticipant(
		bip32RootFromSeed(mnemonicToSeedSync(mnemonic)),
		1,
		binding
	);
}
const policy = {
	htlcMinimumMsat: '1',
	maxHtlcValueInFlightMsat: '4000000000',
	maxAcceptedHtlcs: 40,
	channelReserveSats: '1000'
};
const limits = { local: policy, remote: policy };
function openingWithChange(
	alice: Side,
	bob: Side
): ReturnType<typeof signingFixture> {
	const fixture = signingFixture(false, alice, bob);
	const { candidate, funding, terms } = fixture;
	const scripts = [alice, bob].map(
		(side) =>
			payments.p2wpkh({ pubkey: side.keys.channelBasepoints.fundingPubkey })
				.output!
	);
	for (const [i, input] of candidate.inputs.entries()) {
		const prev = Transaction.fromHex(input.prevTxHex);
		prev.outs[0].script = scripts[i];
		prev.outs[0].value += i === 1 ? 110_030 : 70;
		input.prevTxHex = prev.toHex();
		funding.ins[i].hash = prev.getHash();
	}
	funding.addOutput(scripts[1], 110_000);
	candidate.outputSerialIds.push('3');
	candidate.fundingTxHex = funding.toHex();
	return { ...fixture, counterpart: otherOpeningView(candidate, terms) };
}

export function walletSigner(
	key: Buffer,
	index: number,
	calls: number[]
): (
	tx: Transaction,
	indices: readonly number[],
	prevouts: { scripts: Buffer[]; values: bigint[] }
) => Buffer[][] {
	return (tx, indices, prevouts) => {
		calls.push(index);
		expect(indices).to.deep.equal([index]);
		const pubkey = getPublicKey(key);
		expect(prevouts.scripts[index]).to.deep.equal(
			payments.p2wpkh({ pubkey }).output
		);
		const digest = tx.hashForWitnessV0(
			index,
			payments.p2pkh({ pubkey }).output!,
			Number(prevouts.values[index]),
			Transaction.SIGHASH_ALL
		);
		return [
			[
				script.signature.encode(
					Buffer.from(ecc.sign(digest, key)),
					Transaction.SIGHASH_ALL
				),
				pubkey
			]
		];
	};
}

export function fundReadyPair(
	a: SqliteStorage,
	b: SqliteStorage,
	alice: Side,
	bob: Side
): string {
	const { candidate, counterpart, terms, id } = openingWithChange(alice, bob);
	const second = (p: typeof alice): string =>
		getPublicKey(
			generateFromSeed(p.keys.perCommitmentSeed, MAX_INDEX - 1n)
		).toString('hex');
	a.allocateFinalChannelKeyIndex(alice.index);
	b.allocateFinalChannelKeyIndex(bob.index);
	a.rememberFinalOpeningSession(
		candidate,
		bob.binding.nodeId,
		terms,
		alice.index,
		second(bob),
		limits
	);
	b.rememberFinalOpeningSession(
		counterpart.candidate,
		alice.binding.nodeId,
		counterpart.terms,
		bob.index,
		second(alice),
		limits
	);
	const local = a.finalOpeningTxComplete(id, alice.keys.fundingPrivkey);
	const peer = b.finalOpeningTxComplete(id, bob.keys.fundingPrivkey);
	a.rememberFinalPeerTxComplete(id, peer);
	b.rememberFinalPeerTxComplete(id, local);
	expect(() => a.finalOpeningChannelReady(id, alice.root)).to.throw();
	expect(() => a.renewFinalReestablishNonce(id, alice.root)).to.throw();
	const sa = a.signFinalPeerCommitment(id, terms, alice.root, alice.index);
	const sb = b.signFinalPeerCommitment(
		id,
		counterpart.terms,
		bob.root,
		bob.index
	);
	a.acceptFinalPeerCommitment(id, terms, alice.root, alice.index, sb);
	b.acceptFinalPeerCommitment(id, counterpart.terms, bob.root, bob.index, sa);
	const fa = a.finalOpeningTxSignatures(
		id,
		walletSigner(alice.keys.fundingPrivkey, 0, [])
	);
	b.rememberFinalPeerTxSignatures(id, fa);
	const fb = b.finalOpeningTxSignatures(
		id,
		walletSigner(bob.keys.fundingPrivkey, 1, [])
	);
	a.rememberFinalPeerTxSignatures(id, fb);
	const ra = a.finalOpeningChannelReady(id, alice.root),
		rb = b.finalOpeningChannelReady(id, bob.root);
	a.rememberFinalPeerChannelReady(id, rb, true);
	b.rememberFinalPeerChannelReady(id, ra, true);
	return id;
}
