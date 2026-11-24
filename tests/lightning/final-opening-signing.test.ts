import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ecc } from '../../src/utils/ecc';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../../src/lightning/message/channel-commitment';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { seedFor } from './helpers/taproot-revoked-fixture';

import {
	alice,
	bob,
	peers,
	signingFixture
} from './helpers/final-opening-signing';

function verifyExit(raw: Buffer, funding: Transaction): void {
	const exit = Transaction.fromBuffer(raw);
	expect(exit.ins).to.have.length(1);
	expect(exit.ins[0].hash).to.deep.equal(funding.getHash());
	expect(exit.ins[0].index).to.equal(0);
	expect(exit.ins[0].witness).to.have.length(1);
	const [signature] = exit.ins[0].witness;
	expect(signature).to.have.length(64);
	const { script, value } = funding.outs[0];
	const sighash = exit.hashForWitnessV1(
		0,
		[script],
		[value],
		Transaction.SIGHASH_DEFAULT
	);
	expect(ecc.verifySchnorr(sighash, script.subarray(2), signature)).to.equal(
		true
	);
	expect(
		ecc.verifySchnorr(
			exit.hashForWitnessV1(
				0,
				[script],
				[value - 1],
				Transaction.SIGHASH_DEFAULT
			),
			script.subarray(2),
			signature
		)
	).to.equal(false);
}

describe('Durable final opening commitment signatures', () => {
	let directory: string;
	beforeEach(() => {
		directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-opening-signing-')
		);
	});
	afterEach(() => {
		fs.rmSync(directory, { recursive: true, force: true });
	});

	it('converts both wire shares into enforceable local exits and replays exact bytes after reopening', () => {
		const { a, b, id, terms, bTerms, funding, aFile, bFile } = peers(directory);
		let aShare: Buffer, bShare: Buffer, aExit: Buffer, bExit: Buffer;
		try {
			aShare = a.signFinalPeerCommitment(id, terms, alice.root, alice.index);
			const wire = decodeCommitmentSignedMessage(aShare);
			expect(wire.channelId.toString('hex')).to.equal(id);
			expect(wire.signature).to.deep.equal(Buffer.alloc(64));
			expect(wire.htlcSignatures).to.be.empty;
			expect(wire.fundingTxid).to.deep.equal(funding.getHash());
			expect(wire.partialSignatureWithNonce).to.have.length(98);
			bExit = b.acceptFinalPeerCommitment(
				id,
				bTerms,
				bob.root,
				bob.index,
				aShare
			);
			bShare = b.signFinalPeerCommitment(id, bTerms, bob.root, bob.index);
			aExit = a.acceptFinalPeerCommitment(
				id,
				terms,
				alice.root,
				alice.index,
				bShare
			);
			verifyExit(aExit, funding);
			verifyExit(bExit, funding);
			expect(aExit).not.to.deep.equal(bExit);
			expect(
				a.signFinalPeerCommitment(id, terms, alice.root, alice.index)
			).to.deep.equal(aShare);
			expect(
				b.acceptFinalPeerCommitment(id, bTerms, bob.root, bob.index, aShare)
			).to.deep.equal(bExit);
		} finally {
			a.close();
			b.close();
		}
		for (const [file, identity, view, ours, fromPeer, exit] of [
			[aFile, alice, terms, aShare, bShare, aExit],
			[bFile, bob, bTerms, bShare, aShare, bExit]
		] as const) {
			const primary = SqliteStorage.openFinalWallet(file, identity.binding);
			try {
				expect(primary.loadFinalPeerCommitment(id)).to.deep.equal(ours);
				expect(primary.loadFinalOpeningExit(id)).to.deep.equal(exit);
				expect(
					primary.signFinalPeerCommitment(
						id,
						view,
						identity.root,
						identity.index
					)
				).to.deep.equal(ours);
				expect(
					primary.acceptFinalPeerCommitment(
						id,
						view,
						identity.root,
						identity.index,
						fromPeer
					)
				).to.deep.equal(exit);
			} finally {
				primary.close();
			}
		}
	});

	it('checks signatures, nonce points, funding tag and both key locators before retaining the exit', () => {
		const { a, b, id, terms, bTerms, funding } = peers(directory);
		try {
			expect(() =>
				a.signFinalPeerCommitment(id, terms, bob.root, alice.index)
			).to.throw();
			expect(() =>
				a.signFinalPeerCommitment(id, terms, alice.root, alice.index + 1)
			).to.throw();
			expect(a.loadFinalPeerCommitment(id)).to.equal(null);
			const valid = a.signFinalPeerCommitment(
				id,
				terms,
				alice.root,
				alice.index
			);
			const signed = decodeCommitmentSignedMessage(valid);
			const sig = Buffer.from(signed.partialSignatureWithNonce!);
			sig[0] ^= 1;
			const nonce = Buffer.from(signed.partialSignatureWithNonce!);
			nonce[32] = 4;
			const substitutions = [
				{ ...signed, partialSignatureWithNonce: sig },
				{ ...signed, partialSignatureWithNonce: nonce },
				{ ...signed, signature: Buffer.alloc(64, 1) },
				{ ...signed, htlcSignatures: [Buffer.alloc(64)] },
				{ ...signed, channelId: seedFor(866) },
				{ ...signed, fundingTxid: Buffer.from(funding.getHash()).reverse() }
			];
			for (const changed of substitutions) {
				expect(() =>
					b.acceptFinalPeerCommitment(
						id,
						bTerms,
						bob.root,
						bob.index,
						encodeCommitmentSignedMessage(changed)
					)
				).to.throw();
				expect(b.loadFinalOpeningExit(id)).to.equal(null);
			}
			expect(() =>
				b.acceptFinalPeerCommitment(id, bTerms, bob.root, bob.index + 1, valid)
			).to.throw();
			verifyExit(
				b.acceptFinalPeerCommitment(id, bTerms, bob.root, bob.index, valid),
				funding
			);
			expect(() =>
				a.signFinalPeerCommitment(
					id,
					{ ...terms, commitmentFeeratePerKw: 500 },
					alice.root,
					alice.index
				)
			).to.throw();
			expect(a.loadFinalPeerCommitment(id)).to.deep.equal(valid);
			expect(() =>
				b.acceptFinalPeerCommitment(
					id,
					{ ...bTerms, localToSelfDelay: bTerms.localToSelfDelay + 1 },
					bob.root,
					bob.index,
					valid
				)
			).to.throw();
		} finally {
			a.close();
			b.close();
		}
	});

	it('requires the peer contributing no inputs to hold its verified exit before sending its signature', () => {
		const { a, b, id, terms, bTerms, funding } = peers(directory, true);
		try {
			expect(() =>
				b.signFinalPeerCommitment(id, bTerms, bob.root, bob.index)
			).to.throw();
			expect(b.loadFinalPeerCommitment(id)).to.equal(null);
			const aShare = a.signFinalPeerCommitment(
				id,
				terms,
				alice.root,
				alice.index
			);
			verifyExit(
				b.acceptFinalPeerCommitment(id, bTerms, bob.root, bob.index, aShare),
				funding
			);
			verifyExit(
				a.acceptFinalPeerCommitment(
					id,
					terms,
					alice.root,
					alice.index,
					b.signFinalPeerCommitment(id, bTerms, bob.root, bob.index)
				),
				funding
			);
		} finally {
			a.close();
			b.close();
		}
	});

	it('binds the same opening terms across the outgoing and incoming commitment rounds', () => {
		const { a, b, id, terms, bTerms, funding } = peers(directory);
		try {
			const outgoing = a.signFinalPeerCommitment(
				id,
				terms,
				alice.root,
				alice.index
			);
			const incoming = b.signFinalPeerCommitment(
				id,
				bTerms,
				bob.root,
				bob.index
			);
			// The delay we impose on the peer changes only its commitment.
			const changed = {
				...terms,
				localToSelfDelay: terms.localToSelfDelay + 1
			};
			expect(() =>
				a.acceptFinalPeerCommitment(
					id,
					changed,
					alice.root,
					alice.index,
					incoming
				)
			).to.throw();
			expect(a.loadFinalOpeningExit(id)).to.equal(null);
			expect(a.loadFinalPeerCommitment(id)).to.deep.equal(outgoing);
			verifyExit(
				a.acceptFinalPeerCommitment(
					id,
					terms,
					alice.root,
					alice.index,
					incoming
				),
				funding
			);
		} finally {
			a.close();
			b.close();
		}
	});

	for (const restored of [false, true]) {
		const kind = restored ? 'restored' : 'original';
		it(`protects both directions of the signed key locator on the ${kind} wallet`, async () => {
			const { a, b, id, terms, bTerms, funding } = peers(directory);
			let store = a;
			try {
				const peer = b.signFinalPeerCommitment(id, bTerms, bob.root, bob.index);
				const exit = a.acceptFinalPeerCommitment(
					id,
					terms,
					alice.root,
					alice.index,
					peer
				);
				const backup = path.join(directory, 'with-exit.db');
				if (restored) {
					await a.backup(backup);
					store = SqliteStorage.openFinalWallet(backup, alice.binding);
				}
				const ordinary = seedFor(868).toString('hex');
				store.saveChannelKeyIndex(id, alice.index);
				store.saveChannelKeyIndex(ordinary, alice.index + 1);
				expect(() => store.saveChannelKeyIndex(id, alice.index + 2)).to.throw();
				expect(() =>
					store.saveChannelKeyIndex(ordinary, alice.index)
				).to.throw();
				expect(store.loadFinalOpeningExit(id)).to.deep.equal(exit);
				const nextBackup = path.join(directory, 'still-recoverable.db');
				await store.backup(nextBackup);
				const copy = SqliteStorage.openFinalWallet(nextBackup, alice.binding);
				try {
					verifyExit(copy.loadFinalOpeningExit(id)!, funding);
				} finally {
					copy.close();
				}
			} finally {
				if (store !== a) store.close();
				a.close();
				b.close();
			}
		});
	}

	it('preserves recovery progress when backups from the same wallet reach a destination out of order', async () => {
		const { candidate, terms, counterpart, id, funding } = signingFixture();
		const a = SqliteStorage.createFinalWallet(
			path.join(directory, 'a.db'),
			alice.binding
		);
		const b = SqliteStorage.createFinalWallet(
			path.join(directory, 'b.db'),
			bob.binding
		);
		const steps = ['empty', 'candidate', 'local', 'peer', 'outgoing', 'exit'];
		const images = steps.map((step) => path.join(directory, step + '.db'));
		const target = path.join(directory, 'shared-backup.db');
		try {
			await a.backup(images[0]);
			a.rememberFinalOpening(candidate);
			b.rememberFinalOpening(counterpart.candidate);
			await a.backup(images[1]);
			const local = a.finalOpeningTxComplete(id, alice.keys.fundingPrivkey);
			const peer = b.finalOpeningTxComplete(id, bob.keys.fundingPrivkey);
			await a.backup(images[2]);
			a.rememberFinalPeerTxComplete(id, peer);
			b.rememberFinalPeerTxComplete(id, local);
			await a.backup(images[3]);
			const outgoing = a.signFinalPeerCommitment(
				id,
				terms,
				alice.root,
				alice.index
			);
			await a.backup(images[4]);
			const peerShare = b.signFinalPeerCommitment(
				id,
				counterpart.terms,
				bob.root,
				bob.index
			);
			const exit = a.acceptFinalPeerCommitment(
				id,
				terms,
				alice.root,
				alice.index,
				peerShare
			);
			await a.backup(images[5]);
			for (let next = 0; next < images.length; next++) {
				const newer = SqliteStorage.openFinalWallet(
					images[next],
					alice.binding
				);
				try {
					await newer.backup(target);
					await newer.backup(target);
				} finally {
					newer.close();
				}
				if (next > 0) {
					const older = SqliteStorage.openFinalWallet(
						images[next - 1],
						alice.binding
					);
					try {
						let refused = false;
						await older.backup(target).catch(() => {
							refused = true;
						});
						expect(refused, 'preserve ' + steps[next]).to.equal(true);
					} finally {
						older.close();
					}
				}
				const kept = SqliteStorage.openFinalWallet(target, alice.binding);
				try {
					expect(kept.loadFinalOpening(id)).to.deep.equal(
						next >= 1 ? candidate : null
					);
					expect(kept.loadFinalLocalTxComplete(id)).to.deep.equal(
						next >= 2 ? local : null
					);
					expect(kept.loadFinalPeerTxComplete(id)).to.deep.equal(
						next >= 3 ? peer : null
					);
					expect(kept.loadFinalPeerCommitment(id)).to.deep.equal(
						next >= 4 ? outgoing : null
					);
					expect(kept.loadFinalOpeningExit(id)).to.deep.equal(
						next === 5 ? exit : null
					);
					if (next === 5) verifyExit(kept.loadFinalOpeningExit(id)!, funding);
				} finally {
					kept.close();
				}
			}
		} finally {
			a.close();
			b.close();
		}
	});

	it('recovers saved exits and outgoing commitment bytes on a backup while refusing fresh signing', async () => {
		const { a, b, id, terms, bTerms, funding } = peers(directory);
		const before = path.join(directory, 'before.db'),
			after = path.join(directory, 'after.db');
		try {
			await a.backup(before);
			const peer = b.signFinalPeerCommitment(id, bTerms, bob.root, bob.index);
			const ours = a.signFinalPeerCommitment(
				id,
				terms,
				alice.root,
				alice.index
			);
			const exit = a.acceptFinalPeerCommitment(
				id,
				terms,
				alice.root,
				alice.index,
				peer
			);
			await a.backup(after);
			const empty = SqliteStorage.openFinalWallet(before, alice.binding);
			try {
				expect(empty.loadFinalPeerCommitment(id)).to.equal(null);
				expect(empty.loadFinalOpeningExit(id)).to.equal(null);
				expect(() =>
					empty.signFinalPeerCommitment(id, terms, alice.root, alice.index)
				).to.throw();
				expect(() =>
					empty.acceptFinalPeerCommitment(
						id,
						terms,
						alice.root,
						alice.index,
						peer
					)
				).to.throw();
			} finally {
				empty.close();
			}
			const restored = SqliteStorage.openFinalWallet(after, alice.binding);
			try {
				expect(restored.loadFinalPeerCommitment(id)).to.deep.equal(ours);
				expect(restored.loadFinalOpeningExit(id)).to.deep.equal(exit);
				verifyExit(restored.loadFinalOpeningExit(id)!, funding);
				expect(restored.loadFinalOpeningTerms(id)).to.deep.equal(terms);
				const next = path.join(directory, 'copied-again.db');
				await restored.backup(next);
				expect(fs.existsSync(next + '.opening-signer')).to.equal(false);
				const nextReader = SqliteStorage.openFinalWallet(next, alice.binding);
				try {
					expect(nextReader.loadFinalPeerCommitment(id)).to.deep.equal(ours);
					expect(nextReader.loadFinalOpeningExit(id)).to.deep.equal(exit);
					expect(nextReader.loadFinalOpeningTerms(id)).to.deep.equal(terms);
					verifyExit(nextReader.loadFinalOpeningExit(id)!, funding);
				} finally {
					nextReader.close();
				}
			} finally {
				restored.close();
			}
		} finally {
			a.close();
			b.close();
		}
	});
});
