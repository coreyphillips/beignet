import { expect } from 'chai';
import type Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { payments, script, Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../src/utils/ecc';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	decodeTxSignaturesMessage,
	encodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';
import {
	alice,
	bob,
	participant,
	signingFixture
} from './helpers/final-opening-signing';
import { otherOpeningView } from './helpers/final-opening-commitment';

describe('Final opening wallet witness release', () => {
	let dir: string;
	let a: SqliteStorage, b: SqliteStorage;
	const secrets = [Buffer.alloc(32, 23), Buffer.alloc(32, 24)];
	const keys = secrets.map(getPublicKey);
	const scripts = [
		payments.p2wpkh({ pubkey: keys[0] }).output!,
		Buffer.concat([Buffer.of(0x51, 32), keys[1].subarray(1)])
	];
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'funding-witness-'));
		a = SqliteStorage.createFinalWallet(path.join(dir, 'a'), alice.binding);
		b = SqliteStorage.createFinalWallet(path.join(dir, 'b'), bob.binding);
	});
	afterEach(() => {
		a.close();
		b.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	function prepare(oneSided = false, left = alice, right = bob) {
		const { candidate, terms, id, funding } = signingFixture(
			oneSided,
			left,
			right
		);
		const values = candidate.inputs.map((input, i) => {
			const prev = Transaction.fromHex(input.prevTxHex);
			prev.outs[0].script = scripts[i];
			funding.ins[i].hash = prev.getHash();
			input.prevTxHex = prev.toHex();
			return prev.outs[0].value;
		});
		candidate.fundingTxHex = funding.toHex();
		const other = otherOpeningView(candidate, terms);
		a.rememberFinalOpening(candidate);
		b.rememberFinalOpening(other.candidate);
		const aNonce = a.finalOpeningTxComplete(id, left.keys.fundingPrivkey);
		const bNonce = b.finalOpeningTxComplete(id, right.keys.fundingPrivkey);
		a.rememberFinalPeerTxComplete(id, bNonce);
		b.rememberFinalPeerTxComplete(id, aNonce);
		function commits() {
			const first = a.signFinalPeerCommitment(id, terms, left.root, left.index);
			b.acceptFinalPeerCommitment(
				id,
				other.terms,
				right.root,
				right.index,
				first
			);
			const second = b.signFinalPeerCommitment(
				id,
				other.terms,
				right.root,
				right.index
			);
			a.acceptFinalPeerCommitment(id, terms, left.root, left.index, second);
		}
		function witness(tx: Transaction, indices: readonly number[]): Buffer[][] {
			return indices.map((i) => {
				if (i === 1)
					return [
						Buffer.from(
							ecc.signSchnorr(
								tx.hashForWitnessV1(
									i,
									scripts,
									values,
									Transaction.SIGHASH_DEFAULT
								),
								secrets[i]
							)
						)
					];
				const hash = tx.hashForWitnessV0(
					i,
					payments.p2pkh({ pubkey: keys[i] }).output!,
					values[i],
					Transaction.SIGHASH_ALL
				);
				return [
					script.signature.encode(
						Buffer.from(ecc.sign(hash, secrets[i])),
						Transaction.SIGHASH_ALL
					),
					keys[i]
				];
			});
		}
		return { id, terms, other, funding, commits, witness };
	}
	it('gates the wallet callback on the verified local exit and saved outgoing commitment', () => {
		const { id, terms, other, witness } = prepare();
		let calls = 0;
		const sign = (tx: Transaction, indices: readonly number[]) => {
			calls++;
			return witness(tx, indices);
		};
		expect(() => a.finalOpeningTxSignatures(id, sign)).to.throw();
		const first = a.signFinalPeerCommitment(id, terms, alice.root, alice.index);
		expect(() => a.finalOpeningTxSignatures(id, sign)).to.throw();
		b.acceptFinalPeerCommitment(id, other.terms, bob.root, bob.index, first);
		expect(() => b.finalOpeningTxSignatures(id, sign)).to.throw();
		expect(calls).to.equal(0);
	});
	it('verifies both input types and exactly replays the mixed-input funding transaction across restart and backup', async () => {
		const { id, funding, commits, witness } = prepare();
		commits();
		const once = (tx: Transaction, indices: readonly number[]) => {
			expect(tx.toHex()).to.equal(funding.toHex());
			expect(indices).to.deep.equal([0]);
			return witness(tx, indices);
		};
		const never = (): never => {
			throw new Error('unexpected wallet signing');
		};
		const msgA = a.finalOpeningTxSignatures(id, once);
		expect(a.loadFinalFundingTransaction(id)).to.equal(null);
		const msgB = b.finalOpeningTxSignatures(id, witness);
		const wire = decodeTxSignaturesMessage(msgB, { taproot: true });
		expect(wire.txid.equals(funding.getHash())).to.equal(true);
		for (const bad of [
			{ ...wire, witnesses: [] },
			{ ...wire, txid: Buffer.alloc(32, 5) },
			{ ...wire, witnesses: [[Buffer.alloc(64, 1)]] },
			{ ...wire, sharedInputSignature: Buffer.alloc(64) }
		])
			expect(() =>
				a.rememberFinalPeerTxSignatures(id, encodeTxSignaturesMessage(bad))
			).to.throw();
		expect(a.loadFinalPeerTxSignatures(id)).to.equal(null);
		a.rememberFinalPeerTxSignatures(id, msgB);
		b.rememberFinalPeerTxSignatures(id, msgA);
		const expected = funding.clone();
		expected.setWitness(0, decodeTxSignaturesMessage(msgA).witnesses[0]);
		expected.setWitness(1, wire.witnesses[0]);
		expect(a.loadFinalFundingTransaction(id)).to.deep.equal(
			expected.toBuffer()
		);
		expect(b.loadFinalFundingTransaction(id)).to.deep.equal(
			expected.toBuffer()
		);
		a.close();
		a = SqliteStorage.openFinalWallet(path.join(dir, 'a'), alice.binding);
		expect(a.finalOpeningTxSignatures(id, never)).to.deep.equal(msgA);
		const backup = path.join(dir, 'copy');
		await a.backup(backup);
		const restored = SqliteStorage.openFinalWallet(backup, alice.binding);
		try {
			expect(restored.finalOpeningTxSignatures(id, never)).to.deep.equal(msgA);
			expect(restored.loadFinalFundingTransaction(id)).to.deep.equal(
				expected.toBuffer()
			);
			expect(restored.loadFinalLocalTxSignatures(id)).to.deep.equal(msgA);
		} finally {
			restored.close();
		}
	});
	it('replays the original signer result after SQLite silently skips the first funding update', () => {
		const { id, commits, witness } = prepare();
		commits();
		const raw = (a as unknown as { db: Database.Database }).db;
		raw.exec(
			'CREATE TEMP TRIGGER skip_funding_update BEFORE UPDATE OF nonces_json ON final_opening_candidates BEGIN SELECT RAISE(IGNORE); END'
		);
		let calls = 0;
		const sign = (tx: Transaction, indices: readonly number[]): Buffer[][] => {
			calls++;
			return witness(tx, indices);
		};
		expect(() => a.finalOpeningTxSignatures(id, sign)).to.throw();
		expect(calls).to.equal(1);
		expect(a.loadFinalLocalTxSignatures(id)).to.equal(null);
		a.close();
		a = SqliteStorage.openFinalWallet(path.join(dir, 'a'), alice.binding);
		const sent = a.finalOpeningTxSignatures(id, sign);
		expect(calls).to.equal(1);
		expect(a.loadFinalLocalTxSignatures(id)).to.deep.equal(sent);
	});

	it('keeps a previously signed wallet input exclusive to its own opening across restart', () => {
		const first = prepare();
		const second = prepare(false, participant(840, 12), participant(841, 14));
		expect(first.id).not.to.equal(second.id);
		expect(first.funding.ins[0].hash).to.deep.equal(second.funding.ins[0].hash);
		first.commits();
		second.commits();
		a.finalOpeningTxSignatures(first.id, first.witness);
		a.close();
		a = SqliteStorage.openFinalWallet(path.join(dir, 'a'), alice.binding);
		let calls = 0;
		expect(() =>
			a.finalOpeningTxSignatures(second.id, (tx, indices) => {
				calls++;
				return second.witness(tx, indices);
			})
		).to.throw();
		expect(calls).to.equal(0);
		expect(a.loadFinalLocalTxSignatures(second.id)).to.equal(null);
	});
	it('checks the authenticated funding transaction against the saved witnesses on every read', () => {
		const { id, commits, witness } = prepare();
		commits();
		a.finalOpeningTxSignatures(id, witness);
		a.rememberFinalPeerTxSignatures(
			id,
			b.finalOpeningTxSignatures(id, witness)
		);
		const full = a.loadFinalFundingTransaction(id)!;
		// Exercise the storage writer's readback, including rollback of an inconsistent row.
		const writer = a as unknown as {
			updateOpeningNonces(
				id: string,
				update: (state: { signing: { fundingTransaction: string } }) => void
			): void;
		};
		expect(() =>
			writer.updateOpeningNonces(id, (state) => {
				state.signing.fundingTransaction = '00';
			})
		).to.throw();
		expect(a.loadFinalFundingTransaction(id)).to.deep.equal(full);
	});
	it('rejects a witness produced for different outputs and preserves the negotiated candidate', () => {
		const { id, funding, commits, witness } = prepare();
		commits();
		expect(() =>
			a.finalOpeningTxSignatures(id, (tx, indices) => {
				tx.outs[0].value--;
				return witness(tx, indices);
			})
		).to.throw();
		expect(a.loadFinalLocalTxSignatures(id)).to.equal(null);
		expect(a.loadFinalOpening(id)!.fundingTxHex).to.equal(funding.toHex());
		const recovered = a.finalOpeningTxSignatures(id, witness);
		expect(decodeTxSignaturesMessage(recovered).txid).to.deep.equal(
			funding.getHash()
		);
	});
	it('refuses a fresh witness on a restored backup and never asks a zero-input receiver to sign', async () => {
		const { id, commits } = prepare(true);
		commits();
		const backup = path.join(dir, 'pre-release');
		await a.backup(backup);
		const restored = SqliteStorage.openFinalWallet(backup, alice.binding);
		let calls = 0;
		const none = (): Buffer[][] => {
			calls++;
			return [];
		};
		try {
			expect(() => restored.finalOpeningTxSignatures(id, none)).to.throw();
			expect(calls).to.equal(0);
		} finally {
			restored.close();
		}
		const empty = b.finalOpeningTxSignatures(id, none);
		expect(decodeTxSignaturesMessage(empty).witnesses).to.deep.equal([]);
		expect(calls).to.equal(0);
		expect(() => a.finalOpeningTxSignatures(id, none)).to.throw();
		expect(a.loadFinalLocalTxSignatures(id)).to.equal(null);
	});
});
