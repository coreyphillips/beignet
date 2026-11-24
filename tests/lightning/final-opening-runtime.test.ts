import { expect } from 'chai';
import type Database from 'better-sqlite3';
import { encryptValue } from '../../src/lightning/storage/encryption';
import type { IFinalOpeningNonces } from '../../src/lightning/storage/final-opening-nonces';
import { payments, script, Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { ecc } from '../../src/utils/ecc';
import { alice, bob, signingFixture } from './helpers/final-opening-signing';
import { otherOpeningView } from './helpers/final-opening-commitment';
import { seedFor } from './helpers/taproot-revoked-fixture';

function openingWithChange(): ReturnType<typeof signingFixture> {
	const fixture = signingFixture();
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

function walletSigner(
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

describe('Resuming a peer-bound final opening', function () {
	this.timeout(30000);
	let dir: string;
	let a: SqliteStorage, b: SqliteStorage;
	let aFile: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-final-runtime-'));
		aFile = path.join(dir, 'a.db');
		a = SqliteStorage.createFinalWallet(aFile, alice.binding);
		b = SqliteStorage.createFinalWallet(path.join(dir, 'b.db'), bob.binding);
	});
	afterEach(() => {
		a.close();
		b.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('persists the first peer, locator, terms and candidate across restart and backup', async () => {
		const { candidate, terms, id } = signingFixture();
		expect(a.loadFinalOpeningSession(id)).to.equal(null);
		a.allocateFinalChannelKeyIndex(alice.index);
		const register = (): void =>
			a.rememberFinalOpeningSession(
				candidate,
				bob.binding.nodeId,
				terms,
				alice.index
			);
		register();
		register();
		expect(a.loadFinalOpening(id)).to.deep.equal(candidate);
		const saved = {
			peer: bob.binding.nodeId,
			terms,
			channelKeyIndex: alice.index
		};
		expect(a.loadFinalOpeningSession(id)).to.deep.equal(saved);
		const changed = {
			...terms,
			remoteToSelfDelay: terms.remoteToSelfDelay + 1
		};
		expect(() =>
			a.rememberFinalOpeningSession(
				candidate,
				bob.binding.nodeId,
				changed,
				alice.index
			)
		).to.throw();
		expect(() =>
			a.rememberFinalOpeningSession(
				candidate,
				getPublicKey(seedFor(1050)).toString('hex'),
				terms,
				alice.index
			)
		).to.throw();
		expect(() =>
			a.rememberFinalOpeningSession(
				candidate,
				bob.binding.nodeId,
				terms,
				alice.index + 1
			)
		).to.throw();
		const backup = path.join(dir, 'copy.db');
		await a.backup(backup);
		a.close();
		a = SqliteStorage.openFinalWallet(aFile, alice.binding);
		expect(a.loadFinalOpeningSession(id)).to.deep.equal(saved);
		const copy = SqliteStorage.openFinalWallet(backup, alice.binding);
		try {
			expect(copy.loadFinalOpeningSession(id)).to.deep.equal(saved);
		} finally {
			copy.close();
		}
	});

	it('refuses authenticated daemon sessions it cannot safely interpret or match to its signed terms', () => {
		const { candidate, counterpart, terms, id } = signingFixture();
		a.allocateFinalChannelKeyIndex(alice.index);
		a.rememberFinalOpeningSession(
			candidate,
			bob.binding.nodeId,
			terms,
			alice.index
		);
		b.rememberFinalOpening(counterpart.candidate);
		a.finalOpeningTxComplete(id, alice.keys.fundingPrivkey);
		a.rememberFinalPeerTxComplete(
			id,
			b.finalOpeningTxComplete(id, bob.keys.fundingPrivkey)
		);
		a.signFinalPeerCommitment(id, terms, alice.root, alice.index);
		const raw = a as unknown as {
			db: Database.Database;
			finalOpeningRecord(id: string): {
				nonceKey: Buffer;
				nonces: IFinalOpeningNonces;
			};
		};
		const { nonces, nonceKey } = raw.finalOpeningRecord(id);
		const session = nonces.session!;
		const accepted: string[] = [];
		for (const [label, value] of [
			['null', null],
			['unknown contract field', { ...session, requireFutureProfile: true }],
			['self peer', { ...session, peer: alice.binding.nodeId }],
			[
				'different signed terms',
				{
					...session,
					terms: { ...terms, remoteToSelfDelay: terms.remoteToSelfDelay + 1 }
				}
			]
		] as const) {
			raw.db
				.prepare(
					'UPDATE final_opening_candidates SET nonces_json=? WHERE channel_id=?'
				)
				.run(
					encryptValue(nonceKey, JSON.stringify({ ...nonces, session: value })),
					id
				);
			try {
				a.loadFinalOpeningSession(id);
				accepted.push(label);
			} catch {
				/* Unknown and contradictory session contracts must be refused. */
			}
		}
		expect(accepted).to.deep.equal([]);
	});

	it('authenticates the peer before accepting any wire bytes and releases the smaller raw-input owner first', async () => {
		const { resumeFinalOpening } = await import(
			'../../src/lightning/channel/final-opening-runtime'
		);
		const { candidate, counterpart, terms, id, funding } = openingWithChange();
		a.allocateFinalChannelKeyIndex(alice.index);
		b.allocateFinalChannelKeyIndex(bob.index);
		a.rememberFinalOpeningSession(
			candidate,
			bob.binding.nodeId,
			terms,
			alice.index
		);
		b.rememberFinalOpeningSession(
			counterpart.candidate,
			alice.binding.nodeId,
			counterpart.terms,
			bob.index
		);
		const A = { storage: a, root: alice.root },
			B = { storage: b, root: bob.root };
		const APeer = bob.binding.nodeId,
			BPeer = alice.binding.nodeId;
		const calls: number[] = [];
		const signA = walletSigner(alice.keys.fundingPrivkey, 0, calls);
		const signB = walletSigner(bob.keys.fundingPrivkey, 1, calls);
		const nonceA = resumeFinalOpening(A, APeer, id).messages;
		const nonceB = resumeFinalOpening(B, BPeer, id).messages;
		expect(nonceA.map((m) => m.type)).to.deep.equal([MessageType.TX_COMPLETE]);
		expect(nonceB.map((m) => m.type)).to.deep.equal([MessageType.TX_COMPLETE]);
		expect(() => resumeFinalOpening(A, BPeer, id, nonceB[0], signA)).to.throw();
		expect(a.loadFinalPeerTxComplete(id)).to.equal(null);
		const shareA = resumeFinalOpening(A, APeer, id, nonceB[0], signA).messages;
		const shareB = resumeFinalOpening(B, BPeer, id, nonceA[0], signB).messages;
		expect(shareA.map((m) => m.type)).to.deep.equal([
			MessageType.COMMITMENT_SIGNED
		]);
		expect(shareB.map((m) => m.type)).to.deep.equal([
			MessageType.COMMITMENT_SIGNED
		]);
		expect(calls).to.be.empty;
		expect(resumeFinalOpening(B, BPeer, id, shareA[0], signB).messages).to.be
			.empty;
		expect(b.loadFinalOpeningExit(id)).to.be.instanceOf(Buffer);
		const first = resumeFinalOpening(A, APeer, id, shareB[0], signA);
		expect(a.loadFinalOpeningExit(id)).to.be.instanceOf(Buffer);
		expect(first.messages.map((m) => m.type)).to.deep.equal([
			MessageType.TX_SIGNATURES
		]);
		expect(calls).to.deep.equal([0]);
		const second = resumeFinalOpening(B, BPeer, id, first.messages[0], signB);
		expect(second.messages.map((m) => m.type)).to.deep.equal([
			MessageType.TX_SIGNATURES
		]);
		expect(calls).to.deep.equal([0, 1]);
		const complete = resumeFinalOpening(
			A,
			APeer,
			id,
			second.messages[0],
			signA
		);
		expect(complete.fundingTx).to.deep.equal(second.fundingTx);
		const signed = Transaction.fromBuffer(complete.fundingTx!);
		expect(signed.getId()).to.equal(funding.getId());
		expect(signed.ins.map((i) => i.witness.length)).to.deep.equal([2, 2]);
		expect(resumeFinalOpening(A, APeer, id, second.messages[0], signA).messages)
			.to.be.empty;
		expect(calls).to.deep.equal([0, 1]);
		const held = resumeFinalOpening(A, APeer, id, undefined, signA);
		const backup = path.join(dir, 'signed-copy.db');
		await a.backup(backup);
		const restored = SqliteStorage.openFinalWallet(backup, alice.binding);
		try {
			const replay = resumeFinalOpening(
				{ storage: restored, root: alice.root },
				APeer,
				id,
				undefined,
				signA
			);
			expect(replay).to.deep.equal(held);
			expect(replay.messages.map((m) => m.type)).to.deep.equal([
				MessageType.TX_COMPLETE,
				MessageType.COMMITMENT_SIGNED,
				MessageType.TX_SIGNATURES
			]);
			expect(calls).to.deep.equal([0, 1]);
		} finally {
			restored.close();
		}
	});
});
