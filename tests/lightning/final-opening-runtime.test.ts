import { FinalOpeningTransport } from '../../src/lightning/channel/final-opening-transport';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import { expect } from 'chai';
import type Database from 'better-sqlite3';
import { encryptValue } from '../../src/lightning/storage/encryption';
import type { IFinalOpeningNonces } from '../../src/lightning/storage/final-opening-nonces';
import { payments, script, Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	decodeChannelReadyMessage,
	encodeChannelReadyMessage
} from '../../src/lightning/message/channel-funding';
import { decodeTxCompleteMessage } from '../../src/lightning/message/interactive-tx';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
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

	function fundReadyPair(losePeerWitness = false): string {
		const { candidate, counterpart, terms, id } = openingWithChange();
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
			second(bob)
		);
		b.rememberFinalOpeningSession(
			counterpart.candidate,
			alice.binding.nodeId,
			counterpart.terms,
			bob.index,
			second(alice)
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
		if (!losePeerWitness) a.rememberFinalPeerTxSignatures(id, fb);
		return id;
	}

	it('replays an outstanding funding witness before the lost ready message and agrees on both effective nonces', async () => {
		const id = fundReadyPair(true);
		const sent: { peer: string; type: MessageType; payload: Buffer }[] = [];
		const refused: string[] = [];
		const build = (
			storage: SqliteStorage,
			side: typeof alice
		): FinalOpeningTransport =>
			new FinalOpeningTransport(
				{ storage, root: side.root },
				async () => 'unspent',
				() => null,
				(peer, type, payload) => sent.push({ peer, type, payload }),
				() => undefined,
				(_i, msg) => refused.push(msg),
				() => ({ alias: true, splice: true }),
				(_p, _i, msg) => refused.push('fail ' + msg)
			);
		const A = build(a, alice),
			B = build(b, bob);
		const original = b.finalOpeningChannelReady(id, bob.root);
		expect(a.loadFinalFundingTransaction(id)).to.equal(null);
		A.fundingDepth(id, true);
		B.fundingDepth(id, true);
		A.reconnected(bob.binding.nodeId);
		B.reconnected(alice.binding.nodeId);
		const [pending, funded] = sent.map((x) =>
			decodeChannelReestablishMessage(x.payload, { finalTaproot: true })
		);
		expect(pending.nextFundingRetransmitFlags).to.equal(0);
		expect(funded.nextFundingTxid).to.equal(undefined);
		expect(funded.myCurrentFundingLocked?.txid).to.deep.equal(
			pending.nextFundingTxid
		);
		const deliver = async (): Promise<void> => {
			const batch = sent.splice(0);
			for (const m of batch) {
				const toA = m.peer === alice.binding.nodeId;
				(toA ? A : B).queue(
					toA ? bob.binding.nodeId : alice.binding.nodeId,
					id,
					m
				);
			}
			await new Promise<void>((r) => setImmediate(r));
		};
		await deliver();
		const replay = sent.filter((x) => x.peer === alice.binding.nodeId);
		const witnessIndex = replay.findIndex(
			(x) => x.type === MessageType.TX_SIGNATURES
		);
		const readyIndex = replay.findIndex(
			(x) => x.type === MessageType.CHANNEL_READY
		);
		expect(witnessIndex).to.be.at.least(0);
		expect(readyIndex).to.be.greaterThan(witnessIndex);
		expect(replay[witnessIndex].payload).to.deep.equal(
			b.loadFinalLocalTxSignatures(id)
		);
		expect(replay[readyIndex].payload).to.deep.equal(original);
		for (let n = 0; n < 8 && sent.length; n++) await deliver();
		expect(sent).to.be.empty;
		expect(refused).to.deep.equal([]);
		expect(a.loadFinalFundingTransaction(id)).to.deep.equal(
			b.loadFinalFundingTransaction(id)
		);
		expect(a.loadFinalPeerChannelReady(id)).to.deep.equal(original);
		const aliceNonces = a.loadFinalCommitmentOneNonces(id)!;
		const bobNonces = b.loadFinalCommitmentOneNonces(id)!;
		expect(aliceNonces.local).to.deep.equal(bobNonces.peer);
		expect(aliceNonces.peer).to.deep.equal(bobNonces.local);
	});

	it('retains exact ready bytes, point one and both reconnect promises across restart and backup', async () => {
		const id = fundReadyPair();
		expect(() => a.finalOpeningChannelReady(id, bob.root)).to.throw();
		const local = a.finalOpeningChannelReady(id, alice.root);
		const peer = b.finalOpeningChannelReady(id, bob.root);
		const ours = decodeChannelReadyMessage(local);
		const expected = getPublicKey(
			generateFromSeed(alice.keys.perCommitmentSeed, MAX_INDEX - 1n)
		);
		expect(ours.secondPerCommitmentPoint).to.deep.equal(expected);
		expect(ours.shortChannelId).to.have.length(8);
		const pair = decodeTxCompleteMessage(a.loadFinalLocalTxComplete(id)!, {
			taproot: true
		}).commitNonces!;
		a.rememberFinalPeerChannelReady(id, peer, true);
		a.rememberFinalPeerChannelReady(id, peer, true);
		const backup = path.join(dir, 'ready-copy.db');
		await a.backup(backup);
		const n1 = a.renewFinalReestablishNonce(id, alice.root);
		const theirNonce = b.renewFinalReestablishNonce(id, bob.root);
		a.rememberFinalPeerReestablishNonce(id, theirNonce);
		await a.backup(backup);
		a.close();
		a = SqliteStorage.openFinalWallet(aFile, alice.binding);
		const n2 = a.renewFinalReestablishNonce(id, alice.root);
		expect(
			new Set(
				[pair.current, pair.next, ours.nextLocalNonce!, n1, n2].map((n) =>
					n.toString('hex')
				)
			).size
		).to.equal(5);
		await a.backup(backup);
		for (const store of [
			a,
			SqliteStorage.openFinalWallet(backup, alice.binding)
		]) {
			try {
				expect(store.finalOpeningChannelReady(id, alice.root)).to.deep.equal(
					local
				);
				expect(store.loadFinalLocalChannelReady(id)).to.deep.equal(local);
				expect(store.loadFinalPeerChannelReady(id)).to.deep.equal(peer);
				expect(store.loadFinalCommitmentOneNonces(id)).to.deep.equal({
					local: n2,
					peer: theirNonce
				});
				expect(store.loadFinalLocalReestablishNonce(id)).to.deep.equal(n2);
				expect(store.loadFinalPeerReestablishNonce(id)).to.deep.equal(
					theirNonce
				);
				if (store !== a)
					expect(() =>
						store.renewFinalReestablishNonce(id, alice.root)
					).to.throw();
			} finally {
				if (store !== a) store.close();
			}
		}
	});

	it('selects the reconnect nonce on both sides of a lost-ready crossing', () => {
		const id = fundReadyPair();
		const firstA = a.finalOpeningChannelReady(id, alice.root);
		const firstB = b.finalOpeningChannelReady(id, bob.root);
		a.rememberFinalPeerChannelReady(id, firstB);
		expect(a.loadFinalCommitmentOneNonces(id)).to.deep.equal({
			local: decodeChannelReadyMessage(firstA).nextLocalNonce,
			peer: decodeChannelReadyMessage(firstB).nextLocalNonce
		});
		expect(b.loadFinalCommitmentOneNonces(id)).to.equal(null);
		const latestA = a.renewFinalReestablishNonce(id, alice.root);
		const latestB = b.renewFinalReestablishNonce(id, bob.root);
		b.rememberFinalPeerReestablishNonce(id, latestA);
		a.rememberFinalPeerReestablishNonce(id, latestB);
		b.rememberFinalPeerChannelReady(id, firstA);
		a.rememberFinalPeerChannelReady(id, firstB);
		expect(a.loadFinalCommitmentOneNonces(id)).to.deep.equal({
			local: latestA,
			peer: latestB
		});
		expect(b.loadFinalCommitmentOneNonces(id)).to.deep.equal({
			local: latestB,
			peer: latestA
		});
	});

	it('refuses a stale wallet backup and skips reconnect generations already issued by its device', async () => {
		const id = fundReadyPair();
		const local = a.finalOpeningChannelReady(id, alice.root);
		const peer = b.finalOpeningChannelReady(id, bob.root);
		const db = (a as unknown as { db: Database.Database }).db;
		const row = db
			.prepare(
				'SELECT nonces_json FROM final_opening_candidates WHERE channel_id=?'
			)
			.get(id) as { nonces_json: string };
		a.rememberFinalPeerChannelReady(id, peer);
		const n1 = a.renewFinalReestablishNonce(id, alice.root);
		const n2 = a.renewFinalReestablishNonce(id, alice.root);
		const backup = path.join(dir, 'advanced.db');
		await a.backup(backup);
		db.prepare(
			'UPDATE final_opening_candidates SET nonces_json=? WHERE channel_id=?'
		).run(row.nonces_json, id);
		let failure: unknown;
		try {
			await a.backup(backup);
		} catch (err) {
			failure = err;
		}
		expect(failure).to.be.instanceOf(Error);
		expect(a.finalOpeningChannelReady(id, alice.root)).to.deep.equal(local);
		const changed = encodeChannelReadyMessage({
			...decodeChannelReadyMessage(peer),
			shortChannelId: Buffer.alloc(8, 7)
		});
		a.rememberFinalPeerChannelReady(id, changed);
		expect(a.loadFinalPeerChannelReady(id)).to.deep.equal(peer);
		a.rememberFinalPeerChannelReady(id, peer);
		const n3 = a.renewFinalReestablishNonce(id, alice.root);
		expect(n3).not.to.deep.equal(n1);
		expect(n3).not.to.deep.equal(n2);
		await a.backup(backup);
	});

	it('restores a force-close decision after rolling an original wallet back and retains it in a backup', async () => {
		const id = fundReadyPair();
		const local = a.finalOpeningChannelReady(id, alice.root);
		a.rememberFinalPeerChannelReady(
			id,
			b.finalOpeningChannelReady(id, bob.root)
		);
		a.close();
		const before = path.join(dir, 'before-close.db');
		fs.copyFileSync(aFile, before);
		a = SqliteStorage.openFinalWallet(aFile, alice.binding);
		const exit = a.requestFinalOpeningExit(id);
		a.close();
		fs.copyFileSync(before, aFile);
		a = SqliteStorage.openFinalWallet(aFile, alice.binding);
		expect(a.loadFinalDaemonOpening(id)?.exitToBroadcast).to.deep.equal(exit);
		expect(a.loadFinalCommitmentOneNonces(id)).to.equal(null);
		expect(() => a.renewFinalReestablishNonce(id, alice.root)).to.throw();
		expect(() => a.finalOpeningChannelReady(id, alice.root)).to.throw();
		const pathCopy = path.join(dir, 'closed-backup.db');
		await a.backup(pathCopy);
		const copy = SqliteStorage.openFinalWallet(pathCopy, alice.binding);
		try {
			expect(copy.canSignFinalOpening).to.equal(false);
			expect(copy.loadFinalLocalChannelReady(id)).to.deep.equal(local);
			expect(copy.loadFinalDaemonOpening(id)?.exitToBroadcast).to.deep.equal(
				exit
			);
			expect(copy.requestFinalOpeningExit(id)).to.deep.equal(exit);
		} finally {
			copy.close();
		}
	});

	it('enrolls an existing wallet-only close on upgrade before recovering an older wallet', () => {
		const id = fundReadyPair();
		a.close();
		const before = path.join(dir, 'old-format-before-close.db');
		fs.copyFileSync(aFile, before);
		a = SqliteStorage.openFinalWallet(aFile, alice.binding);
		const raw = a as unknown as {
			db: Database.Database;
			finalOpeningRecord(channelId: string): {
				nonceKey: Buffer;
				nonces: IFinalOpeningNonces;
			};
		};
		const { nonceKey, nonces } = raw.finalOpeningRecord(id);
		nonces.signing!.exitRequested = true;
		raw.db
			.prepare(
				'UPDATE final_opening_candidates SET nonces_json=? WHERE channel_id=?'
			)
			.run(encryptValue(nonceKey, JSON.stringify(nonces)), id);
		a.close();
		a = SqliteStorage.openFinalWallet(aFile, alice.binding);
		const exit = a.loadFinalDaemonOpening(id)!.exitToBroadcast;
		expect(exit).to.deep.equal(a.loadFinalOpeningExit(id));
		a.close();
		fs.copyFileSync(before, aFile);
		a = SqliteStorage.openFinalWallet(aFile, alice.binding);
		expect(a.loadFinalDaemonOpening(id)!.exitToBroadcast).to.deep.equal(exit);
		expect(() => a.renewFinalReestablishNonce(id, alice.root)).to.throw();
	});

	it('validates the peer ready point, nonce, channel and alias and accepts an unused height-one promise', () => {
		const id = fundReadyPair();
		const peer = decodeChannelReadyMessage(
			b.finalOpeningChannelReady(id, bob.root)
		);
		const local = decodeChannelReadyMessage(
			a.finalOpeningChannelReady(id, alice.root)
		);
		const peerOpening = decodeTxCompleteMessage(
			a.loadFinalPeerTxComplete(id)!,
			{ taproot: true }
		).commitNonces!;
		for (const changed of [
			{ ...peer, channelId: seedFor(1010) },
			{ ...peer, secondPerCommitmentPoint: local.secondPerCommitmentPoint },
			{ ...peer, nextLocalNonce: Buffer.alloc(66) },
			{ ...peer, nextLocalNonce: peerOpening.current },
			{ ...peer, nextLocalNonce: local.nextLocalNonce },
			{ ...peer, nextLocalNonce: undefined },
			{ ...peer, shortChannelId: Buffer.alloc(2) },
			{ ...peer, shortChannelId: undefined }
		]) {
			expect(() =>
				a.rememberFinalPeerChannelReady(
					id,
					encodeChannelReadyMessage(changed),
					true
				)
			).to.throw();
			expect(a.loadFinalPeerChannelReady(id)).to.equal(null);
		}
		const deterministic = encodeChannelReadyMessage({
			...peer,
			nextLocalNonce: peerOpening.next
		});
		a.rememberFinalPeerReestablishNonce(id, peerOpening.next);
		a.rememberFinalPeerChannelReady(id, deterministic, true);
		expect(() =>
			a.rememberFinalPeerChannelReady(id, encodeChannelReadyMessage(peer), true)
		).to.throw();
		expect(() =>
			a.rememberFinalPeerReestablishNonce(id, peerOpening.current)
		).to.throw();
		expect(a.loadFinalPeerChannelReady(id)).to.deep.equal(deterministic);
		a.requestFinalOpeningExit(id);
		expect(() => a.renewFinalReestablishNonce(id, alice.root)).to.throw();
		expect(() => a.finalOpeningChannelReady(id, alice.root)).to.throw();
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
