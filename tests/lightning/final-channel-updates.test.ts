import {
	generateSide,
	fundReadyPair,
	type Side
} from './helpers/final-update-pair';
import { expect } from 'chai';
import { encryptValue } from '../../src/lightning/storage/encryption';
import type { IFinalOpeningNonces } from '../../src/lightning/storage/final-opening-nonces';
import { FinalOpeningTransport } from '../../src/lightning/channel/final-opening-transport';
import type { IFinalOpeningMessage } from '../../src/lightning/channel/final-opening-runtime';
import { encodeStartBatchMessage } from '../../src/lightning/message/splice';
import type { IFinalSpliceAttempt } from '../../src/lightning/channel/final-splice-state';
import type { IFinalFundingReference } from '../../src/lightning/channel/final-splice-candidate';
import type { FinalOpeningAuthority } from '../../src/lightning/storage/final-opening-authority';
import {
	signFinalUpdate,
	spliceCommitmentNonceContext,
	updateVerificationNonce
} from '../../src/lightning/storage/final-update-signing';
import { buildFinalCommitmentView } from '../../src/lightning/channel/final-opening-commitment';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { deriveChannelKeys } from '../../src/lightning/keys/wallet-keys';
import { decodeRevokeAndAckMessage } from '../../src/lightning/message/channel-commitment';
import type Database from 'better-sqlite3';
import {
	validateFinalSpliceReserves,
	finalSpliceWithdrawalSats
} from '../../src/lightning/channel/final-commitment-reserve';
import { calculateCommitmentFee } from '../../src/lightning/channel/commitment-builder';
import { ANCHOR_TOTAL_COST } from '../../src/lightning/script/anchor';
import { Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { sha256 } from '../../src/lightning/crypto/provider';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../../src/lightning/message/channel-commitment';
import {
	encodeUpdateFeeMessage,
	encodeUpdateAddHtlcMessage,
	encodeUpdateFulfillHtlcMessage
} from '../../src/lightning/message/channel-update';

describe('Durable final commitment updates', function () {
	this.timeout(60000);
	let dir: string,
		aFile: string,
		a: SqliteStorage,
		b: SqliteStorage,
		alice: Side,
		bob: Side,
		id: string;
	const preimage = Buffer.alloc(32, 234);
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'final-updates-'));
		aFile = path.join(dir, 'a.db');
		alice = generateSide();
		bob = generateSide();
		a = SqliteStorage.createFinalWallet(aFile, alice.binding);
		b = SqliteStorage.createFinalWallet(path.join(dir, 'b.db'), bob.binding);
		id = fundReadyPair(a, b, alice, bob);
	});
	afterEach(() => {
		a?.close();
		b?.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	function stage(
		sender: SqliteStorage,
		receiver: SqliteStorage,
		type: MessageType,
		wire: Buffer
	) {
		sender.stageFinalHtlcUpdate(id, 'local', type, wire);
		receiver.stageFinalHtlcUpdate(id, 'peer', type, wire);
	}
	function exchange(
		sender: SqliteStorage,
		receiver: SqliteStorage,
		left: Side,
		right: Side
	) {
		const sig = sender.signFinalUpdateCommitment(id, left.root);
		expect(sender.signFinalUpdateCommitment(id, left.root)).to.deep.equal(sig);
		const ack = receiver.acceptFinalUpdateCommitment(id, right.root, sig);
		expect(
			receiver.acceptFinalUpdateCommitment(id, right.root, sig)
		).to.deep.equal(ack);
		sender.acceptFinalUpdateRevocation(id, ack);
		sender.acceptFinalUpdateRevocation(id, ack);
		return { sig, ack };
	}
	function add(seq = 0n) {
		return encodeUpdateAddHtlcMessage({
			channelId: Buffer.from(id, 'hex'),
			id: seq,
			amountMsat: 8000000n,
			paymentHash: sha256(preimage),
			cltvExpiry: 1100,
			onionRoutingPacket: Buffer.alloc(1366)
		});
	}
	it('locks add and fulfill on both commitments, recovers after wallet-only rollback and never offers a revoked opening exit', async () => {
		const opening = a.loadFinalOpeningExit(id)!;
		const start = a.loadFinalUpdateStatus(id)!;
		const backup = path.join(dir, 'before.db');
		await a.backup(backup);
		const oldWallet = path.join(dir, 'original.db');
		a.checkpoint();
		fs.copyFileSync(aFile, oldWallet);
		stage(a, b, MessageType.UPDATE_ADD_HTLC, add());
		expect(a.loadFinalOfferedHtlc(id, 0n)?.paymentHash).to.deep.equal(
			sha256(preimage)
		);
		exchange(a, b, alice, bob);
		exchange(b, a, bob, alice);
		expect(a.loadFinalUpdateStatus(id)!.htlcs).to.have.length(1);
		const event = a.loadFinalUpdateDeliveries(id)[0];
		expect(event.payload).to.deep.equal(add());
		a.ackFinalUpdateDelivery(id, event.id);
		const baseFulfill = encodeUpdateFulfillHtlcMessage({
			channelId: Buffer.from(id, 'hex'),
			id: 0n,
			paymentPreimage: preimage
		});
		const fulfill = Buffer.concat([
			baseFulfill,
			Buffer.from([1, 0xfd, 3, 0x98]),
			Buffer.alloc(920)
		]);
		expect(() =>
			a.stageFinalHtlcUpdate(
				id,
				'peer',
				MessageType.UPDATE_FULFILL_HTLC,
				Buffer.concat([baseFulfill, Buffer.of(2, 0)])
			)
		).to.throw(/Unknown required TLV/);
		stage(b, a, MessageType.UPDATE_FULFILL_HTLC, fulfill);
		exchange(b, a, bob, alice);
		exchange(a, b, alice, bob);
		const end = a.loadFinalUpdateStatus(id)!;
		expect(end.localHeight).to.equal(2n);
		expect(end.remoteHeight).to.equal(2n);
		expect(end.localBalanceMsat).to.equal(start.localBalanceMsat - 8000000n);
		expect(end.htlcs).to.deep.equal([]);
		expect(a.loadFinalOfferedHtlc(id, 0n)).to.equal(null);
		const resolutions = a.loadFinalResolutionStates(id)!;
		expect(resolutions.revoked.map((v) => v.height)).to.deep.equal([0n, 1n]);
		expect(
			resolutions.revoked.every((v) => getPublicKey(v.secret!).equals(v.point))
		).to.equal(true);
		expect(resolutions.preimages).to.deep.equal([preimage]);
		expect(resolutions.remote[0].height).to.equal(2n);
		expect(() => a.loadFinalOpeningExit(id)).to.throw(/superseded/);
		const copy = SqliteStorage.openFinalWallet(backup, alice.binding);
		try {
			expect(() => copy.requestFinalOpeningExit(id)).to.throw(/original/);
		} finally {
			copy.close();
		}
		a.close();
		fs.copyFileSync(oldWallet, aFile);
		a = SqliteStorage.openFinalWallet(aFile, alice.binding);
		expect(a.loadFinalUpdateStatus(id)!.localHeight).to.equal(2n);
		const current = a.requestFinalOpeningExit(id);
		expect(current).not.to.deep.equal(opening);
		const terminalDelivery = a.loadFinalUpdateDeliveries(id)[0];
		expect(terminalDelivery.payload).to.deep.equal(fulfill);
		a.ackFinalUpdateDelivery(id, terminalDelivery.id);
		expect(a.loadFinalUpdateDeliveries(id)).to.deep.equal([]);
		expect(a.loadFinalDaemonOpening(id)!.exitToBroadcast).to.deep.equal(
			current
		);
		expect(() =>
			a.stageFinalHtlcUpdate(id, 'local', MessageType.UPDATE_ADD_HTLC, add(1n))
		).to.throw();
	});
	it('re-signs the unchanged bundle against a fresh nonce when commitment_signed was lost', () => {
		stage(a, b, MessageType.UPDATE_ADD_HTLC, add());
		const first = a.signFinalUpdateCommitment(id, alice.root);
		const ra = a.finalUpdateReestablish(id, alice.root),
			rb = b.finalUpdateReestablish(id, bob.root);
		const replay = a.acceptFinalUpdateReestablish(id, alice.root, rb);
		expect(b.acceptFinalUpdateReestablish(id, bob.root, ra)).to.deep.equal([]);
		expect(replay.map((x) => x.type)).to.deep.equal([
			MessageType.UPDATE_ADD_HTLC,
			MessageType.COMMITMENT_SIGNED
		]);
		expect(replay[0].payload).to.deep.equal(add());
		expect(replay[1].payload).not.to.deep.equal(first);
		expect(
			decodeCommitmentSignedMessage(replay[1].payload).htlcSignatures
		).to.deep.equal(decodeCommitmentSignedMessage(first).htlcSignatures);
		b.stageFinalHtlcUpdate(
			id,
			'peer',
			MessageType.UPDATE_ADD_HTLC,
			replay[0].payload
		);
		a.acceptFinalUpdateRevocation(
			id,
			b.acceptFinalUpdateCommitment(id, bob.root, replay[1].payload)
		);
		exchange(b, a, bob, alice);
		expect(b.loadFinalUpdateStatus(id)!.htlcs).to.have.length(1);
	});

	it('replays a lost revocation byte for byte, then accepts the next commitment against its re-advertised nonce', () => {
		stage(a, b, MessageType.UPDATE_ADD_HTLC, add());
		const first = a.signFinalUpdateCommitment(id, alice.root);
		const ack = b.acceptFinalUpdateCommitment(id, bob.root, first);
		const ra = a.finalUpdateReestablish(id, alice.root),
			rb = b.finalUpdateReestablish(id, bob.root);
		expect(a.acceptFinalUpdateReestablish(id, alice.root, rb)).to.deep.equal(
			[]
		);
		const replay = b.acceptFinalUpdateReestablish(id, bob.root, ra);
		expect(replay[0]).to.deep.equal({
			type: MessageType.REVOKE_AND_ACK,
			payload: ack
		});
		a.acceptFinalUpdateRevocation(id, replay[0].payload);
		exchange(b, a, bob, alice);
		stage(a, b, MessageType.UPDATE_ADD_HTLC, add(1n));
		exchange(a, b, alice, bob);
		exchange(b, a, bob, alice);
		expect(b.loadFinalUpdateStatus(id)!.htlcs).to.have.length(2);
	});

	it('keeps crossed proposals isolated until each remote revocation arrives', () => {
		stage(a, b, MessageType.UPDATE_ADD_HTLC, add());
		stage(b, a, MessageType.UPDATE_ADD_HTLC, add());
		const a1 = a.signFinalUpdateCommitment(id, alice.root),
			b1 = b.signFinalUpdateCommitment(id, bob.root);
		const ackA = a.acceptFinalUpdateCommitment(id, alice.root, b1);
		const ackB = b.acceptFinalUpdateCommitment(id, bob.root, a1);
		a.acceptFinalUpdateRevocation(id, ackB);
		b.acceptFinalUpdateRevocation(id, ackA);
		expect(a.loadFinalUpdateStatus(id)!.htlcs).to.have.length(0);
		const a2 = a.signFinalUpdateCommitment(id, alice.root),
			b2 = b.signFinalUpdateCommitment(id, bob.root);
		const ackA2 = a.acceptFinalUpdateCommitment(id, alice.root, b2);
		const ackB2 = b.acceptFinalUpdateCommitment(id, bob.root, a2);
		a.acceptFinalUpdateRevocation(id, ackB2);
		b.acceptFinalUpdateRevocation(id, ackA2);
		expect(
			a
				.loadFinalUpdateStatus(id)!
				.htlcs.map((h) => h.offeredBy)
				.sort()
		).to.deep.equal(['local', 'peer']);
	});

	it('verifies each second-stage signature before releasing a revocation or advancing the device', () => {
		stage(a, b, MessageType.UPDATE_ADD_HTLC, add());
		const good = a.signFinalUpdateCommitment(id, alice.root);
		const bad = decodeCommitmentSignedMessage(good);
		bad.htlcSignatures[0][0] ^= 1;
		expect(() =>
			b.acceptFinalUpdateCommitment(
				id,
				bob.root,
				encodeCommitmentSignedMessage(bad)
			)
		).to.throw(/HTLC signature/);
		expect(b.loadFinalUpdateStatus(id)!.localHeight).to.equal(0n);
		expect(b.acceptFinalUpdateCommitment(id, bob.root, good)).to.be.instanceOf(
			Buffer
		);
	});
	it('recovers the latest enforceable exit after the device commit and a failed wallet commit before revocation release', () => {
		stage(a, b, MessageType.UPDATE_ADD_HTLC, add());
		const sig = a.signFinalUpdateCommitment(id, alice.root);
		const db = (b as unknown as { db: Database.Database }).db;
		db.exec(
			"CREATE TEMP TRIGGER reject_update BEFORE INSERT ON final_channel_update_log BEGIN SELECT RAISE(ABORT,'simulated wallet commit failure'); END"
		);
		expect(() => b.acceptFinalUpdateCommitment(id, bob.root, sig)).to.throw(
			/simulated wallet commit failure/
		);
		db.exec('DROP TRIGGER reject_update');
		const ack = b.acceptFinalUpdateCommitment(id, bob.root, sig);
		expect(b.loadFinalUpdateStatus(id)!.localHeight).to.equal(1n);
		expect(() => b.loadFinalOpeningExit(id)).to.throw(/superseded/);
		a.acceptFinalUpdateRevocation(id, ack);
		exchange(b, a, bob, alice);
	});

	it('holds ordinary updates until the outstanding tx_abort is echoed', () => {
		a['readFinalSpliceAttempts'] = () => [
			{ aborted: 'retiring', awaitingAbortEcho: true } as IFinalSpliceAttempt
		];
		expect(() =>
			a.stageFinalHtlcUpdate(id, 'local', MessageType.UPDATE_ADD_HTLC, add())
		).to.throw(/quiescent/);
		expect(
			a.finalUpdateReestablish(id, alice.root).nextLocalNonces
		).to.have.length(1);
		a['readFinalSpliceAttempts'] = () => [
			{ aborted: 'retiring', awaitingAbortEcho: false } as IFinalSpliceAttempt
		];
		a.stageFinalHtlcUpdate(id, 'local', MessageType.UPDATE_ADD_HTLC, add());
	});
	it('fences the wallet after a valid newer revocation proof and reopens without offering a stale exit', () => {
		const rb = b.finalUpdateReestablish(id, bob.root);
		rb.nextRevocationNumber = 1n;
		rb.yourLastPerCommitmentSecret = generateFromSeed(
			alice.keys.perCommitmentSeed,
			MAX_INDEX
		);
		expect(() => a.acceptFinalUpdateReestablish(id, alice.root, rb)).to.throw(
			/later commitment/
		);
		expect(() => a.requestFinalOpeningExit(id)).to.throw(/later commitment/);
		a.close();
		a = SqliteStorage.openFinalWallet(aFile, alice.binding);
		expect(() => a.loadFinalOpeningExit(id)).to.throw(/later commitment/);
		expect(a.loadFinalDaemonOpening(id)?.exitToBroadcast).to.equal(undefined);
	});
	it('signs every pending funding outpoint atomically and adopts the splice balance and its most recent exit', () => {
		const sources = [
			{ store: a, side: alice },
			{ store: b, side: bob }
		].map(({ store, side }) => ({
			store,
			side,
			snapshot: store.loadFinalCommitmentSnapshot(id)!,
			authority: (
				store as unknown as { openingAuthority: FinalOpeningAuthority }
			).openingAuthority,
			keys: deriveChannelKeys(side.root, 1, 2)
		}));
		const newTx = new Transaction();
		newTx.version = 2;
		const parent = sources[0].snapshot.candidate;
		newTx.addInput(
			Transaction.fromHex(parent.fundingTxHex).getHash(),
			parent.fundingOutputIndex
		);
		newTx.addInput(Buffer.alloc(32, 83), 0);
		newTx.addOutput(
			createTaprootFundingScript(
				sources[0].keys.channelBasepoints.fundingPubkey,
				sources[1].keys.channelBasepoints.fundingPubkey
			).p2trOutput,
			150000
		);
		const nonceKey = spliceCommitmentNonceContext(id, newTx.getHash(), 0);
		const data = sources.map((x, i) => {
			const ref: IFinalFundingReference = {
				fundingTxHex: newTx.toHex(),
				fundingOutputIndex: 0,
				localFundingKeyIndex: 2,
				localFundingPubkey:
					x.keys.channelBasepoints.fundingPubkey.toString('hex'),
				remoteFundingPubkey:
					sources[1 - i].keys.channelBasepoints.fundingPubkey.toString('hex')
			};
			const nonce = (n: number) =>
				Buffer.from(
					updateVerificationNonce(
						x.authority.nonceContext(nonceKey),
						x.keys.fundingPrivkey,
						n,
						{ pub: '', source: 'splice' }
					)
				).toString('hex');
			const view = (local: boolean) =>
				buildFinalCommitmentView(
					x.snapshot.candidate,
					x.snapshot.terms,
					local ? 'local' : 'remote',
					local ? x.snapshot.localPoint : x.snapshot.remotePoint,
					0n,
					{
						localBalanceMsat:
							x.snapshot.localBalanceMsat + (i === 0 ? 10000000n : 0n),
						remoteBalanceMsat:
							x.snapshot.remoteBalanceMsat + (i === 1 ? 10000000n : 0n)
					},
					[],
					ref
				);
			return { ...x, ref, nonce, view };
		});
		const shares = data.map((x, i) =>
			signFinalUpdate(
				x.snapshot.candidate,
				x.view(false),
				x.snapshot.remotePoint,
				0,
				{ pub: data[1 - i].nonce(0) },
				x.side.keys,
				x.authority,
				nonceKey,
				[],
				undefined,
				{ reference: x.ref, privateKey: x.keys.fundingPrivkey }
			)
		);
		const beforeSplice = [a, b].map(
			(w) => w.loadFinalUpdateStatus(id)!.spendableOutboundMsat
		);
		const attempts = data.map((x, i) => {
			const localExit = signFinalUpdate(
				x.snapshot.candidate,
				x.view(true),
				x.snapshot.localPoint,
				0,
				{ pub: x.nonce(0), source: 'splice' },
				x.side.keys,
				x.authority,
				nonceKey,
				[],
				shares[1 - i],
				{ reference: x.ref, privateKey: x.keys.fundingPrivkey }
			);
			// Splice negotiation and wallet funding have independent integration tests. This fixture supplies its authenticated result.
			const attempt = {
				candidate: {
					kind: 'candidate',
					funding: x.ref,
					localDelta: i === 0 ? '10000' : '0',
					peerDelta: i === 1 ? '10000' : '0',
					localExit: localExit.toString('hex'),
					ourCommitment: shares[i].toString('hex'),
					peerCommitment: shares[1 - i].toString('hex'),
					localHeight: 0,
					remoteHeight: 0,
					localNextNonce: x.nonce(1),
					peerNextNonce: data[1 - i].nonce(1)
				},
				funded: newTx.toHex()
			} as IFinalSpliceAttempt;
			x.store['readFinalSpliceAttempts'] = () => [attempt];
			return attempt;
		});
		// Bob has no contribution in the new transaction, but its larger capacity raises his reserve.
		expect(b.loadFinalUpdateStatus(id)!.spendableOutboundMsat).to.equal(
			beforeSplice[1] - 500000n
		);
		expect(a.loadFinalUpdateStatus(id)!.spendableOutboundMsat).to.equal(
			beforeSplice[0]
		);
		const originalExit = attempts[0].candidate!.localExit;
		const corruptExit = Transaction.fromHex(originalExit);
		corruptExit.ins[0].witness[0][0] ^= 1;
		attempts[0].candidate!.localExit = corruptExit.toHex();
		expect(() => a.loadFinalFundingExits(id)).to.throw(/exit signature/i);
		attempts[0].candidate!.localExit = originalExit;
		stage(a, b, MessageType.UPDATE_ADD_HTLC, add());
		const sigs = a.signFinalUpdateCommitmentBatch(id, alice.root);
		expect(sigs).to.have.length(2);
		expect(() => b.acceptFinalUpdateCommitment(id, bob.root, sigs[0])).to.throw(
			/Incomplete batch/
		);
		const bad = Buffer.from(sigs[1]);
		bad[40] ^= 1;
		expect(() =>
			b.acceptFinalUpdateCommitmentBatch(id, bob.root, [sigs[0], bad])
		).to.throw();
		expect(b.loadFinalUpdateStatus(id)!.localHeight).to.equal(0n);
		const ack = b.acceptFinalUpdateCommitmentBatch(id, bob.root, sigs);
		expect(
			decodeRevokeAndAckMessage(ack, { finalTaproot: true }).nextLocalNonces
		).to.have.length(2);
		a.acceptFinalUpdateRevocation(id, ack);
		b.acceptFinalUpdateRevocation(
			id,
			a.acceptFinalUpdateCommitmentBatch(
				id,
				alice.root,
				b.signFinalUpdateCommitmentBatch(id, bob.root)
			)
		);
		expect(a.loadFinalResolutionStates(id)!.locals).to.have.length(2);
		expect(a.loadFinalResolutionStates(id)!.revoked).to.have.length(2);
		attempts.forEach((attempt) => {
			attempt.adopted = newTx.getId();
		});
		expect(a.loadFinalUpdateStatus(id)!.localBalanceMsat).to.equal(
			sources[0].snapshot.localBalanceMsat + 10000000n - 8000000n
		);
		const exit = Transaction.fromBuffer(a.requestFinalOpeningExit(id));
		expect(exit.ins[0].hash).to.deep.equal(newTx.getHash());
		const oldFunding = Transaction.fromHex(parent.fundingTxHex).getHash();
		const old = a.requestFinalOpeningExit(id, oldFunding);
		expect(Transaction.fromBuffer(old).ins[0].hash).to.deep.equal(oldFunding);
		expect(a.requestFinalOpeningExit(id)).to.deep.equal(old);
		expect(a.requestFinalOpeningExit(id, newTx.getHash())).to.deep.equal(
			exit.toBuffer()
		);
	});
	it('recovers a ready opening and the latest exit when the original wallet rolls back before commitment zero', () => {
		const original = a as unknown as {
			db: Database.Database;
			finalOpeningRecord(id: string): {
				nonceKey: Buffer;
				nonces: IFinalOpeningNonces;
			};
		};
		const old = original.finalOpeningRecord(id);
		delete old.nonces.signing;
		delete old.nonces.localReady;
		delete old.nonces.peerReady;
		const before = encryptValue(old.nonceKey, JSON.stringify(old.nonces));
		stage(a, b, MessageType.UPDATE_ADD_HTLC, add());
		exchange(a, b, alice, bob);
		exchange(b, a, bob, alice);
		const current = a.loadFinalFundingExits(id)[0].exit;
		original.db
			.prepare(
				'UPDATE final_opening_candidates SET nonces_json=? WHERE channel_id=?'
			)
			.run(before, id);
		a.close();
		a = SqliteStorage.openFinalWallet(aFile, alice.binding);
		a.assertFinalDaemonIdentity(alice.binding.nodeId);
		expect(a.loadFinalDaemonOpening(id)?.readyExchanged).to.equal(true);
		expect(a.requestFinalOpeningExit(id)).to.deep.equal(current);
	});

	it('signs a staged local add after reconnect if the process died before producing its first share', () => {
		a.stageFinalHtlcUpdate(id, 'local', MessageType.UPDATE_ADD_HTLC, add());
		const mine = a.finalUpdateReestablish(id, alice.root),
			theirs = b.finalUpdateReestablish(id, bob.root);
		const messages = a.acceptFinalUpdateReestablish(id, alice.root, theirs);
		expect(b.acceptFinalUpdateReestablish(id, bob.root, mine)).to.deep.equal(
			[]
		);
		expect(messages.map((m) => m.type)).to.deep.equal([
			MessageType.UPDATE_ADD_HTLC,
			MessageType.COMMITMENT_SIGNED
		]);
		b.stageFinalHtlcUpdate(id, 'peer', messages[0].type, messages[0].payload);
		const ack = b.acceptFinalUpdateCommitment(
			id,
			bob.root,
			messages[1].payload
		);
		a.acceptFinalUpdateRevocation(id, ack);
		exchange(b, a, bob, alice);
	});

	it('collects a batch in peer wire order, resets incomplete batches on disconnect and rejects unrelated frames', () => {
		const receiver = new FinalOpeningTransport(
			{ storage: a, root: alice.root },
			async () => 'unspent',
			() => null,
			() => {},
			() => {},
			() => {}
		);
		const events: IFinalOpeningMessage[] = [];
		receiver.queue = (_peer, _id, m) => {
			if (m) events.push(m);
		};
		const peer = bob.binding.nodeId,
			channelId = Buffer.from(id, 'hex');
		const start = encodeStartBatchMessage({
			channelId,
			batchSize: 2,
			messageType: MessageType.COMMITMENT_SIGNED
		});
		const part1 = Buffer.concat([channelId, Buffer.of(1)]),
			part2 = Buffer.concat([channelId, Buffer.of(2)]);
		expect(
			receiver.collectCommitmentBatch(peer, MessageType.START_BATCH, start)
		).to.equal(true);
		expect(
			receiver.collectCommitmentBatch(
				peer,
				MessageType.COMMITMENT_SIGNED,
				part1
			)
		).to.equal(true);
		expect(events).to.deep.equal([]);
		receiver.disconnected(peer);
		expect(
			receiver.collectCommitmentBatch(
				peer,
				MessageType.COMMITMENT_SIGNED,
				part2
			)
		).to.equal(false);
		receiver.collectCommitmentBatch(peer, MessageType.START_BATCH, start);
		receiver.collectCommitmentBatch(peer, MessageType.COMMITMENT_SIGNED, part1);
		receiver.collectCommitmentBatch(peer, MessageType.COMMITMENT_SIGNED, part2);
		expect(events[0].signatureBatch).to.deep.equal([part1, part2]);
		receiver.collectCommitmentBatch(peer, MessageType.START_BATCH, start);
		receiver.collectCommitmentBatch(
			peer,
			MessageType.COMMITMENT_SIGNED,
			Buffer.alloc(32, 89)
		);
		expect(events[1].batchError).to.match(/Unexpected message/);
	});
	it('signs opener fee updates into both views, retains each revoked rate, and accepts the last fee in a round', () => {
		const fee = (rate: number) =>
			encodeUpdateFeeMessage({
				channelId: Buffer.from(id, 'hex'),
				feeratePerKw: rate
			});
		const opener = a.loadFinalOpening(id)!.isInitiator ? a : b,
			acceptor = opener === a ? b : a;
		const left = opener === a ? alice : bob,
			right = opener === a ? bob : alice;
		const initial =
			opener.loadFinalCommitmentSnapshot(id)!.terms.commitmentFeeratePerKw;
		expect(() =>
			acceptor.stageFinalHtlcUpdate(
				id,
				'local',
				MessageType.UPDATE_FEE,
				fee(300)
			)
		).to.throw(/opener/);
		expect(() =>
			acceptor.stageFinalHtlcUpdate(
				id,
				'peer',
				MessageType.UPDATE_FEE,
				fee(252)
			)
		).to.throw(/fee rate/i);
		expect(() =>
			acceptor.stageFinalHtlcUpdate(
				id,
				'peer',
				MessageType.UPDATE_FEE,
				fee(100000)
			)
		).to.throw(/fee rate/i);
		for (const rate of [400, 700, 400])
			stage(opener, acceptor, MessageType.UPDATE_FEE, fee(rate));
		exchange(opener, acceptor, left, right);
		expect(acceptor.loadFinalResolutionStates(id)!.local.feeratePerKw).to.equal(
			400
		);
		expect(
			acceptor.loadFinalResolutionStates(id)!.remote[0].feeratePerKw
		).to.equal(initial);
		exchange(acceptor, opener, right, left);
		expect(
			opener.loadFinalCommitmentSnapshot(id)!.terms.commitmentFeeratePerKw
		).to.equal(400);
		expect(
			opener.loadFinalResolutionStates(id)!.revoked[0].feeratePerKw
		).to.equal(initial);
		expect(opener.loadFinalUpdateDeliveries(id)).to.deep.equal([]);
	});
});

describe('Final splice reserves', () => {
	const terms = {
		localDustLimitSatoshis: 330,
		remoteDustLimitSatoshis: 750,
		commitmentFeeratePerKw: 2100
	};
	const capacity = 4000000n;
	const reserve = (capacity / 100n) * 1000n;
	const htlcs = [{ amountMsat: 600_000n }, { amountMsat: 329_999n }];
	const cost =
		(calculateCommitmentFee(2100, 1, true, true) + ANCHOR_TOTAL_COST) * 1000n;
	it('quotes the last satoshi withdrawable with the candidate reserve and the actual commitment cost', () => {
		for (const startingBalance of [1n, 50000000n, 100000001n, 3800500801n]) {
			const max = finalSpliceWithdrawalSats(
				capacity,
				terms,
				startingBalance,
				htlcs,
				true
			);
			const check = (withdraw: bigint) =>
				validateFinalSpliceReserves(
					capacity - withdraw,
					terms,
					{
						localBalanceMsat: startingBalance - withdraw * 1000n,
						remoteBalanceMsat: reserve
					},
					htlcs,
					true,
					[true, false]
				);
			if (max > 0n) check(max);
			expect(() => check(max + 1n)).to.throw(/reserve/);
		}
	});

	for (const localIsOpener of [true, false])
		it(
			'protects the new output owners and the opening fee payer when our opener flag is ' +
				localIsOpener,
			() => {
				const owner = localIsOpener ? 'localBalanceMsat' : 'remoteBalanceMsat';
				const other = localIsOpener ? 'remoteBalanceMsat' : 'localBalanceMsat';
				const funds = { localBalanceMsat: reserve, remoteBalanceMsat: reserve };
				funds[owner] += cost;
				validateFinalSpliceReserves(
					capacity,
					terms,
					funds,
					htlcs,
					localIsOpener,
					[true, true]
				);
				funds[owner] -= 1n;
				expect(() =>
					validateFinalSpliceReserves(
						capacity,
						terms,
						funds,
						htlcs,
						localIsOpener,
						[true, true]
					)
				).to.throw(/reserve/);
				// A party without a non-funding output may start below the new reserve.
				validateFinalSpliceReserves(
					capacity,
					terms,
					funds,
					htlcs,
					localIsOpener,
					[!localIsOpener, localIsOpener]
				);
				funds[other] -= 1n;
				expect(() =>
					validateFinalSpliceReserves(
						capacity,
						terms,
						funds,
						htlcs,
						localIsOpener,
						[!localIsOpener, localIsOpener]
					)
				).to.throw(/reserve/);
				funds[owner] = cost - 1n;
				expect(() =>
					validateFinalSpliceReserves(
						capacity,
						terms,
						funds,
						htlcs,
						localIsOpener,
						[false, false]
					)
				).to.throw(/fee budget/);
			}
		);
});
