/**
 * Recovery Protocol phase 5: writer leases (docs/RECOVERY-PROTOCOL.md 5.6).
 *
 * The lease is what makes fencing possible: an epoch, the FRESH RANDOM
 * writer key that epoch is bound to, and the guardian certificates that
 * granted it. These tests pin the properties the protocol leans on: keys
 * are never seed-derived, the private half never sits in plaintext in the
 * database, the persisted epoch and the journal's stamped epoch are the
 * same value, and an acquisition carries both signatures.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { deriveStorageKey } from '../../src/lightning/storage/encryption';
import {
	CRASH_V1_PROFILE,
	GuardianState,
	IGuardianTakeoverCertificate,
	JOURNAL_META_KEYS,
	LEASE_META_KEYS,
	ReferenceGuardian,
	acquireTranscriptHash,
	computeGuardianSetId,
	deriveRecoveryRoot,
	genesisLogHead,
	generateWriterKey,
	loadWriterLease,
	markLeaseConfirmed,
	publicLease,
	registerTranscriptHash,
	saveWriterLease,
	signAcquisition,
	signTranscript,
	statesEqual,
	verifyTranscript,
	xOnlyFromSecret
} from '../../src/lightning/recovery';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`p5-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const NODE_SECRET = sha('p5-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

describe('Recovery phase 5: writer lease', () => {
	it('generates fresh random keys, never seed-derived', () => {
		const a = generateWriterKey();
		const b = generateWriterKey();
		expect(a.secret.length).to.equal(32);
		expect(a.publicKey.length).to.equal(32);
		expect(a.secret.equals(b.secret)).to.equal(false);
		expect(a.publicKey.equals(b.publicKey)).to.equal(false);
		// Not the node identity, not the recovery root: a stolen seed must not
		// forge records for old epochs, and a superseded device's writer key
		// must die with it (wire 1.2).
		expect(a.secret.equals(NODE_SECRET)).to.equal(false);
		expect(a.secret.equals(ROOT.rootSecret)).to.equal(false);
		expect(a.publicKey.equals(ROOT.recoveryId)).to.equal(false);
		expect(a.publicKey.equals(xOnlyFromSecret(a.secret))).to.equal(true);
	});

	it('round trips through storage and shares the journal epoch key', () => {
		const storage = openStorage();
		expect(loadWriterLease(storage)).to.equal(null);

		const writer = generateWriterKey();
		saveWriterLease(storage, {
			epoch: 7n,
			writerSecret: writer.secret,
			writerPublicKey: writer.publicKey,
			guardianCertificates: [],
			confirmedAt: null
		});
		const loaded = loadWriterLease(storage);
		expect(loaded).to.not.equal(null);
		expect(loaded!.epoch).to.equal(7n);
		expect(loaded!.writerSecret.equals(writer.secret)).to.equal(true);
		expect(loaded!.writerPublicKey.equals(writer.publicKey)).to.equal(true);
		expect(loaded!.guardianCertificates).to.have.length(0);
		expect(loaded!.confirmedAt).to.equal(null);
		// The lease epoch IS the journal's writerEpoch: a frame can never be
		// stamped with an epoch the lease does not claim.
		expect(storage.getRecoveryMeta!(JOURNAL_META_KEYS.writerEpoch)).to.equal(
			'7'
		);
		expect(LEASE_META_KEYS.writerEpoch).to.equal(JOURNAL_META_KEYS.writerEpoch);

		markLeaseConfirmed(storage, 1_800_000_000_123n);
		expect(loadWriterLease(storage)!.confirmedAt).to.equal(1_800_000_000_123n);

		const view = publicLease(loadWriterLease(storage)!);
		expect(Object.keys(view)).to.not.include('writerSecret');
		storage.close();
	});

	it('preserves guardian certificates across a round trip', () => {
		const storage = openStorage();
		const guardian = new ReferenceGuardian({
			path: ':memory:',
			guardianSecret: GUARDIAN_SECRETS[0],
			members: GUARDIAN_IDS
		});
		const initialState: GuardianState = {
			recoveryId: ROOT.recoveryId,
			lease: { epoch: 1n, writerPublicKey: generateWriterKey().publicKey },
			origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
			logHead: genesisLogHead()
		};
		guardian.register({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			initialState,
			rootSignature: signTranscript(
				registerTranscriptHash(SET_ID, initialState),
				ROOT.rootSecret
			)
		});
		const newWriter = generateWriterKey();
		const signatures = signAcquisition(
			SET_ID,
			initialState,
			2n,
			newWriter,
			ROOT.rootSecret
		);
		const acquired = guardian.acquireEpoch({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			expectedState: initialState,
			newEpoch: 2n,
			newWriterPublicKey: newWriter.publicKey,
			...signatures
		});
		const certificate = acquired.certificate as IGuardianTakeoverCertificate;
		expect(certificate).to.not.equal(undefined);

		saveWriterLease(storage, {
			epoch: 2n,
			writerSecret: newWriter.secret,
			writerPublicKey: newWriter.publicKey,
			guardianCertificates: [certificate],
			confirmedAt: 1_800_000_000_000n
		});
		const restored = loadWriterLease(storage)!;
		expect(restored.guardianCertificates).to.have.length(1);
		const round = restored.guardianCertificates[0];
		expect(round.guardianId.equals(certificate.guardianId)).to.equal(true);
		expect(round.newEpoch).to.equal(2n);
		expect(round.issuedAt).to.equal(certificate.issuedAt);
		expect(round.signature.equals(certificate.signature)).to.equal(true);
		expect(
			statesEqual(round.supersededState, certificate.supersededState)
		).to.equal(true);
		storage.close();
		guardian.close();
	});

	it('signs an acquisition with BOTH the root and the new writer', () => {
		const state: GuardianState = {
			recoveryId: ROOT.recoveryId,
			lease: { epoch: 4n, writerPublicKey: generateWriterKey().publicKey },
			origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
			logHead: genesisLogHead()
		};
		const newWriter = generateWriterKey();
		const { rootSignature, newWriterSignature } = signAcquisition(
			SET_ID,
			state,
			5n,
			newWriter,
			ROOT.rootSecret
		);
		const hash = acquireTranscriptHash(SET_ID, state, 5n, newWriter.publicKey);
		// Root signature = authority over the namespace; writer signature =
		// possession of the new key. Neither alone suffices (wire 4.2).
		expect(verifyTranscript(hash, rootSignature, ROOT.recoveryId)).to.equal(
			true
		);
		expect(
			verifyTranscript(hash, newWriterSignature, newWriter.publicKey)
		).to.equal(true);
		expect(verifyTranscript(hash, rootSignature, newWriter.publicKey)).to.equal(
			false
		);
		expect(
			verifyTranscript(hash, newWriterSignature, ROOT.recoveryId)
		).to.equal(false);
	});

	it('never writes the writer secret in plaintext when storage is encrypted', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-p5-lease-'));
		const dbPath = path.join(dir, 'lease.sqlite');
		try {
			const key = deriveStorageKey(NODE_SECRET);
			const storage = new SqliteStorage(dbPath, undefined, {
				encryptionKey: key
			});
			storage.open();
			const writer = generateWriterKey();
			saveWriterLease(storage, {
				epoch: 3n,
				writerSecret: writer.secret,
				writerPublicKey: writer.publicKey,
				guardianCertificates: [],
				confirmedAt: null
			});
			expect(
				loadWriterLease(storage)!.writerSecret.equals(writer.secret)
			).to.equal(true);
			storage.close();

			// Read the raw file: the signing secret must not appear anywhere.
			const raw = new Database(dbPath, { readonly: true });
			const rows = raw
				.prepare('SELECT key, value FROM recovery_meta')
				.all() as Array<{ key: string; value: string }>;
			raw.close();
			const stored = rows.find((r) => r.key === LEASE_META_KEYS.writerSecret);
			expect(stored, 'writer secret row present').to.not.equal(undefined);
			expect(stored!.value.startsWith('enc1:')).to.equal(true);
			expect(stored!.value).to.not.contain(writer.secret.toString('hex'));
			const fileBytes = fs.readFileSync(dbPath);
			expect(fileBytes.includes(writer.secret)).to.equal(false);
			expect(
				fileBytes.includes(Buffer.from(writer.secret.toString('hex'), 'utf8'))
			).to.equal(false);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
