/**
 * Recovery Protocol phase 5: writer leases (docs/RECOVERY-PROTOCOL.md 5.6).
 *
 * The lease is what makes fencing possible: an epoch, the FRESH RANDOM
 * writer key that epoch is bound to, and the guardian certificates that
 * granted it. These tests pin the properties the protocol leans on: keys
 * are never seed-derived; the private half never sits in plaintext, and
 * never reaches storage that cannot protect it; the lease is ONE atomic
 * artifact, so no crash yields a new epoch beside an old key; confirmation
 * is identity-bound and never inherited; a damaged lease fails CLOSED; a
 * MISSING lease is evidence rather than proof of first registration; and
 * nothing this module accepts can fail to reload.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { deriveStorageKey } from '../../src/lightning/storage/encryption';
import {
	CRASH_V1_PROFILE,
	CorruptWriterLeaseError,
	GuardianState,
	IGuardianTakeoverCertificate,
	IWriterLeaseKeys,
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

function leaseOf(
	epoch: bigint,
	writer = generateWriterKey(),
	confirmedAt: bigint | null = null,
	certificates: IGuardianTakeoverCertificate[] = []
): IWriterLeaseKeys {
	return {
		epoch,
		writerSecret: writer.secret,
		writerPublicKey: writer.publicKey,
		guardianCertificates: certificates,
		confirmedAt
	};
}

function presentLease(storage: IStorageBackend): IWriterLeaseKeys {
	const loaded = loadWriterLease(storage);
	expect(loaded.state).to.equal('present');
	return (loaded as { state: 'present'; lease: IWriterLeaseKeys }).lease;
}

/** Rewrite the stored blob with one field mangled. */
function mangleStoredLease(
	storage: IStorageBackend,
	mutate: (parsed: Record<string, unknown>) => void
): void {
	const raw = storage.getRecoveryMeta!(LEASE_META_KEYS.lease) as string;
	const parsed = JSON.parse(raw) as Record<string, unknown>;
	mutate(parsed);
	storage.setRecoveryMeta!(LEASE_META_KEYS.lease, JSON.stringify(parsed));
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
		expect(loadWriterLease(storage).state).to.equal('missing');

		const writer = generateWriterKey();
		saveWriterLease(storage, leaseOf(7n, writer));
		const loaded = presentLease(storage);
		expect(loaded.epoch).to.equal(7n);
		expect(loaded.writerSecret.equals(writer.secret)).to.equal(true);
		expect(loaded.writerPublicKey.equals(writer.publicKey)).to.equal(true);
		expect(loaded.guardianCertificates).to.have.length(0);
		expect(loaded.confirmedAt).to.equal(null);
		// The lease epoch IS the journal's writerEpoch: a frame can never be
		// stamped with an epoch the lease does not claim.
		expect(storage.getRecoveryMeta!(JOURNAL_META_KEYS.writerEpoch)).to.equal(
			'7'
		);
		expect(LEASE_META_KEYS.writerEpoch).to.equal(JOURNAL_META_KEYS.writerEpoch);
		storage.close();
	});

	it('does not carry confirmation into a replacement lease', () => {
		const storage = openStorage();
		const first = generateWriterKey();
		saveWriterLease(storage, leaseOf(7n, first, 123n));
		expect(presentLease(storage).confirmedAt).to.equal(123n);

		const second = generateWriterKey();
		saveWriterLease(storage, leaseOf(8n, second));
		const loaded = presentLease(storage);
		expect(loaded.epoch).to.equal(8n);
		// A new epoch has NOT been confirmed by anyone yet; inheriting the old
		// timestamp would let the startup gate pass on stale evidence.
		expect(loaded.confirmedAt).to.equal(null);
		expect(loaded.writerPublicKey.equals(second.publicKey)).to.equal(true);
		storage.close();
	});

	it('binds confirmation to the exact epoch and writer key', () => {
		const storage = openStorage();
		const writer = generateWriterKey();
		saveWriterLease(storage, leaseOf(4n, writer));

		// A late callback for a superseded epoch must not bless this lease.
		expect(() =>
			markLeaseConfirmed(
				storage,
				{ epoch: 3n, writerPublicKey: writer.publicKey },
				999n
			)
		).to.throw(/refusing to confirm/);
		// Nor one naming a different writer key at the right epoch.
		expect(() =>
			markLeaseConfirmed(
				storage,
				{ epoch: 4n, writerPublicKey: generateWriterKey().publicKey },
				999n
			)
		).to.throw(/refusing to confirm/);
		expect(presentLease(storage).confirmedAt).to.equal(null);

		markLeaseConfirmed(
			storage,
			{ epoch: 4n, writerPublicKey: writer.publicKey },
			1_800_000_000_123n
		);
		expect(presentLease(storage).confirmedAt).to.equal(1_800_000_000_123n);
		storage.close();
	});

	it('replaces the lease atomically under a failing transaction', () => {
		const storage = openStorage();
		const first = generateWriterKey();
		saveWriterLease(storage, leaseOf(5n, first, 500n));

		// Fail the second write of the replacement: the whole transaction must
		// roll back, leaving the COMPLETE old lease, never a new epoch beside
		// an old key.
		const second = generateWriterKey();
		let writes = 0;
		const failing = new Proxy(storage, {
			get(target, prop, receiver): unknown {
				if (prop === 'setRecoveryMeta') {
					return (key: string, value: string): void => {
						writes += 1;
						if (writes === 2) throw new Error('disk full');
						target.setRecoveryMeta!(key, value);
					};
				}
				const value = Reflect.get(target, prop, receiver);
				return typeof value === 'function' ? value.bind(target) : value;
			}
		}) as IStorageBackend;
		expect(() => saveWriterLease(failing, leaseOf(6n, second))).to.throw(
			/disk full/
		);

		const loaded = presentLease(storage);
		expect(loaded.epoch).to.equal(5n);
		expect(loaded.writerSecret.equals(first.secret)).to.equal(true);
		expect(loaded.confirmedAt).to.equal(500n);
		expect(storage.getRecoveryMeta!(JOURNAL_META_KEYS.writerEpoch)).to.equal(
			'5'
		);
		storage.close();
	});

	it('fails closed on partial, malformed, or inconsistent state', () => {
		const storage = openStorage();
		const writer = generateWriterKey();
		saveWriterLease(storage, leaseOf(9n, writer));

		// A journal epoch beyond the default with NO lease is lost key
		// material, not a fresh install; reading it as absent would authorize
		// a re-registration over live state.
		const orphaned = openStorage();
		orphaned.setRecoveryMeta!(JOURNAL_META_KEYS.writerEpoch, '4');
		expect(() => loadWriterLease(orphaned)).to.throw(CorruptWriterLeaseError);
		orphaned.close();

		// Malformed JSON.
		storage.setRecoveryMeta!(LEASE_META_KEYS.lease, '{not json');
		expect(() => loadWriterLease(storage)).to.throw(/not valid JSON/);

		// Bad hex width.
		saveWriterLease(storage, leaseOf(9n, writer));
		mangleStoredLease(storage, (p) => {
			p.writerPublicKey = 'ab'.repeat(31);
		});
		expect(() => loadWriterLease(storage)).to.throw(/32 hex bytes/);

		// Secret and public half that do not belong together.
		saveWriterLease(storage, leaseOf(9n, writer));
		mangleStoredLease(storage, (p) => {
			p.writerPublicKey = generateWriterKey().publicKey.toString('hex');
		});
		expect(() => loadWriterLease(storage)).to.throw(/does not belong/);

		// A secret that is not a valid scalar at all.
		saveWriterLease(storage, leaseOf(9n, writer));
		mangleStoredLease(storage, (p) => {
			p.writerSecret = '00'.repeat(32);
		});
		expect(() => loadWriterLease(storage)).to.throw(/valid secp256k1/);

		// Certificates that speak about a different lease.
		saveWriterLease(storage, leaseOf(9n, writer));
		mangleStoredLease(storage, (p) => {
			p.epoch = '10';
		});
		expect(() => loadWriterLease(storage)).to.throw(/disagrees with lease/);

		// Unknown blob version.
		saveWriterLease(storage, leaseOf(9n, writer));
		mangleStoredLease(storage, (p) => {
			p.version = 2;
		});
		expect(() => loadWriterLease(storage)).to.throw(/unsupported stored lease/);

		// Certificates that are not even an array.
		saveWriterLease(storage, leaseOf(9n, writer));
		mangleStoredLease(storage, (p) => {
			p.guardianCertificates = 'nope';
		});
		expect(() => loadWriterLease(storage)).to.throw(/not an array/);
		storage.close();
	});

	it('refuses to persist a lease whose parts disagree', () => {
		const storage = openStorage();
		const writer = generateWriterKey();
		const other = generateWriterKey();
		expect(() =>
			saveWriterLease(storage, {
				epoch: 1n,
				writerSecret: writer.secret,
				writerPublicKey: other.publicKey,
				guardianCertificates: [],
				confirmedAt: null
			})
		).to.throw(/does not belong/);
		expect(() => saveWriterLease(storage, leaseOf(0n, writer))).to.throw(
			/epoch is outside/
		);
		expect(loadWriterLease(storage).state).to.equal('missing');
		storage.close();
	});

	it('refuses storage that cannot protect the signing key at rest', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-p5-plain-'));
		try {
			const dbPath = path.join(dir, 'plain.sqlite');
			const storage = new SqliteStorage(dbPath);
			storage.open();
			expect(storage.secretsEncryptedAtRest()).to.equal(false);
			const writer = generateWriterKey();
			expect(() => saveWriterLease(storage, leaseOf(1n, writer))).to.throw(
				/encryption at rest/
			);
			expect(loadWriterLease(storage).state).to.equal('missing');
			// The operator can accept the risk explicitly, and only explicitly.
			saveWriterLease(storage, leaseOf(1n, writer), {
				allowUnencryptedSecrets: true
			});
			expect(presentLease(storage).epoch).to.equal(1n);
			storage.close();

			// An in-memory database has no file to steal, so it qualifies.
			const memory = openStorage();
			expect(memory.secretsEncryptedAtRest()).to.equal(true);
			memory.close();
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
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
			guardianMembers: GUARDIAN_IDS,
			generation: 1n,
			initialState,
			rootSignature: signTranscript(
				registerTranscriptHash(SET_ID, initialState, 1n),
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

		saveWriterLease(
			storage,
			leaseOf(2n, newWriter, 1_800_000_000_000n, [certificate])
		);
		const restored = presentLease(storage);
		expect(restored.guardianCertificates).to.have.length(1);
		const round = restored.guardianCertificates[0];
		expect(round.guardianId.equals(certificate.guardianId)).to.equal(true);
		expect(round.newEpoch).to.equal(2n);
		expect(round.issuedAt).to.equal(certificate.issuedAt);
		expect(round.signature.equals(certificate.signature)).to.equal(true);
		expect(
			statesEqual(round.supersededState, certificate.supersededState)
		).to.equal(true);

		// A certificate that grants a DIFFERENT epoch than the lease claims is
		// not evidence for this lease.
		expect(() =>
			saveWriterLease(storage, leaseOf(3n, newWriter, null, [certificate]))
		).to.throw(/different epoch/);
		storage.close();
		guardian.close();
	});

	it('publicLease hands out a deep copy, not a handle on the lease', () => {
		const storage = openStorage();
		const guardian = new ReferenceGuardian({
			path: ':memory:',
			guardianSecret: GUARDIAN_SECRETS[1],
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
			guardianMembers: GUARDIAN_IDS,
			generation: 1n,
			initialState,
			rootSignature: signTranscript(
				registerTranscriptHash(SET_ID, initialState, 1n),
				ROOT.rootSecret
			)
		});
		const newWriter = generateWriterKey();
		const acquired = guardian.acquireEpoch({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			expectedState: initialState,
			newEpoch: 2n,
			newWriterPublicKey: newWriter.publicKey,
			...signAcquisition(SET_ID, initialState, 2n, newWriter, ROOT.rootSecret)
		});
		const certificate = acquired.certificate as IGuardianTakeoverCertificate;
		const lease = leaseOf(2n, newWriter, null, [certificate]);
		saveWriterLease(storage, lease);

		const view = publicLease(lease);
		expect(Object.keys(view)).to.not.include('writerSecret');
		view.writerPublicKey.fill(0);
		view.guardianCertificates[0].signature.fill(0);
		view.guardianCertificates[0].supersededState.logHead.frameHash.fill(0);
		// Mutating the view must not touch the lease it came from.
		expect(lease.writerPublicKey.equals(newWriter.publicKey)).to.equal(true);
		expect(
			lease.guardianCertificates[0].signature.equals(certificate.signature)
		).to.equal(true);
		expect(
			lease.guardianCertificates[0].supersededState.logHead.frameHash.equals(
				certificate.supersededState.logHead.frameHash
			)
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
		// A mismatched pair fails locally instead of at the guardian.
		expect(() =>
			signAcquisition(
				SET_ID,
				state,
				5n,
				{ secret: newWriter.secret, publicKey: generateWriterKey().publicKey },
				ROOT.rootSecret
			)
		).to.throw(/does not belong/);
	});

	it('reports a missing lease as evidence, never as proof of first registration', () => {
		const storage = openStorage();
		const writer = generateWriterKey();
		saveWriterLease(storage, leaseOf(1n, writer));

		// Lose the lease row while the journal epoch survives. Epoch 1 is
		// genuinely ambiguous, because the journal writes epoch 1 itself on
		// its first frame: a guardian-disabled node and a node that lost its
		// genesis lease are indistinguishable HERE. So the loader reports
		// missing plus the evidence, and the caller must consult the guardian
		// quorum before concluding anything.
		storage.deleteRecoveryMeta!(LEASE_META_KEYS.lease);
		const loaded = loadWriterLease(storage);
		expect(loaded.state).to.equal('missing');
		expect(
			(loaded as { state: 'missing'; journalEpoch: bigint | null }).journalEpoch
		).to.equal(1n);

		// Above epoch 1 there is no ambiguity: only a lease acquisition ever
		// advances that key, so the key material provably went missing.
		saveWriterLease(storage, leaseOf(2n, writer));
		storage.deleteRecoveryMeta!(LEASE_META_KEYS.lease);
		expect(() => loadWriterLease(storage)).to.throw(CorruptWriterLeaseError);

		// A journal epoch of 0, or anything nonnumeric, is corruption rather
		// than a default.
		const zeroed = openStorage();
		zeroed.setRecoveryMeta!(JOURNAL_META_KEYS.writerEpoch, '0');
		expect(() => loadWriterLease(zeroed)).to.throw(CorruptWriterLeaseError);
		zeroed.setRecoveryMeta!(JOURNAL_META_KEYS.writerEpoch, 'not-a-number');
		expect(() => loadWriterLease(zeroed)).to.throw(CorruptWriterLeaseError);
		zeroed.close();

		// Storage that cannot answer is "cannot determine", not "never
		// registered": it must throw rather than report a fact it lacks.
		const unsupported = {} as IStorageBackend;
		expect(() => loadWriterLease(unsupported)).to.throw(/does not support/);
		storage.close();
	});

	it('never persists a lease or confirmation its own loader would reject', () => {
		const storage = openStorage();
		const writer = generateWriterKey();
		saveWriterLease(storage, leaseOf(1n, writer));

		for (const invalid of [-1n, 0x1_0000_0000_0000_0000n]) {
			expect(() =>
				markLeaseConfirmed(
					storage,
					{ epoch: 1n, writerPublicKey: writer.publicKey },
					invalid
				)
			).to.throw(/u64 range/);
			// The rejected value never reached the blob.
			expect(presentLease(storage).confirmedAt).to.equal(null);
		}
		expect(() =>
			saveWriterLease(storage, leaseOf(1n, writer, 0x1_0000_0000_0000_0000n))
		).to.throw(/u64 range/);

		// A structurally broken certificate is refused on the way IN, not
		// discovered on the way out: an untrusted guardian response reaches
		// this module through a hand-rolled decoder that can hand back short
		// or empty buffers.
		const broken = {
			protocolVersion: 1,
			guardianSetId: SET_ID,
			guardianId: GUARDIAN_IDS[0],
			supersededState: {
				recoveryId: ROOT.recoveryId,
				lease: { epoch: 1n, writerPublicKey: writer.publicKey },
				origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
				logHead: genesisLogHead()
			},
			newEpoch: 1n,
			newWriterPublicKey: writer.publicKey,
			issuedAt: 5n,
			signature: Buffer.alloc(0)
		} as IGuardianTakeoverCertificate;
		expect(() =>
			saveWriterLease(storage, leaseOf(1n, writer, null, [broken]))
		).to.throw(/signature is not 64 bytes/);
		expect(presentLease(storage).guardianCertificates).to.have.length(0);
		storage.close();
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
			saveWriterLease(storage, leaseOf(3n, writer));
			expect(presentLease(storage).writerSecret.equals(writer.secret)).to.equal(
				true
			);
			storage.close();

			// Read the raw file: the signing secret must not appear anywhere.
			const raw = new Database(dbPath, { readonly: true });
			const rows = raw
				.prepare('SELECT key, value FROM recovery_meta')
				.all() as Array<{ key: string; value: string }>;
			raw.close();
			const stored = rows.find((r) => r.key === LEASE_META_KEYS.lease);
			expect(stored, 'lease row present').to.not.equal(undefined);
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
