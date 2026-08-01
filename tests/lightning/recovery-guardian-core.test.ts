/**
 * Reference guardian core (docs/RECOVERY-GUARDIAN-WIRE.md section 5): the
 * per-namespace linearized state machine over the transactional store.
 *
 * The review contract these tests pin mechanically:
 * - idempotent replays return the STORED artifact, never a re-signed
 *   equivalent (the injected clock always advances, so a re-sign would
 *   betray itself with a fresh issuedAt);
 * - record, state and the returned receipt or certificate commit atomically
 *   and survive reopen byte-identically;
 * - the eight-step SYNC_EPOCH validation with its exact status codes;
 * - rollback-then-replay repair (wire 5.10): damaged stores refuse writes,
 *   roll back to the last verifying checkpoint, replay through SYNC_RECORD
 *   and re-enter writability only on a byte-exact quorum-evidenced target.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import {
	CRASH_V1_PROFILE,
	GuardianState,
	IGuardianAcquireEpochRequest,
	IGuardianAlarm,
	IGuardianReceipt,
	IGuardianRecord,
	IGuardianRegisterNodeRequest,
	IGuardianTakeoverCertificate,
	GuardianStatus,
	ReferenceGuardian,
	acquireTranscriptHash,
	computeGuardianSetId,
	deriveRecoveryRoot,
	genesisLogHead,
	receiptTranscriptHash,
	recordTranscriptHash,
	registerTranscriptHash,
	signTranscript,
	statesEqual,
	takeoverTranscriptHash,
	u64be,
	verifyTranscript,
	xOnlyFromSecret
} from '../../src/lightning/recovery';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();
const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`core-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});

const NODE_SECRET = sha('core-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);

function makeWriter(name: string): { secret: Buffer; pub: Buffer } {
	const secret = sha(name);
	return { secret, pub: xOnlyFromSecret(secret) };
}
const WRITER_1 = makeWriter('core-writer-1');
const WRITER_2 = makeWriter('core-writer-2');

// One shared, strictly increasing clock: any artifact signed twice would
// carry two different issuedAt values, so byte-equal artifacts prove the
// stored copy was returned.
let now = 1_700_000_000_000n;
const clock = (): bigint => ++now;

function makeGuardian(
	index: number,
	dbPath = ':memory:',
	onAlarm?: (alarm: IGuardianAlarm) => void
): ReferenceGuardian {
	return new ReferenceGuardian({
		path: dbPath,
		guardianSecret: GUARDIAN_SECRETS[index],
		members: GUARDIAN_IDS,
		clock,
		onAlarm
	});
}

function buildRegistration(opts?: {
	epoch?: bigint;
	origin?: { firstSequence: bigint; previousHash: Buffer };
	writerPub?: Buffer;
}): IGuardianRegisterNodeRequest {
	const initialState: GuardianState = {
		recoveryId: ROOT.recoveryId,
		lease: {
			epoch: opts?.epoch ?? 1n,
			writerPublicKey: opts?.writerPub ?? WRITER_1.pub
		},
		origin: opts?.origin ?? {
			firstSequence: 1n,
			previousHash: Buffer.alloc(32)
		},
		logHead: genesisLogHead()
	};
	return {
		protocolVersion: 1,
		guardianSetId: SET_ID,
		initialState,
		rootSignature: signTranscript(
			registerTranscriptHash(SET_ID, initialState),
			ROOT.rootSecret
		)
	};
}

function buildRecord(opts: {
	epoch: bigint;
	sequence: bigint;
	previousHash: Buffer;
	writerSecret: Buffer;
	ciphertext?: Buffer;
	frameHash?: Buffer;
}): IGuardianRecord {
	const ciphertext =
		opts.ciphertext ?? sha(`ciphertext-${opts.epoch}-${opts.sequence}`);
	const frameHash =
		opts.frameHash ??
		sha(`frame-${opts.epoch}-${opts.sequence}-${ciphertext.toString('hex')}`);
	const signature = signTranscript(
		recordTranscriptHash(SET_ID, {
			recoveryId: ROOT.recoveryId,
			epoch: opts.epoch,
			sequence: opts.sequence,
			previousHash: opts.previousHash,
			frameHash,
			ciphertextHash: sha256(ciphertext)
		}),
		opts.writerSecret
	);
	return {
		protocolVersion: 1,
		guardianSetId: SET_ID,
		recoveryId: ROOT.recoveryId,
		epoch: opts.epoch,
		sequence: opts.sequence,
		previousHash: opts.previousHash,
		frameHash,
		ciphertext,
		writerSignature: signature
	};
}

/** A verified chain of records continuing from a given state. */
function buildChain(from: GuardianState, count: number): IGuardianRecord[] {
	const records: IGuardianRecord[] = [];
	let sequence =
		from.logHead.sequence === 0n
			? from.origin.firstSequence
			: from.logHead.sequence + 1n;
	let previousHash =
		from.logHead.sequence === 0n
			? from.origin.previousHash
			: from.logHead.frameHash;
	for (let i = 0; i < count; i++) {
		const record = buildRecord({
			epoch: from.lease.epoch,
			sequence,
			previousHash,
			writerSecret: WRITER_1.secret
		});
		records.push(record);
		previousHash = record.frameHash;
		sequence += 1n;
	}
	return records;
}

function buildAcquire(
	expectedState: GuardianState,
	newWriter: { secret: Buffer; pub: Buffer }
): IGuardianAcquireEpochRequest {
	const newEpoch = expectedState.lease.epoch + 1n;
	const hash = acquireTranscriptHash(
		SET_ID,
		expectedState,
		newEpoch,
		newWriter.pub
	);
	return {
		protocolVersion: 1,
		guardianSetId: SET_ID,
		expectedState,
		newEpoch,
		newWriterPublicKey: newWriter.pub,
		rootSignature: signTranscript(hash, ROOT.rootSecret),
		newWriterSignature: signTranscript(hash, newWriter.secret)
	};
}

function expectValidReceipt(
	receipt: IGuardianReceipt | undefined,
	guardianIndex: number,
	state?: GuardianState
): IGuardianReceipt {
	expect(receipt, 'receipt present').to.not.equal(undefined);
	const r = receipt as IGuardianReceipt;
	expect(r.guardianId.equals(GUARDIAN_IDS[guardianIndex])).to.equal(true);
	const hash = receiptTranscriptHash(SET_ID, r.guardianId, r.state, r.issuedAt);
	expect(verifyTranscript(hash, r.signature, r.guardianId)).to.equal(true);
	if (state) {
		expect(statesEqual(r.state, state)).to.equal(true);
	}
	return r;
}

function expectValidCertificate(
	cert: IGuardianTakeoverCertificate | undefined,
	guardianIndex: number
): IGuardianTakeoverCertificate {
	expect(cert, 'certificate present').to.not.equal(undefined);
	const c = cert as IGuardianTakeoverCertificate;
	expect(c.guardianId.equals(GUARDIAN_IDS[guardianIndex])).to.equal(true);
	const hash = takeoverTranscriptHash(
		SET_ID,
		c.guardianId,
		c.supersededState,
		c.newEpoch,
		c.newWriterPublicKey,
		c.issuedAt
	);
	expect(verifyTranscript(hash, c.signature, c.guardianId)).to.equal(true);
	return c;
}

function headOf(guardian: ReferenceGuardian): GuardianState {
	const head = guardian.getHead({
		protocolVersion: 1,
		guardianSetId: SET_ID,
		recoveryId: ROOT.recoveryId
	});
	expect(head.status).to.equal(GuardianStatus.OK);
	return head.state as GuardianState;
}

describe('Guardian core: REGISTER_NODE', () => {
	it('registers, returns a verifying receipt, and serves the origin proof', () => {
		const guardian = makeGuardian(0);
		const registration = buildRegistration();
		const response = guardian.register(registration);
		expect(response.status).to.equal(GuardianStatus.OK);
		expectValidReceipt(response.receipt, 0, registration.initialState);

		const head = guardian.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		expect(head.status).to.equal(GuardianStatus.OK);
		expect(
			statesEqual(head.state as GuardianState, registration.initialState)
		).to.equal(true);
		expect(head.possiblyStale).to.equal(false);
		expect(
			(head.certificates as IGuardianTakeoverCertificate[]).length
		).to.equal(0);
		const origin = head.registration as IGuardianRegisterNodeRequest;
		expect(
			statesEqual(origin.initialState, registration.initialState)
		).to.equal(true);
		expect(origin.rootSignature.equals(registration.rootSignature)).to.equal(
			true
		);
		guardian.close();
	});

	it('returns the STORED receipt on duplicate, never a re-signed one', () => {
		const guardian = makeGuardian(0);
		const registration = buildRegistration();
		const first = guardian.register(registration);
		const replay = guardian.register(registration);
		expect(replay.status).to.equal(GuardianStatus.OK_DUPLICATE);
		const original = first.receipt as IGuardianReceipt;
		const stored = replay.receipt as IGuardianReceipt;
		// The clock advanced between the calls; equal issuedAt and signature
		// bytes prove the stored artifact came back.
		expect(stored.issuedAt).to.equal(original.issuedAt);
		expect(stored.signature.equals(original.signature)).to.equal(true);
		guardian.close();
	});

	it('rejects a differing registration with the current state attached', () => {
		const guardian = makeGuardian(0);
		guardian.register(buildRegistration());
		const differing = buildRegistration({ writerPub: WRITER_2.pub });
		const response = guardian.register(differing);
		expect(response.status).to.equal(GuardianStatus.ERR_ALREADY_REGISTERED);
		expect(
			statesEqual(
				response.current as GuardianState,
				buildRegistration().initialState
			)
		).to.equal(true);
		guardian.close();
	});

	it('rejects malformed registrations deterministically', () => {
		const guardian = makeGuardian(0);
		const good = buildRegistration();

		const badSig = { ...good, rootSignature: Buffer.alloc(64) };
		expect(guardian.register(badSig).status).to.equal(
			GuardianStatus.ERR_BAD_SIGNATURE
		);

		const nonGenesis = buildRegistration();
		nonGenesis.initialState.logHead.sequence = 5n;
		expect(guardian.register(nonGenesis).status).to.equal(
			GuardianStatus.ERR_MALFORMED
		);

		const zeroEpoch = buildRegistration({ epoch: 0n });
		expect(guardian.register(zeroEpoch).status).to.equal(
			GuardianStatus.ERR_MALFORMED
		);

		const zeroFirst = buildRegistration({
			origin: { firstSequence: 0n, previousHash: Buffer.alloc(32) }
		});
		expect(guardian.register(zeroFirst).status).to.equal(
			GuardianStatus.ERR_MALFORMED
		);

		const nonZeroPrev = buildRegistration({
			origin: { firstSequence: 1n, previousHash: sha('not-zero') }
		});
		expect(guardian.register(nonZeroPrev).status).to.equal(
			GuardianStatus.ERR_MALFORMED
		);

		expect(guardian.register({ ...good, protocolVersion: 2 }).status).to.equal(
			GuardianStatus.ERR_UNSUPPORTED_VERSION
		);
		expect(
			guardian.register({ ...good, guardianSetId: sha('other-set') }).status
		).to.equal(GuardianStatus.ERR_UNKNOWN_SET);
		guardian.close();
	});

	it('serves nothing for an unregistered namespace', () => {
		const guardian = makeGuardian(0);
		const record = buildRecord({
			epoch: 1n,
			sequence: 1n,
			previousHash: Buffer.alloc(32),
			writerSecret: WRITER_1.secret
		});
		expect(guardian.putState({ record }).status).to.equal(
			GuardianStatus.ERR_UNKNOWN_NODE
		);
		expect(
			guardian.getHead({
				protocolVersion: 1,
				guardianSetId: SET_ID,
				recoveryId: ROOT.recoveryId
			}).status
		).to.equal(GuardianStatus.ERR_UNKNOWN_NODE);
		guardian.close();
	});
});

describe('Guardian core: PUT_STATE', () => {
	it('appends, advances the head, and issues cumulative receipts', () => {
		const guardian = makeGuardian(0);
		const registration = buildRegistration();
		guardian.register(registration);
		const chain = buildChain(registration.initialState, 3);
		for (const [i, record] of chain.entries()) {
			const response = guardian.putState({ record });
			expect(response.status).to.equal(GuardianStatus.OK);
			const receipt = expectValidReceipt(response.receipt, 0);
			expect(receipt.state.logHead.sequence).to.equal(BigInt(i + 1));
			expect(receipt.state.logHead.frameHash.equals(record.frameHash)).to.equal(
				true
			);
			expect(
				receipt.state.logHead.ciphertextHash.equals(sha256(record.ciphertext))
			).to.equal(true);
			expect(receipt.state.logHead.recordEpoch).to.equal(1n);
		}
		const page = guardian.getState({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId,
			fromSequence: 0n,
			maxRecords: 0
		});
		expect(page.status).to.equal(GuardianStatus.OK);
		expect((page.records as IGuardianRecord[]).length).to.equal(3);
		expect(page.hasMore).to.equal(false);
		guardian.close();
	});

	it('returns the stored current receipt for a duplicate of an old record', () => {
		const guardian = makeGuardian(0);
		const registration = buildRegistration();
		guardian.register(registration);
		const chain = buildChain(registration.initialState, 3);
		let last: IGuardianReceipt | undefined;
		for (const record of chain) {
			last = guardian.putState({ record }).receipt;
		}
		const replay = guardian.putState({ record: chain[0] });
		expect(replay.status).to.equal(GuardianStatus.OK_DUPLICATE);
		const stored = replay.receipt as IGuardianReceipt;
		const current = last as IGuardianReceipt;
		expect(stored.issuedAt).to.equal(current.issuedAt);
		expect(stored.signature.equals(current.signature)).to.equal(true);
		expect(statesEqual(stored.state, current.state)).to.equal(true);
		guardian.close();
	});

	it('refuses a differing record at an occupied slot and keeps the original', () => {
		const alarms: IGuardianAlarm[] = [];
		const guardian = makeGuardian(0, ':memory:', (alarm) => alarms.push(alarm));
		const registration = buildRegistration();
		guardian.register(registration);
		const chain = buildChain(registration.initialState, 2);
		for (const record of chain) guardian.putState({ record });

		const forged = buildRecord({
			epoch: 1n,
			sequence: 2n,
			previousHash: chain[0].frameHash,
			writerSecret: WRITER_1.secret,
			ciphertext: sha('a-different-payload')
		});
		const response = guardian.putState({ record: forged });
		expect(response.status).to.equal(GuardianStatus.ERR_CONFLICT);
		expect(alarms.length).to.equal(1);
		expect(alarms[0].status).to.equal(GuardianStatus.ERR_CONFLICT);

		const page = guardian.getState({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId,
			fromSequence: 1n,
			maxRecords: 1
		});
		expect(
			(page.records as IGuardianRecord[])[0].ciphertext.equals(
				chain[1].ciphertext
			)
		).to.equal(true);
		guardian.close();
	});

	it('rejects epoch, gap, previous-hash and signature violations with exact codes', () => {
		const guardian = makeGuardian(0);
		const registration = buildRegistration();
		guardian.register(registration);
		const chain = buildChain(registration.initialState, 2);
		guardian.putState({ record: chain[0] });

		const futureEpoch = buildRecord({
			epoch: 2n,
			sequence: 2n,
			previousHash: chain[0].frameHash,
			writerSecret: WRITER_2.secret
		});
		const ahead = guardian.putState({ record: futureEpoch });
		expect(ahead.status).to.equal(GuardianStatus.ERR_EPOCH_SUPERSEDED);
		expect((ahead.current as GuardianState).lease.epoch).to.equal(1n);

		const gap = buildRecord({
			epoch: 1n,
			sequence: 3n,
			previousHash: chain[0].frameHash,
			writerSecret: WRITER_1.secret
		});
		expect(guardian.putState({ record: gap }).status).to.equal(
			GuardianStatus.ERR_SEQUENCE_GAP
		);

		const wrongPrev = buildRecord({
			epoch: 1n,
			sequence: 2n,
			previousHash: sha('wrong-previous'),
			writerSecret: WRITER_1.secret
		});
		expect(guardian.putState({ record: wrongPrev }).status).to.equal(
			GuardianStatus.ERR_PREV_HASH_MISMATCH
		);

		const wrongSigner = buildRecord({
			epoch: 1n,
			sequence: 2n,
			previousHash: chain[0].frameHash,
			writerSecret: WRITER_2.secret
		});
		expect(guardian.putState({ record: wrongSigner }).status).to.equal(
			GuardianStatus.ERR_BAD_SIGNATURE
		);

		const zeroSequence = buildRecord({
			epoch: 1n,
			sequence: 1n,
			previousHash: Buffer.alloc(32),
			writerSecret: WRITER_1.secret
		});
		expect(
			guardian.putState({ record: { ...zeroSequence, sequence: 0n } }).status
		).to.equal(GuardianStatus.ERR_MALFORMED);
		guardian.close();
	});

	it('anchors the first record at a mid-journal origin', () => {
		const guardian = makeGuardian(0);
		const origin = { firstSequence: 41n, previousHash: sha('frame-40') };
		const registration = buildRegistration({ origin });
		guardian.register(registration);

		const wrongStart = buildRecord({
			epoch: 1n,
			sequence: 1n,
			previousHash: Buffer.alloc(32),
			writerSecret: WRITER_1.secret
		});
		expect(guardian.putState({ record: wrongStart }).status).to.equal(
			GuardianStatus.ERR_SEQUENCE_GAP
		);

		const atOrigin = buildRecord({
			epoch: 1n,
			sequence: 41n,
			previousHash: origin.previousHash,
			writerSecret: WRITER_1.secret
		});
		const response = guardian.putState({ record: atOrigin });
		expect(response.status).to.equal(GuardianStatus.OK);
		expect(
			(response.receipt as IGuardianReceipt).state.logHead.sequence
		).to.equal(41n);
		guardian.close();
	});

	it('enforces the advertised ciphertext limit', () => {
		const guardian = new ReferenceGuardian({
			path: ':memory:',
			guardianSecret: GUARDIAN_SECRETS[0],
			members: GUARDIAN_IDS,
			clock,
			maxCiphertextBytes: 64
		});
		const registration = buildRegistration();
		guardian.register(registration);
		const oversize = buildRecord({
			epoch: 1n,
			sequence: 1n,
			previousHash: Buffer.alloc(32),
			writerSecret: WRITER_1.secret,
			ciphertext: Buffer.alloc(65, 7)
		});
		expect(guardian.putState({ record: oversize }).status).to.equal(
			GuardianStatus.ERR_TOO_LARGE
		);
		guardian.close();
	});
});

describe('Guardian core: GET_STATE pagination', () => {
	it('pages by sequence with an exclusive cursor', () => {
		const guardian = makeGuardian(0);
		const registration = buildRegistration();
		guardian.register(registration);
		for (const record of buildChain(registration.initialState, 5)) {
			guardian.putState({ record });
		}
		const first = guardian.getState({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId,
			fromSequence: 0n,
			maxRecords: 2
		});
		expect(
			(first.records as IGuardianRecord[]).map((r) => r.sequence)
		).to.deep.equal([1n, 2n]);
		expect(first.hasMore).to.equal(true);
		const second = guardian.getState({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId,
			fromSequence: 2n,
			maxRecords: 2
		});
		expect(
			(second.records as IGuardianRecord[]).map((r) => r.sequence)
		).to.deep.equal([3n, 4n]);
		expect(second.hasMore).to.equal(true);
		const third = guardian.getState({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId,
			fromSequence: 4n,
			maxRecords: 2
		});
		expect(
			(third.records as IGuardianRecord[]).map((r) => r.sequence)
		).to.deep.equal([5n]);
		expect(third.hasMore).to.equal(false);
		guardian.close();
	});
});

describe('Guardian core: ACQUIRE_EPOCH', () => {
	function registeredGuardianWithRecords(): {
		guardian: ReferenceGuardian;
		state: GuardianState;
	} {
		const guardian = makeGuardian(0);
		const registration = buildRegistration();
		guardian.register(registration);
		for (const record of buildChain(registration.initialState, 2)) {
			guardian.putState({ record });
		}
		return { guardian, state: headOf(guardian) };
	}

	it('performs a CAS takeover: lease advances, log head stays', () => {
		const { guardian, state } = registeredGuardianWithRecords();
		const response = guardian.acquireEpoch(buildAcquire(state, WRITER_2));
		expect(response.status).to.equal(GuardianStatus.OK);
		const cert = expectValidCertificate(response.certificate, 0);
		expect(statesEqual(cert.supersededState, state)).to.equal(true);
		expect(cert.newEpoch).to.equal(2n);
		const receipt = expectValidReceipt(response.receipt, 0);
		expect(receipt.state.lease.epoch).to.equal(2n);
		expect(receipt.state.lease.writerPublicKey.equals(WRITER_2.pub)).to.equal(
			true
		);
		// recordEpoch lawfully trails the lease until the first new append.
		expect(receipt.state.logHead.recordEpoch).to.equal(1n);
		expect(receipt.state.logHead.sequence).to.equal(state.logHead.sequence);

		const head = guardian.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		expect(
			(head.certificates as IGuardianTakeoverCertificate[]).length
		).to.equal(1);

		// The old writer is fenced; the new writer continues the chain.
		const fenced = buildRecord({
			epoch: 1n,
			sequence: state.logHead.sequence + 1n,
			previousHash: state.logHead.frameHash,
			writerSecret: WRITER_1.secret
		});
		expect(guardian.putState({ record: fenced }).status).to.equal(
			GuardianStatus.ERR_EPOCH_SUPERSEDED
		);
		const continued = buildRecord({
			epoch: 2n,
			sequence: state.logHead.sequence + 1n,
			previousHash: state.logHead.frameHash,
			writerSecret: WRITER_2.secret
		});
		const appended = guardian.putState({ record: continued });
		expect(appended.status).to.equal(GuardianStatus.OK);
		expect(
			(appended.receipt as IGuardianReceipt).state.logHead.recordEpoch
		).to.equal(2n);
		guardian.close();
	});

	it('fails the CAS byte-exactly and attaches state plus certificates', () => {
		const { guardian, state } = registeredGuardianWithRecords();
		const stale: GuardianState = {
			...state,
			logHead: { ...state.logHead, sequence: state.logHead.sequence - 1n }
		};
		const response = guardian.acquireEpoch(buildAcquire(stale, WRITER_2));
		expect(response.status).to.equal(GuardianStatus.ERR_CAS_FAILED);
		expect(statesEqual(response.current as GuardianState, state)).to.equal(
			true
		);
		expect(Array.isArray(response.certificates)).to.equal(true);
		guardian.close();
	});

	it('returns stored artifacts for a duplicate acquisition', () => {
		const { guardian, state } = registeredGuardianWithRecords();
		const request = buildAcquire(state, WRITER_2);
		const first = guardian.acquireEpoch(request);
		const replay = guardian.acquireEpoch(request);
		expect(replay.status).to.equal(GuardianStatus.OK_DUPLICATE);
		const originalCert = first.certificate as IGuardianTakeoverCertificate;
		const storedCert = replay.certificate as IGuardianTakeoverCertificate;
		expect(storedCert.issuedAt).to.equal(originalCert.issuedAt);
		expect(storedCert.signature.equals(originalCert.signature)).to.equal(true);
		const originalReceipt = first.receipt as IGuardianReceipt;
		const storedReceipt = replay.receipt as IGuardianReceipt;
		expect(storedReceipt.issuedAt).to.equal(originalReceipt.issuedAt);
		expect(storedReceipt.signature.equals(originalReceipt.signature)).to.equal(
			true
		);
		guardian.close();
	});

	it('rejects a second writer for the same epoch: first writer wins', () => {
		const { guardian, state } = registeredGuardianWithRecords();
		guardian.acquireEpoch(buildAcquire(state, WRITER_2));
		const loser = makeWriter('core-writer-3');
		const response = guardian.acquireEpoch(buildAcquire(state, loser));
		expect(response.status).to.equal(GuardianStatus.ERR_EPOCH_SUPERSEDED);
		expect((response.current as GuardianState).lease.epoch).to.equal(2n);
		guardian.close();
	});

	it('rejects malformed and unauthorized acquisitions', () => {
		const { guardian, state } = registeredGuardianWithRecords();
		const good = buildAcquire(state, WRITER_2);
		expect(
			guardian.acquireEpoch({ ...good, newEpoch: good.newEpoch + 1n }).status
		).to.equal(GuardianStatus.ERR_MALFORMED);
		expect(
			guardian.acquireEpoch({ ...good, rootSignature: Buffer.alloc(64) }).status
		).to.equal(GuardianStatus.ERR_BAD_SIGNATURE);
		expect(
			guardian.acquireEpoch({ ...good, newWriterSignature: Buffer.alloc(64) })
				.status
		).to.equal(GuardianStatus.ERR_BAD_SIGNATURE);
		guardian.close();
	});
});

describe('Guardian core: SYNC_RECORD backfill', () => {
	it('repairs a lagging guardian with self-authenticating records', () => {
		const a = makeGuardian(0);
		const b = makeGuardian(1);
		const registration = buildRegistration();
		a.register(registration);
		b.register(registration);
		const chain = buildChain(registration.initialState, 3);
		for (const record of chain) a.putState({ record });
		// B missed everything; anyone holding the records repairs it.
		for (const record of chain) {
			const response = b.syncRecord({ record });
			expect(response.status).to.equal(GuardianStatus.OK);
			expectValidReceipt(response.receipt, 1);
		}
		expect(statesEqual(headOf(a), headOf(b))).to.equal(true);
		a.close();
		b.close();
	});
});

describe('Guardian core: SYNC_EPOCH', () => {
	interface ISyncFixture {
		a: ReferenceGuardian;
		b: ReferenceGuardian;
		c: ReferenceGuardian;
		chain: IGuardianRecord[];
		minorityTail: IGuardianRecord;
		supersededState: GuardianState;
		certA: IGuardianTakeoverCertificate;
		certB: IGuardianTakeoverCertificate;
	}

	function syncFixture(): ISyncFixture {
		const a = makeGuardian(0);
		const b = makeGuardian(1);
		const c = makeGuardian(2);
		const registration = buildRegistration();
		for (const g of [a, b, c]) g.register(registration);
		const chain = buildChain(registration.initialState, 2);
		for (const g of [a, b, c]) {
			for (const record of chain) g.putState({ record });
		}
		// C alone stores a minority-tail record before the takeover.
		const supersededState = headOf(a);
		const minorityTail = buildChain(headOf(c), 1)[0];
		expect(c.putState({ record: minorityTail }).status).to.equal(
			GuardianStatus.OK
		);

		const acquire = buildAcquire(supersededState, WRITER_2);
		const certA = a.acquireEpoch(acquire)
			.certificate as IGuardianTakeoverCertificate;
		const certB = b.acquireEpoch(acquire)
			.certificate as IGuardianTakeoverCertificate;
		return { a, b, c, chain, minorityTail, supersededState, certA, certB };
	}

	function closeAll(fixture: ISyncFixture): void {
		fixture.a.close();
		fixture.b.close();
		fixture.c.close();
	}

	it('walks the eight steps with exact codes', () => {
		const fixture = syncFixture();
		const { c, certA, certB } = fixture;

		expect(c.syncEpoch({ certificates: [] }).status).to.equal(
			GuardianStatus.ERR_MALFORMED
		);
		expect(c.syncEpoch({ certificates: [certA] }).status).to.equal(
			GuardianStatus.ERR_INSUFFICIENT_CERTS
		);
		expect(c.syncEpoch({ certificates: [certA, certA] }).status).to.equal(
			GuardianStatus.ERR_CERT_MISMATCH
		);

		const disagreeing = { ...certB, newWriterPublicKey: WRITER_1.pub };
		expect(c.syncEpoch({ certificates: [certA, disagreeing] }).status).to.equal(
			GuardianStatus.ERR_CERT_MISMATCH
		);

		const outsider = makeWriter('outsider');
		const nonMember = {
			...certB,
			guardianId: outsider.pub,
			signature: signTranscript(
				takeoverTranscriptHash(
					SET_ID,
					outsider.pub,
					certB.supersededState,
					certB.newEpoch,
					certB.newWriterPublicKey,
					certB.issuedAt
				),
				outsider.secret
			)
		};
		expect(c.syncEpoch({ certificates: [certA, nonMember] }).status).to.equal(
			GuardianStatus.ERR_CERT_MISMATCH
		);

		const tampered = { ...certB, signature: Buffer.alloc(64) };
		expect(c.syncEpoch({ certificates: [certA, tampered] }).status).to.equal(
			GuardianStatus.ERR_BAD_SIGNATURE
		);
		closeAll(fixture);
	});

	it('rejects a stale bundle on a guardian already past the takeover', () => {
		const fixture = syncFixture();
		const response = fixture.a.syncEpoch({
			certificates: [fixture.certA, fixture.certB]
		});
		expect(response.status).to.equal(GuardianStatus.ERR_EPOCH_REGRESSION);
		closeAll(fixture);
	});

	it('demands SYNC_RECORD first when the local log is behind the certified head', () => {
		const fixture = syncFixture();
		const fresh = makeGuardian(0, ':memory:');
		fresh.register(buildRegistration());
		const response = fresh.syncEpoch({
			certificates: [fixture.certA, fixture.certB]
		});
		expect(response.status).to.equal(GuardianStatus.ERR_HEAD_UNKNOWN);
		fresh.close();
		closeAll(fixture);
	});

	it('flags a certified head conflicting with a stored record', () => {
		const fixture = syncFixture();
		const alarms: IGuardianAlarm[] = [];
		const e = makeGuardian(0, ':memory:', (alarm) => alarms.push(alarm));
		const registration = buildRegistration();
		e.register(registration);
		e.putState({ record: fixture.chain[0] });
		const divergent = buildRecord({
			epoch: 1n,
			sequence: 2n,
			previousHash: fixture.chain[0].frameHash,
			writerSecret: WRITER_1.secret,
			ciphertext: sha('a-divergent-record-2')
		});
		expect(e.putState({ record: divergent }).status).to.equal(
			GuardianStatus.OK
		);
		const response = e.syncEpoch({
			certificates: [fixture.certA, fixture.certB]
		});
		expect(response.status).to.equal(GuardianStatus.ERR_CONFLICT);
		expect(
			alarms.some((a) => a.status === GuardianStatus.ERR_CONFLICT)
		).to.equal(true);
		e.close();
		closeAll(fixture);
	});

	it('adopts the takeover, truncates the minority tail, and reconciles', () => {
		const fixture = syncFixture();
		const { c, minorityTail, supersededState, certA, certB } = fixture;

		const response = c.syncEpoch({ certificates: [certA, certB] });
		expect(response.status).to.equal(GuardianStatus.OK);
		const ownCert = expectValidCertificate(response.certificate, 2);
		expect(statesEqual(ownCert.supersededState, supersededState)).to.equal(
			true
		);
		const receipt = expectValidReceipt(response.receipt, 2);
		expect(receipt.state.lease.epoch).to.equal(2n);
		expect(receipt.state.logHead.sequence).to.equal(2n);

		// The truncated record moved to the orphan archive and left GET_STATE.
		const orphans = c.listOrphanedRecords(ROOT.recoveryId);
		expect(orphans.length).to.equal(1);
		expect(orphans[0].reason).to.equal('sync-epoch-truncation');
		expect(orphans[0].frameHash.equals(minorityTail.frameHash)).to.equal(true);
		const page = c.getState({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId,
			fromSequence: 0n,
			maxRecords: 0
		});
		expect((page.records as IGuardianRecord[]).length).to.equal(2);

		// The new writer re-fills sequence 3 under the new epoch everywhere.
		const refill = buildRecord({
			epoch: 2n,
			sequence: 3n,
			previousHash: supersededState.logHead.frameHash,
			writerSecret: WRITER_2.secret
		});
		expect(c.putState({ record: refill }).status).to.equal(GuardianStatus.OK);
		const refilled = c.getState({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId,
			fromSequence: 2n,
			maxRecords: 0
		});
		const rows = refilled.records as IGuardianRecord[];
		expect(rows.length).to.equal(1);
		expect(rows[0].ciphertext.equals(refill.ciphertext)).to.equal(true);
		expect(rows[0].epoch).to.equal(2n);
		closeAll(fixture);
	});
});

describe('Guardian core: durability and reopen', () => {
	let dir: string;
	before(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-guardian-'));
	});
	after(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('returns identical stored artifacts across a full restart', () => {
		const file = path.join(dir, 'reopen.sqlite');
		const first = makeGuardian(0, file);
		const registration = buildRegistration();
		const registered = first.register(registration);
		const chain = buildChain(registration.initialState, 2);
		let lastPut: { receipt?: IGuardianReceipt } | undefined;
		for (const record of chain) lastPut = first.putState({ record });
		const acquire = buildAcquire(headOf(first), WRITER_2);
		const acquired = first.acquireEpoch(acquire);
		first.close();

		const second = makeGuardian(0, file);
		const head = second.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		expect(head.status).to.equal(GuardianStatus.OK);
		expect(head.possiblyStale).to.equal(false);
		expect(
			statesEqual(
				head.state as GuardianState,
				(acquired.receipt as IGuardianReceipt).state
			)
		).to.equal(true);

		const replayRegister = second.register(registration);
		expect(replayRegister.status).to.equal(GuardianStatus.OK_DUPLICATE);
		expect(
			(replayRegister.receipt as IGuardianReceipt).signature.equals(
				(registered.receipt as IGuardianReceipt).signature
			)
		).to.equal(true);

		const replayPut = second.putState({ record: chain[1] });
		expect(replayPut.status).to.equal(GuardianStatus.OK_DUPLICATE);

		const replayAcquire = second.acquireEpoch(acquire);
		expect(replayAcquire.status).to.equal(GuardianStatus.OK_DUPLICATE);
		expect(
			(
				replayAcquire.certificate as IGuardianTakeoverCertificate
			).signature.equals(
				(acquired.certificate as IGuardianTakeoverCertificate).signature
			)
		).to.equal(true);
		expect(
			(replayAcquire.receipt as IGuardianReceipt).signature.equals(
				(acquired.receipt as IGuardianReceipt).signature
			)
		).to.equal(true);
		expect(
			(lastPut?.receipt as IGuardianReceipt).state.logHead.sequence
		).to.equal(2n);
		second.close();
	});

	it('two connections to one store stay linearized through the database', () => {
		const file = path.join(dir, 'shared.sqlite');
		const g1 = makeGuardian(0, file);
		const g2 = makeGuardian(0, file);
		const registration = buildRegistration();
		expect(g1.register(registration).status).to.equal(GuardianStatus.OK);
		const chain = buildChain(registration.initialState, 4);
		// Interleave appends across independent connections: the BEGIN
		// IMMEDIATE discipline, not shared process memory, keeps the chain.
		expect(g2.putState({ record: chain[0] }).status).to.equal(
			GuardianStatus.OK
		);
		expect(g1.putState({ record: chain[1] }).status).to.equal(
			GuardianStatus.OK
		);
		expect(g2.putState({ record: chain[2] }).status).to.equal(
			GuardianStatus.OK
		);
		expect(g1.putState({ record: chain[3] }).status).to.equal(
			GuardianStatus.OK
		);
		expect(statesEqual(headOf(g1), headOf(g2))).to.equal(true);
		const replay = g1.putState({ record: chain[2] });
		expect(replay.status).to.equal(GuardianStatus.OK_DUPLICATE);
		g1.close();
		g2.close();
	});
});

describe('Guardian core: damaged store, rollback, replay, quorum re-entry', () => {
	let dir: string;
	before(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-guardian-repair-'));
	});
	after(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	interface IRepairFixture {
		file: string;
		registration: IGuardianRegisterNodeRequest;
		chain: IGuardianRecord[];
		finalState: GuardianState;
		evidence: IGuardianReceipt[];
	}

	/** A, file-backed, holds 1..4; B and C hold the same and supply receipts. */
	function repairFixture(name: string): IRepairFixture {
		const file = path.join(dir, name);
		const a = makeGuardian(0, file);
		const b = makeGuardian(1);
		const c = makeGuardian(2);
		const registration = buildRegistration();
		for (const g of [a, b, c]) g.register(registration);
		const chain = buildChain(registration.initialState, 4);
		const evidence: IGuardianReceipt[] = [];
		for (const record of chain) {
			a.putState({ record });
			const rb = b.syncRecord({ record });
			const rc = c.syncRecord({ record });
			if (record === chain[chain.length - 1]) {
				evidence.push(
					rb.receipt as IGuardianReceipt,
					rc.receipt as IGuardianReceipt
				);
			}
		}
		const finalState = headOf(a);
		a.close();
		b.close();
		c.close();
		return { file, registration, chain, finalState, evidence };
	}

	it('rolls back to the checkpoint, refuses writes, replays, and lifts on quorum evidence', () => {
		const fixture = repairFixture('corrupt-ciphertext.sqlite');
		const raw = new Database(fixture.file);
		raw
			.prepare('UPDATE guardian_records SET ciphertext = ? WHERE sequence = ?')
			.run(sha('flipped-bits'), u64be(3n));
		raw.close();

		const alarms: IGuardianAlarm[] = [];
		const guardian = makeGuardian(0, fixture.file, (alarm) =>
			alarms.push(alarm)
		);
		expect(
			alarms.some((a) => a.status === GuardianStatus.ERR_STORE_UNCERTAIN)
		).to.equal(true);

		// Rolled back to the last verifying prefix and flagged.
		const head = guardian.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).logHead.sequence).to.equal(2n);
		const orphans = guardian.listOrphanedRecords(ROOT.recoveryId);
		expect(orphans.filter((o) => o.reason === 'rollback').length).to.equal(2);

		// Ordinary writes refuse; the repair channel stays open.
		expect(guardian.putState({ record: fixture.chain[3] }).status).to.equal(
			GuardianStatus.ERR_STORE_UNCERTAIN
		);
		expect(
			guardian.acquireEpoch(buildAcquire(fixture.finalState, WRITER_2)).status
		).to.equal(GuardianStatus.ERR_STORE_UNCERTAIN);

		// Replay through SYNC_RECORD; evidence before the target is reached
		// fails the byte-exact comparison.
		expect(guardian.syncRecord({ record: fixture.chain[2] }).status).to.equal(
			GuardianStatus.OK
		);
		const early = guardian.submitRepairEvidence({
			recoveryId: ROOT.recoveryId,
			target: fixture.finalState,
			receipts: fixture.evidence,
			certificates: []
		});
		expect(early.status).to.equal(GuardianStatus.ERR_CAS_FAILED);

		expect(guardian.syncRecord({ record: fixture.chain[3] }).status).to.equal(
			GuardianStatus.OK
		);

		// One receipt is not a quorum.
		expect(
			guardian.submitRepairEvidence({
				recoveryId: ROOT.recoveryId,
				target: fixture.finalState,
				receipts: [fixture.evidence[0]],
				certificates: []
			}).status
		).to.equal(GuardianStatus.ERR_INSUFFICIENT_CERTS);

		const lifted = guardian.submitRepairEvidence({
			recoveryId: ROOT.recoveryId,
			target: fixture.finalState,
			receipts: fixture.evidence,
			certificates: []
		});
		expect(lifted.status).to.equal(GuardianStatus.OK);
		const after = guardian.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		expect(after.possiblyStale).to.equal(false);
		const resumed = buildChain(after.state as GuardianState, 1)[0];
		expect(guardian.putState({ record: resumed }).status).to.equal(
			GuardianStatus.OK
		);
		guardian.close();
	});

	it('head verification defeats silent truncation', () => {
		const fixture = repairFixture('truncated.sqlite');
		const raw = new Database(fixture.file);
		raw
			.prepare('DELETE FROM guardian_records WHERE sequence > ?')
			.run(u64be(2n));
		raw.close();

		const guardian = makeGuardian(0, fixture.file);
		const head = guardian.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		// The declared head claimed 4 but the log verifies only through 2:
		// the guardian must confess instead of serving a truncated log as
		// canonical.
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).logHead.sequence).to.equal(2n);
		expect(guardian.putState({ record: fixture.chain[3] }).status).to.equal(
			GuardianStatus.ERR_STORE_UNCERTAIN
		);
		guardian.close();
	});

	it('tombstones a namespace with no checkpoint and re-anchors on re-registration', () => {
		const fixture = repairFixture('lost-registration.sqlite');
		const raw = new Database(fixture.file);
		raw
			.prepare('UPDATE guardian_namespaces SET registration_signature = ?')
			.run(Buffer.alloc(64));
		raw.close();

		const guardian = makeGuardian(0, fixture.file);
		// No registration means no checkpoint at all.
		expect(
			guardian.getHead({
				protocolVersion: 1,
				guardianSetId: SET_ID,
				recoveryId: ROOT.recoveryId
			}).status
		).to.equal(GuardianStatus.ERR_STORE_UNCERTAIN);
		expect(guardian.syncRecord({ record: fixture.chain[0] }).status).to.equal(
			GuardianStatus.ERR_STORE_UNCERTAIN
		);

		// The root-signed registration re-anchors repair at genesis, but the
		// namespace stays possibly stale: history was lost.
		const reanchored = guardian.register(fixture.registration);
		expect(reanchored.status).to.equal(GuardianStatus.OK);
		const head = guardian.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).logHead.sequence).to.equal(0n);

		for (const record of fixture.chain) {
			expect(guardian.syncRecord({ record }).status).to.equal(
				GuardianStatus.OK
			);
		}
		expect(
			guardian.putState({
				record: buildChain(fixture.finalState, 1)[0]
			}).status
		).to.equal(GuardianStatus.ERR_STORE_UNCERTAIN);

		const lifted = guardian.submitRepairEvidence({
			recoveryId: ROOT.recoveryId,
			target: fixture.finalState,
			receipts: fixture.evidence,
			certificates: []
		});
		expect(lifted.status).to.equal(GuardianStatus.OK);
		expect(
			guardian.putState({
				record: buildChain(fixture.finalState, 1)[0]
			}).status
		).to.equal(GuardianStatus.OK);
		guardian.close();
	});

	it('accepts takeover certificates as quorum evidence for a post-takeover target', () => {
		const file = path.join(dir, 'cert-evidence.sqlite');
		const a = makeGuardian(0, file);
		const b = makeGuardian(1);
		const c = makeGuardian(2);
		const registration = buildRegistration();
		for (const g of [a, b, c]) g.register(registration);
		const chain = buildChain(registration.initialState, 2);
		for (const g of [a, b, c]) {
			for (const record of chain) {
				if (g === a) g.putState({ record });
				else g.syncRecord({ record });
			}
		}
		const superseded = headOf(a);
		const acquire = buildAcquire(superseded, WRITER_2);
		const certB = b.acquireEpoch(acquire)
			.certificate as IGuardianTakeoverCertificate;
		const certC = c.acquireEpoch(acquire)
			.certificate as IGuardianTakeoverCertificate;
		const target = b.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		}).state as GuardianState;
		a.close();

		const raw = new Database(file);
		raw
			.prepare('UPDATE guardian_records SET ciphertext = ? WHERE sequence = ?')
			.run(sha('rot'), u64be(2n));
		raw.close();

		const reopened = makeGuardian(0, file);
		expect(headOf(reopened).logHead.sequence).to.equal(1n);
		expect(reopened.syncRecord({ record: chain[1] }).status).to.equal(
			GuardianStatus.OK
		);
		expect(
			reopened.syncEpoch({ certificates: [certB, certC] }).status
		).to.equal(GuardianStatus.OK);
		const lifted = reopened.submitRepairEvidence({
			recoveryId: ROOT.recoveryId,
			target,
			receipts: [],
			certificates: [certB, certC]
		});
		expect(lifted.status).to.equal(GuardianStatus.OK);
		expect(
			reopened.getHead({
				protocolVersion: 1,
				guardianSetId: SET_ID,
				recoveryId: ROOT.recoveryId
			}).possiblyStale
		).to.equal(false);
		reopened.close();
		b.close();
		c.close();
	});
});

describe('Guardian core: structural corruption containment', () => {
	let dir: string;
	before(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-guardian-shape-'));
	});
	after(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	function corrupt(file: string, sql: string, ...params: unknown[]): void {
		const raw = new Database(file);
		raw.prepare(sql).run(...params);
		raw.close();
	}

	interface IShapeFixture {
		file: string;
		registration: IGuardianRegisterNodeRequest;
		chain: IGuardianRecord[];
		finalState: GuardianState;
		evidence: IGuardianReceipt[];
	}

	/** File-backed guardian holding 1..4; B and C receipts serve as evidence. */
	function shapeFixture(name: string): IShapeFixture {
		const file = path.join(dir, name);
		const a = makeGuardian(0, file);
		const b = makeGuardian(1);
		const c = makeGuardian(2);
		const registration = buildRegistration();
		for (const g of [a, b, c]) g.register(registration);
		const chain = buildChain(registration.initialState, 4);
		const evidence: IGuardianReceipt[] = [];
		for (const record of chain) {
			a.putState({ record });
			const rb = b.syncRecord({ record });
			const rc = c.syncRecord({ record });
			if (record === chain[chain.length - 1]) {
				evidence.push(
					rb.receipt as IGuardianReceipt,
					rc.receipt as IGuardianReceipt
				);
			}
		}
		const finalState = headOf(a);
		a.close();
		b.close();
		c.close();
		return { file, registration, chain, finalState, evidence };
	}

	function reopen(file: string, alarms?: IGuardianAlarm[]): ReferenceGuardian {
		const capture = alarms
			? (a: IGuardianAlarm): void => {
					alarms.push(a);
			  }
			: undefined;
		return makeGuardian(0, file, capture);
	}

	function headRequest(): {
		protocolVersion: number;
		guardianSetId: Buffer;
		recoveryId: Buffer;
	} {
		return {
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		};
	}

	it('a malformed record sequence rolls back the namespace instead of stopping the guardian', () => {
		const fixture = shapeFixture('bad-sequence.sqlite');
		corrupt(
			fixture.file,
			'UPDATE guardian_records SET sequence = ? WHERE sequence = ?',
			Buffer.from([0, 0, 0, 0, 0, 0, 3]),
			u64be(3n)
		);
		const alarms: IGuardianAlarm[] = [];
		const guardian = reopen(fixture.file, alarms);
		expect(
			alarms.some((a) => a.status === GuardianStatus.ERR_STORE_UNCERTAIN)
		).to.equal(true);
		const head = guardian.getHead(headRequest());
		expect(head.status).to.equal(GuardianStatus.OK);
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).logHead.sequence).to.equal(2n);
		// The malformed row was SWEPT, not left behind to re-fail every open.
		expect(guardian.listOrphanedRecords(ROOT.recoveryId).length).to.equal(2);
		expect(guardian.syncRecord({ record: fixture.chain[2] }).status).to.equal(
			GuardianStatus.OK
		);
		expect(guardian.syncRecord({ record: fixture.chain[3] }).status).to.equal(
			GuardianStatus.OK
		);
		expect(
			guardian.submitRepairEvidence({
				recoveryId: ROOT.recoveryId,
				target: fixture.finalState,
				receipts: fixture.evidence,
				certificates: []
			}).status
		).to.equal(GuardianStatus.OK);
		guardian.close();

		// A second reopen finds a fully verifying store: no rollback, still
		// writable.
		const laterAlarms: IGuardianAlarm[] = [];
		const again = reopen(fixture.file, laterAlarms);
		expect(laterAlarms.length).to.equal(0);
		const after = again.getHead(headRequest());
		expect(after.possiblyStale).to.equal(false);
		expect(
			again.putState({ record: buildChain(fixture.finalState, 1)[0] }).status
		).to.equal(GuardianStatus.OK);
		again.close();
	});

	it('a malformed record epoch rolls back to the last decodable prefix', () => {
		const fixture = shapeFixture('bad-record-epoch.sqlite');
		corrupt(
			fixture.file,
			'UPDATE guardian_records SET epoch = ? WHERE sequence = ?',
			Buffer.alloc(9, 1),
			u64be(3n)
		);
		const guardian = reopen(fixture.file);
		const head = guardian.getHead(headRequest());
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).logHead.sequence).to.equal(2n);
		guardian.close();
	});

	it('a truncated writer signature is a shape failure, not a crash', () => {
		const fixture = shapeFixture('bad-writer-sig.sqlite');
		corrupt(
			fixture.file,
			'UPDATE guardian_records SET writer_signature = ? WHERE sequence = ?',
			Buffer.alloc(63, 7),
			u64be(2n)
		);
		const guardian = reopen(fixture.file);
		const head = guardian.getHead(headRequest());
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).logHead.sequence).to.equal(1n);
		expect(guardian.putState({ record: fixture.chain[1] }).status).to.equal(
			GuardianStatus.ERR_STORE_UNCERTAIN
		);
		guardian.close();
	});

	function takeoverFixture(name: string): { file: string } {
		const file = path.join(dir, name);
		const a = makeGuardian(0, file);
		const registration = buildRegistration();
		a.register(registration);
		const chain = buildChain(registration.initialState, 2);
		for (const record of chain) a.putState({ record });
		const acquired = a.acquireEpoch(buildAcquire(headOf(a), WRITER_2));
		expect(acquired.status).to.equal(GuardianStatus.OK);
		const continued = buildRecord({
			epoch: 2n,
			sequence: 3n,
			previousHash: chain[1].frameHash,
			writerSecret: WRITER_2.secret
		});
		expect(a.putState({ record: continued }).status).to.equal(
			GuardianStatus.OK
		);
		a.close();
		return { file };
	}

	it('a malformed epoch-row epoch rolls the lease back and sweeps the row', () => {
		const { file } = takeoverFixture('bad-epoch-row.sqlite');
		corrupt(
			file,
			'UPDATE guardian_epochs SET epoch = ? WHERE epoch = ?',
			Buffer.from([0, 0, 0, 0, 0, 0, 2]),
			u64be(2n)
		);
		const guardian = reopen(file);
		const head = guardian.getHead(headRequest());
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).lease.epoch).to.equal(1n);
		expect((head.state as GuardianState).logHead.sequence).to.equal(2n);
		guardian.close();
		// Idempotent: the swept row cannot re-fail the next open.
		const laterAlarms: IGuardianAlarm[] = [];
		const again = reopen(file, laterAlarms);
		expect(laterAlarms.length).to.equal(0);
		again.close();
	});

	it('a malformed certificate issuedAt rolls back to before the takeover', () => {
		const { file } = takeoverFixture('bad-cert-issued-at.sqlite');
		corrupt(
			file,
			'UPDATE guardian_epochs SET cert_issued_at = ? WHERE epoch = ?',
			Buffer.alloc(7, 1),
			u64be(2n)
		);
		const guardian = reopen(file);
		const head = guardian.getHead(headRequest());
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).lease.epoch).to.equal(1n);
		guardian.close();
	});

	it('a malformed cumulative receipt goes stale with a fresh verifying receipt', () => {
		const fixture = shapeFixture('bad-receipt-issued-at.sqlite');
		corrupt(
			fixture.file,
			'UPDATE guardian_namespaces SET receipt_issued_at = ?',
			Buffer.alloc(7, 2)
		);
		const guardian = reopen(fixture.file);
		const head = guardian.getHead(headRequest());
		expect(head.possiblyStale).to.equal(true);
		// The chain itself was intact: nothing was lost, only distrusted.
		expect((head.state as GuardianState).logHead.sequence).to.equal(4n);
		expectValidReceipt(head.receipt, 0, fixture.finalState);
		guardian.close();
	});

	it('an unverifiable registration receipt is replaced and the namespace goes uncertain', () => {
		const fixture = shapeFixture('bad-registration-receipt.sqlite');
		corrupt(
			fixture.file,
			'UPDATE guardian_namespaces SET registration_receipt_signature = ?',
			Buffer.alloc(64)
		);
		const alarms: IGuardianAlarm[] = [];
		const guardian = reopen(fixture.file, alarms);
		expect(
			alarms.some((a) => a.detail.includes('registration receipt'))
		).to.equal(true);
		const head = guardian.getHead(headRequest());
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).logHead.sequence).to.equal(4n);
		// The duplicate path must return a VERIFYING receipt again: the exact
		// original is unprovable, so an honest replacement stands in for it.
		const replay = guardian.register(fixture.registration);
		expect(replay.status).to.equal(GuardianStatus.OK_DUPLICATE);
		expectValidReceipt(replay.receipt, 0, fixture.registration.initialState);
		guardian.close();
	});

	// SQLite storage-class corruption: these are ordinary (non-STRICT)
	// tables, so a TEXT value can occupy a BLOB-affinity column. A
	// same-width TEXT value defeats bare length checks, decodes to no
	// Buffer, and sorts BEFORE every blob so range deletes miss it. Each
	// case must contain, repair where applicable, and NOT re-alarm on the
	// next open.

	it('a same-width TEXT sequence is contained, swept, and repairable', () => {
		const fixture = shapeFixture('text-sequence.sqlite');
		corrupt(
			fixture.file,
			'UPDATE guardian_records SET sequence = ? WHERE sequence = ?',
			'12345678',
			u64be(3n)
		);
		const alarms: IGuardianAlarm[] = [];
		const guardian = reopen(fixture.file, alarms);
		expect(
			alarms.some((a) => a.status === GuardianStatus.ERR_STORE_UNCERTAIN)
		).to.equal(true);
		const head = guardian.getHead(headRequest());
		expect(head.status).to.equal(GuardianStatus.OK);
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).logHead.sequence).to.equal(2n);
		expect(guardian.syncRecord({ record: fixture.chain[2] }).status).to.equal(
			GuardianStatus.OK
		);
		expect(guardian.syncRecord({ record: fixture.chain[3] }).status).to.equal(
			GuardianStatus.OK
		);
		expect(
			guardian.submitRepairEvidence({
				recoveryId: ROOT.recoveryId,
				target: fixture.finalState,
				receipts: fixture.evidence,
				certificates: []
			}).status
		).to.equal(GuardianStatus.OK);
		guardian.close();

		const laterAlarms: IGuardianAlarm[] = [];
		const again = reopen(fixture.file, laterAlarms);
		expect(laterAlarms.length).to.equal(0);
		expect(again.getHead(headRequest()).possiblyStale).to.equal(false);
		again.close();
	});

	it('a same-width TEXT writer signature is contained and swept', () => {
		const fixture = shapeFixture('text-writer-sig.sqlite');
		corrupt(
			fixture.file,
			'UPDATE guardian_records SET writer_signature = ? WHERE sequence = ?',
			'x'.repeat(64),
			u64be(2n)
		);
		const guardian = reopen(fixture.file);
		const head = guardian.getHead(headRequest());
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).logHead.sequence).to.equal(1n);
		guardian.close();
		const laterAlarms: IGuardianAlarm[] = [];
		const again = reopen(fixture.file, laterAlarms);
		expect(laterAlarms.length).to.equal(0);
		again.close();
	});

	it('a same-width TEXT certificate issuedAt is contained and swept', () => {
		const { file } = takeoverFixture('text-cert-issued-at.sqlite');
		corrupt(
			file,
			'UPDATE guardian_epochs SET cert_issued_at = ? WHERE epoch = ?',
			'12345678',
			u64be(2n)
		);
		const guardian = reopen(file);
		const head = guardian.getHead(headRequest());
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).lease.epoch).to.equal(1n);
		expect((head.state as GuardianState).logHead.sequence).to.equal(2n);
		guardian.close();
		const laterAlarms: IGuardianAlarm[] = [];
		const again = reopen(file, laterAlarms);
		expect(laterAlarms.length).to.equal(0);
		again.close();
	});

	it('a same-width TEXT cumulative-receipt issuedAt repairs instead of quarantining', () => {
		const fixture = shapeFixture('text-receipt-issued-at.sqlite');
		corrupt(
			fixture.file,
			'UPDATE guardian_namespaces SET receipt_issued_at = ?',
			'12345678'
		);
		const guardian = reopen(fixture.file);
		const head = guardian.getHead(headRequest());
		// Before the storage-class fix this THREW inside the verifier and the
		// namespace landed in quarantine; the intended path is the ordinary
		// rollback with a fresh verifying receipt over the intact chain.
		expect(head.status).to.equal(GuardianStatus.OK);
		expect(head.possiblyStale).to.equal(true);
		expect((head.state as GuardianState).logHead.sequence).to.equal(4n);
		expectValidReceipt(head.receipt, 0, fixture.finalState);
		guardian.close();
		const laterAlarms: IGuardianAlarm[] = [];
		const again = reopen(fixture.file, laterAlarms);
		expect(laterAlarms.length).to.equal(0);
		again.close();
	});

	it('a same-width TEXT registration-receipt issuedAt is replaced, once', () => {
		const fixture = shapeFixture('text-reg-receipt.sqlite');
		corrupt(
			fixture.file,
			'UPDATE guardian_namespaces SET registration_receipt_issued_at = ?',
			'12345678'
		);
		const alarms: IGuardianAlarm[] = [];
		const guardian = reopen(fixture.file, alarms);
		expect(
			alarms.some((a) => a.detail.includes('registration receipt'))
		).to.equal(true);
		expect(guardian.getHead(headRequest()).possiblyStale).to.equal(true);
		const replay = guardian.register(fixture.registration);
		expect(replay.status).to.equal(GuardianStatus.OK_DUPLICATE);
		expectValidReceipt(replay.receipt, 0, fixture.registration.initialState);
		guardian.close();
		const laterAlarms: IGuardianAlarm[] = [];
		const again = reopen(fixture.file, laterAlarms);
		expect(laterAlarms.length).to.equal(0);
		again.close();
	});

	it('a foreign guardian_set_id quarantines one namespace, untouched, while others serve', () => {
		const file = path.join(dir, 'set-id-quarantine.sqlite');
		const guardian = makeGuardian(0, file);
		const registration = buildRegistration();
		guardian.register(registration);
		const chain = buildChain(registration.initialState, 2);
		for (const record of chain) guardian.putState({ record });

		// A second, independent namespace in the same store.
		const root2 = deriveRecoveryRoot(sha('core-node-secret-2'));
		const state2: GuardianState = {
			recoveryId: root2.recoveryId,
			lease: { epoch: 1n, writerPublicKey: WRITER_1.pub },
			origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
			logHead: genesisLogHead()
		};
		const registration2: IGuardianRegisterNodeRequest = {
			protocolVersion: 1,
			guardianSetId: SET_ID,
			initialState: state2,
			rootSignature: signTranscript(
				registerTranscriptHash(SET_ID, state2),
				root2.rootSecret
			)
		};
		expect(guardian.register(registration2).status).to.equal(GuardianStatus.OK);
		guardian.close();

		corrupt(
			file,
			'UPDATE guardian_namespaces SET guardian_set_id = ? WHERE recovery_id = ?',
			sha('a-different-set'),
			ROOT.recoveryId
		);

		// The guardian STARTS; the damaged namespace is quarantined without a
		// single row modified; the healthy one keeps serving.
		const alarms: IGuardianAlarm[] = [];
		const reopened = reopen(file, alarms);
		expect(alarms.some((a) => a.detail.includes('quarantined'))).to.equal(true);
		expect(reopened.getHead(headRequest()).status).to.equal(
			GuardianStatus.ERR_STORE_UNCERTAIN
		);
		expect(reopened.putState({ record: chain[0] }).status).to.equal(
			GuardianStatus.ERR_STORE_UNCERTAIN
		);
		expect(reopened.register(registration).status).to.equal(
			GuardianStatus.ERR_STORE_UNCERTAIN
		);
		const healthy = reopened.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: root2.recoveryId
		});
		expect(healthy.status).to.equal(GuardianStatus.OK);
		expect(healthy.possiblyStale).to.equal(false);
		reopened.close();

		// Quarantine is non-destructive: every row of the damaged namespace
		// is still on disk, byte for byte.
		const raw = new Database(file);
		const count = raw
			.prepare(
				'SELECT COUNT(*) AS n FROM guardian_records WHERE recovery_id = ?'
			)
			.get(ROOT.recoveryId) as { n: number };
		raw.close();
		expect(count.n).to.equal(2);
	});
});

describe('Guardian core: INFO', () => {
	it('advertises identity, versions, sets and limits', () => {
		const guardian = makeGuardian(1);
		const info = guardian.info();
		expect(info.guardianId.equals(GUARDIAN_IDS[1])).to.equal(true);
		expect(info.minProtocolVersion).to.equal(1);
		expect(info.maxProtocolVersion).to.equal(1);
		expect(info.guardianSetIds.length).to.equal(1);
		expect(info.guardianSetIds[0].equals(SET_ID)).to.equal(true);
		expect(info.maxCiphertextBytes).to.equal(16 * 1024 * 1024);
		expect(info.maxRecordsPerGet).to.equal(256);
		guardian.close();
	});
});
