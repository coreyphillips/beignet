/**
 * Guardian wire crypto (docs/RECOVERY-GUARDIAN-WIRE.md sections 1, 3, 4):
 * recovery root derivation, guardian_set_id, canonical transcripts under
 * per-object domain tags, BIP340 sign/verify round trips, and the
 * deterministic frame IV. Includes the frozen test vectors the wire spec
 * promises with the reference implementation: any change to a transcript
 * layout, tag, or derivation breaks a vector here LOUDLY.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianState,
	acquireTranscriptHash,
	computeGuardianSetId,
	deriveFrameIv,
	deriveRecoveryRoot,
	genesisLogHead,
	isGenesisLogHead,
	receiptTranscriptHash,
	recordTranscriptHash,
	registerTranscriptHash,
	signTranscript,
	stateBytes,
	statesEqual,
	takeoverTranscriptHash,
	verifyTranscript,
	xOnlyFromSecret
} from '../../src/lightning/recovery/guardian-wire';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const NODE_SECRET = sha('guardian-wire-vector-node-secret');
const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const WRITER_SECRET = sha('writer-1');

function vectorState(): GuardianState {
	const { recoveryId } = deriveRecoveryRoot(NODE_SECRET);
	return {
		recoveryId,
		lease: { epoch: 1n, writerPublicKey: xOnlyFromSecret(WRITER_SECRET) },
		origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
		logHead: genesisLogHead()
	};
}

describe('Guardian wire: recovery root', () => {
	it('derives the frozen vector and a valid namespace key', () => {
		const root = deriveRecoveryRoot(NODE_SECRET);
		expect(root.rootSecret.toString('hex')).to.equal(
			'0a25a33707fbf2d91d0ef328d6179c0f9da4fc07e7be6620948afb0a1e106594'
		);
		expect(root.recoveryId.toString('hex')).to.equal(
			'239fe687f2c5df905bed2e81efec0b8e7497dd0299b71f0a77daf9a2dfa830d1'
		);
		// Deterministic, and NOT the node identity key or its x-only form.
		expect(
			deriveRecoveryRoot(NODE_SECRET).recoveryId.equals(root.recoveryId)
		).to.equal(true);
		expect(root.rootSecret.equals(NODE_SECRET)).to.equal(false);
		expect(root.recoveryId.equals(xOnlyFromSecret(NODE_SECRET))).to.equal(
			false
		);
	});
});

describe('Guardian wire: guardian_set_id', () => {
	it('commits to the sorted set and matches the frozen vector', () => {
		const setId = computeGuardianSetId({
			...CRASH_V1_PROFILE,
			guardianIds: GUARDIAN_IDS
		});
		expect(setId.toString('hex')).to.equal(
			'e771903e2260a92d9336d4ab420c050562e927da1e7dd57ff1900907dfe7c06c'
		);
		// Member ORDER must not matter: the transcript sorts.
		const shuffled = computeGuardianSetId({
			...CRASH_V1_PROFILE,
			guardianIds: [GUARDIAN_IDS[2], GUARDIAN_IDS[0], GUARDIAN_IDS[1]]
		});
		expect(shuffled.equals(setId)).to.equal(true);
	});

	it('rejects every profile except crash-v1, and duplicate members', () => {
		expect(() =>
			computeGuardianSetId({
				profileId: 1,
				required: 3,
				total: 4,
				guardianIds: [...GUARDIAN_IDS, xOnlyFromSecret(sha('guardian-4'))]
			})
		).to.throw(/only crash-v1/);
		expect(() =>
			computeGuardianSetId({
				...CRASH_V1_PROFILE,
				guardianIds: [GUARDIAN_IDS[0], GUARDIAN_IDS[0], GUARDIAN_IDS[1]]
			})
		).to.throw(/distinct/);
	});
});

describe('Guardian wire: canonical transcripts', () => {
	const setId = computeGuardianSetId({
		...CRASH_V1_PROFILE,
		guardianIds: GUARDIAN_IDS
	});

	it('STATE is 192 fixed bytes and the register hash matches the vector', () => {
		const state = vectorState();
		expect(stateBytes(state).length).to.equal(192);
		expect(registerTranscriptHash(setId, state).toString('hex')).to.equal(
			'725f51f409c91d9c7e959d5533d4b43117dcf3bcc59b9bba981bb60245f316c7'
		);
		expect(statesEqual(state, vectorState())).to.equal(true);
		expect(isGenesisLogHead(state.logHead)).to.equal(true);
	});

	it('every signed object round-trips and rejects tampering', () => {
		const state = vectorState();
		const { rootSecret, recoveryId } = deriveRecoveryRoot(NODE_SECRET);

		// REGISTER: root signs; the root key IS the namespace.
		const regHash = registerTranscriptHash(setId, state);
		const regSig = signTranscript(regHash, rootSecret);
		expect(verifyTranscript(regHash, regSig, recoveryId)).to.equal(true);

		// RECORD: the writer signs; any field change breaks the signature.
		const record = {
			recoveryId,
			epoch: 1n,
			sequence: 1n,
			previousHash: Buffer.alloc(32),
			frameHash: Buffer.alloc(32, 0xab),
			ciphertextHash: sha('ciphertext')
		};
		const recHash = recordTranscriptHash(setId, record);
		const recSig = signTranscript(recHash, WRITER_SECRET);
		expect(
			verifyTranscript(recHash, recSig, xOnlyFromSecret(WRITER_SECRET))
		).to.equal(true);
		const tampered = recordTranscriptHash(setId, {
			...record,
			sequence: 2n
		});
		expect(
			verifyTranscript(tampered, recSig, xOnlyFromSecret(WRITER_SECRET))
		).to.equal(false);

		// RECEIPT and TAKEOVER: guardians sign the COMPLETE state.
		const receiptHash = receiptTranscriptHash(
			setId,
			GUARDIAN_IDS[0],
			state,
			1_700_000_000_000n
		);
		const receiptSig = signTranscript(receiptHash, GUARDIAN_SECRETS[0]);
		expect(verifyTranscript(receiptHash, receiptSig, GUARDIAN_IDS[0])).to.equal(
			true
		);
		// A different guardian's key must not verify the same receipt.
		expect(verifyTranscript(receiptHash, receiptSig, GUARDIAN_IDS[1])).to.equal(
			false
		);

		const newWriter = xOnlyFromSecret(sha('writer-2'));
		const acqHash = acquireTranscriptHash(setId, state, 2n, newWriter);
		const rootAcqSig = signTranscript(acqHash, rootSecret);
		const writerAcqSig = signTranscript(acqHash, sha('writer-2'));
		expect(verifyTranscript(acqHash, rootAcqSig, recoveryId)).to.equal(true);
		expect(verifyTranscript(acqHash, writerAcqSig, newWriter)).to.equal(true);

		const takeHash = takeoverTranscriptHash(
			setId,
			GUARDIAN_IDS[1],
			state,
			2n,
			newWriter,
			1_700_000_000_001n
		);
		const takeSig = signTranscript(takeHash, GUARDIAN_SECRETS[1]);
		expect(verifyTranscript(takeHash, takeSig, GUARDIAN_IDS[1])).to.equal(true);

		// Domain separation: identical field bytes under different tags never
		// collide, so a receipt can never be replayed as a takeover.
		expect(receiptHash.equals(takeHash)).to.equal(false);
	});
});

describe('Guardian wire: deterministic frame IV', () => {
	it('matches the frozen vector, is 12 bytes, and shifts with every input', () => {
		const { recoveryId } = deriveRecoveryRoot(NODE_SECRET);
		const frameHash = Buffer.alloc(32, 0xab);
		const iv = deriveFrameIv(recoveryId, 1n, 7n, frameHash);
		expect(iv.length).to.equal(12);
		expect(iv.toString('hex')).to.equal('af8890d22236a295fb1f1b1e');
		// Deterministic; distinct on any input change (distinct plaintext at
		// the same position means a distinct frameHash, hence a distinct IV).
		expect(deriveFrameIv(recoveryId, 1n, 7n, frameHash).equals(iv)).to.equal(
			true
		);
		expect(deriveFrameIv(recoveryId, 2n, 7n, frameHash).equals(iv)).to.equal(
			false
		);
		expect(deriveFrameIv(recoveryId, 1n, 8n, frameHash).equals(iv)).to.equal(
			false
		);
		expect(
			deriveFrameIv(recoveryId, 1n, 7n, Buffer.alloc(32, 0xac)).equals(iv)
		).to.equal(false);
		// And it is NOT derivable from a Lightning node id: recovery_id keys it.
		expect(
			deriveFrameIv(xOnlyFromSecret(NODE_SECRET), 1n, 7n, frameHash).equals(iv)
		).to.equal(false);
	});
});
