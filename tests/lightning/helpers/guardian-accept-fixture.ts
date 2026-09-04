/**
 * Shared fixture for the guardian acceptance tests
 * (recovery-guardian-acceptance.test.ts) and the crash child process they
 * spawn (guardian-crash-child.ts). Parent and child must build the
 * IDENTICAL deterministic record chain, byte for byte, so it lives in one
 * module: the parent's post-crash assertions compare the survivors against
 * exactly what the child was appending.
 */

import crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianState,
	IGuardianRecord,
	IGuardianRegisterNodeRequest,
	computeGuardianSetId,
	deriveRecoveryRoot,
	genesisLogHead,
	recordTranscriptHash,
	registerTranscriptHash,
	signTranscript,
	xOnlyFromSecret
} from '../../../src/lightning/recovery';

export const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();
const sha256buf = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

export interface ITestWriter {
	secret: Buffer;
	pub: Buffer;
}

export function makeTestWriter(name: string): ITestWriter {
	const secret = sha(name);
	return { secret, pub: xOnlyFromSecret(secret) };
}

export const ACCEPT_GUARDIAN_SECRETS = [1, 2, 3].map((i) =>
	sha(`accept-guardian-${i}`)
);
export const ACCEPT_GUARDIAN_IDS = ACCEPT_GUARDIAN_SECRETS.map((s) =>
	xOnlyFromSecret(s)
);
export const ACCEPT_SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: ACCEPT_GUARDIAN_IDS
});
export const ACCEPT_NODE_SECRET = sha('accept-node-secret');
export const ACCEPT_ROOT = deriveRecoveryRoot(ACCEPT_NODE_SECRET);
export const ACCEPT_WRITER = makeTestWriter('accept-writer-1');

/** Records in the crash chain; the child appends them all unless killed. */
export const ACCEPT_CHAIN_LENGTH = 40;
/** Large enough that every commit spends real time inside its fsync. */
export const ACCEPT_CIPHERTEXT_BYTES = 96 * 1024;

export function buildRegistrationFor(
	root: { rootSecret: Buffer; recoveryId: Buffer },
	setId: Buffer,
	writerPub: Buffer,
	origin?: { firstSequence: bigint; previousHash: Buffer },
	members: Buffer[] = ACCEPT_GUARDIAN_IDS
): IGuardianRegisterNodeRequest {
	const initialState: GuardianState = {
		recoveryId: root.recoveryId,
		lease: { epoch: 1n, writerPublicKey: writerPub },
		origin: origin ?? { firstSequence: 1n, previousHash: Buffer.alloc(32) },
		logHead: genesisLogHead()
	};
	return {
		protocolVersion: 1,
		guardianSetId: setId,
		guardianMembers: members,
		initialState,
		rootSignature: signTranscript(
			registerTranscriptHash(setId, initialState),
			root.rootSecret
		)
	};
}

export function signRecordFor(
	setId: Buffer,
	recoveryId: Buffer,
	writerSecret: Buffer,
	fields: {
		epoch: bigint;
		sequence: bigint;
		previousHash: Buffer;
		frameHash: Buffer;
		ciphertext: Buffer;
	}
): IGuardianRecord {
	const signature = signTranscript(
		recordTranscriptHash(setId, {
			recoveryId,
			epoch: fields.epoch,
			sequence: fields.sequence,
			previousHash: fields.previousHash,
			frameHash: fields.frameHash,
			ciphertextHash: sha256buf(fields.ciphertext)
		}),
		writerSecret
	);
	return {
		protocolVersion: 1,
		guardianSetId: setId,
		recoveryId,
		epoch: fields.epoch,
		sequence: fields.sequence,
		previousHash: fields.previousHash,
		frameHash: fields.frameHash,
		ciphertext: fields.ciphertext,
		writerSignature: signature
	};
}

/** The deterministic crash chain: parent and child derive identical bytes. */
export function acceptChain(count = ACCEPT_CHAIN_LENGTH): IGuardianRecord[] {
	const records: IGuardianRecord[] = [];
	let previousHash = Buffer.alloc(32);
	for (let i = 0; i < count; i++) {
		const sequence = BigInt(i + 1);
		const ciphertext = Buffer.concat([
			sha(`accept-ct-${sequence}`),
			Buffer.alloc(ACCEPT_CIPHERTEXT_BYTES, Number(sequence % 251n) + 1)
		]);
		const frameHash = sha(`accept-frame-${sequence}`);
		records.push(
			signRecordFor(
				ACCEPT_SET_ID,
				ACCEPT_ROOT.recoveryId,
				ACCEPT_WRITER.secret,
				{
					epoch: 1n,
					sequence,
					previousHash,
					frameHash,
					ciphertext
				}
			)
		);
		previousHash = frameHash;
	}
	return records;
}

export function acceptRegistration(): IGuardianRegisterNodeRequest {
	return buildRegistrationFor(ACCEPT_ROOT, ACCEPT_SET_ID, ACCEPT_WRITER.pub);
}
