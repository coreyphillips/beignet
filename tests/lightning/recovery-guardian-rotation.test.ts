/**
 * Guardian-set rotation on the guardian side (wire 5.9, 5.11, issue #701):
 * the generation inside REGISTER, ROTATE_SET retiring a namespace under the
 * outgoing set, the retired gate on every write, reads staying open with
 * the rotation attached, and the idempotency and ordering rules.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianState,
	GuardianStatus,
	IGuardianRecord,
	IGuardianRegisterNodeRequest,
	IGuardianRotateSetRequest,
	ReferenceGuardian,
	computeGuardianSetId,
	decodeRotateSetRequest,
	deriveRecoveryRoot,
	encodeRotateSetRequest,
	genesisLogHead,
	recordTranscriptHash,
	registerTranscriptHash,
	rotateTranscriptHash,
	signTranscript,
	xOnlyFromSecret
} from '../../src/lightning/recovery';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();
const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

const SECRETS = [1, 2, 3, 4].map((i) => sha(`rotation-guardian-${i}`));
const IDS = SECRETS.map((s) => xOnlyFromSecret(s));
/** The outgoing set: guardians 1, 2, 3. The incoming set: 2, 3, 4. */
const OLD_MEMBERS = [IDS[0], IDS[1], IDS[2]];
const NEW_MEMBERS = [IDS[1], IDS[2], IDS[3]];
const OLD_SET = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: OLD_MEMBERS
});
const NEW_SET = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: NEW_MEMBERS
});
const ROOT = deriveRecoveryRoot(sha('rotation-node-secret'));
const OTHER_ROOT = deriveRecoveryRoot(sha('rotation-other-node'));
const WRITER = {
	secret: sha('rotation-writer'),
	pub: xOnlyFromSecret(sha('rotation-writer'))
};

let now = 1_800_000_000_000n;
const clock = (): bigint => ++now;

function guardianFor(index: number, members: Buffer[]): ReferenceGuardian {
	return new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: SECRETS[index],
		members,
		clock
	});
}

function registration(
	setId: Buffer,
	members: Buffer[],
	generation: bigint,
	root = ROOT
): IGuardianRegisterNodeRequest {
	const initialState: GuardianState = {
		recoveryId: root.recoveryId,
		lease: { epoch: 3n, writerPublicKey: WRITER.pub },
		origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
		logHead: genesisLogHead()
	};
	return {
		protocolVersion: 1,
		guardianSetId: setId,
		guardianMembers: members,
		initialState,
		rootSignature: signTranscript(
			registerTranscriptHash(setId, initialState, generation),
			root.rootSecret
		),
		generation
	};
}

function record(
	setId: Buffer,
	sequence: bigint,
	previousHash: Buffer
): IGuardianRecord {
	const ciphertext = sha(`ct-${setId.toString('hex').slice(0, 8)}-${sequence}`);
	const frameHash = sha(`fh-${sequence}`);
	return {
		protocolVersion: 1,
		guardianSetId: setId,
		recoveryId: ROOT.recoveryId,
		epoch: 3n,
		sequence,
		previousHash,
		frameHash,
		ciphertext,
		writerSignature: signTranscript(
			recordTranscriptHash(setId, {
				recoveryId: ROOT.recoveryId,
				epoch: 3n,
				sequence,
				previousHash,
				frameHash,
				ciphertextHash: sha256(ciphertext)
			}),
			WRITER.secret
		)
	};
}

function rotation(
	overrides: Partial<IGuardianRotateSetRequest> = {},
	root = ROOT
): IGuardianRotateSetRequest {
	const fields = {
		recoveryId: root.recoveryId,
		newGuardianSetId: NEW_SET,
		generation: 2n,
		newMembers: NEW_MEMBERS,
		...overrides
	};
	return {
		protocolVersion: 1,
		guardianSetId: OLD_SET,
		recoveryId: fields.recoveryId,
		newGuardianSetId: fields.newGuardianSetId,
		generation: fields.generation,
		newMembers: fields.newMembers,
		rootSignature: signTranscript(
			rotateTranscriptHash(OLD_SET, {
				recoveryId: fields.recoveryId,
				newGuardianSetId: fields.newGuardianSetId,
				generation: fields.generation,
				newMembers: fields.newMembers
			}),
			root.rootSecret
		),
		newTransports: [
			{ type: 'bolt8', url: 'bolt8://02aa@b.example:9735' },
			{ type: 'bolt8', url: 'bolt8://02bb@c.example:9735' },
			{ type: 'https', url: 'https://d.example' }
		],
		...overrides
	};
}

describe('guardian rotation: REGISTER carries the generation', () => {
	it('stores it, echoes it on GET_HEAD, and refuses zero', () => {
		const g = guardianFor(0, OLD_MEMBERS);
		try {
			expect(
				g.register(registration(OLD_SET, OLD_MEMBERS, 0n)).status
			).to.equal(GuardianStatus.ERR_MALFORMED);
			expect(
				g.register(registration(OLD_SET, OLD_MEMBERS, 5n)).status
			).to.equal(GuardianStatus.OK);
			const head = g.getHead({
				protocolVersion: 1,
				guardianSetId: OLD_SET,
				recoveryId: ROOT.recoveryId
			});
			expect(head.status).to.equal(GuardianStatus.OK);
			expect(head.generation).to.equal(5n);
			expect(head.registration!.generation).to.equal(5n);
			expect(head.rotation).to.equal(undefined);
			// The generation is inside the transcript: the same state at another
			// generation is a DIFFERENT registration, not a duplicate.
			expect(
				g.register(registration(OLD_SET, OLD_MEMBERS, 5n)).status
			).to.equal(GuardianStatus.OK_DUPLICATE);
			expect(
				g.register(registration(OLD_SET, OLD_MEMBERS, 6n)).status
			).to.equal(GuardianStatus.ERR_ALREADY_REGISTERED);
		} finally {
			g.close();
		}
	});
});

describe('guardian rotation: ROTATE_SET on the outgoing set', () => {
	let g: ReferenceGuardian;

	beforeEach(() => {
		g = guardianFor(1, OLD_MEMBERS);
		expect(g.register(registration(OLD_SET, OLD_MEMBERS, 1n)).status).to.equal(
			GuardianStatus.OK
		);
		const first = record(OLD_SET, 1n, Buffer.alloc(32));
		expect(g.putState({ record: first }).status).to.equal(GuardianStatus.OK);
	});

	afterEach(() => g.close());

	it('retires the namespace: writes refuse, reads keep answering with the rotation attached', () => {
		const request = rotation();
		const answer = g.rotateSet(request);
		expect(answer.status, answer.detail).to.equal(GuardianStatus.OK);
		expect(answer.rotation!.generation).to.equal(2n);

		const head = g.getHead({
			protocolVersion: 1,
			guardianSetId: OLD_SET,
			recoveryId: ROOT.recoveryId
		});
		expect(head.status).to.equal(GuardianStatus.OK);
		expect(head.state!.logHead.sequence).to.equal(1n);
		expect(head.generation).to.equal(1n);
		expect(head.rotation!.newGuardianSetId.equals(NEW_SET)).to.equal(true);
		expect(
			head.rotation!.newMembers.map((m) => m.toString('hex'))
		).to.deep.equal(NEW_MEMBERS.map((m) => m.toString('hex')));
		expect(head.rotation!.newTransports).to.deep.equal(request.newTransports);
		expect(head.rotation!.rootSignature.equals(request.rootSignature)).to.equal(
			true
		);

		const state = g.getState({
			protocolVersion: 1,
			guardianSetId: OLD_SET,
			recoveryId: ROOT.recoveryId,
			fromSequence: 0n,
			maxRecords: 10
		});
		expect(state.status).to.equal(GuardianStatus.OK);
		expect(state.records).to.have.length(1);

		const put = g.putState({ record: record(OLD_SET, 2n, sha('fh-1')) });
		expect(put.status).to.equal(GuardianStatus.ERR_SET_RETIRED);
		const sync = g.syncRecord({ record: record(OLD_SET, 2n, sha('fh-1')) });
		expect(sync.status).to.equal(GuardianStatus.ERR_SET_RETIRED);
		expect(
			g.syncEpoch({ certificates: [] }).status,
			'an empty sync is malformed before it is retired; the gate sits behind shape checks'
		).to.not.equal(GuardianStatus.OK);
	});

	it('is idempotent for the same object, a conflict at the same generation, a regression below', () => {
		const request = rotation();
		expect(g.rotateSet(request).status).to.equal(GuardianStatus.OK);
		expect(g.rotateSet(request).status).to.equal(GuardianStatus.OK_DUPLICATE);
		const other = rotation({
			newMembers: [IDS[0], IDS[1], IDS[3]],
			newGuardianSetId: computeGuardianSetId({
				...CRASH_V1_PROFILE,
				guardianIds: [IDS[0], IDS[1], IDS[3]]
			})
		});
		const conflict = g.rotateSet(other);
		expect(conflict.status).to.equal(GuardianStatus.ERR_CONFLICT);
		expect(conflict.rotation!.newGuardianSetId.equals(NEW_SET)).to.equal(true);
		const lower = g.rotateSet(rotation({ generation: 1n }));
		expect(lower.status).to.equal(GuardianStatus.ERR_EPOCH_REGRESSION);
		// A later rotation (generation 3) over the stored one is accepted: the
		// namespace moved on again from wherever it went.
		const later = rotation({ generation: 3n });
		expect(g.rotateSet(later).status).to.equal(GuardianStatus.OK);
		const head = g.getHead({
			protocolVersion: 1,
			guardianSetId: OLD_SET,
			recoveryId: ROOT.recoveryId
		});
		expect(head.rotation!.generation).to.equal(3n);
	});

	it('refuses a rotation that is malformed, unsigned by the root, not above the generation, or for a stranger', () => {
		expect(g.rotateSet(rotation({ generation: 1n })).status).to.equal(
			GuardianStatus.ERR_EPOCH_REGRESSION
		);
		expect(
			g.rotateSet(rotation({ newMembers: NEW_MEMBERS.slice(0, 2) })).status
		).to.equal(GuardianStatus.ERR_MALFORMED);
		expect(
			g.rotateSet(
				rotation({ newGuardianSetId: OLD_SET, newMembers: OLD_MEMBERS })
			).status
		).to.equal(GuardianStatus.ERR_MALFORMED);
		const mismatched = rotation();
		mismatched.newGuardianSetId = sha('not the hash of the members');
		expect(g.rotateSet(mismatched).status).to.equal(
			GuardianStatus.ERR_MALFORMED
		);
		const forged = rotation({}, OTHER_ROOT);
		forged.recoveryId = ROOT.recoveryId;
		expect(g.rotateSet(forged).status).to.equal(
			GuardianStatus.ERR_BAD_SIGNATURE
		);
		const stranger = rotation({}, OTHER_ROOT);
		expect(g.rotateSet(stranger).status).to.equal(
			GuardianStatus.ERR_UNKNOWN_NODE
		);
		const wrongSet = rotation();
		wrongSet.guardianSetId = NEW_SET;
		expect(g.rotateSet(wrongSet).status).to.equal(
			GuardianStatus.ERR_UNKNOWN_SET
		);
		// Nothing above retired the namespace.
		expect(
			g.putState({ record: record(OLD_SET, 2n, sha('fh-1')) }).status
		).to.equal(GuardianStatus.OK);
	});

	it('round-trips the rotation object through the protobuf envelope', () => {
		const request = rotation();
		const back = decodeRotateSetRequest(encodeRotateSetRequest(request));
		expect(back.generation).to.equal(2n);
		expect(back.newMembers.map((m) => m.toString('hex'))).to.deep.equal(
			NEW_MEMBERS.map((m) => m.toString('hex'))
		);
		expect(back.newTransports).to.deep.equal(request.newTransports);
		expect(back.rootSignature.equals(request.rootSignature)).to.equal(true);
		expect(g.rotateSet(back).status).to.equal(GuardianStatus.OK);
	});
});

describe('guardian rotation: a carried-over guardian serves both sets side by side', () => {
	it('registers the incoming set at generation 2 with the current lease while the outgoing namespace is retired', () => {
		// Guardian 2 is in both sets: two ReferenceGuardian instances, one per set,
		// exactly as the host keeps one store per set.
		const outgoing = guardianFor(1, OLD_MEMBERS);
		const incoming = guardianFor(1, NEW_MEMBERS);
		try {
			expect(
				outgoing.register(registration(OLD_SET, OLD_MEMBERS, 1n)).status
			).to.equal(GuardianStatus.OK);
			expect(
				outgoing.putState({ record: record(OLD_SET, 1n, Buffer.alloc(32)) })
					.status
			).to.equal(GuardianStatus.OK);
			// The incoming set: same lease (epoch 3, same writer key), generation 2.
			expect(
				incoming.register(registration(NEW_SET, NEW_MEMBERS, 2n)).status
			).to.equal(GuardianStatus.OK);
			// Records re-signed under the incoming prefix, same sequence numbering.
			expect(
				incoming.putState({ record: record(NEW_SET, 1n, Buffer.alloc(32)) })
					.status
			).to.equal(GuardianStatus.OK);
			expect(outgoing.rotateSet(rotation()).status).to.equal(GuardianStatus.OK);
			expect(
				outgoing.putState({ record: record(OLD_SET, 2n, sha('fh-1')) }).status
			).to.equal(GuardianStatus.ERR_SET_RETIRED);
			expect(
				incoming.putState({ record: record(NEW_SET, 2n, sha('fh-1')) }).status
			).to.equal(GuardianStatus.OK);
			const head = incoming.getHead({
				protocolVersion: 1,
				guardianSetId: NEW_SET,
				recoveryId: ROOT.recoveryId
			});
			expect(head.generation).to.equal(2n);
			expect(head.state!.logHead.sequence).to.equal(2n);
			expect(head.rotation).to.equal(undefined);
			// A record signed under the OUTGOING prefix never validates under the incoming set.
			expect(
				incoming.putState({ record: record(OLD_SET, 3n, sha('fh-2')) }).status
			).to.not.equal(GuardianStatus.OK);
		} finally {
			outgoing.close();
			incoming.close();
		}
	});
});
