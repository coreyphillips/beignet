/**
 * Async receive service internals (issue #709): the registration request,
 * grant and reply codecs with their signature and tamper detection, and the
 * LSP-side service class judged in isolation (two receivers, an injected
 * clock, a memory ledger) for the limits a three-node world cannot reach:
 * global count, value and bytes across receivers, the receiver ceiling,
 * fee insufficiency, credit accounting, supersession and expiry.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature } from '../../src/lightning/features/flags';
import { MemoryLedgerStore } from '../../src/lightning/storage/durable-ledger';
import {
	HeldForwardLedger,
	IHeldForwardRecord
} from '../../src/lightning/async-payments/held-forward-ledger';
import {
	AsyncReceiveService,
	IAdmissionCandidate,
	IAsyncRegistrationRecord
} from '../../src/lightning/async-payments/service';
import {
	IReceiverGrant,
	REGISTRATION_REQUEST_VERSION,
	decodeReceiverGrant,
	decodeRegistrationReply,
	decodeRegistrationRequest,
	encodeReceiverGrant,
	encodeRegistrationReply,
	encodeRegistrationRequest,
	holdingFeeForWindowMsat,
	signReceiverGrant,
	verifyReceiverGrant
} from '../../src/lightning/async-payments/receiver-grant';
import { IAsyncReceiveServiceConfig } from '../../src/lightning/async-payments/types';

const CHAIN = crypto.createHash('sha256').update('chain').digest();
const LSP_KEY = crypto.createHash('sha256').update('lsp').digest();
const LSP_ID = getPublicKey(LSP_KEY);
const CAROL_KEY = crypto.createHash('sha256').update('carol').digest();
const CAROL_ID = getPublicKey(CAROL_KEY);
const DAVE_KEY = crypto.createHash('sha256').update('dave').digest();
const DAVE_ID = getPublicKey(DAVE_KEY);
const SCID_CAROL = Buffer.from('0000340000010000', 'hex');
const SCID_DAVE = Buffer.from('0000340000020000', 'hex');

function sampleGrant(
	overrides: Partial<Parameters<typeof signReceiverGrant>[0]> = {},
	key: Buffer = LSP_KEY
): IReceiverGrant {
	return signReceiverGrant(
		{
			featureBit: Feature.ASYNC_RECEIVE_SERVICE + 1,
			serviceFlags: 0,
			chainHash: CHAIN,
			receiverNodeId: CAROL_ID,
			lspNodeId: LSP_ID,
			registrationId: crypto.randomBytes(32),
			scid: SCID_CAROL,
			maxPartMsat: 1_000_000n,
			maxPaymentMsat: 2_000_000n,
			maxParts: 3,
			maxHeldMsat: 3_000_000n,
			maxHoldBlocks: 144,
			minRemainingCltv: 6,
			admissionFeeMsat: 100n,
			holdingFeeMsatPerBlock: 2n,
			feeCollection: 1,
			creditMsat: 500n,
			issuedAt: 1_700_000_000n,
			expiresAt: 1_700_003_600n,
			nonce: crypto.randomBytes(32),
			witnessProfile: Buffer.alloc(32),
			...overrides
		},
		key
	);
}

describe('Async receive grant codecs (issue #709)', () => {
	it('round-trips a registration request and refuses the wrong length', () => {
		const req = {
			version: REGISTRATION_REQUEST_VERSION,
			chainHash: CHAIN,
			receiverNodeId: CAROL_ID,
			lspNodeId: LSP_ID,
			scid: SCID_CAROL,
			requestedHoldBlocks: 72,
			nonce: crypto.randomBytes(32)
		};
		const wire = encodeRegistrationRequest(req);
		expect(wire).to.have.length(1 + 32 + 33 + 33 + 8 + 2 + 32);
		const back = decodeRegistrationRequest(wire)!;
		expect(back.requestedHoldBlocks).to.equal(72);
		expect(back.receiverNodeId.equals(CAROL_ID)).to.equal(true);
		expect(back.nonce.equals(req.nonce)).to.equal(true);
		expect(decodeRegistrationRequest(wire.subarray(1))).to.equal(null);
		expect(
			decodeRegistrationRequest(Buffer.concat([wire, Buffer.alloc(1)]))
		).to.equal(null);
		const badVersion = Buffer.from(wire);
		badVersion[0] = 2;
		expect(decodeRegistrationRequest(badVersion)).to.equal(null);
	});

	it('round-trips a signed grant, verifies it, and detects every tampered byte', () => {
		const grant = sampleGrant();
		const wire = encodeReceiverGrant(grant);
		const back = decodeReceiverGrant(wire)!;
		expect(back).to.not.equal(null);
		expect(verifyReceiverGrant(back)).to.equal(true);
		expect(back.featureBit).to.equal(261);
		expect(back.maxPartMsat).to.equal(1_000_000n);
		expect(back.maxParts).to.equal(3);
		expect(back.admissionFeeMsat).to.equal(100n);
		expect(back.holdingFeeMsatPerBlock).to.equal(2n);
		expect(back.creditMsat).to.equal(500n);
		expect(back.expiresAt).to.equal(1_700_003_600n);
		expect(back.scid.equals(SCID_CAROL)).to.equal(true);
		expect(holdingFeeForWindowMsat(back)).to.equal(288n);
		// Every byte of the body is under the signature.
		const bodyLen = wire.length - 64;
		for (let i = 0; i < bodyLen; i++) {
			const tampered = Buffer.from(wire);
			tampered[i] ^= 0x01;
			const decoded = decodeReceiverGrant(tampered);
			if (i === 0) {
				expect(decoded, 'version byte').to.equal(null);
				continue;
			}
			expect(verifyReceiverGrant(decoded!), `byte ${i}`).to.equal(false);
		}
		// The wrong key does not verify against the named LSP.
		expect(verifyReceiverGrant(sampleGrant({}, CAROL_KEY))).to.equal(false);
		// Length is exact.
		expect(decodeReceiverGrant(wire.subarray(0, wire.length - 1))).to.equal(
			null
		);
	});

	it('round-trips both reply shapes', () => {
		const grant = sampleGrant();
		const granted = decodeRegistrationReply(
			encodeRegistrationReply({ granted: true, grant })
		)!;
		expect(granted.granted).to.equal(true);
		if (granted.granted) {
			expect(
				granted.grant.registrationId.equals(grant.registrationId)
			).to.equal(true);
			expect(verifyReceiverGrant(granted.grant)).to.equal(true);
		}
		const nonce = crypto.randomBytes(32);
		const refused = decodeRegistrationReply(
			encodeRegistrationReply({ granted: false, nonce, reason: 'no_channel' })
		)!;
		expect(refused.granted).to.equal(false);
		if (!refused.granted) {
			expect(refused.nonce.equals(nonce)).to.equal(true);
			expect(refused.reason).to.equal('no_channel');
		}
		expect(decodeRegistrationReply(Buffer.alloc(0))).to.equal(null);
		expect(decodeRegistrationReply(Buffer.from([1, 2, 3]))).to.equal(null);
		expect(decodeRegistrationReply(Buffer.from([0, 1]))).to.equal(null);
	});
});

describe('AsyncReceiveService in isolation (issue #709)', () => {
	const H = 1366 + 1024;
	let clock: number;
	let height: number;
	let holds: HeldForwardLedger;
	let svc: AsyncReceiveService;

	function build(config: IAsyncReceiveServiceConfig): void {
		clock = 1_700_000_000_000;
		height = 1_000;
		holds = new HeldForwardLedger(new MemoryLedgerStore<IHeldForwardRecord>());
		holds.rehydrate();
		svc = new AsyncReceiveService(
			config,
			new MemoryLedgerStore<IAsyncRegistrationRecord>(),
			holds,
			{
				nodePrivkey: LSP_KEY,
				nodeId: LSP_ID,
				chainHash: CHAIN,
				currentHeight: () => height,
				now: () => clock,
				channelForScid: (scidHex) => {
					if (scidHex === SCID_CAROL.toString('hex')) {
						return {
							channelIdHex: 'c1',
							peerNodeIdHex: CAROL_ID.toString('hex')
						};
					}
					if (scidHex === SCID_DAVE.toString('hex')) {
						return {
							channelIdHex: 'd1',
							peerNodeIdHex: DAVE_ID.toString('hex')
						};
					}
					return null;
				}
			}
		);
	}

	function register(
		receiver: Buffer,
		scid: Buffer,
		nonce = crypto.randomBytes(32)
	): ReturnType<AsyncReceiveService['handleRegistrationRequest']> {
		return svc.handleRegistrationRequest(
			receiver.toString('hex'),
			encodeRegistrationRequest({
				version: REGISTRATION_REQUEST_VERSION,
				chainHash: CHAIN,
				receiverNodeId: receiver,
				lspNodeId: LSP_ID,
				scid,
				requestedHoldBlocks: 0,
				nonce
			})
		);
	}

	function grantOf(
		reply: ReturnType<AsyncReceiveService['handleRegistrationRequest']>
	): IReceiverGrant {
		if (!reply.granted) throw new Error(`refused: ${reply.reason}`);
		return reply.grant;
	}

	function candidate(
		grant: IReceiverGrant,
		over: Partial<IAdmissionCandidate> = {}
	): IAdmissionCandidate {
		const forward = over.forwardAmountMsat ?? 100_000n;
		const holding = holdingFeeForWindowMsat(grant);
		return {
			registrationIdHex: grant.registrationId.toString('hex'),
			receiverNodeIdHex: grant.receiverNodeId.toString('hex'),
			outgoingScidHex: grant.scid.toString('hex'),
			paymentHashHex: crypto.randomBytes(32).toString('hex'),
			incomingAmountMsat: forward + 1_000n + holding,
			forwardAmountMsat: forward,
			policyFeeMsat: 1_000n,
			proposedCutoffHeight: height + 100,
			heldBytes: H,
			...over
		};
	}

	/** Park a hold exactly as the node does after an `ok` verdict. */
	function park(
		grant: IReceiverGrant,
		over: Partial<IAdmissionCandidate> = {}
	) {
		const c = candidate(grant, over);
		const verdict = svc.admit(c);
		if (!verdict.ok) return verdict;
		const result = holds.register({
			inChannelIdHex: 'in',
			inHtlcId: String(holds.list().length + 1),
			paymentHashHex: c.paymentHashHex,
			outChannelIdHex: 'out',
			receiverNodeIdHex: c.receiverNodeIdHex,
			registrationIdHex: c.registrationIdHex,
			incomingAmountMsat: c.incomingAmountMsat.toString(),
			forwardAmountMsat: c.forwardAmountMsat.toString(),
			forwardCltv: height + 150,
			incomingCltvExpiry: height + 200,
			cutoffHeight: verdict.cutoffHeight,
			admittedHeight: verdict.admittedHeight,
			heldBytes: c.heldBytes,
			admissionFeeMsat: verdict.admissionFeeMsat.toString(),
			holdingFeeMsat: verdict.holdingFeeMsat.toString()
		});
		expect(result?.created).to.equal(true);
		return verdict;
	}

	it('is disabled by default and then grants, admits and answers nothing', () => {
		build({ enabled: false });
		expect(svc.isEnabled()).to.equal(false);
		const reply = register(CAROL_ID, SCID_CAROL);
		expect(reply).to.deep.include({
			granted: false,
			reason: 'service_disabled'
		});
		const verdict = svc.admit(candidate(sampleGrant()));
		expect(verdict).to.deep.include({ ok: false, reason: 'service_disabled' });
		expect(svc.metrics()).to.deep.include({
			enabled: false,
			admissionRefusals: 1,
			registrationRefusals: 1
		});
	});

	it('issues a grant carrying the service terms, signed by the LSP, and supersedes on renewal', () => {
		build({
			enabled: true,
			maxHoldBlocks: 100,
			admissionFeeMsat: 7n,
			holdingFeeMsatPerBlock: 3n,
			initialCreditMsat: 70n,
			grantTtlSec: 3600
		});
		const grant = grantOf(register(CAROL_ID, SCID_CAROL));
		expect(verifyReceiverGrant(grant)).to.equal(true);
		expect(grant.lspNodeId.equals(LSP_ID)).to.equal(true);
		expect(grant.receiverNodeId.equals(CAROL_ID)).to.equal(true);
		expect(grant.maxHoldBlocks).to.equal(100);
		expect(grant.admissionFeeMsat).to.equal(7n);
		expect(grant.holdingFeeMsatPerBlock).to.equal(3n);
		expect(grant.creditMsat).to.equal(70n);
		expect(grant.issuedAt).to.equal(1_700_000_000n);
		expect(grant.expiresAt).to.equal(1_700_003_600n);
		expect(grant.witnessProfile.equals(Buffer.alloc(32))).to.equal(true);
		// A requested window shorter than the service maximum is honoured; a
		// longer one is capped.
		const short = grantOf(
			svc.handleRegistrationRequest(
				DAVE_ID.toString('hex'),
				encodeRegistrationRequest({
					version: REGISTRATION_REQUEST_VERSION,
					chainHash: CHAIN,
					receiverNodeId: DAVE_ID,
					lspNodeId: LSP_ID,
					scid: SCID_DAVE,
					requestedHoldBlocks: 40,
					nonce: crypto.randomBytes(32)
				})
			)
		);
		expect(short.maxHoldBlocks).to.equal(40);
		// Renewal supersedes: one ACTIVE registration per (receiver, channel).
		const renewed = grantOf(register(CAROL_ID, SCID_CAROL));
		expect(renewed.registrationId.equals(grant.registrationId)).to.equal(false);
		const rows = svc.listRegistrations();
		expect(rows).to.have.length(3);
		expect(
			rows.find((r) => r.id === grant.registrationId.toString('hex'))!.state
		).to.equal('REVOKED');
		expect(svc.activeRegistrations()).to.have.length(2);
		// The old registration admits nothing now.
		expect(svc.admit(candidate(grant))).to.deep.include({
			ok: false,
			reason: 'registration_revoked'
		});
		expect(svc.admit(candidate(renewed)).ok).to.equal(true);
	});

	it('refuses replayed nonces and a receiver over the receiver ceiling', () => {
		build({ enabled: true, maxReceivers: 1 });
		const nonce = crypto.randomBytes(32);
		expect(register(CAROL_ID, SCID_CAROL, nonce).granted).to.equal(true);
		expect(register(CAROL_ID, SCID_CAROL, nonce)).to.deep.include({
			granted: false,
			reason: 'nonce_replayed'
		});
		// Carol renewing (fresh nonce) is not a second receiver; Dave is.
		expect(register(CAROL_ID, SCID_CAROL).granted).to.equal(true);
		expect(register(DAVE_ID, SCID_DAVE)).to.deep.include({
			granted: false,
			reason: 'too_many_receivers'
		});
		expect(svc.metrics().registrationRefusals).to.equal(2);
	});

	it('enforces global count, value and bytes across receivers, and per-receiver bytes', () => {
		build({
			enabled: true,
			maxHolds: 3,
			maxHeldMsat: 600_000n,
			maxHeldBytes: 3 * H + 100,
			maxHeldBytesPerReceiver: 2 * H + 100,
			maxPartsPerReceiver: 10,
			maxHeldMsatPerReceiver: 10_000_000n
		});
		const carol = grantOf(register(CAROL_ID, SCID_CAROL));
		const dave = grantOf(register(DAVE_ID, SCID_DAVE));
		expect(park(carol).ok).to.equal(true);
		expect(park(carol).ok).to.equal(true);
		// Carol's third hold is over her byte ceiling, whatever else fits.
		expect(park(carol)).to.deep.include({
			ok: false,
			reason: 'receiver_bytes'
		});
		expect(park(carol, { heldBytes: 50 }).ok).to.equal(true);
		// Global count: three holds are parked; Dave's first would be the fourth.
		expect(park(dave, { heldBytes: 1 })).to.deep.include({
			ok: false,
			reason: 'global_count'
		});
		expect(holds.unresolved()).to.have.length(3);
		// Free a slot: Dave's hold now fits by count, but not by global value.
		expect(holds.beginFail(holds.unresolved()[0].id, 'test').outcome).to.equal(
			'applied'
		);
		expect(holds.markFailed(holds.unresolved()[0].id).outcome).to.equal(
			'applied'
		);
		expect(
			park(dave, { forwardAmountMsat: 400_000n, heldBytes: 1 })
		).to.deep.include({ ok: false, reason: 'global_value' });
		// A small enough part fits by value, then bytes are what remains.
		expect(park(dave, { heldBytes: 2 * H + 100 })).to.deep.include({
			ok: false,
			reason: 'global_bytes'
		});
		expect(park(dave, { heldBytes: 10 }).ok).to.equal(true);
		const m = svc.metrics();
		expect(m.occupiedSlots).to.equal(3);
		expect(m.heldBytes).to.equal(H + 50 + 10);
		expect(m.admissionRefusalsByReason).to.deep.equal({
			receiver_bytes: 1,
			global_count: 1,
			global_value: 1,
			global_bytes: 1
		});
	});

	it('prices admission from prepaid credit and the holding window from the payer', () => {
		build({
			enabled: true,
			admissionFeeMsat: 100n,
			holdingFeeMsatPerBlock: 2n,
			maxHoldBlocks: 50,
			initialCreditMsat: 250n
		});
		const grant = grantOf(register(CAROL_ID, SCID_CAROL));
		const regId = grant.registrationId.toString('hex');
		expect(holdingFeeForWindowMsat(grant)).to.equal(100n);
		// The payer must carry the holding fee on top of the policy fee.
		const underpaid = candidate(grant);
		underpaid.incomingAmountMsat -= 1n;
		expect(svc.admit(underpaid)).to.deep.include({
			ok: false,
			reason: 'fee_insufficient'
		});
		const first = park(grant);
		expect(first).to.deep.include({
			ok: true,
			admissionFeeMsat: 100n,
			holdingFeeMsat: 100n,
			admittedHeight: 1_000
		});
		expect(svc.creditRemainingMsat(regId)).to.equal(150n);
		expect(park(grant).ok).to.equal(true);
		expect(svc.creditRemainingMsat(regId)).to.equal(50n);
		// Credit does not come back when a hold resolves, whichever way.
		const [a, b] = holds.unresolved();
		holds.beginFail(a.id, 'cutoff');
		holds.markFailed(a.id);
		holds.beginRelease([b.id], crypto.randomBytes(32).toString('hex'));
		holds.markReleased(b.id);
		expect(svc.creditRemainingMsat(regId)).to.equal(50n);
		expect(park(grant)).to.deep.include({
			ok: false,
			reason: 'credit_exhausted'
		});
		// A top-up admits again; a refused admission never debits.
		expect(svc.creditRegistration(regId, 50n)).to.equal(true);
		expect(svc.creditRemainingMsat(regId)).to.equal(100n);
		expect(park(grant).ok).to.equal(true);
		expect(svc.creditRemainingMsat(regId)).to.equal(0n);
		expect(svc.creditSpentMsat(regId)).to.equal(300n);
	});

	it('clamps the window to the grant, refuses a window too short, and expires the registration on the clock', () => {
		build({
			enabled: true,
			maxHoldBlocks: 30,
			minRemainingCltv: 10,
			grantTtlSec: 100
		});
		const grant = grantOf(register(CAROL_ID, SCID_CAROL));
		const long = svc.admit(
			candidate(grant, { proposedCutoffHeight: height + 500 })
		);
		expect(long).to.deep.include({ ok: true, cutoffHeight: height + 30 });
		const tight = svc.admit(
			candidate(grant, { proposedCutoffHeight: height + 10 })
		);
		expect(tight).to.deep.include({ ok: true, cutoffHeight: height + 10 });
		expect(
			svc.admit(candidate(grant, { proposedCutoffHeight: height + 9 }))
		).to.deep.include({ ok: false, reason: 'cltv_too_short' });
		// Before the first block the window cannot be judged, like the cutoff.
		height = 0;
		expect(
			svc.admit(candidate(grant, { proposedCutoffHeight: 5 })).ok
		).to.equal(true);
		height = 1_000;
		// The clock runs out: the registration expires without any write.
		clock += 100_000;
		expect(svc.admit(candidate(grant))).to.deep.include({
			ok: false,
			reason: 'registration_expired'
		});
		expect(svc.activeRegistrations()).to.have.length(0);
		expect(svc.metrics().registrations).to.equal(0);
	});

	it('scopes admission to the registered receiver and channel, and reports refusals', () => {
		build({ enabled: true });
		const grant = grantOf(register(CAROL_ID, SCID_CAROL));
		expect(
			svc.admit(
				candidate(grant, { receiverNodeIdHex: DAVE_ID.toString('hex') })
			)
		).to.deep.include({ ok: false, reason: 'receiver_mismatch' });
		expect(
			svc.admit(
				candidate(grant, { outgoingScidHex: SCID_DAVE.toString('hex') })
			)
		).to.deep.include({ ok: false, reason: 'channel_mismatch' });
		expect(
			svc.admit(
				candidate(grant, {
					registrationIdHex: crypto.randomBytes(32).toString('hex')
				})
			)
		).to.deep.include({ ok: false, reason: 'unknown_registration' });
		expect(
			svc.revokeRegistration(grant.registrationId.toString('hex'))
		).to.equal(true);
		expect(svc.admit(candidate(grant))).to.deep.include({
			ok: false,
			reason: 'registration_revoked'
		});
		const refused: string[] = [];
		svc.on('admission-refused', (info: { reason: string }) => {
			refused.push(info.reason);
		});
		svc.admit(candidate(grant));
		expect(refused).to.deep.equal(['registration_revoked']);
		expect(svc.metrics().admissionRefusals).to.equal(5);
	});
});
