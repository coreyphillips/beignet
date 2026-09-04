/**
 * Async receive as an opt-in LSP service (issue #709): the service boundary
 * around the held-forward ledger of issue #708. Alice -> LSP -> Carol over
 * the shared world (helpers/async-world.ts); the LSP runs the service and
 * Carol registers with it unless a test says otherwise.
 *
 * One test per acceptance criterion of the issue:
 *  - a node that has not enabled the service never parks a hold_htlc forward;
 *  - a receiver without a valid grant cannot consume a held-forward slot;
 *  - grants are authenticated, scoped, expiring and replay safe;
 *  - per-receiver and global limits cover count, value, bytes and CLTV;
 *  - concurrent admissions cannot exceed a limit through a race;
 *  - pricing and refunds are deterministic for release, failure, disconnect
 *    and expiry, and an abandoned hold is never free;
 *  - feature negotiation stops a receiver assuming support;
 *  - metrics expose the six figures;
 *  - abusive registrations are refused;
 *  - a refusal on a blinded path leaks nothing to the payer.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { Feature } from '../../src/lightning/features/flags';
import { MessageType } from '../../src/lightning/message/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';
import { INVALID_ONION_BLINDING } from '../../src/lightning/onion/types';
import { isUnresolvedHeldForward } from '../../src/lightning/async-payments/held-forward-ledger';
import {
	ASYNC_REGISTRATION_REPLY_TLV_TYPE,
	ASYNC_REGISTRATION_REQUEST_TLV_TYPE
} from '../../src/lightning/async-payments/types';
import {
	IReceiverGrant,
	IUnsignedReceiverGrant,
	REGISTRATION_REQUEST_VERSION,
	encodeReceiverGrant,
	encodeRegistrationRequest,
	signReceiverGrant
} from '../../src/lightning/async-payments/receiver-grant';
import { IAdmissionCandidate } from '../../src/lightning/async-payments/service';
import {
	IWorld,
	LSP_SEED,
	MALLORY_SEED,
	asyncInvoice,
	createNode,
	destroyAll,
	disconnect,
	heldRecords,
	nodePrivkey,
	payPart,
	reconnect,
	settle,
	setupWorld,
	tapOnion,
	waitFor,
	wire
} from './helpers/async-world';

/** Bytes one hold reserves: the onion packet plus its ledger row. */
const HOLD_BYTES = 1366 + 1024;

function nodeId(node: LightningNode): Buffer {
	return Buffer.from(node.getNodeId(), 'hex');
}

function chainHashOf(node: LightningNode): Buffer {
	return (node as unknown as { chainHash: () => Buffer }).chainHash();
}

function nowSec(): number {
	return Math.floor(Date.now() / 1000);
}

/** A grant for Carol at the LSP over their channel, signed by `signer`. */
function forgeGrant(
	w: IWorld,
	overrides: Partial<Omit<IUnsignedReceiverGrant, 'version'>>,
	signer: Buffer
): Buffer {
	const grant: IReceiverGrant = signReceiverGrant(
		{
			featureBit: Feature.ASYNC_RECEIVE_SERVICE + 1,
			serviceFlags: 0,
			chainHash: chainHashOf(w.lsp),
			receiverNodeId: nodeId(w.carol),
			lspNodeId: nodeId(w.lsp),
			registrationId: crypto.randomBytes(32),
			scid: w.scidBC,
			maxPartMsat: 1_000_000_000n,
			maxPaymentMsat: 1_000_000_000n,
			maxParts: 10,
			maxHeldMsat: 1_000_000_000n,
			maxHoldBlocks: 144,
			minRemainingCltv: 6,
			admissionFeeMsat: 0n,
			holdingFeeMsatPerBlock: 0n,
			feeCollection: 1,
			creditMsat: 0n,
			issuedAt: BigInt(nowSec()),
			expiresAt: BigInt(nowSec() + 3600),
			nonce: crypto.randomBytes(32),
			witnessProfile: Buffer.alloc(32),
			...overrides
		},
		signer
	);
	return encodeReceiverGrant(grant);
}

function unresolvedCount(lsp: LightningNode): number {
	return lsp.listHeldForwards().filter((r) => isUnresolvedHeldForward(r.state))
		.length;
}

function sendRawRequest(
	from: LightningNode,
	lsp: LightningNode,
	fields: Partial<Parameters<typeof encodeRegistrationRequest>[0]>
): Buffer {
	const nonce = fields.nonce ?? crypto.randomBytes(32);
	from.getOnionMessageManager().sendOnionMessage(
		nodeId(lsp),
		new Map([
			[
				ASYNC_REGISTRATION_REQUEST_TLV_TYPE,
				encodeRegistrationRequest({
					version: REGISTRATION_REQUEST_VERSION,
					chainHash: chainHashOf(lsp),
					receiverNodeId: nodeId(from),
					lspNodeId: nodeId(lsp),
					scid: Buffer.alloc(8, 9),
					requestedHoldBlocks: 0,
					nonce,
					...fields
				})
			]
		])
	);
	return nonce;
}

async function payAndSettle(
	w: IWorld,
	amountMsat: bigint
): Promise<ReturnType<typeof asyncInvoice>> {
	const invoice = asyncInvoice(w.carol, amountMsat);
	w.alice.sendPayment(invoice.bolt11);
	await settle();
	return invoice;
}

describe('Async receive service (issue #709)', () => {
	describe('opt-in', () => {
		it('a node that has not enabled the service never parks a hold_htlc forward', async function () {
			this.timeout(20_000);
			const w = await setupWorld({
				lspService: { enabled: false },
				carolRegisters: false
			});
			const { alice, lsp, carol } = w;
			expect(
				lsp.getLocalFeatures().hasFeature(Feature.ASYNC_RECEIVE_SERVICE),
				'no feature bit while disabled'
			).to.equal(false);
			expect(lsp.getNodeInfo().asyncReceiveService.enabled).to.equal(false);
			// Carol holds a grant this very LSP signed (out of band, before its
			// operator turned the service off), so her paths carry the marker.
			carol.importAsyncReceiveGrant(forgeGrant(w, {}, nodePrivkey(LSP_SEED)));
			const ignored: string[] = [];
			lsp.on('log', (e: { action?: string; data?: { reason?: string } }) => {
				if (e.action === 'hold_marker_ignored') ignored.push(e.data!.reason!);
			});

			// Carol online: the marker is ignored and the HTLC forwards at once.
			const online = await payAndSettle(w, 5_000_000n);
			expect(heldRecords(lsp), 'nothing parked').to.have.length(0);
			expect(w.forwards).to.equal(1);
			expect(carol.getPayment(online.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			// Carol offline: still nothing parked; the forward fails like any
			// forward to an unreachable peer.
			await disconnect(lsp, carol, w.cutBC);
			const offline = await payAndSettle(w, 5_000_000n);
			await waitFor(
				() =>
					alice.getPayment(offline.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the offline payment to fail back'
			);
			expect(heldRecords(lsp), 'still nothing parked').to.have.length(0);
			expect(ignored).to.deep.equal([
				'async_receive_service_disabled',
				'async_receive_service_disabled'
			]);
			expect(lsp.getAsyncReceiveServiceMetrics().occupiedSlots).to.equal(0);
			destroyAll(alice, lsp, carol);
		});

		it('a receiver without a valid grant cannot consume a held-forward slot', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol } = w;
			// A grant carrying the LSP's genuine signature but a registration
			// the LSP never issued (its ledger has no row): the marker names
			// nothing, and nothing is reserved.
			carol.importAsyncReceiveGrant(forgeGrant(w, {}, nodePrivkey(LSP_SEED)));
			await disconnect(lsp, carol, w.cutBC);
			const unknown = await payAndSettle(w, 5_000_000n);
			await waitFor(
				() =>
					alice.getPayment(unknown.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the unregistered hold to be refused'
			);
			expect(heldRecords(lsp), 'no slot consumed').to.have.length(0);
			expect(w.admissionRefusals).to.deep.equal(['unknown_registration']);
			expect(lsp.getAsyncReceiveServiceMetrics().occupiedSlots).to.equal(0);

			// A registration the operator revoked admits nothing either.
			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await carol.requestAsyncReceiveGrant(lsp.getNodeId(), {
				timeoutMs: 5_000
			});
			const active = lsp
				.listAsyncReceiveRegistrations()
				.filter((r) => r.state === 'ACTIVE');
			expect(active).to.have.length(1);
			// The invoice is built while the grant is honoured...
			const revokedInvoice = asyncInvoice(carol, 5_000_000n);
			expect(lsp.revokeAsyncReceiveRegistration(active[0].id)).to.equal(true);
			await disconnect(lsp, carol, w.cutBC);
			alice.sendPayment(revokedInvoice.bolt11);
			await settle();
			await waitFor(
				() =>
					alice.getPayment(revokedInvoice.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the revoked hold to be refused'
			);
			expect(heldRecords(lsp)).to.have.length(0);
			expect(w.admissionRefusals).to.deep.equal([
				'unknown_registration',
				'registration_revoked'
			]);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('grants', () => {
		it('grants are authenticated, scoped, expiring and replay safe', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolRegisters: false });
			const { alice, lsp, carol } = w;
			const mallory = createNode(MALLORY_SEED);
			wire(mallory, lsp, { val: false });
			const lspKey = nodePrivkey(LSP_SEED);
			const malloryKey = nodePrivkey(MALLORY_SEED);
			const reject = (bytes: Buffer, reason: string): void => {
				expect(() => carol.importAsyncReceiveGrant(bytes)).to.throw(reason);
			};
			// Forged: the LSP's identity, Mallory's signature.
			reject(forgeGrant(w, {}, malloryKey), 'bad_signature');
			// Wrong LSP: correctly signed by Mallory, naming Mallory, who has no
			// channel with Carol to serve.
			reject(
				forgeGrant(w, { lspNodeId: nodeId(mallory) }, malloryKey),
				'wrong_channel'
			);
			// Scoped: a genuine grant for somebody else.
			reject(
				forgeGrant(w, { receiverNodeId: nodeId(mallory) }, lspKey),
				'not_for_us'
			);
			// Scoped: a genuine grant for another chain.
			reject(
				forgeGrant(w, { chainHash: BITCOIN_CHAIN_HASH }, lspKey),
				'wrong_network'
			);
			// Scoped: a genuine grant over a channel that is not ours.
			reject(forgeGrant(w, { scid: w.scidAB }, lspKey), 'wrong_channel');
			// Expiring: a genuine grant past its expiry.
			reject(
				forgeGrant(w, { expiresAt: BigInt(nowSec() - 1) }, lspKey),
				'expired'
			);
			// Tampered: one flipped byte in a genuine grant.
			const genuine = forgeGrant(w, {}, lspKey);
			genuine[100] ^= 0x01;
			reject(genuine, 'bad_signature');
			expect(carol.listAsyncReceiveGrants()).to.have.length(0);

			// Replay safe at the LSP: Carol's real request, then the same bytes
			// again. The LSP mints exactly one registration and refuses the
			// replayed nonce.
			const requests = tapOnion(carol, lsp);
			const grant = await carol.requestAsyncReceiveGrant(lsp.getNodeId(), {
				timeoutMs: 5_000
			});
			expect(grant.featureBit).to.equal(Feature.ASYNC_RECEIVE_SERVICE + 1);
			expect(requests, 'one request went out').to.have.length(1);
			expect(lsp.listAsyncReceiveRegistrations()).to.have.length(1);
			lsp.handlePeerMessage(
				carol.getNodeId(),
				MessageType.ONION_MESSAGE,
				requests[0]
			);
			await settle();
			expect(lsp.listAsyncReceiveRegistrations()).to.have.length(1);
			expect(w.registrationRefusals).to.deep.equal(['nonce_replayed']);

			// The grant Carol keeps is the one the LSP stored, verified.
			const [stored] = carol.listAsyncReceiveGrants();
			expect(stored.registrationId.toString('hex')).to.equal(
				lsp.listAsyncReceiveRegistrations()[0].id
			);
			expect(stored.scid.equals(w.scidBC)).to.equal(true);

			// Scoped at the LSP: a hold under Carol's registration but for a
			// different receiver or a different channel is refused.
			const svc = lsp.getAsyncReceiveService();
			const candidate: IAdmissionCandidate = {
				registrationIdHex: stored.registrationId.toString('hex'),
				receiverNodeIdHex: carol.getNodeId(),
				outgoingScidHex: w.scidBC.toString('hex'),
				paymentHashHex: crypto.randomBytes(32).toString('hex'),
				incomingAmountMsat: 1_001_000n,
				forwardAmountMsat: 1_000_000n,
				policyFeeMsat: 1_000n,
				proposedCutoffHeight: 10_000,
				heldBytes: HOLD_BYTES
			};
			expect(svc.admit(candidate).ok).to.equal(true);
			expect(
				svc.admit({ ...candidate, receiverNodeIdHex: mallory.getNodeId() })
			).to.deep.include({ ok: false, reason: 'receiver_mismatch' });
			expect(
				svc.admit({ ...candidate, outgoingScidHex: w.scidAB.toString('hex') })
			).to.deep.include({ ok: false, reason: 'channel_mismatch' });
			destroyAll(alice, lsp, carol, mallory);
		});

		it('an expired registration admits nothing, and the receiver stops using it', async function () {
			this.timeout(20_000);
			const w = await setupWorld({
				lspService: { enabled: true, grantTtlSec: 2 },
				carolAutoRelease: false
			});
			const { alice, lsp, carol } = w;
			// Built while the grant is live.
			const invoice = asyncInvoice(carol, 5_000_000n);
			await disconnect(lsp, carol, w.cutBC);
			await new Promise((resolve) => setTimeout(resolve, 2_100));
			alice.sendPayment(invoice.bolt11);
			await settle();
			await waitFor(
				() =>
					alice.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the hold under the expired registration to be refused'
			);
			expect(heldRecords(lsp)).to.have.length(0);
			expect(w.admissionRefusals).to.deep.equal(['registration_expired']);
			expect(lsp.getAsyncReceiveServiceMetrics().registrations).to.equal(0);
			// The receiver will not build a hold path on an expired grant.
			expect(() => asyncInvoice(carol, 1_000n)).to.throw(
				'live async receive grant'
			);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('limits', () => {
		it('per-receiver limits on part, payment, value and count are enforced at admission', async function () {
			this.timeout(20_000);
			const w = await setupWorld({
				lspService: {
					enabled: true,
					maxPartMsat: 6_000_000n,
					maxPaymentMsat: 7_000_000n,
					maxHeldMsatPerReceiver: 8_000_000n,
					maxPartsPerReceiver: 2
				},
				carolAutoRelease: false
			});
			const { alice, lsp, carol } = w;
			const [grant] = carol.listAsyncReceiveGrants();
			expect(grant.maxPartMsat).to.equal(6_000_000n);
			expect(grant.maxParts).to.equal(2);
			await disconnect(lsp, carol, w.cutBC);

			// Part too large: nothing reserved.
			await payAndSettle(w, 6_500_000n);
			expect(unresolvedCount(lsp)).to.equal(0);
			// Payment too large: the first part fits, the second would take
			// the payment past the ceiling.
			const mpp = asyncInvoice(carol, 7_500_000n);
			payPart(
				alice,
				mpp.bolt11,
				mpp.paymentHash,
				mpp.paymentSecret,
				3_000_000n,
				7_500_000n
			);
			await settle();
			expect(unresolvedCount(lsp)).to.equal(1);
			payPart(
				alice,
				mpp.bolt11,
				mpp.paymentHash,
				mpp.paymentSecret,
				4_500_000n,
				7_500_000n
			);
			await settle();
			expect(unresolvedCount(lsp)).to.equal(1);
			// Value: 3M held, another 5.5M would exceed 8M.
			await payAndSettle(w, 5_500_000n);
			expect(unresolvedCount(lsp)).to.equal(1);
			// Count: a second small hold fits, a third does not.
			await payAndSettle(w, 1_000_000n);
			expect(unresolvedCount(lsp)).to.equal(2);
			await payAndSettle(w, 1_000_000n);
			expect(unresolvedCount(lsp)).to.equal(2);
			expect(w.admissionRefusals).to.deep.equal([
				'part_too_large',
				'payment_too_large',
				'receiver_value',
				'receiver_count'
			]);
			const m = lsp.getAsyncReceiveServiceMetrics();
			expect(m.occupiedSlots).to.equal(2);
			expect(m.admissionRefusals).to.equal(4);
			destroyAll(alice, lsp, carol);
		});

		it('the CLTV window is clamped to the grant and a hold too short to matter is refused', async function () {
			this.timeout(20_000);
			const w = await setupWorld({
				lspService: { enabled: true, maxHoldBlocks: 20, minRemainingCltv: 10 },
				carolAutoRelease: false
			});
			const { alice, lsp, carol } = w;
			for (const n of [alice, lsp, carol]) n.handleNewBlock(1_000);
			const [grant] = carol.listAsyncReceiveGrants();
			expect(grant.maxHoldBlocks).to.equal(20);
			await disconnect(lsp, carol, w.cutBC);

			const first = await payAndSettle(w, 5_000_000n);
			const [r] = heldRecords(lsp);
			expect(r.paymentHashHex).to.equal(first.paymentHash.toString('hex'));
			const proposed = Math.min(r.forwardCltv - 40, r.incomingCltvExpiry - 18);
			expect(proposed, 'the path asked for the window').to.be.above(1_020);
			expect(r.cutoffHeight, 'clamped to the grant window').to.equal(1_020);
			expect(r.admittedHeight).to.equal(1_000);
			// The clamp is what the LSP acts on: the hold fails at the grant's
			// window, well before the CLTVs alone would have allowed.
			lsp.handleNewBlock(1_020);
			await waitFor(
				() =>
					alice.getPayment(first.paymentHash)?.status === PaymentStatus.FAILED,
				'the hold to expire at the clamped cutoff'
			);
			expect(heldRecords(lsp)[0].failReason).to.equal('cutoff');
			expect(lsp.getAsyncReceiveServiceMetrics().expiries).to.equal(1);

			// The same path judged later, with fewer than minRemainingCltv
			// blocks left before its cutoff: refused, nothing reserved.
			lsp.handleNewBlock(proposed - 5);
			const late = await payAndSettle(w, 5_000_000n);
			await waitFor(
				() =>
					alice.getPayment(late.paymentHash)?.status === PaymentStatus.FAILED,
				'the short hold to be refused'
			);
			expect(unresolvedCount(lsp)).to.equal(0);
			expect(heldRecords(lsp), 'no row for the refusal').to.have.length(1);
			expect(w.admissionRefusals).to.deep.equal(['cltv_too_short']);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('races', () => {
		it('concurrent admissions cannot exceed a limit through a check-then-act race', async function () {
			this.timeout(20_000);
			const w = await setupWorld({
				lspService: { enabled: true, maxPartsPerReceiver: 1 },
				carolAutoRelease: false
			});
			const { alice, lsp, carol } = w;
			await disconnect(lsp, carol, w.cutBC);
			// Every verdict is taken against the ledger as it is at that
			// instant; the durable row lands before the next verdict runs.
			const svc = lsp.getAsyncReceiveService();
			const seen: number[] = [];
			const original = svc.admit.bind(svc);
			(svc as { admit: typeof svc.admit }).admit = (
				c
			): ReturnType<typeof original> => {
				seen.push(unresolvedCount(lsp));
				return original(c);
			};
			const mpp = asyncInvoice(carol, 2_000_000n);
			// Two parts of one payment fired back to back, nothing awaited
			// between them.
			payPart(
				alice,
				mpp.bolt11,
				mpp.paymentHash,
				mpp.paymentSecret,
				1_000_000n,
				2_000_000n
			);
			payPart(
				alice,
				mpp.bolt11,
				mpp.paymentHash,
				mpp.paymentSecret,
				1_000_000n,
				2_000_000n
			);
			await settle();
			expect(
				seen,
				'the second verdict saw the first reservation'
			).to.deep.equal([0, 1]);
			expect(unresolvedCount(lsp)).to.equal(1);
			expect(w.admissionRefusals).to.deep.equal(['receiver_count']);

			// The same property at the ledger: two registrations judged in one
			// synchronous burst, with a limit of one, admit exactly one.
			const manager = lsp.getAsyncPaymentManager();
			const [held] = heldRecords(lsp);
			const outcomes = [1, 2].map((i) =>
				manager.registerHold(
					{
						...held,
						inHtlcId: `${900 + i}`,
						paymentHashHex: crypto.randomBytes(32).toString('hex')
					},
					{ forward: () => 'deferred', fail: () => true },
					() =>
						unresolvedCount(lsp) < 2
							? { ok: true }
							: { ok: false, reason: 'limit' }
				)
			);
			expect('record' in outcomes[0]).to.equal(true);
			expect(outcomes[1]).to.deep.equal({ refused: 'limit' });
			expect(unresolvedCount(lsp)).to.equal(2);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('pricing', () => {
		it('pricing and refunds are deterministic for release, failure, disconnect and expiry, and abandoned holds are never free', async function () {
			this.timeout(30_000);
			const w = await setupWorld({
				lspService: {
					enabled: true,
					admissionFeeMsat: 1_000n,
					holdingFeeMsatPerBlock: 10n,
					maxHoldBlocks: 20,
					initialCreditMsat: 4_000n
				},
				carolAutoRelease: true
			});
			const { alice, lsp, carol } = w;
			const svc = lsp.getAsyncReceiveService();
			const [grant] = carol.listAsyncReceiveGrants();
			expect(grant.admissionFeeMsat).to.equal(1_000n);
			expect(grant.holdingFeeMsatPerBlock).to.equal(10n);
			expect(grant.creditMsat).to.equal(4_000n);
			const regId = grant.registrationId.toString('hex');
			expect(svc.creditRemainingMsat(regId)).to.equal(4_000n);
			const holdingFee = 200n; // 10 msat * 20 blocks, paid by the payer

			// 1. Release: Carol is paid the invoice amount, the LSP keeps the
			//    policy fee plus the holding fee the payer added, the
			//    admission fee is spent.
			await disconnect(lsp, carol, w.cutBC);
			const released = await payAndSettle(w, 5_000_000n);
			let [row] = heldRecords(lsp);
			expect(row.admissionFeeMsat).to.equal('1000');
			expect(row.holdingFeeMsat).to.equal('200');
			const lspFee =
				BigInt(row.incomingAmountMsat) - BigInt(row.forwardAmountMsat);
			const policyFee = 1_000n + BigInt(row.forwardAmountMsat) / 1_000_000n;
			expect(lspFee, 'holding fee on top of the policy fee').to.equal(
				policyFee + holdingFee
			);
			const aliceHtlc = [
				...alice
					.getChannelManager()
					.getChannel(w.abChannelId)!
					.getFullState()
					.htlcs.values()
			].find((h) => h.paymentHash.equals(released.paymentHash))!;
			expect(aliceHtlc.amountMsat, 'the payer carried it').to.equal(
				5_000_000n + lspFee
			);
			expect(svc.creditRemainingMsat(regId)).to.equal(3_000n);
			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					carol.getPayment(released.paymentHash)?.status ===
					PaymentStatus.COMPLETED,
				'Carol to be paid'
			);
			expect(
				Number(carol.getPayment(released.paymentHash)!.amountMsat)
			).to.equal(5_000_000);
			expect(heldRecords(lsp)[0].state).to.equal('RELEASED');
			expect(
				svc.creditRemainingMsat(regId),
				'release refunds nothing'
			).to.equal(3_000n);

			// 2. Failure: the operator fails the hold; the payer is refunded in
			//    full (holding fee included); the admission fee is not.
			await disconnect(lsp, carol, w.cutBC);
			const failed = await payAndSettle(w, 5_000_000n);
			row = heldRecords(lsp).find(
				(r) => r.paymentHashHex === failed.paymentHash.toString('hex')
			)!;
			expect(svc.creditRemainingMsat(regId)).to.equal(2_000n);
			expect(lsp.failHeldForward(row.id)).to.equal(true);
			await waitFor(
				() =>
					alice.getPayment(failed.paymentHash)?.status === PaymentStatus.FAILED,
				'the payer to be refunded'
			);
			expect(
				svc.creditRemainingMsat(regId),
				'failure refunds nothing'
			).to.equal(2_000n);

			// 3. Disconnect: the payer's link drops and comes back while the
			//    hold is parked; the hold, its price and the receiver's credit
			//    are unchanged, and the release then settles as in 1.
			const viaDisconnect = await payAndSettle(w, 5_000_000n);
			expect(svc.creditRemainingMsat(regId)).to.equal(1_000n);
			await disconnect(alice, lsp, w.cutAB);
			await reconnect(alice, lsp, w.cutAB, w.gateAB);
			row = heldRecords(lsp).find(
				(r) => r.paymentHashHex === viaDisconnect.paymentHash.toString('hex')
			)!;
			expect(row.state).to.equal('HELD');
			expect(row.admissionFeeMsat).to.equal('1000');
			expect(svc.creditRemainingMsat(regId)).to.equal(1_000n);
			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					carol.getPayment(viaDisconnect.paymentHash)?.status ===
					PaymentStatus.COMPLETED,
				'Carol to be paid after the disconnect'
			);
			expect(svc.creditRemainingMsat(regId)).to.equal(1_000n);

			// 4. Expiry: the hold reaches its cutoff; the payer is refunded in
			//    full; the admission fee stays spent.
			await disconnect(lsp, carol, w.cutBC);
			const expired = await payAndSettle(w, 5_000_000n);
			row = heldRecords(lsp).find(
				(r) => r.paymentHashHex === expired.paymentHash.toString('hex')
			)!;
			expect(svc.creditRemainingMsat(regId)).to.equal(0n);
			lsp.handleNewBlock(row.cutoffHeight);
			await waitFor(
				() =>
					alice.getPayment(expired.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the payer to be refunded at the cutoff'
			);
			expect(svc.creditRemainingMsat(regId), 'expiry refunds nothing').to.equal(
				0n
			);
			expect(lsp.getAsyncReceiveServiceMetrics().expiries).to.equal(1);
			// The chain moved for everyone, so the next payment's CLTVs are
			// judged against the same height the LSP now sits at.
			for (const n of [alice, carol]) n.handleNewBlock(row.cutoffHeight);

			// 5. Abandoned holds are priced: the credit is gone, so the next
			//    part is refused before anything is reserved, until the
			//    operator is paid and credits the receiver again.
			const refused = await payAndSettle(w, 5_000_000n);
			await waitFor(
				() =>
					alice.getPayment(refused.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the unfunded part to be refused'
			);
			expect(w.admissionRefusals).to.deep.equal(['credit_exhausted']);
			expect(unresolvedCount(lsp)).to.equal(0);
			expect(lsp.creditAsyncReceiver(regId, 1_000n)).to.equal(true);
			await payAndSettle(w, 5_000_000n);
			expect(unresolvedCount(lsp)).to.equal(1);
			expect(svc.creditRemainingMsat(regId)).to.equal(0n);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('negotiation', () => {
		it('feature negotiation prevents a receiver from assuming support from a peer that will ignore the marker', async function () {
			this.timeout(20_000);
			const w = await setupWorld({
				lspService: { enabled: false },
				carolRegisters: false
			});
			const { alice, lsp, carol } = w;
			expect(carol.peerAdvertisesAsyncReceive(lsp.getNodeId())).to.equal(false);
			const sent = tapOnion(carol, lsp);
			let refusal = '';
			await carol
				.requestAsyncReceiveGrant(lsp.getNodeId(), { timeoutMs: 1_000 })
				.catch((err: Error) => {
					refusal = err.message;
				});
			expect(refusal).to.contain('does not advertise');
			expect(sent, 'nothing was even asked').to.have.length(0);
			expect(() => asyncInvoice(carol, 1_000n)).to.throw(
				'live async receive grant'
			);
			expect(() =>
				carol.createOffer({ description: 'async', asyncHold: true })
			).to.throw('live async receive grant');
			// A request that reaches a disabled node anyway is ignored like any
			// unknown TLV: no reply, no registration.
			const replies = tapOnion(lsp, carol);
			sendRawRequest(carol, lsp, { scid: w.scidBC });
			await settle();
			expect(replies).to.have.length(0);
			expect(lsp.listAsyncReceiveRegistrations()).to.have.length(0);
			destroyAll(alice, lsp, carol);

			// With the service on, the bit is advertised and the exchange runs.
			const w2 = await setupWorld({ carolRegisters: false });
			expect(
				w2.lsp.getLocalFeatures().hasFeature(Feature.ASYNC_RECEIVE_SERVICE)
			).to.equal(true);
			expect(w2.carol.peerAdvertisesAsyncReceive(w2.lsp.getNodeId())).to.equal(
				true
			);
			const grant = await w2.carol.requestAsyncReceiveGrant(
				w2.lsp.getNodeId(),
				{ timeoutMs: 5_000 }
			);
			expect(grant.lspNodeId.equals(nodeId(w2.lsp))).to.equal(true);
			expect(w2.carol.listAsyncReceiveGrants()).to.have.length(1);
			destroyAll(w2.alice, w2.lsp, w2.carol);
		});
	});

	describe('metrics', () => {
		it('metrics expose occupied slots, held value, oldest hold, admission refusals, releases and expiries', async function () {
			this.timeout(20_000);
			const w = await setupWorld({
				lspService: { enabled: true, maxPartsPerReceiver: 2 },
				carolAutoRelease: true
			});
			const { alice, lsp, carol } = w;
			const before = lsp.getAsyncReceiveServiceMetrics();
			expect(before).to.deep.include({
				enabled: true,
				registrations: 1,
				occupiedSlots: 0,
				heldValueMsat: '0',
				heldBytes: 0,
				oldestHoldAt: null,
				admissionRefusals: 0,
				releases: 0,
				expiries: 0
			});
			await disconnect(lsp, carol, w.cutBC);
			const a = await payAndSettle(w, 2_000_000n);
			const b = await payAndSettle(w, 3_000_000n);
			await payAndSettle(w, 1_000_000n);
			const rows = heldRecords(lsp);
			const parked = lsp.getAsyncReceiveServiceMetrics();
			expect(parked.occupiedSlots).to.equal(2);
			expect(parked.heldValueMsat).to.equal(
				rows.reduce((s, r) => s + BigInt(r.incomingAmountMsat), 0n).toString()
			);
			expect(parked.heldBytes).to.equal(2 * HOLD_BYTES);
			expect(parked.oldestHoldAt).to.equal(
				Math.min(...rows.map((r) => r.createdAt))
			);
			expect(parked.admissionRefusals).to.equal(1);
			expect(parked.admissionRefusalsByReason).to.deep.equal({
				receiver_count: 1
			});
			expect(lsp.getNodeInfo().asyncReceiveService).to.deep.equal(parked);

			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					[a, b].every(
						(inv) =>
							carol.getPayment(inv.paymentHash)?.status ===
							PaymentStatus.COMPLETED
					),
				'both holds to release'
			);
			expect(lsp.getAsyncReceiveServiceMetrics()).to.deep.include({
				occupiedSlots: 0,
				heldValueMsat: '0',
				oldestHoldAt: null,
				releases: 2,
				expiries: 0
			});

			await disconnect(lsp, carol, w.cutBC);
			const c = await payAndSettle(w, 1_000_000n);
			const row = heldRecords(lsp).find(
				(r) => r.paymentHashHex === c.paymentHash.toString('hex')
			)!;
			lsp.handleNewBlock(row.cutoffHeight);
			await waitFor(
				() => alice.getPayment(c.paymentHash)?.status === PaymentStatus.FAILED,
				'the cutoff to fail the hold'
			);
			expect(lsp.getAsyncReceiveServiceMetrics()).to.deep.include({
				occupiedSlots: 0,
				releases: 2,
				expiries: 1
			});
			destroyAll(alice, lsp, carol);
		});
	});

	describe('abuse', () => {
		it("abusive registrations are refused: no channel, someone else's channel, spoofed sender, replay", async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolRegisters: false });
			const { alice, lsp, carol } = w;
			const mallory = createNode(MALLORY_SEED);
			wire(mallory, lsp, { val: false });
			const malloryReplies = tapOnion(lsp, mallory);
			// Mallory has no channel with the LSP.
			sendRawRequest(mallory, lsp, {});
			// Mallory names Carol's channel as hers.
			sendRawRequest(mallory, lsp, { scid: w.scidBC });
			// Mallory claims to be Carol.
			sendRawRequest(mallory, lsp, {
				receiverNodeId: nodeId(carol),
				scid: w.scidBC
			});
			// Mallory asks another LSP through this one.
			sendRawRequest(mallory, lsp, { lspNodeId: nodeId(mallory) });
			// Mallory on the wrong chain.
			sendRawRequest(mallory, lsp, { chainHash: BITCOIN_CHAIN_HASH });
			// Garbage.
			mallory
				.getOnionMessageManager()
				.sendOnionMessage(
					nodeId(lsp),
					new Map([[ASYNC_REGISTRATION_REQUEST_TLV_TYPE, Buffer.alloc(7, 1)]])
				);
			await settle();
			expect(w.registrationRefusals).to.deep.equal([
				'unknown_channel',
				'channel_peer_mismatch',
				'sender_mismatch',
				'wrong_lsp',
				'wrong_network',
				'malformed'
			]);
			expect(malloryReplies, 'every refusal answered').to.have.length(6);
			expect(lsp.listAsyncReceiveRegistrations()).to.have.length(0);
			expect(lsp.getAsyncReceiveServiceMetrics().registrationRefusals).to.equal(
				6
			);

			// Carol registers; Mallory replays Carol's captured request from
			// her own connection: the sender no longer matches.
			const captured = tapOnion(carol, lsp);
			await carol.requestAsyncReceiveGrant(lsp.getNodeId(), {
				timeoutMs: 5_000
			});
			expect(captured).to.have.length(1);
			lsp.handlePeerMessage(
				mallory.getNodeId(),
				MessageType.ONION_MESSAGE,
				captured[0]
			);
			await settle();
			expect(w.registrationRefusals.slice(-1)).to.deep.equal([
				'sender_mismatch'
			]);
			// A renewal from Carol supersedes her old registration rather than
			// adding a second one.
			await carol.requestAsyncReceiveGrant(lsp.getNodeId(), {
				timeoutMs: 5_000
			});
			const regs = lsp.listAsyncReceiveRegistrations();
			expect(regs.map((r) => r.state).sort()).to.deep.equal([
				'ACTIVE',
				'REVOKED'
			]);
			expect(regs.find((r) => r.state === 'REVOKED')!.revokedReason).to.equal(
				'superseded'
			);
			// Mallory cannot hand Carol a grant Carol never asked for.
			const unsolicited = forgeGrant(w, {}, nodePrivkey(LSP_SEED));
			const carolGrantsBefore = carol
				.listAsyncReceiveGrants()
				.map((g) => g.registrationId.toString('hex'));
			mallory
				.getOnionMessageManager()
				.sendOnionMessage(
					nodeId(carol),
					new Map([
						[
							ASYNC_REGISTRATION_REPLY_TLV_TYPE,
							Buffer.concat([Buffer.from([1]), unsolicited])
						]
					])
				);
			await settle();
			expect(
				carol
					.listAsyncReceiveGrants()
					.map((g) => g.registrationId.toString('hex'))
			).to.deep.equal(carolGrantsBefore);
			destroyAll(alice, lsp, carol, mallory);
		});
	});

	describe('privacy', () => {
		it('a refused admission on a blinded path is invalid_onion_blinding whatever the reason', async function () {
			this.timeout(20_000);
			const w = await setupWorld({
				lspService: { enabled: true, maxPartsPerReceiver: 1 },
				carolAutoRelease: false
			});
			const { alice, lsp, carol } = w;
			const failures: number[] = [];
			lsp.on('message:outbound', (pk: string, type: number) => {
				if (pk === alice.getNodeId()) failures.push(type);
			});
			await disconnect(lsp, carol, w.cutBC);
			// First reason: the receiver's slot is taken.
			await payAndSettle(w, 1_000_000n);
			const overCount = await payAndSettle(w, 1_000_000n);
			await waitFor(
				() =>
					alice.getPayment(overCount.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the over-count part to fail'
			);
			// Second reason: the registration is unknown.
			carol.importAsyncReceiveGrant(forgeGrant(w, {}, nodePrivkey(LSP_SEED)));
			const unknown = await payAndSettle(w, 1_000_000n);
			await waitFor(
				() =>
					alice.getPayment(unknown.paymentHash)?.status ===
					PaymentStatus.FAILED,
				'the unregistered part to fail'
			);
			expect(w.admissionRefusals).to.deep.equal([
				'receiver_count',
				'unknown_registration'
			]);
			for (const hash of [overCount.paymentHash, unknown.paymentHash]) {
				const p = alice.getPayment(hash)!;
				expect(p.failureCode, 'the blinded-path failure').to.equal(
					INVALID_ONION_BLINDING
				);
				expect(p.failureSourceIndex, 'attributed to the intro node').to.equal(
					0
				);
			}
			// The intro node fails with update_fail_htlc (an encrypted failure
			// the payer decrypts), never a malformed report, and no other
			// message type reached the payer for either refusal.
			expect(failures).to.include(MessageType.UPDATE_FAIL_HTLC);
			expect(failures).to.not.include(MessageType.UPDATE_FAIL_MALFORMED_HTLC);
			expect(unresolvedCount(lsp), 'the one admitted hold').to.equal(1);
			destroyAll(alice, lsp, carol);
		});
	});
});
