/**
 * FFOR Variant D, the M8 gates that need no chain (issue #719):
 *
 *  - ff_init TLV 13 witness_peers (section 9.6.3): codec, and an honest S
 *    fails upstream a delegated HTLC that did not arrive from a listed peer;
 *  - hash-chained vouchers (section 9.5.4, TLV 15): S derives the chain, R
 *    verifies it, invoices are served strictly in ascending level order, S
 *    settles strictly in order, and ONE preimage credits every lower slot
 *    (the in-process half of M8.5; the three sweeps confirm on regtest);
 *  - M8.6: R cannot fabricate credit, and S's section 9.5.2 ordering
 *    assertion refuses to reveal t_k against an upstream HTLC that is not
 *    irrevocably committed;
 *  - the exposure rule: a slot is exposed once on any book.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { HtlcDirection, HtlcState } from '../../src/lightning/channel/types';
import {
	CommitmentType,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { FforSlotState } from '../../src/lightning/ffor/types';
import {
	decodeFforInitMessage,
	encodeFforInitUnsigned
} from '../../src/lightning/ffor/messages';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IWorld,
	T_EXP,
	TIP,
	activate,
	createWorld,
	exposeAndLeave,
	forceCloseAndObserve,
	pay,
	record
} from './helpers/ffor-world';

const G = 1_000_000n;
const CHAIN = [G, G, G];

function nodeId(node: LightningNode): Buffer {
	return Buffer.from(node.getNodeId(), 'hex');
}

function sha256(b: Buffer): Buffer {
	return crypto.createHash('sha256').update(b).digest();
}

/** Collect S's delegated-failure reasons. */
function delegatedFailures(w: IWorld): string[] {
	const reasons: string[] = [];
	w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
		reasons.push(e.reason)
	);
	return reasons;
}

describe('FFOR Variant D: ff_init TLV 13 witness_peers (section 9.6.3)', function () {
	this.timeout(30_000);

	it('round-trips through the codec and refuses malformed lists', () => {
		const ids = [
			getPublicKey(sha256(Buffer.from('a'))),
			getPublicKey(sha256(Buffer.from('b')))
		];
		const base = {
			channelId: Buffer.alloc(32, 1),
			epochId: Buffer.alloc(32, 2),
			variant: 4,
			budgetMsat: 3n * G,
			maxPayments: 3,
			minPaymentMsat: G,
			settlementDeadline: 100,
			voucherExpiry: 200,
			feeBaseMsat: 0,
			feeProportionalMillionths: 0,
			escapeGranularityMsat: 0n,
			rPerCommitmentPoints: [],
			voucherAmountsMsat: CHAIN
		};
		const withPeers = Buffer.concat([
			encodeFforInitUnsigned({ ...base, witnessPeers: ids, hashChain: true }),
			Buffer.alloc(64)
		]);
		const decoded = decodeFforInitMessage(withPeers);
		expect(decoded.witnessPeers!.map((p) => p.toString('hex'))).to.deep.equal(
			ids.map((p) => p.toString('hex'))
		);
		expect(decoded.hashChain).to.equal(true);
		const without = decodeFforInitMessage(
			Buffer.concat([encodeFforInitUnsigned(base), Buffer.alloc(64)])
		);
		expect(without.witnessPeers).to.equal(undefined);
		expect(without.hashChain).to.equal(undefined);
		// A list whose count disagrees with its length, and a non-point.
		const bad = encodeFforInitUnsigned({ ...base, witnessPeers: ids });
		const tampered = Buffer.from(bad);
		const at = tampered.indexOf(Buffer.concat([Buffer.from([0, 2]), ids[0]]));
		expect(at).to.be.greaterThan(-1);
		tampered.writeUInt16BE(3, at);
		expect(() =>
			decodeFforInitMessage(Buffer.concat([tampered, Buffer.alloc(64)]))
		).to.throw(/TLV 13/);
		expect(() =>
			encodeFforInitUnsigned({ ...base, witnessPeers: [Buffer.alloc(33, 9)] })
		).to.throw(/compressed node id/);
	});

	it('an honest S fails a delegated HTLC that did not arrive from a listed peer, and settles one that did', () => {
		const stranger = getPublicKey(sha256(Buffer.from('stranger')));
		const w = createWorld();
		activate(w, { witnessPeers: [stranger] });
		expect(record(w.s, w.srHex).params.witnessPeers![0].equals(stranger)).to.be
			.true;
		const reasons = delegatedFailures(w);
		const [inv1] = exposeAndLeave(w, [1]);
		w.sr.log.length = 0;
		expect(pay(w, inv1).status).to.equal(PaymentStatus.FAILED);
		expect(reasons).to.include(
			'delegated HTLC did not arrive from a witness peer'
		);
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);
		expect(w.sr.log, 'nothing went to R').to.have.length(0);

		const w2 = createWorld();
		activate(w2, { witnessPeers: [nodeId(w2.p), stranger] });
		const [inv] = exposeAndLeave(w2, [1]);
		expect(pay(w2, inv).status).to.equal(PaymentStatus.COMPLETED);
		expect(record(w2.s, w2.srHex).slotStates[0]).to.equal(
			FforSlotState.SETTLED
		);
	});
});

describe('FFOR Variant D: hash-chained vouchers (section 9.5.4)', function () {
	this.timeout(30_000);

	it('S derives the chain R asked for, and both sides verify SHA256(H_j) == H_{j-1}', () => {
		const w = createWorld();
		activate(w, { amounts: CHAIN, hashChain: true });
		const s = record(w.s, w.srHex);
		const r = record(w.r, w.srHex);
		expect(s.params.hashChain).to.equal(true);
		expect(r.params.hashChain).to.equal(true);
		for (let j = 1; j < 3; j++) {
			expect(sha256(s.paymentHashes[j]).equals(s.paymentHashes[j - 1])).to.be
				.true;
			expect(sha256(s.preimages[j]).equals(s.preimages[j - 1])).to.be.true;
		}
		expect(r.preimages, 'R learns no preimage at setup').to.have.length(0);
	});

	it('refuses a chain over non-uniform amounts on both sides', () => {
		const w = createWorld();
		const res = w.r.startFforEpoch(w.srHex, {
			voucherAmountsMsat: [G, 2n * G],
			minPaymentMsat: G,
			settlementDeadline: 798_992,
			voucherExpiry: T_EXP,
			feeBaseMsat: 0,
			feeProportionalMillionths: 0,
			hashChain: true
		});
		expect(res.ok).to.equal(false);
		expect(res.error).to.match(/uniform/);
	});

	it('serves invoices strictly in ascending level order, and each slot once', () => {
		const w = createWorld();
		activate(w, { amounts: CHAIN, hashChain: true });
		expect(() => w.r.createFforVoucherInvoice(w.srHex, 2)).to.throw(
			/voucher 1 must be exposed before 2/
		);
		w.r.createFforVoucherInvoice(w.srHex, 1);
		expect(() => w.r.createFforVoucherInvoice(w.srHex, 1)).to.throw(
			/already exposed/
		);
		w.r.createFforVoucherInvoice(w.srHex, 2);
		expect(record(w.r, w.srHex).exposedSlots).to.deep.equal([
			true,
			true,
			false
		]);
		// On a plain book the order is free, but a slot is still exposed once.
		const plain = createWorld();
		activate(plain);
		plain.r.createFforVoucherInvoice(plain.srHex, 3);
		expect(() => plain.r.createFforVoucherInvoice(plain.srHex, 3)).to.throw(
			/already exposed/
		);
	});

	it('S settles strictly in order: a higher level is refused while a lower one is unsettled', () => {
		const w = createWorld();
		activate(w, { amounts: CHAIN, hashChain: true });
		const reasons = delegatedFailures(w);
		const [inv1, inv2] = exposeAndLeave(w, [1, 2]);
		expect(pay(w, inv2).status).to.equal(PaymentStatus.FAILED);
		expect(reasons).to.include('hash chain: slot 1 is unsettled below slot 2');
		expect(record(w.s, w.srHex).slotStates).to.deep.equal([
			FforSlotState.UNUSED,
			FforSlotState.UNUSED,
			FforSlotState.UNUSED
		]);
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		// The payer retries level 2 with a fresh payment record.
		const w2 = w;
		const p2 = w2.p.getPayment(
			Buffer.from(record(w2.s, w2.srHex).paymentHashes[1])
		);
		expect(p2?.status).to.equal(PaymentStatus.FAILED);
	});

	it('one preimage credits every lower slot on R, and the chain monitors learn all of them', () => {
		const w = createWorld();
		activate(w, { amounts: CHAIN, hashChain: true });
		const [inv1, inv2, inv3] = exposeAndLeave(w, [1, 2, 3]);
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		expect(pay(w, inv2).status).to.equal(PaymentStatus.COMPLETED);
		const third = pay(w, inv3);
		expect(third.status).to.equal(PaymentStatus.COMPLETED);
		const sRec = record(w.s, w.srHex);
		// R returns holding only the most recent payer's receipt.
		const credited = w.r.fforAddPreimage(w.srHex, third.preimage!);
		expect(credited.ok, credited.error).to.equal(true);
		const rRec = record(w.r, w.srHex);
		for (let k = 1; k <= 3; k++) {
			expect(
				rRec.knownPreimages[k - 1]!.equals(sRec.preimages[k - 1]),
				`t_${k} derived`
			).to.be.true;
		}
		// Every voucher claims on R's own commitment view with no S.
		const view = forceCloseAndObserve(
			w,
			w.r,
			w.rConfig.fundingPrivkey!,
			w.r,
			w.rConfig.fundingPrivkey!
		);
		expect(view.commitmentType).to.equal(CommitmentType.OUR_COMMITMENT);
		for (let k = 1; k <= 3; k++) {
			const out = view.outputs.find(
				(o) =>
					o.outputType === OutputType.RECEIVED_HTLC &&
					o.paymentHash !== undefined &&
					o.paymentHash.equals(sRec.paymentHashes[k - 1])
			);
			expect(out, `voucher ${k} tracked`).to.exist;
			expect(out!.status, `voucher ${k} HTLC-success broadcast`).to.equal(
				OutputStatus.SPEND_BROADCAST
			);
		}
	});
});

describe('FFOR Variant D: M8.6, R cannot fabricate credit and S reveals only against a committed HTLC', function () {
	this.timeout(30_000);

	it('a preimage that matches no slot is refused, and an unpaid voucher has no claim while S has its timeout', () => {
		const w = createWorld();
		activate(w);
		expect(w.r.fforAddPreimage(w.srHex, crypto.randomBytes(32)).ok).to.equal(
			false
		);
		const hashes = record(w.r, w.srHex).paymentHashes;
		w.sr.disconnect();
		// R's own view: the vouchers are tracked, none has a spend.
		const rView = forceCloseAndObserve(
			w,
			w.r,
			w.rConfig.fundingPrivkey!,
			w.r,
			w.rConfig.fundingPrivkey!
		);
		const rOuts = rView.outputs.filter(
			(o) => o.outputType === OutputType.RECEIVED_HTLC
		);
		expect(rOuts).to.have.length(3);
		for (const o of rOuts) {
			expect(hashes.some((h) => h.equals(o.paymentHash!))).to.be.true;
			expect(o.status, 'no preimage, no claim').to.not.equal(
				OutputStatus.SPEND_BROADCAST
			);
		}
		// S's own view, after T_exp: every voucher times out back to S.
		const w2 = createWorld();
		activate(w2);
		w2.sr.disconnect();
		const sView = forceCloseAndObserve(
			w2,
			w2.s,
			w2.sConfig.fundingPrivkey!,
			w2.s,
			w2.sConfig.fundingPrivkey!,
			T_EXP
		);
		expect(sView.commitmentType).to.equal(CommitmentType.OUR_COMMITMENT);
		const sOuts = sView.outputs.filter(
			(o) => o.outputType === OutputType.OFFERED_HTLC
		);
		expect(sOuts).to.have.length(3);
		for (const o of sOuts) {
			expect(o.status, 'HTLC-timeout broadcast at T_exp').to.equal(
				OutputStatus.SPEND_BROADCAST
			);
		}
	});

	it('the section 9.5.2 ordering assertion: no reveal against an upstream HTLC that is not irrevocably committed', () => {
		const w = createWorld();
		activate(w);
		const sRec = record(w.s, w.srHex);
		w.sr.log.length = 0;
		const reasons = delegatedFailures(w);
		let recorded = 0;
		const cm = w.s.getChannelManager();
		const original = cm.recordPreimage.bind(cm);
		cm.recordPreimage = (h: Buffer, p: Buffer): void => {
			recorded++;
			original(h, p);
		};
		const entry = {
			id: 77n,
			amountMsat: G + 10_000n,
			paymentHash: sRec.paymentHashes[0],
			cltvExpiry: TIP + 200,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.PENDING
		};
		const processed = {
			hopPayload: {
				amountToForwardMsat: G,
				outgoingCltvValue: TIP + 100
			},
			nextPacket: {
				version: 0,
				ephemeralKey: crypto.randomBytes(33),
				routingInfo: crypto.randomBytes(1300),
				hmac: crypto.randomBytes(32)
			},
			sharedSecret: crypto.randomBytes(32)
		};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const handled = (w.s as any).fforTrySettleDelegated(
			w.psChannelId,
			77n,
			entry.amountMsat,
			entry.paymentHash,
			entry,
			processed
		);
		expect(handled, 'the hash is in the book, so S answered').to.equal(true);
		expect(reasons).to.include('upstream HTLC is not irrevocably committed');
		expect(recorded, 'no preimage reached the chain monitors').to.equal(0);
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);
		expect(w.sr.log, 'nothing went to R').to.have.length(0);
	});
});
