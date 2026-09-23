/**
 * Issue #976: a blocking payment's timeout failed the record while its HTLC
 * could still settle.
 *
 * BeignetNode.payInvoice, sendKeysend and payOffer called failPayment when
 * their wait ran out, whatever the HTLCs were doing. BOLT 2 has no way to
 * retract an update_add_htlc, so the record read FAILED while the HTLC was
 * still out, and a payee who settled after the clock turned it back into
 * COMPLETED; payInvoiceSafe, and the payment queue behind it, reported a
 * failure for a payment that was still being made. The timeouts now fail the
 * record only when nothing is out for it, and the PAYMENT_TIMEOUT says which
 * happened.
 *
 * Offline suite: the node boots against an unreachable Electrum server and
 * the engine's senders are stubbed to leave a PENDING record, so nothing here
 * needs a chain or a channel. Whether an HTLC is in flight is the engine's
 * hasHtlcInFlight, stubbed where a case needs one; the ghost cases use the
 * real predicate, which finds no channel and so no HTLC. payOffer shares the
 * same timeout helper and is not driven here: it needs an invoice request
 * round trip first.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as sinon from 'sinon';
import { BeignetNode } from '../../src/cli/beignet-node';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';
import {
	IPaymentInfo,
	LightningErrorCode,
	LightningPaymentError,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';

// Same rationale as tests/cli/pay-invoice-limits.test.ts: a refused loopback
// connect returns instantly, where the regtest default is a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** The engine behind the node, with what these tests stub, spy on or read. */
type Engine = {
	payments: Map<string, IPaymentInfo>;
	sendPayment: (...args: unknown[]) => unknown;
	sendKeysend: (...args: unknown[]) => unknown;
	hasHtlcInFlight: (paymentHash: Buffer) => boolean;
	failPayment: (paymentHash: Buffer, reason?: string) => void;
	emit: (event: string, info: unknown) => boolean;
	on: (event: string, listener: (info: IPaymentInfo) => void) => unknown;
};

const engineOf = (node: BeignetNode): Engine =>
	(node as unknown as { node: Engine }).node;

/** An invoice from somebody else, which is what a payment path is given. */
const invoiceFrom = (
	amountSats: number,
	description: string
): { bolt11: string; paymentHash: Buffer } => {
	const paymentHash = crypto.randomBytes(32);
	return {
		bolt11: encodeInvoice({
			network: Network.REGTEST,
			amountMsat: BigInt(amountSats) * 1000n,
			timestamp: Math.floor(Date.now() / 1000),
			paymentHash,
			paymentSecret: crypto.randomBytes(32),
			description,
			expiry: 3600,
			minFinalCltvExpiry: DEFAULT_MIN_FINAL_CLTV_EXPIRY,
			privateKey: crypto
				.createHash('sha256')
				.update(Buffer.from(`payee-${description}`))
				.digest()
		}),
		paymentHash
	};
};

/** A PENDING OUTGOING record for the hash, as the engine's senders leave one. */
const pendingRecord = (
	paymentHash: Buffer,
	amountSats: number
): IPaymentInfo => ({
	paymentHash,
	amountMsat: BigInt(amountSats) * 1000n,
	status: PaymentStatus.PENDING,
	direction: PaymentDirection.OUTGOING,
	createdAt: Date.now()
});

/**
 * sendPayment that records a PENDING payment for the hash and returns it, and
 * refuses a second send for the hash as the engine does while one is out.
 */
const stubSendPayment = (
	node: BeignetNode,
	paymentHash: Buffer,
	amountSats: number
): void => {
	const engine = engineOf(node);
	const hashHex = paymentHash.toString('hex');
	engine.sendPayment = (): IPaymentInfo => {
		if (engine.payments.has(hashHex)) {
			throw new LightningPaymentError(
				LightningErrorCode.DUPLICATE_PAYMENT,
				'Payment already in flight for this invoice'
			);
		}
		const record = pendingRecord(paymentHash, amountSats);
		engine.payments.set(hashHex, record);
		return record;
	};
};

/** sendKeysend that records a PENDING payment for a fresh hash and returns it. */
const stubSendKeysend = (node: BeignetNode, amountSats: number): Buffer => {
	const paymentHash = crypto.randomBytes(32);
	const engine = engineOf(node);
	engine.sendKeysend = (): IPaymentInfo => {
		const record = pendingRecord(paymentHash, amountSats);
		engine.payments.set(paymentHash.toString('hex'), record);
		return record;
	};
	return paymentHash;
};

/** The payee settles: the record completes and payment:sent fires, in the engine's order. */
const settle = (node: BeignetNode, paymentHash: Buffer): void => {
	const engine = engineOf(node);
	const record = engine.payments.get(paymentHash.toString('hex'));
	expect(record, 'the record the settlement completes').to.not.equal(undefined);
	record!.status = PaymentStatus.COMPLETED;
	record!.completedAt = Date.now();
	engine.emit('payment:sent', record);
};

/** The code and message an attempt rejected with, or an empty message if it resolved. */
const rejectionOf = async (
	attempt: Promise<unknown>
): Promise<{ code?: string; message: string }> => {
	try {
		await attempt;
		return { message: '' };
	} catch (err: unknown) {
		return {
			code: (err as { code?: string }).code,
			message: err instanceof Error ? err.message : String(err)
		};
	}
};

const IN_FLIGHT_SUFFIX =
	'an HTLC is still in flight and the payment stays PENDING until it resolves';

describe('Issue #976: a payment timeout leaves a record with an HTLC in flight PENDING', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;
	let failedEvents: string[];

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-timeout-976-'));
		node = await BeignetNode.create({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			...OFFLINE_ELECTRUM
		});
		failedEvents = [];
		engineOf(node).on('payment:failed', (info) =>
			failedEvents.push(info.paymentHash.toString('hex'))
		);
	});

	afterEach(async () => {
		sinon.restore();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('payInvoice: with an HTLC still out, the timeout fails nothing, payInvoiceSafe answers PENDING, and the payment completes when the payee settles', async () => {
		const { bolt11, paymentHash } = invoiceFrom(1_000, 'held');
		const hashHex = paymentHash.toString('hex');
		stubSendPayment(node, paymentHash, 1_000);
		const engine = engineOf(node);
		engine.hasHtlcInFlight = (hash): boolean => hash.equals(paymentHash);
		const failPayment = sinon.spy(engine, 'failPayment');

		const rejection = await rejectionOf(node.payInvoice(bolt11, 50));
		expect(rejection.code).to.equal('PAYMENT_TIMEOUT');
		expect(rejection.message).to.equal(
			`Payment timed out after 50ms; ${IN_FLIGHT_SUFFIX}`
		);
		// Before the fix failPayment ran here: the record read FAILED and
		// payment:failed fired while the HTLC was still out.
		expect(failPayment.called, 'failPayment was not called').to.equal(false);
		expect(node.getPayment(hashHex)?.status).to.equal('PENDING');
		expect(failedEvents).to.deep.equal([]);

		// What the payment queue sees when it asks again: the engine refuses
		// the hash as in flight (#975) and the safe wrapper answers with the
		// existing record, which now says PENDING rather than FAILED.
		const safe = await node.payInvoiceSafe(bolt11, 50);
		expect(safe.paymentHash).to.equal(hashHex);
		expect(safe.status).to.equal('PENDING');
		expect(failPayment.called).to.equal(false);

		settle(node, paymentHash);
		expect(node.getPayment(hashHex)?.status).to.equal('COMPLETED');
		expect(failedEvents).to.deep.equal([]);
	});

	it('payInvoice: with nothing out for it, the timeout fails the ghost record as before', async () => {
		const { bolt11, paymentHash } = invoiceFrom(1_000, 'ghost');
		const hashHex = paymentHash.toString('hex');
		stubSendPayment(node, paymentHash, 1_000);
		const engine = engineOf(node);
		const failPayment = sinon.spy(engine, 'failPayment');

		const rejection = await rejectionOf(node.payInvoice(bolt11, 50));
		expect(rejection.code).to.equal('PAYMENT_TIMEOUT');
		expect(rejection.message).to.equal('Payment timed out after 50ms');
		expect(failPayment.calledOnce).to.equal(true);
		expect(failPayment.firstCall.args[0].equals(paymentHash)).to.equal(true);
		expect(node.getPayment(hashHex)?.status).to.equal('FAILED');
		expect(failedEvents).to.deep.equal([hashHex]);
	});

	it('sendKeysend: with an HTLC still out, the timeout fails nothing and the record stays PENDING', async () => {
		const paymentHash = stubSendKeysend(node, 1_000);
		const hashHex = paymentHash.toString('hex');
		const engine = engineOf(node);
		engine.hasHtlcInFlight = (hash): boolean => hash.equals(paymentHash);
		const failPayment = sinon.spy(engine, 'failPayment');

		const rejection = await rejectionOf(
			node.sendKeysend('02' + '11'.repeat(32), 1_000, 50)
		);
		expect(rejection.code).to.equal('PAYMENT_TIMEOUT');
		expect(rejection.message).to.equal(
			`Keysend timed out after 50ms; ${IN_FLIGHT_SUFFIX}`
		);
		expect(failPayment.called).to.equal(false);
		expect(node.getPayment(hashHex)?.status).to.equal('PENDING');
		expect(failedEvents).to.deep.equal([]);

		settle(node, paymentHash);
		expect(node.getPayment(hashHex)?.status).to.equal('COMPLETED');
		expect(failedEvents).to.deep.equal([]);
	});

	it('sendKeysend: with nothing out for it, the timeout fails the ghost record as before', async () => {
		const paymentHash = stubSendKeysend(node, 1_000);
		const hashHex = paymentHash.toString('hex');
		const failPayment = sinon.spy(engineOf(node), 'failPayment');

		const rejection = await rejectionOf(
			node.sendKeysend('02' + '11'.repeat(32), 1_000, 50)
		);
		expect(rejection.code).to.equal('PAYMENT_TIMEOUT');
		expect(rejection.message).to.equal('Keysend timed out after 50ms');
		expect(failPayment.calledOnce).to.equal(true);
		expect(node.getPayment(hashHex)?.status).to.equal('FAILED');
		expect(failedEvents).to.deep.equal([hashHex]);
	});
});
