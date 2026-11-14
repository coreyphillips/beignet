/**
 * Interop: BOLT 11 payment_metadata against LND, CLN and Eclair (issue #1998).
 *
 * Each implementation sends payment_metadata (onion TLV 16) when the invoice
 * it pays has an `m` field, so each pays a beignet invoice issued with
 * metadata; beignet used to reject that onion. Eclair writes `m` into every
 * invoice it issues, so beignet pays one through the ordinary sendPayment
 * path. LND and CLN cannot issue an invoice with `m`, so against LND the
 * payer half sends record 16 to an ordinary invoice over an explicit route:
 * LND has to accept the record and settle.
 *
 * Each block skips when its container is not running.
 * Run: docker compose -f docker/docker-compose.yml up -d
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LndRestClient } from './lnd-client';
import {
	requireLnd,
	waitForLndSync,
	cleanupLndState,
	setupLndChannel,
	bitcoinRpc,
	sleep
} from './helpers';
import type { LightningNode } from '../../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../../src/lightning/node/types';
import type { IHopPayload } from '../../../src/lightning/onion/types';
import { decode as decodeInvoice } from '../../../src/lightning/invoice/decode';
import type { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	setupClnChannel
} from './cln-helpers';
import type { EclairRestClient } from './eclair-client';
import {
	isEclairAvailable,
	createEclairClient,
	waitForEclairSync,
	waitForEclairPayment,
	setupEclairChannel,
	setupRoutingForChannel
} from './eclair-helpers';

/** Every final payload the node's receive path is handed. */
function captureFinalPayloads(node: LightningNode): IHopPayload[] {
	const seen: IHopPayload[] = [];
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const n = node as any;
	const original = n.handleFinalHopHtlc.bind(n);
	n.handleFinalHopHtlc = (...args: unknown[]): void => {
		seen.push(args[4] as IHopPayload);
		original(...args);
	};
	return seen;
}

async function waitForStatus(
	node: LightningNode,
	paymentHash: Buffer,
	timeoutMs = 30_000
): Promise<PaymentStatus | undefined> {
	const start = Date.now();
	for (;;) {
		const status = node.getPayment(paymentHash)?.status;
		if (status !== PaymentStatus.PENDING && status !== undefined) {
			return status;
		}
		if (Date.now() - start > timeoutMs) return status;
		await sleep(250);
	}
}

describe('Interop: payment_metadata with LND (regtest)', function () {
	this.timeout(120_000);

	let lnd: LndRestClient;
	let lndPubkey: string;
	let node: LightningNode | undefined;

	before(async function () {
		lnd = await requireLnd(this, 'payment-metadata');
		await waitForLndSync(lnd);
		lndPubkey = (await lnd.getInfo()).identity_pubkey;
		await cleanupLndState(lnd);
	});

	afterEach(function () {
		node?.destroy();
		node = undefined;
	});

	it('LND pays a beignet invoice that carries an m field', async function () {
		const setup = await setupLndChannel(lnd, lndPubkey, 1998, 500_000, 0);
		node = setup.node;
		const seen = captureFinalPayloads(node);

		const metadata = crypto.randomBytes(64);
		const invoice = node.createInvoice({
			amountMsat: 10_000_000n,
			description: 'payment_metadata interop',
			paymentMetadata: metadata
		});

		const result = await lnd.sendPaymentSync(invoice.bolt11);
		expect(result.payment_error || '').to.equal('');
		expect(seen.length).to.be.at.least(1);
		for (const payload of seen) {
			expect(payload.paymentMetadata).to.deep.equal(metadata);
		}
		expect(await waitForStatus(node, invoice.paymentHash)).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('LND settles a beignet HTLC whose final payload carries record 16', async function () {
		const setup = await setupLndChannel(lnd, lndPubkey, 1999, 500_000, 200_000);
		node = setup.node;

		// The HTLC expiry is relative to our height, and LND refuses one
		// below its own height plus the invoice's final delta.
		node.handleNewBlock((await bitcoinRpc('getblockcount')) as number);
		const lndInvoice = await lnd.addInvoice(10_000, 'record 16 from beignet');
		const decoded = decodeInvoice(lndInvoice.payment_request);
		const finalCltv = (decoded.minFinalCltvExpiry ?? 18) + 3;

		node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(lndPubkey, 'hex'),
						// Final hop: no scid goes on the wire, and the channel is
						// picked by peer.
						shortChannelId: Buffer.alloc(8),
						amountToForwardMsat: 10_000_000n,
						outgoingCltvValue: finalCltv
					}
				]
			},
			decoded.paymentHash,
			finalCltv,
			decoded.paymentSecret,
			10_000_000n,
			undefined,
			undefined,
			Buffer.from('beignet payment_metadata')
		);

		const status = await waitForStatus(node, decoded.paymentHash);
		const record = node.getPayment(decoded.paymentHash);
		expect(
			status,
			`failureCode ${record?.failureCode} ${record?.failureReason ?? ''}`
		).to.equal(PaymentStatus.COMPLETED);
		const settled = await lnd.lookupInvoice(
			decoded.paymentHash.toString('hex')
		);
		expect(settled.settled || settled.state === 'SETTLED').to.equal(true);
	});
});

describe('Interop: payment_metadata with CLN (regtest)', function () {
	this.timeout(120_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let node: LightningNode | undefined;

	before(async function () {
		if (!(await isClnAvailable())) {
			console.log('    [skip] CLN container not reachable');
			this.skip();
		}
		cln = (await createClnClient())!;
		await waitForClnSync(cln);
		clnPubkey = ((await cln.getInfo()) as unknown as { id: string }).id;
	});

	afterEach(function () {
		node?.destroy();
		node = undefined;
	});

	it('CLN pays a beignet invoice that carries an m field', async function () {
		const setup = await setupClnChannel(cln, clnPubkey, 2000, 500_000);
		node = setup.node;
		const seen = captureFinalPayloads(node);

		const metadata = crypto.randomBytes(64);
		const invoice = node.createInvoice({
			amountMsat: 10_000_000n,
			description: 'payment_metadata interop',
			paymentMetadata: metadata
		});

		const result = await cln.pay(invoice.bolt11);
		expect(result.payment_preimage).to.be.a('string').that.is.not.empty;
		expect(seen.length).to.be.at.least(1);
		for (const payload of seen) {
			expect(payload.paymentMetadata).to.deep.equal(metadata);
		}
		expect(await waitForStatus(node, invoice.paymentHash)).to.equal(
			PaymentStatus.COMPLETED
		);
	});
});

describe('Interop: payment_metadata with Eclair (regtest)', function () {
	this.timeout(240_000);

	let eclair: EclairRestClient;
	let eclairPubkey: string;
	let node: LightningNode | undefined;

	before(async function () {
		if (!(await isEclairAvailable())) {
			console.log('    [skip] Eclair container not reachable');
			this.skip();
		}
		eclair = (await createEclairClient())!;
		await waitForEclairSync(eclair);
		eclairPubkey = (await eclair.getInfo()).nodeId;
		// Eclair opens and pushes half, so both directions have balance.
		const setup = await setupEclairChannel(
			eclair,
			eclairPubkey,
			2001,
			500_000,
			250_000_000
		);
		node = setup.node;
		setupRoutingForChannel(node, eclairPubkey);
		node.handleNewBlock((await bitcoinRpc('getblockcount')) as number);
	});

	after(function () {
		node?.destroy();
		node = undefined;
	});

	it('beignet pays an Eclair invoice that carries an m field', async function () {
		const eclairInvoice = await eclair.createInvoice(
			10_000_000,
			'payment_metadata from Eclair'
		);
		const decoded = decodeInvoice(eclairInvoice.serialized);
		expect(decoded.metadata, 'Eclair wrote an m field').to.be.instanceOf(
			Buffer
		);

		// The payment's final payload is built from this argument.
		const sentMetadata: Array<Buffer | undefined> = [];
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const n = node as any;
		const original = n.sendPaymentToRoute.bind(n);
		n.sendPaymentToRoute = (...args: unknown[]): unknown => {
			sentMetadata.push(args[7] as Buffer | undefined);
			return original(...args);
		};

		node!.sendPayment(eclairInvoice.serialized);
		const status = await waitForStatus(node!, decoded.paymentHash);
		const record = node!.getPayment(decoded.paymentHash);
		expect(
			status,
			`failureCode ${record?.failureCode} ${record?.failureReason ?? ''}`
		).to.equal(PaymentStatus.COMPLETED);
		expect(sentMetadata.length).to.be.at.least(1);
		for (const m of sentMetadata) {
			expect(m).to.deep.equal(decoded.metadata);
		}
		const received = await eclair.getInvoice(
			decoded.paymentHash.toString('hex')
		);
		expect(received.status.type).to.equal('received');
	});

	it('Eclair pays a beignet invoice that carries an m field', async function () {
		const seen = captureFinalPayloads(node!);
		const metadata = crypto.randomBytes(64);
		const invoice = node!.createInvoice({
			amountMsat: 10_000_000n,
			description: 'payment_metadata interop',
			paymentMetadata: metadata
		});

		await eclair.payInvoice(invoice.bolt11);
		const result = await waitForEclairPayment(
			eclair,
			invoice.paymentHash.toString('hex'),
			60_000
		);
		expect(result.success, result.error).to.equal(true);
		expect(seen.length).to.be.at.least(1);
		for (const payload of seen) {
			expect(payload.paymentMetadata).to.deep.equal(metadata);
		}
		expect(await waitForStatus(node!, invoice.paymentHash)).to.equal(
			PaymentStatus.COMPLETED
		);
	});
});
