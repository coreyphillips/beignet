/**
 * Issue #1036: a BOLT 11 invoice or BOLT 12 offer for another network is
 * refused by decode, validate and pay alike, and a zero amount is refused
 * before any HTLC.
 *
 * Offline suite: the node boots against an unreachable Electrum server and
 * every refusal lands before anything needs a chain, a peer or a channel.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { Network } from '../../src/lightning/invoice/types';
import { encodeOffer } from '../../src/lightning/offer/encode';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const payeeKey = crypto.createHash('sha256').update('payee-1036').digest();

function invoiceFor(network: Network, amountMsat?: bigint): string {
	return encodeInvoice({
		network,
		paymentHash: crypto.randomBytes(32),
		paymentSecret: crypto.randomBytes(32),
		description: 'issue 1036',
		amountMsat,
		payeeNodeKey: getPublicKey(payeeKey),
		privateKey: payeeKey
	});
}

async function refusal(attempt: () => unknown): Promise<BeignetError> {
	try {
		await attempt();
	} catch (err: unknown) {
		expect(err).to.be.instanceOf(BeignetError);
		return err as BeignetError;
	}
	expect.fail('expected a refusal');
}

describe('wrong-network and zero-amount payments are refused (#1036)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1036-'));
		node = await BeignetNode.create({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			...OFFLINE_ELECTRUM
		});
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('decodeInvoice refuses an invoice for another network', async () => {
		const err = await refusal(() =>
			node.decodeInvoice(invoiceFor(Network.MAINNET, 1_000n))
		);
		expect(err.code).to.equal('INVALID_INVOICE');
		expect(err.message).to.contain('network "bc"');
		expect(
			node.decodeInvoice(invoiceFor(Network.REGTEST, 1_000n)).network
		).to.equal(Network.REGTEST);
	});

	it('validatePayment fails an invoice for another network', () => {
		const result = node.validatePayment(invoiceFor(Network.TESTNET, 1_000n));
		expect(result.status).to.equal('FAIL');
		const decode = result.checks.find((c) => c.name === 'INVOICE_DECODE');
		expect(decode?.status).to.equal('FAIL');
		expect(decode?.message).to.contain('network "tb"');
	});

	it('payInvoice refuses an invoice for another network', async () => {
		const err = await refusal(() =>
			node.payInvoice(invoiceFor(Network.MAINNET, 1_000n), 5_000)
		);
		expect(err.code).to.equal('INVALID_PARAMS');
		expect(err.message).to.contain('network "bc"');
		expect(node.listPayments()).to.have.length(0);
	});

	it('payInvoice refuses amountSats 0 on an amountless invoice', async () => {
		const err = await refusal(() =>
			node.payInvoice(invoiceFor(Network.REGTEST), 5_000, undefined, 0)
		);
		expect(err.code).to.equal('INVALID_PARAMS');
		expect(err.message).to.contain('amountMsat must be positive');
		expect(node.listPayments()).to.have.length(0);
	});

	it('payOffer refuses an offer that does not list our chain', async () => {
		// No offer_chains: a mainnet offer.
		const offer = encodeOffer({
			offerId: Buffer.alloc(32),
			description: 'mainnet offer',
			amount: 1_000n,
			issuerId: getPublicKey(payeeKey)
		});
		const err = await refusal(() => node.payOffer(offer, undefined, 5_000, 0));
		expect(err.code).to.equal('INVALID_OFFER');
		expect(err.message).to.contain('offer_chains');
	});
});
