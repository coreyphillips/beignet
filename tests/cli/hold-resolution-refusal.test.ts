/**
 * settleHoldInvoice / cancelHoldInvoice on a hold whose parts are still
 * parked (issue #823). The engine answers false/null both for a hash with
 * nothing parked and for a set a channel refused, and the CLI used to call
 * both NOT_FOUND: a caller told the hold is gone may switch to the other
 * action or give up on a payment that is settling.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError, isRetryableError } from '../../src/cli/errors';
import { statusForErrorCode } from '../../src/cli/daemon';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	buildGraph,
	connectNodes,
	createNode,
	makeExternalHash,
	openReadyChannel,
	scidForIndex
} from '../lightning/helpers/loopback-nodes';

const TAG = 'hold-823';

/** A BeignetNode over the given engine; the prototype keeps helpers resolvable. */
function cliOver(engine: unknown): BeignetNode {
	return Object.assign(Object.create(BeignetNode.prototype), {
		node: engine
	}) as unknown as BeignetNode;
}

function errorFrom(fn: () => unknown): BeignetError {
	try {
		fn();
	} catch (err: unknown) {
		expect(err).to.be.instanceOf(BeignetError);
		return err as BeignetError;
	}
	expect.fail('expected the call to throw');
}

/** Bob holds a two-part MPP payment from Alice, one part per channel. */
function parkTwoParts(): {
	alice: LightningNode;
	bob: LightningNode;
	cli: BeignetNode;
	preimage: Buffer;
	hash: Buffer;
} {
	const alice = createNode(TAG, 1);
	const bob = createNode(TAG, 2);
	connectNodes(alice, bob);
	const channels = [
		openReadyChannel(alice, bob, 100_000n),
		openReadyChannel(alice, bob, 100_000n)
	];
	buildGraph(alice, bob, channels, 100_000_000n);
	const cli = cliOver(bob);
	const { preimage, hash } = makeExternalHash();
	const totalMsat = 90_000_000n;
	const invoice = cli.createHoldInvoice({
		paymentHash: hash.toString('hex'),
		amountMsat: totalMsat
	});
	channels.forEach((_channelId, i) => {
		alice.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.getNodeId(), 'hex'),
						shortChannelId: scidForIndex(i),
						amountToForwardMsat: totalMsat / 2n,
						outgoingCltvValue: 40
					}
				]
			},
			hash,
			40,
			Buffer.from(invoice.paymentSecret!, 'hex'),
			totalMsat
		);
	});
	expect(bob.listHeldHtlcs()[0]?.htlcCount).to.equal(2);
	return { alice, bob, cli, preimage, hash };
}

describe('Hold settle and cancel on a hold with parts still parked (#823)', function () {
	it('reports a refused settle and cancel as pending, not NOT_FOUND', function () {
		const { alice, bob, cli, preimage, hash } = parkTwoParts();
		// AWAITING_REESTABLISH refuses every fulfil and every fail.
		bob.getChannelManager().handlePeerDisconnected(alice.getNodeId());

		for (const call of [
			(): unknown => cli.settleHoldInvoice(preimage.toString('hex')),
			(): unknown => cli.cancelHoldInvoice(hash.toString('hex'))
		]) {
			const err = errorFrom(call);
			expect(err.code).to.equal('HOLD_RESOLUTION_PENDING');
			expect(err.message).to.include('2 parked HTLC(s)');
			expect(statusForErrorCode(err.code)).to.equal(503);
			expect(isRetryableError(err)).to.equal(true);
		}
		expect(bob.listHeldHtlcs()[0]?.htlcCount).to.equal(2);
		expect(cli.listHoldInvoices()[0].state).to.equal('ACCEPTED');
	});

	it('reports a settle or cancel that left some parts parked as pending', function () {
		// The engine's answer once a channel accepted one part and refused the
		// other (#810): false/null, with the refused part still parked.
		const hash = makeExternalHash();
		const cli = cliOver({
			settleHeldHtlc: () => false,
			cancelHoldInvoice: () => null,
			listHeldHtlcs: () => [
				{ paymentHash: hash.hash, amountMsat: 45_000_000n, htlcCount: 1 }
			]
		});

		for (const call of [
			(): unknown => cli.settleHoldInvoice(hash.preimage.toString('hex')),
			(): unknown => cli.cancelHoldInvoice(hash.hash.toString('hex'))
		]) {
			const err = errorFrom(call);
			expect(err.code).to.equal('HOLD_RESOLUTION_PENDING');
			expect(err.message).to.include('1 parked HTLC(s)');
		}
	});

	it('keeps NOT_FOUND for a hash with nothing parked and no open hold invoice', function () {
		const { cli } = parkTwoParts();
		const unknown = makeExternalHash();

		const settle = errorFrom(() =>
			cli.settleHoldInvoice(unknown.preimage.toString('hex'))
		);
		expect(settle.code).to.equal('NOT_FOUND');
		const cancel = errorFrom(() =>
			cli.cancelHoldInvoice(unknown.hash.toString('hex'))
		);
		expect(cancel.code).to.equal('NOT_FOUND');
	});
});
