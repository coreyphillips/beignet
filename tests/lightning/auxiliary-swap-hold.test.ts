/**
 * Issue #2093: a swap is not funded against a held asset HTLC.
 *
 * The swap provider pays bitcoin out on the chain once the hold invoice of
 * a swap holds its full amount, which it reads from the node's snapshot of
 * the held set. An asset HTLC is held for what the host said its units are
 * worth, so a set with one could read as the full amount in bitcoin. The
 * snapshot the swap provider is given says such a set is not complete, and
 * the node's own snapshot and the snapshot of an ordinary hold are what
 * they were.
 */

import { expect } from 'chai';
import { createHash } from 'crypto';
import fs from 'fs';
import path from 'path';
import type { IHeldInvoiceSnapshot } from '../../src/lightning/node/types';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	payAssetUnits,
	turns,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';

describe('a swap and a held asset HTLC (issue #2093 step 8)', function () {
	this.timeout(60_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			try {
				host.node.destroy();
			} catch {
				// already destroyed
			}
		}
	});

	const sha = (data: Buffer | string): Buffer =>
		createHash('sha256').update(data).digest();

	/** The snapshot of a held set as the swap provider is given it. */
	const forSwap = (
		host: IAssetHost,
		paymentHash: Buffer
	): IHeldInvoiceSnapshot | null =>
		(
			host.node as unknown as {
				swapHeldSnapshot: (hash: Buffer) => IHeldInvoiceSnapshot | null;
			}
		).swapHeldSnapshot(paymentHash);

	it('reads a hold invoice paid in full by an asset HTLC as not complete, and one paid in bitcoin between the same nodes as it was', async () => {
		const alice = assetHost('swap-hold', 1);
		const bob = assetHost('swap-hold', 2, {
			// An HTLC without units is not the host's to value.
			valueIncomingHtlc: (context) =>
				context.auxiliaryAmount === undefined
					? undefined
					: context.auxiliaryAmount * 1000n
		});
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag: 'swap-hold',
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		openReadyChannel(alice.node, bob.node);

		const units = sha(sha('swap-hold units'));
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'held units',
			hold: true,
			paymentHash: units
		});
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);
		// The node's own read: one committed part, for the whole amount.
		const own = bob.node.getHeldInvoiceSnapshot(units)!;
		expect(own.state).to.equal('ACCEPTED');
		expect(own.parts).to.have.length(1);
		expect(own.committedMsat).to.equal(5_000_000n);
		expect(own.complete).to.equal(true);
		// The swap provider's: the same set, and not one to fund against.
		expect(forSwap(bob, units)).to.deep.equal({ ...own, complete: false });

		const bitcoin = sha(sha('swap-hold bitcoin'));
		const ordinary = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'held bitcoin',
			hold: true,
			paymentHash: bitcoin
		});
		alice.node.sendPayment(ordinary.bolt11);
		await turns(200);
		const plain = bob.node.getHeldInvoiceSnapshot(bitcoin)!;
		expect(plain.complete).to.equal(true);
		expect(forSwap(bob, bitcoin)).to.deep.equal(plain);
		// A hash nothing is held for, and one that is no hold invoice.
		expect(forSwap(bob, sha('nothing'))).to.equal(null);
	});

	it('is the snapshot the swap provider is wired to', () => {
		const source = fs.readFileSync(
			path.join(__dirname, '../../src/lightning/node/lightning-node.ts'),
			'utf8'
		);
		const wiring = source.slice(source.indexOf('private wireSwapProvider('));
		expect(wiring).to.include(
			'heldSnapshot: (paymentHash) => this.swapHeldSnapshot(paymentHash)'
		);
		expect(wiring).to.not.include('this.getHeldInvoiceSnapshot(paymentHash)');
	});
});
