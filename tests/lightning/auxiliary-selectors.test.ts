/**
 * Asset channels and the node's ways in for a bitcoin payment (issue #2093).
 *
 * An asset channel is no way in for an ordinary payment: it gives no
 * cleartext routing hint and no blinded payment path, an invoice made over
 * it alone is not reported as missing hints it was never owed, its SCID is
 * not named for a held (async) payment, and its remote balance is not
 * inbound a JIT payment is measured against. An ordinary channel beside it
 * is offered as it always was.
 */

import { expect } from 'chai';
import {
	assetHost,
	connectHosts,
	IAssetHost,
	openAssetChannel,
	withAssetOpens
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';

/** The private selectors this suite asks. */
interface ISelectors {
	buildBlindedPaymentPaths(): unknown[];
	getPrivateChannelRoutingHints(): unknown[][];
	asyncReceiveScidFor(peerHex: string): Buffer | null;
	jitShareCrossingLspMsat(
		lspPubkeyHex: string,
		amountMsat: bigint
	): bigint | undefined;
}

const selectors = (host: IAssetHost): ISelectors =>
	host.node as unknown as ISelectors;

describe('An asset channel is no way in for a bitcoin payment (#2093)', function () {
	this.timeout(60_000);
	withAssetOpens();

	const hosts: IAssetHost[] = [];

	afterEach(() => {
		for (const host of hosts.splice(0)) host.node.destroy();
	});

	const pair = async (
		tag: string
	): Promise<{ alice: IAssetHost; bob: IAssetHost; channelId: Buffer }> => {
		const alice = assetHost(tag, 1);
		const bob = assetHost(tag, 2, { valueIncomingHtlc: () => undefined });
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		return { alice, bob, channelId };
	};

	it('offers no blinded payment path and no routing hint over an asset channel, and both over an ordinary channel beside it', async () => {
		const { alice, bob } = await pair('aux-ways-in');
		expect(selectors(bob).buildBlindedPaymentPaths()).to.have.length(0);
		expect(selectors(bob).getPrivateChannelRoutingHints()).to.have.length(0);

		openReadyChannel(alice.node, bob.node);
		expect(selectors(bob).buildBlindedPaymentPaths()).to.have.length(1);
		expect(selectors(bob).getPrivateChannelRoutingHints()).to.have.length(1);
	});

	it('does not report an invoice over an asset channel alone as missing its routing hints', async () => {
		const { alice, bob } = await pair('aux-no-hints');
		bob.node.createInvoice({ amountMsat: 1_000_000n, description: 'asset' });
		expect(bob.errors.filter((error) => error.startsWith('NO_ROUTING_HINTS')))
			.to.be.empty;
		// An ordinary channel gets its hint, so nothing is reported either.
		openReadyChannel(alice.node, bob.node);
		bob.node.createInvoice({ amountMsat: 1_000_000n, description: 'both' });
		expect(bob.errors.filter((error) => error.startsWith('NO_ROUTING_HINTS')))
			.to.be.empty;
	});

	it('names no SCID of an asset channel for a held payment, and counts none of its balance as inbound', async () => {
		const { alice, bob } = await pair('aux-inbound');
		const aliceId = alice.node.getNodeId();
		const lsp = `02${'22'.repeat(32)}`;
		expect(selectors(bob).asyncReceiveScidFor(aliceId)).to.equal(null);
		// With no other inbound, the whole amount crosses the LSP.
		expect(selectors(bob).jitShareCrossingLspMsat(lsp, 100_000n)).to.equal(
			100_000n
		);

		openReadyChannel(alice.node, bob.node);
		expect(selectors(bob).asyncReceiveScidFor(aliceId)).to.not.equal(null);
	});
});
