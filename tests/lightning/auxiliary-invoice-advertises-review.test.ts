/**
 * Issue #2098, step 10: what an asset invoice advertises, in the cases the
 * independent review of the change raised. A peer's own bound on the asset
 * HTLCs it offers at once, a host that values no asset HTLC, more hints than
 * one invoice holds, and the ordinary channel a refused hint ends over.
 */

import { expect } from 'chai';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import type { IRoutingHintHop } from '../../src/lightning/invoice/types';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import type { ICreateInvoiceOptions } from '../../src/lightning/node/types';
import {
	assetInvoiceOptions,
	assetRefusal,
	featureBitsOf,
	hintsOf,
	refusalOf
} from './helpers/auxiliary-invoice';
import {
	RECEIVE_IN_PARTS,
	assetHost,
	connectHosts,
	openAssetChannel,
	turns,
	withAssetOpens,
	withAssetPartsReceived,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { hash } from './helpers/auxiliary-pair';
import { sha256 } from './helpers/auxiliary-parts-checks';
import { openReadyChannel } from './helpers/loopback-nodes';

/** basic_mpp as an invoice sets it: the optional bit. */
const BASIC_MPP_BIT = 17;
const QUOTE_SCID = Buffer.from('000a2e0000210001', 'hex');

const valued: Partial<IAuxiliaryChannelConfig> = {
	valueIncomingHtlc: (context) =>
		context.auxiliaryAmount === undefined
			? undefined
			: context.auxiliaryAmount * 1000n
};

describe('an asset invoice (issue #2098, step 10), in the cases its review raised', function () {
	this.timeout(120_000);
	withAssetOpens();
	withAssetPartsReceived();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			try {
				host.node.destroy();
			} catch {
				// already destroyed
			}
			try {
				host.storage?.close();
			} catch {
				// already closed
			}
		}
	});

	/** Alice, the peer, opens an asset channel to Bob, who makes the invoice. */
	async function pair(
		tag: string,
		alicesHooks: Partial<IAuxiliaryChannelConfig>,
		bobsHooks: Partial<IAuxiliaryChannelConfig>
	): Promise<{ alice: IAssetHost; bob: IAssetHost; channelId: Buffer }> {
		const alice = assetHost(tag, 1, alicesHooks, { sqlite: true });
		const bob = assetHost(tag, 2, bobsHooks, { sqlite: true });
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		await turns(20);
		return { alice, bob, channelId };
	}

	const idOf = (host: IAssetHost): Buffer =>
		Buffer.from(host.node.getNodeId(), 'hex');

	const hop = (pubkey: Buffer, shortChannelId: Buffer): IRoutingHintHop => ({
		pubkey,
		shortChannelId,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		cltvExpiryDelta: 40
	});

	const invoiceOptions = (
		hints: IRoutingHintHop[][],
		extra: Partial<ICreateInvoiceOptions> = {}
	): ICreateInvoiceOptions =>
		assetInvoiceOptions({
			amountMsat: 5_000_000n,
			description: 'an asset invoice',
			extraRoutingHints: hints,
			...extra
		});

	it('offers no basic_mpp through a peer whose asset channel holds one HTLC at once toward the node, as its host set maxHtlcs: 1, and offers it through a peer at the default', async () => {
		const bound = await pair(
			'asset-invoice-review-peer-bound',
			{ maxHtlcs: 1 },
			{ ...valued, ...RECEIVE_IN_PARTS }
		);
		const state = bound.bob.node
			.getChannelManager()
			.getChannel(bound.channelId)!
			.getFullState();
		expect(state.localConfig.maxAcceptedHtlcs).to.be.at.least(2);
		expect(state.remoteConfig.maxAcceptedHtlcs).to.equal(1);
		const through = bound.bob.node.createInvoice(
			invoiceOptions([[hop(idOf(bound.alice), QUOTE_SCID)]])
		);
		expect(featureBitsOf(through.bolt11)).to.not.include(BASIC_MPP_BIT);

		const free = await pair(
			'asset-invoice-review-peer-default',
			{},
			{ ...valued, ...RECEIVE_IN_PARTS }
		);
		const made = free.bob.node.createInvoice(
			invoiceOptions([[hop(idOf(free.alice), QUOTE_SCID)]])
		);
		expect(featureBitsOf(made.bolt11)).to.include(BASIC_MPP_BIT);
	});

	it('is refused on a node whose host values no asset HTLC (no valueIncomingHtlc), before anything is kept', async () => {
		const s = await pair(
			'asset-invoice-review-no-valuation',
			{},
			{
				...RECEIVE_IN_PARTS
			}
		);
		const before = s.bob.node.listInvoices().length;
		const paymentHash = sha256(hash('asset-invoice-review-no-valuation'));
		expect(
			refusalOf(() =>
				s.bob.node.createInvoice(
					invoiceOptions([[hop(idOf(s.alice), QUOTE_SCID)]], {
						hold: true,
						paymentHash
					})
				)
			)
		).to.deep.equal(assetRefusal('ASSET_INVOICE_UNSUPPORTED', 'assetInvoice'));
		expect(s.bob.node.listInvoices().length).to.equal(before);
		expect(s.bob.node.paymentHashInUse(paymentHash)).to.equal(false);
	});

	it('takes at most 20 hints: 21 are refused before anything is kept, and 20 of 12 hops make an invoice that carries them all', async () => {
		const s = await pair(
			'asset-invoice-review-many-hints',
			{},
			{
				...valued,
				...RECEIVE_IN_PARTS
			}
		);
		const longHint = (n: number): IRoutingHintHop[] => [
			...Array.from({ length: 11 }, (_, i) =>
				hop(
					getPublicKey(hash(`asset-invoice-review hop ${n} ${i}`)),
					Buffer.alloc(8, i + 1)
				)
			),
			hop(idOf(s.alice), QUOTE_SCID)
		];
		const hints = (count: number): IRoutingHintHop[][] =>
			Array.from({ length: count }, (_, n) => longHint(n));
		const before = s.bob.node.listInvoices().length;
		const paymentHash = sha256(hash('asset-invoice-review-many-hints'));
		expect(
			refusalOf(() =>
				s.bob.node.createInvoice(
					invoiceOptions(hints(21), { hold: true, paymentHash })
				)
			)
		).to.deep.equal(assetRefusal('ASSET_INVOICE_INVALID', 'extraRoutingHints'));
		expect(s.bob.node.listInvoices().length).to.equal(before);
		expect(s.bob.node.paymentHashInUse(paymentHash)).to.equal(false);

		const made = s.bob.node.createInvoice(
			invoiceOptions(hints(20), { hold: true, paymentHash })
		);
		const carried = hintsOf(made.bolt11);
		expect(carried).to.have.length(20);
		expect(carried.every((hint) => hint.length === 12)).to.equal(true);
	});

	it('names the ordinary channel a refused hint ends over: its short channel id and its channel id', async () => {
		const s = await pair(
			'asset-invoice-review-names',
			{},
			{
				...valued,
				...RECEIVE_IN_PARTS
			}
		);
		const ordinaryId = openReadyChannel(s.alice.node, s.bob.node);
		await turns(20);
		const ordinary = s.bob.node
			.getChannelManager()
			.getChannel(ordinaryId)!
			.getFullState();
		const alias = Buffer.from(ordinary.remoteScidAlias!);
		let message = '';
		try {
			s.bob.node.createInvoice(invoiceOptions([[hop(idOf(s.alice), alias)]]));
		} catch (error) {
			message = (error as Error).message;
		}
		expect(message).to.include(alias.toString('hex'));
		expect(message).to.include(ordinaryId.toString('hex'));
	});
});
