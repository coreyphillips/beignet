/**
 * Issue #2098, step 9: the claim each part of an asset payment sent in
 * parts holds in the daemon's daily ledger, given back when the part is
 * refused at its add and the part sent in its place takes the same id at
 * once, and when the chain takes the part back.
 *
 * A daemon whose node holds a real asset channel with a loopback payee that
 * collects asset invoices in parts (as in asset-payment-limits.test.ts).
 * The invoice is larger than the parts sent, so the payee keeps collecting
 * and the parts stay out.
 */

import { expect } from 'chai';
import { AsyncSpendClaim, BeignetNode } from '../../src/cli/beignet-node';
import {
	EXTENSION_API_VERSION,
	IBeignetExtension
} from '../../src/cli/extension';
import { OutputType } from '../../src/lightning/chain/types';
import type { IAuxiliaryFundingDescriptor } from '../../src/lightning/channel/auxiliary-funding';
import { HtlcDirection } from '../../src/lightning/channel/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { AuxiliaryPaymentError } from '../../src/lightning/node/types';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import {
	RECEIVE_IN_PARTS,
	SEND_IN_PARTS,
	assetHost,
	openAssetChannel,
	turns,
	withAssetOpens,
	withAssetPartsReceived,
	withAssetPartsSent
} from '../lightning/helpers/auxiliary-nodes';
import {
	amountRecord,
	referenceProvider
} from '../lightning/helpers/auxiliary-pair';
import { refusingAdds } from '../lightning/helpers/auxiliary-send-scene';
import { connectNodes } from '../lightning/helpers/loopback-nodes';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const BOOT = {
	mnemonic: MNEMONIC,
	network: 'regtest' as const,
	logLevel: 'silent' as const,
	rapidGossipSync: false,
	autoGossipSync: false,
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};
const CARRIER_MSAT = 354_000n;

type Claim = AsyncSpendClaim & { part?: string };
const claimsOf = (of: BeignetNode, paymentHash: Buffer): Claim[] =>
	(
		of as unknown as { _asyncSpendClaims: Map<string, Claim[]> }
	)._asyncSpendClaims.get(paymentHash.toString('hex')) ?? [];
const reserved = (of: BeignetNode, paymentHash: Buffer): string[] =>
	claimsOf(of, paymentHash)
		.filter((claim) => claim.reserved)
		.map((claim) => `${claim.part}=${claim.sats}`);
const pendingOf = (of: BeignetNode): number =>
	(of as unknown as { _pendingSpendSats: number })._pendingSpendSats;
const keyOf = (channelId: Buffer, htlcId: bigint): string =>
	`${channelId.toString('hex')}:offered-${htlcId}`;

const worth = (context: { auxiliaryAmount?: bigint }): bigint | undefined =>
	context.auxiliaryAmount === undefined
		? undefined
		: context.auxiliaryAmount * 1000n;
const assetPeerFeatures = (): FeatureFlags => {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.STATIC_REMOTE_KEY);
	flags.setOptional(Feature.OPTION_TAPROOT);
	flags.setOptional(Feature.OPTION_TAPROOT_OVERLAY);
	return flags;
};

describe('the claims of the parts of an asset payment sent in parts (#2098, step 9)', function () {
	this.timeout(60_000);
	withAssetOpens();
	withAssetPartsSent();
	withAssetPartsReceived();
	const closers: Array<() => Promise<void>> = [];
	afterEach(async () => {
		for (const close of closers.splice(0).reverse()) await close();
	});

	const world = async (
		tag: string
	): Promise<{
		daemon: BeignetNode;
		node: LightningNode;
		channelId: Buffer;
		payee: ReturnType<typeof assetHost>;
		arm: { next: number };
	}> => {
		const incoming = new Map<string, IAuxiliaryFundingDescriptor>();
		const arm = { next: 0 };
		const extension: IBeignetExtension = {
			id: 'assets',
			version: '1.0.0',
			api: EXTENSION_API_VERSION,
			attach: () => ({
				auxiliaryChannels: {
					provider: refusingAdds(arm)(referenceProvider()),
					allowLegacyHtlcSignatures: (): boolean => true,
					resolveIncoming: (_peer, id) => incoming.get(id.toString('hex')),
					valueIncomingHtlc: worth,
					...SEND_IN_PARTS
				}
			})
		};
		const daemon = await BeignetNode.create({
			...BOOT,
			storage: new MemoryStorage(),
			dailySpendLimitSats: 10_000,
			maxPaymentSats: 5_000,
			extensions: [extension]
		});
		const node = daemon.getNode();
		const wired = node as unknown as {
			peerManager: unknown;
			channelManager: { peerManager: unknown };
		};
		const transport = [wired.peerManager, wired.channelManager.peerManager];
		wired.peerManager = null;
		wired.channelManager.peerManager = null;
		const payee = assetHost(tag, 2, {
			valueIncomingHtlc: worth,
			...RECEIVE_IN_PARTS
		});
		closers.push(async () => {
			payee.node.destroy();
			[wired.peerManager, wired.channelManager.peerManager] = transport;
			await daemon.destroy();
		});
		node.handleNewBlock(1);
		(
			node as unknown as { peerInitFeatures: () => FeatureFlags }
		).peerInitFeatures = assetPeerFeatures;
		connectNodes(node, payee.node);
		const channelId = await openAssetChannel(
			{ node, incoming, broadcasts: [], errors: [] },
			payee,
			{ tag, openerUnits: 9000n, acceptorUnits: 1000n }
		);
		return { daemon, node, channelId, payee, arm };
	};

	const payUnits = (
		w: {
			node: LightningNode;
			channelId: Buffer;
			payee: { node: LightningNode };
		},
		invoice: { paymentHash: Buffer; paymentSecret: Buffer },
		units: bigint,
		totalMsat: bigint
	): unknown => {
		const valueMsat = units * 1000n;
		try {
			w.node.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: Buffer.from(w.payee.node.getNodeId(), 'hex'),
							shortChannelId: Buffer.alloc(8, 9),
							amountToForwardMsat: valueMsat,
							outgoingCltvValue: 40
						}
					],
					totalAmountMsat: valueMsat,
					totalFeeMsat: 0n,
					totalCltvDelta: 40
				} as Parameters<LightningNode['sendPaymentToRoute']>[0],
				invoice.paymentHash,
				40,
				invoice.paymentSecret,
				totalMsat,
				undefined,
				undefined,
				undefined,
				{
					assetPayment: {
						channelId: w.channelId,
						wireAmountMsat: CARRIER_MSAT,
						customRecords: amountRecord(units)
					}
				}
			);
		} catch (err) {
			return err;
		}
		return undefined;
	};

	it('are one per part out when a part refused at its add is sent again at once under the same id', async () => {
		const w = await world('review-claims-resend');
		const invoice = w.payee.node.createInvoice({
			amountMsat: 9_000_000n,
			description: 'collected in parts, never complete here'
		});
		const h = invoice.paymentHash;
		expect(payUnits(w, invoice, 3000n, 9_000_000n)).to.equal(undefined);
		await turns(50);
		const nextId = w.node
			.getChannelManager()
			.getChannel(w.channelId)!
			.getFullState().localHtlcCounter;
		w.arm.next = 1;
		const refusal = payUnits(w, invoice, 2000n, 9_000_000n);
		w.arm.next = 0;
		expect(refusal).to.be.instanceOf(AuxiliaryPaymentError);
		expect((refusal as AuxiliaryPaymentError).code).to.equal(
			'ASSET_HTLC_NOT_ADMITTED'
		);
		// The host sends the part again from its catch, before it awaits
		// anything: the channel's next id is the one the refusal left free.
		expect(payUnits(w, invoice, 2000n, 9_000_000n)).to.equal(undefined);
		expect(
			w.node.getChannelManager().getChannel(w.channelId)!.getFullState()
				.localHtlcCounter
		).to.equal(nextId + 1n);
		await turns(50);
		const listed = w.node
			.getAuxiliaryPaymentHtlcs(h)
			.map(
				(entry) => `${keyOf(entry.channelId, entry.htlcId)}:${entry.amountMsat}`
			);
		expect(listed, 'two parts out, 5,000 sats').to.have.length(2);
		expect(
			reserved(w.daemon, h),
			'one claim per part out: the refused part gave its claim back'
		).to.deep.equal([
			`${keyOf(w.channelId, nextId - 1n)}=3000`,
			`${keyOf(w.channelId, nextId)}=2000`
		]);
		expect(pendingOf(w.daemon)).to.equal(5_000);
	});

	it('give back the claim of a part taken back on the chain by its timeout, marked failed before its end is told', async () => {
		const w = await world('review-claims-onchain');
		const invoice = w.payee.node.createInvoice({
			amountMsat: 9_000_000n,
			description: 'collected in parts, never complete here'
		});
		const h = invoice.paymentHash;
		expect(payUnits(w, invoice, 3000n, 9_000_000n)).to.equal(undefined);
		expect(payUnits(w, invoice, 2000n, 9_000_000n)).to.equal(undefined);
		await turns(50);
		const parts = w.node.getAuxiliaryPaymentHtlcs(h);
		expect(parts).to.have.length(2);
		const first = parts[0];
		expect(pendingOf(w.daemon)).to.equal(5_000);

		// The chain monitor says the first part ended on the chain without
		// its preimage (this node's timeout won), and its output resolves.
		const manager = w.node.getChannelManager() as unknown as {
			auxiliaryHtlcChainEnding: (
				channelId: Buffer,
				direction: HtlcDirection,
				htlcId: bigint
			) => 'fulfilled' | 'failed' | undefined;
		};
		const ending = manager.auxiliaryHtlcChainEnding.bind(manager);
		manager.auxiliaryHtlcChainEnding = (
			channelId,
			direction,
			htlcId
		): 'fulfilled' | 'failed' | undefined =>
			channelId.equals(first.channelId) &&
			direction === HtlcDirection.OFFERED &&
			htlcId === first.htlcId
				? 'failed'
				: ending(channelId, direction, htlcId);
		const seen: Array<{ state: string; failedThen: boolean }> = [];
		w.node.prependListener(
			'payment:htlc-resolved',
			(event: { paymentHash: Buffer; htlcId: bigint; state: string }) => {
				if (!event.paymentHash.equals(h) || event.htlcId !== first.htlcId) {
					return;
				}
				seen.push({
					state: event.state,
					failedThen:
						w.node
							.getAuxiliaryPaymentHtlcs(h)
							.find((entry) => entry.htlcId === first.htlcId)?.failed === true
				});
			}
		);
		(
			w.node as unknown as {
				handleOnChainOutputResolved: (
					channelId: Buffer,
					outputType: OutputType,
					paymentHash: Buffer,
					htlcId: bigint
				) => void;
			}
		).handleOnChainOutputResolved(
			first.channelId,
			OutputType.OFFERED_HTLC,
			h,
			first.htlcId
		);
		await turns(20);
		expect(seen, 'told once, after the part was marked').to.deep.equal([
			{ state: 'onchain-resolved', failedThen: true }
		]);
		expect(
			w.node
				.getAuxiliaryPaymentHtlcs(h)
				.find((entry) => entry.htlcId === first.htlcId)?.failed,
			'the listing marks the part failed once the call returns'
		).to.equal(true);
		expect(
			reserved(w.daemon, h),
			"the failed part's claim should be given back (EXTENSIONS.md: given back when the part fails)"
		).to.deep.equal([`${keyOf(parts[1].channelId, parts[1].htlcId)}=2000`]);
	});
});
