/**
 * beignet's own feature bits must not land on a bit another implementation
 * or the bLIP-2 registry uses (issue #1886). option_ff_receive and
 * option_ff_concurrent sat on 560-563, eclair's on_the_fly_funding and
 * funding_fee_credit, so ACINQ sent current_fee_credit (type 41046, even)
 * after every init and we disconnected.
 */

import { expect } from 'chai';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { decodeNodeAnnouncementMessage } from '../../src/lightning/gossip/messages';
import type { INodeAnnouncementMessage } from '../../src/lightning/gossip/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import type { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { makeNodeConfig } from './helpers/ffor-world';

/**
 * Feature pairs used outside the BOLTs, keyed by the even bit, as read from
 * each project's master branch on 2026-10-26. Below 100 every implementation
 * shares the BOLT 9 assignments on purpose, so that range is left out.
 * Recheck this table whenever a bit is added to Feature.
 */
const FOREIGN_PAIRS: ReadonlyArray<{
	bit: number;
	owner: string;
	name: string;
}> = [
	{ bit: 104, owner: 'CLN', name: 'shutdown_wrong_funding' },
	{ bit: 128, owner: 'eclair, lightning-kmp', name: 'phoenix_zero_reserve' },
	{
		bit: 132,
		owner: 'eclair, lightning-kmp',
		name: 'wake_up_notification_client'
	},
	{ bit: 134, owner: 'lightning-kmp', name: 'wake_up_notification_provider' },
	{ bit: 140, owner: 'LDK', name: 'anchor_zero_fee_commitments staging' },
	{
		bit: 148,
		owner: 'eclair, lightning-kmp, Electrum',
		name: 'trampoline_payment_prototype'
	},
	{ bit: 150, owner: 'Electrum', name: 'trampoline routing (Electrum)' },
	{
		bit: 152,
		owner: 'eclair, LDK',
		name: 'async_payment_prototype, htlc_hold'
	},
	{ bit: 154, owner: 'eclair', name: 'splice_prototype' },
	{ bit: 160, owner: 'LND', name: 'rbf coop close staging' },
	{ bit: 180, owner: 'LND', name: 'simple-taproot-chans-x staging' },
	{ bit: 256, owner: 'bLIP-2', name: 'hosted_channels' },
	{ bit: 258, owner: 'bLIP-2, LDK', name: 'dns_resolver' },
	{
		bit: 260,
		owner: 'bLIP-2, LND',
		name: 'htlc_endorsement, experimental accountability'
	},
	{ bit: 262, owner: 'bLIP-2, LND', name: 'bolt11_blinded_path' },
	{ bit: 560, owner: 'eclair, lightning-kmp', name: 'on_the_fly_funding' },
	{ bit: 562, owner: 'eclair, lightning-kmp', name: 'funding_fee_credit' },
	{
		bit: 564,
		owner: 'eclair, lightning-kmp',
		name: 'option_simple_taproot_phoenix'
	},
	{ bit: 728, owner: 'bLIP-2', name: 'option_supports_lsps (odd 729)' },
	{ bit: 2022, owner: 'LND', name: 'script enforced lease' },
	{ bit: 2024, owner: 'LND', name: 'taproot overlay channels (optional 2025)' },
	{ bit: 2026, owner: 'LND', name: 'taproot overlay channels (required 2026)' }
];

/** Foreign pairs beignet takes on purpose, for the same feature. */
const SHARED_ON_PURPOSE = new Map<number, Feature>([
	// LND's staging taproot bit, which is what LND actually advertises.
	[180, Feature.OPTION_TAPROOT]
]);

function foreignOwner(bit: number): string | null {
	const pair = bit - (bit % 2);
	const entry = FOREIGN_PAIRS.find((p) => p.bit === pair);
	return entry ? `${entry.owner} ${entry.name}` : null;
}

/** Every set bit that is on a foreign pair and not shared on purpose. */
function collisions(bits: number[]): string[] {
	const out: string[] = [];
	for (const bit of bits) {
		const owner = foreignOwner(bit);
		if (!owner) continue;
		if (SHARED_ON_PURPOSE.get(bit - (bit % 2)) !== undefined) continue;
		out.push(`${bit}: ${owner}`);
	}
	return out;
}

/** An eclair init with Phoenix's features on, as ACINQ's node sends it. */
function eclairInit(): FeatureFlags {
	const f = FeatureFlags.empty();
	f.setOptional(Feature.DATA_LOSS_PROTECT);
	f.setOptional(Feature.STATIC_REMOTE_KEY);
	f.setCompulsory(Feature.PAYMENT_SECRET);
	f.setOptional(Feature.BASIC_MPP);
	f.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	f.setOptional(Feature.DUAL_FUND);
	f.setOptional(Feature.QUIESCE);
	f.setOptional(Feature.CHANNEL_TYPE);
	f.setOptional(Feature.SPLICE);
	f.setBit(561); // on_the_fly_funding
	f.setBit(563); // funding_fee_credit
	f.setBit(565); // option_simple_taproot_phoenix
	return f;
}

const PEER = '02' + '11'.repeat(32);

/** Point a manager's peer lookup at an init with the given features. */
function stubRemoteInit(manager: ChannelManager, features: FeatureFlags): void {
	const init = { features };
	const peer = { getRemoteInit: (): typeof init => init };
	(manager as unknown as { peerManager: unknown }).peerManager = {
		getPeer: (): typeof peer => peer
	};
}

function peerSupportsFfor(manager: ChannelManager): boolean {
	return (
		manager as unknown as { peerSupportsFfor(peer: string): boolean }
	).peerSupportsFfor(PEER);
}

describe('Feature bit collisions with other implementations (issue #1886)', () => {
	const nodes: LightningNode[] = [];
	afterEach(() => {
		for (const node of nodes.splice(0)) node.destroy();
	});

	function createNode(seedId: number, asyncService = false): LightningNode {
		const node = new LightningNode(
			makeNodeConfig(
				seedId,
				undefined,
				asyncService ? { asyncReceiveService: { enabled: true } } : {}
			)
		);
		nodes.push(node);
		return node;
	}

	it('no Feature value sits on a foreign pair, except the ones shared on purpose', () => {
		const values = Object.values(Feature).filter(
			(v): v is number => typeof v === 'number'
		);
		expect(collisions(values)).to.deep.equal([]);
		for (const [pair, feature] of SHARED_ON_PURPOSE) {
			expect(feature, `pair ${pair}`).to.equal(pair);
		}
	});

	it('the beignet block is 440-445', () => {
		expect(Feature.OPTION_FF_RECEIVE).to.equal(440);
		expect(Feature.OPTION_FF_CONCURRENT).to.equal(442);
		expect(Feature.ASYNC_RECEIVE_SERVICE).to.equal(444);
	});

	it('a node with every beignet feature on puts no foreign bit in init or node_announcement', () => {
		const node = createNode(18861, true);
		const local = node.getLocalFeatures();
		expect(local.hasFeature(Feature.OPTION_FF_RECEIVE)).to.equal(true);
		expect(local.hasFeature(Feature.OPTION_FF_CONCURRENT)).to.equal(true);
		expect(local.hasFeature(Feature.ASYNC_RECEIVE_SERVICE)).to.equal(true);
		expect(collisions(local.listSetBits()), 'init').to.deep.equal([]);
		for (let bit = 560; bit <= 565; bit++) {
			expect(local.hasBit(bit), `bit ${bit}`).to.equal(false);
		}

		const payload = (
			node as unknown as { buildNodeAnnouncement(t: number): Buffer | null }
		).buildNodeAnnouncement(1_790_000_000);
		expect(payload, 'announcement built').to.not.equal(null);
		const announced = FeatureFlags.fromBuffer(
			decodeNodeAnnouncementMessage(payload!).features
		);
		expect(collisions(announced.listSetBits()), 'announcement').to.deep.equal(
			[]
		);
	});

	it('an eclair init with on_the_fly_funding and funding_fee_credit does not read as an FFOR peer', () => {
		const node = createNode(18862);
		const manager = node.getChannelManager();

		// The seams are live: a beignet init reads as FFOR and concurrent.
		stubRemoteInit(manager, node.getLocalFeatures());
		manager.setFforPeerFeatureSource(() => node.getLocalFeatures());
		expect(peerSupportsFfor(manager)).to.equal(true);
		expect(manager.peerNegotiatedFforConcurrent(PEER)).to.equal(true);

		stubRemoteInit(manager, eclairInit());
		manager.setFforPeerFeatureSource(() => eclairInit());
		expect(peerSupportsFfor(manager)).to.equal(false);
		expect(manager.peerNegotiatedFforConcurrent(PEER)).to.equal(false);
	});

	it('an LND node_announcement with accountability bit 261 does not read as the async receive service', () => {
		const node = createNode(18863);
		const announcedWith = (bit: number): void => {
			const features = FeatureFlags.empty();
			features.setOptional(Feature.QUIESCE);
			features.setBit(bit);
			(
				node as unknown as {
					graph: {
						getVerifiedNodeAnnouncement(
							id: Buffer
						): Partial<INodeAnnouncementMessage> | undefined;
					};
				}
			).graph.getVerifiedNodeAnnouncement =
				(): Partial<INodeAnnouncementMessage> => ({
					features: features.toBuffer()
				});
		};

		announcedWith(261);
		expect(node.peerAdvertisesAsyncReceive(PEER)).to.equal(false);
		announcedWith(Feature.ASYNC_RECEIVE_SERVICE + 1);
		expect(node.peerAdvertisesAsyncReceive(PEER)).to.equal(true);
	});
});
