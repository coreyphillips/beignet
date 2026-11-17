/**
 * An asset channel is never announced (issue #2093).
 *
 * An announced channel is one the network routes ordinary payments over,
 * by its capacity in bitcoin. An asset channel's capacity is not that, and
 * nothing is forwarded over it. An opening that asks for one to be
 * announced is refused (tests/lightning/auxiliary-open-v1.test.ts). What is
 * checked here is the second line behind that refusal: a channel record
 * that says it is announced, as one accepted before the refusal existed
 * would, still signs no announcement and is no published public channel,
 * so the node goes on offering its private paths. An ordinary channel with
 * the same record is the public channel it always was.
 */

import { expect } from 'chai';
import {
	ChannelActionType,
	type ChannelAction
} from '../../src/lightning/channel/channel-actions';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';
import { writableState } from './helpers/writable-state';

describe('An asset channel is never announced (#2093)', function () {
	this.timeout(60_000);
	withAssetOpens();

	const hosts: IAssetHost[] = [];

	afterEach(() => {
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
	});

	const pair = async (
		tag: string
	): Promise<{ alice: IAssetHost; bob: IAssetHost; channelId: Buffer }> => {
		const alice = assetHost(tag, 1);
		const bob = assetHost(tag, 2);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		return { alice, bob, channelId };
	};

	const idOf = (host: IAssetHost): Buffer =>
		Buffer.from(host.node.getNodeId(), 'hex');

	it('opens unannounced on both sides', async () => {
		const { alice, bob, channelId } = await pair('audit announce flags');
		for (const host of [alice, bob]) {
			const state = host.node
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			expect(state.announceChannel).to.equal(false);
			expect(state.announcementSigsSent).to.equal(false);
		}
	});

	it('signs no announcement at announcement depth, though its record says it is announced', async () => {
		const { alice, bob, channelId } = await pair('audit announce depth');
		const sign = (
			host: IAssetHost,
			peer: IAssetHost,
			id: Buffer
		): { actions: ChannelAction[]; signed: number; sent: boolean } => {
			const channel = host.node.getChannelManager().getChannel(id)!;
			writableState(channel).announceChannel = true;
			let signed = 0;
			const actions = channel.handleAnnouncementDepthReached(
				800_000,
				1,
				idOf(host),
				idOf(peer),
				() => {
					signed++;
					return {
						nodeSig: Buffer.alloc(64, 1),
						bitcoinSig: Buffer.alloc(64, 2)
					};
				}
			);
			return {
				actions,
				signed,
				sent: channel.getFullState().announcementSigsSent
			};
		};
		expect(sign(alice, bob, channelId)).to.deep.equal({
			actions: [],
			signed: 0,
			sent: false
		});
		// An ordinary channel with the same record signs, as it always did.
		const ordinary = sign(alice, bob, openReadyChannel(alice.node, bob.node));
		expect(ordinary.signed).to.equal(1);
		expect(ordinary.sent).to.equal(true);
		expect(
			ordinary.actions.filter(
				(action) => action.type === ChannelActionType.SEND_MESSAGE
			)
		).to.have.length(1);
	});

	it('is no published public channel, though its record says the announcement was exchanged', async () => {
		const { alice, bob, channelId } = await pair('audit announce published');
		const published = (): boolean =>
			(
				alice.node as unknown as { hasPublishedPublicChannel(): boolean }
			).hasPublishedPublicChannel();
		const exchanged = (id: Buffer): void => {
			const state = writableState(
				alice.node.getChannelManager().getChannel(id)!
			);
			state.announceChannel = true;
			state.announcementSigsSent = true;
			state.announcementSigsReceived = true;
		};
		expect(published()).to.equal(false);
		exchanged(channelId);
		expect(published()).to.equal(false);
		// An ordinary channel with the same record is one.
		exchanged(openReadyChannel(alice.node, bob.node));
		expect(published()).to.equal(true);
	});
});
