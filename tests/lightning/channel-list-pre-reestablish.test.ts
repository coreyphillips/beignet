/**
 * The channel list reports the state a disconnect wrapped (issue #1899).
 *
 * A disconnect, or a restart, puts a channel in AWAITING_REESTABLISH
 * whatever state it was in. Without the earlier state a client reads a
 * channel still waiting on its funding and one long open alike while the
 * peer is away: a wallet showed an unconfirmed open's payment as completed,
 * and left the opening's balance out of its total.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	ICut,
	IWireGate,
	createNode,
	destroyAll,
	disconnect,
	openReadyChannel,
	reconnect,
	waitFor,
	wire
} from './helpers/async-world';

describe('Channel list: the state before a reestablish (issue #1899)', () => {
	let alice: LightningNode;
	let bob: LightningNode;
	let cut: ICut;
	let gate: IWireGate;

	beforeEach(() => {
		alice = createNode(181);
		bob = createNode(182);
		cut = { val: false };
		gate = { hold: false, queue: [] };
		wire(alice, bob, cut, undefined, gate);
	});
	afterEach(() => destroyAll(alice, bob));

	const listed = (channelId: Buffer) =>
		alice.listChannels().find((c) => c.channelId.equals(channelId))!;

	it('names an opening a disconnect wrapped', async () => {
		const pending = alice.openChannel(bob.getNodeId(), 1_000_000n);
		const channelId = alice.createFunding(
			pending,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		await waitFor(
			() => pending.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED,
			'funding_signed to arrive'
		);
		expect(listed(channelId)).to.not.have.property('preReestablishState');

		await disconnect(alice, bob, cut);
		const away = listed(channelId);
		expect(away.state).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(away.preReestablishState).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
	});

	it('names an open channel a disconnect wrapped, and only while it is wrapped', async () => {
		const channelId = await openReadyChannel(alice, bob);
		expect(listed(channelId).state).to.equal(ChannelState.NORMAL);
		expect(listed(channelId)).to.not.have.property('preReestablishState');

		await disconnect(alice, bob, cut);
		const away = listed(channelId);
		expect(away.state).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(away.preReestablishState).to.equal(ChannelState.NORMAL);

		await reconnect(alice, bob, cut, gate);
		await waitFor(
			() => listed(channelId).state === ChannelState.NORMAL,
			'the channel to reestablish'
		);
		expect(listed(channelId)).to.not.have.property('preReestablishState');
	});
});
