import { expect } from 'chai';
import crypto from 'crypto';
import { BeignetNode } from '../../src/cli/beignet-node';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { ISpliceInFlight } from '../../src/lightning/channel/channel-state';
import { funderCommitmentCostSats } from '../../src/lightning/channel/commitment-builder';
import { ChannelState } from '../../src/lightning/channel/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	connectNodes,
	createNode,
	openReadyChannel
} from '../lightning/helpers/loopback-nodes';

// Exercise the real CLI serializers and engine channels without booting a
// second wallet. These read-only methods need only the wrapped engine.
function wrap(node: LightningNode): BeignetNode {
	return Object.assign(Object.create(BeignetNode.prototype), { node });
}

describe('Exact outbound send ceiling on channel and liquidity snapshots', function () {
	this.timeout(10_000);
	let alice: LightningNode;
	let bob: LightningNode;
	let cli: BeignetNode;
	let channelId: Buffer;

	beforeEach(() => {
		alice = createNode('send-ceiling', 1, undefined, { preferAnchors: true });
		bob = createNode('send-ceiling', 2, undefined, { preferAnchors: true });
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);
		channelId = openReadyChannel(alice, bob);
		cli = wrap(alice);
	});

	afterEach(() => {
		alice.destroy();
		bob.destroy();
	});

	it('keeps the legacy estimate and reports the opener commitment cost separately', () => {
		const channel = alice.getChannelManager().getChannel(channelId)!;
		const state = channel.getFullState();
		const snapshot = cli.getLiquiditySnapshot();
		const listed = cli.listChannels()[0];
		const cost = funderCommitmentCostSats(
			state.localConfig.feeratePerKw * 2,
			2,
			state.channelType
		);
		expect(snapshot.sendableSats).to.equal(
			Number(
				state.localBalanceMsat / 1000n -
					state.remoteConfig.channelReserveSatoshis
			)
		);
		expect(snapshot.maxSendableSats).to.equal(
			snapshot.sendableSats - Number(cost)
		);
		expect(listed.maxSendableSats).to.equal(snapshot.maxSendableSats);
		expect(cli.getChannel(channelId.toString('hex'))!.maxSendableSats).to.equal(
			snapshot.maxSendableSats
		);
		expect(listed.localBalanceSats).to.equal(1_000_000);
	});

	it('refuses one sat above the reported ceiling before an add and pays an amountless invoice at it', () => {
		const channel = alice.getChannelManager().getChannel(channelId)!;
		const maximum = BigInt(cli.listChannels()[0].maxSendableSats!) * 1000n;
		const actions = channel.addHtlc(
			maximum + 1000n,
			crypto.randomBytes(32),
			100,
			Buffer.alloc(1366)
		);
		expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.equal(
			true
		);
		expect(channel.getFullState().htlcs.size).to.equal(0);
		const invoice = bob.createInvoice({ description: 'exact send ceiling' });
		const payment = alice.sendPayment(
			invoice.bolt11,
			undefined,
			undefined,
			maximum
		);
		expect(alice.getPayment(payment.paymentHash)?.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('follows the peer-funder guard down to a trimmed HTLC and then zero', () => {
		const channel = bob.getChannelManager().getChannel(channelId)!;
		const state = channel.getFullState();
		const receiver = wrap(bob);
		const reserve = state.localConfig.channelReserveSatoshis * 1000n;
		const cost =
			funderCommitmentCostSats(
				state.remoteConfig.feeratePerKw,
				0,
				state.channelType
			) * 1000n;
		state.remoteBalanceMsat = reserve + cost;
		state.localBalanceMsat =
			state.fundingSatoshis * 1000n - state.remoteBalanceMsat;
		const trimmed = channel.getSpendableOutboundMsat();
		expect(trimmed > 0n && trimmed < 1_000_000n).to.equal(true);
		expect(receiver.listChannels()[0].maxSendableSats).to.equal(
			Number(trimmed / 1000n)
		);
		expect(receiver.getLiquiditySnapshot().maxSendableSats).to.equal(
			Number(trimmed / 1000n)
		);
		state.remoteBalanceMsat -= 1n;
		state.localBalanceMsat += 1n;
		expect(receiver.listChannels()[0].maxSendableSats).to.equal(0);
		expect(receiver.getLiquiditySnapshot().maxSendableSats).to.equal(0);
		expect(receiver.getLiquiditySnapshot().sendableSats).to.be.greaterThan(
			900_000
		);
	});

	for (const held of [
		'restore',
		'funding',
		'closing',
		'reestablish'
	] as const) {
		it(`reports no send ceiling while ${held} blocks new HTLCs without hiding balance`, () => {
			const state = alice
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			if (held === 'restore') state.restoreRecencyUnproven = true;
			if (held === 'funding') state.fundingUnaccounted = true;
			if (held === 'closing') state.state = ChannelState.SHUTTING_DOWN;
			if (held === 'reestablish')
				state.state = ChannelState.AWAITING_REESTABLISH;
			expect(cli.listChannels()[0].maxSendableSats).to.equal(0);
			expect(cli.listChannels()[0].localBalanceSats).to.equal(1_000_000);
			expect(cli.getLiquiditySnapshot().maxSendableSats).to.equal(0);
		});
	}

	it('reports zero while the initial splice handshake quiesces a NORMAL channel', () => {
		const channel = alice.getChannelManager().getChannel(channelId)!;
		channel.initiateQuiescence();
		expect(channel.getState()).to.equal(ChannelState.NORMAL);
		expect(channel.isQuiescing()).to.equal(true);
		expect(channel.canOfferHtlcSet([1000n])).to.equal(false);
		expect(cli.listChannels()[0].maxSendableSats).to.equal(0);
		expect(cli.getLiquiditySnapshot().maxSendableSats).to.equal(0);
		expect(cli.listChannels()[0].localBalanceSats).to.equal(1_000_000);
	});

	it('sums exact millisatoshi ceilings before flooring the total', () => {
		const second = openReadyChannel(alice, bob);
		let total = 0n;
		for (const id of [channelId, second]) {
			const channel = alice.getChannelManager().getChannel(id)!;
			const state = channel.getFullState();
			state.localBalanceMsat -= 1n;
			state.remoteBalanceMsat += 1n;
			const msat = channel.getSpendableOutboundMsat();
			total += msat;
			expect(cli.getChannel(id.toString('hex'))!.maxSendableSats).to.equal(
				Number(msat / 1000n)
			);
		}
		expect(cli.getLiquiditySnapshot().maxSendableSats).to.equal(
			Number(total / 1000n)
		);
	});

	it('uses the persisted pending splice balance in the ceiling', () => {
		const channel = alice.getChannelManager().getChannel(channelId)!;
		const before = cli.listChannels()[0].maxSendableSats!;
		channel.getFullState().spliceInFlight = {
			newFundingSatoshis: 900_000n,
			localRelativeSatoshis: -100_000n,
			remoteRelativeSatoshis: 0n,
			isInitiator: true,
			spliceTxid: Buffer.alloc(32, 1)
		} as ISpliceInFlight;
		expect(cli.listChannels()[0].maxSendableSats).to.equal(before - 100_000);
		expect(cli.getLiquiditySnapshot().maxSendableSats).to.equal(
			before - 100_000
		);
	});
});
