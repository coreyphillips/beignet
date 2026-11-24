import { expect } from 'chai';
import { createNode } from './helpers/async-world';
import {
	ChannelState,
	HtlcDirection,
	HtlcState,
	type ChannelResult,
	type IHtlcEntry
} from '../../src/lightning/channel/types';
import {
	PaymentStatus,
	type IOutgoingHtlcView,
	type IChannelInfo
} from '../../src/lightning/node/types';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';

describe('routing daemon payments over a private final channel', () => {
	it('keeps a retained offer in flight through close until the chain reports its terminal outcome', () => {
		const node = createNode(45, new MemoryStorage());
		const manager = node.getChannelManager();
		const hash = Buffer.alloc(32, 61);
		const id = Buffer.alloc(32, 3);
		node['htlcPaymentMap'].set(
			id.toString('hex') + ':offered-8',
			hash.toString('hex')
		);
		let onChain = false;
		let terminal = false;
		manager.finalOfferedHtlc = (): ReturnType<
			typeof manager.finalOfferedHtlc
		> => ({
			amountMsat: 4200000n,
			cltvExpiry: 150,
			onChain,
			terminal
		});
		const view = (): IOutgoingHtlcView => node.getOutgoingHtlcs(hash).htlcs[0];
		expect(view().state).to.equal('offered');
		expect(view().amountMsat).to.equal(4200000n);
		onChain = true;
		expect(view().state).to.equal('onchain-pending');
		expect(view().terminal).to.equal(false);
		terminal = true;
		expect(view().state).to.equal('onchain-resolved');
		expect(view().terminal).to.equal(true);
	});

	for (const kind of ['keysend', 'invoice'] as const) {
		it(
			'delivers the ordinary ' + kind + ' onion at the irrevocable HTLC event',
			() => {
				const a = createNode(49, new MemoryStorage()),
					b = createNode(51, new MemoryStorage());
				a.handleNewBlock(200);
				b.handleNewBlock(200);
				const ac = a.getChannelManager(),
					bc = b.getChannelManager(),
					id = Buffer.alloc(32, 77);
				const alias = 'ff00000000000031',
					peer = b.getNodeId();
				ac.finalOpeningInfo = (): IChannelInfo[] => [
					{
						channelId: id,
						channelType: Buffer.from('0100000000000000000000', 'hex'),
						peerPubkey: peer,
						state: ChannelState.NORMAL,
						localBalanceMsat: 20000000n,
						remoteBalanceMsat: 30000000n,
						fundingSatoshis: 50000n,
						shortChannelId: alias,
						htlcUsable: true,
						spendableOutboundMsat: 10000000n
					}
				];
				ac.finalRemoteHtlcMinimum = (): bigint => 1000n;
				ac.finalUpdateStatus = (): ReturnType<typeof ac.finalUpdateStatus> =>
					({ nextLocalHtlcId: 5n }) as NonNullable<
						ReturnType<typeof ac.finalUpdateStatus>
					>;
				let htlc: IHtlcEntry | undefined;
				bc.getPeerForChannel = (): string => a.getNodeId();
				bc.finalReceivedHtlc = (channel, htlcId): IHtlcEntry | undefined =>
					channel.equals(id) && htlc?.id === htlcId ? htlc : undefined;
				bc.fulfillHtlc = (channel, htlcId, preimage): ChannelResult => {
					expect(htlc?.id).to.equal(htlcId);
					ac.emit('htlc:fulfilled', channel, htlcId, preimage, true);
					return { ok: true, actions: [] };
				};
				ac.addHtlc = (
					channel,
					amountMsat,
					paymentHash,
					cltvExpiry,
					onionRoutingPacket
				): ChannelResult => {
					expect(channel.equals(id)).to.equal(true);
					htlc = {
						id: 5n,
						amountMsat,
						paymentHash,
						cltvExpiry,
						onionRoutingPacket,
						direction: HtlcDirection.RECEIVED,
						state: HtlcState.COMMITTED
					};
					bc.emit('htlc:forwarded', id, htlc.id, amountMsat, paymentHash);
					return { ok: true, actions: [] };
				};
				const amountMsat = 100000n;
				const payment =
					kind === 'keysend'
						? a.sendKeysend({
								destination: Buffer.from(peer, 'hex'),
								amountMsat
						  })
						: a.sendPayment(
								b.createInvoice({ amountMsat, description: 'final' }).bolt11
						  );
				expect(b.getPayment(payment.paymentHash)?.status).to.equal(
					PaymentStatus.COMPLETED
				);
				expect(a.getPayment(payment.paymentHash)?.status).to.equal(
					PaymentStatus.COMPLETED
				);
			}
		);
	}
});
