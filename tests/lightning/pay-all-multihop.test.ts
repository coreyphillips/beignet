import { expect } from 'chai';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { REGTEST_CHAIN_HASH } from '../../src/lightning/channel/types';
import { IChannelUpdateMessage } from '../../src/lightning/gossip/types';
import { encodeChannelUpdateMessage } from '../../src/lightning/gossip/messages';
import { signChannelUpdate } from '../../src/lightning/gossip/validation';
import { createFailureMessage } from '../../src/lightning/onion/failures';
import { FEE_INSUFFICIENT } from '../../src/lightning/onion/types';
import {
	createNode,
	makeNodeConfig,
	connectNodes,
	openReadyChannel,
	scidForIndex
} from './helpers/loopback-nodes';

describe('Pay-all multi-hop settlement', function () {
	this.timeout(20_000);
	let alice: LightningNode;
	let bob: LightningNode;
	let carol: LightningNode;
	let ab: Buffer;
	let bc: Buffer;
	let bobPolicy: IChannelUpdateMessage;
	beforeEach(() => {
		alice = createNode('pay-all-multihop', 1);
		bob = createNode('pay-all-multihop', 2, undefined, {
			forwardingFeeBaseMsat: 0,
			forwardingFeePropMillionths: 1000,
			forwardingPolicyGraceMs: 0
		});
		carol = createNode('pay-all-multihop', 3);
		for (const node of [alice, bob, carol]) node.on('node:error', () => {});
		connectNodes(alice, bob);
		connectNodes(bob, carol);
		ab = openReadyChannel(alice, bob);
		bc = openReadyChannel(bob, carol);
		alice.registerChannelScid(ab, scidForIndex(0));
		bob.registerChannelScid(ab, scidForIndex(0));
		bob.registerChannelScid(bc, scidForIndex(1));
		carol.registerChannelScid(bc, scidForIndex(1));
		bob.getChannelManager().getChannel(bc)!.getFullState().shortChannelId =
			scidForIndex(1);
		carol.getChannelManager().getChannel(bc)!.getFullState().shortChannelId =
			scidForIndex(1);
		const b = Buffer.from(bob.getNodeId(), 'hex');
		const c = Buffer.from(carol.getNodeId(), 'hex');
		const bFirst = Buffer.compare(b, c) < 0;
		alice.getGraph().addChannelAnnouncement({
			nodeSignature1: Buffer.alloc(64),
			nodeSignature2: Buffer.alloc(64),
			bitcoinSignature1: Buffer.alloc(64),
			bitcoinSignature2: Buffer.alloc(64),
			features: Buffer.alloc(0),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: scidForIndex(1),
			nodeId1: bFirst ? b : c,
			nodeId2: bFirst ? c : b,
			bitcoinKey1: b,
			bitcoinKey2: c
		});
		const update: IChannelUpdateMessage = {
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: scidForIndex(1),
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: bFirst ? 0 : 1,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			htlcMaximumMsat: 500_000_000n,
			feeBaseMsat: 0,
			feeProportionalMillionths: 1000
		};
		expect(alice.getGraph().applyChannelUpdate(update)).to.equal(true);
		bobPolicy = update;
	});
	afterEach(() => {
		alice.destroy();
		bob.destroy();
		carol.destroy();
	});

	it('settles a real forwarded HTLC with the rounding gap paid to the first hop', () => {
		const invoice = carol.createInvoice({ description: 'fee rounding gap' });
		const before = alice.getBalance().localBalanceMsat;
		const forwarderBefore = bob.getBalance().localBalanceMsat;
		alice.sendPayAll(invoice.bolt11, 1_000_999n, 1000n);
		const payment = alice.getPayment(invoice.paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(payment.payAll).to.deep.equal({
			debitMsat: 1_000_999n,
			maxFeeMsat: 1000n,
			deliveredMsat: 999_999n,
			feeMsat: 1000n,
			remainderMsat: 0n
		});
		expect(before - alice.getBalance().localBalanceMsat).to.equal(1_000_999n);
		expect(bob.getBalance().localBalanceMsat - forwarderBefore).to.equal(1000n);
		expect(carol.getPayment(invoice.paymentHash)!.amountMsat).to.equal(
			999_999n
		);
	});

	it('changes the recipient amount after a signed fee update while retaining the debit and cap', () => {
		const forwarder = bob as unknown as {
			handleForwardHtlc: (...args: unknown[]) => void;
		};
		const forward = forwarder.handleForwardHtlc.bind(bob);
		let attempts = 0;
		forwarder.handleForwardHtlc = (...args: unknown[]): void => {
			if (++attempts === 1) {
				bob.setChannelPolicy(bc, { feeBaseMsat: 2000 });
				const changed = { ...bobPolicy, feeBaseMsat: 2000 };
				const update = encodeChannelUpdateMessage({
					...changed,
					signature: signChannelUpdate(
						encodeChannelUpdateMessage(changed),
						makeNodeConfig('pay-all-multihop', 2).nodePrivateKey
					)
				});
				const data = Buffer.alloc(10 + update.length);
				data.writeBigUInt64BE(1_000_999n);
				data.writeUInt16BE(update.length, 8);
				update.copy(data, 10);
				const [channelId, htlcId, , processed] = args as [
					Buffer,
					bigint,
					Buffer,
					{ sharedSecret: Buffer }
				];
				bob
					.getChannelManager()
					.failHtlc(
						channelId,
						htlcId,
						createFailureMessage(processed.sharedSecret, FEE_INSUFFICIENT, data)
					);
				return;
			}
			forward(...args);
		};
		const invoice = carol.createInvoice({
			description: 'changed fee on retry'
		});
		const before = alice.getBalance().localBalanceMsat;
		alice.sendPayAll(invoice.bolt11, 1_000_999n, 4000n);
		const payment = alice.getPayment(invoice.paymentHash)!;
		expect(attempts).to.equal(2);
		expect(payment.status, payment.failureReason).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(payment.payAll).to.deep.equal({
			debitMsat: 1_000_999n,
			maxFeeMsat: 4000n,
			deliveredMsat: 998_001n,
			feeMsat: 2998n,
			remainderMsat: 0n
		});
		expect(before - alice.getBalance().localBalanceMsat).to.equal(1_000_999n);
		expect(carol.getPayment(invoice.paymentHash)!.amountMsat).to.equal(
			998_001n
		);
	});
});
