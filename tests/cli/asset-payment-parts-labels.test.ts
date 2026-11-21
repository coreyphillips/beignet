/**
 * Issue #2098, step 9: the keys an asset payment sent in parts is recorded
 * under are the node's own. A caller of an ordinary send may pass them in
 * the send's `metadata` (POST /invoice/pay passes it to sendPayment, which
 * passes it to sendPaymentToRoute): none of them is written, the engine
 * lists no part of such a payment, and the daemon charges the day what left
 * the node, as for any payment.
 *
 * A real ordinary channel from the daemon's own node to a loopback payee;
 * the claim is opened by the daemon's own admission, the send writes the
 * record, the payee settles inside the add, and the daemon's own
 * payment:sent handler charges the day.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import { BeignetNode } from '../../src/cli/beignet-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import {
	connectNodes,
	createNode,
	openReadyChannel
} from '../lightning/helpers/loopback-nodes';

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

type Admit = {
	_admitLightningSpend: (
		key: string,
		amountMsat: bigint,
		feeMsat: bigint
	) => unknown;
	_pendingSpendSats: number;
};

describe('the keys of an asset payment sent in parts in the metadata of an ordinary payment (#2098, step 9)', function () {
	this.timeout(60_000);

	it('are not written, and the day is charged what left the node', async () => {
		const daemon = await BeignetNode.create({
			...BOOT,
			storage: new MemoryStorage(),
			dailySpendLimitSats: 10_000,
			maxPaymentSats: 5_000
		});
		const node = daemon.getNode();
		const wired = node as unknown as {
			peerManager: unknown;
			channelManager: { peerManager: unknown };
		};
		const transport = [wired.peerManager, wired.channelManager.peerManager];
		wired.peerManager = null;
		wired.channelManager.peerManager = null;
		const bob = createNode('review-forged-parts', 2);
		try {
			node.handleNewBlock(1);
			bob.handleNewBlock(1);
			connectNodes(node, bob);
			openReadyChannel(node, bob);

			const pay = (
				amountMsat: bigint,
				metadata?: Record<string, string>
			): { status: PaymentStatus; spent: number } => {
				const invoice = bob.createInvoice({
					amountMsat,
					description: 'ordinary'
				});
				const hashHex = invoice.paymentHash.toString('hex');
				// The admission payInvoice runs, with no fee cap.
				(daemon as unknown as Admit)._admitLightningSpend(
					hashHex,
					amountMsat,
					0n
				);
				node.sendPaymentToRoute(
					{
						hops: [
							{
								pubkey: Buffer.from(bob.getNodeId(), 'hex'),
								shortChannelId: Buffer.alloc(8, 9),
								amountToForwardMsat: amountMsat,
								outgoingCltvValue: 40
							}
						]
					},
					invoice.paymentHash,
					40,
					invoice.paymentSecret,
					undefined,
					metadata
				);
				return {
					status: node.getPayment(invoice.paymentHash)!.status,
					spent: daemon.getDailySpendInfo().spentSats
				};
			};

			// An ordinary payment of 4,000 sats, no labels: charged 4,000.
			const plain = pay(4_000_000n);
			expect(plain.status).to.equal(PaymentStatus.COMPLETED);
			expect(plain.spent, 'a plain payment is charged in full').to.equal(4_000);

			// The same, with two labels a caller may pass: a part on a
			// channel that does not exist, worth 1 msat and failed.
			const key = `${crypto.randomBytes(32).toString('hex')}:offered-0`;
			const forged = pay(4_000_000n, {
				_auxiliaryPartAmounts: JSON.stringify({ [key]: '1' }),
				_auxiliaryPartsSent: JSON.stringify({
					[key]: { route: '1', wire: '1', set: 1, failed: true }
				})
			});
			expect(forged.status).to.equal(PaymentStatus.COMPLETED);
			const record = node
				.listPayments()
				.find((p) => p.metadata?._auxiliaryPartAmounts !== undefined)!;
			expect(record.auxiliary, 'the record is not an asset payment').to.equal(
				undefined
			);
			expect(
				record.metadata?._auxiliaryPartsSent,
				"the key of the parts sent is the node's, not a caller's"
			).to.equal(undefined);
			expect(
				node
					.getAuxiliaryPaymentHtlcs(record.paymentHash)
					.filter((p) => p.routeAmountMsat !== undefined),
				'no part sent in parts is listed for an ordinary payment'
			).to.deep.equal([]);
			expect(
				(daemon as unknown as Admit)._pendingSpendSats,
				'no reservation is left'
			).to.equal(0);
			expect(
				forged.spent,
				'a second 4,000 sat payment should bring the day to 8,000'
			).to.equal(8_000);
		} finally {
			[wired.peerManager, wired.channelManager.peerManager] = transport;
			bob.destroy();
			await daemon.destroy();
		}
	});
});
