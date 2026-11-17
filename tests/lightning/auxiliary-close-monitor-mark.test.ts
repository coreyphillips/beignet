/**
 * The chain monitor's record of a spend of an asset channel's funding
 * output that the node holds no close payload for says so (issue #2093).
 *
 * Every spend of the funding output that carries no commitment stamp is
 * recorded as the cooperative close. For an asset channel that includes a
 * transaction the node never signed. The channel's row says which
 * transaction that was (auxiliaryState.unrecordedCloseTxid); the monitor's
 * record, which a host reads through getChannelMonitorState, now carries
 * unrecordedClose: true for it, on the running node and on one restarted
 * from the same database. The record of a close the node signed has no
 * such key.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CommitmentType } from '../../src/lightning/chain/types';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

const settle = async (rounds = 80): Promise<void> => {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

const DESTINATION = Buffer.from('0014' + '11'.repeat(20), 'hex');

/** The monitor's record of the funding spend, as a host reads it. */
const recordOf = (
	host: IAssetHost,
	channelId: Buffer
): Record<string, unknown> =>
	host.node.getChannelMonitorState(channelId)!
		.commitmentBroadcast as unknown as Record<string, unknown>;

describe('The monitor record of an asset close the node holds no payload for (#2093)', function () {
	this.timeout(240_000);
	withAssetOpens();

	it('marks the record of a spend of the funding output that is no close this node signed, and keeps the mark across a restart', async () => {
		const directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'aux-close-monitor-mark-')
		);
		const tag = 'aux-close-monitor-mark';
		const alicePath = path.join(directory, 'alice.sqlite');
		const open: IAssetHost[] = [];
		try {
			let alice = assetHost(tag, 1, {}, { sqlitePath: alicePath });
			const bob = assetHost(tag, 2, {}, { sqlite: true });
			open.push(alice, bob);
			connectHosts(alice, bob);
			const channelId = await openAssetChannel(alice, bob, {
				tag,
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			const before = alice.node
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			// A spend of the funding output that is no commitment and that
			// Alice never signed.
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(
				Buffer.from(before.fundingTxid!),
				before.fundingOutputIndex!,
				0xfffffffd
			);
			tx.addOutput(
				bitcoin.payments.p2tr({
					internalPubkey: before.localBasepoints.fundingPubkey.subarray(1)
				}).output!,
				Number(before.fundingSatoshis) - 1000
			);
			tx.setWitness(0, [Buffer.alloc(64, 1)]);
			alice.node.handleFundingSpent(channelId, tx, 700_000, DESTINATION);
			alice.node.handleNewBlock(700_000);
			await settle();
			expect(
				alice.node.getChannelManager().getChannel(channelId)!.getState()
			).to.equal(ChannelState.CLOSED);
			const record = recordOf(alice, channelId);
			expect(record.commitmentType).to.equal(CommitmentType.COOPERATIVE_CLOSE);
			expect(record.txid).to.equal(tx.getId());
			expect(record.unrecordedClose).to.equal(true);

			// The same report again changes nothing of it.
			alice.node.handleFundingSpent(channelId, tx, 700_000, DESTINATION);
			alice.node.handleNewBlock(700_001);
			await settle();
			expect(recordOf(alice, channelId).unrecordedClose).to.equal(true);

			// Restarted from the same database, the record still says so.
			alice.node.destroy();
			alice = assetHost(tag, 1, {}, { sqlitePath: alicePath });
			open.push(alice);
			const restored = recordOf(alice, channelId);
			expect(restored.txid).to.equal(tx.getId());
			expect(restored.commitmentType).to.equal(
				CommitmentType.COOPERATIVE_CLOSE
			);
			expect(restored.unrecordedClose).to.equal(true);
		} finally {
			for (const host of open) {
				try {
					host.node.destroy();
				} catch {
					// already destroyed
				}
			}
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});

	it('has no such key on the record of the close this node signed', async () => {
		const tag = 'aux-close-monitor-signed';
		const alice = assetHost(tag, 1, {}, { sqlite: true });
		const bob = assetHost(tag, 2, {}, { sqlite: true });
		try {
			connectHosts(alice, bob);
			const channelId = await openAssetChannel(alice, bob, {
				tag,
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			const published: Buffer[] = [];
			alice.node.on('broadcast:tx', (tx: Buffer) => published.push(tx));
			expect(alice.node.closeChannel(channelId, DESTINATION).ok).to.equal(true);
			await settle();
			expect(published).to.have.length(1);
			const close = bitcoin.Transaction.fromBuffer(published[0]);
			for (const host of [alice, bob]) {
				host.node.handleFundingSpent(channelId, close, 700_000, DESTINATION);
				host.node.handleNewBlock(700_000);
			}
			await settle();
			for (const host of [alice, bob]) {
				const record = recordOf(host, channelId);
				expect(record.commitmentType).to.equal(
					CommitmentType.COOPERATIVE_CLOSE
				);
				expect(record.txid).to.equal(close.getId());
				expect('unrecordedClose' in record).to.equal(false);
			}
		} finally {
			alice.node.destroy();
			bob.node.destroy();
		}
	});
});
