import { expect } from 'chai';
import { encodeScb } from '../../../src/lightning/backup/scb';
import {
	CAPSULE_MAX_BYTES,
	RecoveryJournal,
	channelsAfterReplay,
	composeRecoveryCapsule,
	decodeRecoveryCapsuleBlob,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot
} from '../../../src/lightning/recovery';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	turns
} from './auxiliary-nodes';
import {
	fundingData,
	issuances,
	sizedViewProvider
} from './grouped-asset-fixture';

/** Compose a capsule from a single snapshot of a channel with opaque extension data. */
export async function sizedRecoveryCapsule(
	tag: string,
	count: number,
	secret: Buffer
): Promise<{
	blob: Buffer;
	id: string;
	peerId: string;
}> {
	const alice = assetHost(
		tag,
		1,
		{ provider: sizedViewProvider(count) },
		{
			sqlite: true,
			extra: { nodePrivateKey: secret }
		}
	);
	const bob = assetHost(tag, 2, { provider: sizedViewProvider(count) });
	try {
		connectHosts(alice, bob);
		const data = fundingData(count, 2);
		const funded = issuances.slice(0, count);
		const openerUnits = funded.reduce((sum, item) => sum + item.local, 0n);
		const acceptorUnits = funded.reduce((sum, item) => sum + item.remote, 0n);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits,
			acceptorUnits,
			proposedData: fundingData(count, 1),
			fundingData: data
		});
		const manager = alice.node.getChannelManager();
		for (const rate of [700, 800]) {
			expect(manager.updateChannelFee(channelId, rate).ok).to.equal(true);
			await turns();
		}
		const id = channelId.toString('hex');
		const peerId = bob.node.getNodeId();
		const storage = alice.storage!;
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(secret),
			Buffer.from(alice.node.getNodeId(), 'hex'),
			deriveRecoveryRoot(secret).recoveryId
		);
		journal.prepareForReplication();
		const frames = journal.loadVerifiedFrames();
		expect(frames).to.have.length(1);
		const row = channelsAfterReplay(frames).find(
			(entry) => entry.channelId === id
		)!;
		expect(row.peerPubkey).to.equal(peerId);
		const recovered = row.state.auxiliaryState!;
		const current = manager.getChannel(channelId)!.getFullState()
			.auxiliaryState!;
		expect(recovered.channelData).to.deep.equal(data);
		expect(recovered.localBalance).to.equal(openerUnits);
		expect(recovered.remoteBalance).to.equal(acceptorUnits);
		expect(recovered.localCommitments).to.deep.equal(current.localCommitments);
		expect(recovered.remoteCommitments).to.deep.equal(
			current.remoteCommitments
		);
		const markers = [
			...recovered.localCommitments.values(),
			...recovered.remoteCommitments.values()
		].map((view) => view.customData.subarray(0, 32).toString('hex'));
		expect(markers).to.have.length(4);
		expect(new Set(markers).size).to.equal(4);

		const backup = alice.node.buildStaticChannelBackupData();
		expect(backup.channels.map((c) => c.channelId)).to.deep.equal([id]);
		const encryptedScb = encodeScb(
			{ ...backup, version: 1, createdAt: 1 },
			secret
		);
		const result = composeRecoveryCapsule({
			storage,
			encryptedScb,
			nodeSecret: secret
		});
		expect(result.inline).to.equal(false);
		expect(result.inlineError).to.include(
			'inline journal does not fit the capsule'
		);
		expect(result.inlineError).to.include(`${CAPSULE_MAX_BYTES} byte ceiling`);
		expect(result.blob.length).to.be.at.most(CAPSULE_MAX_BYTES);
		const capsule = decodeRecoveryCapsuleBlob(result.blob, secret)!;
		const [snapshot] = storage.loadRecoveryFrames();
		expect(capsule.inlineRecoveryState).to.equal(undefined);
		expect(capsule.encryptedScb).to.equal(encryptedScb);
		expect(capsule.latestSequence).to.equal(BigInt(snapshot.sequence));
		expect(capsule.frameHash).to.deep.equal(snapshot.frameHash);
		expect(capsule.snapshotHash).to.deep.equal(snapshot.frameHash);
		return { blob: result.blob, id, peerId };
	} finally {
		alice.node.destroy();
		bob.node.destroy();
		alice.storage!.close();
	}
}
