import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Transaction } from 'bitcoinjs-lib';
import {
	ChannelManager,
	type IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { AssetSpliceConfirmationCoordinator } from '../../src/lightning/channel/asset-splice-confirmation';
import { encodeSpliceLockedMessage } from '../../src/lightning/message/splice';
import {
	setupFundedAssetUpdatePair,
	assetUpdateTestHost
} from './helpers/asset-splice-update';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { sha256 } from '../../src/lightning/crypto/provider';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../../src/lightning/message/channel-commitment';
import type { AssetUpdateChange } from '../../src/lightning/channel/asset-splice-update-provider';

describe('original-device cross-signed asset updates across all live fundings', function () {
	this.timeout(100000);
	let dir: string, s: Awaited<ReturnType<typeof setupFundedAssetUpdatePair>>;
	beforeEach(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-update-batch-'));
		s = await setupFundedAssetUpdatePair(dir);
	});
	afterEach(() => {
		for (const d of s?.f.devices ?? []) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	const hash = sha256(Buffer.alloc(32, 13));
	const amounts = [{ assetId: '4c'.repeat(32), units: 3n }];
	const changes = (i: number): AssetUpdateChange[] => [
		{
			kind: 'add',
			htlc: {
				id: 0n,
				offeredBy: i ? 'peer' : 'local',
				amountMsat: 5000000n,
				cltvExpiry: 601000,
				paymentHash: hash,
				allocations: amounts
			}
		},
		{
			kind: 'add',
			htlc: {
				id: 0n,
				offeredBy: i ? 'local' : 'peer',
				amountMsat: 2000000n,
				cltvExpiry: 601010,
				paymentHash: hash,
				allocations: []
			}
		}
	];
	const batch = (i: number, ops = changes(i), height = 1n) =>
		s.f.devices[i].store.assetSpliceUpdateBatch(
			s.f.id,
			s.f.devices[i].party.root,
			height,
			ops,
			() => 600900
		);

	it('requires the identical live set, fresh virtual authorizations and both exact tagged Bitcoin commitments before retaining and revoking a prior height', async () => {
		let a = batch(0),
			b = batch(1);
		const hosts = [assetUpdateTestHost(0), assetUpdateTestHost(1)];
		const ao = a.offer(),
			bo = b.offer();
		a.acceptOffer(bo);
		b.acceptOffer(ao);
		const pair = (await Promise.all([
			a.signAssetShares(hosts[0]),
			b.signAssetShares(hosts[1])
		])) as [Buffer, Buffer];
		await assert.rejects(() =>
			a.verifyAssetShares(hosts[0], pair, [Buffer.of(3), Buffer.of(4)])
		);
		const children = (await Promise.all([
			a.signAssetHtlcs(hosts[0], pair),
			b.signAssetHtlcs(hosts[1], pair)
		])) as [Buffer, Buffer];
		await assert.rejects(() =>
			a.signAssetHtlcs(hosts[0], [pair[0], Buffer.of(99)])
		);
		await a.verifyAssetShares(hosts[0], pair, children);
		await b.verifyAssetShares(hosts[1], pair, children);
		const ours = a.commitments(),
			theirs = b.commitments();
		assert.equal(ours.length, 2);
		assert(
			ours.every(
				(w) =>
					decodeCommitmentSignedMessage(w, {
						customRecords: true
					}).customRecords?.has(65537n)
			)
		);
		assert.throws(() => a.revocation());
		await assert.rejects(() => a.acceptCommitments(hosts[0], [theirs[0]]));
		await assert.rejects(() =>
			a.acceptCommitments(hosts[0], [theirs[0], theirs[0]])
		);
		const altered = decodeCommitmentSignedMessage(theirs[1], {
			customRecords: true
		});
		altered.partialSignatureWithNonce![0] ^= 1;
		await assert.rejects(() =>
			a.acceptCommitments(hosts[0], [
				theirs[0],
				encodeCommitmentSignedMessage(altered)
			])
		);
		const changed = Buffer.from(theirs[1]);
		changed[changed.length - 1] ^= 1;
		await assert.rejects(() =>
			a.acceptCommitments(hosts[0], [theirs[0], changed])
		);
		await assert.rejects(() =>
			a.acceptCommitments(
				{
					...hosts[0],
					async retainAssetUpdateViews() {
						throw Error('lost proof receipt');
					}
				},
				theirs
			)
		);
		assert.throws(() => a.revocation());
		await a.acceptCommitments(hosts[0], theirs);
		await b.acceptCommitments(hosts[1], ours);
		const newExits = s.f.devices[0].store
			.loadFinalFundingExits(s.f.id)
			.map((x) => Transaction.fromBuffer(x.exit));
		assert.equal(newExits.length, 2);
		assert(
			newExits.every(
				(tx) =>
					tx.outs.length >= 4 &&
					!s.f.views[0].parent.expected.getHash().equals(tx.getHash())
			)
		);
		const head = s.f.devices[0].store.assetSpliceUpdateHead(s.f.id);
		assert.equal(head.inProgress?.stateNumber, 1n);
		assert.deepEqual(head.inProgress?.changes, changes(0));
		const id = s.f.id,
			peer = s.f.devices[1].party.binding.nodeId;
		const proof =
			s.f.devices[0].store.loadAssetSpliceFundingInfo(id).pending[0];
		const txid = proof.candidate.fundingTxid;
		let imports = 0,
			samples = 0;
		const coordinator = () =>
			new AssetSpliceConfirmationCoordinator(
				s.f.devices[0].store,
				{
					verifySpliceFunding: async () => {},
					confirmSpliceFunding: async () => {
						imports++;
					},
					retractSpliceFunding: async () => {}
				},
				() => {},
				() => {}
			);
		const inclusion = async () => {
			samples++;
			return {
				txid,
				blockHash: 'a3'.repeat(32),
				confirmations: proof.minimumDepth
			};
		};
		let locks = coordinator();
		locks.restore(id);
		await locks.receive(
			peer,
			encodeSpliceLockedMessage({
				channelId: Buffer.from(id, 'hex'),
				fundingTxid: Buffer.from(txid, 'hex').reverse()
			})
		);
		await locks.observe(id, txid, 600901, inclusion, () => true);
		assert.equal(locks.status(id, txid)?.localLocked, true);
		assert.equal(locks.status(id, txid)?.peerLocked, true);
		assert.equal(locks.status(id, txid)?.adopted, false);
		assert.equal(imports, 0);
		const ra = a.revocation(),
			rb = b.revocation();
		for (const d of s.f.devices) {
			d.store.close();
			d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		}
		a = batch(0);
		b = batch(1);
		assert.deepEqual(a.commitments(), ours);
		assert.deepEqual(a.revocation(), ra);
		locks = coordinator();
		locks.restore(id);
		await locks.observe(id, txid, 600901, inclusion, () => true);
		assert.equal(locks.status(id, txid)?.adopted, false);
		a.receiveRevocation(rb);
		a.receiveRevocation(rb);
		b.receiveRevocation(ra);
		for (const [i, d] of s.f.devices.entries()) {
			const manager = new ChannelManager({
				finalOpening: { storage: d.store, root: d.party.root },
				persistence: { persist: () => 'committed' }
			} as unknown as IChannelManagerConfig);
			const row = manager.finalOpeningInfo(Buffer.from(id, 'hex'))[0],
				e = s.f.evidence(i);
			assert.equal(row.htlcCount, 2);
			assert.equal(
				row.localBalanceMsat,
				BigInt(e.parent.localRecovery.localBalanceMsat) -
					(i ? 2000000n : 5000000n)
			);
			assert.equal(
				row.pendingSpliceLocalBalanceMsat,
				BigInt(e.candidate.localRecovery.localBalanceMsat) -
					(i ? 2000000n : 5000000n)
			);
		}
		const priorSamples = samples;
		await locks.retry(id);
		assert.equal(samples, priorSamples + 1);
		assert.equal(imports, 1);
		assert.equal(locks.status(id, txid)?.available, true);

		assert.equal(
			s.f.devices[0].store.assetSpliceUpdateHead(s.f.id).inProgress,
			undefined
		);
		assert.equal(
			s.f.devices[0].store.assetSpliceUpdateHead(s.f.id).nextNumber,
			2n
		);
		assert.throws(() =>
			batch(
				0,
				[{ kind: 'fail', offeredBy: 'local', id: 99n, reason: Buffer.of(1) }],
				2n
			)
		);
		const fulfill: AssetUpdateChange = {
			kind: 'fulfill',
			offeredBy: 'local',
			id: 0n,
			preimage: Buffer.alloc(32, 13)
		};
		assert(batch(0, [fulfill], 2n).offer().length > 0);
	});
});
