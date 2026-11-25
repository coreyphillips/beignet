import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { signatureRoundFixture } from './helpers/asset-splice-signature-round';
import {
	assetUpdateTestHost,
	setupFundedAssetUpdatePair
} from './helpers/asset-splice-update';
import { FinalOpeningTransport } from '../../src/lightning/channel/final-opening-transport';
import { AssetSpliceConfirmationCoordinator } from '../../src/lightning/channel/asset-splice-confirmation';
import type { AssetUpdateChange } from '../../src/lightning/channel/asset-splice-update-provider';
import {
	assetReconnectReservation,
	acceptAssetSpliceReestablish
} from '../../src/lightning/storage/asset-splice-reestablish';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import { decodeRevokeAndAckMessage } from '../../src/lightning/message/channel-commitment';
import { decodeTxCompleteMessage } from '../../src/lightning/message/interactive-tx';
import { encodeSpliceLockedMessage } from '../../src/lightning/message/splice';
import { MessageType as M } from '../../src/lightning/message/types';
import { sha256 } from '../../src/lightning/crypto/provider';

type DevicePair = ReturnType<typeof signatureRoundFixture>;
function markReady(f: DevicePair) {
	const ready = f.f.devices.map((d) =>
		d.store.finalOpeningChannelReady(f.f.id, d.party.root)
	);
	f.f.devices.forEach((d, i) =>
		d.store.rememberFinalPeerChannelReady(f.f.id, ready[1 - i], true)
	);
}
function openTransportPair(f: DevicePair) {
	const id = f.f.id,
		sent: { from: number; type: M; payload: Buffer }[] = [],
		refusals: string[] = [],
		resumes: string[] = [];
	const peer = (i: number) => f.f.devices[1 - i].party.binding.nodeId;
	const transports = f.f.devices.map(
		(d, i) =>
			new FinalOpeningTransport(
				{ storage: d.store, root: d.party.root },
				async () => 'unspent',
				() => null,
				(_peer, type, payload) => sent.push({ from: i, type, payload }),
				() => {
					throw Error('Unexpected opening rebroadcast');
				},
				(_id, message) => refusals.push(message),
				() => ({ alias: true, splice: true }),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				(_peer, channelId) => resumes.push(channelId)
			)
	);
	const cycle = async () => {
		sent.length = 0;
		transports.forEach((t, i) => {
			t.disconnected(peer(i));
			t.assetSpliceSpendable(id, true);
			t.reconnected(peer(i), id);
		});
		const raw = sent.filter((m) => m.type === M.CHANNEL_REESTABLISH);
		assert.equal(raw.length, 2);
		for (const m of raw)
			transports[1 - m.from].queue(peer(1 - m.from), id, {
				type: m.type,
				payload: m.payload
			});
		await new Promise<void>((done) => setImmediate(done));
		assert.deepEqual(refusals, []);
		assert(transports.every((t) => t.connected(id)));
		assert(
			!sent.some(
				(m) => m.type === M.COMMITMENT_SIGNED || m.type === M.TX_SIGNATURES
			)
		);
		return raw.map((m) =>
			decodeChannelReestablishMessage(m.payload, { finalTaproot: true })
		);
	};
	return { transports, cycle, sent, resumes, refusals };
}
const sortedIds = (m: { nextLocalNonces?: { fundingTxid: Buffer }[] }) =>
	m.nextLocalNonces!.map((n) =>
		Buffer.from(n.fundingTxid).reverse().toString('hex')
	);
describe('original-device asset splice channel_reestablish', function () {
	this.timeout(90000);
	let dir: string, f: DevicePair;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-reconnect-'));
	});
	afterEach(() => {
		for (const d of f?.f.devices ?? []) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	it('accepts a retransmitted original inbound share and rejects a different commitment after opening', async () => {
		f = signatureRoundFixture(dir);
		markReady(f);
		const id = f.f.id,
			t = openTransportPair(f),
			d = f.f.devices[0],
			peer = f.f.devices[1];
		await t.cycle();
		const share = peer.store.loadFinalPeerCommitment(id)!;
		assert(d.store.loadReceivedOpeningCommitment(id)!.equals(share));
		assert(!d.store.loadFinalPeerCommitment(id)!.equals(share));
		t.transports[0].queue(peer.party.binding.nodeId, id, {
			type: M.COMMITMENT_SIGNED,
			payload: share
		});
		await new Promise<void>((done) => setImmediate(done));
		assert.deepEqual(t.refusals, []);
		t.transports[0].queue(peer.party.binding.nodeId, id, {
			type: M.COMMITMENT_SIGNED,
			payload: d.store.loadFinalPeerCommitment(id)!
		});
		await new Promise<void>((done) => setImmediate(done));
		assert.deepEqual(t.refusals, [
			'Opening replay differs from the secured original funding'
		]);
	});

	it('renews a height-one promise on two funded opening devices, then freezes the emitted offer even across a restart', async () => {
		f = signatureRoundFixture(dir);
		markReady(f);
		const id = f.f.id,
			t = openTransportPair(f),
			first = await t.cycle(),
			second = await t.cycle(),
			txid = f.s.layout.parent.getId();
		for (const i of [0, 1]) {
			assert.equal(second[i].nextCommitmentNumber, 1n);
			assert.equal(second[i].nextRevocationNumber, 0n);
			assert.deepEqual(sortedIds(second[i]), [txid]);
			assert(
				!first[i].nextLocalNonces![0].nonce.equals(
					second[i].nextLocalNonces![0].nonce
				)
			);
			assert.deepEqual(
				second[i].myCurrentFundingLocked?.txid,
				f.s.layout.parent.getHash()
			);
		}
		const batches = f.f.devices.map((d) =>
			d.store.assetSpliceUpdateBatch(
				id,
				d.party.root,
				1n,
				[{ kind: 'fee', feeratePerKw: 400 }],
				() => 600900
			)
		);
		const own = batches[0].offer();
		assert.equal(
			JSON.parse(own.toString()).nonces[0],
			second[0].nextLocalNonces![0].nonce.toString('hex')
		);
		for (const d of f.f.devices) {
			d.store.close();
			d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		}
		const third = await openTransportPair(f).cycle();
		assert.deepEqual(third[0].nextLocalNonces, second[0].nextLocalNonces);
		assert(
			!third[1].nextLocalNonces![0].nonce.equals(
				second[1].nextLocalNonces![0].nonce
			)
		);
		assert(f.f.devices[0].store.loadFinalOpeningExit(id));
	});
	it('requests missing candidate commitment signatures with its actual construction nonce and refuses an altered promise', async () => {
		f = signatureRoundFixture(dir);
		markReady(f);
		f.construct();
		const rounds = [f.round(0), f.round(1)];
		const joint = (await Promise.all(
			rounds.map((r, i) => r.signExitShares(f.hosts[i], f.ctx(i)))
		)) as [Buffer, Buffer];
		const evidence = await Promise.all(
			rounds.map((r, i) => r.verifyExitShares(f.hosts[i], f.ctx(i), joint))
		);
		const commits = rounds.map((r, i) => r.commitmentSigned(evidence[i]));
		const m = (await openTransportPair(f).cycle())[1],
			d = f.f.devices[0];
		assert.deepEqual(m.nextFundingTxid, f.s.tx.getHash());
		assert.equal(m.nextFundingRetransmitFlags, 1);
		assert.deepEqual(
			m.currentCommitNonce,
			decodeTxCompleteMessage(rounds[1].txComplete(), { taproot: true })
				.commitNonces!.current
		);
		for (const bad of [
			{
				...m,
				myCurrentPerCommitmentPoint: m.nextLocalNonces![0].nonce.subarray(0, 33)
			},
			{ ...m, currentCommitNonce: m.nextLocalNonces![0].nonce },
			{ ...m, nextFundingTxid: Buffer.alloc(32, 77) },
			{ ...m, yourLastPerCommitmentSecret: Buffer.alloc(32, 22) }
		])
			assert.throws(() =>
				acceptAssetSpliceReestablish(d.store, f.f.id, d.party.root, bad)
			);
		for (const [i, r] of rounds.entries()) {
			r.acceptCommitmentSigned(evidence[i], commits[1 - i]);
			await r.retainExits(f.hosts[i], f.ctx(i), evidence[i]);
		}
		const waiting = await openTransportPair(f).cycle();
		for (const pending of waiting) {
			assert.deepEqual(pending.nextFundingTxid, f.s.tx.getHash());
			assert.equal(pending.nextFundingRetransmitFlags, 0);
			assert.equal(pending.currentCommitNonce, undefined);
		}
	});
	it('authenticates both live txid and nonce associations, signs on the advertised nonce, and reports the adopted funding after a secured update', async () => {
		f = await setupFundedAssetUpdatePair(dir);
		markReady(f);
		const id = f.f.id,
			t = openTransportPair(f),
			fields = await t.cycle();
		const funding = [f.s.tx.getId(), f.s.layout.parent.getId()].sort();
		const local = f.f.devices[0];
		assert.throws(() => local.store.loadFinalOpeningExit(id), /superseded/);
		const msg = fields[1];
		assert.deepEqual(sortedIds(msg), funding);
		assert.equal(msg.nextFundingTxid, undefined);
		for (const [i, d] of f.f.devices.entries())
			for (const n of fields[i].nextLocalNonces!) {
				const txid = Buffer.from(n.fundingTxid).reverse().toString('hex');
				assert.equal(
					assetReconnectReservation(d.store, id, true, 1n, txid)?.pub,
					n.nonce.toString('hex')
				);
				assert.equal(
					assetReconnectReservation(
						f.f.devices[1 - i].store,
						id,
						false,
						1n,
						txid
					)?.pub,
					n.nonce.toString('hex')
				);
			}
		const ops = (i: number): AssetUpdateChange[] => [
			{
				kind: 'add',
				htlc: {
					id: 0n,
					offeredBy: i ? 'peer' : 'local',
					paymentHash: sha256(Buffer.alloc(32, 33)),
					cltvExpiry: 601100,
					amountMsat: 4000000n,
					allocations: [{ assetId: '4c'.repeat(32), units: 2n }]
				}
			}
		];
		const batches = f.f.devices.map((d, i) =>
			d.store.assetSpliceUpdateBatch(id, d.party.root, 1n, ops(i), () => 600900)
		);
		const offers = batches.map((b) => b.offer());
		for (const [i, b] of batches.entries()) {
			b.acceptOffer(offers[1 - i]);
			assert.deepEqual(
				JSON.parse(offers[i].toString()).nonces,
				fields[i].nextLocalNonces!.map((n) => n.nonce.toString('hex'))
			);
		}
		const swapped = {
			...msg,
			nextLocalNonces: msg.nextLocalNonces!.map((n, i) => ({
				...n,
				fundingTxid: msg.nextLocalNonces![1 - i].fundingTxid
			}))
		};
		let swappedRejected = false;
		try {
			acceptAssetSpliceReestablish(local.store, id, local.party.root, swapped);
		} catch {
			swappedRejected = true;
		}
		acceptAssetSpliceReestablish(local.store, id, local.party.root, msg);
		const h = [assetUpdateTestHost(0), assetUpdateTestHost(1)],
			joins = (await Promise.all(
				batches.map((b, i) => b.signAssetShares(h[i]))
			)) as [Buffer, Buffer];
		const kids = (await Promise.all(
			batches.map((b, i) => b.signAssetHtlcs(h[i], joins))
		)) as [Buffer, Buffer];
		await Promise.all(
			batches.map((b, i) => b.verifyAssetShares(h[i], joins, kids))
		);
		const commits = batches.map((b) => b.commitments());
		await Promise.all(
			batches.map((b, i) => b.acceptCommitments(h[i], commits[1 - i]))
		);
		const revokes = batches.map((b) => b.revocation());
		batches.forEach((b, i) => b.receiveRevocation(revokes[1 - i]));
		const revived = await t.cycle();
		assert.equal(revived[1].nextCommitmentNumber, 2n);
		assert.equal(revived[1].nextRevocationNumber, 1n);
		assert.deepEqual(
			revived[1].yourLastPerCommitmentSecret,
			decodeRevokeAndAckMessage(revokes[0], { finalTaproot: true })
				.perCommitmentSecret
		);
		assert(!t.sent.some((m) => m.type === M.CHANNEL_READY));
		assert.throws(() =>
			acceptAssetSpliceReestablish(local.store, id, local.party.root, {
				...revived[1],
				yourLastPerCommitmentSecret: Buffer.alloc(32, 2)
			})
		);
		for (const [i, d] of f.f.devices.entries()) {
			const watch = new AssetSpliceConfirmationCoordinator(
				d.store,
				{
					verifySpliceFunding: async () => {},
					confirmSpliceFunding: async () => {},
					retractSpliceFunding: async () => {}
				},
				() => {},
				() => {}
			);
			watch.restore(id);
			await watch.receive(
				f.f.devices[1 - i].party.binding.nodeId,
				encodeSpliceLockedMessage({
					channelId: Buffer.from(id, 'hex'),
					fundingTxid: f.s.tx.getHash()
				})
			);
			await watch.observe(
				id,
				f.s.tx.getId(),
				600902,
				async () => ({
					txid: f.s.tx.getId(),
					blockHash: '11'.repeat(32),
					confirmations: 3
				}),
				() => true
			);
			assert(watch.status(id, f.s.tx.getId())?.available);
		}
		const final = await t.cycle();
		assert.deepEqual(sortedIds(final[0]), [f.s.tx.getId()]);
		assert.deepEqual(final[0].myCurrentFundingLocked?.txid, f.s.tx.getHash());
		assert.throws(() => local.store.loadFinalOpeningExit(id), /superseded/);
		assert(
			swappedRejected,
			'A frozen nonce was reassigned to another funding txid'
		);
	});
});
