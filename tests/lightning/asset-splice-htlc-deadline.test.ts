import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import sinon from 'sinon';
import { Transaction } from 'bitcoinjs-lib';
import {
	AssetSpliceTransport,
	type AssetSpliceHost
} from '../../src/lightning/channel/asset-splice-transport';
import type { IAssetSpliceContext } from '../../src/lightning/channel/asset-splice-agreement';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { MessageType as M } from '../../src/lightning/message/types';
import { encodeStfuMessage } from '../../src/lightning/message/stfu';
import { signatureRoundFixture } from './helpers/asset-splice-signature-round';
import { assetUpdateTestHost } from './helpers/asset-splice-update';

const expiry = 601000;
const options = { fundingFeeratePerkw: 1000, minimumDepth: 3 };
const nextTurn = () => new Promise<void>((resolve) => setImmediate(resolve));

describe('Asset splice quiescence with an irrevocable HTLC', function () {
	this.timeout(60000);
	let dir: string,
		fixture: ReturnType<typeof signatureRoundFixture>,
		tip: number;
	let clock: ReturnType<typeof sinon.useFakeTimers> | undefined;
	const transports: AssetSpliceTransport[] = [];
	beforeEach(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-htlc-deadline-'));
		fixture = signatureRoundFixture(dir);
		tip = expiry - 100;
		const { id, devices } = fixture.f;
		const ready = devices.map((d) =>
			d.store.finalOpeningChannelReady(id, d.party.root)
		);
		devices.forEach((d, i) =>
			d.store.rememberFinalPeerChannelReady(id, ready[1 - i], true)
		);
		const batches = devices.map((d, i) =>
			d.store.assetSpliceUpdateBatch(
				id,
				d.party.root,
				1n,
				[
					{
						kind: 'add',
						htlc: {
							offeredBy: i ? 'peer' : 'local',
							id: 0n,
							amountMsat: 5000000n,
							cltvExpiry: expiry,
							paymentHash: Buffer.alloc(32, 9),
							allocations: [{ assetId: '4c'.repeat(32), units: 3n }]
						}
					}
				],
				() => tip
			)
		);
		const hosts = [
			assetUpdateTestHost(0, [], 1),
			assetUpdateTestHost(1, [], 1)
		];
		const offers = batches.map((b) => b.offer());
		batches.forEach((b, i) => b.acceptOffer(offers[1 - i]));
		const joint = (await Promise.all(
			batches.map((b, i) => b.signAssetShares(hosts[i]))
		)) as [Buffer, Buffer];
		const children = (await Promise.all(
			batches.map((b, i) => b.signAssetHtlcs(hosts[i], joint))
		)) as [Buffer, Buffer];
		await Promise.all(
			batches.map((b, i) => b.verifyAssetShares(hosts[i], joint, children))
		);
		const commits = batches.map((b) => b.commitments());
		await Promise.all(
			batches.map((b, i) => b.acceptCommitments(hosts[i], commits[1 - i]))
		);
		const revokes = batches.map((b) => b.revocation());
		batches.forEach((b, i) => b.receiveRevocation(revokes[1 - i]));
		clock = sinon.useFakeTimers({
			now: Date.now(),
			toFake: ['Date', 'setTimeout', 'clearTimeout']
		});
	});
	afterEach(() => {
		transports.splice(0).forEach((t) => t.destroy());
		clock?.restore();
		for (const d of fixture.f.devices) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	function device(
		proposal: (ctx: IAssetSpliceContext) => Promise<Buffer> = async () =>
			Buffer.from('proposal'),
		index = 0
	) {
		const d = fixture.f.devices[index],
			id = fixture.f.id,
			peer = fixture.f.devices[1 - index].party.binding.nodeId;
		const wires: number[] = [],
			disconnected: string[] = [],
			exits: Buffer[] = [],
			abandoned: string[] = [];
		const t = new AssetSpliceTransport(
			{ storage: d.store, root: d.party.root },
			{
				proposeSplice: proposal,
				spliceContribution: () => 0n,
				abandonSplice: async (ctx: IAssetSpliceContext) => {
					abandoned.push(ctx.attempt.toString('hex'));
				}
			} as unknown as AssetSpliceHost,
			(p, c) => p === peer && c === id,
			() => true,
			() => tip,
			(_p, type) => wires.push(type),
			async () => 'unspent',
			() => undefined,
			() => undefined,
			() => undefined,
			{
				disconnect: (p: string) => disconnected.push(p),
				close: (c: string) => {
					exits.push(d.store.requestFinalOpeningExit(c));
				}
			}
		);
		transports.push(t);
		return {
			d,
			id,
			peer,
			t,
			wires,
			disconnected,
			exits,
			abandoned,
			ack: () =>
				t.handle(
					peer,
					M.STFU,
					encodeStfuMessage({
						channelId: Buffer.from(id, 'hex'),
						initiator: false
					})
				)
		};
	}
	it('declines local and remote starts at the earliest claim height before accepting a quiescent state', async () => {
		const n = device();
		tip = expiry - 25;
		n.t.checkHtlcDeadlines(tip, 25);
		await assert.rejects(n.t.start(n.id, options), /claim margin/i);
		n.t.handle(
			n.peer,
			M.STFU,
			encodeStfuMessage({
				channelId: Buffer.from(n.id, 'hex'),
				initiator: true
			})
		);
		await nextTurn();
		assert.deepEqual(n.wires, []);
		assert.deepEqual(n.disconnected, [n.peer]);
		assert(
			!n.d.store
				.readAssetSpliceJournal<{ kind: string }>(n.id)
				.records.some((r) => r.kind === 'peer-splice')
		);
	});
	it('preserves the first quiescence deadline when simultaneous starts elect the other initiator', async () => {
		const n = device(undefined, 1);
		await n.t.start(n.id, options);
		clock!.tick(59000);
		n.t.handle(
			n.peer,
			M.STFU,
			encodeStfuMessage({
				channelId: Buffer.from(n.id, 'hex'),
				initiator: true
			})
		);
		await nextTurn();
		const begins = n.d.store
			.readAssetSpliceJournal<{
				kind: string;
				deadline: number;
				initiator: boolean;
			}>(n.id)
			.records.filter((r) => r.kind === 'peer-splice');
		assert.deepEqual(
			begins.map((b) => b.initiator),
			[true, false]
		);
		assert.equal(begins[1].deadline, begins[0].deadline);
		clock!.tick(1000);
		assert.deepEqual(n.disconnected, [n.peer]);
	});
	it('ends quiescence at sixty seconds even while a wallet proposal is outstanding', async () => {
		let ctx: IAssetSpliceContext | undefined,
			complete!: (bytes: Buffer) => void;
		const n = device((c) => {
			ctx = c;
			return new Promise((resolve) => {
				complete = resolve;
			});
		});
		await n.t.start(n.id, options);
		clock!.tick(59000);
		n.ack();
		await nextTurn();
		assert(ctx);
		assert(ctx.currentParent());
		clock!.tick(1000);
		assert.deepEqual(n.disconnected, [n.peer]);
		assert(!ctx.currentParent());
		complete(Buffer.from('late-proposal'));
		await nextTurn();
		await nextTurn();
		assert.deepEqual(n.wires, [M.STFU]);
		assert.equal(n.abandoned.length, 1);
		assert.deepEqual(n.exits, []);
		assert(
			n.d.store
				.readAssetSpliceJournal<{ field?: string }>(n.id)
				.records.some((r) => r.field === 'retired')
		);
	});
	it('preserves an irreversible wallet reservation on timeout and resolves the latest signed parent offline at the claim margin', async () => {
		let ctx: IAssetSpliceContext | undefined;
		const n = device(async (c) => {
			ctx = c;
			return Buffer.from('retained-proposal');
		});
		await n.t.start(n.id, options);
		n.ack();
		await nextTurn();
		assert(ctx);
		assert(ctx.currentParent());
		assert(n.wires.includes(M.SPLICE));
		const journal = n.d.store.readAssetSpliceJournal(n.id);
		n.d.store.appendAssetSpliceEvent(n.id, journal, {
			kind: 'splice-authorization-start',
			attempt: ctx.attempt.toString('hex')
		});
		clock!.tick(60000);
		await nextTurn();
		assert.deepEqual(n.disconnected, [n.peer]);
		assert(!ctx.currentParent());
		assert.deepEqual(n.abandoned, []);
		n.t.destroy();
		n.d.store.close();
		n.d.store = SqliteStorage.openFinalWallet(n.d.file, n.d.party.binding);
		const reopened = device();
		reopened.t.resume(n.peer, n.id);
		await nextTurn();
		assert.deepEqual(reopened.wires, []);
		assert.deepEqual(reopened.disconnected, []);
		reopened.t.destroy();
		const offline = device();
		tip = expiry - 19;
		offline.t.checkHtlcDeadlines(tip, 18);
		assert.deepEqual(offline.exits, []);
		tip++;
		offline.t.checkHtlcDeadlines(tip, 18);
		assert.equal(offline.exits.length, 1);
		const prior = n.d.store.assetSpliceUpdateHead(n.id).committed!;
		assert.equal(
			Transaction.fromBuffer(offline.exits[0]).toHex(),
			prior.members[0].localCommitment
		);
		assert.deepEqual(offline.abandoned, []);
	});
});
