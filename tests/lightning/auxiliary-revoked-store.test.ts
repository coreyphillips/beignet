/**
 * Issue #2093: the store of revoked asset views.
 *
 * To punish a revoked commitment whose outputs carry units, a node needs
 * the asset side of that commitment as it was signed. The view of each
 * revoked commitment of the peer goes to a table of its own, in the
 * transaction of the channel row that drops it, and leaves memory once
 * that transaction has committed.
 */

import { expect } from 'chai';
import type Database from 'better-sqlite3';
import type { IAuxiliaryCommitmentData } from '../../src/lightning/channel/auxiliary';
import {
	holdAuxiliaryRevokedView,
	markAuxiliaryRevokedViewsStored,
	recordAuxiliaryRevokedView
} from '../../src/lightning/channel/auxiliary-revoked';
import type { IChannelState } from '../../src/lightning/channel/channel-state';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	deserializeAuxiliaryCommitmentView,
	deserializeAuxiliaryState,
	serializeAuxiliaryCommitmentView,
	serializeAuxiliaryState
} from '../../src/lightning/storage/auxiliary-serialization';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { settle } from './helpers/auxiliary-on-chain';
import { amountRecord, taprootPair } from './helpers/auxiliary-pair';

describe('the store of revoked asset views (issue #2093)', function () {
	this.timeout(180_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
	});

	async function pair(
		tag: string
	): Promise<{ alice: IAssetHost; bob: IAssetHost; channelId: Buffer }> {
		const alice = assetHost(tag, 1, {}, { sqlite: true });
		const bob = assetHost(
			tag,
			2,
			{
				valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }) =>
					(context.auxiliaryAmount ?? 0n) * 1000n
			},
			{ sqlite: true }
		);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		return { alice, bob, channelId };
	}

	/** Alice pays Bob `units` over the asset channel, and it settles. */
	async function pay(
		alice: IAssetHost,
		bob: IAssetHost,
		channelId: Buffer,
		units: bigint
	): Promise<void> {
		const invoice = bob.node.createInvoice({
			amountMsat: units * 1000n,
			description: 'units'
		});
		alice.node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						shortChannelId: Buffer.alloc(8, 9),
						amountToForwardMsat: units * 1000n,
						outgoingCltvValue: 40
					}
				]
			},
			invoice.paymentHash,
			40,
			invoice.paymentSecret,
			undefined,
			undefined,
			undefined,
			undefined,
			{
				assetPayment: {
					channelId,
					wireAmountMsat: 354_000n,
					customRecords: amountRecord(units)
				}
			}
		);
		await settle();
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	}

	// A node with the asset channel alone has no channel to name in the
	// routing hints of an invoice, and says so each time.
	const errorsOf = (host: IAssetHost): string[] =>
		host.errors.filter((error) => !error.startsWith('NO_ROUTING_HINTS'));
	const stateOf = (host: IAssetHost, channelId: Buffer): IChannelState =>
		host.node.getChannelManager().getChannel(channelId)!.getFullState();
	const database = (host: IAssetHost): Database.Database =>
		(host.storage as unknown as { db: Database.Database }).db;
	const stored = (
		host: IAssetHost,
		channelId: Buffer
	): { rows: number; bytes: number } =>
		database(host)
			.prepare(
				'SELECT count(*) AS rows, coalesce(sum(length(view_json)), 0) AS bytes ' +
					'FROM auxiliary_revoked_commitments WHERE channel_id = ?'
			)
			.get(channelId.toString('hex')) as { rows: number; bytes: number };
	const inMemory = (host: IAssetHost, channelId: Buffer): number =>
		stateOf(host, channelId).auxiliaryState!.revokedCommitments?.size ?? 0;

	it('holds the view of every revoked commitment of the peer as it was signed, and only the last few in memory and in the row', async () => {
		const { alice, bob, channelId } = await pair('aux-revoked-store');
		const hex = channelId.toString('hex');
		// Every view, as each save of the row held it while it was current.
		const signed = new Map<IAssetHost, Map<string, string>>();
		for (const host of [alice, bob]) {
			const views = new Map<string, string>();
			signed.set(host, views);
			const storage = host.storage!;
			const save = storage.saveChannel.bind(storage);
			storage.saveChannel = (id, state, peer): void => {
				for (const [number, view] of state.auxiliaryState?.remoteCommitments ??
					[]) {
					views.set(number.toString(), serializeAuxiliaryCommitmentView(view));
				}
				save(id, state, peer);
			};
		}
		for (let i = 0; i < 6; i++) await pay(alice, bob, channelId, 10n);

		for (const host of [alice, bob]) {
			const state = stateOf(host, channelId);
			const storage = host.storage as SqliteStorage;
			const current = state.remoteCommitmentNumber;
			expect(current > 10n).to.equal(true);
			let found = 0;
			for (let number = 0n; number < current; number++) {
				const view = storage.loadAuxiliaryRevokedCommitment(hex, number);
				// The last one revoked is still among the views of the row,
				// until the next signature drops it from there.
				const held =
					state.auxiliaryState!.revokedCommitments?.get(number) ??
					state.auxiliaryState!.remoteCommitments.get(number);
				expect(!!view || !!held, `commitment ${number}`).to.equal(true);
				if (!view) continue;
				found++;
				expect(serializeAuxiliaryCommitmentView(view)).to.equal(
					signed.get(host)!.get(number.toString())
				);
			}
			expect(found).to.be.at.least(Number(current) - 3);
			expect(stored(host, channelId).rows).to.be.at.least(found);
			// The commitments that are not revoked are in the row, not here.
			expect(storage.loadAuxiliaryRevokedCommitment(hex, current)).to.equal(
				null
			);
			expect(state.auxiliaryState!.remoteCommitments.has(current)).to.equal(
				true
			);
			expect(inMemory(host, channelId)).to.be.at.most(2);
			const row = storage.loadChannel(hex)!.state.auxiliaryState!;
			expect(row.revokedCommitments?.size ?? 0).to.be.at.most(2);
		}
		expect(errorsOf(alice).concat(errorsOf(bob))).to.deep.equal([]);

		// The views go with the channel.
		(alice.storage as SqliteStorage).deleteChannel(hex);
		expect(stored(alice, channelId)).to.deep.equal({ rows: 0, bytes: 0 });
	});

	it('grows by one entry of a steady size for each of 300 revoked commitments, while the row and memory do not grow', () => {
		// Two channels that sign round after round, and the storage of a
		// node under one of them: each round the row is written, and what
		// the write put in the store is let go, as a commit does.
		const made = taprootPair(77);
		const storage = new SqliteStorage(':memory:');
		storage.open();
		try {
			const hex = made.id.toString('hex');
			const state = made.aliceChannel.getFullState();
			const db = (storage as unknown as { db: Database.Database }).db;
			const measure = (): { rows: number; bytes: number; row: number } => ({
				...(db
					.prepare(
						'SELECT count(*) AS rows, coalesce(sum(length(view_json)), 0) AS bytes ' +
							'FROM auxiliary_revoked_commitments WHERE channel_id = ?'
					)
					.get(hex) as { rows: number; bytes: number }),
				row: (
					db
						.prepare(
							'SELECT length(state_json) AS bytes FROM channels WHERE channel_id = ?'
						)
						.get(hex) as { bytes: number }
				).bytes
			});
			let most = 0;
			const write = (): void => {
				const views = state.auxiliaryState!.revokedCommitments;
				most = Math.max(most, views?.size ?? 0);
				const written = [...(views?.keys() ?? [])];
				storage.saveChannel(hex, state, 'peer');
				markAuxiliaryRevokedViewsStored(state, written);
			};
			// Signed rounds: the view of a commitment leaves the row two
			// rounds after it was signed, when it is revoked and replaced.
			const SIGNED = 24;
			for (let round = 1; round <= SIGNED; round++) {
				expect(
					made.alice.updateChannelFee(made.id, 700 + (round % 2) * 100).ok
				).to.equal(true);
				write();
				expect(measure().rows).to.equal(Math.max(0, round - 2));
			}
			expect(state.remoteCommitmentNumber).to.equal(BigInt(SIGNED));
			const signed = measure();
			// The rest are recorded as the channel records them, with the
			// view of the last round: three hundred signed rounds take two
			// minutes and ask nothing more of the store.
			const view = state.auxiliaryState!.remoteCommitments.get(BigInt(SIGNED))!;
			const marks: Array<ReturnType<typeof measure>> = [];
			for (let number = SIGNED - 1; number <= 300; number++) {
				recordAuxiliaryRevokedView(state, BigInt(number), view);
				write();
				if (number % 100 === 0) marks.push(measure());
			}
			const [first, second, last] = marks;
			expect([first.rows, second.rows, last.rows]).to.deep.equal([
				100, 200, 300
			]);
			const each = (second.bytes - first.bytes) / 100;
			// With the provider of these tests a view is a few hundred bytes
			// of text; a real one is as large as what its provider keeps
			// with a commitment. It does not grow with the rounds.
			expect(each).to.be.within(100, 2_000);
			expect((last.bytes - second.bytes) / 100).to.equal(each);
			expect(Math.abs(signed.bytes / signed.rows - each)).to.be.lessThan(
				each * 0.1
			);
			expect(last.row).to.equal(first.row);
			expect(Math.abs(first.row - signed.row)).to.be.lessThan(64);
			expect(most).to.equal(1);
			expect(state.auxiliaryState!.revokedCommitments).to.equal(undefined);
			// Each is read back by its number.
			expect(storage.loadAuxiliaryRevokedCommitment(hex, 150n)).to.deep.equal(
				view
			);
			expect(storage.loadAuxiliaryRevokedCommitment(hex, 301n)).to.equal(null);
		} finally {
			storage.close();
		}
	});

	it('writes a view in the transaction of the channel row: a transaction that is rolled back leaves neither, and the view stays in memory', async () => {
		const { alice, bob, channelId } = await pair('aux-revoked-rollback');
		const hex = channelId.toString('hex');
		await pay(alice, bob, channelId, 10n);
		const storage = alice.storage as SqliteStorage;
		const state = stateOf(alice, channelId);
		const view: IAuxiliaryCommitmentData = [
			...state.auxiliaryState!.remoteCommitments.values()
		][0];
		const number = 0xffffffn;
		(state.auxiliaryState!.revokedCommitments ??= new Map()).set(number, view);
		const peer = bob.node.getNodeId();
		expect(() =>
			database(alice).transaction(() => {
				storage.saveChannel(hex, state, peer);
				expect(
					storage.loadAuxiliaryRevokedCommitment(hex, number)
				).to.not.equal(null);
				throw new Error('the disk is full');
			})()
		).to.throw('the disk is full');
		expect(storage.loadAuxiliaryRevokedCommitment(hex, number)).to.equal(null);
		expect(state.auxiliaryState!.revokedCommitments!.has(number)).to.equal(
			true
		);

		storage.saveChannel(hex, state, peer);
		expect(storage.loadAuxiliaryRevokedCommitment(hex, number)).to.deep.equal(
			view
		);
		// Stored, it is let go; held for a commitment on the chain, it stays.
		markAuxiliaryRevokedViewsStored(state, [number]);
		expect(state.auxiliaryState!.revokedCommitments?.has(number)).to.not.equal(
			true
		);
		expect(
			holdAuxiliaryRevokedView(state, number, () =>
				storage.loadAuxiliaryRevokedCommitment(hex, number)
			)
		).to.equal(true);
		markAuxiliaryRevokedViewsStored(state, [number]);
		expect(state.auxiliaryState!.revokedCommitments!.get(number)).to.deep.equal(
			view
		);
		// A view that is nowhere cannot be held.
		expect(holdAuxiliaryRevokedView(state, 0xfffffen, () => null)).to.equal(
			false
		);
	});

	it('reads a revoked view back as it was written, in the row and in the store, and refuses one that is not a view', async () => {
		const { alice, bob, channelId } = await pair('aux-revoked-codec');
		await pay(alice, bob, channelId, 10n);
		const auxiliary = stateOf(alice, channelId).auxiliaryState!;
		const view = [...auxiliary.remoteCommitments.values()][0];
		expect(view.outputLeaves.size).to.be.greaterThan(0);
		expect(
			deserializeAuxiliaryCommitmentView(serializeAuxiliaryCommitmentView(view))
		).to.deep.equal(view);
		const withRevoked = {
			...auxiliary,
			revokedCommitments: new Map([
				[7n, view],
				[8n, view]
			])
		};
		delete withRevoked.revokedCommitmentHeld;
		const read = deserializeAuxiliaryState(
			JSON.parse(JSON.stringify(serializeAuxiliaryState(withRevoked)))
		);
		expect(read.revokedCommitments).to.deep.equal(
			withRevoked.revokedCommitments
		);
		// A state without revoked views is written as it always was.
		const without = { ...withRevoked };
		delete (without as { revokedCommitments?: unknown }).revokedCommitments;
		expect('revokedCommitments' in serializeAuxiliaryState(without)).to.equal(
			false
		);
		for (const text of ['null', '{}', '{"customData":"00"}', '[]']) {
			expect(() => deserializeAuxiliaryCommitmentView(text), text).to.throw();
		}
	});

	it('tells its host how large the store of revoked views of a channel is, in rows and in bytes, and it grows with every commitment the peer revokes', async () => {
		const { alice, bob, channelId } = await pair('aux-revoked-store-size');
		const sizeOf = (
			host: IAssetHost
		): { rows: number; bytes: number } | undefined =>
			host.node.getAuxiliaryChannelInfo(channelId)!.revokedViews;
		// Asked before anything was revoked, and after every payment: what
		// the host reads is what the table holds, kept current by the write
		// of each row and never by reading every view again.
		let last = sizeOf(alice)!;
		expect(last).to.deep.equal(stored(alice, channelId));
		for (let i = 0; i < 5; i++) {
			await pay(alice, bob, channelId, 10n);
			for (const host of [alice, bob]) {
				expect(sizeOf(host)).to.deep.equal(stored(host, channelId));
			}
			const now = sizeOf(alice)!;
			// Every payment revokes commitments of the peer, and each one
			// revoked is a row more.
			expect(now.rows).to.be.greaterThan(last.rows);
			expect(now.bytes).to.be.greaterThan(last.bytes);
			last = now;
		}
		expect(last.rows).to.be.greaterThan(inMemory(alice, channelId));
		// What is handed out is a copy.
		sizeOf(alice)!.rows = 0;
		expect(sizeOf(alice)).to.deep.equal(last);

		// A write of the channel row inside a transaction that is rolled
		// back leaves the answer as it was.
		const storage = alice.storage!;
		const before = stored(alice, channelId);
		expect(() =>
			database(alice).transaction(() => {
				const state = stateOf(alice, channelId);
				const [number, view] = [
					...state.auxiliaryState!.remoteCommitments.entries()
				][0];
				state.auxiliaryState!.revokedCommitments = new Map([
					[number + 1_000_000n, view]
				]);
				storage.saveChannel(
					channelId.toString('hex'),
					state,
					bob.node.getNodeId()
				);
				expect(sizeOf(alice)!.rows).to.equal(before.rows + 1);
				throw new Error('rolled back');
			})()
		).to.throw('rolled back');
		expect(sizeOf(alice)).to.deep.equal(before);
		expect(stored(alice, channelId)).to.deep.equal(before);

		// A storage asked for the first time, as after a restart, counts the
		// table once.
		const again = (
			storage as unknown as {
				_auxiliaryRevokedSizes: Map<string, unknown>;
			}
		)._auxiliaryRevokedSizes;
		again.clear();
		expect(sizeOf(alice)).to.deep.equal(before);

		// The store goes with the channel.
		storage.deleteChannel(channelId.toString('hex'));
		expect(
			storage.auxiliaryRevokedCommitmentsSize(channelId.toString('hex'))
		).to.deep.equal({ rows: 0, bytes: 0 });
	});
});
