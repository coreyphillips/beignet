/**
 * Issue #2093: an outgoing asset payment whose record was written and whose
 * HTLC never entered its channel.
 *
 * The record of an asset payment is written, with the HTLC id it was
 * prepared for, before the HTLC is added. The database of each test here is
 * a copy taken at exactly that point: the node stops with the record and
 * its HTLC mapping on disk and nothing in the channel. When it is restored
 * the payment ends FAILED at once, in a committed write and without waiting
 * for a block or for ten minutes; the host is told through onHtlcResolved
 * with the outcome 'never-sent'; the part is no longer listed for the
 * payment; and the id it was recorded under, which the channel gives to its
 * next HTLC, belongs to that HTLC alone.
 */

import { expect } from 'chai';
import { createHash } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	payAssetUnits,
	reconnectHosts,
	turns,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

describe('an outgoing asset payment that was recorded and never sent (issue #2093 step 8)', function () {
	this.timeout(60_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	const directories: string[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			try {
				host.node.destroy();
			} catch {
				// already destroyed
			}
			try {
				host.storage?.close();
			} catch {
				// already closed
			}
		}
		for (const directory of directories.splice(0)) {
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});

	interface ITold {
		outcome: string;
		htlcId: bigint;
		direction: string;
		units: bigint;
		hash: string;
		channel: string;
		records: unknown;
	}

	const telling = (told: ITold[]): Parameters<typeof assetHost>[2] => ({
		onHtlcResolved: (context) => {
			told.push({
				outcome: context.outcome,
				htlcId: context.htlcId,
				direction: context.direction,
				units: context.auxiliaryAmount,
				hash: context.paymentHash.toString('hex'),
				channel: context.channelId.toString('hex'),
				records: context.customRecords
			});
		}
	});

	const failures = (host: IAssetHost): string[] => {
		const failed: string[] = [];
		host.node.on('payment:failed', (payment: { paymentHash: Buffer }) => {
			failed.push(payment.paymentHash.toString('hex'));
		});
		return failed;
	};

	/**
	 * Alice and Bob with an asset channel, and a copy of Alice's database
	 * taken where her node stops: the record of a payment of 5000 units and
	 * its HTLC mapping are written, and the HTLC has not entered the channel.
	 */
	async function stoppedBeforeTheHtlc(tag: string): Promise<{
		bob: IAssetHost;
		channelId: Buffer;
		paymentHash: Buffer;
		ordinaryHash: Buffer;
		copy: () => string;
	}> {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-never-sent-'));
		directories.push(directory);
		const snapshot = path.join(directory, 'stopped.sqlite');
		const alice = assetHost(
			tag,
			1,
			{},
			{ sqlitePath: path.join(directory, 'alice.sqlite') }
		);
		const bob = assetHost(
			tag,
			2,
			{ valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n },
			{ sqlite: true }
		);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		// An ordinary payment in the same state: master's sweep is its own.
		const ordinaryHash = createHash('sha256')
			.update(`${tag} ordinary`)
			.digest();
		alice.storage!.savePayment(ordinaryHash.toString('hex'), {
			paymentHash: ordinaryHash,
			amountMsat: 1_000_000n,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now()
		});
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'never sent'
		});
		const manager = alice.node.getChannelManager() as unknown as {
			addHtlc: (...args: unknown[]) => unknown;
		};
		let stops = 0;
		manager.addHtlc = () => {
			(
				alice.storage as unknown as { db: { exec(sql: string): unknown } }
			).db.exec(`VACUUM INTO '${snapshot}'`);
			stops++;
			throw new Error('the node stopped here');
		};
		try {
			payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		} catch {
			// the stop
		}
		expect(stops).to.equal(1);
		alice.node.destroy();
		alice.storage!.close();
		let copies = 0;
		return {
			bob,
			channelId,
			paymentHash: invoice.paymentHash,
			ordinaryHash,
			copy: () => {
				const file = path.join(directory, `restored-${copies++}.sqlite`);
				fs.copyFileSync(snapshot, file);
				return file;
			}
		};
	}

	it('is ended FAILED when the node is restored, with no block, in a committed write, is reported as never sent, and is no longer listed under an HTLC id the next HTLC takes', async () => {
		const tag = 'aux-never-sent';
		const { bob, channelId, paymentHash, ordinaryHash, copy } =
			await stoppedBeforeTheHtlc(tag);
		const hashHex = paymentHash.toString('hex');
		const told: ITold[] = [];
		const file = copy();
		const alice = assetHost(tag, 1, telling(told), { sqlitePath: file });
		hosts.push(alice);
		const failed = failures(alice);

		// At once: nothing has been awaited, and no block has come.
		const record = alice.node.getPayment(paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.FAILED);
		expect(record.failureReason).to.include('never sent');
		expect(record.auxiliary).to.equal(true);
		expect(told).to.deep.equal([
			{
				outcome: 'never-sent',
				htlcId: 0n,
				direction: 'OFFERED',
				units: 0n,
				hash: hashHex,
				channel: channelId.toString('hex'),
				records: undefined
			}
		]);
		expect(alice.node.getAuxiliaryPaymentHtlcs(paymentHash)).to.deep.equal([]);
		// The write is committed, and what it holds says nothing is owed.
		const stored = alice.storage!.loadPayment(hashHex)!;
		expect(stored.status).to.equal(PaymentStatus.FAILED);
		expect(Object.keys(stored.metadata ?? {}).sort()).to.deep.equal([
			'_auxiliaryChannelId',
			'_auxiliaryWireAmountMsat'
		]);
		expect(
			alice
				.storage!.loadAllHtlcPaymentMappings()
				.map((row) => row.paymentHashHex)
		).to.not.include(hashHex);
		// The ordinary payment in the same state is not this pass's.
		expect(alice.node.getPayment(ordinaryHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		await turns(5);
		expect(failed).to.deep.equal([hashHex]);

		// The channel gives the id to its next HTLC, and it is that HTLC's.
		connectHosts(alice, bob);
		await reconnectHosts(alice, bob);
		const next = bob.node.createInvoice({
			amountMsat: 2_000_000n,
			description: 'the next HTLC'
		});
		payAssetUnits(alice, bob, channelId, next, 2_000_000n, 2000n);
		await turns(200);
		expect(alice.node.getPayment(next.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(
			alice.node
				.getAuxiliaryPaymentHtlcs(next.paymentHash)
				.map((htlc) => htlc.htlcId)
		).to.deep.equal([0n]);
		expect(alice.node.getAuxiliaryPaymentHtlcs(paymentHash)).to.deep.equal([]);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(told.map((entry) => `${entry.outcome}:${entry.hash}`)).to.deep.equal(
			[`never-sent:${hashHex}`, `fulfilled:${next.paymentHash.toString('hex')}`]
		);
		expect(failed).to.deep.equal([hashHex]);
	});

	it('with a block after the restore it is failed once and reported once, and a further restart reports nothing', async () => {
		const tag = 'aux-never-sent-block';
		const { paymentHash, ordinaryHash, copy } = await stoppedBeforeTheHtlc(tag);
		const hashHex = paymentHash.toString('hex');
		const told: ITold[] = [];
		const file = copy();
		const alice = assetHost(tag, 1, telling(told), { sqlitePath: file });
		hosts.push(alice);
		const failed = failures(alice);
		alice.node.handleNewBlock(1);
		await turns(20);
		alice.node.handleNewBlock(2);
		await turns(20);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(failed).to.deep.equal([hashHex]);
		expect(told.map((entry) => entry.outcome)).to.deep.equal(['never-sent']);
		// Master's sweep still owns the ordinary payment: not ten minutes old.
		expect(alice.node.getPayment(ordinaryHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		alice.node.destroy();
		alice.storage!.close();

		const again: ITold[] = [];
		const restarted = assetHost(tag, 1, telling(again), { sqlitePath: file });
		hosts.push(restarted);
		const failedAgain = failures(restarted);
		restarted.node.handleNewBlock(3);
		await turns(20);
		expect(again).to.deep.equal([]);
		expect(failedAgain).to.deep.equal([]);
		expect(restarted.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
	});

	it('a host whose callback throws is told again when the node is next restored, and once it has returned, no more', async () => {
		const tag = 'aux-never-sent-redelivery';
		const { paymentHash, copy } = await stoppedBeforeTheHtlc(tag);
		const hashHex = paymentHash.toString('hex');
		const file = copy();
		let asked = 0;
		const first = assetHost(
			tag,
			1,
			{
				onHtlcResolved: () => {
					asked++;
					throw new Error('the asset store is down');
				}
			},
			{ sqlitePath: file }
		);
		hosts.push(first);
		expect(asked).to.equal(1);
		// Ended all the same, and no longer listed.
		expect(first.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(first.node.getAuxiliaryPaymentHtlcs(paymentHash)).to.deep.equal([]);
		expect(
			first.storage!.loadPayment(hashHex)!.metadata!._auxiliaryNeverSent
		).to.be.a('string');
		first.node.destroy();
		first.storage!.close();

		const told: ITold[] = [];
		const second = assetHost(tag, 1, telling(told), { sqlitePath: file });
		hosts.push(second);
		expect(
			told.map((entry) => `${entry.outcome}:${entry.htlcId}`)
		).to.deep.equal(['never-sent:0']);
		second.node.destroy();
		second.storage!.close();

		const third: ITold[] = [];
		const last = assetHost(tag, 1, telling(third), { sqlitePath: file });
		hosts.push(last);
		expect(third).to.deep.equal([]);
	});
});
