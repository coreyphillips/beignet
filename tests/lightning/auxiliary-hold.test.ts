/**
 * Issue #2093: a hold invoice paid over an asset channel, and the one HTLC
 * an asset invoice is paid by.
 *
 * The host values an asset HTLC once, when it is accepted. A held HTLC keeps
 * that value for as long as it is held, through a reestablish and a restart,
 * and is listed in flight by getAuxiliaryChannelInfo all the while. Its
 * settle and its cancel go through the asset provider like any other
 * removal: one the provider refuses is not reported as done, stays chosen,
 * and is asked for again by the node's periodic work.
 *
 * An asset invoice paid in several parts is outside this build: the sender
 * refuses it with a typed error and the receiver fails the part back.
 */

import { expect } from 'chai';
import { createHash } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	AuxiliaryPaymentError,
	PaymentStatus
} from '../../src/lightning/node/types';
import {
	assetHost,
	connectHosts,
	failingProvider,
	openAssetChannel,
	payAssetUnits,
	reconnectHosts,
	turns,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

describe('a hold invoice paid over an asset channel (issue #2093 step 8)', function () {
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

	const sha = (data: Buffer | string): Buffer =>
		createHash('sha256').update(data).digest();

	const inFlight = (
		host: IAssetHost,
		channelId: Buffer
	): Array<{ direction: string; units?: bigint; hash: string }> =>
		host.node.getAuxiliaryChannelInfo(channelId)!.htlcs.map((htlc) => ({
			direction: htlc.direction,
			units: htlc.auxiliaryAmount,
			hash: htlc.paymentHash.toString('hex')
		}));

	const units = (host: IAssetHost, channelId: Buffer): bigint =>
		host.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance;

	const paid = (host: IAssetHost): string[] => {
		const received: string[] = [];
		host.node.on('payment:received', (payment: { paymentHash: Buffer }) => {
			received.push(payment.paymentHash.toString('hex'));
		});
		return received;
	};

	/** The node's periodic work on what the asset provider left owed. */
	const periodicWork = (host: IAssetHost): void =>
		(
			host.node as unknown as { retryAuxiliaryOwed: () => void }
		).retryAuxiliaryOwed();

	/** Alice has paid 5000 units to a hold invoice of Bob, who holds the HTLC. */
	async function held(
		tag: string,
		arm: { down: boolean; thrown: number },
		bobHooks: Parameters<typeof assetHost>[2] = {}
	): Promise<{
		alice: IAssetHost;
		bob: IAssetHost;
		channelId: Buffer;
		paymentHash: Buffer;
		preimage: Buffer;
	}> {
		const alice = assetHost(tag, 1, {}, { sqlite: true });
		const bob = assetHost(
			tag,
			2,
			{
				// Bob's provider cannot build a commitment while `arm.down`.
				provider: failingProvider((method) => {
					if (method !== 'buildCommitment' || !arm.down) return false;
					arm.thrown++;
					return true;
				}),
				valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n,
				...bobHooks
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
		const preimage = sha(`${tag} preimage`);
		const paymentHash = sha(preimage);
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'held',
			hold: true,
			paymentHash
		});
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);
		expect(inFlight(bob, channelId)).to.have.length(1);
		return { alice, bob, channelId, paymentHash, preimage };
	}

	it('is valued once, at its acceptance, is listed in flight, and is settled after a restart for what it was valued at', async () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-hold-'));
		directories.push(directory);
		const file = path.join(directory, 'bob.sqlite');
		const asked = { first: 0, restarted: 0 };
		const alice = assetHost('aux-hold-restart', 1, {}, { sqlite: true });
		const bob = assetHost(
			'aux-hold-restart',
			2,
			{
				valueIncomingHtlc: (context) => {
					asked.first++;
					return context.auxiliaryAmount! * 1000n;
				}
			},
			{ sqlitePath: file }
		);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag: 'aux-hold-restart',
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		const preimage = sha('aux-hold-restart preimage');
		const paymentHash = sha(preimage);
		const hashHex = paymentHash.toString('hex');
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'held through a restart',
			hold: true,
			paymentHash
		});
		expect(invoice.paymentHash.equals(paymentHash)).to.equal(true);
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);
		expect(asked.first).to.equal(1);
		const listed = [{ direction: 'received', units: 5000n, hash: hashHex }];
		expect(inFlight(bob, channelId)).to.deep.equal(listed);
		// Held, the units are nobody's yet.
		expect(units(bob, channelId)).to.equal(1000n);
		expect(bob.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		// A reestablish goes through the held HTLC again, and asks nothing.
		await reconnectHosts(alice, bob);
		expect(asked.first).to.equal(1);
		expect(inFlight(bob, channelId)).to.deep.equal(listed);

		bob.node.destroy();
		bob.storage!.close();
		const restarted = assetHost(
			'aux-hold-restart',
			2,
			{
				// A host that could no longer value it: it is not asked.
				valueIncomingHtlc: () => {
					asked.restarted++;
					throw new Error('no rate for these units any more');
				}
			},
			{ sqlitePath: file }
		);
		hosts.push(restarted);
		const received = paid(restarted);
		connectHosts(alice, restarted);
		await reconnectHosts(alice, restarted);
		await turns(100);
		expect(asked.restarted).to.equal(0);
		expect(inFlight(restarted, channelId)).to.deep.equal(listed);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		expect(restarted.node.settleHeldHtlc(paymentHash, preimage)).to.equal(true);
		await turns(200);
		const record = restarted.node.getPayment(paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.COMPLETED);
		expect(record.amountMsat).to.equal(5_000_000n);
		expect('receivedMsat' in record).to.equal(false);
		expect(record.auxiliary).to.equal(true);
		expect(restarted.node.getInvoice(hashHex)!.auxiliary).to.equal(true);
		expect(received).to.deep.equal([hashHex]);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(inFlight(restarted, channelId)).to.deep.equal([]);
		expect(units(restarted, channelId)).to.equal(6000n);
		expect(units(alice, channelId)).to.equal(4000n);
	});

	it('a settle the asset provider refuses is not reported as done, cannot be turned into a cancel, and is made by the periodic work', async () => {
		const arm = { down: false, thrown: 0 };
		const { alice, bob, channelId, paymentHash, preimage } = await held(
			'aux-hold-settle',
			arm
		);
		const received = paid(bob);
		arm.down = true;
		expect(bob.node.settleHeldHtlc(paymentHash, preimage)).to.equal(false);
		await turns(100);
		expect(arm.thrown).to.be.greaterThan(0);
		expect(received).to.deep.equal([]);
		expect(bob.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(inFlight(bob, channelId)).to.have.length(1);
		// The preimage is stored and the fulfil is owed: no cancel now.
		expect(bob.node.cancelHeldHtlc(paymentHash)).to.equal(false);
		await turns(50);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		arm.down = false;
		periodicWork(bob);
		await turns(200);
		expect(received).to.deep.equal([paymentHash.toString('hex')]);
		expect(bob.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(units(bob, channelId)).to.equal(6000n);
		expect(inFlight(bob, channelId)).to.deep.equal([]);
	});

	it('a cancel the asset provider refuses stays chosen, cannot be turned into a settle, and is made by the periodic work', async () => {
		const arm = { down: false, thrown: 0 };
		const { alice, bob, channelId, paymentHash, preimage } = await held(
			'aux-hold-cancel',
			arm
		);
		const received = paid(bob);
		arm.down = true;
		expect(bob.node.cancelHeldHtlc(paymentHash)).to.equal(false);
		await turns(100);
		expect(arm.thrown).to.be.greaterThan(0);
		expect(inFlight(bob, channelId)).to.have.length(1);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(bob.node.settleHeldHtlc(paymentHash, preimage)).to.equal(false);

		arm.down = false;
		periodicWork(bob);
		await turns(200);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(received).to.deep.equal([]);
		expect(bob.node.getPayment(paymentHash)!.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
		expect(inFlight(bob, channelId)).to.deep.equal([]);
		expect(units(alice, channelId)).to.equal(9000n);
		expect(units(bob, channelId)).to.equal(1000n);
	});

	it('a settle the asset provider refused is not made once the held HTLC has expired', async () => {
		const arm = { down: false, thrown: 0 };
		const { alice, bob, channelId, paymentHash, preimage } = await held(
			'aux-hold-expiry',
			arm
		);
		const received = paid(bob);
		arm.down = true;
		expect(bob.node.settleHeldHtlc(paymentHash, preimage)).to.equal(false);
		await turns(50);
		const expiry =
			bob.node.getAuxiliaryChannelInfo(channelId)!.htlcs[0].cltvExpiry;
		bob.node.handleNewBlock(expiry);
		await turns(100);
		// The provider answers again, too late: the peer can already take
		// the HTLC back on chain, and the preimage is not given to it.
		arm.down = false;
		periodicWork(bob);
		bob.node.handleNewBlock(expiry + 1);
		await turns(200);
		expect(received).to.deep.equal([]);
		expect(bob.node.getPayment(paymentHash)!.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
		expect(alice.node.getPayment(paymentHash)!.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('a settle the asset provider refused is given up when the held HTLC has expired: the HTLC is failed back, the invoice ends cancelled, the host is told, and nothing stays parked', async () => {
		const arm = { down: false, thrown: 0 };
		const outcomes: string[] = [];
		const { alice, bob, channelId, paymentHash, preimage } = await held(
			'aux-hold-given-up',
			arm,
			{
				onHtlcResolved: (context) => {
					outcomes.push(
						`${context.direction}:${context.htlcId}:${context.outcome}:${context.auxiliaryAmount}`
					);
				}
			}
		);
		const hashHex = paymentHash.toString('hex');
		const received = paid(bob);
		const parked = bob.node as unknown as {
			heldHtlcs: Map<string, unknown[]>;
			heldResolutions: Map<string, unknown>;
		};
		arm.down = true;
		expect(bob.node.settleHeldHtlc(paymentHash, preimage)).to.equal(false);
		await turns(50);
		const expiry =
			bob.node.getAuxiliaryChannelInfo(channelId)!.htlcs[0].cltvExpiry;
		// The provider is still down as the HTLC expires: the settle is
		// given up, and the fail back it is turned into is refused and owed.
		bob.node.handleNewBlock(expiry);
		await turns(100);
		expect(inFlight(bob, channelId)).to.have.length(1);
		expect(parked.heldHtlcs.get(hashHex)).to.have.length(1);
		expect(outcomes).to.deep.equal([]);

		arm.down = false;
		bob.node.handleNewBlock(expiry + 1);
		await turns(200);
		expect(inFlight(bob, channelId)).to.deep.equal([]);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(units(alice, channelId)).to.equal(9000n);
		expect(units(bob, channelId)).to.equal(1000n);
		// Never paid: cancelled, with nothing parked and the host told.
		expect(received).to.deep.equal([]);
		expect(bob.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(bob.node.getInvoice(hashHex)!.cancelledAt).to.be.a('number');
		expect('auxiliary' in bob.node.getInvoice(hashHex)!).to.equal(false);
		expect(outcomes).to.deep.equal(['RECEIVED:0:failed:5000']);
		expect(parked.heldHtlcs.size).to.equal(0);
		expect(parked.heldResolutions.size).to.equal(0);
		expect(bob.node.settleHeldHtlc(paymentHash, preimage)).to.equal(false);
	});

	it('a held asset HTLC that has left its channel another way is not kept parked, and its invoice ends cancelled', async () => {
		const arm = { down: false, thrown: 0 };
		const { bob, channelId, paymentHash, preimage } = await held(
			'aux-hold-left',
			arm
		);
		const hashHex = paymentHash.toString('hex');
		const parked = bob.node as unknown as {
			heldHtlcs: Map<string, unknown[]>;
			heldResolutions: Map<string, unknown>;
		};
		expect(parked.heldHtlcs.get(hashHex)).to.have.length(1);
		// The parked HTLC is known, also in what is stored, as an asset HTLC.
		const stored = JSON.parse(
			bob.storage!.loadMetadata('held_htlcs')!
		) as Array<{
			htlcs: Array<{ auxiliary?: boolean }>;
		}>;
		expect(stored[0].htlcs[0].auxiliary).to.equal(true);
		// As the chain leaves it: the HTLC is no longer in the channel.
		(
			bob.node.getChannelManager().getChannel(channelId)!.getFullState()
				.htlcs as Map<string, unknown>
		).delete('received-0');
		bob.node.handleNewBlock(1);
		await turns(20);
		expect(parked.heldHtlcs.size).to.equal(0);
		expect(parked.heldResolutions.size).to.equal(0);
		expect(bob.node.getInvoice(hashHex)!.cancelledAt).to.be.a('number');
		expect(bob.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(bob.node.settleHeldHtlc(paymentHash, preimage)).to.equal(false);
		expect(JSON.parse(bob.storage!.loadMetadata('held_htlcs')!)).to.deep.equal(
			[]
		);
	});

	describe('an asset invoice paid in several parts', () => {
		it('is refused at the sender with a typed error, and nothing is sent or recorded', async () => {
			const alice = assetHost('aux-parts-send', 1, {}, { sqlite: true });
			const bob = assetHost(
				'aux-parts-send',
				2,
				{ valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n },
				{ sqlite: true }
			);
			hosts.push(alice, bob);
			connectHosts(alice, bob);
			const channelId = await openAssetChannel(alice, bob, {
				tag: 'aux-parts-send',
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			const invoice = bob.node.createInvoice({
				amountMsat: 10_000_000n,
				description: 'two parts'
			});
			const amount = Buffer.alloc(8);
			amount.writeBigUInt64BE(5000n);
			let thrown: unknown;
			try {
				alice.node.sendPaymentToRoute(
					{
						hops: [
							{
								pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
								shortChannelId: Buffer.alloc(8, 9),
								amountToForwardMsat: 5_000_000n,
								outgoingCltvValue: 40
							}
						]
					},
					invoice.paymentHash,
					40,
					invoice.paymentSecret,
					// The first of two parts of 5,000,000 msat.
					10_000_000n,
					undefined,
					undefined,
					undefined,
					{
						assetPayment: {
							channelId,
							wireAmountMsat: 354_000n,
							customRecords: new Map([[65536n, amount]])
						}
					}
				);
			} catch (err) {
				thrown = err;
			}
			expect(thrown).to.be.instanceOf(AuxiliaryPaymentError);
			expect((thrown as AuxiliaryPaymentError).code).to.equal(
				'ASSET_PAYMENT_UNSUPPORTED'
			);
			await turns(50);
			expect(alice.node.getPayment(invoice.paymentHash) ?? null).to.equal(null);
			expect(inFlight(alice, channelId)).to.deep.equal([]);
			expect(units(alice, channelId)).to.equal(9000n);
		});

		it('is refused at the receiver: an asset HTLC worth less than the total its onion declares is failed back, not kept as a part', async () => {
			const alice = assetHost('aux-parts-receive', 1, {}, { sqlite: true });
			const bob = assetHost(
				'aux-parts-receive',
				2,
				// Bob's host values the units at half of what the onion says
				// the payment comes to: the HTLC would be the first part of two.
				{ valueIncomingHtlc: (context) => context.auxiliaryAmount! * 500n },
				{ sqlite: true }
			);
			hosts.push(alice, bob);
			const logged: string[] = [];
			bob.node.on('log', (log: { action: string }) => {
				logged.push(log.action);
			});
			connectHosts(alice, bob);
			const channelId = await openAssetChannel(alice, bob, {
				tag: 'aux-parts-receive',
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'half of it'
			});
			payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
			await turns(200);
			expect(logged).to.include('asset_multi_part_refused');
			expect(inFlight(bob, channelId)).to.deep.equal([]);
			expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			expect(units(alice, channelId)).to.equal(9000n);
			expect(units(bob, channelId)).to.equal(1000n);
		});
	});
});
