/**
 * Issue #2093: what a refusal of the asset provider leaves owed.
 *
 * The provider is asked before a channel takes the settlement or the
 * failure of an HTLC and before a commitment is signed, and can refuse. A
 * refusal writes and sends nothing, and what was refused stays owed: it is
 * taken up again from the node's periodic work and on each block, a bounded
 * number of times per interval, and by the replay of the HTLC after a
 * reconnect or a restart. An invoice is reported paid only once the channel
 * has taken the fulfil.
 */

import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { PaymentStatus } from '../../src/lightning/node/types';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { ChannelState } from '../../src/lightning/channel/types';
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

describe('what a refusal of the asset provider leaves owed (issue #2093 step 8)', function () {
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

	const refusals = (host: IAssetHost): string[] =>
		host.errors.filter((error) => error.includes('The asset provider refused'));

	const paid = (host: IAssetHost): string[] => {
		const received: string[] = [];
		host.node.on('payment:received', (payment: { paymentHash: Buffer }) => {
			received.push(payment.paymentHash.toString('hex'));
		});
		return received;
	};

	async function scene(
		tag: string,
		aliceHooks: Partial<IAuxiliaryChannelConfig>,
		bobHooks: Partial<IAuxiliaryChannelConfig>,
		bobPath?: string
	): Promise<{ alice: IAssetHost; bob: IAssetHost; channelId: Buffer }> {
		const alice = assetHost(tag, 1, aliceHooks, { sqlite: true });
		const bob = assetHost(
			tag,
			2,
			{
				valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n,
				...bobHooks
			},
			bobPath ? { sqlitePath: bobPath } : { sqlite: true }
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

	/** Bob's provider cannot build a commitment while `arm.down`. */
	const settleRefuser = (arm: {
		down: boolean;
		thrown: number;
	}): Partial<IAuxiliaryChannelConfig> => ({
		provider: failingProvider((method) => {
			if (method !== 'buildCommitment' || !arm.down) return false;
			arm.thrown++;
			return true;
		}),
		valueIncomingHtlc: (context) => {
			// The host has valued the HTLC; the next question the node puts
			// to the provider, the settlement's commitment, is not answered.
			arm.down = true;
			return context.auxiliaryAmount! * 1000n;
		}
	});

	it('an invoice whose settlement the provider refused is not reported paid, and is settled and reported once from the next block', async () => {
		const arm = { down: false, thrown: 0 };
		const { alice, bob, channelId } = await scene(
			'aux-owed-settle',
			{},
			settleRefuser(arm)
		);
		const received = paid(bob);
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'settle refused once'
		});
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);

		// Refused: the HTLC is held, the units are not this node's, and
		// nothing says paid.
		expect(arm.thrown).to.equal(1);
		expect(refusals(bob)).to.have.length(1);
		expect(refusals(bob)[0]).to.include('the settlement of an HTLC');
		let info = bob.node.getAuxiliaryChannelInfo(channelId)!;
		expect(info.htlcs).to.have.length(1);
		expect(info.localAssetBalance).to.equal(1000n);
		expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(received).to.deep.equal([]);
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		// The provider is back. The connection stood all along: the next
		// block takes the settlement up.
		arm.down = false;
		bob.node.handleNewBlock(1);
		await turns(200);
		info = bob.node.getAuxiliaryChannelInfo(channelId)!;
		expect(info.state).to.equal(ChannelState.NORMAL);
		expect(info.htlcs).to.deep.equal([]);
		expect(info.localAssetBalance).to.equal(6000n);
		expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(received).to.deep.equal([invoice.paymentHash.toString('hex')]);
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		// Nothing is owed any more: further blocks ask nothing.
		const asked = arm.thrown;
		bob.node.handleNewBlock(2);
		await turns(50);
		expect(arm.thrown).to.equal(asked);
		expect(received).to.have.length(1);
	});

	it('a refused settlement is asked again a bounded number of times per interval, with one error per refusal', async () => {
		const arm = { down: false, thrown: 0 };
		const { alice, bob, channelId } = await scene(
			'aux-owed-bound',
			{},
			settleRefuser(arm)
		);
		const received = paid(bob);
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'settle refused for a while'
		});
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);
		expect(arm.thrown).to.equal(1);

		for (let height = 1; height <= 12; height++) {
			bob.node.handleNewBlock(height);
			await turns(10);
		}
		const bound = ChannelManager.AUXILIARY_RETRY_ATTEMPTS_PER_INTERVAL;
		expect(arm.thrown).to.equal(1 + bound);
		expect(refusals(bob)).to.have.length(1 + bound);
		expect(received).to.deep.equal([]);
		expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		// A later interval asks again, and the provider answers.
		arm.down = false;
		const manager = bob.node.getChannelManager();
		manager.retryAuxiliaryOwed(
			undefined,
			Date.now() + ChannelManager.AUXILIARY_RETRY_INTERVAL_MS
		);
		await turns(200);
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(
			bob.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance
		).to.equal(6000n);
	});

	it('a settlement the provider refused is made after a restart, from what the channel row holds', async () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-owed-'));
		directories.push(directory);
		const file = path.join(directory, 'bob.sqlite');
		const arm = { down: false, thrown: 0 };
		const { alice, bob, channelId } = await scene(
			'aux-owed-restart',
			{},
			settleRefuser(arm),
			file
		);
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'settle refused, then a restart'
		});
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);
		expect(arm.thrown).to.equal(1);
		expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		bob.node.destroy();
		bob.storage!.close();

		const restarted = assetHost(
			'aux-owed-restart',
			2,
			{ valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n },
			{ sqlitePath: file }
		);
		hosts.push(restarted);
		const received = paid(restarted);
		expect(restarted.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		connectHosts(alice, restarted);
		await reconnectHosts(alice, restarted);
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(restarted.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(received).to.deep.equal([invoice.paymentHash.toString('hex')]);
		expect(
			restarted.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance
		).to.equal(6000n);
	});

	it('with the peer connected and the provider still refusing as the HTLC nears its expiry, the node keeps asking, gives the settlement up at the expiry, and never reports the invoice paid', async () => {
		const arm = { down: false, thrown: 0 };
		const { alice, bob, channelId } = await scene(
			'aux-owed-expiry',
			{},
			settleRefuser(arm)
		);
		const received = paid(bob);
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'never settled'
		});
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);
		const manager = bob.node.getChannelManager();
		const htlc = [
			...manager.getChannel(channelId)!.getFullState().htlcs.values()
		][0];
		expect(manager.owesAuxiliaryRemoval(channelId, htlc.id)).to.equal(true);

		const unpaid = (): void => {
			expect(received).to.deep.equal([]);
			expect(bob.node.getPayment(invoice.paymentHash)!.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			const info = bob.node.getAuxiliaryChannelInfo(channelId)!;
			expect(info.localAssetBalance).to.equal(1000n);
			expect(info.htlcs).to.have.length(1);
		};
		// Every block up to the one before the expiry: asked again, within
		// the bound, refused, nothing reported.
		for (let height = 1; height < htlc.cltvExpiry; height++) {
			bob.node.handleNewBlock(height);
			await turns(5);
			unpaid();
		}
		expect(arm.thrown).to.be.greaterThan(1);
		expect(manager.owesAuxiliaryRemoval(channelId, htlc.id)).to.equal(true);

		// At the expiry the settlement is given up: the preimage is not
		// revealed for an HTLC the peer can take back on chain.
		bob.node.handleNewBlock(htlc.cltvExpiry);
		await turns(5);
		unpaid();
		expect(manager.owesAuxiliaryRemoval(channelId, htlc.id)).to.equal(false);
		expect(bob.errors.join('\n')).to.include(
			`The settlement of HTLC ${htlc.id} that the asset provider refused is given up at its expiry ${htlc.cltvExpiry}`
		);

		// The provider comes back too late: nothing is settled, nothing paid.
		arm.down = false;
		manager.retryAuxiliaryOwed(
			undefined,
			Date.now() + 2 * ChannelManager.AUXILIARY_RETRY_INTERVAL_MS
		);
		await turns(50);
		unpaid();
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('an HTLC whose fail back the provider refused is failed back from the next block', async () => {
		const arm = { down: false, thrown: 0 };
		const { alice, bob, channelId } = await scene(
			'aux-owed-fail',
			{},
			{
				provider: failingProvider((method) => {
					if (method !== 'buildCommitment' || !arm.down) return false;
					arm.thrown++;
					return true;
				}),
				valueIncomingHtlc: () => {
					arm.down = true;
					throw new Error('no quote');
				}
			}
		);
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'refused by the host'
		});
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);
		expect(arm.thrown).to.equal(1);
		expect(refusals(bob)[0]).to.include('the failure of an HTLC');
		expect(bob.node.getAuxiliaryChannelInfo(channelId)!.htlcs).to.have.length(
			1
		);
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		arm.down = false;
		bob.node.handleNewBlock(1);
		await turns(200);
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		for (const host of [alice, bob]) {
			const info = host.node.getAuxiliaryChannelInfo(channelId)!;
			expect(info.state).to.equal(ChannelState.NORMAL);
			expect(info.htlcs).to.deep.equal([]);
		}
		expect(
			alice.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance
		).to.equal(9000n);
	});

	for (const who of ['alice', 'bob'] as const) {
		it(`a commitment ${who}'s provider could not sign once is signed from the node's periodic work, without a reconnect`, async () => {
			const arm = { on: false, thrown: 0 };
			const provider = failingProvider((method) => {
				if (method !== 'signHtlcs' || !arm.on) return false;
				arm.on = false;
				arm.thrown++;
				return true;
			});
			const { alice, bob, channelId } = await scene(
				`aux-owed-sign-${who}`,
				who === 'alice' ? { provider } : {},
				who === 'bob' ? { provider } : {}
			);
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'a round refused once'
			});
			arm.on = true;
			payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
			await turns(200);
			expect(arm.thrown).to.equal(1);
			const refusing = who === 'alice' ? alice : bob;
			expect(refusals(refusing)[0]).to.include('a commitment');
			expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);

			// The work the node's timers do, at the height the HTLC was made.
			(
				refusing.node as unknown as { retryAuxiliaryOwed(): void }
			).retryAuxiliaryOwed();
			await turns(200);
			expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(bob.node.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			for (const host of [alice, bob]) {
				const info = host.node.getAuxiliaryChannelInfo(channelId)!;
				expect(info.state).to.equal(ChannelState.NORMAL);
				expect(info.htlcs).to.deep.equal([]);
			}
		});
	}
});

describe('an asset HTLC that is dropped unsigned on a held channel (issue #2093 step 8)', function () {
	this.timeout(60_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
	});

	it('is reported to the host as failed, with its units back', async () => {
		const arm = { on: false };
		const resolved: Array<{
			htlcId: bigint;
			direction: string;
			outcome: string;
			auxiliaryAmount: bigint;
			paymentHash: string;
		}> = [];
		const alice = assetHost(
			'aux-drop-held',
			1,
			{
				// The add is made and its commitment cannot be signed: it
				// stays in the channel, unsigned.
				provider: failingProvider((method) => method === 'signHtlcs' && arm.on),
				onHtlcResolved: (context) => {
					resolved.push({
						htlcId: context.htlcId,
						direction: context.direction,
						outcome: context.outcome,
						auxiliaryAmount: context.auxiliaryAmount,
						paymentHash: context.paymentHash.toString('hex')
					});
				}
			},
			{ sqlite: true }
		);
		const bob = assetHost(
			'aux-drop-held',
			2,
			{ valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n },
			{ sqlite: true }
		);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag: 'aux-drop-held',
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'never signed'
		});
		arm.on = true;
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(100);
		const manager = alice.node.getChannelManager();
		const state = manager.getChannel(channelId)!.getFullState();
		expect(state.htlcs.size).to.equal(1);
		expect(state.auxiliaryState!.localBalance).to.equal(4000n);
		expect(resolved).to.deep.equal([]);

		// The channel becomes one whose restore could not prove its
		// recency: on the disconnect it drops the add no commitment covers.
		(state as { restoreRecencyUnproven?: boolean }).restoreRecencyUnproven =
			true;
		manager.handlePeerDisconnected(bob.node.getNodeId());
		await turns(50);
		expect(state.htlcs.size).to.equal(0);
		expect(state.auxiliaryState!.localBalance).to.equal(9000n);
		expect(resolved).to.deep.equal([
			{
				htlcId: 0n,
				direction: 'OFFERED',
				outcome: 'failed',
				auxiliaryAmount: 5000n,
				paymentHash: invoice.paymentHash.toString('hex')
			}
		]);
		// Told once: the outcome is not kept for a host that has taken it.
		expect(state.auxiliaryState!.resolvedHtlcs?.size ?? 0).to.equal(0);
	});
});
