/**
 * Issue #2093: a provider that cannot answer while a message of the peer is
 * taken in.
 *
 * A throw of this node's own provider is this node's failure. The channel
 * is not failed for it and nothing that blames the peer is sent: the node
 * raises a typed local error and drops the connection, and the reestablish
 * of the next one has the peer send the round again. The channel is failed
 * with a wire error only on an answer of the provider that shows the peer's
 * data to be bad. A throw of validateHtlc is the host rejecting one HTLC:
 * that HTLC is failed back and the channel stays.
 */

import { expect } from 'chai';
import { PaymentStatus } from '../../src/lightning/node/types';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import { ChannelState } from '../../src/lightning/channel/types';
import { referenceProvider } from './helpers/auxiliary-pair';
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

type Method = keyof IChannelAuxiliaryProvider;

/** The reference provider, with a throw wherever `fail` says so. */
function failingProvider(
	fail: (method: Method, args: unknown[]) => boolean
): IChannelAuxiliaryProvider {
	const inner = referenceProvider() as unknown as Record<
		string,
		(...args: unknown[]) => unknown
	>;
	const out: Record<string, unknown> = {};
	for (const method of Object.keys(inner)) {
		out[method] = (...args: unknown[]): unknown => {
			if (fail(method as Method, args)) {
				throw new Error(`provider down in ${method}`);
			}
			return inner[method](...args);
		};
	}
	return out as unknown as IChannelAuxiliaryProvider;
}

describe('a provider that cannot answer for a message of the peer (issue #2093 step 6)', function () {
	this.timeout(60_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			try {
				host.node.destroy();
			} catch {
				// already destroyed
			}
			host.storage?.close();
		}
	});

	interface IScene {
		alice: IAssetHost;
		bob: IAssetHost;
		channelId: Buffer;
		/** BOLT 1 error (17) and warning (1) texts bob sent. */
		blame: string[];
		/** Peers bob asked its host to disconnect. */
		dropped: string[];
	}

	async function scene(
		tag: string,
		bobHooks: Partial<IAuxiliaryChannelConfig>
	): Promise<IScene> {
		const alice = assetHost(tag, 1, {}, { sqlite: true });
		const bob = assetHost(
			tag,
			2,
			{
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
		const blame: string[] = [];
		bob.node.on(
			'message:outbound',
			(_peer: string, type: number, payload: Buffer) => {
				if (type === 17 || type === 1) {
					blame.push(payload.subarray(34).toString('utf8'));
				}
			}
		);
		const dropped: string[] = [];
		bob.node.on('peer:disconnect-requested', (peer: string) => {
			dropped.push(peer);
		});
		return { alice, bob, channelId, blame, dropped };
	}

	const refusals = (host: IAssetHost): string[] =>
		host.errors.filter((error) => error.includes('The asset provider refused'));

	const cases: Array<{
		name: string;
		operation: string;
		fail: (arm: {
			on: boolean;
		}) => (method: Method, args: unknown[]) => boolean;
	}> = [
		{
			name: 'builds the commitment a commitment_signed is verified against',
			operation: 'the verification of a commitment',
			fail: (arm) => (method, args) =>
				method === 'buildCommitment' &&
				arm.on &&
				(args[0] as { side?: string }).side === 'local'
		},
		{
			name: 'verifies the asset signatures of a commitment_signed',
			operation: 'the verification of a commitment',
			fail: (arm) => (method) => method === 'verifyHtlcs' && arm.on
		},
		{
			name: 'reads the units of an HTLC the peer adds',
			operation: 'an HTLC of the peer',
			fail: (arm) => (method) => method === 'getHtlcAmount' && arm.on
		}
	];
	for (const { name, operation, fail } of cases) {
		it(`a provider that throws once while it ${name} does not fail the channel or blame the peer, and the round is taken up after the reconnect`, async () => {
			const arm = { on: false, thrown: 0 };
			const decide = fail(arm);
			const { alice, bob, channelId, blame, dropped } = await scene(
				`aux-local-${cases.findIndex((c) => c.name === name)}`,
				{
					provider: failingProvider((method, args) => {
						if (!decide(method, args)) return false;
						arm.on = false;
						arm.thrown++;
						return true;
					})
				}
			);
			const invoice = bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'provider down once'
			});
			arm.on = true;
			payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
			await turns(200);

			expect(arm.thrown, 'the provider threw once').to.equal(1);
			// Nothing on the wire blames the peer, and neither channel failed.
			expect(blame).to.deep.equal([]);
			expect(bob.node.getAuxiliaryChannelInfo(channelId)!.state).to.not.equal(
				ChannelState.ERRORED
			);
			expect(alice.node.getAuxiliaryChannelInfo(channelId)!.state).to.equal(
				ChannelState.NORMAL
			);
			// A typed local error that names what was being done.
			expect(refusals(bob)).to.have.length(1);
			expect(refusals(bob)[0]).to.include(
				`CHANNEL_ERROR: The asset provider refused ${operation} (channel ${channelId.toString(
					'hex'
				)})`
			);
			// The connection is dropped, and nothing of the round was kept.
			expect(dropped).to.deep.equal([alice.node.getNodeId()]);
			expect(bob.node.getPayment(invoice.paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);

			await reconnectHosts(alice, bob);
			expect(blame).to.deep.equal([]);
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
			expect(
				bob.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance
			).to.equal(6000n);
		});
	}

	it('a provider that cannot build the commitment an added HTLC would leave is this node failing, not the peer', async () => {
		const arm = { on: false, thrown: 0 };
		const { alice, bob, channelId, blame, dropped } = await scene(
			'aux-local-empty',
			{
				provider: failingProvider((method) => {
					if (method !== 'buildCommitment' || !arm.on) return false;
					arm.on = false;
					arm.thrown++;
					return true;
				})
			}
		);
		// A reserve below the dust limit has every add of the peer measured
		// against the commitment it would leave, which asks the provider.
		bob.node
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState().localConfig.channelReserveSatoshis = 0n;
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'provider down at the add'
		});
		arm.on = true;
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);
		expect(arm.thrown).to.equal(1);
		expect(blame).to.deep.equal([]);
		expect(refusals(bob)[0]).to.include(
			'The asset provider refused an HTLC of the peer'
		);
		expect(dropped).to.deep.equal([alice.node.getNodeId()]);
		await reconnectHosts(alice, bob);
		expect(blame).to.deep.equal([]);
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(bob.node.getAuxiliaryChannelInfo(channelId)!.state).to.equal(
			ChannelState.NORMAL
		);
	});

	it('a provider that answers that the signatures of the peer are bad still fails the channel with a wire error', async () => {
		const arm = { on: false };
		const inner = referenceProvider();
		const { alice, bob, channelId, blame } = await scene('aux-peer-bad', {
			provider: {
				...inner,
				verifyHtlcs: (context, records) =>
					arm.on ? false : inner.verifyHtlcs(context, records)
			}
		});
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'bad asset signature'
		});
		arm.on = true;
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);
		expect(blame).to.deep.equal(['Invalid asset HTLC signature']);
		expect(bob.node.getAuxiliaryChannelInfo(channelId)!.state).to.equal(
			ChannelState.ERRORED
		);
	});

	it('an HTLC the provider refuses in validateHtlc is failed back, the channel stays, and the next HTLC is taken', async () => {
		const arm = { on: false, thrown: 0 };
		const inner = referenceProvider();
		const { alice, bob, channelId, blame, dropped } = await scene(
			'aux-validate',
			{
				provider: {
					...inner,
					validateHtlc: (state, entry) => {
						if (arm.on) {
							arm.thrown++;
							throw new Error('not an HTLC this host takes');
						}
						inner.validateHtlc(state, entry);
					}
				}
			}
		);
		const refused = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'refused by the host'
		});
		arm.on = true;
		payAssetUnits(alice, bob, channelId, refused, 5_000_000n, 5000n);
		await turns(200);
		arm.on = false;

		expect(arm.thrown).to.equal(1);
		expect(blame).to.deep.equal([]);
		expect(dropped).to.deep.equal([]);
		expect(alice.node.getPayment(refused.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(bob.node.getPayment(refused.paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
		for (const host of [alice, bob]) {
			const info = host.node.getAuxiliaryChannelInfo(channelId)!;
			expect(info.state).to.equal(ChannelState.NORMAL);
			expect(info.htlcs).to.deep.equal([]);
		}
		// The units went back to their sender.
		expect(
			alice.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance
		).to.equal(9000n);

		const taken = bob.node.createInvoice({
			amountMsat: 1_000_000n,
			description: 'taken'
		});
		payAssetUnits(alice, bob, channelId, taken, 1_000_000n, 1000n);
		await turns(200);
		expect(alice.node.getPayment(taken.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(
			bob.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance
		).to.equal(2000n);
	});
});
