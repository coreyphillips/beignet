/**
 * Issue #2093: the outcomes of asset HTLCs that a channel keeps for its
 * host until onHtlcResolved has returned for them.
 *
 * They live in the channel's row. What is read back from disk is refused
 * by the codec's own error when a list is not a list. What the host has
 * taken leaves the row with a write of its own, so a restart does not
 * deliver it again. A host that keeps throwing is told so in one line a
 * pass, sees the count in getAuxiliaryChannelInfo, and past a bound the
 * channel takes no further asset HTLC, so the row grows by the host's
 * failure and never by what the peer offers.
 */

import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { HtlcDirection } from '../../src/lightning/channel/types';
import {
	AuxiliaryPaymentError,
	PaymentStatus
} from '../../src/lightning/node/types';
import {
	deserializeAuxiliaryState,
	serializeAuxiliaryState
} from '../../src/lightning/storage/auxiliary-serialization';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	payAssetUnits,
	turns,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

describe('the outcomes of asset HTLCs a channel keeps for its host (issue #2093 step 8)', function () {
	this.timeout(120_000);
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

	const auxiliaryOf = (host: IAssetHost, channelId: Buffer) =>
		host.node.getChannelManager().getChannel(channelId)!.getFullState()
			.auxiliaryState!;

	const hostDown = (): never => {
		throw new Error('the asset store is down');
	};

	async function open(
		tag: string,
		aliceHooks: Parameters<typeof assetHost>[2],
		bobHooks: Parameters<typeof assetHost>[2],
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

	const pay = async (
		alice: IAssetHost,
		bob: IAssetHost,
		channelId: Buffer,
		units: bigint
	): Promise<Buffer> => {
		const invoice = bob.node.createInvoice({
			amountMsat: units * 1000n,
			description: `${units} units`
		});
		payAssetUnits(alice, bob, channelId, invoice, units * 1000n, units);
		await turns(200);
		return invoice.paymentHash;
	};

	/** Outcomes the host has not taken, as many as asked, written as the channel writes them. */
	const hold = (
		host: IAssetHost,
		channelId: Buffer,
		direction: HtlcDirection,
		count: number,
		first = 1_000_000,
		paymentHash = Buffer.alloc(32, 7)
	): void => {
		const auxiliary = auxiliaryOf(host, channelId);
		auxiliary.resolvedHtlcs ??= new Map();
		for (let i = 0; i < count; i++) {
			const htlcId = BigInt(first + i);
			auxiliary.resolvedHtlcs.set(`${direction}:${htlcId}`, {
				htlcId,
				direction,
				paymentHash,
				auxiliaryAmount: 1n,
				outcome: 'failed'
			});
		}
	};

	it('a list of the stored asset state that is not a list, or holds something that is not a pair, is refused by the codec by name', async () => {
		const { alice, bob, channelId } = await open(
			'aux-outcomes-codec',
			{ onHtlcResolved: hostDown },
			{}
		);
		await pay(alice, bob, channelId, 500n);
		const auxiliary = auxiliaryOf(alice, channelId);
		expect(auxiliary.resolvedHtlcs!.size).to.equal(1);
		const stored = JSON.parse(
			JSON.stringify(serializeAuxiliaryState(auxiliary))
		) as Record<string, unknown>;
		// Every list in the stored form, however deep.
		const lists: Array<Array<string | number>> = [];
		const walk = (node: unknown, at: Array<string | number>): void => {
			if (Array.isArray(node)) {
				lists.push(at);
				node.forEach((item, index) => walk(item, [...at, index]));
			} else if (node && typeof node === 'object') {
				for (const [key, value] of Object.entries(node)) {
					walk(value, [...at, key]);
				}
			}
		};
		walk(stored, []);
		expect(lists.length).to.be.greaterThan(8);
		expect(lists.some((at) => at[at.length - 1] === 'resolvedHtlcs')).to.equal(
			true
		);
		for (const at of lists) {
			for (const wrong of [{}, 7, 'xy']) {
				const copy = JSON.parse(JSON.stringify(stored)) as Record<
					string,
					unknown
				>;
				let node = copy as unknown as Record<string | number, unknown>;
				for (const step of at.slice(0, -1)) {
					node = node[step] as Record<string | number, unknown>;
				}
				node[at[at.length - 1]] = wrong;
				let thrown: unknown;
				try {
					deserializeAuxiliaryState(
						copy as unknown as Parameters<typeof deserializeAuxiliaryState>[0]
					);
				} catch (err) {
					thrown = err;
				}
				const where = `${at.join('.')} = ${JSON.stringify(wrong)}`;
				expect(thrown, where).to.be.instanceOf(Error);
				expect(thrown, where).to.not.be.instanceOf(TypeError);
				expect((thrown as Error).message, where).to.match(
					/^Malformed serialized /
				);
			}
		}
	});

	it('a host that keeps throwing is told so in one line a pass with the count held, and the count is in the channel info', async () => {
		const { alice, bob, channelId } = await open(
			'aux-outcomes-count',
			{ onHtlcResolved: hostDown },
			{}
		);
		await pay(alice, bob, channelId, 500n);
		await pay(alice, bob, channelId, 600n);
		expect(
			alice.node.getAuxiliaryChannelInfo(channelId)!.undeliveredOutcomes
		).to.equal(2);
		const lines = alice.errors.filter((error) =>
			error.includes('Asset resolution callback failed')
		);
		expect(lines.length).to.be.greaterThan(0);
		expect(lines[lines.length - 1]).to.include(
			'the asset store is down; 2 outcome(s) of the channel are held undelivered'
		);
		// A pass says it once, however many outcomes the host refused in it.
		hold(alice, channelId, HtlcDirection.OFFERED, 20);
		const before = alice.errors.length;
		await pay(alice, bob, channelId, 700n);
		const after = alice.errors
			.slice(before)
			.filter((error) => error.includes('Asset resolution callback failed'));
		expect(after.length).to.be.greaterThan(0);
		expect(after.length).to.be.lessThan(8);
		expect(after[after.length - 1]).to.include('23 outcome(s)');
		// Bob's host asks for no outcomes: none is kept for it, and its
		// channel info has no such figure.
		expect(
			'undeliveredOutcomes' in bob.node.getAuxiliaryChannelInfo(channelId)!
		).to.equal(false);
	});

	it('outcomes the host cannot take do not keep a pass from the ones behind them: a pass stops at eight refusals and the next starts behind the last outcome it tried', async () => {
		const unknown = Buffer.alloc(32, 7);
		const seen = { refused: 0, taken: [] as string[] };
		const { alice, bob, channelId } = await open(
			'aux-outcomes-fair',
			{
				// A host that always throws for one hash.
				onHtlcResolved: (context) => {
					if (context.paymentHash.equals(unknown)) {
						seen.refused++;
						throw new Error('the asset store does not know this HTLC');
					}
					seen.taken.push(`${context.direction}:${context.htlcId}`);
				}
			},
			{}
		);
		const manager = alice.node.getChannelManager();
		/** One pass over the channel's outcomes; answers how many the host refused in it. */
		const pass = (): number => {
			seen.refused = 0;
			(
				manager as unknown as {
					_notifyAuxiliaryResolutions(channel: unknown): void;
				}
			)._notifyAuxiliaryResolutions(manager.getChannel(channelId)!);
			return seen.refused;
		};
		// Twelve outcomes of that hash are ahead of five the host can take.
		hold(alice, channelId, HtlcDirection.OFFERED, 12);
		hold(
			alice,
			channelId,
			HtlcDirection.OFFERED,
			5,
			2_000_000,
			Buffer.alloc(32, 9)
		);
		expect(pass()).to.equal(8);
		expect(seen.taken).to.deep.equal([]);
		// The second pass starts at the ninth: four refusals, the five are
		// taken, and it goes round to the first four.
		expect(pass()).to.equal(8);
		expect(seen.taken).to.deep.equal(
			[0, 1, 2, 3, 4].map((i) => `${HtlcDirection.OFFERED}:${2_000_000 + i}`)
		);
		expect(auxiliaryOf(alice, channelId).resolvedHtlcs!.size).to.equal(12);
		expect(
			alice.node.getAuxiliaryChannelInfo(channelId)!.undeliveredOutcomes
		).to.equal(12);
		// Never more than eight refusals a pass, whatever is held.
		expect(pass()).to.equal(8);
		expect(pass()).to.equal(8);

		// The outcome of a payment made now is behind all twelve, and the
		// host has it all the same.
		const hash = await pay(alice, bob, channelId, 500n);
		expect(alice.node.getPayment(hash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		for (let i = 0; i < 3 && seen.taken.length < 6; i++) pass();
		expect(seen.taken[5]).to.equal(`${HtlcDirection.OFFERED}:0`);
		expect(auxiliaryOf(alice, channelId).resolvedHtlcs!.size).to.equal(12);
	});

	it('past the bound the channel offers no further asset HTLC, with a typed refusal, and takes none from its peer, whose HTLC leaves no outcome', async () => {
		const asked = { count: 0 };
		const { alice, bob, channelId } = await open(
			'aux-outcomes-bound',
			{ onHtlcResolved: hostDown },
			{
				valueIncomingHtlc: (context) => {
					asked.count++;
					return context.auxiliaryAmount! * 1000n;
				},
				onHtlcResolved: hostDown
			}
		);
		const bound = ChannelManager.AUXILIARY_MAX_UNDELIVERED_OUTCOMES;
		expect(bound).to.equal(1000);

		// Bob's host has not taken 1001 outcomes: the HTLC Alice offers is
		// failed back without being put to it, and adds nothing to the row.
		hold(bob, channelId, HtlcDirection.RECEIVED, bound + 1);
		const refused = await pay(alice, bob, channelId, 500n);
		expect(asked.count).to.equal(0);
		expect(alice.node.getPayment(refused)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(bob.node.getPayment(refused)!.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(auxiliaryOf(bob, channelId).resolvedHtlcs!.size).to.equal(bound + 1);
		expect(
			bob.node.getAuxiliaryChannelInfo(channelId)!.undeliveredOutcomes
		).to.equal(bound + 1);
		expect(bob.node.getAuxiliaryChannelInfo(channelId)!.htlcs).to.deep.equal(
			[]
		);
		expect(
			alice.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance
		).to.equal(9000n);

		// Alice's host has not taken more than the bound either: she offers
		// no further asset HTLC, and nothing is recorded or sent.
		hold(alice, channelId, HtlcDirection.OFFERED, bound + 1);
		const invoice = bob.node.createInvoice({
			amountMsat: 500_000n,
			description: 'not sent'
		});
		let thrown: unknown;
		try {
			payAssetUnits(alice, bob, channelId, invoice, 500_000n, 500n);
		} catch (err) {
			thrown = err;
		}
		expect(thrown).to.be.instanceOf(AuxiliaryPaymentError);
		expect((thrown as AuxiliaryPaymentError).code).to.equal(
			'ASSET_OUTCOMES_UNDELIVERED'
		);
		expect(alice.node.getPayment(invoice.paymentHash) ?? null).to.equal(null);
		expect(alice.node.getAuxiliaryChannelInfo(channelId)!.htlcs).to.deep.equal(
			[]
		);
	});

	it('what the host has taken leaves the row at once: a restart straight after the delivery delivers nothing again', async () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-outcomes-'));
		directories.push(directory);
		const file = path.join(directory, 'bob.sqlite');
		const taken: string[] = [];
		const { alice, bob, channelId } = await open(
			'aux-outcomes-restart',
			{},
			{
				onHtlcResolved: (context) => {
					taken.push(`first:${context.direction}:${context.htlcId}`);
				}
			},
			file
		);
		await pay(alice, bob, channelId, 500n);
		expect(taken).to.deep.equal(['first:RECEIVED:0']);
		for (const life of ['second', 'third']) {
			const before = hosts[hosts.length - 1];
			before.node.destroy();
			before.storage!.close();
			const restarted = assetHost(
				'aux-outcomes-restart',
				2,
				{
					onHtlcResolved: (context) => {
						taken.push(`${life}:${context.direction}:${context.htlcId}`);
					}
				},
				{ sqlitePath: file }
			);
			hosts.push(restarted);
			await turns(20);
		}
		expect(taken).to.deep.equal(['first:RECEIVED:0']);
	});

	it('an outcome delivered when the channel is restored is delivered once: the restart after it delivers nothing', async () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-outcomes-'));
		directories.push(directory);
		const file = path.join(directory, 'bob.sqlite');
		const taken: string[] = [];
		const { alice, bob, channelId } = await open(
			'aux-outcomes-restore',
			{},
			{ onHtlcResolved: hostDown },
			file
		);
		await pay(alice, bob, channelId, 500n);
		expect(auxiliaryOf(bob, channelId).resolvedHtlcs!.size).to.equal(1);
		for (const life of ['second', 'third']) {
			const before = hosts[hosts.length - 1];
			before.node.destroy();
			before.storage!.close();
			const restarted = assetHost(
				'aux-outcomes-restore',
				2,
				{
					onHtlcResolved: (context) => {
						taken.push(`${life}:${context.direction}:${context.htlcId}`);
					}
				},
				{ sqlitePath: file }
			);
			hosts.push(restarted);
			await turns(20);
		}
		expect(taken).to.deep.equal(['second:RECEIVED:0']);
	});
});
