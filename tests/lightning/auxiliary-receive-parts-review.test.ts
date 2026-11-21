/**
 * Issue #2098, step 8: what follows the commit of a set of asset parts when
 * its fulfils cannot be made, from the independent review of the step.
 * Each case drives the contract in docs/EXTENSIONS.md ("The commit, and
 * every part claimed").
 */

import { expect } from 'chai';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import { HtlcState } from '../../src/lightning/channel/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	aliasOf,
	forwardChainWorld,
	payInParts,
	type IPartsInvoice
} from './helpers/auxiliary-forward-world';
import {
	listenCarol,
	openPartsScene,
	type IPartsScene
} from './helpers/auxiliary-forward-scene';
import {
	withAssetForwards,
	withAssetOpens,
	withAssetPartsReceived,
	type IAssetHost
} from './helpers/auxiliary-nodes';

const hex = (value: Buffer): string => value.toString('hex');

interface IArm {
	down: boolean;
	/** Refuse only for this channel, when set. */
	only?: string;
}

function refusing(
	arm: IArm
): (provider: IChannelAuxiliaryProvider) => IChannelAuxiliaryProvider {
	return (provider) =>
		new Proxy(provider, {
			get(target, key, receiver): unknown {
				const value = Reflect.get(target, key, receiver) as unknown;
				if (typeof value !== 'function') return value;
				return (...args: unknown[]): unknown => {
					if (arm.down && key === 'buildCommitment') {
						const channelId = (
							args[0] as { state?: { channelId?: Buffer } } | undefined
						)?.state?.channelId;
						if (!arm.only || (channelId && hex(channelId) === arm.only)) {
							(arm as { refusedFor?: string[] }).refusedFor ??= [];
							(arm as { refusedFor?: string[] }).refusedFor!.push(
								channelId ? hex(channelId) : 'none'
							);
							throw new Error('provider down in buildCommitment');
						}
						(arm as { passedFor?: string[] }).passedFor ??= [];
						(arm as { passedFor?: string[] }).passedFor!.push(
							channelId ? hex(channelId) : 'none'
						);
					}
					return (value as (...rest: unknown[]) => unknown).apply(target, args);
				};
			}
		});
}

interface ITrace {
	fails: string[];
	errors: Array<{ code: string; channelId?: Buffer; message: string }>;
}

function trace(host: IAssetHost): ITrace {
	const t: ITrace = { fails: [], errors: [] };
	const manager = host.node.getChannelManager();
	const fail = manager.failHtlc.bind(manager);
	manager.failHtlc = (
		channelId,
		htlcId,
		reason,
		direction
	): ReturnType<typeof fail> => {
		t.fails.push(`${hex(channelId)}:${htlcId}`);
		return fail(channelId, htlcId, reason, direction);
	};
	host.node.on('node:error', (error: ITrace['errors'][number]) => {
		t.errors.push(error);
	});
	return t;
}

function settledKeys(s: IPartsScene, invoice: IPartsInvoice): string[] {
	return (
		s.w.hosts.carol.node.getPayment(invoice.paymentHash)?.settledHtlcs ?? []
	);
}

function entryOf(
	host: IAssetHost,
	key: string
): { state: HtlcState; cltvExpiry: number } | undefined {
	const [channelHex, id] = key.split(':');
	const entry = host.node
		.getChannelManager()
		.getChannel(Buffer.from(channelHex, 'hex'))
		?.getFullState()
		.htlcs.get(`received-${id}`);
	return entry
		? { state: entry.state, cltvExpiry: entry.cltvExpiry }
		: undefined;
}

function decisionOf(host: IAssetHost, key: string): string | undefined {
	const [channelHex, id] = key.split(':');
	return host.node
		.getChannelManager()
		.auxiliaryHtlcDecision(Buffer.from(channelHex, 'hex'), BigInt(id))?.outcome;
}

function claimBufferOf(host: IAssetHost): number {
	return Math.max(
		18,
		(host.node as unknown as { htlcSafetyMargin: number }).htlcSafetyMargin
	);
}

describe('a committed set of asset parts whose fulfils cannot be made (issue #2098, step 8)', function () {
	this.timeout(180_000);
	withAssetOpens();
	withAssetForwards();
	withAssetPartsReceived();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	it('the provider refuses every fulfil after the commit: no part is failed back, and the channel is closed to claim at the claim buffer', async () => {
		const tag = 'review-r1';
		const arm: IArm = { down: false };
		const s = await openPartsScene(world, tag, {
			world: { wrapProvider: { carol: refusing(arm) } }
		});
		const carol = s.w.hosts.carol;
		carol.node.on('log', (log: { action: string }) => {
			if (log.action === 'asset_set_committed') arm.down = true;
		});
		const t = trace(carol);
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		expect(carol.node.getPayment(invoice.paymentHash)?.status).to.equal(
			PaymentStatus.COMPLETED
		);
		const keys = settledKeys(s, invoice);
		expect(keys.length).to.equal(2);
		for (const key of keys) {
			expect(decisionOf(carol, key), `decision of ${key}`).to.equal('settle');
			expect(entryOf(carol, key)?.state, `state of ${key}`).to.equal(
				HtlcState.COMMITTED
			);
		}
		const expiry = Math.min(
			...keys.map((key) => entryOf(carol, key)!.cltvExpiry)
		);
		const buffer = claimBufferOf(carol);
		await world.passTo(s.w, expiry - buffer - 1);
		expect(
			t.errors.filter((e) => e.code === 'HTLC_CLAIM_FORCE_CLOSE'),
			'no close before the claim buffer'
		).to.deep.equal([]);
		await world.mine(s.w, 1);
		expect(
			t.fails.filter((key) => keys.includes(key)),
			'no part is failed back'
		).to.deep.equal([]);
		expect(
			t.errors.filter((e) => e.code === 'HTLC_CLAIM_FORCE_CLOSE').length,
			`a close to claim at the claim buffer (errors: ${JSON.stringify(
				t.errors.map((e) => e.code)
			)})`
		).to.be.greaterThan(0);
	});

	it('the decisions do not land at the commit: they are written on the next block, and the claim follows at the claim buffer', async () => {
		const tag = 'review-r2';
		const arm: IArm = { down: false };
		const s = await openPartsScene(world, tag, {
			world: { wrapProvider: { carol: refusing(arm) } }
		});
		const carol = s.w.hosts.carol;
		const manager = carol.node.getChannelManager();
		const decide = manager.recordAuxiliaryHtlcDecision.bind(manager);
		const writes = { refuse: false, refused: 0 };
		manager.recordAuxiliaryHtlcDecision = (
			channelId,
			htlcId,
			outcome,
			preimage
		): boolean => {
			if (writes.refuse) {
				writes.refused++;
				return false;
			}
			return decide(channelId, htlcId, outcome, preimage);
		};
		carol.node.on('log', (log: { action: string }) => {
			if (log.action === 'asset_set_committed') {
				arm.down = true;
				writes.refuse = true;
			}
		});
		const t = trace(carol);
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		writes.refuse = false;
		expect(
			writes.refused,
			'the commit tried a decision per part'
		).to.be.at.least(2);
		const keys = settledKeys(s, invoice);
		expect(keys.length).to.equal(2);
		for (const key of keys) {
			expect(decisionOf(carol, key), `no decision yet for ${key}`).to.equal(
				undefined
			);
		}
		await world.mine(s.w, 1);
		for (const key of keys) {
			expect(
				decisionOf(carol, key),
				`decision of ${key} after a block`
			).to.equal('settle');
		}
		const expiry = Math.min(
			...keys.map((key) => entryOf(carol, key)!.cltvExpiry)
		);
		await world.passTo(s.w, expiry - claimBufferOf(carol));
		expect(t.fails.filter((key) => keys.includes(key))).to.deep.equal([]);
		expect(
			t.errors.filter((e) => e.code === 'HTLC_CLAIM_FORCE_CLOSE').length
		).to.be.greaterThan(0);
	});

	it('over two channels, the fulfil of one part leaves and the other is refused: the refused part is claimed at the claim buffer and never failed', async () => {
		const tag = 'review-r3';
		const arm: IArm = { down: false };
		const s = await openPartsScene(world, tag, {
			world: { secondOut: 'asset', wrapProvider: { carol: refusing(arm) } }
		});
		const carol = s.w.hosts.carol;
		arm.only = hex(s.w.outChannel2!);
		carol.node.on('log', (log: { action: string }) => {
			if (log.action === 'asset_set_committed') {
				arm.down = true;
				// A transient refusal: the answer the preflight kept is not reused.
				carol.node
					.getChannelManager()
					.getChannel(s.w.outChannel2!)!
					.getFullState()
					.auxiliaryAnswers?.clear();
			}
		});
		const t = trace(carol);
		const second = aliasOf(s.w.hosts.bob, s.w.outChannel2!);
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n], {
			part: (index) => (index === 1 ? { next: second } : {})
		});
		const keys = settledKeys(s, invoice);
		expect(keys.length).to.equal(2);
		const refused = keys.find((key) => key.startsWith(hex(s.w.outChannel2!)))!;
		const taken = keys.find((key) => key.startsWith(hex(s.w.outChannel)))!;
		expect(entryOf(carol, taken)?.state ?? 'removed').to.not.equal(
			HtlcState.COMMITTED
		);
		expect(entryOf(carol, refused)?.state).to.equal(HtlcState.COMMITTED);
		expect(decisionOf(carol, refused)).to.equal('settle');
		const expiry = entryOf(carol, refused)!.cltvExpiry;
		await world.passTo(s.w, expiry - claimBufferOf(carol));
		expect(t.fails.filter((key) => keys.includes(key))).to.deep.equal([]);
		const closes = t.errors.filter((e) => e.code === 'HTLC_CLAIM_FORCE_CLOSE');
		expect(closes.length).to.be.greaterThan(0);
		expect(closes.map((e) => hex(e.channelId!))).to.include(
			hex(s.w.outChannel2!)
		);
	});

	it('a label written over the record (setPaymentMetadata, POST /payment/metadata) takes the commit marker with it, and the refused part is then never claimed', async () => {
		const tag = 'review-r4';
		const arm: IArm = { down: false };
		const s = await openPartsScene(world, tag, {
			world: { wrapProvider: { carol: refusing(arm) } }
		});
		const carol = s.w.hosts.carol;
		carol.node.on('log', (log: { action: string }) => {
			if (log.action === 'asset_set_committed') arm.down = true;
		});
		const t = trace(carol);
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		const keys = settledKeys(s, invoice);
		expect(keys.length).to.equal(2);
		// A caller labels the payment; the engine keeps _keysend from callers,
		// not this key.
		carol.node.setPaymentMetadata(invoice.paymentHash, {
			_auxiliaryReceivedParts: 'relabelled'
		});
		const expiry = Math.min(
			...keys.map((key) => entryOf(carol, key)!.cltvExpiry)
		);
		await world.passTo(s.w, expiry - claimBufferOf(carol));
		await world.mine(s.w, 2);
		expect(t.fails.filter((key) => keys.includes(key))).to.deep.equal([]);
		expect(
			t.errors.filter((e) => e.code === 'HTLC_CLAIM_FORCE_CLOSE').length,
			`the set's parts are claimed at the claim buffer whatever a label says (parts still ${keys
				.map((key) => entryOf(carol, key)?.state)
				.join(',')})`
		).to.be.greaterThan(0);
	});

	it('a host listener that throws on the log of the commit: every part is still fulfilled off the chain', async () => {
		const tag = 'review-r6';
		const s = await openPartsScene(world, tag);
		const carol = s.w.hosts.carol;
		const thrown = { done: false, caught: [] as string[] };
		carol.node.on('log', (log: { action: string }) => {
			if (log.action === 'asset_set_committed' && !thrown.done) {
				thrown.done = true;
				throw new Error('a host logger failed');
			}
		});
		const t = trace(carol);
		let invoice: IPartsInvoice | undefined;
		try {
			invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		} catch (err) {
			thrown.caught.push(String(err));
		}
		expect(thrown.done, 'the listener threw').to.equal(true);
		const hash = [...s.carolLogs]
			.reverse()
			.find((log) => log.action === 'asset_set_committed')!.data
			.paymentHash as string;
		const record = carol.node.getPayment(Buffer.from(hash, 'hex'));
		expect(record?.status).to.equal(PaymentStatus.COMPLETED);
		const keys = record!.settledHtlcs!;
		// A few blocks pass, the link staying up: nothing is left to the chain.
		await world.mine(s.w, 3);
		const states = keys.map((key) => entryOf(carol, key)?.state ?? 'removed');
		expect(
			states,
			`every part fulfilled (caught: ${JSON.stringify(
				thrown.caught
			)}, decisions: ${keys
				.map((key) => decisionOf(carol, key))
				.join(',')}, payment:received ${s.received.length}, invoice ${
				invoice !== undefined
			})`
		).to.not.include(HtlcState.COMMITTED);
		expect(
			t.errors.filter((e) => e.code === 'HTLC_CLAIM_FORCE_CLOSE')
		).to.deep.equal([]);
		expect(s.received.length, 'payment:received once').to.equal(1);
	});

	it('the commit write does not land: the whole set fails back, nothing decided, fulfilled or revealed, and the record stays PENDING', async () => {
		const tag = 'review-r7';
		const s = await openPartsScene(world, tag, {
			world: { carolOnFile: true }
		});
		const carol = s.w.hosts.carol;
		const node = carol.node as unknown as {
			commitMutations: (label: string, ...rest: unknown[]) => boolean;
		};
		const commit = node.commitMutations.bind(carol.node);
		const refusedLabels: string[] = [];
		node.commitMutations = (label: string, ...rest: unknown[]): boolean => {
			if (label === 'commit a set of asset parts') {
				refusedLabels.push(label);
				return false;
			}
			return commit(label, ...rest);
		};
		const manager = carol.node.getChannelManager();
		const fulfil = manager.fulfillHtlc.bind(manager);
		const fulfils: string[] = [];
		manager.fulfillHtlc = (
			channelId,
			htlcId,
			preimage
		): ReturnType<typeof fulfil> => {
			fulfils.push(`${hex(channelId)}:${htlcId}`);
			return fulfil(channelId, htlcId, preimage);
		};
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		await world.mine(s.w, 1);
		for (let i = 0; i < 2; i++) {
			world.cut(s.w, 'out');
			await world.reconnect(s.w, 'out');
		}
		expect(refusedLabels.length).to.equal(1);
		expect(
			s.carolLogs
				.filter((log) => log.action === 'asset_set_not_settled')
				.map((log) => log.data.reason)
		).to.deep.equal(['write']);
		expect(fulfils).to.deep.equal([]);
		expect(carol.node.getPayment(invoice.paymentHash)?.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(
			s.w.hosts.alice.node.getPayment(invoice.paymentHash)?.preimage
		).to.equal(undefined);
		expect(s.received.length).to.equal(0);
	});

	it('parts lost on the chain one by one: each is counted once, the record stays COMPLETED until the last is lost', async () => {
		const tag = 'review-r8';
		const s = await openPartsScene(world, tag);
		const carol = s.w.hosts.carol;
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		const record = carol.node.getPayment(invoice.paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.COMPLETED);
		const values = JSON.parse(
			(record as { metadata?: Record<string, string> }).metadata!
				._auxiliaryReceivedParts
		) as Record<string, string>;
		const keys = Object.keys(values);
		expect(keys.length).to.equal(2);
		const manager = carol.node.getChannelManager();
		const lost: Array<{
			channelId: Buffer;
			htlcId: bigint;
			paymentHash: Buffer;
		}> = [];
		(
			manager as unknown as { auxiliaryClaimsLost: () => typeof lost }
		).auxiliaryClaimsLost = (): typeof lost => lost;
		const t = trace(carol);
		const failed: unknown[] = [];
		carol.node.on('payment:failed', (payment: unknown) => failed.push(payment));
		const run = (): void =>
			(
				carol.node as unknown as { failAssetReceiptsLostOnChain: () => void }
			).failAssetReceiptsLostOnChain();
		const [first, second] = keys;
		const part = (key: string): (typeof lost)[number] => ({
			channelId: Buffer.from(key.split(':')[0], 'hex'),
			htlcId: BigInt(key.split(':')[1]),
			paymentHash: invoice.paymentHash
		});
		lost.push(part(first));
		run();
		run();
		let now = carol.node.getPayment(invoice.paymentHash)!;
		expect(now.status).to.equal(PaymentStatus.COMPLETED);
		expect(now.receivedMsat).to.equal(BigInt(values[second]));
		expect(
			t.errors.filter((e) => e.code === 'ASSET_HTLC_CLAIM_LOST').length
		).to.equal(1);
		lost.push(part(second));
		run();
		run();
		now = carol.node.getPayment(invoice.paymentHash)!;
		expect(now.status).to.equal(PaymentStatus.FAILED);
		expect(failed.length).to.equal(1);
		expect(
			t.errors.filter((e) => e.code === 'ASSET_HTLC_CLAIM_LOST').length
		).to.equal(2);
	});

	it('a label written back from a copy read before a loss puts the lost part back, and its loss is told again', async () => {
		const tag = 'review-r9';
		const s = await openPartsScene(world, tag);
		const carol = s.w.hosts.carol;
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		const before = carol.node.getPayment(invoice.paymentHash) as unknown as {
			metadata: Record<string, string>;
		};
		// A labeller reads the record (GET, or getPayment) ...
		const copy = { ...before.metadata };
		const keys = Object.keys(JSON.parse(copy._auxiliaryReceivedParts));
		const manager = carol.node.getChannelManager();
		const lost: Array<{
			channelId: Buffer;
			htlcId: bigint;
			paymentHash: Buffer;
		}> = [];
		(
			manager as unknown as { auxiliaryClaimsLost: () => typeof lost }
		).auxiliaryClaimsLost = (): typeof lost => lost;
		const t = trace(carol);
		const run = (): void =>
			(
				carol.node as unknown as { failAssetReceiptsLostOnChain: () => void }
			).failAssetReceiptsLostOnChain();
		lost.push({
			channelId: Buffer.from(keys[0].split(':')[0], 'hex'),
			htlcId: BigInt(keys[0].split(':')[1]),
			paymentHash: invoice.paymentHash
		});
		run();
		// ... and writes its label back with what it read, after the loss.
		carol.node.setPaymentMetadata(invoice.paymentHash, {
			...copy,
			label: 'coffee'
		});
		run();
		const parts = JSON.parse(
			(
				carol.node.getPayment(invoice.paymentHash) as unknown as {
					metadata: Record<string, string>;
				}
			).metadata._auxiliaryReceivedParts
		) as Record<string, string>;
		expect(
			{
				lostTold: t.errors.filter((e) => e.code === 'ASSET_HTLC_CLAIM_LOST')
					.length,
				lostPartNamed: parts[keys[0]] !== undefined
			},
			'one part lost, told once, and named no more'
		).to.deep.equal({ lostTold: 1, lostPartNamed: false });
	});

	it('a restart inside the claim buffer, the decisions never written: the restore writes them and claims, and no part is failed', async () => {
		const tag = 'review-r5';
		const arm: IArm = { down: false };
		const s = await openPartsScene(world, tag, {
			world: { carolOnFile: true, wrapProvider: { carol: refusing(arm) } }
		});
		const carol = s.w.hosts.carol;
		const manager = carol.node.getChannelManager();
		const decide = manager.recordAuxiliaryHtlcDecision.bind(manager);
		const writes = { refuse: false };
		manager.recordAuxiliaryHtlcDecision = (
			channelId,
			htlcId,
			outcome,
			preimage
		): boolean =>
			writes.refuse ? false : decide(channelId, htlcId, outcome, preimage);
		carol.node.on('log', (log: { action: string }) => {
			if (log.action === 'asset_set_committed') {
				arm.down = true;
				writes.refuse = true;
			}
		});
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		const keys = settledKeys(s, invoice);
		expect(keys.length).to.equal(2);
		const expiry = Math.min(
			...keys.map((key) => entryOf(carol, key)!.cltvExpiry)
		);
		const target = expiry - claimBufferOf(carol) + 2;
		await world.restartCarol(s.w, tag, {
			wrapProvider: refusing(arm),
			reconnect: false,
			whileDown: () => world.passTo(s.w, target)
		});
		listenCarol(s);
		const again = s.w.hosts.carol;
		const t = trace(again);
		await world.mine(s.w, 1);
		for (const key of keys) {
			expect(decisionOf(again, key), `decision of ${key}`).to.equal('settle');
		}
		expect(t.fails.filter((key) => keys.includes(key))).to.deep.equal([]);
		const state = again.node
			.getChannelManager()
			.getChannel(s.w.outChannel)
			?.getState();
		expect(
			t.errors.filter((e) => e.code === 'HTLC_CLAIM_FORCE_CLOSE').length +
				(String(state).includes('CLOSE') ? 1 : 0),
			`closed to claim (state ${state}, errors ${JSON.stringify(
				t.errors.map((e) => e.code)
			)})`
		).to.be.greaterThan(0);
	});
});
