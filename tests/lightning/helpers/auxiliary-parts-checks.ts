/**
 * What the tests of an asset invoice paid in parts read off the payee and
 * arm on it (issue #2098, step 8), on the scene of auxiliary-forward-scene.ts:
 * the parts it collects and holds, their settle decisions, what it sends
 * its peer, and providers that refuse at the moment a test chooses.
 */

import crypto from 'crypto';
import { expect } from 'chai';
import type {
	IAuxiliaryCommitmentContext,
	IChannelAuxiliaryProvider
} from '../../../src/lightning/channel/auxiliary';
import {
	HtlcState,
	type IHtlcEntry
} from '../../../src/lightning/channel/types';
import { OutputStatus, OutputType } from '../../../src/lightning/chain/types';
import type { ITrackedOutput } from '../../../src/lightning/chain/types';
import { PaymentStatus } from '../../../src/lightning/node/types';
import type { IPartsInvoice } from './auxiliary-forward-world';
import { rounds, type IPartsScene } from './auxiliary-forward-scene';
import type { IAssetHost } from './auxiliary-nodes';
import { turns } from './auxiliary-nodes';
import { trackedOutputs } from './auxiliary-on-chain';

export type Log = {
	category: string;
	action: string;
	data: Record<string, unknown>;
};

export const hex = (value: Buffer): string => value.toString('hex');
export const sha256 = (value: Buffer): Buffer =>
	crypto.createHash('sha256').update(value).digest();
export const keyOf = (channelId: Buffer, htlcId: bigint): string =>
	`${hex(channelId)}:${htlcId}`;

/** The update messages of BOLT 2 that end an HTLC. */
export const UPDATE_FULFILL_HTLC = 130;
export const UPDATE_FAIL_HTLC = 131;
export const UPDATE_FAIL_MALFORMED_HTLC = 135;

type PendingSets = Map<string, { receivedParts: Array<{ status: string }> }>;

/** The parts a host collects for a hash, still pending, in its set. */
export const collected = (host: IAssetHost, paymentHash: Buffer): number =>
	(
		(
			host.node as unknown as { pendingMppPayments: PendingSets }
		).pendingMppPayments.get(hex(paymentHash))?.receivedParts ?? []
	).filter((part) => part.status === PaymentStatus.PENDING).length;

/** The HTLCs a host received for a hash on a channel and still holds there, by id. */
export const receivedEntries = (
	host: IAssetHost,
	channelId: Buffer,
	paymentHash: Buffer
): IHtlcEntry[] =>
	[
		...(host.node.getChannelManager().getChannel(channelId)?.getFullState()
			.htlcs ?? new Map<string, IHtlcEntry>())
	]
		.filter(
			([key, entry]) =>
				key.startsWith('received-') &&
				entry.paymentHash.equals(paymentHash) &&
				entry.state === HtlcState.COMMITTED
		)
		.map(([, entry]) => entry)
		.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

export const heldOn = (
	host: IAssetHost,
	channelId: Buffer,
	paymentHash: Buffer
): number => receivedEntries(host, channelId, paymentHash).length;

export const decisionOf = (
	host: IAssetHost,
	channelId: Buffer,
	htlcId: bigint
): string | undefined =>
	host.node.getChannelManager().auxiliaryHtlcDecision(channelId, htlcId)
		?.outcome;

export const metadataOf = (
	payment: object | undefined
): Record<string, string> | undefined =>
	(payment as { metadata?: Record<string, string> } | undefined)?.metadata;

/** The parts a committed record names, with the value of each. */
export const partsOf = (
	payment: object | undefined
): Record<string, string> | undefined => {
	const parts = metadataOf(payment)?._auxiliaryReceivedParts;
	return parts === undefined
		? undefined
		: (JSON.parse(parts) as Record<string, string>);
};

export const unitsOf = (host: IAssetHost, channelId: Buffer): bigint =>
	host.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance;

/** The settle decisions and fulfils and fails a host's channel manager was asked for. */
export interface IWatch {
	decisions: Array<{ key: string; outcome: string; written: boolean }>;
	fulfils: Array<{ key: string; ok: boolean }>;
	fails: string[];
}
export function watchManager(host: IAssetHost): IWatch {
	const watch: IWatch = { decisions: [], fulfils: [], fails: [] };
	const manager = host.node.getChannelManager();
	const decide = manager.recordAuxiliaryHtlcDecision.bind(manager);
	manager.recordAuxiliaryHtlcDecision = (
		channelId,
		htlcId,
		outcome,
		preimage
	): boolean => {
		const written = decide(channelId, htlcId, outcome, preimage);
		watch.decisions.push({ key: keyOf(channelId, htlcId), outcome, written });
		return written;
	};
	const fulfil = manager.fulfillHtlc.bind(manager);
	manager.fulfillHtlc = (
		channelId,
		htlcId,
		preimage
	): ReturnType<typeof fulfil> => {
		const result = fulfil(channelId, htlcId, preimage);
		watch.fulfils.push({ key: keyOf(channelId, htlcId), ok: result.ok });
		return result;
	};
	const fail = manager.failHtlc.bind(manager);
	manager.failHtlc = (
		channelId: Buffer,
		htlcId: bigint,
		...rest: unknown[]
	): ReturnType<typeof fail> => {
		watch.fails.push(keyOf(channelId, htlcId));
		return (fail as (...args: unknown[]) => ReturnType<typeof fail>)(
			channelId,
			htlcId,
			...rest
		);
	};
	return watch;
}

/** Every update a host sent that ends an HTLC, as `type:channel:id`. */
export function wireWatch(host: IAssetHost): string[] {
	const sent: string[] = [];
	host.node.on(
		'message:outbound',
		(_pubkey: string, type: number, payload: Buffer) => {
			if (
				type !== UPDATE_FULFILL_HTLC &&
				type !== UPDATE_FAIL_HTLC &&
				type !== UPDATE_FAIL_MALFORMED_HTLC
			) {
				return;
			}
			sent.push(
				`${type}:${hex(payload.subarray(0, 32))}:${payload.readBigUInt64BE(32)}`
			);
		}
	);
	return sent;
}

/** The ends a wire watch saw of one HTLC, by message type. */
export const endsOf = (
	sent: string[],
	channelId: Buffer,
	htlcId: bigint
): number[] =>
	sent
		.filter((entry) => entry.endsWith(`:${keyOf(channelId, htlcId)}`))
		.map((entry) => Number(entry.split(':')[0]));

/**
 * A provider that throws in buildCommitment while `arm.down`, as one whose
 * asset store refuses a removal; otherwise the one it wraps.
 */
export function refusing(arm: {
	down: boolean;
}): (provider: IChannelAuxiliaryProvider) => IChannelAuxiliaryProvider {
	return (provider) =>
		new Proxy(provider, {
			get(target, key, receiver): unknown {
				const value = Reflect.get(target, key, receiver) as unknown;
				if (typeof value !== 'function') return value;
				return (...args: unknown[]): unknown => {
					if (arm.down && key === 'buildCommitment') {
						throw new Error('provider down in buildCommitment');
					}
					return (value as (...rest: unknown[]) => unknown).apply(target, args);
				};
			}
		});
}

/**
 * A provider that refuses every commitment which leaves out an HTLC it is
 * told to keep (`<channel hex>:<id>`): the removal of that HTLC alone is
 * refused, and every other update of its channel is taken.
 */
export function keeping(arm: {
	keep: Set<string>;
}): (provider: IChannelAuxiliaryProvider) => IChannelAuxiliaryProvider {
	return (provider) =>
		new Proxy(provider, {
			get(target, key, receiver): unknown {
				const value = Reflect.get(target, key, receiver) as unknown;
				if (typeof value !== 'function') return value;
				return (...args: unknown[]): unknown => {
					if (key === 'buildCommitment' && arm.keep.size > 0) {
						const context = args[0] as IAuxiliaryCommitmentContext;
						const channelHex = hex(context.state.channelId ?? Buffer.alloc(0));
						const listed = new Set(
							context.htlcs.map((htlc) => htlc.htlcId.toString())
						);
						for (const kept of arm.keep) {
							const [channel, id] = kept.split(':');
							if (channel === channelHex && !listed.has(id)) {
								throw new Error(
									`provider refuses the removal of HTLC ${id} in buildCommitment`
								);
							}
						}
					}
					return (value as (...rest: unknown[]) => unknown).apply(target, args);
				};
			}
		});
}

/**
 * Run `armed` once, at the moment the payee commits a set: its log
 * asset_set_committed, which comes after the records are written and
 * before any part's settle decision or fulfil.
 */
export function onCommit(s: IPartsScene, armed: (log: Log) => void): void {
	let done = false;
	s.w.hosts.carol.node.on('log', (log: Log) => {
		if (done || log.action !== 'asset_set_committed') return;
		done = true;
		try {
			armed(log);
		} catch (error) {
			// Thrown out of the node's emit, it would break the commit itself:
			// it fails the test from outside instead.
			setImmediate(() => {
				throw error;
			});
		}
	});
}

/** The HTLCs a host received on a channel and still holds there, of any hash, by id. */
export const openReceived = (
	host: IAssetHost,
	channelId: Buffer
): IHtlcEntry[] =>
	[
		...(host.node.getChannelManager().getChannel(channelId)?.getFullState()
			.htlcs ?? new Map<string, IHtlcEntry>())
	]
		.filter(
			([key, entry]) =>
				key.startsWith('received-') && entry.state === HtlcState.COMMITTED
		)
		.map(([, entry]) => entry)
		.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

export const carolsRecord = (
	s: IPartsScene,
	invoice: IPartsInvoice
): ReturnType<IAssetHost['node']['getPayment']> =>
	s.w.hosts.carol.node.getPayment(invoice.paymentHash);

export const alicesStatus = (
	s: IPartsScene,
	invoice: IPartsInvoice
): PaymentStatus | undefined =>
	s.w.hosts.alice.node.getPayment(invoice.paymentHash)?.status;

export async function committed(
	s: IPartsScene,
	invoice: IPartsInvoice
): Promise<void> {
	await rounds(
		'Carol commits the set',
		() => carolsRecord(s, invoice)?.status === PaymentStatus.COMPLETED,
		40
	);
}

export async function alicePaid(
	s: IPartsScene,
	invoice: IPartsInvoice
): Promise<void> {
	await rounds(
		'Alice is paid',
		() => alicesStatus(s, invoice) === PaymentStatus.COMPLETED,
		60
	);
	await turns(100);
}

/** Carol's log of each part a set of `invoice` lost on the chain. */
export const lossesOf = (s: IPartsScene, invoice: IPartsInvoice): Log[] =>
	s.carolLogs.filter(
		(log) =>
			log.action === 'asset_htlc_claim_lost' &&
			log.data.paymentHash === hex(invoice.paymentHash)
	);

export const notSettledOf = (s: IPartsScene, invoice: IPartsInvoice): Log[] =>
	s.carolLogs.filter(
		(log) =>
			log.action === 'asset_set_not_settled' &&
			log.data.paymentHash === hex(invoice.paymentHash)
	);

/** What Carol's host was asked about the parts of an invoice, in order. */
export const asksFor = (
	s: IPartsScene,
	invoice: IPartsInvoice
): IPartsScene['carolAsks'] =>
	s.carolAsks.filter((ask) => ask.paymentHash.equals(invoice.paymentHash));

/** Carol's first-level outputs of the HTLCs she received for `paymentHash`. */
export const receivedOutputs = (
	host: IAssetHost,
	channelId: Buffer,
	paymentHash: Buffer
): ITrackedOutput[] =>
	trackedOutputs(host, channelId).filter(
		(output) =>
			output.outputType === OutputType.RECEIVED_HTLC &&
			!output.isSecondLevelHtlc &&
			output.paymentHash?.equals(paymentHash) === true
	);

export const isSpent = (output: ITrackedOutput | undefined): boolean =>
	!!output &&
	[OutputStatus.SPEND_CONFIRMED, OutputStatus.IRREVOCABLY_RESOLVED].includes(
		output.status
	);

/** Whether the spend of an output that is in a block shows the preimage of the hash. */
export const showsPreimage = (
	s: IPartsScene,
	output: ITrackedOutput,
	paymentHash: Buffer
): boolean =>
	s.w.chain.confirmed
		.get(output.resolutionTxid ?? '')
		?.tx.ins.some((input) =>
			input.witness.some(
				(element) =>
					element.length === 32 && sha256(element).equals(paymentHash)
			)
		) === true;

/** Carol's outputs of a hash that a spend of hers in a block claimed by the preimage. */
export const claimedByPreimage = (
	s: IPartsScene,
	channelId: Buffer,
	paymentHash: Buffer
): ITrackedOutput[] =>
	receivedOutputs(s.w.hosts.carol, channelId, paymentHash).filter(
		(output) => isSpent(output) && showsPreimage(s, output, paymentHash)
	);

/** Every node:error code a host raised. */
export const errorCodes = (host: IAssetHost): string[] =>
	host.errors.map((error) => error.split(':')[0]);

/**
 * A set that was not settled at its completion: logged with its reason,
 * no settle decision written, no fulfil tried or sent, nothing revealed,
 * the host not told of a payment.
 */
export function expectNothingSettled(
	s: IPartsScene,
	invoice: IPartsInvoice,
	reason: string,
	watch: IWatch,
	sent: string[]
): void {
	expect(
		[...new Set(notSettledOf(s, invoice).map((log) => log.data.reason))],
		'the set is not settled, with its reason'
	).to.deep.equal([reason]);
	expect(
		watch.decisions.filter((decision) => decision.outcome === 'settle'),
		'no settle decision was written'
	).to.deep.equal([]);
	expect(watch.fulfils, 'no fulfil was tried').to.deep.equal([]);
	expect(
		sent.filter((entry) => entry.startsWith(`${UPDATE_FULFILL_HTLC}:`)),
		'no fulfil was sent'
	).to.deep.equal([]);
	expect(
		s.w.hosts.alice.node.getPayment(invoice.paymentHash)?.preimage,
		'nothing was revealed'
	).to.equal(undefined);
	expect(carolsRecord(s, invoice)?.status).to.not.equal(
		PaymentStatus.COMPLETED
	);
	expect(
		s.received.filter((payment) =>
			payment.paymentHash.equals(invoice.paymentHash)
		)
	).to.deep.equal([]);
	for (const ask of asksFor(s, invoice)) {
		expect(
			decisionOf(s.w.hosts.carol, ask.channelId, ask.htlcId),
			`no settle decision for ${keyOf(ask.channelId, ask.htlcId)}`
		).to.not.equal('settle');
	}
}
