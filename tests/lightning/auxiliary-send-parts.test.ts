/**
 * Issue #2098, step 9: an asset payment sent in parts. A host that opts in
 * (`sendInParts: true`), on a build whose switch is on, sends each part of
 * an asset payment by its own sendPaymentToRoute: the parts leave over the
 * asset channels of one peer, each with its own units and its own carrier,
 * each recorded before it is sent and counted toward its channel's HTLC
 * bound, all under one record that is kept across the parts. Every refusal
 * comes before anything is recorded or sent. A part that fails while another
 * is out leaves the record PENDING, and the host may send it again. Without
 * the opt-in, or with the build's switch off, a part is refused as before
 * and a payment of one HTLC is recorded as before, byte for byte.
 *
 * The cases run on the chain world of auxiliary-forward-world.ts, asset in
 * and bitcoin out: Alice is the wallet, Bob her primary, whose host values
 * each part and forwards it to Carol over an ordinary channel as a forward
 * of its own, and Carol collects the parts as any multi-part set. A
 * loopback pair has a part's fulfil, or its failure, run inside its own add.
 * The ends of parts on the chain are tested apart.
 *
 * Written first: on the build before step 9 each case of new behaviour fails
 * where that build refuses a part (an asset HTLC whose total is above its
 * value), or where it records, lists and asks the gate what it always did,
 * and the regression cases pass. The contract is "An asset payment sent in
 * parts" in docs/EXTENSIONS.md.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	AuxiliaryPaymentError,
	PaymentDirection,
	PaymentStatus,
	type AuxiliaryPaymentGate
} from '../../src/lightning/node/types';
import { constructBlindedPath } from '../../src/lightning/onion/blinded-path';
// temporary_channel_failure is how Bob fails a forward his host refused, and
// mpp_timeout how Carol fails the parts of a set that never completed.
import {
	MPP_TIMEOUT,
	TEMPORARY_CHANNEL_FAILURE
} from '../../src/lightning/onion/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { rounds } from './helpers/auxiliary-forward-scene';
import {
	FORWARD_CARRIER_MSAT,
	aliasOf,
	forwardChainWorld,
	heldPartsInvoice,
	partUnits,
	partsInvoice,
	sendAssetPart,
	sendPart,
	type IAssetPartSent
} from './helpers/auxiliary-forward-world';
import {
	assetPartsSentSwitch,
	turns,
	withAssetForwards,
	withAssetOpens,
	withAssetPartsReceived,
	withAssetPartsSent,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { collected } from './helpers/auxiliary-parts-checks';
import {
	listenAlice,
	openSendScene,
	partsPair,
	sendPairPart,
	stopAtAdd,
	timeOutSets,
	type ISendScene
} from './helpers/auxiliary-send-scene';

const hex = (value: Buffer): string => value.toString('hex');
const CARRIER = FORWARD_CARRIER_MSAT;
const NOT_DECRYPTED =
	'Remote failure could not be decrypted (no hop HMAC matched)';
/** The engine's keys that setPaymentMetadata leaves alone on every record. */
const NEW_KEYS = [
	'_auxiliaryPartsSent',
	'_auxiliaryPeer',
	'_auxiliaryPartsTotalMsat'
];
/** And those it leaves alone on a record of the new path. */
const OLD_KEYS = [
	'_auxiliaryPartAmounts',
	'_auxiliaryChannelId',
	'_auxiliaryWireAmountMsat',
	'_auxiliaryNeverSent',
	'_auxiliaryAdmissionRejected'
];

type GateRequest = Parameters<AuxiliaryPaymentGate>[0] & {
	totalMsat?: bigint;
	htlcId?: bigint;
};

/** A part as the listing gives it, without the live view of its HTLC. */
interface IListed {
	channelId: Buffer;
	htlcId: bigint;
	amountMsat: bigint;
	routeAmountMsat?: bigint;
	wireAmountMsat?: bigint;
	failed: boolean;
}

const keyOf = (part: { channelId: Buffer; htlcId: bigint }): string =>
	`${hex(part.channelId)}:offered-${part.htlcId}`;

/** What the listing of an asset payment says of each part, in the order sent. */
function recorded(node: LightningNode, paymentHash: Buffer): IListed[] {
	return (
		node.getAuxiliaryPaymentHtlcs(paymentHash) as unknown as Array<
			IListed & { failed?: boolean }
		>
	).map((entry) => ({
		channelId: entry.channelId,
		htlcId: entry.htlcId,
		amountMsat: entry.amountMsat,
		routeAmountMsat: entry.routeAmountMsat,
		wireAmountMsat: entry.wireAmountMsat,
		failed: entry.failed === true
	}));
}

/** What the listing says of a part sent in the new path. */
const entryOf = (part: IAssetPartSent, failed = false): IListed => ({
	channelId: part.channelId,
	htlcId: part.htlcId,
	amountMsat: part.valueMsat,
	routeAmountMsat: part.routeAmountMsat,
	wireAmountMsat: part.wireAmountMsat,
	failed
});

const figures = (
	node: LightningNode,
	paymentHash: Buffer
):
	| {
			status: PaymentStatus;
			amountMsat: bigint;
			auxiliaryValueMsat?: bigint;
	  }
	| undefined => {
	const payment = node.getPayment(paymentHash);
	return payment
		? {
				status: payment.status,
				amountMsat: payment.amountMsat,
				auxiliaryValueMsat: payment.auxiliaryValueMsat
		  }
		: undefined;
};

/** The send went through: it returned a record and threw nothing. */
function sentOk(part: IAssetPartSent): void {
	expect(part.error, `the part was not sent: ${String(part.error)}`).to.equal(
		undefined
	);
	expect(part.payment, 'the send returned the record').to.not.equal(undefined);
}

/** The send was refused with a typed error, with this code, naming this channel. */
function refusedWith(
	part: { error?: unknown; payment?: { status: string } },
	code: string,
	channelId: Buffer
): void {
	expect(
		part.error,
		part.error === undefined
			? `the part was not refused: the send returned a record ${String(
					part.payment?.status
			  )}`
			: `the part was refused otherwise: ${String(part.error)}`
	).to.be.instanceOf(AuxiliaryPaymentError);
	const error = part.error as AuxiliaryPaymentError;
	expect(error.code, error.message).to.equal(code);
	expect(error.channelId, 'the refusal names the channel').to.equal(
		hex(channelId)
	);
}

/** The HTLC mappings stored for a hash, by key. */
const storedMappings = (host: IAssetHost, paymentHash: Buffer): string[] =>
	host
		.storage!.loadAllHtlcPaymentMappings()
		.filter((row) => row.paymentHashHex === hex(paymentHash))
		.map((row) => row.key)
		.sort();

/** The HTLC mappings a node holds in memory for a hash, by key. */
const heldMappings = (host: IAssetHost, paymentHash: Buffer): string[] =>
	[
		...(host.node as unknown as { htlcPaymentMap: Map<string, string> })
			.htlcPaymentMap
	]
		.filter(([, value]) => value === hex(paymentHash))
		.map(([key]) => key)
		.sort();

/** The value of each part as the stored record keeps it, by key. */
const storedPartAmounts = (
	host: IAssetHost,
	paymentHash: Buffer
): Record<string, string> =>
	JSON.parse(
		host.storage!.loadPayment(hex(paymentHash))?.metadata
			?._auxiliaryPartAmounts ?? '{}'
	) as Record<string, string>;

const plain = (value: unknown): unknown =>
	JSON.parse(
		JSON.stringify(value, (_key, item: unknown) =>
			typeof item === 'bigint' ? `${item}n` : item
		)
	);

/**
 * Everything of Alice's that a send may move for a hash: the record in
 * memory and stored, the listing, the HTLC mappings, and each of her
 * channels' HTLCs, next id, units and bitcoin. Equal before and after a
 * refusal when nothing was recorded or sent.
 */
function trace(s: ISendScene, paymentHash: Buffer): unknown {
	const alice = s.w.hosts.alice;
	const channels = [s.w.inChannel, s.w.inChannel2, s.w.daveChannel].filter(
		(channelId): channelId is Buffer => channelId !== undefined
	);
	return plain({
		record: alice.node.getPayment(paymentHash) ?? null,
		stored: alice.storage!.loadPayment(hex(paymentHash)),
		listing: alice.node.getAuxiliaryPaymentHtlcs(paymentHash),
		held: heldMappings(alice, paymentHash),
		mapped: storedMappings(alice, paymentHash),
		channels: channels.map((channelId) => {
			const state = alice.node
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			return {
				next: state.localHtlcCounter,
				htlcs: [...state.htlcs.keys()].sort(),
				balance: state.localBalanceMsat,
				units:
					alice.node.getAuxiliaryChannelInfo(channelId)?.localAssetBalance ??
					null
			};
		}),
		forwardsAsked: s.asked.length
	});
}

/** The ends Alice's host was told of for a hash, as `outcome:channel:id`, sorted. */
const endsFor = (
	s: { resolved: ISendScene['resolved'] },
	paymentHash: Buffer
): string[] =>
	s.resolved
		.filter((end) => end.paymentHash.equals(paymentHash))
		.map((end) => `${end.outcome}:${hex(end.channelId)}:${end.htlcId}`)
		.sort();

const endOf = (outcome: string, part: IAssetPartSent): string =>
	`${outcome}:${hex(part.channelId)}:${part.htlcId}`;

const unitsOf = (host: IAssetHost, channelId: Buffer): bigint =>
	host.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance;

/** The HTLCs of a hash Carol holds under a hold invoice. */
const heldAtCarol = (s: ISendScene, paymentHash: Buffer): number =>
	(
		(
			s.w.hosts.carol.node as unknown as {
				heldHtlcs: Map<string, unknown[]>;
			}
		).heldHtlcs.get(hex(paymentHash)) ?? []
	).length;

const countOf = (list: string[], paymentHash: Buffer): number =>
	list.filter((entry) => entry === hex(paymentHash)).length;

/** What Alice's provider was asked about each HTLC she added, at the add. */
interface ISeenAtAdd {
	listed: IListed[];
	stored: Record<string, string>;
	mapped: string[];
}
function watchAdds(s: ISendScene, paymentHash: Buffer): ISeenAtAdd[] {
	const seen: ISeenAtAdd[] = [];
	const alice = s.w.hosts.alice;
	const manager = alice.node.getChannelManager() as unknown as {
		addHtlc: (...args: unknown[]) => unknown;
	};
	const add = manager.addHtlc.bind(manager);
	manager.addHtlc = (...args: unknown[]): unknown => {
		const hashOfAdd = args[2];
		if (Buffer.isBuffer(hashOfAdd) && hashOfAdd.equals(paymentHash)) {
			seen.push({
				listed: recorded(alice.node, paymentHash),
				stored: storedPartAmounts(alice, paymentHash),
				mapped: storedMappings(alice, paymentHash)
			});
		}
		return add(...args);
	};
	return seen;
}

describe('an asset payment sent in parts (issue #2098, step 9)', function () {
	this.timeout(120_000);
	withAssetOpens();
	withAssetForwards();
	withAssetPartsReceived();
	withAssetPartsSent();
	const world = forwardChainWorld();
	const pairHosts: IAssetHost[] = [];
	const directories: string[] = [];
	afterEach(() => {
		world.dispose();
		for (const host of pairHosts.splice(0)) {
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

	const alicePaid = async (
		s: ISendScene,
		paymentHash: Buffer
	): Promise<void> => {
		await rounds(
			'Alice is paid',
			() =>
				s.w.hosts.alice.node.getPayment(paymentHash)?.status ===
				PaymentStatus.COMPLETED,
			60
		);
		await turns(100);
	};
	const carolCollects = (
		s: ISendScene,
		paymentHash: Buffer,
		parts: number
	): Promise<void> =>
		rounds(
			`Carol collects ${parts} parts`,
			() => collected(s.w.hosts.carol, paymentHash) === parts,
			60
		);
	const carolHolds = (
		s: ISendScene,
		paymentHash: Buffer,
		parts: number
	): Promise<void> =>
		rounds(
			`Carol holds ${parts} parts`,
			() => heldAtCarol(s, paymentHash) === parts,
			60
		);
	const toldFailed = (
		s: ISendScene,
		part: IAssetPartSent,
		paymentHash: Buffer
	): Promise<void> =>
		rounds(
			'Alice is told the part failed',
			() => endsFor(s, paymentHash).includes(endOf('failed', part)),
			60
		);

	/** A temporary directory, removed after the test. */
	const directory = (prefix: string): string => {
		const made = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
		directories.push(made);
		return made;
	};

	/** Put a copy of `snapshot` where Alice's database is, with a preimage stored in it when given. */
	const restoreCopy = (
		s: ISendScene,
		snapshot: string,
		preimage?: Buffer
	): void => {
		const file = s.w.alicePath!;
		for (const stale of [file, `${file}-wal`, `${file}-shm`]) {
			fs.rmSync(stale, { force: true });
		}
		fs.copyFileSync(snapshot, file);
		if (preimage) {
			const storage = new SqliteStorage(file);
			storage.open();
			storage.savePreimage(
				hex(crypto.createHash('sha256').update(preimage).digest()),
				preimage
			);
			storage.close();
		}
	};

	describe('sent and settled', () => {
		it('two parts over one asset channel are each recorded before they are sent, with their value, first hop and carrier, are forwarded by Bob one by one, and settle together: COMPLETED once with their sums, payment:sent once, each part told to the host, the units moved', async () => {
			const tag = 'send-parts-one-channel';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const seen = watchAdds(s, h);
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			const second = sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n });
			sentOk(second);
			expect(second.htlcId).to.equal(first.htlcId + 1n);
			expect(
				seen,
				'each part was listed and stored, with its mapping, before its HTLC was added'
			).to.deep.equal([
				{
					listed: [entryOf(first)],
					stored: { [keyOf(first)]: '3000000' },
					mapped: [keyOf(first)]
				},
				{
					listed: [entryOf(first), entryOf(second)],
					stored: { [keyOf(first)]: '3000000', [keyOf(second)]: '2000000' },
					mapped: [keyOf(first), keyOf(second)].sort()
				}
			]);
			await alicePaid(s, h);
			expect(
				s.asked.map((request) => ({
					htlcId: request.incoming.htlcId,
					units: request.incoming.auxiliaryAmount,
					forward: request.amountToForwardMsat
				})),
				'Bob forwarded each part as a forward of its own'
			).to.deep.equal([
				{ htlcId: first.htlcId, units: first.units, forward: 3_000_000n },
				{ htlcId: second.htlcId, units: second.units, forward: 2_000_000n }
			]);
			const record = s.w.hosts.alice.node.getPayment(h)!;
			expect({
				status: record.status,
				direction: record.direction,
				auxiliary: record.auxiliary,
				amountMsat: record.amountMsat,
				auxiliaryValueMsat: record.auxiliaryValueMsat
			}).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				auxiliary: true,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h), 'payment:sent once').to.equal(1);
			expect(countOf(s.failed, h)).to.equal(0);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second)
			]);
			expect(endsFor(s, h)).to.deep.equal(
				[endOf('fulfilled', first), endOf('fulfilled', second)].sort()
			);
			expect(unitsOf(s.w.hosts.alice, s.w.inChannel)).to.equal(
				9000n - first.units - second.units
			);
			expect(s.w.hosts.carol.node.getPayment(h)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('two parts over two asset channels of one peer each leave over their own channel, with their own units, and settle together', async () => {
			const tag = 'send-parts-two-channels';
			const s = await openSendScene(world, tag, {
				world: { secondIn: 'asset' }
			});
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			const second = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				channelId: s.w.inChannel2
			});
			sentOk(second);
			await alicePaid(s, h);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second)
			]);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h)).to.equal(1);
			expect(
				s.asked.map((request) => hex(request.incoming.channelId)).sort(),
				'Bob was asked about each part on its own channel'
			).to.deep.equal([hex(s.w.inChannel), hex(s.w.inChannel2!)].sort());
			expect(endsFor(s, h)).to.deep.equal(
				[endOf('fulfilled', first), endOf('fulfilled', second)].sort()
			);
			expect(unitsOf(s.w.hosts.alice, s.w.inChannel)).to.equal(
				9000n - first.units
			);
			expect(unitsOf(s.w.hosts.alice, s.w.inChannel2!)).to.equal(
				9000n - second.units
			);
		});

		it("parts up to the node's maxHtlcs on one channel are sent, and the next is refused before anything is recorded or sent (ASSET_HTLC_LIMIT_REACHED); over the other channel it completes the set", async () => {
			const tag = 'send-parts-bound';
			const s = await openSendScene(world, tag, {
				world: { secondIn: 'asset' }
			});
			// The gate is asked last: a part the engine refuses never reaches it.
			const asked: GateRequest[] = [];
			s.w.hosts.alice.node.setAuxiliaryPaymentGate((request) => {
				asked.push({ ...request });
				return undefined;
			});
			const invoice = partsInvoice(s.w, tag, 4_500_000n);
			const h = invoice.paymentHash;
			const parts: IAssetPartSent[] = [];
			for (let i = 0; i < 8; i++) {
				const part = sendAssetPart(s.w, invoice, { valueMsat: 500_000n });
				sentOk(part);
				parts.push(part);
			}
			await carolCollects(s, h, 8);
			const before = trace(s, h);
			const ninth = sendAssetPart(s.w, invoice, { valueMsat: 500_000n });
			refusedWith(ninth, 'ASSET_HTLC_LIMIT_REACHED', s.w.inChannel);
			expect(
				asked,
				'the gate was not asked about the refused part'
			).to.have.length(8);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal(
				parts.map((part) => entryOf(part))
			);
			const last = sendAssetPart(s.w, invoice, {
				valueMsat: 500_000n,
				channelId: s.w.inChannel2
			});
			sentOk(last);
			await alicePaid(s, h);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 9n * CARRIER,
				auxiliaryValueMsat: 4_500_000n
			});
			expect(countOf(s.sent, h)).to.equal(1);
		});

		it("a part past the peer's max_accepted_htlcs on its channel is refused before anything is recorded or sent (ASSET_HTLC_NOT_ADMITTED); over the other channel it completes the set", async () => {
			const tag = 'send-parts-peer-bound';
			// Bob announces 2 as his max_accepted_htlcs on the channels he accepts.
			const s = await openSendScene(world, tag, {
				bob: { maxHtlcs: 2 },
				world: { secondIn: 'asset' }
			});
			// The gate is asked last: a part the engine refuses never reaches it.
			const asked: GateRequest[] = [];
			s.w.hosts.alice.node.setAuxiliaryPaymentGate((request) => {
				asked.push({ ...request });
				return undefined;
			});
			const invoice = partsInvoice(s.w, tag, 3_000_000n);
			const h = invoice.paymentHash;
			for (let i = 0; i < 2; i++) {
				sentOk(sendAssetPart(s.w, invoice, { valueMsat: 1_000_000n }));
			}
			await carolCollects(s, h, 2);
			const before = trace(s, h);
			const third = sendAssetPart(s.w, invoice, { valueMsat: 1_000_000n });
			refusedWith(third, 'ASSET_HTLC_NOT_ADMITTED', s.w.inChannel);
			expect(
				asked,
				'the gate was not asked about the refused part'
			).to.have.length(2);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
			expect(countOf(s.failed, h)).to.equal(0);
			sentOk(
				sendAssetPart(s.w, invoice, {
					valueMsat: 1_000_000n,
					channelId: s.w.inChannel2
				})
			);
			await alicePaid(s, h);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 3n * CARRIER,
				auxiliaryValueMsat: 3_000_000n
			});
		});

		it('a payment of one HTLC takes the new path as a set of one: the gate is told its total and its id, it is listed with its first hop and carrier, and it settles once', async () => {
			const tag = 'send-parts-one-htlc';
			const s = await openSendScene(world, tag);
			const asked: GateRequest[] = [];
			s.w.hosts.alice.node.setAuxiliaryPaymentGate((request) => {
				asked.push({ ...request });
				return undefined;
			});
			const invoice = partsInvoice(s.w, tag, 2_000_000n);
			const h = invoice.paymentHash;
			const one = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				totalMsat: null
			});
			sentOk(one);
			expect(asked).to.have.length(1);
			expect(asked[0]).to.deep.include({
				amountMsat: 2_000_000n,
				totalMsat: 2_000_000n,
				htlcId: one.htlcId
			});
			await alicePaid(s, h);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([entryOf(one)]);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: CARRIER,
				auxiliaryValueMsat: 2_000_000n
			});
			expect(countOf(s.sent, h)).to.equal(1);
			expect(endsFor(s, h)).to.deep.equal([endOf('fulfilled', one)]);
		});
	});

	describe('refused, with nothing recorded or sent', () => {
		it("a part over an asset channel of another peer than the payment's first HTLC is refused (ASSET_PAYMENT_ROUTE_REQUIRED)", async () => {
			const tag = 'send-parts-other-peer';
			const s = await openSendScene(world, tag, {
				world: { secondPeer: {} }
			});
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }));
			await carolCollects(s, h, 1);
			const before = trace(s, h);
			const other = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				channelId: s.w.daveChannel,
				firstHop: s.w.dave
			});
			refusedWith(other, 'ASSET_PAYMENT_ROUTE_REQUIRED', s.w.daveChannel!);
			// The peer is judged before the total: a part over the other peer's
			// channel that also declares another total is refused for its peer.
			refusedWith(
				sendAssetPart(s.w, invoice, {
					valueMsat: 2_000_000n,
					channelId: s.w.daveChannel,
					firstHop: s.w.dave,
					totalMsat: 6_000_000n
				}),
				'ASSET_PAYMENT_ROUTE_REQUIRED',
				s.w.daveChannel!
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
			expect(
				s.w.dave!.node.getAuxiliaryChannelInfo(s.w.daveChannel!)!.htlcs
			).to.deep.equal([]);
		});

		it('an asset part, or an asset payment of one HTLC, for a hash with an ordinary HTLC in flight is refused (ASSET_PAYMENT_UNSUPPORTED)', async () => {
			const tag = 'send-parts-mixed-asset';
			const s = await openSendScene(world, tag, {
				world: { secondIn: 'ordinary' }
			});
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			// An ordinary part, over Alice's ordinary channel with Bob.
			sendPart(s.w, invoice, 2_000_000n);
			await carolCollects(s, h, 1);
			expect(s.w.hosts.alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.PENDING
			);
			const before = trace(s, h);
			refusedWith(
				sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }),
				'ASSET_PAYMENT_UNSUPPORTED',
				s.w.inChannel
			);
			refusedWith(
				sendAssetPart(s.w, invoice, {
					valueMsat: 3_000_000n,
					totalMsat: null
				}),
				'ASSET_PAYMENT_UNSUPPORTED',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
		});

		it('an ordinary part for a hash with an asset part in flight is refused as before (ASSET_PAYMENT_ROUTE_REQUIRED)', async () => {
			const tag = 'send-parts-mixed-ordinary';
			const s = await openSendScene(world, tag, {
				world: { secondIn: 'ordinary' }
			});
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }));
			await carolCollects(s, h, 1);
			const before = trace(s, h);
			let thrown: unknown;
			try {
				sendPart(s.w, invoice, 2_000_000n);
			} catch (error) {
				thrown = error;
			}
			refusedWith(
				{ error: thrown },
				'ASSET_PAYMENT_ROUTE_REQUIRED',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
		});

		it('a part that declares another total than the parts in flight declared is refused (ASSET_PAYMENT_INVALID)', async () => {
			const tag = 'send-parts-other-total';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }));
			await carolCollects(s, h, 1);
			const before = trace(s, h);
			refusedWith(
				sendAssetPart(s.w, invoice, {
					valueMsat: 2_000_000n,
					totalMsat: 6_000_000n
				}),
				'ASSET_PAYMENT_INVALID',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
		});

		it('a part that declares a total below its value is refused (ASSET_PAYMENT_INVALID)', async () => {
			const tag = 'send-parts-total-below';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const before = trace(s, h);
			refusedWith(
				sendAssetPart(s.w, invoice, {
					valueMsat: 3_000_000n,
					totalMsat: 2_000_000n
				}),
				'ASSET_PAYMENT_INVALID',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
		});

		it('a part that declares a total above its value without a payment secret is refused (ASSET_PAYMENT_INVALID)', async () => {
			const tag = 'send-parts-no-secret';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const before = trace(s, h);
			refusedWith(
				sendAssetPart(s.w, invoice, {
					valueMsat: 3_000_000n,
					paymentSecret: null
				}),
				'ASSET_PAYMENT_INVALID',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
		});

		it('a part whose value would carry the values in flight past the total is refused (ASSET_PAYMENT_INVALID), and one that reaches the total exactly is sent and completes the set', async () => {
			const tag = 'send-parts-past-total';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }));
			await carolCollects(s, h, 1);
			const before = trace(s, h);
			refusedWith(
				sendAssetPart(s.w, invoice, { valueMsat: 2_000_001n }),
				'ASSET_PAYMENT_INVALID',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n }));
			await alicePaid(s, h);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
		});

		it('a payment of one HTLC in flight and a part of the same hash are not sent beside each other, whichever is first: the second declares another total (ASSET_PAYMENT_INVALID)', async () => {
			const tag = 'send-parts-beside-one';
			const s = await openSendScene(world, tag);
			// A payment of one HTLC, held at Carol, then a part.
			const held = heldPartsInvoice(s.w, `${tag} held`, 2_000_000n);
			sentOk(
				sendAssetPart(s.w, held, { valueMsat: 2_000_000n, totalMsat: null })
			);
			await carolHolds(s, held.paymentHash, 1);
			const beforeHeld = trace(s, held.paymentHash);
			refusedWith(
				sendAssetPart(s.w, held, {
					valueMsat: 1_000_000n,
					totalMsat: 3_000_000n
				}),
				'ASSET_PAYMENT_INVALID',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, held.paymentHash)).to.deep.equal(beforeHeld);
			// A part in flight, then a payment of one HTLC.
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }));
			await carolCollects(s, h, 1);
			const before = trace(s, h);
			refusedWith(
				sendAssetPart(s.w, invoice, {
					valueMsat: 2_000_000n,
					totalMsat: null
				}),
				'ASSET_PAYMENT_INVALID',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
		});

		it("a part, or an asset payment of one HTLC, to the node's own invoice is refused (ASSET_PAYMENT_UNSUPPORTED), and the invoice's record is untouched", async () => {
			const tag = 'send-parts-own-invoice';
			const s = await openSendScene(world, tag);
			const own = s.w.hosts.alice.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'her own'
			});
			const invoice = {
				paymentHash: own.paymentHash,
				paymentSecret: own.paymentSecret,
				totalMsat: 5_000_000n
			};
			const h = own.paymentHash;
			expect(s.w.hosts.alice.node.getPayment(h)?.direction).to.equal(
				PaymentDirection.INCOMING
			);
			const before = trace(s, h);
			refusedWith(
				sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }),
				'ASSET_PAYMENT_UNSUPPORTED',
				s.w.inChannel
			);
			refusedWith(
				sendAssetPart(s.w, invoice, {
					valueMsat: 5_000_000n,
					totalMsat: null
				}),
				'ASSET_PAYMENT_UNSUPPORTED',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
		});

		it('a part for a record failed while a part of it is in flight is refused (ASSET_PAYMENT_UNSUPPORTED); once nothing of it is in flight, a new set starts and completes', async () => {
			const tag = 'send-parts-after-cancel';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }));
			await carolCollects(s, h, 1);
			s.w.hosts.alice.node.failPayment(h);
			expect(s.w.hosts.alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.FAILED
			);
			const before = trace(s, h);
			refusedWith(
				sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n }),
				'ASSET_PAYMENT_UNSUPPORTED',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
			// Carol gives the part back; then nothing of the payment is in flight.
			timeOutSets(s.w.hosts.carol);
			await rounds(
				'nothing of the payment is in flight',
				() => !s.w.hosts.alice.node.hasHtlcInFlight(h),
				60
			);
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }));
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n }));
			await alicePaid(s, h);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h)).to.equal(1);
		});

		it('beside a part in flight, a pay-all, a part for a hash the node retries on its own, and a part that starts a blinded path at this node are refused as before (ASSET_PAYMENT_UNSUPPORTED)', async () => {
			const tag = 'send-parts-as-before';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }));
			await carolCollects(s, h, 1);
			const before = trace(s, h);
			const payAll = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				payAll: { debitMsat: 2_002_000n, maxFeeMsat: 2000n }
			});
			refusedWith(payAll, 'ASSET_PAYMENT_UNSUPPORTED', s.w.inChannel);
			expect(String(payAll.error)).to.include('cannot be a pay-all');
			const contexts = (
				s.w.hosts.alice.node as unknown as {
					paymentRetryContexts: Map<string, unknown>;
				}
			).paymentRetryContexts;
			contexts.set(hex(h), { retryCount: 0, maxRetries: 3 });
			const retried = sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n });
			contexts.delete(hex(h));
			refusedWith(retried, 'ASSET_PAYMENT_UNSUPPORTED', s.w.inChannel);
			expect(String(retried.error)).to.include('retries on its own');
			// A blinded path whose introduction is Alice herself, on to Bob.
			const alicePub = Buffer.from(s.w.hosts.alice.node.getNodeId(), 'hex');
			const blinded = constructBlindedPath(
				crypto.randomBytes(32),
				[alicePub, Buffer.from(s.w.hosts.bob.node.getNodeId(), 'hex')],
				[
					{
						shortChannelId: aliasOf(s.w.hosts.alice, s.w.inChannel),
						paymentRelay: {
							cltvExpiryDelta: 40,
							feeProportionalMillionths: 0,
							feeBaseMsat: 0
						},
						paymentConstraints: {
							maxCltvExpiry: 1_000_000,
							htlcMinimumMsat: 0n
						}
					},
					{ pathId: crypto.randomBytes(32) }
				]
			);
			const start = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				hops: [
					{
						pubkey: alicePub,
						shortChannelId: Buffer.alloc(8),
						amountToForwardMsat: partUnits(2_000_000n) * 1000n,
						outgoingCltvValue: 100,
						encryptedRecipientData: blinded.blindedHops[0].encryptedData,
						blindingPoint: blinded.blindingPoint
					},
					{
						pubkey: blinded.blindedHops[1].blindedNodeId,
						shortChannelId: Buffer.alloc(8),
						amountToForwardMsat: 2_000_000n,
						outgoingCltvValue: 60,
						encryptedRecipientData: blinded.blindedHops[1].encryptedData
					}
				]
			});
			refusedWith(start, 'ASSET_PAYMENT_UNSUPPORTED', s.w.inChannel);
			expect(String(start.error)).to.include('cannot start a blinded path');
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
		});
	});

	describe('a part that fails while another is out', () => {
		it('its failure is its own, decrypted with its own secrets; the record stays PENDING with no payment:failed, the listing marks the part and the figures leave it out; sent again over the other channel, the set completes', async () => {
			const tag = 'send-parts-one-fails';
			const s = await openSendScene(world, tag, {
				world: { secondIn: 'asset' }
			});
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			await carolCollects(s, h, 1);
			s.bobRefuses.next = 1;
			const second = sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n });
			sentOk(second);
			await toldFailed(s, second, h);
			await turns(50);
			const record = s.w.hosts.alice.node.getPayment(h)!;
			expect({
				status: record.status,
				failureCode: record.failureCode,
				failureSourceIndex: record.failureSourceIndex
			}).to.deep.equal({
				status: PaymentStatus.PENDING,
				failureCode: TEMPORARY_CHANNEL_FAILURE,
				failureSourceIndex: 0
			});
			expect(countOf(s.failed, h), 'no payment:failed').to.equal(0);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second, true)
			]);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.PENDING,
				amountMsat: CARRIER,
				auxiliaryValueMsat: 3_000_000n
			});
			const again = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				channelId: s.w.inChannel2
			});
			sentOk(again);
			await alicePaid(s, h);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second, true),
				entryOf(again)
			]);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h)).to.equal(1);
			expect(countOf(s.failed, h)).to.equal(0);
			expect(endsFor(s, h)).to.deep.equal(
				[
					endOf('fulfilled', first),
					endOf('failed', second),
					endOf('fulfilled', again)
				].sort()
			);
		});

		it("when every part of the set fails, the record turns FAILED once, with payment:failed once after the last, the last part's own failure and the set's figures", async () => {
			const tag = 'send-parts-all-fail';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			await carolCollects(s, h, 1);
			s.bobRefuses.next = 1;
			const second = sendAssetPart(s.w, invoice, { valueMsat: 1_000_000n });
			sentOk(second);
			await toldFailed(s, second, h);
			await turns(50);
			expect(s.w.hosts.alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.PENDING
			);
			expect(countOf(s.failed, h)).to.equal(0);
			timeOutSets(s.w.hosts.carol);
			await rounds(
				'the payment fails at Alice',
				() =>
					s.w.hosts.alice.node.getPayment(h)?.status === PaymentStatus.FAILED,
				60
			);
			await turns(100);
			const record = s.w.hosts.alice.node.getPayment(h)!;
			expect({
				status: record.status,
				failureCode: record.failureCode,
				failureSourceIndex: record.failureSourceIndex,
				amountMsat: record.amountMsat,
				auxiliaryValueMsat: record.auxiliaryValueMsat
			}).to.deep.equal({
				status: PaymentStatus.FAILED,
				failureCode: MPP_TIMEOUT,
				failureSourceIndex: 1,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 4_000_000n
			});
			expect(countOf(s.failed, h), 'payment:failed once').to.equal(1);
			expect(countOf(s.sent, h)).to.equal(0);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([
				entryOf(first, true),
				entryOf(second, true)
			]);
		});
	});

	describe('a part the channel refuses at the add, after it was recorded', () => {
		it('beside a part in flight: the send throws ASSET_HTLC_NOT_ADMITTED naming the channel, the part is not listed, the record stays PENDING with no payment:failed; sent again, it completes the set', async () => {
			const tag = 'send-parts-add-refused';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			await carolCollects(s, h, 1);
			s.aliceRefusesAdds.next = 1;
			const second = sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n });
			s.aliceRefusesAdds.next = 0;
			refusedWith(second, 'ASSET_HTLC_NOT_ADMITTED', s.w.inChannel);
			await turns(50);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([entryOf(first)]);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.PENDING,
				amountMsat: CARRIER,
				auxiliaryValueMsat: 3_000_000n
			});
			expect(countOf(s.failed, h)).to.equal(0);
			expect(storedMappings(s.w.hosts.alice, h)).to.deep.equal([keyOf(first)]);
			expect(Object.keys(storedPartAmounts(s.w.hosts.alice, h))).to.deep.equal([
				keyOf(first)
			]);
			expect(s.asked, 'Bob was sent nothing more').to.have.length(1);
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n }));
			await alicePaid(s, h);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
		});

		it('alone: the send throws ASSET_HTLC_NOT_ADMITTED, the record is FAILED, and payment:failed came once, before the throw reached the caller', async () => {
			const tag = 'send-parts-add-refused-alone';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			s.aliceRefusesAdds.next = 1;
			const part = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			s.aliceRefusesAdds.next = 0;
			// Read at once: nothing ran between the throw and here.
			const failedAtThrow = countOf(s.failed, h);
			refusedWith(part, 'ASSET_HTLC_NOT_ADMITTED', s.w.inChannel);
			expect(failedAtThrow, 'payment:failed before the throw').to.equal(1);
			await turns(50);
			expect(s.w.hosts.alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(countOf(s.failed, h), 'payment:failed once').to.equal(1);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([]);
			expect(storedMappings(s.w.hosts.alice, h)).to.deep.equal([]);
			expect(heldMappings(s.w.hosts.alice, h)).to.deep.equal([]);
			expect(
				s.w.hosts.alice.node.getAuxiliaryChannelInfo(s.w.inChannel)!.htlcs
			).to.deep.equal([]);
			expect(unitsOf(s.w.hosts.alice, s.w.inChannel)).to.equal(9000n);
		});
	});

	describe('a cancel, and an offered part at its expiry, with parts out', () => {
		it('a cancel fails the whole record once; no part joins it while parts are out; and the parts out, fulfilled, complete it', async () => {
			const tag = 'send-parts-cancel';
			const s = await openSendScene(world, tag);
			const invoice = heldPartsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }));
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n }));
			await carolHolds(s, h, 2);
			s.w.hosts.alice.node.failPayment(h);
			expect(s.w.hosts.alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(countOf(s.failed, h)).to.equal(1);
			const before = trace(s, h);
			refusedWith(
				sendAssetPart(s.w, invoice, { valueMsat: 1_000_000n }),
				'ASSET_PAYMENT_UNSUPPORTED',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
			expect(
				s.w.hosts.carol.node.settleHeldHtlc(h, invoice.preimage),
				'Carol settles the set'
			).to.equal(true);
			await alicePaid(s, h);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h)).to.equal(1);
			expect(countOf(s.failed, h)).to.equal(1);
		});

		it('an offered part reaching its expiry on an open channel fails the whole record once; no part joins it; and the parts out, fulfilled, complete it', async () => {
			const tag = 'send-parts-expiry';
			const s = await openSendScene(world, tag);
			const invoice = heldPartsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n }));
			await carolHolds(s, h, 2);
			const expiry = s.w.hosts.alice.node
				.getChannelManager()
				.getChannel(s.w.inChannel)!
				.getFullState()
				.htlcs.get(`offered-${first.htlcId}`)!.cltvExpiry;
			// Alice alone hears of a block at the first part's expiry.
			s.w.hosts.alice.node.handleNewBlock(expiry);
			await turns(20);
			expect(s.w.hosts.alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(countOf(s.failed, h)).to.equal(1);
			const before = trace(s, h);
			refusedWith(
				sendAssetPart(s.w, invoice, { valueMsat: 1_000_000n }),
				'ASSET_PAYMENT_UNSUPPORTED',
				s.w.inChannel
			);
			await turns(20);
			expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(before);
			expect(s.w.hosts.carol.node.settleHeldHtlc(h, invoice.preimage)).to.equal(
				true
			);
			await alicePaid(s, h);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h)).to.equal(1);
		});
	});

	describe('on a loopback pair, a part that ends inside its own add', () => {
		it('a part whose fulfil runs inside its own add leaves the record COMPLETED when the send returns, both parts listed and the record stored so, with payment:sent once', async () => {
			const tag = 'send-parts-loop-fulfil';
			const pair = await partsPair(tag, pairHosts);
			const made = pair.bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'loopback parts'
			});
			const invoice = {
				paymentHash: made.paymentHash,
				paymentSecret: made.paymentSecret,
				totalMsat: 5_000_000n
			};
			const h = invoice.paymentHash;
			const first = sendPairPart(pair, invoice, 3_000_000n);
			sentOk(first);
			expect(pair.alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.PENDING
			);
			const second = sendPairPart(pair, invoice, 2_000_000n);
			sentOk(second);
			// At once: Bob settled the set inside the add of the second part.
			expect(figures(pair.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(pair.alice.storage!.loadPayment(hex(h))?.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(recorded(pair.alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second)
			]);
			await turns(50);
			expect(figures(pair.alice.node, h)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(countOf(pair.sent, h)).to.equal(1);
			expect(countOf(pair.failed, h)).to.equal(0);
			expect(unitsOf(pair.alice, pair.channelId)).to.equal(4000n);
		});

		it('a part whose failure runs inside its own add leaves the record PENDING when the send returns, the part marked failed; a part sent again completes the set', async () => {
			const tag = 'send-parts-loop-fail';
			const pair = await partsPair(tag, pairHosts);
			const made = pair.bob.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'loopback parts'
			});
			const invoice = {
				paymentHash: made.paymentHash,
				paymentSecret: made.paymentSecret,
				totalMsat: 5_000_000n
			};
			const h = invoice.paymentHash;
			const first = sendPairPart(pair, invoice, 3_000_000n);
			sentOk(first);
			pair.bobRefuses.next = 1;
			const second = sendPairPart(pair, invoice, 2_000_000n);
			sentOk(second);
			// At once: Bob failed the part inside its add.
			expect(figures(pair.alice.node, h)).to.deep.equal({
				status: PaymentStatus.PENDING,
				amountMsat: CARRIER,
				auxiliaryValueMsat: 3_000_000n
			});
			expect(recorded(pair.alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second, true)
			]);
			expect(countOf(pair.failed, h)).to.equal(0);
			const again = sendPairPart(pair, invoice, 2_000_000n);
			sentOk(again);
			expect(figures(pair.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			await turns(50);
			expect(countOf(pair.sent, h)).to.equal(1);
			expect(countOf(pair.failed, h)).to.equal(0);
		});
	});

	describe('fulfils', () => {
		it("each fulfilled part's HTLC mapping is released, the later part's too", async () => {
			const tag = 'send-parts-mappings';
			const s = await openSendScene(world, tag, {
				world: { secondIn: 'asset' }
			});
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			const second = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				channelId: s.w.inChannel2
			});
			sentOk(second);
			await alicePaid(s, h);
			expect(heldMappings(s.w.hosts.alice, h)).to.deep.equal([]);
			expect(storedMappings(s.w.hosts.alice, h)).to.deep.equal([]);
		});

		it('a fulfil replayed after a restart for a part whose mapping is still there is handled: the mapping is released, the record keeps its figures and payment:sent does not come again', async () => {
			const tag = 'send-parts-replay';
			const s = await openSendScene(world, tag, {
				world: { secondIn: 'asset', aliceOnFile: true }
			});
			const snapshot = path.join(directory('send-parts-replay-'), 'at.sqlite');
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			// Alice's node stops as the second fulfil reaches it: a copy of her
			// database is taken, and nothing passes between her and Bob after it.
			const node = s.w.hosts.alice.node as unknown as {
				handleHtlcFulfilled: (
					channelId: Buffer,
					htlcId: bigint,
					preimage: Buffer,
					replay?: boolean
				) => boolean;
			};
			const handle = node.handleHtlcFulfilled.bind(node);
			let fulfils = 0;
			node.handleHtlcFulfilled = (
				channelId,
				htlcId,
				preimage,
				replay
			): boolean => {
				const ofThis = crypto
					.createHash('sha256')
					.update(preimage)
					.digest()
					.equals(h);
				if (ofThis && replay !== true && ++fulfils === 2) {
					(
						s.w.hosts.alice.storage as unknown as {
							db: { exec(sql: string): unknown };
						}
					).db.exec(`VACUUM INTO '${snapshot}'`);
					world.silence(s.w, 'in');
				}
				return handle(channelId, htlcId, preimage, replay);
			};
			sentOk(sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n }));
			sentOk(
				sendAssetPart(s.w, invoice, {
					valueMsat: 2_000_000n,
					channelId: s.w.inChannel2
				})
			);
			await rounds('the second fulfil reaches Alice', () => fulfils === 2, 60);
			await turns(50);
			await world.restartAlice(s.w, tag, {
				hooks: s.aliceHooks,
				reconnect: false,
				whileDown: () => restoreCopy(s, snapshot)
			});
			// The first fulfil completed the record before the stop.
			const sentBefore = countOf(s.sent, h);
			expect(sentBefore).to.equal(1);
			listenAlice(s);
			expect(s.w.hosts.alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(
				storedMappings(s.w.hosts.alice, h),
				"the later part's mapping is still there"
			).to.not.deep.equal([]);
			await world.reconnect(s.w, 'in');
			await rounds(
				"the later part's mapping is released",
				() => storedMappings(s.w.hosts.alice, h).length === 0,
				60
			);
			await turns(50);
			expect(heldMappings(s.w.hosts.alice, h)).to.deep.equal([]);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h), 'no second payment:sent').to.equal(sentBefore);
		});
	});

	describe('a restart', () => {
		it('two parts out when the node restarts both end through their mappings: the set settles and the record is COMPLETED once', async () => {
			const tag = 'send-parts-restart';
			const s = await openSendScene(world, tag, {
				world: { secondIn: 'asset', aliceOnFile: true }
			});
			const invoice = heldPartsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			const second = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				channelId: s.w.inChannel2
			});
			sentOk(second);
			await carolHolds(s, h, 2);
			await world.restartAlice(s.w, tag, { hooks: s.aliceHooks });
			listenAlice(s);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second)
			]);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.PENDING,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(s.w.hosts.carol.node.settleHeldHtlc(h, invoice.preimage)).to.equal(
				true
			);
			await alicePaid(s, h);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h)).to.equal(1);
			expect(endsFor(s, h)).to.deep.equal(
				[endOf('fulfilled', first), endOf('fulfilled', second)].sort()
			);
			expect(storedMappings(s.w.hosts.alice, h)).to.deep.equal([]);
		});

		it("a part's failure after a restart is read with the record's secrets, the set's first part's: a later part's failure cannot be decrypted, and the record stays PENDING while the first part is out", async () => {
			const tag = 'send-parts-restart-failure';
			const s = await openSendScene(world, tag, {
				world: { aliceOnFile: true }
			});
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			await carolCollects(s, h, 1);
			// The second part's add and commitment never reach Bob before the stop.
			world.silence(s.w, 'in');
			const second = sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n });
			sentOk(second);
			await turns(80);
			await world.restartAlice(s.w, tag, {
				hooks: s.aliceHooks,
				reconnect: false
			});
			listenAlice(s);
			s.bobRefuses.next = 1;
			await world.reconnect(s.w, 'in');
			await toldFailed(s, second, h);
			await turns(50);
			const record = s.w.hosts.alice.node.getPayment(h)!;
			expect(record.status).to.equal(PaymentStatus.PENDING);
			expect(record.failureReason).to.include(NOT_DECRYPTED);
			expect(record.failureCode).to.equal(undefined);
			expect(countOf(s.failed, h)).to.equal(0);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second, true)
			]);
		});

		it('at a restore, a part never sent leaves the record and the listing, and the record stays PENDING while another part of it is live; sent again under the same id, it completes the set', async () => {
			const tag = 'send-parts-never-sent';
			const s = await openSendScene(world, tag, {
				world: { aliceOnFile: true }
			});
			const snapshot = path.join(directory('send-parts-never-'), 'at.sqlite');
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			await carolCollects(s, h, 1);
			const stop = stopAtAdd(s, snapshot);
			const second = sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n });
			expect(
				stop.stops,
				`the node stopped at the add of the second part: ${String(
					second.error
				)}`
			).to.equal(1);
			await world.restartAlice(s.w, tag, {
				hooks: s.aliceHooks,
				reconnect: false,
				whileDown: () => restoreCopy(s, snapshot)
			});
			listenAlice(s);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([entryOf(first)]);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.PENDING,
				amountMsat: CARRIER,
				auxiliaryValueMsat: 3_000_000n
			});
			expect(storedMappings(s.w.hosts.alice, h)).to.deep.equal([keyOf(first)]);
			expect(
				endsFor(s, h).filter((end) => end.startsWith('never-sent'))
			).to.deep.equal([endOf('never-sent', second)]);
			expect(countOf(s.failed, h)).to.equal(0);
			await world.reconnect(s.w, 'in');
			const again = sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n });
			sentOk(again);
			expect(again.htlcId).to.equal(second.htlcId);
			await alicePaid(s, h);
			expect(figures(s.w.hosts.alice.node, h)).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
		});

		it('at a restore, a stored preimage of the hash keeps the record from FAILED when its only part never left; without the preimage it is FAILED', async () => {
			const tag = 'send-parts-never-sent-preimage';
			const s = await openSendScene(world, tag, {
				world: { aliceOnFile: true }
			});
			const snapshot = path.join(
				directory('send-parts-preimage-'),
				'at.sqlite'
			);
			const preimage = crypto.randomBytes(32);
			const h = crypto.createHash('sha256').update(preimage).digest();
			const invoice = {
				paymentHash: h,
				paymentSecret: crypto.randomBytes(32),
				totalMsat: 5_000_000n
			};
			const stop = stopAtAdd(s, snapshot);
			const part = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			expect(
				stop.stops,
				`the node stopped at the add of the part: ${String(part.error)}`
			).to.equal(1);
			await world.restartAlice(s.w, tag, {
				hooks: s.aliceHooks,
				reconnect: false,
				whileDown: () => restoreCopy(s, snapshot, preimage)
			});
			listenAlice(s);
			await turns(20);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([]);
			expect(s.w.hosts.alice.node.getPayment(h)?.status).to.not.equal(
				PaymentStatus.FAILED
			);
			expect(countOf(s.failed, h)).to.equal(0);
			// The same stop, restored without the preimage.
			await world.restartAlice(s.w, tag, {
				hooks: s.aliceHooks,
				reconnect: false,
				whileDown: () => restoreCopy(s, snapshot)
			});
			listenAlice(s);
			await turns(20);
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([]);
			expect(s.w.hosts.alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.FAILED
			);
		});
	});

	describe("the engine's own keys", () => {
		it("on a record of the new path, setPaymentMetadata neither sets nor clears the engine's keys, and writes the caller's own", async () => {
			const tag = 'send-parts-keys';
			const s = await openSendScene(world, tag);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			await carolCollects(s, h, 1);
			const before = {
				...s.w.hosts.alice.node.getPayment(h)!.metadata
			} as Record<string, string | undefined>;
			const junk: Record<string, string> = { label: 'mine' };
			for (const key of [...NEW_KEYS, ...OLD_KEYS]) junk[key] = '{}';
			s.w.hosts.alice.node.setPaymentMetadata(h, junk);
			const after = s.w.hosts.alice.node.getPayment(h)!.metadata!;
			const stored = s.w.hosts.alice.storage!.loadPayment(hex(h))!.metadata!;
			for (const key of [...NEW_KEYS, ...OLD_KEYS]) {
				expect(after[key], key).to.equal(before[key]);
				expect(stored[key], `${key}, stored`).to.equal(before[key]);
			}
			expect(after.label).to.equal('mine');
			expect(recorded(s.w.hosts.alice.node, h)).to.deep.equal([entryOf(first)]);
		});

		it("on any other record, setPaymentMetadata cannot add the engine's new keys: an ordinary payment's, and the node's own invoice's", async () => {
			const tag = 'send-parts-keys-other';
			const s = await openSendScene(world, tag, {
				world: { secondIn: 'ordinary' }
			});
			const ordinary = partsInvoice(s.w, tag, 1_000_000n);
			sendPart(s.w, ordinary, 1_000_000n);
			await alicePaid(s, ordinary.paymentHash);
			const own = s.w.hosts.alice.node.createInvoice({
				amountMsat: 1_000_000n,
				description: 'her own'
			});
			for (const h of [ordinary.paymentHash, own.paymentHash]) {
				const labels: Record<string, string> = { label: 'mine' };
				for (const key of NEW_KEYS) labels[key] = '{}';
				s.w.hosts.alice.node.setPaymentMetadata(h, labels);
				const metadata = s.w.hosts.alice.node.getPayment(h)!.metadata!;
				expect(metadata.label).to.equal('mine');
				for (const key of NEW_KEYS) {
					expect(metadata[key], key).to.equal(undefined);
					expect(
						s.w.hosts.alice.storage!.loadPayment(hex(h))!.metadata?.[key],
						`${key}, stored`
					).to.equal(undefined);
				}
			}
		});
	});

	describe("the gate's request", () => {
		it('in the new path carries the total each part declares and the id its HTLC takes, which the listing gives too', async () => {
			const tag = 'send-parts-gate';
			const s = await openSendScene(world, tag, {
				world: { secondIn: 'asset' }
			});
			const asked: GateRequest[] = [];
			s.w.hosts.alice.node.setAuxiliaryPaymentGate((request) => {
				asked.push({ ...request });
				return undefined;
			});
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			const second = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				channelId: s.w.inChannel2
			});
			sentOk(second);
			expect(
				asked.map((request) => ({
					paymentHash: hex(request.paymentHash),
					channelId: hex(request.channelId),
					amountMsat: request.amountMsat,
					wireAmountMsat: request.wireAmountMsat,
					routeAmountMsat: request.routeAmountMsat,
					totalMsat: request.totalMsat,
					htlcId: request.htlcId
				}))
			).to.deep.equal(
				[first, second].map((part) => ({
					paymentHash: hex(h),
					channelId: hex(part.channelId),
					amountMsat: part.valueMsat,
					wireAmountMsat: CARRIER,
					routeAmountMsat: part.routeAmountMsat,
					totalMsat: 5_000_000n,
					htlcId: part.htlcId
				}))
			);
			expect(
				recorded(s.w.hosts.alice.node, h).map((entry) => entry.htlcId)
			).to.deep.equal([first.htlcId, second.htlcId]);
		});
	});

	for (const [name, optIn, enabled] of [
		['without the opt-in', false, true],
		['with the switch off', true, false]
	] as const) {
		describe(`${name}, everything is as before`, () => {
			withAssetPartsSent(enabled);

			it('a part is refused with the typed error and its sentence, and nothing is recorded or sent', async () => {
				const tag = `send-parts-before-refused-${optIn}`;
				expect(assetPartsSentSwitch()?.enabled ?? false).to.equal(
					enabled && assetPartsSentSwitch() !== undefined
				);
				const s = await openSendScene(world, tag, { optIn });
				const invoice = partsInvoice(s.w, tag, 5_000_000n);
				const h = invoice.paymentHash;
				const before = trace(s, h);
				const part = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
				refusedWith(part, 'ASSET_PAYMENT_UNSUPPORTED', s.w.inChannel);
				expect((part.error as Error).message).to.equal(
					`An asset payment is made by one HTLC and cannot be a part of a multi-part payment (channel ${hex(
						s.w.inChannel
					)})`
				);
				await turns(20);
				expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(
					before
				);
			});

			it("every attempt of an asset payment names its record's one channel (ASSET_PAYMENT_ROUTE_REQUIRED)", async () => {
				const tag = `send-parts-before-pin-${optIn}`;
				const s = await openSendScene(world, tag, {
					optIn,
					world: { secondIn: 'asset' }
				});
				const invoice = partsInvoice(s.w, tag, 2_000_000n);
				const h = invoice.paymentHash;
				s.bobRefuses.next = 1;
				sentOk(
					sendAssetPart(s.w, invoice, {
						valueMsat: 2_000_000n,
						totalMsat: null
					})
				);
				await rounds(
					'the first attempt fails',
					() =>
						s.w.hosts.alice.node.getPayment(h)?.status === PaymentStatus.FAILED,
					60
				);
				await turns(50);
				const before = trace(s, h);
				refusedWith(
					sendAssetPart(s.w, invoice, {
						valueMsat: 2_000_000n,
						totalMsat: null,
						channelId: s.w.inChannel2
					}),
					'ASSET_PAYMENT_ROUTE_REQUIRED',
					s.w.inChannel
				);
				await turns(20);
				expect(trace(s, h), 'nothing was recorded or sent').to.deep.equal(
					before
				);
			});

			it('an asset payment of one HTLC is recorded as before, byte for byte: the gate asked what it always was, the record and its keys, the listing, and a second attempt that replaces the record', async () => {
				const tag = `send-parts-before-bytes-${optIn}`;
				const s = await openSendScene(world, tag, { optIn });
				const asked: GateRequest[] = [];
				s.w.hosts.alice.node.setAuxiliaryPaymentGate((request) => {
					asked.push({ ...request });
					return undefined;
				});
				const invoice = partsInvoice(s.w, tag, 2_000_000n);
				const h = invoice.paymentHash;
				s.bobRefuses.next = 1;
				sentOk(
					sendAssetPart(s.w, invoice, {
						valueMsat: 2_000_000n,
						totalMsat: null
					})
				);
				await rounds(
					'the first attempt fails',
					() =>
						s.w.hosts.alice.node.getPayment(h)?.status === PaymentStatus.FAILED,
					60
				);
				await turns(50);
				expect(
					s.w.hosts.alice.node.getPayment(h)?.failureCode,
					"the first attempt's failure"
				).to.equal(TEMPORARY_CHANNEL_FAILURE);
				const retry = sendAssetPart(s.w, invoice, {
					valueMsat: 2_000_000n,
					totalMsat: null,
					units: partUnits(2_000_000n) + 1n
				});
				sentOk(retry);
				await alicePaid(s, h);
				expect(
					asked.map((request) => Object.keys(request).sort()),
					"the gate's request has the keys it always had"
				).to.deep.equal(
					[0, 1].map(() => [
						'amountMsat',
						'channelId',
						'paymentHash',
						'routeAmountMsat',
						'wireAmountMsat'
					])
				);
				const record = s.w.hosts.alice.node.getPayment(h)!;
				expect(Object.keys(record.metadata ?? {}).sort()).to.deep.equal([
					'_auxiliaryChannelId',
					'_auxiliaryPartAmounts',
					'_auxiliaryWireAmountMsat'
				]);
				expect(record.metadata!._auxiliaryChannelId).to.equal(
					hex(s.w.inChannel)
				);
				expect(record.metadata!._auxiliaryWireAmountMsat).to.equal(
					CARRIER.toString()
				);
				expect({
					status: record.status,
					amountMsat: record.amountMsat,
					auxiliary: record.auxiliary,
					routeAmountMsat: record.route?.hops[0].amountToForwardMsat,
					failureCode: record.failureCode
				}).to.deep.equal({
					status: PaymentStatus.COMPLETED,
					amountMsat: CARRIER,
					auxiliary: true,
					routeAmountMsat: retry.routeAmountMsat,
					failureCode: undefined
				});
				for (const entry of s.w.hosts.alice.node.getAuxiliaryPaymentHtlcs(h)) {
					expect(Object.keys(entry).sort()).to.deep.equal([
						'amountMsat',
						'channelId',
						'htlcId'
					]);
				}
				expect(
					s.w.hosts.alice.storage!.loadPayment(hex(h))!.metadata
				).to.deep.equal(record.metadata);
			});
		});
	}
});
