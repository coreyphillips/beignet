/**
 * Issue #2098, step 10: an asset invoice, made by
 * `createInvoice({ assetInvoice })` on a node with asset channels. It
 * carries only the routing hints its caller gives (the hops of the edge node
 * that turns a payer's bitcoin into units for this node), and it offers
 * basic_mpp only where its parts can be collected: the node collects asset
 * parts, the invoice is no hold invoice, every hint ends at one peer, that
 * peer's asset channels with the node can hold two HTLCs toward it at once,
 * and the field does not say `inParts: false`. A field the node cannot honour
 * is refused with an AuxiliaryInvoiceError before anything is kept. Without
 * the field, createInvoice makes the invoice it makes for any caller.
 *
 * Most cases run on loopback: Bob is the payee, a wallet with an asset
 * channel to Alice, the edge node his hints name, and an ordinary channel to
 * her that can receive. The cases paid end to end run on the chain world of
 * auxiliary-forward-world.ts, where Carol is the payee and Bob the edge node.
 * Invoices are read by decoding them, never by their strings, which carry a
 * timestamp.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as lightningChannel from '../../src/lightning/channel';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { ChannelState } from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature } from '../../src/lightning/features/flags';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import type { IRoutingHintHop } from '../../src/lightning/invoice/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	LightningErrorCode,
	PaymentStatus,
	type ICreateInvoiceOptions,
	type INodeConfig
} from '../../src/lightning/node/types';
import {
	constructOnionPacket,
	encodeOnionPacket
} from '../../src/lightning/onion/construct';
import {
	aliasOf,
	forwardChainWorld,
	type IPartsInvoice
} from './helpers/auxiliary-forward-world';
import {
	QUOTE_RECORD,
	openPartsScene,
	type IPartsScene
} from './helpers/auxiliary-forward-scene';
import {
	assetInvoiceOptions,
	assetRefusal,
	featureBitsOf,
	hintView,
	hintsOf,
	refusalOf,
	type IRefusal
} from './helpers/auxiliary-invoice';
import {
	RECEIVE_IN_PARTS,
	assetHost,
	connectHosts,
	fixRandomness,
	openAssetChannel,
	plainHost,
	restoreRandomness,
	turns,
	withAssetForwards,
	withAssetOpens,
	withAssetPartsReceived,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { amountRecord, hash } from './helpers/auxiliary-pair';
import {
	alicePaid,
	asksFor,
	carolsRecord,
	collected,
	heldOn,
	hex,
	sha256,
	unitsOf,
	type Log
} from './helpers/auxiliary-parts-checks';
import { createNode, openReadyChannel } from './helpers/loopback-nodes';

/** The feature bits of an invoice without basic_mpp: TLV onion and payment secret, compulsory. */
const BITS = [Feature.TLV_ONION, Feature.PAYMENT_SECRET];
/** The same with basic_mpp, optional (bit 17). */
const BITS_MPP = [...BITS, Feature.BASIC_MPP + 1];

/** The short channel ids Alice knows her asset channels to Bob by, as a quote of hers would name them. */
const EDGE_SCID = Buffer.from('000a2e0000210001', 'hex');
const EDGE_SCID_2 = Buffer.from('000a2e0000220001', 'hex');
/** A node Bob has no channel with. */
const STRANGER = getPublicKey(hash('a node the payee has no channel with'));
const STRANGER_2 = getPublicKey(
	hash('another node the payee has no channel with')
);

const INVOICE: ICreateInvoiceOptions = {
	amountMsat: 5_000_000n,
	description: 'an asset invoice'
};

const idOf = (host: IAssetHost): Buffer =>
	Buffer.from(host.node.getNodeId(), 'hex');

const hop = (
	pubkey: Buffer,
	shortChannelId: Buffer,
	policy: Partial<IRoutingHintHop> = {}
): IRoutingHintHop => ({
	pubkey,
	shortChannelId,
	feeBaseMsat: 1000,
	feeProportionalMillionths: 1,
	cltvExpiryDelta: 40,
	...policy
});

/** A hint of one hop: `edge` forwards to the payee over the channel `scid` names. */
const edgeHint = (edge: IAssetHost, scid = EDGE_SCID): IRoutingHintHop[] => [
	hop(idOf(edge), scid)
];

/** A hint of two hops that ends at `edge`. */
const viaHint = (edge: IAssetHost, scid = EDGE_SCID_2): IRoutingHintHop[] => [
	hop(STRANGER, Buffer.from('000a2e0000230001', 'hex')),
	hop(idOf(edge), scid)
];

/** The hints the node builds from its own channels, as any invoice of it carries them. */
const ownHints = (host: IAssetHost): IRoutingHintHop[][] =>
	(
		host.node as unknown as {
			getPrivateChannelRoutingHints(): IRoutingHintHop[][];
		}
	).getPrivateChannelRoutingHints();

/** An asset invoice of `host` with these options and this field. */
const assetInvoice = (
	host: IAssetHost,
	options: Partial<ICreateInvoiceOptions>,
	field: unknown = {}
): ReturnType<LightningNode['createInvoice']> =>
	host.node.createInvoice(
		assetInvoiceOptions({ ...INVOICE, ...options }, field)
	);

/** What the node keeps for its invoices, in memory and in its storage. */
interface IKept {
	invoices: string[];
	payments: string[];
	secrets: string[];
	preimages: string[];
	held: string[];
	rows?: {
		invoices: string[];
		payments: string[];
		preimages: string[];
		secrets: string[];
	};
}

function keptBy(host: IAssetHost): IKept {
	const node = host.node as unknown as {
		payments: Map<string, unknown>;
		paymentSecrets: Map<string, Buffer>;
		preimages: Map<string, Buffer>;
		heldInvoiceHashes: Set<string>;
	};
	const sorted = (values: Iterable<string>): string[] => [...values].sort();
	return {
		invoices: sorted(
			host.node.listInvoices().map((invoice) => invoice.paymentHash)
		),
		payments: sorted(node.payments.keys()),
		secrets: sorted(node.paymentSecrets.keys()),
		preimages: sorted(node.preimages.keys()),
		held: sorted(node.heldInvoiceHashes),
		...(host.storage
			? {
					rows: {
						invoices: sorted(
							host.storage.loadAllInvoices().map((row) => row.paymentHashHex)
						),
						payments: sorted(
							host.storage.loadAllPayments().map((row) => row.paymentHash)
						),
						preimages: sorted(
							host.storage.loadAllPreimages().map((row) => row.paymentHash)
						),
						secrets: sorted(
							host.storage
								.loadAllPaymentSecrets()
								.map((row) => row.paymentHashHex)
						)
					}
			  }
			: {})
	};
}

/** The ordinary invoice a refused call is followed by, and what a node draws for it alone. */
const FOLLOWING: ICreateInvoiceOptions = {
	amountMsat: 1_000n,
	description: 'an ordinary invoice'
};

/** The payment hash and secret a fresh node gives FOLLOWING, the randomness fixed by `label`. */
function drawnAlone(label: string): string[] {
	const twin = createNode('asset-invoice-twin', 9);
	try {
		fixRandomness(label);
		try {
			const made = twin.createInvoice(FOLLOWING);
			return [hex(made.paymentHash), hex(made.paymentSecret)];
		} finally {
			restoreRandomness();
		}
	} finally {
		twin.destroy();
	}
}

/**
 * `options` are refused as `expected`, with nothing kept: no invoice or
 * payment record, no secret, preimage or hold mark, no storage row, and no
 * random bytes drawn, so that the ordinary invoice made right after, with
 * the randomness fixed, has the payment hash and secret a node gives it
 * alone.
 */
function expectRefused(
	host: IAssetHost,
	options: ICreateInvoiceOptions,
	expected: IRefusal,
	label: string
): void {
	const before = keptBy(host);
	let refusal: ReturnType<typeof refusalOf>;
	let after: IKept;
	let following: ReturnType<LightningNode['createInvoice']>;
	fixRandomness(label);
	try {
		refusal = refusalOf(() => host.node.createInvoice(options));
		after = keptBy(host);
		following = host.node.createInvoice(FOLLOWING);
	} finally {
		restoreRandomness();
	}
	expect(refusal, label).to.deep.equal(expected);
	expect(after, `${label}: nothing is kept`).to.deep.equal(before);
	expect(
		[hex(following.paymentHash), hex(following.paymentSecret)],
		`${label}: no random bytes are drawn`
	).to.deep.equal(drawnAlone(label));
}

/** A record with the keys that hold nothing left out, as storage gives it back. */
const plain = (record: object): Record<string, unknown> =>
	Object.fromEntries(
		Object.entries(record).filter(([, value]) => value !== undefined)
	);

interface IPayee {
	/** The edge node Bob's hints name: his peer over an asset channel. */
	alice: IAssetHost;
	/** The payee, whose invoices these are. */
	bob: IAssetHost;
	assetId: Buffer;
	/** Bob's ordinary channel with Alice, which can receive. */
	ordinaryId?: Buffer;
	/** Bob's structured logs. */
	logs: Log[];
}

interface IPayeeOptions {
	/** Bob's host opts in to being paid in parts (receiveInParts: true), unless false. */
	optIn?: boolean;
	/** Bob's other hooks. */
	hooks?: Partial<IAuxiliaryChannelConfig>;
	/** More of Bob's node configuration. */
	node?: Partial<INodeConfig>;
	/** Bob has an ordinary channel with Alice too, unless false. */
	ordinary?: boolean;
	/** Bob runs from this database file, in place of memory. */
	sqlitePath?: string;
}

/** Bob's hooks: a part is worth its units at 1000 msat, and he opts in unless said. */
const bobHooks = (
	options: IPayeeOptions
): Partial<IAuxiliaryChannelConfig> => ({
	valueIncomingHtlc: (context) =>
		context.auxiliaryAmount === undefined
			? undefined
			: context.auxiliaryAmount * 1000n,
	...(options.optIn === false ? {} : RECEIVE_IN_PARTS),
	...options.hooks
});

/**
 * Alice puts an asset part on her channel to Bob by hand: `units` in the
 * records, a 354 sat carrier, and an onion of one hop that declares
 * `totalMsat`.
 */
function assetPart(
	payer: IAssetHost,
	payeeHost: IAssetHost,
	channelId: Buffer,
	invoice: { paymentHash: Buffer; paymentSecret: Buffer },
	part: { units: bigint; totalMsat: bigint }
): void {
	const packet = constructOnionPacket(
		hash(`asset invoice part ${hex(channelId)} ${part.units}`),
		[
			{
				pubkey: idOf(payeeHost),
				payload: {
					amountToForwardMsat: part.units * 1000n,
					outgoingCltvValue: 40,
					paymentSecret: invoice.paymentSecret,
					totalMsat: part.totalMsat
				}
			}
		],
		invoice.paymentHash
	);
	const added = payer.node
		.getChannelManager()
		.addHtlc(
			channelId,
			354_000n,
			invoice.paymentHash,
			40,
			encodeOnionPacket(packet),
			undefined,
			undefined,
			{ customRecords: amountRecord(part.units) }
		);
	expect(added.ok, added.error).to.equal(true);
}

describe('an asset invoice (issue #2098, step 10)', function () {
	this.timeout(120_000);
	withAssetOpens();
	withAssetPartsReceived();

	const hosts: IAssetHost[] = [];
	const files: string[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			try {
				host.node.destroy();
			} catch {
				// destroyed by the test already
			}
			try {
				host.storage?.close();
			} catch {
				// closed by the test already
			}
		}
		for (const file of files.splice(0)) fs.rmSync(file, { force: true });
	});

	/** Bob and Alice on loopback: an asset channel (Alice 9000 units, Bob 1000) and an ordinary one. */
	async function payee(
		tag: string,
		options: IPayeeOptions = {}
	): Promise<IPayee> {
		const alice = assetHost(tag, 1, {}, { sqlite: true });
		const bob = assetHost(tag, 2, bobHooks(options), {
			...(options.sqlitePath
				? { sqlitePath: options.sqlitePath }
				: { sqlite: true }),
			...(options.node ? { extra: options.node } : {})
		});
		hosts.push(alice, bob);
		const logs: Log[] = [];
		bob.node.on('log', (log: Log) => {
			logs.push(log);
		});
		connectHosts(alice, bob);
		const assetId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		const ordinaryId =
			options.ordinary === false
				? undefined
				: openReadyChannel(alice.node, bob.node);
		await turns(20);
		return { alice, bob, assetId, ordinaryId, logs };
	}

	/**
	 * Another peer of Bob's, `seed` of `tag`: with an asset channel to him,
	 * one that is not confirmed yet, or an ordinary channel.
	 */
	async function peerOf(
		s: IPayee,
		tag: string,
		seed: number,
		kind: 'asset' | 'unconfirmed' | 'ordinary'
	): Promise<{ host: IAssetHost; channelId: Buffer }> {
		const host = assetHost(tag, seed, {}, { sqlite: true });
		hosts.push(host);
		connectHosts(host, s.bob);
		if (kind === 'ordinary') {
			const channelId = openReadyChannel(host.node, s.bob.node);
			await turns(20);
			return { host, channelId };
		}
		const channelId = await openAssetChannel(host, s.bob, {
			tag: `${tag} peer ${seed}`,
			openerUnits: 9000n,
			acceptorUnits: 1000n,
			...(kind === 'unconfirmed'
				? { beforeConfirmation: (): boolean => false }
				: {})
		});
		return { host, channelId };
	}

	/** The state Bob has a channel in. */
	const stateOf = (s: IPayee, channelId: Buffer): ChannelState | undefined =>
		s.bob.node.getChannelManager().getChannel(channelId)?.getState();

	describe('what it carries', () => {
		it('carries exactly the hints its caller gives, in order, and none for the ordinary channel of its node that can receive, with nothing reported missing', async () => {
			const s = await payee('asset-invoice-hints');
			expect(
				ownHints(s.bob).length,
				'the ordinary channel gives a hint'
			).to.equal(1);
			const given = [edgeHint(s.alice), viaHint(s.alice)];
			const made = assetInvoice(s.bob, { extraRoutingHints: given });
			expect(hintsOf(made.bolt11)).to.deep.equal(given.map(hintView));
			expect(
				s.bob.errors.filter((error) => error.startsWith('NO_ROUTING_HINTS'))
			).to.deep.equal([]);
		});

		for (const field of [{}, { inParts: true }]) {
			it(`offers basic_mpp with ${JSON.stringify(
				field
			)} where every condition holds, and carries only its caller's hint`, async () => {
				const s = await payee(`asset-invoice-mpp-${Object.keys(field).length}`);
				const made = assetInvoice(
					s.bob,
					{ extraRoutingHints: [edgeHint(s.alice)] },
					field
				);
				expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS_MPP);
				expect(hintsOf(made.bolt11)).to.deep.equal([
					hintView(edgeHint(s.alice))
				]);
			});
		}

		describe('with the build switch for collecting asset parts off', () => {
			withAssetPartsReceived(false);
			it('offers no basic_mpp', async () => {
				const s = await payee('asset-invoice-switch-off');
				const made = assetInvoice(s.bob, {
					extraRoutingHints: [edgeHint(s.alice)]
				});
				expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS);
			});
		});

		for (const [label, hooks] of [
			['leaves receiveInParts out', {}],
			[
				'sets receiveInParts to false',
				{ receiveInParts: false } as unknown as Partial<IAuxiliaryChannelConfig>
			]
		] as const) {
			it(`offers no basic_mpp when the host ${label}`, async () => {
				const s = await payee(
					`asset-invoice-no-opt-in-${label.split(' ')[0]}`,
					{ optIn: false, hooks }
				);
				const made = assetInvoice(s.bob, {
					extraRoutingHints: [edgeHint(s.alice)]
				});
				expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS);
				expect(hintsOf(made.bolt11)).to.deep.equal([
					hintView(edgeHint(s.alice))
				]);
			});
		}

		it("offers no basic_mpp when the node's own features lack it", async () => {
			const features = LightningNode.defaultFeatures();
			features.clearBit(Feature.BASIC_MPP);
			features.clearBit(Feature.BASIC_MPP + 1);
			const s = await payee('asset-invoice-no-mpp-feature', {
				node: { localFeatures: features }
			});
			expect(
				s.bob.node.getLocalFeatures().hasFeature(Feature.BASIC_MPP)
			).to.equal(false);
			const made = assetInvoice(s.bob, {
				extraRoutingHints: [edgeHint(s.alice)]
			});
			expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS);
		});

		it('offers no basic_mpp on a hold invoice, and a hold asset invoice with an external payment hash uses that hash', async () => {
			const s = await payee('asset-invoice-hold');
			const held = assetInvoice(s.bob, {
				hold: true,
				extraRoutingHints: [edgeHint(s.alice)]
			});
			expect(featureBitsOf(held.bolt11)).to.deep.equal(BITS);

			const paymentHash = sha256(hash('asset-invoice-hold preimage'));
			const external = assetInvoice(s.bob, {
				hold: true,
				paymentHash,
				extraRoutingHints: [edgeHint(s.alice)]
			});
			expect(featureBitsOf(external.bolt11)).to.deep.equal(BITS);
			expect(hex(external.paymentHash)).to.equal(hex(paymentHash));
			expect(hex(decodeInvoice(external.bolt11).paymentHash)).to.equal(
				hex(paymentHash)
			);
			expect(s.bob.node.getInvoice(hex(paymentHash))?.hold).to.equal(true);
		});

		it('offers no basic_mpp when its hints end at two peers, and offers it when two hints end at one', async () => {
			const tag = 'asset-invoice-two-peers';
			const s = await payee(tag);
			const dave = await peerOf(s, tag, 3, 'asset');
			const twoPeers = assetInvoice(s.bob, {
				extraRoutingHints: [edgeHint(s.alice), edgeHint(dave.host)]
			});
			expect(featureBitsOf(twoPeers.bolt11)).to.deep.equal(BITS);
			expect(hintsOf(twoPeers.bolt11)).to.deep.equal([
				hintView(edgeHint(s.alice)),
				hintView(edgeHint(dave.host))
			]);

			const onePeer = assetInvoice(s.bob, {
				extraRoutingHints: [edgeHint(s.alice), viaHint(s.alice)]
			});
			expect(featureBitsOf(onePeer.bolt11)).to.deep.equal(BITS_MPP);
		});

		it("offers no basic_mpp while the peer's asset channels that take HTLCs can hold only one toward the node, and offers it once a second one sums to two", async () => {
			const tag = 'asset-invoice-one-htlc';
			const s = await payee(tag, { hooks: { maxHtlcs: 1 } });
			const maxAccepted = (channelId: Buffer): number | undefined =>
				s.bob.node.getChannelManager().getChannel(channelId)?.getFullState()
					.localConfig.maxAcceptedHtlcs;
			expect(maxAccepted(s.assetId)).to.equal(1);
			const hints = { extraRoutingHints: [edgeHint(s.alice)] };
			expect(featureBitsOf(assetInvoice(s.bob, hints).bolt11)).to.deep.equal(
				BITS
			);

			// A second asset channel of Alice's, not yet confirmed, takes no HTLC.
			const second = await openAssetChannel(s.alice, s.bob, {
				tag: `${tag} second`,
				openerUnits: 9000n,
				acceptorUnits: 1000n,
				beforeConfirmation: () => false
			});
			expect(maxAccepted(second)).to.equal(1);
			expect(stateOf(s, second)).to.not.equal(ChannelState.NORMAL);
			expect(featureBitsOf(assetInvoice(s.bob, hints).bolt11)).to.deep.equal(
				BITS
			);

			s.alice.node.handleFundingConfirmed(second);
			s.bob.node.handleFundingConfirmed(second);
			await turns(20);
			expect(stateOf(s, second)).to.equal(ChannelState.NORMAL);
			expect(featureBitsOf(assetInvoice(s.bob, hints).bolt11)).to.deep.equal(
				BITS_MPP
			);
		});

		it("counts the asset channel of a peer that is away, awaiting a reestablish: the invoice is made with basic_mpp and only its caller's hint", async () => {
			const s = await payee('asset-invoice-peer-away');
			s.alice.node
				.getChannelManager()
				.handlePeerDisconnected(s.bob.node.getNodeId());
			s.bob.node
				.getChannelManager()
				.handlePeerDisconnected(s.alice.node.getNodeId());
			await turns(20);
			expect(stateOf(s, s.assetId)).to.equal(ChannelState.AWAITING_REESTABLISH);
			expect(
				ownHints(s.bob).length,
				'the ordinary channel still gives a hint'
			).to.equal(1);
			const made = assetInvoice(s.bob, {
				extraRoutingHints: [edgeHint(s.alice)]
			});
			expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS_MPP);
			expect(hintsOf(made.bolt11)).to.deep.equal([hintView(edgeHint(s.alice))]);
		});

		it('offers no basic_mpp when the field says inParts: false', async () => {
			const s = await payee('asset-invoice-in-parts-false');
			const made = assetInvoice(
				s.bob,
				{ extraRoutingHints: [edgeHint(s.alice)] },
				{ inParts: false }
			);
			expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS);
			expect(hintsOf(made.bolt11)).to.deep.equal([hintView(edgeHint(s.alice))]);
		});

		it('sets TLV onion and payment secret compulsory, as any invoice does, and payment metadata with its m field when given', async () => {
			const s = await payee('asset-invoice-metadata');
			const metadata = Buffer.from('what the payee keeps of this invoice');
			const hints = { extraRoutingHints: [edgeHint(s.alice)] };
			const made = assetInvoice(
				s.bob,
				{ ...hints, paymentMetadata: metadata },
				{ inParts: false }
			);
			const decoded = decodeInvoice(made.bolt11);
			expect(featureBitsOf(made.bolt11)).to.deep.equal([
				...BITS,
				Feature.PAYMENT_METADATA + 1
			]);
			expect(decoded.featureBits!.isCompulsory(Feature.TLV_ONION)).to.equal(
				true
			);
			expect(
				decoded.featureBits!.isCompulsory(Feature.PAYMENT_SECRET)
			).to.equal(true);
			expect(hex(decoded.metadata!)).to.equal(hex(metadata));
			expect(
				s.bob.node.getInvoice(hex(made.paymentHash))!.paymentMetadata
			).to.equal(hex(metadata));

			const inParts = assetInvoice(s.bob, {
				...hints,
				paymentMetadata: metadata
			});
			expect(featureBitsOf(inParts.bolt11)).to.deep.equal([
				...BITS_MPP,
				Feature.PAYMENT_METADATA + 1
			]);
			expect(hex(decodeInvoice(inParts.bolt11).metadata!)).to.equal(
				hex(metadata)
			);
		});

		it('takes a hint of twelve hops, and fees and deltas at their bounds', async () => {
			const s = await payee('asset-invoice-bounds');
			const long = [
				...Array.from({ length: 11 }, (_, i) =>
					hop(
						getPublicKey(hash(`a hop of a long hint ${i}`)),
						Buffer.from(`000a2e00003${i.toString(16)}0001`.slice(0, 16), 'hex')
					)
				),
				hop(idOf(s.alice), EDGE_SCID)
			];
			const highest = [
				hop(idOf(s.alice), EDGE_SCID_2, {
					feeBaseMsat: 4294967295,
					feeProportionalMillionths: 4294967295,
					cltvExpiryDelta: 65535
				})
			];
			const lowest = [
				hop(idOf(s.alice), EDGE_SCID_2, {
					feeBaseMsat: 0,
					feeProportionalMillionths: 0,
					cltvExpiryDelta: 0
				})
			];
			for (const hint of [long, highest, lowest]) {
				const made = assetInvoice(s.bob, { extraRoutingHints: [hint] });
				expect(hintsOf(made.bolt11)).to.deep.equal([hintView(hint)]);
			}
		});
	});

	describe('its record', () => {
		it('is the record any invoice writes: the same keys, its payment record the same, and no auxiliary mark', async () => {
			const s = await payee('asset-invoice-record');
			const made = assetInvoice(s.bob, {
				extraRoutingHints: [edgeHint(s.alice)]
			});
			const ordinary = s.bob.node.createInvoice({
				...INVOICE,
				extraRoutingHints: [edgeHint(s.alice)]
			});
			const record = s.bob.node.getInvoice(hex(made.paymentHash))!;
			const ordinaryRecord = s.bob.node.getInvoice(hex(ordinary.paymentHash))!;
			expect(Object.keys(record).sort()).to.deep.equal(
				Object.keys(ordinaryRecord).sort()
			);
			expect(record).to.not.have.property('auxiliary');
			expect(
				Object.keys(s.bob.node.getPayment(made.paymentHash)!).sort()
			).to.deep.equal(
				Object.keys(s.bob.node.getPayment(ordinary.paymentHash)!).sort()
			);
			expect(s.bob.node.getPayment(made.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			// The payment records agree on every field but their hash, preimage
			// and creation time, which are each invoice's own.
			const fields = (info: object): Record<string, unknown> => {
				const {
					paymentHash: _hash,
					preimage: _preimage,
					createdAt: _createdAt,
					...rest
				} = info as Record<string, unknown>;
				return rest;
			};
			expect(fields(s.bob.node.getPayment(made.paymentHash)!)).to.deep.equal(
				fields(s.bob.node.getPayment(ordinary.paymentHash)!)
			);
			// What sets the two apart is in the invoice alone.
			expect(hintsOf(record.bolt11)).to.deep.equal([
				hintView(edgeHint(s.alice))
			]);
			expect(hintsOf(ordinaryRecord.bolt11)).to.deep.equal([
				...ownHints(s.bob).map(hintView),
				hintView(edgeHint(s.alice))
			]);
		});

		it('is read back after a restart over SQLite: the same record and the same bolt11', async () => {
			const tag = 'asset-invoice-restart';
			const file = path.join(
				os.tmpdir(),
				`${tag}-${process.pid}-${crypto.randomBytes(4).toString('hex')}.sqlite`
			);
			files.push(file, `${file}-wal`, `${file}-shm`);
			const s = await payee(tag, { sqlitePath: file });
			const made = assetInvoice(
				s.bob,
				{ extraRoutingHints: [edgeHint(s.alice)] },
				{ inParts: false }
			);
			const record = plain(s.bob.node.getInvoice(hex(made.paymentHash))!);
			s.bob.node.destroy();
			s.bob.storage!.close();

			const again = assetHost(tag, 2, bobHooks({}), { sqlitePath: file });
			hosts.push(again);
			const read = again.node.getInvoice(hex(made.paymentHash));
			expect(plain(read!)).to.deep.equal(record);
			expect(read!.bolt11).to.equal(record.bolt11);
			expect(hintsOf(read!.bolt11)).to.deep.equal([
				hintView(edgeHint(s.alice))
			]);
			expect(featureBitsOf(read!.bolt11)).to.deep.equal(BITS);
			expect(again.node.getPayment(made.paymentHash)?.status).to.equal(
				PaymentStatus.PENDING
			);
		});
	});

	describe('refused before anything is kept', () => {
		const INVALID = 'ASSET_INVOICE_INVALID';
		const UNSUPPORTED = 'ASSET_INVOICE_UNSUPPORTED';

		it('a field that is neither an object nor off, or whose inParts is no boolean', async () => {
			const s = await payee('asset-invoice-bad-field');
			const hints = { extraRoutingHints: [edgeHint(s.alice)] };
			for (const field of [
				true,
				1,
				'yes',
				[],
				{ inParts: 'no' },
				{ inParts: 1 }
			]) {
				expectRefused(
					s.bob,
					assetInvoiceOptions({ ...INVOICE, ...hints }, field),
					assetRefusal(INVALID, 'assetInvoice'),
					`field ${JSON.stringify(field)}`
				);
			}
		});

		it('on a node without asset channels, an asset invoice; a malformed field there is refused as malformed first', () => {
			const carol = plainHost('asset-invoice-plain', 1, { sqlite: true });
			hosts.push(carol);
			const hint = [hop(STRANGER, EDGE_SCID)];
			expectRefused(
				carol,
				assetInvoiceOptions({ ...INVOICE, extraRoutingHints: [hint] }),
				assetRefusal(UNSUPPORTED, 'assetInvoice'),
				'plain node'
			);
			expectRefused(
				carol,
				assetInvoiceOptions(
					{ ...INVOICE, extraRoutingHints: [hint], useBlindedPaths: true },
					{}
				),
				assetRefusal(UNSUPPORTED, 'assetInvoice'),
				'plain node, blinded'
			);
			expectRefused(
				carol,
				assetInvoiceOptions({ ...INVOICE, extraRoutingHints: [hint] }, 'yes'),
				assetRefusal(INVALID, 'assetInvoice'),
				'plain node, malformed field'
			);
		});

		it('an option an asset invoice cannot carry, named in its order: useBlindedPaths, asyncHold, fforVoucher, jitFeeAllowance', async () => {
			const s = await payee('asset-invoice-options');
			const hints = { extraRoutingHints: [edgeHint(s.alice)] };
			const jitFeeAllowance = { flatFeeSat: 0, feePpm: 0 };
			const cases: Array<[string, Partial<ICreateInvoiceOptions>]> = [
				[
					'useBlindedPaths',
					{
						useBlindedPaths: true,
						asyncHold: true,
						fforVoucher: true,
						jitFeeAllowance
					}
				],
				['asyncHold', { asyncHold: true, fforVoucher: true, jitFeeAllowance }],
				['fforVoucher', { fforVoucher: true, jitFeeAllowance }],
				['jitFeeAllowance', { jitFeeAllowance }]
			];
			for (const [option, options] of cases) {
				expectRefused(
					s.bob,
					assetInvoiceOptions({ ...INVOICE, ...hints, ...options }),
					assetRefusal(UNSUPPORTED, option),
					option
				);
			}
		});

		it('the checks of the field and of the options come before those of the hints', async () => {
			const s = await payee('asset-invoice-order');
			expectRefused(
				s.bob,
				assetInvoiceOptions(
					{ ...INVOICE, useBlindedPaths: true },
					{
						inParts: 'no'
					}
				),
				assetRefusal(INVALID, 'assetInvoice'),
				'a malformed field, blinded paths and no hints'
			);
			expectRefused(
				s.bob,
				assetInvoiceOptions({
					...INVOICE,
					jitFeeAllowance: { flatFeeSat: 0, feePpm: 0 }
				}),
				assetRefusal(UNSUPPORTED, 'jitFeeAllowance'),
				'a JIT allowance and no hints'
			);
		});

		it('the checks createInvoice makes of any invoice come first, as for any invoice', async () => {
			const s = await payee('asset-invoice-existing-checks');
			const hints = { extraRoutingHints: [edgeHint(s.alice)] };
			const plainRefusal = (message: string): IRefusal => ({
				name: 'Error',
				message
			});
			expectRefused(
				s.bob,
				assetInvoiceOptions({ amountMsat: 5_000_000n, ...hints }, 'yes'),
				plainRefusal('Must specify either description or descriptionHash'),
				'no description'
			);
			expectRefused(
				s.bob,
				assetInvoiceOptions(
					{
						...INVOICE,
						...hints,
						jitFeeAllowance: { flatFeeSat: -1, feePpm: 0 }
					},
					'yes'
				),
				plainRefusal(
					'jitFeeAllowance.flatFeeSat must be a non-negative integer'
				),
				'a negative JIT fee'
			);
			expectRefused(
				s.bob,
				assetInvoiceOptions(
					{ ...INVOICE, ...hints, paymentMetadata: Buffer.alloc(0) },
					'yes'
				),
				plainRefusal('paymentMetadata must be 1 to 639 bytes'),
				'empty metadata'
			);
			expectRefused(
				s.bob,
				assetInvoiceOptions(
					{
						...INVOICE,
						...hints,
						hold: true,
						paymentHash: Buffer.alloc(31, 7)
					},
					'yes'
				),
				plainRefusal('paymentHash must be 32 bytes'),
				'a hold hash of 31 bytes'
			);
			// With those right, the field is refused for itself.
			expectRefused(
				s.bob,
				assetInvoiceOptions({ ...INVOICE, ...hints }, 'yes'),
				assetRefusal(INVALID, 'assetInvoice'),
				'the field'
			);
		});

		it('hints that are absent, empty, or have a hint with no hop or more than twelve', async () => {
			const s = await payee('asset-invoice-hint-shapes');
			const thirteen = [
				...Array.from({ length: 12 }, (_, i) =>
					hop(
						getPublicKey(hash(`a hop of a hint too long ${i}`)),
						Buffer.alloc(8, i + 1)
					)
				),
				hop(idOf(s.alice), EDGE_SCID)
			];
			const shapes: Array<[string, Partial<ICreateInvoiceOptions>]> = [
				['no hints', {}],
				['an empty list', { extraRoutingHints: [] }],
				['a hint with no hop', { extraRoutingHints: [edgeHint(s.alice), []] }],
				['a hint of thirteen hops', { extraRoutingHints: [thirteen] }]
			];
			for (const [label, options] of shapes) {
				expectRefused(
					s.bob,
					assetInvoiceOptions({ ...INVOICE, ...options }),
					assetRefusal(INVALID, 'extraRoutingHints'),
					label
				);
			}
		});

		it('a hop whose pubkey, short channel id, fees or delta is out of its bounds, on the last hop or another', async () => {
			const s = await payee('asset-invoice-hop-bounds');
			const edge = idOf(s.alice);
			const offCurve = Buffer.concat([
				Buffer.from([0x02]),
				Buffer.alloc(32, 0xff)
			]);
			const badHops: Array<[string, Partial<IRoutingHintHop>]> = [
				['a pubkey of 32 bytes', { pubkey: Buffer.alloc(32, 2) }],
				['a pubkey off the curve', { pubkey: offCurve }],
				[
					'a pubkey with no compressed prefix',
					{ pubkey: Buffer.concat([Buffer.from([0x04]), edge.subarray(1)]) }
				],
				[
					'a pubkey as text',
					{ pubkey: edge.toString('hex') as unknown as Buffer }
				],
				["the node's own id", { pubkey: idOf(s.bob) }],
				[
					'a short channel id of 7 bytes',
					{ shortChannelId: Buffer.alloc(7, 1) }
				],
				[
					'a short channel id as text',
					{ shortChannelId: EDGE_SCID.toString('hex') as unknown as Buffer }
				],
				['a negative base fee', { feeBaseMsat: -1 }],
				['a base fee over 32 bits', { feeBaseMsat: 4294967296 }],
				['a fractional base fee', { feeBaseMsat: 1.5 }],
				['a negative proportional fee', { feeProportionalMillionths: -1 }],
				[
					'a proportional fee over 32 bits',
					{ feeProportionalMillionths: 4294967296 }
				],
				['a fractional proportional fee', { feeProportionalMillionths: 0.5 }],
				['a negative delta', { cltvExpiryDelta: -1 }],
				['a delta over 16 bits', { cltvExpiryDelta: 65536 }],
				['a fractional delta', { cltvExpiryDelta: 1.5 }]
			];
			for (const [label, bad] of badHops) {
				// The last hop names the edge node unless its pubkey is what is wrong.
				const last = hop(edge, EDGE_SCID, bad);
				expectRefused(
					s.bob,
					assetInvoiceOptions({ ...INVOICE, extraRoutingHints: [[last]] }),
					assetRefusal(INVALID, 'extraRoutingHints'),
					`${label}, on the last hop`
				);
				const first = hop(STRANGER_2, EDGE_SCID_2, bad);
				expectRefused(
					s.bob,
					assetInvoiceOptions({
						...INVOICE,
						extraRoutingHints: [[first, hop(edge, EDGE_SCID)]]
					}),
					assetRefusal(INVALID, 'extraRoutingHints'),
					`${label}, on the first hop of two`
				);
			}
		});

		it('a hint whose last hop is no peer of an asset channel of the node that takes HTLCs: a stranger, a peer of an ordinary channel only, a peer whose asset channel is not open', async () => {
			const tag = 'asset-invoice-not-asset-peer';
			const s = await payee(tag);
			const carol = await peerOf(s, tag, 3, 'ordinary');
			const dave = await peerOf(s, tag, 4, 'unconfirmed');
			expect(stateOf(s, dave.channelId)).to.not.equal(ChannelState.NORMAL);
			for (const [label, last] of [
				['a stranger', STRANGER],
				['a peer of an ordinary channel only', idOf(carol.host)],
				['a peer whose asset channel is not open', idOf(dave.host)]
			] as const) {
				expectRefused(
					s.bob,
					assetInvoiceOptions({
						...INVOICE,
						extraRoutingHints: [edgeHint(s.alice), [hop(last, EDGE_SCID_2)]]
					}),
					assetRefusal(INVALID, 'extraRoutingHints'),
					label
				);
			}
		});

		it('a hint whose last hop names an ordinary channel of the node: by either alias, or by its real short channel id', async () => {
			const s = await payee('asset-invoice-ordinary-scid');
			const channel = s.bob.node.getChannelManager().getChannel(s.ordinaryId!)!;
			const aliases = {
				'its alias': Buffer.from(channel.getFullState().scidAlias!),
				"the peer's alias": Buffer.from(channel.getFullState().remoteScidAlias!)
			};
			for (const [label, scid] of Object.entries(aliases)) {
				expectRefused(
					s.bob,
					assetInvoiceOptions({
						...INVOICE,
						extraRoutingHints: [[hop(idOf(s.alice), scid)]]
					}),
					assetRefusal(INVALID, 'extraRoutingHints'),
					label
				);
			}
			// The funding is buried at height 800, the first transaction of its block.
			channel.handleAnnouncementDepthReached(
				800,
				1,
				idOf(s.bob),
				idOf(s.alice),
				() => ({ nodeSig: Buffer.alloc(64), bitcoinSig: Buffer.alloc(64) })
			);
			const real = channel.getShortChannelId();
			expect(real, 'the channel has its real short channel id').to.not.equal(
				null
			);
			expectRefused(
				s.bob,
				assetInvoiceOptions({
					...INVOICE,
					extraRoutingHints: [[hop(idOf(s.alice), Buffer.from(real!))]]
				}),
				assetRefusal(INVALID, 'extraRoutingHints'),
				'its real short channel id'
			);
		});

		it('a refused hold call leaves its external payment hash free: a valid call with the same hash right after is made', async () => {
			const s = await payee('asset-invoice-hash-free');
			const paymentHash = sha256(hash('asset-invoice-hash-free preimage'));
			expectRefused(
				s.bob,
				assetInvoiceOptions({ ...INVOICE, hold: true, paymentHash }),
				assetRefusal(INVALID, 'extraRoutingHints'),
				'a hold call with no hints'
			);
			expect(s.bob.node.paymentHashInUse(paymentHash)).to.equal(false);
			const made = assetInvoice(s.bob, {
				hold: true,
				paymentHash,
				extraRoutingHints: [edgeHint(s.alice)]
			});
			expect(hex(decodeInvoice(made.bolt11).paymentHash)).to.equal(
				hex(paymentHash)
			);
			expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS);
		});
	});

	describe('what does not change', () => {
		/** The payment hash and secret `host` gives `options`, the randomness fixed by `label`. */
		const drawn = (
			host: IAssetHost,
			options: ICreateInvoiceOptions,
			label: string
		): {
			made: ReturnType<LightningNode['createInvoice']>;
			drawn: string[];
		} => {
			fixRandomness(label);
			try {
				const made = host.node.createInvoice(options);
				return {
					made,
					drawn: [hex(made.paymentHash), hex(made.paymentSecret)]
				};
			} finally {
				restoreRandomness();
			}
		};

		for (const off of [undefined, null, false]) {
			it(`with the field ${String(
				off
			)}, a node with asset channels makes the invoice it makes without the field: basic_mpp, a hint for its ordinary channel and the caller's, and the same random draws`, async () => {
				const s = await payee(`asset-invoice-off-${String(off)}`);
				const given = { ...INVOICE, extraRoutingHints: [edgeHint(s.alice)] };
				const label = `field off ${String(off)}`;
				const withField = drawn(s.bob, assetInvoiceOptions(given, off), label);
				expect(featureBitsOf(withField.made.bolt11)).to.deep.equal(BITS_MPP);
				expect(hintsOf(withField.made.bolt11)).to.deep.equal([
					...ownHints(s.bob).map(hintView),
					hintView(edgeHint(s.alice))
				]);
				expect(ownHints(s.bob).length).to.equal(1);
				// The same draws as any invoice, on a node of its own.
				const twin = assetHost('asset-invoice-off-twin', 9);
				hosts.push(twin);
				expect(withField.drawn).to.deep.equal(drawn(twin, given, label).drawn);
			});
		}

		it('on a node without a provider, the field off makes the invoice it always makes', async () => {
			const tag = 'asset-invoice-off-plain';
			const alice = plainHost(tag, 1);
			const bob = plainHost(tag, 2);
			hosts.push(alice, bob);
			connectHosts(alice, bob);
			openReadyChannel(alice.node, bob.node);
			await turns(20);
			const hint = [hop(idOf(alice), EDGE_SCID)];
			for (const off of [undefined, null, false]) {
				const made = bob.node.createInvoice(
					assetInvoiceOptions({ ...INVOICE, extraRoutingHints: [hint] }, off)
				);
				expect(featureBitsOf(made.bolt11), String(off)).to.deep.equal(BITS_MPP);
				expect(hintsOf(made.bolt11), String(off)).to.deep.equal([
					...ownHints(bob).map(hintView),
					hintView(hint)
				]);
				expect(ownHints(bob).length).to.equal(1);
			}
		});

		it('an ordinary invoice of a node that made asset invoices: basic_mpp and the hint of its ordinary channel', async () => {
			const s = await payee('asset-invoice-then-ordinary');
			assetInvoice(s.bob, { extraRoutingHints: [edgeHint(s.alice)] });
			assetInvoice(
				s.bob,
				{ extraRoutingHints: [edgeHint(s.alice)] },
				{ inParts: false }
			);
			const ordinary = s.bob.node.createInvoice(INVOICE);
			expect(featureBitsOf(ordinary.bolt11)).to.deep.equal(BITS_MPP);
			expect(hintsOf(ordinary.bolt11)).to.deep.equal(
				ownHints(s.bob).map(hintView)
			);
			expect(ownHints(s.bob).length).to.equal(1);
		});

		it('a JIT invoice of a node with asset channels: basic_mpp, the hint of its ordinary channel and the LSP hint', async () => {
			const s = await payee('asset-invoice-jit');
			const lsp = getPublicKey(hash('the LSP of the payee'));
			const lspHint = hop(lsp, Buffer.from('000a2e0000300001', 'hex'));
			(
				s.bob.node as unknown as {
					requestJitReceive: () => Promise<unknown>;
				}
			).requestJitReceive = async (): Promise<unknown> => ({
				interceptScid: lspHint.shortChannelId,
				hint: lspHint,
				flatFeeSat: 1n,
				feePpm: 10,
				feeMode: 'skim'
			});
			const made = await s.bob.node.createJitInvoice({
				lspPubkeyHex: hex(lsp),
				amountMsat: 5_000_000n
			});
			expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS_MPP);
			expect(hintsOf(made.bolt11)).to.deep.equal([
				...ownHints(s.bob).map(hintView),
				hintView([lspHint])
			]);
			expect(
				s.bob.node.getInvoice(hex(made.paymentHash))?.jitFee
			).to.deep.equal({ flatFeeSat: 1, feePpm: 10 });
		});

		it('takes receiveInParts as the host has it when a part arrives: turned off after an invoice offered parts, the invoice still offers them and an asset part of a set is refused as on a node that collects none', async () => {
			const s = await payee('asset-invoice-parts-turned-off');
			const made = assetInvoice(s.bob, {
				extraRoutingHints: [edgeHint(s.alice)]
			});
			expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS_MPP);
			expect(hintsOf(made.bolt11)).to.deep.equal([hintView(edgeHint(s.alice))]);
			(
				s.bob.node as unknown as {
					auxiliaryChannels: { receiveInParts?: boolean };
				}
			).auxiliaryChannels.receiveInParts = false;

			assetPart(s.alice, s.bob, s.assetId, made, {
				units: 3000n,
				totalMsat: 5_000_000n
			});
			await turns(200);
			const refused = s.logs.filter(
				(log) =>
					log.action === 'asset_multi_part_refused' &&
					log.data.paymentHash === hex(made.paymentHash)
			);
			expect(refused.length, 'the part is refused, and logged').to.equal(1);
			expect(refused[0].data).to.not.have.property('reason');
			expect(heldOn(s.bob, s.assetId, made.paymentHash)).to.equal(0);
			expect(collected(s.bob, made.paymentHash)).to.equal(0);
			expect(unitsOf(s.bob, s.assetId)).to.equal(1000n);
			expect(
				featureBitsOf(s.bob.node.getInvoice(hex(made.paymentHash))!.bolt11)
			).to.deep.equal(BITS_MPP);
		});
	});

	describe('paid end to end, through the edge node that converts', () => {
		withAssetForwards();
		const world = forwardChainWorld();
		afterEach(() => world.dispose());

		/** More than either of Alice's channels to Bob carries alone. */
		const INVOICE_MSAT = 2_000_000_000n;

		/**
		 * Alice pays bitcoin over two ordinary channels to Bob, the edge
		 * node; his host gives a part the units of what its onion asks him to
		 * forward to Carol, the payee, over his asset channel to her, where
		 * he holds 3,000,000 units. Carol has an ordinary channel from Bob
		 * too, which can receive.
		 */
		async function edgeScene(tag: string): Promise<{
			s: IPartsScene;
			edge: IRoutingHintHop;
		}> {
			const s = await openPartsScene(world, tag, {
				world: {
					secondIn: 'ordinary',
					secondOut: 'ordinary',
					units: { out: { opener: 3_000_000n, acceptor: 1000n } }
				}
			});
			for (const channelId of [s.w.inChannel, s.w.inChannel2!]) {
				const spendable = s.w.hosts.alice.node
					.getChannelManager()
					.getChannel(channelId)!
					.getSpendableOutboundMsat();
				expect(
					spendable < INVOICE_MSAT,
					'no channel of Alice carries it alone'
				).to.equal(true);
			}
			return {
				s,
				edge: hop(idOf(s.w.hosts.bob), aliasOf(s.w.hosts.bob, s.w.outChannel))
			};
		}

		/** The HTLCs Alice offered for a hash, on either of her channels to Bob. */
		const offeredByAlice = (s: IPartsScene, paymentHash: Buffer): number =>
			[s.w.inChannel, s.w.inChannel2!]
				.map(
					(channelId) =>
						[
							...(s.w.hosts.alice.node
								.getChannelManager()
								.getChannel(channelId)
								?.getFullState().htlcs ?? new Map())
						].filter(
							([key, entry]) =>
								key.startsWith('offered-') &&
								entry.paymentHash.equals(paymentHash)
						).length
				)
				.reduce((all, count) => all + count, 0);

		it('a payer splits an invoice that offers basic_mpp over two first hops, the edge node takes two forwards, and the payee collects the set', async () => {
			const tag = 'asset-invoice-end-to-end';
			const { s, edge } = await edgeScene(tag);
			const carol = s.w.hosts.carol;
			const made = carol.node.createInvoice(
				assetInvoiceOptions({
					amountMsat: INVOICE_MSAT,
					description: `asset invoice ${tag}`,
					extraRoutingHints: [[edge]]
				})
			);
			expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS_MPP);
			expect(hintsOf(made.bolt11)).to.deep.equal([hintView([edge])]);
			expect(
				carol.node.getInvoice(hex(made.paymentHash)),
				'no auxiliary mark before an asset HTLC settles it'
			).to.not.have.property('auxiliary');

			s.w.hosts.alice.node.sendPayment(made.bolt11);
			const invoice: IPartsInvoice = {
				paymentHash: made.paymentHash,
				paymentSecret: made.paymentSecret,
				invoiceMsat: INVOICE_MSAT,
				totalMsat: INVOICE_MSAT
			};
			await alicePaid(s, invoice);
			expect(
				s.asked.filter((request) =>
					request.paymentHash.equals(made.paymentHash)
				).length,
				'Bob took two forwards'
			).to.equal(2);
			const asks = asksFor(s, invoice);
			expect(asks.length, 'two asset parts reached Carol').to.equal(2);
			expect(
				asks.map((ask) => ask.customRecords.get(QUOTE_RECORD)?.[0]),
				'both under one quote'
			).to.deep.equal([1, 1]);
			const record = carolsRecord(s, invoice)!;
			expect(record.status).to.equal(PaymentStatus.COMPLETED);
			expect(record.settledHtlcs?.length).to.equal(2);
			expect(
				carol.node.getInvoice(hex(made.paymentHash))?.auxiliary,
				'the invoice an asset set settled is marked'
			).to.equal(true);
			// Bob's host rounds each part's units down, so the set carries the
			// invoice's worth to within a unit a part.
			const carried = asks.reduce(
				(sum, ask) => sum + (ask.auxiliaryAmount ?? 0n),
				0n
			);
			expect(INVOICE_MSAT / 1000n - carried <= 2n).to.equal(true);
			expect(
				unitsOf(carol, s.w.outChannel),
				'the units of the set moved to Carol'
			).to.equal(1000n + carried);
		});

		it('a payer sends no part of an invoice that offers no basic_mpp and that no single route carries', async () => {
			const tag = 'asset-invoice-end-to-end-whole';
			const { s, edge } = await edgeScene(tag);
			const made = s.w.hosts.carol.node.createInvoice(
				assetInvoiceOptions(
					{
						amountMsat: INVOICE_MSAT,
						description: `asset invoice ${tag}`,
						extraRoutingHints: [[edge]]
					},
					{ inParts: false }
				)
			);
			expect(featureBitsOf(made.bolt11)).to.deep.equal(BITS);

			const refusal = refusalOf(() =>
				s.w.hosts.alice.node.sendPayment(made.bolt11)
			);
			await turns(100);
			expect(refusal).to.deep.include({ code: LightningErrorCode.NO_ROUTE });
			expect(
				offeredByAlice(s, made.paymentHash),
				'no HTLC left Alice'
			).to.equal(0);
			expect(
				s.asked.filter((request) =>
					request.paymentHash.equals(made.paymentHash)
				).length,
				'Bob was asked nothing'
			).to.equal(0);
			expect(
				s.w.hosts.carol.node.getPayment(made.paymentHash)?.status
			).to.equal(PaymentStatus.PENDING);
		});
	});

	describe('what the build says it offers a host', () => {
		it('names createInvoice:assetInvoice immediately after sendInParts at version 1 with nothing declared', () => {
			const api = lightningChannel.AUXILIARY_CHANNELS_API;
			const send = api.surfaces.indexOf('sendInParts');
			expect(send).to.be.at.least(0);
			expect(api.surfaces[send + 1]).to.equal('createInvoice:assetInvoice');
			expect(api.version).to.equal(1);
			expect([...api.declared]).to.deep.equal([]);
		});
	});
});
