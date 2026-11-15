/**
 * BOLT 4 route blinding rules a reader and relay must apply (issue #2047):
 * the strict encrypted_data_tlv reader, blinded_payinfo features, the
 * sciddir introduction point, both next-hop forms in both relays, the
 * intermediate onion message rules, a double path key, and rotating to an
 * invoice's next blinded path.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IStructuredLog,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	constructBlindedPath,
	decodeBlindedHopData,
	encodeBlindedHopData,
	IBlindedHopData,
	IBlindedPath,
	payInfoRequiresUnknownFeature,
	resolveIntroductionNode
} from '../../src/lightning/onion/blinded-path';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import {
	findRouteToBlindedPath,
	ILocalChannelEdge
} from '../../src/lightning/gossip/pathfinding';
import { MessageType } from '../../src/lightning/message/types';
import { encodeTlvStream } from '../../src/lightning/message/tlv';
import { encodeBigSize } from '../../src/lightning/message/codec';
import { decodeUpdateFailMalformedHtlcMessage } from '../../src/lightning/message/channel-update';
import { INVALID_ONION_BLINDING } from '../../src/lightning/onion/types';
import { Feature } from '../../src/lightning/features/flags';
import { constructOnionMessagePacket } from '../../src/lightning/onion-message/construct';
import { encodeOnionMessagePayload } from '../../src/lightning/onion-message/codec';
import { processOnionMessage } from '../../src/lightning/onion-message/process';
import type { IOnionMessagePayload } from '../../src/lightning/onion-message/types';

// ─────────────── Helpers (mirrors node.test.ts) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`blinded-spec-rules-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function nodePrivkeyFor(seedId: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(makeSeed(seedId))
		.update(Buffer.from('node-identity'))
		.digest();
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: nodePrivkeyFor(seedId),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		// Secret behind makeBasepoints' htlcBasepoint (keys[4]) so the signer
		// can produce HTLC second-level signatures for commitment_signed.
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest()
	};
}

function createNode(
	seedId: number,
	extra: Partial<INodeConfig> = {}
): LightningNode {
	const node = new LightningNode({ ...makeNodeConfig(seedId), ...extra });
	return node;
}

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
		if (pk === b.getNodeId()) b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
		if (pk === a.getNodeId()) a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	amount = 2_000_000n
): Buffer {
	const ch = alice.openChannel(bob.getNodeId(), amount);
	const txid = crypto.randomBytes(32);
	const channelId = alice.createFunding(ch, txid, 0, crypto.randomBytes(64))!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

/** Give the payer a graph edge to the introduction node. */
function addGraphEdge(
	node: LightningNode,
	scid: Buffer,
	pubA: Buffer,
	pubB: Buffer
): void {
	const is1 = Buffer.compare(pubA, pubB) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: is1 ? pubA : pubB,
		nodeId2: is1 ? pubB : pubA,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const dir of [0, 1]) {
		node.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: dir,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		});
	}
}

const CONSTRAINTS = { maxCltvExpiry: 10_000_000, htlcMinimumMsat: 0n };
const RELAY = {
	cltvExpiryDelta: 40,
	feeProportionalMillionths: 1000,
	feeBaseMsat: 0
};
const PAY_INFO = {
	feeBaseMsat: RELAY.feeBaseMsat,
	feeProportionalMillionths: RELAY.feeProportionalMillionths,
	cltvExpiryDelta: RELAY.cltvExpiryDelta,
	htlcMinimumMsat: 0n,
	htlcMaximumMsat: 1_000_000_000n
};

const tlv = (records: [number, Buffer][]): Buffer =>
	encodeTlvStream(
		records.map(([type, value]) => ({ type: BigInt(type), value }))
	);

const pub = (n: number): Buffer => getPublicKey(Buffer.alloc(32, n));

/**
 * Alice -> Bob -> Carol with channels open and Bob's SCIDs registered.
 * `issue` mints Carol's BOLT 11 invoice carrying the given paths through Bob.
 */
function buildWorld(): {
	alice: LightningNode;
	bob: LightningNode;
	carol: LightningNode;
	scidBC: Buffer;
	bobPub: Buffer;
	carolPub: Buffer;
	aliceAdds: number;
	issue: (paths: { hopData: IBlindedHopData[]; features?: Buffer }[]) => {
		invoiceStr: string;
		paymentHash: Buffer;
		paymentSecret: Buffer;
	};
	destroy: () => void;
} {
	const alice = createNode(1);
	const bob = createNode(2, {
		forwardingFeeBaseMsat: RELAY.feeBaseMsat,
		forwardingFeePropMillionths: RELAY.feeProportionalMillionths
	});
	const carol = createNode(3);
	connectNodes(alice, bob);
	connectNodes(bob, carol);
	const abChannelId = openReadyChannel(alice, bob);
	const bcChannelId = openReadyChannel(bob, carol);
	const scidAB = encodeShortChannelId({
		block: 900,
		txIndex: 1,
		outputIndex: 0
	});
	const scidBC = encodeShortChannelId({
		block: 900,
		txIndex: 2,
		outputIndex: 0
	});
	alice.registerChannelScid(abChannelId, scidAB);
	bob.registerChannelScid(abChannelId, scidAB);
	bob.registerChannelScid(bcChannelId, scidBC);
	carol.registerChannelScid(bcChannelId, scidBC);
	const alicePub = getPublicKey(nodePrivkeyFor(1));
	const bobPub = getPublicKey(nodePrivkeyFor(2));
	const carolPub = getPublicKey(nodePrivkeyFor(3));
	addGraphEdge(alice, scidAB, alicePub, bobPub);

	const world = {
		alice,
		bob,
		carol,
		scidBC,
		bobPub,
		carolPub,
		aliceAdds: 0,
		issue: (
			paths: { hopData: IBlindedHopData[]; features?: Buffer }[]
		): { invoiceStr: string; paymentHash: Buffer; paymentSecret: Buffer } => {
			const decoded = decodeInvoice(
				carol.createInvoice({ amountMsat: 1_000_000n, description: 'x' }).bolt11
			);
			const invoiceStr = encodeInvoice({
				network: Network.REGTEST,
				amountMsat: 1_000_000n,
				paymentHash: decoded.paymentHash,
				paymentSecret: decoded.paymentSecret,
				description: 'x',
				blindedPaths: paths.map(({ hopData, features }) => ({
					path: constructBlindedPath(
						crypto.randomBytes(32),
						[bobPub, carolPub],
						hopData
					),
					payInfo: { ...PAY_INFO, ...(features && { features }) }
				})),
				minFinalCltvExpiry: 40,
				privateKey: nodePrivkeyFor(3)
			});
			return {
				invoiceStr,
				paymentHash: decoded.paymentHash,
				paymentSecret: decoded.paymentSecret!
			};
		},
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
			carol.destroy();
		}
	};
	alice.on('message:outbound', (_pk: string, type: number) => {
		if (type === MessageType.UPDATE_ADD_HTLC) world.aliceAdds++;
	});
	return world;
}

describe('BOLT 4 route blinding reader and relay rules (#2047)', function () {
	describe('encrypted_data_tlv reader', function () {
		const scid = Buffer.alloc(8, 1);

		it('refuses an unknown even type and skips an unknown odd one', function () {
			expect(() =>
				decodeBlindedHopData(
					tlv([
						[2, scid],
						[16, Buffer.from([1])]
					])
				)
			).to.throw('Unknown required TLV type: 16');
			const data = decodeBlindedHopData(
				tlv([
					[2, scid],
					[17, Buffer.from([1])]
				])
			);
			expect(data.shortChannelId).to.deep.equal(scid);
		});

		it('refuses a hop naming both short_channel_id and next_node_id', function () {
			expect(() =>
				decodeBlindedHopData(
					tlv([
						[2, scid],
						[4, pub(1)]
					])
				)
			).to.throw('both short_channel_id and next_node_id');
		});

		it('refuses next-hop and path-key fields of the wrong length', function () {
			expect(() => decodeBlindedHopData(tlv([[2, Buffer.alloc(7)]]))).to.throw(
				'must be 8 bytes'
			);
			expect(() =>
				decodeBlindedHopData(tlv([[4, pub(1).subarray(1)]]))
			).to.throw('must be 33 bytes');
			expect(() =>
				decodeBlindedHopData(tlv([[8, Buffer.alloc(32, 2)]]))
			).to.throw('must be 33 bytes');
			expect(() => decodeBlindedHopData(tlv([[10, Buffer.alloc(5)]]))).to.throw(
				'invalid length'
			);
		});

		it('accepts an empty allowed_features and refuses any bit in it, odd included', function () {
			expect(
				decodeBlindedHopData(
					tlv([
						[2, scid],
						[14, Buffer.alloc(0)]
					])
				).allowedFeatures
			).to.deep.equal(Buffer.alloc(0));
			expect(() =>
				decodeBlindedHopData(
					tlv([
						[2, scid],
						[14, Buffer.from([0x02])]
					])
				)
			).to.throw('allowed_features');
		});

		it('round-trips allowed_features through the writer', function () {
			const data = decodeBlindedHopData(
				encodeBlindedHopData({
					shortChannelId: scid,
					allowedFeatures: Buffer.alloc(0)
				})
			);
			expect(data.allowedFeatures).to.deep.equal(Buffer.alloc(0));
		});
	});

	describe('blinded_payinfo features', function () {
		it('flags any even bit and ignores odd bits', function () {
			expect(payInfoRequiresUnknownFeature({})).to.equal(false);
			expect(
				payInfoRequiresUnknownFeature({ features: Buffer.from([0x02]) })
			).to.equal(false);
			expect(
				payInfoRequiresUnknownFeature({ features: Buffer.from([0x01]) })
			).to.equal(true);
			// bit 8, in the second-to-last byte
			expect(
				payInfoRequiresUnknownFeature({ features: Buffer.from([0x01, 0x00]) })
			).to.equal(true);
		});

		it('refuses to pay over a path whose payinfo sets an unknown even bit', function () {
			const world = buildWorld();
			try {
				const { invoiceStr } = world.issue([
					{
						hopData: [
							{
								shortChannelId: world.scidBC,
								paymentRelay: RELAY,
								paymentConstraints: CONSTRAINTS
							},
							{ paymentConstraints: CONSTRAINTS }
						],
						features: Buffer.from([0x01])
					}
				]);
				expect(() => world.alice.sendPayment(invoiceStr)).to.throw(
					'No route to blinded path'
				);
				expect(world.aliceAdds).to.equal(0);
			} finally {
				world.destroy();
			}
		});
	});

	describe('sciddir introduction point', function () {
		const ends = { nodeId1: pub(1), nodeId2: pub(2) };
		const scid = Buffer.alloc(8, 7);
		const path = (first: Buffer): IBlindedPath => ({
			introductionNodeId: first,
			blindingPoint: pub(3),
			blindedHops: [{ blindedNodeId: pub(4), encryptedData: Buffer.alloc(0) }]
		});
		const lookup = (s: Buffer): typeof ends | undefined =>
			s.equals(scid) ? ends : undefined;

		it('names node_1 for direction 0 and node_2 for direction 1', function () {
			expect(
				resolveIntroductionNode(
					path(Buffer.concat([Buffer.from([0]), scid])),
					lookup
				)?.introductionNodeId
			).to.deep.equal(ends.nodeId1);
			expect(
				resolveIntroductionNode(
					path(Buffer.concat([Buffer.from([1]), scid])),
					lookup
				)?.introductionNodeId
			).to.deep.equal(ends.nodeId2);
		});

		it('returns null for an unknown channel and keeps a pubkey as it is', function () {
			expect(
				resolveIntroductionNode(
					path(Buffer.concat([Buffer.from([0]), Buffer.alloc(8, 9)])),
					lookup
				)
			).to.equal(null);
			const p = path(pub(5));
			expect(resolveIntroductionNode(p, lookup)).to.equal(p);
		});
	});

	describe('onion message intermediate node', function () {
		const bobPriv = Buffer.alloc(32, 0x0b);
		const carolPriv = Buffer.alloc(32, 0x0c);
		const carolPub = getPublicKey(carolPriv);

		/** A Bob -> Carol path with Bob's payload given raw. */
		function messageAtBob(
			bobHop: IBlindedHopData,
			bobPayload: (erd: Buffer) => Buffer
		): { packet: Buffer; path: IBlindedPath } {
			const path = constructBlindedPath(
				crypto.randomBytes(32),
				[getPublicKey(bobPriv), carolPub],
				[bobHop, {}]
			);
			const final: IOnionMessagePayload = {
				encryptedRecipientData: path.blindedHops[1].encryptedData,
				messageTlvs: new Map([[64, Buffer.from('hi')]])
			};
			const packet = constructOnionMessagePacket(crypto.randomBytes(32), [
				{
					pubkey: path.blindedHops[0].blindedNodeId,
					payload: bobPayload(path.blindedHops[0].encryptedData)
				},
				{
					pubkey: path.blindedHops[1].blindedNodeId,
					payload: encodeOnionMessagePayload(final)
				}
			]);
			return { packet, path };
		}
		const rawPayload = (records: [number, Buffer][]): Buffer => {
			const stream = tlv(records);
			return Buffer.concat([encodeBigSize(BigInt(stream.length)), stream]);
		};

		it('forwards a payload holding only encrypted_recipient_data', function () {
			const { packet, path } = messageAtBob({ nextNodeId: carolPub }, (erd) =>
				rawPayload([[4, erd]])
			);
			const result = processOnionMessage(packet, bobPriv, path.blindingPoint);
			expect(result.type).to.equal('forward');
			if (result.type === 'forward') {
				expect(result.nextNodeId).to.deep.equal(carolPub);
			}
		});

		for (const [label, extra] of [
			['a reply_path', 2],
			['an unknown odd field', 5],
			['an invoice_request', 64]
		] as const) {
			it(`ignores a relay payload that also carries ${label}`, function () {
				const { packet, path } = messageAtBob({ nextNodeId: carolPub }, (erd) =>
					rawPayload(
						extra < 4
							? [
									[extra, Buffer.from([1])],
									[4, erd]
							  ]
							: [
									[4, erd],
									[extra, Buffer.from([1])]
							  ]
					)
				);
				expect(() =>
					processOnionMessage(packet, bobPriv, path.blindingPoint)
				).to.throw();
			});
		}

		it('ignores a relay hop whose encrypted data carries a path_id', function () {
			const { packet, path } = messageAtBob(
				{ nextNodeId: carolPub, pathId: Buffer.alloc(32, 1) },
				(erd) => rawPayload([[4, erd]])
			);
			expect(() =>
				processOnionMessage(packet, bobPriv, path.blindingPoint)
			).to.throw('path_id');
		});

		it('forwards a hop named by short_channel_id through the resolver', function () {
			const scid = Buffer.alloc(8, 3);
			const { packet, path } = messageAtBob({ shortChannelId: scid }, (erd) =>
				rawPayload([[4, erd]])
			);
			expect(() =>
				processOnionMessage(packet, bobPriv, path.blindingPoint)
			).to.throw('short_channel_id');
			const result = processOnionMessage(
				packet,
				bobPriv,
				path.blindingPoint,
				(s) => (s.equals(scid) ? carolPub : undefined)
			);
			expect(result.type).to.equal('forward');
			if (result.type === 'forward') {
				expect(result.nextNodeId).to.deep.equal(carolPub);
			}
		});
	});

	describe('payment relay', function () {
		it('forwards a blinded hop named by next_node_id', function () {
			const world = buildWorld();
			try {
				const { invoiceStr, paymentHash } = world.issue([
					{
						hopData: [
							{
								nextNodeId: world.carolPub,
								paymentRelay: RELAY,
								paymentConstraints: CONSTRAINTS
							},
							{ paymentConstraints: CONSTRAINTS }
						]
					}
				]);
				world.alice.sendPayment(invoiceStr);
				expect(world.alice.getPayment(paymentHash)!.status).to.equal(
					PaymentStatus.COMPLETED
				);
				expect(world.carol.getPayment(paymentHash)!.status).to.equal(
					PaymentStatus.COMPLETED
				);
			} finally {
				world.destroy();
			}
		});

		it('refuses an HTLC carrying a path key in both update_add_htlc and the onion', function () {
			const world = buildWorld();
			try {
				const { invoiceStr, paymentHash, paymentSecret } = world.issue([
					{
						hopData: [
							{
								shortChannelId: world.scidBC,
								paymentRelay: RELAY,
								paymentConstraints: CONSTRAINTS
							},
							{ paymentConstraints: CONSTRAINTS }
						]
					}
				]);
				const blinded = decodeInvoice(invoiceStr).blindedPaths![0];
				const route = findRouteToBlindedPath(
					world.alice.getGraph(),
					getPublicKey(nodePrivkeyFor(1)),
					blinded.path,
					blinded.payInfo,
					1_000_000n,
					80,
					undefined,
					undefined,
					undefined,
					(
						world.alice as unknown as {
							getLocalChannelEdges: () => ILocalChannelEdge[];
						}
					).getLocalChannelEdges()
				)!;
				expect(route, 'route to the blinded path').to.not.equal(null);
				// The final hop also gets current_path_key (TLV 12), on top of
				// the path_key Bob puts in his update_add_htlc.
				route.hops[route.hops.length - 1].blindingPoint =
					blinded.path.blindingPoint;

				const logs: IStructuredLog[] = [];
				world.carol.on('log', (l: IStructuredLog) => logs.push(l));
				const malformed: number[] = [];
				world.carol.on(
					'message:outbound',
					(_pk: string, type: number, payload: Buffer) => {
						if (type === MessageType.UPDATE_FAIL_MALFORMED_HTLC) {
							malformed.push(
								decodeUpdateFailMalformedHtlcMessage(payload).failureCode
							);
						}
					}
				);
				try {
					world.alice.sendPaymentToRoute(
						route,
						paymentHash,
						80,
						paymentSecret,
						1_000_000n
					);
				} catch {
					// the failure is what is asserted
				}
				expect(logs.map((l) => l.action)).to.include('blinded_double_path_key');
				expect(malformed).to.deep.equal([INVALID_ONION_BLINDING]);
				expect(world.carol.getPayment(paymentHash)?.status).to.not.equal(
					PaymentStatus.COMPLETED
				);
			} finally {
				world.destroy();
			}
		});
	});

	describe('payer path rotation', function () {
		it('pays over the second path when the first fails inside its blinded segment', function () {
			const world = buildWorld();
			try {
				const unknownScid = encodeShortChannelId({
					block: 900,
					txIndex: 9,
					outputIndex: 0
				});
				const { invoiceStr, paymentHash } = world.issue([
					{
						hopData: [
							{
								shortChannelId: unknownScid,
								paymentRelay: RELAY,
								paymentConstraints: CONSTRAINTS
							},
							{ paymentConstraints: CONSTRAINTS }
						]
					},
					{
						hopData: [
							{
								shortChannelId: world.scidBC,
								paymentRelay: RELAY,
								paymentConstraints: CONSTRAINTS
							},
							{ paymentConstraints: CONSTRAINTS }
						]
					}
				]);
				world.alice.sendPayment(invoiceStr);
				expect(world.aliceAdds, 'one attempt per path').to.equal(2);
				expect(world.alice.getPayment(paymentHash)!.status).to.equal(
					PaymentStatus.COMPLETED
				);
				expect(world.carol.getPayment(paymentHash)!.status).to.equal(
					PaymentStatus.COMPLETED
				);
			} finally {
				world.destroy();
			}
		});
	});

	it('advertises option_route_blinding in the default init features', function () {
		const node = createNode(9);
		try {
			expect(
				node.getLocalFeatures().hasFeature(Feature.ROUTE_BLINDING)
			).to.equal(true);
		} finally {
			node.destroy();
		}
	});
});
