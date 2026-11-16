/**
 * Asset channels, step 4 of issue #2093: the taproot overlay feature pair,
 * the asset channel bits 450 and 452, and init custom records.
 *
 * The rule under test is that all of it is off without an auxiliary channel
 * provider. The golden values were taken from the code before the bits
 * existed: a node with no provider must send the same init bytes as then.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import type { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	isOverlayChannel
} from '../../src/lightning/channel/types';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	Feature,
	FeatureFlags,
	TAPROOT_OVERLAY_DEPENDENCIES,
	hasUnsupportedRequiredFeatures
} from '../../src/lightning/features/flags';
import type { ILogger } from '../../src/logger';
import {
	encodeInitMessage,
	decodeInitMessage
} from '../../src/lightning/message/init';
import { encodeTlvStream } from '../../src/lightning/message/tlv';
import { TransportCipher } from '../../src/lightning/transport/cipher';

/** Set bits of a node built by `makeNode()` before this change. */
const DEFAULT_BITS = [
	1, 7, 8, 13, 14, 17, 19, 23, 25, 27, 29, 35, 39, 43, 45, 47, 51, 55, 61, 63,
	65, 441, 443, 455
];
/** Its init payload with one chain hash of 32 bytes 0xab, before this change. */
const DEFAULT_INIT =
	'00000039800a000000000000000000000000000000000000000000000000000000000000' +
	'0000000000000000000000000000000002a088a8882a8a61820120' +
	'ab'.repeat(32);
/**
 * A caller-supplied set carrying the asset bits by hand, as the node
 * advertised it before this change: untouched.
 */
const SUPPLIED_BITS = [13, 19, 23, 65, 451, 453, 2025];
const SUPPLIED_INIT =
	'000000' +
	'fe' +
	'02' +
	'00'.repeat(196) +
	'28' +
	'00'.repeat(47) +
	'02' +
	'00'.repeat(5) +
	'88' +
	'20' +
	'00';

const key = (n: number): Buffer => getPublicKey(Buffer.alloc(32, n));

function makeNode(extra: Partial<INodeConfig> = {}): LightningNode {
	return new LightningNode({
		nodePrivateKey: Buffer.alloc(32, 1),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: {
			fundingPubkey: key(2),
			revocationBasepoint: key(3),
			paymentBasepoint: key(4),
			delayedPaymentBasepoint: key(5),
			htlcBasepoint: key(6),
			firstPerCommitmentPoint: key(7)
		},
		perCommitmentSeed: Buffer.alloc(32, 8),
		fundingPrivkey: Buffer.alloc(32, 9),
		...extra
	});
}

function auxiliary(
	extra: Partial<IAuxiliaryChannelConfig> = {}
): IAuxiliaryChannelConfig {
	return {
		provider: {} as IChannelAuxiliaryProvider,
		resolveIncoming: () => undefined,
		...extra
	};
}

/** An init payload with no features and the given raw TLV records. */
function initWith(records: Array<[bigint, Buffer]>): Buffer {
	return Buffer.concat([
		Buffer.alloc(4),
		encodeTlvStream(records.map(([type, value]) => ({ type, value })))
	]);
}

describe('Asset channel feature bits and init custom records', function () {
	this.timeout(15000);
	const nodes: LightningNode[] = [];
	afterEach(() => {
		for (const node of nodes.splice(0)) node.destroy();
	});
	const track = (node: LightningNode): LightningNode => {
		nodes.push(node);
		return node;
	};

	it('uses the deployed overlay feature pair and rejects an unavailable extension', () => {
		const optional = FeatureFlags.empty();
		optional.setOptional(Feature.OPTION_TAPROOT_OVERLAY);
		const required = FeatureFlags.empty();
		required.setCompulsory(Feature.OPTION_TAPROOT_OVERLAY);
		expect(optional.listSetBits()).to.deep.equal([2025]);
		expect(required.listSetBits()).to.deep.equal([2026]);
		expect(optional.hasFeature(Feature.OPTION_TAPROOT_OVERLAY)).to.equal(true);
		expect(optional.isOptional(Feature.OPTION_TAPROOT_OVERLAY)).to.equal(true);
		expect(optional.isCompulsory(Feature.OPTION_TAPROOT_OVERLAY)).to.equal(
			false
		);
		expect(isOverlayChannel(required.toBuffer())).to.equal(true);
		expect(isOverlayChannel(optional.toBuffer())).to.equal(true);
		expect(isOverlayChannel(null)).to.equal(false);
		expect(isOverlayChannel(Buffer.alloc(0))).to.equal(false);
		// A node that runs asset channels understands a peer that requires
		// 2026 through its own 2025.
		const assetNode = { taprootOverlay: true };
		expect(
			hasUnsupportedRequiredFeatures(optional, required, assetNode)
		).to.deep.equal([]);
		expect(
			hasUnsupportedRequiredFeatures(FeatureFlags.empty(), required, assetNode)
		).to.deep.equal([2026]);
		// 2027 is not the overlay's optional bit: an asset node that set it
		// by mistake does not understand a peer that requires 2026.
		const wrongPartner = FeatureFlags.empty();
		wrongPartner.setBit(2027);
		expect(wrongPartner.hasFeature(Feature.OPTION_TAPROOT_OVERLAY)).to.equal(
			false
		);
		expect(
			hasUnsupportedRequiredFeatures(wrongPartner, required, assetNode)
		).to.deep.equal([2026]);
	});

	it('pairs bit 2026 with 2027, as it always did, for a node that runs no asset channels', () => {
		const required = FeatureFlags.empty();
		required.setBit(2026);
		const with2025 = FeatureFlags.empty();
		with2025.setBit(2025);
		const with2027 = FeatureFlags.empty();
		with2027.setBit(2027);
		// Both outcomes are the ones the check gave before the overlay pair
		// was known: 2025 says nothing about 2026, and 2027 answers for it.
		expect(hasUnsupportedRequiredFeatures(with2025, required)).to.deep.equal([
			2026
		]);
		expect(hasUnsupportedRequiredFeatures(with2027, required)).to.deep.equal(
			[]
		);
		expect(
			hasUnsupportedRequiredFeatures(FeatureFlags.empty(), required)
		).to.deep.equal([2026]);
	});

	it('keeps the adjacent optional bit for every other feature', () => {
		for (const feature of [
			Feature.STATIC_REMOTE_KEY,
			Feature.OPTION_TAPROOT,
			Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS,
			Feature.OPTION_ASSET_CHILD_CUSTODY
		]) {
			const flags = FeatureFlags.empty();
			flags.setOptional(feature);
			expect(flags.listSetBits()).to.deep.equal([feature + 1]);
			expect(flags.hasFeature(feature)).to.equal(true);
			expect(flags.isOptional(feature)).to.equal(true);
		}
		expect(Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS).to.equal(450);
		expect(Feature.OPTION_ASSET_CHILD_CUSTODY).to.equal(452);
		// A peer that requires an asset bit is not understood by a node that
		// does not advertise it.
		for (const bit of [450, 452]) {
			const required = FeatureFlags.empty();
			required.setBit(bit);
			expect(
				hasUnsupportedRequiredFeatures(FeatureFlags.empty(), required)
			).to.deep.equal([bit]);
		}
	});

	it('a node with no provider sends the same init bytes as before', () => {
		const node = track(makeNode());
		const features = node.getLocalFeatures();
		expect(features.listSetBits()).to.deep.equal(DEFAULT_BITS);
		expect(
			encodeInitMessage({
				features,
				networks: [Buffer.alloc(32, 0xab)]
			}).toString('hex')
		).to.equal(DEFAULT_INIT);
		expect(node.getPeerCustomRecords(key(11).toString('hex')).size).to.equal(0);
	});

	it('leaves a caller-supplied feature set alone when there is no provider', () => {
		const supplied = FeatureFlags.empty();
		supplied.setOptional(Feature.STATIC_REMOTE_KEY);
		supplied.setBit(2025);
		supplied.setBit(451);
		supplied.setBit(453);
		const node = track(makeNode({ localFeatures: supplied }));
		expect(node.getLocalFeatures().listSetBits()).to.deep.equal(SUPPLIED_BITS);
		expect(
			encodeInitMessage({ features: node.getLocalFeatures() }).toString('hex')
		).to.equal(SUPPLIED_INIT);
	});

	it('a node with a provider advertises the overlay with simple taproot, and loses only simple close', () => {
		const node = track(makeNode({ auxiliaryChannels: auxiliary() }));
		const bits = node.getLocalFeatures().listSetBits();
		const expected = DEFAULT_BITS.filter(
			(bit) => bit !== Feature.SIMPLE_CLOSE + 1
		)
			.concat([181, 2025])
			.sort((a, b) => a - b);
		expect(bits).to.deep.equal(expected);
		expect(DEFAULT_BITS).to.include(Feature.SIMPLE_CLOSE + 1);
		// dual funding stays advertised: an asset open asks for v1 itself.
		expect(bits).to.include(Feature.DUAL_FUND + 1);
	});

	it('does not advertise fixed HTLC outputs or child custody from a caller-supplied set', () => {
		const supplied = LightningNode.defaultFeatures();
		supplied.setBit(451);
		supplied.setBit(453);
		const node = track(
			makeNode({ localFeatures: supplied, auxiliaryChannels: auxiliary() })
		);
		const bits = node.getLocalFeatures().listSetBits();
		expect(bits).to.include(2025);
		for (const bit of [450, 451, 452, 453]) expect(bits).to.not.include(bit);
	});

	describe('what a peer requires beside the overlay', () => {
		/**
		 * LND drops a connection whose init sets a feature without the
		 * features it depends on (feature/deps.go). For the overlay that is
		 * simple taproot, TLV onion and scid alias, then zero-fee-HTLC
		 * anchors and explicit channel type for simple taproot, then
		 * static_remotekey for the anchors.
		 */
		const CLOSURE = [
			Feature.OPTION_TAPROOT,
			Feature.TLV_ONION,
			Feature.SCID_ALIAS,
			Feature.ANCHOR_ZERO_FEE_HTLC,
			Feature.CHANNEL_TYPE,
			Feature.STATIC_REMOTE_KEY
		];
		/** Either the overlay with its whole closure, or no overlay at all. */
		const expectWholeOrAbsent = (node: LightningNode): boolean => {
			const features = node.getLocalFeatures();
			const advertised = features.hasFeature(Feature.OPTION_TAPROOT_OVERLAY);
			expect(node.getAuxiliaryAdvertisement().advertised).to.equal(advertised);
			if (advertised) {
				for (const feature of CLOSURE) {
					expect(features.hasFeature(feature), `feature ${feature}`).to.equal(
						true
					);
				}
			} else {
				expect(features.listSetBits()).to.not.include(2025);
				expect(features.listSetBits()).to.not.include(2026);
			}
			return advertised;
		};
		const warnings = (): { logger: ILogger; lines: string[] } => {
			const lines: string[] = [];
			return {
				lines,
				logger: {
					debug: () => undefined,
					info: () => undefined,
					warn: (message: string) => lines.push(message),
					error: () => undefined
				}
			};
		};

		it('names the closure LND checks', () => {
			expect(
				TAPROOT_OVERLAY_DEPENDENCIES.map(([feature]) => feature)
			).to.deep.equal(CLOSURE);
			expect(
				TAPROOT_OVERLAY_DEPENDENCIES.map(([feature]) => feature)
			).to.deep.equal([180, 8, 46, 22, 44, 12]);
		});

		it('a provider node advertises the overlay with its whole closure', () => {
			const node = track(makeNode({ auxiliaryChannels: auxiliary() }));
			expect(expectWholeOrAbsent(node)).to.equal(true);
			expect(node.getAuxiliaryAdvertisement()).to.deep.equal({
				advertised: true
			});
			const bits = node.getLocalFeatures().listSetBits();
			for (const bit of [8, 13, 23, 45, 47, 181, 2025]) {
				expect(bits).to.include(bit);
			}
		});

		it('no configuration switch takes a dependency away and leaves the overlay', () => {
			const switches: Array<Partial<INodeConfig>> = [
				{ preferAnchors: false },
				{ preferAnchors: true },
				{ preferTaproot: true },
				{ preferTaproot: false },
				{ largeChannels: false },
				{ largeChannels: true },
				{ peerStorageEnabled: false },
				{ peerStorageEnabled: true },
				{ asyncReceiveService: { enabled: true } },
				{ preferAnchors: false, preferTaproot: true, largeChannels: false }
			];
			for (const extra of switches) {
				const node = track(
					makeNode({ ...extra, auxiliaryChannels: auxiliary() })
				);
				expect(expectWholeOrAbsent(node), JSON.stringify(extra)).to.equal(true);
			}
		});

		it('a supplied set that lacks a dependency advertises no overlay, and says why', () => {
			const cases: Array<[Feature, string, Partial<INodeConfig>]> = [
				[Feature.TLV_ONION, 'var_onion_optin (8/9)', {}],
				[Feature.SCID_ALIAS, 'option_scid_alias (46/47)', {}],
				[
					Feature.ANCHOR_ZERO_FEE_HTLC,
					'option_anchors_zero_fee_htlc_tx (22/23)',
					// The node adds anchors back to any set while it prefers them.
					{ preferAnchors: false }
				],
				[Feature.CHANNEL_TYPE, 'option_channel_type (44/45)', {}],
				[Feature.STATIC_REMOTE_KEY, 'option_static_remotekey (12/13)', {}]
			];
			for (const [feature, name, extra] of cases) {
				const supplied = (): FeatureFlags => {
					const flags = LightningNode.defaultFeatures();
					flags.clearBit(feature);
					flags.clearBit(feature + 1);
					return flags;
				};
				const plain = track(makeNode({ ...extra, localFeatures: supplied() }));
				const log = warnings();
				const node = track(
					makeNode({
						...extra,
						localFeatures: supplied(),
						auxiliaryChannels: auxiliary({
							initCustomRecords: new Map([[65539n, Buffer.from('aa', 'hex')]])
						}),
						logger: log.logger
					})
				);
				expect(expectWholeOrAbsent(node), name).to.equal(false);
				// On the wire it is the node its configuration asked for: the
				// bits of the same set without a provider, so no simple
				// taproot either, and simple close stays.
				expect(node.getLocalFeatures().listSetBits(), name).to.deep.equal(
					plain.getLocalFeatures().listSetBits()
				);
				expect(node.getLocalFeatures().listSetBits()).to.not.include(181);
				const advertisement = node.getAuxiliaryAdvertisement();
				expect(advertisement.advertised).to.equal(false);
				const reason = advertisement.advertised ? '' : advertisement.reason;
				expect(reason).to.equal(
					`Asset channels are not advertised: the configured feature set lacks ${name}, which a peer requires of a node that advertises the taproot overlay`
				);
				expect(log.lines).to.deep.equal([reason]);
			}
		});

		it('names every missing dependency, and takes a hand-set overlay bit off', () => {
			const supplied = FeatureFlags.empty();
			supplied.setCompulsory(Feature.TLV_ONION);
			supplied.setOptional(Feature.STATIC_REMOTE_KEY);
			supplied.setBit(2025);
			supplied.setOptional(Feature.OPTION_TAPROOT);
			const node = track(
				makeNode({
					preferAnchors: false,
					localFeatures: supplied,
					auxiliaryChannels: auxiliary()
				})
			);
			expect(expectWholeOrAbsent(node)).to.equal(false);
			const advertisement = node.getAuxiliaryAdvertisement();
			expect(advertisement.advertised ? '' : advertisement.reason).to.equal(
				'Asset channels are not advertised: the configured feature set lacks option_scid_alias (46/47), option_anchors_zero_fee_htlc_tx (22/23), option_channel_type (44/45), which a peer requires of a node that advertises the taproot overlay'
			);
		});

		it('a node without a provider reports that, logs nothing and keeps its bits', () => {
			const log = warnings();
			const node = track(makeNode({ logger: log.logger }));
			expect(node.getAuxiliaryAdvertisement()).to.deep.equal({
				advertised: false,
				reason: 'No auxiliary channel provider is configured'
			});
			expect(node.getLocalFeatures().listSetBits()).to.deep.equal(DEFAULT_BITS);
			expect(log.lines).to.deep.equal([]);
			// A supplied set with the overlay bit and nothing beside it stays
			// as supplied without a provider, as it did before.
			const supplied = FeatureFlags.empty();
			supplied.setOptional(Feature.STATIC_REMOTE_KEY);
			supplied.setBit(2025);
			const bare = track(
				makeNode({ localFeatures: supplied, preferAnchors: false })
			);
			expect(bare.getLocalFeatures().listSetBits()).to.deep.equal([
				13, 19, 65, 2025
			]);
		});
	});

	it('orders chain hashes before init custom records', () => {
		const networks = [crypto.createHash('sha256').update('regtest').digest()];
		const customRecords = new Map([
			[65547n, Buffer.from('later')],
			[65545n, Buffer.from([0, 1, 0x68])]
		]);
		const payload = encodeInitMessage({
			features: FeatureFlags.empty(),
			networks,
			customRecords
		});
		const decoded = decodeInitMessage(payload, { customRecords: true });
		expect(decoded.networks).to.deep.equal(networks);
		expect([...decoded.customRecords!.keys()]).to.deep.equal([65545n, 65547n]);
		expect(decoded.customRecords).to.deep.equal(
			new Map([
				[65545n, Buffer.from([0, 1, 0x68])],
				[65547n, Buffer.from('later')]
			])
		);
		// Without custom records the bytes are what they always were.
		expect(
			encodeInitMessage({ features: FeatureFlags.empty(), networks }).equals(
				encodeInitMessage({
					features: FeatureFlags.empty(),
					networks,
					customRecords: new Map()
				})
			)
		).to.equal(true);
	});

	it('still rejects an unknown even init record above 65535 unless custom records are asked for', () => {
		const even = initWith([[65536n, Buffer.from('asset')]]);
		expect(() => decodeInitMessage(even)).to.throw(
			'Unknown required TLV type: 65536'
		);
		expect(() => decodeInitMessage(even, {})).to.throw(
			'Unknown required TLV type: 65536'
		);
		expect(
			decodeInitMessage(even, { customRecords: true }).customRecords
		).to.deep.equal(new Map([[65536n, Buffer.from('asset')]]));

		// An odd custom record is ignored as before, and is not surfaced.
		const odd = initWith([[65537n, Buffer.from('hint')]]);
		expect(decodeInitMessage(odd).customRecords).to.equal(undefined);
		expect(
			decodeInitMessage(odd, { customRecords: true }).customRecords
		).to.deep.equal(new Map([[65537n, Buffer.from('hint')]]));

		// Below the custom range the unknown-even rule holds in both modes.
		const standard = initWith([[4n, Buffer.from('x')]]);
		expect(() => decodeInitMessage(standard)).to.throw(
			'Unknown required TLV type: 4'
		);
		expect(() => decodeInitMessage(standard, { customRecords: true })).to.throw(
			'Unknown required TLV type: 4'
		);
	});

	it('refuses to encode reserved, malformed and oversized init custom records', () => {
		const features = FeatureFlags.empty();
		for (const type of [1n, 65535n, 1n << 64n]) {
			expect(() =>
				encodeInitMessage({
					features,
					customRecords: new Map([[type, Buffer.alloc(1)]])
				})
			).to.throw('Invalid or reserved Lightning custom record');
		}
		expect(() =>
			encodeInitMessage({
				features,
				customRecords: new Map([[65536n, Buffer.alloc(65533)]])
			})
		).to.throw('BOLT 8 payload limit');
	});

	describe('over a real connection', () => {
		function networked(
			seed: number,
			extra: Partial<INodeConfig> = {}
		): LightningNode {
			return track(
				makeNode({
					nodePrivateKey: Buffer.alloc(32, seed),
					enableNetworking: true,
					...extra
				})
			);
		}
		async function listen(node: LightningNode): Promise<number> {
			await node.listen(0, '127.0.0.1');
			return (
				node.getPeerManager() as unknown as {
					server: { address(): { port: number } };
				}
			).server.address().port;
		}

		/** The plaintext of every packet a peer encrypts while `run` runs. */
		async function sentPackets(run: () => Promise<void>): Promise<Buffer[]> {
			const packets: Buffer[] = [];
			const original = TransportCipher.prototype.encryptPacket;
			TransportCipher.prototype.encryptPacket = function (
				this: TransportCipher,
				payload: Buffer
			): Buffer {
				packets.push(Buffer.from(payload));
				return original.call(this, payload);
			};
			try {
				await run();
			} finally {
				TransportCipher.prototype.encryptPacket = original;
			}
			return packets;
		}
		function withBit(bit: number): FeatureFlags {
			const flags = LightningNode.defaultFeatures();
			flags.setBit(bit);
			return flags;
		}

		it('a node without a provider sends, as its init, the bytes it sent before', async () => {
			// Captured from two such nodes connecting on the code as it stood
			// before asset channels: the whole init message, type included,
			// as each peer handed it to its cipher.
			const before =
				'001000000039800a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a088a8882a8a6182';
			const b = networked(31);
			const a = networked(32);
			const port = await listen(b);
			const packets = await sentPackets(async () => {
				await a.connectPeer(b.getNodeId(), '127.0.0.1', port);
				await new Promise((resolve) => setTimeout(resolve, 200));
			});
			const inits = packets
				.filter((packet) => packet.readUInt16BE(0) === 16)
				.map((packet) => packet.toString('hex'));
			expect(inits).to.deep.equal([before, before]);
		});

		it('a node without a provider ends a handshake over bit 2026 as it did before', async () => {
			// The peer requires 2026. A node that only happens to set 2025
			// does not understand it and disconnects.
			const strict = networked(41, { localFeatures: withBit(2026) });
			const odd2025 = networked(42, { localFeatures: withBit(2025) });
			let error: Error | undefined;
			try {
				await odd2025.connectPeer(
					strict.getNodeId(),
					'127.0.0.1',
					await listen(strict)
				);
			} catch (err) {
				error = err as Error;
			}
			expect(error, 'the handshake fails').to.be.instanceOf(Error);
			expect(error!.message).to.include(
				'Peer requires unsupported features: 2026'
			);

			// A node that sets 2027 answers for 2026, as for any feature.
			const strictToo = networked(43, { localFeatures: withBit(2026) });
			const odd2027 = networked(44, { localFeatures: withBit(2027) });
			await odd2027.connectPeer(
				strictToo.getNodeId(),
				'127.0.0.1',
				await listen(strictToo)
			);
		});

		it('a provider node connects to a peer that requires the overlay', async () => {
			const strict = networked(45, { localFeatures: withBit(2026) });
			const assetNode = networked(46, { auxiliaryChannels: auxiliary() });
			expect(assetNode.getLocalFeatures().hasBit(2025)).to.equal(true);
			await assetNode.connectPeer(
				strict.getNodeId(),
				'127.0.0.1',
				await listen(strict)
			);
		});

		it('a provider node reads the custom records of a peer init, both ways', async () => {
			const theirs = new Map([
				[65536n, Buffer.from('required')],
				[65545n, Buffer.from('optional')]
			]);
			const ours = new Map([[65539n, Buffer.from('ours')]]);
			const a = networked(21, {
				auxiliaryChannels: auxiliary({ initCustomRecords: ours })
			});
			const b = networked(22, {
				auxiliaryChannels: auxiliary({ initCustomRecords: theirs })
			});
			const port = await listen(b);
			await a.connectPeer(b.getNodeId(), '127.0.0.1', port);
			expect(a.getPeerCustomRecords(b.getNodeId())).to.deep.equal(theirs);
			// The value is a copy: changing it does not reach the next read.
			a.getPeerCustomRecords(b.getNodeId()).get(65536n)!.fill(0);
			expect(a.getPeerCustomRecords(b.getNodeId().toUpperCase())).to.deep.equal(
				theirs
			);
			for (let i = 0; i < 100; i++) {
				if (b.getPeerCustomRecords(a.getNodeId()).size > 0) break;
				await new Promise((resolve) => setTimeout(resolve, 20));
			}
			expect(b.getPeerCustomRecords(a.getNodeId())).to.deep.equal(ours);
		});

		it('a node without a provider still fails the handshake on an even custom init record', async () => {
			const b = networked(23, {
				auxiliaryChannels: auxiliary({
					initCustomRecords: new Map([[65536n, Buffer.from('required')]])
				})
			});
			const plain = networked(24);
			const port = await listen(b);
			let error: Error | undefined;
			try {
				await plain.connectPeer(b.getNodeId(), '127.0.0.1', port);
			} catch (err) {
				error = err as Error;
			}
			expect(error, 'the handshake fails').to.be.instanceOf(Error);
			expect(error!.message).to.include('Unknown required TLV type: 65536');
			expect(plain.getPeerCustomRecords(b.getNodeId()).size).to.equal(0);
		});

		it('a node without a provider connects past odd custom init records and does not surface them', async () => {
			const b = networked(25, {
				auxiliaryChannels: auxiliary({
					initCustomRecords: new Map([[65537n, Buffer.from('optional')]])
				})
			});
			const plain = networked(26);
			const port = await listen(b);
			await plain.connectPeer(b.getNodeId(), '127.0.0.1', port);
			expect(plain.getPeerCustomRecords(b.getNodeId()).size).to.equal(0);
		});
	});
});
