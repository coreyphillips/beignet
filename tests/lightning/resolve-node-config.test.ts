/**
 * resolveNodeConfig is the one place an INodeConfig default lives. The
 * snapshot below pins every default as it stood when the defaults were
 * gathered there: a change to it is a change to how every node behaves.
 */
import { expect } from 'chai';
import * as bip39 from 'bip39';
import * as configModule from '../../src/lightning/node/config';
import { resolveNodeConfig } from '../../src/lightning/node/config';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import type {
	INodeConfig,
	LightningNodeSeedOptions
} from '../../src/lightning/node/types';
import type { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import type { IChannelConfig } from '../../src/lightning/channel/types';
import { Network } from '../../src/lightning/invoice/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import { noopLogger } from '../../src/logger';
const sinon = require('sinon');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const KEYS = {
	nodePrivateKey: Buffer.alloc(32, 1),
	channelBasepoints: {} as IChannelBasepoints,
	perCommitmentSeed: Buffer.alloc(32, 2),
	fundingPrivkey: Buffer.alloc(32, 3)
};

const DEFAULTS = {
	network: Network.REGTEST,
	enableNetworking: false,
	autoReconnect: false,
	autoReleaseHeldForwards: true,
	resourceConfig: {
		maxCompletedPayments: 10_000,
		completedPaymentTtlMs: 86_400_000,
		cleanupIntervalMs: 60_000
	},
	recovery: { enabled: false, durability: 'async-remote', guardians: [] },
	htlcSafetyMargin: 6,
	forwarding: {
		enabled: true,
		cltvDelta: 40,
		feeBaseMsat: 1000,
		feePropMillionths: 1,
		policyGraceMs: 600_000
	},
	ffor: {
		settle: undefined,
		concurrent: undefined,
		witness: undefined,
		issuer: undefined
	},
	eagerGossipVerify: false,
	cooperativeGraphRestore: false,
	jitReceive: undefined,
	jitReceiveClient: { maxFlatFeeSat: 10_000n, maxFeePpm: 50_000 },
	directFunding: undefined,
	swaps: undefined,
	mppTimeoutMs: 60_000,
	announcedAddresses: [],
	socks5ProxyScope: 'all',
	watchtowers: [],
	preferAnchors: true,
	largeChannels: true,
	peerStorageEnabled: true,
	logger: noopLogger,
	wireTrace: false,
	maxPaymentRetries: 3,
	maxTotalInFlightHtlcs: 1000,
	reestablishTimeoutBlocks: 2016,
	autoUpdateChannelFees: false,
	zeroReserve: { role: 'wallet', advertise: true },
	autoRebalance: {
		enabled: false,
		budgetSatsPerDay: 1000,
		minImbalancePct: 20,
		intervalMs: 3_600_000
	},
	autoTuneFees: {
		enabled: false,
		intervalMs: 21_600_000,
		floorPpm: 1,
		ceilPpm: 10_000
	}
};

describe('resolveNodeConfig', () => {
	it('pins every default', () => {
		expect(resolveNodeConfig({ ...KEYS })).to.deep.equal({
			...KEYS,
			...DEFAULTS
		});
	});

	it('pins the defaults it fills into the subsystem configs', () => {
		const resolved = resolveNodeConfig({
			...KEYS,
			jitReceive: { enabled: true },
			ffor: { witness: { enabled: true } },
			directFunding: {},
			swaps: { enabled: true }
		});
		expect(resolved.jitReceive).to.deep.equal({
			enabled: true,
			holdExpiryMarginBlocks: 18
		});
		expect(resolved.ffor.witness).to.deep.equal({
			enabled: true,
			safetyDelta: 19
		});
		expect(resolved.directFunding).to.deep.equal({ requestTtlMs: 3_600_000 });
		expect(resolved.swaps).to.deep.equal({
			enabled: true,
			exposure: {
				minSwapSat: 10_000n,
				maxSwapSat: 1_000_000n,
				maxTotalExposureSat: 5_000_000n,
				maxConcurrentSwaps: 8,
				feeReserveSat: 50_000n,
				fundingFeeRateCeilingSatPerVbyte: 200
			},
			confirmations: { fundingConfirmations: 1, resolutionConfirmations: 3 }
		});
		// A JIT LSP is a primary, which keeps its own reserve and does not
		// advertise zero-reserve unless it waives its clients'.
		expect(resolved.zeroReserve).to.deep.equal({
			role: 'primary',
			advertise: false
		});
	});

	it('derives the HTLC margins from a larger htlcSafetyMargin', () => {
		const resolved = resolveNodeConfig({
			...KEYS,
			htlcSafetyMargin: 30,
			jitReceive: { enabled: true },
			ffor: { witness: { enabled: true } }
		});
		expect(resolved.jitReceive?.holdExpiryMarginBlocks).to.equal(30);
		expect(resolved.ffor.witness?.safetyDelta).to.equal(31);
	});

	it('resolves the zero-reserve role and advertisement', () => {
		expect(
			resolveNodeConfig({ ...KEYS, zeroReserve: { waiveClientReserve: true } })
				.zeroReserve
		).to.deep.equal({
			role: 'primary',
			advertise: true,
			waiveClientReserve: true
		});
		expect(
			resolveNodeConfig({ ...KEYS, zeroReserve: { advertise: false } })
				.zeroReserve
		).to.deep.equal({ role: 'wallet', advertise: false });
	});

	it('defaults autoReconnect to enableNetworking', () => {
		expect(
			resolveNodeConfig({ ...KEYS, enableNetworking: true }).autoReconnect
		).to.equal(true);
		expect(
			resolveNodeConfig({
				...KEYS,
				enableNetworking: true,
				autoReconnect: false
			}).autoReconnect
		).to.equal(false);
	});

	it('neither changes nor freezes its input, and freezes its result', () => {
		const input: INodeConfig = {
			...KEYS,
			forwarding: { cltvDelta: 80 },
			autoRebalance: { enabled: true },
			announcedAddresses: [
				{ type: 4, host: 'x.onion', port: 9735 },
				{ type: 1, host: '1.2.3.4', port: 9735 }
			]
		};
		const resolved = resolveNodeConfig(input);
		expect(input.forwarding).to.deep.equal({ cltvDelta: 80 });
		expect(input.autoRebalance).to.deep.equal({ enabled: true });
		expect(input.announcedAddresses!.map((a) => a.type)).to.deep.equal([4, 1]);
		expect(Object.isFrozen(input)).to.equal(false);
		expect(Object.isFrozen(input.forwarding)).to.equal(false);
		expect(Object.isFrozen(input.autoRebalance)).to.equal(false);

		expect(resolved.announcedAddresses.map((a) => a.type)).to.deep.equal([
			1, 4
		]);
		for (const value of [
			resolved,
			resolved.forwarding,
			resolved.ffor,
			resolved.recovery,
			resolved.resourceConfig,
			resolved.jitReceiveClient,
			resolved.zeroReserve,
			resolved.autoRebalance,
			resolved.autoTuneFees
		]) {
			expect(Object.isFrozen(value)).to.equal(true);
		}
	});

	it('folds the deprecated flat names into their groups', () => {
		const settle = { enabled: true };
		const witness = { enabled: true };
		const issuer = { enabled: true };
		const resolved = resolveNodeConfig({
			...KEYS,
			forwardingEnabled: false,
			forwardingCltvDelta: 80,
			forwardingFeeBaseMsat: 2000,
			forwardingFeePropMillionths: 50,
			forwardingPolicyGraceMs: 0,
			fforSettle: settle,
			fforConcurrent: { enabled: false },
			fforWitness: witness,
			fforIssuer: issuer
		});
		expect(resolved.forwarding).to.deep.equal({
			enabled: false,
			cltvDelta: 80,
			feeBaseMsat: 2000,
			feePropMillionths: 50,
			policyGraceMs: 0
		});
		expect(resolved.ffor.settle).to.equal(settle);
		expect(resolved.ffor.concurrent).to.deep.equal({ enabled: false });
		expect(resolved.ffor.witness).to.deep.equal({
			enabled: true,
			safetyDelta: 19
		});
		expect(resolved.ffor.issuer).to.equal(issuer);
		for (const flat of [
			'forwardingEnabled',
			'forwardingCltvDelta',
			'forwardingFeeBaseMsat',
			'forwardingFeePropMillionths',
			'forwardingPolicyGraceMs',
			'fforSettle',
			'fforConcurrent',
			'fforWitness',
			'fforIssuer'
		]) {
			expect(resolved).not.to.have.property(flat);
		}
	});

	it('lets the nested form win over a flat name', () => {
		const resolved = resolveNodeConfig({
			...KEYS,
			forwardingCltvDelta: 80,
			forwardingFeeBaseMsat: 2000,
			forwarding: { cltvDelta: 144 },
			fforConcurrent: { enabled: false },
			ffor: { concurrent: { enabled: true } }
		});
		expect(resolved.forwarding.cltvDelta).to.equal(144);
		expect(resolved.forwarding.feeBaseMsat).to.equal(2000);
		expect(resolved.ffor.concurrent).to.deep.equal({ enabled: true });
	});
});

describe('LightningNode.fromMnemonic options', () => {
	const nodes: LightningNode[] = [];
	afterEach(() => {
		sinon.restore();
		for (const node of nodes.splice(0)) node.destroy();
	});

	it('hands every non-key option to the constructor unchanged', () => {
		// A Record over every key, so a new INodeConfig option fails to
		// compile here until it is listed.
		const given: Record<keyof LightningNodeSeedOptions, unknown> = {
			auxiliaryChannels: undefined,
			nativeTaprootFunding: undefined,
			zeroReserve: undefined,
			network: undefined,
			channelConfig: undefined,
			signerFactory: undefined,
			fundingProvider: undefined,
			enableNetworking: undefined,
			localFeatures: undefined,
			chainHashes: undefined,
			autoReconnect: undefined,
			autoReleaseHeldForwards: undefined,
			asyncReceiveService: undefined,
			ffor: undefined,
			fforWitness: undefined,
			fforIssuer: undefined,
			fforSettle: undefined,
			fforConcurrent: undefined,
			maxReconnectDelay: undefined,
			maxInboundPeers: undefined,
			resourceConfig: undefined,
			storage: undefined,
			guardianHost: undefined,
			recovery: undefined,
			chainBackend: undefined,
			htlcSafetyMargin: undefined,
			forwarding: undefined,
			forwardingEnabled: undefined,
			eagerGossipVerify: undefined,
			cooperativeGraphRestore: undefined,
			jitReceive: undefined,
			jitReceiveClient: undefined,
			directFunding: undefined,
			swaps: undefined,
			forwardingCltvDelta: undefined,
			forwardingFeeBaseMsat: undefined,
			forwardingFeePropMillionths: undefined,
			forwardingPolicyGraceMs: undefined,
			mppTimeoutMs: undefined,
			alias: undefined,
			announcedAddresses: undefined,
			socks5Proxy: undefined,
			socks5ProxyScope: undefined,
			webSocketImpl: undefined,
			iroh: undefined,
			watchtowers: undefined,
			preferAnchors: undefined,
			largeChannels: undefined,
			preferTaproot: undefined,
			leaseRates: undefined,
			peerStorageEnabled: undefined,
			feeEstimator: undefined,
			logger: undefined,
			wireTrace: undefined,
			maxPaymentRetries: undefined,
			maxTotalInFlightHtlcs: undefined,
			quiescenceTimeoutMs: undefined,
			nextChannelIndex: undefined,
			channelKeyDeriver: undefined,
			newChannelsRefused: undefined,
			rateLimitConfig: undefined,
			reestablishTimeoutBlocks: undefined,
			autoUpdateChannelFees: undefined,
			sweepDestinationScript: undefined,
			autoRebalance: undefined,
			autoTuneFees: undefined,
			passphrase: undefined,
			seed: undefined,
			coinType: undefined
		};
		const derivation = new Set(['passphrase', 'seed', 'coinType', 'iroh']);
		const options: Record<string, unknown> = {
			seed: bip39.mnemonicToSeedSync(MNEMONIC),
			coinType: 1,
			iroh: { relays: ['sentinel'] }
		};
		for (const key of Object.keys(given)) {
			if (!derivation.has(key)) options[key] = { sentinel: key };
		}

		const seen: INodeConfig[] = [];
		sinon
			.stub(configModule, 'resolveNodeConfig')
			.callsFake((input: INodeConfig) => {
				seen.push(input);
				throw new Error('captured');
			});
		expect(() =>
			LightningNode.fromMnemonic(
				MNEMONIC,
				options as unknown as LightningNodeSeedOptions
			)
		).to.throw('captured');

		const input = seen[0] as unknown as Record<string, unknown>;
		for (const key of Object.keys(given)) {
			if (derivation.has(key)) continue;
			expect(input[key], key).to.equal(options[key]);
		}
		for (const key of ['passphrase', 'seed', 'coinType']) {
			expect(input, key).not.to.have.property(key);
		}
		const iroh = input.iroh as { relays: string[]; secretKey: Uint8Array };
		expect(iroh.relays).to.deep.equal(['sentinel']);
		expect(iroh.secretKey).to.have.length(32);
	});

	it('advertises the required simple Taproot dependency for asset overlays', () => {
		const node = LightningNode.fromMnemonic(MNEMONIC, {
			auxiliaryChannels: {
				provider: {} as IChannelAuxiliaryProvider,
				resolveIncoming: () => undefined
			}
		});
		nodes.push(node);
		const flags = node.getLocalFeatures();
		expect(flags.listSetBits()).to.include(181);
		expect(flags.listSetBits()).to.include(2025);
		expect(flags.hasFeature(Feature.STATIC_REMOTE_KEY)).to.equal(true);
		expect(flags.hasFeature(Feature.ANCHOR_ZERO_FEE_HTLC)).to.equal(true);
	});

	it('advertises asset custody only when its concurrent round protocol is enabled', () => {
		for (const enabled of [false, true]) {
			const node = LightningNode.fromMnemonic(MNEMONIC, {
				ffor: { concurrent: { enabled } },
				auxiliaryChannels: {
					provider: {
						validateFforAssetTerms: () => undefined
					} as unknown as IChannelAuxiliaryProvider,
					resolveIncoming: () => undefined
				}
			});
			nodes.push(node);
			expect(
				node.getLocalFeatures().hasFeature(Feature.OPTION_FF_ASSET)
			).to.equal(enabled);
		}
	});

	it('advertises revoked-child custody only with explicit authority and bounded fee capability', () => {
		for (const enabled of [false, true])
			for (const fees of [false, true]) {
				const features = FeatureFlags.empty();
				features.setOptional(Feature.OPTION_ASSET_CHILD_CUSTODY);
				const node = LightningNode.fromMnemonic(MNEMONIC, {
					localFeatures: features,
					auxiliaryChannels: {
						allowRevokedChildCustody: enabled,
						provider: {
							prepareRevokedChild: () => Buffer.from('capsule')
						} as unknown as IChannelAuxiliaryProvider,
						resolveIncoming: () => undefined
					},
					fundingProvider: {
						supportsFixedOutputFees: () => fees,
						buildFundingTransaction: async () => {
							throw new Error('unused funding');
						},
						broadcastTransaction: async () => ''
					}
				});
				nodes.push(node);
				expect(
					node.getLocalFeatures().hasFeature(Feature.OPTION_ASSET_CHILD_CUSTODY)
				).equal(enabled && fees);
			}
		expect(() =>
			LightningNode.fromMnemonic(MNEMONIC, {
				auxiliaryChannels: {
					allowRevokedChildCustody: true,
					provider: {} as IChannelAuxiliaryProvider,
					resolveIncoming: () => undefined
				}
			})
		).to.throw('capsule provider');
	});

	it('applies the options it used to drop', () => {
		const channelConfig: IChannelConfig = {
			dustLimitSatoshis: 546n,
			maxHtlcValueInFlightMsat: 1_000_000_000n,
			channelReserveSatoshis: 20_000n,
			htlcMinimumMsat: 2_000n,
			toSelfDelay: 288,
			maxAcceptedHtlcs: 100,
			feeratePerKw: 1000
		};
		const node = LightningNode.fromMnemonic(MNEMONIC, {
			channelConfig,
			autoReleaseHeldForwards: false,
			asyncReceiveService: { enabled: true },
			resourceConfig: { maxCompletedPayments: 7 },
			htlcSafetyMargin: 12,
			forwardingPolicyGraceMs: 5,
			mppTimeoutMs: 1234,
			preferTaproot: true,
			maxPaymentRetries: 9,
			maxTotalInFlightHtlcs: 42,
			quiescenceTimeoutMs: 777,
			rateLimitConfig: { maxHtlcsPerSecond: 5, burstMultiplier: 3 },
			reestablishTimeoutBlocks: 100
		});
		nodes.push(node);
		const internals = node as unknown as {
			channelManager: {
				config: { localConfig: IChannelConfig; quiescenceTimeoutMs: number };
			};
			autoReleaseHeldForwards: boolean;
			resourceConfig: { maxCompletedPayments: number };
			htlcSafetyMargin: number;
			forwardingPolicyGraceMs: number;
			mppTimeoutMs: number;
			maxPaymentRetries: number;
			maxTotalInFlightHtlcs: number;
			rateLimiter: { maxTokens: number };
			reestablishTimeoutBlocks: number;
			localFeatures: { hasFeature(f: Feature): boolean };
		};
		expect(internals.channelManager.config.localConfig).to.equal(channelConfig);
		expect(internals.channelManager.config.quiescenceTimeoutMs).to.equal(777);
		expect(internals.autoReleaseHeldForwards).to.equal(false);
		expect(internals.resourceConfig.maxCompletedPayments).to.equal(7);
		expect(internals.htlcSafetyMargin).to.equal(12);
		expect(internals.forwardingPolicyGraceMs).to.equal(5);
		expect(internals.mppTimeoutMs).to.equal(1234);
		expect(internals.maxPaymentRetries).to.equal(9);
		expect(internals.maxTotalInFlightHtlcs).to.equal(42);
		expect(internals.rateLimiter.maxTokens).to.equal(15);
		expect(internals.reestablishTimeoutBlocks).to.equal(100);
		expect(internals.localFeatures.hasFeature(Feature.DUAL_FUND)).to.equal(
			false
		);
		expect(
			internals.localFeatures.hasFeature(Feature.ASYNC_RECEIVE_SERVICE)
		).to.equal(true);
	});
});
