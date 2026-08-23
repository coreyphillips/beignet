/**
 * Issue #158: openChannel must select v1 vs v2 from the peer's features.
 *
 * The default feature set advertises option_dual_fund, but openChannel always
 * initiated a v1 open_channel. BOLT 2: once option_dual_fund is negotiated,
 * open_channel must not be used, and dual-fund peers enforce it (CLN:
 * "OPT_DUAL_FUND: cannot use open_channel"). So the default open path,
 * including the dashboard's connect-and-open, failed against any dual-fund
 * peer even though the v2 machinery existed one call away.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { InvalidChannelOpenError } from '../../src/lightning/node/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

function makeBasepoints(): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) keys.push(crypto.randomBytes(32));
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(
	extra: Partial<ConstructorParameters<typeof LightningNode>[0]> = {}
): LightningNode {
	const node = new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		perCommitmentSeed: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(),
		fundingPrivkey: crypto.randomBytes(32),
		localFeatures: LightningNode.defaultFeatures(),
		...extra
	});
	node.on('error', () => {});
	return node;
}

function peerFeatures(dualFund: boolean): FeatureFlags {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.STATIC_REMOTE_KEY);
	if (dualFund) flags.setOptional(Feature.DUAL_FUND);
	return flags;
}

describe('Issue #158: openChannel routes v1 vs v2 by peer features', function () {
	this.timeout(10_000);

	let node: LightningNode;
	let peerPubkey: string;
	let v1Calls: Array<{ fundingSatoshis: bigint; pushMsat?: bigint }>;
	let v2Calls: Array<{
		fundingSatoshis: bigint;
		fundingFeeratePerkw?: number;
	}>;

	function wirePeer(dualFund: boolean, connected = true): void {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const n = node as any;
		n.peerManager = {
			getPeer: (pubkey: string) =>
				connected && pubkey === peerPubkey
					? {
							getRemoteInit: () => ({ features: peerFeatures(dualFund) })
					  }
					: undefined,
			destroy: (): void => {}
		};
		n.channelManager.openChannel = (
			_pubkey: string,
			fundingSatoshis: bigint,
			pushMsat?: bigint
		): { getTemporaryChannelId: () => Buffer } => {
			v1Calls.push({ fundingSatoshis, pushMsat });
			return { getTemporaryChannelId: (): Buffer => crypto.randomBytes(32) };
		};
		n.openChannelV2 = (
			_pubkey: string,
			params: { fundingSatoshis: bigint; fundingFeeratePerkw?: number }
		): { v2: boolean } => {
			v2Calls.push(params);
			return { v2: true };
		};
	}

	beforeEach(function () {
		node = makeNode();
		peerPubkey = crypto.randomBytes(33).toString('hex');
		peerPubkey = '02' + peerPubkey.slice(2); // valid compressed-key prefix
		v1Calls = [];
		v2Calls = [];
	});

	afterEach(function () {
		node.destroy();
	});

	it('routes to open_channel2 when the peer negotiated option_dual_fund', function () {
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n);
		expect(v2Calls.length, 'v2 used').to.equal(1);
		expect(v2Calls[0].fundingSatoshis).to.equal(100_000n);
		expect(v1Calls.length, 'v1 not used').to.equal(0);
	});

	it('keeps v1 for a peer without option_dual_fund', function () {
		wirePeer(false);
		node.openChannel(peerPubkey, 100_000n);
		expect(v1Calls.length, 'v1 used').to.equal(1);
		expect(v2Calls.length, 'v2 not used').to.equal(0);
	});

	it('routes to v1 when the peer is not connected (no init to judge by)', function () {
		// Only the ROUTING decision is under test: the stub stands in for
		// ChannelManager.openChannel, which in real code throws 'Not connected
		// to peer' for an unconnected peer. Nothing is queued for later.
		wirePeer(true, false);
		node.openChannel(peerPubkey, 100_000n);
		expect(v1Calls.length).to.equal(1);
		expect(v2Calls.length).to.equal(0);
	});

	it('converts the caller sat/vB rate to sat/kw for the v2 open', function () {
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n, undefined, 5);
		expect(v2Calls.length).to.equal(1);
		// 1 sat/vB = 250 sat/kw
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(1250);
	});

	it('a v2 open without a caller rate uses the fee estimator, like v1', function () {
		// The v1 path asks the estimator at funding time (handleAutoFunding).
		// v2 cannot defer, since open_channel2 itself carries
		// funding_feerate_perkw, so the estimator's latest sample (the fee
		// advisor) must be pinned at open time. Falling back to the static
		// localConfig feerate here would silently underprice funding during
		// elevated mempool fees.
		wirePeer(true);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).feeAdvisor = { getCurrentRate: (): number => 20 };
		node.openChannel(peerPubkey, 100_000n);
		expect(v2Calls.length).to.equal(1);
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(20 * 250);
	});

	it('clamps an absurdly low caller rate, matching v1 funding', function () {
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n, undefined, 0.1);
		expect(v2Calls.length).to.equal(1);
		// clampFeeRateSatPerVbyte floors at 1 sat/vB = 250 sat/kw
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(250);
	});

	it('clamps an absurdly high caller rate, matching v1 funding', function () {
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n, undefined, 100_000);
		expect(v2Calls.length).to.equal(1);
		// MAX_FEE_RATE_SAT_PER_VBYTE = 5000 sat/vB = 1_250_000 sat/kw
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(1_250_000);
	});

	it('a fresh node with a real fee estimator prices its first v2 open from it', async function () {
		// The invariant behind the estimator test above, WITHOUT mocking the
		// advisor: the constructor seeds the advisor from the estimator, so by
		// the time the node is usable its first dual-funded open carries the
		// estimated, clamped rate rather than falling back to the static
		// configured feerate. This is what a v1 open gets by asking the
		// estimator at funding time.
		const fresh = makeNode({
			feeEstimator: { estimateFee: async (): Promise<number> => 20 }
		});
		// Let the constructor's non-blocking seed land.
		await new Promise((resolve) => setImmediate(resolve));
		const saved = node;
		node = fresh; // reuse wirePeer/afterEach against this node
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n);
		expect(v2Calls.length).to.equal(1);
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(20 * 250);
		saved.destroy();
	});

	it('refuses a v2 open while a configured estimator is still unsampled', function () {
		// "Estimator configured but not yet sampled" must not collapse into
		// the "no estimator" static fallback: that silently underprices the
		// funding tx. The open fails honestly instead; the seed resolves
		// almost immediately in practice and a retry succeeds.
		const fresh = makeNode({
			feeEstimator: {
				estimateFee: (): Promise<number> => new Promise(() => {})
			}
		});
		const saved = node;
		node = fresh;
		wirePeer(true);
		expect(() => node.openChannel(peerPubkey, 100_000n)).to.throw(
			/fee estimate not ready/i
		);
		expect(v2Calls.length).to.equal(0);
		saved.destroy();
	});

	it('leaves the rate unset when neither caller nor estimator has one', function () {
		// openChannelV2 then falls back to the configured commitment feerate,
		// the same last resort the estimator-less v1 path lands on.
		wirePeer(true);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).feeAdvisor = { getCurrentRate: (): number => 0 };
		node.openChannel(peerPubkey, 100_000n);
		expect(v2Calls.length).to.equal(1);
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(undefined);
	});

	it('rejects a push on a dual-funded open with an honest error', function () {
		wirePeer(true);
		expect(() => node.openChannel(peerPubkey, 100_000n, 10_000_000n)).to.throw(
			/push.*open_channel2/i
		);
		expect(v1Calls.length).to.equal(0);
		expect(v2Calls.length).to.equal(0);
	});

	it('the push refusal is typed, so the daemon can answer 400 (issue #464)', function () {
		// An untyped throw is scrubbed to a generic 500 "Internal server
		// error" by the daemon, which hid this message from the caller.
		wirePeer(true);
		try {
			node.openChannel(peerPubkey, 100_000n, 10_000_000n);
			expect.fail('expected the push to be refused');
		} catch (err: unknown) {
			expect(err).to.be.instanceOf(InvalidChannelOpenError);
			expect((err as Error).message).to.include('open_channel2');
		}
	});

	it('types every refusal that is about the caller arguments (issue #464)', function () {
		// No wirePeer: each of these is refused on the arguments alone,
		// before the v1/v2 routing decision needs a peer.
		const refusals: Array<[string, () => unknown]> = [
			['bad pubkey', (): unknown => node.openChannel('not-a-pubkey', 100_000n)],
			['zero funding', (): unknown => node.openChannel(peerPubkey, 0n)],
			[
				'push over funding',
				(): unknown => node.openChannel(peerPubkey, 100n, 1_000_000n)
			],
			[
				'bad fee rate',
				(): unknown =>
					node.openChannel(peerPubkey, 100_000n, undefined, Number.NaN)
			],
			[
				'max without a pinned rate',
				(): unknown =>
					node.openChannel(peerPubkey, 100_000n, undefined, undefined, true)
			],
			[
				'v2 bad pubkey',
				(): unknown =>
					node.openChannelV2('not-a-pubkey', { fundingSatoshis: 100_000n })
			],
			[
				'v2 zero funding',
				(): unknown => node.openChannelV2(peerPubkey, { fundingSatoshis: 0n })
			],
			[
				'v2 lease without a fee ceiling',
				(): unknown =>
					node.openChannelV2(peerPubkey, {
						fundingSatoshis: 100_000n,
						requestFunds: { requestedSats: 50_000n, blockheight: 1 }
					})
			],
			[
				'v2 max with a lease',
				(): unknown =>
					node.openChannelV2(peerPubkey, {
						fundingSatoshis: 100_000n,
						fundMax: true,
						requestFunds: { requestedSats: 50_000n, blockheight: 1 },
						maxLeaseRates: {
							fundingWeightWitness: 500,
							leaseFeeBasis: 100,
							leaseFeeBaseSat: 1000,
							channelFeeMaxBaseMsat: 1000,
							channelFeeMaxProportionalThousandths: 10
						}
					})
			]
		];
		for (const [label, refuse] of refusals) {
			try {
				refuse();
				expect.fail(`expected ${label} to be refused`);
			} catch (err: unknown) {
				expect(err, label).to.be.instanceOf(InvalidChannelOpenError);
			}
		}
		// The trusted-open refusal is the one that needs a peer to judge:
		// this one never negotiated option_zeroconf.
		wirePeer(true);
		try {
			node.openChannel(peerPubkey, 100_000n, undefined, 1, false, true);
			expect.fail('expected the trusted open to be refused');
		} catch (err: unknown) {
			expect(err, 'trusted open').to.be.instanceOf(InvalidChannelOpenError);
		}
	});

	it('a max open toward a dual-fund peer commits the provider v2 quote', function () {
		// The caller's amount is v1 sweep math (actual tx vbytes); a v2
		// initiator pays the interactive-tx weight formula, so the engine
		// recommits the funding provider's own quote at the pinned rate.
		wirePeer(true);
		const quoteCalls: number[] = [];
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).fundingProvider = {
			quoteDualFundingMax: (feeratePerKw: number) => {
				quoteCalls.push(feeratePerKw);
				return {
					fundingSatoshis: 123_456n,
					spendableSats: 125_000n,
					feeSats: 1_544n,
					inputCount: 2
				};
			},
			selectMaxDualFundingInputs: async () => ({
				inputs: [],
				changeScript: Buffer.alloc(0)
			})
		};
		node.openChannel(peerPubkey, 100_000n, undefined, 5, true);
		expect(v2Calls.length, 'v2 used').to.equal(1);
		expect(quoteCalls, 'quoted at the pinned rate in sat/kw').to.deep.equal([
			1250
		]);
		expect(v2Calls[0].fundingSatoshis, 'quote committed').to.equal(123_456n);
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(1250);
		expect(
			(v2Calls[0] as { fundMax?: boolean }).fundMax,
			'max marker forwarded'
		).to.equal(true);
	});

	it('a max open without provider max support fails honestly', function () {
		wirePeer(true);
		expect(() =>
			node.openChannel(peerPubkey, 100_000n, undefined, 5, true)
		).to.throw(/requires a funding provider with quoteDualFundingMax/i);
		expect(v2Calls.length).to.equal(0);
	});

	it('a max open on an empty wallet fails honestly', function () {
		wirePeer(true);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).fundingProvider = {
			quoteDualFundingMax: () => ({
				fundingSatoshis: 0n,
				spendableSats: 100n,
				feeSats: 700n,
				inputCount: 1
			}),
			selectMaxDualFundingInputs: async () => ({
				inputs: [],
				changeScript: Buffer.alloc(0)
			})
		};
		expect(() =>
			node.openChannel(peerPubkey, 100_000n, undefined, 5, true)
		).to.throw(/insufficient funds for a max dual-funded open/i);
		expect(v2Calls.length).to.equal(0);
	});

	it('a max open still requires a pinned rate, v1 and v2 alike', function () {
		wirePeer(true);
		expect(() =>
			node.openChannel(peerPubkey, 100_000n, undefined, undefined, true)
		).to.throw(/max funding requires a pinned satsPerVbyte/i);
		expect(v2Calls.length).to.equal(0);
	});

	it('listChannels names the peer for a v2 channel mid-negotiation', function () {
		// accept_channel2 swaps the temporary id for the derived v2 channel_id,
		// but the peer map keeps the temporary-id key until promotion. The
		// listing must fall back to the temp id — an empty peerPubkey renders
		// in the dashboard as an unknown, offline peer whose Reconnect button
		// sends an empty pubkey.
		const channel = node.openChannelV2(peerPubkey, {
			fundingSatoshis: 100_000n
		});
		channel.getFullState().channelId = crypto.randomBytes(32);
		const infos = node.listChannels();
		expect(infos.length).to.equal(1);
		expect(infos[0].peerPubkey, 'peer resolved via temp id').to.equal(
			peerPubkey
		);
	});

	it('a zero push routes to v2 rather than erroring', function () {
		// pushMsat: 0n expresses "no push"; only an actual push is impossible
		// to represent in open_channel2.
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n, 0n);
		expect(v2Calls.length).to.equal(1);
	});

	it('preferTaproot masks dual_fund globally: v2 refused, generic opens use v1 taproot', function () {
		// Taproot v2 signing does not exist, so a preferTaproot node must
		// never negotiate a v2 open: the configured preference is honored
		// through the working v1 taproot path, never silently downgraded to
		// a non-taproot v2 type. The explicit API refuses outright, and the
		// generic open routes v1 even against a dual-fund-advertising peer.
		const taprootNode = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			perCommitmentSeed: crypto.randomBytes(32),
			channelBasepoints: makeBasepoints(),
			fundingPrivkey: crypto.randomBytes(32),
			localFeatures: LightningNode.defaultFeatures(),
			preferTaproot: true
		});
		taprootNode.on('error', () => {});
		expect(() =>
			taprootNode.openChannelV2(peerPubkey, { fundingSatoshis: 100_000n })
		).to.throw(/does not advertise option_dual_fund/);

		const saved = node;
		node = taprootNode; // reuse wirePeer/afterEach against this node
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n);
		expect(v1Calls.length, 'v1 used: taproot preference preserved').to.equal(1);
		expect(v2Calls.length).to.equal(0);
		saved.destroy();
	});

	it('openChannelV2 with a real peer manager requires a connected, dual-fund peer', function () {
		// The explicit v2 API enforces the SAME negotiated-feature contract
		// as the generic router: with a peer manager attached, a missing
		// peer, an incomplete init, or a peer without the bit all refuse
		// BEFORE a key index is burned or a temp channel is retained.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const cm = (node as any).channelManager;
		cm.peerManager = { getPeer: () => undefined };
		expect(() =>
			node.openChannelV2(peerPubkey, { fundingSatoshis: 100_000n })
		).to.throw(/Not connected to peer/);

		cm.peerManager = {
			getPeer: () => ({ getRemoteInit: () => undefined })
		};
		expect(() =>
			node.openChannelV2(peerPubkey, { fundingSatoshis: 100_000n })
		).to.throw(/has not completed init/);

		cm.peerManager = {
			getPeer: () => ({
				getRemoteInit: () => ({ features: peerFeatures(false) })
			})
		};
		expect(() =>
			node.openChannelV2(peerPubkey, { fundingSatoshis: 100_000n })
		).to.throw(/did not advertise option_dual_fund/);
		expect(node.listChannels(), 'nothing was retained').to.have.length(0);

		// A connected peer advertising the bit (and the commitment-format
		// features the default type needs) passes the guard.
		const rich = peerFeatures(true);
		rich.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
		cm.peerManager = {
			getPeer: () => ({ getRemoteInit: () => ({ features: rich }) })
		};
		const channel = node.openChannelV2(peerPubkey, {
			fundingSatoshis: 100_000n
		});
		expect(channel.getTemporaryChannelId()).to.exist;
	});

	it('does not use v2 when our own features omit option_dual_fund', function () {
		const flags = FeatureFlags.empty();
		flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
		const bare = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			perCommitmentSeed: crypto.randomBytes(32),
			channelBasepoints: makeBasepoints(),
			fundingPrivkey: crypto.randomBytes(32),
			localFeatures: flags
		});
		bare.on('error', () => {});
		const saved = node;
		node = bare; // reuse wirePeer/afterEach against this node
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n);
		expect(v1Calls.length, 'v1 used: dual fund not negotiated by us').to.equal(
			1
		);
		expect(v2Calls.length).to.equal(0);
		saved.destroy();
	});
});
