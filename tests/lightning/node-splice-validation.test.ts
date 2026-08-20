import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	estimateSpliceTxWeight,
	spliceFeeSats
} from '../../src/lightning/channel/splice-weight';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

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

const FUNDING_SATOSHIS = 1_000_000n;

function createTestNode(localFeatures?: FeatureFlags): LightningNode {
	const seed = crypto
		.createHash('sha256')
		.update('splice-validation-node')
		.digest();
	const node = new LightningNode({
		nodePrivateKey: crypto
			.createHash('sha256')
			.update('splice-validation-priv')
			.digest(),
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		network: Network.REGTEST,
		...(localFeatures ? { localFeatures } : {})
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/** Inject a synthetic NORMAL channel directly into the node's manager. */
function injectNormalChannel(node: LightningNode): Buffer {
	const seed = crypto
		.createHash('sha256')
		.update('splice-validation-chan')
		.digest();
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: FUNDING_SATOSHIS,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: seed
	});
	state.channelId = crypto.randomBytes(32);
	state.state = ChannelState.NORMAL;
	state.fundingTxid = crypto.randomBytes(32);
	state.localBalanceMsat = FUNDING_SATOSHIS * 1000n;
	state.remoteBalanceMsat = 0n;
	const channel = new Channel(state);

	const manager = (node as any).channelManager;
	manager.channels.set(state.channelId!.toString('hex'), channel);
	manager.channelPeers.set(
		state.channelId!.toString('hex'),
		'02'.padEnd(66, 'ab')
	);
	return state.channelId!;
}

describe('LightningNode splice validation', function () {
	it('rejects a dust-level splice-out amount', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const result = node.spliceOut(channelId, 500n, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('dust floor');
		node.destroy();
	});

	it('rejects a splice-out whose fee meets or exceeds the amount', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		// At 3000 sat/kw a 724-WU splice-out costs ~2172 sats — more than the
		// 2000 sats withdrawn (a footgun: more burned in fees than withdrawn).
		const result = node.spliceOut(channelId, 2000n, 3000);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('meets or exceeds the amount');
		node.destroy();
	});

	it('rejects a splice-out exceeding the spendable balance', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const result = node.spliceOut(channelId, FUNDING_SATOSHIS, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('insufficient channel balance');
		node.destroy();
	});

	it('passes validation for a sane splice-out (fails later only on missing peer)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const dest = node.getSweepDestinationScript();
		const fee = spliceFeeSats(
			estimateSpliceTxWeight({
				walletInputCount: 0,
				destinationScriptLen: dest.length
			}),
			2500
		);
		expect(fee < 10_000n, 'fee sanity').to.be.true;
		const result = node.spliceOut(channelId, 10_000n, 2500);
		// Validation passed; the splice proceeds (initiateSplice succeeds — the
		// stfu is queued via message:outbound since no peer transport exists).
		expect(result.error ?? '').to.not.include('dust floor');
		expect(result.error ?? '').to.not.include('meets or exceeds');
		expect(result.error ?? '').to.not.include('insufficient channel balance');
		node.destroy();
	});

	it('rejects a dust-level splice-in amount before sourcing wallet inputs', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const result = node.spliceIn(channelId, 100n, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('dust floor');
		node.destroy();
	});

	it('reports a clear error when no splice-capable funding provider exists', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const result = node.spliceIn(channelId, 100_000n, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('selectSpliceInputs');
		node.destroy();
	});

	it('throws when destinationScript is provided but empty', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		expect(() =>
			node.spliceOut(channelId, 10_000n, 2500, Buffer.alloc(0))
		).to.throw('destinationScript must be a non-empty Buffer');
		node.destroy();
	});

	it('records an external destinationScript for splice-out', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		// A P2WPKH scriptPubKey (OP_0 <20-byte hash>) for an address the node
		// does not own, proving splice-out can pay an external destination.
		const externalScript = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			crypto.randomBytes(20)
		]);
		const result = node.spliceOut(channelId, 10_000n, 2500, externalScript);
		expect(result.error ?? '').to.not.include('insufficient channel balance');
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		expect(channel._spliceOutDestination.script.equals(externalScript)).to.be
			.true;
		node.destroy();
	});

	it('enforces the negotiated dust floor on splice-out, not just the generic 546 (issue #389)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		// The peer negotiated a 1000-sat commitment dust limit, so every
		// output we add to the splice tx must clear 1000, not 546 — the
		// withdrawal destination included.
		channel.getFullState().remoteConfig.dustLimitSatoshis = 1_000n;
		expect(channel.spliceInteractiveTxDustFloor()).to.equal(1_000n);

		// 800 sats clears the generic 546-sat preflight but not this
		// channel's floor: the peer would refuse the tx_add_output and the
		// splice would abort only after the stfu round.
		const refused = node.spliceOut(channelId, 800n, 253);
		expect(refused.ok).to.be.false;
		expect(refused.error).to.match(/negotiated dust floor \(1000 sats\)/);

		// At the floor the new preflight admits it; whatever can still fail
		// later, it is never this arm.
		const atFloor = node.spliceOut(channelId, 1_000n, 253);
		expect(atFloor.error ?? '').to.not.include('negotiated dust floor');
		node.destroy();
	});

	it('prices the splice-out reserve at the post-splice capacity (issue #423)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		// Zero the stored reserve so only the derived post-capacity bound can
		// refuse: with 100k local of 1M capacity, withdrawing 92k leaves
		// ~7_816 sats, below 1% of the ~908k post-splice capacity.
		channel.getFullState().remoteConfig.channelReserveSatoshis = 0n;
		channel.getFullState().localBalanceMsat = 100_000_000n;
		channel.getFullState().remoteBalanceMsat = 900_000_000n;

		const refused = node.spliceOut(channelId, 92_000n, 253);
		expect(refused.ok).to.be.false;
		expect(refused.error).to.include('insufficient channel balance');

		// 80k leaves ~19_816 sats, above the ~9_198-sat derived bound: this
		// arm admits it (whatever can still fail later is never this arm).
		const admitted = node.spliceOut(channelId, 80_000n, 253);
		expect(admitted.error ?? '').to.not.include('insufficient channel balance');
		node.destroy();
	});

	it('refuses a splice-in that leaves us below the reserve at the new capacity (issue #423)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		channel.getFullState().localBalanceMsat = 2_000_000n;
		channel.getFullState().remoteBalanceMsat = 998_000_000n;

		// 2k + 3k = 5k post balance, below v2ReserveWeKeep(1_003_000) =
		// 10_030. Refused synchronously, BEFORE the funding-provider check
		// (no provider is configured on this node).
		const refused = node.spliceIn(channelId, 3_000n);
		expect(refused.ok).to.be.false;
		expect(refused.error).to.include('below the channel reserve');

		// 2k + 20k = 22k clears the 10_200-sat bound and falls through to
		// the provider requirement, proving the arm's order.
		const admitted = node.spliceIn(channelId, 20_000n);
		expect(admitted.ok).to.be.false;
		expect(admitted.error).to.include('selectSpliceInputs');
		node.destroy();
	});

	it('spliceQuote reports the derived reserve when the stored one is lower (issue #423)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		channel.getFullState().remoteConfig.channelReserveSatoshis = 0n;
		const quote = node.spliceQuote(channelId, 'out', 253);
		// v2ReserveWeKeep(1_000_000, 354, 354) = 10_000, not the stored 0.
		expect(quote.reserveSats).to.equal(10_000);
		node.destroy();
	});

	it('admits a splice-out exactly at the default 546-sat floor (issue #389)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		// The interactive-tx builder accepts an output AT the floor, so both
		// preflights must too: the generic arm is strict (< 546) and, on a
		// default-dust channel, the negotiated floor IS 546. Anything that
		// still fails later is never a dust arm.
		const atFloor = node.spliceOut(channelId, 546n, 253);
		expect(atFloor.error ?? '').to.not.include('dust floor');
		// One below stays refused.
		const below = node.spliceOut(channelId, 545n, 253);
		expect(below.ok).to.be.false;
		expect(below.error).to.include('below the dust floor');
		node.destroy();
	});
});

describe('LightningNode peerSupportsSplicing', function () {
	const PEER = '02'.padEnd(66, 'ab');
	const withInit = (node: LightningNode, features: FeatureFlags | null) => {
		(node as any).peerManager = {
			getPeer: () =>
				features === null ? undefined : { getRemoteInit: () => ({ features }) },
			destroy: () => {}
		};
	};

	it('is null when there is nothing to read', function () {
		const node = createTestNode();
		expect(node.peerSupportsSplicing(PEER), 'no peer manager yet').to.be.null;
		withInit(node, null);
		expect(node.peerSupportsSplicing(PEER), 'peer not connected').to.be.null;
		node.destroy();
	});

	it('reads the negotiated features, not a guess', function () {
		const node = createTestNode();
		const both = new FeatureFlags();
		both.setOptional(Feature.QUIESCE);
		both.setOptional(Feature.SPLICE);
		withInit(node, both);
		expect(node.peerSupportsSplicing(PEER)).to.be.true;

		// splice without quiesce is not splicing support: stfu is the first
		// message of every splice, so both bits are required, same as the
		// validation this mirrors.
		const spliceOnly = new FeatureFlags();
		spliceOnly.setOptional(Feature.SPLICE);
		withInit(node, spliceOnly);
		expect(node.peerSupportsSplicing(PEER)).to.be.false;

		withInit(node, new FeatureFlags());
		expect(node.peerSupportsSplicing(PEER)).to.be.false;
		node.destroy();
	});

	it('is what the splice pre-flight enforces: an LND-shaped peer refuses', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		// LND advertises neither option_splice nor option_quiesce.
		withInit(node, new FeatureFlags());
		const result = node.spliceIn(channelId, 100_000n, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('not negotiated');
		node.destroy();
	});

	// Negotiation is mutual. localFeatures is caller configuration, so a node
	// configured without splicing must not report a channel spliceable just
	// because the peer across it is willing: the daemon would advertise a
	// capability its own init never offered, and the splice would die at stfu.
	it('is false when the remote is willing but our own features are not', () => {
		const remote = new FeatureFlags();
		remote.setOptional(Feature.QUIESCE);
		remote.setOptional(Feature.SPLICE);

		const noQuiesce = new FeatureFlags();
		noQuiesce.setOptional(Feature.SPLICE);
		const nodeNoQuiesce = createTestNode(noQuiesce);
		withInit(nodeNoQuiesce, remote);
		expect(nodeNoQuiesce.peerSupportsSplicing(PEER)).to.be.false;
		nodeNoQuiesce.destroy();

		const noSplice = new FeatureFlags();
		noSplice.setOptional(Feature.QUIESCE);
		const nodeNoSplice = createTestNode(noSplice);
		withInit(nodeNoSplice, remote);
		expect(nodeNoSplice.peerSupportsSplicing(PEER)).to.be.false;
		nodeNoSplice.destroy();

		// And the default features do negotiate it, so a stock node against a
		// willing peer still answers true.
		const stock = createTestNode();
		withInit(stock, remote);
		expect(stock.peerSupportsSplicing(PEER)).to.be.true;
		stock.destroy();
	});

	// A missing remote init means unknown only when the local half is capable.
	// Local incapability is a certainty no amount of remote information can
	// overturn, so it must not hide behind null while the peer is offline.
	it('local incapability is false even with no remote init to read', () => {
		const spliceOnly = new FeatureFlags();
		spliceOnly.setOptional(Feature.SPLICE);
		const noQuiesce = createTestNode(spliceOnly);
		expect(noQuiesce.peerSupportsSplicing(PEER)).to.be.false;
		noQuiesce.destroy();

		const quiesceOnly = new FeatureFlags();
		quiesceOnly.setOptional(Feature.QUIESCE);
		const noSplice = createTestNode(quiesceOnly);
		expect(noSplice.peerSupportsSplicing(PEER)).to.be.false;
		noSplice.destroy();

		const both = new FeatureFlags();
		both.setOptional(Feature.QUIESCE);
		both.setOptional(Feature.SPLICE);
		const capable = createTestNode(both);
		expect(
			capable.peerSupportsSplicing(PEER),
			'a capable node with no init to read is genuinely unknown'
		).to.be.null;
		capable.destroy();
	});

	it('the pre-flight refuses a splice on local incapability alone', () => {
		const spliceOnly = new FeatureFlags();
		spliceOnly.setOptional(Feature.SPLICE);
		const node = createTestNode(spliceOnly);
		const channelId = injectNormalChannel(node);
		// No peer manager stub at all: the peer is unreachable, and the
		// refusal must not wait to hear from it.
		const result = node.spliceIn(channelId, 100_000n, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('not negotiated');
		node.destroy();
	});
});
