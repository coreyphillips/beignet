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

function createTestNode(): LightningNode {
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
		network: Network.REGTEST
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
});
