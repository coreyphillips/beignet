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

/**
 * Startup peer recovery under autoReconnect.
 *
 * The PeerManager's disconnect-time redials always answered to the flag; the
 * startup recovery path did not. autoReconnectPeers() dials persisted channel
 * partners directly, on its own timers, so a node started with
 * autoReconnect=false still called its peers back on every start, which is
 * the opposite of what a deliberately parked node wants. These pin the gate,
 * and the half that is easy to lose: the ready lifecycle belongs to this
 * method on every exit, so a gated node must still come up ready.
 */

const PEER = '02'.padEnd(66, 'ab');

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

function createTestNode(autoReconnect: boolean): LightningNode {
	const seed = crypto
		.createHash('sha256')
		.update('auto-reconnect-node')
		.digest();
	const node = new LightningNode({
		nodePrivateKey: crypto
			.createHash('sha256')
			.update('auto-reconnect-priv')
			.digest(),
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		network: Network.REGTEST,
		autoReconnect
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/** A channel parked mid-reestablish, the shape a restart restores. */
function injectReestablishingChannel(node: LightningNode): void {
	const seed = crypto
		.createHash('sha256')
		.update('auto-reconnect-chan')
		.digest();
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: seed
	});
	state.channelId = crypto.randomBytes(32);
	state.state = ChannelState.AWAITING_REESTABLISH;
	state.fundingTxid = crypto.randomBytes(32);
	state.localBalanceMsat = 1_000_000_000n;
	state.remoteBalanceMsat = 0n;
	const channel = new Channel(state);
	const manager = (node as any).channelManager;
	manager.channels.set(state.channelId!.toString('hex'), channel);
	manager.channelPeers.set(state.channelId!.toString('hex'), PEER);
}

/** Wire the stubs the recovery path reads, and a spy on the one thing at stake. */
function armRecovery(node: LightningNode): { dialed: string[] } {
	const dialed: string[] = [];
	(node as any).storage = {
		loadAllPeerAddresses: () => [
			{ pubkey: PEER, host: '203.0.113.9', port: 9735 }
		],
		loadAllAnnouncedPeerAddresses: () => []
	};
	(node as any).peerManager = {
		connectPeer: (pubkey: string) => {
			dialed.push(pubkey);
			return Promise.resolve();
		},
		setAnnouncedAddresses: () => {},
		destroy: () => {}
	};
	return { dialed };
}

const ready = (node: LightningNode): Promise<void> =>
	new Promise((resolve) => node.on('node:ready', () => resolve()));

const sleep = (ms: number): Promise<void> =>
	new Promise((r) => setTimeout(r, ms));

describe('LightningNode startup recovery under autoReconnect', function () {
	it('does not dial persisted channel peers when autoReconnect is false, and still comes up ready', async () => {
		const node = createTestNode(false);
		injectReestablishingChannel(node);
		const { dialed } = armRecovery(node);

		const readyPromise = ready(node);
		(node as any).autoReconnectPeers();
		await readyPromise;
		await sleep(50);

		expect(dialed, 'a parked node calls nobody back').to.deep.equal([]);
		node.destroy();
	});

	it('dials them when autoReconnect is true, the status quo', async () => {
		const node = createTestNode(true);
		injectReestablishingChannel(node);
		const { dialed } = armRecovery(node);

		const readyPromise = ready(node);
		(node as any).autoReconnectPeers();
		await readyPromise;

		expect(dialed).to.deep.equal([PEER]);
		node.destroy();
	});
});
