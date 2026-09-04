/**
 * FFOR Variant D over a real peer connection: two LightningNodes with
 * networking enabled, a TCP loopback socket between them, and the FFOR
 * messages carried by the PeerManager's registered channel-message handlers
 * (the production path, not a direct handleMessage call): ff_init through
 * ff_activate_ack, then ff_close through ff_close_ack.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature } from '../../src/lightning/features/flags';
import { MessageType } from '../../src/lightning/message/types';
import { FforState } from '../../src/lightning/ffor/types';

function sha(...parts: (Buffer | string)[]): Buffer {
	const h = crypto.createHash('sha256');
	for (const p of parts) h.update(p);
	return h.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const k = (i: number): Buffer => getPublicKey(sha(seed, Buffer.from([i])));
	return {
		fundingPubkey: k(0),
		revocationBasepoint: k(1),
		paymentBasepoint: k(2),
		delayedPaymentBasepoint: k(3),
		htlcBasepoint: k(4),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(seedId: number): LightningNode {
	const seed = sha(`ffor-d-net-${seedId}`);
	const features = LightningNode.defaultFeatures();
	features.clearBit(Feature.DUAL_FUND + 1);
	const config: INodeConfig = {
		nodePrivateKey: sha(seed, 'node-identity'),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: sha(seed, 'per-commitment'),
		fundingPrivkey: sha(seed, Buffer.from([0])),
		htlcBasepointSecret: sha(seed, Buffer.from([4])),
		enableNetworking: true,
		// A v1 open: with option_dual_fund on both sides the open would take
		// the interactive-tx path, which this test does not drive.
		localFeatures: features
	};
	const node = new LightningNode(config);
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

async function waitFor(
	cond: () => boolean,
	label: string,
	timeoutMs = 15_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!cond()) {
		if (Date.now() > deadline)
			throw new Error(`Timed out waiting for ${label}`);
		await new Promise((r) => setTimeout(r, 25));
	}
}

const TIP = 790_000;

describe('FFOR Variant D over a real PeerManager connection', function () {
	this.timeout(60_000);

	it('carries ff_init to ff_activate_ack and ff_close to ff_close_ack over TCP', async () => {
		const s = makeNode(1);
		const r = makeNode(2);
		try {
			await s.listen(0, '127.0.0.1');
			const port = (
				s.getPeerManager() as unknown as {
					server: { address(): { port: number } };
				}
			).server.address().port;
			// Every message each PeerManager delivers, by type.
			const atS: number[] = [];
			const atR: number[] = [];
			s.getPeerManager()!.on('message', (_pk: string, type: number) =>
				atS.push(type)
			);
			r.getPeerManager()!.on('message', (_pk: string, type: number) =>
				atR.push(type)
			);

			await r.connectPeer(s.getNodeId(), '127.0.0.1', port);
			await waitFor(() => s.listPeers().length === 1, 'S sees R');

			// Channel open over the socket: S funds.
			const accepted = new Promise<void>((resolve) => {
				s.getChannelManager().once('channel:accepted', () => resolve());
			});
			const channel = s.openChannel(r.getNodeId(), 1_000_000n);
			await accepted;
			const channelId = s.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			)!;
			await waitFor(() => {
				const chs = r.getChannelManager().listChannels();
				return chs.length === 1 && chs[0].getChannelId() !== null;
			}, 'R channel funded');
			await waitFor(
				() =>
					s.getChannel(channelId)?.state ===
					ChannelState.AWAITING_FUNDING_CONFIRMED,
				'S funding signed'
			);
			s.handleFundingConfirmed(channelId);
			r.handleFundingConfirmed(channelId);
			await waitFor(
				() =>
					s.getChannel(channelId)?.state === ChannelState.NORMAL &&
					r.getChannelManager().listChannels()[0].getState() ===
						ChannelState.NORMAL,
				'channel NORMAL both sides'
			);
			s.handleNewBlock(TIP);
			r.handleNewBlock(TIP);
			const srHex = channelId.toString('hex');

			// Setup and activation over the wire.
			const res = r.startFforEpoch(srHex, {
				voucherAmountsMsat: [1_000_000n, 2_000_000n],
				minPaymentMsat: 400_000n,
				settlementDeadline: 798_992,
				voucherExpiry: 800_000,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 5000
			});
			expect(res.ok, res.error).to.equal(true);
			await waitFor(
				() =>
					s.getFforEpoch(srHex)?.state === FforState.ACTIVE &&
					r.getFforEpoch(srHex)?.state === FforState.ACTIVE,
				'both ACTIVE'
			);
			expect(atS).to.include(MessageType.FF_INIT);
			expect(atS).to.include(MessageType.FF_ACTIVATE);
			expect(atR).to.include(MessageType.FF_ACCEPT);
			expect(atR).to.include(MessageType.FF_ACTIVATE_ACK);
			expect(s.getFforEpoch(srHex)!.hAct!.equals(r.getFforEpoch(srHex)!.hAct!))
				.to.be.true;

			// Close and drain over the wire.
			const closed = r.closeFforEpoch(srHex);
			expect(closed.ok, closed.error).to.equal(true);
			await waitFor(
				() =>
					s.getFforEpoch(srHex)?.state === FforState.CLOSED &&
					r.getFforEpoch(srHex)?.state === FforState.CLOSED,
				'both CLOSED'
			);
			expect(atS).to.include(MessageType.FF_CLOSE);
			expect(atR).to.include(MessageType.FF_CLOSE_ACK);
			expect(s.getChannel(channelId)?.state).to.equal(ChannelState.NORMAL);
			expect(
				r.getChannelManager().listChannels()[0].getFullState().htlcs.size
			).to.equal(0);
		} finally {
			s.destroy();
			r.destroy();
		}
	});
});
