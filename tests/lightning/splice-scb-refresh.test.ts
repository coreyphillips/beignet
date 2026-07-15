/**
 * Regression (FS-7): the node must re-emit an outward splice:complete event when
 * a splice LOCKS, so the embedder can refresh its static channel backup while
 * fundingTxid holds the NEW outpoint.
 *
 * The CLI previously refreshed the SCB at splice INITIATION (fundingTxid still
 * the old outpoint), and the splice:complete handler did not surface an event to
 * refresh again. A restore then watched the spent pre-splice outpoint and missed
 * the peer's force-close on the new one. This asserts the node surfaces the
 * event with the post-splice outpoint.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const k: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		k.push(
			getPublicKey(
				crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from([i]))
					.digest()
			)
		);
	}
	return {
		fundingPubkey: k[0],
		revocationBasepoint: k[1],
		paymentBasepoint: k[2],
		delayedPaymentBasepoint: k[3],
		htlcBasepoint: k[4],
		firstPerCommitmentPoint: k[5]
	};
}

describe('FS-7: splice:complete refreshes the SCB with the new outpoint', () => {
	it('re-emits splice:complete outward carrying the post-splice fundingTxid', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		const {
			createOpenerState
		} = require('../../src/lightning/channel/channel-state');
		const { Channel } = require('../../src/lightning/channel/channel');
		const {
			ChannelState,
			DEFAULT_CHANNEL_CONFIG
		} = require('../../src/lightning/channel/types');

		const basepoints = makeBasepoints(crypto.randomBytes(32));
		const node = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			channelBasepoints: basepoints,
			perCommitmentSeed: crypto.randomBytes(32),
			fundingPrivkey: crypto.randomBytes(32)
		});
		node.on('node:error', () => {});

		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints: basepoints,
			localPerCommitmentSeed: crypto.randomBytes(32)
		});
		state.state = ChannelState.NORMAL;
		state.channelId = crypto.randomBytes(32);
		// The splice has LOCKED, so fundingTxid already holds the NEW outpoint.
		const newFundingTxid = crypto.randomBytes(32);
		state.fundingTxid = newFundingTxid;
		state.fundingOutputIndex = 0;
		state.remoteBasepoints = makeBasepoints(crypto.randomBytes(32));
		const channel = new Channel(state);
		node.getChannelManager().restoreChannel(channel, 'cd'.repeat(33));

		let emitted: { channelId: Buffer; fundingTxid?: Buffer } | null = null;
		node.on(
			'splice:complete',
			(data: { channelId: Buffer; fundingTxid?: Buffer }) => {
				emitted = data;
			}
		);

		// The channel manager signals the splice locked.
		node.getChannelManager().emit('splice:complete', state.channelId);

		expect(emitted, 'node surfaced splice:complete outward').to.not.be.null;
		expect(emitted!.channelId.equals(state.channelId)).to.equal(true);
		expect(
			emitted!.fundingTxid?.equals(newFundingTxid),
			'the event carries the post-splice outpoint'
		).to.equal(true);

		node.destroy();
	});
});
