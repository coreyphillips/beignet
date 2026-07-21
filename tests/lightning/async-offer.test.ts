/**
 * M2.4 — BOLT 12 async offer construction.
 *
 * createOffer({ asyncHold: true }) must build a blinded path through the node's
 * LSP (channel peer) whose introduction hop is marked hold_htlc, so the LSP
 * parks an inbound HTLC for the (offline) receiver. We verify by decrypting the
 * introduction hop with the LSP's key — exactly what the LSP does on a forward.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { processBlindedHop } from '../../src/lightning/onion/blinded-path';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';

function validPriv(): Buffer {
	let k: Buffer;
	do {
		k = crypto.randomBytes(32);
	} while (!secp.utils.isValidPrivateKey(k));
	return k;
}

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
	};
}

describe('BOLT 12 async offer (M2.4)', function () {
	it('marks the LSP introduction hop hold_htlc', function () {
		const node = new LightningNode({
			nodePrivateKey: validPriv(),
			channelBasepoints: makeBasepoints(),
			perCommitmentSeed: crypto.randomBytes(32),
			fundingPrivkey: validPriv(),
			network: Network.REGTEST
		});
		node.on('error', () => {});

		// Inject a NORMAL channel to an LSP peer (whose privkey we keep to decrypt).
		const lspPriv = validPriv();
		const lspPubkey = getPublicKey(lspPriv);
		const scid = encodeShortChannelId({
			block: 800000,
			txIndex: 5,
			outputIndex: 0
		});
		const channelId = crypto.randomBytes(32);
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints: makeBasepoints(),
			localPerCommitmentSeed: crypto.randomBytes(32)
		});
		state.state = ChannelState.NORMAL;
		state.channelId = channelId;
		// The SCID a peer resolves is the alias the PEER generated and sent us,
		// which we store as remoteScidAlias (BOLT 2). A real channel_ready exchange
		// populates this; injecting only our own scidAlias would not.
		state.remoteScidAlias = scid;
		const cm = (node as any).channelManager;
		cm.channels.set(channelId.toString('hex'), new Channel(state));
		cm.channelPeers.set(channelId.toString('hex'), lspPubkey.toString('hex'));

		const { offer } = node.createOffer({
			description: 'async coffee',
			asyncHold: true
		});

		expect(offer.paths, 'offer carries a blinded path').to.have.length(1);
		const path = offer.paths![0];
		// Introduction node is the LSP, not us.
		expect(path.introductionNodeId).to.deep.equal(lspPubkey);
		expect(path.introductionNodeId).to.not.deep.equal(
			Buffer.from(node.getNodeId(), 'hex')
		);

		// The LSP decrypts its hop and sees hold_htlc + where to forward (us).
		const { hopData } = processBlindedHop(
			path.blindingPoint,
			lspPriv,
			path.blindedHops[0].encryptedData
		);
		expect(hopData.holdHtlc, 'LSP hop is marked hold_htlc').to.equal(true);
		expect(hopData.nextNodeId).to.deep.equal(
			Buffer.from(node.getNodeId(), 'hex')
		);
		expect(hopData.shortChannelId).to.deep.equal(scid);

		node.destroy();
	});

	it('does not mark hold_htlc for a normal offer', function () {
		const node = new LightningNode({
			nodePrivateKey: validPriv(),
			channelBasepoints: makeBasepoints(),
			perCommitmentSeed: crypto.randomBytes(32),
			fundingPrivkey: validPriv(),
			network: Network.REGTEST
		});
		node.on('error', () => {});

		// A normal offer with no channels has no auto-built path.
		const { offer } = node.createOffer({ description: 'plain' });
		expect(offer.paths ?? []).to.have.length(0);

		node.destroy();
	});
});
