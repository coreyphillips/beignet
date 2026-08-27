/**
 * Interop: a live CLN relays a LARGE onion message (BOLT 4 32834-byte
 * form) between two beignet nodes (issue #552, LFBW port #532
 * workstream 2A).
 *
 * Topology: B1 -> CLN -> B2, where B1 and B2 are never connected to
 * each other, so delivery is only possible if lightningd accepts the
 * 32834-byte packet and forwards it at the same size. B1 builds a
 * blinded path [CLN, B2] with CLN as the introduction node and sends a
 * TLV payload too large for the 1366-byte standard form; the reply leg
 * runs the same relay in reverse over a [CLN, B1] reply path.
 *
 * Onion messaging is channel-less by design and lightningd v26 relays
 * between directly connected peers, so no channels are funded here.
 *
 * Requires the `cln` container; auto-skips otherwise.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	waitFor,
	sleep,
	CLN_P2P_HOST,
	CLN_P2P_PORT
} from './cln-helpers';
import { bitcoinRpc, TEST_MNEMONIC } from './shared-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { REGTEST_CHAIN_HASH } from '../../../src/lightning/channel/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import { constructBlindedPath } from '../../../src/lightning/onion/blinded-path';
import { LARGE_ONION_PACKET_LENGTH } from '../../../src/lightning/onion/types';

const LARGE_WIRE_LENGTH = 33 + 2 + LARGE_ONION_PACKET_LENGTH;

function buildNode(passphrase: string): LightningNode {
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		passphrase,
		LnCoinType.REGTEST
	);
	const features = FeatureFlags.empty();
	features.setOptional(Feature.DATA_LOSS_PROTECT);
	features.setOptional(Feature.STATIC_REMOTE_KEY);
	features.setOptional(Feature.PAYMENT_SECRET);
	features.setOptional(Feature.TLV_ONION);
	features.setOptional(Feature.CHANNEL_TYPE);
	features.setOptional(Feature.GOSSIP_QUERIES);
	features.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	features.setOptional(Feature.ONION_MESSAGES);
	features.setOptional(Feature.ROUTE_BLINDING);
	return new LightningNode({
		nodePrivateKey: keys.nodePrivateKey,
		channelBasepoints: keys.channelBasepoints,
		perCommitmentSeed: keys.perCommitmentSeed,
		fundingPrivkey: keys.fundingPrivkey,
		htlcBasepointSecret: keys.htlcBasepointSecret,
		paymentBasepointSecret: keys.paymentBasepointSecret,
		revocationBasepointSecret: keys.revocationBasepointSecret,
		delayedPaymentBasepointSecret: keys.delayedPaymentBasepointSecret,
		network: Network.REGTEST,
		enableNetworking: true,
		localFeatures: features,
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true
	});
}

describe('Interop: CLN relays a large onion message', function () {
	this.timeout(300_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let skipAll = false;
	let b1: LightningNode | undefined;
	let b2: LightningNode | undefined;

	before(async function () {
		this.timeout(120_000);
		if (!(await isClnAvailable())) {
			skipAll = true;
			console.log('    [skip] CLN container not reachable');
			this.skip();
			return;
		}
		cln = (await createClnClient())!;
		await waitForClnSync(cln);
		const info = (await cln.getInfo()) as unknown as { id: string };
		clnPubkey = info.id;
	});

	after(function () {
		for (const node of [b1, b2]) {
			if (!node) continue;
			try {
				node.disconnectPeer(clnPubkey);
			} catch {
				/* ignore */
			}
			try {
				node.destroy();
			} catch {
				/* ignore */
			}
		}
	});

	it('delivers a 32834-byte onion B1 -> CLN -> B2 and a large reply back', async function () {
		if (skipAll) this.skip();

		const salt = Date.now() % 100000;
		b1 = buildNode(`cln-large-om-b1-${salt}`);
		b2 = buildNode(`cln-large-om-b2-${salt}`);
		for (const node of [b1, b2]) {
			node.on('node:error', (e: { code?: string; message?: string }) => {
				console.log(`    [node:error] ${e.code}: ${e.message}`);
			});
		}
		const tip = (await bitcoinRpc('getblockcount', [])) as number;
		b1.handleNewBlock(tip);
		b2.handleNewBlock(tip);
		await b1.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await b2.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await sleep(1500);

		const clnPubkeyBuf = Buffer.from(clnPubkey, 'hex');
		const outbound = crypto.randomBytes(1500);
		const replyBody = crypto.randomBytes(1500);

		// Tap the outbound wire so the test proves the LARGE form actually
		// left B1 (and later B2), not just that some message arrived.
		const b1Sent: Buffer[] = [];
		b1.getOnionMessageManager().on(
			'message:send',
			(_to: string, _type: number, payload: Buffer) => {
				b1Sent.push(payload);
			}
		);
		const b2Sent: Buffer[] = [];
		b2.getOnionMessageManager().on(
			'message:send',
			(_to: string, _type: number, payload: Buffer) => {
				b2Sent.push(payload);
			}
		);

		const received: { fromPeer: string; data: Buffer }[] = [];
		b2.getOnionMessageManager().registerTlvHandler(
			65,
			(fromPeer, _t, data, replyPath) => {
				received.push({ fromPeer, data });
				expect(replyPath, 'reply path delivered with the message').to.exist;
				b2!
					.getOnionMessageManager()
					.sendReply(replyPath!, new Map([[65, replyBody]]));
			}
		);
		const replies: { fromPeer: string; data: Buffer }[] = [];
		b1.getOnionMessageManager().registerTlvHandler(65, (fromPeer, _t, data) => {
			replies.push({ fromPeer, data });
		});

		// The reply path is blinded over [CLN, B1]: B2 hands the reply to CLN
		// (the introduction node), which forwards to B1, the same relay in
		// reverse.
		const b1NodeId = Buffer.from(b1.getNodeId(), 'hex');
		const b2NodeId = Buffer.from(b2.getNodeId(), 'hex');
		const replyPath = constructBlindedPath(
			crypto.randomBytes(32),
			[clnPubkeyBuf, b1NodeId],
			[{ nextNodeId: b1NodeId }, {}]
		);

		b1.getOnionMessageManager().sendMultiHopOnionMessage(
			[clnPubkeyBuf],
			b2NodeId,
			new Map([[65, outbound]]),
			{ replyPath }
		);

		expect(b1Sent.length, 'B1 emitted the onion message').to.equal(1);
		expect(b1Sent[0].length, 'B1 sent the large form').to.equal(
			LARGE_WIRE_LENGTH
		);
		expect(b1Sent[0].readUInt16BE(33)).to.equal(LARGE_ONION_PACKET_LENGTH);

		await waitFor(() => (received.length > 0 ? true : null), 60_000);
		expect(received[0].fromPeer, 'message arrived via CLN').to.equal(clnPubkey);
		expect(received[0].data.equals(outbound), 'payload intact').to.be.true;
		console.log('    CLN RELAYED THE 32834-BYTE ONION MESSAGE to B2');

		expect(b2Sent.length, 'B2 emitted the reply').to.equal(1);
		expect(b2Sent[0].length, 'B2 replied in the large form').to.equal(
			LARGE_WIRE_LENGTH
		);

		await waitFor(() => (replies.length > 0 ? true : null), 60_000);
		expect(replies[0].fromPeer, 'reply arrived via CLN').to.equal(clnPubkey);
		expect(replies[0].data.equals(replyBody), 'reply intact').to.be.true;
		console.log('    CLN RELAYED THE LARGE REPLY back to B1');
	});
});
