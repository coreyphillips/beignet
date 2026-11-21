/**
 * Issue #2098, step 10: the daemon's POST /invoice/create takes no asset
 * invoice. An `assetInvoice` in its JSON body, beside hints of the caller's,
 * is ignored like any field the route does not read: the route makes the
 * ordinary invoice it makes for the same body without them, with basic_mpp
 * and a hint for each usable channel of the node, and refuses nothing.
 *
 * Run against a daemon over HTTP, since what matters is the bolt11 the
 * route hands back. The daemon's node is given one ordinary channel that can
 * receive, put in its channel manager as a channel at NORMAL, so that it has
 * a hint of its own to offer.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon } from '../../src/cli/daemon';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature } from '../../src/lightning/features/flags';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { decode } from '../../src/lightning/invoice/decode';
import type { LightningNode } from '../../src/lightning/node/lightning-node';

const key = (label: string): Buffer =>
	crypto.createHash('sha256').update(label).digest();

/** The peer of the daemon's channel, and the alias it forwards to the daemon by. */
const PEER = getPublicKey(key('the peer of the daemon'));
const PEER_ALIAS = encodeShortChannelId({
	block: 800000,
	txIndex: 7,
	outputIndex: 0
});

interface IChannelBook {
	channels: Map<string, Channel>;
	channelPeers: Map<string, string>;
}

/** Put an ordinary channel at NORMAL with PEER into the node's channel manager. */
function giveChannel(engine: LightningNode): string {
	const channelId = key('the channel of the daemon');
	const state = createOpenerState({
		temporaryChannelId: key('the temporary id of the daemon channel'),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: {
			fundingPubkey: getPublicKey(key('daemon basepoint 0')),
			revocationBasepoint: getPublicKey(key('daemon basepoint 1')),
			paymentBasepoint: getPublicKey(key('daemon basepoint 2')),
			delayedPaymentBasepoint: getPublicKey(key('daemon basepoint 3')),
			htlcBasepoint: getPublicKey(key('daemon basepoint 4')),
			firstPerCommitmentPoint: getPublicKey(key('daemon basepoint 5'))
		},
		localPerCommitmentSeed: key('daemon per-commitment seed')
	});
	state.state = ChannelState.NORMAL;
	state.channelId = channelId;
	// The alias the peer sent at channel_ready, which it resolves.
	state.remoteScidAlias = PEER_ALIAS;
	const book = (engine as unknown as { channelManager: IChannelBook })
		.channelManager;
	book.channels.set(channelId.toString('hex'), new Channel(state));
	book.channelPeers.set(channelId.toString('hex'), PEER.toString('hex'));
	return channelId.toString('hex');
}

function takeChannel(engine: LightningNode, channelIdHex: string): void {
	const book = (engine as unknown as { channelManager: IChannelBook })
		.channelManager;
	book.channels.delete(channelIdHex);
	book.channelPeers.delete(channelIdHex);
}

describe('POST /invoice/create with an assetInvoice field (issue #2098, step 10)', function () {
	this.timeout(30_000);
	let dataDir: string;
	let daemon: Awaited<ReturnType<typeof startDaemon>>;
	let port: number;
	let engine: LightningNode;
	let channelIdHex: string;

	const create = (
		body: Record<string, unknown>
	): Promise<{ status: number; json: Record<string, unknown> }> =>
		new Promise((resolve, reject) => {
			const req = http.request(
				{
					host: '127.0.0.1',
					port,
					path: '/invoice/create',
					method: 'POST',
					headers: { 'content-type': 'application/json' }
				},
				(res) => {
					let raw = '';
					res.on('data', (chunk) => (raw += chunk));
					res.on('end', () =>
						resolve({
							status: res.statusCode ?? 0,
							json: JSON.parse(raw) as Record<string, unknown>
						})
					);
				}
			);
			req.on('error', reject);
			req.end(JSON.stringify(body));
		});

	const bolt11Of = async (body: Record<string, unknown>): Promise<string> => {
		const { status, json } = await create(body);
		expect(status, JSON.stringify(json)).to.equal(200);
		return (json.result as { bolt11: string }).bolt11;
	};

	/** What an invoice says, without what differs between any two: hash, secret, timestamp, signature. */
	const reading = (bolt11: string): Record<string, unknown> => {
		const invoice = decode(bolt11);
		return {
			amountMsat: invoice.amountMsat,
			description: invoice.description,
			expiry: invoice.expiry,
			minFinalCltvExpiry: invoice.minFinalCltvExpiry,
			featureBits: [...(invoice.featureBits?.listSetBits() ?? [])].sort(
				(a, b) => a - b
			),
			routingHints: (invoice.routingHints ?? []).map((hint) =>
				hint.map((hop) => ({
					pubkey: hop.pubkey.toString('hex'),
					shortChannelId: hop.shortChannelId.toString('hex'),
					feeBaseMsat: hop.feeBaseMsat,
					feeProportionalMillionths: hop.feeProportionalMillionths,
					cltvExpiryDelta: hop.cltvExpiryDelta
				}))
			),
			metadata: invoice.metadata
		};
	};

	const ASKED = {
		amountSats: 5_000,
		description: 'an invoice asked of the daemon'
	};
	/** Hints of the caller's, as a JSON body can carry them. */
	const CALLER_HINTS = [
		[
			{
				pubkey: getPublicKey(key('an edge node of the caller')).toString('hex'),
				shortChannelId: '000a2e0000210001',
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1,
				cltvExpiryDelta: 40
			}
		]
	];

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-asset-invoice-'));
		daemon = await startDaemon({
			// Nothing here needs a chain, and a refused loopback connect returns
			// at once.
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			network: 'regtest',
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			dataDir,
			daemonPort: 0
		});
		port = (daemon.server.address() as AddressInfo).port;
		engine = (daemon.node as unknown as { node: LightningNode }).node;
		channelIdHex = giveChannel(engine);
	});

	after(async () => {
		takeChannel(engine, channelIdHex);
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	it('makes the ordinary invoice it makes without the field: basic_mpp, the hint of its channel, and none of the caller', async () => {
		const ordinary = reading(await bolt11Of(ASKED));
		expect(ordinary.featureBits).to.deep.equal([
			Feature.TLV_ONION,
			Feature.PAYMENT_SECRET,
			Feature.BASIC_MPP + 1
		]);
		expect(ordinary.routingHints).to.have.length(1);
		expect(
			(
				ordinary.routingHints as Array<
					Array<{ pubkey: string; shortChannelId: string }>
				>
			)[0].map((hop) => [hop.pubkey, hop.shortChannelId])
		).to.deep.equal([[PEER.toString('hex'), PEER_ALIAS.toString('hex')]]);

		for (const assetInvoice of [{}, { inParts: true }, { inParts: false }]) {
			const asked = reading(
				await bolt11Of({
					...ASKED,
					assetInvoice,
					extraRoutingHints: CALLER_HINTS
				})
			);
			expect(asked, JSON.stringify(assetInvoice)).to.deep.equal(ordinary);
		}
	});

	it('refuses no value of the field, as it reads none', async () => {
		for (const assetInvoice of [true, 'yes', 1, [], { inParts: 'no' }]) {
			const { status, json } = await create({ ...ASKED, assetInvoice });
			expect(status, JSON.stringify(json)).to.equal(200);
		}
	});
});
