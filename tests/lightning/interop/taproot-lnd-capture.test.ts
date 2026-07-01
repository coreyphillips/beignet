/**
 * STAGE E — beignet → LND simple-taproot-channels handshake CAPTURE.
 *
 * Drives a real beignet→LND taproot channel open against the dedicated
 * `lnd-taproot` container (v0.20, --protocol.simple-taproot-chans) and
 * captures every raw Lightning message LND sends back. The point is to
 * EMPIRICALLY pin LND's taproot wire format against beignet's provisional
 * choices:
 *   - the channel_type bits LND accepts/echoes (staging 180/181 vs final 80/81)
 *   - the TLV type numbers for the MuSig2 nonce(s) in accept_channel
 *     (beignet provisionally uses next_local_nonce = TLV type 4)
 *   - whether LND sends an `error` (→ what it objects to) instead.
 *
 * Auto-skips when the taproot LND container is not reachable. This test is a
 * DIAGNOSTIC capture: it logs the wire bytes and asserts only that LND
 * responded to our taproot open (accept_channel OR a decodable error), so the
 * captured format can be diffed and beignet corrected.
 */

import { expect } from 'chai';
import {
	createLndTaprootClient,
	LND_TAPROOT_P2P_HOST,
	LND_TAPROOT_P2P_PORT
} from './lnd-taproot-helpers';
import {
	TEST_MNEMONIC,
	ensureBitcoindFunds,
	sleep,
	mineBlocks,
	bitcoinRpc,
	BitcoindFundingProvider
} from './shared-helpers';
import { waitForLndChannels } from './lnd-helpers';
import { LndRestClient } from './lnd-client';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { MessageType } from '../../../src/lightning/message/types';
import { decodeAcceptChannelMessage } from '../../../src/lightning/message/channel-open';
import { decodeTlvStream } from '../../../src/lightning/message/tlv';
import { isTaprootChannel } from '../../../src/lightning/channel/types';

const ACCEPT_CHANNEL_FIXED_LENGTH = 270; // BOLT 2 fixed fields, before TLV stream

interface ICaptured {
	type: number;
	name: string;
	payload: Buffer;
}

function messageName(type: number): string {
	const entry = Object.entries(MessageType).find(([, v]) => v === type);
	return entry ? entry[0] : `UNKNOWN(${type})`;
}

/** Enumerate every TLV record in an accept_channel payload (type + hex). */
function dumpAcceptChannelTlvs(payload: Buffer): void {
	if (payload.length <= ACCEPT_CHANNEL_FIXED_LENGTH) {
		console.log('      (no TLV stream present)');
		return;
	}
	try {
		const { records } = decodeTlvStream(
			payload,
			ACCEPT_CHANNEL_FIXED_LENGTH
		);
		for (const r of records) {
			console.log(
				`      TLV type=${r.type} len=${r.value.length} value=${r.value.toString(
					'hex'
				)}`
			);
		}
	} catch (e) {
		console.log(`      (TLV decode failed: ${(e as Error).message})`);
	}
}

async function buildTaprootBeignetNode(
	seedId: number,
	fundingProvider: BitcoindFundingProvider
): Promise<LightningNode> {
	const { FeatureFlags, Feature } = await import(
		'../../../src/lightning/features/flags'
	);
	const { REGTEST_CHAIN_HASH } = await import(
		'../../../src/lightning/channel/types'
	);
	const { Network } = await import('../../../src/lightning/invoice/types');
	const { deriveLightningKeysFromMnemonic, LnCoinType } = await import(
		'../../../src/lightning/keys/wallet-keys'
	);

	const passphrase = `taproot-capture-${seedId}`;
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
	// The reason we're here: advertise simple taproot channels (staging bit 181).
	features.setOptional(Feature.OPTION_TAPROOT);

	return new LightningNode({
		nodePrivateKey: keys.nodePrivateKey,
		channelBasepoints: keys.channelBasepoints,
		perCommitmentSeed: keys.perCommitmentSeed,
		fundingPrivkey: keys.fundingPrivkey,
		htlcBasepointSecret: keys.htlcBasepointSecret,
		network: Network.REGTEST,
		enableNetworking: true,
		localFeatures: features,
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true,
		preferTaproot: true,
		fundingProvider
	});
}

describe('Stage E — beignet→LND simple-taproot-channels capture', function () {
	this.timeout(120_000);

	let lnd: LndRestClient | null = null;
	let lndPubkey = '';
	let node: LightningNode | null = null;

	before(async function () {
		lnd = await createLndTaprootClient();
		if (!lnd) {
			console.log('    [skip] lnd-taproot not reachable (REST 8082)');
			this.skip();
			return;
		}
		const info = await lnd.getInfo();
		lndPubkey = info.identity_pubkey;
		console.log(
			`    lnd-taproot pubkey: ${lndPubkey} (synced=${info.synced_to_chain}, h=${info.block_height})`
		);
		// Feature bit 181 (simple-taproot-chans-x) confirmed live via getinfo REST.
	});

	after(function () {
		if (node) {
			try {
				node.disconnectPeer(lndPubkey);
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

	it('captures LND accept_channel (or error) for a taproot open', async function () {
		if (!lnd) {
			this.skip();
			return;
		}
		await ensureBitcoindFunds(2.0);

		const fundingProvider = new BitcoindFundingProvider();
		node = await buildTaprootBeignetNode(1, fundingProvider);

		const captured: ICaptured[] = [];
		const errors: Array<{ code?: string; message?: string }> = [];
		node.on('node:error', (err: { code?: string; message?: string }) => {
			errors.push(err);
		});

		// Tap raw incoming peer messages from LND.
		const peerManager = (
			node as unknown as {
				peerManager: {
					on(
						ev: 'message',
						cb: (pubkey: string, type: number, payload: Buffer) => void
					): void;
				} | null;
			}
		).peerManager;
		expect(peerManager, 'peerManager must exist (networking enabled)').to.exist;
		peerManager!.on('message', (_pubkey, type, payload) => {
			captured.push({ type, name: messageName(type), payload });
		});

		await node.connectPeer(
			lndPubkey,
			LND_TAPROOT_P2P_HOST,
			LND_TAPROOT_P2P_PORT
		);
		await sleep(2000);

		// Drive the taproot open. preferTaproot:true on the node config makes
		// initiateOpen negotiate option_taproot + exchange the MuSig2 nonce.
		node.openChannel(lndPubkey, 200_000n);

		// Collect messages for a window; LND should reply accept_channel or error.
		const deadline = Date.now() + 20_000;
		let accept: ICaptured | undefined;
		let errMsg: ICaptured | undefined;
		while (Date.now() < deadline) {
			accept = captured.find((c) => c.type === MessageType.ACCEPT_CHANNEL);
			errMsg = captured.find((c) => c.type === MessageType.ERROR);
			if (accept || errMsg) break;
			await sleep(500);
		}

		// ── Report everything LND sent ──────────────────────────────
		console.log('\n    ── LND messages received ──');
		for (const c of captured) {
			console.log(`    ${c.name} (type ${c.type}) — ${c.payload.length} bytes`);
		}
		if (errors.length) {
			console.log('\n    ── beignet node:error events ──');
			for (const e of errors) console.log(`    ${e.code}: ${e.message}`);
		}

		if (errMsg) {
			// LND objected — the error text tells us what to fix.
			const ascii = errMsg.payload
				.subarray(34) // 32B channel_id + 2B len
				.toString('utf8')
				.replace(/[^\x20-\x7e]/g, '.');
			console.log(`\n    ── LND ERROR ──\n    ${ascii}`);
			console.log(`    raw: ${errMsg.payload.toString('hex')}`);
		}

		if (accept) {
			console.log('\n    ── LND accept_channel ──');
			console.log(`    raw: ${accept.payload.toString('hex')}`);
			dumpAcceptChannelTlvs(accept.payload);
			const decoded = decodeAcceptChannelMessage(accept.payload);
			console.log(
				`    channel_type: ${
					decoded.channelType ? decoded.channelType.toString('hex') : '(none)'
				} → isTaproot=${isTaprootChannel(decoded.channelType ?? null)}`
			);
			console.log(
				`    next_local_nonce (TLV4): ${
					decoded.nextLocalNonce
						? `${decoded.nextLocalNonce.length}B ${decoded.nextLocalNonce.toString(
								'hex'
						  )}`
						: '(none — nonce is at a different TLV type, see dump above)'
			}`
			);
		}

		// Diagnostic test: assert only that LND ENGAGED with our taproot open.
		expect(
			accept || errMsg,
			'LND sent neither accept_channel nor error — open was ignored (likely feature/connection issue)'
		).to.exist;
	});

	it('CAPSTONE: opens a full beignet→LND simple-taproot channel to active', async function () {
		if (!lnd) {
			this.skip();
			return;
		}
		await ensureBitcoindFunds(2.0);

		const fundingProvider = new BitcoindFundingProvider();
		const tnode = await buildTaprootBeignetNode(2, fundingProvider);
		node = tnode; // let after() clean it up
		const errors: Array<{ code?: string; message?: string }> = [];
		tnode.on('node:error', (err: { code?: string; message?: string }) =>
			errors.push(err)
		);

		await tnode.connectPeer(
			lndPubkey,
			LND_TAPROOT_P2P_HOST,
			LND_TAPROOT_P2P_PORT
		);
		await sleep(2000);

		// Beignet opens the taproot channel; auto-funding (BitcoindFundingProvider)
		// builds + broadcasts the funding tx after LND's funding_signed.
		tnode.openChannel(lndPubkey, 200_000n);

		// Wait for a real channelId — set once funding_created is sent (i.e. after
		// LND accepted our MuSig2 funding partial sig and returned funding_signed).
		const cm = tnode.getChannelManager();
		const deadline = Date.now() + 30_000;
		let funded = cm.listChannels().find((c) => c.getChannelId() !== null);
		while (!funded && Date.now() < deadline) {
			await sleep(500);
			funded = cm.listChannels().find((c) => c.getChannelId() !== null);
		}
		if (!funded) {
			const msgs = errors.map((e) => `${e.code}: ${e.message}`).join('; ');
			throw new Error(`No funded taproot channel (errors: [${msgs}])`);
		}
		const channelId = funded.getChannelId()!;
		const fundingTxid = funded.getFullState().fundingTxid;

		// Wait for the funding tx to hit bitcoind's mempool before mining.
		if (fundingTxid) {
			const h1 = Buffer.from(fundingTxid).toString('hex');
			const h2 = Buffer.from(fundingTxid).reverse().toString('hex');
			const mp = Date.now() + 15_000;
			while (Date.now() < mp) {
				const mempool = (await bitcoinRpc('getrawmempool')) as string[];
				if (mempool.includes(h1) || mempool.includes(h2)) break;
				await sleep(500);
			}
		}

		if (errors.length) {
			console.log('\n    ── beignet node:error events (capstone) ──');
			for (const e of errors) console.log(`    ${e.code}: ${e.message}`);
		}

		// LND requires 3 confirmations for taproot channels; mine 6 to be safe.
		await mineBlocks(6);
		await sleep(3000);
		tnode.handleFundingConfirmed(channelId);

		// LND should now mark the taproot channel active.
		await waitForLndChannels(lnd, 1, 60_000);

		const { channels } = await lnd.listChannels();
		const active = (channels || []).filter((c) => c.active);
		console.log(
			`\n    LND active channels: ${active.length}; taproot points: ${active
				.map((c) => c.channel_point)
				.join(', ')}`
		);
		expect(active.length, 'LND must report an active taproot channel').to.be.at.least(
			1
		);
	});
});
