/**
 * Interop: option_simple_close (closing_complete / closing_sig) vs live Eclair.
 *
 * Eclair ≥ 0.11 activates option_simple_close by default, making it the
 * primary interop gate for beignet's simplified mutual close. The CLN Tier 6
 * tests still exercise the LEGACY closing_signed fallback because the shared
 * interop helper nodes deliberately do not advertise Feature.SIMPLE_CLOSE
 * (note: modern CLN itself does advertise bits 60/61, so the legacy coverage
 * relies on the helper's feature set, not on CLN's).
 *
 * Also captures Eclair's real closing_complete/closing_sig wire bytes into
 * tests/lightning/conformance/vectors/eclair-simple-close.json (no upstream
 * test vectors exist for simple close).
 */

import { expect } from 'chai';
import fs from 'fs';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { ChannelState } from '../../../src/lightning/channel/types';
import { MessageType } from '../../../src/lightning/message/types';
import { decodeClosingCompleteMessage } from '../../../src/lightning/message/channel-close';
import { EclairRestClient } from './eclair-client';
import {
	isEclairAvailable,
	createEclairClient,
	waitForEclairSync,
	setupEclairChannel,
	sleep,
	mineBlocks,
	bitcoinRpc
} from './eclair-helpers';

const VECTORS_PATH = path.join(
	__dirname,
	'..',
	'conformance',
	'vectors',
	'eclair-simple-close.json'
);

interface ICapturedMsg {
	type: number;
	direction: 'inbound';
	payloadHex: string;
}

/** Capture inbound closing_complete/closing_sig wire bytes from Eclair. */
function captureCloseMessages(node: LightningNode): ICapturedMsg[] {
	const captured: ICapturedMsg[] = [];
	const cm = node.getChannelManager();
	const orig = cm.handleMessage.bind(cm);
	cm.handleMessage = (peerPubkey: string, type: number, payload: Buffer) => {
		if (
			type === MessageType.CLOSING_COMPLETE ||
			type === MessageType.CLOSING_SIG
		) {
			captured.push({
				type,
				direction: 'inbound',
				payloadHex: payload.toString('hex')
			});
		}
		return orig(peerPubkey, type, payload);
	};
	return captured;
}

/** Relay beignet's close broadcasts to regtest bitcoind. */
function relayBroadcasts(node: LightningNode): Buffer[] {
	const txs: Buffer[] = [];
	node.on('broadcast:tx', (tx: Buffer) => {
		txs.push(tx);
		bitcoinRpc('sendrawtransaction', [tx.toString('hex')]).catch(() => {
			// Eclair may have broadcast the same (or a conflicting alternative)
			// close first — already-known / conflict errors are fine.
		});
	});
	return txs;
}

async function waitForState(
	node: LightningNode,
	channelId: Buffer,
	state: ChannelState,
	timeoutMs: number
): Promise<boolean> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const ch = node.getChannelManager().getChannel(channelId);
		if (ch && ch.getState() === state) return true;
		await sleep(500);
	}
	return false;
}

function defaultShutdownScript(node: LightningNode, channelId: Buffer): Buffer {
	const channel = node.getChannelManager().getChannel(channelId)!;
	const state = channel.getFullState();
	return bitcoin.payments.p2wpkh({
		pubkey: state.localBasepoints.fundingPubkey
	}).output!;
}

describe('Interop: option_simple_close vs Eclair (regtest)', function () {
	this.timeout(300_000);

	let eclair: EclairRestClient;
	let eclairPubkey: string;
	let node: LightningNode;
	let skipAll = false;
	const allCaptured: ICapturedMsg[] = [];

	before(async function () {
		this.timeout(300_000);
		if (!(await isEclairAvailable())) {
			skipAll = true;
			console.log(
				'    ⚠ Eclair not available — skipping simple-close interop. Start Docker: docker start eclair'
			);
			this.skip();
			return;
		}
		const client = await createEclairClient();
		if (!client) {
			skipAll = true;
			this.skip();
			return;
		}
		eclair = client;
		await waitForEclairSync(eclair, 180_000);

		const info = await eclair.getInfo();
		eclairPubkey = info.nodeId;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const activated = (info as any).features?.activated as
			| Record<string, string>
			| undefined;
		if (activated) {
			expect(
				Object.prototype.hasOwnProperty.call(activated, 'option_simple_close'),
				'eclair advertises option_simple_close'
			).to.equal(true);
		}
	});

	afterEach(function () {
		if (node) node.destroy();
	});

	after(function () {
		// Freeze real Eclair wire bytes as decode fixtures.
		if (allCaptured.length > 0) {
			fs.mkdirSync(path.dirname(VECTORS_PATH), { recursive: true });
			fs.writeFileSync(
				VECTORS_PATH,
				JSON.stringify(
					{
						description:
							'closing_complete (40) / closing_sig (41) payloads captured from a live eclair 0.13 node (no upstream vectors exist)',
						messages: allCaptured
					},
					null,
					'\t'
				)
			);
			console.log(
				`    captured ${allCaptured.length} simple-close messages → ${VECTORS_PATH}`
			);
		}
	});

	it('closes as CLOSEE: eclair funds the close, beignet co-signs and broadcasts', async function () {
		if (skipAll) this.skip();

		// Eclair-funded channel: beignet's balance is 0, so beignet never sends
		// its own closing_complete and acts purely as the closee.
		const setup = await setupEclairChannel(eclair, eclairPubkey, 260, 500_000);
		node = setup.node;
		const captured = captureCloseMessages(node);
		const broadcasts = relayBroadcasts(node);

		const ok = node.closeChannel(
			setup.channelId,
			defaultShutdownScript(node, setup.channelId)
		);
		expect(ok.ok).to.equal(true);

		const closed = await waitForState(
			node,
			setup.channelId,
			ChannelState.CLOSED,
			60_000
		);
		expect(closed, 'beignet channel reaches CLOSED').to.equal(true);

		// Eclair sent a closing_complete we accepted and answered.
		const cc = captured.filter((m) => m.type === MessageType.CLOSING_COMPLETE);
		expect(
			cc.length,
			'received closing_complete from eclair'
		).to.be.greaterThan(0);
		const decoded = decodeClosingCompleteMessage(
			Buffer.from(cc[0].payloadHex, 'hex')
		);
		expect(decoded.channelId.equals(setup.channelId)).to.equal(true);

		// We broadcast the (verified) close tx ourselves.
		expect(broadcasts.length).to.be.greaterThan(0);

		allCaptured.push(...captured);

		await mineBlocks(6);
		await sleep(3000);
		const remaining = await eclair.channels(node.getNodeId());
		const stillOpen = remaining.filter((c) => c.state === 'NORMAL');
		expect(
			stillOpen.length,
			'eclair no longer lists the channel NORMAL'
		).to.equal(0);
	});

	it('closes as CLOSER: beignet pays the fee from its pushed balance', async function () {
		if (skipAll) this.skip();

		// Push 100k sat so beignet has a balance and runs the closer path
		// (sends closing_complete, receives closing_sig).
		const setup = await setupEclairChannel(
			eclair,
			eclairPubkey,
			261,
			500_000,
			100_000_000
		);
		node = setup.node;
		const captured = captureCloseMessages(node);
		const broadcasts = relayBroadcasts(node);

		const ok = node.closeChannel(
			setup.channelId,
			defaultShutdownScript(node, setup.channelId)
		);
		expect(ok.ok).to.equal(true);

		const closed = await waitForState(
			node,
			setup.channelId,
			ChannelState.CLOSED,
			60_000
		);
		expect(closed, 'beignet channel reaches CLOSED').to.equal(true);

		// Eclair answered our closing_complete with closing_sig.
		const cs = captured.filter((m) => m.type === MessageType.CLOSING_SIG);
		expect(cs.length, 'received closing_sig from eclair').to.be.greaterThan(0);
		expect(broadcasts.length).to.be.greaterThan(0);

		allCaptured.push(...captured);

		await mineBlocks(6);
		await sleep(3000);
		const remaining = await eclair.channels(node.getNodeId());
		const stillOpen = remaining.filter((c) => c.state === 'NORMAL');
		expect(stillOpen.length).to.equal(0);
	});
});
