/**
 * Taproot cooperative close vs live LND (simple-taproot channels, MuSig2).
 *
 * Runs against the dedicated `lnd-taproot` container (v0.20,
 * --protocol.simple-taproot-chans). Auto-skips when it is not reachable.
 *
 * Wire format: shutdown carries the MuSig2 closing nonce as TLV type 8 (66B),
 * closing_signed carries the 32-byte partial signature as TLV type 6 with the
 * ECDSA field zeroed, and fee negotiation is single-round (the responder
 * accepts the initiator's fee verbatim). The first test is the diagnostic
 * capture that originally pinned the TLV layout; the rest drive real closes
 * in both directions plus the reestablish (shutdown retransmit) path.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	createLndTaprootClient,
	setupTaprootLndChannel,
	LND_TAPROOT_P2P_HOST,
	LND_TAPROOT_P2P_PORT
} from './lnd-taproot-helpers';
import { sleep, mineBlocks, bitcoinRpc } from './shared-helpers';
import { LndRestClient } from './lnd-client';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { ChannelState } from '../../../src/lightning/channel/types';
import { MessageType } from '../../../src/lightning/message/types';
import { decodeTlvStream } from '../../../src/lightning/message/tlv';

interface ICaptured {
	type: number;
	name: string;
	payload: Buffer;
}

function messageName(type: number): string {
	const entry = Object.entries(MessageType).find(([, v]) => v === type);
	return entry ? entry[0] : `UNKNOWN(${type})`;
}

/** shutdown = [32B channel_id][u16 len][len script][TLV stream]. */
function dumpShutdownTlvs(
	payload: Buffer
): Array<{ type: bigint; value: Buffer }> {
	const scriptLen = payload.readUInt16BE(32);
	const tlvStart = 34 + scriptLen;
	if (payload.length <= tlvStart) return [];
	const { records } = decodeTlvStream(payload, tlvStart);
	return records.map((r) => ({ type: r.type, value: r.value }));
}

describe('Taproot coop close vs live LND', function () {
	this.timeout(180_000);

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
	});

	afterEach(function () {
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
			node = null;
		}
	});

	it('CAPTURE: LND-initiated close carries the shutdown nonce TLV (type 8, 66B)', async function () {
		if (!lnd) {
			this.skip();
			return;
		}

		const setup = await setupTaprootLndChannel(lnd, lndPubkey, 60);
		node = setup.node;

		const captured: ICaptured[] = [];
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
		expect(peerManager, 'peerManager must exist').to.exist;
		peerManager!.on('message', (_pubkey, type, payload) => {
			captured.push({ type, name: messageName(type), payload });
		});

		// Ask LND to cooperatively close. LND opens with `shutdown` carrying
		// its MuSig2 closing nonce, which this test captures raw off the wire.
		const st = node.getChannelManager().listChannels()[0].getFullState();
		const displayTxid = Buffer.from(st.fundingTxid!).reverse().toString('hex');
		await lnd.closeChannel(displayTxid, st.fundingOutputIndex);

		const deadline = Date.now() + 20_000;
		let shutdown: ICaptured | undefined;
		while (Date.now() < deadline) {
			shutdown = captured.find((c) => c.type === MessageType.SHUTDOWN);
			if (shutdown) break;
			await sleep(500);
		}

		console.log('\n    ── LND messages received ──');
		for (const c of captured) {
			console.log(`    ${c.name} (type ${c.type}) — ${c.payload.length} bytes`);
		}

		expect(shutdown, 'LND must send shutdown').to.exist;
		console.log(
			`\n    ── LND shutdown raw ──\n    ${shutdown!.payload.toString('hex')}`
		);

		const tlvs = dumpShutdownTlvs(shutdown!.payload);
		for (const r of tlvs) {
			console.log(
				`    TLV type=${r.type} len=${r.value.length} value=${r.value.toString(
					'hex'
				)}`
			);
		}

		const nonceTlv = tlvs.find((r) => r.type === 8n);
		expect(nonceTlv, 'shutdown must carry TLV type 8 (MuSig2 closing nonce)').to
			.exist;
		expect(nonceTlv!.value.length, 'closing nonce must be 66 bytes').to.equal(
			66
		);

		// With coop close implemented, the LND-initiated close driven for this
		// capture actually completes — let it settle so the channel does not
		// linger half-closed on the shared container.
		await waitForClosed(node!, 30_000);
	});

	/** Wait until the beignet side of the (single) channel reaches CLOSED. */
	async function waitForClosed(
		n: LightningNode,
		timeoutMs: number
	): Promise<boolean> {
		const deadline = Date.now() + timeoutMs;
		while (Date.now() < deadline) {
			const ch = n.getChannelManager().listChannels()[0];
			if (ch && ch.getState() === ChannelState.CLOSED) return true;
			await sleep(500);
		}
		return false;
	}

	/**
	 * Confirm the mutual close on-chain and assert LND records the channel as
	 * cooperatively closed.
	 */
	async function confirmCooperativeClose(
		closeTx: Buffer,
		fundingTxidInternal: Buffer
	): Promise<void> {
		const tx = bitcoin.Transaction.fromBuffer(closeTx);
		expect(tx.ins[0].witness.length, 'key-spend witness').to.equal(1);
		expect(tx.ins[0].witness[0].length).to.equal(64);

		// beignet broadcasts the close itself; LND does too. Either copy may
		// already be in the mempool — tolerate the duplicate.
		try {
			await bitcoinRpc('sendrawtransaction', [tx.toHex()]);
		} catch {
			/* already in mempool */
		}
		await mineBlocks(3);
		await sleep(2000);

		const mined = (await bitcoinRpc('getrawtransaction', [
			tx.getId(),
			true
		])) as { confirmations?: number };
		expect((mined.confirmations ?? 0) >= 1, 'close tx confirmed').to.equal(
			true
		);

		// LND lists the channel as cooperatively closed.
		const displayFunding = Buffer.from(fundingTxidInternal)
			.reverse()
			.toString('hex');
		let cooperative = false;
		const deadline = Date.now() + 45_000;
		while (Date.now() < deadline) {
			const { channels } = await lnd!.closedChannels();
			const entry = (channels || []).find((c) =>
				c.channel_point.startsWith(displayFunding)
			);
			if (entry) {
				console.log(
					`    LND closed-channel entry: close_type=${entry.close_type} closing_txid=${entry.closing_tx_hash}`
				);
				expect(entry.close_type).to.equal('COOPERATIVE_CLOSE');
				expect(entry.closing_tx_hash).to.equal(tx.getId());
				cooperative = true;
				break;
			}
			await mineBlocks(1);
			await sleep(2000);
		}
		expect(cooperative, 'LND must list a cooperative close').to.equal(true);
	}

	it('beignet-initiated coop close completes and LND records COOPERATIVE_CLOSE', async function () {
		if (!lnd) {
			this.skip();
			return;
		}

		// Push 50k sat so LND has a non-dust closing output too.
		const setup = await setupTaprootLndChannel(
			lnd,
			lndPubkey,
			61,
			200_000n,
			50_000_000n
		);
		node = setup.node;
		const channel = node.getChannelManager().getChannel(setup.channelId)!;
		const fundingTxid = channel.getFullState().fundingTxid!;

		const broadcasts: Buffer[] = [];
		node.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		const destScript = bitcoin.payments.p2wpkh({
			pubkey: channel.getFullState().localBasepoints.fundingPubkey
		}).output!;
		const res = node.closeChannel(setup.channelId, destScript);
		expect(res.ok, res.error).to.equal(true);

		expect(
			await waitForClosed(node, 30_000),
			'channel reaches CLOSED'
		).to.equal(true);
		expect(broadcasts.length, 'beignet broadcast the mutual close').to.be.gte(
			1
		);
		await confirmCooperativeClose(broadcasts[0], fundingTxid);
	});

	it('LND-initiated coop close completes and LND records COOPERATIVE_CLOSE', async function () {
		if (!lnd) {
			this.skip();
			return;
		}

		const setup = await setupTaprootLndChannel(
			lnd,
			lndPubkey,
			62,
			200_000n,
			50_000_000n
		);
		node = setup.node;
		const channel = node.getChannelManager().getChannel(setup.channelId)!;
		const st = channel.getFullState();
		const fundingTxid = st.fundingTxid!;

		const broadcasts: Buffer[] = [];
		node.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		const displayTxid = Buffer.from(fundingTxid).reverse().toString('hex');
		await lnd.closeChannel(displayTxid, st.fundingOutputIndex);

		expect(
			await waitForClosed(node, 30_000),
			'channel reaches CLOSED'
		).to.equal(true);
		expect(broadcasts.length, 'beignet broadcast the mutual close').to.be.gte(
			1
		);
		await confirmCooperativeClose(broadcasts[0], fundingTxid);
	});

	it('completes the close on a REESTABLISHED connection (fresh closing nonces)', async function () {
		if (!lnd) {
			this.skip();
			return;
		}

		const setup = await setupTaprootLndChannel(
			lnd,
			lndPubkey,
			63,
			200_000n,
			50_000_000n
		);
		node = setup.node;
		const channel = node.getChannelManager().getChannel(setup.channelId)!;
		const fundingTxid = channel.getFullState().fundingTxid!;

		// Disconnect and reconnect so the whole closing flow runs on a
		// reestablished connection: verification nonces re-derived, closing
		// nonces generated fresh on this connection. (The mid-negotiation
		// shutdown-retransmit path is covered deterministically in
		// tests/lightning/taproot-coop-close.test.ts.)
		node.disconnectPeer(lndPubkey);
		await sleep(1500);
		await node.connectPeer(
			lndPubkey,
			LND_TAPROOT_P2P_HOST,
			LND_TAPROOT_P2P_PORT
		);
		const reestablished = await (async (): Promise<boolean> => {
			const deadline = Date.now() + 20_000;
			while (Date.now() < deadline) {
				if (channel.getState() === ChannelState.NORMAL) return true;
				await sleep(500);
			}
			return false;
		})();
		expect(reestablished, 'channel back to NORMAL after reestablish').to.equal(
			true
		);

		const broadcasts: Buffer[] = [];
		node.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		const destScript = bitcoin.payments.p2wpkh({
			pubkey: channel.getFullState().localBasepoints.fundingPubkey
		}).output!;
		const res = node.closeChannel(setup.channelId, destScript);
		expect(res.ok, res.error).to.equal(true);

		expect(
			await waitForClosed(node, 45_000),
			'channel reaches CLOSED after reestablish'
		).to.equal(true);
		expect(broadcasts.length, 'beignet broadcast the mutual close').to.be.gte(
			1
		);
		await confirmCooperativeClose(broadcasts[0], fundingTxid);
	});
});
