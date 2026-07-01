/**
 * STAGE E — taproot FORCE-CLOSE on-chain vs live LND.
 *
 * Opens a live beignet→LND simple-taproot channel, then beignet force-closes by
 * broadcasting its commitment (a MuSig2 key-spend of the funding output, built by
 * aggregating beignet's partial with LND's stored partial). The taproot
 * commitment is low-fee (anchor channel) so it rides into the mempool as a
 * package with its CPFP child. Asserts:
 *   - the package (commitment + CPFP child) is relay-acceptable and confirms;
 *   - LND RECOGNIZES the force-close (channel leaves active; appears in
 *     pending_force_closing) — i.e. LND accepts beignet's taproot commitment as a
 *     valid spend of the funding output.
 * Auto-skips when lnd-taproot is down.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	createLndTaprootClient,
	setupTaprootLndChannel
} from './lnd-taproot-helpers';
import { sleep, mineBlocks, bitcoinRpc } from './shared-helpers';
import { LndRestClient } from './lnd-client';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { isTaprootChannel } from '../../../src/lightning/channel/types';

describe('Stage E — taproot force-close on-chain vs live LND', function () {
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
		lndPubkey = (await lnd.getInfo()).identity_pubkey;
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

	it('beignet force-closes and LND recognizes the taproot commitment on-chain', async function () {
		if (!lnd) {
			this.skip();
			return;
		}

		// Open with a push so the commitment has both a to_local (beignet) and a
		// to_remote (LND) output (more representative than a single-sided close).
		const setup = await setupTaprootLndChannel(
			lnd,
			lndPubkey,
			5,
			200_000n,
			50_000_000n
		);
		node = setup.node;
		const channel = node.getChannelManager().getChannel(setup.channelId)!;
		expect(isTaprootChannel(channel.getFullState().channelType)).to.be.true;
		const fundingPoint = channel.getFullState().fundingTxid;

		// Capture everything beignet broadcasts (commitment + CPFP child).
		const broadcasts: Buffer[] = [];
		node.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		const destScript = bitcoin.payments.p2wpkh({
			pubkey: channel.getFullState().localBasepoints.fundingPubkey
		}).output!;

		const fc = node.forceCloseChannel(setup.channelId, destScript);
		expect(fc.ok, `forceClose failed: ${fc.error}`).to.be.true;

		// CPFP child is built asynchronously (wallet input selection).
		await sleep(4000);

		expect(broadcasts.length, 'commitment (+ CPFP child)').to.be.gte(1);
		const commitment = bitcoin.Transaction.fromBuffer(broadcasts[0]);
		const commitmentHash = commitment.getHash();
		const child = broadcasts
			.map((b) => bitcoin.Transaction.fromBuffer(b))
			.find(
				(t) =>
					!t.getHash().equals(commitmentHash) &&
					t.ins.some((i) => Buffer.from(i.hash).equals(commitmentHash))
			);

		// Submit as a package if there's a CPFP child, else solo.
		const hexes = child
			? [commitment.toHex(), child.toHex()]
			: [commitment.toHex()];
		const pkg = (await bitcoinRpc('testmempoolaccept', [hexes])) as Array<{
			allowed: boolean;
			['reject-reason']?: string;
		}>;
		const reasons = pkg.map((r) => r['reject-reason'] || 'ok').join(', ');
		console.log(
			`\n    broadcasts=${broadcasts.length} child=${!!child} relay: ${reasons}`
		);

		if (child) {
			const submit = (await bitcoinRpc('submitpackage', [hexes])) as {
				package_msg: string;
			};
			expect(submit.package_msg, 'submitpackage').to.equal('success');
		} else {
			// No CPFP child — the commitment must itself be relayable.
			expect(pkg[0].allowed, `commitment relay: ${reasons}`).to.be.true;
			await bitcoinRpc('sendrawtransaction', [commitment.toHex()]);
		}

		await mineBlocks(3);
		await sleep(3000);

		// The commitment confirmed on-chain.
		const conf = (await bitcoinRpc('getrawtransaction', [
			commitment.getId(),
			true
		])) as { confirmations?: number };
		expect(conf.confirmations || 0, 'commitment confirmed').to.be.gte(1);

		// LND must RECOGNIZE the force-close: the channel leaves active and shows up
		// as force-closing (LND saw the funding output spent by beignet's commitment).
		let recognized = false;
		const deadline = Date.now() + 45_000;
		while (Date.now() < deadline) {
			const { channels } = await lnd.listChannels();
			const stillActive = (channels || []).some(
				(c) =>
					c.active &&
					fundingPoint &&
					c.channel_point.startsWith(
						Buffer.from(fundingPoint).reverse().toString('hex')
					)
			);
			const pending = await lnd.pendingChannels();
			const forceClosing = (pending.pending_force_closing_channels || []).length;
			const waiting =
				(
					pending as unknown as {
						waiting_close_channels?: unknown[];
					}
				).waiting_close_channels?.length || 0;
			if (!stillActive && (forceClosing > 0 || waiting > 0)) {
				recognized = true;
				console.log(
					`    ✓ LND recognized force-close (force_closing=${forceClosing}, waiting=${waiting})`
				);
				break;
			}
			await mineBlocks(1);
			await sleep(2000);
		}
		expect(recognized, 'LND must recognize the taproot force-close').to.be.true;
	});
});
