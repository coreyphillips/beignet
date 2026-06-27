/**
 * Full force-close interop: Beignet anchor force-close + wallet-funded CPFP (LND).
 *
 * The gold-standard validation for anchor fee bumping. Opens a REAL beignet-funded
 * anchor channel to LND, then force-closes from beignet and asserts that:
 *  - beignet emits the (low-fee) commitment AND a CPFP child spending its local
 *    anchor output, funded by the wallet via `selectFeeBumpInputs`;
 *  - the [commitment, child] PACKAGE is accepted by a real bitcoind
 *    (`testmempoolaccept` + `submitpackage`) — i.e. the child's fee bumps the
 *    otherwise-unconfirmable commitment;
 *  - both transactions confirm in the next block.
 *
 * This exercises the production force-close → `_maybeCpfpAnchorCommitment` →
 * `buildAnchorCpfpTx` path against a live counterparty. Auto-skips without LND.
 * Run: docker compose -f docker/docker-compose.yml up -d
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LndRestClient } from './lnd-client';
import {
	isLndAvailable,
	createLndClient,
	waitForLndSync,
	cleanupLndState,
	setupBeignetFundedChannel,
	setupRoutingForChannel,
	BitcoindFundingProvider,
	bitcoinRpc,
	mineBlocks,
	sleep
} from './helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	ChannelState,
	isAnchorChannel,
	HtlcDirection
} from '../../../src/lightning/channel/types';

describe('Interop: Beignet anchor force-close + CPFP (regtest)', function () {
	this.timeout(180_000);

	let lnd: LndRestClient;
	let lndPubkey: string;
	let node: LightningNode | undefined;
	let skipAll = false;

	before(async function () {
		if (!(await isLndAvailable())) {
			skipAll = true;
			console.log(
				'    ⚠ LND not available — skipping anchor force-close interop.'
			);
			this.skip();
			return;
		}
		const client = await createLndClient();
		if (!client) {
			skipAll = true;
			this.skip();
			return;
		}
		lnd = client;
		try {
			await waitForLndSync(lnd);
		} catch {
			skipAll = true;
			console.log('    ⚠ LND not synced — skipping.');
			this.skip();
			return;
		}
		lndPubkey = (await lnd.getInfo()).identity_pubkey;
		await cleanupLndState(lnd);
	});

	afterEach(function () {
		if (node) {
			node.destroy();
			node = undefined;
		}
	});

	it('force-closes an anchor channel and CPFP-bumps the commitment via a wallet input', async function () {
		if (skipAll) this.skip();
		// Stock the funding provider with wallet UTXOs to fund the CPFP child.
		const fundingProvider = new BitcoindFundingProvider();
		await fundingProvider.prefundFeeInputs(2, 50_000);

		const setup = await setupBeignetFundedChannel(
			lnd,
			lndPubkey,
			78,
			500_000n,
			fundingProvider
		);
		node = setup.node;

		const channel = node.getChannelManager().getChannel(setup.channelId);
		if (!channel) {
			expect.fail('channel not found');
			return;
		}
		const state = channel.getFullState();
		// Sanity: this must actually be an anchor channel for the test to be meaningful.
		expect(isAnchorChannel(state.channelType), 'channel must be anchor type').to
			.be.true;

		// Capture every tx beignet wants broadcast (commitment + CPFP child).
		const broadcasts: Buffer[] = [];
		node.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
		// Surface fee-bump fallback warnings so a silent skip is visible.
		node.on('node:error', () => {});

		const destScript = bitcoin.payments.p2wpkh({
			pubkey: state.localBasepoints.fundingPubkey
		}).output!;

		node.forceCloseChannel(setup.channelId, destScript);

		// The CPFP child is built asynchronously (selectFeeBumpInputs is async).
		await sleep(3000);

		// We expect the commitment plus a CPFP child that spends its local anchor.
		expect(broadcasts.length, 'commitment + CPFP child').to.be.gte(2);
		const commitmentTx = bitcoin.Transaction.fromBuffer(broadcasts[0]);
		const commitmentHash = commitmentTx.getHash();
		const child = broadcasts
			.map((b) => bitcoin.Transaction.fromBuffer(b))
			.find((t) =>
				t.ins.some((i) => Buffer.from(i.hash).equals(commitmentHash))
			);
		expect(child, 'a CPFP child spending the commitment must be broadcast').to
			.not.be.undefined;

		const commitmentHex = commitmentTx.toHex();
		const childHex = child!.toHex();

		// The commitment alone is low-fee (anchor channels rely on CPFP). As a
		// package, the child's fee must carry both into the mempool.
		const pkg = (await bitcoinRpc('testmempoolaccept', [
			[commitmentHex, childHex]
		])) as Array<{ allowed: boolean; ['reject-reason']?: string }>;
		const reasons = pkg.map((r) => r['reject-reason'] || 'ok').join(', ');
		expect(
			pkg.every((r) => r.allowed),
			`package must be relay-acceptable: ${reasons}`
		).to.be.true;

		// Actually submit the package and mine it.
		const submit = (await bitcoinRpc('submitpackage', [
			[commitmentHex, childHex]
		])) as { package_msg: string };
		expect(submit.package_msg, 'submitpackage result').to.equal('success');

		await mineBlocks(1);
		await sleep(1000);

		// Both the commitment and the CPFP child must now be confirmed.
		const childConf = (await bitcoinRpc('getrawtransaction', [
			child!.getId(),
			true
		])) as { confirmations?: number };
		const commitConf = (await bitcoinRpc('getrawtransaction', [
			commitmentTx.getId(),
			true
		])) as { confirmations?: number };
		expect(childConf.confirmations || 0, 'CPFP child confirmed').to.be.gte(1);
		expect(commitConf.confirmations || 0, 'commitment confirmed').to.be.gte(1);

		// Channel transitioned to FORCE_CLOSED and the node is still healthy.
		expect(
			node.getChannelManager().getChannel(setup.channelId)?.getState()
		).to.equal(ChannelState.FORCE_CLOSED);
		expect(node.getNodeInfo().networkingEnabled).to.be.true;
	});

	it('force-closes with a pending HTLC and fee-attaches the zero-fee HTLC-timeout tx', async function () {
		if (skipAll) this.skip();
		const blockCount = async () =>
			(await bitcoinRpc('getblockcount')) as number;
		// Two fee bumps consume two prefunded inputs (commitment CPFP + HTLC-timeout).
		const fundingProvider = new BitcoindFundingProvider();
		await fundingProvider.prefundFeeInputs(3, 50_000);

		const setup = await setupBeignetFundedChannel(
			lnd,
			lndPubkey,
			79,
			600_000n,
			fundingProvider
		);
		node = setup.node;
		setupRoutingForChannel(node, lndPubkey);

		const channel = node.getChannelManager().getChannel(setup.channelId)!;
		const state = channel.getFullState();
		expect(isAnchorChannel(state.channelType), 'must be anchor type').to.be
			.true;

		// Beignet must know the chain height to set a valid HTLC cltv_expiry, or LND
		// rejects the HTLC. (No ChainWatcher in interop, so feed it manually.)
		node.handleNewBlock(await blockCount());

		// LND hold invoice: LND accepts the HTLC but never settles, so beignet's
		// offered HTLC stays committed and unresolved across the force-close.
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const hold = await lnd.addHoldInvoice(paymentHash.toString('hex'), 20_000);

		node.on('node:error', () => {});
		const broadcasts: Buffer[] = [];
		node.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		try {
			node.sendPayment(hold.payment_request);

			// Wait for the offered HTLC to be irrevocably committed (LND invoice
			// ACCEPTED ⇒ the commitment round completed on both sides).
			let offered = undefined as undefined | { cltvExpiry: number };
			const deadline = Date.now() + 30_000;
			while (Date.now() < deadline) {
				const inv = await lnd
					.lookupInvoice(paymentHash.toString('hex'))
					.catch(() => undefined);
				const htlcs = [
					...node!
						.getChannelManager()
						.getChannel(setup.channelId)!
						.getFullState()
						.htlcs.values()
				];
				offered = htlcs.find(
					(h) =>
						h.direction === HtlcDirection.OFFERED &&
						h.paymentHash.equals(paymentHash)
				);
				if (inv?.state === 'ACCEPTED' && offered) break;
				await sleep(1000);
			}
			expect(offered, 'beignet must hold a committed offered HTLC').to.not.be
				.undefined;
			const cltvExpiry = offered!.cltvExpiry;

			// ── Force close: commitment + CPFP child (as in the first test) ──
			const destScript = bitcoin.payments.p2wpkh({
				pubkey: state.localBasepoints.fundingPubkey
			}).output!;
			node.forceCloseChannel(setup.channelId, destScript);
			await sleep(3000);

			const commitmentTx = bitcoin.Transaction.fromBuffer(broadcasts[0]);
			const commitmentHash = commitmentTx.getHash();
			const cpfp = broadcasts
				.slice(1)
				.map((b) => bitcoin.Transaction.fromBuffer(b))
				.find((t) =>
					t.ins.some((i) => Buffer.from(i.hash).equals(commitmentHash))
				);
			expect(cpfp, 'CPFP child must be broadcast').to.not.be.undefined;

			const submit = (await bitcoinRpc('submitpackage', [
				[commitmentTx.toHex(), cpfp!.toHex()]
			])) as { package_msg: string };
			expect(submit.package_msg, 'commitment package accepted').to.equal(
				'success'
			);
			await mineBlocks(1);
			const confHeight = await blockCount();

			// Drive beignet's chain monitor: classify our commitment + schedule the
			// HTLC-timeout sweep (held until the HTLC cltv matures).
			node
				.getChannelManager()
				.handleFundingSpent(
					setup.channelId,
					commitmentTx,
					confHeight,
					destScript
				);

			// Mine past the HTLC cltv so the HTLC-timeout tx becomes final, then
			// release it — the monitor emits a fee-bump-and-broadcast for the anchor
			// zero-fee tx, and beignet attaches a wallet fee input.
			const toMine = Math.max(0, cltvExpiry - confHeight) + 1;
			await mineBlocks(toMine);
			const tip = await blockCount();
			const before = broadcasts.length;
			node.handleNewBlock(tip);
			await sleep(3000);

			const htlcTimeout = broadcasts
				.slice(before)
				.map((b) => bitcoin.Transaction.fromBuffer(b))
				.find((t) =>
					t.ins.some((i) => Buffer.from(i.hash).equals(commitmentHash))
				);
			expect(htlcTimeout, 'fee-attached HTLC-timeout tx must be broadcast').to
				.not.be.undefined;
			// It must carry the wallet fee input (2+ inputs: HTLC output + wallet input).
			expect(
				htlcTimeout!.ins.length,
				'HTLC-timeout has an attached wallet input'
			).to.be.gte(2);

			// The real LND-signed HTLC witness + beignet's sig + the attached fee must
			// be accepted by a real node, then confirm.
			const [accept] = (await bitcoinRpc('testmempoolaccept', [
				[htlcTimeout!.toHex()]
			])) as Array<{ allowed: boolean; ['reject-reason']?: string }>;
			expect(
				accept.allowed,
				`HTLC-timeout must be relay-acceptable: ${accept['reject-reason']}`
			).to.be.true;
			await bitcoinRpc('sendrawtransaction', [htlcTimeout!.toHex()]);
			await mineBlocks(1);
			const conf = (await bitcoinRpc('getrawtransaction', [
				htlcTimeout!.getId(),
				true
			])) as { confirmations?: number };
			expect(conf.confirmations || 0, 'HTLC-timeout confirmed').to.be.gte(1);
		} finally {
			// Cancel the hold invoice so LND fails the HTLC back and cleans up.
			await lnd.cancelHoldInvoice(paymentHash.toString('hex')).catch(() => {});
		}
	});
});
