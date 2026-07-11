/**
 * Interop regression: CLN-funded channel update_fee desync (live).
 *
 * Pins the live failure this branch fixes: CLN (funder/opener) sends
 * update_fee shortly after a CLN-funded anchor channel reaches NORMAL
 * (regtest anchor commitment target ~1250 sat/kw vs the opening rate).
 * Pre-fix, beignet's next commitment_signed after that fee round was built
 * at the wrong rate ("Bad commit_sig" at CLN), its shachain bookkeeping
 * desynced ("Invalid per-commitment secret"), and on reconnect CLN failed
 * the channel with "bad future last_local_per_commit_secret: N vs N-1".
 *
 * This test runs the exact live sequence with STRICT assertions:
 *   1. CLN funds a channel to beignet (push_msat both ways).
 *   2. Wait for / absorb CLN's update_fee round (staged rate fully settled).
 *   3. Payment beignet → CLN: settled at CLN, exact amount.
 *   4. Payment CLN → beignet: settled at beignet, exact amount.
 *   5. Disconnect + reconnect: channel reestablishes cleanly (no force
 *      close, CLN channel stays CHANNELD_NORMAL, no bad-secret errors).
 *   6. Another payment beignet → CLN: settled, exact amount.
 *
 * Auto-skips when Docker/CLN is unavailable.
 * Run: docker compose -f docker/docker-compose.yml up -d
 */

import { expect } from 'chai';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	waitForClnPeerChannelNormal,
	fundClnWallet,
	setupClnChannel,
	setupRoutingForChannel,
	payClnInvoiceStrict,
	payBeignetInvoiceStrict,
	waitFor,
	sleep,
	CLN_P2P_HOST,
	CLN_P2P_PORT
} from './cln-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { ChannelState } from '../../../src/lightning/channel/types';

describe('Interop: CLN-funded update_fee desync regression (live)', function () {
	this.timeout(180_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let node: LightningNode;
	let skipAll = false;

	before(async function () {
		const available = await isClnAvailable();
		if (!available) {
			skipAll = true;
			console.log(
				'    ⚠ CLN not available — skipping. Start Docker: docker compose -f docker/docker-compose.yml up -d'
			);
			this.skip();
			return;
		}
		const client = await createClnClient();
		if (!client) {
			skipAll = true;
			this.skip();
			return;
		}
		cln = client;
		await waitForClnSync(cln);
		const info = await cln.getInfo();
		clnPubkey = info.id;
	});

	beforeEach(function () {
		if (skipAll) this.skip();
	});

	afterEach(function () {
		if (node) node.destroy();
	});

	it('absorbs CLN update_fee, pays strictly both ways, reestablishes cleanly, pays again', async function () {
		// Unique seed per run so repeated executions get fresh channels.
		const seedId = 700 + (Date.now() % 97);
		const setup = await setupClnChannel(
			cln,
			clnPubkey,
			seedId,
			1_000_000,
			300_000_000
		);
		node = setup.node;
		const channelId = setup.channelId;
		const channel = node.getChannelManager().getChannel(channelId)!;
		expect(channel.getState()).to.equal(ChannelState.NORMAL);

		// Track desync-class errors; routing noise is irrelevant, these are not.
		const desyncErrors: string[] = [];
		node.on('node:error', (e: unknown) => {
			const msg = JSON.stringify(e);
			if (
				/Invalid per-commitment secret|Invalid commitment signature|Unexpected revoke_and_ack|Invalid HTLC signature/.test(
					msg
				)
			) {
				desyncErrors.push(msg);
			}
		});

		setupRoutingForChannel(node, clnPubkey);
		await fundClnWallet(cln);

		// ── 2. Wait for / absorb CLN's update_fee round ──
		// CLN raises an anchor channel's commitment feerate (regtest target
		// ~1250 sat/kw) right after NORMAL; wait for a fee round to land and
		// fully settle (staged rate promoted, nothing pending).
		const openRate = channel.getFullState().remoteConfig.feeratePerKw;
		const feeRound = await waitFor(() => {
			const st = channel.getFullState();
			return st.remoteConfig.feeratePerKw !== openRate &&
				st.pendingFeeratePerKw === undefined
				? st.remoteConfig.feeratePerKw
				: null;
		}, 25_000);
		if (feeRound !== null) {
			console.log(
				`    CLN update_fee absorbed: ${openRate} → ${feeRound} sat/kw`
			);
		} else {
			console.log(
				`    No CLN update_fee within 25s (opened at ${openRate} sat/kw) — continuing`
			);
			// Whatever happened, no fee round may be left dangling.
			expect(channel.getFullState().pendingFeeratePerKw).to.equal(undefined);
		}

		// ── 3. beignet → CLN, strict ──
		await payClnInvoiceStrict(node, cln, 5_000_000, 'after-fee-round');

		// ── 4. CLN → beignet, strict ──
		await payBeignetInvoiceStrict(node, cln, 7_000_000, 'cln-to-beignet');

		expect(desyncErrors, desyncErrors.join('; ')).to.deep.equal([]);

		// ── 5. Disconnect + reestablish ──
		node.disconnectPeer(clnPubkey);
		await sleep(2000);
		await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);

		const normalAgain = await waitFor(
			() => (channel.getState() === ChannelState.NORMAL ? true : null),
			30_000
		);
		expect(normalAgain, 'channel must reestablish to NORMAL').to.equal(true);

		// CLN must still consider the channel operational — a "bad future
		// last_local_per_commit_secret" (the pre-fix symptom) kills it here.
		const clnChannel = await waitForClnPeerChannelNormal(
			cln,
			node.getNodeId(),
			30_000
		);
		expect(clnChannel.state).to.equal('CHANNELD_NORMAL');

		// ── 6. Another strict payment after reestablish ──
		await sleep(2000);
		await payClnInvoiceStrict(node, cln, 3_000_000, 'after-reestablish');

		expect(desyncErrors, desyncErrors.join('; ')).to.deep.equal([]);
		expect(channel.getState()).to.equal(ChannelState.NORMAL);
	});
});
