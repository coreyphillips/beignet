/**
 * Interop chaos: crash mid-payment against live LND, resume from the same DB
 * (regtest).
 *
 * The channel is LND-funded. LND pays one baseline invoice, then a second
 * payment is interrupted at its nastiest point: the moment beignet's first
 * revoke_and_ack for the in-flight HTLC hits the wire, the storage is sealed
 * and every later send is dropped (fail-stop, exactly as a real SIGKILL
 * right after the revoke's bytes), then the node is destroyed. A fresh node
 * on the same DB file must reestablish, release the commitment_signed it
 * owes (issue #301), settle the interrupted payment so LND's blocked
 * sendPaymentSync resolves, survive without a force-close on either side,
 * and route a probe payment.
 *
 * Requires the compose stack (bitcoind 43782, lnd REST 8081 / P2P 9735).
 * Run solo:
 *   npx mocha --exit --timeout 240000 -r ts-node/register tests/lightning/interop/chaos-lnd-crash-resume.test.ts
 * (On hosts with a port override use e.g. LND_REST_PORT=8091.)
 * Auto-skips when the containers are down.
 */

import { expect } from 'chai';
import * as path from 'path';
import * as os from 'os';
import { LndRestClient } from './lnd-client';
import {
	isLndAvailable,
	createLndClient,
	waitForLndSync,
	waitForLndChannels,
	cleanupLndState,
	fundLndWallet,
	LND_P2P_HOST,
	LND_P2P_PORT,
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	setupRoutingForChannel,
	sleep
} from './lnd-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	ChannelState,
	REGTEST_CHAIN_HASH
} from '../../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { Network } from '../../../src/lightning/invoice/types';
import { LnCoinType } from '../../../src/lightning/keys/wallet-keys';
import { MessageType } from '../../../src/lightning/message/types';
import type { IStorageBackend } from '../../../src/lightning/storage/types';
import { KillSwitch, sealableStorage } from '../helpers/chaos-harness';

const SEED_PASSPHRASE = 'interop-seed-301';

async function waitFor(
	probe: () => boolean,
	what: string,
	timeoutMs: number,
	intervalMs = 250
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		if (probe()) return;
		await sleep(intervalMs);
	}
	throw new Error(`timed out waiting for ${what}`);
}

describe('Interop chaos: LND crash-resume (regtest)', function () {
	this.timeout(240_000);

	let lnd: LndRestClient;
	let lndPubkey: string;
	let skipAll = false;
	let node: LightningNode | null = null;
	let storage: SqliteStorage | null = null;

	before(async function () {
		this.timeout(60_000);
		if (!(await isLndAvailable())) {
			skipAll = true;
			console.log('    [skip] LND container not reachable');
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
		await waitForLndSync(lnd);
		await cleanupLndState(lnd);
		lndPubkey = (await lnd.getInfo()).identity_pubkey;
	});

	beforeEach(function () {
		if (skipAll) this.skip();
	});

	afterEach(() => {
		if (node) {
			try {
				node.destroy();
			} catch {
				/* already destroyed by the chaos kill */
			}
			node = null;
		}
		if (storage) {
			try {
				storage.close();
			} catch {
				/* ignore */
			}
			storage = null;
		}
	});

	const mkFeatures = (): FeatureFlags => {
		const f = FeatureFlags.empty();
		f.setOptional(Feature.DATA_LOSS_PROTECT);
		f.setOptional(Feature.STATIC_REMOTE_KEY);
		f.setOptional(Feature.PAYMENT_SECRET);
		f.setOptional(Feature.TLV_ONION);
		f.setOptional(Feature.CHANNEL_TYPE);
		f.setOptional(Feature.GOSSIP_QUERIES);
		f.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
		return f;
	};

	const mkNode = (s: IStorageBackend): LightningNode => {
		const n = LightningNode.fromMnemonic(TEST_MNEMONIC, {
			passphrase: SEED_PASSPHRASE,
			coinType: LnCoinType.REGTEST,
			network: Network.REGTEST,
			enableNetworking: true,
			localFeatures: mkFeatures(),
			chainHashes: [REGTEST_CHAIN_HASH],
			preferAnchors: true,
			storage: s
		});
		n.on('node:error', () => {
			/* absorb */
		});
		n.on('error', () => {
			/* absorb */
		});
		return n;
	};

	it('resumes after a kill on the first revoke_and_ack of an in-flight payment', async function () {
		const dbPath = path.join(
			os.tmpdir(),
			`chaos-lnd-${Date.now()}-${process.pid}.db`
		);

		try {
			// ── Life 1: open an LND-funded channel and settle a baseline payment ──
			storage = new SqliteStorage(dbPath);
			storage.open();
			const kill = new KillSwitch();
			node = mkNode(sealableStorage(storage, kill));
			const nodeId = node.getNodeId();

			await fundLndWallet(lnd, 110);
			await node.connectPeer(lndPubkey, LND_P2P_HOST, LND_P2P_PORT);
			await sleep(2000);
			await lnd.openChannelSync(nodeId, 500_000, 100_000);
			await mineBlocks(6);
			await sleep(3000);

			const channels = node.getChannelManager().listChannels();
			expect(channels.length).to.be.greaterThan(0);
			const channelId = channels[0].getChannelId()!;
			node.handleFundingConfirmed(channelId);
			await waitForLndChannels(lnd, 1, 30_000);
			// THIS run's channel point: the no-force-close assertion at the end
			// must ignore zombies of earlier runs (same seed, same pubkey) that
			// the before() cleanup force-closed.
			const lndView = await lnd.listChannels();
			const ourChannelPoint = (lndView.channels || []).find(
				(c) =>
					(c as unknown as { remote_pubkey?: string }).remote_pubkey ===
						nodeId && c.active
			)?.channel_point;
			expect(ourChannelPoint, 'LND lists our active channel').to.be.a('string');

			setupRoutingForChannel(node, lndPubkey);
			const tip = (await bitcoinRpc('getblockcount')) as number;
			node.handleNewBlock(tip);

			const baseline = node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'chaos baseline'
			});
			const baselinePay = await lnd.sendPaymentSync(baseline.bolt11);
			expect(baselinePay.payment_error || '').to.equal('');
			expect(baselinePay.payment_preimage).to.be.a('string');

			// Let the tail of the settle dance (final commitment round and
			// revoke_and_ack exchange) finish before arming the kill, so the
			// tap can only trip on the interrupted payment's own revoke.
			await sleep(3000);

			// ── Arm: seal storage, drop later sends, die after the revoke ──
			const victim = node;
			const pm = (
				victim as unknown as {
					peerManager: {
						sendToPeer(pk: string, type: number, payload: Buffer): void;
					};
				}
			).peerManager;
			const realSend = pm.sendToPeer.bind(pm);
			pm.sendToPeer = (pk, type, payload) => {
				// Fail-stop: after the kill instant nothing else may reach the
				// wire, exactly as a real SIGKILL right after the revoke's bytes.
				// Without this the node's follow-up commitment_signed escapes
				// while the write behind it was sealed away, an interleaving no
				// real crash can produce (and one that wedges reestablish).
				if (kill.killed) return;
				realSend(pk, type, payload);
				if (type === MessageType.REVOKE_AND_ACK) {
					kill.fire('post-send:revoke_and_ack');
					setImmediate(() => {
						try {
							victim.destroy();
						} catch {
							/* ignore */
						}
					});
				}
			};

			const interrupted = node.createInvoice({
				amountMsat: 4_000_000n,
				description: 'chaos interrupted'
			});
			const inflight = lnd
				.sendPaymentSync(interrupted.bolt11)
				.catch(() => null);

			await waitFor(() => kill.killed, 'chaos kill to fire', 30_000);
			await sleep(1500);

			// ── Life 2: fresh process simulation on the same DB file ──
			storage = new SqliteStorage(dbPath);
			storage.open();
			node = mkNode(storage);
			expect(node.getNodeId()).to.equal(nodeId);

			const broadcasts: unknown[] = [];
			node.on('broadcast:tx', (tx: unknown) => broadcasts.push(tx));

			const recovered = node.getChannelManager().listChannels();
			expect(recovered.length).to.be.greaterThan(0);
			const channel = recovered[0];
			expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

			setupRoutingForChannel(node, lndPubkey);
			node.handleNewBlock(tip);
			await node.connectPeer(lndPubkey, LND_P2P_HOST, LND_P2P_PORT);
			await waitFor(
				() => channel.getState() === ChannelState.NORMAL,
				'channel to reestablish to NORMAL',
				60_000
			);

			// The payment that was in flight across the crash must complete:
			// the restored node releases the owed commitment_signed, re-drives
			// the fulfill and LND's blocked sendPaymentSync resolves.
			const inflightResult = await Promise.race([
				inflight,
				sleep(90_000).then(() => {
					throw new Error('interrupted payment did not resolve');
				})
			]);
			expect(inflightResult, 'interrupted payment errored').to.not.equal(null);
			expect(inflightResult!.payment_error || '').to.equal('');
			expect(inflightResult!.payment_preimage).to.be.a('string');
			expect(inflightResult!.payment_preimage.length).to.be.greaterThan(0);

			// Probe payment over the resumed channel.
			const probe = node.createInvoice({
				amountMsat: 3_000_000n,
				description: 'chaos probe'
			});
			const probePay = await lnd.sendPaymentSync(probe.bolt11);
			expect(probePay.payment_error || '').to.equal('');
			expect(probePay.payment_preimage).to.be.a('string');

			// Neither side escalated to chain. The shared container carries
			// pending force-closes of zombie channels from other runs (the
			// before() cleanup itself force-closes them), so only THIS run's
			// channel point matters here.
			expect(broadcasts.length).to.equal(0);
			const pending = await lnd.pendingChannels();
			const oursForceClosing = (
				pending.pending_force_closing_channels || []
			).filter(
				(p) =>
					(p as unknown as { channel?: { channel_point?: string } }).channel
						?.channel_point === ourChannelPoint
			);
			expect(oursForceClosing.length).to.equal(0);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);
		} catch (err) {
			const msg = (err as Error).message || '';
			if (msg.includes('not available') || msg.includes('ECONNREFUSED')) {
				console.log(`    chaos-lnd-crash-resume skipped: ${msg}`);
				this.skip();
				return;
			}
			throw err;
		}
	});
});
