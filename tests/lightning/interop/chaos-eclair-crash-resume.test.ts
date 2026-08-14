/**
 * Interop chaos: crash mid-payment against live Eclair, resume from the same
 * DB (regtest).
 *
 * The channel is Eclair-funded. Eclair pays one baseline invoice, then a
 * second payment is interrupted: the moment beignet's first revoke_and_ack
 * for the in-flight HTLC hits the wire, the storage is sealed (post-send
 * semantics: everything up to the send is durable, nothing after persists)
 * and the node is destroyed. A fresh node on the same DB file must
 * reestablish, settle the interrupted payment, stay off chain on both sides,
 * and route a probe payment.
 *
 * Requires the compose `eclair` container (HTTP 8082, P2P 9737), which is
 * built locally and runs natively on arm64. Run solo:
 *   npx mocha --exit --timeout 240000 -r ts-node/register tests/lightning/interop/chaos-eclair-crash-resume.test.ts
 * Auto-skips when the containers are down.
 */

import { expect } from 'chai';
import * as path from 'path';
import * as os from 'os';
import { EclairRestClient } from './eclair-client';
import {
	isEclairAvailable,
	createEclairClient,
	waitForEclairSync,
	waitForEclairChannels,
	waitForEclairPayment,
	fundEclairWallet,
	restartEclairAndSync,
	ECLAIR_P2P_HOST,
	ECLAIR_P2P_PORT,
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	setupRoutingForChannel,
	sleep
} from './eclair-helpers';
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
import {
	PaymentDirection,
	PaymentStatus
} from '../../../src/lightning/node/types';
import type { IStorageBackend } from '../../../src/lightning/storage/types';
import { KillSwitch, sealableStorage } from '../helpers/chaos-harness';

const SEED_PASSPHRASE = 'interop-seed-303';

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

describe('Interop chaos: Eclair crash-resume (regtest)', function () {
	this.timeout(240_000);

	let eclair: EclairRestClient;
	let eclairPubkey: string;
	let skipAll = false;
	let node: LightningNode | null = null;
	let storage: SqliteStorage | null = null;

	before(async function () {
		this.timeout(60_000);
		if (!(await isEclairAvailable())) {
			skipAll = true;
			console.log('    [skip] Eclair container not reachable');
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
		await waitForEclairSync(eclair);
		eclairPubkey = (await eclair.getInfo()).nodeId;
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
			`chaos-eclair-${Date.now()}-${process.pid}.db`
		);

		try {
			// ── Life 1: Eclair-funded channel, baseline payment ──
			storage = new SqliteStorage(dbPath);
			storage.open();
			const kill = new KillSwitch();
			node = mkNode(sealableStorage(storage, kill));
			const nodeId = node.getNodeId();

			await fundEclairWallet(eclair);
			await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);
			await eclair.open(nodeId, 500_000);
			await sleep(3000);
			await mineBlocks(6);
			await sleep(1000);

			const channels = node.getChannelManager().listChannels();
			expect(channels.length).to.be.greaterThan(0);
			const channelId = channels[0].getChannelId()!;
			node.handleFundingConfirmed(channelId);
			await sleep(1000);

			// Eclair only sees the confirmations after a restart (ZMQ is
			// unreliable under Docker); the restart drops the P2P connection.
			await restartEclairAndSync(eclair, 60_000);
			await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);
			await waitForEclairChannels(eclair, 1, 30_000);
			await waitFor(
				() => channels[0].getState() === ChannelState.NORMAL,
				'channel_ready exchange to complete',
				30_000
			);

			setupRoutingForChannel(node, eclairPubkey);
			const tip = (await bitcoinRpc('getblockcount')) as number;
			node.handleNewBlock(tip);

			const baseline = node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'chaos baseline'
			});
			await eclair.payInvoice(baseline.bolt11);
			const baselineResult = await waitForEclairPayment(
				eclair,
				baseline.paymentHash.toString('hex'),
				30_000
			);
			expect(baselineResult.success, baselineResult.error).to.equal(true);

			// Let the tail of the settle dance finish before arming the kill,
			// so the tap can only trip on the interrupted payment's own revoke.
			await sleep(3000);

			// ── Arm: seal storage and die right after our first revoke_and_ack ──
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
			const interruptedHash = interrupted.paymentHash.toString('hex');
			await eclair.payInvoice(interrupted.bolt11);

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

			node.handleNewBlock(tip);
			await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);
			await waitFor(
				() => channel.getState() === ChannelState.NORMAL,
				'channel to reestablish to NORMAL',
				60_000
			);
			// Inject synthetic routing only AFTER the reconnect settled: if the
			// zero-signature graph entry exists when Eclair runs its on-connect
			// gossip sync, beignet serves it and Eclair 0.14+ closes the
			// connection on the malformed announcement, killing the reestablish
			// this test is about (see #340).
			setupRoutingForChannel(node, eclairPubkey);

			// The payment that was in flight across the crash must complete on
			// both sides after reestablish.
			const restoredNode = node;
			await waitFor(
				() =>
					restoredNode
						.listPayments()
						.some(
							(p) =>
								p.direction === PaymentDirection.INCOMING &&
								p.paymentHash.toString('hex') === interruptedHash &&
								p.status === PaymentStatus.COMPLETED
						),
				'interrupted payment to complete at the payee',
				90_000,
				500
			);
			const inflightResult = await waitForEclairPayment(
				eclair,
				interruptedHash,
				60_000
			);
			expect(inflightResult.success, inflightResult.error).to.equal(true);

			// Probe payment over the resumed channel.
			const probe = node.createInvoice({
				amountMsat: 3_000_000n,
				description: 'chaos probe'
			});
			await eclair.payInvoice(probe.bolt11);
			const probeResult = await waitForEclairPayment(
				eclair,
				probe.paymentHash.toString('hex'),
				30_000
			);
			expect(probeResult.success, probeResult.error).to.equal(true);

			// Neither side escalated to chain.
			expect(broadcasts.length).to.equal(0);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);
		} catch (err) {
			const msg = (err as Error).message || '';
			if (msg.includes('not available') || msg.includes('ECONNREFUSED')) {
				console.log(`    chaos-eclair-crash-resume skipped: ${msg}`);
				this.skip();
				return;
			}
			throw err;
		}
	});
});
