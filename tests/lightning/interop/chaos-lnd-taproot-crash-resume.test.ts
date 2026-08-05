/**
 * Interop chaos: crash mid-payment on a simple taproot channel against live
 * LND, resume from the same DB (regtest).
 *
 * Beignet funds a taproot channel to LND (MuSig2 funding) with a push so LND
 * can pay. LND pays one baseline invoice, then a second payment is
 * interrupted: the moment beignet's first revoke_and_ack for the in-flight
 * HTLC hits the wire, the storage is sealed and every later send is dropped
 * (fail-stop, as a real SIGKILL right after the revoke's bytes), then the
 * node is destroyed. A fresh node on the same DB file must reestablish (the
 * taproot rebuild re-advertises its verification nonce), settle the
 * interrupted payment, stay off chain, and route a probe payment.
 *
 * Requires the standalone `lnd-taproot` container (REST 8082, P2P 9736).
 * It shares host port 8082 with the compose `eclair` container; stop eclair
 * first (docker stop eclair && docker start lnd-taproot).
 * Run solo:
 *   npx mocha --exit --timeout 240000 -r ts-node/register tests/lightning/interop/chaos-lnd-taproot-crash-resume.test.ts
 * Auto-skips when the containers are down.
 */

import { expect } from 'chai';
import * as path from 'path';
import * as os from 'os';
import { LndRestClient } from './lnd-client';
import {
	isLndTaprootAvailable,
	createLndTaprootClient,
	LND_TAPROOT_P2P_HOST,
	LND_TAPROOT_P2P_PORT
} from './lnd-taproot-helpers';
import {
	waitForLndSync,
	waitForLndChannels,
	cleanupLndState
} from './lnd-helpers';
import {
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	ensureBitcoindFunds,
	setupRoutingForChannel,
	sleep,
	BitcoindFundingProvider
} from './shared-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	ChannelState,
	REGTEST_CHAIN_HASH
} from '../../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import { MessageType } from '../../../src/lightning/message/types';
import type { IStorageBackend } from '../../../src/lightning/storage/types';
import { KillSwitch, sealableStorage } from '../helpers/chaos-harness';

const SEED_PASSPHRASE = 'taproot-interop-304';

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

describe('Interop chaos: LND taproot crash-resume (regtest)', function () {
	this.timeout(240_000);

	let lnd: LndRestClient;
	let lndPubkey: string;
	let skipAll = false;
	let node: LightningNode | null = null;
	let storage: SqliteStorage | null = null;

	before(async function () {
		this.timeout(60_000);
		if (!(await isLndTaprootAvailable())) {
			skipAll = true;
			console.log('    [skip] lnd-taproot container not reachable');
			this.skip();
			return;
		}
		const client = await createLndTaprootClient();
		if (!client) {
			skipAll = true;
			console.log('    [skip] lnd-taproot macaroon not loadable');
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
		f.setOptional(Feature.OPTION_TAPROOT);
		return f;
	};

	const mkNode = (
		s: IStorageBackend,
		fundingProvider: BitcoindFundingProvider
	): LightningNode => {
		const keys = deriveLightningKeysFromMnemonic(
			TEST_MNEMONIC,
			SEED_PASSPHRASE,
			LnCoinType.REGTEST
		);
		const n = new LightningNode({
			nodePrivateKey: keys.nodePrivateKey,
			channelBasepoints: keys.channelBasepoints,
			perCommitmentSeed: keys.perCommitmentSeed,
			fundingPrivkey: keys.fundingPrivkey,
			htlcBasepointSecret: keys.htlcBasepointSecret,
			revocationBasepointSecret: keys.revocationBasepointSecret,
			paymentBasepointSecret: keys.paymentBasepointSecret,
			delayedPaymentBasepointSecret: keys.delayedPaymentBasepointSecret,
			network: Network.REGTEST,
			enableNetworking: true,
			localFeatures: mkFeatures(),
			chainHashes: [REGTEST_CHAIN_HASH],
			preferAnchors: true,
			preferTaproot: true,
			fundingProvider,
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
			`chaos-taproot-${Date.now()}-${process.pid}.db`
		);

		try {
			// ── Life 1: beignet-funded taproot channel, baseline payment ──
			await ensureBitcoindFunds(2.0);
			const fundingProvider = new BitcoindFundingProvider();
			storage = new SqliteStorage(dbPath);
			storage.open();
			const kill = new KillSwitch();
			node = mkNode(sealableStorage(storage, kill), fundingProvider);
			const nodeId = node.getNodeId();

			await node.connectPeer(
				lndPubkey,
				LND_TAPROOT_P2P_HOST,
				LND_TAPROOT_P2P_PORT
			);
			await sleep(2000);
			// The push gives LND outbound liquidity for the LND→beignet payments.
			node.openChannel(lndPubkey, 200_000n, 100_000_000n);

			const cm = node.getChannelManager();
			await waitFor(
				() => cm.listChannels().some((c) => c.getChannelId() !== null),
				'taproot channel to be funded',
				30_000,
				500
			);
			const funded = cm.listChannels().find((c) => c.getChannelId() !== null)!;
			const channelId = funded.getChannelId()!;

			const fundingTxid = funded.getFullState().fundingTxid;
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

			await mineBlocks(6);
			await sleep(3000);
			node.handleFundingConfirmed(channelId);
			const tip = (await bitcoinRpc('getblockcount')) as number;
			node.handleNewBlock(tip);
			await waitForLndChannels(lnd, 1, 60_000);
			await waitFor(
				() => funded.getState() === ChannelState.NORMAL,
				'channel_ready exchange to complete',
				30_000
			);
			// LND marks the channel active moments before it will actually
			// route through it; paying immediately loses to that race.
			await sleep(2000);
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

			const baseline = node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'chaos baseline'
			});
			const baselinePay = await lnd.sendPaymentSync(baseline.bolt11);
			expect(baselinePay.payment_error || '').to.equal('');
			expect(baselinePay.payment_preimage).to.be.a('string');

			// Let the tail of the settle dance finish before arming the kill.
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
			node = mkNode(storage, new BitcoindFundingProvider());
			expect(node.getNodeId()).to.equal(nodeId);

			const broadcasts: unknown[] = [];
			node.on('broadcast:tx', (tx: unknown) => broadcasts.push(tx));

			const recovered = node.getChannelManager().listChannels();
			expect(recovered.length).to.be.greaterThan(0);
			const channel = recovered[0];
			expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

			setupRoutingForChannel(node, lndPubkey);
			node.handleNewBlock(tip);
			await node.connectPeer(
				lndPubkey,
				LND_TAPROOT_P2P_HOST,
				LND_TAPROOT_P2P_PORT
			);
			await waitFor(
				() => channel.getState() === ChannelState.NORMAL,
				'taproot channel to reestablish to NORMAL',
				60_000
			);

			// The payment that was in flight across the crash must complete.
			const inflightResult = await Promise.race([
				inflight,
				sleep(90_000).then(() => {
					throw new Error('interrupted payment did not resolve');
				})
			]);
			expect(inflightResult, 'interrupted payment errored').to.not.equal(null);
			expect(inflightResult!.payment_error || '').to.equal('');
			expect(inflightResult!.payment_preimage).to.be.a('string');

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
				console.log(`    chaos-lnd-taproot-crash-resume skipped: ${msg}`);
				this.skip();
				return;
			}
			throw err;
		}
	});
});
