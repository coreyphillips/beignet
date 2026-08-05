/**
 * Interop chaos: crash mid-payment against live CLN, resume from the same DB
 * (regtest).
 *
 * The channel is CLN-funded. CLN pays one baseline invoice, then a second
 * payment is interrupted: the moment beignet's first revoke_and_ack for the
 * in-flight HTLC hits the wire, the storage is sealed (post-send semantics:
 * everything up to the send is durable, nothing after persists) and the node
 * is destroyed. A fresh node on the same DB file must reestablish, settle
 * the interrupted payment, stay off chain on both sides, and route a probe
 * payment.
 *
 * Requires the compose `cln` container (CLNRest 3010, P2P 19846).
 * Run solo:
 *   npx mocha --exit --timeout 240000 -r ts-node/register tests/lightning/interop/chaos-cln-crash-resume.test.ts
 * Auto-skips when the containers are down.
 */

import { expect } from 'chai';
import * as path from 'path';
import * as os from 'os';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	waitForClnChannels,
	waitForClnPeerChannelNormal,
	fundClnWallet,
	CLN_P2P_HOST,
	CLN_P2P_PORT,
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	setupRoutingForChannel,
	sleep
} from './cln-helpers';
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

const SEED_PASSPHRASE = 'interop-seed-302';

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

describe('Interop chaos: CLN crash-resume (regtest)', function () {
	this.timeout(240_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let skipAll = false;
	let node: LightningNode | null = null;
	let storage: SqliteStorage | null = null;

	before(async function () {
		this.timeout(60_000);
		if (!(await isClnAvailable())) {
			skipAll = true;
			console.log('    [skip] CLN container not reachable');
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
		clnPubkey = (await cln.getInfo()).id;
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
			`chaos-cln-${Date.now()}-${process.pid}.db`
		);

		try {
			// ── Life 1: open a CLN-funded channel and settle a baseline payment ──
			storage = new SqliteStorage(dbPath);
			storage.open();
			const kill = new KillSwitch();
			node = mkNode(sealableStorage(storage, kill));
			const nodeId = node.getNodeId();

			await fundClnWallet(cln);
			await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
			await sleep(2000);
			await cln.fundChannel(nodeId, 500_000);
			await mineBlocks(6);
			await sleep(3000);

			const channels = node.getChannelManager().listChannels();
			expect(channels.length).to.be.greaterThan(0);
			const channelId = channels[0].getChannelId()!;
			node.handleFundingConfirmed(channelId);
			await waitForClnChannels(cln, 1, 30_000);
			await waitFor(
				() => channels[0].getState() === ChannelState.NORMAL,
				'channel_ready exchange to complete',
				30_000
			);

			setupRoutingForChannel(node, clnPubkey);
			const tip = (await bitcoinRpc('getblockcount')) as number;
			node.handleNewBlock(tip);

			const baseline = node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'chaos baseline'
			});
			const baselinePay = await cln.pay(baseline.bolt11);
			expect(baselinePay.payment_preimage).to.be.a('string');
			expect(baselinePay.payment_preimage.length).to.be.greaterThan(0);

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
			const inflight = cln.pay(interrupted.bolt11).catch(() => null);

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

			setupRoutingForChannel(node, clnPubkey);
			node.handleNewBlock(tip);
			await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
			await waitFor(
				() => channel.getState() === ChannelState.NORMAL,
				'channel to reestablish to NORMAL',
				60_000
			);

			// The payment that was in flight across the crash must complete on
			// the payee side: the restored node re-drives the fulfill after
			// reestablish. CLN's blocked pay call resolves with the preimage
			// (tolerate a CLNRest transport hiccup; the payee-side record and
			// the probe below are the ground truth).
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
			const inflightResult = await Promise.race([
				inflight,
				sleep(60_000).then(() => null)
			]);
			if (inflightResult) {
				expect(inflightResult.payment_preimage).to.be.a('string');
				expect(inflightResult.payment_preimage.length).to.be.greaterThan(0);
			}

			// Probe payment over the resumed channel.
			const probe = node.createInvoice({
				amountMsat: 3_000_000n,
				description: 'chaos probe'
			});
			const probePay = await cln.pay(probe.bolt11);
			expect(probePay.payment_preimage).to.be.a('string');
			expect(probePay.payment_preimage.length).to.be.greaterThan(0);

			// Neither side escalated to chain.
			expect(broadcasts.length).to.equal(0);
			await waitForClnPeerChannelNormal(cln, nodeId, 30_000);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);
		} catch (err) {
			const msg = (err as Error).message || '';
			if (msg.includes('not available') || msg.includes('ECONNREFUSED')) {
				console.log(`    chaos-cln-crash-resume skipped: ${msg}`);
				this.skip();
				return;
			}
			throw err;
		}
	});
});
