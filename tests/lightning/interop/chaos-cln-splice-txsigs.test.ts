/**
 * Interop chaos: crash between the splice commitment round and tx_signatures
 * against live CLN, resume from the same DB (regtest).
 *
 * The channel is CLN-funded with a push so beignet holds balance to splice
 * out. Beignet initiates a splice-out; the moment its tx_signatures would go
 * out, the message is dropped, the storage is sealed and the node destroyed
 * (fail-stop: the splice commitment round is durable, the signatures never
 * left). A fresh node on the same DB file must reestablish with
 * next_funding_txid on both sides, retransmit tx_signatures, drive the
 * splice to broadcast, confirm and lock it, and end NORMAL on the new
 * funding outpoint with CLN agreeing.
 *
 * Requires the compose `cln` container (CLNRest 3010, P2P 19846) with
 * experimental splicing. Run solo:
 *   npx mocha --exit --timeout 240000 -r ts-node/register tests/lightning/interop/chaos-cln-splice-txsigs.test.ts
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
import type { IStorageBackend } from '../../../src/lightning/storage/types';
import { KillSwitch, sealableStorage } from '../helpers/chaos-harness';

const SEED_PASSPHRASE = 'interop-seed-305';

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

describe('Interop chaos: CLN splice tx_signatures crash-resume (regtest)', function () {
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
		f.setOptional(Feature.QUIESCE);
		f.setOptional(Feature.SPLICE);
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

	/** Current splice txid recorded on the channel state (display order). */
	const spliceTxidHex = (
		n: LightningNode,
		channelId: Buffer
	): string | null => {
		const st = n
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState() as unknown as { spliceFundingTxid?: Buffer | null };
		return st.spliceFundingTxid
			? Buffer.from(st.spliceFundingTxid).reverse().toString('hex')
			: null;
	};

	it('resumes a splice whose tx_signatures died with the process', async function () {
		const dbPath = path.join(
			os.tmpdir(),
			`chaos-cln-splice-${Date.now()}-${process.pid}.db`
		);

		try {
			// ── Life 1: CLN-funded channel with pushed balance, splice-out ──
			storage = new SqliteStorage(dbPath);
			storage.open();
			const kill = new KillSwitch();
			node = mkNode(sealableStorage(storage, kill));
			const nodeId = node.getNodeId();

			await fundClnWallet(cln);
			await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
			await sleep(2000);
			// The push gives beignet the local balance the splice-out spends.
			await cln.fundChannel(nodeId, 500_000, 200_000_000);
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
			const oldFundingTxidHex = Buffer.from(
				channels[0].getFullState().fundingTxid!
			).toString('hex');

			setupRoutingForChannel(node, clnPubkey);
			const tip = (await bitcoinRpc('getblockcount')) as number;
			node.handleNewBlock(tip);

			// ── Arm: drop tx_signatures, seal storage, die ──
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
				// Fail-stop: the splice commitment round is durable, the
				// tx_signatures never reach the wire, nothing after does either.
				if (kill.killed) return;
				if (type === MessageType.TX_SIGNATURES) {
					kill.fire('pre-send:tx_signatures');
					setImmediate(() => {
						try {
							victim.destroy();
						} catch {
							/* ignore */
						}
					});
					return;
				}
				realSend(pk, type, payload);
			};

			const spliceResult = node.spliceOut(channelId, 45_000n, 1000);
			expect(spliceResult.ok, spliceResult.error).to.equal(true);

			await waitFor(() => kill.killed, 'chaos kill to fire', 60_000);
			await sleep(1500);

			// ── Life 2: fresh process simulation on the same DB file ──
			storage = new SqliteStorage(dbPath);
			storage.open();
			node = mkNode(storage);
			expect(node.getNodeId()).to.equal(nodeId);

			const recovered = node.getChannelManager().listChannels();
			expect(recovered.length).to.be.greaterThan(0);

			setupRoutingForChannel(node, clnPubkey);
			node.handleNewBlock(tip);
			await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);

			// Reestablish carries next_funding_txid on both sides; beignet
			// retransmits its tx_signatures and the splice proceeds. Wait for
			// the negotiated splice tx to reach bitcoind, mine it to lock
			// depth, and let beignet send splice_locked (no chain backend).
			const restoredNode = node;
			let spliceTxid: string | null = null;
			await waitFor(
				() => {
					spliceTxid = spliceTxidHex(restoredNode, channelId);
					return spliceTxid !== null;
				},
				'restored channel to recall the splice txid',
				30_000,
				500
			);

			let seen = false;
			const seenDeadline = Date.now() + 60_000;
			while (Date.now() < seenDeadline) {
				try {
					await bitcoinRpc('getrawtransaction', [spliceTxid!]);
					seen = true;
					break;
				} catch {
					await sleep(1000);
				}
			}
			expect(seen, `splice tx ${spliceTxid} was broadcast`).to.equal(true);

			await mineBlocks(6);
			await sleep(2000);
			node.getChannelManager().sendSpliceLocked(channelId);

			// Splice completes: NORMAL on a new funding outpoint.
			await waitFor(
				() => {
					const st = restoredNode
						.getChannelManager()
						.getChannel(channelId)
						?.getFullState();
					return (
						!!st &&
						st.state === ChannelState.NORMAL &&
						!!st.fundingTxid &&
						Buffer.from(st.fundingTxid).toString('hex') !== oldFundingTxidHex
					);
				},
				'splice to complete on the new funding outpoint',
				90_000,
				1000
			);

			// CLN agrees on the same post-splice channel.
			const expectedFunding = spliceTxid!;
			const deadline = Date.now() + 90_000;
			let last = '';
			let clnNormal = false;
			while (Date.now() < deadline) {
				const { channels: clnChannels } = await cln.listChannels();
				const entry = (clnChannels || []).find(
					(c) => c.peer_id === nodeId && c.funding_txid === expectedFunding
				);
				if (entry && entry.state === 'CHANNELD_NORMAL') {
					clnNormal = true;
					break;
				}
				last = entry ? entry.state : 'no-entry';
				await sleep(1000);
			}
			expect(
				clnNormal,
				`CLN reached CHANNELD_NORMAL on ${expectedFunding} (last: ${last})`
			).to.equal(true);

			// Probe payment over the spliced channel.
			const probe = node.createInvoice({
				amountMsat: 3_000_000n,
				description: 'chaos splice probe'
			});
			const probePay = await cln.pay(probe.bolt11);
			expect(probePay.payment_preimage).to.be.a('string');
			expect(probePay.payment_preimage.length).to.be.greaterThan(0);
		} catch (err) {
			const msg = (err as Error).message || '';
			if (msg.includes('not available') || msg.includes('ECONNREFUSED')) {
				console.log(`    chaos-cln-splice-txsigs skipped: ${msg}`);
				this.skip();
				return;
			}
			throw err;
		}
	});
});
