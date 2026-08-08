/**
 * Interop chaos: crash INSIDE a v2 (dual-funded) open against live CLN,
 * resume from the same DB over reestablish next_funding (regtest).
 *
 * Two kill points, the two sub-states the durable v2InFlight record makes
 * resumable (issues 288/289):
 *
 * 1. Before our tx_signatures leave. CLN contributes no inputs so it signs
 *    first; the kill lands after its signatures arrived and ours were about
 *    to go. The restart must answer CLN's reestablish next_funding_txid by
 *    retransmitting our tx_signatures byte-identically, broadcast, confirm,
 *    and end CHANNELD_NORMAL on CLN.
 * 2. Before our commitment_signed leaves, the state that owes it already
 *    durable (the persist-before-send boundary; the #302 analogue for
 *    opens). CLN always retransmits its own commitment_signed on a v2-open
 *    reestablish and asks for ours; the restart re-signs byte-identically
 *    (RFC 6979), the exchange completes, and the open proceeds to NORMAL.
 *
 * CLN is the strongest external oracle here: it hard-errors when a peer
 * forgets a v2 open past commitment_signed, so a resumed open reaching
 * CHANNELD_NORMAL proves the record carried everything BOLT 2 requires.
 *
 * Requires the compose `cln` container with --experimental-dual-fund. Run
 * solo:
 *   npx mocha --exit --timeout 300000 -r ts-node/register tests/lightning/interop/chaos-cln-v2open-txsigs.test.ts
 * Auto-skips when the containers are down.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as path from 'path';
import * as os from 'os';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	waitForClnPeerChannelNormal,
	CLN_P2P_HOST,
	CLN_P2P_PORT,
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	ensureBitcoindFunds,
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
	PaymentStatus,
	IFundingProvider
} from '../../../src/lightning/node/types';
import { ISpliceWalletInput } from '../../../src/lightning/channel/channel';
import type { IStorageBackend } from '../../../src/lightning/storage/types';
import { KillSwitch, sealableStorage } from '../helpers/chaos-harness';

bitcoin.initEccLib(ecc);

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

describe('Interop chaos: CLN v2 open crash-resume (regtest)', function () {
	this.timeout(300_000);

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
		const info = (await cln.getInfo()) as unknown as {
			id: string;
			our_features?: { init: string };
		};
		clnPubkey = info.id;
		// option_dual_fund = bit 28/29 of the init features.
		const init = BigInt(`0x${info.our_features?.init ?? '0'}`);
		if (((init >> 28n) & 1n) === 0n && ((init >> 29n) & 1n) === 0n) {
			skipAll = true;
			console.log('    [skip] CLN lacks --experimental-dual-fund');
			this.skip();
			return;
		}
		await ensureBitcoindFunds(2.0);
	});

	beforeEach(function () {
		if (skipAll) this.skip();
	});

	afterEach(() => {
		if (node) {
			try {
				node.disconnectPeer(clnPubkey);
			} catch {
				/* ignore */
			}
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
		f.setOptional(Feature.DUAL_FUND);
		return f;
	};

	/**
	 * A real bitcoind UTXO behind the funding provider, the role
	 * WalletFundingProvider plays in the daemon. The provider is only
	 * consulted in life 1: the restored node resumes from the record, whose
	 * witnesses were signed at creation.
	 */
	const mkProvider = async (): Promise<IFundingProvider> => {
		const walletPriv = crypto
			.createHash('sha256')
			.update(Buffer.from(`v2open-chaos-wallet-${Date.now()}`))
			.digest();
		const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
		const walletPayment = bitcoin.payments.p2wpkh({
			pubkey: walletPub,
			network: bitcoin.networks.regtest
		});
		const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
		const utxoValue = 600_000;
		const fundTxid = (await bitcoinRpc('sendtoaddress', [
			walletPayment.address!,
			utxoValue / 1e8
		])) as string;
		await mineBlocks(1);
		const prevRaw = (await bitcoinRpc('getrawtransaction', [
			fundTxid
		])) as string;
		const prevTx = bitcoin.Transaction.fromHex(prevRaw);
		const prevVout = prevTx.outs.findIndex((o) =>
			Buffer.from(o.script).equals(walletPayment.output!)
		);
		expect(prevVout).to.be.gte(0);
		const input: ISpliceWalletInput = {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: prevVout,
			value: BigInt(utxoValue),
			sequence: 0xfffffffd,
			confirmed: true,
			signWitness: (tx, inputIndex, value): Buffer[] => {
				const sighash = tx.hashForWitnessV0(
					inputIndex,
					scriptCode,
					Number(value),
					bitcoin.Transaction.SIGHASH_ALL
				);
				const der = bitcoin.script.signature.encode(
					Buffer.from(ecc.sign(sighash, walletPriv)),
					bitcoin.Transaction.SIGHASH_ALL
				);
				return [der, walletPub];
			}
		};
		return {
			buildFundingTransaction: async () => {
				throw new Error('v1 funding must not run for a v2 open');
			},
			broadcastTransaction: async (txHex: string) =>
				(await bitcoinRpc('sendrawtransaction', [txHex])) as string,
			selectSpliceInputs: async () => ({
				inputs: [input],
				changeScript: walletPayment.output!
			})
		};
	};

	const mkNode = (
		s: IStorageBackend,
		passphrase: string,
		fundingProvider?: IFundingProvider,
		kill?: KillSwitch,
		onRelay?: () => void
	): LightningNode => {
		const n = LightningNode.fromMnemonic(TEST_MNEMONIC, {
			passphrase,
			coinType: LnCoinType.REGTEST,
			network: Network.REGTEST,
			enableNetworking: true,
			localFeatures: mkFeatures(),
			chainHashes: [REGTEST_CHAIN_HASH],
			preferAnchors: true,
			storage: s,
			...(fundingProvider ? { fundingProvider } : {})
		});
		n.on('node:error', () => {
			/* absorb */
		});
		n.on('error', () => {
			/* absorb */
		});
		// No chain watcher in this harness: relay broadcast:tx to bitcoind
		// ourselves (the daemon's Electrum chain watcher does this in
		// production). Duplicate submissions are fine; CLN may broadcast too.
		// FAIL-STOP: once the kill fired, nothing may reach the network.
		// The armed send tap drops the message and returns, but the
		// synchronous dispatcher continues its batch, and for the
		// tx_signatures kill that batch ends in BROADCAST_TX; relaying it
		// would put the funding on chain from the DYING life and life 2's
		// chain-presence assertions would prove nothing.
		n.on('broadcast:tx', (tx: Buffer) => {
			if (kill?.killed) return;
			onRelay?.();
			bitcoinRpc('sendrawtransaction', [tx.toString('hex')]).catch(() => {
				/* already known / already broadcast */
			});
		});
		return n;
	};

	/**
	 * One crash-resume run: open a v2 channel to CLN, fail-stop the moment
	 * the given message type would leave (drop it, seal the storage, destroy
	 * the node), restart on the same file, reconnect, and require the open
	 * to complete through NORMAL on both sides with a probe payment.
	 */
	async function crashResumeRun(
		passphrase: string,
		killOn: MessageType,
		killLabel: string
	): Promise<void> {
		const dbPath = path.join(
			os.tmpdir(),
			`chaos-cln-v2open-${Date.now()}-${process.pid}.db`
		);

		// ── Life 1: dual-funded open, die at the armed send ──
		storage = new SqliteStorage(dbPath);
		storage.open();
		const kill = new KillSwitch();
		let life1Broadcasts = 0;
		node = mkNode(
			sealableStorage(storage, kill),
			passphrase,
			await mkProvider(),
			kill,
			() => life1Broadcasts++
		);
		const nodeId = node.getNodeId();

		await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await sleep(2000);

		const victim = node;
		const pm = (
			victim as unknown as {
				peerManager: {
					sendToPeer(pk: string, type: number, payload: Buffer): void;
				};
			}
		).peerManager;
		const realSend = pm.sendToPeer.bind(pm);
		let droppedPayload: Buffer | null = null;
		pm.sendToPeer = (pk, type, payload) => {
			// Fail-stop: everything up to the armed send is durable, the armed
			// message never reaches the wire, nothing after does either.
			if (kill.killed) return;
			if (type === killOn) {
				droppedPayload = Buffer.from(payload);
				kill.fire(killLabel);
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

		const channel = node.openChannelV2(clnPubkey, {
			fundingSatoshis: 500_000n,
			fundingFeeratePerkw: 1000,
			commitmentFeeratePerkw: 253
		});
		void channel;

		await waitFor(() => kill.killed, 'chaos kill to fire', 60_000);
		await sleep(1500);
		expect(droppedPayload, 'the armed message was captured').to.not.equal(null);
		expect(
			life1Broadcasts,
			'the dying life relayed nothing to bitcoind'
		).to.equal(0);

		// ── Life 2: fresh process simulation on the same DB file ──
		storage = new SqliteStorage(dbPath);
		storage.open();
		const rows = storage.loadAllChannels();
		expect(rows.length, 'the durable open survived the kill').to.equal(1);
		expect(
			rows[0].state.v2InFlight,
			'the row carries the v2InFlight record'
		).to.not.equal(null);
		// The funding tx must NOT be on the network yet: chain presence
		// after the resume has to be attributable to the RESTORED node (or
		// to CLN completing with what the restored node retransmits), never
		// to the dying life.
		const rowTxidHex = Buffer.from(rows[0].state.fundingTxid!)
			.reverse()
			.toString('hex');
		let preSeen = false;
		try {
			await bitcoinRpc('getrawtransaction', [rowTxidHex]);
			preSeen = true;
		} catch {
			/* expected: not broadcast */
		}
		expect(
			preSeen,
			'the funding tx is not on chain before the restored node acts'
		).to.equal(false);

		node = mkNode(storage, passphrase);
		expect(node.getNodeId()).to.equal(nodeId);
		const restored = node.getChannelManager().listChannels();
		expect(restored.length, 'the channel restored').to.equal(1);
		const channelId = restored[0].getChannelId()!;

		// Capture the restored node's first send of the armed type: the
		// resume must re-emit the very bytes the dead process dropped
		// (verbatim witnesses for tx_signatures, an RFC 6979 re-sign for
		// commitment_signed).
		const pm2 = (
			node as unknown as {
				peerManager: {
					sendToPeer(pk: string, type: number, payload: Buffer): void;
				};
			}
		).peerManager;
		const realSend2 = pm2.sendToPeer.bind(pm2);
		let retransmitted: Buffer | null = null;
		pm2.sendToPeer = (pk, type, payload) => {
			if (type === killOn && retransmitted === null) {
				retransmitted = Buffer.from(payload);
			}
			realSend2(pk, type, payload);
		};

		await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);

		// Reestablish carries next_funding on CLN's side; the resume either
		// retransmits our tx_signatures or re-signs the owed commitment, then
		// the funding tx becomes broadcastable and reaches bitcoind.
		const restoredNode = node;
		let displayTxid: string | null = null;
		await waitFor(
			() => {
				const st = restoredNode
					.getChannelManager()
					.getChannel(channelId)
					?.getFullState();
				if (!st?.fundingTxid) return false;
				displayTxid = Buffer.from(st.fundingTxid).reverse().toString('hex');
				return true;
			},
			'restored channel to hold the negotiated funding txid',
			30_000,
			500
		);

		let seen = false;
		const seenDeadline = Date.now() + 60_000;
		while (Date.now() < seenDeadline) {
			try {
				await bitcoinRpc('getrawtransaction', [displayTxid!]);
				seen = true;
				break;
			} catch {
				await sleep(1000);
			}
		}
		expect(seen, `funding tx ${displayTxid} was broadcast`).to.equal(true);

		await mineBlocks(6);
		await sleep(2000);
		node.handleFundingConfirmed(channelId);

		await waitForClnPeerChannelNormal(cln, nodeId, 90_000);
		await waitFor(
			() =>
				restoredNode.getChannelManager().getChannel(channelId)?.getState() ===
				ChannelState.NORMAL,
			'beignet side NORMAL',
			30_000,
			500
		);

		// The boundary was genuinely replayed: the restored node re-sent the
		// dropped message BYTE-IDENTICALLY.
		expect(
			retransmitted,
			'the restored node re-sent the dropped message'
		).to.not.equal(null);
		expect(
			(retransmitted as unknown as Buffer).equals(droppedPayload!),
			'the retransmission is byte-identical to the dropped send'
		).to.equal(true);

		// CLN agrees on the SAME funding tx: the resumed exchange finished
		// the open the dead process started, rather than a fresh one.
		const { channels: clnChannels } = await cln.listChannels();
		const entry = (clnChannels || []).find(
			(c) =>
				c.peer_id === nodeId &&
				c.state === 'CHANNELD_NORMAL' &&
				c.funding_txid === displayTxid
		);
		expect(entry, `CLN holds CHANNELD_NORMAL on funding ${displayTxid}`).to
			.exist;

		// Probe payment over the resumed channel (beignet holds the balance:
		// v2 opens push nothing).
		const tip = (await bitcoinRpc('getblockcount')) as number;
		node.handleNewBlock(tip);
		setupRoutingForChannel(node, clnPubkey);
		const label = `v2open-probe-${Date.now()}`;
		const clnInvoice = await cln.createInvoice(
			3_000_000,
			label,
			'chaos v2 open probe'
		);
		const payment = node.sendPayment(clnInvoice.bolt11);
		await waitFor(
			() => payment.status !== PaymentStatus.PENDING,
			'probe payment to settle',
			30_000,
			200
		);
		expect(payment.status, 'probe payment settled').to.equal(
			PaymentStatus.COMPLETED
		);
		console.log(
			`    v2 open resumed after ${killLabel}: funding ${displayTxid}`
		);
	}

	it('resumes a v2 open whose tx_signatures died with the process', async function () {
		try {
			await crashResumeRun(
				'interop-seed-v2open-1',
				MessageType.TX_SIGNATURES,
				'pre-send:tx_signatures'
			);
		} catch (err) {
			const msg = (err as Error).message || '';
			if (msg.includes('not available') || msg.includes('ECONNREFUSED')) {
				console.log(`    chaos-cln-v2open skipped: ${msg}`);
				this.skip();
				return;
			}
			throw err;
		}
	});

	it('resumes a v2 open whose commitment_signed died with the process, the state owing it durable', async function () {
		try {
			await crashResumeRun(
				'interop-seed-v2open-2',
				MessageType.COMMITMENT_SIGNED,
				'pre-send:commitment_signed'
			);
		} catch (err) {
			const msg = (err as Error).message || '';
			if (msg.includes('not available') || msg.includes('ECONNREFUSED')) {
				console.log(`    chaos-cln-v2open skipped: ${msg}`);
				this.skip();
				return;
			}
			throw err;
		}
	});
});
