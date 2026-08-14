/**
 * Interop chaos: crash INSIDE a v2 (dual-funded) open against live Eclair,
 * resume from the same DB over reestablish next_funding (regtest).
 *
 * The Eclair mirror of chaos-cln-v2open-txsigs.test.ts, closing issue #305:
 * Eclair 0.14+ implements the post-#1289 channel_reestablish next_funding
 * form (TLV type 1 = [32:txid][1:retransmit_flags]) that beignet emits, so
 * a mid-open crash must now resume against Eclair exactly as it does against
 * CLN. Eclair 0.13.x could not decode that TLV (its type 1 was a different,
 * strictly 32-byte field) and is not supported here.
 *
 * Two kill points, the two sub-states the durable v2InFlight record makes
 * resumable (issues 288/289):
 *
 * 1. Before our tx_signatures leave. Eclair contributes no inputs so it
 *    signs first; the kill lands after its signatures arrived and ours were
 *    about to go. The restart must answer Eclair's reestablish next_funding
 *    by retransmitting our tx_signatures byte-identically, broadcast,
 *    confirm, and end NORMAL on Eclair.
 * 2. Before our commitment_signed leaves, the state that owes it already
 *    durable (the persist-before-send boundary). Eclair's reestablish sets
 *    retransmit_flags bit 0 asking for our commitment_signed; the restart
 *    re-signs byte-identically (RFC 6979), the exchange completes, and the
 *    open proceeds to NORMAL. NOTE: this cell keeps the dying node's socket
 *    open for a moment after the kill. Eclair only persists the open once
 *    its FSM reaches WAIT_FOR_DUAL_FUNDING_SIGNED, and that transition
 *    (driven by its interactive-tx builder) races an instant disconnect; a
 *    disconnect that wins the race hits WAIT_FOR_DUAL_FUNDING_CREATED,
 *    which aborts the open by design (spec-legal: resumability starts at
 *    the commitment_signed exchange). The delayed teardown deterministically
 *    lands the kill in the RESUMABLE state this test is about; the
 *    fail-stop contract is untouched (no send, no persist after the kill).
 *
 * Requires the compose `eclair` container (0.14+, option_dual_fund enabled;
 * HTTP 8082, P2P 9737). On ARM Macs run an arm64-native image and set
 * ECLAIR_ARM64_NATIVE=1. Run solo:
 *   ECLAIR_ARM64_NATIVE=1 npx mocha --exit --timeout 300000 -r ts-node/register tests/lightning/interop/chaos-eclair-v2open-txsigs.test.ts
 * Auto-skips when the containers are down.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as path from 'path';
import * as os from 'os';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { EclairRestClient, IEclairChannel } from './eclair-client';
import {
	isEclairAvailable,
	createEclairClient,
	waitForEclairSync,
	waitForEclairPeerChannelNormal,
	restartEclairAndSync,
	ECLAIR_P2P_HOST,
	ECLAIR_P2P_PORT,
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	ensureBitcoindFunds,
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
	PaymentStatus,
	IFundingProvider
} from '../../../src/lightning/node/types';
import { ISpliceWalletInput } from '../../../src/lightning/channel/channel';
import type { IStorageBackend } from '../../../src/lightning/storage/types';
import { KillSwitch, sealableStorage } from '../helpers/chaos-harness';

bitcoin.initEccLib(ecc);

const isArmMac = os.platform() === 'darwin' && os.arch() === 'arm64';
const skipChannelTests = isArmMac && process.env.ECLAIR_ARM64_NATIVE !== '1';

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

describe('Interop chaos: Eclair v2 open crash-resume (regtest)', function () {
	this.timeout(300_000);

	let eclair: EclairRestClient;
	let eclairPubkey: string;
	let skipAll = false;
	let node: LightningNode | null = null;
	let storage: SqliteStorage | null = null;

	before(async function () {
		this.timeout(120_000);
		if (skipChannelTests) {
			skipAll = true;
			console.log(
				'    [skip] ARM Mac without ECLAIR_ARM64_NATIVE=1 (amd64 Eclair SIGSEGVs on channel ops)'
			);
			this.skip();
			return;
		}
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
		const info = (await eclair.getInfo()) as unknown as {
			nodeId: string;
			features?: { activated?: Record<string, string> };
		};
		eclairPubkey = info.nodeId;
		if (!info.features?.activated?.option_dual_fund) {
			skipAll = true;
			console.log('    [skip] Eclair lacks option_dual_fund (need 0.14+)');
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
				node.disconnectPeer(eclairPubkey);
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
			.update(Buffer.from(`v2open-eclair-chaos-wallet-${Date.now()}`))
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
		// production). Duplicate submissions are fine; Eclair may broadcast
		// too. FAIL-STOP: once the kill fired, nothing may reach the network.
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
	 * One crash-resume run: open a v2 channel to Eclair, fail-stop the moment
	 * the given message type would leave (drop it, seal the storage, destroy
	 * the node), restart on the same file, reconnect, and require the open
	 * to complete through NORMAL on both sides with a probe payment.
	 */
	async function crashResumeRun(
		passphrase: string,
		killOn: MessageType,
		killLabel: string,
		destroyDelayMs: number
	): Promise<void> {
		const dbPath = path.join(
			os.tmpdir(),
			`chaos-eclair-v2open-${Date.now()}-${process.pid}.db`
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

		await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);
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
				// The kill is immediate (nothing sends or persists past this
				// instant); destroyDelayMs only delays the TCP teardown so
				// Eclair's FSM can finish entering its resumable state (see
				// the header note on the commitment_signed cell).
				setTimeout(() => {
					try {
						victim.destroy();
					} catch {
						/* ignore */
					}
				}, destroyDelayMs);
				return;
			}
			realSend(pk, type, payload);
		};

		const channel = node.openChannelV2(eclairPubkey, {
			fundingSatoshis: 500_000n,
			fundingFeeratePerkw: 1000,
			commitmentFeeratePerkw: 253
		});
		void channel;

		await waitFor(() => kill.killed, 'chaos kill to fire', 60_000);
		await sleep(1500 + destroyDelayMs);
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
		// to Eclair completing with what the restored node retransmits),
		// never to the dying life.
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

		await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);

		// Reestablish carries next_funding on Eclair's side; the resume
		// either retransmits our tx_signatures or re-signs the owed
		// commitment, then the funding tx becomes broadcastable and reaches
		// bitcoind.
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

		// The boundary was genuinely replayed: the restored node re-sent the
		// dropped message BYTE-IDENTICALLY. Assert this BEFORE the Eclair
		// restart below tears the connection down again.
		expect(
			retransmitted,
			'the restored node re-sent the dropped message'
		).to.not.equal(null);
		expect(
			(retransmitted as unknown as Buffer).equals(droppedPayload!),
			'the retransmission is byte-identical to the dropped send'
		).to.equal(true);

		await mineBlocks(6);
		await sleep(2000);
		node.handleFundingConfirmed(channelId);

		// Eclair only learns of confirmations reliably via a restart here
		// (ZMQ is unreliable under Docker on ARM Macs), and the restored
		// node's autoReconnect redial can race our explicit connect, so a
		// message sent on the losing transport is dead-lettered inside
		// Eclair. Cycle restart + reconnect: every reestablish re-answers
		// whatever Eclair still lacks (tx_signatures, channel_ready) on the
		// CURRENT transport, and every restart makes Eclair re-check the
		// funding confirmation at startup.
		// Eclair's post-restart funding watch (armed after the compose
		// container's max-restart-watch-delay, pinned to 1s) re-checks
		// confirmations only when a NEW block event arrives, so mine trigger
		// blocks inside the wait. The reconnected transport then carries the
		// channel_ready exchange.
		let eclairChannel: IEclairChannel | null = null;
		for (let attempt = 0; attempt < 2 && !eclairChannel; attempt++) {
			await restartEclairAndSync(eclair, 60_000);
			try {
				await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);
			} catch {
				/* may already be reconnecting */
			}
			await sleep(3000);
			for (let i = 0; i < 6 && !eclairChannel; i++) {
				await mineBlocks(1);
				try {
					eclairChannel = await waitForEclairPeerChannelNormal(
						eclair,
						nodeId,
						10_000
					);
				} catch {
					/* mine another trigger block and re-check */
				}
			}
		}
		expect(eclairChannel, 'Eclair reached NORMAL').to.not.equal(null);
		await waitFor(
			() =>
				restoredNode.getChannelManager().getChannel(channelId)?.getState() ===
				ChannelState.NORMAL,
			'beignet side NORMAL',
			30_000,
			500
		);

		// Eclair agrees on the SAME funding tx: the resumed exchange finished
		// the open the dead process started, rather than a fresh one. The
		// channel JSON embeds the funding txid (schema varies across Eclair
		// versions, so search the serialized form).
		expect(
			JSON.stringify(eclairChannel!).includes(displayTxid!),
			`Eclair NORMAL channel references funding ${displayTxid}`
		).to.equal(true);

		// Probe payment over the resumed channel (beignet holds the balance:
		// v2 opens push nothing).
		const tip = (await bitcoinRpc('getblockcount')) as number;
		node.handleNewBlock(tip);
		setupRoutingForChannel(node, eclairPubkey);
		const invoice = await eclair.createInvoice(
			3_000_000,
			`v2open-probe-${Date.now()}`
		);
		const payment = node.sendPayment(invoice.serialized);
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
				'interop-seed-v2open-eclair-1',
				MessageType.TX_SIGNATURES,
				'pre-send:tx_signatures',
				0
			);
		} catch (err) {
			const msg = (err as Error).message || '';
			if (msg.includes('not available') || msg.includes('ECONNREFUSED')) {
				console.log(`    chaos-eclair-v2open skipped: ${msg}`);
				this.skip();
				return;
			}
			throw err;
		}
	});

	it('resumes a v2 open whose commitment_signed died with the process, the state owing it durable', async function () {
		try {
			await crashResumeRun(
				'interop-seed-v2open-eclair-2',
				MessageType.COMMITMENT_SIGNED,
				'pre-send:commitment_signed',
				2500
			);
		} catch (err) {
			const msg = (err as Error).message || '';
			if (msg.includes('not available') || msg.includes('ECONNREFUSED')) {
				console.log(`    chaos-eclair-v2open skipped: ${msg}`);
				this.skip();
				return;
			}
			throw err;
		}
	});
});
