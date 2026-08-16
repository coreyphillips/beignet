/**
 * Interop: v2 open RBF in the BOLT 2 spec window, against live Eclair
 * (regtest). Closes issue #360 (this file previously pinned the pre-#360
 * refusal for issue #309; the refusal semantics stay covered by the unit
 * pins in dual-funding-reestablish.test.ts).
 *
 * BOLT 2's RBF window is a COMPLETED attempt: tx_signatures exchanged, the
 * funding tx broadcast but unconfirmed, no channel_ready yet. Eclair only
 * RBFs there. This test pins the full replacement live:
 *
 * 1. Eclair (the initiator) opens a dual-funded channel to beignet at a
 *    pinned 5 sat/vB; tx_signatures cross and the funding tx sits
 *    unconfirmed in the mempool.
 * 2. The eclair operator calls rbfopen at 15 sat/vB. Eclair sends
 *    tx_init_rbf (with its funding_output_contribution TLV); beignet
 *    answers tx_ack_rbf and the interactive exchange renegotiates the
 *    replacement through its own commitment and tx_signatures.
 * 3. Beignet records the replacement as attempt 1 and RETAINS attempt 0 in
 *    v2PreviousAttempts (either tx can still confirm; the replacement
 *    double-spends it). The replacement evicts the original from the
 *    mempool.
 * 4. Mining confirms the REPLACEMENT and both sides reach NORMAL on the new
 *    funding txid; a probe payment settles.
 *
 * Requires the compose `eclair` container (0.14+, option_dual_fund
 * enabled; HTTP 8082, P2P 9737). Run solo:
 *   npx mocha --exit --timeout 300000 -r ts-node/register tests/lightning/interop/eclair-v2open-rbf.test.ts
 * Auto-skips when the containers are down.
 */

import { expect } from 'chai';
import { EclairRestClient, IEclairChannel } from './eclair-client';
import {
	isEclairAvailable,
	createEclairClient,
	waitForEclairSync,
	waitForEclairPeerChannelNormal,
	waitForEclairPayment,
	restartEclairAndSync,
	fundEclairWallet,
	ECLAIR_P2P_HOST,
	ECLAIR_P2P_PORT,
	TEST_MNEMONIC,
	bitcoinRpc,
	mineBlocks,
	ensureBitcoindFunds,
	sleep
} from './eclair-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	ChannelState,
	REGTEST_CHAIN_HASH
} from '../../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { Network } from '../../../src/lightning/invoice/types';
import { LnCoinType } from '../../../src/lightning/keys/wallet-keys';
import { MessageType } from '../../../src/lightning/message/types';
import { decode } from '../../../src/lightning/invoice/decode';

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

describe('Interop: v2 open RBF completes vs Eclair (regtest, issue 360)', function () {
	this.timeout(300_000);

	let eclair: EclairRestClient;
	let eclairPubkey: string;
	let skipAll = false;
	let node: LightningNode | null = null;

	before(async function () {
		this.timeout(120_000);
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
				/* ignore */
			}
			node = null;
		}
	});

	// DUAL_FUND is an explicit opt-in: createInteropNode deliberately leaves
	// it off so the shared v1 tiers never negotiate v2 (see the compose
	// comment beside the CLN service).
	const mkDualFundNode = (): LightningNode => {
		const f = FeatureFlags.empty();
		f.setOptional(Feature.DATA_LOSS_PROTECT);
		f.setOptional(Feature.STATIC_REMOTE_KEY);
		f.setOptional(Feature.PAYMENT_SECRET);
		f.setOptional(Feature.TLV_ONION);
		f.setOptional(Feature.CHANNEL_TYPE);
		f.setOptional(Feature.GOSSIP_QUERIES);
		f.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
		f.setOptional(Feature.DUAL_FUND);
		const n = LightningNode.fromMnemonic(TEST_MNEMONIC, {
			passphrase: 'interop-seed-eclair-rbf-360-1',
			coinType: LnCoinType.REGTEST,
			network: Network.REGTEST,
			enableNetworking: true,
			localFeatures: f,
			chainHashes: [REGTEST_CHAIN_HASH],
			preferAnchors: true
		});
		n.on('node:error', () => {
			/* absorb */
		});
		n.on('error', () => {
			/* absorb */
		});
		// No chain watcher in this harness: relay broadcast:tx to bitcoind
		// ourselves. Eclair broadcasts the funding tx too; duplicates are fine.
		n.on('broadcast:tx', (tx: Buffer) => {
			bitcoinRpc('sendrawtransaction', [tx.toString('hex')]).catch(() => {
				/* already known / already broadcast */
			});
		});
		return n;
	};

	// No mid-run skip translation: the before hook already gates on container
	// availability, so an ECONNREFUSED once the scenario started is a real
	// regression and must FAIL.
	it('eclair rbfopen after tx_signatures is acked; the replacement completes, confirms and the channel reaches NORMAL on it', async function () {
		// ── Phase A: eclair-initiated v2 open, stopped before confirmation ──
		await fundEclairWallet(eclair);

		node = mkDualFundNode();
		const beignetNodeId = node.getNodeId();
		const abortedEvents: string[] = [];
		node.on('channel:aborted', (temporaryChannelId: Buffer, reason: string) => {
			abortedEvents.push(`${temporaryChannelId.toString('hex')}: ${reason}`);
		});

		await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);
		await sleep(2000);

		// Pin the initial funding feerate (5 sat/vB) so the rbfopen bump below
		// provably clears both floors (ours and eclair's 25/24).
		await eclair.open(
			beignetNodeId,
			500_000,
			undefined,
			'anchor_outputs_zero_fee_htlc_tx',
			100_000,
			5
		);

		const liveNode = node;
		await waitFor(
			() => liveNode.getChannelManager().listChannels().length > 0,
			'beignet to register the inbound v2 channel',
			30_000,
			500
		);
		const channel = liveNode.getChannelManager().listChannels()[0];
		await waitFor(
			() =>
				channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED &&
				!!channel.getFullState().fundingTxid &&
				channel.isV2AttemptBroadcastable(),
			'the v2 open to complete its signature exchange',
			60_000,
			500
		);
		const channelId = channel.getChannelId()!;
		expect(
			channel.getFullState().fundingVersion,
			'the open negotiated as a v2 (dual-funded) channel'
		).to.equal(2);
		const attempt0Txid = Buffer.from(channel.getFullState().fundingTxid!)
			.reverse()
			.toString('hex');

		// Broadcast but NOT confirmed: exactly the window rbfopen targets.
		let seen = false;
		const seenDeadline = Date.now() + 30_000;
		while (Date.now() < seenDeadline) {
			try {
				await bitcoinRpc('getrawtransaction', [attempt0Txid]);
				seen = true;
				break;
			} catch {
				await sleep(1000);
			}
		}
		expect(seen, `funding tx ${attempt0Txid} reached the mempool`).to.equal(
			true
		);

		let eclairChannel: IEclairChannel | null = null;
		const confirmedDeadline = Date.now() + 60_000;
		while (Date.now() < confirmedDeadline) {
			const chans = await eclair.channels(beignetNodeId);
			const match = chans.find(
				(c) => c.state === 'WAIT_FOR_DUAL_FUNDING_CONFIRMED'
			);
			if (match) {
				eclairChannel = match;
				break;
			}
			await sleep(1000);
		}
		expect(
			eclairChannel,
			'Eclair reached WAIT_FOR_DUAL_FUNDING_CONFIRMED'
		).to.not.equal(null);
		// v2 derives one shared channel_id on both sides.
		const eclairChannelId = eclairChannel!.channelId;
		expect(eclairChannelId).to.equal(channelId.toString('hex'));

		// ── Phase B: arm the ack observer, fire rbfopen ──
		const pm = (
			liveNode as unknown as {
				peerManager: {
					sendToPeer(pk: string, type: number, payload: Buffer): void;
				};
			}
		).peerManager;
		const realSend = pm.sendToPeer.bind(pm);
		let capturedAck: Buffer | null = null;
		let capturedAbort: Buffer | null = null;
		pm.sendToPeer = (pk, type, payload): void => {
			if (type === MessageType.TX_ACK_RBF && capturedAck === null) {
				capturedAck = Buffer.from(payload);
			}
			if (type === MessageType.TX_ABORT && capturedAbort === null) {
				capturedAbort = Buffer.from(payload);
			}
			realSend(pk, type, payload);
		};

		// Eclair answers the command once the replacement attempt resolves: a
		// success resolves with RES_BUMP_FUNDING_FEE {rbfIndex, fundingTxId}.
		const rbfResult = (await eclair.rbfOpen(eclairChannelId, 15)) as {
			rbfIndex?: number;
			fundingTxId?: string;
		};
		console.log(`    rbfopen outcome: ${JSON.stringify(rbfResult)}`);
		// A refusal rejects the promise; success resolves with the replacement
		// attempt (eclair numbers the first RBF 0) and its funding txid.
		expect(
			rbfResult.rbfIndex,
			'eclair reports the replacement attempt index'
		).to.be.greaterThanOrEqual(0);
		expect(rbfResult.fundingTxId).to.be.a('string');

		await waitFor(
			() => capturedAck !== null,
			'beignet to answer tx_init_rbf with tx_ack_rbf',
			30_000,
			200
		);
		expect(
			(capturedAck as unknown as Buffer).subarray(0, 32).toString('hex'),
			'the tx_ack_rbf targets the shared channel_id'
		).to.equal(eclairChannelId);
		expect(capturedAbort, 'nothing was refused').to.equal(null);

		// ── Phase C: the replacement completes; attempt 0 stays a candidate ──
		await waitFor(
			() =>
				channel.getFullState().v2InFlight?.rbfAttempt === 1 &&
				!!channel.getFullState().v2InFlight?.fullySigned &&
				channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED,
			'the replacement to complete its signature exchange',
			60_000,
			500
		);
		const state = channel.getFullState();
		const attempt1Txid = Buffer.from(state.v2InFlight!.fundingTxid)
			.reverse()
			.toString('hex');
		expect(attempt1Txid).to.not.equal(attempt0Txid);
		expect(rbfResult.fundingTxId, 'both sides negotiated one tx').to.equal(
			attempt1Txid
		);
		expect(
			state.v2PreviousAttempts,
			'the superseded attempt stays tracked'
		).to.have.length(1);
		expect(
			Buffer.from(state.v2PreviousAttempts![0].fundingTxid)
				.reverse()
				.toString('hex')
		).to.equal(attempt0Txid);
		expect(abortedEvents, 'no channel teardown fired').to.deep.equal([]);
		expect(liveNode.getChannelManager().listChannels().length).to.equal(1);

		// The replacement double-spends attempt 0 and evicts it: the new tx
		// reaches the mempool, the old one leaves it.
		let newSeen = false;
		const newDeadline = Date.now() + 30_000;
		while (Date.now() < newDeadline) {
			try {
				await bitcoinRpc('getrawtransaction', [attempt1Txid]);
				newSeen = true;
				break;
			} catch {
				await sleep(1000);
			}
		}
		expect(
			newSeen,
			`replacement tx ${attempt1Txid} reached the mempool`
		).to.equal(true);
		let oldEvicted = false;
		const evictDeadline = Date.now() + 30_000;
		while (Date.now() < evictDeadline) {
			try {
				await bitcoinRpc('getrawtransaction', [attempt0Txid]);
				await sleep(1000);
			} catch {
				oldEvicted = true;
				break;
			}
		}
		expect(
			oldEvicted,
			'the original attempt was evicted by the replacement'
		).to.equal(true);

		// ── Phase D: the REPLACEMENT confirms and completes the open ──
		await mineBlocks(6);
		await sleep(2000);
		liveNode.handleFundingConfirmed(channelId, attempt1Txid);

		// Eclair's funding watch re-checks only when a NEW block event
		// arrives, and ZMQ delivery is flaky per container instance: mine
		// trigger blocks inside the wait, and fall back to a restart cycle
		// (reestablish re-answers whatever eclair still lacks) if the live
		// feed is dead.
		let eclairNormal: IEclairChannel | null = null;
		for (let attempt = 0; attempt < 2 && !eclairNormal; attempt++) {
			if (attempt > 0) {
				await restartEclairAndSync(eclair, 60_000);
				try {
					await liveNode.connectPeer(
						eclairPubkey,
						ECLAIR_P2P_HOST,
						ECLAIR_P2P_PORT
					);
				} catch {
					/* may already be reconnecting */
				}
				await sleep(3000);
			}
			for (let i = 0; i < 6 && !eclairNormal; i++) {
				await mineBlocks(1);
				try {
					eclairNormal = await waitForEclairPeerChannelNormal(
						eclair,
						beignetNodeId,
						10_000
					);
				} catch {
					/* mine another trigger block and re-check */
				}
			}
		}
		expect(eclairNormal, 'Eclair reached NORMAL').to.not.equal(null);
		expect(
			JSON.stringify(eclairNormal).includes(attempt1Txid),
			'Eclair NORMAL on the REPLACEMENT funding tx'
		).to.equal(true);
		await waitFor(
			() => channel.getState() === ChannelState.NORMAL,
			'beignet side NORMAL',
			30_000,
			500
		);
		expect(
			Buffer.from(channel.getFullState().fundingTxid!)
				.reverse()
				.toString('hex'),
			'beignet NORMAL on the replacement funding tx'
		).to.equal(attempt1Txid);
		expect(channel.getFullState().v2PreviousAttempts ?? []).to.have.length(0);
		const confirmations = (
			(await bitcoinRpc('getrawtransaction', [attempt1Txid, 1])) as {
				confirmations?: number;
			}
		).confirmations;
		expect(confirmations ?? 0).to.be.greaterThanOrEqual(6);

		// Tolerant probe, eclair -> beignet (the initiator holds the whole
		// balance; a direct-channel payment needs no routing setup). The hard
		// assertions are Phases B/C/D above.
		const tip = (await bitcoinRpc('getblockcount')) as number;
		liveNode.handleNewBlock(tip);
		const invoice = liveNode.createInvoice({
			amountMsat: 10_000_000n,
			description: `rbf-360-probe-${Date.now()}`
		});
		try {
			await eclair.payInvoice(invoice.bolt11);
			const paymentHash = decode(invoice.bolt11).paymentHash.toString('hex');
			const result = await waitForEclairPayment(eclair, paymentHash, 30_000);
			if (result.success) {
				expect(result.preimage).to.be.a('string');
			}
			console.log(
				`    probe payment ${result.success ? 'settled' : 'did not settle'}`
			);
		} catch (err: unknown) {
			console.log(
				`    Payment error (expected in some configs): ${
					(err as Error).message
				}`
			);
		}
		console.log(
			`    rbf completed: both sides NORMAL on the replacement ${attempt1Txid}`
		);
	});
});
