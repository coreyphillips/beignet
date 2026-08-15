/**
 * Interop: tx_abort as the RBF refusal for a v2 open, against live Eclair
 * (regtest). Closes issue #309.
 *
 * BOLT 2: the receiver of tx_init_rbf MUST respond with tx_ack_rbf or
 * tx_abort, and MAY send tx_abort for any reason. The refusal is
 * ATTEMPT-scoped: only the replacement attempt dies, both sides keep the
 * current attempt, and with a fully signed attempt the channel keeps
 * waiting for confirmation. This test pins that convergence live:
 *
 * 1. Eclair (the initiator, the only side allowed to send tx_init_rbf)
 *    opens a dual-funded channel to beignet; tx_signatures cross and the
 *    funding tx sits unconfirmed in the mempool.
 * 2. The eclair operator calls rbfopen. Eclair sends tx_init_rbf; beignet
 *    refuses with tx_abort ('RBF of a broadcastable attempt not
 *    supported': the ecosystem RBF window is a completed attempt, which
 *    beignet declines to replace; see the dual-funding module header).
 * 3. BOTH sides keep the original attempt: beignet stays in
 *    AWAITING_FUNDING_CONFIRMED on the same funding txid, Eclair rolls its
 *    RbfRequested status back and stays in WAIT_FOR_DUAL_FUNDING_CONFIRMED
 *    instead of tearing the open down.
 * 4. Mining confirms the ORIGINAL funding tx and both sides reach NORMAL,
 *    proving the refusal cost nothing but the attempt.
 *
 * Requires the compose `eclair` container (0.14+, option_dual_fund
 * enabled; HTTP 8082, P2P 9737). Run solo:
 *   npx mocha --exit --timeout 300000 -r ts-node/register tests/lightning/interop/eclair-v2open-rbf-refusal.test.ts
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

describe('Interop: v2 open RBF refusal via tx_abort vs Eclair (regtest)', function () {
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
			passphrase: 'interop-seed-eclair-rbf-refusal-1',
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
	it('eclair rbfopen after tx_signatures is refused with tx_abort; both sides keep the original attempt and reach NORMAL', async function () {
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
		// provably clears eclair's own 25/24 floor.
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
		const displayTxid = Buffer.from(channel.getFullState().fundingTxid!)
			.reverse()
			.toString('hex');

		// Broadcast but NOT confirmed: exactly the window rbfopen targets.
		let seen = false;
		const seenDeadline = Date.now() + 30_000;
		while (Date.now() < seenDeadline) {
			try {
				await bitcoinRpc('getrawtransaction', [displayTxid]);
				seen = true;
				break;
			} catch {
				await sleep(1000);
			}
		}
		expect(seen, `funding tx ${displayTxid} reached the mempool`).to.equal(
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
		expect(
			JSON.stringify(eclairChannel).includes(displayTxid),
			'Eclair holds the same funding tx'
		).to.equal(true);
		// v2 derives one shared channel_id on both sides.
		const eclairChannelId = eclairChannel!.channelId;
		expect(eclairChannelId).to.equal(channelId.toString('hex'));

		// ── Phase B: arm the refusal observer, fire rbfopen ──
		const pm = (
			liveNode as unknown as {
				peerManager: {
					sendToPeer(pk: string, type: number, payload: Buffer): void;
				};
			}
		).peerManager;
		const realSend = pm.sendToPeer.bind(pm);
		let capturedAbort: Buffer | null = null;
		pm.sendToPeer = (pk, type, payload): void => {
			if (type === MessageType.TX_ABORT && capturedAbort === null) {
				capturedAbort = Buffer.from(payload);
			}
			realSend(pk, type, payload);
		};

		// Eclair answers the command only once the attempt resolves; a refusal
		// surfaces as a rejected promise. Diagnostic only: the assertions
		// below run on the wire capture and on channel state.
		let rbfOutcome: string;
		try {
			rbfOutcome = JSON.stringify(await eclair.rbfOpen(eclairChannelId, 50));
		} catch (err: unknown) {
			rbfOutcome = (err as Error).message;
		}
		console.log(`    rbfopen outcome: ${rbfOutcome}`);

		await waitFor(
			() => capturedAbort !== null,
			'beignet to answer tx_init_rbf with tx_abort',
			30_000,
			200
		);
		const abortMsg = capturedAbort as unknown as Buffer;
		expect(
			abortMsg.subarray(0, 32).toString('hex'),
			'the tx_abort targets the shared channel_id'
		).to.equal(eclairChannelId);
		expect(
			abortMsg.toString('utf8'),
			'the tx_abort carries the policy refusal reason'
		).to.include('RBF of a broadcastable attempt not supported');

		// ── Phase C: the refusal is attempt-scoped on BOTH sides ──
		// Let eclair's answering echo tx_abort land and be swallowed.
		await sleep(2000);

		expect(
			channel.getState(),
			'beignet keeps waiting on the original attempt'
		).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
		expect(
			Buffer.from(channel.getFullState().fundingTxid!)
				.reverse()
				.toString('hex'),
			'beignet keeps the original funding tx'
		).to.equal(displayTxid);
		expect(channel.isV2AttemptBroadcastable()).to.equal(true);
		expect(liveNode.getChannelManager().listChannels().length).to.equal(1);
		expect(abortedEvents, 'no channel teardown fired').to.deep.equal([]);

		const afterRefusal = await eclair.channels(beignetNodeId);
		const eclairAfter = afterRefusal.find(
			(c) => c.state === 'WAIT_FOR_DUAL_FUNDING_CONFIRMED'
		);
		expect(
			eclairAfter,
			'Eclair rolled the rbf attempt back instead of tearing down'
		).to.not.equal(undefined);
		expect(
			JSON.stringify(eclairAfter).includes(displayTxid),
			'Eclair still holds the original funding tx'
		).to.equal(true);

		// ── Phase D: the ORIGINAL attempt confirms and completes the open ──
		await mineBlocks(6);
		await sleep(2000);
		liveNode.handleFundingConfirmed(channelId);

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
			JSON.stringify(eclairNormal).includes(displayTxid),
			'Eclair NORMAL on the ORIGINAL funding tx'
		).to.equal(true);
		await waitFor(
			() => channel.getState() === ChannelState.NORMAL,
			'beignet side NORMAL',
			30_000,
			500
		);
		const confirmations = (
			(await bitcoinRpc('getrawtransaction', [displayTxid, 1])) as {
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
			description: `rbf-refusal-probe-${Date.now()}`
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
			`    rbf refusal converged: both sides NORMAL on ${displayTxid}`
		);
	});
});
