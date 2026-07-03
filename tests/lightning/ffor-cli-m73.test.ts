/**
 * FFOR M7.3: operator CLI flags + offline-receive UX.
 *
 * - CLI: parseArgs recognizes --tower/--tower-store/--tower-demo/--use-tower;
 *   buildTowerStore enforces durability (the footgun gate: --tower on a
 *   :memory: store is REFUSED unless --tower-demo).
 * - End-to-end: nodes P - S - R plus a separate tower node T (T != S, T != R),
 *   configured as the CLI would (T runs enableTower over real BOLT-8, R runs
 *   useTower, S auto-resolves T from ff_init). R startOfflineReceiveEpoch,
 *   goes offline, P pays a delegated invoice, S settles via T over real
 *   BOLT-8, P's payment COMPLETES while R offline; R reconnects, recoverFromTower
 *   + reconcile, vouchers become balance. towerStatus() reflects the epoch.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import os from 'os';
import fs from 'fs';
import path from 'path';
import { parseArgs, buildTowerStore } from '../../example/lightning';
import { SqliteTowerStore } from '../../src/lightning/ffor/tower-store-sqlite';
import { MemoryTowerStore } from '../../src/lightning/ffor/tower';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ChannelState } from '../../src/lightning/channel/types';
import { Network } from '../../src/lightning/invoice/types';
import { REGTEST_CHAIN_HASH } from '../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../src/lightning/keys/wallet-keys';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();
const TEST_MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function tmpDir(tag: string): string {
	return fs.mkdtempSync(path.join(os.tmpdir(), `ffor-m73-${tag}-`));
}

// ─────────────── CLI flags ───────────────

describe('FFOR M7.3: CLI flags', function () {
	it('parseArgs recognizes the tower flags', function () {
		const a = parseArgs([
			'node',
			'script',
			'--tower',
			'--tower-store',
			'/tmp/t.db',
			'--use-tower',
			'abcd@127.0.0.1:9999'
		]);
		expect(a.tower).to.equal(true);
		expect(a.towerStore).to.equal('/tmp/t.db');
		expect(a.useTower).to.equal('abcd@127.0.0.1:9999');
		expect(a.towerDemo).to.equal(undefined);
	});

	it('--tower on a file store builds a durable SqliteTowerStore', function () {
		const dir = tmpDir('durable');
		try {
			const store = buildTowerStore(
				{ towerStore: path.join(dir, 'tower.db') },
				path.join(dir, 'default.db')
			);
			expect(store).to.be.instanceOf(SqliteTowerStore);
			(store as SqliteTowerStore).close();
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('FOOTGUN GATE: --tower on a :memory: store is REFUSED without --tower-demo', function () {
		expect(() =>
			buildTowerStore({ towerStore: ':memory:' }, '/tmp/default.db')
		).to.throw(/non-durable|refused/i);
	});

	it('--tower-demo permits a non-durable memory store (with a loud warning)', function () {
		const warnings: string[] = [];
		const orig = console.warn;
		console.warn = (...a: unknown[]): void => {
			warnings.push(a.join(' '));
		};
		try {
			const store = buildTowerStore(
				{ towerStore: ':memory:', towerDemo: true },
				'/tmp/default.db'
			);
			expect(store).to.be.instanceOf(MemoryTowerStore);
			expect(warnings.join('\n')).to.match(/NON-DURABLE|WARNING/);
		} finally {
			console.warn = orig;
		}
	});
});

// ─────────────── End-to-end gate ───────────────

function makeNode(seedId: number): LightningNode {
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		`ffor-m73-${seedId}`,
		LnCoinType.REGTEST
	);
	const features = FeatureFlags.empty();
	features.setOptional(Feature.STATIC_REMOTE_KEY);
	features.setOptional(Feature.PAYMENT_SECRET);
	features.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	features.setOptional(Feature.QUIESCE);
	features.setOptional(Feature.OPTION_FF_RECEIVE);
	return new LightningNode({
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
		localFeatures: features,
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true
	});
}

const sleep = (ms = 20): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Start listening on an ephemeral port and return it. */
async function listenEphemeral(node: LightningNode): Promise<number> {
	await node.listen(0);
	const pm = node.getPeerManager()!;
	const server = (pm as unknown as { server: { address(): { port: number } } })
		.server;
	return server.address().port;
}

/** Open a fake-funded channel over a live BOLT-8 connection. */
async function openChannelBolt8(
	opener: LightningNode,
	acceptor: LightningNode
): Promise<Buffer> {
	const om = opener.getChannelManager();
	const am = acceptor.getChannelManager();
	const ch = om.openChannel(acceptor.getNodeId(), 1_000_000n);
	await sleep(300); // open_channel -> accept_channel
	om.createFunding(ch, crypto.randomBytes(32), 0, crypto.randomBytes(64));
	await sleep(300); // funding_created -> funding_signed
	const id = ch.getChannelId()!;
	om.handleFundingConfirmed(id);
	const ach = am
		.getChannelsByPeer(opener.getNodeId())
		.find((c) => c.getChannelId()?.equals(id))!;
	am.handleFundingConfirmed(ach.getChannelId()!);
	await sleep(100);
	expect(ch.getState(), 'opener channel NORMAL').to.equal(ChannelState.NORMAL);
	return id;
}

describe('FFOR M7.3 GATE: offline-receive via a tower, CLI-configured, over real BOLT-8', function () {
	this.timeout(40_000);

	it('R provisions T + goes offline; P pays; S settles via T; R recovers', async function () {
		const dbDir = tmpDir('e2e');
		const P = makeNode(1);
		const S = makeNode(2);
		const R = makeNode(3);
		const T = makeNode(4);
		const sPub = S.getNodeId();
		const tPub = T.getNodeId();
		const pm = P.getChannelManager();
		const sm = S.getChannelManager();
		const rm = R.getChannelManager();
		[P, S, R, T].forEach((n) => n.on('node:error', () => {}));
		[pm, sm, rm].forEach((m) => m.on('error', () => {}));
		const pFulfilled: Buffer[] = [];
		pm.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
			pFulfilled.push(preimage)
		);

		try {
			// ── T: durable embedded tower over real BOLT-8 (the --tower path). ──
			T.enableTower(new SqliteTowerStore(path.join(dbDir, 'tower.db')));
			const tPort = await listenEphemeral(T);
			const sPort = await listenEphemeral(S);
			await listenEphemeral(R);
			await listenEphemeral(P);

			// ── R: configure T as its tower (the --use-tower path). ──
			R.useTower(`${tPub}@127.0.0.1:${tPort}`);

			// Peer connections over real BOLT-8: P<->S and S<->R.
			await P.connectPeer(sPub, '127.0.0.1', sPort);
			await R.connectPeer(sPub, '127.0.0.1', sPort);
			await sleep(300);

			// Channels: P->S (payer) and S->R (R is the recipient).
			const psId = await openChannelBolt8(P, S);
			const srId = await openChannelBolt8(S, R);
			const rChannel = rm
				.getChannelsByPeer(sPub)
				.find((c) => c.getChannelId()?.equals(srId))!;

			// ── R: one-shot offline-receive setup (provisions T up-front). ──
			const epoch = await R.startOfflineReceiveEpoch({
				channelId: srId,
				budgetMsat: 100_000_000n,
				maxPayments: 2,
				minPaymentMsat: 500_000n,
				settlementDeadline: 1000,
				voucherExpiry: 2008
			});
			await sleep(200); // let ff_init reach S + S auto-resolve the tower
			expect(epoch.invoices.length).to.equal(2);
			expect(
				sm.hasFforTowerClient(),
				'S auto-resolved the tower from ff_init'
			).to.equal(true);
			expect(T.towerStatus().epochs.length).to.equal(1);

			// ── R goes offline. ──
			R.disconnectPeer(sPub);
			await sleep(200);

			// ── P pays a delegated invoice (its hash is in the epoch's set).
			//    S auto-settles it via the tower over real BOLT-8, while R is
			//    offline; the payer completes. ──
			pm.addHtlc(
				psId,
				1_000_000n,
				epoch.paymentHashes[0],
				900,
				Buffer.alloc(1366)
			);
			await sleep(1500); // S connects to T + releases the preimage

			expect(pFulfilled.length, 'payment completed while R offline').to.equal(
				1
			);
			expect(sha256(pFulfilled[0]).equals(epoch.paymentHashes[0])).to.equal(
				true
			);
			expect(
				S.getPeerManager()!.getPeer(tPub) !== undefined,
				'S dialed the auto-resolved tower over BOLT-8'
			).to.equal(true);
			expect(T.towerStatus().epochs[0].lastReleased).to.equal(1);

			// ── R returns and recovers from the tower over real BOLT-8: the
			//    R-side recoverFromTower wrapper fetches the settled package +
			//    preimage and ingests it, so the credited voucher is R's to claim
			//    (the on-return reconcile/convert path is the M2/M4 machinery). ──
			await R.connectPeer(sPub, '127.0.0.1', sPort);
			await sleep(300);
			const rec = await R.recoverFromTower(srId);
			expect(rec.ok, rec.error).to.equal(true);
			const rEpoch = rChannel.getFforEpoch()!;
			expect(rEpoch.lastSeq, 'R ingested the settled package').to.equal(1);
			expect(
				sha256(rEpoch.preimages[0]).equals(epoch.paymentHashes[0]),
				'R holds the voucher preimage fetched from the tower'
			).to.equal(true);
		} finally {
			await P.destroy();
			await S.destroy();
			await R.destroy();
			await T.destroy();
			fs.rmSync(dbDir, { recursive: true, force: true });
		}
	});
});
