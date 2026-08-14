/**
 * Issue #214: closing/closed channels expose a derived closeStatus on the
 * channel info DTO (who closed, why, the closing txid, whether the tx
 * reached the network, confirmation height, sweep progress, and the to_local
 * maturity height), plus a manual rebroadcast path that can only ever
 * re-send the latest state, and an openChannelCount that stops counting
 * terminal channels forever.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { encodeErrorMessage } from '../../src/lightning/message/error';

// ─── Helpers (model: error-forecloses-channel.test.ts) ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`close-status-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId())
			b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId())
			a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

function openReadyChannel(alice: LightningNode, bob: LightningNode): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

function destScript(node: LightningNode): Buffer {
	return bitcoin.payments.p2wpkh({
		pubkey: Buffer.from(node.getNodeId(), 'hex')
	}).output!;
}

function closeStatusOf(node: LightningNode, channelId: Buffer): any {
	const info = node.listChannels().find((c) => c.channelId.equals(channelId));
	expect(info, 'channel present in listChannels').to.not.equal(undefined);
	return info!.closeStatus;
}

interface IFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	broadcasts: Buffer[];
	destroy: () => void;
}

function setup(seedBase: number): IFixture {
	const alice = createNode(seedBase);
	const bob = createNode(seedBase + 1);
	connectNodes(alice, bob);
	const channelId = openReadyChannel(alice, bob);
	const broadcasts: Buffer[] = [];
	(alice as any).channelManager.on('broadcast:tx', (tx: Buffer) =>
		broadcasts.push(tx)
	);
	return {
		alice,
		bob,
		channelId,
		broadcasts,
		destroy: () => {
			alice.destroy();
			bob.destroy();
		}
	};
}

/** Feed a captured commitment tx into a node's funding-spent path. */
function observeSpend(
	node: LightningNode,
	channelId: Buffer,
	tx: Buffer,
	height: number
): void {
	(node as any).channelManager.handleFundingSpent(
		channelId,
		bitcoin.Transaction.fromBuffer(tx),
		height,
		destScript(node)
	);
}

describe('Issue #214: close status on the channel listing', function () {
	this.timeout(10_000);

	it('a NORMAL channel reports no closeStatus', () => {
		const fx = setup(211);
		expect(closeStatusOf(fx.alice, fx.channelId)).to.equal(undefined);
		fx.destroy();
	});

	it('our force-close before any observation: local/user, not broadcast, unconfirmed, pending', () => {
		const fx = setup(221);
		const result = fx.alice.forceCloseChannel(
			fx.channelId,
			destScript(fx.alice)
		);
		expect(result.ok).to.equal(true);

		const cs = closeStatusOf(fx.alice, fx.channelId);
		expect(cs).to.not.equal(undefined);
		expect(cs.closer).to.equal('local');
		expect(cs.reason).to.equal('user');
		// The engine knows which txid it is trying to broadcast even though
		// nothing has confirmed success yet: exactly the window the field
		// report was blind in.
		expect(cs.closingTxid).to.equal(result.commitmentTxid);
		expect(cs.broadcast).to.equal(false);
		expect(cs.confirmationHeight).to.equal(0);
		expect(cs.resolution).to.equal('pending');
		expect(cs.fundsAvailableHeight).to.equal(undefined);
		fx.destroy();
	});

	it('after the spend confirms at height H: broadcast, confirmed, sweeping, funds at H + CSV', () => {
		const fx = setup(231);
		const result = fx.alice.forceCloseChannel(
			fx.channelId,
			destScript(fx.alice)
		);
		expect(fx.broadcasts.length).to.be.greaterThan(0);

		observeSpend(fx.alice, fx.channelId, fx.broadcasts[0], 100);

		const cs = closeStatusOf(fx.alice, fx.channelId);
		expect(cs.closer).to.equal('local');
		expect(cs.reason).to.equal('user');
		expect(cs.closingTxid).to.equal(result.commitmentTxid);
		expect(cs.broadcast).to.equal(true);
		expect(cs.confirmationHeight).to.equal(100);
		expect(cs.resolution).to.equal('sweeping');
		expect(cs.fundsAvailableHeight).to.equal(
			100 + DEFAULT_CHANNEL_CONFIG.toSelfDelay
		);
		fx.destroy();
	});

	it('a mempool-first sighting: broadcast true but height 0 and no funds height yet', () => {
		const fx = setup(241);
		fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice));

		observeSpend(fx.alice, fx.channelId, fx.broadcasts[0], 0);

		const cs = closeStatusOf(fx.alice, fx.channelId);
		expect(cs.broadcast).to.equal(true);
		expect(cs.confirmationHeight).to.equal(0);
		// No CSV base until the commitment confirms.
		expect(cs.fundsAvailableHeight).to.equal(undefined);
		fx.destroy();
	});

	it('an automatic close carries its code in reason', () => {
		const fx = setup(251);
		fx.alice.handlePeerMessage(
			fx.bob.getNodeId(),
			MessageType.ERROR,
			encodeErrorMessage({
				channelId: fx.channelId,
				data: Buffer.from('internal error', 'utf8')
			})
		);
		const cs = closeStatusOf(fx.alice, fx.channelId);
		expect(cs.closer).to.equal('local');
		expect(cs.reason).to.equal('CHANNEL_FAILED_FORCE_CLOSED');
		fx.destroy();
	});

	it("the peer's force-close reads remote with no reason", () => {
		// A pushed balance gives bob's commitment a to_local output, which is
		// what lets alice's monitor classify the spend as the peer's current
		// commitment rather than an ambiguous UNKNOWN.
		const alice = createNode(261);
		const bob = createNode(262);
		connectNodes(alice, bob);
		const opened = alice.openChannel(bob.getNodeId(), 1_000_000n, 300_000_000n);
		const channelId = alice.createFunding(
			opened,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		const fx: IFixture = {
			alice,
			bob,
			channelId,
			broadcasts: [],
			destroy: () => {
				alice.destroy();
				bob.destroy();
			}
		};
		const bobBroadcasts: Buffer[] = [];
		(fx.bob as any).channelManager.on('broadcast:tx', (tx: Buffer) =>
			bobBroadcasts.push(tx)
		);
		fx.bob.forceCloseChannel(fx.channelId, destScript(fx.bob));
		expect(bobBroadcasts.length).to.be.greaterThan(0);

		observeSpend(fx.alice, fx.channelId, bobBroadcasts[0], 120);

		const cs = closeStatusOf(fx.alice, fx.channelId);
		expect(cs.closer).to.equal('remote');
		expect(cs.reason).to.equal(undefined);
		expect(cs.broadcast).to.equal(true);
		expect(cs.confirmationHeight).to.equal(120);
		// The to_local maturity is about OUR force close; a remote close has
		// none to report.
		expect(cs.fundsAvailableHeight).to.equal(undefined);
		fx.destroy();
	});

	it('a user cooperative close reads cooperative/user while negotiating', () => {
		const fx = setup(271);
		const result = fx.alice.closeChannel(fx.channelId, destScript(fx.alice));
		expect(result.ok).to.equal(true);

		const cs = closeStatusOf(fx.alice, fx.channelId);
		expect(cs).to.not.equal(undefined);
		expect(cs.closer).to.equal('cooperative');
		expect(cs.reason).to.equal('user');
		fx.destroy();
	});

	it('openChannelCount excludes terminal channels while channelCount keeps them', () => {
		const fx = setup(281);
		expect(fx.alice.getNodeInfo().channelCount).to.equal(1);
		expect(fx.alice.getNodeInfo().openChannelCount).to.equal(1);

		fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice));

		const info = fx.alice.getNodeInfo();
		expect(info.channelCount).to.equal(1);
		expect(info.openChannelCount).to.equal(0);
		fx.destroy();
	});
});

describe('Issue #214: manual close rebroadcast', function () {
	this.timeout(10_000);

	it('refuses a channel that is not closed', async () => {
		const fx = setup(311);
		const result = await fx.alice.rebroadcastClose(fx.channelId);
		expect(result.ok).to.equal(false);
		expect(result.error).to.contain('not closed');
		fx.destroy();
	});

	it('rebuilds the byte-identical commitment, broadcasts once, keeps the monitor', async () => {
		const fx = setup(321);
		const forced = fx.alice.forceCloseChannel(
			fx.channelId,
			destScript(fx.alice)
		);
		const monitorBefore = (fx.alice as any).channelManager.getMonitor(
			fx.channelId
		);
		const broadcastCountBefore = fx.broadcasts.length;
		const sent: string[] = [];
		(fx.alice as any)._chainBackend = {
			broadcastTransaction: async (hex: string) => {
				sent.push(hex);
				return bitcoin.Transaction.fromHex(hex).getId();
			}
		};

		const result = await fx.alice.rebroadcastClose(fx.channelId);

		expect(result.ok).to.equal(true);
		expect(result.txid).to.equal(forced.commitmentTxid);
		expect(result.broadcastOk).to.equal(true);
		expect(sent.length).to.equal(1);
		// The engine-owned monitor must survive (a replaced monitor would
		// discard tracked outputs), and the rebuild must not double-broadcast
		// through the watcher queue.
		expect((fx.alice as any).channelManager.getMonitor(fx.channelId)).to.equal(
			monitorBefore
		);
		expect(fx.broadcasts.length).to.equal(broadcastCountBefore);
		// The successful manual rebroadcast now shows on the listing.
		const cs = closeStatusOf(fx.alice, fx.channelId);
		expect(cs.broadcast).to.equal(true);
		expect(cs.closingTxid).to.equal(forced.commitmentTxid);

		// Idempotent: a second call re-sends the same txid.
		const again = await fx.alice.rebroadcastClose(fx.channelId);
		expect(again.ok).to.equal(true);
		expect(again.txid).to.equal(forced.commitmentTxid);
		fx.destroy();
	});

	it('treats a duplicate rejection as success', async () => {
		const fx = setup(331);
		fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice));
		(fx.alice as any)._chainBackend = {
			broadcastTransaction: async () => {
				throw new Error('Transaction already in block chain');
			}
		};

		const result = await fx.alice.rebroadcastClose(fx.channelId);
		expect(result.ok).to.equal(true);
		expect(result.broadcastOk).to.equal(true);
		fx.destroy();
	});

	it('reports a failed broadcast honestly', async () => {
		const fx = setup(341);
		fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice));
		(fx.alice as any)._chainBackend = {
			broadcastTransaction: async () => {
				throw new Error('connection refused');
			}
		};

		const result = await fx.alice.rebroadcastClose(fx.channelId);
		expect(result.ok).to.equal(true);
		expect(result.broadcastOk).to.equal(false);
		const cs = closeStatusOf(fx.alice, fx.channelId);
		expect(cs.broadcast).to.equal(false);
		fx.destroy();
	});

	it('is a no-op success once the close confirmed', async () => {
		const fx = setup(351);
		const forced = fx.alice.forceCloseChannel(
			fx.channelId,
			destScript(fx.alice)
		);
		observeSpend(fx.alice, fx.channelId, fx.broadcasts[0], 100);

		const result = await fx.alice.rebroadcastClose(fx.channelId);
		expect(result.ok).to.equal(true);
		expect(result.txid).to.equal(forced.commitmentTxid);
		expect(result.broadcastOk).to.equal(true);
		fx.destroy();
	});

	it('refuses a CLOSED channel with no recorded close tx', async () => {
		const fx = setup(361);
		const channel = (fx.alice as any).channelManager.getChannel(fx.channelId);
		channel.getFullState().state = ChannelState.CLOSED;

		const result = await fx.alice.rebroadcastClose(fx.channelId);
		expect(result.ok).to.equal(false);
		expect(result.error).to.contain('No close transaction recorded');
		fx.destroy();
	});

	it('rebroadcasts a recorded cooperative close on a CLOSED channel', async () => {
		const fx = setup(371);
		const channel = (fx.alice as any).channelManager.getChannel(fx.channelId);
		// Any parseable tx stands in for the negotiated mutual close.
		const coopTx = new bitcoin.Transaction();
		coopTx.addInput(crypto.randomBytes(32), 0);
		coopTx.addOutput(destScript(fx.alice), 900_000);
		channel.recordCooperativeCloseTx(coopTx.toHex());
		channel.getFullState().state = ChannelState.CLOSED;
		const sent: string[] = [];
		(fx.alice as any)._chainBackend = {
			broadcastTransaction: async (hex: string) => {
				sent.push(hex);
				return bitcoin.Transaction.fromHex(hex).getId();
			}
		};

		const result = await fx.alice.rebroadcastClose(fx.channelId);
		expect(result.ok).to.equal(true);
		expect(result.txid).to.equal(coopTx.getId());
		expect(result.broadcastOk).to.equal(true);
		expect(sent).to.deep.equal([coopTx.toHex()]);
		fx.destroy();
	});
});
