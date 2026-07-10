/**
 * Channel lifecycle event granularity (M4 batch 2b):
 * - channel:opening fires when the funding negotiation completes (both roles)
 * - channel:pending-close fires when a coop close is initiated (local + remote)
 * - channel:force-closing fires on our force-close broadcast (local) and when
 *   a peer's unilateral close is detected on-chain (remote)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`lifecycle-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
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

function makeConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: fundingPrivkey,
		htlcBasepointSecret
	};
}

function connectManagers(
	managerA: ChannelManager,
	pubkeyA: string,
	managerB: ChannelManager,
	pubkeyB: string
): void {
	managerA.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyB) {
				managerB.handleMessage(pubkeyA, type, payload);
			}
		}
	);
	managerB.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyA) {
				managerA.handleMessage(pubkeyB, type, payload);
			}
		}
	);
}

describe('Channel lifecycle events (M4 batch 2b)', function () {
	const aliceConfig = makeConfig(1);
	const bobConfig = makeConfig(2);
	const alicePubkey = aliceConfig.localBasepoints.fundingPubkey.toString('hex');
	const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');
	const destScript = Buffer.from('0014' + 'ab'.repeat(20), 'hex');

	function createConnectedManagers(): {
		alice: ChannelManager;
		bob: ChannelManager;
	} {
		const alice = new ChannelManager(aliceConfig);
		const bob = new ChannelManager(bobConfig);
		connectManagers(alice, alicePubkey, bob, bobPubkey);
		return { alice, bob };
	}

	function openAndReadyChannel(): {
		alice: ChannelManager;
		bob: ChannelManager;
		channelId: Buffer;
	} {
		const { alice, bob } = createConnectedManagers();
		const channel = alice.openChannel(bobPubkey, 1_000_000n);
		const fundingTxid = crypto.randomBytes(32);
		const channelId = alice.createFunding(
			channel,
			fundingTxid,
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		return { alice, bob, channelId };
	}

	describe('channel:opening', function () {
		it('fires on the funder when funding_signed is received', function () {
			const { alice, bob } = createConnectedManagers();
			const opening: Array<{ channelId: Buffer; fundingTxid: Buffer }> = [];
			alice.on('channel:opening', (channelId: Buffer, fundingTxid: Buffer) => {
				opening.push({ channelId, fundingTxid });
			});

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			expect(opening, 'no opening event before funding').to.have.length(0);

			const fundingTxid = crypto.randomBytes(32);
			const channelId = alice.createFunding(
				channel,
				fundingTxid,
				0,
				crypto.randomBytes(64)
			)!;

			expect(opening).to.have.length(1);
			expect(opening[0].channelId.equals(channelId)).to.equal(true);
			expect(opening[0].fundingTxid.equals(fundingTxid)).to.equal(true);
			void bob;
		});

		it('fires on the fundee when it sends funding_signed', function () {
			const { alice, bob } = createConnectedManagers();
			const opening: Buffer[] = [];
			bob.on('channel:opening', (channelId: Buffer) => {
				opening.push(channelId);
			});

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const channelId = alice.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			)!;

			expect(opening).to.have.length(1);
			expect(opening[0].equals(channelId)).to.equal(true);
		});

		it('fires before channel:ready', function () {
			const { alice, bob } = createConnectedManagers();
			const order: string[] = [];
			alice.on('channel:opening', () => order.push('opening'));
			alice.on('channel:ready', () => order.push('ready'));

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const channelId = alice.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			)!;
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);

			expect(order).to.deep.equal(['opening', 'ready']);
		});
	});

	describe('channel:pending-close', function () {
		it('fires with initiator local on the closing side and remote on the peer', function () {
			const { alice, bob, channelId } = openAndReadyChannel();
			const aliceEvents: string[] = [];
			const bobEvents: string[] = [];
			alice.on('channel:pending-close', (cid: Buffer, initiator: string) => {
				expect(cid.equals(channelId)).to.equal(true);
				aliceEvents.push(initiator);
			});
			bob.on('channel:pending-close', (cid: Buffer, initiator: string) => {
				expect(cid.equals(channelId)).to.equal(true);
				bobEvents.push(initiator);
			});

			alice.initiateShutdown(
				channelId,
				Buffer.from('0014' + '0'.repeat(40), 'hex')
			);

			// Bob's shutdown reply reaches Alice while she is already
			// SHUTTING_DOWN, so she must NOT also report a remote initiation.
			expect(aliceEvents).to.deep.equal(['local']);
			expect(bobEvents).to.deep.equal(['remote']);
		});

		it('does not fire when initiateShutdown fails (unknown channel)', function () {
			const { alice } = createConnectedManagers();
			alice.on('error', () => {});
			let fired = false;
			alice.on('channel:pending-close', () => {
				fired = true;
			});
			alice.initiateShutdown(
				crypto.randomBytes(32),
				Buffer.from('0014' + '0'.repeat(40), 'hex')
			);
			expect(fired).to.equal(false);
		});
	});

	describe('channel:force-closing', function () {
		it('fires with initiator local when we force-close', function () {
			const { alice, channelId } = openAndReadyChannel();
			const events: string[] = [];
			alice.on('channel:force-closing', (cid: Buffer, initiator: string) => {
				expect(cid.equals(channelId)).to.equal(true);
				events.push(initiator);
			});

			const result = alice.forceClose(channelId, destScript, 10);
			expect(result.ok).to.equal(true);
			expect(events).to.deep.equal(['local']);
		});

		it('does not fire when forceClose fails (unknown channel)', function () {
			const { alice } = createConnectedManagers();
			alice.on('error', () => {});
			let fired = false;
			alice.on('channel:force-closing', () => {
				fired = true;
			});
			alice.forceClose(crypto.randomBytes(32), destScript, 10);
			expect(fired).to.equal(false);
		});

		it('fires with initiator remote when the peer commitment confirms on-chain', function () {
			const { alice, bob, channelId } = openAndReadyChannel();

			// Alice force-closes: her commitment tx is, from Bob's perspective,
			// a remote unilateral close.
			const result = alice.forceClose(channelId, destScript, 10);
			expect(result.ok).to.equal(true);
			const broadcastAction = result.actions.find(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			) as { tx: Buffer } | undefined;
			expect(broadcastAction, 'force-close broadcasts a commitment').to.exist;
			const commitmentTx = bitcoin.Transaction.fromBuffer(broadcastAction!.tx);

			const events: string[] = [];
			const closed: Buffer[] = [];
			bob.on('channel:force-closing', (cid: Buffer, initiator: string) => {
				expect(cid.equals(channelId)).to.equal(true);
				events.push(initiator);
			});
			bob.on('channel:closed', (cid: Buffer) => closed.push(cid));

			bob.handleFundingSpent(channelId, commitmentTx, 100, destScript, 10);

			expect(events).to.deep.equal(['remote']);
			expect(closed.length, 'channel:closed also fires').to.be.greaterThan(0);

			// Re-detection of the same spend must not re-emit.
			bob.handleFundingSpent(channelId, commitmentTx, 101, destScript, 10);
			expect(events).to.deep.equal(['remote']);
		});

		it('does not fire remote for a cooperative close spend', function () {
			const { alice, bob, channelId } = openAndReadyChannel();
			let fired = false;
			bob.on('channel:force-closing', () => {
				fired = true;
			});

			// Full coop close via loopback (negotiation completes synchronously).
			alice.initiateShutdown(
				channelId,
				Buffer.from('0014' + '0'.repeat(40), 'hex')
			);
			expect(fired).to.equal(false);
			void bob;
		});
	});
});
