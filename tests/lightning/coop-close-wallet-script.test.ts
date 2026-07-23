/**
 * A remote-initiated cooperative close must pay the wallet, not the
 * funding-key fallback.
 *
 * The daemon resolves a wallet-owned sweep script BEFORE constructing the
 * node and passes it in the constructor config. The constructor stored it
 * for force-close sweeps but never forwarded it to the channel manager,
 * whose shutdown-script selection only learned the wallet address through
 * setSweepDestinationScript — a path taken when the address resolves LATE.
 * So on the happy path, a peer-initiated coop close made our shutdown reply
 * fall back to P2WPKH(funding_pubkey), an address the on-chain wallet never
 * scans: the whole payout sat confirmed but invisible until the startup
 * fallback-recovery sweep spent a second transaction bringing it home.
 * Observed live: a 172,500 sat close payout stranded until restart.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { decodeShutdownMessage } from '../../src/lightning/message/channel-close';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`coop-close-seed-${id}`))
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

function createNode(
	seedId: number,
	extra: Partial<INodeConfig> = {}
): LightningNode {
	const node = new LightningNode({ ...makeNodeConfig(seedId), ...extra });
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function wire(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId()) {
			b.handlePeerMessage(a.getNodeId(), type, payload);
		}
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId()) {
			a.handlePeerMessage(b.getNodeId(), type, payload);
		}
	});
}

/** Open and fund a channel alice -> bob, both sides NORMAL. */
function openChannel(alice: LightningNode, bob: LightningNode): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

function walletScript(tag: string): Buffer {
	return bitcoin.payments.p2wpkh({
		pubkey: getPublicKey(
			crypto.createHash('sha256').update(Buffer.from(tag)).digest()
		)
	}).output!;
}

describe('Cooperative close pays the wallet script', function () {
	this.timeout(10_000);

	let alice: LightningNode;
	let bob: LightningNode;

	afterEach(function () {
		alice.destroy();
		bob.destroy();
	});

	it('a remote-initiated close replies shutdown with the constructor-configured wallet script', function () {
		// Bob's wallet address, as the daemon would resolve and configure it.
		const bobWalletScript = walletScript('bob-wallet');

		alice = createNode(1);
		bob = createNode(2, { sweepDestinationScript: bobWalletScript });

		const bobShutdowns: Buffer[] = [];
		bob.on(
			'message:outbound',
			(_pubkey: string, type: number, payload: Buffer) => {
				if (type === MessageType.SHUTDOWN) bobShutdowns.push(payload);
			}
		);
		wire(alice, bob);
		const channelId = openChannel(alice, bob);

		// ALICE initiates the close: bob's reply shutdown carries the script his
		// payout will be locked to.
		const res = alice.closeChannel(channelId, walletScript('alice-wallet'));
		expect(res.ok, res.error ?? 'close initiated').to.equal(true);

		expect(bobShutdowns.length, 'bob replied shutdown').to.be.greaterThan(0);
		const msg = decodeShutdownMessage(bobShutdowns[0]);
		expect(
			msg.scriptPubkey.equals(bobWalletScript),
			'payout locked to the wallet script, not the funding-key fallback'
		).to.equal(true);
	});

	it('without a configured wallet script, the funding-key fallback still applies', function () {
		// The fallback keeps a bare library node functional; recoverFallbackFunds
		// remains the safety net for it. This documents the boundary.
		alice = createNode(3);
		bob = createNode(4);

		const bobFallback = bitcoin.payments.p2wpkh({
			pubkey: makeNodeConfig(4).channelBasepoints.fundingPubkey
		}).output!;

		const bobShutdowns: Buffer[] = [];
		bob.on(
			'message:outbound',
			(_pubkey: string, type: number, payload: Buffer) => {
				if (type === MessageType.SHUTDOWN) bobShutdowns.push(payload);
			}
		);
		wire(alice, bob);
		const channelId = openChannel(alice, bob);

		const res = alice.closeChannel(channelId, walletScript('alice-wallet-2'));
		expect(res.ok, res.error ?? 'close initiated').to.equal(true);

		expect(bobShutdowns.length).to.be.greaterThan(0);
		const msg = decodeShutdownMessage(bobShutdowns[0]);
		expect(
			msg.scriptPubkey.equals(bobFallback),
			'bare node falls back to P2WPKH(funding_pubkey)'
		).to.equal(true);
	});
});
