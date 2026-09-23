import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IFundingProvider,
	ILightningError
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { createFundingScript } from '../../src/lightning/script/funding';
import { neverSettles, settle } from './helpers/settle';

bitcoin.initEccLib(ecc);

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`auto-fund-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	fundingPrivkey: Buffer;
	htlcSecret: Buffer;
} {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		fundingPrivkey: keys[0],
		htlcSecret: keys[4]
	};
}

function makeNodeConfig(
	seedId: number,
	fundingProvider?: IFundingProvider
): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const { basepoints, fundingPrivkey, htlcSecret } = makeBasepoints(seed);
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: basepoints,
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret: htlcSecret,
		fundingProvider
	};
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeB.getNodeId()) {
				nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
			}
		}
	);
	nodeB.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeA.getNodeId()) {
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		}
	);
}

/**
 * Build a realistic-looking funding tx that pays to a P2WSH address.
 */
function buildMockFundingTx(
	address: string,
	amountSats: number
): { txHex: string; txid: Buffer; outputIndex: number } {
	const tx = new bitcoin.Transaction();
	// Dummy input (fake UTXO)
	tx.addInput(crypto.randomBytes(32), 0);

	// Output 0: change
	const changeScript = bitcoin.script.compile([
		bitcoin.opcodes.OP_0,
		crypto.randomBytes(20)
	]);
	tx.addOutput(changeScript, 50_000);

	// Output 1: funding output
	const fundingScript = bitcoin.address.toOutputScript(
		address,
		bitcoin.networks.regtest
	);
	tx.addOutput(fundingScript, amountSats);

	const txHex = tx.toHex();
	const txid = Buffer.from(tx.getHash());

	return { txHex, txid, outputIndex: 1 };
}

// ─────────────── Tests ───────────────

describe('Auto-Funding Integration', function () {
	describe('full auto-funding flow', function () {
		it('should auto-build and broadcast funding tx after accept_channel', async function () {
			let buildCalled = false;
			let broadcastCalled = false;
			let capturedAddress = '';
			let capturedAmount = 0n;
			let builtHex = '';
			let broadcastHex = '';

			const mockProvider: IFundingProvider = {
				buildFundingTransaction: async (address, amountSats) => {
					buildCalled = true;
					capturedAddress = address;
					capturedAmount = amountSats;
					const built = buildMockFundingTx(address, Number(amountSats));
					builtHex = built.txHex;
					return built;
				},
				broadcastTransaction: async (txHex) => {
					// Only record here: a failed expect in this callback becomes a
					// node:error the listener below absorbs, so the checks live in
					// the test body.
					broadcastHex = txHex;
					broadcastCalled = true;
					return bitcoin.Transaction.fromHex(txHex).getId();
				}
			};

			const alice = new LightningNode(makeNodeConfig(1, mockProvider));
			const bob = new LightningNode(makeNodeConfig(2));

			// Absorb error events
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});

			connectNodes(alice, bob);

			try {
				const fundingSatoshis = 500_000n;
				alice.openChannel(bob.getNodeId(), fundingSatoshis);

				// The auto-funding flow is async. Wait on the provider call itself,
				// not a fixed window a loaded machine can overrun (issue #947).
				await settle(() => buildCalled);
				expect(capturedAmount).to.equal(fundingSatoshis);
				// The address should be a valid regtest P2WSH address
				expect(capturedAddress).to.match(/^bcrt1/);

				// After buildFundingTransaction resolves, funding_created is sent,
				// bob responds with funding_signed, and then broadcast is called
				// via the watch:funding listener
				await settle(() => broadcastCalled);
				// The node broadcasts the transaction the provider built.
				expect(broadcastHex).to.equal(builtHex);

				// Both nodes should have the channel
				const aliceChannels = alice.listChannels();
				const bobChannels = bob.listChannels();
				expect(aliceChannels.length).to.equal(1);
				expect(bobChannels.length).to.equal(1);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});

		it('should use correct P2WSH funding address from both pubkeys', async function () {
			let capturedAddress = '';
			const aliceConfig = makeNodeConfig(10);
			const bobConfig = makeNodeConfig(20);

			const mockProvider: IFundingProvider = {
				buildFundingTransaction: async (address, amountSats) => {
					capturedAddress = address;
					return buildMockFundingTx(address, Number(amountSats));
				},
				broadcastTransaction: async () => 'txid'
			};

			aliceConfig.fundingProvider = mockProvider;
			const alice = new LightningNode(aliceConfig);
			const bob = new LightningNode(bobConfig);
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});
			connectNodes(alice, bob);

			try {
				alice.openChannel(bob.getNodeId(), 100_000n);
				await settle(() => capturedAddress !== '');

				// Verify the address matches what createFundingScript would produce
				const { address } = createFundingScript(
					aliceConfig.channelBasepoints.fundingPubkey,
					bobConfig.channelBasepoints.fundingPubkey,
					bitcoin.networks.regtest
				);
				expect(capturedAddress).to.equal(address);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});
	});

	describe('manual flow still works without fundingProvider', function () {
		it('should allow manual createFunding when no provider is set', function () {
			const alice = new LightningNode(makeNodeConfig(3));
			const bob = new LightningNode(makeNodeConfig(4));
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});
			connectNodes(alice, bob);

			const channel = alice.openChannel(bob.getNodeId(), 200_000n);

			// Manual funding: create a fake funding tx
			const fundingTxid = crypto.randomBytes(32);
			const sig = crypto.randomBytes(64);
			const channelId = alice.createFunding(channel, fundingTxid, 0, sig);

			expect(channelId).to.not.be.null;
			expect(channelId!.length).to.equal(32);

			alice.destroy();
			bob.destroy();
		});
	});

	describe('error handling', function () {
		it('should emit AUTO_FUNDING_FAILED when wallet has insufficient funds', async function () {
			const mockProvider: IFundingProvider = {
				buildFundingTransaction: async () => {
					throw new Error('Insufficient funds');
				},
				broadcastTransaction: async () => ''
			};

			const alice = new LightningNode(makeNodeConfig(5, mockProvider));
			const bob = new LightningNode(makeNodeConfig(6));
			bob.on('node:error', () => {});

			connectNodes(alice, bob);

			const errors: ILightningError[] = [];
			alice.on('node:error', (err: ILightningError) => {
				errors.push(err);
			});

			try {
				alice.openChannel(bob.getNodeId(), 100_000n);
				await settle(() =>
					errors.some((e) => e.code === 'AUTO_FUNDING_FAILED')
				);

				const fundingError = errors.find(
					(e) => e.code === 'AUTO_FUNDING_FAILED'
				);
				expect(fundingError!.message).to.include('Insufficient funds');
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});

		it('should emit FUNDING_BROADCAST_FAILED when broadcast fails', async function () {
			const mockProvider: IFundingProvider = {
				buildFundingTransaction: async (address, amountSats) => {
					return buildMockFundingTx(address, Number(amountSats));
				},
				broadcastTransaction: async () => {
					throw new Error('Connection refused');
				}
			};

			const alice = new LightningNode(makeNodeConfig(7, mockProvider));
			const bob = new LightningNode(makeNodeConfig(8));
			bob.on('node:error', () => {});

			connectNodes(alice, bob);

			const errors: ILightningError[] = [];
			alice.on('node:error', (err: ILightningError) => {
				errors.push(err);
			});

			try {
				alice.openChannel(bob.getNodeId(), 100_000n);
				await settle(() =>
					errors.some((e) => e.code === 'FUNDING_BROADCAST_FAILED')
				);

				const broadcastError = errors.find(
					(e) => e.code === 'FUNDING_BROADCAST_FAILED'
				);
				expect(broadcastError!.message).to.include('Connection refused');
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});
	});

	describe('fromMnemonic with fundingProvider', function () {
		it('should accept fundingProvider in fromMnemonic options', function () {
			const mockProvider: IFundingProvider = {
				buildFundingTransaction: async () => ({
					txHex: '',
					txid: Buffer.alloc(32),
					outputIndex: 0
				}),
				broadcastTransaction: async () => ''
			};

			const mnemonic =
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

			const node = LightningNode.fromMnemonic(mnemonic, {
				network: Network.REGTEST,
				fundingProvider: mockProvider
			});

			expect(node).to.be.instanceOf(LightningNode);
			expect(node.getNodeId()).to.be.a('string');

			node.destroy();
		});
	});

	describe('max funding flag plumbing', function () {
		// Deliver peer messages on the next tick rather than synchronously. A real
		// transport is async, so openChannel returns (registering the fee rate and
		// max flag against the temporary id) before accept_channel comes back and
		// handleAutoFunding reads them. Synchronous delivery would run funding inside
		// openChannel, before those are set, which no real network does.
		function connectNodesAsync(a: LightningNode, b: LightningNode): void {
			a.on('message:outbound', (pubkey, type, payload) => {
				if (pubkey === b.getNodeId())
					setImmediate(() => b.handlePeerMessage(a.getNodeId(), type, payload));
			});
			b.on('message:outbound', (pubkey, type, payload) => {
				if (pubkey === a.getNodeId())
					setImmediate(() => a.handlePeerMessage(b.getNodeId(), type, payload));
			});
		}

		// A capturing provider records exactly what handleAutoFunding passes at
		// funding time, so these assert the temporary-id flag reaches the provider,
		// not the sweep math (covered in wallet-funding-provider.test.ts).
		function capturingProvider(): {
			provider: IFundingProvider;
			calls: Array<{ amount: bigint; rate?: number; max?: boolean }>;
		} {
			const calls: Array<{ amount: bigint; rate?: number; max?: boolean }> = [];
			const provider: IFundingProvider = {
				buildFundingTransaction: async (address, amountSats, rate, max) => {
					calls.push({ amount: amountSats, rate, max });
					return buildMockFundingTx(address, Number(amountSats));
				},
				broadcastTransaction: async (txHex) =>
					bitcoin.Transaction.fromHex(txHex).getId()
			};
			return { provider, calls };
		}

		it('threads max and the pinned rate through accept_channel to funding', async function () {
			const { provider, calls } = capturingProvider();
			const alice = new LightningNode(makeNodeConfig(41, provider));
			const bob = new LightningNode(makeNodeConfig(42));
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});
			connectNodesAsync(alice, bob);

			try {
				alice.openChannel(bob.getNodeId(), 99_500n, undefined, 2, true);
				await settle(() => calls.length >= 1);
				// A duplicate build would land after the first, so hold a window for
				// it. Like the fixed window this replaces, it also gives the queued
				// funding_created and funding_signed time to land before the nodes
				// are destroyed (issue #947).
				await neverSettles(() => calls.length > 1, 80);

				expect(calls.length, 'funding built once').to.equal(1);
				expect(calls[0].max, 'max threaded to provider').to.be.true;
				expect(calls[0].rate, 'pinned rate threaded').to.equal(2);
				expect(calls[0].amount).to.equal(99_500n);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});

		it('does not leak the max flag to a later non-max open', async function () {
			// Sequential opens: a max open funds and consumes its flag, then a later
			// open to a different peer must not inherit it (the temporary-id entry is
			// per-channel and cleared after use).
			const { provider, calls } = capturingProvider();
			const alice = new LightningNode(makeNodeConfig(43, provider));
			const bob = new LightningNode(makeNodeConfig(44));
			const carol = new LightningNode(makeNodeConfig(45));
			[alice, bob, carol].forEach((n) => n.on('node:error', () => {}));
			connectNodesAsync(alice, bob);
			connectNodesAsync(alice, carol);

			try {
				alice.openChannel(bob.getNodeId(), 99_500n, undefined, 2, true);
				// handleAutoFunding deletes the temporary-id flag before it calls the
				// provider, so a recorded call means the max flag is already spent.
				await settle(() => calls.length >= 1);
				// The window a duplicate build would need. It also gives the first
				// handshake time to drain, so the opens run one after the other as
				// they did under the old fixed window (issue #947).
				await neverSettles(() => calls.length > 1, 80);
				expect(calls.length, 'max open funded').to.equal(1);
				expect(calls[0].max, 'max open swept').to.be.true;

				// A later, non-max open to a different peer.
				alice.openChannel(carol.getNodeId(), 40_000n, undefined, 2);
				await settle(() => calls.length >= 2);
				await neverSettles(() => calls.length > 2, 80);
				expect(calls.length, 'both opens funded').to.equal(2);
				expect(calls[1].amount).to.equal(40_000n);
				expect(calls[1].max, 'plain open did not inherit max').to.not.equal(
					true
				);
			} finally {
				alice.destroy();
				bob.destroy();
				carol.destroy();
			}
		});

		it('rejects a max open without a pinned satsPerVbyte', function () {
			// An unpinned rate would let funding price the sweep differently from the
			// committed amount; the open is refused up front rather than failing after
			// the peer has accepted.
			const { provider } = capturingProvider();
			const alice = new LightningNode(makeNodeConfig(46, provider));
			const bob = new LightningNode(makeNodeConfig(47));
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});
			connectNodes(alice, bob);

			expect(() =>
				alice.openChannel(bob.getNodeId(), 99_500n, undefined, undefined, true)
			).to.throw(/pinned satsPerVbyte/);

			alice.destroy();
			bob.destroy();
		});
	});
});
