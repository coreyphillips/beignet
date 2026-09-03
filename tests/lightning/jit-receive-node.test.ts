/**
 * JIT channel receive wired into LightningNode (issue #594, LFBW port 3A).
 *
 * Two nodes over a loopback transport: alice is the LSP, bob the wallet with
 * no channel. Bob registers a receive intent over the beignet custom message
 * type, alice mints an intercept SCID, and an HTLC addressed to that SCID
 * makes alice open a real zero-conf channel to bob and forward onto it.
 *
 * The rest is about what registering an intent must NOT buy: it authorizes
 * alice's own outbound zero-conf open to bob and nothing else, and it never
 * lets an intercept SCID be shadowed by a channel alias.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import {
	Channel,
	ISpliceWalletInput
} from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IFundingProvider } from '../../src/lightning/node/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	encodeCustomMessage
} from '../../src/lightning/message/custom';
import {
	IJitReceiveAck,
	decodeJitAck,
	encodeJitAuthorization
} from '../../src/lightning/liquidity/jit-receive';
import { ROUTING_INFO_LENGTH } from '../../src/lightning/onion/types';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';

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

function nodeConfig(
	label: string
): ConstructorParameters<typeof LightningNode>[0] {
	const seed = crypto.createHash('sha256').update(`jit-${label}`).digest();
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(`jit-priv-${label}`)
			.digest(),
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		network: Network.REGTEST
	};
}

/** A real spendable P2WPKH UTXO with a working witness-signing closure. */
function makeWalletInput(valueSats: number): ISpliceWalletInput {
	const priv = crypto.randomBytes(32);
	const pub = getPublicKey(priv);
	const payment = bitcoin.payments.p2wpkh({ pubkey: pub });
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(payment.output!, valueSats);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output!;
	return {
		prevTx: prevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(valueSats),
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value): Buffer[] => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				scriptCode,
				Number(value),
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [
				bitcoin.script.signature.encode(
					Buffer.from(ecc.sign(sighash, priv)),
					bitcoin.Transaction.SIGHASH_ALL
				),
				pub
			];
		}
	};
}

function fundingProvider(): IFundingProvider {
	const changeScript = bitcoin.payments.p2wpkh({
		hash: crypto.randomBytes(20)
	}).output!;
	return {
		buildFundingTransaction: async () => {
			throw new Error('v1 funding must not run for a dual-fund peer');
		},
		broadcastTransaction: async () => 'broadcast-txid',
		selectDualFundingInputs: async () => ({
			inputs: [makeWalletInput(500_000)],
			changeScript
		})
	} as IFundingProvider;
}

interface IPair {
	alice: LightningNode;
	bob: LightningNode;
	destroy: () => void;
}

function nodePair(
	aliceExtras: Partial<ConstructorParameters<typeof LightningNode>[0]> = {}
): IPair {
	const alice = new LightningNode({
		...nodeConfig('alice'),
		fundingProvider: fundingProvider(),
		jitReceive: {
			enabled: true,
			fundingBufferSats: 10_000n,
			fundingRetryDelayMs: 1
		},
		...aliceExtras
	});
	const bob = new LightningNode(nodeConfig('bob'));
	for (const n of [alice, bob]) {
		n.on('error', () => undefined);
		n.on('node:error', () => undefined);
	}
	const deliver = (from: LightningNode, to: LightningNode) => {
		return (pk: string, t: number, p: Buffer): void => {
			if (pk === to.getNodeId()) to.handlePeerMessage(from.getNodeId(), t, p);
		};
	};
	alice.on('message:outbound', deliver(alice, bob));
	bob.on('message:outbound', deliver(bob, alice));
	// A peer session so the trusted (zero-conf, dual-funded) open routes v2 and
	// custom messages have somewhere to go.
	const features = LightningNode.defaultFeatures();
	features.setBit(Feature.DUAL_FUND + 1);
	for (const [self, peer] of [
		[alice, bob],
		[bob, alice]
	] as const) {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(self as any).peerManager = {
			getPeer: (pubkey: string) =>
				pubkey === peer.getNodeId()
					? { getRemoteInit: (): { features: FeatureFlags } => ({ features }) }
					: undefined,
			sendToPeer: deliver(self, peer),
			destroy: (): void => undefined
		};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(self as any).feeAdvisor = { getCurrentRate: (): number => 4 };
	}
	// The WALLET trusts its LSP, which is what lets bob accept a zero-conf
	// channel from alice. Alice deliberately does NOT trust bob: her side of
	// the open is authorized by bob's intent alone.
	bob.addTrustedPeer(alice.getNodeId());
	return {
		alice,
		bob,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
}

/** Bob asks alice for JIT inbound; returns alice's ack as bob decoded it. */
function registerIntent(
	pair: IPair,
	overrides: {
		maxAmountMsat?: bigint;
		expectedTotalMsat?: bigint;
		targetRemainingInboundSat?: bigint;
		paymentHash?: Buffer;
	} = {}
): IJitReceiveAck {
	let ack: IJitReceiveAck | undefined;
	pair.bob.on('custom-message', (m: { subtype: number; payload: Buffer }) => {
		if (m.subtype === BeignetCustomSubtype.JIT_RECEIVE_ACK) {
			ack = decodeJitAck(m.payload);
		}
	});
	pair.alice.handlePeerMessage(
		pair.bob.getNodeId(),
		BEIGNET_CUSTOM_MESSAGE_TYPE,
		encodeCustomMessage(
			BeignetCustomSubtype.JIT_RECEIVE_AUTHORIZATION,
			encodeJitAuthorization({
				requestId: crypto.randomBytes(8),
				maxAmountMsat: overrides.maxAmountMsat ?? 100_000_000n,
				targetRemainingInboundSat:
					overrides.targetRemainingInboundSat ?? 20_000n,
				expirySeconds: 600,
				...(overrides.expectedTotalMsat !== undefined
					? { expectedTotalMsat: overrides.expectedTotalMsat }
					: {}),
				...(overrides.paymentHash ? { paymentHash: overrides.paymentHash } : {})
			})
		)
	);
	expect(ack, 'bob received no JIT ack').to.not.equal(undefined);
	return ack!;
}

/** Drive one forward through alice addressed to `scid`. */
function driveForward(
	alice: LightningNode,
	scid: Buffer,
	opts: { amountMsat?: bigint; incomingCltvExpiry?: number } = {}
): { paymentHash: Buffer } {
	const paymentHash = crypto.randomBytes(32);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(alice as any).handleForwardHtlc(
		crypto.randomBytes(32),
		7n,
		paymentHash,
		{
			hopPayload: {
				amountToForwardMsat: opts.amountMsat ?? 2_000_000n,
				outgoingCltvValue: 800_050,
				shortChannelId: scid
			},
			nextPacket: {
				version: 0,
				ephemeralKey: getPublicKey(crypto.randomBytes(32)),
				routingInfo: Buffer.alloc(ROUTING_INFO_LENGTH),
				hmac: crypto.randomBytes(32)
			},
			sharedSecret: crypto.randomBytes(32)
		},
		// Generous relay fee, so a forward onto a real channel clears the
		// outgoing policy check and reaches the add.
		(opts.amountMsat ?? 2_000_000n) + 100_000n,
		opts.incomingCltvExpiry ?? 800_200
	);
	return { paymentHash };
}

describe('JIT receive on LightningNode (issue #594)', function () {
	this.timeout(15_000);
	const open: IPair[] = [];

	afterEach(function () {
		for (const pair of open.splice(0)) pair.destroy();
	});

	it('holds an HTLC for a minted SCID, opens a zero-conf channel and forwards onto it', async function () {
		const pair = nodePair();
		open.push(pair);
		const { alice, bob } = pair;

		const ack = registerIntent(pair, { targetRemainingInboundSat: 25_000n });
		expect(ack.accepted).to.equal(true);
		expect(alice.listChannels()).to.have.length(0);

		const forwards: Buffer[] = [];
		alice.on('htlc:forward', (_in, outChannelId: Buffer) =>
			forwards.push(outChannelId)
		);
		const forwarded = new Promise<void>((resolve, reject) => {
			alice.once('jit:forwarded', () => resolve());
			alice.once('jit:failed', (d: { reason: string }) =>
				reject(new Error(d.reason))
			);
		});

		driveForward(alice, ack.interceptScid);
		await forwarded;

		const channels = alice.listChannels();
		expect(channels, 'alice funded a channel to bob').to.have.length(1);
		expect(channels[0].state).to.equal(ChannelState.NORMAL);
		// 2000 sat received + 25000 target inbound + 10000 buffer.
		expect(channels[0].fundingSatoshis).to.equal(37_000n);
		expect(bob.listChannels()).to.have.length(1);
		expect(forwards).to.have.length(1);
		expect(forwards[0].equals(channels[0].channelId)).to.equal(true);
	});

	// Issue #687: the price belongs before the decision to create an invoice.
	it('answers a quote without registering an intent', async function () {
		const pair = nodePair({
			jitReceive: {
				enabled: true,
				fundingBufferSats: 10_000n,
				flatFeeSat: 100n,
				feePpm: 2_000
			}
		});
		open.push(pair);
		const { alice, bob } = pair;
		const quote = await bob.requestJitQuote(alice.getNodeId(), {
			maxAmountMsat: 2_000_000n,
			targetRemainingInboundSat: 25_000n
		});
		expect(quote.accepted).to.equal(true);
		expect(quote.flatFeeSat).to.equal(100n);
		expect(quote.feePpm).to.equal(2_000);
		// 100 sat flat + 2000 ppm of 2000 sat = 104 sat.
		expect(quote.feeSats).to.equal(104n);
		// 2000 sat + 25000 target inbound + 10000 buffer, the open's own sizing.
		expect(quote.fundingSats).to.equal(37_000n);
		expect(quote.withinCeilings).to.equal(true);
		expect(alice.getJitReceiveManager()!.listIntents()).to.have.length(0);
		expect(alice.listChannels()).to.have.length(0);
	});

	it('declines a quote the LSP cannot front from its on-chain funds', async function () {
		const pair = nodePair({
			fundingProvider: {
				...fundingProvider(),
				quoteSpliceIn: () => ({
					spendableSats: 12_000n,
					feeSats: 2_000n,
					maxAmountSats: 10_000n,
					inputCount: 1
				})
			} as IFundingProvider
		});
		open.push(pair);
		const { alice, bob } = pair;
		const quote = await bob.requestJitQuote(alice.getNodeId(), {
			maxAmountMsat: 2_000_000n,
			targetRemainingInboundSat: 25_000n
		});
		expect(quote.accepted).to.equal(false);
		expect(quote.reason).to.equal(
			'the provider does not hold enough on-chain funds to front this receive right now'
		);
		expect(quote.fundingSats).to.equal(0n);
		expect(alice.getJitReceiveManager()!.listIntents()).to.have.length(0);
	});

	it('holds for a splice when the add onto a JIT client channel is refused', async function () {
		const pair = nodePair();
		open.push(pair);
		const { alice } = pair;

		// Open the client's channel through the JIT path first.
		const first = registerIntent(pair, { targetRemainingInboundSat: 25_000n });
		const opened = new Promise<void>((resolve) =>
			alice.once('jit:forwarded', () => resolve())
		);
		driveForward(alice, first.interceptScid);
		await opened;
		// The splice spends an intent of its own: the payment below is 900_000
		// sat, so an intent that does not cover it authorizes nothing.
		registerIntent(pair, { maxAmountMsat: 900_000_000n });

		const events: string[] = [];
		alice.on('jit:funding', (d: { channelIdHex?: string }) =>
			events.push(`funding:${d.channelIdHex ?? 'open'}`)
		);
		alice.on('jit:failed', () => events.push('failed'));

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const scidHex = [...(alice as any).scidToChannelId.keys()][0] as string;
		const channelId = alice.listChannels()[0].channelId.toString('hex');
		// A payment past what the live intent registered for is never spliced
		// for: being a JIT client is not the authorization, the intent is.
		driveForward(alice, Buffer.from(scidHex, 'hex'), {
			amountMsat: 950_000_000n
		});
		expect(events.filter((e) => e.startsWith('funding'))).to.deep.equal([]);

		const settled = new Promise<void>((resolve) =>
			alice.once('jit:failed', () => resolve())
		);
		// Far past alice's 37000 sat side of the channel, so the add is refused
		// for liquidity: for a JIT client that is a splice, not a dead end.
		driveForward(alice, Buffer.from(scidHex, 'hex'), {
			amountMsat: 900_000_000n
		});
		await settled;

		// The part was HELD (a splice was attempted for this channel) before
		// anything failed: the hook sits in forwardHtlcOnto's refusal arm.
		// The splice itself cannot run without a wallet selection provider, so
		// it then fails the part cleanly rather than leaking it.
		expect(events).to.include(`funding:${channelId}`);
		expect(events).to.include('failed');
	});

	it('authorizes only OUR outbound open, never an inbound zero-conf channel', function () {
		const pair = nodePair();
		open.push(pair);
		const manager = pair.alice.getChannelManager();
		const bobId = pair.bob.getNodeId();

		registerIntent(pair);

		expect(manager.isJitClient(bobId)).to.equal(true);
		// Trusted-set membership is symmetric: it also makes an INBOUND
		// zero-conf channel from the peer usable at depth 0. Registering an
		// intent must not buy that.
		expect(manager.isTrustedPeer(bobId)).to.equal(false);
		expect(manager.listTrustedPeers()).to.deep.equal([]);
	});

	it('withdraws the authorization when the intent expires', function () {
		const pair = nodePair();
		open.push(pair);
		const manager = pair.alice.getChannelManager();
		registerIntent(pair);

		const engine = pair.alice.getJitReceiveManager()!;
		engine.listIntents()[0].expiresAt = Date.now() - 1;
		pair.alice.handleNewBlock(800_001);

		expect(engine.listIntents()).to.have.length(0);
		expect(manager.isJitClient(pair.bob.getNodeId())).to.equal(false);
	});

	it('fails a held part on the block tick once its inbound CLTV deadline nears', function () {
		const pair = nodePair();
		open.push(pair);
		const { alice } = pair;
		// A declared total the single part cannot reach, so it stays held.
		const ack = registerIntent(pair, { expectedTotalMsat: 90_000_000n });

		const failures: number[] = [];
		const engine = alice.getJitReceiveManager()!;
		expect(
			engine.tryInterceptUnknownScid(ack.interceptScid.toString('hex'), {
				inChannelId: crypto.randomBytes(32),
				inHtlcId: 3n,
				paymentHash: crypto.randomBytes(32),
				forwardAmountMsat: 1_000_000n,
				forwardCltv: 800_000,
				incomingCltvExpiry: 800_100,
				nextPacket: {
					version: 0,
					ephemeralKey: getPublicKey(crypto.randomBytes(32)),
					routingInfo: Buffer.alloc(ROUTING_INFO_LENGTH),
					hmac: crypto.randomBytes(32)
				},
				failIncoming: (code: number): boolean => {
					failures.push(code);
					return true;
				}
			})
		).to.equal(true);

		alice.handleNewBlock(800_090);

		expect(failures).to.have.length(1);
		expect(engine.heldTotalMsat(ack.interceptScid.toString('hex'))).to.equal(
			0n
		);
	});

	it('refuses to register a channel SCID that would shadow a live intent', function () {
		const pair = nodePair();
		open.push(pair);
		const { alice } = pair;
		const ack = registerIntent(pair);

		const channelId = crypto.randomBytes(32);
		alice.registerChannelScid(channelId, ack.interceptScid);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const mapped = (alice as any).scidToChannelId.get(
			ack.interceptScid.toString('hex')
		);
		expect(
			mapped,
			'a peer alias must not take over an intercept SCID'
		).to.equal(undefined);

		// An unrelated SCID still registers normally.
		const real = encodeShortChannelId({
			block: 800_000,
			txIndex: 3,
			outputIndex: 0
		});
		alice.registerChannelScid(channelId, real);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((alice as any).scidToChannelId.has(real.toString('hex'))).to.equal(
			true
		);
	});

	it('drops a malformed authorization without disconnecting or blocking other listeners', function () {
		const pair = nodePair();
		open.push(pair);
		const seen: number[] = [];
		pair.alice.on('custom-message', (m: { subtype: number }) =>
			seen.push(m.subtype)
		);

		expect(() =>
			pair.alice.handlePeerMessage(
				pair.bob.getNodeId(),
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				encodeCustomMessage(
					BeignetCustomSubtype.JIT_RECEIVE_AUTHORIZATION,
					Buffer.alloc(4)
				)
			)
		).to.not.throw();
		// Our handler runs first; the application's listener must still see it.
		expect(seen).to.deep.equal([
			BeignetCustomSubtype.JIT_RECEIVE_AUTHORIZATION
		]);
		expect(pair.alice.getJitReceiveManager()!.listIntents()).to.have.length(0);
	});

	it('fails a part held across a restart, upstream and off-chain', function () {
		const inChannelId = crypto.randomBytes(32);
		const peerId = '02' + 'dd'.repeat(32);
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const node = new LightningNode({
			...nodeConfig('restart'),
			storage,
			jitReceive: { enabled: true }
		});
		node.on('error', () => undefined);
		node.on('node:error', () => undefined);
		try {
			// The channel and its committed inbound HTLC come back from channel
			// state; installing them here stands in for that restore.
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 200_000n,
				pushMsat: 100_000_000n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(crypto.randomBytes(32)),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.channelId = inChannelId;
			state.htlcs.set('received-4', {
				id: 4n,
				amountMsat: 1_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 800_400,
				direction: HtlcDirection.RECEIVED,
				state: HtlcState.COMMITTED,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			const channel = new Channel(state);
			const manager = node.getChannelManager();
			manager.restoreChannel(channel, peerId);

			// What the node that went down left behind: one held part, and a
			// disposition naming what the restart owes its inbound leg.
			storage.saveMetadata(
				'jit:held',
				JSON.stringify([
					{
						inChannelIdHex: inChannelId.toString('hex'),
						inHtlcId: '4',
						paymentHashHex: crypto.randomBytes(32).toString('hex'),
						amountMsat: '1000000',
						incomingCltvExpiry: 800_400,
						disposition: 'fail'
					}
				])
			);

			// The onion shared secret comes back from storage with the channel,
			// and the failure the payer decrypts is built from it.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(node as any).receivedHtlcSharedSecrets.set(
				`${inChannelId.toString('hex')}:4`,
				crypto.randomBytes(32)
			);

			const failed: bigint[] = [];
			const reasons: Buffer[] = [];
			const original = manager.failHtlc.bind(manager);
			manager.failHtlc = (
				cid: Buffer,
				htlcId: bigint,
				reason: Buffer
			): ReturnType<typeof original> => {
				const result = original(cid, htlcId, reason);
				if (result.ok !== false) {
					failed.push(htlcId);
					reasons.push(reason);
				}
				return result;
			};

			node.getJitReceiveManager()!.restore();

			// A restored channel is AWAITING_REESTABLISH, so the fail cannot be
			// delivered yet: the row must survive rather than be dropped as done.
			expect(failed).to.deep.equal([]);
			expect(JSON.parse(storage.loadMetadata('jit:held')!)).to.have.length(1);

			// Once the channel is back, the block tick delivers it.
			const live = channel.getFullState() as unknown as {
				state: ChannelState;
				preReestablishState?: ChannelState;
			};
			live.state = ChannelState.NORMAL;
			live.preReestablishState = undefined;
			node.handleNewBlock(800_001);

			expect(failed).to.deep.equal([4n]);
			// The refused first attempt must not have consumed the shared
			// secret: a retry without it can only send a zeroed packet the
			// payer cannot decrypt.
			expect(reasons[0].equals(Buffer.alloc(reasons[0].length))).to.equal(
				false
			);
			expect(storage.loadMetadata('jit:held')).to.equal('[]');
		} finally {
			node.destroy();
			storage.close?.();
		}
	});

	it('never re-dispatches an HTLC the restored hold queue owes a refund', function () {
		// The restore repair re-dispatches committed inbound HTLCs whose
		// forward this process lost. One the JIT engine was holding is already
		// owed a refund, so dispatching it would forward a payment the sweep is
		// about to fail upstream: paid downstream and refunded upstream.
		const inChannelId = crypto.randomBytes(32);
		const peerId = '02' + 'ee'.repeat(32);
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const node = new LightningNode({
			...nodeConfig('redispatch'),
			storage,
			jitReceive: { enabled: true }
		});
		node.on('error', () => undefined);
		node.on('node:error', () => undefined);
		try {
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 200_000n,
				pushMsat: 100_000_000n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(crypto.randomBytes(32)),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.channelId = inChannelId;
			for (const id of [4n, 5n]) {
				state.htlcs.set(`received-${id}`, {
					id,
					amountMsat: 1_000_000n,
					paymentHash: crypto.randomBytes(32),
					cltvExpiry: 800_400,
					direction: HtlcDirection.RECEIVED,
					state: HtlcState.COMMITTED,
					onionRoutingPacket: Buffer.alloc(1366),
					forwardEmitted: true
				});
			}
			const manager = node.getChannelManager();
			manager.restoreChannel(new Channel(state), peerId);

			// Only HTLC 4 was held by the engine when the process went away.
			storage.saveMetadata(
				'jit:held',
				JSON.stringify([
					{
						inChannelIdHex: inChannelId.toString('hex'),
						inHtlcId: '4',
						paymentHashHex: crypto.randomBytes(32).toString('hex'),
						amountMsat: '1000000',
						incomingCltvExpiry: 800_400,
						disposition: 'fail'
					}
				])
			);
			node.getJitReceiveManager()!.restore();

			const dispatched: bigint[] = [];
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(node as any).handleIncomingHtlc = (_cid: Buffer, id: bigint): void => {
				dispatched.push(id);
			};
			manager.emit('channel:restore-ready', inChannelId);

			// The unheld one is still repaired: the guard is scoped to the queue.
			expect(dispatched).to.deep.equal([5n]);
		} finally {
			node.destroy();
			storage.close?.();
		}
	});
});
