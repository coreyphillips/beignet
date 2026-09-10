/**
 * Issue #774: the HTLC backstops on a splicing channel.
 *
 * A splice takes blocks, from quiescence through to splice_locked, and the
 * per-block scans that force close to claim an inbound HTLC we hold the
 * preimage for, to time out an offered HTLC the peer sits on, or to move an
 * unresolved forward on chain, admitted NORMAL and ERRORED only. Every one of
 * them was off for the whole splice. The planner builds against whichever
 * funding the chain has (issue #764), so admitting SPLICING is all it takes.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { createFundingScript } from '../../src/lightning/script/funding';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry
} from '../../src/lightning/channel/types';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { buildLocalCommitment } from '../../src/lightning/channel/commitment-builder';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`htlc-backstops-splicing-seed-${id}`))
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

/** A backend that records broadcasts and answers every history with nothing. */
class ControlledBackend implements IChainBackend {
	broadcasts: string[] = [];
	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		return [];
	}
	async getTransaction(): Promise<Buffer> {
		throw new Error('not needed');
	}
	async broadcastTransaction(hex: string): Promise<string> {
		this.broadcasts.push(hex);
		return bitcoin.Transaction.fromHex(hex).getId();
	}
}

const tick = (ms = 25): Promise<void> => new Promise((r) => setTimeout(r, ms));

const HEIGHT = 800_000;
const PEER_FUNDING_PRIV = crypto
	.createHash('sha256')
	.update('htlc-backstops-splicing-peer-funding')
	.digest();

interface IFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	backend: ControlledBackend;
	fundingTxid: Buffer;
	events: string[];
	destroy: () => void;
}

async function setup(seedBase: number): Promise<IFixture> {
	const backend = new ControlledBackend();
	const configA = makeNodeConfig(seedBase);
	configA.chainBackend = backend;
	const alice = new LightningNode(configA);
	const bob = new LightningNode(makeNodeConfig(seedBase + 1));
	for (const node of [alice, bob]) {
		node.on('error', () => {});
	}
	bob.on('node:error', () => {});
	const events: string[] = [];
	alice.on('node:error', (err: { code: string }) => events.push(err.code));
	alice.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === bob.getNodeId())
			bob.handlePeerMessage(alice.getNodeId(), type, payload);
	});
	bob.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === alice.getNodeId())
			alice.handlePeerMessage(bob.getNodeId(), type, payload);
	});

	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const fundingTxid = crypto
		.createHash('sha256')
		.update(`htlc-backstops-splicing-funding-${seedBase}`)
		.digest();
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	await tick(60); // let the chain watcher auto-start
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(alice as any).currentBlockHeight = HEIGHT;

	return {
		alice,
		bob,
		channelId,
		backend,
		fundingTxid,
		events,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
}

/** The peer's signature over the commitment the splice record adopts to. */
function signAdoptedCommitment(
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	channel: any,
	peer: ChannelSigner
): Buffer {
	const view = {
		...channel.getFullState(),
		...channel._computeSpliceAdoption()
	};
	const built = buildLocalCommitment(
		view,
		perCommitmentPointFromSecret(
			generateFromSeed(
				view.localPerCommitmentSeed,
				MAX_INDEX - view.localCommitmentNumber
			)
		),
		undefined,
		true
	);
	return peer.signCommitmentTx(
		built.result.tx,
		built.fundingWitnessScript,
		built.fundingAmount
	);
}

/**
 * Put the channel in SPLICING with a fully signed, unlocked, depth-locked
 * splice. `pendingLock` false leaves the signature exchange unfinished, the
 * shape of a splice still negotiating; `seenAt` stamps the splice as mined
 * at that height, below its lock depth.
 */
function putInSplicing(
	node: LightningNode,
	channelId: Buffer,
	opts: { seenAt?: number; pendingLock?: boolean } = {}
): Buffer {
	const channel = node.getChannelManager().getChannel(channelId)!;
	const peer = new ChannelSigner(PEER_FUNDING_PRIV);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const raw = channel.getFullState() as any;
	const spliceTx = new bitcoin.Transaction();
	spliceTx.version = 2;
	spliceTx.addInput(Buffer.from(raw.fundingTxid), raw.fundingOutputIndex);
	spliceTx.addOutput(
		createFundingScript(
			raw.localBasepoints.fundingPubkey,
			peer.fundingPubkey,
			bitcoin.networks.regtest
		).p2wshOutput,
		1_000_000
	);
	const spliceTxid = Buffer.from(spliceTx.getHash());
	const pendingLock = opts.pendingLock ?? true;
	raw.spliceInFlight = {
		spliceTxid,
		newFundingOutputIndex: 0,
		newFundingSatoshis: 1_000_000n,
		spliceTxHex: spliceTx.toHex(),
		fullySigned: pendingLock,
		isInitiator: true,
		localRelativeSatoshis: 0n,
		remoteRelativeSatoshis: 0n,
		remoteFundingPubkey: peer.fundingPubkey,
		ourSharedInputSig: Buffer.alloc(64),
		ourWalletWitnesses: [],
		ourWalletInputIndices: [],
		inputPrevouts: [],
		remoteCommitmentSig: Buffer.alloc(64),
		sentTxSignatures: pendingLock,
		receivedTxSignatures: pendingLock,
		localSpliceLocked: false,
		remoteSpliceLocked: false,
		confirmed: false,
		lockAtDepth: 3
	};
	raw.spliceInFlight.remoteCommitmentSig = signAdoptedCommitment(channel, peer);
	raw.state = ChannelState.SPLICING;
	raw.preSpliceState = ChannelState.NORMAL;
	if (opts.seenAt !== undefined) channel.markSpliceSeenOnChain(opts.seenAt);
	return spliceTxid;
}

/**
 * An HTLC row injected straight into channel state. The 40 sat amount is
 * trimmed, so the commitment the stored signature covers is unchanged and
 * the force close's rebuild still verifies (issue #657).
 */
function addHtlc(
	node: LightningNode,
	channelId: Buffer,
	key: string,
	htlc: Partial<IHtlcEntry> & { id: bigint; cltvExpiry: number }
): IHtlcEntry {
	const entry: IHtlcEntry = {
		amountMsat: 40_000n,
		paymentHash: crypto.randomBytes(32),
		onionRoutingPacket: Buffer.alloc(1366),
		direction: key.startsWith('received-')
			? HtlcDirection.RECEIVED
			: HtlcDirection.OFFERED,
		state: HtlcState.COMMITTED,
		removalRemoteCommitted: false,
		...htlc
	} as IHtlcEntry;
	node
		.getChannelManager()
		.getChannel(channelId)!
		.getFullState()
		.htlcs.set(key, entry);
	return entry;
}

/** An inbound HTLC we hold the preimage for, inside the claim buffer. */
function heldInbound(fx: IFixture): void {
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(fx.alice as any).preimages.set(paymentHash.toString('hex'), preimage);
	addHtlc(fx.alice, fx.channelId, 'received-3', {
		id: 3n,
		paymentHash,
		cltvExpiry: HEIGHT + 10
	});
}

function lastBroadcastSpends(fx: IFixture): Buffer {
	const tx = bitcoin.Transaction.fromHex(
		fx.backend.broadcasts[fx.backend.broadcasts.length - 1]
	);
	return Buffer.from(tx.ins[0].hash);
}

function spyFailHtlc(fx: IFixture): bigint[] {
	const calls: bigint[] = [];
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const mgr = fx.alice.getChannelManager() as any;
	const real = mgr.failHtlc.bind(mgr);
	mgr.failHtlc = (
		channelId: Buffer,
		htlcId: bigint,
		reason: Buffer
	): unknown => {
		calls.push(htlcId);
		return real(channelId, htlcId, reason);
	};
	return calls;
}

describe('Issue #774: the HTLC backstops on a splicing channel', function () {
	this.timeout(10_000);

	describe('scanExpiringHtlcs', () => {
		it('force closes to claim a held preimage while the splice is unmined', async () => {
			const fx = await setup(7741);
			putInSplicing(fx.alice, fx.channelId);
			heldInbound(fx);
			const before = fx.backend.broadcasts.length;

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(fx.alice as any).scanExpiringHtlcs(HEIGHT);
			await tick();

			expect(fx.events).to.include('HTLC_CLAIM_FORCE_CLOSE');
			expect(fx.backend.broadcasts.length, 'a close went out').to.equal(
				before + 1
			);
			expect(
				lastBroadcastSpends(fx).equals(fx.fundingTxid),
				'spending the pre-splice funding, the only one the chain has'
			).to.equal(true);
			fx.destroy();
		});

		it('force closes onto the splice once the chain has it below its lock depth', async () => {
			const fx = await setup(7751);
			const spliceTxid = putInSplicing(fx.alice, fx.channelId, {
				seenAt: HEIGHT - 1
			});
			heldInbound(fx);
			const before = fx.backend.broadcasts.length;

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(fx.alice as any).scanExpiringHtlcs(HEIGHT);
			await tick();

			expect(fx.events).to.include('HTLC_CLAIM_FORCE_CLOSE');
			expect(fx.backend.broadcasts.length).to.equal(before + 1);
			expect(
				lastBroadcastSpends(fx).equals(spliceTxid),
				'spending the splice funding'
			).to.equal(true);
			fx.destroy();
		});

		it('is admitted through the reestablish wrapper', async () => {
			const fx = await setup(7761);
			putInSplicing(fx.alice, fx.channelId);
			const state = fx.alice
				.getChannelManager()
				.getChannel(fx.channelId)!
				.getFullState();
			state.preReestablishState = ChannelState.SPLICING;
			state.state = ChannelState.AWAITING_REESTABLISH;
			heldInbound(fx);

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(fx.alice as any).scanExpiringHtlcs(HEIGHT);
			await tick();

			expect(fx.events).to.include('HTLC_CLAIM_FORCE_CLOSE');
			fx.destroy();
		});

		it('still leaves a parked hold-invoice HTLC alone', async () => {
			const fx = await setup(7771);
			putInSplicing(fx.alice, fx.channelId);
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const a = fx.alice as any;
			a.preimages.set(paymentHash.toString('hex'), preimage);
			a.heldInvoiceHashes.add(paymentHash.toString('hex'));
			addHtlc(fx.alice, fx.channelId, 'received-3', {
				id: 3n,
				paymentHash,
				cltvExpiry: HEIGHT + 10,
				state: HtlcState.COMMITTED
			});

			a.scanExpiringHtlcs(HEIGHT);
			await tick();

			expect(fx.events).to.not.include('HTLC_CLAIM_FORCE_CLOSE');
			fx.destroy();
		});

		it('fails an unclaimable inbound HTLC off chain in the pending-lock window, and not before', async () => {
			const parked = await setup(7781);
			putInSplicing(parked.alice, parked.channelId, { pendingLock: false });
			addHtlc(parked.alice, parked.channelId, 'received-4', {
				id: 4n,
				cltvExpiry: HEIGHT + 2
			});
			const parkedCalls = spyFailHtlc(parked);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(parked.alice as any).scanExpiringHtlcs(HEIGHT);
			await tick();
			expect(parkedCalls, 'no update can leave mid-negotiation').to.have.length(
				0
			);
			expect(parked.events).to.not.include('HTLC_CLAIM_FORCE_CLOSE');
			parked.destroy();

			const flowing = await setup(7791);
			putInSplicing(flowing.alice, flowing.channelId);
			addHtlc(flowing.alice, flowing.channelId, 'received-4', {
				id: 4n,
				cltvExpiry: HEIGHT + 2
			});
			const flowingCalls = spyFailHtlc(flowing);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(flowing.alice as any).scanExpiringHtlcs(HEIGHT);
			await tick();
			expect(flowingCalls, 'the fail goes out once updates flow').to.deep.equal(
				[4n]
			);
			flowing.destroy();
		});
	});

	describe('scanExpiringOfferedHtlcs', () => {
		it('times out an offered HTLC past expiry and grace on a splicing channel', async () => {
			const fx = await setup(7801);
			putInSplicing(fx.alice, fx.channelId);
			addHtlc(fx.alice, fx.channelId, 'offered-9', {
				id: 9n,
				cltvExpiry: HEIGHT - 6
			});
			const before = fx.backend.broadcasts.length;

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(fx.alice as any).scanExpiringOfferedHtlcs(HEIGHT);
			await tick();

			expect(fx.events).to.include('HTLC_EXPIRY_FORCE_CLOSE');
			expect(fx.backend.broadcasts.length).to.equal(before + 1);
			expect(lastBroadcastSpends(fx).equals(fx.fundingTxid)).to.equal(true);
			fx.destroy();
		});

		it('keeps the grace period on a splicing channel', async () => {
			const fx = await setup(7811);
			putInSplicing(fx.alice, fx.channelId);
			addHtlc(fx.alice, fx.channelId, 'offered-9', {
				id: 9n,
				cltvExpiry: HEIGHT
			});

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(fx.alice as any).scanExpiringOfferedHtlcs(HEIGHT);
			await tick();

			expect(fx.events).to.not.include('HTLC_EXPIRY_FORCE_CLOSE');
			fx.destroy();
		});
	});

	describe('scanForwardTimeouts', () => {
		async function setupForward(
			seedBase: number,
			opts: { pendingLock: boolean; outboundFailed: boolean }
		): Promise<IFixture & { calls: bigint[] }> {
			const fx = await setup(seedBase);
			putInSplicing(fx.alice, fx.channelId, { pendingLock: opts.pendingLock });
			const carol = new LightningNode(makeNodeConfig(seedBase + 2));
			carol.on('error', () => {});
			carol.on('node:error', () => {});
			fx.alice.on('message:outbound', (pubkey, type, payload) => {
				if (pubkey === carol.getNodeId())
					carol.handlePeerMessage(fx.alice.getNodeId(), type, payload);
			});
			carol.on('message:outbound', (pubkey, type, payload) => {
				if (pubkey === fx.alice.getNodeId())
					fx.alice.handlePeerMessage(carol.getNodeId(), type, payload);
			});
			const out = fx.alice.openChannel(carol.getNodeId(), 1_000_000n);
			const outChannelId = fx.alice.createFunding(
				out,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			)!;
			fx.alice.handleFundingConfirmed(outChannelId);
			carol.handleFundingConfirmed(outChannelId);
			const paymentHash = crypto.randomBytes(32);
			// Inbound leg on the splicing channel, inside the double margin.
			addHtlc(fx.alice, fx.channelId, 'received-7', {
				id: 7n,
				paymentHash,
				cltvExpiry: HEIGHT + 8
			});
			// A failed outbound leg counts only once its removal is irrevocable.
			addHtlc(fx.alice, outChannelId, 'offered-7', {
				id: 7n,
				paymentHash,
				cltvExpiry: HEIGHT - 40,
				state: opts.outboundFailed ? HtlcState.FAILED : HtlcState.COMMITTED,
				removalRemoteCommitted: opts.outboundFailed ? true : false
			});
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(fx.alice as any).forwardedHtlcs.set(
				`${outChannelId.toString('hex')}:offered-7`,
				{ inChannelId: fx.channelId, inHtlcId: 7n }
			);
			const calls = spyFailHtlc(fx);
			const destroy = fx.destroy;
			return {
				...fx,
				calls,
				destroy: (): void => {
					destroy();
					carol.destroy();
				}
			};
		}

		it('force closes the splicing inbound channel when the outbound leg is unresolved', async () => {
			const fx = await setupForward(7821, {
				pendingLock: false,
				outboundFailed: false
			});
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(fx.alice as any).scanForwardTimeouts(HEIGHT);
			await tick();
			expect(fx.events).to.include('FORWARD_TIMEOUT_FORCE_CLOSE');
			fx.destroy();
		});

		it('waits for the refund to be sendable rather than closing at the double margin', async () => {
			const fx = await setupForward(7831, {
				pendingLock: false,
				outboundFailed: true
			});
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(fx.alice as any).scanForwardTimeouts(HEIGHT);
			await tick();
			expect(fx.calls).to.have.length(0);
			expect(fx.events).to.not.include('FORWARD_TIMEOUT_FORCE_CLOSE');
			fx.destroy();

			const flowing = await setupForward(7841, {
				pendingLock: true,
				outboundFailed: true
			});
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(flowing.alice as any).scanForwardTimeouts(HEIGHT);
			await tick();
			expect(
				flowing.calls,
				'the refund travels once updates flow'
			).to.deep.equal([7n]);
			expect(flowing.events).to.not.include('FORWARD_TIMEOUT_FORCE_CLOSE');
			flowing.destroy();
		});
	});
});
