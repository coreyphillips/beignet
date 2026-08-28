/**
 * JIT receive, wallet side (issue #595, LFBW port 3B).
 *
 * Two nodes over a loopback transport: alice runs the 3A LSP engine, bob is
 * the wallet with no channel. Bob's `requestJitReceive` sends an authorization
 * on the beignet custom message type and waits for the ack alice's engine
 * answers with, then `createJitInvoice` turns the minted intercept SCID into
 * a payable BOLT 11 and registers the quoted fee as an allowance.
 *
 * What the wallet owes itself here: it accepts the LSP's SCID but not the
 * LSP's price. An ack quoting more than the operator configured is refused
 * rather than turned into an invoice authorizing that deduction, and a request
 * that never gets off the socket leaves nothing armed behind it.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { Network } from '../../src/lightning/invoice/types';
import { decode } from '../../src/lightning/invoice/decode';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { FeatureFlags } from '../../src/lightning/features/flags';
import { IInvoiceInfo } from '../../src/lightning/storage/types';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import {
	BeignetCustomSubtype,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import {
	JIT_INTERCEPT_SCID_BLOCK,
	decodeJitAuthorization,
	encodeJitAck
} from '../../src/lightning/liquidity/jit-receive';

/* eslint-disable @typescript-eslint/no-explicit-any */

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
	const seed = crypto.createHash('sha256').update(`jit3b-${label}`).digest();
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(`jit3b-priv-${label}`)
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

interface IPair {
	alice: LightningNode;
	bob: LightningNode;
	destroy: () => void;
}

function nodePair(
	lspConfig: Record<string, unknown> = {},
	walletConfig: Record<string, unknown> = {}
): IPair {
	const alice = new LightningNode({
		...nodeConfig('alice'),
		jitReceive: { enabled: true, ...lspConfig }
	});
	const bob = new LightningNode({ ...nodeConfig('bob'), ...walletConfig });
	for (const n of [alice, bob]) {
		n.on('error', () => undefined);
		n.on('node:error', () => undefined);
	}
	const deliver =
		(from: LightningNode, to: LightningNode) =>
		(pk: string, t: number, p: Buffer): void => {
			if (pk === to.getNodeId()) to.handlePeerMessage(from.getNodeId(), t, p);
		};
	alice.on('message:outbound', deliver(alice, bob));
	bob.on('message:outbound', deliver(bob, alice));
	const features = LightningNode.defaultFeatures();
	for (const [self, peer] of [
		[alice, bob],
		[bob, alice]
	] as const) {
		(self as any).peerManager = {
			getPeer: (pubkey: string) =>
				pubkey === peer.getNodeId()
					? { getRemoteInit: (): { features: FeatureFlags } => ({ features }) }
					: undefined,
			sendToPeer: deliver(self, peer),
			destroy: (): void => undefined
		};
	}
	return {
		alice,
		bob,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
}

/** SCIDs the engine mints all carry the pinned block field. */
function isMintedScid(scid: Buffer): boolean {
	return scid.readUIntBE(0, 3) === JIT_INTERCEPT_SCID_BLOCK;
}

/** A NORMAL channel with inbound, so a blinded path can be built from it. */
function injectNormalChannel(node: LightningNode): void {
	const channelId = crypto.randomBytes(32);
	const peerPubkey = getPublicKey(
		crypto.createHash('sha256').update('jit3b-blinded-peer').digest()
	);
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: makeBasepoints(crypto.randomBytes(32)),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = channelId;
	// The SCID a peer resolves is the alias the PEER sent us (BOLT 2).
	state.remoteScidAlias = encodeShortChannelId({
		block: 800000,
		txIndex: 1,
		outputIndex: 0
	});
	const cm = (node as any).channelManager;
	cm.channels.set(channelId.toString('hex'), new Channel(state));
	cm.channelPeers.set(channelId.toString('hex'), peerPubkey.toString('hex'));
}

describe('JIT receive wallet side (issue #595)', function () {
	this.timeout(15_000);
	const open: IPair[] = [];

	afterEach(function () {
		for (const pair of open.splice(0)) pair.destroy();
	});

	it('registers an intent and returns the LSP hint plus its quote', async () => {
		const pair = nodePair({ flatFeeSat: 3n, feePpm: 500 });
		open.push(pair);
		const grant = await pair.bob.requestJitReceive(pair.alice.getNodeId(), {
			maxAmountMsat: 10_000_000n,
			targetRemainingInboundSat: 20_000n
		});

		expect(
			isMintedScid(grant.interceptScid),
			'a minted intercept SCID'
		).to.equal(true);
		expect(grant.flatFeeSat).to.equal(3n);
		expect(grant.feePpm).to.equal(500);
		expect(grant.hint.pubkey.toString('hex')).to.equal(pair.alice.getNodeId());
		expect(grant.hint.shortChannelId.equals(grant.interceptScid)).to.equal(
			true
		);
		// The LSP is paid by the skim, so a hop fee on the hint would have the
		// sender over-deliver on top of the deduction.
		expect(grant.hint.feeBaseMsat).to.equal(0);
		expect(grant.hint.feeProportionalMillionths).to.equal(0);
		expect(grant.hint.cltvExpiryDelta).to.be.greaterThan(40);

		const intents = pair.alice.getJitReceiveManager()!.listIntents();
		expect(intents).to.have.length(1);
		expect(intents[0].walletPubkeyHex).to.equal(pair.bob.getNodeId());
		expect(intents[0].acceptsSkimmedFee, 'the LSP may charge its fee').to.equal(
			true
		);
	});

	it('refuses a quote above the configured ceiling', async () => {
		const pair = nodePair(
			{ flatFeeSat: 0n, feePpm: 40_000 },
			{ jitReceiveClient: { maxFeePpm: 1_000 } }
		);
		open.push(pair);
		let error: unknown = null;
		try {
			await pair.bob.requestJitReceive(pair.alice.getNodeId(), {
				maxAmountMsat: 10_000_000n,
				targetRemainingInboundSat: 0n
			});
		} catch (e) {
			error = e;
		}
		expect((error as Error | null)?.message).to.match(/above the accepted/);
	});

	it('refuses a flat quote above the configured ceiling', async () => {
		const pair = nodePair(
			{ flatFeeSat: 5_000n, feePpm: 0 },
			{ jitReceiveClient: { maxFlatFeeSat: 100n } }
		);
		open.push(pair);
		let error: unknown = null;
		try {
			await pair.bob.requestJitReceive(pair.alice.getNodeId(), {
				maxAmountMsat: 10_000_000n,
				targetRemainingInboundSat: 0n
			});
		} catch (e) {
			error = e;
		}
		expect((error as Error | null)?.message).to.match(/above the accepted/);
	});

	it('surfaces the LSP refusal reason rather than issuing an invoice', async () => {
		// maxClientFundingSats bounds what the engine will front; asking past
		// it is declined with a reason, and the wallet must not paper over it.
		const pair = nodePair({ maxClientFundingSats: 1_000n });
		open.push(pair);
		let error: unknown = null;
		try {
			await pair.bob.createJitInvoice({
				lspPubkeyHex: pair.alice.getNodeId(),
				amountMsat: 500_000_000n,
				description: 'too big'
			});
		} catch (e) {
			error = e;
		}
		expect((error as Error | null)?.message).to.match(/declined/);
		expect(
			[...(pair.bob as any).invoices.values()],
			'no invoice carries an allowance for a declined intent'
		).to.have.length(0);
	});

	it('leaves no listener or timer behind when the send itself fails', async () => {
		const pair = nodePair();
		open.push(pair);
		// Networking gone: sendCustomMessage throws before anything is on the
		// wire, with the ack listener and its timeout already armed.
		(pair.bob as any).peerManager = undefined;
		const before = pair.bob.listenerCount('custom-message');
		let error: unknown = null;
		try {
			await pair.bob.requestJitReceive(pair.alice.getNodeId(), {
				maxAmountMsat: 10_000_000n,
				targetRemainingInboundSat: 0n
			});
		} catch (e) {
			error = e;
		}
		expect((error as Error | null)?.message).to.match(/Networking/);
		expect(pair.bob.listenerCount('custom-message')).to.equal(before);
	});

	it('times out without leaving a listener armed', async () => {
		const pair = nodePair();
		open.push(pair);
		// A peer that receives the authorization and never answers.
		(pair.bob as any).peerManager = {
			getPeer: () => undefined,
			sendToPeer: (): void => undefined,
			destroy: (): void => undefined
		};
		const before = pair.bob.listenerCount('custom-message');
		let error: unknown = null;
		try {
			await pair.bob.requestJitReceive(pair.alice.getNodeId(), {
				maxAmountMsat: 10_000_000n,
				targetRemainingInboundSat: 0n,
				timeoutMs: 30
			});
		} catch (e) {
			error = e;
		}
		expect((error as Error | null)?.message).to.match(/timed out/);
		expect(pair.bob.listenerCount('custom-message')).to.equal(before);
	});

	it('resolves on its own ack, ignoring a foreign or malformed one', async () => {
		const pair = nodePair();
		open.push(pair);
		// A peer that takes the authorization but answers nothing, so the acks
		// below are the only ones in play.
		const sent: Buffer[] = [];
		(pair.bob as any).peerManager = {
			getPeer: () => undefined,
			sendToPeer: (_pk: string, _t: number, envelope: Buffer): void => {
				sent.push(envelope);
			},
			destroy: (): void => undefined
		};

		let settled = false;
		const pending = pair.bob
			.requestJitReceive(pair.alice.getNodeId(), {
				maxAmountMsat: 10_000_000n,
				targetRemainingInboundSat: 0n,
				timeoutMs: 2_000
			})
			.then((g) => {
				settled = true;
				return g;
			});

		const auth = decodeJitAuthorization(
			decodeCustomMessage(sent[0]).payload as Buffer
		);
		const scid = encodeShortChannelId({
			block: JIT_INTERCEPT_SCID_BLOCK,
			txIndex: 7,
			outputIndex: 1
		});
		const ackFrom = (requestId: Buffer): Buffer =>
			encodeJitAck({
				requestId,
				interceptScid: scid,
				accepted: true,
				flatFeeSat: 0n,
				feePpm: 0
			});
		const deliverAck = (payload: Buffer): void => {
			pair.bob.emit('custom-message', {
				peerPubkey: pair.alice.getNodeId(),
				subtype: BeignetCustomSubtype.JIT_RECEIVE_ACK,
				payload
			});
		};

		deliverAck(ackFrom(Buffer.alloc(8, 9)));
		deliverAck(Buffer.alloc(4)); // truncated: swallowed, not fatal
		await new Promise((r) => setTimeout(r, 5));
		expect(settled, 'a foreign or malformed ack must not resolve us').to.equal(
			false
		);

		deliverAck(ackFrom(auth.requestId));
		const grant = await pending;
		expect(grant.interceptScid.equals(scid)).to.equal(true);
	});

	it('issues an invoice through the intercept hint with the fee allowance', async () => {
		const pair = nodePair({ flatFeeSat: 2n, feePpm: 1_000 });
		open.push(pair);
		const result = await pair.bob.createJitInvoice({
			lspPubkeyHex: pair.alice.getNodeId(),
			amountMsat: 1_000_000n,
			description: 'jit receive'
		});

		const decoded = decode(result.bolt11);
		expect(
			decoded.routingHints,
			'the invoice carries the LSP hint'
		).to.have.length(1);
		const hop = decoded.routingHints![0][0];
		expect(hop.pubkey.toString('hex')).to.equal(pair.alice.getNodeId());
		expect(hop.shortChannelId.equals(result.interceptScid)).to.equal(true);
		// Blocks mined while the LSP funds the channel must not push the HTLC
		// under our own minimum.
		expect(decoded.minFinalCltvExpiry).to.equal(72);

		const record = (pair.bob as any).invoices.get(
			result.paymentHash.toString('hex')
		) as IInvoiceInfo;
		expect(record.jitFee).to.deep.equal({ flatFeeSat: 2, feePpm: 1000 });
		expect(result.flatFeeSat).to.equal(2n);
		expect(result.feePpm).to.equal(1000);
	});

	it('keeps the intercept hint out of a blinded invoice', async () => {
		const pair = nodePair();
		open.push(pair);
		const grant = await pair.bob.requestJitReceive(pair.alice.getNodeId(), {
			maxAmountMsat: 10_000_000n,
			targetRemainingInboundSat: 0n
		});
		// The hint names our LSP in the clear, which is the node id blinding
		// exists to hide: it follows the same suppression as any other
		// cleartext hint. Bob gets an injected NORMAL channel here only so a
		// blinded path can be built at all.
		injectNormalChannel(pair.bob);

		const blinded = pair.bob.createInvoice({
			amountMsat: 1_000_000n,
			description: 'blinded',
			useBlindedPaths: true,
			extraRoutingHints: [[grant.hint]]
		});
		const decoded = decode(blinded.bolt11);
		expect(
			decoded.blindedPaths ?? [],
			'a blinded invoice'
		).to.have.length.above(0);
		expect(
			decoded.routingHints ?? [],
			'no cleartext hint, intercept included'
		).to.have.length(0);
	});
});
