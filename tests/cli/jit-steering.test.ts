/**
 * JIT receive steered through the ranked primaries (issue #1922, step 2a).
 *
 * Three nodes over a loopback transport: alice and carol run the LSP engine,
 * bob is the wallet, wrapped in BeignetNode so the steering above the
 * library is what runs. Bob's stub peer manager is the whole network: which
 * LSPs are connected, which dials succeed, and where a custom message goes.
 *
 * What the wallet owes itself here: a receive that names no LSP lands on the
 * primary the policy selects, a primary that is down or declines is passed
 * over without an invoice minted at it, a named LSP never falls back, and
 * when none takes it nothing is minted anywhere.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError, isRetryableError } from '../../src/cli/errors';
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
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import {
	PeerError,
	PeerErrorCode
} from '../../src/lightning/transport/peer-manager';

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
	const seed = crypto.createHash('sha256').update(`steer-${label}`).digest();
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(`steer-priv-${label}`)
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

interface IWorld {
	alice: LightningNode;
	carol: LightningNode;
	bob: LightningNode;
	/** Bob as the library's node class, the steering layer over `bob`. */
	wallet: BeignetNode;
	/** LSPs bob is connected to; a dial that succeeds adds to it. */
	connected: Set<string>;
	/** Pubkeys whose dial fails. */
	down: Set<string>;
	dials: string[];
	destroy: () => void;
}

function world(
	opts: {
		alice?: Record<string, unknown>;
		carol?: Record<string, unknown>;
		wallet?: Record<string, unknown>;
	} = {}
): IWorld {
	const alice = new LightningNode({
		...nodeConfig('alice'),
		jitReceive: { enabled: true, ...opts.alice }
	});
	const carol = new LightningNode({
		...nodeConfig('carol'),
		jitReceive: { enabled: true, ...opts.carol }
	});
	const bob = new LightningNode({ ...nodeConfig('bob'), ...opts.wallet });
	for (const n of [alice, carol, bob]) n.on('node:error', () => undefined);
	const lsps = new Map([
		[alice.getNodeId(), alice],
		[carol.getNodeId(), carol]
	]);
	const connected = new Set<string>(lsps.keys());
	const down = new Set<string>();
	const dials: string[] = [];
	const features = LightningNode.defaultFeatures();
	const init = {
		getRemoteInit: (): { features: FeatureFlags } => ({ features })
	};
	const toLsp = (pk: string, t: number, p: Buffer): void => {
		const lsp = lsps.get(pk);
		if (!lsp || !connected.has(pk)) {
			throw new PeerError(
				PeerErrorCode.NOT_CONNECTED,
				`Not connected to peer ${pk}`
			);
		}
		lsp.handlePeerMessage(bob.getNodeId(), t, p);
	};
	bob.on('message:outbound', (pk, t, p) => {
		if (connected.has(pk)) toLsp(pk, t, p);
	});
	(bob as any).peerManager = {
		getPeer: (pk: string) => (connected.has(pk) ? init : undefined),
		sendToPeer: toLsp,
		listPeers: () =>
			[...connected].map((pubkey) => ({
				pubkey,
				host: 'lsp.example',
				port: 9735,
				state: 'ready'
			})),
		connectPeer: async (pk: string): Promise<void> => {
			dials.push(pk);
			if (down.has(pk) || !lsps.has(pk))
				throw new Error('connect ECONNREFUSED');
			connected.add(pk);
		},
		cancellationToken: (): number => 0,
		destroy: (): void => undefined
	};
	for (const lsp of lsps.values()) {
		const toBob = (pk: string, t: number, p: Buffer): void => {
			if (pk === bob.getNodeId()) bob.handlePeerMessage(lsp.getNodeId(), t, p);
		};
		lsp.on('message:outbound', toBob);
		(lsp as any).peerManager = {
			getPeer: (pk: string) => (pk === bob.getNodeId() ? init : undefined),
			sendToPeer: toBob,
			destroy: (): void => undefined
		};
	}
	const data = new Map<string, string>();
	const wallet = Object.assign(Object.create(BeignetNode.prototype), {
		node: bob,
		storage: {
			saveWalletData: (k: string, v: string): void => void data.set(k, v),
			loadWalletData: (k: string): string | null => data.get(k) ?? null
		},
		_connectTimeoutMs: 1_000,
		logLevel: 'silent'
	}) as BeignetNode;
	return {
		alice,
		carol,
		bob,
		wallet,
		connected,
		down,
		dials,
		destroy: (): void => {
			alice.destroy();
			carol.destroy();
			bob.destroy();
		}
	};
}

/** A NORMAL channel with `peerHex` holding `localSats` on our side. */
function injectChannel(
	node: LightningNode,
	peerHex: string,
	localSats: number
): void {
	const channelId = crypto.randomBytes(32);
	const remoteSats = 50_000n;
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: BigInt(localSats) + remoteSats,
		pushMsat: 0n,
		localConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: makeBasepoints(crypto.randomBytes(32)),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = channelId;
	state.localBalanceMsat = BigInt(localSats) * 1000n;
	state.remoteBalanceMsat = remoteSats * 1000n;
	state.remoteScidAlias = encodeShortChannelId({
		block: 800000,
		txIndex: 1 + Math.floor(Math.random() * 1000),
		outputIndex: 0
	});
	const cm = (node as any).channelManager;
	cm.channels.set(channelId.toString('hex'), new Channel(state));
	cm.channelPeers.set(channelId.toString('hex'), peerHex);
}

const intentsAt = (lsp: LightningNode): number =>
	lsp.getJitReceiveManager()!.listIntents().length;

async function rejection(fn: () => Promise<unknown>): Promise<BeignetError> {
	try {
		await fn();
	} catch (e) {
		expect(e).to.be.instanceOf(BeignetError);
		return e as BeignetError;
	}
	throw new Error('expected a rejection');
}

describe('JIT receive steered through the primaries (issue #1922)', function () {
	this.timeout(15_000);
	const open: IWorld[] = [];
	const STRANGER = '02' + '77'.repeat(32);

	afterEach(function () {
		for (const w of open.splice(0)) w.destroy();
	});

	it('needs an LSP when no primary is configured', async () => {
		const w = world();
		open.push(w);
		const err = await rejection(() =>
			w.wallet.createJitInvoice({ amountSats: 5_000 })
		);
		expect(err.code).to.equal('INVALID_PARAMS');
		expect(err.message).to.match(/lspPubkey is required when no primaries/);
		const quote = await rejection(() =>
			w.wallet.getJitQuote({ amountSats: 5_000 })
		);
		expect(quote.code).to.equal('INVALID_PARAMS');
	});

	it('registers the intent with the selected primary and names it', async () => {
		const w = world({ alice: { flatFeeSat: 3n, feePpm: 500 } });
		open.push(w);
		w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
		w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
		const invoice = await w.wallet.createJitInvoice({
			amountSats: 5_000,
			description: 'steered'
		});
		expect(invoice.lspPubkey).to.equal(w.alice.getNodeId());
		expect(invoice.flatFeeSat).to.equal(3);
		expect(invoice.skipped).to.equal(undefined);
		expect(
			decode(invoice.bolt11).routingHints![0][0].pubkey.toString('hex')
		).to.equal(w.alice.getNodeId());
		expect(intentsAt(w.alice)).to.equal(1);
		expect(intentsAt(w.carol)).to.equal(0);
		expect(w.dials, 'a connected primary is not dialed').to.deep.equal([]);
	});

	it('passes over a primary whose dial fails and takes the next', async () => {
		const w = world();
		open.push(w);
		w.wallet.addPrimary({ pubkey: STRANGER, host: '10.0.0.9', port: 9735 });
		w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
		const invoice = await w.wallet.createJitInvoice({ amountSats: 5_000 });
		expect(invoice.lspPubkey).to.equal(w.alice.getNodeId());
		expect(w.dials).to.deep.equal([STRANGER]);
		expect(invoice.skipped).to.have.length(1);
		expect(invoice.skipped![0]).to.include({
			pubkey: STRANGER,
			rank: 1,
			stage: 'connect',
			code: 'CONNECT_FAILED'
		});
		expect(intentsAt(w.alice)).to.equal(1);
	});

	it('dials a primary that is not connected before asking it', async () => {
		const w = world();
		open.push(w);
		w.connected.delete(w.alice.getNodeId());
		w.wallet.addPrimary({
			pubkey: w.alice.getNodeId(),
			host: 'lsp.example',
			port: 9735
		});
		w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
		const invoice = await w.wallet.createJitInvoice({ amountSats: 5_000 });
		expect(w.dials).to.deep.equal([w.alice.getNodeId()]);
		expect(invoice.lspPubkey).to.equal(w.alice.getNodeId());
		expect(invoice.skipped).to.equal(undefined);
		expect(intentsAt(w.alice)).to.equal(1);
	});

	it('moves past a primary that declines, minting nothing at it', async () => {
		const w = world({ alice: { maxClientFundingSats: 1_000n } });
		open.push(w);
		w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
		w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
		const invoice = await w.wallet.createJitInvoice({ amountSats: 500_000 });
		expect(invoice.lspPubkey).to.equal(w.carol.getNodeId());
		expect(invoice.skipped![0]).to.include({
			pubkey: w.alice.getNodeId(),
			stage: 'attempt',
			code: 'JIT_REFUSED'
		});
		expect(invoice.skipped![0].message).to.match(/declined/);
		expect(intentsAt(w.alice)).to.equal(0);
		expect(intentsAt(w.carol)).to.equal(1);
		// One invoice, carrying carol's intercept hint and nothing of alice.
		expect([...(w.bob as any).invoices.values()]).to.have.length(1);
		expect(
			decode(invoice.bolt11).routingHints![0][0].pubkey.toString('hex')
		).to.equal(w.carol.getNodeId());
	});

	it('moves to the next primary, channel or not, once the first is at the threshold', async () => {
		const w = world();
		open.push(w);
		injectChannel(w.bob, w.alice.getNodeId(), 1_000_000);
		w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
		w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
		w.wallet.setPrimariesFillThreshold(1_000_000);
		expect(w.wallet.listPrimaries().receiveTarget).to.equal(
			w.carol.getNodeId()
		);
		const invoice = await w.wallet.createJitInvoice({ amountSats: 5_000 });
		expect(invoice.lspPubkey).to.equal(w.carol.getNodeId());
		expect(invoice.skipped).to.equal(undefined);
		expect(intentsAt(w.carol)).to.equal(1);
		expect(intentsAt(w.alice)).to.equal(0);
	});

	it('levels full primaries: the lowest balance takes the receive', async () => {
		const w = world();
		open.push(w);
		injectChannel(w.bob, w.alice.getNodeId(), 2_000_000);
		injectChannel(w.bob, w.carol.getNodeId(), 1_000_000);
		w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
		w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
		w.wallet.setPrimariesFillThreshold(1_000_000);
		const invoice = await w.wallet.createJitInvoice({ amountSats: 5_000 });
		expect(invoice.lspPubkey).to.equal(w.carol.getNodeId());
		expect(intentsAt(w.carol)).to.equal(1);
	});

	it('fails typed when no primary takes it, and mints nothing anywhere', async () => {
		const w = world({
			alice: { maxClientFundingSats: 1_000n },
			carol: { maxClientFundingSats: 1_000n }
		});
		open.push(w);
		w.wallet.addPrimary({ pubkey: STRANGER, host: '10.0.0.9', port: 9735 });
		w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
		w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
		const err = await rejection(() =>
			w.wallet.createJitInvoice({ amountSats: 500_000 })
		);
		expect(err.code).to.equal('NO_PRIMARY_AVAILABLE');
		expect(err.message).to.include('(3 of 3 tried)');
		expect(err.message).to.include(
			`${STRANGER.slice(0, 16)} (rank 1): CONNECT_FAILED`
		);
		expect(err.message).to.include(
			`${w.alice.getNodeId().slice(0, 16)} (rank 2): JIT_REFUSED`
		);
		expect(err.message).to.include(
			`${w.carol.getNodeId().slice(0, 16)} (rank 3): JIT_REFUSED`
		);
		expect(isRetryableError(err)).to.equal(true);
		expect([...(w.bob as any).invoices.values()]).to.have.length(0);
		expect(intentsAt(w.alice) + intentsAt(w.carol)).to.equal(0);
	});

	it('a named LSP never falls back', async () => {
		const w = world({ alice: { maxClientFundingSats: 1_000n } });
		open.push(w);
		w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
		w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
		const err = await rejection(() =>
			w.wallet.createJitInvoice({
				lspPubkey: w.alice.getNodeId(),
				amountSats: 500_000
			})
		);
		expect(err.code).to.equal('JIT_REFUSED');
		expect(intentsAt(w.carol)).to.equal(0);
		// And a named LSP that is not there is PEER_NOT_CONNECTED, as before.
		const away = await rejection(() =>
			w.wallet.createJitInvoice({ lspPubkey: STRANGER, amountSats: 5_000 })
		);
		expect(away.code).to.equal('PEER_NOT_CONNECTED');
		expect(w.dials).to.deep.equal([]);
	});

	it('rethrows a bad parameter at once rather than walking the list', async () => {
		const w = world();
		open.push(w);
		w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
		const err = await rejection(() =>
			w.wallet.createJitInvoice({ amountSats: 1.5 })
		);
		expect(err.code).to.equal('INVALID_PARAMS');
		expect(err.message).to.match(/amountSats/);
		const budget = await rejection(() =>
			w.wallet.createJitInvoice({ amountSats: 5_000, timeoutMs: 0 })
		);
		expect(budget.message).to.match(/timeoutMs/);
		expect(intentsAt(w.alice)).to.equal(0);
	});

	it('a primary with a live channel takes it while new channels are fenced', async () => {
		const w = world();
		open.push(w);
		(w.bob as any).channelManager.config.newChannelsRefused = (): string =>
			'no chain tip yet';
		injectChannel(w.bob, w.carol.getNodeId(), 10_000);
		w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
		w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
		const invoice = await w.wallet.createJitInvoice({ amountSats: 5_000 });
		expect(invoice.lspPubkey).to.equal(w.carol.getNodeId());
		expect(invoice.skipped![0]).to.include({
			pubkey: w.alice.getNodeId(),
			code: 'NEW_CHANNELS_REFUSED'
		});
		expect(intentsAt(w.alice)).to.equal(0);
		expect(intentsAt(w.carol)).to.equal(1);
	});

	describe('quote', () => {
		it('prices the primary a create would land on, passing a decline by', async () => {
			const w = world({
				alice: { maxClientFundingSats: 1_000n },
				carol: { flatFeeSat: 7n, feePpm: 100 }
			});
			open.push(w);
			w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
			w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
			const quote = await w.wallet.getJitQuote({ amountSats: 500_000 });
			expect(quote.accepted).to.equal(true);
			expect(quote.lspPubkey).to.equal(w.carol.getNodeId());
			expect(quote.flatFeeSat).to.equal(7);
			expect(quote.skipped![0]).to.include({
				pubkey: w.alice.getNodeId(),
				code: 'JIT_REFUSED'
			});
			// Nothing registered by a quote, at either LSP.
			expect(intentsAt(w.alice) + intentsAt(w.carol)).to.equal(0);
			// And the create that names what the quote named lands there.
			const invoice = await w.wallet.createJitInvoice({
				lspPubkey: quote.lspPubkey,
				amountSats: 500_000
			});
			expect(invoice.lspPubkey).to.equal(w.carol.getNodeId());
		});

		it('passes over a primary whose price is above the ceilings', async () => {
			const w = world({
				alice: { flatFeeSat: 5_000n, feePpm: 0 },
				carol: { flatFeeSat: 10n, feePpm: 0 },
				wallet: { jitReceiveClient: { maxFlatFeeSat: 100n } }
			});
			open.push(w);
			w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
			w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
			const quote = await w.wallet.getJitQuote({ amountSats: 5_000 });
			expect(quote.lspPubkey).to.equal(w.carol.getNodeId());
			expect(quote.withinCeilings).to.equal(true);
			expect(quote.skipped![0].message).to.match(/above the accepted ceiling/);
		});

		it('answers NO_PRIMARY_AVAILABLE when none would serve it', async () => {
			const w = world({
				alice: { maxClientFundingSats: 1_000n },
				carol: { maxClientFundingSats: 1_000n }
			});
			open.push(w);
			w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
			w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
			const err = await rejection(() =>
				w.wallet.getJitQuote({ amountSats: 500_000 })
			);
			expect(err.code).to.equal('NO_PRIMARY_AVAILABLE');
			expect(err.message).to.include('(2 of 2 tried)');
		});

		it('a named LSP is quoted as before: its decline is the answer', async () => {
			const w = world({ alice: { maxClientFundingSats: 1_000n } });
			open.push(w);
			w.wallet.addPrimary({ pubkey: w.alice.getNodeId() });
			w.wallet.addPrimary({ pubkey: w.carol.getNodeId() });
			const quote = await w.wallet.getJitQuote({
				lspPubkey: w.alice.getNodeId(),
				amountSats: 500_000
			});
			expect(quote.accepted).to.equal(false);
			expect(quote.lspPubkey).to.equal(w.alice.getNodeId());
			expect(quote.skipped).to.equal(undefined);
		});
	});
});
