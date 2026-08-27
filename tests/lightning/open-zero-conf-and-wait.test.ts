/**
 * LightningNode.openZeroConfChannelAndWait (issue #572): open a trusted
 * zero-conf channel and wait for NORMAL, resolving with the funding-derived
 * channel id. The id changes from temporary to permanent during a v2 open,
 * so the helper holds the Channel object rather than an id.
 *
 * Funding failures must reject FAST so a caller's retry loop (the Phase 3
 * JIT engine) engages instead of spinning to the timeout: the v2 route
 * surfaces "v2 open not funded" as a CHANNEL_ERROR, the v1 route aborts via
 * channel:aborted after a channelId-less AUTO_FUNDING_FAILED.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IFundingProvider } from '../../src/lightning/node/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { MessageType } from '../../src/lightning/message/types';
import { encodeErrorMessage } from '../../src/lightning/message/error';

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

function makeNodeConfig(
	id: number
): ConstructorParameters<typeof LightningNode>[0] {
	const seed = crypto
		.createHash('sha256')
		.update(`zero-conf-wait-${id}`)
		.digest();
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(`zero-conf-wait-priv-${id}`)
			.digest(),
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		network: Network.REGTEST,
		// Secret behind makeBasepoints' htlcBasepoint (keys[4]): without it
		// per-HTLC signatures use a fallback key and the peer rejects them.
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest()
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
			const der = bitcoin.script.signature.encode(
				Buffer.from(ecc.sign(sighash, priv)),
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [der, pub];
		}
	};
}

interface IPair {
	alice: LightningNode;
	bob: LightningNode;
}

function nodePair(
	aliceProvider?: IFundingProvider,
	opts?: { bobTrustsAlice?: boolean }
): IPair {
	const alice = new LightningNode({
		...makeNodeConfig(1),
		...(aliceProvider ? { fundingProvider: aliceProvider } : {})
	});
	const bob = new LightningNode(makeNodeConfig(2));
	for (const n of [alice, bob]) {
		n.on('error', () => {});
		n.on('node:error', () => {});
	}
	alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
		if (pk === bob.getNodeId()) {
			bob.handlePeerMessage(alice.getNodeId(), t, p);
		}
	});
	bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
		if (pk === alice.getNodeId()) {
			alice.handlePeerMessage(bob.getNodeId(), t, p);
		}
	});
	alice.addTrustedPeer(bob.getNodeId());
	if (opts?.bobTrustsAlice !== false) {
		bob.addTrustedPeer(alice.getNodeId());
	}
	return { alice, bob };
}

/** Route alice's opens to the v2 path: a stub peer session whose remote
 *  init advertises dual funding plus the zero-conf pair. */
function wireDualFundPeer(alice: LightningNode, bobId: string): void {
	const features = LightningNode.defaultFeatures();
	features.setBit(Feature.DUAL_FUND + 1);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(alice as any).peerManager = {
		getPeer: (pubkey: string) =>
			pubkey === bobId
				? { getRemoteInit: (): { features: FeatureFlags } => ({ features }) }
				: undefined,
		destroy: (): void => {}
	};
	// Deterministic funding feerate without a chain fee estimator.
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(alice as any).feeAdvisor = { getCurrentRate: (): number => 4 };
}

function autofundProvider(
	selection:
		| { inputs: ISpliceWalletInput[]; changeScript: Buffer }
		| (() => Promise<{ inputs: ISpliceWalletInput[]; changeScript: Buffer }>)
): IFundingProvider {
	return {
		buildFundingTransaction: async () => {
			throw new Error('v1 funding must not run for a dual-fund peer');
		},
		broadcastTransaction: async () => 'broadcast-txid',
		selectDualFundingInputs:
			typeof selection === 'function'
				? selection
				: async (): Promise<{
						inputs: ISpliceWalletInput[];
						changeScript: Buffer;
				  }> => selection
	} as IFundingProvider;
}

describe('LightningNode.openZeroConfChannelAndWait (issue #572)', function () {
	this.timeout(10_000);
	const pairs: IPair[] = [];

	afterEach(function () {
		for (const { alice, bob } of pairs.splice(0)) {
			alice.destroy();
			bob.destroy();
		}
	});

	it('resolves with the funding-derived id once the v2 open reaches NORMAL', async function () {
		const changeScript = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20)
		}).output!;
		const pair = nodePair(
			autofundProvider({ inputs: [makeWalletInput(200_000)], changeScript })
		);
		pairs.push(pair);
		const { alice, bob } = pair;
		wireDualFundPeer(alice, bob.getNodeId());

		const channelId = await alice.openZeroConfChannelAndWait(
			bob.getNodeId(),
			150_000n
		);

		const raw = alice.getRawChannel(channelId)!;
		expect(raw.getState()).to.equal(ChannelState.NORMAL);
		// The resolved id is the PERMANENT (funding-derived) one.
		expect(raw.getChannelId()!.equals(channelId)).to.equal(true);
		expect(raw.getTemporaryChannelId().equals(channelId)).to.equal(false);
		const bobInfo = bob.listChannels();
		expect(bobInfo).to.have.length(1);
		expect(bobInfo[0].state).to.equal(ChannelState.NORMAL);
	});

	it('rejects fast when the v2 wallet selection fails', async function () {
		const pair = nodePair(
			autofundProvider(async () => {
				throw new Error('wallet empty');
			})
		);
		pairs.push(pair);
		const { alice, bob } = pair;
		wireDualFundPeer(alice, bob.getNodeId());

		let error = '';
		const started = Date.now();
		try {
			await alice.openZeroConfChannelAndWait(bob.getNodeId(), 150_000n);
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.match(/v2 open not funded/);
		// Fast failure, not a burned timeout window.
		expect(Date.now() - started).to.be.lessThan(2_000);
	});

	it('rejects fast when v1 auto-funding fails (channel:aborted scope)', async function () {
		// No stub peer session: the open routes v1, whose auto-funding runs
		// off channel:accepted and reports failure without a channel id.
		const pair = nodePair({
			buildFundingTransaction: async () => {
				throw new Error('Insufficient funds');
			},
			broadcastTransaction: async () => 'unused'
		} as IFundingProvider);
		pairs.push(pair);
		const { alice, bob } = pair;

		let error = '';
		const started = Date.now();
		try {
			await alice.openZeroConfChannelAndWait(bob.getNodeId(), 150_000n);
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.match(/aborted|auto-funding failed/);
		expect(Date.now() - started).to.be.lessThan(2_000);
	});

	it('rejects on timeout when nothing ever completes the open', async function () {
		// A selection that never settles: the open just hangs.
		const pair = nodePair(
			autofundProvider(
				() =>
					new Promise<{
						inputs: ISpliceWalletInput[];
						changeScript: Buffer;
					}>(() => {})
			)
		);
		pairs.push(pair);
		const { alice, bob } = pair;
		wireDualFundPeer(alice, bob.getNodeId());

		let error = '';
		try {
			await alice.openZeroConfChannelAndWait(bob.getNodeId(), 150_000n, 100);
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.match(/not ready within 100ms/);
	});

	it('a foreign AUTO_FUNDING_FAILED does not reject this wait', async function () {
		// AUTO_FUNDING_FAILED carries no channel id: with two concurrent
		// opens, one wallet failure must not reject every unfunded wait.
		// The v1 failure path is scoped through channel:aborted instead.
		const pair = nodePair(
			autofundProvider(
				() =>
					new Promise<{
						inputs: ISpliceWalletInput[];
						changeScript: Buffer;
					}>(() => {})
			)
		);
		pairs.push(pair);
		const { alice, bob } = pair;
		wireDualFundPeer(alice, bob.getNodeId());

		const wait = alice.openZeroConfChannelAndWait(
			bob.getNodeId(),
			150_000n,
			400
		);
		alice.emit('node:error', {
			code: 'AUTO_FUNDING_FAILED',
			message: 'some other open ran out of coins',
			timestamp: Date.now()
		});

		let error = '';
		try {
			await wait;
		} catch (err) {
			error = (err as Error).message;
		}
		// The wait survived the foreign failure and only the timeout ended it.
		expect(error).to.match(/not ready within 400ms/);
	});

	it('throws immediately when the peer rejects the open inside openChannel', async function () {
		// A synchronous transport settles bob's zero-conf refusal (alice is
		// not in HIS trusted set) before any listener could exist: the
		// terminal check fails the call now instead of burning the timeout.
		const pair = nodePair(undefined, { bobTrustsAlice: false });
		pairs.push(pair);
		const { alice, bob } = pair;
		wireDualFundPeer(alice, bob.getNodeId());

		let error = '';
		const started = Date.now();
		try {
			await alice.openZeroConfChannelAndWait(bob.getNodeId(), 150_000n);
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.match(/channel open failed/);
		expect(Date.now() - started).to.be.lessThan(2_000);
	});

	it('a scoped error that leaves the open ERRORED rejects the wait fast', async function () {
		// Not every fatal opening failure says "v2 open not funded": a BOLT 1
		// error from the peer scoped to this open fails the channel with its
		// own message, and the wait must settle on it rather than time out.
		const pair = nodePair(
			autofundProvider(
				() =>
					new Promise<{
						inputs: ISpliceWalletInput[];
						changeScript: Buffer;
					}>(() => {})
			)
		);
		pairs.push(pair);
		const { alice, bob } = pair;
		wireDualFundPeer(alice, bob.getNodeId());

		const wait = alice.openZeroConfChannelAndWait(bob.getNodeId(), 150_000n);
		// The open_channel2 already went to bob; alice's channel is the only
		// temp-resident one. Fail it with a peer error scoped to its id.
		const mgr = alice.getChannelManager();
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const temp = [...(mgr as any).tempChannels.values()][0] as {
			getTemporaryChannelId(): Buffer;
		};
		alice.handlePeerMessage(
			bob.getNodeId(),
			MessageType.ERROR,
			encodeErrorMessage({
				channelId: temp.getTemporaryChannelId(),
				data: Buffer.from('no thanks', 'ascii')
			})
		);

		let error = '';
		const started = Date.now();
		try {
			await wait;
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.match(/channel open failed/);
		expect(Date.now() - started).to.be.lessThan(2_000);
	});

	it('throws synchronously for an untrusted peer', function () {
		const pair = nodePair();
		pairs.push(pair);
		const { alice } = pair;
		const stranger = getPublicKey(crypto.randomBytes(32)).toString('hex');
		let error = '';
		alice.openZeroConfChannelAndWait(stranger, 100_000n).catch((err) => {
			error = (err as Error).message;
		});
		return new Promise<void>((resolve) =>
			setImmediate(() => {
				expect(error).to.match(/not in the trusted set/);
				resolve();
			})
		);
	});
});
