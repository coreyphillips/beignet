/**
 * Issue #588: a header from the configured chain backend must drive the
 * node-level per-block work.
 *
 * A node with a chain backend never calls LightningNode.handleNewBlock: the
 * backend's header callback runs ChainWatcher.handleNewBlock, which advances
 * the ChannelManager and emits 'block'. That listener used to run a handful of
 * retries only, so on every production node the commitment CPFP re-bump and
 * every timeout scan were driven by nothing at all.
 *
 * Both tests deliver the tip the way the backend does, through the captured
 * subscribeToHeaders callback.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import type { ISpliceWalletInput } from '../../src/lightning/channel/channel';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;
const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`live-header-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		keys.push(
			getPublicKey(
				crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from([i]))
					.digest()
			)
		);
	}
	return {
		fundingPubkey: keys[0],
		revocationBasepoint: keys[1],
		paymentBasepoint: keys[2],
		delayedPaymentBasepoint: keys[3],
		htlcBasepoint: keys[4],
		firstPerCommitmentPoint: keys[5]
	};
}

function makeNodeConfig(seedId: number, backend?: IChainBackend): INodeConfig {
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
			.digest(),
		// Pinned so the two timeout thresholds (6 and 12 blocks) are explicit.
		htlcSafetyMargin: 6,
		...(backend ? { chainBackend: backend } : {})
	};
}

/** The production driver: whatever subscribeToHeaders was handed. */
class HeaderCaptureBackend implements IChainBackend {
	broadcasts: string[] = [];
	onHeader: ((height: number) => void) | null = null;
	async subscribeToHeaders(cb: (height: number) => void): Promise<void> {
		this.onHeader = cb;
	}
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

/** A real P2WPKH wallet input so the CPFP child can actually be built. */
function makeWalletInput(valueSats: number, seed: string): ISpliceWalletInput {
	const priv = crypto.createHash('sha256').update(seed).digest();
	const keyPair = ECPair.fromPrivateKey(priv, { network });
	const pubkey = Buffer.from(keyPair.publicKey);
	const script = bitcoin.payments.p2wpkh({ pubkey, network }).output!;
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(script, valueSats);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey, network }).output!;
	return {
		prevTx: Buffer.from(prevTx.toBuffer()),
		prevOutputIndex: 0,
		value: BigInt(valueSats),
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value) => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				scriptCode,
				Number(value),
				SIGHASH_ALL
			);
			const sig64 = Buffer.from(ecc.sign(sighash, priv));
			return [bitcoin.script.signature.encode(sig64, SIGHASH_ALL), pubkey];
		}
	};
}

const tick = (ms = 40): Promise<void> => new Promise((r) => setTimeout(r, ms));

function createNode(seedId: number, backend?: IChainBackend): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, backend));
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

function destScript(node: LightningNode): Buffer {
	return bitcoin.payments.p2wpkh({
		pubkey: Buffer.from(node.getNodeId(), 'hex')
	}).output!;
}

/** Count what each header drives, without changing what it does. */
function countDrives(node: LightningNode): {
	channelManagerBlocks: () => number;
	reCpfp: () => number;
} {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const cm = node.getChannelManager() as any;
	let blocks = 0;
	let recpfp = 0;
	const realBlock = cm.handleNewBlock.bind(cm);
	cm.handleNewBlock = (height: number): unknown => {
		blocks++;
		return realBlock(height);
	};
	const realRecpfp = cm.reCpfpStuckCommitments.bind(cm);
	cm.reCpfpStuckCommitments = (height: number, feeRate: number): unknown => {
		recpfp++;
		return realRecpfp(height, feeRate);
	};
	return {
		channelManagerBlocks: (): number => blocks,
		reCpfp: (): number => recpfp
	};
}

const HEIGHT = 800_000;

describe('Issue #588: backend headers drive the per-block work', function () {
	this.timeout(10_000);

	/**
	 * Alice force-closes with a pending, unconfirmed commitment CPFP package
	 * whose re-bump interval has elapsed and whose last bid the live feerate
	 * beats. Only a re-bump pass can move it.
	 */
	async function stuckPackage(seedBase: number): Promise<{
		alice: LightningNode;
		bob: LightningNode;
		backend: HeaderCaptureBackend;
		commitmentTxid: string;
		destroy: () => void;
	}> {
		const backend = new HeaderCaptureBackend();
		const alice = createNode(seedBase, backend);
		const bob = createNode(seedBase + 1);
		connectNodes(alice, bob);

		const changeScript = bitcoin.payments.p2wpkh({
			pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
			network
		}).output!;
		alice.getChannelManager().setFundingProvider({
			selectFeeBumpInputs: async () => ({
				inputs: [makeWalletInput(200_000, `live-header-wallet-${seedBase}`)],
				changeScript
			})
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any);

		const channelId = openReadyChannel(alice, bob);
		await tick(60);
		expect(backend.onHeader, 'header callback captured').to.not.equal(null);

		const forced = alice.forceCloseChannel(channelId, destScript(alice));
		expect(forced.ok, 'force close broadcast').to.equal(true);
		await tick();

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const cm = alice.getChannelManager() as any;
		const entry = cm._pendingCommitmentCpfp.get(channelId.toString('hex'));
		expect(entry, 'CPFP armed on close').to.not.equal(undefined);
		// Stalled: broadcast a full re-bump interval ago, at a feerate the live
		// force-close rate now beats.
		entry.broadcastHeight = HEIGHT - 6;
		entry.lastFeeRate = 1;

		return {
			alice,
			bob,
			backend,
			commitmentTxid: forced.commitmentTxid!,
			destroy: (): void => {
				alice.destroy();
				bob.destroy();
			}
		};
	}

	it('a backend header re-bumps a stuck commitment package', async () => {
		const fx = await stuckPackage(5881);
		const counts = countDrives(fx.alice);
		fx.backend.broadcasts.length = 0;

		fx.backend.onHeader!(HEIGHT);
		await tick(80);

		expect(counts.reCpfp(), 're-bump pass ran once').to.equal(1);
		expect(
			counts.channelManagerBlocks(),
			'ChannelManager advanced once, not twice'
		).to.equal(1);

		const parent = fx.backend.broadcasts.find(
			(hex) => bitcoin.Transaction.fromHex(hex).getId() === fx.commitmentTxid
		);
		expect(parent, 'commitment re-broadcast').to.not.equal(undefined);
		const parentHash = Buffer.from(fx.commitmentTxid, 'hex').reverse();
		const child = fx.backend.broadcasts.find((hex) => {
			const tx = bitcoin.Transaction.fromHex(hex);
			return (
				tx.getId() !== fx.commitmentTxid &&
				tx.ins.some((input) => Buffer.from(input.hash).equals(parentHash))
			);
		});
		expect(child, 'CPFP child spending the commitment').to.not.equal(undefined);

		fx.destroy();
	});

	it('the embedder-driven block still runs the same work exactly once', async () => {
		// The public entry point owns the ChannelManager advance itself, so the
		// shared drive point must not add a second one.
		const fx = await stuckPackage(5883);
		const counts = countDrives(fx.alice);
		fx.backend.broadcasts.length = 0;

		fx.alice.handleNewBlock(HEIGHT);
		await tick(80);

		expect(counts.reCpfp()).to.equal(1);
		expect(counts.channelManagerBlocks()).to.equal(1);
		expect(
			fx.backend.broadcasts.some(
				(hex) => bitcoin.Transaction.fromHex(hex).getId() === fx.commitmentTxid
			),
			'commitment re-broadcast'
		).to.equal(true);

		fx.destroy();
	});

	it('a backend header runs the forward timeout scan', async () => {
		// Alice forwards Bob -> Carol. The inbound leg expires at HEIGHT+5, well
		// inside the doubled safety margin, and its outbound leg is still live:
		// the forward scan must force-close the inbound rather than refund it.
		const backend = new HeaderCaptureBackend();
		const alice = createNode(5885, backend);
		const bob = createNode(5886);
		const carol = createNode(5887);
		connectNodes(alice, bob);
		connectNodes(alice, carol);
		const inChannelId = openReadyChannel(alice, bob);
		const outChannelId = openReadyChannel(alice, carol);
		await tick(60);
		expect(backend.onHeader, 'header callback captured').to.not.equal(null);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = alice as any;
		a.currentBlockHeight = HEIGHT;

		const paymentHash = crypto.randomBytes(32);
		const inHtlcs: Map<string, IHtlcEntry> = a.channelManager
			.getChannel(inChannelId)
			.getFullState().htlcs;
		inHtlcs.set('received-7', {
			id: 7n,
			amountMsat: 50_000n,
			paymentHash,
			cltvExpiry: HEIGHT + 5,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.COMMITTED
		});
		const outHtlcs: Map<string, IHtlcEntry> = a.channelManager
			.getChannel(outChannelId)
			.getFullState().htlcs;
		outHtlcs.set('offered-7', {
			id: 7n,
			amountMsat: 49_000n,
			paymentHash,
			cltvExpiry: HEIGHT + 500,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.OFFERED,
			state: HtlcState.COMMITTED
		});
		a.forwardedHtlcs.set(`${outChannelId.toString('hex')}:offered-7`, {
			inChannelId,
			inHtlcId: 7n
		});

		const forceClosed: Buffer[] = [];
		alice.on('node:error', (err: { code: string; channelId?: Buffer }) => {
			if (err.code === 'FORWARD_TIMEOUT_FORCE_CLOSE' && err.channelId) {
				forceClosed.push(err.channelId);
			}
		});

		backend.onHeader!(HEIGHT + 1);
		await tick(80);

		expect(
			forceClosed.filter((id) => id.equals(inChannelId)).length,
			'inbound force-closed exactly once'
		).to.equal(1);
		expect(alice.getCurrentBlockHeight()).to.equal(HEIGHT + 1);

		alice.destroy();
		bob.destroy();
		carol.destroy();
	});
});
