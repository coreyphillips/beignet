/**
 * Issue #578: a force-close commitment that CONFIRMS and is then demoted by a
 * reorg must keep its CPFP re-bump tracking. The tracking is memory-only, so a
 * restart during the confirmed window leaves nothing to resume; the funding
 * watch's demotion report has to re-arm it, or the floor-feerate commitment
 * rides unbumped past cltv_expiry and the peer's HTLC-timeout takes an HTLC we
 * hold the preimage for.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import type { ISpliceWalletInput } from '../../src/lightning/channel/channel';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;
const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`cpfp-reorg-seed-${id}`))
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

class RecordingBackend implements IChainBackend {
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

const tick = (ms = 25): Promise<void> => new Promise((r) => setTimeout(r, ms));

interface IFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	backend: RecordingBackend;
	destroy: () => void;
}

async function setup(seedBase: number): Promise<IFixture> {
	const backend = new RecordingBackend();
	const configA = makeNodeConfig(seedBase);
	configA.chainBackend = backend;
	const alice = new LightningNode(configA);
	const bob = new LightningNode(makeNodeConfig(seedBase + 1));
	for (const n of [alice, bob]) {
		n.on('error', () => {});
		n.on('node:error', () => {});
	}
	alice.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === bob.getNodeId())
				bob.handlePeerMessage(alice.getNodeId(), type, payload);
		}
	);
	bob.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === alice.getNodeId())
				alice.handlePeerMessage(bob.getNodeId(), type, payload);
		}
	);

	// Wallet inputs for the anchor CPFP child; without a funding provider the
	// manager never arms commitment CPFP at all.
	const changeScript = bitcoin.payments.p2wpkh({
		pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
		network
	}).output!;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	alice.getChannelManager().setFundingProvider({
		selectFeeBumpInputs: async () => ({
			inputs: [makeWalletInput(200_000, `cpfp-reorg-wallet-${seedBase}`)],
			changeScript
		})
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any);

	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	await tick(60);

	return {
		alice,
		bob,
		channelId,
		backend,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
}

function destScript(node: LightningNode): Buffer {
	return bitcoin.payments.p2wpkh({
		pubkey: Buffer.from(node.getNodeId(), 'hex')
	}).output!;
}

describe('Issue #578: commitment CPFP survives a confirmation and a reorg', function () {
	this.timeout(10_000);

	/** Force-close, then report the commitment confirmed at `height`. */
	async function closeAndConfirm(
		fx: IFixture,
		height: number
	): Promise<{
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		cm: any;
		idHex: string;
		closeTx: bitcoin.Transaction;
	}> {
		const forced = fx.alice.forceCloseChannel(
			fx.channelId,
			destScript(fx.alice)
		);
		expect(forced.ok, 'force close broadcast').to.equal(true);
		await tick();
		const closeTx = bitcoin.Transaction.fromHex(
			fx.backend.broadcasts.find(
				(hex) =>
					bitcoin.Transaction.fromHex(hex).getId() === forced.commitmentTxid
			)!
		);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const cm = fx.alice.getChannelManager() as any;
		const idHex = fx.channelId.toString('hex');
		expect(
			cm._pendingCommitmentCpfp.has(idHex),
			'CPFP armed on close'
		).to.equal(true);
		cm.handleFundingSpent(fx.channelId, closeTx, height, destScript(fx.alice));
		expect(cm.getMonitor(fx.channelId).isCommitmentConfirmed()).to.equal(true);
		return { cm, idHex, closeTx };
	}

	it('parks the CPFP entry through confirmation instead of deleting it', async () => {
		const fx = await setup(5781);
		const { cm, idHex } = await closeAndConfirm(fx, 100);

		fx.alice.handleNewBlock(101);
		await tick();

		expect(cm._pendingCommitmentCpfp.has(idHex), 'entry retained').to.equal(
			true
		);
		expect(cm._pendingCommitmentCpfp.get(idHex).sawConfirmation).to.equal(true);
		fx.destroy();
	});

	it('re-arms a lost CPFP entry when the re-report demotes our commitment', async () => {
		const fx = await setup(5782);
		const { cm, idHex, closeTx } = await closeAndConfirm(fx, 100);
		// The restart shape: _pendingCommitmentCpfp is memory-only, so a process
		// that dies inside the confirmed window comes back with nothing tracked.
		cm._pendingCommitmentCpfp.delete(idHex);

		const rebroadcast: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => rebroadcast.push(tx));
		// The reorg: the funding watch re-reports the same spend at height 0.
		cm.handleFundingSpent(fx.channelId, closeTx, 0, destScript(fx.alice));
		await tick();

		expect(cm.getMonitor(fx.channelId).isCommitmentConfirmed()).to.equal(false);
		expect(cm._pendingCommitmentCpfp.has(idHex), 'CPFP re-armed').to.equal(
			true
		);
		expect(
			rebroadcast.some(
				(tx) => bitcoin.Transaction.fromBuffer(tx).getId() === closeTx.getId()
			),
			'commitment re-broadcast'
		).to.equal(true);
		fx.destroy();
	});

	it('re-arms when the funding history reports the confirmed spend absent', async () => {
		const fx = await setup(5783);
		const { cm, idHex, closeTx } = await closeAndConfirm(fx, 100);
		cm._pendingCommitmentCpfp.delete(idHex);

		const rebroadcast: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => rebroadcast.push(tx));
		expect(cm.handleFundingSpendAbsent(fx.channelId)).to.equal(true);
		await tick();

		expect(cm.getMonitor(fx.channelId).isCommitmentConfirmed()).to.equal(false);
		expect(cm._pendingCommitmentCpfp.has(idHex), 'CPFP re-armed').to.equal(
			true
		);
		expect(
			rebroadcast.some(
				(tx) => bitcoin.Transaction.fromBuffer(tx).getId() === closeTx.getId()
			),
			'commitment re-broadcast'
		).to.equal(true);
		fx.destroy();
	});

	it('does not re-broadcast on an ordinary unconfirmed re-report', async () => {
		// The commitment was never confirmed, so nothing was demoted. The watch
		// re-reports the mempool sighting every sweep; re-broadcasting there would
		// put a commitment on the wire every block.
		const fx = await setup(5784);
		const forced = fx.alice.forceCloseChannel(
			fx.channelId,
			destScript(fx.alice)
		);
		await tick();
		const closeTx = bitcoin.Transaction.fromHex(
			fx.backend.broadcasts.find(
				(hex) =>
					bitcoin.Transaction.fromHex(hex).getId() === forced.commitmentTxid
			)!
		);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const cm = fx.alice.getChannelManager() as any;
		cm.handleFundingSpent(fx.channelId, closeTx, 0, destScript(fx.alice));

		const rebroadcast: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => rebroadcast.push(tx));
		cm.handleFundingSpent(fx.channelId, closeTx, 0, destScript(fx.alice));
		await tick();

		expect(rebroadcast.length).to.equal(0);
		fx.destroy();
	});
});
