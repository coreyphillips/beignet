/**
 * A force close prices its package by whether anything on the commitment has
 * a deadline. An HTLC must be claimed before its expiry, so a commitment with
 * one bids the deadline rate (the live rate times 1.5, never below 10
 * sat/vB). A commitment with no HTLC has nothing that must confirm by a
 * deadline: its anchor child, its re-bids and the to_local sweep the monitor
 * builds at once all bid the live rate itself.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { OutputType } from '../../src/lightning/chain/types';
import type { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import {
	buildGraph,
	connectNodes,
	createNode,
	openReadyChannel
} from './helpers/loopback-nodes';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;
const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;
const TAG = 'force-close-no-deadline-fee';
const FUNDING_SATS = 1_000_000;
const WALLET_INPUT_SATS = 200_000;

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

/** A real P2WPKH wallet input, so the anchor child is actually built. */
function makeWalletInput(seed: string): ISpliceWalletInput {
	const priv = crypto.createHash('sha256').update(seed).digest();
	const keyPair = ECPair.fromPrivateKey(priv, { network });
	const pubkey = Buffer.from(keyPair.publicKey);
	const script = bitcoin.payments.p2wpkh({ pubkey, network }).output!;
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(script, WALLET_INPUT_SATS);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey, network }).output!;
	return {
		prevTx: Buffer.from(prevTx.toBuffer()),
		prevOutputIndex: 0,
		value: BigInt(WALLET_INPUT_SATS),
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value): Buffer[] => {
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

/** A fee estimate the node's fee advisor takes as its newest sample. */
function sampleFee(node: LightningNode, satPerVbyte: number): void {
	(
		node as unknown as {
			feeAdvisor: { recordSample(rate: number): void };
		}
	).feeAdvisor.recordSample(satPerVbyte);
}

interface IFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	backend: RecordingBackend;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	cm: any;
	idHex: string;
	destroy: () => void;
}

/** Alice and Bob with an anchor channel; Alice can fund anchor children. */
function setup(seedBase: number): IFixture {
	const backend = new RecordingBackend();
	const alice = createNode(TAG, seedBase, undefined, { chainBackend: backend });
	const bob = createNode(TAG, seedBase + 1);
	for (const n of [alice, bob]) n.on('node:error', () => {});
	connectNodes(alice, bob);
	const changeScript = bitcoin.payments.p2wpkh({
		pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
		network
	}).output!;
	alice.getChannelManager().setFundingProvider({
		selectFeeBumpInputs: async () => ({
			inputs: [makeWalletInput(`${TAG}-wallet-${seedBase}-${Math.random()}`)],
			changeScript
		})
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any);
	const channelId = openReadyChannel(alice, bob, BigInt(FUNDING_SATS));
	buildGraph(alice, bob, [channelId]);
	buildGraph(bob, alice, [channelId]);
	return {
		alice,
		bob,
		channelId,
		backend,
		cm: alice.getChannelManager(),
		idHex: channelId.toString('hex'),
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

const inputTxid = (input: bitcoin.TxInput): string =>
	Buffer.from(input.hash).reverse().toString('hex');

const sumOuts = (tx: bitcoin.Transaction): number =>
	tx.outs.reduce((sum, out) => sum + Number(out.value), 0);

function broadcastTx(fx: IFixture, txid: string): bitcoin.Transaction {
	const hex = fx.backend.broadcasts.find(
		(candidate) => bitcoin.Transaction.fromHex(candidate).getId() === txid
	);
	if (!hex) throw new Error(`${txid} was not broadcast`);
	return bitcoin.Transaction.fromHex(hex);
}

/** Every anchor child of the commitment that was broadcast, in order. */
function childrenOf(
	fx: IFixture,
	commitment: bitcoin.Transaction
): bitcoin.Transaction[] {
	const txid = commitment.getId();
	return fx.backend.broadcasts
		.map((hex) => bitcoin.Transaction.fromHex(hex))
		.filter((tx) => tx.ins.some((input) => inputTxid(input) === txid));
}

function feesOf(
	commitment: bitcoin.Transaction,
	child: bitcoin.Transaction
): { parentFee: number; childFee: number } {
	const childIn = child.ins.reduce((sum, input) => {
		if (inputTxid(input) === commitment.getId()) {
			return sum + Number(commitment.outs[input.index].value);
		}
		return sum + WALLET_INPUT_SATS;
	}, 0);
	return {
		parentFee: FUNDING_SATS - sumOuts(commitment),
		childFee: childIn - sumOuts(child)
	};
}

/** The fee rate the commitment and one child pay together. */
function packageRate(
	commitment: bitcoin.Transaction,
	child: bitcoin.Transaction
): number {
	const { parentFee, childFee } = feesOf(commitment, child);
	return (
		(parentFee + childFee) / (commitment.virtualSize() + child.virtualSize())
	);
}

/**
 * The child was priced for `rate`: it pays what lifts the package to that
 * rate, and at least its own size at it. The child is sized with dummy
 * witnesses before it is signed, so it may pay for a few vbytes more.
 */
function expectChildBid(
	commitment: bitcoin.Transaction,
	child: bitcoin.Transaction,
	rate: number
): void {
	const { parentFee, childFee } = feesOf(commitment, child);
	const parentVbytes = commitment.virtualSize();
	const childVbytes = child.virtualSize();
	const want = Math.max(
		Math.ceil(rate * (parentVbytes + childVbytes)) - parentFee,
		Math.ceil(rate * childVbytes)
	);
	expect(childFee, `the child's fee at ${rate} sat/vB`).to.be.within(
		want,
		want + rate * 4
	);
}

async function forceClose(fx: IFixture): Promise<bitcoin.Transaction> {
	const forced = fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice));
	expect(forced.ok, 'force close').to.equal(true);
	await tick();
	return broadcastTx(fx, forced.commitmentTxid!);
}

/** A hold invoice of Bob's paid by Alice: the HTLC stays on the commitment. */
async function parkHtlc(fx: IFixture): Promise<void> {
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	const invoice = fx.bob.createInvoice({
		amountMsat: 50_000_000n,
		description: 'held',
		hold: true,
		paymentHash
	});
	void fx.alice.sendPayment(invoice.bolt11);
	await tick(150);
	expect(
		fx.cm.getChannel(fx.channelId).getFullState().htlcs.size,
		'the HTLC is on the channel'
	).to.be.greaterThan(0);
}

describe('A force close bids by whether anything on the commitment has a deadline', function () {
	this.timeout(20_000);

	it('with no HTLC on the commitment, the anchor child bids the live rate, not the floor of 10', async () => {
		const fx = setup(10);
		try {
			sampleFee(fx.alice, 1);
			const commitment = await forceClose(fx);

			const entry = fx.cm._pendingCommitmentCpfp.get(fx.idHex);
			expect(entry.noDeadline).to.equal(true);
			expect(entry.action.feeratePerVbyte).to.equal(1);
			expect(entry.lastFeeRate).to.equal(1);

			const children = childrenOf(fx, commitment);
			expect(children.length).to.equal(1);
			expectChildBid(commitment, children[0], 1);
			// The commitment pays its own fee at the rate agreed at the open,
			// so the package is at that rate or 1, and far below the floor.
			expect(packageRate(commitment, children[0])).to.be.below(3);
		} finally {
			fx.destroy();
		}
	});

	it('with no HTLC on the commitment, the to_local sweep is built at the live rate', async () => {
		const fx = setup(20);
		try {
			sampleFee(fx.alice, 1);
			const commitment = await forceClose(fx);
			const monitor = fx.cm.getMonitor(fx.channelId);
			expect(monitor._feeRatePerVbyte).to.equal(1);

			// The commitment confirms: the monitor resolves its outputs and
			// holds the to_local sweep for its delay, priced now.
			fx.cm.handleFundingSpent(
				fx.channelId,
				commitment,
				101,
				destScript(fx.alice)
			);
			const toLocal = monitor
				.getTrackedOutputs()
				.find(
					(output: { outputType: OutputType }) =>
						output.outputType === OutputType.TO_LOCAL
				);
			expect(toLocal, 'a to_local output').to.not.equal(undefined);
			expect(toLocal.originalFeeRate).to.equal(1);
			// The sweep pays 1 sat/vB on its signed size, where the floor
			// priced it at 10. It is sized with the longest signature, so it
			// may be a vbyte over.
			const sweep = bitcoin.Transaction.fromHex(toLocal.sweepTxHex);
			const swept = Number(commitment.outs[toLocal.outputIndex].value);
			expect(sweep.ins[0].witness.length, 'the sweep is signed').to.equal(3);
			expect(swept - sumOuts(sweep))
				.to.be.at.least(sweep.virtualSize())
				.and.at.most(sweep.virtualSize() + 1);
		} finally {
			fx.destroy();
		}
	});

	it('with an HTLC on the commitment, the package and the monitor keep the deadline rate', async () => {
		const fx = setup(30);
		try {
			await parkHtlc(fx);
			sampleFee(fx.alice, 1);
			const commitment = await forceClose(fx);

			const entry = fx.cm._pendingCommitmentCpfp.get(fx.idHex);
			expect(entry.noDeadline).to.equal(undefined);
			// ceil(1 * 1.5) = 2, raised to the floor of 10.
			expect(entry.lastFeeRate).to.equal(10);
			expect(fx.cm.getMonitor(fx.channelId)._feeRatePerVbyte).to.equal(10);

			const children = childrenOf(fx, commitment);
			expect(children.length).to.equal(1);
			expectChildBid(commitment, children[0], 10);
			expect(packageRate(commitment, children[0])).to.be.at.least(10);
		} finally {
			fx.destroy();
		}
	});

	it('re-bids a stuck package with no HTLC at the live rate each block, not at the floor', async () => {
		const fx = setup(40);
		try {
			sampleFee(fx.alice, 1);
			const commitment = await forceClose(fx);
			const entry = fx.cm._pendingCommitmentCpfp.get(fx.idHex);
			const firstHeight = entry.broadcastHeight;

			// The market moves to 4 sat/vB and the package has waited out the
			// re-bump interval unconfirmed. The deadline rate is 10 meanwhile.
			sampleFee(fx.alice, 4);
			fx.alice.handleNewBlock(firstHeight + 6);
			await tick();

			expect(entry.lastFeeRate).to.equal(4);
			const children = childrenOf(fx, commitment);
			expect(children.length).to.equal(2);
			expectChildBid(commitment, children[1], 4);
			expect(packageRate(commitment, children[1])).to.be.below(10);
		} finally {
			fx.destroy();
		}
	});

	it('a re-armed or rebuilt package with no HTLC bids the no-deadline rate', async () => {
		const fx = setup(50);
		try {
			sampleFee(fx.alice, 1);
			await forceClose(fx);

			// The tracking is memory only: after a restart it is re-armed.
			fx.cm._pendingCommitmentCpfp.delete(fx.idHex);
			fx.cm.rearmCommitmentCpfp(fx.channelId, 10, 2);
			let entry = fx.cm._pendingCommitmentCpfp.get(fx.idHex);
			expect(entry.noDeadline).to.equal(true);
			expect(entry.lastFeeRate).to.equal(2);

			// The manual rebroadcast rebuilds it.
			fx.cm._pendingCommitmentCpfp.delete(fx.idHex);
			const rebuilt = fx.cm.rebuildForceCloseCommitment(fx.channelId, 10, 3);
			expect(rebuilt.ok).to.equal(true);
			entry = fx.cm._pendingCommitmentCpfp.get(fx.idHex);
			expect(entry.noDeadline).to.equal(true);
			expect(entry.lastFeeRate).to.equal(3);

			// A caller that gives no no-deadline rate prices it as before.
			fx.cm._pendingCommitmentCpfp.delete(fx.idHex);
			fx.cm.rearmCommitmentCpfp(fx.channelId, 10);
			entry = fx.cm._pendingCommitmentCpfp.get(fx.idHex);
			expect(entry.noDeadline).to.equal(true);
			expect(entry.lastFeeRate).to.equal(10);
			await tick();
		} finally {
			fx.destroy();
		}
	});
});
