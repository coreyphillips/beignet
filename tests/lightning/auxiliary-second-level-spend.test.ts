/**
 * How the spend of an HTLC output of an asset channel is told, and who
 * can add inputs to this node's own spend of one (issue #2093 step 10).
 *
 * An ending is what the witness of the spend says: a preimage of the
 * payment hash in it, the HTLC was fulfilled; none, it timed out. It is
 * not read from whether the transaction that confirmed is one this node
 * made, which a transaction id cannot say for a spend whose signatures
 * let anybody add inputs.
 *
 * And this node's own signature on such a spend is over the whole
 * transaction (SIGHASH_DEFAULT), fee inputs and all, so that nobody can
 * put its HTLC input and witness into another transaction. The peer's
 * signature on a second-level transaction stays the one the commitment
 * round gave, which allows added inputs: that is what lets this node add
 * its fee input, and only this node holds the other signature. The
 * stagings are those of the review of step 10.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as crypto from 'crypto';
import { expect } from 'chai';
import { ecc } from '../../src/utils/ecc';
import {
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import type { ITrackedOutput } from '../../src/lightning/chain/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	disconnect,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

const outcomes: { alice: string[]; bob: string[] } = { alice: [], bob: [] };
const told =
	(who: 'alice' | 'bob') =>
	(context: {
		direction: string;
		outcome: string;
		auxiliaryAmount: bigint;
	}): void => {
		outcomes[who].push(
			`${context.direction}:${context.outcome}:${context.auxiliaryAmount}`
		);
	};
const hooks = {
	alice: { onHtlcResolved: told('alice') },
	bob: {
		valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }): bigint =>
			context.auxiliaryAmount! * 1000n,
		onHtlcResolved: told('bob')
	}
};
const sha = (text: string): Buffer =>
	crypto.createHash('sha256').update(text).digest();

describe('the spend of an HTLC output of an asset channel is told by its witness, and only the node can add inputs to its own (issue #2093 step 10)', function () {
	this.timeout(180000);
	withAssetOpens();
	const world = assetChainWorld();
	let holdEvents: string[] = [];
	beforeEach(() => {
		outcomes.alice = [];
		outcomes.bob = [];
		holdEvents = [];
	});
	afterEach(() => world.dispose());

	const htlcOf = (
		host: IAssetHost,
		pair: IAssetChainPair
	): ITrackedOutput | undefined =>
		trackedOutputs(host, pair.channelId).find(
			(output) =>
				!output.isSecondLevelHtlc &&
				(output.outputType === OutputType.OFFERED_HTLC ||
					output.outputType === OutputType.RECEIVED_HTLC)
		);
	const opened = async (tag: string): Promise<IAssetChainPair> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks
		});
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		for (const name of ['hold:settled', 'hold:cancelled']) {
			pair.bob.node.on(name as never, (() => holdEvents.push(name)) as never);
		}
		return pair;
	};
	/** Keep what a host sends to spend its HTLC output from the chain, and hand it back. */
	const withhold = (
		pair: IAssetChainPair,
		who: 'alice' | 'bob',
		outpoint: ITrackedOutput
	): string[] => {
		const backend = pair.backends[who];
		const publish = backend.broadcastTransaction.bind(backend);
		const kept: string[] = [];
		backend.broadcastTransaction = async (hex: string): Promise<string> => {
			const tx = bitcoin.Transaction.fromHex(hex);
			const spendsHtlc =
				Buffer.from(tx.ins[0].hash).reverse().toString('hex') ===
					outpoint.txid && tx.ins[0].index === outpoint.outputIndex;
			if (!spendsHtlc) return publish(hex);
			if (!kept.includes(hex)) kept.push(hex);
			return tx.getId();
		};
		return kept;
	};
	/**
	 * What anybody could make of a spend seen in the mempool if its
	 * signatures allowed it: its first input and witness, its outputs, and
	 * a fee input of their own in place of the node's.
	 */
	const rewrapped = (
		pair: IAssetChainPair,
		seen: bitcoin.Transaction
	): bitcoin.Transaction => {
		const secret = sha('somebody else');
		const pubkey = Buffer.from(ecc.pointFromScalar(secret, true)!);
		const script = bitcoin.payments.p2wpkh({
			pubkey,
			network: bitcoin.networks.regtest
		}).output!;
		const coin = new bitcoin.Transaction();
		coin.version = 2;
		coin.addInput(sha(`somebody else's coin ${seen.getId()}`), 0);
		coin.addOutput(script, 60_000);
		pair.chain.seed(coin);
		const tx = new bitcoin.Transaction();
		tx.version = seen.version;
		tx.locktime = seen.locktime;
		tx.addInput(
			Buffer.from(seen.ins[0].hash),
			seen.ins[0].index,
			seen.ins[0].sequence
		);
		tx.addInput(coin.getHash(), 0, 0xfffffffd);
		for (const out of seen.outs) tx.addOutput(out.script, out.value);
		tx.setWitness(0, seen.ins[0].witness);
		const digest = tx.hashForWitnessV0(
			1,
			bitcoin.payments.p2pkh({ pubkey }).output!,
			60_000,
			bitcoin.Transaction.SIGHASH_ALL
		);
		tx.setWitness(1, [
			bitcoin.script.signature.encode(
				Buffer.from(ecc.sign(digest, secret)),
				bitcoin.Transaction.SIGHASH_ALL
			),
			pubkey
		]);
		return tx;
	};
	/**
	 * Whether the signature at `at` in the witness of the first input is
	 * one over the whole transaction (SIGHASH_DEFAULT) by the first key
	 * the leaf names, which is this node's.
	 */
	const signedOverAll = (
		pair: IAssetChainPair,
		tx: bitcoin.Transaction,
		at: number
	): boolean => {
		const witness = tx.ins[0].witness;
		const signature = witness[at];
		if (signature.length !== 64) return false;
		const leaf = witness[witness.length - 2];
		const key = bitcoin.script
			.decompile(leaf)!
			.find((el): el is Buffer => Buffer.isBuffer(el) && el.length === 32)!;
		const spent = tx.ins.map(
			(input) =>
				pair.chain.output(
					Buffer.from(input.hash).reverse().toString('hex'),
					input.index
				)!
		);
		const sighash = tx.hashForWitnessV1(
			0,
			spent.map((output) => output.script),
			spent.map((output) => Number(output.value)),
			bitcoin.Transaction.SIGHASH_DEFAULT,
			tapleafHash(leaf)
		);
		return ecc.verifySchnorr(sighash, key, signature);
	};
	const shows = (tx: bitcoin.Transaction, paymentHash: Buffer): boolean =>
		tx.ins[0].witness.some(
			(el) =>
				el.length === 32 &&
				crypto.createHash('sha256').update(el).digest().equals(paymentHash)
		);

	it('signs its own half of an HTLC-timeout over the whole transaction, so the chain refuses the transaction with another fee input; and a timeout under a transaction id that is not its own is still told as failed', async () => {
		const pair = await opened('aux-second-timeout');
		const held = await holdUnits(pair, 5000n, 'rewrap timeout');
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		const outpoint = htlcOf(pair.alice, pair)!;
		expect(outpoint.outputType).to.equal(OutputType.OFFERED_HTLC);
		const kept = withhold(pair, 'alice', outpoint);
		pair.chain.advance(held.cltvExpiry - 1 - pair.chain.height);
		await settle();
		for (let i = 0; i < 6 && kept.length === 0; i++) await world.mine(pair, 1);
		expect(kept.length, 'alice sent her HTLC-timeout').to.be.greaterThan(0);
		const own = bitcoin.Transaction.fromHex(kept[0]);
		expect(own.ins.length).to.equal(2);
		// The peer's signature is the one the commitment round gave: it
		// lets inputs be added. This node's own is over everything.
		expect(own.ins[0].witness[0].length).to.equal(65);
		expect(own.ins[0].witness[0][64] & 0x80).to.equal(0x80);
		expect(signedOverAll(pair, own, 1)).to.equal(true);
		expect(() => pair.chain.accept(own)).to.not.throw();

		const other = rewrapped(pair, own);
		expect(other.getId()).to.not.equal(own.getId());
		expect(signedOverAll(pair, other, 1)).to.equal(false);
		expect(() => pair.chain.accept(other)).to.throw(/does not verify/);

		// Were such a transaction to confirm all the same (one signed
		// before this rule, say), it is told by what its witness shows.
		pair.chain.mine(other, () => undefined);
		await settle();
		const spent = htlcOf(pair.alice, pair)!;
		expect(spent.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		expect(spent.resolutionTxid).to.equal(other.getId());
		expect(spent.auxiliarySweepAttempts?.[other.getId()]).to.equal(undefined);
		expect(shows(other, held.paymentHash)).to.equal(false);

		pair.chain.advance(IRREVOCABLE_DEPTH);
		await settle();
		await world.mine(pair, 2);
		await settle();
		expect(pair.alice.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(outcomes.alice).to.deep.equal(['OFFERED:failed:5000']);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
	});

	it('signs its own half of an HTLC-success over the whole transaction; and a claim with the preimage under a transaction id that is not its own is still told as fulfilled, with the invoice paid', async () => {
		const pair = await opened('aux-second-success');
		const held = await holdUnits(pair, 5000n, 'rewrap success');
		disconnect(pair);
		pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage);
		await settle();
		const closed = pair.bob.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 1);
		const outpoint = htlcOf(pair.bob, pair)!;
		expect(outpoint.outputType).to.equal(OutputType.RECEIVED_HTLC);
		const kept = withhold(pair, 'bob', outpoint);
		for (let i = 0; i < 6 && kept.length === 0; i++) await world.mine(pair, 1);
		expect(kept.length, 'bob sent his HTLC-success').to.be.greaterThan(0);
		const own = bitcoin.Transaction.fromHex(kept[0]);
		expect(own.ins[0].witness[0].length).to.equal(65);
		expect(signedOverAll(pair, own, 1)).to.equal(true);
		expect(() => pair.chain.accept(own)).to.not.throw();

		const other = rewrapped(pair, own);
		expect(signedOverAll(pair, other, 1)).to.equal(false);
		expect(() => pair.chain.accept(other)).to.throw(/does not verify/);

		pair.chain.mine(other, () => undefined);
		await settle();
		const spent = htlcOf(pair.bob, pair)!;
		expect(spent.resolutionTxid).to.equal(other.getId());
		expect(spent.auxiliarySweepAttempts?.[other.getId()]).to.equal(undefined);
		expect(shows(other, held.paymentHash)).to.equal(true);
		expect(pair.chain.confirmed.get(other.getId())!.height).to.be.at.most(
			held.cltvExpiry
		);
		// The payer has the preimage from the chain.
		expect(pair.alice.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);

		pair.chain.advance(IRREVOCABLE_DEPTH);
		await settle();
		await world.mine(pair, 2);
		await settle();
		expect(outcomes.bob).to.deep.equal(['RECEIVED:fulfilled:5000']);
		expect(outcomes.alice).to.deep.equal(['OFFERED:fulfilled:5000']);
		expect(holdEvents).to.deep.equal(['hold:settled']);
		expect(pair.bob.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('signs a direct claim on the commitment of the peer over the whole transaction too: the chain refuses it with another fee input', async () => {
		const pair = await opened('aux-direct-claim');
		const held = await holdUnits(pair, 5000n, 'direct claim');
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		const outpoint = htlcOf(pair.bob, pair)!;
		expect(outpoint.outputType).to.equal(OutputType.RECEIVED_HTLC);
		const kept = withhold(pair, 'bob', outpoint);
		expect(
			pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage)
		).to.equal(true);
		await settle();
		for (let i = 0; i < 6 && kept.length === 0; i++) await world.mine(pair, 1);
		expect(kept.length, 'bob sent his claim').to.be.greaterThan(0);
		const own = bitcoin.Transaction.fromHex(kept[0]);
		expect(own.ins.length).to.be.greaterThan(1);
		expect(shows(own, held.paymentHash)).to.equal(true);
		// One signature, this node's, over everything.
		expect(signedOverAll(pair, own, 0)).to.equal(true);
		expect(() => pair.chain.accept(own)).to.not.throw();
		const other = rewrapped(pair, own);
		expect(signedOverAll(pair, other, 0)).to.equal(false);
		expect(() => pair.chain.accept(other)).to.throw(/does not verify/);
	});
});
