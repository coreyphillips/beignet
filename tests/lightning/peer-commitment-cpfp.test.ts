/**
 * Issue #559: anchor CPFP against the PEER's mempool commitment.
 *
 * An adversarial peer can park a below-floor commitment in the mempool: our
 * preimage claim of an inbound HTLC on that commitment is CSV-1, so it cannot
 * even be broadcast until THEIR tx confirms, at a time the peer controls.
 * Their commitment carries an anchor keyed to us for exactly this; the manager
 * must attach a wallet-funded CPFP child to it when a deadline-bound claim
 * (an inbound HTLC whose preimage we hold) is at stake.
 *
 * These tests drive _maybeCpfpTheirCommitment directly with a synthesized
 * peer commitment and verify the emitted child spends the remote-side anchor
 * with a valid signature: witness-v0 ECDSA under our funding pubkey on legacy
 * anchor channels, BIP341 key-path Schnorr under our static payment basepoint
 * on simple taproot channels.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import type { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry
} from '../../src/lightning/channel/types';
import {
	buildAnchorOutput,
	buildAnchorScript
} from '../../src/lightning/script/anchor';
import { buildTaprootAnchorOutput } from '../../src/lightning/script/commitment-taproot';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;
const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;

const fundingPriv = crypto.createHash('sha256').update('p559-funding').digest();
const paymentPriv = crypto.createHash('sha256').update('p559-payment').digest();

function localBasepoints(): IChannelBasepoints {
	const p = (t: string): Buffer =>
		getPublicKey(crypto.createHash('sha256').update(t).digest());
	return {
		fundingPubkey: getPublicKey(fundingPriv),
		revocationBasepoint: p('p559-revocation'),
		paymentBasepoint: getPublicKey(paymentPriv),
		delayedPaymentBasepoint: p('p559-delayed'),
		htlcBasepoint: p('p559-htlc'),
		firstPerCommitmentPoint: p('p559-first')
	};
}

function channelTypeOf(feature: Feature): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(feature);
	return flags.toBuffer();
}

/** Build a real P2WPKH wallet input with a working signWitness closure. */
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
			const der = bitcoin.script.signature.encode(sig64, SIGHASH_ALL);
			return [der, pubkey];
		}
	};
}

const WALLET_VALUE = 200_000;
const WALLET_SEED = 'p559-wallet';

function makeManager(): ChannelManager {
	const cm = new ChannelManager({
		localBasepoints: localBasepoints(),
		localPerCommitmentSeed: crypto
			.createHash('sha256')
			.update('p559-seed')
			.digest(),
		localFundingPrivkey: fundingPriv,
		paymentBasepointSecret: paymentPriv
	} as any);
	cm.on('error', () => {});
	const changeScript = bitcoin.payments.p2wpkh({
		pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
		network
	}).output!;
	cm.setFundingProvider({
		selectFeeBumpInputs: async () => ({
			inputs: [makeWalletInput(WALLET_VALUE, WALLET_SEED)],
			changeScript
		})
	} as any);
	return cm;
}

function makeState(channelType: Buffer): any {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: localBasepoints(),
		localPerCommitmentSeed: crypto
			.createHash('sha256')
			.update('p559-seed')
			.digest()
	});
	state.state = ChannelState.NORMAL;
	state.channelId = crypto.randomBytes(32);
	state.channelType = channelType;
	return state;
}

function fulfilledInboundHtlc(paymentHash: Buffer): IHtlcEntry {
	return {
		id: 0n,
		amountMsat: 2_000_000_000n,
		paymentHash,
		cltvExpiry: 800_000,
		onionRoutingPacket: Buffer.alloc(0),
		direction: HtlcDirection.RECEIVED,
		state: HtlcState.FULFILLED
	};
}

/** Synthesize the PEER's commitment: to_remote-ish output + the given anchor. */
function theirCommitment(anchorScript: Buffer): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(
		bitcoin.payments.p2wpkh({
			pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
			network
		}).output!,
		995_000
	);
	tx.addOutput(anchorScript, 330);
	return tx;
}

const tick = (): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, 30));

describe('issue #559: peer commitment anchor CPFP', () => {
	it('legacy anchors: spends our funding-keyed anchor on their commitment', async () => {
		const cm = makeManager();
		const state = makeState(channelTypeOf(Feature.ANCHOR_ZERO_FEE_HTLC));
		state.htlcs.set('received-0', fulfilledInboundHtlc(crypto.randomBytes(32)));

		const anchorScript = buildAnchorOutput(getPublicKey(fundingPriv)).script;
		const theirTx = theirCommitment(anchorScript);
		const broadcasts: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		(cm as any)._maybeCpfpTheirCommitment(state.channelId, state, theirTx, 20);
		await tick();

		expect(broadcasts.length, 'a CPFP child was broadcast').to.equal(1);
		const child = bitcoin.Transaction.fromBuffer(broadcasts[0]);

		// Input 0 spends the anchor outpoint on THEIR commitment.
		expect(Buffer.from(child.ins[0].hash).reverse().toString('hex')).to.equal(
			theirTx.getId()
		);
		expect(child.ins[0].index).to.equal(1);

		// Witness [sig, witnessScript]: ECDSA under OUR funding pubkey.
		const witnessScript = buildAnchorScript(getPublicKey(fundingPriv));
		expect(child.ins[0].witness[1].equals(witnessScript)).to.be.true;
		const sighash = child.hashForWitnessV0(0, witnessScript, 330, SIGHASH_ALL);
		const decoded = bitcoin.script.signature.decode(child.ins[0].witness[0]);
		expect(ecc.verify(sighash, getPublicKey(fundingPriv), decoded.signature)).to
			.be.true;

		// Tracked for re-bumps until their commitment confirms.
		const entry = (cm as any)._pendingCommitmentCpfp.get(
			state.channelId.toString('hex')
		);
		expect(entry).to.exist;
		expect(entry.action.commitmentTxid).to.equal(theirTx.getId());
		expect(entry.action.tx.equals(theirTx.toBuffer())).to.be.true;

		// A second sighting report must not double-arm.
		(cm as any)._maybeCpfpTheirCommitment(state.channelId, state, theirTx, 25);
		await tick();
		expect(broadcasts.length).to.equal(1);
	});

	it('taproot: key-path spends the payment-basepoint anchor on their commitment', async () => {
		const cm = makeManager();
		const state = makeState(channelTypeOf(Feature.OPTION_TAPROOT));
		state.htlcs.set('received-0', fulfilledInboundHtlc(crypto.randomBytes(32)));

		// On their commitment the remote (our) taproot anchor is keyed to our
		// STATIC payment basepoint, not a delayed key.
		const anchor = buildTaprootAnchorOutput(getPublicKey(paymentPriv));
		const theirTx = theirCommitment(anchor.output);
		const broadcasts: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		(cm as any)._maybeCpfpTheirCommitment(state.channelId, state, theirTx, 20);
		await tick();

		expect(broadcasts.length, 'a CPFP child was broadcast').to.equal(1);
		const child = bitcoin.Transaction.fromBuffer(broadcasts[0]);
		expect(Buffer.from(child.ins[0].hash).reverse().toString('hex')).to.equal(
			theirTx.getId()
		);
		expect(child.ins[0].index).to.equal(1);

		// Single Schnorr signature verifying as a BIP341 key-path spend of the
		// P2TR anchor, signed by the payment basepoint secret.
		const anchorWitness = child.ins[0].witness;
		expect(anchorWitness.length).to.equal(1);
		const walletScript = bitcoin.Transaction.fromBuffer(
			makeWalletInput(WALLET_VALUE, WALLET_SEED).prevTx
		).outs[0].script;
		const sighash = child.hashForWitnessV1(
			0,
			[anchor.output, walletScript],
			[330, WALLET_VALUE],
			bitcoin.Transaction.SIGHASH_DEFAULT
		);
		expect(
			ecc.verifySchnorr(
				sighash,
				anchor.outputKey,
				anchorWitness[0].subarray(0, 64)
			)
		).to.be.true;
	});

	it('does nothing without a deadline-bound claim, arms once a preimage is recorded', async () => {
		const cm = makeManager();
		const state = makeState(channelTypeOf(Feature.ANCHOR_ZERO_FEE_HTLC));
		const paymentHash = crypto.randomBytes(32);
		// Inbound HTLC still pending and no preimage known: their commitment
		// confirming is the PEER's problem, not worth our wallet's fees.
		const htlc = fulfilledInboundHtlc(paymentHash);
		htlc.state = HtlcState.COMMITTED;
		state.htlcs.set('received-0', htlc);

		const anchorScript = buildAnchorOutput(getPublicKey(fundingPriv)).script;
		const theirTx = theirCommitment(anchorScript);
		const broadcasts: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		(cm as any)._maybeCpfpTheirCommitment(state.channelId, state, theirTx, 20);
		await tick();
		expect(broadcasts.length).to.equal(0);
		expect(
			(cm as any)._pendingCommitmentCpfp.has(state.channelId.toString('hex'))
		).to.be.false;

		// The preimage learned from downstream makes the claim deadline-bound.
		const preimage = crypto.randomBytes(32);
		const hash = crypto.createHash('sha256').update(preimage).digest();
		htlc.paymentHash = hash;
		cm.recordPreimage(hash, preimage);

		(cm as any)._maybeCpfpTheirCommitment(state.channelId, state, theirTx, 20);
		await tick();
		expect(broadcasts.length).to.equal(1);
	});

	it('does nothing on a non-anchor channel', async () => {
		const cm = makeManager();
		const state = makeState(Buffer.alloc(0));
		state.channelType = null;
		state.htlcs.set('received-0', fulfilledInboundHtlc(crypto.randomBytes(32)));

		const anchorScript = buildAnchorOutput(getPublicKey(fundingPriv)).script;
		const theirTx = theirCommitment(anchorScript);
		const broadcasts: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		(cm as any)._maybeCpfpTheirCommitment(state.channelId, state, theirTx, 20);
		await tick();
		expect(broadcasts.length).to.equal(0);
	});
});
