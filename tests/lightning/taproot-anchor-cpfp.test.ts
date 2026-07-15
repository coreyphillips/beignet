/**
 * Regression: simple-taproot force-close commitments must be CPFP-able.
 *
 * Two defects (FS-4):
 *   1. _maybeCpfpAnchorCommitment located our anchor with the legacy witness-v0
 *      P2WSH script (buildAnchorOutput of the funding key). Taproot commitments
 *      carry a P2TR anchor keyed to the to_local DELAYED pubkey, so findIndex
 *      returned -1 and no CPFP child was ever built for a taproot force-close.
 *   2. buildAnchorCpfpTx signed witness-v0 ECDSA, invalid for a P2TR anchor.
 *
 * These tests drive the real manager anchor-matching path and the sweep builder
 * and verify the emitted child spends the P2TR anchor with a valid BIP341
 * key-path (Schnorr) signature.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { buildAnchorCpfpTx } from '../../src/lightning/chain/sweep';
import type { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { buildTaprootAnchorOutput } from '../../src/lightning/script/commitment-taproot';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChannelBasepoints,
	derivePublicKey,
	derivePrivateKey,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed } from '../../src/lightning/keys/shachain';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;
const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;

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

function pubForSecret(secret: Buffer): Buffer {
	return getPublicKey(secret);
}

const MAX_INDEX = 0xffffffffffffn;

describe('FS-4: taproot anchor commitment CPFP', () => {
	// Fixed delayed key so the anchor's owner (to_local delayed) key is known.
	const delayedSecret = crypto
		.createHash('sha256')
		.update('fs4-delayed-basepoint')
		.digest();
	const delayedBasepoint = pubForSecret(delayedSecret);

	function localBasepoints(): IChannelBasepoints {
		const p = (t: string) =>
			pubForSecret(crypto.createHash('sha256').update(t).digest());
		return {
			fundingPubkey: p('fs4-funding'),
			revocationBasepoint: p('fs4-revocation'),
			paymentBasepoint: p('fs4-payment'),
			delayedPaymentBasepoint: delayedBasepoint,
			htlcBasepoint: p('fs4-htlc'),
			firstPerCommitmentPoint: p('fs4-first')
		};
	}

	function taprootChannelType(): Buffer {
		const flags = FeatureFlags.empty();
		flags.setCompulsory(Feature.OPTION_TAPROOT);
		return flags.toBuffer();
	}

	it('buildAnchorCpfpTx key-path spends the P2TR anchor with a valid Schnorr sig', () => {
		const localPerCommitmentSeed = crypto.randomBytes(32);
		const point = perCommitmentPointFromSecret(
			generateFromSeed(localPerCommitmentSeed, MAX_INDEX)
		);
		const localDelayedPubkey = derivePublicKey(delayedBasepoint, point);
		const anchor = buildTaprootAnchorOutput(localDelayedPubkey);
		// The spending key is the delayed privkey for this commitment (derivePrivateKey
		// mirrors derivePublicKey, so it corresponds to localDelayedPubkey).
		const delayedPrivkey = derivePrivateKey(
			delayedSecret,
			point,
			delayedBasepoint
		);

		const walletInput = makeWalletInput(100_000, 'fs4-cpfp-wallet');
		const changeScript = bitcoin.payments.p2wpkh({
			pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
			network
		}).output!;

		const commitmentTxid = crypto.randomBytes(32).toString('hex');
		const { tx } = buildAnchorCpfpTx({
			commitmentTxid,
			anchorOutputIndex: 1,
			anchorAmount: 330n,
			anchorWitnessScript: Buffer.alloc(0),
			localFundingPrivkey: delayedPrivkey,
			parentVbytes: 200,
			parentFeeSats: 0n,
			walletInputs: [walletInput],
			changeScript,
			feeratePerVbyte: 20,
			taprootAnchorScript: anchor.output,
			taprootAnchorMerkleRoot: anchor.merkleRoot
		});

		// Anchor witness is a single Schnorr signature (no witness script).
		const anchorWitness = tx.ins[0].witness;
		expect(anchorWitness.length).to.equal(1);
		expect(anchorWitness[0].length).to.be.oneOf([64, 65]);

		// The signature verifies as a BIP341 key-path spend of the P2TR anchor.
		const walletScript = bitcoin.Transaction.fromBuffer(walletInput.prevTx)
			.outs[0].script;
		const sighash = tx.hashForWitnessV1(
			0,
			[anchor.output, walletScript],
			[330, 100_000],
			bitcoin.Transaction.SIGHASH_DEFAULT
		);
		const sig64 = anchorWitness[0].subarray(0, 64);
		expect(ecc.verifySchnorr(sighash, anchor.outputKey, sig64)).to.be.true;
	});

	it('manager builds a CPFP child that spends the P2TR anchor of a taproot force-close', async () => {
		const localPerCommitmentSeed = crypto.randomBytes(32);
		const cm = new ChannelManager({
			localBasepoints: localBasepoints(),
			localPerCommitmentSeed,
			localFundingPrivkey: crypto
				.createHash('sha256')
				.update('fs4-node-funding')
				.digest(),
			delayedPaymentBasepointSecret: delayedSecret
		} as any);
		cm.on('error', () => {});

		// Minimal funding provider: one wallet input + a change script.
		const changeScript = bitcoin.payments.p2wpkh({
			pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
			network
		}).output!;
		cm.setFundingProvider({
			selectFeeBumpInputs: async () => ({
				inputs: [makeWalletInput(200_000, 'fs4-mgr-wallet')],
				changeScript
			})
		} as any);

		// Register a taproot channel whose delayed basepoint matches delayedSecret.
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints: localBasepoints(),
			localPerCommitmentSeed
		});
		state.state = ChannelState.NORMAL;
		state.channelId = crypto.randomBytes(32);
		state.channelType = taprootChannelType();
		const channel = new Channel(state);
		cm.restoreChannel(channel, 'ab'.repeat(33));

		// Synthesize the broadcast local commitment: a P2TR anchor keyed to our
		// to_local delayed pubkey for this commitment, at output index 1.
		const point = perCommitmentPointFromSecret(
			generateFromSeed(
				localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			)
		);
		const localDelayedPubkey = derivePublicKey(delayedBasepoint, point);
		const anchor = buildTaprootAnchorOutput(localDelayedPubkey);
		const commitmentTx = new bitcoin.Transaction();
		commitmentTx.version = 2;
		commitmentTx.addInput(crypto.randomBytes(32), 0);
		// to_local (some P2TR), then our anchor.
		commitmentTx.addOutput(
			bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
				network
			}).output!,
			900_000
		);
		commitmentTx.addOutput(anchor.output, 330);
		const commitmentTxid = commitmentTx.getId();

		const broadcasts: Buffer[] = [];
		cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		(cm as any)._maybeCpfpAnchorCommitment(
			state.channelId,
			state,
			[{ type: ChannelActionType.BROADCAST_TX, tx: commitmentTx.toBuffer() }],
			20
		);
		await new Promise((resolve) => setTimeout(resolve, 30));

		// A CPFP child was emitted (pre-fix: the P2WSH lookup missed the anchor and
		// nothing was broadcast).
		expect(broadcasts.length, 'a CPFP child was broadcast').to.equal(1);
		const child = bitcoin.Transaction.fromBuffer(broadcasts[0]);

		// Its first input spends our anchor outpoint.
		expect(Buffer.from(child.ins[0].hash).reverse().toString('hex')).to.equal(
			commitmentTxid
		);
		expect(child.ins[0].index).to.equal(1);

		// The anchor witness is a single Schnorr signature that verifies against
		// the P2TR anchor output key.
		const anchorWitness = child.ins[0].witness;
		expect(anchorWitness.length).to.equal(1);
		const walletScript = bitcoin.Transaction.fromBuffer(
			makeWalletInput(200_000, 'fs4-mgr-wallet').prevTx
		).outs[0].script;
		const sighash = child.hashForWitnessV1(
			0,
			[anchor.output, walletScript],
			[330, 200_000],
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
});
