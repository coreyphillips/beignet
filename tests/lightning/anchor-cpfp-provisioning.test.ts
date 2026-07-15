/**
 * Regression (FS-9): the anchor-CPFP wallet-input selection target must be sized
 * to the CHILD-PACKAGE deficit, not the parent-only fee.
 *
 * _handleFeeBumpAndBroadcast passed ceil(feerate * parentVbytes) to
 * selectFeeBumpInputs, omitting the child's own weight (base overhead + the
 * anchor input) and the parentFeeSats / anchor-value credits. buildAnchorCpfpTx
 * actually needs ceil(feerate * (parentVbytes + childVbytes)) - parentFeeSats,
 * so with small P2WPKH UTXOs at a high bump feerate the selection under-funded
 * the child, buildAnchorCpfpTx threw "insufficient funds", and no CPFP child was
 * emitted while the commitment sat at its stale feerate. This asserts the target
 * now reflects the child package (and exceeds the old parent-only value).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { ChainActionType } from '../../src/lightning/chain/types';
import { buildAnchorScript } from '../../src/lightning/script/anchor';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);
const network = bitcoin.networks.regtest;

function makeBasepoints(seed: string): IChannelBasepoints {
	const p = (i: number): Buffer =>
		getPublicKey(crypto.createHash('sha256').update(`${seed}-${i}`).digest());
	return {
		fundingPubkey: p(0),
		revocationBasepoint: p(1),
		paymentBasepoint: p(2),
		delayedPaymentBasepoint: p(3),
		htlcBasepoint: p(4),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

/** Capture the fee target the manager asks the wallet to fund. */
function captureTarget(cm: ChannelManager): { value: bigint | null } {
	const captured: { value: bigint | null } = { value: null };
	cm.setFundingProvider({
		selectFeeBumpInputs: async (targetFeeSats: bigint) => {
			captured.value = targetFeeSats;
			// Abort after capturing; the caller's catch handles it (no broadcast).
			throw new Error('capture');
		}
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any);
	return captured;
}

async function runAnchorCpfp(
	cm: ChannelManager,
	opts: {
		feeratePerVbyte: number;
		parentVbytes: number;
		parentFeeSats: bigint;
		taproot?: boolean;
	}
): Promise<void> {
	const fundingPub = getPublicKey(
		crypto.createHash('sha256').update('cpfp-funding').digest()
	);
	const commitment = new bitcoin.Transaction();
	commitment.version = 2;
	commitment.addInput(crypto.randomBytes(32), 0);
	commitment.addOutput(
		bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(crypto.randomBytes(32)),
			network
		}).output!,
		900_000
	);
	await (
		cm as unknown as {
			_handleFeeBumpAndBroadcast: (id: Buffer, a: unknown) => Promise<void>;
		}
	)._handleFeeBumpAndBroadcast(crypto.randomBytes(32), {
		type: ChainActionType.FEE_BUMP_AND_BROADCAST,
		kind: 'anchor-cpfp',
		tx: commitment.toBuffer(),
		description: 'anchor commitment CPFP',
		feeratePerVbyte: opts.feeratePerVbyte,
		anchorOutputIndex: 0,
		anchorWitnessScript: buildAnchorScript(fundingPub),
		parentVbytes: opts.parentVbytes,
		parentFeeSats: opts.parentFeeSats,
		commitmentTxid: commitment.getId(),
		...(opts.taproot
			? {
					taprootAnchorScript: Buffer.alloc(34),
					taprootAnchorMerkleRoot: crypto.randomBytes(32)
			  }
			: {})
	});
}

describe('FS-9: anchor CPFP input provisioning', () => {
	function makeCm(): ChannelManager {
		const cm = new ChannelManager({
			localBasepoints: makeBasepoints('cpfp-cm'),
			localPerCommitmentSeed: crypto
				.createHash('sha256')
				.update('cpfp-seed')
				.digest(),
			localFundingPrivkey: crypto
				.createHash('sha256')
				.update('cpfp-funding')
				.digest()
		});
		cm.on('error', () => {});
		return cm;
	}

	it('targets the child-package deficit (legacy anchor), not the parent-only fee', async () => {
		const cm = makeCm();
		const captured = captureTarget(cm);

		const feeratePerVbyte = 100;
		const parentVbytes = 200;
		const parentFeeSats = 253n;
		await runAnchorCpfp(cm, { feeratePerVbyte, parentVbytes, parentFeeSats });

		// Corrected target: ceil(feerate * (parentVbytes + 85)) - parentFeeSats - 330.
		const expected =
			BigInt(Math.ceil(feeratePerVbyte * (parentVbytes + 85))) -
			parentFeeSats -
			330n;
		expect(captured.value).to.equal(expected);

		// And it strictly exceeds the old parent-only target that under-funded it.
		const oldParentOnly = BigInt(Math.ceil(feeratePerVbyte * parentVbytes));
		expect(captured.value! > oldParentOnly).to.equal(true);
	});

	it('uses the taproot anchor-input overhead when the anchor is taproot', async () => {
		const cm = makeCm();
		const captured = captureTarget(cm);

		const feeratePerVbyte = 100;
		const parentVbytes = 200;
		const parentFeeSats = 253n;
		await runAnchorCpfp(cm, {
			feeratePerVbyte,
			parentVbytes,
			parentFeeSats,
			taproot: true
		});

		const expected =
			BigInt(Math.ceil(feeratePerVbyte * (parentVbytes + 70))) -
			parentFeeSats -
			330n;
		expect(captured.value).to.equal(expected);
	});

	it('never asks for a negative target', async () => {
		const cm = makeCm();
		const captured = captureTarget(cm);
		// A commitment that already massively overpaid: the deficit is negative.
		await runAnchorCpfp(cm, {
			feeratePerVbyte: 2,
			parentVbytes: 200,
			parentFeeSats: 100_000n
		});
		expect(captured.value).to.equal(0n);
	});
});
