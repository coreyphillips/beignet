/**
 * Regression (S-4.M3 / M4 / M5): BOLT 4 final-node safety checks.
 *
 * - M5: the final-hop cltv_expiry check required EXACT equality with the onion's
 *   outgoing_cltv_value, rejecting a compliant sender that over-provisions the
 *   final expiry. The spec only fails when cltv_expiry < outgoing_cltv_value.
 * - M4: the final node never enforced amount_msat >= amt_to_forward, so keysend
 *   and zero-amount invoices had no skim protection.
 * - M3: the keysend receive path fulfilled (revealing the preimage) BEFORE the
 *   final-hop cltv/amount checks, so it would settle a next-block-expiring HTLC.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	KEYSEND_TLV_TYPE,
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
} from '../../src/lightning/onion/types';
import { decryptFailureMessage } from '../../src/lightning/onion/failures';

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const k = (i: number): Buffer =>
		getPublicKey(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	return {
		fundingPubkey: k(0),
		revocationBasepoint: k(1),
		paymentBasepoint: k(2),
		delayedPaymentBasepoint: k(3),
		htlcBasepoint: k(4),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(): LightningNode {
	const seed = crypto.randomBytes(32);
	const node = new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: crypto.randomBytes(32),
		fundingPrivkey: crypto.randomBytes(32)
	});
	node.on('node:error', () => {});
	return node;
}

describe('BOLT 4 final-hop safety (S-4.M3/M4/M5)', () => {
	describe('finalHopSafetyFailure', () => {
		it('allows an over-provisioned final cltv_expiry (S-4.M5)', () => {
			const node = makeNode();
			const res = (
				node as unknown as {
					finalHopSafetyFailure: (...a: unknown[]) => Buffer | null;
				}
			).finalHopSafetyFailure(
				undefined,
				{ amountToForwardMsat: 1000n, outgoingCltvValue: 800_000 },
				800_010, // incoming cltv > outgoing: over-provisioned, allowed
				1000n,
				'ab'.repeat(32)
			);
			expect(res, 'over-provisioned cltv is accepted').to.be.null;
			node.destroy();
		});

		it('fails a final cltv_expiry below the onion value (S-4.M5)', () => {
			const node = makeNode();
			const res = (
				node as unknown as {
					finalHopSafetyFailure: (...a: unknown[]) => Buffer | null;
				}
			).finalHopSafetyFailure(
				undefined,
				{ amountToForwardMsat: 1000n, outgoingCltvValue: 800_000 },
				799_999, // shortfall
				1000n,
				'ab'.repeat(32)
			);
			expect(res, 'cltv shortfall is rejected').to.not.be.null;
			node.destroy();
		});

		it('fails when the HTLC amount is below amt_to_forward (S-4.M4)', () => {
			const node = makeNode();
			const res = (
				node as unknown as {
					finalHopSafetyFailure: (...a: unknown[]) => Buffer | null;
				}
			).finalHopSafetyFailure(
				undefined,
				{ amountToForwardMsat: 10_000n, outgoingCltvValue: 800_000 },
				800_000,
				9_999n, // skimmed below amt_to_forward
				'ab'.repeat(32)
			);
			expect(res, 'amount below amt_to_forward is rejected').to.not.be.null;
			node.destroy();
		});

		it('accepts an HTLC amount at or above amt_to_forward', () => {
			const node = makeNode();
			const res = (
				node as unknown as {
					finalHopSafetyFailure: (...a: unknown[]) => Buffer | null;
				}
			).finalHopSafetyFailure(
				undefined,
				{ amountToForwardMsat: 10_000n, outgoingCltvValue: 800_000 },
				800_000,
				10_000n,
				'ab'.repeat(32)
			);
			expect(res).to.be.null;
			node.destroy();
		});
	});

	it('a keysend with a too-soon cltv is failed, not fulfilled (S-4.M3)', () => {
		const node = makeNode();
		node.handleNewBlock(800_000);

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();

		// Spy on the channel manager: a fulfilled keysend would reveal the preimage.
		const failed: bigint[] = [];
		const fulfilled: bigint[] = [];
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const cm = node.getChannelManager() as any;
		cm.failHtlc = (_c: Buffer, id: bigint): void => {
			failed.push(id);
		};
		cm.fulfillHtlc = (_c: Buffer, id: bigint): void => {
			fulfilled.push(id);
		};

		const hopPayload = {
			amountToForwardMsat: 1000n,
			outgoingCltvValue: 800_000,
			customRecords: new Map<number, Buffer>([[KEYSEND_TLV_TYPE, preimage]])
		};

		(
			node as unknown as {
				handleFinalHopHtlc: (...a: unknown[]) => void;
			}
		).handleFinalHopHtlc(
			crypto.randomBytes(32),
			7n,
			1000n,
			paymentHash,
			hopPayload,
			800_001 // < height(800000) + min_final(40): too soon
		);

		expect(failed, 'keysend HTLC was failed').to.have.length(1);
		expect(fulfilled, 'preimage was NOT revealed').to.have.length(0);
		node.destroy();
	});
});

/**
 * BOLT 4 requires incorrect_or_unknown_payment_details to carry
 * [`u64`:`htlc_msat`][`u32`:`height`]. We previously sent it with empty failure
 * data, so a sender had no way to tell a transient block-height disagreement
 * apart from a genuinely unknown payment hash.
 */
describe('incorrect_or_unknown_payment_details carries htlc_msat and height', () => {
	it('reports our block height and the HTLC amount', () => {
		const node = makeNode();
		node.handleNewBlock(800_000);

		const sharedSecret = crypto.randomBytes(32);
		const reason = (
			node as unknown as {
				finalHopSafetyFailure: (...a: unknown[]) => Buffer | null;
			}
		).finalHopSafetyFailure(
			sharedSecret,
			{ amountToForwardMsat: 1000n, outgoingCltvValue: 0 },
			800_001, // far inside any final-expiry requirement
			1000n,
			'ab'.repeat(32)
		);
		expect(reason, 'a too-soon expiry is failed').to.not.be.null;

		const decoded = decryptFailureMessage([sharedSecret], reason!);
		expect(decoded, 'failure decrypts').to.not.be.null;
		expect(decoded!.failure.failureCode).to.equal(
			INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
		);

		const data = decoded!.failure.failureData;
		expect(data.length, 'htlc_msat(8) + height(4)').to.equal(12);
		expect(data.readBigUInt64BE(0), 'htlc_msat').to.equal(1000n);
		expect(data.readUInt32BE(8), 'our block height').to.equal(800_000);

		node.destroy();
	});
});
