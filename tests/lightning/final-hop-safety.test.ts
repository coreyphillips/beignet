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
import {
	Network,
	DEFAULT_MIN_FINAL_CLTV_EXPIRY
} from '../../src/lightning/invoice/types';
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

/**
 * Regression: a payment failed permanently with incorrect_or_unknown_payment_details
 * whenever the recipient's block height was even one block ahead of the sender's.
 *
 * The sender builds the final expiry as senderHeight + min_final_cltv_expiry, and the
 * receiver MUST reject anything below receiverHeight + min_final_cltv_expiry_delta.
 * Together those require senderHeight >= receiverHeight. The receiver side is what
 * BOLT 4 mandates, so the fix belongs on the sender: pad the delta, and treat a
 * PERM|15 whose reported height is ahead of ours as transient instead of fatal.
 *
 * Note these tests set real block heights via handleNewBlock(). The receiver check
 * is guarded by `currentBlockHeight > 0`, so a test that leaves the height at 0
 * (as the rest of the suite does) never exercises this path at all.
 */
describe('Block-height skew is handled by the sender, not by relaxing the check', () => {
	function safetyCheck(
		node: LightningNode,
		incomingCltvExpiry: number
	): Buffer | null {
		return (
			node as unknown as {
				finalHopSafetyFailure: (...a: unknown[]) => Buffer | null;
			}
		).finalHopSafetyFailure(
			undefined,
			{ amountToForwardMsat: 1000n, outgoingCltvValue: 0 },
			incomingCltvExpiry,
			1000n,
			'ab'.repeat(32)
		);
	}

	// BOLT 4: "if incoming cltv_expiry < current_block_height +
	// min_final_cltv_expiry_delta: MUST fail the HTLC". We advertise
	// DEFAULT_MIN_FINAL_CLTV_EXPIRY, so we enforce exactly that.
	it('enforces the full advertised min_final_cltv_expiry_delta', () => {
		const node = makeNode();
		node.handleNewBlock(800_000);
		const threshold = 800_000 + DEFAULT_MIN_FINAL_CLTV_EXPIRY;
		expect(safetyCheck(node, threshold), 'at the boundary').to.be.null;
		expect(safetyCheck(node, threshold - 1), 'one short').to.not.be.null;
		node.destroy();
	});

	it('pads the final CLTV delta on outgoing payments', () => {
		const node = makeNode();
		const padded = (
			node as unknown as { paddedFinalCltvExpiry: (m?: number) => number }
		).paddedFinalCltvExpiry.bind(node);
		expect(padded(40), 'advertised delta is padded').to.be.greaterThan(40);
		expect(padded(), 'default delta is padded').to.be.greaterThan(
			DEFAULT_MIN_FINAL_CLTV_EXPIRY
		);
		node.destroy();
	});

	describe('noteHeightSkewFailure', () => {
		function note(node: LightningNode, code: number, data?: Buffer): boolean {
			return (
				node as unknown as {
					noteHeightSkewFailure: (c?: number, d?: Buffer) => boolean;
				}
			).noteHeightSkewFailure(code, data);
		}

		function failureData(amountMsat: bigint, height: number): Buffer {
			const buf = Buffer.alloc(12);
			buf.writeBigUInt64BE(amountMsat, 0);
			buf.writeUInt32BE(height, 8);
			return buf;
		}

		it('treats a final node ahead of us as transient and raises our CLTV base', () => {
			const node = makeNode();
			node.handleNewBlock(800_000);
			expect(
				note(
					node,
					INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
					failureData(1000n, 800_002)
				)
			).to.be.true;
			// Later sends must build against the height the payee reported, or the
			// retry would repeat the same stale expiry and fail identically.
			const base = (
				node as unknown as { cltvBaseHeight: () => number }
			).cltvBaseHeight.call(node);
			expect(base).to.equal(800_002);
			node.destroy();
		});

		it('does not treat an unknown payment hash as transient', () => {
			const node = makeNode();
			node.handleNewBlock(800_000);
			// Same code, but the payee is at or behind us: nothing to re-sync, so
			// this is the genuinely permanent half of PERM|15.
			expect(
				note(
					node,
					INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
					failureData(1000n, 800_000)
				)
			).to.be.false;
			node.destroy();
		});

		it('ignores an implausible height claim', () => {
			const node = makeNode();
			node.handleNewBlock(800_000);
			// A peer must not be able to inflate every expiry we send.
			expect(
				note(
					node,
					INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
					failureData(1000n, 900_000)
				)
			).to.be.false;
			expect(
				(
					node as unknown as { cltvBaseHeight: () => number }
				).cltvBaseHeight.call(node)
			).to.equal(800_000);
			node.destroy();
		});

		it('ignores a peer that omits the height field', () => {
			const node = makeNode();
			node.handleNewBlock(800_000);
			expect(note(node, INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, Buffer.alloc(0)))
				.to.be.false;
			node.destroy();
		});
	});
});
