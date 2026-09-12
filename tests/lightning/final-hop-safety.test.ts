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
import { IInvoiceInfo } from '../../src/lightning/storage/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

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

function makeNode(storage?: SqliteStorage): LightningNode {
	const seed = crypto.randomBytes(32);
	const node = new LightningNode({
		...(storage ? { storage } : {}),
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

	/**
	 * PERM|15 is overloaded. It is also returned for an unknown payment hash, a
	 * wrong payment secret, underpayment and gross overpayment, so a reported
	 * height alone must not be enough to call a failure transient.
	 */
	describe('noteHeightSkewFailure', () => {
		const HASH = Buffer.alloc(32, 7);

		function failureData(amountMsat: bigint, height: number): Buffer {
			const buf = Buffer.alloc(12);
			buf.writeBigUInt64BE(amountMsat, 0);
			buf.writeUInt32BE(height, 8);
			return buf;
		}

		/** A 2-hop outgoing payment whose final hop is index 1. */
		function makePayment(opts: {
			failureSourceIndex?: number;
			cltvBaseHeight?: number;
		}): Record<string, unknown> {
			return {
				paymentHash: HASH,
				failureCode: INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
				failureSourceIndex: opts.failureSourceIndex ?? 1,
				cltvBaseHeight: opts.cltvBaseHeight,
				route: {
					hops: [{ pubkey: Buffer.alloc(33) }, { pubkey: Buffer.alloc(33) }]
				}
			};
		}

		function setup(height: number): {
			node: LightningNode;
			note: (p: Record<string, unknown>, d?: Buffer) => boolean;
			override: () => number | undefined;
		} {
			const node = makeNode();
			node.handleNewBlock(height);
			// A skew override is recorded on the payment's retry context.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const anyNode = node as any;
			anyNode.paymentRetryContexts.set(HASH.toString('hex'), {
				excludedChannels: new Set(),
				retryCount: 0,
				maxRetries: 3
			});
			return {
				node,
				note: (p, d): boolean => anyNode.noteHeightSkewFailure(p, d),
				override: (): number | undefined =>
					anyNode.paymentRetryContexts.get(HASH.toString('hex'))
						?.cltvBaseHeightOverride
			};
		}

		it('treats a final node ahead of this attempt as transient', () => {
			const { node, note, override } = setup(800_000);
			expect(
				note(
					makePayment({ cltvBaseHeight: 800_000 }),
					failureData(1000n, 800_002)
				)
			).to.be.true;
			// The retry must be built against the reported height, or it would
			// repeat the same stale expiry and fail identically.
			expect(override()).to.equal(800_002);
			node.destroy();
		});

		it('does not treat a payee at or behind us as transient', () => {
			const { node, note, override } = setup(800_000);
			// The genuinely permanent half of PERM|15: unknown hash, wrong secret.
			expect(
				note(
					makePayment({ cltvBaseHeight: 800_000 }),
					failureData(1000n, 800_000)
				)
			).to.be.false;
			expect(override()).to.be.undefined;
			node.destroy();
		});

		it('does not re-treat a height this attempt already used', () => {
			const { node, note } = setup(800_000);
			// We already retried against 800_002. The payee reporting it again is
			// telling us nothing new, so this failure is about something else and
			// must not burn the remaining retries.
			expect(
				note(
					makePayment({ cltvBaseHeight: 800_002 }),
					failureData(1000n, 800_002)
				)
			).to.be.false;
			node.destroy();
		});

		it('ignores a height reported by a hop that is not the payee', () => {
			const { node, note } = setup(800_000);
			// BOLT 4 defines the field as the FINAL node's height.
			expect(
				note(
					makePayment({ failureSourceIndex: 0, cltvBaseHeight: 800_000 }),
					failureData(1000n, 800_002)
				)
			).to.be.false;
			node.destroy();
		});

		it('ignores an implausible height claim', () => {
			const { node, note, override } = setup(800_000);
			// A peer must not be able to inflate the expiry of what we send.
			expect(
				note(
					makePayment({ cltvBaseHeight: 800_000 }),
					failureData(1000n, 900_000)
				)
			).to.be.false;
			expect(override()).to.be.undefined;
			node.destroy();
		});

		it('ignores a peer that omits the height field', () => {
			const { node, note } = setup(800_000);
			expect(note(makePayment({ cltvBaseHeight: 800_000 }), Buffer.alloc(0))).to
				.be.false;
			node.destroy();
		});
	});
});

/**
 * Issue #770: the invoice's own min_final_cltv_expiry, signed into the BOLT
 * 11 c tag, was never compared against the arriving HTLC; the final hop
 * enforced the 40-block node default for every invoice. A swap leg that
 * advertised 200 blocks so it would outlive an on-chain refund then parked
 * an HTLC that cleared only 40, and the payer could reclaim over Lightning
 * while still claiming the contract.
 */
describe("the invoice's advertised min_final_cltv_expiry is enforced (issue #770)", () => {
	const HEIGHT = 800_000;

	/* eslint-disable @typescript-eslint/no-explicit-any */
	function seedInvoice(
		node: LightningNode,
		hashHex: string,
		extra: Partial<IInvoiceInfo>
	): void {
		(node as any).invoices.set(hashHex, {
			paymentHash: hashHex,
			bolt11: 'lnbcrt1seeded',
			expiry: 3600,
			createdAt: 0,
			...extra
		} as IInvoiceInfo);
	}

	/** Drive one final-hop HTLC through handleFinalHopHtlc with stubbed channel calls. */
	function deliver(
		node: LightningNode,
		paymentHash: Buffer,
		cltvExpiry: number,
		hopPayload: Record<string, unknown>
	): { failed: Buffer[]; fulfilled: bigint[] } {
		const failed: Buffer[] = [];
		const fulfilled: bigint[] = [];
		const cm = node.getChannelManager() as any;
		cm.failHtlc = (_c: Buffer, _id: bigint, reason: Buffer): void => {
			failed.push(reason);
		};
		cm.fulfillHtlc = (_c: Buffer, id: bigint): void => {
			fulfilled.push(id);
		};
		const channelId = crypto.randomBytes(32);
		const htlcId = 9n;
		const sharedSecret = crypto.randomBytes(32);
		(node as any).receivedHtlcSharedSecrets.set(
			`${channelId.toString('hex')}:${htlcId}`,
			sharedSecret
		);
		(node as any).handleFinalHopHtlc(
			channelId,
			htlcId,
			1000n,
			paymentHash,
			hopPayload,
			cltvExpiry
		);
		// Decode in place so a caller can assert on the failure without the secret.
		for (let i = 0; i < failed.length; i++) {
			const decoded = decryptFailureMessage([sharedSecret], failed[i]);
			expect(decoded, 'the failure decrypts for the payer').to.not.be.null;
			failed[i] = Buffer.concat([
				Buffer.from([
					decoded!.failure.failureCode >> 8,
					decoded!.failure.failureCode & 0xff
				]),
				decoded!.failure.failureData
			]);
		}
		return { failed, fulfilled };
	}
	/* eslint-enable @typescript-eslint/no-explicit-any */

	function safety(
		node: LightningNode,
		hashHex: string,
		cltv: number
	): Buffer | null {
		return (
			node as unknown as {
				finalHopSafetyFailure: (...a: unknown[]) => Buffer | null;
			}
		).finalHopSafetyFailure(
			undefined,
			{ amountToForwardMsat: 1000n, outgoingCltvValue: 0 },
			cltv,
			1000n,
			hashHex,
			'stub:1'
		);
	}

	it('refuses an HTLC that clears only the default when the invoice advertised 200', () => {
		const node = makeNode();
		node.handleNewBlock(HEIGHT);
		const paymentHash = crypto.randomBytes(32);
		const hashHex = paymentHash.toString('hex');
		seedInvoice(node, hashHex, { minFinalCltvExpiry: 200 });

		const { failed, fulfilled } = deliver(
			node,
			paymentHash,
			HEIGHT + DEFAULT_MIN_FINAL_CLTV_EXPIRY,
			{ amountToForwardMsat: 1000n, outgoingCltvValue: HEIGHT + 40 }
		);
		expect(failed, 'the HTLC was failed').to.have.length(1);
		expect(fulfilled, 'no preimage was revealed').to.have.length(0);
		// incorrect_or_unknown_payment_details with [htlc_msat][height], as
		// before: the payer treats a reported height as transient and retries
		// with the delta the invoice asked for.
		expect(failed[0].readUInt16BE(0)).to.equal(
			INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
		);
		expect(failed[0].length, 'code(2) + htlc_msat(8) + height(4)').to.equal(14);
		expect(failed[0].readBigUInt64BE(2)).to.equal(1000n);
		expect(failed[0].readUInt32BE(10), 'our height').to.equal(HEIGHT);
		// One block short of the advertised delta is still refused; the delta
		// itself is accepted.
		expect(safety(node, hashHex, HEIGHT + 199), 'one short').to.not.be.null;
		expect(safety(node, hashHex, HEIGHT + 200), 'at the boundary').to.be.null;
		node.destroy();
	});

	it('accepts an HTLC that clears the advertised delta and settles a real invoice on it', () => {
		const node = makeNode();
		node.handleNewBlock(HEIGHT);
		const invoice = node.createInvoice({
			amountMsat: 1000n,
			description: 'swap leg',
			minFinalCltvExpiry: 200
		});
		const hashHex = invoice.paymentHash.toString('hex');
		// createInvoice recorded the delta it signed into the c tag.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const record = (node as any).invoices.get(hashHex) as IInvoiceInfo;
		expect(record.minFinalCltvExpiry).to.equal(200);

		const short = deliver(node, invoice.paymentHash, HEIGHT + 40, {
			amountToForwardMsat: 1000n,
			outgoingCltvValue: HEIGHT + 40,
			paymentSecret: invoice.paymentSecret,
			totalMsat: 1000n
		});
		expect(short.fulfilled, 'a 40-block HTLC is not settled').to.have.length(0);
		expect(short.failed).to.have.length(1);

		const ok = deliver(node, invoice.paymentHash, HEIGHT + 200, {
			amountToForwardMsat: 1000n,
			outgoingCltvValue: HEIGHT + 200,
			paymentSecret: invoice.paymentSecret,
			totalMsat: 1000n
		});
		expect(ok.failed, 'a 200-block HTLC is not failed').to.have.length(0);
		expect(ok.fulfilled, 'and is settled').to.have.length(1);
		node.destroy();
	});

	it('keeps the default for a hash with no invoice and for an invoice without a delta', () => {
		const node = makeNode();
		node.handleNewBlock(HEIGHT);
		const unknown = 'ab'.repeat(32);
		expect(safety(node, unknown, HEIGHT + 40), 'unknown hash, default').to.be
			.null;
		expect(safety(node, unknown, HEIGHT + 39), 'unknown hash, one short').to.not
			.be.null;
		const recorded = 'cd'.repeat(32);
		seedInvoice(node, recorded, {});
		expect(safety(node, recorded, HEIGHT + 40), 'no delta recorded').to.be.null;
		// An invoice cannot lower the bound below the node's own claim window.
		const low = 'ef'.repeat(32);
		seedInvoice(node, low, { minFinalCltvExpiry: 18 });
		expect(safety(node, low, HEIGHT + 39), 'advertised 18, still 40').to.not.be
			.null;
		expect(safety(node, low, HEIGHT + 40)).to.be.null;
		node.destroy();
	});

	it('leaves keysend on the default even when an invoice for another hash asks for more', () => {
		const node = makeNode();
		node.handleNewBlock(HEIGHT);
		seedInvoice(node, 'ab'.repeat(32), { minFinalCltvExpiry: 200 });
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const { failed, fulfilled } = deliver(node, paymentHash, HEIGHT + 40, {
			amountToForwardMsat: 1000n,
			outgoingCltvValue: HEIGHT + 40,
			customRecords: new Map<number, Buffer>([[KEYSEND_TLV_TYPE, preimage]])
		});
		expect(failed, 'a 40-block keysend is not failed').to.have.length(0);
		expect(fulfilled, 'and is settled').to.have.length(1);
		node.destroy();
	});

	it('carries the delta through storage, and a row without one loads as the default', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const node = makeNode(storage);
		try {
			const swapLeg = node.createInvoice({
				amountMsat: 1000n,
				description: 'swap leg',
				minFinalCltvExpiry: 200
			});
			const plain = node.createInvoice({ amountMsat: 1000n, description: 'p' });
			const rowFor = (hash: Buffer): IInvoiceInfo =>
				storage
					.loadAllInvoices()
					.find((r) => r.paymentHashHex === hash.toString('hex'))!.invoice;
			expect(rowFor(swapLeg.paymentHash).minFinalCltvExpiry).to.equal(200);
			expect(
				rowFor(plain.paymentHash).minFinalCltvExpiry,
				'an invoice on the default records nothing'
			).to.equal(undefined);
			expect(
				'minFinalCltvExpiry' in rowFor(plain.paymentHash),
				'and the loaded row carries no key for it'
			).to.equal(true);

			// A row written before the field existed.
			const legacyHex = '11'.repeat(32);
			storage.saveInvoice(legacyHex, {
				paymentHash: legacyHex,
				bolt11: 'lnbcrt1legacy',
				expiry: 3600,
				createdAt: 1
			});
			expect(rowFor(Buffer.from(legacyHex, 'hex')).minFinalCltvExpiry).to.equal(
				undefined
			);

			// A restarted node enforces the persisted delta.
			const restarted = makeNode(storage);
			try {
				restarted.handleNewBlock(HEIGHT);
				const hex = swapLeg.paymentHash.toString('hex');
				expect(safety(restarted, hex, HEIGHT + 199), 'after restart').to.not.be
					.null;
				expect(safety(restarted, hex, HEIGHT + 200)).to.be.null;
				expect(safety(restarted, legacyHex, HEIGHT + 40), 'legacy row').to.be
					.null;
			} finally {
				restarted.destroy();
			}
		} finally {
			node.destroy();
			storage.close();
		}
	});
});
