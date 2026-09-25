/**
 * Issue #177: UPDATE-flagged forwarding failures must carry their BOLT 4
 * failure data.
 *
 * Every one of these was sent with EMPTY failure data, omitting not just the
 * channel_update but the fixed fields in front of it, so a payer could not
 * tell what amount or expiry was rejected. BOLT 4 today says the
 * channel_update itself is no longer mandatory (nodes "are expected to
 * transition away from including it", as Eclair and LDK already have), so the
 * compliant shape is the fixed fields for the code followed by a zero-length
 * update:
 *
 *   temporary_channel_failure  [u16 len=0]
 *   expiry_too_soon            [u16 len=0]
 *   amount_below_minimum       [u64 htlc_msat][u16 len=0]
 *   fee_insufficient           [u64 htlc_msat][u16 len=0]
 *   incorrect_cltv_expiry      [u32 cltv_expiry][u16 len=0]
 *   channel_disabled           [u16 disabled_flags][u16 len=0]
 *
 * unknown_next_peer (PERM|10) has no data by definition and must stay empty.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import {
	ROUTING_INFO_LENGTH,
	TEMPORARY_CHANNEL_FAILURE,
	FEE_INSUFFICIENT,
	INCORRECT_CLTV_EXPIRY,
	EXPIRY_TOO_SOON,
	AMOUNT_BELOW_MINIMUM,
	CHANNEL_DISABLED,
	UNKNOWN_NEXT_PEER,
	INVALID_ONION_BLINDING
} from '../../src/lightning/onion/types';
import { decryptFailureMessage } from '../../src/lightning/onion/failures';
import { constructBlindedPath } from '../../src/lightning/onion/blinded-path';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

function makeBasepoints(): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) keys.push(crypto.randomBytes(32));
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function plainChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	return flags.toBuffer();
}

/** A confirmed channel with a real SCID, installed and SCID-registered. */
function installChannel(node: LightningNode): {
	channelId: Buffer;
	realScid: Buffer;
} {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 100_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	const channelId = crypto.randomBytes(32);
	const realScid = encodeShortChannelId({
		block: 900_000,
		txIndex: 42,
		outputIndex: 0
	});
	state.channelId = channelId;
	state.shortChannelId = realScid;
	state.scidAlias = crypto.randomBytes(8);
	state.announceChannel = true;
	state.channelType = plainChannelType();
	const channel = new Channel(state);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(node as any).channelManager.restoreChannel(
		channel,
		crypto.randomBytes(33).toString('hex')
	);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(node as any).registerChannelScids(channelId);
	return { channelId, realScid };
}

describe('Issue #177: forwarding failures carry their BOLT 4 data', function () {
	this.timeout(10_000);

	let node: LightningNode;
	let failHtlcCalls: Array<{ reason: Buffer }>;
	let addHtlcCalls: number;
	let sharedSecret: Buffer;

	beforeEach(function () {
		node = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			perCommitmentSeed: crypto.randomBytes(32),
			channelBasepoints: makeBasepoints(),
			fundingPrivkey: crypto.randomBytes(32)
		});
		failHtlcCalls = [];
		addHtlcCalls = 0;
		sharedSecret = crypto.randomBytes(32);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const cm = (node as any).channelManager;
		cm.addHtlc = (): { ok: boolean; error: string } => {
			addHtlcCalls++;
			return { ok: false, error: 'refused' };
		};
		cm.failHtlc = (
			_c: Buffer,
			_id: bigint,
			reason: Buffer
		): { ok: boolean } => {
			failHtlcCalls.push({ reason });
			return { ok: true };
		};
		node.on('error', () => {});
	});

	afterEach(function () {
		node.destroy();
	});

	function forward(
		outgoingScid: Buffer,
		incomingAmountMsat: bigint,
		incomingCltvExpiry: number,
		forwardAmountMsat: bigint,
		forwardCltv: number,
		blinded?: { blindingPoint: Buffer; encryptedRecipientData: Buffer }
	): void {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).handleForwardHtlc(
			crypto.randomBytes(32),
			0n,
			crypto.randomBytes(32),
			{
				hopPayload: {
					amountToForwardMsat: forwardAmountMsat,
					outgoingCltvValue: forwardCltv,
					shortChannelId: outgoingScid,
					...(blinded ?? {})
				},
				nextPacket: {
					version: 0,
					ephemeralKey: crypto.randomBytes(33),
					routingInfo: Buffer.alloc(ROUTING_INFO_LENGTH),
					hmac: crypto.randomBytes(32)
				},
				sharedSecret
			},
			incomingAmountMsat,
			incomingCltvExpiry
		);
	}

	function decodedFailure(): { failureCode: number; failureData: Buffer } {
		expect(failHtlcCalls.length, 'incoming HTLC was failed').to.equal(1);
		const decrypted = decryptFailureMessage(
			[sharedSecret],
			failHtlcCalls[0].reason
		);
		expect(decrypted, 'failure decrypts').to.not.be.null;
		return decrypted!.failure;
	}

	it('fee_insufficient carries [htlc_msat][u16 len=0]', function () {
		const { realScid } = installChannel(node);
		// Default policy: base 1000 msat + 1 ppm. 500 msat of fee is short.
		forward(realScid, 1_000_500n, 700_500, 1_000_000n, 700_000);

		const { failureCode, failureData } = decodedFailure();
		expect(failureCode).to.equal(FEE_INSUFFICIENT);
		expect(failureData.length, '[u64][u16]').to.equal(10);
		expect(failureData.readBigUInt64BE(0), 'incoming HTLC amount').to.equal(
			1_000_500n
		);
		expect(failureData.readUInt16BE(8), 'zero-length channel_update').to.equal(
			0
		);
	});

	it('incorrect_cltv_expiry carries [outgoing cltv_expiry][u16 len=0]', function () {
		const { realScid } = installChannel(node);
		// Default forwarding delta is 40; 20 blocks of headroom is short.
		forward(realScid, 2_000_000n, 700_020, 1_000_000n, 700_000);

		const { failureCode, failureData } = decodedFailure();
		expect(failureCode).to.equal(INCORRECT_CLTV_EXPIRY);
		expect(failureData.length, '[u32][u16]').to.equal(6);
		// BOLT 4: "report the cltv_expiry of the outgoing HTLC" — the onion's
		// outgoing_cltv_value (700_000), NOT the incoming HTLC's 700_020.
		expect(failureData.readUInt32BE(0), 'outgoing cltv_expiry').to.equal(
			700_000
		);
		expect(failureData.readUInt16BE(4), 'zero-length channel_update').to.equal(
			0
		);
	});

	it('temporary_channel_failure carries [u16 len=0]', function () {
		const { realScid } = installChannel(node);
		// Amount and CLTV both fine; the onward addHtlc refusal (stubbed in
		// beforeEach) drives the temporary_channel_failure path.
		forward(realScid, 2_000_000n, 700_500, 1_000_000n, 700_000);

		const { failureCode, failureData } = decodedFailure();
		expect(failureCode).to.equal(TEMPORARY_CHANNEL_FAILURE);
		expect(failureData.length, '[u16]').to.equal(2);
		expect(failureData.readUInt16BE(0), 'zero-length channel_update').to.equal(
			0
		);
	});

	it('unknown_next_peer stays data-less (PERM, no defined fields)', function () {
		installChannel(node);
		// An SCID we never registered.
		forward(crypto.randomBytes(8), 2_000_000n, 700_500, 1_000_000n, 700_000);

		const { failureCode, failureData } = decodedFailure();
		expect(failureCode).to.equal(UNKNOWN_NEXT_PEER);
		expect(failureData.length).to.equal(0);
	});

	it('shapes every UPDATE-flagged code it may be asked for', function () {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const data = (code: number, fields?: object): Buffer | undefined =>
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(node as any).updateFlaggedFailureData(code, fields);

		expect(data(EXPIRY_TOO_SOON)!.length, 'expiry_too_soon [u16]').to.equal(2);
		expect(
			data(AMOUNT_BELOW_MINIMUM, { htlcMsat: 42n })!.length,
			'amount_below_minimum [u64][u16]'
		).to.equal(10);
		expect(
			data(AMOUNT_BELOW_MINIMUM, { htlcMsat: 42n })!.readBigUInt64BE(0)
		).to.equal(42n);
		expect(
			data(CHANNEL_DISABLED)!.length,
			'channel_disabled [u16 flags][u16]'
		).to.equal(4);
		// Codes without defined data must not grow any.
		expect(data(UNKNOWN_NEXT_PEER)).to.be.undefined;
		// Required fields must never silently default: a zeroed amount or expiry
		// would be a syntactically valid but semantically bogus BOLT failure.
		expect(() => data(FEE_INSUFFICIENT)).to.throw(/htlcMsat/);
		expect(() => data(AMOUNT_BELOW_MINIMUM)).to.throw(/htlcMsat/);
		expect(() => data(INCORRECT_CLTV_EXPIRY)).to.throw(/cltvExpiry/);
	});

	describe('outgoing cltv_expiry against our tip (issue #1009)', function () {
		const HEIGHT = 700_000;

		function atHeight(height: number): void {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(node as any).currentBlockHeight = height;
		}

		function expectExpiryTooSoon(): void {
			const { failureCode, failureData } = decodedFailure();
			expect(failureCode).to.equal(EXPIRY_TOO_SOON);
			expect(failureData.length, '[u16]').to.equal(2);
			expect(
				failureData.readUInt16BE(0),
				'zero-length channel_update'
			).to.equal(0);
			expect(addHtlcCalls, 'never offered downstream').to.equal(0);
		}

		it('fails an outgoing expiry already in the past with expiry_too_soon', function () {
			const { realScid } = installChannel(node);
			atHeight(HEIGHT);
			// The attack shape: the incoming HTLC clears our 40-block delta
			// with room to spare, and the onion's outgoing_cltv_value is a
			// thousand blocks stale. Before the fix this was relayed as is.
			forward(realScid, 2_000_000n, HEIGHT + 41, 1_000_000n, HEIGHT - 1000);
			expectExpiryTooSoon();
		});

		it('fails an outgoing expiry within OUTGOING_CLTV_REJECT_DELTA of the tip', function () {
			const { realScid } = installChannel(node);
			atHeight(HEIGHT);
			forward(realScid, 2_000_000n, HEIGHT + 500, 1_000_000n, HEIGHT + 3);
			expectExpiryTooSoon();
		});

		it('relays an outgoing expiry one block past the reject delta', function () {
			const { realScid } = installChannel(node);
			atHeight(HEIGHT);
			forward(realScid, 2_000_000n, HEIGHT + 500, 1_000_000n, HEIGHT + 4);
			// Reached the (stubbed, refusing) onward add: the refusal path,
			// not the expiry check, is what failed it.
			expect(addHtlcCalls, 'offered downstream').to.equal(1);
			expect(decodedFailure().failureCode).to.equal(TEMPORARY_CHANNEL_FAILURE);
		});

		it('is skipped while our tip is unknown', function () {
			const { realScid } = installChannel(node);
			atHeight(0);
			forward(realScid, 2_000_000n, HEIGHT + 41, 1_000_000n, HEIGHT - 1000);
			expect(addHtlcCalls, 'offered downstream').to.equal(1);
			expect(decodedFailure().failureCode).to.equal(TEMPORARY_CHANNEL_FAILURE);
		});

		it('answers invalid_onion_blinding on a blinded hop, before the onward add', function () {
			const { realScid } = installChannel(node);
			atHeight(HEIGHT);
			// We are the introduction node of a one-relay blinded path whose
			// payment_relay is ours to invert: the outgoing expiry is the
			// incoming one minus the relay delta, so the incoming expiry
			// chooses which side of the reject delta the forward lands on.
			const relay = {
				cltvExpiryDelta: 40,
				feeBaseMsat: 5_000,
				feeProportionalMillionths: 0
			};
			const path = constructBlindedPath(
				crypto.randomBytes(32),
				[Buffer.from(node.getNodeId(), 'hex')],
				[
					{
						shortChannelId: realScid,
						paymentRelay: relay,
						paymentConstraints: {
							maxCltvExpiry: 10_000_000,
							htlcMinimumMsat: 0n
						}
					}
				]
			);
			const blinded = {
				blindingPoint: path.blindingPoint,
				encryptedRecipientData: path.blindedHops[0].encryptedData
			};

			// Outgoing HEIGHT + 3: refused, and the blinded role converts the
			// cause into invalid_onion_blinding rather than leaking it.
			forward(realScid, 2_000_000n, HEIGHT + 43, 0n, 0, blinded);
			expect(addHtlcCalls, 'never offered downstream').to.equal(0);
			expect(decodedFailure().failureCode).to.equal(INVALID_ONION_BLINDING);

			// Control, outgoing HEIGHT + 4: the same path reaches the add.
			failHtlcCalls.length = 0;
			forward(realScid, 2_000_000n, HEIGHT + 44, 0n, 0, blinded);
			expect(addHtlcCalls, 'offered downstream').to.equal(1);
			expect(decodedFailure().failureCode).to.equal(INVALID_ONION_BLINDING);
		});

		it('re-judges a forward at placement, after a hold, without touching the linkage', function () {
			// A JIT part held for a splice, or a held forward released late,
			// reaches forwardHtlcOnto blocks after it was judged.
			const { channelId } = installChannel(node);
			const codes: number[] = [];
			const part = (forwardCltv: number): object => ({
				inChannelId: crypto.randomBytes(32),
				inHtlcId: 9n,
				paymentHash: crypto.randomBytes(32),
				forwardAmountMsat: 1_000_000n,
				incomingAmountMsat: 2_000_000n,
				forwardCltv,
				incomingCltvExpiry: HEIGHT + 500,
				nextPacket: {
					version: 0,
					ephemeralKey: crypto.randomBytes(33),
					routingInfo: Buffer.alloc(ROUTING_INFO_LENGTH),
					hmac: crypto.randomBytes(32)
				},
				failIncoming: (code: number): boolean => {
					codes.push(code);
					return true;
				}
			});
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const place = (p: object): string =>
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				(node as any).forwardHtlcOnto(channelId, p);

			atHeight(HEIGHT);
			expect(place(part(HEIGHT + 3))).to.equal('refused');
			expect(codes).to.deep.equal([EXPIRY_TOO_SOON]);
			expect(addHtlcCalls, 'never offered downstream').to.equal(0);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect((node as any).forwardedHtlcs.size, 'no linkage row').to.equal(0);

			expect(place(part(HEIGHT + 4))).to.equal('refused');
			expect(addHtlcCalls, 'offered downstream').to.equal(1);
			expect(codes).to.deep.equal([EXPIRY_TOO_SOON, TEMPORARY_CHANNEL_FAILURE]);
		});
	});
});
