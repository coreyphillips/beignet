/**
 * BOLT 4 failure handling gaps (issue #1025).
 *
 * 1. A downstream update_fail_malformed_htlc on a forward is failed upstream
 *    with a failure we originate (its code, sha256 of the onion we forwarded),
 *    not relayed as a 4-byte synthetic blob no hop's key decrypts.
 * 2. An unparseable non-blinded onion is answered with
 *    update_fail_malformed_htlc and the BADONION code for its error class.
 * 3. An invalid update_add_htlc blinding point fails its HTLC, not the
 *    channel, and a throwing htlc:forwarded listener cannot skip the sibling
 *    HTLCs of its batch.
 * 4. An authenticated failure with failure_len < 2 is attributed to its hop.
 * 5. Hop payloads missing required fields, or with wrong-length fields, are
 *    invalid_onion_payload; the blinded relay enforces htlc_minimum_msat and
 *    refuses cleartext forwarding fields.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeBigSize } from '../../src/lightning/message/codec';
import {
	decodeUpdateAddHtlcMessage,
	encodeUpdateAddHtlcMessage
} from '../../src/lightning/message/channel-update';
import {
	constructOnionPacket,
	encodeOnionPacket,
	decodeOnionPacket
} from '../../src/lightning/onion/construct';
import {
	processOnionPacket,
	OnionProcessingError
} from '../../src/lightning/onion/process';
import {
	decodeHopPayload,
	InvalidOnionPayloadError
} from '../../src/lightning/onion/hop-payload';
import {
	computeSharedSecrets,
	deriveHopKeys,
	generateCipherStream
} from '../../src/lightning/onion/sphinx-crypto';
import {
	decryptFailureMessage,
	wrapFailureMessage
} from '../../src/lightning/onion/failures';
import {
	constructBlindedPath,
	deriveBlindedPrivkey
} from '../../src/lightning/onion/blinded-path';
import {
	IHopPayload,
	INVALID_ONION_BLINDING,
	INVALID_ONION_HMAC,
	INVALID_ONION_KEY,
	INVALID_ONION_PAYLOAD,
	INVALID_ONION_VERSION
} from '../../src/lightning/onion/types';

// ─── Node plumbing (the forward-fail-deferral fixture) ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`bolt4-failure-handling-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
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
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		htlcSafetyMargin: 6
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId())
			b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId())
			a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

function openSyncChannel(a: LightningNode, b: LightningNode): Buffer {
	const channel = a.openChannel(b.getNodeId(), 1_000_000n);
	const channelId = a.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	a.handleFundingConfirmed(channelId);
	b.handleFundingConfirmed(channelId);
	return channelId;
}

const HEIGHT = 800_000;

interface IFixture {
	alice: LightningNode;
	bob: LightningNode;
	inChannelId: Buffer;
	outChannelId: Buffer;
	inHtlcs: Map<string, IHtlcEntry>;
	outHtlcs: Map<string, IHtlcEntry>;
	failed: Array<{ channelId: string; htlcId: bigint; reason: Buffer }>;
	malformed: Array<{ htlcId: bigint; sha256OfOnion: Buffer; code: number }>;
	destroy: () => void;
}

/** Alice between Bob (inbound) and Carol (outbound), fails captured. */
function makeFixture(seedBase: number): IFixture {
	const alice = createNode(seedBase);
	const bob = createNode(seedBase + 1);
	const carol = createNode(seedBase + 2);
	connectNodes(alice, bob);
	connectNodes(alice, carol);
	const inChannelId = openSyncChannel(alice, bob);
	const outChannelId = openSyncChannel(alice, carol);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const a = alice as any;
	a.currentBlockHeight = HEIGHT;

	const failed: IFixture['failed'] = [];
	const malformed: IFixture['malformed'] = [];
	a.channelManager.failHtlc = (
		channelId: Buffer,
		htlcId: bigint,
		reason: Buffer
	): { ok: boolean } => {
		failed.push({ channelId: channelId.toString('hex'), htlcId, reason });
		return { ok: true };
	};
	a.channelManager.failMalformedHtlc = (
		_channelId: Buffer,
		htlcId: bigint,
		sha256OfOnion: Buffer,
		code: number
	): { ok: boolean } => {
		malformed.push({ htlcId, sha256OfOnion, code });
		return { ok: true };
	};

	return {
		alice,
		bob,
		inChannelId,
		outChannelId,
		inHtlcs: a.channelManager.getChannel(inChannelId).getFullState().htlcs,
		outHtlcs: a.channelManager.getChannel(outChannelId).getFullState().htlcs,
		failed,
		malformed,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
			carol.destroy();
		}
	};
}

function sha256(buf: Buffer): Buffer {
	return crypto.createHash('sha256').update(buf).digest();
}

/** The reason the channel layer surfaces for update_fail_malformed_htlc. */
function malformedReason(code: number): Buffer {
	const reason = Buffer.alloc(4);
	reason.writeUInt16BE(code, 0);
	return reason;
}

/** A 33-byte buffer with a point prefix that is not on the curve (x >= p). */
const NOT_A_POINT = Buffer.concat([
	Buffer.from([0x02]),
	Buffer.alloc(32, 0xff)
]);

function receivedEntry(
	id: bigint,
	paymentHash: Buffer,
	onion: Buffer,
	blindingPoint?: Buffer
): IHtlcEntry {
	return {
		id,
		amountMsat: 50_000n,
		paymentHash,
		cltvExpiry: HEIGHT + 500,
		onionRoutingPacket: onion,
		direction: HtlcDirection.RECEIVED,
		state: HtlcState.COMMITTED,
		...(blindingPoint ? { blindingPoint } : {})
	};
}

/** A one-hop onion to `nodeId` carrying `payload`, and its shared secret. */
function onionTo(
	nodeId: Buffer,
	payload: IHopPayload,
	paymentHash: Buffer
): { onion: Buffer; sharedSecret: Buffer } {
	const sessionKey = crypto.randomBytes(32);
	const packet = constructOnionPacket(
		sessionKey,
		[{ pubkey: nodeId, payload }],
		paymentHash
	);
	return {
		onion: encodeOnionPacket(packet),
		sharedSecret: computeSharedSecrets(sessionKey, [nodeId]).sharedSecrets[0]
	};
}

describe('BOLT 4 failure handling (issue #1025)', function () {
	this.timeout(10_000);

	describe('1. downstream update_fail_malformed_htlc on a forward', function () {
		/**
		 * Carol fails Alice's forward by update_fail_malformed_htlc, or when
		 * `forged`, by an update_fail_htlc whose reason has the same 4 bytes.
		 */
		function forwardFailedMalformed(
			seedBase: number,
			provisional: boolean,
			forged = false
		): {
			f: IFixture;
			inSecret: Buffer;
			forwardedOnion: Buffer;
		} {
			const f = makeFixture(seedBase);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const a = f.alice as any;
			const paymentHash = crypto.randomBytes(32);
			const forwardedOnion = crypto.randomBytes(1366);
			f.inHtlcs.set(
				'received-7',
				receivedEntry(7n, paymentHash, Buffer.alloc(1366))
			);
			f.outHtlcs.set('offered-7', {
				id: 7n,
				amountMsat: 49_000n,
				paymentHash,
				cltvExpiry: HEIGHT + 400,
				onionRoutingPacket: forwardedOnion,
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			const outKey = `${f.outChannelId.toString('hex')}:offered-7`;
			a.forwardedHtlcs.set(outKey, {
				inChannelId: f.inChannelId,
				inHtlcId: 7n
			});
			const inSecret = crypto.randomBytes(32);
			a.receivedHtlcSharedSecrets.set(
				`${f.inChannelId.toString('hex')}:7`,
				inSecret
			);
			const cm = a.channelManager;
			const channel = cm.getChannel(f.outChannelId);
			const actions = forged
				? channel.handleUpdateFailHtlc({
						channelId: f.outChannelId,
						id: 7n,
						reason: malformedReason(INVALID_ONION_HMAC)
				  })
				: channel.handleUpdateFailMalformedHtlc({
						channelId: f.outChannelId,
						id: 7n,
						sha256OfOnion: sha256(forwardedOnion),
						failureCode: INVALID_ONION_HMAC
				  });
			if (!provisional) {
				// The removal round has run.
				const entry = f.outHtlcs.get('offered-7')!;
				entry.removalLocallyRevoked = true;
				entry.removalRemoteCommitted = true;
			}
			cm.processActions(cm.getPeerForChannel(f.outChannelId), channel, actions);
			return { f, inSecret, forwardedOnion };
		}

		function expectOriginated(
			f: IFixture,
			inSecret: Buffer,
			forwardedOnion: Buffer
		): void {
			expect(f.failed.length, 'inbound failed once').to.equal(1);
			expect(f.failed[0].channelId).to.equal(f.inChannelId.toString('hex'));
			const decrypted = decryptFailureMessage([inSecret], f.failed[0].reason);
			expect(decrypted, 'the sender can decrypt it').to.not.be.null;
			expect(decrypted!.originIndex).to.equal(0);
			expect(decrypted!.failure.failureCode).to.equal(INVALID_ONION_HMAC);
			expect(
				decrypted!.failure.failureData.equals(sha256(forwardedOnion)),
				'data is sha256 of the onion we forwarded'
			).to.equal(true);
		}

		it('fails upstream with a failure we originate, not the wrapped 4-byte reason', function () {
			const { f, inSecret, forwardedOnion } = forwardFailedMalformed(
				700,
				false
			);
			expectOriginated(f, inSecret, forwardedOnion);
			// What used to go upstream: the synthetic reason XORed with our
			// stream, which no hop's key decrypts.
			expect(
				decryptFailureMessage(
					[inSecret],
					wrapFailureMessage(inSecret, malformedReason(INVALID_ONION_HMAC))
				)
			).to.be.null;
			f.destroy();
		});

		it('originates it before a deferral, so it survives the outgoing entry going away', function () {
			const { f, inSecret, forwardedOnion } = forwardFailedMalformed(710, true);
			expect(f.failed.length, 'held until the removal round ends').to.equal(0);
			// The settlement loop drops the entry when the removal completes.
			f.outHtlcs.delete('offered-7');
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(f.alice as any).drainForwardsAwaitingRemoval(f.outChannelId);
			expectOriginated(f, inSecret, forwardedOnion);
			f.destroy();
		});

		it('relays an update_fail_htlc of the same 4 bytes instead of vouching for it', function () {
			const { f, inSecret } = forwardFailedMalformed(715, false, true);
			expect(f.failed.length).to.equal(1);
			expect(
				f.failed[0].reason.equals(
					wrapFailureMessage(inSecret, malformedReason(INVALID_ONION_HMAC))
				),
				'wrapped as received, not a failure under our key'
			).to.equal(true);
			f.destroy();
		});
	});

	describe('2. unparseable non-blinded onion', function () {
		function incoming(
			seedBase: number,
			mutate: (onion: Buffer) => void
		): IFixture & { onion: Buffer } {
			const f = makeFixture(seedBase);
			const paymentHash = crypto.randomBytes(32);
			const { onion } = onionTo(
				Buffer.from(f.alice.getNodeId(), 'hex'),
				{ amountToForwardMsat: 1_000n, outgoingCltvValue: HEIGHT + 100 },
				paymentHash
			);
			mutate(onion);
			f.inHtlcs.set('received-9', receivedEntry(9n, paymentHash, onion));
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(f.alice as any).handleIncomingHtlc(
				f.inChannelId,
				9n,
				50_000n,
				paymentHash
			);
			return { ...f, onion };
		}

		function expectMalformed(
			f: IFixture & { onion: Buffer },
			code: number
		): void {
			expect(f.failed, 'no update_fail_htlc under a zero key').to.deep.equal(
				[]
			);
			expect(f.malformed.length).to.equal(1);
			expect(f.malformed[0].htlcId).to.equal(9n);
			expect(f.malformed[0].code).to.equal(code);
			expect(f.malformed[0].sha256OfOnion.equals(sha256(f.onion))).to.equal(
				true
			);
		}

		it('the BADONION codes carry PERM, as BOLT 4 defines them', function () {
			expect([
				INVALID_ONION_VERSION,
				INVALID_ONION_HMAC,
				INVALID_ONION_KEY
			]).to.deep.equal([0xc004, 0xc005, 0xc006]);
		});

		it('a bad HMAC is invalid_onion_hmac', function () {
			const f = incoming(720, (onion) => {
				onion[100] ^= 0x01;
			});
			expectMalformed(f, INVALID_ONION_HMAC);
			f.destroy();
		});

		it('an unknown version is invalid_onion_version', function () {
			const f = incoming(730, (onion) => {
				onion[0] = 1;
			});
			expectMalformed(f, INVALID_ONION_VERSION);
			f.destroy();
		});

		it('an ephemeral key that is not a point is invalid_onion_key', function () {
			const f = incoming(740, (onion) => {
				NOT_A_POINT.copy(onion, 1);
			});
			expectMalformed(f, INVALID_ONION_KEY);
			f.destroy();
		});

		it('a sound onion with an invalid payload is invalid_onion_payload under the sender key', function () {
			const f = makeFixture(750);
			const paymentHash = crypto.randomBytes(32);
			// A forward that lacks amt_to_forward and outgoing_cltv_value.
			const { onion, sharedSecret } = onionTo(
				Buffer.from(f.alice.getNodeId(), 'hex'),
				{
					amountToForwardMsat: 0n,
					outgoingCltvValue: 0,
					omitForwardAmounts: true,
					shortChannelId: crypto.randomBytes(8)
				},
				paymentHash
			);
			f.inHtlcs.set('received-9', receivedEntry(9n, paymentHash, onion));
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(f.alice as any).handleIncomingHtlc(
				f.inChannelId,
				9n,
				50_000n,
				paymentHash
			);
			expect(f.malformed).to.deep.equal([]);
			expect(f.failed.length).to.equal(1);
			const decrypted = decryptFailureMessage(
				[sharedSecret],
				f.failed[0].reason
			);
			expect(decrypted, 'the sender can decrypt it').to.not.be.null;
			expect(decrypted!.failure.failureCode).to.equal(INVALID_ONION_PAYLOAD);
			// [bigsize type=2][u16 offset=0]
			expect(decrypted!.failure.failureData.toString('hex')).to.equal('020000');
			f.destroy();
		});
	});

	describe('3. invalid update_add_htlc blinding point', function () {
		it('fails the HTLC with invalid_onion_blinding instead of throwing', function () {
			expect(() =>
				deriveBlindedPrivkey(NOT_A_POINT, crypto.randomBytes(32))
			).to.throw();
			const f = makeFixture(760);
			const paymentHash = crypto.randomBytes(32);
			const onion = crypto.randomBytes(1366);
			onion[0] = 0;
			f.inHtlcs.set(
				'received-9',
				receivedEntry(9n, paymentHash, onion, NOT_A_POINT)
			);
			expect(() =>
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				(f.alice as any).handleIncomingHtlc(
					f.inChannelId,
					9n,
					50_000n,
					paymentHash
				)
			).to.not.throw();
			expect(f.malformed.length).to.equal(1);
			expect(f.malformed[0].code).to.equal(INVALID_ONION_BLINDING);
			f.destroy();
		});

		it('the update_add_htlc decoder keeps a blinding point off the curve for the HTLC to fail', function () {
			const msg = {
				channelId: crypto.randomBytes(32),
				id: 1n,
				amountMsat: 1_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: HEIGHT,
				onionRoutingPacket: crypto.randomBytes(1366)
			};
			const valid = getPublicKey(crypto.randomBytes(32));
			expect(
				decodeUpdateAddHtlcMessage(
					encodeUpdateAddHtlcMessage({ ...msg, blindingPoint: valid })
				).blindingPoint?.equals(valid)
			).to.equal(true);
			// A decoder throw would fail the whole channel.
			expect(
				decodeUpdateAddHtlcMessage(
					encodeUpdateAddHtlcMessage({ ...msg, blindingPoint: NOT_A_POINT })
				).blindingPoint?.equals(NOT_A_POINT)
			).to.equal(true);
		});

		it('a throwing htlc:forwarded listener does not skip later HTLCs of the batch', function () {
			const f = makeFixture(770);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const cm = (f.alice as any).channelManager;
			const seen: bigint[] = [];
			const errors: string[] = [];
			cm.on('htlc:forwarded', (_c: Buffer, htlcId: bigint) => {
				seen.push(htlcId);
				if (htlcId === 1n) throw new Error('boom');
			});
			cm.on('error', (_c: Buffer, message: string) => errors.push(message));
			const forwarded = (htlcId: bigint): object => ({
				type: ChannelActionType.HTLC_FORWARDED,
				htlcId,
				amountMsat: 1_000n,
				paymentHash: crypto.randomBytes(32)
			});
			cm.processActions(f.bob.getNodeId(), cm.getChannel(f.inChannelId), [
				forwarded(1n),
				forwarded(2n)
			]);
			expect(seen).to.deep.equal([1n, 2n]);
			expect(errors.some((m) => /HTLC 1: boom/.test(m))).to.equal(true);
			f.destroy();
		});
	});

	describe('4. authenticated failure with failure_len < 2', function () {
		/** A failure from the hop owning `secret` whose plaintext is `lenAndPad`. */
		function authenticated(secret: Buffer, lenAndPad: Buffer): Buffer {
			const keys = deriveHopKeys(secret);
			const hmac = crypto
				.createHmac('sha256', keys.um)
				.update(lenAndPad)
				.digest();
			const inner = Buffer.concat([hmac, lenAndPad]);
			const stream = generateCipherStream(keys.ammag, inner.length);
			return Buffer.from(inner.map((b, i) => b ^ stream[i]));
		}

		it('attributes a zero failure_len to its hop with no code, without throwing', function () {
			const secrets = [crypto.randomBytes(32), crypto.randomBytes(32)];
			// Hop 1 authors it, hop 0 wraps it on the way back.
			const fromHop1 = wrapFailureMessage(
				secrets[0],
				authenticated(secrets[1], Buffer.alloc(260))
			);
			const result = decryptFailureMessage(secrets, fromHop1);
			expect(result).to.deep.equal({
				originIndex: 1,
				failure: { failureCode: 0, failureData: Buffer.alloc(0) }
			});
		});

		it('handles a failure_len past the message and a message too short to hold one', function () {
			const secret = crypto.randomBytes(32);
			const overlong = Buffer.alloc(260);
			overlong.writeUInt16BE(1000, 0);
			expect(
				decryptFailureMessage([secret], authenticated(secret, overlong))
			).to.deep.include({ originIndex: 0 });
			expect(
				decryptFailureMessage(
					[secret],
					authenticated(secret, Buffer.from([0x00]))
				)?.failure.failureCode
			).to.equal(0);
		});
	});

	describe('5. hop payload validation', function () {
		function stream(...records: Array<[number, Buffer]>): Buffer {
			const body = Buffer.concat(
				records.map(([type, value]) =>
					Buffer.concat([
						encodeBigSize(BigInt(type)),
						encodeBigSize(BigInt(value.length)),
						value
					])
				)
			);
			return Buffer.concat([encodeBigSize(BigInt(body.length)), body]);
		}

		function rejection(buf: Buffer): InvalidOnionPayloadError {
			try {
				decodeHopPayload(buf, 0);
			} catch (err) {
				expect(err).to.be.instanceOf(InvalidOnionPayloadError);
				return err as InvalidOnionPayloadError;
			}
			throw new Error('decoded');
		}

		const AMT: [number, Buffer] = [2, Buffer.from([0x64])];
		const CLTV: [number, Buffer] = [4, Buffer.from([0x0a])];
		const ERD: [number, Buffer] = [10, crypto.randomBytes(40)];

		it('a cleartext payload must carry amt_to_forward and outgoing_cltv_value', function () {
			const scid: [number, Buffer] = [6, crypto.randomBytes(8)];
			expect(rejection(stream(CLTV, scid)).tlvType).to.equal(2);
			expect(rejection(stream(AMT, scid)).tlvType).to.equal(4);
			const { payload } = decodeHopPayload(stream(AMT, CLTV, scid), 0);
			expect(payload.amountToForwardMsat).to.equal(100n);
			expect(payload.omitForwardAmounts).to.equal(undefined);
		});

		it('a blinded payload carries both amount fields or neither', function () {
			expect(rejection(stream(AMT, ERD)).tlvType).to.equal(4);
			const { payload } = decodeHopPayload(stream(ERD), 0);
			expect(payload.omitForwardAmounts).to.equal(true);
			expect(
				decodeHopPayload(stream(AMT, CLTV, ERD), 0).payload.omitForwardAmounts
			).to.equal(undefined);
		});

		it('names the record and its offset for a wrong-length field', function () {
			// AMT and CLTV are 3 bytes each on the wire, so type 6 starts at 6.
			const scid = rejection(stream(AMT, CLTV, [6, crypto.randomBytes(7)]));
			expect([scid.tlvType, scid.offset]).to.deep.equal([6, 6]);
			const data = rejection(stream(AMT, CLTV, [8, crypto.randomBytes(31)]));
			expect([data.tlvType, data.offset]).to.deep.equal([8, 6]);
			const point = rejection(stream(AMT, CLTV, [12, crypto.randomBytes(32)]));
			expect([point.tlvType, point.offset]).to.deep.equal([12, 6]);
		});

		it('processOnionPacket returns the shared secret with an invalid payload', function () {
			const nodeKey = crypto.randomBytes(32);
			const paymentHash = crypto.randomBytes(32);
			const { onion, sharedSecret } = onionTo(
				getPublicKey(nodeKey),
				{
					amountToForwardMsat: 0n,
					outgoingCltvValue: 0,
					omitForwardAmounts: true,
					shortChannelId: crypto.randomBytes(8)
				},
				paymentHash
			);
			try {
				processOnionPacket(decodeOnionPacket(onion), nodeKey, paymentHash);
				expect.fail('processed');
			} catch (err) {
				expect(err).to.be.instanceOf(OnionProcessingError);
				const e = err as OnionProcessingError;
				expect(e.failureCode).to.equal(INVALID_ONION_PAYLOAD);
				expect(e.sharedSecret?.equals(sharedSecret)).to.equal(true);
				expect(e.failureData.toString('hex')).to.equal('020000');
			}
		});

		describe('blinded relay', function () {
			let node: LightningNode;
			let adds: number;
			let failures: Buffer[];
			let outScid: Buffer;

			beforeEach(function () {
				node = createNode(780);
				adds = 0;
				failures = [];
				outScid = crypto.randomBytes(8);
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const n = node as any;
				n.scidToChannelId.set(outScid.toString('hex'), crypto.randomBytes(32));
				n.channelManager.addHtlc = (): { ok: boolean; error: string } => {
					adds++;
					return { ok: false, error: 'refused' };
				};
				n.channelManager.failHtlc = (
					_c: Buffer,
					_id: bigint,
					reason: Buffer
				): { ok: boolean } => {
					failures.push(reason);
					return { ok: true };
				};
			});

			afterEach(function () {
				node.destroy();
			});

			/** We are the introduction node; the relay pays 5000 msat base. */
			function relay(
				htlcMinimumMsat: bigint,
				payload: Partial<IHopPayload> = {}
			): number {
				const path = constructBlindedPath(
					crypto.randomBytes(32),
					[Buffer.from(node.getNodeId(), 'hex')],
					[
						{
							shortChannelId: outScid,
							paymentRelay: {
								cltvExpiryDelta: 40,
								feeBaseMsat: 5_000,
								feeProportionalMillionths: 0
							},
							paymentConstraints: {
								maxCltvExpiry: 10_000_000,
								htlcMinimumMsat
							}
						}
					]
				);
				const sharedSecret = crypto.randomBytes(32);
				failures.length = 0;
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				(node as any).handleForwardHtlc(
					crypto.randomBytes(32),
					0n,
					crypto.randomBytes(32),
					{
						hopPayload: {
							amountToForwardMsat: 0n,
							outgoingCltvValue: 0,
							omitForwardAmounts: true,
							blindingPoint: path.blindingPoint,
							encryptedRecipientData: path.blindedHops[0].encryptedData,
							...payload
						},
						nextPacket: decodeOnionPacket(crypto.randomBytes(1366)),
						sharedSecret
					},
					2_000_000n,
					HEIGHT + 500
				);
				expect(failures.length).to.equal(1);
				const decrypted = decryptFailureMessage([sharedSecret], failures[0]);
				return decrypted!.failure.failureCode;
			}

			it('refuses an incoming amount below payment_constraints.htlc_minimum_msat', function () {
				expect(relay(2_000_001n)).to.equal(INVALID_ONION_BLINDING);
				expect(adds, 'never offered downstream').to.equal(0);
				// At the minimum the forward reaches the (refusing) onward add.
				relay(2_000_000n);
				expect(adds).to.equal(1);
			});

			it('refuses cleartext forwarding fields in a blinded intermediate payload', function () {
				const withAmounts = relay(0n, {
					amountToForwardMsat: 1_000n,
					outgoingCltvValue: HEIGHT,
					omitForwardAmounts: undefined
				});
				const withScid = relay(0n, { shortChannelId: outScid });
				const withSecret = relay(0n, { paymentSecret: crypto.randomBytes(32) });
				const withTotal = relay(0n, { totalAmountMsat: 1_000n });
				expect([withAmounts, withScid, withSecret, withTotal]).to.deep.equal([
					INVALID_ONION_BLINDING,
					INVALID_ONION_BLINDING,
					INVALID_ONION_BLINDING,
					INVALID_ONION_BLINDING
				]);
				expect(adds, 'never offered downstream').to.equal(0);
			});
		});
	});
});
