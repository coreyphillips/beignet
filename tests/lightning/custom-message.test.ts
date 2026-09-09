/**
 * Beignet custom peer messaging (issue #546, LFBW port #532 workstream 1E).
 *
 * One odd wire type (44069) carries [u16 version][u16 subtype][payload].
 * The envelope codec round-trips and bounds its fields; the node surfaces
 * every decodable envelope (unknown subtypes and versions included) on the
 * 'custom-message' event, drops undecodable ones without disconnecting, and
 * never lets the custom type fall through to the channel manager.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BEIGNET_CUSTOM_MAX_PAYLOAD,
	BEIGNET_CUSTOM_PROTOCOL_VERSION,
	BeignetCustomSubtype,
	encodeCustomMessage,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import {
	SPLICE_CONFLICT_LENGTH,
	SPLICE_CONFLICT_REASON_MAX,
	decodeSpliceConflict,
	decodeSpliceConflictAck,
	encodeSpliceConflict,
	encodeSpliceConflictAck
} from '../../src/lightning/message/splice-conflict';

const PEER = '02' + 'ab'.repeat(32);

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
	return new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(crypto.randomBytes(32)),
		perCommitmentSeed: crypto.randomBytes(32),
		fundingPrivkey: crypto.randomBytes(32)
	});
}

describe('Custom message codec (type 44069)', () => {
	it('round-trips version, subtype and payload', () => {
		const payload = crypto.randomBytes(64);
		const wire = encodeCustomMessage(
			BeignetCustomSubtype.JIT_RECEIVE_AUTHORIZATION,
			payload
		);
		const decoded = decodeCustomMessage(wire);
		expect(decoded.version).to.equal(BEIGNET_CUSTOM_PROTOCOL_VERSION);
		expect(decoded.subtype).to.equal(
			BeignetCustomSubtype.JIT_RECEIVE_AUTHORIZATION
		);
		expect(decoded.payload.equals(payload)).to.equal(true);
	});

	it('round-trips an empty payload and the u16 extremes', () => {
		const wire = encodeCustomMessage(0xffff, Buffer.alloc(0), 0xffff);
		const decoded = decodeCustomMessage(wire);
		expect(decoded.subtype).to.equal(0xffff);
		expect(decoded.version).to.equal(0xffff);
		expect(decoded.payload.length).to.equal(0);
	});

	it('refuses out-of-range or fractional fields at the boundary', () => {
		for (const bad of [-1, 0x1_0000, 1.5]) {
			expect(() => encodeCustomMessage(bad, Buffer.alloc(0))).to.throw(
				/subtype out of range/
			);
			expect(() => encodeCustomMessage(1, Buffer.alloc(0), bad)).to.throw(
				/version out of range/
			);
		}
	});

	it('refuses an envelope shorter than its header', () => {
		expect(() => decodeCustomMessage(Buffer.alloc(3))).to.throw(/too short/);
	});

	it('caps the payload at the BOLT 8 frame minus type and header, exactly', () => {
		// 65535 - 2 (wire type) - 4 (envelope header): one byte more would be
		// rejected deep in the transport cipher AFTER the caller thinks it
		// sent (issue #546 review); it must fail here, named.
		const max = encodeCustomMessage(
			1,
			Buffer.alloc(BEIGNET_CUSTOM_MAX_PAYLOAD)
		);
		expect(decodeCustomMessage(max).payload.length).to.equal(
			BEIGNET_CUSTOM_MAX_PAYLOAD
		);
		expect(BEIGNET_CUSTOM_MAX_PAYLOAD).to.equal(65_529);
		expect(() =>
			encodeCustomMessage(1, Buffer.alloc(BEIGNET_CUSTOM_MAX_PAYLOAD + 1))
		).to.throw(/exceeds the 65529-byte maximum/);
	});
});

describe('LightningNode custom message surface (issue #546)', () => {
	it('surfaces a decodable envelope on custom-message, unknown subtypes included', () => {
		const node = makeNode();
		try {
			const seen: Array<{
				peerPubkey: string;
				version: number;
				subtype: number;
				payload: Buffer;
			}> = [];
			node.on('custom-message', (m) => seen.push(m));
			const payload = Buffer.from('jit intent');
			node.handlePeerMessage(
				PEER,
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				encodeCustomMessage(BeignetCustomSubtype.JIT_RECEIVE_ACK, payload)
			);
			// Unknown subtype and future version both ride the event untouched:
			// tolerating them is what lets protocols evolve without a flag day.
			node.handlePeerMessage(
				PEER,
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				encodeCustomMessage(40_000, Buffer.alloc(1, 9), 7)
			);
			expect(seen).to.have.length(2);
			expect(seen[0].peerPubkey).to.equal(PEER);
			expect(seen[0].subtype).to.equal(BeignetCustomSubtype.JIT_RECEIVE_ACK);
			expect(seen[0].version).to.equal(BEIGNET_CUSTOM_PROTOCOL_VERSION);
			expect(seen[0].payload.equals(payload)).to.equal(true);
			expect(seen[1].subtype).to.equal(40_000);
			expect(seen[1].version).to.equal(7);
		} finally {
			node.destroy();
		}
	});

	it('drops an undecodable envelope without throwing or emitting', () => {
		const node = makeNode();
		try {
			let events = 0;
			node.on('custom-message', () => events++);
			node.handlePeerMessage(
				PEER,
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				Buffer.alloc(2)
			);
			expect(events).to.equal(0);
		} finally {
			node.destroy();
		}
	});

	it('never lets the custom type fall through to the channel manager', () => {
		const node = makeNode();
		try {
			const manager = node.getChannelManager() as unknown as {
				handleMessage: (p: string, t: number, b: Buffer) => void;
			};
			const forwarded: number[] = [];
			const original = manager.handleMessage.bind(manager);
			manager.handleMessage = (p: string, t: number, b: Buffer): void => {
				forwarded.push(t);
				original(p, t, b);
			};
			node.handlePeerMessage(
				PEER,
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				encodeCustomMessage(1, Buffer.alloc(0))
			);
			expect(forwarded).to.have.length(0);
		} finally {
			node.destroy();
		}
	});

	it('a throwing listener is contained and labeled as its own failure', () => {
		// A listener error is the observer's bug: it must not be mislabeled
		// as a peer decode failure, and it must never escape into the
		// transport (issue #546 review).
		const node = makeNode();
		try {
			const logs: Array<{ action: string }> = [];
			node.on('log', (...args: unknown[]) =>
				logs.push(args[0] as { action: string })
			);
			node.on('custom-message', () => {
				throw new Error('observer bug');
			});
			expect(() =>
				node.handlePeerMessage(
					PEER,
					BEIGNET_CUSTOM_MESSAGE_TYPE,
					encodeCustomMessage(1, Buffer.alloc(0))
				)
			).to.not.throw();
			expect(
				logs.some((l) => l.action === 'custom_message_listener_failed'),
				'labeled as a listener failure'
			).to.equal(true);
			expect(
				logs.some((l) => l.action === 'custom_message_decode_failed'),
				'never labeled as a decode failure'
			).to.equal(false);
		} finally {
			node.destroy();
		}
	});

	it('a throwing log listener on a malformed envelope never reaches the transport', () => {
		const node = makeNode();
		try {
			node.on('log', () => {
				throw new Error('log observer bug');
			});
			expect(() =>
				node.handlePeerMessage(
					PEER,
					BEIGNET_CUSTOM_MESSAGE_TYPE,
					Buffer.alloc(2)
				)
			).to.not.throw();
		} finally {
			node.destroy();
		}
	});

	it('sendCustomMessage requires networking and emits the encoded envelope', () => {
		const node = makeNode();
		try {
			expect(() => node.sendCustomMessage(PEER, 1, Buffer.alloc(0))).to.throw(
				/Networking is not enabled/
			);
			// With a peer manager the envelope goes out on the odd type intact.
			const sent: Array<{ peer: string; type: number; payload: Buffer }> = [];
			(node as unknown as { peerManager: unknown }).peerManager = {
				sendToPeer: (peer: string, type: number, payload: Buffer): void => {
					sent.push({ peer, type, payload });
				}
			};
			const payload = Buffer.from('offer');
			node.sendCustomMessage(
				PEER,
				BeignetCustomSubtype.DIRECT_FUNDING_OFFER,
				payload
			);
			expect(sent).to.have.length(1);
			expect(sent[0].peer).to.equal(PEER);
			expect(sent[0].type).to.equal(BEIGNET_CUSTOM_MESSAGE_TYPE);
			const decoded = decodeCustomMessage(sent[0].payload);
			expect(decoded.subtype).to.equal(
				BeignetCustomSubtype.DIRECT_FUNDING_OFFER
			);
			expect(decoded.payload.equals(payload)).to.equal(true);
		} finally {
			(node as unknown as { peerManager: unknown }).peerManager = undefined;
			node.destroy();
		}
	});
});

describe('Splice conflict codecs (issue #760, subtypes 64/65)', () => {
	const channelId = crypto.randomBytes(32);
	const spliceTxid = crypto.randomBytes(32);
	const conflictTxid = crypto.randomBytes(32);

	it('round-trips SPLICE_CONFLICT at its fixed length', () => {
		const encoded = encodeSpliceConflict({
			channelId,
			spliceTxid,
			conflictTxid,
			inputIndex: 3
		});
		expect(encoded.length).to.equal(SPLICE_CONFLICT_LENGTH);
		expect(encoded.subarray(0, 32).equals(channelId)).to.equal(true);
		expect(encoded.subarray(32, 64).equals(spliceTxid)).to.equal(true);
		expect(encoded.subarray(64, 96).equals(conflictTxid)).to.equal(true);
		expect(encoded.readUInt16BE(96)).to.equal(3);
		const decoded = decodeSpliceConflict(encoded);
		expect(decoded.channelId.equals(channelId)).to.equal(true);
		expect(decoded.spliceTxid.equals(spliceTxid)).to.equal(true);
		expect(decoded.conflictTxid.equals(conflictTxid)).to.equal(true);
		expect(decoded.inputIndex).to.equal(3);
		expect(BeignetCustomSubtype.SPLICE_CONFLICT).to.equal(64);
		expect(BeignetCustomSubtype.SPLICE_CONFLICT_ACK).to.equal(65);
	});

	it('refuses a SPLICE_CONFLICT of the wrong length or a non-u16 index', () => {
		const good = encodeSpliceConflict({
			channelId,
			spliceTxid,
			conflictTxid,
			inputIndex: 0
		});
		expect(() => decodeSpliceConflict(good.subarray(0, 97))).to.throw(
			/98 bytes/
		);
		expect(() =>
			decodeSpliceConflict(Buffer.concat([good, Buffer.from([0])]))
		).to.throw(/98 bytes/);
		expect(() =>
			encodeSpliceConflict({
				channelId,
				spliceTxid,
				conflictTxid,
				inputIndex: 65536
			})
		).to.throw(/u16/);
		expect(() =>
			encodeSpliceConflict({
				channelId: Buffer.alloc(31),
				spliceTxid,
				conflictTxid,
				inputIndex: 0
			})
		).to.throw(/channelId must be 32 bytes/);
	});

	it('round-trips SPLICE_CONFLICT_ACK, agreed and refused, with a utf8 reason', () => {
		const agreed = decodeSpliceConflictAck(
			encodeSpliceConflictAck({
				channelId,
				spliceTxid,
				agreed: true,
				reason: ''
			})
		);
		expect(agreed.agreed).to.equal(true);
		expect(agreed.reason).to.equal('');
		expect(agreed.channelId.equals(channelId)).to.equal(true);
		expect(agreed.spliceTxid.equals(spliceTxid)).to.equal(true);
		const reason = 'not confirmed at depth on our chain view: caf\u00e9';
		const encoded = encodeSpliceConflictAck({
			channelId,
			spliceTxid,
			agreed: false,
			reason
		});
		expect(encoded.readUInt8(64)).to.equal(0);
		expect(encoded.readUInt16BE(65)).to.equal(
			Buffer.byteLength(reason, 'utf8')
		);
		const refused = decodeSpliceConflictAck(encoded);
		expect(refused.agreed).to.equal(false);
		expect(refused.reason).to.equal(reason);
	});

	it('bounds the ack reason and refuses a malformed ack', () => {
		const long = 'x'.repeat(SPLICE_CONFLICT_REASON_MAX + 1);
		expect(() =>
			encodeSpliceConflictAck({
				channelId,
				spliceTxid,
				agreed: false,
				reason: long
			})
		).to.throw(/exceeds/);
		const good = encodeSpliceConflictAck({
			channelId,
			spliceTxid,
			agreed: false,
			reason: 'behind'
		});
		// Truncated reason.
		expect(() =>
			decodeSpliceConflictAck(good.subarray(0, good.length - 1))
		).to.throw(/does not match its reason length/);
		// Trailing bytes.
		expect(() =>
			decodeSpliceConflictAck(Buffer.concat([good, Buffer.from([1])]))
		).to.throw(/does not match/);
		// agreed outside {0, 1}.
		const bad = Buffer.from(good);
		bad.writeUInt8(2, 64);
		expect(() => decodeSpliceConflictAck(bad)).to.throw(
			/agreed must be 0 or 1/
		);
		// A declared reason longer than the cap.
		const capped = Buffer.from(good);
		capped.writeUInt16BE(SPLICE_CONFLICT_REASON_MAX + 1, 65);
		expect(() => decodeSpliceConflictAck(capped)).to.throw(/exceeds/);
		expect(() => decodeSpliceConflictAck(good.subarray(0, 66))).to.throw(
			/at least 67 bytes/
		);
	});
});
