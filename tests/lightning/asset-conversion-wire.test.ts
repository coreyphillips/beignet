/**
 * #2151 Step 3a, contract tests 1 (the splice TLV) and 9 (the envelope).
 * Members that Step 3a adds are read through helpers/conversion-modules.ts,
 * so on a tree without them each test fails on its own.
 */
import { expect } from 'chai';
import { createHash } from 'crypto';
import { Transaction } from 'bitcoinjs-lib';
import { AssetOpeningSession } from '../../src/lightning/channel/asset-opening-session';
import {
	ChannelManager,
	type IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from '../../src/lightning/features/asset-opening';
import {
	AssetOpenObjectReceiver,
	decodeAssetOpenFrame,
	encodeAssetOpenFrame,
	type IAssetOpenFrame
} from '../../src/lightning/message/asset-open';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import * as splice from '../../src/lightning/message/splice';
import { decodeTlvStream } from '../../src/lightning/message/tlv';
import type { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	completeRecoveryHost,
	CONVERSION_HOST_KEYS
} from './helpers/asset-conversion-node';
import { plainTypePair, scratch } from './helpers/channel-type-pairs';
import { member } from './helpers/conversion-modules';

type Conversion = { termsDigest: Buffer; targetType: Buffer };
type InitV = splice.ISpliceMessage & { conversion?: Conversion };
type AckV = splice.ISpliceAckMessage & { conversion?: Conversion };
const encodeInit = splice.encodeSpliceMessage as (m: InitV) => Buffer;
const decodeInit = splice.decodeSpliceMessage as (p: Buffer) => InitV;
const encodeAck = splice.encodeSpliceAckMessage as (m: AckV) => Buffer;
const decodeAck = splice.decodeSpliceAckMessage as (p: Buffer) => AckV;

const sha = (...parts: Buffer[]): Buffer =>
	createHash('sha256').update(Buffer.concat(parts)).digest();
const hex = (s: string): Buffer => Buffer.from(s, 'hex');

// ---- Test 1 vectors (section 2), built by hand from the wire layout ----

const CHANNEL = 'a1'.repeat(32);
const INIT_PUBKEY =
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const ACK_PUBKEY =
	'02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
const DIGEST = 'd1'.repeat(32);
const PLAIN_TYPE = '0100000000000000000000';
/** channel_id, -25000 sat, 2500 sat/kw, locktime 600000, funding key. */
const INIT_FIXED =
	CHANNEL + 'ffffffffffff9e58' + '000009c4' + '000927c0' + INIT_PUBKEY;
/** channel_id, +12000 sat, funding key. */
const ACK_FIXED = CHANNEL + '0000000000002ee0' + ACK_PUBKEY;
/** Type 65537, length 2, depth 3. */
const LOCK_DEPTH_3 = 'fe00010001' + '02' + '0003';
/** Type 65540 (BigSize fe00010004), BigSize length, digest, then the type. */
const CONVERSION_TO_PLAIN = 'fe00010004' + '2b' + DIGEST + PLAIN_TYPE;
const CONVERSION_TO_ASSET =
	'fe00010004' + 'fd011e' + DIGEST + ASSET_SPLICE_RECOVERY_TYPE_HEX;

const targets = [
	{ name: 'plain', type: PLAIN_TYPE, tlv: CONVERSION_TO_PLAIN },
	{
		name: 'the recovery asset type',
		type: ASSET_SPLICE_RECOVERY_TYPE_HEX,
		tlv: CONVERSION_TO_ASSET
	}
];

/** sha256 of each pinned vector, so the hand-built hex itself is fixed. */
const VECTOR_HASHES: Record<string, string> = {
	'splice_init to plain with lock depth 3':
		'1d2820c2f868ddddb7a973bcdd476c17371066b78ab681f3f7059d3525db1825',
	'splice_ack to plain with lock depth 3':
		'88eb03e60ed833e652620d643ad09d930f2ac2f1e889ba471ea310a5a2215093',
	'splice_init to plain':
		'e4d8aa71e08b6c1d48e0174ddb80b3303d09eded84bfba42ad0ba0a2c542fddb',
	'splice_ack to plain':
		'd9e4656f28c5db695c963ca3525339bb682db8eb704f208c2acd31f50f6c47a1',
	'splice_init to the recovery asset type with lock depth 3':
		'8ce6e01d28c5589225182ce23bda961a347521e749e6828305e5367cf638ecb4',
	'splice_ack to the recovery asset type with lock depth 3':
		'2a5df9d5acc8aa74a06a57f1451184efb24af1934d63deed3a1cc33f2616d20f',
	'splice_init to the recovery asset type':
		'6531a0163cce06bfb9a488434e9899262a48699e501a3a62e3068b3724f2f6b5',
	'splice_ack to the recovery asset type':
		'557c8a11249eb2fc496b55b4be816d1e4892904a4b8f2d8ca27acd792f72ada7'
};

interface IVector {
	label: string;
	kind: 'init' | 'ack';
	hex: string;
	lockDepth?: number;
	targetType: string;
}

function vectors(): IVector[] {
	const out: IVector[] = [];
	for (const t of targets)
		for (const depth of [3, undefined]) {
			const tlvs = (depth ? LOCK_DEPTH_3 : '') + t.tlv;
			out.push(
				{
					label: `splice_init to ${t.name}${depth ? ' with lock depth 3' : ''}`,
					kind: 'init',
					hex: INIT_FIXED + tlvs,
					lockDepth: depth,
					targetType: t.type
				},
				{
					label: `splice_ack to ${t.name}${depth ? ' with lock depth 3' : ''}`,
					kind: 'ack',
					hex: ACK_FIXED + tlvs,
					lockDepth: depth,
					targetType: t.type
				}
			);
		}
	return out;
}

function message(v: IVector): InitV | AckV {
	const conversion = {
		termsDigest: hex(DIGEST),
		targetType: hex(v.targetType)
	};
	return v.kind === 'init'
		? {
				channelId: hex(CHANNEL),
				relativeSatoshis: -25000n,
				fundingFeeratePerkw: 2500,
				locktime: 600000,
				fundingPubkey: hex(INIT_PUBKEY),
				...(v.lockDepth !== undefined && { lockDepth: v.lockDepth }),
				conversion
		  }
		: {
				channelId: hex(CHANNEL),
				relativeSatoshis: 12000n,
				fundingPubkey: hex(ACK_PUBKEY),
				...(v.lockDepth !== undefined && { lockDepth: v.lockDepth }),
				conversion
		  };
}

const encodeAny = (v: IVector, m: InitV | AckV): Buffer =>
	v.kind === 'init' ? encodeInit(m as InitV) : encodeAck(m as AckV);
const decodeAny = (v: IVector, raw: Buffer): InitV | AckV =>
	v.kind === 'init' ? decodeInit(raw) : decodeAck(raw);
const fixedLength = (v: IVector): number => (v.kind === 'init' ? 81 : 73);
const tlvTypes = (raw: Buffer, offset: number): bigint[] =>
	decodeTlvStream(raw, offset).records.map((r) => r.type);

describe('Asset conversion splice TLV (#2151 step 3a, test 1)', function () {
	it('pins the hand-built vectors by hash', () => {
		expect(ASSET_SPLICE_RECOVERY_TYPE_HEX.length / 2).to.equal(254);
		expect(
			Object.fromEntries(
				vectors().map((v) => [v.label, sha(hex(v.hex)).toString('hex')])
			)
		).to.deep.equal(VECTOR_HASHES);
	});

	it('names the TLV 65540, even, in the experimental range', () => {
		const tlv: number = member(
			splice,
			'ASSET_CONVERSION_TLV',
			'message/splice'
		);
		expect(tlv).to.equal(65540);
		expect(tlv % 2).to.equal(0);
		expect(tlv).to.be.greaterThan(65537);
	});

	for (const v of vectors())
		it(`encodes ${v.label} to the pinned bytes and decodes it back`, () => {
			const raw = encodeAny(v, message(v));
			expect(raw.toString('hex')).to.equal(v.hex);
			const back = decodeAny(v, hex(v.hex));
			expect(back.conversion, 'decoded conversion').to.not.equal(undefined);
			expect(back.conversion!.termsDigest.toString('hex')).to.equal(DIGEST);
			expect(back.conversion!.targetType.toString('hex')).to.equal(
				v.targetType
			);
			expect(back.lockDepth).to.equal(v.lockDepth);
			expect(encodeAny(v, back).toString('hex')).to.equal(v.hex);
		});

	for (const v of vectors())
		it(`a reader with the old known set refuses ${v.label}`, () => {
			expect(() =>
				decodeTlvStream(hex(v.hex), fixedLength(v), new Set([2n, 65537n]))
			).to.throw('Unknown required TLV type: 65540');
		});

	it('writes TLVs in ascending type order, with and without a lock depth', () => {
		const conversion = {
			termsDigest: hex(DIGEST),
			targetType: hex(PLAIN_TYPE)
		};
		const base = {
			channelId: hex(CHANNEL),
			relativeSatoshis: 1n,
			fundingFeeratePerkw: 253,
			locktime: 0,
			fundingPubkey: hex(INIT_PUBKEY)
		};
		const cases: [InitV, bigint[]][] = [
			[{ ...base, conversion }, [65540n]],
			[{ ...base, lockDepth: 3, conversion }, [65537n, 65540n]],
			[{ ...base, requireConfirmedInputs: true, conversion }, [2n, 65540n]],
			[
				{ ...base, requireConfirmedInputs: true, lockDepth: 6, conversion },
				[2n, 65537n, 65540n]
			]
		];
		for (const [m, order] of cases) {
			expect(tlvTypes(encodeInit(m), 81)).to.deep.equal(order);
			const ack: AckV = {
				channelId: m.channelId,
				relativeSatoshis: m.relativeSatoshis,
				fundingPubkey: hex(ACK_PUBKEY),
				...(m.requireConfirmedInputs && { requireConfirmedInputs: true }),
				...(m.lockDepth !== undefined && { lockDepth: m.lockDepth }),
				conversion
			};
			expect(tlvTypes(encodeAck(ack), 73)).to.deep.equal(order);
		}
	});

	it('refuses to encode a digest of another length or an empty type', () => {
		const base = {
			channelId: hex(CHANNEL),
			relativeSatoshis: 0n,
			fundingFeeratePerkw: 253,
			locktime: 0,
			fundingPubkey: hex(INIT_PUBKEY)
		};
		const bad: Conversion[] = [
			{ termsDigest: Buffer.alloc(31, 1), targetType: hex(PLAIN_TYPE) },
			{ termsDigest: Buffer.alloc(33, 1), targetType: hex(PLAIN_TYPE) },
			{ termsDigest: Buffer.alloc(0), targetType: hex(PLAIN_TYPE) },
			{ termsDigest: Buffer.alloc(32, 1), targetType: Buffer.alloc(0) }
		];
		for (const conversion of bad) {
			expect(() => encodeInit({ ...base, conversion })).to.throw(
				'asset_conversion needs a 32-byte digest and a channel type'
			);
			expect(() =>
				encodeAck({
					channelId: base.channelId,
					relativeSatoshis: 0n,
					fundingPubkey: hex(ACK_PUBKEY),
					conversion
				})
			).to.throw('asset_conversion needs a 32-byte digest and a channel type');
		}
	});

	it('refuses to decode a value shorter than 33 bytes, and does not judge the type', () => {
		for (const length of [0, 1, 31, 32]) {
			const value = Buffer.alloc(length, 0xd1).toString('hex');
			const tlv = 'fe00010004' + length.toString(16).padStart(2, '0') + value;
			expect(
				() => decodeInit(hex(INIT_FIXED + tlv)),
				`init ${length}`
			).to.throw(
				'asset_conversion must carry a terms digest and a channel type'
			);
			expect(() => decodeAck(hex(ACK_FIXED + tlv)), `ack ${length}`).to.throw(
				'asset_conversion must carry a terms digest and a channel type'
			);
		}
		// 33 bytes: a digest and a one-byte type the codec does not judge.
		const odd = 'fe00010004' + '21' + DIGEST + 'ff';
		const init = decodeInit(hex(INIT_FIXED + odd));
		expect(init.conversion!.targetType.toString('hex')).to.equal('ff');
		const ack = decodeAck(hex(ACK_FIXED + odd));
		expect(ack.conversion!.termsDigest.toString('hex')).to.equal(DIGEST);
	});

	it("keeps today's bytes and decoded shape for splice messages without the TLV", () => {
		const init: InitV = {
			channelId: hex(CHANNEL),
			relativeSatoshis: -25000n,
			fundingFeeratePerkw: 2500,
			locktime: 600000,
			fundingPubkey: hex(INIT_PUBKEY),
			lockDepth: 3
		};
		expect(encodeInit(init).toString('hex')).to.equal(
			INIT_FIXED + LOCK_DEPTH_3
		);
		expect(
			encodeInit({ ...init, lockDepth: undefined }).toString('hex')
		).to.equal(INIT_FIXED);
		const ack: AckV = {
			channelId: hex(CHANNEL),
			relativeSatoshis: 12000n,
			fundingPubkey: hex(ACK_PUBKEY),
			lockDepth: 3
		};
		expect(encodeAck(ack).toString('hex')).to.equal(ACK_FIXED + LOCK_DEPTH_3);
		expect(decodeInit(hex(INIT_FIXED + LOCK_DEPTH_3)).conversion).to.equal(
			undefined
		);
		expect(decodeAck(hex(ACK_FIXED)).conversion).to.equal(undefined);
		// 65538 stays an unknown even type (splice-lock-depth.test.ts keeps it).
		expect(() => decodeInit(hex(INIT_FIXED + 'fe00010002' + '00'))).to.throw(
			'Unknown required TLV type: 65538'
		);
	});
});

// ---- Test 9 (section 8): the envelope ----

const TERMS = 'conversion_terms' as IAssetOpenFrame['phase'];
const REPLY = 'conversion_reply' as IAssetOpenFrame['phase'];
const CHUNK = 32 * 1024;
type ReceiverPhase = ConstructorParameters<typeof AssetOpenObjectReceiver>[1];

/** Frames of phases 0 to 6, captured on e29bb788. */
const GOLDEN: [IAssetOpenFrame['phase'], string][] = [
	[
		'layout',
		'01001010101010101010101010101010101010101010101010101010101010101010dd471ebdb76a68d905718a59c879fab387744f122f40c5ba4850b203876372a6000000070000000070686173652d30'
	],
	[
		'authorization',
		'010111111111111111111111111111111111111111111111111111111111111111110310edb6344182b0448624fbae1eab6bee88ca6552e577095c063216f57ca868000000070000000070686173652d31'
	],
	[
		'final',
		'01021212121212121212121212121212121212121212121212121212121212121212faab8e0c10b71ad285a706fcf8c1f96c7e15ce3e1d3607c61767af3778a304ea000000070000000070686173652d32'
	],
	[
		'exit',
		'0103131313131313131313131313131313131313131313131313131313131313131368e32fdc2a964e0693f1dd753e5a59d9d570ae8a47a03e9f2c23f0cd5863b3af000000070000000070686173652d33'
	],
	[
		'layout_ack',
		'0104141414141414141414141414141414141414141414141414141414141414141424242424242424242424242424242424242424242424242424242424242424240000000000000000'
	],
	[
		'final_ack',
		'0105151515151515151515151515151515151515151515151515151515151515151525252525252525252525252525252525252525252525252525252525252525250000000000000000'
	],
	[
		'construction_checkpoint',
		'0106161616161616161616161616161616161616161616161616161616161616161626262626262626262626262626262626262626262626262626262626262626260000000000000000'
	]
];

function frame(
	phase: IAssetOpenFrame['phase'],
	bytes: Buffer,
	total = bytes.length,
	offset = 0,
	attempt = Buffer.alloc(32, 0x31),
	digest = sha(bytes)
): IAssetOpenFrame {
	return { phase, attempt, digest, total, offset, bytes };
}

/**
 * The frame's bytes by the envelope's layout, written without the encoder so
 * a test can inject a frame the encoder of this tree would refuse.
 */
function rawFrame(f: IAssetOpenFrame, phaseByte: number): Buffer {
	const raw = Buffer.alloc(74 + f.bytes.length);
	raw[0] = 1;
	raw[1] = phaseByte;
	f.attempt.copy(raw, 2);
	f.digest.copy(raw, 34);
	raw.writeUInt32BE(f.total, 66);
	raw.writeUInt32BE(f.offset, 70);
	f.bytes.copy(raw, 74);
	return raw;
}
const phaseByte = (phase: IAssetOpenFrame['phase']): number =>
	phase === TERMS ? 7 : phase === REPLY ? 8 : -1;

describe('Asset conversion envelope phases (#2151 step 3a, test 9)', function () {
	it('keeps the golden bytes of a frame of each of phases 0 to 6', () => {
		for (const [i, [phase, golden]] of GOLDEN.entries()) {
			const ack = i >= 4;
			const bytes = ack ? Buffer.alloc(0) : Buffer.from('phase-' + i);
			const raw = encodeAssetOpenFrame({
				phase,
				attempt: Buffer.alloc(32, 0x10 + i),
				digest: ack ? Buffer.alloc(32, 0x20 + i) : sha(bytes),
				total: bytes.length,
				offset: 0,
				bytes
			});
			expect(raw.toString('hex'), phase).to.equal(golden);
			expect(raw[1], phase).to.equal(i);
			expect(decodeAssetOpenFrame(hex(golden)).phase).to.equal(phase);
		}
	});

	it('decodes phase bytes 7 and 8 as the conversion phases and refuses 9', () => {
		const terms = Buffer.from('{"version":1}');
		const t = encodeAssetOpenFrame(frame(TERMS, terms));
		expect(t[1]).to.equal(7);
		expect(decodeAssetOpenFrame(t).phase).to.equal('conversion_terms');
		const r = encodeAssetOpenFrame(frame(REPLY, Buffer.of(0)));
		expect(r[1]).to.equal(8);
		expect(decodeAssetOpenFrame(r).phase).to.equal('conversion_reply');
		const nine = Buffer.from(t);
		nine[1] = 9;
		expect(() => decodeAssetOpenFrame(nine)).to.throw();
	});

	it('bounds conversion_reply to one frame at offset 0 of 1 to 201 bytes', () => {
		for (const bytes of [
			Buffer.of(0),
			Buffer.concat([Buffer.of(1), Buffer.alloc(200, 0x61)])
		]) {
			const raw = encodeAssetOpenFrame(frame(REPLY, bytes));
			const back = decodeAssetOpenFrame(raw);
			expect(back.phase).to.equal('conversion_reply');
			expect(back.bytes).to.deep.equal(bytes);
		}
		const refused: IAssetOpenFrame[] = [
			frame(REPLY, Buffer.of(1), 2, 1),
			frame(REPLY, Buffer.alloc(202, 1)),
			frame(REPLY, Buffer.alloc(0), 0),
			frame(REPLY, Buffer.of(0), 2),
			frame(REPLY, Buffer.alloc(201, 1), 202)
		];
		for (const f of refused) {
			expect(() => encodeAssetOpenFrame(f), `${f.total}/${f.offset}`).to.throw(
				'Invalid asset conversion frame'
			);
			// The same frame written past the encoder is refused on decode.
			expect(
				() => decodeAssetOpenFrame(rawFrame(f, 8)),
				`decode ${f.total}/${f.offset}`
			).to.throw('Invalid asset conversion frame');
		}
	});

	it('bounds a conversion_terms object at 65,536 bytes', () => {
		const max = Buffer.alloc(65536, 0x7b);
		for (const offset of [0, CHUNK]) {
			const f = frame(
				TERMS,
				max.subarray(offset, offset + CHUNK),
				65536,
				offset
			);
			expect(decodeAssetOpenFrame(encodeAssetOpenFrame(f)).total).to.equal(
				65536
			);
		}
		const over = Buffer.alloc(65537, 0x7b);
		for (const offset of [0, CHUNK, 2 * CHUNK]) {
			const f = frame(
				TERMS,
				over.subarray(offset, Math.min(offset + CHUNK, 65537)),
				65537,
				offset
			);
			expect(() => encodeAssetOpenFrame(f), `offset ${offset}`).to.throw(
				'Invalid asset conversion frame'
			);
			expect(
				() => decodeAssetOpenFrame(rawFrame(f, 7)),
				`decode offset ${offset}`
			).to.throw('Invalid asset conversion frame');
		}
	});

	it('assembles a two-chunk terms object, and keeps conversion_reply out of the object phases', () => {
		const attempt = Buffer.alloc(32, 0x41);
		const bytes = Buffer.alloc(40000, 0x22);
		const digest = sha(bytes);
		const receiver = new AssetOpenObjectReceiver(
			attempt,
			TERMS as ReceiverPhase,
			65536
		);
		expect(
			receiver.receive(
				frame(TERMS, bytes.subarray(0, CHUNK), 40000, 0, attempt, digest)
			)
		).to.equal(undefined);
		expect(
			receiver.receive(
				frame(TERMS, bytes.subarray(CHUNK), 40000, CHUNK, attempt, digest)
			)
		).to.deep.equal(bytes);
		for (const phase of [
			REPLY,
			'layout_ack',
			'final_ack',
			'construction_checkpoint'
		])
			expect(
				() =>
					new AssetOpenObjectReceiver(attempt, phase as ReceiverPhase, 65536),
				phase
			).to.throw('Invalid asset opening object receiver');
		for (const phase of ['layout', 'authorization', 'final', 'exit'])
			expect(
				() =>
					new AssetOpenObjectReceiver(attempt, phase as ReceiverPhase, 65536),
				phase
			).to.not.throw();
	});

	it('the asset opening session refuses phases 7 and 8 under subtype 96', () => {
		for (const [phase, bytes] of [
			[TERMS, Buffer.from('{"version":1}')],
			[REPLY, Buffer.of(0)]
		] as const) {
			const attempt = Buffer.alloc(32, 0x51);
			const stops: string[] = [];
			const session = Object.assign(
				Object.create(AssetOpeningSession.prototype) as object,
				{
					ctx: { attempt },
					stopped: false,
					paused: false,
					chunks: new Map(),
					hashes: new Map(),
					read: (): null => null,
					save: (): void => {
						stops.push('saved');
					},
					enqueue: (): void => {
						stops.push('enqueued');
					},
					stop: (reason: string): void => {
						stops.push(reason);
					}
				}
			) as unknown as AssetOpeningSession;
			session.custom(
				BeignetCustomSubtype.ASSET_OPEN,
				rawFrame(
					frame(phase, bytes, bytes.length, 0, attempt),
					phaseByte(phase)
				)
			);
			expect(stops, phase).to.deep.equal(['Unexpected asset opening phase']);
		}
	});

	describe('the no-transport responder (section 7)', function () {
		this.timeout(60000);
		const s = scratch('asset-conversion-wire-');
		afterEach(() => s.release());

		function responder(generation: 5 | 6): {
			manager: ChannelManager;
			peer: string;
			id: string;
			txid: Buffer;
			outputIndex: number;
			replies(): IAssetOpenFrame[];
		} {
			const pair = plainTypePair(s, 0, generation);
			const store: SqliteStorage = pair.stores[0];
			const manager = new ChannelManager({
				finalOpening: { storage: store, root: pair.devices[0].root },
				verifyRemoteFundingInput: async () => 'unspent',
				persistence: { persist: () => 'committed' },
				// A generation 6 host without the conversion surface (step 3b:
				// its six members, its version and its margin).
				...(generation === 6 && {
					auxiliaryChannels: {
						dualFunding: completeRecoveryHost([], CONVERSION_HOST_KEYS)
					}
				})
			} as unknown as IChannelManagerConfig);
			manager.on('error', () => {});
			s.closing(() => manager.removeAllListeners());
			const sent: { type: number; payload: Buffer }[] = [];
			manager.on('message:outbound', (_peer, type, payload) =>
				sent.push({ type, payload })
			);
			const candidate = store.loadFinalOpening(pair.id)!;
			return {
				manager,
				peer: pair.sides[1].binding.nodeId,
				id: pair.id,
				txid: Transaction.fromHex(candidate.fundingTxHex).getHash(),
				outputIndex: candidate.fundingOutputIndex,
				replies: () =>
					sent
						.filter((m) => m.type === BEIGNET_CUSTOM_MESSAGE_TYPE)
						.map((m) => decodeCustomMessage(m.payload))
						.filter((m) => m.subtype === BeignetCustomSubtype.ASSET_SPLICE)
						.map((m) => decodeAssetOpenFrame(m.payload))
						.filter((f) => f.phase === REPLY)
			};
		}

		/** Terms naming the channel, and their attempt id by section 6. */
		function terms(
			r: ReturnType<typeof responder>,
			reference: string
		): { attempt: Buffer; bytes: Buffer } {
			const bytes = Buffer.from(
				JSON.stringify({
					version: 1,
					channelId: r.id,
					parent: {
						txid: Buffer.from(r.txid).reverse().toString('hex'),
						outputIndex: r.outputIndex,
						stateNumber: '0'
					},
					direction: 'to-asset',
					targetType: ASSET_SPLICE_RECOVERY_TYPE_HEX,
					giver: 'acceptor',
					candidate: {
						dustLimitSats: { opener: '354', acceptor: '354' },
						maxAcceptedHtlcs: { opener: 83, acceptor: 83 }
					},
					contributions: { opener: '0', acceptor: '0' },
					units: {
						holder: 'acceptor',
						issuances: [{ assetId: '4c'.repeat(32), amount: '1000' }]
					},
					firstCommitment: {
						commitmentFeeratePerKw: 253,
						balanceMsat: { opener: '1000000', acceptor: '1000000' },
						units: [{ assetId: '4c'.repeat(32), opener: '0', acceptor: '1000' }]
					},
					fees: {
						fundingPayer: 'acceptor',
						budgets: { opener: '0', acceptor: '5000' },
						feeratePerKw: 1000
					},
					agreement: { reference, expiresAt: 4102444800 },
					lockDepth: 3
				})
			);
			const D = sha(Buffer.from('beignet/asset-conversion/terms/v1\0'), bytes);
			const index = Buffer.alloc(4);
			index.writeUInt32BE(r.outputIndex);
			// The peer, the opening's acceptor, initiates (role 0x01).
			const attempt = sha(
				Buffer.from('asset-conversion-attempt/v1\0'),
				hex(r.id),
				r.txid,
				index,
				D,
				Buffer.from([1])
			);
			return { attempt, bytes };
		}

		const inject = (
			r: ReturnType<typeof responder>,
			f: IAssetOpenFrame
		): void =>
			r.manager.handleAssetOpenFrame(
				r.peer,
				BeignetCustomSubtype.ASSET_SPLICE,
				rawFrame(f, phaseByte(f.phase))
			);

		for (const generation of [5, 6] as const)
			it(`answers a generation ${generation} wallet's terms once per attempt until the peer disconnects`, () => {
				const r = responder(generation);
				const a = terms(r, 'ab01');
				const decline = Buffer.concat([
					Buffer.of(1),
					Buffer.from('Asset conversion is not offered by this node')
				]);
				const first = frame(TERMS, a.bytes, a.bytes.length, 0, a.attempt);
				inject(r, first);
				expect(r.replies(), 'first answer').to.have.length(1);
				const [reply] = r.replies();
				expect(reply.attempt).to.deep.equal(a.attempt);
				// The decline carries the received frame's digest field (v3.1 item 7).
				expect(reply.digest).to.deep.equal(first.digest);
				expect(reply.offset).to.equal(0);
				expect(reply.total).to.equal(decline.length);
				expect(reply.bytes).to.deep.equal(decline);
				inject(r, first);
				expect(r.replies(), 'same attempt again').to.have.length(1);
				// A frame of another attempt at a non-zero offset is not answered.
				const big = Buffer.alloc(40000, 0x7b);
				const other = Buffer.alloc(32, 0x99);
				inject(
					r,
					frame(TERMS, big.subarray(CHUNK), 40000, CHUNK, other, sha(big))
				);
				expect(r.replies(), 'offset 32768').to.have.length(1);
				// The responder keeps the last attempt answered, cleared on disconnect.
				r.manager.handlePeerDisconnected(r.peer);
				inject(r, first);
				expect(r.replies(), 'after disconnect').to.have.length(2);
				expect(r.replies()[1].bytes).to.deep.equal(decline);
				expect(r.replies()[1].digest).to.deep.equal(first.digest);
				const b = terms(r, 'ab02');
				const second = frame(TERMS, b.bytes, b.bytes.length, 0, b.attempt);
				inject(r, second);
				expect(r.replies(), 'another attempt').to.have.length(3);
				expect(r.replies()[2].attempt).to.deep.equal(b.attempt);
				expect(r.replies()[2].digest).to.deep.equal(second.digest);
			});
	});
});
