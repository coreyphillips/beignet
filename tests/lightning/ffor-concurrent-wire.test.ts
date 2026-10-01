/**
 * FFOR concurrent receive, version 1: the negotiation wire surface
 * (specs/CONCURRENT-RECEIVE.md section 1.1).
 *
 * ff_init and ff_accept TLV 17 `concurrent_version` is exactly the two bytes
 * `00 01`. The TLV is absent in both messages of a baseline epoch, whose
 * bytes are the ones a build without the extension produced. A duplicated
 * TLV, a noncanonical BigSize or a length other than two is malformed.
 * Feature pair 562/563 is defined and off by default.
 */

import { expect } from 'chai';
import {
	Feature,
	FeatureFlags,
	hasUnsupportedRequiredFeatures,
	implementedFeatures
} from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	decodeFforAcceptMessage,
	decodeFforInitMessage,
	encodeFforAcceptUnsigned,
	encodeFforInitUnsigned,
	fforTranscriptConcurrentVersion,
	fforWireBytes,
	signFforMessage,
	verifyFforMessage
} from '../../src/lightning/ffor/messages';
import {
	FF_ACCEPT_TYPE,
	FF_CONCURRENT_FEATURE_BIT,
	FF_CONCURRENT_VERSION,
	FF_INIT_TYPE
} from '../../src/lightning/ffor/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	BASELINE_FIXTURE,
	FIXTURE_CHANNEL_ID,
	FIXTURE_EPOCH_ID,
	FIXTURE_R_KEY,
	FIXTURE_S_KEY,
	fixtureParams,
	fixtureTranscript
} from './helpers/ffor-concurrent-fixture';

const TLV_17 = Buffer.from('11020001', 'hex');

/** Re-sign an unsigned body whose TLV stream a test rewrote by hand. */
function signed(type: number, unsigned: Buffer, key: Buffer): Buffer {
	return signFforMessage(type, unsigned, key);
}

describe('FFOR concurrent receive: wire (CONCURRENT-RECEIVE.md 1.1)', () => {
	describe('feature pair 562/563', () => {
		it('is bit 562, with 563 the optional bit', () => {
			expect(Feature.OPTION_FF_CONCURRENT).to.equal(562);
			expect(FF_CONCURRENT_FEATURE_BIT).to.equal(562);
			const flags = FeatureFlags.empty();
			flags.setOptional(Feature.OPTION_FF_CONCURRENT);
			expect(flags.hasBit(563)).to.equal(true);
			expect(flags.hasBit(562)).to.equal(false);
			expect(flags.hasFeature(Feature.OPTION_FF_CONCURRENT)).to.equal(true);
		});

		it('is not advertised by default and not in the implemented set', () => {
			expect(
				LightningNode.defaultFeatures().hasFeature(Feature.OPTION_FF_CONCURRENT)
			).to.equal(false);
			expect(
				implementedFeatures().hasFeature(Feature.OPTION_FF_CONCURRENT)
			).to.equal(false);
		});

		it('a peer that requires it is unsupported until a node opts in', () => {
			const remote = FeatureFlags.empty();
			remote.setCompulsory(Feature.OPTION_FF_CONCURRENT);
			expect(
				hasUnsupportedRequiredFeatures(LightningNode.defaultFeatures(), remote)
			).to.deep.equal([562]);
			const optedIn = LightningNode.defaultFeatures();
			optedIn.setOptional(Feature.OPTION_FF_CONCURRENT);
			expect(hasUnsupportedRequiredFeatures(optedIn, remote)).to.deep.equal([]);
		});
	});

	describe('baseline bytes are unchanged', () => {
		it('ff_init without TLV 17 is the pinned pre-extension message', () => {
			const tx = fixtureTranscript();
			expect(tx.initUnsigned.toString('hex')).to.equal(
				BASELINE_FIXTURE.init_unsigned
			);
			expect(tx.initWire.toString('hex')).to.equal(BASELINE_FIXTURE.init_wire);
			const decoded = decodeFforInitMessage(tx.initBody);
			expect(decoded).to.not.have.property('concurrentVersion');
			// Decode and re-encode is the identity on the pinned bytes.
			expect(encodeFforInitUnsigned(decoded).toString('hex')).to.equal(
				BASELINE_FIXTURE.init_unsigned
			);
		});

		it('ff_accept without TLV 17 is the pinned pre-extension message', () => {
			const tx = fixtureTranscript();
			expect(tx.acceptUnsigned.toString('hex')).to.equal(
				BASELINE_FIXTURE.accept_unsigned
			);
			expect(tx.acceptWire.toString('hex')).to.equal(
				BASELINE_FIXTURE.accept_wire
			);
			const decoded = decodeFforAcceptMessage(tx.acceptBody);
			expect(decoded).to.not.have.property('concurrentVersion');
			expect(encodeFforAcceptUnsigned(decoded).toString('hex')).to.equal(
				BASELINE_FIXTURE.accept_unsigned
			);
		});
	});

	describe('TLV 17 concurrent_version', () => {
		it('encodes as 11 02 00 01, last in the ff_init TLV stream', () => {
			const tx = fixtureTranscript(FF_CONCURRENT_VERSION);
			expect(tx.initUnsigned.toString('hex')).to.equal(
				BASELINE_FIXTURE.init_unsigned + TLV_17.toString('hex')
			);
			const decoded = decodeFforInitMessage(tx.initBody);
			expect(decoded.concurrentVersion).to.equal(1);
			expect(encodeFforInitUnsigned(decoded).equals(tx.initUnsigned)).to.equal(
				true
			);
			expect(
				verifyFforMessage(
					FF_INIT_TYPE,
					tx.initBody,
					getPublicKey(FIXTURE_R_KEY)
				)
			).to.equal(true);
		});

		it('follows TLV 15 when a hash chain is also asked for', () => {
			// The handler refuses the combination; the codec keeps TLV order.
			const unsigned = encodeFforInitUnsigned({
				channelId: FIXTURE_CHANNEL_ID,
				epochId: FIXTURE_EPOCH_ID,
				...fixtureParams(FF_CONCURRENT_VERSION),
				hashChain: true
			});
			expect(unsigned.subarray(-7).toString('hex')).to.equal('0f010111020001');
			const decoded = decodeFforInitMessage(
				signed(FF_INIT_TYPE, unsigned, FIXTURE_R_KEY)
			);
			expect(decoded.hashChain).to.equal(true);
			expect(decoded.concurrentVersion).to.equal(1);
		});

		it('encodes as 11 02 00 01, last in the ff_accept TLV stream', () => {
			const baseline = fixtureTranscript();
			const tx = fixtureTranscript(undefined, FF_CONCURRENT_VERSION);
			// Same ff_init, so the same init_hash: the echo is the only change.
			expect(tx.acceptUnsigned.toString('hex')).to.equal(
				baseline.acceptUnsigned.toString('hex') + TLV_17.toString('hex')
			);
			const decoded = decodeFforAcceptMessage(tx.acceptBody);
			expect(decoded.concurrentVersion).to.equal(1);
			expect(
				encodeFforAcceptUnsigned(decoded).equals(tx.acceptUnsigned)
			).to.equal(true);
			expect(
				verifyFforMessage(
					FF_ACCEPT_TYPE,
					tx.acceptBody,
					getPublicKey(FIXTURE_S_KEY)
				)
			).to.equal(true);
		});

		it('is covered by the signature: adding or changing it breaks the one made without it', () => {
			const tx = fixtureTranscript();
			const sig = tx.initBody.subarray(-64);
			for (const tlv of ['11020001', '11020002']) {
				const tampered = Buffer.concat([
					tx.initUnsigned,
					Buffer.from(tlv, 'hex'),
					sig
				]);
				expect(decodeFforInitMessage(tampered).concurrentVersion).to.be.a(
					'number'
				);
				expect(
					verifyFforMessage(FF_INIT_TYPE, tampered, getPublicKey(FIXTURE_R_KEY))
				).to.equal(false);
			}
		});

		it('keeps any two-byte value for the handler to judge', () => {
			for (const [hex, value] of [
				['0000', 0],
				['0002', 2],
				['ffff', 0xffff]
			] as const) {
				const tx = fixtureTranscript();
				const tlv = Buffer.from('1102' + hex, 'hex');
				const init = signed(
					FF_INIT_TYPE,
					Buffer.concat([tx.initUnsigned, tlv]),
					FIXTURE_R_KEY
				);
				expect(decodeFforInitMessage(init).concurrentVersion).to.equal(value);
				const accept = signed(
					FF_ACCEPT_TYPE,
					Buffer.concat([tx.acceptUnsigned, tlv]),
					FIXTURE_S_KEY
				);
				expect(decodeFforAcceptMessage(accept).concurrentVersion).to.equal(
					value
				);
			}
		});

		it('a length other than two is malformed in both messages', () => {
			const tx = fixtureTranscript();
			for (const hex of ['1100', '110101', '1103000100', '110400000001']) {
				const tlv = Buffer.from(hex, 'hex');
				expect(
					() =>
						decodeFforInitMessage(
							signed(
								FF_INIT_TYPE,
								Buffer.concat([tx.initUnsigned, tlv]),
								FIXTURE_R_KEY
							)
						),
					`ff_init ${hex}`
				).to.throw(/TLV 17 must be 2 bytes/);
				expect(
					() =>
						decodeFforAcceptMessage(
							signed(
								FF_ACCEPT_TYPE,
								Buffer.concat([tx.acceptUnsigned, tlv]),
								FIXTURE_S_KEY
							)
						),
					`ff_accept ${hex}`
				).to.throw(/TLV 17 must be 2 bytes/);
			}
		});

		it('a duplicated TLV 17 is malformed in both messages', () => {
			const tx = fixtureTranscript();
			const twice = Buffer.concat([TLV_17, TLV_17]);
			expect(() =>
				decodeFforInitMessage(
					signed(
						FF_INIT_TYPE,
						Buffer.concat([tx.initUnsigned, twice]),
						FIXTURE_R_KEY
					)
				)
			).to.throw(/not in order/);
			expect(() =>
				decodeFforAcceptMessage(
					signed(
						FF_ACCEPT_TYPE,
						Buffer.concat([tx.acceptUnsigned, twice]),
						FIXTURE_S_KEY
					)
				)
			).to.throw(/not in order/);
		});

		it('a noncanonical BigSize type or length is malformed in both messages', () => {
			const tx = fixtureTranscript();
			// Type 17 as a 3-byte BigSize, then length 2 as a 3-byte BigSize.
			for (const hex of ['fd0011020001', '11fd00020001']) {
				const tlv = Buffer.from(hex, 'hex');
				expect(
					() =>
						decodeFforInitMessage(
							signed(
								FF_INIT_TYPE,
								Buffer.concat([tx.initUnsigned, tlv]),
								FIXTURE_R_KEY
							)
						),
					`ff_init ${hex}`
				).to.throw(/non-canonical/);
				expect(
					() =>
						decodeFforAcceptMessage(
							signed(
								FF_ACCEPT_TYPE,
								Buffer.concat([tx.acceptUnsigned, tlv]),
								FIXTURE_S_KEY
							)
						),
					`ff_accept ${hex}`
				).to.throw(/non-canonical/);
			}
		});

		it('a truncated TLV 17 is malformed in both messages', () => {
			const tx = fixtureTranscript();
			const tlv = Buffer.from('110200', 'hex');
			expect(() =>
				decodeFforInitMessage(
					signed(
						FF_INIT_TYPE,
						Buffer.concat([tx.initUnsigned, tlv]),
						FIXTURE_R_KEY
					)
				)
			).to.throw(/expected 2 bytes/);
			expect(() =>
				decodeFforAcceptMessage(
					signed(
						FF_ACCEPT_TYPE,
						Buffer.concat([tx.acceptUnsigned, tlv]),
						FIXTURE_S_KEY
					)
				)
			).to.throw(/expected 2 bytes/);
		});

		it('the encoder refuses a value that does not fit two bytes', () => {
			for (const bad of [-1, 0x10000, 1.5]) {
				expect(() =>
					encodeFforInitUnsigned({
						channelId: FIXTURE_CHANNEL_ID,
						epochId: FIXTURE_EPOCH_ID,
						...fixtureParams(bad)
					})
				).to.throw(/two bytes/);
			}
		});
	});

	describe('reading the selection back from a stored transcript', () => {
		it('reports the request and the echo of each profile', () => {
			const baseline = fixtureTranscript();
			expect(
				fforTranscriptConcurrentVersion(baseline.initWire, baseline.acceptWire)
			).to.deep.equal({ requested: undefined, echoed: undefined });
			const concurrent = fixtureTranscript(1, 1);
			expect(
				fforTranscriptConcurrentVersion(
					concurrent.initWire,
					concurrent.acceptWire
				)
			).to.deep.equal({ requested: 1, echoed: 1 });
			expect(
				fforTranscriptConcurrentVersion(concurrent.initWire, null)
			).to.deep.equal({ requested: 1, echoed: undefined });
			const noEcho = fixtureTranscript(1);
			expect(
				fforTranscriptConcurrentVersion(noEcho.initWire, noEcho.acceptWire)
			).to.deep.equal({ requested: 1, echoed: undefined });
		});

		it('cannot say for bytes that are not the stored messages', () => {
			const tx = fixtureTranscript(1, 1);
			expect(fforTranscriptConcurrentVersion(Buffer.alloc(0), null)).to.equal(
				null
			);
			// The right body under the wrong message type.
			expect(
				fforTranscriptConcurrentVersion(
					fforWireBytes(FF_ACCEPT_TYPE, tx.initBody),
					null
				)
			).to.equal(null);
			expect(
				fforTranscriptConcurrentVersion(
					tx.initWire,
					fforWireBytes(FF_INIT_TYPE, tx.acceptBody)
				)
			).to.equal(null);
			expect(
				fforTranscriptConcurrentVersion(
					tx.initWire,
					tx.acceptWire.subarray(0, 80)
				)
			).to.equal(null);
		});
	});
});
