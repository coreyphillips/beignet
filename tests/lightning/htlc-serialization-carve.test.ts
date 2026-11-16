/**
 * The HTLC entry codec moved from storage/serialization.ts to
 * storage/htlc-serialization.ts. A channel row is hashed into recovery
 * frames and read back by every later release, so the move must not change
 * one byte of what the codec writes. The golden strings below were produced
 * by the codec before it moved.
 */

import { expect } from 'chai';
import {
	serializeHtlcEntry,
	deserializeHtlcEntry,
	bufToHex,
	hexToBuf,
	bigintToStr,
	strToBigint
} from '../../src/lightning/storage/serialization';
import * as carved from '../../src/lightning/storage/htlc-serialization';
import * as primitives from '../../src/lightning/storage/serialization-primitives';
import type { IHtlcEntry } from '../../src/lightning/channel/types';
import { HtlcDirection, HtlcState } from '../../src/lightning/channel/types';

const ONION = Buffer.concat([Buffer.from([0]), Buffer.alloc(1365, 0x5c)]);

const FULL_ENTRY: IHtlcEntry = {
	id: 18446744073709551615n,
	amountMsat: 2100000000000000000n,
	paymentHash: Buffer.alloc(32, 0xa1),
	cltvExpiry: 800123,
	onionRoutingPacket: ONION,
	direction: HtlcDirection.RECEIVED,
	state: HtlcState.FULFILLED,
	blindingPoint: Buffer.concat([Buffer.from([2]), Buffer.alloc(32, 0xb2)]),
	paymentPreimage: Buffer.alloc(32, 0xc3),
	addRemoteCommitted: true,
	removalRemoteCommitted: false,
	commitCoverPending: true,
	addLocallyRevoked: false,
	removalLocallyRevoked: true,
	addRemotelyRevoked: false,
	addCoverPending: true,
	addRemoteSigned: false,
	forwardEmitted: true,
	fforVoucher: true,
	fforMismatch: true,
	dustExposureFailback: false,
	expiredOnArrival: true,
	funderFeeFailback: false,
	addedWhileRestoreUnproven: true,
	addedWhileFundingUnaccounted: false
};

const FULL_GOLDEN =
	'{"key":"received-18446744073709551615","id":"18446744073709551615",' +
	'"amountMsat":"2100000000000000000",' +
	'"paymentHash":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",' +
	'"cltvExpiry":800123,' +
	`"onionRoutingPacket":"00${'5c'.repeat(1365)}",` +
	'"direction":"RECEIVED","state":"FULFILLED",' +
	'"fforVoucher":true,"fforMismatch":true,' +
	'"blindingPoint":"02b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",' +
	'"paymentPreimage":"c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",' +
	'"addRemoteCommitted":true,"removalRemoteCommitted":false,' +
	'"commitCoverPending":true,"addLocallyRevoked":false,' +
	'"removalLocallyRevoked":true,"addRemotelyRevoked":false,' +
	'"addCoverPending":true,"addRemoteSigned":false,"forwardEmitted":true,' +
	'"dustExposureFailback":false,"expiredOnArrival":true,' +
	'"funderFeeFailback":false,"addedWhileRestoreUnproven":true,' +
	'"addedWhileFundingUnaccounted":false}';

const BARE_ENTRY: IHtlcEntry = {
	id: 0n,
	amountMsat: 1n,
	paymentHash: Buffer.alloc(32, 0x01),
	cltvExpiry: 1,
	onionRoutingPacket: Buffer.alloc(0),
	direction: HtlcDirection.OFFERED,
	state: HtlcState.PENDING
};

const BARE_GOLDEN =
	'{"key":"offered-0","id":"0","amountMsat":"1",' +
	'"paymentHash":"0101010101010101010101010101010101010101010101010101010101010101",' +
	'"cltvExpiry":1,"onionRoutingPacket":"","direction":"OFFERED",' +
	'"state":"PENDING"}';

describe('HTLC entry codec after the carve', () => {
	it('serializes every optional HTLC field to the same JSON as before', () => {
		const json = JSON.stringify(
			serializeHtlcEntry('received-18446744073709551615', FULL_ENTRY)
		);
		expect(json.length).to.equal(3594);
		expect(json).to.equal(FULL_GOLDEN);
	});

	it('serializes an HTLC with no optional field to the same JSON as before', () => {
		expect(
			JSON.stringify(serializeHtlcEntry('offered-0', BARE_ENTRY))
		).to.equal(BARE_GOLDEN);
	});

	it('reads both golden rows back to the entries that wrote them', () => {
		const full = deserializeHtlcEntry(JSON.parse(FULL_GOLDEN));
		expect(full.key).to.equal('received-18446744073709551615');
		expect(full.entry).to.deep.equal(FULL_ENTRY);
		const bare = deserializeHtlcEntry(JSON.parse(BARE_GOLDEN));
		expect(bare.key).to.equal('offered-0');
		expect(bare.entry).to.deep.equal(BARE_ENTRY);
		// An absent optional field stays absent: no key with an undefined value.
		expect(Object.keys(bare.entry)).to.deep.equal(Object.keys(BARE_ENTRY));
	});

	it('exports the same functions from serialization.ts as from the new modules', () => {
		expect(serializeHtlcEntry).to.equal(carved.serializeHtlcEntry);
		expect(deserializeHtlcEntry).to.equal(carved.deserializeHtlcEntry);
		expect(bufToHex).to.equal(primitives.bufToHex);
		expect(hexToBuf).to.equal(primitives.hexToBuf);
		expect(bigintToStr).to.equal(primitives.bigintToStr);
		expect(strToBigint).to.equal(primitives.strToBigint);
	});
});
