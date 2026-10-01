/**
 * The deterministic setup transcript behind
 * tests/lightning/fixtures/ffor/concurrent-baseline.json: one ff_init and
 * one ff_accept with fixed keys, ids and terms, and an epoch record built
 * on them for each role.
 *
 * The fixture file was written from these inputs BEFORE the concurrent
 * receive extension existed (beignet 744c0acc). A baseline message or
 * record rebuilt from them must reproduce those bytes exactly; the
 * concurrent variants differ only by what the extension adds.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	encodeFforAcceptUnsigned,
	encodeFforInitUnsigned,
	fforWireBytes,
	signFforMessage
} from '../../../src/lightning/ffor/messages';
import {
	computeTInit,
	computeTSetup
} from '../../../src/lightning/ffor/transcript';
import {
	FF_ACCEPT_TYPE,
	FF_INIT_TYPE,
	FforSlotState,
	FforState,
	FforVariant,
	IFforEpochParams,
	IFforEpochRecord
} from '../../../src/lightning/ffor/types';

export interface IBaselineFixture {
	init_unsigned: string;
	init_wire: string;
	accept_unsigned: string;
	accept_wire: string;
	record_r: string;
	record_s: string;
}

export const BASELINE_FIXTURE: IBaselineFixture = JSON.parse(
	fs.readFileSync(
		path.join(__dirname, '../fixtures/ffor/concurrent-baseline.json'),
		'utf8'
	)
);

function sha(s: string): Buffer {
	return crypto.createHash('sha256').update(Buffer.from(s, 'ascii')).digest();
}

export const FIXTURE_R_KEY = sha('ffor-concurrent/fixture/R-node-key');
export const FIXTURE_S_KEY = sha('ffor-concurrent/fixture/S-node-key');
export const FIXTURE_CHANNEL_ID = Buffer.alloc(32, 0x11);
export const FIXTURE_EPOCH_ID = Buffer.alloc(32, 0x22);
export const FIXTURE_AMOUNTS = [1_000_000n, 2_500_000n];
export const FIXTURE_PREIMAGES = [
	sha('ffor-concurrent/fixture/t1'),
	sha('ffor-concurrent/fixture/t2')
];
export const FIXTURE_HASHES = FIXTURE_PREIMAGES.map((p) =>
	crypto.createHash('sha256').update(p).digest()
);

/** The ff_init terms; `concurrentVersion` adds TLV 17. */
export function fixtureParams(concurrentVersion?: number): IFforEpochParams {
	return {
		variant: FforVariant.D,
		budgetMsat: 3_500_000n,
		maxPayments: 2,
		minPaymentMsat: 400_000n,
		settlementDeadline: 798_992,
		voucherExpiry: 800_000,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		escapeGranularityMsat: 0n,
		rPerCommitmentPoints: [],
		voucherAmountsMsat: FIXTURE_AMOUNTS,
		...(concurrentVersion !== undefined ? { concurrentVersion } : {})
	};
}

export interface IFixtureTranscript {
	initUnsigned: Buffer;
	initBody: Buffer;
	initWire: Buffer;
	tInit: Buffer;
	acceptUnsigned: Buffer;
	acceptBody: Buffer;
	acceptWire: Buffer;
	tSetup: Buffer;
}

/**
 * ff_init signed by R and ff_accept signed by S. `request` and `echo` are
 * the TLV 17 values of each message; undefined leaves the TLV out.
 */
export function fixtureTranscript(
	request?: number,
	echo?: number
): IFixtureTranscript {
	const initUnsigned = encodeFforInitUnsigned({
		channelId: FIXTURE_CHANNEL_ID,
		epochId: FIXTURE_EPOCH_ID,
		...fixtureParams(request)
	});
	const initBody = signFforMessage(FF_INIT_TYPE, initUnsigned, FIXTURE_R_KEY);
	const initWire = fforWireBytes(FF_INIT_TYPE, initBody);
	const tInit = computeTInit(initWire);
	const acceptUnsigned = encodeFforAcceptUnsigned({
		channelId: FIXTURE_CHANNEL_ID,
		epochId: FIXTURE_EPOCH_ID,
		sCommitmentNumber: 7n,
		paymentHashes: FIXTURE_HASHES,
		sHtlcIdBase: 3n,
		voucherAmountsMsat: FIXTURE_AMOUNTS,
		initHash: tInit,
		...(echo !== undefined ? { concurrentVersion: echo } : {})
	});
	const acceptBody = signFforMessage(
		FF_ACCEPT_TYPE,
		acceptUnsigned,
		FIXTURE_S_KEY
	);
	const acceptWire = fforWireBytes(FF_ACCEPT_TYPE, acceptBody);
	return {
		initUnsigned,
		initBody,
		initWire,
		tInit,
		acceptUnsigned,
		acceptBody,
		acceptWire,
		tSetup: computeTSetup(tInit, acceptWire)
	};
}

/**
 * An ACTIVE epoch record on the fixture transcript. With no arguments it is
 * the baseline record the fixture file pins.
 */
export function fixtureRecord(
	role: 'R' | 'S',
	request?: number,
	echo?: number
): IFforEpochRecord {
	const tx = fixtureTranscript(request, echo);
	return {
		role,
		state: FforState.ACTIVE,
		epochId: FIXTURE_EPOCH_ID,
		params: fixtureParams(request),
		remoteNodeId: getPublicKey(role === 'R' ? FIXTURE_S_KEY : FIXTURE_R_KEY),
		initWire: tx.initWire,
		acceptWire: tx.acceptWire,
		sCommitmentNumber: 7n,
		sHtlcIdBase: 3n,
		paymentHashes: FIXTURE_HASHES,
		preimages: role === 'S' ? FIXTURE_PREIMAGES : [],
		tInit: tx.tInit,
		tSetup: tx.tSetup,
		hBook: Buffer.alloc(32, 0x33),
		hCommit: Buffer.alloc(32, 0x44),
		hAct: Buffer.alloc(32, 0x55),
		epochStartHeight: 795_000,
		activateWire: Buffer.alloc(40, 0x66),
		activateAckWire: Buffer.alloc(40, 0x77),
		closeWire: null,
		closeAckWire: null,
		slotStates: [FforSlotState.UNUSED, FforSlotState.SETTLED],
		slotUpstream: [null, role === 'S' ? 'ab'.repeat(32) + ':4' : null],
		settledBitmap: null,
		knownPreimages: [null, null],
		exposedSlots: [role === 'R', false],
		issuerProvisioned: false,
		witnesses: [],
		closeProcessed: false,
		voucherRoundFailed: false,
		unwindOwed: false,
		abortReason: null,
		closeSent: false,
		activationMismatch: false
	};
}
