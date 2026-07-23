/**
 * M1.1 — BOLT 11 blinded-paths tagged field round-trip.
 *
 * Verifies the new blinded-paths invoice field encodes/decodes losslessly and
 * that the shared blinded-path serializer (onion/blinded-path.ts) is used by
 * both BOLT 11 and BOLT 12 (byte-for-byte cross-check).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import { encode } from '../../src/lightning/invoice/encode';
import { decode } from '../../src/lightning/invoice/decode';
import { Network } from '../../src/lightning/invoice/types';
import {
	IBlindedHop,
	IBlindedPaymentPath,
	encodeBlindedPaths,
	decodeBlindedPaths,
	encodeInvoiceBlindedPaymentPaths,
	decodeInvoiceBlindedPaymentPaths
} from '../../src/lightning/onion/blinded-path';

function makeKeypair(): Buffer {
	let privKey: Buffer;
	do {
		privKey = crypto.randomBytes(32);
	} while (!secp.utils.isValidPrivateKey(privKey));
	return privKey;
}

/** A real compressed point: the decoder validates every path pubkey. */
function makePoint(): Buffer {
	return Buffer.from(secp.getPublicKey(makeKeypair(), true));
}

function makeBlindedPaymentPath(numHops: number): IBlindedPaymentPath {
	const blindedHops: IBlindedHop[] = [];
	for (let i = 0; i < numHops; i++) {
		blindedHops.push({
			blindedNodeId: makePoint(),
			encryptedData: crypto.randomBytes(20 + i) // variable length on purpose
		});
	}
	return {
		path: {
			introductionNodeId: makePoint(),
			blindingPoint: makePoint(),
			blindedHops
		},
		payInfo: {
			feeBaseMsat: 1000,
			feeProportionalMillionths: 250,
			cltvExpiryDelta: 144,
			htlcMinimumMsat: 1n,
			htlcMaximumMsat: 100_000_000n
		}
	};
}

describe('BOLT 11 blinded paths (M1.1)', function () {
	it('round-trips a single blinded payment path through an invoice', function () {
		const blindedPaths = [makeBlindedPaymentPath(2)];
		const invoiceStr = encode({
			network: Network.REGTEST,
			amountMsat: 50_000_000n,
			paymentHash: crypto.randomBytes(32),
			paymentSecret: crypto.randomBytes(32),
			description: 'blinded',
			blindedPaths,
			privateKey: makeKeypair()
		});

		const inv = decode(invoiceStr);
		expect(inv.blindedPaths, 'blindedPaths present').to.have.length(1);

		const got = inv.blindedPaths![0];
		const want = blindedPaths[0];
		expect(got.path.introductionNodeId).to.deep.equal(
			want.path.introductionNodeId
		);
		expect(got.path.blindingPoint).to.deep.equal(want.path.blindingPoint);
		expect(got.path.blindedHops).to.have.length(2);
		expect(got.path.blindedHops[0].blindedNodeId).to.deep.equal(
			want.path.blindedHops[0].blindedNodeId
		);
		expect(got.path.blindedHops[1].encryptedData).to.deep.equal(
			want.path.blindedHops[1].encryptedData
		);
		expect(got.payInfo.feeBaseMsat).to.equal(1000);
		expect(got.payInfo.feeProportionalMillionths).to.equal(250);
		expect(got.payInfo.cltvExpiryDelta).to.equal(144);
		expect(got.payInfo.htlcMinimumMsat).to.equal(1n);
		expect(got.payInfo.htlcMaximumMsat).to.equal(100_000_000n);
	});

	it('round-trips multiple blinded payment paths', function () {
		const blindedPaths = [makeBlindedPaymentPath(1), makeBlindedPaymentPath(3)];
		const invoiceStr = encode({
			network: Network.MAINNET,
			paymentHash: crypto.randomBytes(32),
			description: 'multi',
			blindedPaths,
			privateKey: makeKeypair()
		});

		const inv = decode(invoiceStr);
		expect(inv.blindedPaths).to.have.length(2);
		expect(inv.blindedPaths![0].path.blindedHops).to.have.length(1);
		expect(inv.blindedPaths![1].path.blindedHops).to.have.length(3);
	});

	it('omits the field when no blinded paths are provided', function () {
		const invoiceStr = encode({
			network: Network.MAINNET,
			paymentHash: crypto.randomBytes(32),
			description: 'none',
			privateKey: makeKeypair()
		});
		expect(decode(invoiceStr).blindedPaths).to.be.undefined;
	});

	it('uses a shared path serializer (BOLT 11 entries match BOLT 12 path bytes)', function () {
		const entry = makeBlindedPaymentPath(2);

		// The combined BOLT 11 blob begins with num(1) then the same path bytes
		// the BOLT 12 array serializer produces for that single path. The
		// BOLT 12 array itself carries NO count prefix (S-4.H4: [...*blinded_path]
		// fills the TLV length).
		const combined = encodeInvoiceBlindedPaymentPaths([entry]);
		const pathsOnly = encodeBlindedPaths([entry.path]);
		// combined: [num=1][path][payinfo(28, no features)]; pathsOnly: [path]
		const combinedPathBytes = combined.subarray(1, combined.length - 28);
		expect(combinedPathBytes).to.deep.equal(pathsOnly);

		// And the path decodes identically through either decoder.
		expect(decodeBlindedPaths(pathsOnly)[0].introductionNodeId).to.deep.equal(
			decodeInvoiceBlindedPaymentPaths(combined)[0].path.introductionNodeId
		);
	});
});
