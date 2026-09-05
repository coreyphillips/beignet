/**
 * Section 9.7.3 step 4: a fresh blinded payment path per invoice, built
 * from the issuer manifest's template (first witness ... S, then R), with
 * blinded_payinfo aggregated per BOLT 4, and the conservative wall-clock
 * bound on an invoice's expiry (section 7.5.6).
 */

import crypto from 'crypto';
import {
	IBlindedHopData,
	IBlindedPaymentPath,
	constructBlindedPath
} from '../onion/blinded-path';
import { IBlindedPayInfo } from '../offer/types';
import { IFforIssuerHop } from './issuer-messages';

/**
 * Fold relay terms upstream-first into one blinded_payinfo, the way the
 * node's own path builder does for its intro extension: the upstream hop's
 * fee applies on top of the downstream amount, fees included.
 */
export function aggregateBlindedPayInfo(
	relayHops: IFforIssuerHop[]
): IBlindedPayInfo {
	if (relayHops.length === 0) {
		throw new Error('a payment path needs at least one relay hop');
	}
	const last = relayHops[relayHops.length - 1];
	let base = last.feeBaseMsat;
	let prop = last.feeProportionalMillionths;
	let cltv = last.cltvExpiryDelta;
	let min = last.htlcMinimumMsat;
	let max = last.htlcMaximumMsat;
	for (let i = relayHops.length - 2; i >= 0; i--) {
		const up = relayHops[i];
		base =
			up.feeBaseMsat +
			base +
			Math.ceil((base * up.feeProportionalMillionths) / 1e6);
		prop =
			up.feeProportionalMillionths +
			prop +
			Math.ceil((up.feeProportionalMillionths * prop) / 1e6);
		cltv = up.cltvExpiryDelta + cltv;
		if (up.htlcMinimumMsat > min) min = up.htlcMinimumMsat;
		if (up.htlcMaximumMsat > 0n && (max === 0n || up.htlcMaximumMsat < max)) {
			max = up.htlcMaximumMsat;
		}
	}
	return {
		feeBaseMsat: base,
		feeProportionalMillionths: prop,
		cltvExpiryDelta: cltv,
		htlcMinimumMsat: min,
		htlcMaximumMsat: max > 0n ? max : 21_000_000n * 100_000_000n * 1000n
	};
}

/**
 * A payment path over `hops` (the template: every relay hop, then R last)
 * under a fresh path key. Every hop but the last relays with the template's
 * terms; the last hop is R, which identifies vouchers from the book and
 * never reads its payload.
 */
export function buildIssuerPaymentPath(
	hops: IFforIssuerHop[],
	maxCltvExpiry: number
): IBlindedPaymentPath {
	if (hops.length < 2) throw new Error('template needs a relay hop and R');
	const relays = hops.slice(0, -1);
	const hopData: IBlindedHopData[] = relays.map((h, i) => ({
		nextNodeId: hops[i + 1].nodeId,
		shortChannelId: h.shortChannelId,
		paymentRelay: {
			cltvExpiryDelta: h.cltvExpiryDelta,
			feeProportionalMillionths: h.feeProportionalMillionths,
			feeBaseMsat: h.feeBaseMsat
		},
		paymentConstraints: { maxCltvExpiry, htlcMinimumMsat: h.htlcMinimumMsat }
	}));
	hopData.push({ paymentConstraints: { maxCltvExpiry, htlcMinimumMsat: 0n } });
	const path = constructBlindedPath(
		crypto.randomBytes(32),
		hops.map((h) => h.nodeId),
		hopData
	);
	return { path, payInfo: aggregateBlindedPayInfo(relays) };
}

/**
 * Section 7.5.6: at most 8 minutes per remaining block, then a margin, and
 * never under a minute.
 */
export function conservativeExpirySeconds(remainingBlocks: number): number {
	return Math.max(
		60,
		Math.floor(Math.max(0, remainingBlocks) * 8 * 60 * 0.9) - 600
	);
}
