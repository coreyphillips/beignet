/**
 * Storage codec for one HTLC entry of a channel row.
 */

import type { IHtlcEntry, HtlcDirection, HtlcState } from '../channel/types';
import { bigintToStr, strToBigint } from './serialization-primitives';
import {
	serializeCustomRecords,
	deserializeCustomRecords
} from './auxiliary-serialization';
import type { SerializedCustomRecords } from './auxiliary-serialization';

export interface ISerializedHtlcEntry {
	key: string;
	id: string;
	amountMsat: string;
	paymentHash: string;
	cltvExpiry: number;
	onionRoutingPacket: string;
	direction: string;
	state: string;
	/** Route blinding: blinding_point (hex) so an in-flight blinded receive
	 * survives restart and can still peel its onion with the blinded key. */
	blindingPoint?: string;
	/** The preimage the peer's fulfil revealed (hex; see
	 * IHtlcEntry.paymentPreimage). Absent on rows written before it existed. */
	paymentPreimage?: string;
	/** Two-phase update flags (see IHtlcEntry). Optional for compatibility. */
	addRemoteCommitted?: boolean;
	removalRemoteCommitted?: boolean;
	commitCoverPending?: boolean;
	addLocallyRevoked?: boolean;
	removalLocallyRevoked?: boolean;
	addRemotelyRevoked?: boolean;
	addCoverPending?: boolean;
	/** FFOR Variant D voucher marker (see IHtlcEntry.fforVoucher). */
	fforVoucher?: boolean;
	/** FFOR Variant D mismatching-add marker (see IHtlcEntry.fforMismatch). */
	fforMismatch?: boolean;
	/** Whether the stored remote signature covers this add (see IHtlcEntry). */
	addRemoteSigned?: boolean;
	/** Edge-trigger marker for HTLC_FORWARDED dispatch (see IHtlcEntry). */
	forwardEmitted?: boolean;
	/** Admission-time dust-exposure classification (see IHtlcEntry). */
	dustExposureFailback?: boolean;
	/** Admission-time expired-at-our-tip classification (see IHtlcEntry). */
	expiredOnArrival?: boolean;
	/** Admission-time funder-fee band classification (see IHtlcEntry). */
	funderFeeFailback?: boolean;
	/** Admitted while the capsule-restore hold stood (see IHtlcEntry). */
	addedWhileRestoreUnproven?: boolean;
	/** Admitted while the funding-missing quarantine stood (see IHtlcEntry). */
	addedWhileFundingUnaccounted?: boolean;
	/**
	 * Asset channels only (see IHtlcEntry): the custom records of the add and
	 * the asset amount read from them. Written only when present, so an HTLC
	 * of any other channel serializes to the bytes it always did.
	 */
	customRecords?: SerializedCustomRecords;
	auxiliaryAmount?: string;
}

export function serializeHtlcEntry(
	key: string,
	e: IHtlcEntry
): ISerializedHtlcEntry {
	return {
		key,
		id: bigintToStr(e.id),
		amountMsat: bigintToStr(e.amountMsat),
		paymentHash: e.paymentHash.toString('hex'),
		cltvExpiry: e.cltvExpiry,
		onionRoutingPacket: e.onionRoutingPacket.toString('hex'),
		direction: e.direction,
		state: e.state,
		...(e.fforVoucher === true ? { fforVoucher: true } : {}),
		...(e.fforMismatch === true ? { fforMismatch: true } : {}),
		...(e.blindingPoint
			? { blindingPoint: e.blindingPoint.toString('hex') }
			: {}),
		...(e.paymentPreimage
			? { paymentPreimage: e.paymentPreimage.toString('hex') }
			: {}),
		...(e.addRemoteCommitted !== undefined
			? { addRemoteCommitted: e.addRemoteCommitted }
			: {}),
		...(e.removalRemoteCommitted !== undefined
			? { removalRemoteCommitted: e.removalRemoteCommitted }
			: {}),
		...(e.commitCoverPending !== undefined
			? { commitCoverPending: e.commitCoverPending }
			: {}),
		...(e.addLocallyRevoked !== undefined
			? { addLocallyRevoked: e.addLocallyRevoked }
			: {}),
		...(e.removalLocallyRevoked !== undefined
			? { removalLocallyRevoked: e.removalLocallyRevoked }
			: {}),
		...(e.addRemotelyRevoked !== undefined
			? { addRemotelyRevoked: e.addRemotelyRevoked }
			: {}),
		...(e.addCoverPending !== undefined
			? { addCoverPending: e.addCoverPending }
			: {}),
		...(e.addRemoteSigned !== undefined
			? { addRemoteSigned: e.addRemoteSigned }
			: {}),
		...(e.forwardEmitted !== undefined
			? { forwardEmitted: e.forwardEmitted }
			: {}),
		...(e.dustExposureFailback !== undefined
			? { dustExposureFailback: e.dustExposureFailback }
			: {}),
		...(e.expiredOnArrival !== undefined
			? { expiredOnArrival: e.expiredOnArrival }
			: {}),
		...(e.funderFeeFailback !== undefined
			? { funderFeeFailback: e.funderFeeFailback }
			: {}),
		...(e.addedWhileRestoreUnproven !== undefined
			? { addedWhileRestoreUnproven: e.addedWhileRestoreUnproven }
			: {}),
		...(e.addedWhileFundingUnaccounted !== undefined
			? { addedWhileFundingUnaccounted: e.addedWhileFundingUnaccounted }
			: {}),
		...(e.customRecords !== undefined
			? { customRecords: serializeCustomRecords(e.customRecords) }
			: {}),
		...(e.auxiliaryAmount !== undefined
			? { auxiliaryAmount: serializeAuxiliaryAmount(e.auxiliaryAmount) }
			: {})
	};
}

export function deserializeHtlcEntry(s: ISerializedHtlcEntry): {
	key: string;
	entry: IHtlcEntry;
} {
	return {
		key: s.key,
		entry: {
			id: strToBigint(s.id),
			amountMsat: strToBigint(s.amountMsat),
			paymentHash: Buffer.from(s.paymentHash, 'hex'),
			cltvExpiry: s.cltvExpiry,
			onionRoutingPacket: Buffer.from(s.onionRoutingPacket, 'hex'),
			direction: s.direction as HtlcDirection,
			state: s.state as HtlcState,
			...(s.fforVoucher === true ? { fforVoucher: true } : {}),
			...(s.fforMismatch === true ? { fforMismatch: true } : {}),
			...(s.blindingPoint
				? { blindingPoint: Buffer.from(s.blindingPoint, 'hex') }
				: {}),
			...(s.paymentPreimage
				? { paymentPreimage: Buffer.from(s.paymentPreimage, 'hex') }
				: {}),
			...(s.addRemoteCommitted !== undefined
				? { addRemoteCommitted: s.addRemoteCommitted }
				: {}),
			...(s.removalRemoteCommitted !== undefined
				? { removalRemoteCommitted: s.removalRemoteCommitted }
				: {}),
			...(s.commitCoverPending !== undefined
				? { commitCoverPending: s.commitCoverPending }
				: {}),
			...(s.addLocallyRevoked !== undefined
				? { addLocallyRevoked: s.addLocallyRevoked }
				: {}),
			...(s.removalLocallyRevoked !== undefined
				? { removalLocallyRevoked: s.removalLocallyRevoked }
				: {}),
			...(s.addRemotelyRevoked !== undefined
				? { addRemotelyRevoked: s.addRemotelyRevoked }
				: {}),
			...(s.addCoverPending !== undefined
				? { addCoverPending: s.addCoverPending }
				: {}),
			...(s.addRemoteSigned !== undefined
				? { addRemoteSigned: s.addRemoteSigned }
				: {}),
			...(s.forwardEmitted !== undefined
				? { forwardEmitted: s.forwardEmitted }
				: {}),
			...(s.dustExposureFailback !== undefined
				? { dustExposureFailback: s.dustExposureFailback }
				: {}),
			...(s.expiredOnArrival !== undefined
				? { expiredOnArrival: s.expiredOnArrival }
				: {}),
			...(s.funderFeeFailback !== undefined
				? { funderFeeFailback: s.funderFeeFailback }
				: {}),
			...(s.addedWhileRestoreUnproven !== undefined
				? { addedWhileRestoreUnproven: s.addedWhileRestoreUnproven }
				: {}),
			...(s.addedWhileFundingUnaccounted !== undefined
				? { addedWhileFundingUnaccounted: s.addedWhileFundingUnaccounted }
				: {}),
			...(s.customRecords !== undefined
				? { customRecords: deserializeCustomRecords(s.customRecords) }
				: {}),
			...(s.auxiliaryAmount !== undefined
				? { auxiliaryAmount: deserializeAuxiliaryAmount(s.auxiliaryAmount) }
				: {})
		}
	};
}

/** A stored asset amount: a canonical u64 decimal, or a throw. */
/** Written through the reader's own checks, so a save refuses what a read would. */
function serializeAuxiliaryAmount(value: bigint): string {
	if (typeof value !== 'bigint') {
		throw new Error('Malformed asset amount');
	}
	const serialized = value.toString();
	deserializeAuxiliaryAmount(serialized);
	return serialized;
}

function deserializeAuxiliaryAmount(value: string): bigint {
	if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
		throw new Error('Malformed serialized asset amount');
	}
	const amount = strToBigint(value);
	if (amount > 0xffffffffffffffffn) {
		throw new Error('Serialized asset amount is out of range');
	}
	return amount;
}
