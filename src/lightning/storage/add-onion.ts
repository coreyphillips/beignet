/**
 * A pending update_add_htlc of ours journaled without its onion (recovery
 * frame version 4). Internal: not re-exported by the storage barrel.
 */

import type { IChannelState } from '../channel/channel-state';
import type { IHtlcEntry } from '../channel/types';
import { MessageType } from '../message/types';

/**
 * update_add_htlc is `[32: channel_id][8: id][8: amount_msat]
 * [32: payment_hash][4: cltv_expiry][1366: onion_routing_packet]` and then
 * its TLV stream.
 */
const ADD_ID_OFFSET = 32;
const ADD_ONION_OFFSET = 84;
const ONION_BYTES = 1366;

/**
 * An update_add_htlc of ours without its onion, when the offered HTLC entry
 * it added holds the same onion, so a frame need journal it only once.
 * Null for any other message.
 */
export function addWithoutOnion(
	htlcs: Map<string, IHtlcEntry>,
	type: number,
	payload: Buffer
): Buffer | null {
	if (type !== MessageType.UPDATE_ADD_HTLC) return null;
	if (payload.length < ADD_ONION_OFFSET + ONION_BYTES) return null;
	const id = payload.readBigUInt64BE(ADD_ID_OFFSET);
	const onion = htlcs.get(`offered-${id}`)?.onionRoutingPacket;
	if (
		onion === undefined ||
		onion.length !== ONION_BYTES ||
		!onion.equals(
			payload.subarray(ADD_ONION_OFFSET, ADD_ONION_OFFSET + ONION_BYTES)
		)
	) {
		return null;
	}
	return Buffer.concat([
		payload.subarray(0, ADD_ONION_OFFSET),
		payload.subarray(ADD_ONION_OFFSET + ONION_BYTES)
	]);
}

/** Whether serializing with `addOnionsByReference` would leave out an onion. */
export function hasReferencedAddOnions(s: IChannelState): boolean {
	return (s.pendingLocalUpdates ?? []).some(
		(u) => addWithoutOnion(s.htlcs, u.type, u.payload) !== null
	);
}

/** The inverse of addWithoutOnion. Throws when no offered HTLC has the onion. */
export function restoreAddOnion(
	htlcs: Map<string, IHtlcEntry>,
	type: number,
	payloadHex: string
): Buffer {
	const rest = Buffer.from(payloadHex, 'hex');
	if (type !== MessageType.UPDATE_ADD_HTLC || rest.length < ADD_ONION_OFFSET) {
		throw new Error('A message without its onion is not an add');
	}
	const id = rest.readBigUInt64BE(ADD_ID_OFFSET);
	const onion = htlcs.get(`offered-${id}`)?.onionRoutingPacket;
	if (onion === undefined || onion.length !== ONION_BYTES) {
		throw new Error(`Add ${id} has no offered HTLC to take its onion from`);
	}
	return Buffer.concat([
		rest.subarray(0, ADD_ONION_OFFSET),
		onion,
		rest.subarray(ADD_ONION_OFFSET)
	]);
}
