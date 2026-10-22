/**
 * Identifiers as `BeignetNode` takes and returns them: hex strings at the
 * boundary, bytes inside the protocol layer.
 *
 * The three types are plain aliases of `string` for now, so they change no
 * caller. A later major release turns them into branded types; the facade
 * will still accept a plain string for each and validate it.
 */

/** A 32-byte channel id as 64 hex characters. */
export type ChannelIdHex = string;

/**
 * A transaction id as 64 hex characters in display byte order: the order
 * bitcoind, block explorers and `Transaction.getId()` print. The bytes in a
 * transaction's hash and in every outpoint that spends it are the reverse.
 */
export type TxidHex = string;

/** A 32-byte payment hash as 64 hex characters. */
export type PaymentHashHex = string;

/**
 * The display-order txid for a transaction hash in internal byte order, as
 * `Transaction.getHash()` and an input's `hash` hold it. Leaves `hash` as it
 * was: `Buffer.prototype.reverse` reverses in place.
 */
export function txidToDisplayHex(hash: Uint8Array): TxidHex {
	if (hash.length !== 32) {
		throw new RangeError(`A transaction hash is 32 bytes, got ${hash.length}`);
	}
	return Buffer.from(hash).reverse().toString('hex');
}

/**
 * The internal-order hash for a display-order txid, ready for an outpoint.
 * Refuses anything but 64 hex characters: `Buffer.from(hex, 'hex')` stops at
 * the first non-hex pair, so a malformed txid would come back as a short hash
 * rather than an error.
 */
export function txidFromDisplayHex(txid: TxidHex): Buffer {
	if (typeof txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(txid)) {
		throw new RangeError('A txid is 64 hex characters');
	}
	return Buffer.from(txid, 'hex').reverse();
}
