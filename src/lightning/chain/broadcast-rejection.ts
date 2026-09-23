/**
 * Refusals that mean the network ALREADY HAS this exact transaction. Bitcoin
 * Core's wording, matched anywhere in the message because the funding
 * providers and the Electrum backend wrap the server's text in their own
 * prefix:
 *  - "Transaction already in block chain" (Core up to 27, ALREADY_IN_CHAIN;
 *    lowercase before 0.19): an output of this txid is unspent in the chain.
 *  - "Transaction outputs already in utxo set" (Core 28+, the same check
 *    renamed ALREADY_IN_UTXO_SET): returned only while an output of THIS txid
 *    is unspent in the chainstate, so the transaction is confirmed (issue
 *    #921).
 *  - "txn-already-in-mempool", "txn-already-known" and "already known": the
 *    mempool already holds this txid.
 *
 * Deliberately an allowlist, because every caller treats a match as a
 * successful broadcast. "Input already spent by conflicting transaction",
 * "bad-txns-inputs-missingorspent", "txn-mempool-conflict" and the fee
 * refusals mean this transaction can NOT be on the network, and the bare RPC
 * error code (-27) is shared by several of them, so none of those may match.
 */
const DUPLICATE_BROADCAST_REJECTION =
	/already in block ?chain|already in utxo set|already known|txn-already/i;

/**
 * Whether a broadcast refusal says the network already has the transaction,
 * mined or in the mempool. For a caller that holds a signed transaction to
 * get it on chain, that is success, not a failure to retry.
 */
export function isDuplicateBroadcastRejection(message: string): boolean {
	return DUPLICATE_BROADCAST_REJECTION.test(message);
}
