/**
 * Which broadcast refusals mean the network already has the transaction
 * (issue #921).
 *
 * Bitcoin Core 28 renamed ALREADY_IN_CHAIN ("Transaction already in block
 * chain") to ALREADY_IN_UTXO_SET ("Transaction outputs already in utxo
 * set"), so a rebroadcast of a confirmed funding or close read as a real
 * failure on every node running a current Core. The classifier is an
 * allowlist: refusals that also say "already" but mean the transaction can
 * never be on the network must stay failures.
 */

import { expect } from 'chai';
import { isDuplicateBroadcastRejection } from '../../src/lightning/chain/broadcast-rejection';

describe('isDuplicateBroadcastRejection (issue #921)', function () {
	const duplicates = [
		// Core 28+, bare and inside the wrappers the providers and the
		// Electrum backend put around the server's text.
		'Transaction outputs already in utxo set',
		'Broadcast failed: Transaction outputs already in utxo set',
		'Failed to broadcast transaction: Error: sendrawtransaction RPC error -27: Transaction outputs already in utxo set',
		'the transaction was rejected by network rules.\n\nTransaction outputs already in utxo set\n[02000000000101]',
		// Core up to 27, and older lowercase wording.
		'Transaction already in block chain',
		'transaction already in block chain',
		'Failed to broadcast transaction: Transaction already in block chain',
		// Mempool reject reasons for this same transaction.
		'txn-already-in-mempool',
		'txn-already-known',
		'Transaction already known'
	];

	const failures = [
		// These say "already" or name the inputs, but mean this transaction
		// can NOT be on the network.
		'Input already spent by conflicting transaction',
		'bad-txns-inputs-missingorspent',
		'txn-mempool-conflict',
		'insufficient fee, rejecting replacement',
		'min relay fee not met',
		'Transaction rejected by mempool',
		'electrum hiccup',
		// The RPC error code alone is shared by several refusals.
		'sendrawtransaction RPC error -27',
		''
	];

	for (const message of duplicates) {
		const label = JSON.stringify(message);
		it(`counts ${label} as already on the network`, function () {
			expect(isDuplicateBroadcastRejection(message)).to.equal(true);
		});
	}

	for (const message of failures) {
		const label = JSON.stringify(message);
		it(`keeps ${label} a failure`, function () {
			expect(isDuplicateBroadcastRejection(message)).to.equal(false);
		});
	}
});
