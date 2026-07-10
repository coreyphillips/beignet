import * as bitcoin from 'bitcoinjs-lib';
import { BIP32Interface } from 'bip32';
import { Network } from 'bitcoinjs-lib';

import { err, ok, Result } from './result';

/**
 * Typed error returned when a direct spend (send/sendMany/sendMax/sweep) is
 * attempted on a multisig wallet. Multisig spends MUST go through the PSBT
 * flow so every cosigner can contribute a signature.
 */
export class MultisigSpendError extends Error {
	public readonly code = 'MULTISIG_REQUIRES_PSBT';
	constructor(
		message = 'Multisig wallets spend via the PSBT flow: buildPsbt -> signPsbtWithOurKey (each cosigner) -> combinePsbts -> importSignedPsbt -> broadcastTransaction.'
	) {
		super(message);
		this.name = 'MultisigSpendError';
	}
}

// The only BIP 48 script type beignet supports: 2' = P2WSH sorted multisig.
export const BIP48_SCRIPT_TYPE = '2';

export interface IParsedBip48Path {
	coinType: string;
	account: string;
	change: number;
	index: number;
}

/**
 * Parses and validates a full BIP 48 P2WSH path
 * (m/48'/coin'/account'/2'/change/index).
 * @param {string} path
 * @returns {Result<IParsedBip48Path>}
 */
export const parseBip48Path = (path: string): Result<IParsedBip48Path> => {
	const segments = path.replace(/'/g, '').split('/');
	if (segments.length !== 7 || segments[0] !== 'm' || segments[1] !== '48') {
		return err(
			`Expected a BIP 48 path (m/48'/coin'/account'/2'/change/index): ${path}`
		);
	}
	if (segments[4] !== BIP48_SCRIPT_TYPE) {
		return err(
			`Unsupported BIP 48 script type ${segments[4]}' (only 2' = P2WSH sorted multisig): ${path}`
		);
	}
	const change = Number(segments[5]);
	const index = Number(segments[6]);
	if (
		!Number.isInteger(change) ||
		!Number.isInteger(index) ||
		(change !== 0 && change !== 1) ||
		index < 0
	) {
		return err(`Invalid change/index segments in path: ${path}`);
	}
	return ok({
		coinType: segments[2],
		account: segments[3],
		change,
		index
	});
};

export interface ISortedMultisigPayment {
	address: string;
	// P2WSH scriptPubKey.
	output: Buffer;
	// The p2ms redeem script (m-of-n OP_CHECKMULTISIG over sorted keys).
	witnessScript: Buffer;
	// Derived child public keys in BIP 67 (lexicographic) order.
	sortedPublicKeys: Buffer[];
}

/**
 * Builds the sorted-multisig (BIP 67) P2WSH payment for one derivation index.
 * Cosigner nodes are ACCOUNT-level public nodes; each is derived at
 * change/index and the resulting child keys are sorted lexicographically
 * before entering the m-of-n script, matching wsh(sortedmulti(...)).
 * @param {number} threshold
 * @param {BIP32Interface[]} cosignerNodes
 * @param {number} change
 * @param {number} index
 * @param {Network} network
 * @returns {Result<ISortedMultisigPayment>}
 */
export const buildSortedMultisigPayment = ({
	threshold,
	cosignerNodes,
	change,
	index,
	network
}: {
	threshold: number;
	cosignerNodes: BIP32Interface[];
	change: number;
	index: number;
	network: Network;
}): Result<ISortedMultisigPayment> => {
	try {
		const sortedPublicKeys = cosignerNodes
			.map((node) => node.derive(change).derive(index).publicKey)
			.sort((a, b) => a.compare(b));
		const p2ms = bitcoin.payments.p2ms({
			m: threshold,
			pubkeys: sortedPublicKeys,
			network
		});
		if (!p2ms.output) return err('Unable to build multisig redeem script.');
		const p2wsh = bitcoin.payments.p2wsh({ redeem: p2ms, network });
		if (!p2wsh.address || !p2wsh.output) {
			return err('Unable to build multisig P2WSH output.');
		}
		return ok({
			address: p2wsh.address,
			output: p2wsh.output,
			witnessScript: p2ms.output,
			sortedPublicKeys
		});
	} catch (e) {
		return err(e);
	}
};
