import { EAddressType } from '../types';

export const BITKIT_WALLET_SEED_HASH_PREFIX = Buffer.from(
	'@Bitkit/wallet-uuid'
);

export const WALLET_ID_PREFIX = Buffer.from('@Beignet/wallet-id');

//How many addresses to generate when more are needed.
export const GENERATE_ADDRESS_AMOUNT = 5;

// TODO: Add this as a settings for users to adjust when needed.
export const GAP_LIMIT = 20;
export const GAP_LIMIT_CHANGE = 20;

export const DUST_LIMITS = {
	[EAddressType.p2pkh]: 546,
	[EAddressType.p2sh]: 546,
	[EAddressType.p2wpkh]: 294,
	[EAddressType.p2tr]: 294,
	[EAddressType.p2wsh]: 330
};

/**
 * How long stop() waits for an in-flight refresh before shutting down anyway.
 *
 * A refresh is not itself bounded: it awaits an Electrum client that falls into
 * an untimed server_version handshake whenever a network has no client, plus
 * caller-supplied storage and address callbacks that answer on their own
 * schedule. Anything sequenced behind stop() (closing a wallet, a network
 * switch, releasing an exclusive storage lease) waits with it, so one server
 * that accepts the socket and then says nothing would leave a wallet that
 * cannot be reopened until the process dies.
 *
 * Generous enough that a refresh which is merely slow still finishes and saves
 * its work. A longer scan on a slow server can exceed it and be abandoned mid
 * read, which costs nothing but the unsaved part of that scan; callers who
 * would rather wait can pass their own deadline.
 */
export const STOP_REFRESH_WAIT_MS = 30_000;

export const TRANSACTION_DEFAULTS = {
	recommendedBaseFee: 256, // Total recommended tx base fee in sats
	dustLimit: 546 // Minimum value in sats for an output. Outputs below the dust limit may not be processed because the fees required to include them in a block would be greater than the value of the transaction itself.
};

export const BLOCKTANK_HOST = 'https://api.stag.blocktank.to';
