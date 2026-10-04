/** One-way home-channel policy for option_zero_reserve (BOLTs proposal 1140). */
export interface IZeroReserveConfig {
	/** Advertise support in init. Defaults on for wallets and opted-in primaries. */
	advertise?: boolean;
	/** Wallets accept waivers. Primaries always retain their own reserve. */
	role?: 'wallet' | 'primary';
	/** Primary-only operator setting, applying only to new private channels. */
	waiveClientReserve?: boolean;
}

/** Negotiated permissions for a fresh channel, separate from persisted waivers. */
export interface IZeroReservePolicy {
	acceptWaiver: boolean;
	waivePeer: boolean;
	/** Outbound waivers additionally require a live JIT receive intent. */
	waiveOnOpen: boolean;
}
