export type TScriptElement = string | number;

export interface IHedgehogData {
	[key: string]: IHedgehogChannel;
}

export interface IHedgehogChannel {
	alices_privkey: string;
	bobs_privkey: string;
	alices_pubkey: string;
	bobs_pubkey: string;
	multisig_script: string;
	multisig_tree: any | null;
	multisig_utxo_info: { [key: string]: any };
	i_was_last_to_send: boolean;
	alice_can_revoke: any[];
	bob_can_revoke: any[];
	balances: any[];
	balances_before_most_recent_send: any[];
	balances_before_most_recent_receive: any[];
	alices_revocation_preimages: string[];
	alices_revocation_hashes: string[];
	bobs_revocation_preimages: string[];
	bobs_revocation_hashes: string[];
	txids_to_watch_for: { [key: string]: any };
	latest_force_close_txs: any[];
	extra_outputs: any[];
}

export type TKeyPairs = {
	[key: string]: { privateKey: string; preImage: string };
};
