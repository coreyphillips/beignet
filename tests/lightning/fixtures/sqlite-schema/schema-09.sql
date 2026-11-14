-- SqliteStorage schema 9, written by beignet 0.7.6
-- (01fc5bcd) with scripts/storage-fixture.ts.
CREATE TABLE action_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				category TEXT NOT NULL,
				action TEXT NOT NULL,
				timestamp INTEGER NOT NULL,
				data TEXT NOT NULL
			);
CREATE TABLE announced_peer_addresses (
				pubkey TEXT PRIMARY KEY,
				announcement_timestamp INTEGER NOT NULL,
				addresses_json TEXT NOT NULL
			);
CREATE TABLE chain_monitors (
				channel_id TEXT PRIMARY KEY,
				state_json TEXT NOT NULL
			);
CREATE TABLE channel_key_indices (
				channel_id TEXT PRIMARY KEY,
				channel_index INTEGER NOT NULL
			);
CREATE TABLE channel_policies (
				channel_id TEXT PRIMARY KEY,
				policy_json TEXT NOT NULL
			);
CREATE TABLE channels (
				channel_id TEXT PRIMARY KEY,
				state_json TEXT NOT NULL,
				peer_pubkey TEXT NOT NULL
			, channel_index INTEGER DEFAULT 0);
CREATE TABLE forwarded_htlcs (
				out_key TEXT PRIMARY KEY,
				in_channel_id TEXT NOT NULL,
				in_htlc_id TEXT NOT NULL
			);
CREATE TABLE forwarding_events (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				settled_at INTEGER NOT NULL,
				in_channel_id TEXT NOT NULL,
				out_channel_id TEXT NOT NULL,
				in_scid TEXT,
				out_scid TEXT,
				amount_in_msat TEXT NOT NULL,
				amount_out_msat TEXT NOT NULL,
				fee_msat TEXT NOT NULL
			);
CREATE TABLE gossip_channels (
				scid_hex TEXT PRIMARY KEY,
				channel_json TEXT NOT NULL
			);
CREATE TABLE gossip_nodes (
				node_id_hex TEXT PRIMARY KEY,
				node_json TEXT NOT NULL
			);
CREATE TABLE htlc_payment_map (
				htlc_key TEXT PRIMARY KEY,
				payment_hash_hex TEXT NOT NULL
			);
CREATE TABLE htlc_shared_secrets (
				key TEXT PRIMARY KEY,
				secret TEXT NOT NULL
			);
CREATE TABLE invoices (
				payment_hash_hex TEXT PRIMARY KEY,
				invoice_json TEXT NOT NULL
			);
CREATE TABLE metadata (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
			);
CREATE TABLE mission_control (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				data_json TEXT NOT NULL
			);
CREATE TABLE payment_queue (
				id TEXT PRIMARY KEY,
				bolt11 TEXT NOT NULL,
				priority INTEGER NOT NULL,
				status TEXT NOT NULL,
				amount_sats INTEGER,
				max_fee_sats INTEGER,
				metadata TEXT,
				error TEXT,
				created_at INTEGER NOT NULL,
				completed_at INTEGER
			);
CREATE TABLE payment_secrets (
				payment_hash_hex TEXT PRIMARY KEY,
				secret TEXT NOT NULL
			);
CREATE TABLE payments (
				payment_hash TEXT PRIMARY KEY,
				payment_json TEXT NOT NULL
			);
CREATE TABLE peer_addresses (
				pubkey TEXT PRIMARY KEY,
				host TEXT NOT NULL,
				port INTEGER NOT NULL,
				last_connected INTEGER NOT NULL DEFAULT 0
			);
CREATE TABLE peer_storage_blobs (
				peer_pubkey TEXT PRIMARY KEY,
				blob TEXT NOT NULL,
				received_at INTEGER NOT NULL
			);
CREATE TABLE preimages (
				payment_hash TEXT PRIMARY KEY,
				preimage TEXT NOT NULL
			);
CREATE TABLE schema_version (
				version INTEGER PRIMARY KEY
			);
CREATE TABLE scid_mappings (
				scid_hex TEXT PRIMARY KEY,
				channel_id TEXT NOT NULL
			);
CREATE TABLE wallet_data (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
			);
CREATE TABLE watchtower_sessions (
				session_id TEXT PRIMARY KEY,
				tower_uri TEXT NOT NULL,
				tower_pubkey TEXT NOT NULL,
				session_key TEXT NOT NULL,
				blob_type INTEGER NOT NULL,
				max_updates INTEGER NOT NULL,
				sweep_fee_rate TEXT NOT NULL,
				seq_num INTEGER NOT NULL,
				last_applied INTEGER NOT NULL,
				created_at INTEGER NOT NULL,
				dials_with_session_key INTEGER NOT NULL DEFAULT 0
			);
CREATE TABLE watchtower_updates (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				tower_uri TEXT NOT NULL,
				channel_id TEXT NOT NULL,
				hint TEXT NOT NULL,
				encrypted_blob TEXT NOT NULL,
				seq_num INTEGER NOT NULL,
				acked INTEGER NOT NULL,
				created_at INTEGER NOT NULL,
				blob_type INTEGER NOT NULL DEFAULT 2
			);
CREATE TABLE webhooks (
				id TEXT PRIMARY KEY,
				url TEXT NOT NULL,
				events TEXT NOT NULL,
				secret_hash TEXT,
				created_at INTEGER NOT NULL
			);
INSERT INTO "channel_key_indices" VALUES('e80954876cbb084a0ff4b980b5639bb623368a535426714275a709a284567d5c',7);
INSERT INTO "channels" VALUES('e80954876cbb084a0ff4b980b5639bb623368a535426714275a709a284567d5c','{"channelId":"e80954876cbb084a0ff4b980b5639bb623368a535426714275a709a284567d5c","temporaryChannelId":"67d49c70c59b37822ee522d8502a51476f0cd9a478683a8a98527ba76f1ec127","role":"OPENER","state":"NORMAL","fundingSatoshis":"1000000","pushMsat":"0","fundingTxid":"ca4e28703d9b45bad4da592006aa32a66ae776af969c9f61ee1ac6dc7bf21de0","fundingOutputIndex":0,"minimumDepth":0,"localConfig":{"dustLimitSatoshis":"354","maxHtlcValueInFlightMsat":"18446744073709551615","channelReserveSatoshis":"10000","htlcMinimumMsat":"1000","toSelfDelay":144,"maxAcceptedHtlcs":483,"feeratePerKw":253},"localBasepoints":{"fundingPubkey":"038f3447ca66e0787b93118df2afb310da00f31b05b94412869b21aa82c56a9814","revocationBasepoint":"028796f54a6e0777650e7045f45fb4e6b83580de365c1571f6df6d899dd91d83ac","paymentBasepoint":"033fb92b1780408e3235d2298637857082f9863c9276413e1c52ce80fa7398cc68","delayedPaymentBasepoint":"03ca3ff31f398a89dadd8c86c483d8f3fecd7a68692ae906e4af3ad006762ec452","htlcBasepoint":"0222e5bd2b3d1aeedb5559c196240713e51188344569cf7e85ceae55fcbf5a9bbd","firstPerCommitmentPoint":"03ada8081dce3e8147bd8179ac73bae8f96b2b79936701a15255bfba1dd25820de"},"localPerCommitmentSeed":"50386707eae75e52db7d32051206e506e791d37aa4490c7e5c32c3156dfe364c","remoteConfig":{"dustLimitSatoshis":"354","maxHtlcValueInFlightMsat":"18446744073709551615","channelReserveSatoshis":"10000","htlcMinimumMsat":"1000","toSelfDelay":144,"maxAcceptedHtlcs":483,"feeratePerKw":253},"remoteBasepoints":{"fundingPubkey":"02b96278650b0816105d9851809b1ab5baa30860d57e9091c313f95309b2a15059","revocationBasepoint":"03dfcb2e301d2f5d438ba29e87f0808d72efc78a841178eeeb6a677cc2bc821e4d","paymentBasepoint":"03599bbce9fb834620acc2e900019a760e21c47ad229b57a519e65e6236b81a546","delayedPaymentBasepoint":"0304e1d6de85e64a34fe07ba65cab7c4276810f2c7d5346d1302c55c2051e86629","htlcBasepoint":"035356cb2405e581f9b52864ed8bae1e3db25d5a3c045e576962ec56f69ca79125","firstPerCommitmentPoint":"021ae2cde84cbb37302a64db583eb7056d30786789d0b1d650728332b724f329fb"},"localCommitmentNumber":"5","remoteCommitmentNumber":"3","remoteRevocationNumber":"0","needsCommitment":false,"localBalanceMsat":"800000000","remoteBalanceMsat":"200000000","shaChainData":{"entries":[],"knownCount":"0"},"remoteCurrentPerCommitmentPoint":"021ae2cde84cbb37302a64db583eb7056d30786789d0b1d650728332b724f329fb","remoteNextPerCommitmentPoint":null,"localHtlcCounter":"0","htlcs":[],"remoteCommitmentSignature":null,"remoteHtlcSignatures":[],"remoteSigningNonce":null,"channelType":null,"localChannelReady":false,"remoteChannelReady":false,"localShutdownScript":null,"remoteShutdownScript":null,"lastSentCommitmentSigned":null,"lastSentPartialSignatureWithNonce":null,"pendingLocalUpdates":[],"pendingLocalUpdatesSignedCount":0,"lastSentHtlcSignatures":[],"lastSentRevokeSecret":null,"lastSentRevokeNextPoint":null,"lastSentWasRevoke":null,"preReestablishState":null,"lastProposedClosingFeeSat":null,"closingFeeMin":null,"closingFeeMax":null,"theirLastClosingFeeSat":null,"simpleClose":null,"lastCloseFeeSat":null,"lastCloseLocktime":null,"lastCloseCloserScript":null,"lastCloseCloseeScript":null,"lastCloseSentVariants":null,"shortChannelId":null,"fundingConfirmationHeight":0,"fundingBroadcastHeight":0,"fundingTxIndex":0,"announcementSigsSent":false,"announcementSigsReceived":false,"remoteAnnouncementNodeSig":null,"remoteAnnouncementBitcoinSig":null,"localAnnouncementNodeSig":null,"localAnnouncementBitcoinSig":null,"announceChannel":true,"scidAlias":null,"remoteScidAlias":null,"zeroConfEnabled":false,"trustedPeer":false,"quiescenceState":"NORMAL","quiescenceInitiator":false,"spliceFundingTxid":null,"spliceFundingOutputIndex":0,"preSpliceState":null,"spliceInFlight":null,"remoteForwardingPolicy":null,"fundingVersion":1,"commitmentFeeratePerkw":0,"fundingLocktime":0,"dlpRemotePerCommitmentPoint":null}','0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',0);
INSERT INTO "invoices" VALUES('eb1162baa818d3ebdc2d9dc2a15f80b52bab0622792cb62a758c51adeff86ab4','{"paymentHash":"eb1162baa818d3ebdc2d9dc2a15f80b52bab0622792cb62a758c51adeff86ab4","bolt11":"lnbcrt210n1fixture","amountMsat":"21000","description":"fixture invoice","expiry":3600,"createdAt":1750000002000}');
INSERT INTO "metadata" VALUES('fixture:metadata','{"fixture":true}');
INSERT INTO "payment_secrets" VALUES('eb1162baa818d3ebdc2d9dc2a15f80b52bab0622792cb62a758c51adeff86ab4','538959a6153a58f4dd35f21f99af2bce9bea6bc2d719a690ced3e23e432e4cc0');
INSERT INTO "payments" VALUES('ac1de25687e7199b4bb8227937291018cc839ef4b4612d4fbe1d366852eec4f0','{"paymentHash":"ac1de25687e7199b4bb8227937291018cc839ef4b4612d4fbe1d366852eec4f0","preimage":"104d9361cfc79043493e6d1ea25873563032fd8bbe4a89221fe397d38169e07f","amountMsat":"21000","status":"COMPLETED","direction":"OUTGOING","createdAt":1750000000000,"completedAt":1750000001000,"metadata":{"label":"fixture"}}');
INSERT INTO "peer_addresses" VALUES('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798','203.0.113.7',9735,1794637294845);
INSERT INTO "preimages" VALUES('ac1de25687e7199b4bb8227937291018cc839ef4b4612d4fbe1d366852eec4f0','104d9361cfc79043493e6d1ea25873563032fd8bbe4a89221fe397d38169e07f');
INSERT INTO "schema_version" VALUES(1);
INSERT INTO "schema_version" VALUES(2);
INSERT INTO "schema_version" VALUES(3);
INSERT INTO "schema_version" VALUES(4);
INSERT INTO "schema_version" VALUES(5);
INSERT INTO "schema_version" VALUES(6);
INSERT INTO "schema_version" VALUES(7);
INSERT INTO "schema_version" VALUES(8);
INSERT INTO "schema_version" VALUES(9);
INSERT INTO "sqlite_sequence" VALUES('watchtower_updates',1);
INSERT INTO "wallet_data" VALUES('fixture:wallet','{"balance":0}');
INSERT INTO "watchtower_sessions" VALUES('90c33fdd9636926fcc4a77f7be7f8969a3e7849207f775e200a211ba56e33bf9','tower@203.0.113.8:9911','02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5','tIJT1DaB2IKfujKNhrr6sskR+b3yUGoLS7+pBpcMxts=',2,1024,'2500',1,0,1750000004000,0);
INSERT INTO "watchtower_updates" VALUES(1,'tower@203.0.113.8:9911','e80954876cbb084a0ff4b980b5639bb623368a535426714275a709a284567d5c','a1179ab520ae42f02aa3a01912c78e0f','c094bd2dc2e2d2919d754698a718bb090a58bf978944866d685ec8be34b1ed91',1,0,1750000005000,2);
CREATE INDEX idx_action_log_category ON action_log(category);
CREATE INDEX idx_action_log_timestamp ON action_log(timestamp);
CREATE INDEX idx_forwarding_events_settled_at ON forwarding_events(settled_at);
CREATE INDEX idx_watchtower_sessions_tower ON watchtower_sessions(tower_uri);
CREATE INDEX idx_watchtower_updates_pending ON watchtower_updates(tower_uri, acked);
