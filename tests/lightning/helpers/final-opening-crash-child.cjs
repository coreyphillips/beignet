const fs = require('fs');
const {
	SqliteStorage
} = require('../../../dist/lightning/storage/sqlite-storage');

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const store = SqliteStorage.openFinalWallet(input.file, {
	nodeId: input.nodeId,
	network: input.network,
	encryptionKey: Buffer.from(input.encryptionKey, 'hex')
});

function killAt(boundary) {
	fs.writeSync(1, boundary);
	process.kill(process.pid, 'SIGKILL');
}

if (input.boundary === 'during-update') {
	// SQLite has modified the row, but the transaction has not committed.
	store.db.function('kill_after_update', () => killAt('during-update'));
	store.db.exec(`
		CREATE TEMP TRIGGER kill_after_nonce_update
		AFTER UPDATE OF nonces_json ON final_opening_candidates
		BEGIN SELECT kill_after_update(); END;
	`);
}
let payload;
if (input.operation) {
	const {
		bip32RootFromSeed
	} = require('../../../dist/lightning/keys/wallet-keys');
	const keys = bip32RootFromSeed(Buffer.from(input.walletSeed, 'hex'));
	const authority = store.openingAuthority;
	if (input.boundary === 'before-device-result') {
		const original = authority.finish.bind(authority);
		authority.finish = (slot, transcript, result) => {
			if (slot.startsWith('commitment/nonce/')) killAt('before-device-result');
			return original(slot, transcript, result);
		};
	}
	const args = [input.channelId, input.terms, keys, input.channelIndex];
	payload =
		input.operation === 'accept'
			? store.acceptFinalPeerCommitment(
					...args,
					Buffer.from(input.peerCommitment, 'hex')
			  )
			: store.signFinalPeerCommitment(...args);
} else {
	payload = store.finalOpeningTxComplete(
		input.channelId,
		Buffer.from(input.fundingKey, 'hex')
	);
}
if (input.boundary === 'after-return') killAt(payload.toString('hex'));
throw new Error('Expected SIGKILL at ' + input.boundary);
