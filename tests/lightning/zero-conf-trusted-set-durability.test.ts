/**
 * The zero-conf trusted set is durable.
 *
 * The set answers one question: whose UNCONFIRMED funding will this node
 * treat as a usable channel. That is an operator declaration, not session
 * state, but it lived only in ZeroConfManager's in-memory Set: nothing wrote
 * it down and nothing read it back, so every restart silently emptied it.
 *
 * What that cost is not a slower open. An inbound open proposing the
 * zero_conf channel type is REFUSED OUTRIGHT by an acceptor that does not
 * trust the opener ("Proposed zero_conf channel type requires a trusted
 * peer"), never downgraded to a confirmed one, and the JIT receive engine
 * has no confirmed fallback: its openZeroConfChannelAndWait throws and the
 * held HTLCs fail back upstream. So a wallet that had trusted its LSP, and
 * whose daemon then restarted, stopped being able to receive over a channel
 * that does not exist yet until something re-added the peer. Nothing in the
 * daemon did: the set is populated only by POST /trusted-peer/add and by an
 * explicit trusted open.
 *
 * The fix writes the whole set to a metadata row on every change and reloads
 * it during restoreFromStorage, before any peer can reconnect.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	ChannelManager,
	IPerChannelKeys
} from '../../src/lightning/channel/channel-manager';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { LnCoinType } from '../../src/lightning/keys/wallet-keys';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
/** A real height, so the new-channel fence (issue #906) is not what refuses. */
const TIP = 850_000;
/** Where LightningNode keeps the trusted set. */
const TRUSTED_KEY = 'zero_conf_trusted_peers';
const LSP_PUBKEY = '02' + 'ab'.repeat(32);
const OTHER_PUBKEY = '03' + 'ef'.repeat(32);
const WALLET_PUBKEY = '03' + 'cd'.repeat(32);
const noop = (): void => {};

// ─── Helpers ───

function makeSeed(tag: string): Buffer {
	return crypto.createHash('sha256').update(`zctsd-${tag}`).digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) keys.push(derivePrivkey(seed, i));
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makePerChannelKeys(channelIndex: number): IPerChannelKeys {
	const seed = makeSeed(`per-channel-${channelIndex}`);
	const fundingPrivkey = derivePrivkey(seed, 0);
	return {
		fundingPrivkey,
		basepoints: {
			...makeBasepoints(seed),
			fundingPubkey: getPublicKey(fundingPrivkey)
		},
		perCommitmentSeed: makeSeed(`pcs-${channelIndex}`),
		htlcBasepointSecret: derivePrivkey(seed, 4)
	};
}

/** The LSP side: a manager that proposes the zero_conf channel type. */
function zeroConfOpen(tag: string): Buffer {
	const seed = makeSeed(tag);
	const opener = new ChannelManager({
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(`${tag}-pcs`),
		localFundingPrivkey: derivePrivkey(seed, 0),
		htlcBasepointSecret: derivePrivkey(seed, 4),
		chainHash: REGTEST_CHAIN_HASH,
		channelKeyDeriver: makePerChannelKeys
	});
	opener.on('error', noop);
	// The opener's own half of the trust: openChannel refuses a trusted open
	// to a peer it does not carry in canOpenZeroConfTo.
	opener.addTrustedPeer(WALLET_PUBKEY);
	let captured: Buffer | null = null;
	const capture = (_peer: string, type: number, payload: Buffer): void => {
		if (type === MessageType.OPEN_CHANNEL) captured = payload;
	};
	opener.on('message:outbound', capture);
	opener.openChannel(WALLET_PUBKEY, 100_000n, undefined, undefined, {
		trusted: true
	});
	opener.off('message:outbound', capture);
	expect(captured, 'captured the zero-conf open_channel').to.not.equal(null);
	return captured!;
}

interface IInboundResult {
	wireTypes: number[];
	wireErrors: string[];
}

/** Feed one inbound message to a node and collect what it answered. */
function feed(node: LightningNode, payload: Buffer): IInboundResult {
	const manager = node.getChannelManager();
	const wire: Array<{ type: number; payload: Buffer }> = [];
	const onWire = (_peer: string, t: number, body: Buffer): void => {
		wire.push({ type: t, payload: body });
	};
	manager.on('message:outbound', onWire);
	manager.on('error', noop);
	manager.handleMessage(LSP_PUBKEY, MessageType.OPEN_CHANNEL, payload);
	manager.off('message:outbound', onWire);
	return {
		wireTypes: wire.map((w) => w.type),
		wireErrors: wire
			.filter((w) => w.type === MessageType.ERROR)
			.map((w) => decodeErrorMessage(w.payload).data.toString('utf8'))
	};
}

function bootNode(storage: IStorageBackend): LightningNode {
	const node = LightningNode.fromMnemonic(MNEMONIC, {
		coinType: LnCoinType.REGTEST,
		storage,
		enableNetworking: false
	});
	node.on('error', noop);
	node.on('node:error', noop);
	return node;
}

function fileStorage(): {
	dir: string;
	dbPath: string;
	storage: SqliteStorage;
} {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-zctsd-'));
	const dbPath = path.join(dir, 'wallet.db');
	const storage = new SqliteStorage(dbPath);
	storage.open();
	return { dir, dbPath, storage };
}

function reopen(dbPath: string): SqliteStorage {
	const storage = new SqliteStorage(dbPath);
	storage.open();
	return storage;
}

// ─── The restart that used to empty the set ───

describe('Zero-conf trusted set durability', () => {
	it('keeps the operator declaration across a restart', () => {
		const { dir, dbPath, storage } = fileStorage();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		try {
			expect(
				storage.loadMetadata(TRUSTED_KEY),
				'nothing declared yet'
			).to.equal(null);
			node.addTrustedPeer(LSP_PUBKEY);
			node.addTrustedPeer(OTHER_PUBKEY);
			// Durable at the moment of the declaration, not at shutdown: a
			// daemon that is killed never gets a shutdown.
			expect(JSON.parse(storage.loadMetadata(TRUSTED_KEY)!)).to.have.members([
				LSP_PUBKEY,
				OTHER_PUBKEY
			]);

			node.destroy();
			second = bootNode(reopen(dbPath));
			expect(second.listTrustedPeers()).to.have.members([
				LSP_PUBKEY,
				OTHER_PUBKEY
			]);
		} finally {
			if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('accepts the LSP zero-conf open after the restart that used to refuse it', () => {
		const { dir, dbPath, storage } = fileStorage();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		try {
			node.handleNewBlock(TIP);
			node.addTrustedPeer(LSP_PUBKEY);
			node.destroy();

			second = bootNode(reopen(dbPath));
			second.handleNewBlock(TIP);
			const answer = feed(second, zeroConfOpen('after-restart'));
			expect(answer.wireErrors).to.deep.equal([]);
			expect(answer.wireTypes).to.deep.equal([MessageType.ACCEPT_CHANNEL]);
		} finally {
			if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('still refuses the same open from a peer nobody declared', () => {
		// The control, and the shape of what every restart used to do: the
		// acceptor does not downgrade a zero_conf proposal to a confirmed
		// open, it fails the channel.
		const { dir, storage } = fileStorage();
		const node = bootNode(storage);
		try {
			node.handleNewBlock(TIP);
			const answer = feed(node, zeroConfOpen('untrusted'));
			expect(answer.wireTypes).to.deep.equal([MessageType.ERROR]);
			expect(answer.wireErrors[0]).to.contain(
				'zero_conf channel type requires a trusted peer'
			);
		} finally {
			node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('carries a removal across the restart too', () => {
		const { dir, dbPath, storage } = fileStorage();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		try {
			node.addTrustedPeer(LSP_PUBKEY);
			node.addTrustedPeer(OTHER_PUBKEY);
			node.removeTrustedPeer(LSP_PUBKEY);
			node.destroy();

			second = bootNode(reopen(dbPath));
			expect(second.listTrustedPeers()).to.deep.equal([OTHER_PUBKEY]);
		} finally {
			if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('reads a corrupted row as no trust rather than failing the boot', () => {
		// Trust is the direction that cannot be guessed at: a row that will
		// not parse, or that holds something other than compressed pubkeys,
		// costs a confirmed open. Inventing trust from it would cost the
		// acceptance of a stranger's unconfirmed funding.
		const { dir, dbPath, storage } = fileStorage();
		storage.saveMetadata(TRUSTED_KEY, '{ not json');
		storage.close();
		let node = bootNode(reopen(dbPath));
		try {
			expect(node.listTrustedPeers()).to.deep.equal([]);
			node.destroy();

			const seeded = reopen(dbPath);
			seeded.saveMetadata(
				TRUSTED_KEY,
				JSON.stringify([LSP_PUBKEY, 'not-a-pubkey', 42, null])
			);
			seeded.close();
			node = bootNode(reopen(dbPath));
			expect(node.listTrustedPeers()).to.deep.equal([LSP_PUBKEY]);
		} finally {
			node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
