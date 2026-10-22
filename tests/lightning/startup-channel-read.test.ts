/**
 * Issue #1681: startup reads the channels table once. Every read decrypts
 * and deserializes every row, revoked HTLC history included, so the quorum
 * preflight, the FFOR identity pass, the restore loop and the SCID backfill
 * share one.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	createOpenerState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import {
	DurabilityBarrier,
	GuardianReplicator,
	GUARDIAN_HOST_DEFAULT_MAX_CIPHERTEXT_BYTES
} from '../../src/lightning/recovery';

const PEER = '02' + 'aa'.repeat(32);

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`startup-read-${id}`).digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(
	storage: SqliteStorage,
	recovery?: INodeConfig['recovery']
): INodeConfig {
	const seed = makeSeed(1);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update('node-identity')
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(2),
		fundingPrivkey: crypto.createHash('sha256').update(seed).digest(),
		storage,
		recovery
	};
}

/** An enforcing barrier whose replicator never confirms anything. */
function quorumRecovery(): INodeConfig['recovery'] {
	const replicator = {
		replicatedThrough: (): bigint => 0n,
		namespaceLostBackfill: (): string | null => null,
		watermarkExceedingJournal: (): string | null => null,
		maxRecordBytes: (): number => GUARDIAN_HOST_DEFAULT_MAX_CIPHERTEXT_BYTES,
		replicatePending: async (): Promise<void> => undefined
	} as unknown as GuardianReplicator;
	return {
		enabled: true,
		durability: 'quorum',
		barrier: new DurabilityBarrier({
			durability: 'quorum',
			replicator,
			lease: () => null,
			timeoutMs: 500,
			retryDelayMs: 50
		})
	};
}

function storedChannel(index: number): IChannelState {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 100_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(makeSeed(100 + index)),
		localPerCommitmentSeed: makeSeed(1000 + index)
	});
	state.channelId = crypto.randomBytes(32);
	state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
	state.shortChannelId = encodeShortChannelId({
		block: 800_000 + index,
		txIndex: 1,
		outputIndex: 0
	});
	return state;
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

function countChannelReads(storage: SqliteStorage): () => number {
	const load = storage.loadAllChannels.bind(storage);
	let calls = 0;
	storage.loadAllChannels = (): ReturnType<
		SqliteStorage['loadAllChannels']
	> => {
		calls++;
		return load();
	};
	return () => calls;
}

function registeredScids(node: LightningNode): Map<string, Buffer> {
	return (node as unknown as { scidToChannelId: Map<string, Buffer> })
		.scidToChannelId;
}

describe('Startup reads the channels table once (issue #1681)', function () {
	it('restores 50 stored channels from a single read', function () {
		const storage = openStorage();
		const states = Array.from({ length: 50 }, (_, i) => storedChannel(i));
		for (const state of states)
			storage.saveChannel(state.channelId!.toString('hex'), state, PEER);
		const reads = countChannelReads(storage);

		const node = new LightningNode(makeNodeConfig(storage));
		node.on('error', () => {});
		node.on('node:error', () => {});
		try {
			expect(reads()).to.equal(1);
			expect(node.getChannelManager().listChannels()).to.have.length(50);
			// The SCID backfill ran over the shared rows.
			const scids = registeredScids(node);
			for (const state of states) {
				const mapped = scids.get(state.shortChannelId!.toString('hex'));
				expect(mapped?.equals(state.channelId!)).to.equal(true);
			}
		} finally {
			node.destroy();
			storage.close();
		}
	});

	it('the quorum preflight shares the same read', function () {
		const storage = openStorage();
		for (let i = 0; i < 50; i++) {
			const state = storedChannel(i);
			storage.saveChannel(state.channelId!.toString('hex'), state, PEER);
		}
		const reads = countChannelReads(storage);

		const node = new LightningNode(makeNodeConfig(storage, quorumRecovery()));
		node.on('error', () => {});
		node.on('node:error', () => {});
		try {
			expect(reads()).to.equal(1);
			expect(node.getChannelManager().listChannels()).to.have.length(50);
		} finally {
			node.destroy();
			storage.close();
		}
	});

	it('does not backfill the SCID of a row restore removed', function () {
		const storage = openStorage();
		const live = storedChannel(0);
		const condemned = storedChannel(1);
		condemned.condemned = true;
		for (const state of [live, condemned])
			storage.saveChannel(state.channelId!.toString('hex'), state, PEER);

		const node = new LightningNode(makeNodeConfig(storage));
		node.on('error', () => {});
		node.on('node:error', () => {});
		try {
			expect(
				storage.loadChannel(condemned.channelId!.toString('hex'))
			).to.equal(null);
			const condemnedScid = condemned.shortChannelId!.toString('hex');
			expect(registeredScids(node).has(condemnedScid)).to.equal(false);
			expect(
				storage.loadAllScidMappings().map((m) => m.scidHex)
			).to.not.include(condemnedScid);
			expect(
				registeredScids(node).has(live.shortChannelId!.toString('hex'))
			).to.equal(true);
		} finally {
			node.destroy();
			storage.close();
		}
	});
});
