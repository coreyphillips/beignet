import { expect } from 'chai';
import Database from 'better-sqlite3';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { Channel } from '../../src/lightning/channel/channel';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	decodeFrame,
	encodeFrame
} from '../../src/lightning/recovery/frame-codec';
import {
	reconstructFromFrames,
	SNAPSHOT_SCHEMA_VERSION
} from '../../src/lightning/recovery/journal';
import type { RecoveryFrame } from '../../src/lightning/recovery/types';
import { restoreFromRecoveryCapsule } from '../../src/lightning/recovery/capsule';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	encodeScb,
	decodeScb,
	SCB_PREFIX,
	type IScbChannelEntry,
	type IStaticChannelBackup
} from '../../src/lightning/backup/scb';
import {
	encryptWithPrefix,
	hkdfKey
} from '../../src/lightning/storage/encryption';
import { makeNodeConfig } from './helpers/loopback-nodes';
import { makeAssetChannel, referenceProvider } from './helpers/auxiliary-pair';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import {
	createOpenerState,
	type IChannelState
} from '../../src/lightning/channel/channel-state';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	channelRowToStore,
	channelRowFromStore,
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import { basepointsOf, seedFor } from './helpers/taproot-revoked-fixture';

const rawType = (bits: number[]): Buffer => {
	const flags = FeatureFlags.empty();
	for (const bit of bits) flags.setBit(bit);
	return flags.toBuffer();
};
const pending = createOpenerState({
	temporaryChannelId: seedFor(850),
	fundingSatoshis: 500_000n,
	pushMsat: 0n,
	localConfig: DEFAULT_CHANNEL_CONFIG,
	localBasepoints: basepointsOf(seedFor(851)),
	localPerCommitmentSeed: seedFor(852)
});
pending.state = ChannelState.DUAL_FUNDING_V2;
pending.fundingVersion = 2;
pending.minimumDepth = 3;

const finalContext = { finalTaproot: true } as const;
const profile = 'simple-taproot-final' as const;

describe('Persisted final Taproot commitment profile', function () {
	for (const bits of [[80], [80, Feature.SCID_ALIAS]]) {
		it(`restores the final profile for exact channel type ${bits.join(
			'+'
		)} only in a final-capable context`, function () {
			const channelType = rawType(bits);
			const marked = { ...pending, channelType, commitmentProfile: profile };
			expect(() => serializeChannelState(marked)).to.throw();
			const row = serializeChannelState(marked, finalContext);
			expect(row).to.have.property('commitmentProfile', profile);
			expect(row.channelType).to.equal(channelType.toString('hex'));
			expect(() => deserializeChannelState(row)).to.throw();
			const restored = deserializeChannelState(row, finalContext);
			expect(restored).to.have.property('commitmentProfile', profile);
			expect(restored.channelType).to.deep.equal(channelType);
		});
	}

	it('refuses an unknown profile and mismatched final type or funding generation before restore', function () {
		const base = serializeChannelState(pending);
		const final = {
			...base,
			commitmentProfile: profile,
			channelType: rawType([80]).toString('hex')
		};
		for (const row of [
			{ ...final, commitmentProfile: 'future-format' },
			{ ...final, channelType: rawType([81]).toString('hex') },
			{ ...final, channelType: rawType([80, 180]).toString('hex') },
			{
				...final,
				channelType: rawType([80, Feature.OPTION_TAPROOT_OVERLAY]).toString(
					'hex'
				)
			},
			{ ...final, channelType: '00' + final.channelType },
			{ ...final, channelType: final.channelType + 'xx' },
			{ ...final, channelType: final.channelType + '0' },
			{ ...final, fundingVersion: 1 as const },
			{ ...base, channelType: final.channelType }
		]) {
			expect(() => deserializeChannelState(row, finalContext)).to.throw();
		}
	});
});

const oldId = seedFor(860).toString('hex');
const newId = seedFor(861).toString('hex');
const peer = pending.localBasepoints.fundingPubkey.toString('hex');
const finalState = {
	...pending,
	channelType: rawType([80]),
	commitmentProfile: profile
};
const legacyState = {
	...pending,
	channelType: rawType([Feature.STATIC_REMOTE_KEY])
};

function assetState(...extraBits: number[]): IChannelState {
	return makeAssetChannel(
		new Channel({ ...pending }),
		referenceProvider(),
		10n,
		20n,
		rawType([Feature.OPTION_TAPROOT_OVERLAY, ...extraBits])
	);
}

describe('Channel profile storage boundaries', function () {
	it('refuses to start a Channel from a positively decoded final descriptor', function () {
		const state = deserializeChannelState(
			serializeChannelState(finalState, finalContext),
			finalContext
		);
		expect(() => new Channel(state)).to.throw();
	});

	// Earlier interactive funding accepted these channel types as ordinary P2WSH.
	it('preserves unmarked historical type bytes and only requires a final marker in the new context', function () {
		for (const bits of [[80], [80, Feature.SCID_ALIAS], [81]]) {
			for (const padding of [Buffer.alloc(0), Buffer.alloc(1)]) {
				const channelType = Buffer.concat([padding, rawType(bits)]);
				const unmarked = { ...pending, channelType };
				const row = serializeChannelState(unmarked);
				const state = deserializeChannelState(row);
				expect(state).not.to.have.property('commitmentProfile');
				expect(new Channel(state).getFullState().channelType).to.deep.equal(
					channelType
				);
				expect(isTaprootChannel(state.channelType)).to.equal(false);
				expect(serializeChannelState(state)).to.deep.equal(row);
				expect(() => serializeChannelState(unmarked, finalContext)).to.throw();
				expect(() => deserializeChannelState(row, finalContext)).to.throw();
			}
		}
	});

	it('preserves historical JSON byte representations and refuses them as final descriptors', function () {
		const base = serializeChannelState(pending);
		for (const bits of [[80], [80, Feature.SCID_ALIAS]]) {
			const bytes = rawType(bits);
			for (const channelType of [Array.from(bytes), bytes.toJSON()]) {
				const row = JSON.parse(JSON.stringify({ ...base, channelType }));
				const state = deserializeChannelState(row);
				expect(state.channelType).to.deep.equal(bytes);
				expect(state).not.to.have.property('commitmentProfile');
				expect(() => deserializeChannelState(row, finalContext)).to.throw();
			}
		}
	});

	it('refuses a final descriptor with an asset funding root or auxiliary state independently', function () {
		const asset = assetState();
		const serialized = serializeChannelState(asset);
		const raw = {
			...serializeChannelState(pending),
			commitmentProfile: profile,
			channelType: rawType([80]).toString('hex')
		};
		for (const state of [
			{
				...finalState,
				fundingTaprootMerkleRoot: asset.fundingTaprootMerkleRoot
			},
			{ ...finalState, auxiliaryState: asset.auxiliaryState },
			{ ...finalState, auxiliaryProvider: referenceProvider() }
		]) {
			expect(() => serializeChannelState(state, finalContext)).to.throw();
		}
		for (const row of [
			{ ...raw, fundingTaprootMerkleRoot: serialized.fundingTaprootMerkleRoot },
			{ ...raw, auxiliaryState: serialized.auxiliaryState }
		]) {
			expect(() => deserializeChannelState(row, finalContext)).to.throw();
		}
	});

	for (const [name, open] of [
		['memory', (): MemoryStorage => new MemoryStorage()],
		['SQLite', (): SqliteStorage => new SqliteStorage(':memory:')]
	] as const) {
		it(
			'refuses new and replacement final rows before ordinary ' +
				name +
				' storage writes',
			function () {
				const storage = open();
				storage.open();
				try {
					storage.saveChannel(oldId, legacyState, peer);
					const before = storage.loadChannel(oldId)!;
					for (const id of [newId, oldId]) {
						expect(() => storage.saveChannel(id, finalState, peer)).to.throw();
						expect(storage.loadChannel(newId)).to.equal(null);
						expect(storage.loadChannel(oldId)).to.deep.equal(before);
					}
				} finally {
					storage.close();
				}
			}
		);
	}

	it('preserves historical unmarked P2WSH channel types through both ordinary stores and recovery frames', function () {
		for (const storage of [
			new MemoryStorage(),
			new SqliteStorage(':memory:')
		]) {
			storage.open();
			try {
				for (const bits of [[80], [80, Feature.SCID_ALIAS], [81]]) {
					const channelType = rawType(bits);
					storage.saveChannel(oldId, { ...pending, channelType }, peer);
					const restored = storage.loadAllChannels()[0].state;
					expect(restored.channelType).to.deep.equal(channelType);
					expect(restored).not.to.have.property('commitmentProfile');
					const frame = decodeFrame(encodeFrame(snapshot(restored)));
					expect(frame.snapshot!.channels[0].state.channelType).to.deep.equal(
						channelType
					);
					expect(frame.snapshot!.channels[0].state).not.to.have.property(
						'commitmentProfile'
					);
				}
			} finally {
				storage.close();
			}
		}
	});

	it('refuses to start a node if a custom backend returns a marked channel', function () {
		const storage = new MemoryStorage();
		const original = storage.loadAllChannels.bind(storage);
		storage.loadAllChannels = (): ReturnType<
			MemoryStorage['loadAllChannels']
		> => [
			...original(),
			{ channelId: newId, state: finalState, peerPubkey: peer }
		];
		let node: LightningNode | undefined;
		try {
			expect(() => {
				node = new LightningNode({
					...makeNodeConfig('profile-startup', 1),
					storage
				});
			}).to.throw();
			expect(storage.loadChannel(newId)).to.equal(null);
		} finally {
			node?.destroy();
			storage.close();
		}
	});

	it('refuses a whole mixed SQLite channel set while preserving both stored rows', function () {
		const directory = mkdtempSync(join(tmpdir(), 'beignet-channel-profile-'));
		const path = join(directory, 'channels.db');
		const storage = new SqliteStorage(path);
		const raw = new Database(path);
		try {
			storage.open();
			storage.saveChannel(oldId, legacyState, peer);
			storage.saveChannel(newId, legacyState, peer);
			const update = raw.prepare(
				'UPDATE channels SET state_json=? WHERE channel_id=?'
			);
			const readRows = raw.prepare(
				'SELECT channel_id, state_json FROM channels ORDER BY channel_id'
			);
			const old = serializeChannelState(pending);
			for (const row of [
				{
					...old,
					commitmentProfile: profile,
					channelType: rawType([80]).toString('hex')
				},
				{ ...old, commitmentProfile: 'unknown-format' }
			]) {
				update.run(JSON.stringify(row), newId);
				const before = readRows.all();
				expect(() => storage.loadAllChannels()).to.throw();
				expect(() => storage.loadChannel(newId)).to.throw();
				expect(readRows.all()).to.deep.equal(before);
			}
		} finally {
			raw.close();
			storage.close();
			rmSync(directory, { recursive: true, force: true });
		}
	});

	it('preserves the plain and asset-envelope layouts and re-encodes the entire stored record byte for byte', function () {
		const states = [
			{ ...pending, channelType: null },
			legacyState,
			{ ...pending, channelType: rawType([Feature.ANCHOR_ZERO_FEE_HTLC]) },
			{
				...pending,
				channelType: rawType([Feature.OPTION_TAPROOT]),
				remoteSigningNonce: Buffer.alloc(66, 5)
			},
			{ ...pending, channelType: rawType([80, Feature.STATIC_REMOTE_KEY]) },
			{ ...pending, channelType: rawType([80, Feature.OPTION_TAPROOT]) },
			assetState(),
			assetState(80)
		];
		for (const state of states) {
			const row = serializeChannelState(state);
			expect(row).not.to.have.property('commitmentProfile');
			expect(row.channelType).to.equal(
				state.channelType?.toString('hex') ?? null
			);
			expect(row.remoteSigningNonce).to.equal(
				state.remoteSigningNonce?.toString('hex') ?? null
			);
			const expected = state.auxiliaryState
				? { assetChannelRow: 1, channel: row }
				: row;
			const bytes = JSON.stringify(expected);
			for (const context of [undefined, finalContext]) {
				const stored = channelRowToStore(serializeChannelState(state, context));
				expect(JSON.stringify(stored)).to.equal(bytes);
				const restored = deserializeChannelState(
					channelRowFromStore(JSON.parse(bytes)),
					context
				);
				expect(restored).not.to.have.property('commitmentProfile');
				expect(
					JSON.stringify(
						channelRowToStore(serializeChannelState(restored, context))
					)
				).to.equal(bytes);
			}
		}
	});
});

function snapshot(state: IChannelState): RecoveryFrame {
	return {
		version: 2,
		sequence: 1n,
		writerEpoch: 1n,
		previousFrameHash: Buffer.alloc(32),
		timestamp: 1,
		mutations: [],
		outboundMessages: [],
		snapshot: {
			schemaVersion: SNAPSHOT_SCHEMA_VERSION,
			channels: [{ channelId: oldId, state, peerPubkey: peer }],
			keyIndices: [],
			chainMonitors: [],
			preimages: [],
			payments: [],
			paymentSecrets: [],
			htlcPaymentMappings: [],
			forwardedHtlcs: [],
			htlcSharedSecrets: [],
			invoices: [],
			invoicePathIds: [],
			forwardingEvents: [],
			outbox: []
		}
	};
}
function delta(state: IChannelState): RecoveryFrame {
	return {
		version: 2,
		sequence: 2n,
		writerEpoch: 1n,
		previousFrameHash: Buffer.alloc(32),
		timestamp: 2,
		outboundMessages: [],
		mutations: [
			{ type: 'channel_state', channelId: newId, state, peerPubkey: peer }
		]
	};
}

describe('Channel profile recovery boundaries', function () {
	it('keeps final profiles out of recovery frame snapshot and delta writes', function () {
		for (const shape of [snapshot, delta]) {
			expect(() => encodeFrame(shape(finalState))).to.throw();
		}
	});
	it('refuses final profiles in both recovery frame representations during decode', function () {
		for (const shape of [snapshot, delta]) {
			const data = JSON.parse(encodeFrame(shape(legacyState)).toString());
			const row = data.snapshot?.channels[0].state ?? data.mutations[0].state;
			row.commitmentProfile = profile;
			row.channelType = rawType([80]).toString('hex');
			expect(() => decodeFrame(Buffer.from(JSON.stringify(data)))).to.throw();
		}
	});
	it('preflights a final channel in a decoded delta before installing the preceding snapshot', function () {
		const storage = new MemoryStorage();
		storage.open();
		try {
			expect(() =>
				reconstructFromFrames(storage, [
					snapshot(legacyState),
					delta(finalState)
				])
			).to.throw();
			expect(storage.loadAllChannels()).to.be.empty;
		} finally {
			storage.close();
		}
	});
});

const legacyEntry: IScbChannelEntry = {
	channelId: oldId,
	peerNodeId: peer,
	peerAddresses: [],
	fundingTxid: seedFor(862).toString('hex'),
	fundingOutputIndex: 0,
	fundingSatoshis: '500000',
	channelKeyIndex: null,
	channelType: rawType([Feature.STATIC_REMOTE_KEY]).toString('hex'),
	role: 'OPENER',
	isTaproot: false,
	isAnchor: false
};

function scb(channels: IScbChannelEntry[]): IStaticChannelBackup {
	return { version: 1, network: 'regtest', createdAt: 1, channels };
}
function rawScb(backup: IStaticChannelBackup): string {
	return encryptWithPrefix(
		hkdfKey(seedFor(863), 'beignet-scb-v1'),
		JSON.stringify(backup),
		SCB_PREFIX
	);
}

describe('Static channel backup version 1 profile boundary', function () {
	for (const [name, fields] of [
		[
			'final marker',
			{ channelType: rawType([80]).toString('hex'), commitmentProfile: profile }
		],
		['unknown marker', { commitmentProfile: 'future-format' }]
	] as const) {
		const entries = [
			legacyEntry,
			{ ...legacyEntry, channelId: newId, ...fields }
		];
		it('refuses a mixed ' + name + ' backup at encode and decode', function () {
			expect(() => encodeScb(scb(entries), seedFor(863))).to.throw();
			expect(() => decodeScb(rawScb(scb(entries)), seedFor(863))).to.throw();
		});
		it(
			'refuses a direct mixed ' +
				name +
				' restore before creating the first recovery channel',
			async function () {
				const storage = new MemoryStorage();
				storage.open();
				const node = new LightningNode({
					...makeNodeConfig('scb-profile', 1),
					storage
				});
				try {
					let error: unknown;
					try {
						await node.recoverFromStaticChannelBackup(entries);
					} catch (cause) {
						error = cause;
					}
					expect(error).to.be.instanceOf(Error);
					expect(node.getChannelManager().listChannels()).to.be.empty;
					expect(storage.loadAllChannels()).to.be.empty;
					expect(storage.loadAllChainMonitors()).to.be.empty;
				} finally {
					node.destroy();
				}
			}
		);
	}
	it('refuses a single recovery capsule carrying a marked v1 backup before writing its target', function () {
		const marked = { ...legacyEntry, commitmentProfile: profile };
		const backup = scb([marked]);
		const storage = new MemoryStorage();
		storage.open();
		try {
			expect(() =>
				restoreFromRecoveryCapsule(
					{
						version: 1,
						encryptedScb: rawScb(backup),
						generation: 0n,
						writerEpoch: 0n,
						latestSequence: 0n,
						frameHash: Buffer.alloc(32),
						snapshotHash: Buffer.alloc(32),
						guardians: []
					},
					storage,
					seedFor(863)
				)
			).to.throw(/commitment profile/i);
			expect(storage.loadAllChannels()).to.be.empty;
		} finally {
			storage.close();
		}
	});
	it('recovers unmarked historical P2WSH types and refuses to export a marked channel through v1', async function () {
		const storage = new MemoryStorage();
		storage.open();
		const node = new LightningNode({
			...makeNodeConfig('legacy-profile-scb', 1),
			storage
		});
		try {
			const entries = [[80], [80, Feature.SCID_ALIAS], [81]].map((bits, i) => ({
				...legacyEntry,
				channelId: seedFor(870 + i).toString('hex'),
				fundingTxid: seedFor(880 + i).toString('hex'),
				channelType: rawType(bits).toString('hex')
			}));
			const backup = scb(entries);
			const decoded = decodeScb(encodeScb(backup, seedFor(863)), seedFor(863));
			expect(decoded).to.deep.equal(backup);
			const result = await node.recoverFromStaticChannelBackup(
				decoded.channels
			);
			expect(result.recovering).to.deep.equal(
				entries.map((entry) => entry.channelId)
			);
			const exported = node.buildStaticChannelBackupData().channels;
			for (const entry of entries) {
				const saved = exported.find(
					(item) => item.channelId === entry.channelId
				);
				expect(saved?.channelType).to.equal(entry.channelType);
				expect(saved?.isTaproot).to.equal(false);
			}
			const channel = node.getChannelManager().listChannels()[0];
			Object.assign(channel.getFullState(), { commitmentProfile: profile });
			expect(() => node.buildStaticChannelBackupData()).to.throw();
		} finally {
			node.destroy();
		}
	});
	it('round-trips existing SCBs with static, staging and overlay mixed types', function () {
		for (const bit of [
			Feature.STATIC_REMOTE_KEY,
			Feature.OPTION_TAPROOT,
			Feature.OPTION_TAPROOT_OVERLAY
		]) {
			const backup = scb([
				{ ...legacyEntry, channelType: rawType([bit, 80]).toString('hex') }
			]);
			expect(
				decodeScb(encodeScb(backup, seedFor(863)), seedFor(863))
			).to.deep.equal(backup);
		}
	});
});
