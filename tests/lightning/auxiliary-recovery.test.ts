/**
 * Asset channels and the Recovery Protocol (issue #2093, step 14).
 *
 * A node that replicates its recovery journal to guardians neither opens
 * nor accepts an asset channel. A restore that holds asset channels is
 * refused, with nothing installed, unless the provider says it can restore
 * them; with no provider the refusal is the one a start over such rows
 * gives.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { encodeScb } from '../../src/lightning/backup/scb';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryRestoredChannel
} from '../../src/lightning/channel/auxiliary-funding';
import { MessageType } from '../../src/lightning/message/types';
import type { LightningNode } from '../../src/lightning/node/lightning-node';
import { AuxiliaryProviderRequiredError } from '../../src/lightning/node/types';
import {
	assertGuardianJournalHoldsNoAuxiliaryChannels,
	AuxiliaryGuardianModeError,
	AuxiliaryGuardianRestoreError,
	AuxiliaryGuardianStartError,
	AuxiliaryRestoreRefusedError,
	composeRecoveryCapsule,
	encryptRecoveryCapsule,
	GuardianDescriptor,
	isGuardianRecoveryMode,
	RecoveryCapsule,
	restoreBestRecoveryCapsule,
	restoreFromRecoveryCapsule
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	assetHost,
	connectHosts,
	IAssetHost,
	openAssetChannel,
	withAssetOpens
} from './helpers/auxiliary-nodes';
import {
	ASSET_FUNDING_ROOT,
	referenceProvider
} from './helpers/auxiliary-pair';
import {
	createNode,
	makeNodeConfig,
	openReadyChannel
} from './helpers/loopback-nodes';

const GUARDIAN: GuardianDescriptor = {
	guardianId: 'ab'.repeat(32),
	transports: [{ type: 'https', url: 'https://guardian.example.com' }]
};

const openStorage = (): SqliteStorage => {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
};

const thrownBy = (work: () => unknown): unknown => {
	try {
		work();
	} catch (err) {
		return err;
	}
	throw new Error('expected a throw');
};

describe('asset channels in a guardian recovery mode', () => {
	withAssetOpens();

	let hosts: IAssetHost[];

	beforeEach(() => {
		hosts = [];
	});

	afterEach(() => {
		for (const host of hosts) host.node.destroy();
	});

	const host = (
		tag: string,
		seedId: number,
		guardianMode: boolean
	): IAssetHost => {
		const made = assetHost(
			tag,
			seedId,
			{},
			guardianMode ? { extra: { recovery: { guardians: [GUARDIAN] } } } : {}
		);
		hosts.push(made);
		return made;
	};

	it('says which recovery configurations replicate to guardians', () => {
		expect(isGuardianRecoveryMode(undefined)).to.equal(false);
		expect(isGuardianRecoveryMode({})).to.equal(false);
		expect(isGuardianRecoveryMode({ guardians: [] })).to.equal(false);
		expect(isGuardianRecoveryMode({ guardians: [GUARDIAN] })).to.equal(true);
		expect(isGuardianRecoveryMode({ barrier: {} })).to.equal(true);
		expect(isGuardianRecoveryMode({ startupGate: {} })).to.equal(true);
	});

	it('refuses to open an asset channel, by a stable code and a sentence', () => {
		const tag = 'guardian open';
		const alice = host(tag, 1, true);
		const bob = host(tag, 2, false);
		connectHosts(alice, bob);
		const refusal = thrownBy(() =>
			alice.node.openAuxiliaryChannel(bob.node.getNodeId(), 2_000_000n, {
				temporaryChannelId: Buffer.alloc(32, 7),
				fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
				channelData: Buffer.from('proposed asset funding'),
				localBalance: 900n,
				remoteBalance: 100n
			})
		);
		expect(refusal).to.be.instanceOf(AuxiliaryGuardianModeError);
		expect((refusal as AuxiliaryGuardianModeError).code).to.equal(
			'AUXILIARY_GUARDIAN_MODE'
		);
		expect((refusal as Error).message).to.equal(
			'Asset channels cannot be opened or accepted while this node ' +
				'replicates its recovery journal to guardians ' +
				'(AUXILIARY_GUARDIAN_MODE). Use a recovery mode without guardians ' +
				'for a wallet that holds asset channels.'
		);
		// Nothing was sent, and nothing is held.
		expect(alice.node.listChannels()).to.have.length(0);
		expect(bob.node.listChannels()).to.have.length(0);
	});

	it('refuses to accept an asset channel, and tells the peer no more than that', async () => {
		const tag = 'guardian accept';
		const alice = host(tag, 1, false);
		const bob = host(tag, 2, true);
		connectHosts(alice, bob);
		const refusals: string[] = [];
		bob.node.on('message:outbound', (_peer: string, type: number, payload) => {
			if (type === MessageType.ERROR) {
				refusals.push((payload as Buffer).toString('latin1'));
			}
		});
		const reasons: string[] = [];
		const manager = (
			bob.node as unknown as {
				channelManager: {
					on(event: 'error', listener: (...args: unknown[]) => void): void;
				};
			}
		).channelManager;
		manager.on('error', (...args: unknown[]) => {
			reasons.push(args.map((arg) => String(arg)).join(' '));
		});
		let failure: unknown;
		try {
			await openAssetChannel(alice, bob, {
				tag,
				openerUnits: 900n,
				acceptorUnits: 100n
			});
		} catch (err) {
			failure = err;
		}
		expect(failure).to.be.instanceOf(Error);
		expect((failure as Error).message).to.match(/was not accepted/);
		// The node knows why, by the code.
		expect(reasons.join('\n')).to.match(
			/open_channel refused: Asset channels cannot be opened or accepted .*AUXILIARY_GUARDIAN_MODE/
		);
		// The peer is told the opening was refused, and not this node's
		// recovery arrangements.
		expect(refusals).to.have.length(1);
		expect(refusals[0]).to.include(
			'open_channel refused: the asset channel could not be accepted'
		);
		expect(refusals[0]).to.not.match(/guardian/i);
		expect(bob.node.listChannels()).to.have.length(0);
	});

	it('still opens and accepts an ordinary channel', () => {
		const tag = 'guardian ordinary';
		const alice = host(tag, 1, true);
		const bob = host(tag, 2, true);
		connectHosts(alice, bob);
		const channelId = openReadyChannel(alice.node, bob.node);
		expect(alice.node.getAuxiliaryChannelInfo(channelId)).to.equal(undefined);
		expect(alice.node.listChannels()).to.have.length(1);
		expect(bob.node.listChannels()).to.have.length(1);
	});

	it('refuses a journal from the guardians that holds an asset channel as one this build never replicates, and asks no provider', async () => {
		const tag = 'guardian journal';
		const alice = assetHost(tag, 1, {}, { sqlite: true });
		const bob = host(tag, 2, false);
		hosts.push(alice);
		connectHosts(alice, bob);
		const ordinary = openReadyChannel(alice.node, bob.node);
		// A target that holds only an ordinary channel is read and passed.
		expect(() =>
			assertGuardianJournalHoldsNoAuxiliaryChannels(alice.storage!)
		).to.not.throw();
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 700n,
			acceptorUnits: 300n
		});
		const hex = channelId.toString('hex');
		const refusal = thrownBy(() =>
			assertGuardianJournalHoldsNoAuxiliaryChannels(alice.storage!)
		);
		expect(refusal).to.be.instanceOf(AuxiliaryGuardianRestoreError);
		const typed = refusal as AuxiliaryGuardianRestoreError;
		expect(typed.code).to.equal('AUXILIARY_GUARDIAN_RESTORE_REFUSED');
		expect(typed.channelIds).to.deep.equal([hex]);
		expect(typed.channelIds).to.not.include(ordinary.toString('hex'));
		expect(typed.message).to.equal(
			`The journal the guardians hold for this wallet carries 1 asset channel (${hex}). ` +
				'This build never replicates an asset channel to guardians and ' +
				'cannot restore one from them, so nothing of the journal was ' +
				'installed (AUXILIARY_GUARDIAN_RESTORE_REFUSED).'
		);
	});

	it('does not start over a stored asset channel, with a provider or without one, and changes nothing', async () => {
		const tag = 'guardian start';
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-guardian-'));
		try {
			const file = path.join(directory, 'alice.sqlite');
			const alice = assetHost(tag, 1, {}, { sqlitePath: file });
			const bob = host(tag, 2, false);
			connectHosts(alice, bob);
			const channelId = await openAssetChannel(alice, bob, {
				tag,
				openerUnits: 700n,
				acceptorUnits: 300n
			});
			const hex = channelId.toString('hex');
			alice.node.destroy();
			const stored = (): unknown => {
				const storage = new SqliteStorage(file);
				storage.open();
				const row = storage.loadChannel(hex);
				storage.close();
				return row;
			};
			const before = stored();
			expect(before).to.not.equal(null);

			for (const provider of [true, false]) {
				const storage = new SqliteStorage(file);
				storage.open();
				const refusal = thrownBy(() =>
					createNode(tag, 1, storage, {
						recovery: { guardians: [GUARDIAN] },
						...(provider
							? {
									auxiliaryChannels: {
										provider: referenceProvider(),
										resolveIncoming: (): undefined => undefined
									}
							  }
							: {})
					})
				);
				try {
					storage.close();
				} catch {
					// The node that did not start had closed it.
				}
				expect(refusal).to.be.instanceOf(AuxiliaryGuardianStartError);
				const typed = refusal as AuxiliaryGuardianStartError;
				expect(typed.code).to.equal('AUXILIARY_GUARDIAN_START_REFUSED');
				expect(typed.channelIds).to.deep.equal([hex]);
				expect(typed.message).to.equal(
					`This wallet holds 1 asset channel (${hex}) and is set to back up ` +
						'to guardians, which cannot restore an asset channel, so it ' +
						'was not started (AUXILIARY_GUARDIAN_START_REFUSED). Close ' +
						'the asset channel, or start without the guardian backup.'
				);
				expect(stored()).to.deep.equal(before);
			}

			// Without guardians the same storage starts, with the channel.
			const again = assetHost(tag, 1, {}, { sqlitePath: file });
			hosts.push(again);
			expect(
				again.node
					.listChannels()
					.map((row) => [row.channelId.toString('hex'), row.auxiliary])
			).to.deep.equal([[hex, true]]);
		} finally {
			for (const made of hosts.splice(0)) made.node.destroy();
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
});

describe('a restore that holds asset channels', () => {
	withAssetOpens();

	const TAG = 'asset restore';
	const SECRET = makeNodeConfig(TAG, 1).nodePrivateKey as Buffer;

	let hosts: IAssetHost[];
	let nodes: LightningNode[];
	let storages: SqliteStorage[];

	beforeEach(() => {
		hosts = [];
		nodes = [];
		storages = [];
	});

	afterEach(() => {
		for (const node of nodes) node.destroy();
		for (const host of hosts) host.node.destroy();
		for (const storage of storages) {
			try {
				storage.close();
			} catch {
				// Closed with its node.
			}
		}
	});

	const target = (): SqliteStorage => {
		const storage = openStorage();
		storages.push(storage);
		return storage;
	};

	const scb = (): string =>
		encodeScb(
			{ version: 1, network: 'regtest', createdAt: 1, channels: [] },
			SECRET
		);

	/** A journaled node with one asset channel, and the capsule of its journal. */
	const journaled = async (): Promise<{
		alice: IAssetHost;
		channelId: Buffer;
		capsule: RecoveryCapsule;
	}> => {
		const storage = openStorage();
		const alice = assetHost(
			TAG,
			1,
			{},
			{ extra: { storage, recovery: { enabled: true } } }
		);
		const bob = assetHost(TAG, 2);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag: TAG,
			openerUnits: 900n,
			acceptorUnits: 100n
		});
		const { capsule, inline, inlineError } = composeRecoveryCapsule({
			storage,
			encryptedScb: scb(),
			nodeSecret: SECRET
		});
		expect(inline, String(inlineError)).to.equal(true);
		return { alice, channelId, capsule };
	};

	const provider = (
		canRestore?: IAuxiliaryChannelConfig['canRestore']
	): IAuxiliaryChannelConfig => ({
		provider: referenceProvider(),
		resolveIncoming: (): undefined => undefined,
		...(canRestore ? { canRestore } : {})
	});

	/** Nothing of a refused restore is left in the database it was for. */
	const expectUntouched = (storage: SqliteStorage): void => {
		expect(storage.loadAllChannels()).to.deep.equal([]);
		expect(storage.loadRecoveryFrames!(0)).to.deep.equal([]);
	};

	it('is refused with the refusal of a start when there is no provider, and installs nothing', async () => {
		const { channelId, capsule } = await journaled();
		const into = target();
		const refusal = thrownBy(() =>
			restoreFromRecoveryCapsule(capsule, into, SECRET)
		);
		expect(refusal).to.be.instanceOf(AuxiliaryProviderRequiredError);
		expect((refusal as AuxiliaryProviderRequiredError).code).to.equal(
			'AUXILIARY_PROVIDER_REQUIRED'
		);
		expect(
			(refusal as AuxiliaryProviderRequiredError).channelIds
		).to.deep.equal([channelId.toString('hex')]);
		expectUntouched(into);
	});

	it('is refused unless the provider says it can restore, and installs nothing', async () => {
		const { channelId, capsule } = await journaled();
		const id = channelId.toString('hex');
		const answers: Array<[string, IAuxiliaryChannelConfig, string?]> = [
			['no canRestore', provider()],
			['false', provider(() => false)],
			[
				'a promise',
				provider(() => Promise.resolve(true) as unknown as boolean)
			],
			[
				'a throw',
				provider(() => {
					throw new Error('the proofs of this channel are not here');
				}),
				'the proofs of this channel are not here'
			]
		];
		for (const [name, auxiliaryChannels, detail] of answers) {
			const into = target();
			const refusal = thrownBy(() =>
				restoreFromRecoveryCapsule(capsule, into, SECRET, {
					auxiliaryChannels
				})
			);
			expect(refusal, name).to.be.instanceOf(AuxiliaryRestoreRefusedError);
			const typed = refusal as AuxiliaryRestoreRefusedError;
			expect(typed.code, name).to.equal('AUXILIARY_RESTORE_REFUSED');
			expect(typed.channelIds, name).to.deep.equal([id]);
			expect(typed.detail, name).to.equal(detail);
			expect(typed.message, name).to.equal(
				`This restore holds 1 asset channel (${id}) and the asset channel ` +
					'provider did not say it can restore it, so nothing of it was ' +
					'restored (AUXILIARY_RESTORE_REFUSED).' +
					(detail ? ` The provider answered: ${detail}` : '')
			);
			expectUntouched(into);
		}
	});

	it('goes on when the provider says it can restore, and tells it which channels', async () => {
		const { alice, channelId, capsule } = await journaled();
		const asked: IAuxiliaryRestoredChannel[][] = [];
		const into = target();
		const result = restoreFromRecoveryCapsule(capsule, into, SECRET, {
			auxiliaryChannels: provider((channels) => {
				asked.push([...channels]);
				return true;
			})
		});
		expect(result.tier).to.equal(2);
		expect(asked).to.have.length(1);
		expect(asked[0]).to.have.length(1);
		expect(asked[0][0].channelId.equals(channelId)).to.equal(true);
		expect(asked[0][0].peerPubkey).to.equal(hosts[1].node.getNodeId());
		expect(asked[0][0].source).to.equal('journal');
		expect(asked[0][0].channelData?.length).to.be.greaterThan(0);
		const restored = into.loadChannel(channelId.toString('hex'));
		expect(restored?.state.auxiliaryState?.localBalance).to.equal(
			alice.node.getAuxiliaryChannelInfo(channelId)?.localAssetBalance
		);
		expect(restored?.state.restoreRecencyUnproven).to.equal(true);
		// What a refused restore is checked not to leave behind.
		expect(into.loadRecoveryFrames!(0).length).to.be.greaterThan(0);
	});

	it('is refused as a whole by the best-capsule restore: no older candidate, no fallback to the backup alone', async () => {
		const { capsule } = await journaled();
		const into = target();
		const refusal = thrownBy(() =>
			restoreBestRecoveryCapsule(
				[encryptRecoveryCapsule(capsule, SECRET)],
				into,
				SECRET,
				{
					scratchStorage: openStorage,
					auxiliaryChannels: provider(() => false)
				}
			)
		);
		expect(refusal).to.be.instanceOf(AuxiliaryRestoreRefusedError);
		expectUntouched(into);
	});

	it('never asks about a restore that holds no asset channel', () => {
		const storage = openStorage();
		const alice = createNode(TAG, 1, storage, { recovery: { enabled: true } });
		const bob = createNode(TAG, 2);
		nodes.push(alice, bob);
		alice.on('node:error', () => undefined);
		bob.on('node:error', () => undefined);
		const connect = (from: LightningNode, to: LightningNode): void => {
			from.on('message:outbound', (pubkey: string, type: number, payload) => {
				if (pubkey === to.getNodeId()) {
					to.handlePeerMessage(from.getNodeId(), type, payload as Buffer);
				}
			});
		};
		connect(alice, bob);
		connect(bob, alice);
		const channelId = openReadyChannel(alice, bob);
		const { capsule, inline } = composeRecoveryCapsule({
			storage,
			encryptedScb: scb(),
			nodeSecret: SECRET
		});
		expect(inline).to.equal(true);
		let asked = 0;
		const withProvider = target();
		const plain = target();
		restoreFromRecoveryCapsule(capsule, withProvider, SECRET, {
			auxiliaryChannels: provider(() => {
				asked++;
				return false;
			})
		});
		restoreFromRecoveryCapsule(capsule, plain, SECRET);
		expect(asked).to.equal(0);
		const id = channelId.toString('hex');
		expect(withProvider.loadChannel(id)).to.deep.equal(plain.loadChannel(id));
		expect(plain.loadChannel(id)).to.not.equal(null);
	});

	it('recovers an asset channel from a static backup only where the provider says it can', async () => {
		const { alice, channelId } = await journaled();
		const id = channelId.toString('hex');
		const entries = alice.node.buildStaticChannelBackupData().channels;
		expect(entries.map((entry) => entry.channelId)).to.deep.equal([id]);

		const recover = async (
			auxiliaryChannels?: IAuxiliaryChannelConfig
		): Promise<Array<{ channelId: string; reason: string }>> => {
			const node = createNode(
				TAG,
				1,
				undefined,
				auxiliaryChannels ? { auxiliaryChannels } : {}
			);
			nodes.push(node);
			node.on('node:error', () => undefined);
			return (await node.recoverFromStaticChannelBackup(entries)).skipped;
		};

		const withNone = await recover();
		expect(withNone).to.have.length(1);
		expect(withNone[0].reason).to.equal(
			new AuxiliaryProviderRequiredError([id]).message
		);
		const unsaid = await recover(provider());
		expect(unsaid).to.have.length(1);
		expect(unsaid[0].reason).to.equal(
			new AuxiliaryRestoreRefusedError([id]).message
		);
		const asked: IAuxiliaryRestoredChannel[] = [];
		const agreed = await recover(
			provider((channels) => {
				asked.push(...channels);
				return true;
			})
		);
		expect(asked.map((channel) => channel.source)).to.deep.equal([
			'static-backup'
		]);
		expect(asked[0].channelData).to.equal(undefined);
		expect(
			agreed.filter((entry) => /AUXILIARY_/.test(entry.reason))
		).to.deep.equal([]);
	});
});
