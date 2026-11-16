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
	framesWithoutChannels,
	isGuardianRecoveryMode,
	RecoveryCapsule,
	refusedAuxiliaryChannels,
	restoreBestRecoveryCapsule,
	restoreFromRecoveryCapsule,
	storedAuxiliaryChannelIds
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { isStorageTransactionActive } from '../../src/lightning/storage/transaction';
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

	/**
	 * A journaled node with one asset channel, and the capsule of its
	 * journal. With `ordinary`, an ordinary channel with the same peer too.
	 */
	const journaled = async (
		ordinary = false
	): Promise<{
		alice: IAssetHost;
		channelId: Buffer;
		ordinaryId?: Buffer;
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
		const ordinaryId = ordinary
			? openReadyChannel(alice.node, bob.node)
			: undefined;
		const { capsule, inline, inlineError } = composeRecoveryCapsule({
			storage,
			encryptedScb: scb(),
			nodeSecret: SECRET,
			// Two channels' journal is more than a peer stores: the restore
			// is handed the capsule itself here.
			...(ordinary ? { maxBytes: 1_000_000 } : {})
		});
		expect(inline, String(inlineError)).to.equal(true);
		return { alice, channelId, ...(ordinaryId ? { ordinaryId } : {}), capsule };
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

	it('asks the provider before the install opens: outside any storage transaction, with none of the rows of the restore to read, and for exactly the channels it then installs', async () => {
		const { channelId, capsule } = await journaled();
		for (const answer of [false, true]) {
			const into = target();
			const seen: Array<{ inside: boolean; rows: number }> = [];
			const refusal = ((): unknown => {
				try {
					restoreFromRecoveryCapsule(capsule, into, SECRET, {
						auxiliaryChannels: provider(() => {
							seen.push({
								inside: isStorageTransactionActive(into),
								rows: into.loadAllChannels().length
							});
							// What the hook writes is its own, not the install's.
							into.saveMetadata('provider:note', 'written by the hook');
							return answer;
						})
					});
				} catch (err) {
					return err;
				}
				return undefined;
			})();
			expect(seen, String(answer)).to.deep.equal([{ inside: false, rows: 0 }]);
			expect(into.loadMetadata('provider:note')).to.equal(
				'written by the hook'
			);
			if (answer) {
				expect(refusal).to.equal(undefined);
				expect(
					into.loadAllChannels().map((row) => row.channelId)
				).to.deep.equal([channelId.toString('hex')]);
			} else {
				expect(refusal).to.be.instanceOf(AuxiliaryRestoreRefusedError);
				expectUntouched(into);
			}
		}
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

	describe('and the list of them', () => {
		it("is carried by the refusal, with each channel's peer and capacity, whether a provider is missing or said no", async () => {
			const { channelId, capsule } = await journaled();
			const whole = target();
			restoreFromRecoveryCapsule(capsule, whole, SECRET, {
				auxiliaryChannels: provider(() => true)
			});
			const held = [
				{
					channelId: channelId.toString('hex'),
					peerPubkey: hosts[1].node.getNodeId(),
					capacitySatoshis: whole.loadChannel(channelId.toString('hex'))!.state
						.fundingSatoshis
				}
			];
			expect(held[0].capacitySatoshis > 0n).to.equal(true);
			const missing = thrownBy(() =>
				restoreFromRecoveryCapsule(capsule, target(), SECRET)
			);
			expect(missing).to.be.instanceOf(AuxiliaryProviderRequiredError);
			expect(refusedAuxiliaryChannels(missing)).to.deep.equal(held);
			const refused = thrownBy(() =>
				restoreFromRecoveryCapsule(capsule, target(), SECRET, {
					auxiliaryChannels: provider(() => false)
				})
			);
			expect(refused).to.be.instanceOf(AuxiliaryRestoreRefusedError);
			expect(refusedAuxiliaryChannels(refused)).to.deep.equal(held);
			expect((refused as AuxiliaryRestoreRefusedError).channels).to.deep.equal(
				held
			);
			// A refusal that was not a capsule restore's has no list, and
			// neither has any other error.
			expect(
				refusedAuxiliaryChannels(
					new AuxiliaryProviderRequiredError([held[0].channelId])
				)
			).to.equal(undefined);
			expect(refusedAuxiliaryChannels(new Error('disk full'))).to.equal(
				undefined
			);
			expect(refusedAuxiliaryChannels(undefined)).to.equal(undefined);
		});
	});

	describe('run with omitAuxiliaryChannels', () => {
		it('leaves every asset channel out, writes no row of it, asks no provider, restores the rest as it would have been and says what was left out', async () => {
			const { channelId, ordinaryId, capsule } = await journaled(true);
			const id = channelId.toString('hex');
			const ordinary = ordinaryId!.toString('hex');
			const peer = hosts[1].node.getNodeId();

			// The same capsule restored whole, by a provider that agrees.
			const whole = target();
			restoreFromRecoveryCapsule(capsule, whole, SECRET, {
				auxiliaryChannels: provider(() => true)
			});
			expect(whole.loadChannel(id)).to.not.equal(null);

			let asked = 0;
			const into = target();
			const result = restoreFromRecoveryCapsule(capsule, into, SECRET, {
				omitAuxiliaryChannels: true,
				auxiliaryChannels: provider(() => {
					asked++;
					return true;
				})
			});
			expect(asked).to.equal(0);
			expect(result.tier).to.equal(2);
			expect(result.omittedAuxiliaryChannels).to.deep.equal([
				{
					channelId: id,
					peerPubkey: peer,
					capacitySatoshis: whole.loadChannel(id)!.state.fundingSatoshis
				}
			]);
			// No row of the asset channel.
			expect(into.loadChannel(id)).to.equal(null);
			expect(storedAuxiliaryChannelIds(into)).to.deep.equal([]);
			expect(
				into.loadAllChainMonitors().map((row) => row.channelId)
			).to.not.include(id);
			expect(into.loadOutboxMessages!(id)).to.deep.equal([]);
			expect(
				into
					.loadAllHtlcPaymentMappings()
					.filter((row) => row.key.startsWith(id))
			).to.deep.equal([]);
			// Its key index stays, so its keys are never derived again.
			expect(into.loadChannelKeyIndex(id)).to.equal(
				whole.loadChannelKeyIndex(id)
			);
			expect(into.loadChannelKeyIndex(id)).to.not.equal(null);
			// The ordinary channel, its monitor and its messages are what the
			// whole restore installed.
			expect(into.loadChannel(ordinary)).to.deep.equal(
				whole.loadChannel(ordinary)
			);
			expect(into.loadChannel(ordinary)?.state.restoreRecencyUnproven).to.equal(
				true
			);
			expect(
				into.loadAllChainMonitors().filter((row) => row.channelId === ordinary)
			).to.deep.equal(
				whole.loadAllChainMonitors().filter((row) => row.channelId === ordinary)
			);
			expect(
				into.loadOutboxMessages!(ordinary).map((row) => row.wireMessage)
			).to.deep.equal(
				whole.loadOutboxMessages!(ordinary).map((row) => row.wireMessage)
			);
			expect(into.loadAllChannelKeyIndices()).to.deep.equal(
				whole.loadAllChannelKeyIndices()
			);
			// The journal is installed whole, as the capsule carried it.
			expect(into.loadRecoveryFrames!(0)).to.deep.equal(
				whole.loadRecoveryFrames!(0)
			);

			// A node with no provider starts on it, and runs the ordinary
			// channel alone.
			const node = createNode(TAG, 1, into, { recovery: { enabled: true } });
			nodes.push(node);
			node.on('node:error', () => undefined);
			expect(
				node.listChannels().map((channel) => channel.channelId.toString('hex'))
			).to.deep.equal([ordinary]);
		});

		it('is the default restore, to the row, for a capsule that holds no asset channel', () => {
			const storage = openStorage();
			storages.push(storage);
			const alice = createNode(TAG, 1, storage, {
				recovery: { enabled: true }
			});
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
			const id = openReadyChannel(alice, bob).toString('hex');
			const { capsule, inline } = composeRecoveryCapsule({
				storage,
				encryptedScb: scb(),
				nodeSecret: SECRET
			});
			expect(inline).to.equal(true);
			const plain = target();
			const omitting = target();
			const expected = restoreFromRecoveryCapsule(capsule, plain, SECRET);
			const result = restoreFromRecoveryCapsule(capsule, omitting, SECRET, {
				omitAuxiliaryChannels: true
			});
			expect(result).to.not.have.property('omittedAuxiliaryChannels');
			expect(result.framesApplied).to.equal(expected.framesApplied);
			expect(omitting.loadChannel(id)).to.deep.equal(plain.loadChannel(id));
			expect(omitting.loadAllChainMonitors()).to.deep.equal(
				plain.loadAllChainMonitors()
			);
			expect(omitting.loadOutboxMessages!()).to.deep.equal(
				plain.loadOutboxMessages!()
			);
			expect(omitting.loadRecoveryFrames!(0)).to.deep.equal(
				plain.loadRecoveryFrames!(0)
			);
		});

		it('takes only the exact true for the option, and refuses as before for anything else', async () => {
			const { capsule } = await journaled();
			for (const given of [false, undefined, 'true', 1]) {
				const into = target();
				const refusal = thrownBy(() =>
					restoreFromRecoveryCapsule(capsule, into, SECRET, {
						omitAuxiliaryChannels: given as boolean | undefined
					})
				);
				expect(refusal, String(given)).to.be.instanceOf(
					AuxiliaryProviderRequiredError
				);
				expectUntouched(into);
			}
		});

		it('is carried through the best-capsule restore, with the list', async () => {
			const { channelId, capsule } = await journaled();
			const into = target();
			const result = restoreBestRecoveryCapsule(
				[encryptRecoveryCapsule(capsule, SECRET)],
				into,
				SECRET,
				{ scratchStorage: openStorage, omitAuxiliaryChannels: true }
			);
			expect(result.tier).to.equal(2);
			expect(
				result.omittedAuxiliaryChannels?.map((channel) => channel.channelId)
			).to.deep.equal([channelId.toString('hex')]);
			expect(into.loadAllChannels()).to.deep.equal([]);
			expect(into.loadRecoveryFrames!(0).length).to.be.greaterThan(0);
		});

		it('drops what is keyed by a channel left out, in the snapshot and in the frames after it, and keeps its key index and the history of the wallet', () => {
			type Frames = Parameters<typeof framesWithoutChannels>[0];
			const out = 'aa'.repeat(32);
			const kept = 'bb'.repeat(32);
			const secret = Buffer.alloc(32, 1);
			const message = (channelId?: string): Record<string, unknown> => ({
				peerId: '02' + '11'.repeat(32),
				...(channelId ? { channelId } : {}),
				messageType: 132,
				wireMessage: Buffer.from('signed')
			});
			const frame = (
				over: Record<string, unknown>
			): Record<string, unknown> => ({
				version: 5,
				writerEpoch: 1n,
				sequence: 1n,
				previousFrameHash: Buffer.alloc(32),
				timestamp: 1,
				mutations: [],
				outboundMessages: [],
				...over
			});
			const snapshot = {
				schemaVersion: '2',
				channels: [
					{ channelId: out, state: { n: 1 }, peerPubkey: 'peer' },
					{ channelId: kept, state: { n: 2 }, peerPubkey: 'peer' }
				],
				keyIndices: [
					{ channelId: out, channelIndex: 4 },
					{ channelId: kept, channelIndex: 5 }
				],
				chainMonitors: [
					{ channelId: out, state: { n: 1 } },
					{ channelId: kept, state: { n: 2 } }
				],
				preimages: [{ paymentHash: 'h1', preimage: secret }],
				payments: [{ paymentHash: 'h1', payment: { status: 'pending' } }],
				htlcPaymentMappings: [
					{ key: `${out}:offered-1`, paymentHash: 'h1' },
					{ key: `${kept}:offered-2`, paymentHash: 'h2' }
				],
				forwardedHtlcs: [
					{
						outKey: `${out}:3`,
						inChannelId: Buffer.from(kept, 'hex'),
						inHtlcId: 1n
					},
					{
						outKey: `${kept}:4`,
						inChannelId: Buffer.from(out, 'hex'),
						inHtlcId: 2n
					},
					{
						outKey: `${kept}:5`,
						inChannelId: Buffer.from(kept, 'hex'),
						inHtlcId: 3n
					}
				],
				htlcSharedSecrets: [
					{ key: `${out}:1`, secret },
					{ key: `${kept}:2`, secret }
				],
				outbox: [
					{ ...message(out), frameSequence: 1 },
					{ ...message(kept), frameSequence: 1 },
					{ ...message(), frameSequence: null }
				]
			};
			const mutations = [
				{
					type: 'channel_state',
					channelId: out,
					state: { n: 3 },
					peerPubkey: 'peer'
				},
				{
					type: 'channel_state',
					channelId: kept,
					state: { n: 4 },
					peerPubkey: 'peer'
				},
				{ type: 'channel_key_index', channelId: out, channelIndex: 4 },
				{ type: 'chain_monitor', channelId: out, state: { n: 3 } },
				{ type: 'chain_monitor', channelId: kept, state: { n: 4 } },
				{
					type: 'htlc_payment_mapping',
					htlcKey: `${out}:offered-7`,
					paymentHash: 'h3'
				},
				{
					type: 'htlc_payment_mapping',
					htlcKey: `${kept}:offered-8`,
					paymentHash: 'h4'
				},
				{ type: 'delete_htlc_payment_mapping', htlcKey: `${out}:offered-1` },
				{ type: 'htlc_shared_secret', key: `${out}:7`, secret },
				{ type: 'delete_htlc_shared_secret', key: `${out}:1` },
				{
					type: 'forwarded_htlc',
					outKey: `${kept}:9`,
					inChannelId: Buffer.from(out, 'hex'),
					inHtlcId: 4n
				},
				{ type: 'delete_forwarded_htlc', outKey: `${out}:3` },
				{ type: 'outbox_supersede', channelId: out },
				{ type: 'outbox_supersede', channelId: kept },
				{ type: 'channel_closed', channelId: out },
				{ type: 'payment_preimage', paymentHash: 'h3', preimage: secret },
				{
					type: 'payment_state',
					paymentHash: 'h3',
					payment: { status: 'pending' }
				}
			];
			const frames = [
				frame({ snapshot }),
				frame({
					sequence: 2n,
					mutations,
					outboundMessages: [message(out), message(kept), message()]
				})
			] as unknown as Frames;
			const before = JSON.stringify(frames, (_key, value) =>
				typeof value === 'bigint' ? `${value}n` : value
			);
			// The set is read without regard to case.
			const left = framesWithoutChannels(frames, new Set([out.toUpperCase()]));
			expect(
				JSON.stringify(frames, (_key, value) =>
					typeof value === 'bigint' ? `${value}n` : value
				)
			).to.equal(before);
			const base = left[0].snapshot! as unknown as typeof snapshot;
			expect(base.channels.map((row) => row.channelId)).to.deep.equal([kept]);
			expect(base.chainMonitors.map((row) => row.channelId)).to.deep.equal([
				kept
			]);
			expect(base.keyIndices).to.deep.equal(snapshot.keyIndices);
			expect(base.preimages).to.deep.equal(snapshot.preimages);
			expect(base.payments).to.deep.equal(snapshot.payments);
			expect(base.htlcPaymentMappings.map((row) => row.key)).to.deep.equal([
				`${kept}:offered-2`
			]);
			expect(base.forwardedHtlcs.map((row) => row.outKey)).to.deep.equal([
				`${kept}:5`
			]);
			expect(base.htlcSharedSecrets.map((row) => row.key)).to.deep.equal([
				`${kept}:2`
			]);
			expect(base.outbox).to.deep.equal([
				snapshot.outbox[1],
				snapshot.outbox[2]
			]);
			expect(base.schemaVersion).to.equal('2');
			expect(left[1].sequence).to.equal(2n);
			expect(left[1].mutations).to.deep.equal([
				mutations[1],
				mutations[2],
				mutations[4],
				mutations[6],
				mutations[13],
				mutations[15],
				mutations[16]
			]);
			expect(left[1].outboundMessages).to.deep.equal([
				message(kept),
				message()
			]);
			// No channel named: the frames themselves.
			expect(framesWithoutChannels(frames, new Set())).to.equal(frames);
		});
	});
});
